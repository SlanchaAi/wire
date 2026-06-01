//! RFC-001 — operator / organization enrollment (producer side).
//!
//! The verifier side (`org_membership`, `pair_decision`, `org_policy`) consumes
//! identity claims; this is the half that *produces* them. Pure over the
//! supplied keypairs — key STORAGE (where the operator's / org's private keys
//! live on disk) is the CLI's concern, deliberately not here, so this stays
//! unit-testable and reusable by the CLI, the live agent, and the e2e alike.
//!
//! Two operations:
//!  - an **org issues a membership cert** for an operator (`issue_member_cert`):
//!    the org key signs the operator's `op_did`;
//!  - an **operator assembles its session claims** (`build_member_claims`):
//!    signs `op_cert` over the session DID and carries `op_pubkey` + each org's
//!    pubkey inline so the resulting card verifies fully offline (#94).

use crate::agent_card::{IdentityClaims, OrgMembership, did_for_op};
use crate::identity::{CertError, sign_did_cert};
use crate::signing::b64encode;

/// One org membership an operator holds, ready to assemble into card claims.
/// `member_cert` is produced by the org via [`issue_member_cert`].
pub struct MemberOf {
    pub org_did: String,
    pub org_pubkey: [u8; 32],
    pub member_cert: String,
}

/// An org issues a membership cert for an operator: the org's key signs the
/// operator's `op_did` (UTF-8 bytes). The operator carries the returned base64
/// cert in its card; a receiver verifies it with `identity::verify_member_cert`
/// against the inline `org_pubkey`.
pub fn issue_member_cert(org_sk: &[u8], op_did: &str) -> Result<String, CertError> {
    sign_did_cert(org_sk, op_did)
}

/// Assemble the v3.2 [`IdentityClaims`] a session presents.
///
/// Given the operator's handle + keypair, the session DID this card belongs to,
/// and the operator's org memberships, this signs `op_cert` over the session
/// DID and carries `op_pubkey` + each membership's `org_pubkey` inline. The
/// resulting claims, layered via `agent_card::with_identity_claims` and signed,
/// verify fully offline through `org_membership::evaluate_card_membership`.
pub fn build_member_claims(
    op_handle: &str,
    op_sk: &[u8; 32],
    op_pk: &[u8; 32],
    session_did: &str,
    memberships: &[MemberOf],
    project: Option<String>,
) -> Result<IdentityClaims, CertError> {
    let op_did = did_for_op(op_handle, op_pk);
    let op_cert = sign_did_cert(op_sk, session_did)?;
    let org_memberships = memberships
        .iter()
        .map(|m| OrgMembership {
            org_did: m.org_did.clone(),
            org_pubkey: b64encode(&m.org_pubkey),
            member_cert: m.member_cert.clone(),
        })
        .collect();
    Ok(IdentityClaims {
        op_did: Some(op_did),
        op_cert: Some(op_cert),
        op_pubkey: Some(b64encode(op_pk)),
        org_memberships,
        project,
    })
}

/// Card-emit (RFC-001 Phase 1b): if this machine has an enrolled operator
/// (`op.key` present), attach the operator's identity claims + stored org
/// memberships to `card`. Returns the card unchanged when not enrolled, so
/// card-build stays correct for the common case. The returned card is UNSIGNED;
/// the caller signs it (`sign_agent_card`). Malformed stored memberships are
/// skipped, not fatal.
pub fn with_op_claims_if_enrolled(
    card: crate::agent_card::AgentCard,
) -> anyhow::Result<crate::agent_card::AgentCard> {
    with_op_claims_if_enrolled_inner(card)
}

/// Rebuild the on-disk agent card with the **current** enrollment state and
/// re-sign it. Closes the enroll-after-`init` DX gap: claims are normally
/// attached at card-build time (`pair_session::init_self` / `cli.rs` init via
/// [`with_op_claims_if_enrolled`]), but an operator who enrolls AFTER `init`
/// has a stored card that pre-dates the claims. This reads the stored card,
/// strips any pre-existing identity-claim fields + signature, overlays the
/// current claims via the same helper used at init, re-signs with the existing
/// session key, and writes the card back. **Pure rebuild** — does NOT publish;
/// callers (the `wire enroll republish` CLI dispatcher) chain the existing
/// `republish_card_to_phonebook` to push to the phonebook. Bails if `wire init`
/// hasn't run; idempotent when not enrolled (strips stale claims → identical to
/// a freshly-init'd non-enrolled card → re-signed → written).
pub fn rebuild_card_with_current_claims() -> anyhow::Result<crate::agent_card::AgentCard> {
    use anyhow::Context;
    let mut card = crate::config::read_agent_card()
        .context("no stored agent card — run `wire init` before `wire enroll republish`")?;
    if let Some(obj) = card.as_object_mut() {
        // Strip any pre-existing identity claims + the old self-signature so
        // the rebuilt card is constructed exactly as init would have built it
        // for the current enrollment state (no stale claims survive).
        obj.remove("op_did");
        obj.remove("op_cert");
        obj.remove("op_pubkey");
        obj.remove("org_memberships");
        obj.remove("signature");

        // v0.14.2 (#126): refresh the wire/* entry in `capabilities[]` so
        // the republished card advertises the binary's current
        // CARD_SCHEMA_VERSION. Pre-fix: an operator who init'd at
        // v0.13.5 (capabilities=["wire/v3.1"]) and republished at
        // v0.14.1 kept the old "wire/v3.1" entry even though
        // schema_version bumped to v3.2 — peers gating on the
        // capabilities set silently bypassed upgraded sessions. Only
        // wire/* entries are binary-derived; operator-defined caps
        // (e.g. custom task tags, future feature flags) are preserved.
        let current_wire_cap = format!("wire/{}", crate::agent_card::CARD_SCHEMA_VERSION);
        let preserved_caps: Vec<serde_json::Value> = obj
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter(|c| c.as_str().map(|s| !s.starts_with("wire/")).unwrap_or(false))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut new_caps = vec![serde_json::Value::String(current_wire_cap)];
        new_caps.extend(preserved_caps);
        obj.insert("capabilities".into(), serde_json::Value::Array(new_caps));
    }
    let card = with_op_claims_if_enrolled_inner(card)?;
    let sk = crate::config::read_private_key()
        .context("no session signing key on disk — re-run `wire init`")?;
    let signed = crate::agent_card::sign_agent_card(&card, &sk);
    crate::config::write_agent_card(&signed)?;
    Ok(signed)
}

fn with_op_claims_if_enrolled_inner(
    card: crate::agent_card::AgentCard,
) -> anyhow::Result<crate::agent_card::AgentCard> {
    let Ok(op_sk) = crate::config::read_op_key() else {
        return Ok(card); // not enrolled → no claims
    };
    let session_did = card
        .get("did")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if session_did.is_empty() {
        return Ok(card);
    }
    let op_handle = crate::config::read_op_handle()
        .ok()
        .flatten()
        .unwrap_or_else(|| "operator".to_string());
    let op_pk = ed25519_dalek::SigningKey::from_bytes(&op_sk)
        .verifying_key()
        .to_bytes();

    let mut memberships = Vec::new();
    for m in crate::config::read_memberships().unwrap_or_default() {
        let (Some(org_did), Some(org_pubkey_b64), Some(member_cert)) = (
            m.get("org_did").and_then(|v| v.as_str()),
            m.get("org_pubkey").and_then(|v| v.as_str()),
            m.get("member_cert").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let Ok(bytes) = crate::signing::b64decode(org_pubkey_b64) else {
            continue;
        };
        if bytes.len() != 32 {
            continue;
        }
        let mut org_pk = [0u8; 32];
        org_pk.copy_from_slice(&bytes);
        memberships.push(MemberOf {
            org_did: org_did.to_string(),
            org_pubkey: org_pk,
            member_cert: member_cert.to_string(),
        });
    }

    let project = card
        .get("project")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    // Fail-soft: a cert-build / attach error degrades to "no claims" rather than
    // breaking card-build (init/up is critical-path; a broken identity config
    // must never stop a basic agent from coming up).
    let claims = match build_member_claims(
        &op_handle,
        &op_sk,
        &op_pk,
        &session_did,
        &memberships,
        project,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wire: op-claims skipped (cert build failed: {e:?})");
            return Ok(card);
        }
    };
    match crate::agent_card::with_identity_claims(&card, &claims) {
        Ok(c) => Ok(c),
        Err(e) => {
            eprintln!("wire: op-claims skipped (attach failed: {e:?})");
            Ok(card)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_card::{
        build_agent_card, did_for_org, sign_agent_card, verify_agent_card, with_identity_claims,
    };
    use crate::org_membership::{MembershipOutcome, evaluate_card_membership};
    use crate::signing::generate_keypair;

    #[test]
    fn with_op_claims_attaches_when_enrolled() {
        crate::config::test_support::with_temp_home(|| {
            let (op_sk, op_pk) = generate_keypair();
            crate::config::write_op_key(&op_sk).unwrap();
            crate::config::write_op_handle("darby").unwrap();
            let op_did = did_for_op("darby", &op_pk);

            let (org_sk, org_pk) = generate_keypair();
            let org_did = did_for_org("slanchaai", &org_pk);
            let member_cert = issue_member_cert(&org_sk, &op_did).unwrap();
            crate::config::add_membership(
                &org_did,
                &crate::signing::b64encode(&org_pk),
                &member_cert,
            )
            .unwrap();

            let (_sess_sk, sess_pk) = generate_keypair();
            let base = build_agent_card("vesper-valley", &sess_pk, None, None, None);
            let with = with_op_claims_if_enrolled(base).unwrap();
            assert_eq!(crate::agent_card::card_op_did(&with), Some(op_did.as_str()));
            assert_eq!(crate::agent_card::card_org_memberships(&with).len(), 1);
        });
    }

    #[test]
    fn with_op_claims_noop_when_not_enrolled() {
        crate::config::test_support::with_temp_home(|| {
            let (_sk, pk) = generate_keypair();
            let base = build_agent_card("plain", &pk, None, None, None);
            let out = with_op_claims_if_enrolled(base.clone()).unwrap();
            assert_eq!(out, base); // unchanged — not enrolled
            assert_eq!(crate::agent_card::card_op_did(&out), None);
        });
    }

    #[test]
    fn with_op_claims_failsoft_on_corrupt_memberships() {
        crate::config::test_support::with_temp_home(|| {
            let (op_sk, _op_pk) = generate_keypair();
            crate::config::write_op_key(&op_sk).unwrap(); // creates config dir
            crate::config::write_op_handle("darby").unwrap();
            // Corrupt the memberships store — must NOT break card-build.
            std::fs::write(crate::config::memberships_path().unwrap(), b"{ not json").unwrap();

            let (_s, pk) = generate_keypair();
            let base = build_agent_card("vesper-valley", &pk, None, None, None);
            // Degrades to op-claim-only (no orgs), never errors.
            let out = with_op_claims_if_enrolled(base).unwrap();
            assert!(crate::agent_card::card_op_did(&out).is_some());
            assert_eq!(crate::agent_card::card_org_memberships(&out).len(), 0);
        });
    }

    /// Producer → consumer round-trip: claims built here verify on the other side.
    #[test]
    fn built_claims_verify_offline() {
        let (op_sk, op_pk) = generate_keypair();
        let (org_sk, org_pk) = generate_keypair();
        let (sess_sk, sess_pk) = generate_keypair();

        let op_did = did_for_op("darby", &op_pk);
        let org_did = did_for_org("slanchaai", &org_pk);
        let member_cert = issue_member_cert(&org_sk, &op_did).unwrap();

        let base = build_agent_card("vesper-valley", &sess_pk, None, None, None);
        let session_did = base
            .get("did")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let claims = build_member_claims(
            "darby",
            &op_sk,
            &op_pk,
            &session_did,
            &[MemberOf {
                org_did: org_did.clone(),
                org_pubkey: org_pk,
                member_cert,
            }],
            Some("print-shop".into()),
        )
        .unwrap();

        let card = sign_agent_card(&with_identity_claims(&base, &claims).unwrap(), &sess_sk);
        verify_agent_card(&card).unwrap();
        assert_eq!(
            evaluate_card_membership(&card),
            MembershipOutcome::Verified {
                op_did,
                org_dids: vec![org_did]
            }
        );
    }

    /// An operator with no org memberships still produces a well-formed op claim
    /// (op_did/op_cert/op_pubkey) — it just won't reach ORG_VERIFIED (no vouch).
    #[test]
    fn operator_without_org_builds_but_is_not_verified() {
        let (op_sk, op_pk) = generate_keypair();
        let (sess_sk, sess_pk) = generate_keypair();
        let base = build_agent_card("vesper-valley", &sess_pk, None, None, None);
        let session_did = base
            .get("did")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let claims = build_member_claims("darby", &op_sk, &op_pk, &session_did, &[], None).unwrap();
        assert!(claims.op_did.is_some());
        assert!(claims.op_cert.is_some());
        assert!(claims.op_pubkey.is_some());
        assert!(claims.org_memberships.is_empty());

        let card = sign_agent_card(&with_identity_claims(&base, &claims).unwrap(), &sess_sk);
        // No org vouch → Rejected (no membership verified), never ORG_VERIFIED.
        assert!(matches!(
            evaluate_card_membership(&card),
            MembershipOutcome::Rejected { .. }
        ));
    }

    /// The DX-gap fix: an operator who enrolls AFTER `wire init` can run
    /// `wire enroll republish` to pick up their fresh claims without a re-init.
    #[test]
    fn rebuild_picks_up_post_init_enrollment() {
        crate::config::test_support::with_temp_home(|| {
            std::fs::create_dir_all(crate::config::config_dir().unwrap()).unwrap();
            // Simulate `wire init`: write a session key + a stored card without claims.
            let (sess_sk, sess_pk) = generate_keypair();
            crate::config::write_private_key(&sess_sk).unwrap();
            let base = build_agent_card("vesper-valley", &sess_pk, None, None, None);
            crate::config::write_agent_card(&sign_agent_card(&base, &sess_sk)).unwrap();
            assert_eq!(
                crate::agent_card::card_op_did(&crate::config::read_agent_card().unwrap()),
                None
            );

            // Operator enrolls AFTER init.
            let (op_sk, op_pk) = generate_keypair();
            crate::config::write_op_key(&op_sk).unwrap();
            crate::config::write_op_handle("darby").unwrap();
            let op_did = crate::agent_card::did_for_op("darby", &op_pk);
            let (org_sk, org_pk) = generate_keypair();
            let org_did = did_for_org("slanchaai", &org_pk);
            let member_cert = issue_member_cert(&org_sk, &op_did).unwrap();
            crate::config::add_membership(
                &org_did,
                &crate::signing::b64encode(&org_pk),
                &member_cert,
            )
            .unwrap();

            // Republish rebuild — picks up the post-init claims.
            let signed = rebuild_card_with_current_claims().unwrap();
            verify_agent_card(&signed).unwrap();
            assert_eq!(
                crate::agent_card::card_op_did(&signed),
                Some(op_did.as_str())
            );
            assert_eq!(crate::agent_card::card_org_memberships(&signed).len(), 1);
            // The new card is what's on disk now.
            let on_disk = crate::config::read_agent_card().unwrap();
            assert_eq!(on_disk, signed);
        });
    }

    /// Idempotent / fail-soft: not-enrolled stays not-enrolled, AND any stale
    /// claims on the on-disk card get stripped (the as-current invariant).
    #[test]
    fn rebuild_strips_stale_claims_when_unenrolled() {
        crate::config::test_support::with_temp_home(|| {
            std::fs::create_dir_all(crate::config::config_dir().unwrap()).unwrap();
            let (sess_sk, sess_pk) = generate_keypair();
            crate::config::write_private_key(&sess_sk).unwrap();

            // Manufacture a card with stale claims (as if the operator was once
            // enrolled, ran republish, then later un-enrolled by removing op.key).
            let (op_sk, op_pk) = generate_keypair();
            let op_did = crate::agent_card::did_for_op("darby", &op_pk);
            let (org_sk, org_pk) = generate_keypair();
            let org_did = did_for_org("slanchaai", &org_pk);
            let stale = with_identity_claims(
                &build_agent_card("vesper-valley", &sess_pk, None, None, None),
                &IdentityClaims {
                    op_did: Some(op_did.clone()),
                    op_cert: Some(crate::identity::sign_did_cert(&op_sk, &op_did).unwrap()),
                    op_pubkey: Some(crate::signing::b64encode(&op_pk)),
                    org_memberships: vec![OrgMembership {
                        org_did,
                        org_pubkey: crate::signing::b64encode(&org_pk),
                        member_cert: issue_member_cert(&org_sk, &op_did).unwrap(),
                    }],
                    project: None,
                },
            )
            .unwrap();
            crate::config::write_agent_card(&sign_agent_card(&stale, &sess_sk)).unwrap();
            assert!(
                crate::agent_card::card_op_did(&crate::config::read_agent_card().unwrap())
                    .is_some()
            );

            // No op.key on disk → not enrolled → rebuild strips the stale claims.
            let signed = rebuild_card_with_current_claims().unwrap();
            verify_agent_card(&signed).unwrap();
            assert_eq!(crate::agent_card::card_op_did(&signed), None);
            assert_eq!(crate::agent_card::card_org_memberships(&signed).len(), 0);
        });
    }

    /// #126 fix: a v0.13.5-era stored card has `capabilities=["wire/v3.1"]`.
    /// Republish on v0.14.x must refresh the wire/* entry to match the
    /// binary's current CARD_SCHEMA_VERSION; otherwise peers gating on
    /// `capabilities` silently bypass upgraded sessions even as
    /// `schema_version` bumps to v3.2.
    #[test]
    fn rebuild_refreshes_wire_capability_to_current() {
        crate::config::test_support::with_temp_home(|| {
            std::fs::create_dir_all(crate::config::config_dir().unwrap()).unwrap();
            let (sess_sk, sess_pk) = generate_keypair();
            crate::config::write_private_key(&sess_sk).unwrap();
            // Manufacture a stored card with the legacy "wire/v3.1" capability.
            let legacy = build_agent_card(
                "slate-lotus",
                &sess_pk,
                None,
                Some(vec!["wire/v3.1".to_string()]),
                None,
            );
            crate::config::write_agent_card(&sign_agent_card(&legacy, &sess_sk)).unwrap();
            // Sanity: precondition matches the bug honey/slate-lotus reported.
            let before = crate::config::read_agent_card().unwrap();
            assert_eq!(
                before["capabilities"],
                serde_json::json!(["wire/v3.1"]),
                "precondition: stored card has legacy capability"
            );

            // Republish (no claims) — must refresh capabilities[].
            let signed = rebuild_card_with_current_claims().unwrap();
            verify_agent_card(&signed).unwrap();
            assert_eq!(
                signed["capabilities"],
                serde_json::json!([format!("wire/{}", crate::agent_card::CARD_SCHEMA_VERSION)]),
                "republish must refresh wire/* to current CARD_SCHEMA_VERSION"
            );
        });
    }

    /// #126 fix invariant: non-wire/* capabilities are operator-defined and
    /// MUST survive the republish refresh. Only the wire/* slot is
    /// binary-derived; custom task tags, feature flags, etc. persist.
    #[test]
    fn rebuild_preserves_non_wire_capabilities_through_refresh() {
        crate::config::test_support::with_temp_home(|| {
            std::fs::create_dir_all(crate::config::config_dir().unwrap()).unwrap();
            let (sess_sk, sess_pk) = generate_keypair();
            crate::config::write_private_key(&sess_sk).unwrap();
            // Mixed caps: legacy wire/* + two operator-defined entries.
            let mixed = build_agent_card(
                "slate-lotus",
                &sess_pk,
                None,
                Some(vec![
                    "wire/v3.1".to_string(),
                    "custom-tag".to_string(),
                    "org/v1".to_string(),
                ]),
                None,
            );
            crate::config::write_agent_card(&sign_agent_card(&mixed, &sess_sk)).unwrap();

            let signed = rebuild_card_with_current_claims().unwrap();
            verify_agent_card(&signed).unwrap();
            let caps: Vec<String> = signed["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            // Current wire/* prepended, legacy wire/* dropped, others preserved
            // in their original order.
            assert_eq!(
                caps,
                vec![
                    format!("wire/{}", crate::agent_card::CARD_SCHEMA_VERSION),
                    "custom-tag".to_string(),
                    "org/v1".to_string(),
                ],
                "non-wire/* caps must survive the refresh; only wire/* is replaced"
            );
        });
    }

    /// No `wire init` → no stored card → clear error (not a panic).
    #[test]
    fn rebuild_bails_without_init() {
        crate::config::test_support::with_temp_home(|| {
            let err = rebuild_card_with_current_claims().unwrap_err();
            let msg = format!("{err:?}");
            assert!(
                msg.contains("agent card") || msg.contains("init"),
                "got: {msg}"
            );
        });
    }
}
