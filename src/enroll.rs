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

/// Import an externally-issued `{org_did, org_pubkey, member_cert}` bundle into
/// this operator's local memberships, validating every claim before persisting.
///
/// AC-F-INGEST entry point (issue #127). The operator-side counterpart to
/// `org-add-member`: org owners run `wire enroll org-add-member` to mint the
/// bundle; non-owner operators run `wire enroll org-import-member-cert` to
/// ingest it. Closes the v0.14.1 audit DX hole where joining an existing org
/// required hand-editing `config/wire/memberships.json`.
///
/// Validation order (each fails closed; file is **never** mutated on any
/// rejection — the success-shaped-failure mode dthoma1 flagged in #127 is the
/// thing we are designing against here):
///
/// 1. `org_did` is well-formed `did:wire:org:*` (rejects `did:wire:op:*`, bare
///    session DIDs, and arbitrary strings).
/// 2. `org_pubkey` base64-decodes to exactly 32 bytes (Ed25519 public-key size).
/// 3. `org_did` commits to `org_pubkey` via the long-fingerprint construction
///    (`org_membership::commits_to`). Anti-spoof: a hostile bundle cannot
///    substitute a different pubkey under a known `org_did`.
/// 4. A local operator is enrolled (`op.key` + handle present). Without it the
///    member cert has no payload subject to verify against.
/// 5. `identity::verify_member_cert(&org_pubkey, &member_cert, &local_op_did)`
///    succeeds — the cert actually signs THIS operator under THIS org pubkey.
///
/// Only after all five pass does the function call `config::add_membership` to
/// persist. Idempotent over `org_did`: re-importing the same `org_did` replaces
/// the prior entry, matching `add_membership`'s existing semantics.
pub fn import_member_cert(
    org_did: &str,
    org_pubkey_b64: &str,
    member_cert_b64: &str,
) -> anyhow::Result<String> {
    use anyhow::{Context, bail};

    // Check 1: org_did well-formed.
    if !crate::agent_card::is_org_did(org_did) {
        bail!(
            "rejecting import: org_did must be a `did:wire:org:<handle>-<32hex>` (got `{org_did}`)"
        );
    }

    // Check 2: org_pubkey decodes to 32 bytes.
    let org_pubkey_bytes = crate::signing::b64decode(org_pubkey_b64)
        .with_context(|| format!("rejecting import: org_pubkey is not valid base64 ({org_pubkey_b64})"))?;
    if org_pubkey_bytes.len() != 32 {
        bail!(
            "rejecting import: org_pubkey decodes to {} bytes (Ed25519 public keys are 32 bytes)",
            org_pubkey_bytes.len()
        );
    }
    let mut org_pubkey = [0u8; 32];
    org_pubkey.copy_from_slice(&org_pubkey_bytes);

    // Check 3: org_did commits to org_pubkey (anti-spoof).
    if !crate::org_membership::commits_to(org_did, &org_pubkey) {
        bail!(
            "rejecting import: org_did `{org_did}` does NOT commit to the supplied org_pubkey \
             (the DID's hex suffix must equal `long_fingerprint(org_pubkey)` — see RFC-001 §1)"
        );
    }

    // Check 4: this operator is enrolled.
    let op_sk = crate::config::read_op_key()
        .context("rejecting import: no local operator enrolled — run `wire enroll op` first")?;
    let op_handle = crate::config::read_op_handle()
        .ok()
        .flatten()
        .unwrap_or_else(|| "operator".to_string());
    let op_pk = ed25519_dalek::SigningKey::from_bytes(&op_sk)
        .verifying_key()
        .to_bytes();
    let local_op_did = crate::agent_card::did_for_op(&op_handle, &op_pk);

    // Check 5: member_cert verifies under (org_pubkey, local_op_did).
    crate::identity::verify_member_cert(&org_pubkey, member_cert_b64, &local_op_did)
        .with_context(|| {
            "rejecting import: member_cert does not verify under (org_pubkey, local op_did) — \
             either the cert was issued to a different operator or it was tampered with"
        })?;

    // All checks pass. Persist.
    crate::config::add_membership(org_did, org_pubkey_b64, member_cert_b64)?;

    Ok(local_op_did)
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

    // ---------- AC-F-INGEST: import_member_cert (issue #127) ----------
    //
    // Five validation checks before the bundle is allowed to land in
    // memberships.json. Each negative case asserts the file is NEVER
    // mutated on rejection — the "success-shaped failure that republishes
    // forever" mode dthoma1 flagged is the thing we're designing against.

    /// Helper: mint a valid {org_did, org_pubkey, member_cert} bundle for a
    /// local op_did + handle. Used as the happy-path baseline + as a source
    /// for the negative cases to mutate.
    fn mint_valid_bundle(
        op_did: &str,
    ) -> (String, [u8; 32], String) {
        let (org_sk, org_pk) = generate_keypair();
        let org_did = did_for_org("test-fleet", &org_pk);
        let member_cert = issue_member_cert(&org_sk, op_did).unwrap();
        (org_did, org_pk, member_cert)
    }

    fn enroll_local_op(handle: &str) -> String {
        let (op_sk, op_pk) = generate_keypair();
        crate::config::write_op_key(&op_sk).unwrap();
        crate::config::write_op_handle(handle).unwrap();
        did_for_op(handle, &op_pk)
    }

    #[test]
    fn import_member_cert_happy_path() {
        crate::config::test_support::with_temp_home(|| {
            let local_op_did = enroll_local_op("darby");
            let (org_did, org_pk, member_cert) = mint_valid_bundle(&local_op_did);
            let org_pubkey_b64 = crate::signing::b64encode(&org_pk);

            let returned = import_member_cert(&org_did, &org_pubkey_b64, &member_cert).unwrap();
            assert_eq!(returned, local_op_did);

            // Persisted exactly once with the expected fields.
            let stored = crate::config::read_memberships().unwrap();
            assert_eq!(stored.len(), 1);
            assert_eq!(
                stored[0].get("org_did").and_then(|v| v.as_str()),
                Some(org_did.as_str())
            );

            // Sanity: republish attaches → evaluate_card_membership verifies.
            let (_sess_sk, sess_pk) = generate_keypair();
            let base = build_agent_card("vesper-valley", &sess_pk, None, None, None);
            let with = with_op_claims_if_enrolled(base).unwrap();
            assert_eq!(crate::agent_card::card_org_memberships(&with).len(), 1);
        });
    }

    #[test]
    fn import_rejects_op_did_for_org_did_slot() {
        // Check 1: org_did must be did:wire:org:* — a did:wire:op:* should
        // be refused before any cert verification runs.
        crate::config::test_support::with_temp_home(|| {
            let local_op_did = enroll_local_op("darby");
            let (_org_did, org_pk, member_cert) = mint_valid_bundle(&local_op_did);
            let org_pubkey_b64 = crate::signing::b64encode(&org_pk);
            // Cram a did:wire:op:* into the org_did slot.
            let bad_org_did = local_op_did.clone();

            let err = import_member_cert(&bad_org_did, &org_pubkey_b64, &member_cert).unwrap_err();
            let msg = format!("{err:?}");
            assert!(msg.contains("did:wire:org"), "got: {msg}");
            assert_eq!(crate::config::read_memberships().unwrap().len(), 0);
        });
    }

    #[test]
    fn import_rejects_wrong_org_pubkey_for_org_did() {
        // Check 3: anti-spoof. A bundle whose org_pubkey doesn't commit to
        // the claimed org_did must fail at the commitment check before any
        // cert verification runs.
        crate::config::test_support::with_temp_home(|| {
            let local_op_did = enroll_local_op("darby");
            let (org_did, _org_pk, member_cert) = mint_valid_bundle(&local_op_did);
            // Generate a DIFFERENT keypair and try to claim it under the
            // original org_did. The DID still parses as did:wire:org:*
            // (check 1 passes) and the 32-byte length check passes (check
            // 2 passes) but commits_to fails (check 3).
            let (_other_sk, other_pk) = generate_keypair();
            let wrong_pubkey_b64 = crate::signing::b64encode(&other_pk);

            let err = import_member_cert(&org_did, &wrong_pubkey_b64, &member_cert).unwrap_err();
            let msg = format!("{err:?}");
            assert!(msg.contains("commit") || msg.contains("fingerprint"), "got: {msg}");
            assert_eq!(crate::config::read_memberships().unwrap().len(), 0);
        });
    }

    #[test]
    fn import_rejects_cert_for_different_op_did() {
        // Check 5: cert must sign THIS operator's op_did. A cert issued to
        // a DIFFERENT op_did must be rejected even though it verifies fine
        // against the supplied org_pubkey under its actual subject.
        crate::config::test_support::with_temp_home(|| {
            let _local_op_did = enroll_local_op("darby");

            // Mint an org keypair + cert binding org → SOMEONE ELSE'S op_did
            // (not the locally-enrolled darby).
            let (_other_op_sk, other_op_pk) = generate_keypair();
            let other_op_did = did_for_op("not-darby", &other_op_pk);
            let (org_sk, org_pk) = generate_keypair();
            let org_did = did_for_org("test-fleet", &org_pk);
            let cert_for_other = issue_member_cert(&org_sk, &other_op_did).unwrap();
            let org_pubkey_b64 = crate::signing::b64encode(&org_pk);

            // Import-time we look up the local op_did from on-disk state;
            // the cert was signed for other_op_did, so verification fails.
            let err =
                import_member_cert(&org_did, &org_pubkey_b64, &cert_for_other).unwrap_err();
            let msg = format!("{err:?}");
            assert!(
                msg.contains("verify") || msg.contains("member_cert"),
                "got: {msg}"
            );
            assert_eq!(crate::config::read_memberships().unwrap().len(), 0);
        });
    }

    #[test]
    fn import_rejects_malformed_org_pubkey_b64() {
        // Check 2: 32-byte length. Catches both bad-base64 and wrong-length
        // payloads via the decode + length check.
        crate::config::test_support::with_temp_home(|| {
            let local_op_did = enroll_local_op("darby");
            let (org_did, _org_pk, member_cert) = mint_valid_bundle(&local_op_did);

            // Garbage base64.
            let err = import_member_cert(&org_did, "not!valid!b64!@#", &member_cert).unwrap_err();
            let msg = format!("{err:?}");
            assert!(msg.contains("base64") || msg.contains("decode"), "got: {msg}");
            assert_eq!(crate::config::read_memberships().unwrap().len(), 0);

            // Valid base64, but wrong length (16 bytes instead of 32).
            let too_short = crate::signing::b64encode(&[0u8; 16]);
            let err = import_member_cert(&org_did, &too_short, &member_cert).unwrap_err();
            let msg = format!("{err:?}");
            assert!(msg.contains("32 bytes"), "got: {msg}");
            assert_eq!(crate::config::read_memberships().unwrap().len(), 0);
        });
    }

    #[test]
    fn import_bails_without_local_op_enrollment() {
        // Check 4: a local op_did must be enrolled before any cert can be
        // checked against it. No op.key → clean error, no file mutation.
        crate::config::test_support::with_temp_home(|| {
            // No enroll_local_op() call here.
            let (_throwaway_sk, throwaway_pk) = generate_keypair();
            let throwaway_did = did_for_op("nobody", &throwaway_pk);
            let (org_did, org_pk, member_cert) = mint_valid_bundle(&throwaway_did);
            let org_pubkey_b64 = crate::signing::b64encode(&org_pk);

            let err = import_member_cert(&org_did, &org_pubkey_b64, &member_cert).unwrap_err();
            let msg = format!("{err:?}");
            assert!(
                msg.contains("operator") || msg.contains("op") || msg.contains("enroll"),
                "got: {msg}"
            );
            assert_eq!(crate::config::read_memberships().unwrap().len(), 0);
        });
    }
}
