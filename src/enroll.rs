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
}
