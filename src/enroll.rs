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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_card::{
        build_agent_card, did_for_org, sign_agent_card, verify_agent_card, with_identity_claims,
    };
    use crate::org_membership::{MembershipOutcome, evaluate_card_membership};
    use crate::signing::generate_keypair;

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
