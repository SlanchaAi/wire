//! End-to-end proof of the RFC-001 identity layer (the v0.14 ship-gate "the
//! chain works" artifact): an operator enrolled in an org produces a signed
//! v3.2 agent-card that a receiver verifies **fully offline** and, under a
//! per-org auto-pair policy, reaches `ORG_VERIFIED` — while forged, cross-org,
//! and untrusted claims fall through to `Manual` and NEVER reach `VERIFIED`.
//!
//! Exercises the whole chain across modules: keygen, DID derivation, op_cert
//! and member_cert signing, the v3.2 card build (inline op_pubkey/org_pubkey),
//! the card self-signature, evaluate_card_membership, decide, and the tier.

use std::collections::HashMap;
use wire::agent_card::{
    IdentityClaims, OrgMembership, build_agent_card, did_for_op, did_for_org, sign_agent_card,
    verify_agent_card, with_identity_claims,
};
use wire::identity::sign_did_cert;
use wire::org_membership::{MembershipOutcome, evaluate_card_membership};
use wire::pair_decision::{InboundMode, OrgPolicy, PairAction, decide};
use wire::signing::{b64encode, generate_keypair};
use wire::trust::tier_order;

struct OrgSet(HashMap<String, InboundMode>);
impl OrgPolicy for OrgSet {
    fn inbound_mode(&self, org_did: &str) -> Option<InboundMode> {
        self.0.get(org_did).copied()
    }
}
fn policy(entries: &[(&str, InboundMode)]) -> OrgSet {
    OrgSet(entries.iter().map(|(k, v)| (k.to_string(), *v)).collect())
}

/// One operator + one org's keypairs and DIDs.
struct Fixture {
    op_sk: [u8; 32],
    op_pk: [u8; 32],
    org_sk: [u8; 32],
    org_pk: [u8; 32],
    op_did: String,
    org_did: String,
}
fn fixture() -> Fixture {
    let (op_sk, op_pk) = generate_keypair();
    let (org_sk, org_pk) = generate_keypair();
    let op_did = did_for_op("darby", &op_pk);
    let org_did = did_for_org("slanchaai", &org_pk);
    Fixture {
        op_sk,
        op_pk,
        org_sk,
        org_pk,
        op_did,
        org_did,
    }
}

/// Build + sign a v3.2 session card. `member_signer` signs the member_cert
/// (use the real org key for a valid vouch, a wrong key to forge it).
/// `inline_org_pk` is the org pubkey written into the card (use the real org
/// key for a valid commitment, a wrong key to break it).
fn signed_card(
    f: &Fixture,
    member_signer_sk: &[u8; 32],
    inline_org_pk: &[u8; 32],
    org_did_claimed: &str,
) -> serde_json::Value {
    let (sess_sk, sess_pk) = generate_keypair();
    let base = build_agent_card("vesper-valley", &sess_pk, None, None, None);
    let session_did = base
        .get("did")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let op_cert = sign_did_cert(&f.op_sk, &session_did).unwrap();
    let member_cert = sign_did_cert(member_signer_sk, &f.op_did).unwrap();
    let claims = IdentityClaims {
        op_did: Some(f.op_did.clone()),
        op_cert: Some(op_cert),
        op_pubkey: Some(b64encode(&f.op_pk)),
        org_memberships: vec![OrgMembership {
            org_did: org_did_claimed.to_string(),
            org_pubkey: b64encode(inline_org_pk),
            member_cert,
        }],
        project: Some("print-shop".into()),
        same_machine_attestation: None,
    };
    let unsigned = with_identity_claims(&base, &claims).unwrap();
    sign_agent_card(&unsigned, &sess_sk)
}

#[test]
fn happy_path_reaches_org_verified_offline() {
    let f = fixture();
    let card = signed_card(&f, &f.org_sk, &f.org_pk, &f.org_did);

    // Card self-signature holds (the inline op_pubkey/org_pubkey are covered).
    verify_agent_card(&card).expect("v3.2 card self-sig verifies");

    // Offline membership verification — no resolver, no network.
    let outcome = evaluate_card_membership(&card);
    assert_eq!(
        outcome,
        MembershipOutcome::Verified {
            op_did: f.op_did.clone(),
            org_dids: vec![f.org_did.clone()],
        }
    );

    // Receiver's policy auto-pairs its own org → ORG_VERIFIED, no tap.
    let pol = policy(&[(f.org_did.as_str(), InboundMode::Auto)]);
    assert_eq!(
        decide(&outcome, &pol),
        PairAction::AutoOrgVerified {
            org_did: f.org_did.clone()
        }
    );
}

#[test]
fn notify_when_org_is_option_b() {
    let f = fixture();
    let card = signed_card(&f, &f.org_sk, &f.org_pk, &f.org_did);
    let outcome = evaluate_card_membership(&card);
    let pol = policy(&[(f.org_did.as_str(), InboundMode::Notify)]);
    assert_eq!(
        decide(&outcome, &pol),
        PairAction::NotifyOrgEligible {
            org_did: f.org_did.clone()
        }
    );
}

#[test]
fn forged_member_cert_is_rejected() {
    let f = fixture();
    let (attacker_sk, _) = generate_keypair();
    // member_cert signed by an attacker, not the org → no valid vouch.
    let card = signed_card(&f, &attacker_sk, &f.org_pk, &f.org_did);
    assert!(matches!(
        evaluate_card_membership(&card),
        MembershipOutcome::Rejected { .. }
    ));
    let pol = policy(&[(f.org_did.as_str(), InboundMode::Auto)]);
    assert_eq!(
        decide(&evaluate_card_membership(&card), &pol),
        PairAction::Manual
    );
}

#[test]
fn broken_org_pubkey_commitment_is_rejected() {
    let f = fixture();
    let (_, wrong_org_pk) = generate_keypair();
    // Inline org_pubkey doesn't hash to the claimed org_did → commitment fails.
    let card = signed_card(&f, &f.org_sk, &wrong_org_pk, &f.org_did);
    assert!(matches!(
        evaluate_card_membership(&card),
        MembershipOutcome::Rejected { .. }
    ));
}

#[test]
fn untrusted_org_falls_through_to_manual() {
    let f = fixture();
    let card = signed_card(&f, &f.org_sk, &f.org_pk, &f.org_did);
    let outcome = evaluate_card_membership(&card);
    // Verified membership, but the receiver doesn't trust this org.
    assert!(matches!(outcome, MembershipOutcome::Verified { .. }));
    let pol = policy(&[("did:wire:org:someone-else-1", InboundMode::Auto)]);
    assert_eq!(decide(&outcome, &pol), PairAction::Manual);
}

#[test]
fn org_verified_is_strictly_below_verified() {
    // The load-bearing ceiling: nothing in this layer can reach VERIFIED;
    // ORG_VERIFIED ranks strictly below it, so a `>= VERIFIED` policy check
    // never passes for an org-verified peer.
    let order = tier_order();
    assert!(order["ORG_VERIFIED"] < order["VERIFIED"]);
    assert!(order["UNTRUSTED"] < order["ORG_VERIFIED"]);
}
