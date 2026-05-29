//! RFC-001 Phase 1 — evaluate a received agent-card's organizational
//! membership claims and decide whether the peer qualifies for
//! `Tier::OrgVerified`.
//!
//! This is the bridge between Phase 0's cert verifiers (`identity.rs`, #90)
//! and the live pairing path. Pubkey resolution (`op_did` / `org_did` → the
//! 32-byte Ed25519 key) is abstracted behind [`PubkeyResolver`], implemented
//! by Phase 2 (did:web well-known + DNS-TXT, registry-free). Keeping the
//! verification logic resolver-agnostic lets it be unit-tested with a mock
//! and lets Phase 2 evolve the resolution model independently.
//!
//! Invariant (RFC-001 §5): the *most* this grants is `ORG_VERIFIED`.
//! Crossing into `VERIFIED` still requires bilateral SPAKE2+SAS — that path
//! is untouched here. This module only ever returns membership facts; the
//! caller maps a verified membership + a per-org policy opt-in (Phase 3) to
//! an `ORG_VERIFIED` pin, and never higher.

use crate::agent_card::{self, AgentCard};
use crate::identity::{verify_member_cert, verify_op_cert};

/// Resolves an `op_did` / `org_did` to its 32-byte Ed25519 public key.
///
/// Implemented by Phase 2 (did:web `/.well-known/did.json` + DNS-TXT). The
/// trait boundary is deliberate: membership verification is pure over the
/// resolver, so it is testable without network and the resolution model can
/// change without touching the trust logic.
pub trait PubkeyResolver {
    fn resolve_op_pubkey(&self, op_did: &str) -> Result<[u8; 32], ResolveError>;
    fn resolve_org_pubkey(&self, org_did: &str) -> Result<[u8; 32], ResolveError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The DID is not published anywhere the resolver can reach it.
    NotFound,
    /// Transient: network/DNS unreachable. Fail closed (no promotion), retry later.
    Unreachable,
    /// The published document was malformed / the key was unparseable.
    Malformed,
}

/// Outcome of evaluating a card's organizational claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipOutcome {
    /// No `op_did` on the card — an ordinary peer; no org easing applies.
    NoClaim,
    /// Operator binding AND ≥1 org vouch verified end-to-end. Carries the
    /// `op_did` and the `org_did`s that checked out (for the Phase 3 filter
    /// surface + policy match).
    Verified {
        op_did: String,
        org_dids: Vec<String>,
    },
    /// A claim was present but failed verification. The caller MUST NOT
    /// promote — treat the peer as if it had no claim (fail closed) and may
    /// surface `reason` for diagnostics.
    Rejected { reason: String },
}

/// Verify a received card's organizational claims. Pure over `resolver`.
///
/// All of the following must hold for [`MembershipOutcome::Verified`]:
///  1. the card carries a well-formed `op_did` (`did:wire:op:…`) and an `op_cert`;
///  2. **`op_cert` verifies** — the operator's key (resolved from `op_did`)
///     signed this card's `did` (the session DID). This closes the
///     "claim someone else's `op_did`" forgery: a session cannot ride an
///     operator's identity without that operator's signature over the session;
///  3. **≥1 `org_memberships[]` entry's `member_cert` verifies** — the org's
///     key (resolved from `org_did`) signed the `op_did`, i.e. the org vouches
///     for the operator.
///
/// An org whose key cannot be resolved, or whose `member_cert` fails, is
/// skipped (not fatal — other orgs may still vouch); if *none* verify the
/// result is `Rejected`. An unresolvable/forged `op_cert` is fatal (the
/// session↔operator binding is the load-bearing step).
pub fn evaluate_card_membership(
    card: &AgentCard,
    resolver: &dyn PubkeyResolver,
) -> MembershipOutcome {
    let op_did = match agent_card::card_op_did(card) {
        Some(d) => d,
        None => return MembershipOutcome::NoClaim,
    };

    let session_did = card.get("did").and_then(|v| v.as_str()).unwrap_or_default();
    if session_did.is_empty() {
        return MembershipOutcome::Rejected {
            reason: "card has no `did` to bind the operator cert to".into(),
        };
    }
    if !agent_card::is_op_did(op_did) {
        return MembershipOutcome::Rejected {
            reason: format!("`op_did` slot holds a non-operator DID: {op_did}"),
        };
    }
    let op_cert = match agent_card::card_op_cert(card) {
        Some(c) => c,
        None => {
            return MembershipOutcome::Rejected {
                reason: "`op_did` present without an `op_cert` — operator binding unprovable"
                    .into(),
            };
        }
    };

    // Step 2 — operator authorized THIS session.
    let op_pubkey = match resolver.resolve_op_pubkey(op_did) {
        Ok(pk) => pk,
        Err(e) => {
            return MembershipOutcome::Rejected {
                reason: format!("operator pubkey unresolved for {op_did}: {e:?}"),
            };
        }
    };
    if verify_op_cert(&op_pubkey, op_cert, session_did).is_err() {
        return MembershipOutcome::Rejected {
            reason: "`op_cert` does not bind this session to the operator".into(),
        };
    }

    // Step 3 — at least one org vouches for the operator.
    let mut verified_orgs = Vec::new();
    for (org_did, member_cert) in agent_card::card_org_memberships(card) {
        if !agent_card::is_org_did(org_did) {
            continue; // malformed org slot — ignore, don't fail the whole card
        }
        let org_pubkey = match resolver.resolve_org_pubkey(org_did) {
            Ok(pk) => pk,
            Err(_) => continue, // org key unresolvable → can't vouch → skip (fail closed)
        };
        if verify_member_cert(&org_pubkey, member_cert, op_did).is_ok() {
            verified_orgs.push(org_did.to_string());
        }
    }

    if verified_orgs.is_empty() {
        return MembershipOutcome::Rejected {
            reason: "no `org_memberships[]` cert verified against a resolvable org key".into(),
        };
    }

    MembershipOutcome::Verified {
        op_did: op_did.to_string(),
        org_dids: verified_orgs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_card::{did_for_op, did_for_org};
    use crate::identity::sign_did_cert;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use std::collections::HashMap;

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = [seed; 32];
        let pk = SigningKey::from_bytes(&sk).verifying_key().to_bytes();
        (sk, pk)
    }

    #[derive(Default)]
    struct MockResolver {
        op: HashMap<String, [u8; 32]>,
        org: HashMap<String, [u8; 32]>,
    }
    impl PubkeyResolver for MockResolver {
        fn resolve_op_pubkey(&self, op_did: &str) -> Result<[u8; 32], ResolveError> {
            self.op.get(op_did).copied().ok_or(ResolveError::NotFound)
        }
        fn resolve_org_pubkey(&self, org_did: &str) -> Result<[u8; 32], ResolveError> {
            self.org.get(org_did).copied().ok_or(ResolveError::NotFound)
        }
    }

    /// Build a v3.2 card with the given claims (unsigned at the wire-card
    /// level here — the self-signature is verified separately in agent_card;
    /// this module is about the op/org cert chain).
    fn card(
        session_did: &str,
        op_did: Option<&str>,
        op_cert: Option<&str>,
        orgs: &[(&str, &str)],
    ) -> AgentCard {
        let mut c = json!({ "schema_version": "v3.2", "did": session_did, "handle": "peer" });
        if let Some(o) = op_did {
            c["op_did"] = json!(o);
        }
        if let Some(oc) = op_cert {
            c["op_cert"] = json!(oc);
        }
        if !orgs.is_empty() {
            c["org_memberships"] = json!(
                orgs.iter()
                    .map(|(o, cert)| json!({"org_did": o, "member_cert": cert}))
                    .collect::<Vec<_>>()
            );
        }
        c
    }

    // Happy path: op_cert binds session, member_cert vouches → Verified.
    #[test]
    fn verified_when_op_cert_and_member_cert_check_out() {
        let (op_sk, op_pk) = keypair(1);
        let (org_sk, org_pk) = keypair(2);
        let op_did = did_for_op("darby", &op_pk);
        let org_did = did_for_org("slanchaai", &org_pk);
        let session_did = "did:wire:swift-harbor-4092b577";
        let op_cert = sign_did_cert(&op_sk, session_did).unwrap();
        let member_cert = sign_did_cert(&org_sk, &op_did).unwrap();

        let mut r = MockResolver::default();
        r.op.insert(op_did.clone(), op_pk);
        r.org.insert(org_did.clone(), org_pk);

        let c = card(
            session_did,
            Some(&op_did),
            Some(&op_cert),
            &[(&org_did, &member_cert)],
        );
        assert_eq!(
            evaluate_card_membership(&c, &r),
            MembershipOutcome::Verified {
                op_did,
                org_dids: vec![org_did_clone(&org_pk)]
            }
        );
    }

    fn org_did_clone(org_pk: &[u8; 32]) -> String {
        did_for_org("slanchaai", org_pk)
    }

    #[test]
    fn no_claim_when_no_op_did() {
        let r = MockResolver::default();
        let c = card("did:wire:plain-deadbeef", None, None, &[]);
        assert_eq!(evaluate_card_membership(&c, &r), MembershipOutcome::NoClaim);
    }

    #[test]
    fn rejected_when_op_did_without_op_cert() {
        let (_, op_pk) = keypair(1);
        let op_did = did_for_op("darby", &op_pk);
        let mut r = MockResolver::default();
        r.op.insert(op_did.clone(), op_pk);
        let c = card("did:wire:x-1", Some(&op_did), None, &[]);
        assert!(matches!(
            evaluate_card_membership(&c, &r),
            MembershipOutcome::Rejected { .. }
        ));
    }

    // Forged op_cert: signed by an attacker key, not the resolved operator key.
    #[test]
    fn rejected_when_op_cert_forged() {
        let (_, op_pk) = keypair(1);
        let (attacker_sk, _) = keypair(9);
        let (org_sk, org_pk) = keypair(2);
        let op_did = did_for_op("darby", &op_pk);
        let org_did = did_for_org("slanchaai", &org_pk);
        let session_did = "did:wire:x-1";
        let forged_op_cert = sign_did_cert(&attacker_sk, session_did).unwrap();
        let member_cert = sign_did_cert(&org_sk, &op_did).unwrap();
        let mut r = MockResolver::default();
        r.op.insert(op_did.clone(), op_pk);
        r.org.insert(org_did.clone(), org_pk);
        let c = card(
            session_did,
            Some(&op_did),
            Some(&forged_op_cert),
            &[(&org_did, &member_cert)],
        );
        assert!(matches!(
            evaluate_card_membership(&c, &r),
            MembershipOutcome::Rejected { .. }
        ));
    }

    // Forged member_cert: not signed by the resolved org key → no org vouches.
    #[test]
    fn rejected_when_member_cert_forged() {
        let (op_sk, op_pk) = keypair(1);
        let (_, org_pk) = keypair(2);
        let (attacker_sk, _) = keypair(9);
        let op_did = did_for_op("darby", &op_pk);
        let org_did = did_for_org("slanchaai", &org_pk);
        let session_did = "did:wire:x-1";
        let op_cert = sign_did_cert(&op_sk, session_did).unwrap();
        let forged_member = sign_did_cert(&attacker_sk, &op_did).unwrap();
        let mut r = MockResolver::default();
        r.op.insert(op_did.clone(), op_pk);
        r.org.insert(org_did.clone(), org_pk);
        let c = card(
            session_did,
            Some(&op_did),
            Some(&op_cert),
            &[(&org_did, &forged_member)],
        );
        assert!(matches!(
            evaluate_card_membership(&c, &r),
            MembershipOutcome::Rejected { .. }
        ));
    }

    // Unresolvable org key → fail closed (skip that org → none verified).
    #[test]
    fn rejected_when_org_key_unresolvable() {
        let (op_sk, op_pk) = keypair(1);
        let (org_sk, org_pk) = keypair(2);
        let op_did = did_for_op("darby", &op_pk);
        let org_did = did_for_org("slanchaai", &org_pk);
        let session_did = "did:wire:x-1";
        let op_cert = sign_did_cert(&op_sk, session_did).unwrap();
        let member_cert = sign_did_cert(&org_sk, &op_did).unwrap();
        let mut r = MockResolver::default();
        r.op.insert(op_did.clone(), op_pk); // op resolves, org does NOT
        let c = card(
            session_did,
            Some(&op_did),
            Some(&op_cert),
            &[(&org_did, &member_cert)],
        );
        assert!(matches!(
            evaluate_card_membership(&c, &r),
            MembershipOutcome::Rejected { .. }
        ));
    }

    // A session DID mistakenly placed in the op_did slot is rejected.
    #[test]
    fn rejected_when_op_did_slot_is_a_session_did() {
        let r = MockResolver::default();
        let c = card(
            "did:wire:x-1",
            Some("did:wire:not-an-op-did"),
            Some("AA=="),
            &[],
        );
        assert!(matches!(
            evaluate_card_membership(&c, &r),
            MembershipOutcome::Rejected { .. }
        ));
    }
}
