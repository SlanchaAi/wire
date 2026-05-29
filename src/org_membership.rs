//! RFC-001 Phase 1 — evaluate a received agent-card's organizational
//! membership claims and decide which orgs vouch for the peer.
//!
//! Bridges Phase 0's cert verifiers (`identity.rs`, #90) toward the live
//! pairing path. **The whole membership chain verifies offline** — no network,
//! no relay endpoint, no did:web on the hot path — because every DID is a hash
//! commitment to its key (surfaced by a security/systems-design persona
//! critique, 2026-05-29):
//!
//! - `op_did`  = `did:wire:op:<handle>-<32hex sha256(op_pubkey)>`
//! - `org_did` = `did:wire:org:<handle>-<32hex sha256(org_pubkey)>`
//!
//! The card carries `op_pubkey` and each membership's `org_pubkey` inline; we
//! verify each by recomputing its commitment, then check the cert it anchors.
//! A peer therefore cannot substitute a key for any DID it claims.
//!
//! What this module does NOT do: decide *which* orgs to trust. It returns the
//! set of `org_did`s that cryptographically vouch for the operator; the caller
//! (Phase 3 policy) matches those against the receiver's own trusted-org set.
//! Resolving a domain → `org_did` (DNS-TXT / did:web) is a *policy-setup-time*
//! convenience (`wire org policy set <domain>`), not a per-pairing dependency —
//! it belongs to a later phase, not here.
//!
//! Invariant (RFC-001 §5): the *most* a verified membership earns is
//! `ORG_VERIFIED`. Crossing into `VERIFIED` still requires bilateral
//! SPAKE2+SAS — untouched here.

use crate::agent_card::{self, AgentCard};
use crate::identity::{verify_member_cert, verify_op_cert};
use crate::signing::b64decode;

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

/// Decode a base64 32-byte Ed25519 key, or `None` if absent/malformed.
fn key32(v: Option<&serde_json::Value>) -> Option<[u8; 32]> {
    let bytes = v.and_then(|v| v.as_str()).and_then(|s| b64decode(s).ok())?;
    if bytes.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Some(k)
}

/// True iff `did` ends with the long-fingerprint commitment of `pubkey` —
/// i.e. `did` is the DID derived from `pubkey`. This is what makes an inline
/// key self-certifying against a `did:wire:op:`/`did:wire:org:` identifier.
fn commits_to(did: &str, pubkey: &[u8; 32]) -> bool {
    did.ends_with(&format!("-{}", agent_card::long_fingerprint(pubkey)))
}

/// Verify a received card's organizational claims. Fully offline.
///
/// For [`MembershipOutcome::Verified`] all must hold:
///  1. well-formed `op_did` + inline `op_pubkey` that commits to it, + `op_cert`;
///  2. `op_cert` verifies — `op_pubkey` signed this card's `did` (session DID).
///     Closes "claim someone else's `op_did`": no operator identity without
///     the operator's signature over the session;
///  3. ≥1 `org_memberships[]` entry with a well-formed `org_did`, an inline
///     `org_pubkey` that commits to it, and a `member_cert` the org key signed
///     over `op_did`.
///
/// Any membership entry that fails a check is skipped (others may vouch); none
/// verifying → `Rejected`. A bad `op_pubkey` commitment / `op_cert` is fatal.
pub fn evaluate_card_membership(card: &AgentCard) -> MembershipOutcome {
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
    let op_pubkey = match key32(card.get("op_pubkey")) {
        Some(k) => k,
        None => {
            return MembershipOutcome::Rejected {
                reason: "`op_pubkey` missing or not a 32-byte base64 key".into(),
            };
        }
    };
    if !commits_to(op_did, &op_pubkey) {
        return MembershipOutcome::Rejected {
            reason: "`op_pubkey` does not match the `op_did` hash commitment".into(),
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
    if verify_op_cert(&op_pubkey, op_cert, session_did).is_err() {
        return MembershipOutcome::Rejected {
            reason: "`op_cert` does not bind this session to the operator".into(),
        };
    }

    // At least one org must vouch for the operator — each entry self-certifying.
    let mut verified_orgs = Vec::new();
    if let Some(entries) = card.get("org_memberships").and_then(|v| v.as_array()) {
        for m in entries {
            let Some(org_did) = m.get("org_did").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(member_cert) = m.get("member_cert").and_then(|v| v.as_str()) else {
                continue;
            };
            if !agent_card::is_org_did(org_did) {
                continue;
            }
            let Some(org_pubkey) = key32(m.get("org_pubkey")) else {
                continue; // no inline org key → can't verify the vouch → skip (fail closed)
            };
            if !commits_to(org_did, &org_pubkey) {
                continue; // inline org key doesn't match the claimed org_did
            }
            if verify_member_cert(&org_pubkey, member_cert, op_did).is_ok() {
                verified_orgs.push(org_did.to_string());
            }
        }
    }

    if verified_orgs.is_empty() {
        return MembershipOutcome::Rejected {
            reason: "no `org_memberships[]` entry verified (commitment + member_cert)".into(),
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
    use crate::signing::b64encode;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = [seed; 32];
        let pk = SigningKey::from_bytes(&sk).verifying_key().to_bytes();
        (sk, pk)
    }

    fn card(
        session_did: &str,
        op_did: Option<&str>,
        op_pubkey: Option<&[u8; 32]>,
        op_cert: Option<&str>,
        orgs: &[(&str, Option<&[u8; 32]>, &str)],
    ) -> AgentCard {
        let mut c = json!({ "schema_version": "v3.2", "did": session_did, "handle": "peer" });
        if let Some(o) = op_did {
            c["op_did"] = json!(o);
        }
        if let Some(pk) = op_pubkey {
            c["op_pubkey"] = json!(b64encode(pk));
        }
        if let Some(oc) = op_cert {
            c["op_cert"] = json!(oc);
        }
        if !orgs.is_empty() {
            c["org_memberships"] = json!(
                orgs.iter()
                    .map(|(od, opk, cert)| {
                        let mut e = json!({"org_did": od, "member_cert": cert});
                        if let Some(pk) = opk {
                            e["org_pubkey"] = json!(b64encode(*pk));
                        }
                        e
                    })
                    .collect::<Vec<_>>()
            );
        }
        c
    }

    #[test]
    fn verified_when_offline_chain_checks_out() {
        let (op_sk, op_pk) = keypair(1);
        let (org_sk, org_pk) = keypair(2);
        let op_did = did_for_op("darby", &op_pk);
        let org_did = did_for_org("slanchaai", &org_pk);
        let session_did = "did:wire:swift-harbor-4092b577";
        let op_cert = sign_did_cert(&op_sk, session_did).unwrap();
        let member_cert = sign_did_cert(&org_sk, &op_did).unwrap();
        let c = card(
            session_did,
            Some(&op_did),
            Some(&op_pk),
            Some(&op_cert),
            &[(&org_did, Some(&org_pk), &member_cert)],
        );
        assert_eq!(
            evaluate_card_membership(&c),
            MembershipOutcome::Verified {
                op_did,
                org_dids: vec![org_did_for(&org_pk)]
            }
        );
    }

    fn org_did_for(pk: &[u8; 32]) -> String {
        did_for_org("slanchaai", pk)
    }

    #[test]
    fn no_claim_when_no_op_did() {
        assert_eq!(
            evaluate_card_membership(&card("did:wire:plain-deadbeef", None, None, None, &[])),
            MembershipOutcome::NoClaim
        );
    }

    #[test]
    fn rejected_when_op_pubkey_breaks_commitment() {
        let (_, real_op_pk) = keypair(1);
        let (_, wrong_pk) = keypair(7);
        let op_did = did_for_op("darby", &real_op_pk);
        let c = card(
            "did:wire:x-1",
            Some(&op_did),
            Some(&wrong_pk),
            Some("AA=="),
            &[],
        );
        assert!(matches!(
            evaluate_card_membership(&c),
            MembershipOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn rejected_when_org_pubkey_breaks_commitment() {
        let (op_sk, op_pk) = keypair(1);
        let (org_sk, real_org_pk) = keypair(2);
        let (_, wrong_org_pk) = keypair(8);
        let op_did = did_for_op("darby", &op_pk);
        let org_did = did_for_org("slanchaai", &real_org_pk); // commits to real org key
        let session_did = "did:wire:x-1";
        let op_cert = sign_did_cert(&op_sk, session_did).unwrap();
        let member_cert = sign_did_cert(&org_sk, &op_did).unwrap();
        // present the WRONG org pubkey inline → org commitment fails → skipped → none verify
        let c = card(
            session_did,
            Some(&op_did),
            Some(&op_pk),
            Some(&op_cert),
            &[(&org_did, Some(&wrong_org_pk), &member_cert)],
        );
        assert!(matches!(
            evaluate_card_membership(&c),
            MembershipOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn rejected_when_op_cert_forged() {
        let (_, op_pk) = keypair(1);
        let (attacker_sk, _) = keypair(9);
        let (org_sk, org_pk) = keypair(2);
        let op_did = did_for_op("darby", &op_pk);
        let org_did = did_for_org("slanchaai", &org_pk);
        let session_did = "did:wire:x-1";
        let forged = sign_did_cert(&attacker_sk, session_did).unwrap();
        let member_cert = sign_did_cert(&org_sk, &op_did).unwrap();
        let c = card(
            session_did,
            Some(&op_did),
            Some(&op_pk),
            Some(&forged),
            &[(&org_did, Some(&org_pk), &member_cert)],
        );
        assert!(matches!(
            evaluate_card_membership(&c),
            MembershipOutcome::Rejected { .. }
        ));
    }

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
        let c = card(
            session_did,
            Some(&op_did),
            Some(&op_pk),
            Some(&op_cert),
            &[(&org_did, Some(&org_pk), &forged_member)],
        );
        assert!(matches!(
            evaluate_card_membership(&c),
            MembershipOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn rejected_when_org_pubkey_absent() {
        let (op_sk, op_pk) = keypair(1);
        let (org_sk, org_pk) = keypair(2);
        let op_did = did_for_op("darby", &op_pk);
        let org_did = did_for_org("slanchaai", &org_pk);
        let session_did = "did:wire:x-1";
        let op_cert = sign_did_cert(&op_sk, session_did).unwrap();
        let member_cert = sign_did_cert(&org_sk, &op_did).unwrap();
        let c = card(
            session_did,
            Some(&op_did),
            Some(&op_pk),
            Some(&op_cert),
            &[(&org_did, None, &member_cert)], // no inline org_pubkey
        );
        assert!(matches!(
            evaluate_card_membership(&c),
            MembershipOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn rejected_when_op_did_without_op_cert() {
        let (_, op_pk) = keypair(1);
        let op_did = did_for_op("darby", &op_pk);
        let c = card("did:wire:x-1", Some(&op_did), Some(&op_pk), None, &[]);
        assert!(matches!(
            evaluate_card_membership(&c),
            MembershipOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn rejected_when_op_did_slot_is_a_session_did() {
        let c = card(
            "did:wire:x-1",
            Some("did:wire:not-an-op-did"),
            None,
            Some("AA=="),
            &[],
        );
        assert!(matches!(
            evaluate_card_membership(&c),
            MembershipOutcome::Rejected { .. }
        ));
    }
}
