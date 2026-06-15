//! RFC-001 amendment (#182): same-owner same-machine signed attestation.
//!
//! Wire already auto-pins *sister sessions* by reading their card off local
//! disk (`pull::maybe_autopin_local_sister`) — a filesystem witness. Coral's
//! #182 review flagged that witness as too weak on its own: anything that can
//! write the data-dir tree could mint a sibling. This module is the
//! *cryptographic* hardening: an operator-signed claim, carried in the agent
//! card, that a receiver verifies against ITS OWN machine before auto-pinning
//! the sender at `ORG_VERIFIED`.
//!
//! ## The claim
//!
//! `same_machine_attestation = { machine_fingerprint, signature }` where the
//! signature is the operator root key (`op_sk`) over the domain-separated
//! canonical message
//!
//! ```text
//! wire-same-machine-v1|<fingerprint_hex>|<session_did>
//! ```
//!
//! Signing with `op_sk` (not the session key) is the point: it proves *the
//! operator who owns this session says all my sessions on machine X share this
//! fingerprint*, which is the trust-model claim the receiver acts on.
//!
//! ## Receiver safety (the two checks that make it sound)
//!
//! 1. **Fingerprint strict-equality** — the receiver recomputes its own
//!    `machine_fingerprint` from its local `(machine_id, os_user_id)` and
//!    refuses unless the attestation's fingerprint byte-equals it. A remote
//!    sender cannot know the receiver's fingerprint without already being on
//!    the receiver's machine.
//! 2. **Signature over the canonical bytes** — verified under the same inline
//!    `op_pubkey` the op-chain already validated. A card that publishes the
//!    receiver's fingerprint but signs a *different* one (the hostile-forge
//!    case, AC-SM3) fails here.
//!
//! ## Deviations from the amendment doc (deliberate, equivalent)
//!
//! - **sha256, not blake2b.** A one-way 32-byte commitment; sha2 is already a
//!   dependency, blake2 is not. Domain tag `wire-same-machine-v1` is unchanged.
//! - **canonical message is a domain-separated string** (mirroring
//!   `identity::succession_payload`) rather than raw byte concatenation, so it
//!   reuses the audited `sign_did_cert` / `verify_payload_sig` path and can
//!   never be replayed as an op/member/succession cert.

use crate::identity::{CertError, sign_did_cert, verify_payload_sig};
use crate::signing::{b64decode, b64encode};
use sha2::{Digest, Sha256};

/// Domain-separation tag. The `v1` lets a future fingerprint construction ship
/// as `v2` without renaming the card field. Protects against cross-protocol
/// collision on the shared `machine_id` identifier.
pub const FINGERPRINT_DOMAIN: &str = "wire-same-machine-v1";

/// Errors verifying a received same-machine attestation. Every variant is a
/// fall-through (the receiver drops the same-machine fast-path and proceeds
/// with standard pairing), never a hard failure of the pull.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// `machine_fingerprint` field is not valid base64 or not 32 bytes.
    BadFingerprint,
    /// The attestation's fingerprint does not match the receiver's own machine
    /// — i.e. the sender is not actually on this `(machine, OS user)`. The
    /// hostile-forge mitigation (§C step 5) and the legitimate different-uid
    /// case (AC-SM2) both land here.
    FingerprintMismatch,
    /// Signature did not verify under the inline `op_pubkey` over the canonical
    /// message (tampered field, wrong key, or signed-vs-published mismatch —
    /// AC-SM3).
    Signature(CertError),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::BadFingerprint => write!(f, "malformed machine_fingerprint"),
            VerifyError::FingerprintMismatch => {
                write!(f, "attestation fingerprint is not this machine")
            }
            VerifyError::Signature(e) => write!(f, "attestation signature: {e}"),
        }
    }
}

/// Compute the 32-byte machine fingerprint from raw platform inputs.
///
/// Pure: the caller supplies the raw `machine_id` bytes and the per-OS-user id
/// bytes (read by `platform::machine_id_raw` / `platform::os_user_id_bytes`).
/// The OS-user component is what stops two different users on one shared host
/// (same `/etc/machine-id`) from cross-pairing — different uid → different
/// fingerprint → receiver's strict-equality check fails.
pub fn machine_fingerprint(machine_id: &[u8], os_user_id: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(machine_id);
    h.update(os_user_id);
    h.update(FINGERPRINT_DOMAIN.as_bytes());
    let digest = h.finalize();
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&digest);
    fp
}

/// The canonical message the operator key signs / a receiver verifies.
/// Domain-separated; the fingerprint is lowercase hex so the message is a plain
/// printable string on the same `sign_did_cert` path as the other certs.
pub fn attestation_payload(fingerprint: &[u8; 32], session_did: &str) -> String {
    format!(
        "{FINGERPRINT_DOMAIN}|{}|{session_did}",
        hex::encode(fingerprint)
    )
}

/// Build the attestation: `op_sk` signs the canonical message over
/// `(fingerprint, session_did)`. Returns `(machine_fingerprint_b64,
/// signature_b64)` ready to drop into the card's `same_machine_attestation`.
pub fn build_attestation(
    op_sk: &[u8],
    fingerprint: &[u8; 32],
    session_did: &str,
) -> Result<(String, String), CertError> {
    let payload = attestation_payload(fingerprint, session_did);
    let sig = sign_did_cert(op_sk, &payload)?;
    Ok((b64encode(fingerprint), sig))
}

/// Verify a received attestation (amendment §C steps 4–6). **Fail-closed.**
///
/// - `op_pubkey` — the inline operator pubkey the op-chain already verified to
///   commit to the sender's `op_did` (and to have the same `op_did` as the
///   receiver; that same-operator check is the caller's, done before this).
/// - `attest_fingerprint_b64` / `attest_sig_b64` — the card's two fields.
/// - `sender_session_did` — the `did` of the card being evaluated.
/// - `local_fingerprint` — the receiver's OWN fingerprint, recomputed from its
///   local platform sources. The source of truth for "what is my machine".
///
/// Strict byte-equality on the fingerprint — no prefix / no "or-better".
pub fn verify_attestation(
    op_pubkey: &[u8],
    attest_fingerprint_b64: &str,
    attest_sig_b64: &str,
    sender_session_did: &str,
    local_fingerprint: &[u8; 32],
) -> Result<(), VerifyError> {
    let fp_bytes = b64decode(attest_fingerprint_b64).map_err(|_| VerifyError::BadFingerprint)?;
    if fp_bytes.len() != 32 {
        return Err(VerifyError::BadFingerprint);
    }
    // §C step 5: strict equality against the receiver's own machine. A remote
    // sender can't produce a fingerprint that matches without being here.
    if fp_bytes.as_slice() != local_fingerprint.as_slice() {
        return Err(VerifyError::FingerprintMismatch);
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&fp_bytes);
    // §C step 6: signature verifies under op_pubkey over the canonical message
    // reconstructed from the *published* fingerprint. AC-SM3 (published == ours
    // but signed over a different one) fails right here.
    let payload = attestation_payload(&fp, sender_session_did);
    verify_payload_sig(op_pubkey, attest_sig_b64, &payload).map_err(VerifyError::Signature)
}

/// Read this machine's local fingerprint from platform sources. `None` when
/// either source can't be read (the session still functions; it just can't
/// participate in the same-machine lane — fail-closed per §A).
pub fn local_fingerprint() -> Option<[u8; 32]> {
    let machine_id = crate::platform::machine_id_raw()?;
    let os_user_id = crate::platform::os_user_id_bytes()?;
    Some(machine_fingerprint(&machine_id, &os_user_id))
}

/// This session's own `op_did`, read from its on-disk agent card. `None` when
/// not enrolled / no card. Used to gate the same-machine lane on "same
/// operator as me" (§C step 2).
fn my_op_did() -> Option<String> {
    let card = crate::config::read_agent_card().ok()?;
    crate::agent_card::card_op_did(&card).map(str::to_string)
}

/// Receiver decision (amendment §C, all 7 steps): should a received `peer_card`
/// be auto-pinned at `ORG_VERIFIED` because it proves it is on THIS machine,
/// owned by the SAME operator? Returns `Some(peer_op_did)` when every check
/// passes, `None` to fall through to standard pairing. Fully offline.
///
/// Because a wire `op_did` is a hash commitment to the operator key, "peer's
/// op_did == my op_did" already forces "peer's inline op_pubkey == my op_pubkey"
/// — i.e. genuinely the same operator, not a look-alike. The fingerprint match
/// then forces "same (machine, OS user)", and the signature forces "this exact
/// session, not a replay".
pub fn auto_pin_decision(peer_card: &serde_json::Value) -> Option<String> {
    // §C step 1: the peer's op-chain (op_did ⟵ op_pubkey, op_cert over session)
    // must verify. A broken / absent claim → no same-machine consideration.
    let anchor = crate::org_membership::verify_op_anchor(peer_card)
        .ok()
        .flatten()?;
    // §C step 2: same operator — the peer's op_did must equal mine.
    if anchor.op_did != my_op_did()? {
        return None;
    }
    // §C step 3: the attestation field must be present + shaped.
    let att = peer_card.get("same_machine_attestation")?;
    let fp_b64 = att.get("machine_fingerprint").and_then(|v| v.as_str())?;
    let sig_b64 = att.get("signature").and_then(|v| v.as_str())?;
    let sender_did = peer_card.get("did").and_then(|v| v.as_str())?;
    // §C step 4: recompute MY local fingerprint.
    let local_fp = local_fingerprint()?;
    // §C steps 5–6: strict fingerprint equality + signature over the canonical
    // message under the (already op-chain-verified) op_pubkey.
    verify_attestation(&anchor.op_pubkey, fp_b64, sig_b64, sender_did, &local_fp).ok()?;
    // §C step 7: caller pins ORG_VERIFIED.
    Some(anchor.op_did)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;

    #[test]
    fn fingerprint_is_deterministic_and_user_salted() {
        let m = b"machine-uuid-aaaa";
        let fp_u1000 = machine_fingerprint(m, b"1000");
        // Same inputs → same fingerprint.
        assert_eq!(fp_u1000, machine_fingerprint(m, b"1000"));
        // Different OS user on the SAME machine → different fingerprint. This is
        // the multi-user-host isolation (Security §S1).
        assert_ne!(fp_u1000, machine_fingerprint(m, b"1001"));
        // Different machine, same user → different fingerprint.
        assert_ne!(fp_u1000, machine_fingerprint(b"machine-uuid-bbbb", b"1000"));
    }

    #[test]
    fn payload_is_domain_separated() {
        let fp = machine_fingerprint(b"m", b"1000");
        let p = attestation_payload(&fp, "did:wire:slate-lotus-88232017");
        assert!(p.starts_with("wire-same-machine-v1|"));
        assert!(p.ends_with("|did:wire:slate-lotus-88232017"));
        // The succession-cert / op-cert domains are distinct prefixes, so an
        // attestation can never be replayed as one of those certs.
        assert!(!p.starts_with("wire-succession-v1"));
    }

    /// AC-SM1 core: a genuine same-op + same-machine attestation verifies.
    #[test]
    fn roundtrip_same_machine_verifies() {
        let (op_sk, op_pk) = generate_keypair();
        let fp = machine_fingerprint(b"machine-X", b"1000");
        let did = "did:wire:slate-lotus-88232017";
        let (fp_b64, sig) = build_attestation(&op_sk, &fp, did).unwrap();
        // Receiver recomputes the SAME local fingerprint (same machine + uid).
        assert_eq!(verify_attestation(&op_pk, &fp_b64, &sig, did, &fp), Ok(()));
    }

    /// AC-SM2: same machine, same op, but the receiver's uid differs → the
    /// receiver's local fingerprint differs → strict-equality rejects.
    #[test]
    fn different_uid_rejected() {
        let (op_sk, op_pk) = generate_keypair();
        let sender_fp = machine_fingerprint(b"machine-X", b"1000");
        let did = "did:wire:slate-lotus-88232017";
        let (fp_b64, sig) = build_attestation(&op_sk, &sender_fp, did).unwrap();
        // Receiver is uid 1001 on the same box.
        let receiver_fp = machine_fingerprint(b"machine-X", b"1001");
        assert_eq!(
            verify_attestation(&op_pk, &fp_b64, &sig, did, &receiver_fp),
            Err(VerifyError::FingerprintMismatch)
        );
    }

    /// AC-SM3: hostile forge — the published `machine_fingerprint` equals the
    /// receiver's (so step 5 passes) but the signature was made over a
    /// *different* fingerprint. Signature verification (step 6) must reject.
    #[test]
    fn hostile_forge_signed_over_other_fingerprint_rejected() {
        let (op_sk, op_pk) = generate_keypair();
        let receiver_fp = machine_fingerprint(b"machine-victim", b"1000");
        let attacker_fp = machine_fingerprint(b"machine-attacker", b"1000");
        let did = "did:wire:evil-1234";
        // Sign over the attacker's real fingerprint...
        let sig = sign_did_cert(&op_sk, &attestation_payload(&attacker_fp, did)).unwrap();
        // ...but PUBLISH the victim's fingerprint to slip past step 5 (fp match).
        let published_fp_b64 = b64encode(&receiver_fp);
        // Step 5 passes (published == receiver), but step 6 reconstructs the
        // canonical message from the PUBLISHED fingerprint and the signature was
        // made over the attacker's — so it fails to verify. Either way: rejected.
        assert_eq!(
            verify_attestation(&op_pk, &published_fp_b64, &sig, did, &receiver_fp),
            Err(VerifyError::Signature(CertError::Rejected))
        );
    }

    /// AC-SM3 variant where the published fingerprint genuinely matches the
    /// receiver (step 5 passes) but the signature is over a different message.
    #[test]
    fn published_matches_but_signature_mismatched_rejected() {
        let (op_sk, op_pk) = generate_keypair();
        let receiver_fp = machine_fingerprint(b"machine-victim", b"1000");
        let did = "did:wire:evil-1234";
        // Signature is over a DIFFERENT session_did than the one presented.
        let sig = sign_did_cert(
            &op_sk,
            &attestation_payload(&receiver_fp, "did:wire:some-other-9999"),
        )
        .unwrap();
        let published_fp_b64 = b64encode(&receiver_fp);
        assert_eq!(
            verify_attestation(&op_pk, &published_fp_b64, &sig, did, &receiver_fp),
            Err(VerifyError::Signature(CertError::Rejected))
        );
    }

    #[test]
    fn wrong_op_key_rejected() {
        let (op_sk, _op_pk) = generate_keypair();
        let (_other_sk, other_pk) = generate_keypair();
        let fp = machine_fingerprint(b"machine-X", b"1000");
        let did = "did:wire:slate-lotus-1";
        let (fp_b64, sig) = build_attestation(&op_sk, &fp, did).unwrap();
        // Verifying under a different op pubkey fails.
        assert_eq!(
            verify_attestation(&other_pk, &fp_b64, &sig, did, &fp),
            Err(VerifyError::Signature(CertError::Rejected))
        );
    }

    #[test]
    fn malformed_fingerprint_rejected() {
        let (_sk, pk) = generate_keypair();
        let fp = machine_fingerprint(b"m", b"1000");
        assert_eq!(
            verify_attestation(&pk, "!!!not-base64", "sig", "did:wire:x", &fp),
            Err(VerifyError::BadFingerprint)
        );
        // Valid base64 but wrong length.
        assert_eq!(
            verify_attestation(&pk, &b64encode(b"too-short"), "sig", "did:wire:x", &fp),
            Err(VerifyError::BadFingerprint)
        );
    }

    /// Idempotency substrate for AC-SM4: the canonical message is deterministic,
    /// so re-signing the same fleet produces the byte-identical attestation.
    #[test]
    fn build_is_deterministic() {
        let (op_sk, _pk) = generate_keypair();
        let fp = machine_fingerprint(b"machine-X", b"1000");
        let did = "did:wire:slate-lotus-1";
        assert_eq!(
            build_attestation(&op_sk, &fp, did).unwrap(),
            build_attestation(&op_sk, &fp, did).unwrap()
        );
    }

    /// Build a peer card for the SAME operator (`op_sk`/`op_pk`), with an
    /// attestation over `attest_fp`. Returns the unsigned card Value.
    #[cfg(test)]
    fn peer_card_for(
        op_sk: &[u8; 32],
        op_pk: &[u8; 32],
        op_handle: &str,
        attest_fp: &[u8; 32],
    ) -> serde_json::Value {
        let (_peer_sk, peer_pk) = generate_keypair();
        let base = crate::agent_card::build_agent_card("sister", &peer_pk, None, None, None);
        let session_did = base
            .get("did")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let op_did = crate::agent_card::did_for_op(op_handle, op_pk);
        let op_cert = crate::identity::sign_did_cert(op_sk, &session_did).unwrap();
        let (fp_b64, sig) = build_attestation(op_sk, attest_fp, &session_did).unwrap();
        let claims = crate::agent_card::IdentityClaims {
            op_did: Some(op_did),
            op_cert: Some(op_cert),
            op_pubkey: Some(b64encode(op_pk)),
            org_memberships: vec![],
            project: None,
            same_machine_attestation: Some((fp_b64, sig)),
        };
        crate::agent_card::with_identity_claims(&base, &claims).unwrap()
    }

    /// Enroll a self-session under `op_sk` and write its card so `my_op_did()`
    /// resolves. Returns the operator did.
    #[cfg(test)]
    fn enroll_self(op_sk: &[u8; 32], op_handle: &str) {
        crate::config::write_op_key(op_sk).unwrap();
        crate::config::write_op_handle(op_handle).unwrap();
        let (my_sk, my_pk) = generate_keypair();
        let base = crate::agent_card::build_agent_card("me", &my_pk, None, None, None);
        let card = crate::enroll::with_op_claims_if_enrolled(base).unwrap();
        crate::config::write_agent_card(&crate::agent_card::sign_agent_card(&card, &my_sk))
            .unwrap();
    }

    /// AC-SM1 end-to-end through the real platform fingerprint: a same-op card
    /// attesting THIS machine's actual fingerprint is accepted.
    #[test]
    fn auto_pin_decision_accepts_same_op_same_machine() {
        crate::config::test_support::with_temp_home(|| {
            let Some(local_fp) = local_fingerprint() else {
                return; // platform can't read machine-id/uid → lane unavailable; skip.
            };
            let (op_sk, op_pk) = generate_keypair();
            enroll_self(&op_sk, "darby");
            let op_did = crate::agent_card::did_for_op("darby", &op_pk);
            let peer = peer_card_for(&op_sk, &op_pk, "darby", &local_fp);
            assert_eq!(auto_pin_decision(&peer), Some(op_did));
        });
    }

    /// A card from a DIFFERENT operator (different op key) is not same-machine
    /// eligible even if it attests this machine's fingerprint.
    #[test]
    fn auto_pin_decision_rejects_different_operator() {
        crate::config::test_support::with_temp_home(|| {
            let Some(local_fp) = local_fingerprint() else {
                return;
            };
            let (my_op_sk, _my_op_pk) = generate_keypair();
            enroll_self(&my_op_sk, "darby");
            // Peer is a different operator.
            let (other_sk, other_pk) = generate_keypair();
            let peer = peer_card_for(&other_sk, &other_pk, "mallory", &local_fp);
            assert_eq!(auto_pin_decision(&peer), None);
        });
    }

    /// A same-op card attesting a DIFFERENT machine's fingerprint is rejected
    /// (the fingerprint won't match this receiver's local one).
    #[test]
    fn auto_pin_decision_rejects_other_machine_fingerprint() {
        crate::config::test_support::with_temp_home(|| {
            if local_fingerprint().is_none() {
                return;
            }
            let (op_sk, op_pk) = generate_keypair();
            enroll_self(&op_sk, "darby");
            let other_machine_fp = machine_fingerprint(b"some-other-box", b"31337");
            let peer = peer_card_for(&op_sk, &op_pk, "darby", &other_machine_fp);
            assert_eq!(auto_pin_decision(&peer), None);
        });
    }
}
