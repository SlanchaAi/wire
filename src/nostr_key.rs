//! RFC-007 D3.1 (curve spike → Option 1): the Nostr **transport** key binding.
//!
//! Wire identities are Ed25519; Nostr verifies secp256k1/schnorr (BIP-340) and
//! public relays reject anything else. The curve spike
//! (`docs/history/0007-spike-curve-derivation.md`) resolved the gap to **dual-key,
//! transport-only, cross-signed** — never derive one key from the other (the
//! cross-curve anti-pattern SLIP-0010 exists to prevent). So an agent keeps its
//! one Ed25519 identity and mints a SEPARATE secp256k1 key that is *only* a
//! transport endpoint, bound to the identity by a cross-signature.
//!
//! ## The binding (mutual)
//!
//! Carried as an additive `nostr_pubkey` card field (sibling of `dh_pubkey` /
//! `op_did`, RFC-006 reservation discipline). Both directions are proven over
//! the domain-separated message
//!
//! ```text
//! wire-nostr-binding-v1|<session_did>|<nostr_xonly_hex>
//! ```
//!
//! - **`ed_sig`** — the Ed25519 *identity* key signs the message: "this npub is
//!   my Nostr transport". This is the spike's specified direction.
//! - **`schnorr_sig`** — the secp256k1 transport key signs the same message:
//!   proof-of-possession. Without it, a card could claim *any* npub as its
//!   transport (the card signature alone would "vouch" for a key the agent
//!   doesn't hold) — letting an agent squat someone else's npub binding. The
//!   possession proof closes that.
//!
//! ## ONE-NAME invariant
//!
//! The secp key is a transport endpoint, **never** a persona/identity anchor.
//! `did:wire` stays the only name; `nostr_pubkey` is plumbing. No code path may
//! promote an npub to an identity. (`[[project_wire_one_name_invariant]]`.)

use rand::RngCore;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature};
use sha2::{Digest, Sha256};

use crate::identity::{CertError, sign_did_cert, verify_payload_sig};
use crate::signing::{b64decode, b64encode};

/// Domain-separation tag for the cross-signature. `v1` lets the binding
/// construction evolve without renaming the card field.
pub const NOSTR_BINDING_DOMAIN: &str = "wire-nostr-binding-v1";

/// Errors building / verifying a Nostr transport binding. Verify-side variants
/// are all fall-throughs: an invalid binding means "no usable Nostr transport",
/// never a hard failure of card processing.
#[derive(Debug, PartialEq, Eq)]
pub enum NostrKeyError {
    /// A secp256k1 secret/pubkey/signature was malformed.
    Secp,
    /// A field was not valid base64, or the wrong length.
    BadEncoding,
    /// The Ed25519 identity cross-signature did not verify.
    IdentitySig(CertError),
    /// The secp256k1 possession (schnorr) signature did not verify.
    PossessionSig,
}

impl std::fmt::Display for NostrKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NostrKeyError::Secp => write!(f, "malformed secp256k1 key/signature"),
            NostrKeyError::BadEncoding => write!(f, "malformed binding field encoding"),
            NostrKeyError::IdentitySig(e) => write!(f, "identity cross-signature: {e}"),
            NostrKeyError::PossessionSig => write!(f, "secp256k1 possession proof failed"),
        }
    }
}

/// The three card fields of a Nostr transport binding (all base64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrBinding {
    /// secp256k1 x-only public key (32 bytes) — the Nostr `npub` material.
    pub pubkey: String,
    /// Ed25519 signature by the identity key over the binding message.
    pub ed_sig: String,
    /// schnorr signature by the secp256k1 transport key over the binding message
    /// (proof-of-possession).
    pub schnorr_sig: String,
}

/// Generate a fresh secp256k1 transport keypair. Returns `(secret_32, xonly_32)`.
/// The secret is stored under `nostr.key`; the x-only pubkey is the npub.
pub fn generate_transport_key() -> ([u8; 32], [u8; 32]) {
    let secp = Secp256k1::new();
    // Use the project's rand (0.8) rather than secp256k1's bundled rand trait,
    // and rejection-sample into a valid secret scalar (a uniform 32-byte draw is
    // out of `[1, n-1]` only with negligible probability).
    let mut rng = rand::thread_rng();
    loop {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        if let Ok(sk) = SecretKey::from_byte_array(seed) {
            let kp = Keypair::from_secret_key(&secp, &sk);
            return (sk.secret_bytes(), kp.x_only_public_key().0.serialize());
        }
    }
}

/// The x-only public key for a stored secret.
pub fn xonly_from_secret(secret: &[u8; 32]) -> Result<[u8; 32], NostrKeyError> {
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_byte_array(&secp, *secret).map_err(|_| NostrKeyError::Secp)?;
    Ok(kp.x_only_public_key().0.serialize())
}

/// The domain-separated message both keys sign. The npub is lowercase hex so
/// the message is a plain printable string on the same `sign_did_cert` path the
/// other wire certs use.
pub fn binding_payload(session_did: &str, nostr_xonly: &[u8; 32]) -> String {
    format!(
        "{NOSTR_BINDING_DOMAIN}|{session_did}|{}",
        hex::encode(nostr_xonly)
    )
}

/// The 32-byte digest the secp/schnorr signature is computed over (BIP-340
/// signs a 32-byte message). sha256 of the canonical binding string.
fn binding_digest(session_did: &str, nostr_xonly: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(binding_payload(session_did, nostr_xonly).as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Build the mutual binding for `session_did`: the Ed25519 identity key vouches
/// for the secp transport key, and the secp key proves possession.
pub fn build_binding(
    session_ed_sk: &[u8],
    nostr_secp_sk: &[u8; 32],
    session_did: &str,
) -> Result<NostrBinding, NostrKeyError> {
    let secp = Secp256k1::new();
    let kp =
        Keypair::from_seckey_byte_array(&secp, *nostr_secp_sk).map_err(|_| NostrKeyError::Secp)?;
    let xonly = kp.x_only_public_key().0.serialize();

    // Identity direction: Ed25519 over the canonical string.
    let payload = binding_payload(session_did, &xonly);
    let ed_sig = sign_did_cert(session_ed_sk, &payload).map_err(NostrKeyError::IdentitySig)?;

    // Possession direction: schnorr (BIP-340) over the 32-byte digest.
    let digest = binding_digest(session_did, &xonly);
    let sig = schnorr_sign_digest(nostr_secp_sk, &digest)?;

    Ok(NostrBinding {
        pubkey: b64encode(&xonly),
        ed_sig,
        schnorr_sig: b64encode(&sig),
    })
}

/// Sign a 32-byte digest with a secp256k1 key (BIP-340 schnorr, no aux rand →
/// deterministic). Returns the 64-byte signature. The low-level secp primitive
/// behind the binding's possession proof AND the NIP-01 event signature (D3.2a),
/// so secp usage stays centralized in this module.
pub fn schnorr_sign_digest(
    secp_sk: &[u8; 32],
    digest: &[u8; 32],
) -> Result<[u8; 64], NostrKeyError> {
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_byte_array(&secp, *secp_sk).map_err(|_| NostrKeyError::Secp)?;
    Ok(*secp.sign_schnorr_no_aux_rand(digest, &kp).as_ref())
}

/// Verify a 64-byte schnorr signature over a 32-byte digest under an x-only
/// public key. `Err(PossessionSig)` on any failure (malformed key/sig or bad
/// signature) — fail-closed.
pub fn schnorr_verify_digest(
    xonly: &[u8; 32],
    digest: &[u8; 32],
    sig: &[u8; 64],
) -> Result<(), NostrKeyError> {
    let secp = Secp256k1::new();
    let pk = XOnlyPublicKey::from_byte_array(*xonly).map_err(|_| NostrKeyError::Secp)?;
    let sig = Signature::from_byte_array(*sig);
    secp.verify_schnorr(&sig, digest, &pk)
        .map_err(|_| NostrKeyError::PossessionSig)
}

/// Verify a card's Nostr binding (both directions). `session_ed_pubkey` is the
/// card's identity verify key. Returns the verified x-only npub on success.
/// **Fail-closed**: any malformed/failed check returns `Err`.
pub fn verify_binding(
    session_ed_pubkey: &[u8],
    pubkey_b64: &str,
    ed_sig_b64: &str,
    schnorr_sig_b64: &str,
    session_did: &str,
) -> Result<[u8; 32], NostrKeyError> {
    let xonly_bytes = b64decode(pubkey_b64).map_err(|_| NostrKeyError::BadEncoding)?;
    if xonly_bytes.len() != 32 {
        return Err(NostrKeyError::BadEncoding);
    }
    let mut xonly_arr = [0u8; 32];
    xonly_arr.copy_from_slice(&xonly_bytes);

    // Identity cross-signature (Ed25519 over the canonical string).
    let payload = binding_payload(session_did, &xonly_arr);
    verify_payload_sig(session_ed_pubkey, ed_sig_b64, &payload)
        .map_err(NostrKeyError::IdentitySig)?;

    // Possession proof (schnorr over the digest).
    let sig_bytes = b64decode(schnorr_sig_b64).map_err(|_| NostrKeyError::BadEncoding)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| NostrKeyError::BadEncoding)?;
    let digest = binding_digest(session_did, &xonly_arr);
    schnorr_verify_digest(&xonly_arr, &digest, &sig_arr)?;

    Ok(xonly_arr)
}

/// Read `nostr_pubkey` (the binding sub-object) from a card and verify it
/// against the card's identity key. `Ok(None)` = no Nostr transport claimed;
/// `Err` = a claim is present but broken. The session's identity verify key is
/// passed in (the caller already resolved it from the card's `verify_keys`).
pub fn card_nostr_binding(
    card: &serde_json::Value,
    session_ed_pubkey: &[u8],
) -> Result<Option<[u8; 32]>, NostrKeyError> {
    let Some(b) = card.get("nostr_pubkey") else {
        return Ok(None);
    };
    let session_did = card.get("did").and_then(|v| v.as_str()).unwrap_or_default();
    let pubkey = b.get("pubkey").and_then(|v| v.as_str());
    let ed_sig = b.get("ed_sig").and_then(|v| v.as_str());
    let schnorr_sig = b.get("schnorr_sig").and_then(|v| v.as_str());
    let (Some(pubkey), Some(ed_sig), Some(schnorr_sig)) = (pubkey, ed_sig, schnorr_sig) else {
        return Err(NostrKeyError::BadEncoding);
    };
    verify_binding(session_ed_pubkey, pubkey, ed_sig, schnorr_sig, session_did).map(Some)
}

/// Card-emit hook (RFC-007 D3.1): if a Nostr transport key is present
/// (`nostr.key`), attach a freshly cross-signed `nostr_pubkey` binding to the
/// (unsigned) `card`. No-op when not keyed, so card-build stays correct for the
/// common case. The returned card is UNSIGNED; the caller signs it. Fail-soft —
/// a build error degrades to "no binding" rather than breaking card-build
/// (init/up is critical-path).
pub fn with_nostr_binding_if_keyed(
    mut card: crate::agent_card::AgentCard,
) -> anyhow::Result<crate::agent_card::AgentCard> {
    let Ok(nostr_sk) = crate::config::read_nostr_key() else {
        return Ok(card); // no transport key → no binding
    };
    let Ok(session_sk) = crate::config::read_private_key() else {
        return Ok(card);
    };
    let session_did = card
        .get("did")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if session_did.is_empty() {
        return Ok(card);
    }
    match build_binding(&session_sk, &nostr_sk, &session_did) {
        Ok(b) => {
            if let Some(obj) = card.as_object_mut() {
                obj.insert(
                    "nostr_pubkey".into(),
                    serde_json::json!({
                        "pubkey": b.pubkey,
                        "ed_sig": b.ed_sig,
                        "schnorr_sig": b.schnorr_sig,
                    }),
                );
            }
            Ok(card)
        }
        Err(e) => {
            eprintln!("wire: nostr binding skipped (build failed: {e})");
            Ok(card)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;

    #[test]
    fn roundtrip_binding_verifies() {
        let (ed_sk, ed_pk) = generate_keypair();
        let (nostr_sk, nostr_xonly) = generate_transport_key();
        let did = "did:wire:slate-lotus-88232017";
        let b = build_binding(&ed_sk, &nostr_sk, did).unwrap();
        // The published pubkey is the transport key's x-only.
        assert_eq!(b64decode(&b.pubkey).unwrap(), nostr_xonly.to_vec());
        // Both directions verify, and the recovered npub matches.
        assert_eq!(
            verify_binding(&ed_pk, &b.pubkey, &b.ed_sig, &b.schnorr_sig, did),
            Ok(nostr_xonly)
        );
    }

    #[test]
    fn wrong_identity_key_rejected() {
        let (ed_sk, _ed_pk) = generate_keypair();
        let (_other_sk, other_pk) = generate_keypair();
        let (nostr_sk, _x) = generate_transport_key();
        let did = "did:wire:x-1";
        let b = build_binding(&ed_sk, &nostr_sk, did).unwrap();
        // Verifying under a DIFFERENT identity key fails the identity direction.
        assert!(matches!(
            verify_binding(&other_pk, &b.pubkey, &b.ed_sig, &b.schnorr_sig, did),
            Err(NostrKeyError::IdentitySig(_))
        ));
    }

    /// npub-squat: an attacker publishes a victim's npub but cannot produce the
    /// schnorr possession proof (doesn't hold the secp secret). Forge the
    /// identity sig over the victim's key — possession proof still fails.
    #[test]
    fn npub_squat_without_possession_rejected() {
        let (ed_sk, ed_pk) = generate_keypair();
        let (_victim_sk, victim_xonly) = generate_transport_key();
        let did = "did:wire:squatter-9";
        // Attacker legitimately signs (their OWN identity) over the victim's npub,
        // but has no schnorr sig for it — fake one from a key they DO hold.
        let payload = binding_payload(did, &victim_xonly);
        let ed_sig = sign_did_cert(&ed_sk, &payload).unwrap();
        let (attacker_sk, _ax) = generate_transport_key();
        let secp = Secp256k1::new();
        let kp = Keypair::from_seckey_byte_array(&secp, attacker_sk).unwrap();
        let digest = binding_digest(did, &victim_xonly);
        let bad_sig = secp.sign_schnorr_no_aux_rand(&digest, &kp);
        assert_eq!(
            verify_binding(
                &ed_pk,
                &b64encode(&victim_xonly),
                &ed_sig,
                &b64encode(bad_sig.as_ref()),
                did
            ),
            Err(NostrKeyError::PossessionSig)
        );
    }

    #[test]
    fn tampered_did_rejected() {
        let (ed_sk, ed_pk) = generate_keypair();
        let (nostr_sk, _x) = generate_transport_key();
        let b = build_binding(&ed_sk, &nostr_sk, "did:wire:real-1").unwrap();
        // Verify against a different session_did → both sigs were over the real
        // one → identity direction fails first.
        assert!(
            verify_binding(
                &ed_pk,
                &b.pubkey,
                &b.ed_sig,
                &b.schnorr_sig,
                "did:wire:other-2"
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_fields_rejected() {
        let (_sk, pk) = generate_keypair();
        assert_eq!(
            verify_binding(&pk, "!!notb64", "x", "y", "did:wire:z"),
            Err(NostrKeyError::BadEncoding)
        );
        assert_eq!(
            verify_binding(&pk, &b64encode(b"short"), "x", "y", "did:wire:z"),
            Err(NostrKeyError::BadEncoding)
        );
    }

    #[test]
    fn xonly_from_secret_matches_generation() {
        let (sk, xonly) = generate_transport_key();
        assert_eq!(xonly_from_secret(&sk).unwrap(), xonly);
    }

    #[test]
    fn card_nostr_binding_reads_and_verifies() {
        let (ed_sk, ed_pk) = generate_keypair();
        let (nostr_sk, nostr_xonly) = generate_transport_key();
        let did = "did:wire:reader-1";
        let b = build_binding(&ed_sk, &nostr_sk, did).unwrap();
        let card = serde_json::json!({
            "did": did,
            "nostr_pubkey": {
                "pubkey": b.pubkey,
                "ed_sig": b.ed_sig,
                "schnorr_sig": b.schnorr_sig,
            }
        });
        assert_eq!(card_nostr_binding(&card, &ed_pk), Ok(Some(nostr_xonly)));
        // A card with no nostr_pubkey → Ok(None).
        let plain = serde_json::json!({"did": did});
        assert_eq!(card_nostr_binding(&plain, &ed_pk), Ok(None));
    }
}
