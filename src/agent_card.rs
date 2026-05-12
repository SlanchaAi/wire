//! Agent card — DID-anchored identity for a wire endpoint.
//!
//! An agent card binds:
//!   - a handle (`paul`)
//!   - to a DID (`did:wire:paul`)
//!   - to one or more Ed25519 verify keys
//!   - with a signature from the canonical key
//!
//! Bilateral pairing produces a 6-digit Short Authentication String (SAS) by
//! HMAC'ing the two sorted public keys. Both peers compute the same digits
//! independently from their own knowledge of both keys; the operator reads
//! them aloud out-of-band (the magic-wormhole flow) to confirm.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical::canonical;
use crate::signing::{b64decode, b64encode, make_key_id};

pub const CARD_SCHEMA_VERSION: &str = "v3.1";
pub const DID_METHOD: &str = "did:wire";

/// Build a DID from `handle` + `public_key`. Returns
/// `did:wire:<handle>-<8-hex-of-sha256(public_key)>`. The pubkey suffix
/// makes the DID uniquely tied to the keypair — two operators picking
/// the same handle (e.g., both auto-init'ing as `<hostname>` on the same
/// hostname) get distinct DIDs.
///
/// Pass-through for any string already starting with `did:*` (so callers
/// can be lazy with mixed inputs).
///
/// Backward-compat: legacy DIDs of the form `did:wire:<handle>` (no
/// pubkey suffix) shipped pre-v0.5.7. They still verify because signature
/// verification reads the pubkey from `verify_keys`, not from the DID
/// string. They're just non-unique across operators picking the same
/// handle — the v0.5.7 cohort onward gets uniqueness by construction.
pub fn did_for_with_key(handle: &str, public_key: &[u8]) -> String {
    if handle.starts_with("did:") {
        return handle.to_string();
    }
    let suffix = crate::signing::fingerprint(public_key);
    format!("{DID_METHOD}:{handle}-{suffix}")
}

/// Legacy DID constructor — DID = `did:wire:<handle>` with no pubkey
/// suffix. Pre-v0.5.7 model. Kept for backward-compat in code paths
/// that don't have the pubkey on hand (display helpers, test fixtures)
/// and for tests that pin specific DID strings. NEW callers should use
/// `did_for_with_key`.
pub fn did_for(handle: &str) -> String {
    if handle.starts_with("did:") {
        handle.to_string()
    } else {
        format!("{DID_METHOD}:{handle}")
    }
}

/// Extract the display-friendly handle from a DID. Handles both legacy
/// (`did:wire:paul`) and v0.5.7+ (`did:wire:paul-abc12345`) forms. The
/// v0.5.7 trailing `-<8-hex>` suffix is stripped when present.
pub fn display_handle_from_did(did: &str) -> &str {
    let stripped = did.strip_prefix("did:wire:").unwrap_or(did);
    // v0.5.7+ form: `<handle>-<8-hex>`. Detect by trailing exactly 8 hex
    // chars after a final `-`. Anything else passes through unchanged.
    if let Some(idx) = stripped.rfind('-') {
        let suffix = &stripped[idx + 1..];
        if suffix.len() == 8 && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            return &stripped[..idx];
        }
    }
    stripped
}

/// Convenience type — at this stage we use serde_json::Value so the wire
/// shape stays explicit. A typed struct can come in v0.2+.
pub type AgentCard = Value;

#[derive(Debug, Error)]
pub enum CardError {
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("verify_keys is empty or malformed")]
    NoVerifyKeys,
    #[error("signature decode failed")]
    BadSignature,
    #[error("signature did not verify")]
    SignatureRejected,
}

/// Build an unsigned agent card for `handle` with one verify key.
///
/// Optional overrides:
///   - `name`: human-friendly display name (defaults to capitalized handle)
///   - `capabilities`: list of capability strings (defaults to `["wire/v3.1"]`)
///   - `max_body_kb`: per-message body cap in KB (defaults to 64)
///
/// v0.1 deliberately does NOT include `registries`, `onboard_endpoint`,
/// `wire_raw_url_template`, or `revoked_at`. Those land in v0.2+ along
/// with the registry feature itself (see ANTI_FEATURES.md).
pub fn build_agent_card(
    handle: &str,
    public_key: &[u8],
    name: Option<&str>,
    capabilities: Option<Vec<String>>,
    max_body_kb: Option<u64>,
) -> AgentCard {
    let display_name = name
        .map(str::to_string)
        .unwrap_or_else(|| capitalize(handle));
    let caps = capabilities.unwrap_or_else(|| vec!["wire/v3.1".to_string()]);
    let body_kb = max_body_kb.unwrap_or(64);

    let key_id = make_key_id(handle, public_key);
    let key_id_full = format!("ed25519:{key_id}");

    json!({
        "schema_version": CARD_SCHEMA_VERSION,
        "did": did_for_with_key(handle, public_key),
        "handle": handle,
        "name": display_name,
        "capabilities": caps,
        "verify_keys": {
            key_id_full: {
                "key": b64encode(public_key),
                "alg": "ed25519",
                "active": true,
            }
        },
        "policies": {
            "max_message_body_kb": body_kb,
        }
    })
}

/// Capitalize the first character of an ASCII handle (`paul` → `Paul`).
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Canonical bytes of an agent card — strips `signature` before serialization.
pub fn card_canonical(card: &AgentCard) -> Vec<u8> {
    canonical(card, false)
}

/// Sign an agent card with `private_key`. Returns the card with `signature`
/// field appended (base64 of Ed25519 signature over `card_canonical(card)`).
pub fn sign_agent_card(card: &AgentCard, private_key: &[u8]) -> AgentCard {
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&private_key[..32]);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let sig = sk.sign(&card_canonical(card));
    let mut out = card.as_object().cloned().unwrap_or_default();
    out.insert(
        "signature".into(),
        Value::String(b64encode(&sig.to_bytes())),
    );
    Value::Object(out)
}

/// Verify a signed card. Picks the first verify_key, validates the
/// signature over `card_canonical(card)` (stripped of `signature`).
pub fn verify_agent_card(card: &AgentCard) -> Result<(), CardError> {
    let signature_b64 = card
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(CardError::MissingField("signature"))?;

    let verify_keys = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .ok_or(CardError::MissingField("verify_keys"))?;

    let (_kid, key_record) = verify_keys.iter().next().ok_or(CardError::NoVerifyKeys)?;
    let pk_b64 = key_record
        .get("key")
        .and_then(Value::as_str)
        .ok_or(CardError::MissingField("verify_keys[*].key"))?;
    let pk_bytes = b64decode(pk_b64).map_err(|_| CardError::BadSignature)?;
    if pk_bytes.len() != 32 {
        return Err(CardError::BadSignature);
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| CardError::BadSignature)?;

    let sig_bytes = b64decode(signature_b64).map_err(|_| CardError::BadSignature)?;
    if sig_bytes.len() != 64 {
        return Err(CardError::BadSignature);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    vk.verify(&card_canonical(card), &sig)
        .map_err(|_| CardError::SignatureRejected)
}

/// 6-digit bilateral SAS over two raw 32-byte public keys.
///
/// `sha256(min(a, b) || max(a, b))` then take the last 6 decimal digits.
/// Symmetric in `(a, b)` so either operator computes the same digits from
/// independent knowledge of both keys.
pub fn compute_sas(public_key_a: &[u8], public_key_b: &[u8]) -> String {
    let (lo, hi) = if public_key_a <= public_key_b {
        (public_key_a, public_key_b)
    } else {
        (public_key_b, public_key_a)
    };
    let mut h = Sha256::new();
    h.update(lo);
    h.update(hi);
    let digest = h.finalize();
    // Take low 4 bytes -> u32, mod 1_000_000 for 6 digits.
    let n = u32::from_be_bytes([digest[28], digest[29], digest[30], digest[31]]);
    format!("{:06}", n % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;

    #[test]
    fn did_for_handle() {
        assert_eq!(did_for("paul"), "did:wire:paul");
    }

    #[test]
    fn did_for_already_did_passthrough() {
        assert_eq!(did_for("did:wire:paul"), "did:wire:paul");
        assert_eq!(did_for("did:key:abc"), "did:key:abc");
    }

    #[test]
    fn did_method_constant() {
        assert_eq!(DID_METHOD, "did:wire");
    }

    #[test]
    fn build_minimal_card() {
        let (_, pk) = generate_keypair();
        let card = build_agent_card("paul", &pk, None, None, None);
        assert_eq!(card["schema_version"], CARD_SCHEMA_VERSION);
        // v0.5.7+: DID is pubkey-suffixed for cross-operator uniqueness.
        let did = card["did"].as_str().unwrap();
        assert!(did.starts_with("did:wire:paul-"), "got: {did}");
        assert_eq!(did.len(), "did:wire:paul-".len() + 8);
        assert_eq!(card["handle"], "paul");
        assert_eq!(card["name"], "Paul");
        let vks = card["verify_keys"].as_object().unwrap();
        assert_eq!(vks.len(), 1);
        assert_eq!(card["policies"]["max_message_body_kb"], 64);
    }

    #[test]
    fn build_card_with_overrides() {
        let (_, pk) = generate_keypair();
        let card = build_agent_card(
            "carol",
            &pk,
            Some("Carol's Agent"),
            Some(vec!["custom-cap".to_string()]),
            Some(128),
        );
        assert_eq!(card["name"], "Carol's Agent");
        assert_eq!(card["capabilities"], json!(["custom-cap"]));
        assert_eq!(card["policies"]["max_message_body_kb"], 128);
    }

    #[test]
    fn build_card_does_not_carry_v02_fields() {
        let (_, pk) = generate_keypair();
        let card = build_agent_card("paul", &pk, None, None, None);
        let obj = card.as_object().unwrap();
        for v02 in [
            "registries",
            "onboard_endpoint",
            "wire_raw_url_template",
            "revoked_at",
        ] {
            assert!(
                !obj.contains_key(v02),
                "v0.2+ field {v02} leaked into v0.1 card"
            );
        }
    }

    #[test]
    fn card_canonical_excludes_signature() {
        let v = json!({"schema_version": "v3.1", "did": "did:wire:paul", "signature": "sig"});
        let bytes = card_canonical(&v);
        assert!(!String::from_utf8_lossy(&bytes).contains("signature"));
    }

    #[test]
    fn card_canonical_sort_keys_stable() {
        let a = json!({"b": 1, "a": 2, "did": "did:wire:paul"});
        let b = json!({"did": "did:wire:paul", "a": 2, "b": 1});
        assert_eq!(card_canonical(&a), card_canonical(&b));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pk) = generate_keypair();
        let card = build_agent_card("paul", &pk, None, None, None);
        let signed = sign_agent_card(&card, &sk);
        assert!(signed.get("signature").is_some());
        verify_agent_card(&signed).unwrap();
    }

    #[test]
    fn verify_rejects_unsigned_card() {
        let (_, pk) = generate_keypair();
        let card = build_agent_card("paul", &pk, None, None, None);
        let err = verify_agent_card(&card).unwrap_err();
        assert!(matches!(err, CardError::MissingField("signature")));
    }

    #[test]
    fn verify_rejects_tampered_card() {
        let (sk, pk) = generate_keypair();
        let mut signed = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        signed["name"] = json!("TamperedName");
        let err = verify_agent_card(&signed).unwrap_err();
        assert!(matches!(err, CardError::SignatureRejected));
    }

    #[test]
    fn verify_rejects_card_with_no_verify_keys() {
        let (sk, _) = generate_keypair();
        let card = json!({"schema_version": "v3.1", "did": "did:wire:paul", "verify_keys": {}});
        let signed = sign_agent_card(&card, &sk);
        let err = verify_agent_card(&signed).unwrap_err();
        assert!(matches!(err, CardError::NoVerifyKeys));
    }

    #[test]
    fn compute_sas_is_6_digits() {
        let (_, a) = generate_keypair();
        let (_, b) = generate_keypair();
        let sas = compute_sas(&a, &b);
        assert_eq!(sas.len(), 6);
        assert!(sas.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn compute_sas_bilateral_symmetric() {
        let (_, a) = generate_keypair();
        let (_, b) = generate_keypair();
        assert_eq!(compute_sas(&a, &b), compute_sas(&b, &a));
    }

    #[test]
    fn compute_sas_changes_with_inputs() {
        let (_, a) = generate_keypair();
        let (_, b) = generate_keypair();
        let (_, c) = generate_keypair();
        assert_ne!(compute_sas(&a, &b), compute_sas(&a, &c));
    }
}
