//! Ed25519 sign-over-event_id (Nostr NIP-01 style).
//!
//! Sign flow:
//!   1. Compute SHA-256 over canonical bytes of `msg` (strict: drops event_id).
//!   2. That 32-byte digest IS the `event_id` (hex-encoded for transport).
//!   3. Sign the raw 32-byte digest. The signature commits to event_id, which
//!      transitively commits to the canonical body — tamper anything, the
//!      digest changes, the signature fails.
//!
//! Why sign the id and not the body: lets relays/index layers cite events by
//! id without re-canonicalizing every body. Same property Nostr exploits.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ops::Range;
use thiserror::Error;

use crate::canonical::canonical;

// ---------- kind ranges ----------

/// Disjoint kind-id ranges. Mirrors v3 protocol; v0.1 ships a strict subset.
///
/// v0.2+ kinds (file_share=1900, file_revoke=1901, registry_revocation=10500)
/// are deliberately ABSENT — see ANTI_FEATURES.md.
pub static KIND_RANGES: &[(KindClass, Range<u32>)] = &[
    (KindClass::Regular, 1000..10000),
    (KindClass::Replaceable, 10000..20000),
    (KindClass::Ephemeral, 20000..30000),
    (KindClass::Addressable, 30000..40000),
];

/// v0.1 named kinds. Anything not here is unknown to this version.
pub fn kinds() -> &'static [(u32, &'static str)] {
    &[
        (1, "decision"),    // Nostr-compat short text — special-cased to Regular
        (100, "heartbeat"), // ephemeral liveness ping — special-cased to Ephemeral
        (1000, "decision"),
        (1001, "claim"),
        (1002, "ack"),
        (1100, "agent_card"),
        (1101, "trust_add_key"),
        (1102, "trust_revoke_key"),
        (1200, "wire_open"),
        (1201, "wire_close"),
    ]
}

/// `kinds()` as a `BTreeMap` for membership tests. Allocated per call —
/// callers that need it hot should cache.
pub fn kinds_map() -> BTreeMap<u32, &'static str> {
    kinds().iter().copied().collect()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KindClass {
    Regular,
    Replaceable,
    Ephemeral,
    Addressable,
}

impl KindClass {
    pub fn as_str(self) -> &'static str {
        match self {
            KindClass::Regular => "regular",
            KindClass::Replaceable => "replaceable",
            KindClass::Ephemeral => "ephemeral",
            KindClass::Addressable => "addressable",
        }
    }
}

/// Classify a kind id. `None` means unknown — caller decides how to handle.
pub fn kind_class(kind: u32) -> Option<KindClass> {
    // Documented out-of-range special cases (Nostr NIP-01 compatibility +
    // v3 heartbeat carve-out). Keep these explicit, not a hidden lookup.
    match kind {
        1 => return Some(KindClass::Regular),
        100 => return Some(KindClass::Ephemeral),
        _ => {}
    }
    for (cls, range) in KIND_RANGES {
        if range.contains(&kind) {
            return Some(*cls);
        }
    }
    None
}

// ---------- canonical re-export (keeps call sites symmetric with Python) ----------

pub fn canonical_event(value: &Value, strict: bool) -> Vec<u8> {
    canonical(value, strict)
}

// Public alias matching Python `signing.canonical(...)` import path.
pub use crate::canonical::canonical as canonical_value;

// ---------- event_id ----------

pub fn compute_event_id(msg: &Value) -> String {
    let bytes = canonical(msg, true);
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

// ---------- key id + fingerprint ----------

pub fn fingerprint(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(&digest[..4])
}

pub fn make_key_id(handle: &str, public_key: &[u8]) -> String {
    format!("{handle}:{}", fingerprint(public_key))
}

// ---------- base64 helpers ----------

pub fn b64encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    B64.decode(s)
}

// ---------- key generation ----------

/// Returns `(private_key_bytes, public_key_bytes)` — both 32 bytes, raw.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    (sk.to_bytes(), pk.to_bytes())
}

// ---------- sign / verify ----------

#[derive(Debug, Error)]
pub enum SignError {
    #[error("private key must be 32 bytes, got {0}")]
    BadPrivateLen(usize),
    #[error("public key must be 32 bytes, got {0}")]
    BadPublicLen(usize),
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("event_id mismatch — body was tampered after signing")]
    EventIdMismatch,
    #[error("signer {0:?} not in trust")]
    UnknownAgent(String),
    #[error("key {0:?} not found for agent {1:?}")]
    UnknownKey(String, String),
    #[error("key {0:?} for agent {1:?} is deactivated")]
    DeactivatedKey(String, String),
    #[error("signature decode failed")]
    BadSignature,
    #[error("signature did not verify")]
    SignatureRejected,
}

/// Sign a message. Returns the canonical wire form: original fields + the
/// computed `event_id`, `public_key_id`, `signature`.
pub fn sign_message_v31(
    msg: &Value,
    private_key: &[u8],
    public_key: &[u8],
    agent: &str,
) -> Result<Value, SignError> {
    if private_key.len() != 32 {
        return Err(SignError::BadPrivateLen(private_key.len()));
    }
    if public_key.len() != 32 {
        return Err(SignError::BadPublicLen(public_key.len()));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(private_key);
    let sk = SigningKey::from_bytes(&sk_bytes);

    let event_id = compute_event_id(msg);
    let raw = hex::decode(&event_id).expect("compute_event_id always returns valid hex");
    let sig = sk.sign(&raw);

    let mut out = msg.as_object().cloned().unwrap_or_default();
    out.insert("event_id".into(), Value::String(event_id));
    out.insert(
        "public_key_id".into(),
        Value::String(make_key_id(agent, public_key)),
    );
    out.insert(
        "signature".into(),
        Value::String(b64encode(&sig.to_bytes())),
    );
    Ok(Value::Object(out))
}

/// Verify a signed message against a trust dict (see `trust` module).
///
/// Returns `Ok(())` iff: event_id matches recomputed, signer's key is in
/// trust + active, and the Ed25519 signature validates over the event_id.
pub fn verify_message_v31(msg: &Value, trust: &Value) -> Result<(), VerifyError> {
    let from = msg
        .get("from")
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingField("from"))?;
    // v0.5.7+: DID may include a `-<8-hex>` pubkey suffix
    // (`did:wire:paul-abc12345`). Trust map is keyed by the bare handle,
    // so strip both the `did:wire:` prefix AND the optional pubkey suffix.
    let handle = crate::agent_card::display_handle_from_did(from);

    let public_key_id = msg
        .get("public_key_id")
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingField("public_key_id"))?;

    let signature_b64 = msg
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingField("signature"))?;

    let event_id = msg
        .get("event_id")
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingField("event_id"))?;

    let recomputed = compute_event_id(msg);
    if recomputed != event_id {
        return Err(VerifyError::EventIdMismatch);
    }

    let agent = trust
        .get("agents")
        .and_then(|a| a.get(handle))
        .ok_or_else(|| VerifyError::UnknownAgent(handle.to_string()))?;

    let public_keys = agent
        .get("public_keys")
        .and_then(Value::as_array)
        .ok_or_else(|| VerifyError::UnknownKey(public_key_id.to_string(), handle.to_string()))?;

    let key_record = public_keys
        .iter()
        .find(|k| k.get("key_id").and_then(Value::as_str) == Some(public_key_id))
        .ok_or_else(|| VerifyError::UnknownKey(public_key_id.to_string(), handle.to_string()))?;

    let active = key_record
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !active {
        return Err(VerifyError::DeactivatedKey(
            public_key_id.to_string(),
            handle.to_string(),
        ));
    }

    let pk_b64 = key_record
        .get("key")
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingField("key"))?;
    let pk_bytes = b64decode(pk_b64).map_err(|_| VerifyError::BadSignature)?;
    if pk_bytes.len() != 32 {
        return Err(VerifyError::BadSignature);
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| VerifyError::BadSignature)?;

    let sig_bytes = b64decode(signature_b64).map_err(|_| VerifyError::BadSignature)?;
    if sig_bytes.len() != 64 {
        return Err(VerifyError::BadSignature);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    let raw = hex::decode(event_id).map_err(|_| VerifyError::BadSignature)?;
    vk.verify(&raw, &sig)
        .map_err(|_| VerifyError::SignatureRejected)
}

fn strip_did_wire(s: &str) -> &str {
    s.strip_prefix("did:wire:").unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn trust_for(handle: &str, pub_key: &[u8]) -> Value {
        let kid = make_key_id(handle, pub_key);
        json!({
            "agents": {
                handle: {
                    "public_keys": [
                        {"key_id": kid, "key": b64encode(pub_key), "active": true}
                    ]
                }
            }
        })
    }

    #[test]
    fn kind_ranges_disjoint() {
        let mut seen = std::collections::HashSet::new();
        for (_, rng) in KIND_RANGES {
            for k in rng.clone() {
                assert!(seen.insert(k), "kind {k} in multiple ranges");
            }
        }
    }

    #[test]
    fn kind_class_known_ranges() {
        assert_eq!(kind_class(20000), Some(KindClass::Ephemeral));
        assert_eq!(kind_class(29999), Some(KindClass::Ephemeral));
        assert_eq!(kind_class(1000), Some(KindClass::Regular));
        assert_eq!(kind_class(9999), Some(KindClass::Regular));
        assert_eq!(kind_class(10000), Some(KindClass::Replaceable));
        assert_eq!(kind_class(19999), Some(KindClass::Replaceable));
        assert_eq!(kind_class(30000), Some(KindClass::Addressable));
    }

    #[test]
    fn kind_class_special_cases() {
        assert_eq!(kind_class(1), Some(KindClass::Regular));
        assert_eq!(kind_class(100), Some(KindClass::Ephemeral));
    }

    #[test]
    fn kind_class_unknown_returns_none() {
        assert_eq!(kind_class(99999), None);
        assert_eq!(kind_class(7), None);
    }

    #[test]
    fn v01_does_not_ship_v02_kinds() {
        let names = kinds_map();
        for deferred in [1900, 1901, 10500] {
            assert!(
                !names.contains_key(&deferred),
                "v0.2+ kind {deferred} leaked into v0.1"
            );
        }
    }

    #[test]
    fn fingerprint_is_8_hex() {
        let fp = fingerprint(&[0u8; 32]);
        assert_eq!(fp.len(), 8);
        u32::from_str_radix(&fp, 16).expect("hex");
    }

    #[test]
    fn make_key_id_format() {
        let (_, pk) = generate_keypair();
        let kid = make_key_id("paul", &pk);
        assert!(kid.starts_with("paul:"));
        assert_eq!(kid.split(':').nth(1).unwrap().len(), 8);
    }

    #[test]
    fn generate_keypair_returns_32_byte_pair() {
        let (sk, pk) = generate_keypair();
        assert_eq!(sk.len(), 32);
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pk) = generate_keypair();
        let msg = json!({
            "timestamp": "2026-05-09T00:00:00Z",
            "from": "paul",
            "type": "decision",
            "kind": 1,
            "subject": "test",
            "body": {"content": "hello"},
        });
        let signed = sign_message_v31(&msg, &sk, &pk, "paul").unwrap();
        assert!(signed.get("event_id").is_some());
        assert!(signed.get("public_key_id").is_some());
        assert!(signed.get("signature").is_some());
        verify_message_v31(&signed, &trust_for("paul", &pk)).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let (sk, pk) = generate_keypair();
        let msg = json!({"from": "paul", "type": "decision", "body": {"content": "original"}});
        let mut signed = sign_message_v31(&msg, &sk, &pk, "paul").unwrap();
        signed["body"]["content"] = json!("tampered");
        let err = verify_message_v31(&signed, &trust_for("paul", &pk)).unwrap_err();
        assert!(matches!(err, VerifyError::EventIdMismatch));
    }

    #[test]
    fn verify_accepts_did_wire_prefix_in_from() {
        let (sk, pk) = generate_keypair();
        let msg = json!({"from": "did:wire:paul", "type": "decision", "body": {}});
        let signed = sign_message_v31(&msg, &sk, &pk, "paul").unwrap();
        verify_message_v31(&signed, &trust_for("paul", &pk)).unwrap();
    }

    #[test]
    fn verify_rejects_unknown_agent() {
        let (sk, pk) = generate_keypair();
        let msg = json!({"from": "paul", "type": "decision", "body": {}});
        let signed = sign_message_v31(&msg, &sk, &pk, "paul").unwrap();
        let trust = json!({"agents": {"willard": {"public_keys": []}}});
        let err = verify_message_v31(&signed, &trust).unwrap_err();
        assert!(matches!(err, VerifyError::UnknownAgent(h) if h == "paul"));
    }

    #[test]
    fn verify_rejects_inactive_key() {
        let (sk, pk) = generate_keypair();
        let msg = json!({"from": "paul", "type": "decision", "body": {}});
        let signed = sign_message_v31(&msg, &sk, &pk, "paul").unwrap();
        let mut trust = trust_for("paul", &pk);
        trust["agents"]["paul"]["public_keys"][0]["active"] = json!(false);
        let err = verify_message_v31(&signed, &trust).unwrap_err();
        assert!(matches!(err, VerifyError::DeactivatedKey(_, _)));
    }

    #[test]
    fn compute_event_id_is_64_hex() {
        let v = json!({"from": "paul", "type": "test"});
        let eid = compute_event_id(&v);
        assert_eq!(eid.len(), 64);
        for c in eid.chars() {
            assert!(c.is_ascii_hexdigit());
        }
    }
}
