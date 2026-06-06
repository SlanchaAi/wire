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

pub const CARD_SCHEMA_VERSION: &str = "v3.2";
pub const DID_METHOD: &str = "did:wire";

/// DID method prefix for operator anchor (RFC-001 §1). Distinct from
/// `did:wire:` session DIDs so a session DID and an operator DID can
/// never be confused at parse time.
pub const DID_METHOD_OP: &str = "did:wire:op";

/// DID method prefix for organization anchor (RFC-001 §1).
pub const DID_METHOD_ORG: &str = "did:wire:org";

/// Length of the hex tail on op_did / org_did (RFC-001 §1). 32 hex
/// (128 bits) makes collision search 2^128, much harder than session
/// DID's 2^32 — appropriate for long-lived identities that anchor
/// trust scopes rather than ephemeral sessions.
pub const LONG_FINGERPRINT_HEX_LEN: usize = 32;

/// Build a DID from `handle` + `public_key`. Returns
/// `did:wire:<handle>-<8-hex-of-sha256(public_key)>`. The pubkey suffix
/// makes the DID uniquely tied to the keypair — two operators picking
/// the same handle (e.g., both auto-init'ing as `<hostname>` on the same
/// hostname) get distinct DIDs.
///
/// Pass-through for any string already starting with `did:*` (so callers
/// can be lazy with mixed inputs).
pub fn did_for_with_key(handle: &str, public_key: &[u8]) -> String {
    if handle.starts_with("did:") {
        return handle.to_string();
    }
    let suffix = crate::signing::fingerprint(public_key);
    format!("{DID_METHOD}:{handle}-{suffix}")
}

/// Build an operator DID (`did:wire:op:<handle>-<32hex>`). RFC-001
/// §1 calls for a 32-hex tail (16 bytes of sha256(pubkey)) so the
/// long-lived operator anchor is collision-resistant at 2^128.
///
/// Pass-through for any string already starting with `did:wire:op:`
/// so callers can be lazy with mixed inputs.
pub fn did_for_op(handle: &str, public_key: &[u8]) -> String {
    if handle.starts_with("did:wire:op:") {
        return handle.to_string();
    }
    let suffix = long_fingerprint(public_key);
    format!("{DID_METHOD_OP}:{handle}-{suffix}")
}

/// Build an organization DID (`did:wire:org:<handle>-<32hex>`). Same
/// construction as `did_for_op` but under the org prefix; org_dids
/// gate the eased-pair surface, so they share the longer hex tail.
pub fn did_for_org(handle: &str, public_key: &[u8]) -> String {
    if handle.starts_with("did:wire:org:") {
        return handle.to_string();
    }
    let suffix = long_fingerprint(public_key);
    format!("{DID_METHOD_ORG}:{handle}-{suffix}")
}

/// 32-hex (16-byte) fingerprint over the public key for op/org DIDs.
/// Wider than `signing::fingerprint` (which returns 8 hex / 4 bytes)
/// because op/org identities are long-lived and grant trust scope.
pub fn long_fingerprint(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(&digest[..16])
}

/// True iff `did` is a well-formed `did:wire:op:<handle>-<32hex>`.
/// Used at card-validation time to refuse a `did:wire:` session DID
/// mistakenly placed in the `op_did` slot (and vice versa).
pub fn is_op_did(did: &str) -> bool {
    let Some(rest) = did.strip_prefix("did:wire:op:") else {
        return false;
    };
    has_long_hex_suffix(rest)
}

/// True iff `did` is a well-formed `did:wire:org:<handle>-<32hex>`.
pub fn is_org_did(did: &str) -> bool {
    let Some(rest) = did.strip_prefix("did:wire:org:") else {
        return false;
    };
    has_long_hex_suffix(rest)
}

fn has_long_hex_suffix(s: &str) -> bool {
    let Some(idx) = s.rfind('-') else {
        return false;
    };
    let suffix = &s[idx + 1..];
    suffix.len() == LONG_FINGERPRINT_HEX_LEN && suffix.chars().all(|c| c.is_ascii_hexdigit())
}

/// Strip the federation suffix (`@relay.example`) from a handle, returning
/// the bare local-part. This is the canonical on-disk form: outbox/inbox
/// files are keyed by bare handle (`paul-mac.jsonl`), and the pinned-peers
/// map in `relay_state.json` is keyed by bare handle.
///
/// Why this exists (v0.5.13): `wire send paul-mac@wireup.net "..."` used
/// to write the outbox to `paul-mac@wireup.net.jsonl`, but `wire push`
/// only enumerated bare-handle filenames. Events stuck silently for 25
/// minutes (issue #2). Normalizing here makes the on-disk contract the
/// single source of truth — accepts both `paul-mac` and `paul-mac@host`,
/// always writes to `paul-mac.jsonl`.
pub fn bare_handle(handle: &str) -> &str {
    handle.split_once('@').map(|(n, _)| n).unwrap_or(handle)
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
///   - `capabilities`: list of capability strings (defaults to `["wire/v3.2"]`)
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
    let caps = capabilities.unwrap_or_else(|| vec!["wire/v3.2".to_string()]);
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

// ─── RFC-001 §1: identity claims (operator / organization / project) ───────
//
// Optional, orthogonal claims layered onto the agent card. Cards without
// any of these verify and route exactly as before — the additions are
// strictly additive. v3.1 cards remain readable; v3.2 cards may carry
// any subset of these fields.

/// One entry in `org_memberships[]` (RFC-001 §1). `member_cert` is the
/// org's signature over the operator's `op_did` UTF-8 bytes. A peer
/// verifies the cert by looking up the org's pubkey (from a roster
/// pull or a previously-pinned org) and calling
/// `identity::verify_member_cert`.
#[derive(Debug, Clone)]
pub struct OrgMembership {
    pub org_did: String,
    /// Base64 Ed25519 public key of the org, carried inline so a receiver
    /// verifies the vouch fully offline — `org_did` commits to this key
    /// (`did:wire:org:<h>-<32hex sha256(org_pubkey)>`) and `member_cert` is
    /// checked against it (RFC-001 Phase 1, `org_membership::evaluate_card_membership`).
    pub org_pubkey: String,
    /// Base64 Ed25519 signature by the org's key over `op_did` UTF-8 bytes.
    pub member_cert: String,
}

/// Identity claims that may be layered onto an agent card. Each field
/// is independently optional — a card may declare an operator anchor
/// without an org membership, or an org membership without a project
/// tag. The fields are orthogonal axes per RFC-001.
#[derive(Debug, Clone, Default)]
pub struct IdentityClaims {
    /// Operator DID — `did:wire:op:<handle>-<32hex>`. Must satisfy
    /// `is_op_did(...)`. The operator's root key separately signs
    /// `op_cert` over the *session* DID this card belongs to, anchoring
    /// the session under the operator.
    pub op_did: Option<String>,
    /// Base64 Ed25519 signature by the operator's key over this card's
    /// session DID (UTF-8 bytes). Verifiable with `identity::verify_op_cert`.
    /// Meaningful only when `op_did` is set.
    pub op_cert: Option<String>,
    /// Base64 Ed25519 operator root public key, carried inline so the operator
    /// binding verifies offline — `op_did` commits to this key and `op_cert` is
    /// checked against it. Set whenever `op_did` is set; without it the operator
    /// claim is unverifiable and a receiver fails it closed (RFC-001 Phase 1).
    pub op_pubkey: Option<String>,
    /// Zero or more org membership entries. An operator may sit in
    /// multiple orgs simultaneously; each entry stands on its own.
    pub org_memberships: Vec<OrgMembership>,
    /// Opaque routing tag — NEVER trust-bearing. RFC-001 §6.
    pub project: Option<String>,
}

/// Layer identity claims onto an existing (unsigned) card. The returned
/// card is unsigned; the caller signs it with `sign_agent_card` after
/// all claims are attached. Fields with `None`/empty values are not
/// added to the JSON, keeping the canonical bytes minimal for v3.1-only
/// peers and making round-trip semantics deterministic.
///
/// Returns `Err(ClaimError::InvalidOpDid)` if `op_did` is set but does
/// not parse as `did:wire:op:<handle>-<32hex>`; same shape for
/// `InvalidOrgDid`. The check is structural — cryptographic verification
/// of `op_cert` / `member_cert` happens in `identity::verify_*`, which
/// needs the pubkeys those certs are signed by.
pub fn with_identity_claims(
    card: &AgentCard,
    claims: &IdentityClaims,
) -> Result<AgentCard, ClaimError> {
    if let Some(op_did) = &claims.op_did
        && !is_op_did(op_did)
    {
        return Err(ClaimError::InvalidOpDid(op_did.clone()));
    }
    for m in &claims.org_memberships {
        if !is_org_did(&m.org_did) {
            return Err(ClaimError::InvalidOrgDid(m.org_did.clone()));
        }
    }

    let mut out = card.as_object().cloned().unwrap_or_default();

    if let Some(op_did) = &claims.op_did {
        out.insert("op_did".into(), Value::String(op_did.clone()));
    }
    if let Some(op_cert) = &claims.op_cert {
        out.insert("op_cert".into(), Value::String(op_cert.clone()));
    }
    if let Some(op_pubkey) = &claims.op_pubkey {
        out.insert("op_pubkey".into(), Value::String(op_pubkey.clone()));
    }
    if !claims.org_memberships.is_empty() {
        let arr: Vec<Value> = claims
            .org_memberships
            .iter()
            .map(|m| {
                json!({
                    "org_did": m.org_did,
                    "org_pubkey": m.org_pubkey,
                    "member_cert": m.member_cert,
                })
            })
            .collect();
        out.insert("org_memberships".into(), Value::Array(arr));
    }
    if let Some(project) = &claims.project {
        out.insert("project".into(), Value::String(project.clone()));
    }

    // v0.14.x retro-fix: when ANY RFC-001 op claim lands on the card,
    // bump `schema_version` to at least `CARD_SCHEMA_VERSION` (currently
    // "v3.2"). Existing cards minted at v3.1 keep their version field
    // until republish hits this path — at which point the version
    // matches the inline-fields shape. Monotonic (never downgrades): a
    // card already at >= v3.2 is unchanged. Readers that key off
    // `schema_version >= "v3.2"` to discriminate "carries op claims"
    // now have a truthful signal. (The bug it closes: v0.14 stored
    // op_did but kept emitting `schema_version: "v3.1"` — readers
    // couldn't tell from the version alone whether the card had
    // op claims; they had to probe the inline fields directly.)
    let has_any_op_claim = claims.op_did.is_some()
        || claims.op_cert.is_some()
        || claims.op_pubkey.is_some()
        || !claims.org_memberships.is_empty();
    if has_any_op_claim {
        let current = out
            .get("schema_version")
            .and_then(Value::as_str)
            .unwrap_or("v3.0");
        let target = max_schema_version(current, CARD_SCHEMA_VERSION);
        out.insert("schema_version".into(), Value::String(target.to_string()));
    }

    Ok(Value::Object(out))
}

/// Compare two `vX.Y` schema-version strings as `(major, minor)` integer
/// tuples and return the higher. Defensive: unparseable inputs fall back
/// to the OTHER argument (so a malformed stored card doesn't poison the
/// republish). `v3.10` correctly compares as > `v3.2`.
fn max_schema_version<'a>(a: &'a str, b: &'a str) -> &'a str {
    fn parse(s: &str) -> Option<(u32, u32)> {
        let rest = s.strip_prefix('v')?;
        let (maj, min) = rest.split_once('.')?;
        Some((maj.parse().ok()?, min.parse().ok()?))
    }
    match (parse(a), parse(b)) {
        (Some(pa), Some(pb)) => {
            if pa >= pb {
                a
            } else {
                b
            }
        }
        // Bias toward the parseable one; if neither parses, keep `a`.
        (Some(_), None) => a,
        (None, Some(_)) => b,
        (None, None) => a,
    }
}

#[derive(Debug, Error)]
pub enum ClaimError {
    #[error("op_did is not a well-formed did:wire:op:<handle>-<32hex>: {0}")]
    InvalidOpDid(String),
    #[error("org_did is not a well-formed did:wire:org:<handle>-<32hex>: {0}")]
    InvalidOrgDid(String),
}

/// Read `op_did` from a card. Returns `None` if absent or malformed.
pub fn card_op_did(card: &AgentCard) -> Option<&str> {
    card.get("op_did").and_then(Value::as_str)
}

/// Read `op_cert` from a card. Returns `None` if absent.
pub fn card_op_cert(card: &AgentCard) -> Option<&str> {
    card.get("op_cert").and_then(Value::as_str)
}

/// Read `project` routing tag from a card.
pub fn card_project(card: &AgentCard) -> Option<&str> {
    card.get("project").and_then(Value::as_str)
}

/// Read `org_memberships[]` from a card as a list of `(org_did,
/// member_cert)` borrowed pairs. Returns empty if absent or malformed.
pub fn card_org_memberships(card: &AgentCard) -> Vec<(&str, &str)> {
    card.get("org_memberships")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    let org = entry.get("org_did").and_then(Value::as_str)?;
                    let cert = entry.get("member_cert").and_then(Value::as_str)?;
                    Some((org, cert))
                })
                .collect()
        })
        .unwrap_or_default()
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

    // ─── RFC-001 §1: identity claims ───────────────────────────────────────

    fn op_did_for_test(handle: &str) -> (String, Vec<u8>, Vec<u8>) {
        let (sk, pk) = generate_keypair();
        (did_for_op(handle, &pk), sk.to_vec(), pk.to_vec())
    }

    fn org_did_for_test(handle: &str) -> (String, Vec<u8>, Vec<u8>) {
        let (sk, pk) = generate_keypair();
        (did_for_org(handle, &pk), sk.to_vec(), pk.to_vec())
    }

    #[test]
    fn schema_version_is_v3_2() {
        assert_eq!(CARD_SCHEMA_VERSION, "v3.2");
    }

    #[test]
    fn op_did_has_long_hex_suffix_and_method_prefix() {
        let (did, _, _) = op_did_for_test("darby");
        assert!(did.starts_with("did:wire:op:darby-"), "got: {did}");
        let tail = did.rsplit('-').next().unwrap();
        assert_eq!(tail.len(), LONG_FINGERPRINT_HEX_LEN);
        assert!(tail.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn org_did_has_long_hex_suffix_and_method_prefix() {
        let (did, _, _) = org_did_for_test("slanchaai");
        assert!(did.starts_with("did:wire:org:slanchaai-"), "got: {did}");
        let tail = did.rsplit('-').next().unwrap();
        assert_eq!(tail.len(), LONG_FINGERPRINT_HEX_LEN);
        assert!(tail.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn op_did_passthrough_when_already_op_did() {
        // Passing a fully-formed op_did back through `did_for_op` is a no-op;
        // protects callers that mix raw handles + already-built DIDs.
        let (_, pk) = generate_keypair();
        let did = did_for_op("darby", &pk);
        let again = did_for_op(&did, &pk);
        assert_eq!(did, again);
    }

    #[test]
    fn is_op_did_rejects_session_did() {
        // The classification check exists precisely to refuse this confusion.
        let (_, pk) = generate_keypair();
        let session_did = did_for_with_key("darby", &pk);
        assert!(!is_op_did(&session_did));
        assert!(!is_org_did(&session_did));
    }

    #[test]
    fn is_op_did_rejects_org_did_and_vice_versa() {
        // Disjoint namespaces — an org_did is not an op_did even though both
        // share the long-hex suffix shape.
        let (op, _, _) = op_did_for_test("darby");
        let (org, _, _) = org_did_for_test("slanchaai");
        assert!(is_op_did(&op) && !is_org_did(&op));
        assert!(is_org_did(&org) && !is_op_did(&org));
    }

    #[test]
    fn is_op_did_rejects_short_hex_suffix() {
        // An 8-hex tail (session-DID shape) under the op prefix would be a
        // namespace squat. Refuse on syntax alone.
        assert!(!is_op_did("did:wire:op:darby-deadbeef"));
        assert!(!is_org_did("did:wire:org:slanchaai-deadbeef"));
    }

    #[test]
    fn is_op_did_rejects_non_hex_suffix() {
        let bad = format!("did:wire:op:darby-{}", "z".repeat(LONG_FINGERPRINT_HEX_LEN));
        assert!(!is_op_did(&bad));
    }

    #[test]
    fn with_identity_claims_attaches_all_fields() {
        let (sk, pk) = generate_keypair();
        let card = build_agent_card("vesper-valley", &pk, None, None, None);
        let (op_did, _, op_pk) = op_did_for_test("darby");
        let (org_did, _, org_pk) = org_did_for_test("slanchaai");
        let op_pubkey = crate::signing::b64encode(&op_pk);
        let org_pubkey = crate::signing::b64encode(&org_pk);
        let claims = IdentityClaims {
            op_did: Some(op_did.clone()),
            op_cert: Some("AAAA".into()),
            op_pubkey: Some(op_pubkey.clone()),
            org_memberships: vec![OrgMembership {
                org_did: org_did.clone(),
                org_pubkey: org_pubkey.clone(),
                member_cert: "BBBB".into(),
            }],
            project: Some("wire-codex-integration".into()),
        };
        let with = with_identity_claims(&card, &claims).unwrap();
        assert_eq!(card_op_did(&with), Some(op_did.as_str()));
        assert_eq!(card_op_cert(&with), Some("AAAA"));
        assert_eq!(
            with.get("op_pubkey").and_then(|v| v.as_str()),
            Some(op_pubkey.as_str())
        );
        assert_eq!(card_project(&with), Some("wire-codex-integration"));
        let orgs = card_org_memberships(&with);
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0], (org_did.as_str(), "BBBB"));
        assert_eq!(
            with.get("org_memberships").unwrap()[0]
                .get("org_pubkey")
                .and_then(|v| v.as_str()),
            Some(org_pubkey.as_str())
        );
        // Card still signs + verifies after identity claims are layered.
        let signed = sign_agent_card(&with, &sk);
        verify_agent_card(&signed).unwrap();
    }

    #[test]
    fn with_identity_claims_skips_absent_fields() {
        // A card with no claims must not gain empty `op_did`/`project`/etc.
        // entries — keeps canonical bytes minimal and v3.1-peer-friendly.
        let (_, pk) = generate_keypair();
        let card = build_agent_card("vesper-valley", &pk, None, None, None);
        let with = with_identity_claims(&card, &IdentityClaims::default()).unwrap();
        let obj = with.as_object().unwrap();
        for field in ["op_did", "op_cert", "org_memberships", "project"] {
            assert!(
                !obj.contains_key(field),
                "{field} leaked into claim-less card"
            );
        }
    }

    #[test]
    fn with_identity_claims_rejects_malformed_op_did() {
        let (_, pk) = generate_keypair();
        let card = build_agent_card("vesper-valley", &pk, None, None, None);
        let claims = IdentityClaims {
            // Session-DID shape under op prefix → namespace confusion.
            op_did: Some("did:wire:op:darby-deadbeef".into()),
            ..Default::default()
        };
        let err = with_identity_claims(&card, &claims).unwrap_err();
        assert!(matches!(err, ClaimError::InvalidOpDid(_)));
    }

    #[test]
    fn with_identity_claims_rejects_malformed_org_did() {
        let (_, pk) = generate_keypair();
        let card = build_agent_card("vesper-valley", &pk, None, None, None);
        let claims = IdentityClaims {
            org_memberships: vec![OrgMembership {
                org_did: "did:wire:slanchaai".into(),
                org_pubkey: "AAAA".into(),
                member_cert: "BBBB".into(),
            }],
            ..Default::default()
        };
        let err = with_identity_claims(&card, &claims).unwrap_err();
        assert!(matches!(err, ClaimError::InvalidOrgDid(_)));
    }

    #[test]
    fn v3_1_card_remains_verifiable_under_v3_2_code() {
        // Backward-compat: a v3.1-shaped card (no identity claims, schema
        // string literally "v3.1") still round-trips signing and verify.
        // This is the wire-compat invariant — peers on the network mid-
        // upgrade keep talking.
        let (sk, pk) = generate_keypair();
        let mut card = build_agent_card("paul", &pk, None, None, None);
        card["schema_version"] = json!("v3.1");
        let signed = sign_agent_card(&card, &sk);
        verify_agent_card(&signed).unwrap();
    }

    #[test]
    fn build_agent_card_default_capability_advertises_v3_2() {
        let (_, pk) = generate_keypair();
        let card = build_agent_card("paul", &pk, None, None, None);
        let caps = card["capabilities"].as_array().unwrap();
        let has_v32 = caps.iter().any(|v| v.as_str() == Some("wire/v3.2"));
        assert!(has_v32, "default caps should advertise wire/v3.2: {caps:?}");
    }

    // v0.14.x retro-fix tests: when op claims are attached, the card's
    // `schema_version` field bumps to at least `CARD_SCHEMA_VERSION`. The
    // bump is monotonic (never downgrades), conditional (claim-less
    // attach leaves the field alone), and version-numeric (v3.10 > v3.2,
    // not lexicographic).

    #[test]
    fn with_identity_claims_bumps_schema_version_when_op_did_attached() {
        // A card that was minted at v3.1 (the pre-v0.14 emit version)
        // must surface as >= v3.2 once op claims are attached — readers
        // discriminate "card carries op_*" off the version field.
        let (_, pk) = generate_keypair();
        let mut card = build_agent_card("vesper-valley", &pk, None, None, None);
        // Roll back to v3.1 to simulate a pre-v0.14 stored card.
        card.as_object_mut()
            .unwrap()
            .insert("schema_version".into(), json!("v3.1"));
        let (op_did, _, op_pk) = op_did_for_test("darby");
        let claims = IdentityClaims {
            op_did: Some(op_did),
            op_pubkey: Some(crate::signing::b64encode(&op_pk)),
            op_cert: Some("AAAA".into()),
            ..Default::default()
        };
        let with = with_identity_claims(&card, &claims).unwrap();
        assert_eq!(
            with.get("schema_version").and_then(|v| v.as_str()),
            Some(CARD_SCHEMA_VERSION),
            "post-attach schema_version must bump to {CARD_SCHEMA_VERSION}",
        );
    }

    #[test]
    fn with_identity_claims_does_not_touch_schema_version_when_no_claims() {
        // Claim-less attach (e.g. an unenrolled operator's republish)
        // leaves the version field exactly as it was — no spurious bump
        // for a v3.1 peer that has zero op_* fields to surface.
        let (_, pk) = generate_keypair();
        let mut card = build_agent_card("vesper-valley", &pk, None, None, None);
        card.as_object_mut()
            .unwrap()
            .insert("schema_version".into(), json!("v3.1"));
        let with = with_identity_claims(&card, &IdentityClaims::default()).unwrap();
        assert_eq!(
            with.get("schema_version").and_then(|v| v.as_str()),
            Some("v3.1"),
            "claim-less attach must NOT bump",
        );
    }

    #[test]
    fn with_identity_claims_never_downgrades_schema_version() {
        // A hypothetical v3.5 card (future extension peer) attaching op
        // claims via an older `CARD_SCHEMA_VERSION` build must NOT lose
        // its higher version. Monotonic invariant.
        let (_, pk) = generate_keypair();
        let mut card = build_agent_card("vesper-valley", &pk, None, None, None);
        card.as_object_mut()
            .unwrap()
            .insert("schema_version".into(), json!("v3.5"));
        let (op_did, _, op_pk) = op_did_for_test("darby");
        let claims = IdentityClaims {
            op_did: Some(op_did),
            op_pubkey: Some(crate::signing::b64encode(&op_pk)),
            op_cert: Some("AAAA".into()),
            ..Default::default()
        };
        let with = with_identity_claims(&card, &claims).unwrap();
        assert_eq!(
            with.get("schema_version").and_then(|v| v.as_str()),
            Some("v3.5"),
            "monotonic bump must not downgrade v3.5 to {CARD_SCHEMA_VERSION}",
        );
    }

    #[test]
    fn max_schema_version_compares_numerically_not_lexicographically() {
        // Lexicographic compare would call "v3.10" < "v3.2" because '1' <
        // '2'. The helper parses to (major, minor) ints so v3.10 > v3.2.
        assert_eq!(max_schema_version("v3.10", "v3.2"), "v3.10");
        assert_eq!(max_schema_version("v3.2", "v3.10"), "v3.10");
        assert_eq!(max_schema_version("v3.2", "v3.2"), "v3.2");
        assert_eq!(max_schema_version("v4.0", "v3.99"), "v4.0");
    }

    #[test]
    fn max_schema_version_biases_to_parseable_on_malformed_input() {
        // A malformed stored card must not poison the republish: parseable
        // wins, both-malformed keeps `a` (deterministic, no panic).
        assert_eq!(max_schema_version("garbage", "v3.2"), "v3.2");
        assert_eq!(max_schema_version("v3.2", "garbage"), "v3.2");
        assert_eq!(max_schema_version("garbage1", "garbage2"), "garbage1");
    }
}
