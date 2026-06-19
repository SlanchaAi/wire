//! RFC-007 D3.2a: the NIP-01 event codec — wire event ⇄ Nostr event.
//!
//! Wire events are already ~90% Nostr events (`signing.rs`: "Ed25519
//! sign-over-event_id, NIP-01 style"; the kind ranges are NIP-01's). The gap is
//! the wire format vs the exact NIP-01 envelope a public relay verifies. This
//! module is that translation — pure + offline; the WebSocket plumbing that
//! carries these events (`NostrWs` + the `Transport` trait) is the D3.2b slice.
//!
//! ## The two-signature chain
//!
//! A Nostr-delivered wire message carries TWO signatures:
//!
//! 1. **outer (transport)** — the secp256k1 schnorr signature over the NIP-01
//!    `id`, by the agent's D3.1 transport key. This is what a public relay
//!    checks; it proves the event came from that `npub`.
//! 2. **inner (identity)** — the original Ed25519 wire signature, carried intact
//!    inside the Nostr event's `content` (the full signed wire event). This
//!    proves the message came from that `did:wire`.
//!
//! A receiver verifies both, plus the D3.1 binding tying `npub → did:wire`. No
//! single signature is load-bearing alone: the transport sig says "this npub
//! sent it", the binding says "this npub is that did", the inner sig says "that
//! did authored it". The identity anchor stays Ed25519 (ONE-NAME invariant);
//! the npub is transport only.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::nostr_key::{
    NostrKeyError, schnorr_sign_digest, schnorr_verify_digest, xonly_from_secret,
};

/// A NIP-01 event in its wire (relay) JSON shape. All binary fields are
/// lowercase hex, per NIP-01.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrEvent {
    /// 32-byte event id (hex) = sha256 of the NIP-01 serialization.
    pub id: String,
    /// 32-byte x-only secp256k1 public key (hex) — the sender's npub material.
    pub pubkey: String,
    /// Unix seconds.
    pub created_at: i64,
    pub kind: u32,
    /// NIP-01 tags (`[["p","<hex>"], ["wire","did:wire:…"], …]`).
    pub tags: Vec<Vec<String>>,
    /// Event content. For a wire message this is the FULL signed wire event JSON.
    pub content: String,
    /// 64-byte BIP-340 schnorr signature (hex) over `id`.
    pub sig: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NostrEventError {
    /// A required wire field was missing or the wrong type.
    BadField(&'static str),
    /// hex / length decode failure on a NIP-01 field.
    BadEncoding,
    /// The recomputed NIP-01 id did not match the event's `id`.
    IdMismatch,
    /// The schnorr signature did not verify, or a secp key was malformed.
    Sig(NostrKeyError),
    /// The `content` did not parse back into a JSON object (wire event).
    BadContent,
}

impl std::fmt::Display for NostrEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NostrEventError::BadField(s) => write!(f, "wire event missing/invalid field: {s}"),
            NostrEventError::BadEncoding => write!(f, "malformed NIP-01 field encoding"),
            NostrEventError::IdMismatch => write!(f, "NIP-01 id does not match the event body"),
            NostrEventError::Sig(e) => write!(f, "NIP-01 signature: {e}"),
            NostrEventError::BadContent => write!(f, "event content is not a wire event"),
        }
    }
}

/// Compute the 32-byte NIP-01 event id: `sha256` over the canonical NIP-01
/// serialization `[0, pubkey, created_at, kind, tags, content]`.
///
/// NIP-01 mandates a compact (no-whitespace) UTF-8 JSON array that escapes only
/// the minimal set (`"`, `\`, and control chars) and does NOT `\u`-escape
/// non-ASCII. `serde_json`'s default string serialization produces exactly that,
/// so the array built here serializes to the spec-required preimage.
pub fn nostr_event_id(
    pubkey_hex: &str,
    created_at: i64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    let preimage = serde_json::to_string(&json!([0, pubkey_hex, created_at, kind, tags, content]))
        .expect("a JSON array of scalars/strings always serializes");
    let mut h = Sha256::new();
    h.update(preimage.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Parse an RFC-3339 timestamp into unix seconds.
fn unix_from_rfc3339(ts: &str) -> Option<i64> {
    time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

/// Encode a signed wire event as a NIP-01 event, signed by the secp256k1
/// transport key (`nostr_secp_sk`). The full wire event rides in `content` (its
/// inner Ed25519 signature intact); `kind` and `created_at` mirror the wire
/// event; a `["wire", <from_did>]` tag carries the sender's did for traceability.
/// Recipient `p`-tags are added by the transport/routing layer (D3.2b).
pub fn wire_to_nostr(
    wire_event: &Value,
    nostr_secp_sk: &[u8; 32],
) -> Result<NostrEvent, NostrEventError> {
    wire_to_nostr_tagged(wire_event, nostr_secp_sk, &[])
}

/// Encode a signed wire event as a NIP-01 event **addressed to a recipient** —
/// same as [`wire_to_nostr`] but adds a `["p", <peer_xonly_hex>]` tag so the
/// peer's `#p`-filtered relay subscription (see `wire nostr fetch`) selects it.
/// The p-tag is part of the signed `id` preimage, so it must be baked in here,
/// before signing — it cannot be appended after the fact.
pub fn wire_to_nostr_addressed(
    wire_event: &Value,
    nostr_secp_sk: &[u8; 32],
    peer_xonly_hex: &str,
) -> Result<NostrEvent, NostrEventError> {
    let p_tag = vec!["p".to_string(), peer_xonly_hex.to_string()];
    wire_to_nostr_tagged(wire_event, nostr_secp_sk, std::slice::from_ref(&p_tag))
}

/// Shared builder: encode `wire_event` as a NIP-01 event signed by the secp
/// transport key, with `["wire", <from_did>]` first and any `extra_tags`
/// appended (e.g. a recipient `p`-tag) — all covered by the signed id.
fn wire_to_nostr_tagged(
    wire_event: &Value,
    nostr_secp_sk: &[u8; 32],
    extra_tags: &[Vec<String>],
) -> Result<NostrEvent, NostrEventError> {
    let kind = wire_event
        .get("kind")
        .and_then(Value::as_u64)
        .ok_or(NostrEventError::BadField("kind"))? as u32;
    let ts = wire_event
        .get("timestamp")
        .and_then(Value::as_str)
        .ok_or(NostrEventError::BadField("timestamp"))?;
    let created_at = unix_from_rfc3339(ts).ok_or(NostrEventError::BadField("timestamp"))?;

    let xonly = xonly_from_secret(nostr_secp_sk).map_err(NostrEventError::Sig)?;
    let pubkey_hex = hex::encode(xonly);

    let mut tags: Vec<Vec<String>> = Vec::new();
    if let Some(from) = wire_event.get("from").and_then(Value::as_str) {
        tags.push(vec!["wire".to_string(), from.to_string()]);
    }
    tags.extend(extra_tags.iter().cloned());

    // content = the full signed wire event (inner Ed25519 sig preserved).
    let content = serde_json::to_string(wire_event).map_err(|_| NostrEventError::BadContent)?;

    let id = nostr_event_id(&pubkey_hex, created_at, kind, &tags, &content);
    let sig = schnorr_sign_digest(nostr_secp_sk, &id).map_err(NostrEventError::Sig)?;

    Ok(NostrEvent {
        id: hex::encode(id),
        pubkey: pubkey_hex,
        created_at,
        kind,
        tags,
        content,
        sig: hex::encode(sig),
    })
}

/// Verify a NIP-01 event's transport layer and return the inner wire event.
///
/// Checks (fail-closed): (1) the recomputed NIP-01 id matches `ev.id`, (2) the
/// schnorr signature verifies under `ev.pubkey`. Returns the parsed wire event
/// from `content`. The caller MUST still verify the inner Ed25519 wire signature
/// and the D3.1 `npub → did` binding before trusting the message — this function
/// only authenticates the *transport* hop.
pub fn verify_and_decode(ev: &NostrEvent) -> Result<Value, NostrEventError> {
    verify_transport(ev)?;
    let wire: Value = serde_json::from_str(&ev.content).map_err(|_| NostrEventError::BadContent)?;
    if !wire.is_object() {
        return Err(NostrEventError::BadContent);
    }
    Ok(wire)
}

/// Authenticate a Nostr event's transport layer **without** interpreting its
/// `content`: recompute the NIP-01 id and verify the schnorr signature under
/// `ev.pubkey`. Returns the sender's x-only pubkey on success. Used for events
/// whose content is not a wire event — e.g. a NIP-44-encrypted pairing payload
/// (NIP-W1, D3.4) — where `verify_and_decode`'s wire-event parse doesn't apply.
pub fn verify_transport(ev: &NostrEvent) -> Result<[u8; 32], NostrEventError> {
    let pubkey = hex_exact::<32>(&ev.pubkey)?;
    let claimed_id = hex_exact::<32>(&ev.id)?;
    let sig = hex_exact::<64>(&ev.sig)?;
    let id = nostr_event_id(&ev.pubkey, ev.created_at, ev.kind, &ev.tags, &ev.content);
    if id != claimed_id {
        return Err(NostrEventError::IdMismatch);
    }
    schnorr_verify_digest(&pubkey, &id, &sig).map_err(NostrEventError::Sig)?;
    Ok(pubkey)
}

/// Decode a hex string into exactly `N` bytes; wrong length or bad hex →
/// `BadEncoding`.
fn hex_exact<const N: usize>(s: &str) -> Result<[u8; N], NostrEventError> {
    let v = hex::decode(s).map_err(|_| NostrEventError::BadEncoding)?;
    v.as_slice()
        .try_into()
        .map_err(|_| NostrEventError::BadEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr_key::generate_transport_key;
    use crate::signing::{generate_keypair, sign_message_v31};

    fn signed_wire_event() -> Value {
        let (sk, pk) = generate_keypair();
        let msg = json!({
            "v": "3.1",
            "timestamp": "2026-06-14T12:00:00Z",
            "from": "did:wire:slate-lotus-88232017",
            "to": "did:wire:raven-kettle-1234",
            "kind": 1,
            "body": {"content": "hello over nostr"},
        });
        sign_message_v31(&msg, &sk, &pk, "slate-lotus").unwrap()
    }

    #[test]
    fn id_is_sha256_of_canonical_nip01_array() {
        // The preimage is the compact array; the id is its sha256. Lock the
        // serialization shape (compact, no spaces, 0-prefixed).
        let preimage = serde_json::to_string(&json!([
            0,
            "ab",
            1700000000i64,
            1u32,
            [["wire", "x"]],
            "hi"
        ]))
        .unwrap();
        assert_eq!(preimage, r#"[0,"ab",1700000000,1,[["wire","x"]],"hi"]"#);
    }

    #[test]
    fn roundtrip_encode_then_verify() {
        let wire = signed_wire_event();
        let (nsk, _x) = generate_transport_key();
        let ev = wire_to_nostr(&wire, &nsk).unwrap();
        // The transport layer authenticates + hands back the inner wire event.
        let decoded = verify_and_decode(&ev).unwrap();
        assert_eq!(decoded, wire, "inner wire event must survive intact");
        // kind + created_at mirror the wire event.
        assert_eq!(ev.kind, 1);
        assert_eq!(
            ev.created_at,
            unix_from_rfc3339("2026-06-14T12:00:00Z").unwrap()
        );
        // The sender's did rides as a wire tag.
        assert!(ev.tags.iter().any(|t| t[0] == "wire"));
    }

    #[test]
    fn addressed_event_carries_p_tag_and_still_verifies() {
        let wire = signed_wire_event();
        let (nsk, _x) = generate_transport_key();
        let (_psk, peer_x) = generate_transport_key();
        let peer_hex = hex::encode(peer_x);
        let ev = wire_to_nostr_addressed(&wire, &nsk, &peer_hex).unwrap();
        // The recipient p-tag is present (this is what the peer's #p filter selects on).
        assert!(
            ev.tags
                .iter()
                .any(|t| t.first().map(String::as_str) == Some("p") && t.get(1) == Some(&peer_hex)),
            "addressed event must carry a [\"p\", <peer>] tag, tags={:?}",
            ev.tags
        );
        // The wire did-tag still leads (order is stable).
        assert_eq!(ev.tags[0][0], "wire");
        // Transport still authenticates and the inner wire event survives intact —
        // proving the p-tag was part of the signed id, not appended after.
        assert_eq!(verify_and_decode(&ev).unwrap(), wire);
    }

    #[test]
    fn tampered_content_fails_id_check() {
        let wire = signed_wire_event();
        let (nsk, _x) = generate_transport_key();
        let mut ev = wire_to_nostr(&wire, &nsk).unwrap();
        ev.content.push_str("tampered");
        assert_eq!(verify_and_decode(&ev), Err(NostrEventError::IdMismatch));
    }

    #[test]
    fn tampered_id_with_resigned_body_still_needs_matching_sig() {
        // Recompute a valid id for tampered content but keep the old sig → the
        // schnorr check fails (sig was over the original id).
        let wire = signed_wire_event();
        let (nsk, _x) = generate_transport_key();
        let mut ev = wire_to_nostr(&wire, &nsk).unwrap();
        ev.content = serde_json::to_string(&json!({"kind":1,"body":"evil"})).unwrap();
        ev.id = hex::encode(nostr_event_id(
            &ev.pubkey,
            ev.created_at,
            ev.kind,
            &ev.tags,
            &ev.content,
        ));
        // id now matches the tampered content, but the sig doesn't.
        assert_eq!(
            verify_and_decode(&ev),
            Err(NostrEventError::Sig(NostrKeyError::PossessionSig))
        );
    }

    #[test]
    fn forged_pubkey_rejected() {
        // Swap in a different pubkey: the id recompute incorporates it, so either
        // the id mismatches or (if id is recomputed) the sig fails under the new
        // key. Here we recompute id for the swapped key → sig fails.
        let wire = signed_wire_event();
        let (nsk, _x) = generate_transport_key();
        let mut ev = wire_to_nostr(&wire, &nsk).unwrap();
        let (_other_sk, other_x) = generate_transport_key();
        ev.pubkey = hex::encode(other_x);
        ev.id = hex::encode(nostr_event_id(
            &ev.pubkey,
            ev.created_at,
            ev.kind,
            &ev.tags,
            &ev.content,
        ));
        assert_eq!(
            verify_and_decode(&ev),
            Err(NostrEventError::Sig(NostrKeyError::PossessionSig))
        );
    }

    #[test]
    fn missing_kind_or_timestamp_errors() {
        let (nsk, _x) = generate_transport_key();
        assert_eq!(
            wire_to_nostr(&json!({"timestamp":"2026-06-14T12:00:00Z"}), &nsk),
            Err(NostrEventError::BadField("kind"))
        );
        assert_eq!(
            wire_to_nostr(&json!({"kind":1}), &nsk),
            Err(NostrEventError::BadField("timestamp"))
        );
    }

    #[test]
    fn nostr_event_serde_roundtrips_relay_shape() {
        let wire = signed_wire_event();
        let (nsk, _x) = generate_transport_key();
        let ev = wire_to_nostr(&wire, &nsk).unwrap();
        let s = serde_json::to_string(&ev).unwrap();
        // The relay JSON has exactly the NIP-01 keys.
        let v: Value = serde_json::from_str(&s).unwrap();
        for k in [
            "id",
            "pubkey",
            "created_at",
            "kind",
            "tags",
            "content",
            "sig",
        ] {
            assert!(v.get(k).is_some(), "NIP-01 event must carry `{k}`");
        }
        let back: NostrEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ev);
    }
}
