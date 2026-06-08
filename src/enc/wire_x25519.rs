//! `wire-x25519.v1` — NIP-44 v2's symmetric envelope over an X25519 IKM.
//!
//! This is the D1 DM-encryption crypto core. It reuses NIP-44 v2's vetted
//! symmetric construction (HKDF → ChaCha20 + HMAC-SHA256, encrypt-then-MAC,
//! length-hiding padding) but derives the conversation key from an **X25519**
//! ECDH (wire identities are Ed25519 → X25519 via the same-curve map) with a
//! **wire-specific HKDF salt** (`wire-x25519-v1`). It is therefore *not*
//! Nostr-wire-compatible NIP-44 — the discriminator is `wire-x25519.v1`, never
//! `nip44.v2`, so a Nostr reader never mis-decrypts a wire body.
//!
//! Design + rationale: `docs/rfc/0006-d1-nip44-design.md`.
//!
//! Security notes (load-bearing):
//! - **No standalone authenticity.** This symmetric layer has no sender/
//!   recipient/direction authenticity — that comes from the outer Ed25519
//!   signature. `open()` MUST NOT be called on an event that has not passed
//!   `verify_message_v31`. The `(from, to)` context bound into the HKDF `info`
//!   is defence-in-depth (reflection resistance), not a substitute. The
//!   integration MUST make verify-before-open structural (a `VerifiedEvent`
//!   newtype or a `decrypt_verified_event` wrapper that re-verifies), not a
//!   call-site convention.
//! - **Canonical identity form (NORMATIVE).** `from`/`to` MUST be the VERBATIM
//!   `from`/`to` DID strings as they appear on the signed event (which the
//!   `event_id`/signature already commit to). Readers MUST decrypt from the
//!   persisted signed line and MUST NOT re-resolve/normalize identities — a
//!   spelling mismatch (bare handle vs `did:wire:h` vs `did:wire:h-<8hex>`)
//!   between seal and open silently breaks decryption (→ `MacFail`).
//! - **No forward secrecy / no post-compromise security.** The conversation
//!   key is static per identity-pair; an Ed25519-seed compromise retroactively
//!   decrypts every message ever exchanged. Treat the seed as a long-term root
//!   secret. (Inherited NIP-44 property; FS would need an epoch/ephemeral input.)
//!
//! INTEGRATION GATE (status as of the wiring PR):
//!   1. [CRITICAL — CLOSED] Verbatim signed-event `from`/`to` are bound INSIDE
//!      [`seal_event_body`] / [`open_event_body`]; raw `seal`/`open` are
//!      `pub(crate)`, so no call site can stringify identities.
//!   2. [CRITICAL — CLOSED] Verify-before-open is STRUCTURAL: `open` is
//!      `pub(crate)`; the only public decrypt path, `open_event_body`, re-runs
//!      `verify_message_v31` first and is opaque on post-MAC failure.
//!   3. [Satisfied by construction] "Never downgrade a dh-capable peer": the
//!      encrypt decision keys off the peer's PINNED, SELF-SIGNED card's
//!      `dh_pubkey` — a MITM cannot strip it (breaks the card signature), and a
//!      legitimate peer's card always carries it (injected in `sign_agent_card`).
//!      A peer omitting its own `dh_pubkey` only de-protects its own inbox.
//!   4. [Partial] `Zeroizing` wraps the long-lived scalar + conversation key in
//!      the event API; the per-message `okm`/chacha/hmac locals in `seal`/`open`
//!      are still bare (short-lived) — a follow-up nicety, not a gate item.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::signing::{b64decode, b64encode};

/// The `enc` discriminator for this scheme. Deliberately NOT `nip44.v2`.
pub const ENC_DISCRIMINATOR: &str = "wire-x25519.v1";
/// HKDF-Extract salt — domain-separated from NIP-44's `nip44-v2` so identical
/// plaintext never collides with a real NIP-44 keystream.
const HKDF_SALT: &[u8] = b"wire-x25519-v1";
const VERSION: u8 = 0x02;
const MAX_PLAINTEXT: usize = 65535;
// version(1) + nonce(32) + min-ciphertext(2-byte len prefix + 32 padded) + mac(32)
const MIN_RAW: usize = 1 + 32 + 34 + 32; // 99
// version(1) + nonce(32) + max-ciphertext(2-byte len prefix + 65536 padded) + mac(32)
const MAX_RAW: usize = 1 + 32 + (2 + 65536) + 32; // 65603

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncError {
    #[error("x25519 produced an all-zero shared secret (low-order/contributory point)")]
    ZeroSharedSecret,
    #[error("plaintext length {0} out of range 1..=65535")]
    BadLength(usize),
    #[error("base64 decode failed")]
    BadBase64,
    #[error("payload length out of bounds")]
    BadPayloadLen,
    #[error("unsupported version")]
    BadVersion,
    #[error("mac verification failed")]
    MacFail,
    #[error("invalid padding")]
    BadPadding,
    #[error("plaintext is not valid utf-8")]
    BadUtf8,
}

// ---------------------------------------------------------------- key derivation

/// Derive the X25519 secret scalar from the 32-byte Ed25519 *seed*:
/// `clamp(SHA-512(seed)[0..32])` — the exact scalar Ed25519 signs with
/// (RFC 8032 §5.1.5 expansion + RFC 7748 §5 clamping). Same-curve conversion,
/// not a cross-curve derivation.
pub fn x25519_scalar_from_ed25519_seed(seed: &[u8; 32]) -> [u8; 32] {
    let h = Sha512::digest(seed);
    let mut s = [0u8; 32];
    s.copy_from_slice(&h[0..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    s
}

/// The X25519 public key corresponding to an Ed25519 seed (for the card's
/// `dh_pubkey`). `base · clamp(SHA-512(seed)[0..32])`.
pub fn x25519_pub_from_ed25519_seed(seed: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(x25519_scalar_from_ed25519_seed(seed));
    PublicKey::from(&secret).to_bytes()
}

/// `conversation_key = HKDF-Extract(salt = wire-x25519-v1, IKM = X25519(our_scalar, peer_pub))`.
/// Rejects the all-zero shared secret (RFC 7748 §6.1 contributory-behaviour guard)
/// before key material is derived. Symmetric: `conv(a, B) == conv(b, A)`.
pub fn derive_conversation_key(
    our_scalar: &[u8; 32],
    peer_pub: &[u8; 32],
) -> Result<[u8; 32], EncError> {
    let secret = StaticSecret::from(*our_scalar);
    let peer = PublicKey::from(*peer_pub);
    let shared = secret.diffie_hellman(&peer);
    let shared_bytes = shared.to_bytes();
    if shared_bytes == [0u8; 32] {
        return Err(EncError::ZeroSharedSecret);
    }
    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), &shared_bytes);
    let mut ck = [0u8; 32];
    ck.copy_from_slice(&prk);
    Ok(ck)
}

// ------------------------------------------------------------ per-message keys

/// `context_info = nonce(32) ‖ u16_be(len from) ‖ from ‖ u16_be(len to) ‖ to`
/// — bound into HKDF-Expand so per-message keys are direction-specific
/// (reflection/cross-direction resistance at the symmetric layer; defence-in-
/// depth behind the signature). Length-prefixed (not 0x00-separated) so the
/// framing is injective regardless of the identity charset — the bound `from`/
/// `to` are full signed-event DIDs, which contain `:` and `-` (review fix #6/#9).
fn context_info(nonce: &[u8; 32], from: &str, to: &str) -> Vec<u8> {
    // The u16 length-prefix is injective only for identities ≤ 65535 bytes.
    // wire DIDs are <100 bytes; assert in dev so a future long identity can't
    // silently truncate the cast and break the framing (review re-sweep #3).
    debug_assert!(
        from.len() <= u16::MAX as usize && to.len() <= u16::MAX as usize,
        "identity too long for u16 length-prefix framing"
    );
    let mut v = Vec::with_capacity(32 + 2 + from.len() + 2 + to.len());
    v.extend_from_slice(nonce);
    v.extend_from_slice(&(from.len() as u16).to_be_bytes());
    v.extend_from_slice(from.as_bytes());
    v.extend_from_slice(&(to.len() as u16).to_be_bytes());
    v.extend_from_slice(to.as_bytes());
    v
}

/// HKDF-Expand the conversation key into (chacha_key[32], chacha_nonce[12], hmac_key[32]).
fn message_keys(conversation_key: &[u8; 32], info: &[u8]) -> ([u8; 32], [u8; 12], [u8; 32]) {
    let hk = Hkdf::<Sha256>::from_prk(conversation_key).expect("32-byte prk is valid");
    let mut okm = [0u8; 76];
    hk.expand(info, &mut okm).expect("76 < 255*32");
    let mut chacha_key = [0u8; 32];
    chacha_key.copy_from_slice(&okm[0..32]);
    let mut chacha_nonce = [0u8; 12];
    chacha_nonce.copy_from_slice(&okm[32..44]);
    let mut hmac_key = [0u8; 32];
    hmac_key.copy_from_slice(&okm[44..76]);
    (chacha_key, chacha_nonce, hmac_key)
}

// ------------------------------------------------------------------- padding

/// NIP-44 length-hiding padded length for `unpadded` (1..=65535).
fn calc_padded_len(unpadded: usize) -> usize {
    if unpadded <= 32 {
        return 32;
    }
    let l = unpadded as u32;
    // 1 << (floor(log2(L-1)) + 1) == 1 << (32 - (L-1).leading_zeros())
    let next_power = 1usize << (32 - (l - 1).leading_zeros());
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * (((unpadded - 1) / chunk) + 1)
}

/// `u16_be(len) ‖ plaintext ‖ zeros` to `2 + calc_padded_len(len)`.
fn pad(pt: &[u8]) -> Result<Vec<u8>, EncError> {
    let l = pt.len();
    if !(1..=MAX_PLAINTEXT).contains(&l) {
        return Err(EncError::BadLength(l));
    }
    let total = 2 + calc_padded_len(l);
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(l as u16).to_be_bytes());
    buf.extend_from_slice(pt);
    buf.resize(total, 0);
    Ok(buf)
}

/// Inverse of [`pad`]. All three checks mandatory (length-tamper / oracle guard).
fn unpad(buf: &[u8]) -> Result<Vec<u8>, EncError> {
    if buf.len() < 2 {
        return Err(EncError::BadPadding);
    }
    let l = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let end = 2usize.checked_add(l).ok_or(EncError::BadPadding)?;
    if l == 0 || buf.len() < end {
        return Err(EncError::BadPadding);
    }
    let out = &buf[2..end];
    if out.len() != l || buf.len() != 2 + calc_padded_len(l) {
        return Err(EncError::BadPadding);
    }
    Ok(out.to_vec())
}

// ------------------------------------------------------------------ seal / open

/// Encrypt `plaintext` for the conversation, bound to `(from, to)`. Returns the
/// base64 payload `version(0x02) ‖ nonce(32) ‖ ciphertext ‖ mac(32)`.
///
/// `pub(crate)`: the only PUBLIC entry is [`seal_event_body`], which binds
/// `from`/`to` from the event itself (CRITICAL canonicalization gate).
pub(crate) fn seal(
    conversation_key: &[u8; 32],
    plaintext: &[u8],
    from: &str,
    to: &str,
) -> Result<String, EncError> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let (chacha_key, chacha_nonce, hmac_key) =
        message_keys(conversation_key, &context_info(&nonce, from, to));

    let mut ct = pad(plaintext)?;
    let mut cipher = ChaCha20::new(
        chacha20::Key::from_slice(&chacha_key),
        chacha20::Nonce::from_slice(&chacha_nonce),
    );
    cipher.apply_keystream(&mut ct);

    let mut mac = HmacSha256::new_from_slice(&hmac_key).expect("hmac accepts any key length");
    mac.update(&nonce);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(1 + 32 + ct.len() + 32);
    payload.push(VERSION);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ct);
    payload.extend_from_slice(&tag);
    Ok(b64encode(&payload))
}

/// Decrypt a `wire-x25519.v1` payload. MAC is verified (constant-time) BEFORE
/// decryption. Caller MUST have verified the outer event signature first.
///
/// `pub(crate)`: the only PUBLIC entry is [`open_event_body`], which re-runs
/// `verify_message_v31` (structural verify-before-open gate) and binds
/// `from`/`to` from the verified event.
pub(crate) fn open(
    conversation_key: &[u8; 32],
    payload_b64: &str,
    from: &str,
    to: &str,
) -> Result<String, EncError> {
    // Reserved future non-base64 encoding guard (matches NIP-44's '#').
    if payload_b64.as_bytes().first() == Some(&b'#') {
        return Err(EncError::BadVersion);
    }
    // Bound the INPUT length before decoding (decode-bomb / OOM guard, review
    // fix #4): base64 allocates ~3/4 of the input up front, so cap the encoded
    // string at the max-payload's base64 size before paying that allocation.
    if payload_b64.len() > MAX_RAW * 4 / 3 + 4 {
        return Err(EncError::BadPayloadLen);
    }
    let raw = b64decode(payload_b64).map_err(|_| EncError::BadBase64)?;
    if !(MIN_RAW..=MAX_RAW).contains(&raw.len()) {
        return Err(EncError::BadPayloadLen);
    }
    if raw[0] != VERSION {
        return Err(EncError::BadVersion);
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&raw[1..33]);
    let mac_start = raw.len() - 32;
    let ct = &raw[33..mac_start];
    let tag = &raw[mac_start..];

    let (chacha_key, chacha_nonce, hmac_key) =
        message_keys(conversation_key, &context_info(&nonce, from, to));

    let mut mac = HmacSha256::new_from_slice(&hmac_key).expect("hmac accepts any key length");
    mac.update(&nonce);
    mac.update(ct);
    mac.verify_slice(tag).map_err(|_| EncError::MacFail)?; // constant-time, BEFORE decrypt

    let mut buf = ct.to_vec();
    let mut cipher = ChaCha20::new(
        chacha20::Key::from_slice(&chacha_key),
        chacha20::Nonce::from_slice(&chacha_nonce),
    );
    cipher.apply_keystream(&mut buf);
    let out = unpad(&buf)?;
    String::from_utf8(out).map_err(|_| EncError::BadUtf8)
}

// ----------------------------------------------------------- event-level API
// The ONLY public entry points. They close the two CRITICAL integration-gate
// items structurally: (1) `from`/`to` are read from the event itself, never
// stringified by a caller; (2) `open_event_body` re-runs `verify_message_v31`
// before decrypting, so decryption cannot run on an unverified event.

/// Base64 X25519 public key for the agent card's `dh_pubkey`, derived from the
/// Ed25519 seed (same-curve map). Emitted on the card at build/sign time.
pub fn self_dh_pubkey_b64(seed: &[u8; 32]) -> String {
    b64encode(&x25519_pub_from_ed25519_seed(seed))
}

fn decode_dh(b64: &str) -> Option<[u8; 32]> {
    let v = b64decode(b64).ok()?;
    let arr: [u8; 32] = v.try_into().ok()?;
    Some(arr)
}

/// Read a peer's pinned `dh_pubkey` from the trust map (`agents[<handle>].card`).
/// `None` ⇒ legacy/unenrolled peer ⇒ caller falls back to plaintext.
pub fn peer_dh_pubkey(trust: &Value, peer_did_or_handle: &str) -> Option<[u8; 32]> {
    let handle = crate::agent_card::display_handle_from_did(peer_did_or_handle);
    let b64 = trust
        .get("agents")?
        .get(handle)?
        .get("card")?
        .get("dh_pubkey")?
        .as_str()?;
    decode_dh(b64)
}

/// Seal an outbound event's `body` IN PLACE, binding the event's own `from`/`to`
/// (CRITICAL #1: identities are read here, never stringified by a caller). Sets
/// `enc = "wire-x25519.v1"` and replaces `body` with `{"ct": <base64>}`. Call
/// only when the peer is dh-capable (see [`peer_dh_pubkey`]); MUST run BEFORE
/// the event is signed so the signature covers the ciphertext body.
pub fn seal_event_body(
    event: &mut Value,
    peer_dh_pubkey: &[u8; 32],
    our_seed: &[u8; 32],
) -> anyhow::Result<()> {
    let from = event
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("event missing `from`"))?
        .to_string();
    let to = event
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("encryption requires a `to` recipient on the event"))?
        .to_string();
    let our_scalar = Zeroizing::new(x25519_scalar_from_ed25519_seed(our_seed));
    let ck = Zeroizing::new(
        derive_conversation_key(&our_scalar, peer_dh_pubkey)
            .map_err(|e| anyhow::anyhow!("derive conversation key: {e}"))?,
    );
    let pt = serde_json::to_vec(event.get("body").unwrap_or(&Value::Null))?;
    let ct = seal(&ck, &pt, &from, &to).map_err(|e| anyhow::anyhow!("seal: {e}"))?;
    let obj = event
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("event is not a JSON object"))?;
    obj.insert("enc".into(), json!(ENC_DISCRIMINATOR));
    obj.insert("body".into(), json!({ "ct": ct }));
    Ok(())
}

/// VERIFY-GATED decrypt of an inbound event's body.
/// - `Ok(None)` — not `enc`-bearing (plaintext) OR an `enc` scheme we don't know;
/// - `Ok(Some(body))` — the decrypted body `Value`;
/// - `Err(_)` — signature verification failed, peer has no `dh_pubkey`, or
///   decryption failed (opaque — post-MAC errors are not distinguishable, no oracle).
///
/// CRITICAL #2: re-runs `verify_message_v31` before any decryption, and binds
/// `from`/`to` from the verified event. Decryption is unreachable for an
/// unverified event by construction (`open` is `pub(crate)`).
pub fn open_event_body(
    event: &Value,
    trust: &Value,
    our_seed: &[u8; 32],
) -> anyhow::Result<Option<Value>> {
    match event.get("enc").and_then(Value::as_str) {
        Some(ENC_DISCRIMINATOR) => {}
        Some(_) | None => return Ok(None),
    }
    // STRUCTURAL verify-before-open gate.
    crate::signing::verify_message_v31(event, trust)
        .map_err(|e| anyhow::anyhow!("refusing to decrypt unverified event: {e}"))?;

    let from = event
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("event missing `from`"))?;
    let to = event
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("encrypted event missing `to`"))?;
    let ct = event
        .get("body")
        .and_then(|b| b.get("ct"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("enc event body missing `ct`"))?;

    let peer_dh = peer_dh_pubkey(trust, from)
        .ok_or_else(|| anyhow::anyhow!("sender has no pinned dh_pubkey — cannot decrypt"))?;
    let our_scalar = Zeroizing::new(x25519_scalar_from_ed25519_seed(our_seed));
    let ck = Zeroizing::new(
        derive_conversation_key(&our_scalar, &peer_dh)
            .map_err(|e| anyhow::anyhow!("derive conversation key: {e}"))?,
    );
    // Opaque on failure (verify already passed → a failure here is key-mismatch
    // or corruption, never an attacker-driven oracle).
    let pt = open(&ck, ct, from, to).map_err(|_| anyhow::anyhow!("decryption failed"))?;
    let body: Value = serde_json::from_str(&pt)
        .map_err(|_| anyhow::anyhow!("decrypted body is not valid json"))?;
    Ok(Some(body))
}

/// Best-effort load of our Ed25519 seed for read-surface decryption. `None`
/// when uninitialized — callers then render ciphertext as-is.
pub fn self_seed_for_read() -> Option<[u8; 32]> {
    crate::config::read_private_key()
        .ok()
        .and_then(|v| v.get(..32).and_then(|s| <[u8; 32]>::try_from(s).ok()))
}

/// Return a copy of `event` with its body decrypted IF it is enc-bearing and
/// verifies (verify-gated via [`open_event_body`]); decrypted events are marked
/// `dec: true`. Otherwise the event is returned unchanged. For the human/agent
/// READ surfaces (`wire tail`, `wire_tail`, the `wire://inbox` resource). The
/// persisted JSONL is never touched — this only shapes the response.
pub fn decrypt_event_for_read(event: &Value, trust: &Value, seed: &[u8; 32]) -> Value {
    if event.get("enc").and_then(Value::as_str) == Some(ENC_DISCRIMINATOR)
        && let Ok(Some(plain)) = open_event_body(event, trust, seed)
    {
        let mut e = event.clone();
        if let Some(obj) = e.as_object_mut() {
            obj.insert("body".into(), plain);
            obj.insert("dec".into(), json!(true));
        }
        return e;
    }
    event.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two fixed seeds → deterministic identities for the golden + symmetry tests.
    const SEED_A: [u8; 32] = [1u8; 32];
    const SEED_B: [u8; 32] = [2u8; 32];

    fn conv(seed_self: &[u8; 32], seed_peer: &[u8; 32]) -> [u8; 32] {
        let our = x25519_scalar_from_ed25519_seed(seed_self);
        let peer_pub = x25519_pub_from_ed25519_seed(seed_peer);
        derive_conversation_key(&our, &peer_pub).unwrap()
    }

    fn hex_to_32(h: &str) -> [u8; 32] {
        let v = hex::decode(h).expect("valid hex");
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn round_trips_with_production_did_identity_form() {
        // Canonicalization guard (review findings #1/#2): the bound `from`/`to`
        // are the FULL signed-event DIDs (`did:wire:<handle>-<8hex>`), which
        // contain `:` and `-`. Exercise that production spelling, not "alice".
        let ck = conv(&SEED_A, &SEED_B);
        let from = "did:wire:alice-1b1b58dd";
        let to = "did:wire:bob-60346e7c";
        let payload = seal(&ck, b"production-form message", from, to).unwrap();
        assert_eq!(
            open(&ck, &payload, from, to).unwrap(),
            "production-form message"
        );
        // A different DID spelling for the same party fails — this is exactly
        // the silent-decryption-outage the integration MUST avoid by binding
        // the verbatim event DID on both ends.
        assert_eq!(
            open(&ck, &payload, "alice", to).unwrap_err(),
            EncError::MacFail
        );
    }

    #[test]
    fn oversized_input_rejected_without_large_alloc() {
        // Decode-bomb guard (review finding #4): a multi-MB payload is rejected
        // by the pre-decode length cap, not after allocating a ~3/4-size Vec.
        let ck = conv(&SEED_A, &SEED_B);
        let bomb = "A".repeat(10_000_000);
        assert_eq!(
            open(&ck, &bomb, "a", "b").unwrap_err(),
            EncError::BadPayloadLen
        );
    }

    #[test]
    fn truncated_payload_rejected() {
        let ck = conv(&SEED_A, &SEED_B);
        let payload = seal(&ck, b"hi", "a", "b").unwrap();
        let raw = b64decode(&payload).unwrap();
        let truncated = b64encode(&raw[..raw.len() - 40]); // below MIN_RAW
        assert_eq!(
            open(&ck, &truncated, "a", "b").unwrap_err(),
            EncError::BadPayloadLen
        );
    }

    #[test]
    fn zero_shared_secret_is_rejected() {
        // The all-zero u-coordinate is a low-order Curve25519 point; X25519
        // against it yields an all-zero shared secret. Must be rejected before
        // key derivation (C3 / RFC 7748 §6.1) — coverage for the guard path.
        let our = x25519_scalar_from_ed25519_seed(&SEED_A);
        assert_eq!(
            derive_conversation_key(&our, &[0u8; 32]).unwrap_err(),
            EncError::ZeroSharedSecret
        );
    }

    #[test]
    fn decode_bomb_cap_boundary() {
        // One char over the base64 ceiling for a max payload → rejected pre-decode;
        // a legitimately-sized payload still round-trips (the cap is not too tight).
        let ck = conv(&SEED_A, &SEED_B);
        let over = "A".repeat(MAX_RAW * 4 / 3 + 5);
        assert_eq!(
            open(&ck, &over, "a", "b").unwrap_err(),
            EncError::BadPayloadLen
        );
        // a real near-max payload (~64KB plaintext) seals + opens under the cap
        let big = vec![b'z'; 60000];
        let payload = seal(&ck, &big, "a", "b").unwrap();
        assert!(
            payload.len() < MAX_RAW * 4 / 3 + 5,
            "real payload is under the cap"
        );
        assert_eq!(open(&ck, &payload, "a", "b").unwrap().len(), 60000);
    }

    #[test]
    fn calc_padded_len_conformance_nip44_vectors() {
        // EXTERNAL ANCHOR — the official NIP-44 v2 `calc_padded_len` vectors
        // (github.com/paulmillr/nip44 nip44.vectors.json). Salt/curve/info-
        // independent, so they apply verbatim. Catches a wrong-but-self-
        // consistent padding formula that round-trip + golden would miss
        // (review finding #5a). Plus a couple of small cases (1, 32).
        let nip44: &[(usize, usize)] = &[
            (1, 32),
            (16, 32),
            (32, 32),
            (33, 64),
            (37, 64),
            (45, 64),
            (49, 64),
            (64, 64),
            (65, 96),
            (100, 128),
            (111, 128),
            (200, 224),
            (250, 256),
            (320, 320),
            (383, 384),
            (384, 384),
            (400, 448),
            (500, 512),
            (512, 512),
            (515, 640),
            (700, 768),
            (800, 896),
            (900, 1024),
            (1020, 1024),
            (65536, 65536),
        ];
        for &(unpadded, padded) in nip44 {
            assert_eq!(
                calc_padded_len(unpadded),
                padded,
                "calc_padded_len({unpadded})"
            );
        }
    }

    #[test]
    fn message_keys_conformance_nip44_vector() {
        // EXTERNAL ANCHOR for the HKDF-Expand split (review finding #5b):
        // the official NIP-44 v2 `get_message_keys` vector. NIP-44 derives
        // per-message keys as HKDF-Expand(prk=conversation_key, info=nonce, 76)
        // split 32/12/32. Our `message_keys` takes arbitrary `info`; feeding
        // info = the 32-byte nonce reproduces NIP-44 exactly, anchoring the
        // okm offsets to an external authority (catches an okm[40..72] bug that
        // self-consistent tests cannot).
        let conversation_key =
            hex_to_32("a1a3d60f3470a8612633924e91febf96dc5366ce130f658b1f0fc652c20b3b54");
        let nonce = hex_to_32("e1e6f880560d6d149ed83dcc7e5861ee62a5ee051f7fde9975fe5d25d2a02d72");
        let (chacha_key, chacha_nonce, hmac_key) = message_keys(&conversation_key, &nonce);
        assert_eq!(
            hex::encode(chacha_key),
            "f145f3bed47cb70dbeaac07f3a3fe683e822b3715edb7c4fe310829014ce7d76"
        );
        assert_eq!(hex::encode(chacha_nonce), "c4ad129bb01180c0933a160c");
        assert_eq!(
            hex::encode(hmac_key),
            "027c1db445f05e2eee864a0975b0ddef5b7110583c8c192de3732571ca5838c4"
        );
    }

    #[test]
    fn conversation_key_is_symmetric() {
        // conv(a, B) == conv(b, A) — role-independent.
        assert_eq!(conv(&SEED_A, &SEED_B), conv(&SEED_B, &SEED_A));
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(
            x25519_pub_from_ed25519_seed(&SEED_A),
            x25519_pub_from_ed25519_seed(&SEED_A)
        );
    }

    #[test]
    fn golden_seed_to_pub_and_conv_key() {
        // GOLDEN VECTOR — locks the §1a Ed25519→X25519 derivation + the
        // X25519+wire-salt conversation key so a dalek-version bump or a
        // divergent re-implementation fails IN CI, not silently in the field.
        // (A wrong-but-stable derivation passes symmetry/round-trip; only a
        // committed literal catches it.)
        let pub_a = x25519_pub_from_ed25519_seed(&SEED_A);
        let pub_b = x25519_pub_from_ed25519_seed(&SEED_B);
        assert_eq!(hex::encode(pub_a), GOLDEN_PUB_A);
        assert_eq!(hex::encode(pub_b), GOLDEN_PUB_B);
        assert_eq!(hex::encode(conv(&SEED_A, &SEED_B)), GOLDEN_CONV_AB);
    }

    #[test]
    fn round_trip_across_lengths() {
        let ck = conv(&SEED_A, &SEED_B);
        for &len in &[1usize, 31, 32, 33, 256, 257, 1000, 65535] {
            let pt = "x".repeat(len);
            let payload = seal(&ck, pt.as_bytes(), "alice", "bob").unwrap();
            let got = open(&ck, &payload, "alice", "bob").unwrap();
            assert_eq!(got, pt, "round-trip failed at len {len}");
        }
    }

    #[test]
    fn direction_binding_rejects_reflection() {
        // A→B ciphertext opened as B→A (swapped context) MUST fail the MAC,
        // even with the same (symmetric) conversation key.
        let ck = conv(&SEED_A, &SEED_B);
        let payload = seal(&ck, b"secret", "alice", "bob").unwrap();
        assert_eq!(
            open(&ck, &payload, "bob", "alice").unwrap_err(),
            EncError::MacFail
        );
    }

    #[test]
    fn tamper_is_rejected_before_decrypt() {
        let ck = conv(&SEED_A, &SEED_B);
        let payload = seal(&ck, b"hello world", "alice", "bob").unwrap();
        let raw = b64decode(&payload).unwrap();

        // flip a ciphertext byte
        let mut t = raw.clone();
        t[40] ^= 0x01;
        assert_eq!(
            open(&ck, &b64encode(&t), "alice", "bob").unwrap_err(),
            EncError::MacFail
        );

        // flip a nonce byte
        let mut t = raw.clone();
        t[1] ^= 0x01;
        assert_eq!(
            open(&ck, &b64encode(&t), "alice", "bob").unwrap_err(),
            EncError::MacFail
        );

        // flip a mac byte
        let n = raw.len();
        let mut t = raw.clone();
        t[n - 1] ^= 0x01;
        assert_eq!(
            open(&ck, &b64encode(&t), "alice", "bob").unwrap_err(),
            EncError::MacFail
        );

        // bad version (clone, not in-place — avoids order-coupling footgun)
        let mut t = raw.clone();
        t[0] = 0x01;
        assert_eq!(
            open(&ck, &b64encode(&t), "alice", "bob").unwrap_err(),
            EncError::BadVersion
        );
    }

    #[test]
    fn plaintext_bounds_enforced() {
        let ck = conv(&SEED_A, &SEED_B);
        assert_eq!(
            seal(&ck, b"", "a", "b").unwrap_err(),
            EncError::BadLength(0)
        );
        let too_big = vec![0u8; 65536];
        assert_eq!(
            seal(&ck, &too_big, "a", "b").unwrap_err(),
            EncError::BadLength(65536)
        );
    }

    #[test]
    fn wrong_conversation_key_fails() {
        let ck = conv(&SEED_A, &SEED_B);
        let payload = seal(&ck, b"secret", "alice", "bob").unwrap();
        let other = x25519_scalar_from_ed25519_seed(&[9u8; 32]);
        let wrong =
            derive_conversation_key(&other, &x25519_pub_from_ed25519_seed(&SEED_B)).unwrap();
        assert_eq!(
            open(&wrong, &payload, "alice", "bob").unwrap_err(),
            EncError::MacFail
        );
    }

    #[test]
    fn event_level_round_trip_and_verify_gate() {
        // End-to-end integration proof of the public event API: A seals a body
        // for B, signs it; B verify-gates + decrypts; tamper is refused by the
        // gate; a plaintext event passes through as None.
        use crate::signing::{generate_keypair, make_key_id, sign_message_v31};

        let (a_seed, a_pk) = generate_keypair();
        let (b_seed, b_pk) = generate_keypair();
        let a_did = "did:wire:alice-1b1b58dd";
        let b_did = "did:wire:bob-60346e7c";
        let b_dh = x25519_pub_from_ed25519_seed(&b_seed);
        let a_dh = x25519_pub_from_ed25519_seed(&a_seed);
        let _ = &b_pk;

        // B's trust pins A: A's verify key + A's card (carrying A's dh_pubkey).
        let trust_b = json!({"agents": {"alice": {
            "public_keys": [{"key_id": make_key_id("alice", &a_pk), "key": b64encode(&a_pk), "active": true}],
            "card": {"dh_pubkey": b64encode(&a_dh)},
        }}});

        // A: build → seal (binds the event's own from/to) → sign.
        let mut event = json!({
            "from": a_did, "to": b_did, "type": "decision", "kind": 1000,
            "body": "secret hello",
        });
        seal_event_body(&mut event, &b_dh, &a_seed).unwrap();
        assert_eq!(event["enc"], json!(ENC_DISCRIMINATOR));
        assert!(
            event["body"]["ct"].is_string(),
            "body replaced with ciphertext"
        );
        assert_ne!(event["body"], json!("secret hello"));
        let signed = sign_message_v31(&event, &a_seed, &a_pk, "alice").unwrap();

        // B: verify-gated decrypt recovers the plaintext body.
        assert_eq!(
            open_event_body(&signed, &trust_b, &b_seed).unwrap(),
            Some(json!("secret hello"))
        );

        // Verify-gate: tampering the ciphertext breaks the signature → refused
        // BEFORE any decrypt attempt.
        let mut tampered = signed.clone();
        tampered["body"]["ct"] = json!("AAAAAAAA");
        assert!(open_event_body(&tampered, &trust_b, &b_seed).is_err());

        // Plaintext event → None (caller renders the body as-is).
        let plain = json!({"from": a_did, "to": b_did, "body": "hi"});
        assert_eq!(open_event_body(&plain, &trust_b, &b_seed).unwrap(), None);
    }

    #[test]
    fn full_card_pin_seal_read_pipeline() {
        // Exercises the REAL integration chain end-to-end (no WIRE_HOME I/O):
        // build+sign cards (sign_agent_card injects dh_pubkey) → pin via
        // add_agent_card_pin → seal+sign a message → read via the public
        // read-surface helper → plaintext. Catches breakage across
        // agent_card + trust + enc that the in-module unit tests can't.
        use crate::agent_card::{build_agent_card, card_dh_pubkey, sign_agent_card};
        use crate::signing::{generate_keypair, sign_message_v31};
        use crate::trust::{add_agent_card_pin, empty_trust};

        let (a_seed, a_pk) = generate_keypair();
        let (b_seed, b_pk) = generate_keypair();
        let a_card = sign_agent_card(&build_agent_card("alice", &a_pk, None, None, None), &a_seed);
        let _b_card = sign_agent_card(&build_agent_card("bob", &b_pk, None, None, None), &b_seed);

        // sign_agent_card injected dh_pubkey, derived from the seed.
        assert_eq!(
            card_dh_pubkey(&a_card).unwrap(),
            b64encode(&x25519_pub_from_ed25519_seed(&a_seed))
        );

        // B pins A's full card (carrying A's dh_pubkey + verify key).
        let mut trust_b = empty_trust();
        add_agent_card_pin(&mut trust_b, &a_card, Some("VERIFIED"));

        // A seals + signs a message to B (B's dh from B's card/derivation).
        let a_handle = a_card["handle"].as_str().unwrap().to_string();
        let a_did = a_card["did"].as_str().unwrap().to_string();
        let b_did = _b_card["did"].as_str().unwrap().to_string();
        let b_dh = x25519_pub_from_ed25519_seed(&b_seed);
        let mut event = json!({
            "from": a_did, "to": b_did, "type": "decision", "kind": 1000,
            "body": "pipeline secret",
        });
        seal_event_body(&mut event, &b_dh, &a_seed).unwrap();
        let signed = sign_message_v31(&event, &a_seed, &a_pk, &a_handle).unwrap();

        // B reads it via the public read-surface helper → decrypted plaintext.
        let viewed = decrypt_event_for_read(&signed, &trust_b, &b_seed);
        assert_eq!(viewed["body"], json!("pipeline secret"));
        assert_eq!(viewed["dec"], json!(true));
    }

    // Golden literals — captured from this implementation; any drift fails CI.
    const GOLDEN_PUB_A: &str = "1b1b58dd50ea14b60da17b790cd02754d970c9bab864ebb3c0f3016fe51d3f57";
    const GOLDEN_PUB_B: &str = "60346e7c911a5f6ba154129174cafe75b294ac3bbd5549632f48cec6266f8410";
    const GOLDEN_CONV_AB: &str = "9ade86510fe31aa30c0a583c7282a2cce1447103f2cd70e165489ac5b09dbd2e";

    #[test]
    #[ignore = "run with --ignored --nocapture to (re)capture golden literals"]
    fn print_golden() {
        eprintln!(
            "PUB_A={}",
            hex::encode(x25519_pub_from_ed25519_seed(&SEED_A))
        );
        eprintln!(
            "PUB_B={}",
            hex::encode(x25519_pub_from_ed25519_seed(&SEED_B))
        );
        eprintln!("CONV_AB={}", hex::encode(conv(&SEED_A, &SEED_B)));
    }
}
