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
//! Security note (load-bearing): this symmetric layer has **no standalone
//! sender/recipient/direction authenticity** — that comes from the outer
//! Ed25519 signature. `open()` MUST NOT be called on an event that has not
//! passed `verify_message_v31`. The `(from, to)` context bound into the HKDF
//! `info` is defence-in-depth (reflection resistance), not a substitute.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::signing::{b64decode, b64encode};

/// The `enc` discriminator for this scheme. Deliberately NOT `nip44.v2`.
pub const ENC_DISCRIMINATOR: &str = "wire-x25519.v1";
/// HKDF-Extract salt — domain-separated from NIP-44's `nip44-v2` so identical
/// plaintext never collides with a real NIP-44 keystream.
const HKDF_SALT: &[u8] = b"wire-x25519-v1";
const VERSION: u8 = 0x02;
const MAX_PLAINTEXT: usize = 65535;
// version(1) + nonce(32) + min-ciphertext(2 + 32) + mac(32)
const MIN_RAW: usize = 1 + 32 + 34 + 32; // 99
// version(1) + nonce(32) + max-ciphertext(2 + 65536) + mac(32)
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

/// `context_info = nonce(32) ‖ from ‖ 0x00 ‖ to` — bound into HKDF-Expand so
/// per-message keys are direction-specific (reflection/cross-direction
/// resistance at the symmetric layer; defence-in-depth behind the signature).
fn context_info(nonce: &[u8; 32], from: &str, to: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + from.len() + 1 + to.len());
    v.extend_from_slice(nonce);
    v.extend_from_slice(from.as_bytes());
    v.push(0u8);
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
pub fn seal(
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
pub fn open(
    conversation_key: &[u8; 32],
    payload_b64: &str,
    from: &str,
    to: &str,
) -> Result<String, EncError> {
    // Reserved future non-base64 encoding guard (matches NIP-44's '#').
    if payload_b64.as_bytes().first() == Some(&b'#') {
        return Err(EncError::BadVersion);
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

    #[test]
    fn calc_padded_len_matches_nip44() {
        assert_eq!(calc_padded_len(1), 32);
        assert_eq!(calc_padded_len(32), 32);
        assert_eq!(calc_padded_len(33), 64);
        assert_eq!(calc_padded_len(100), 128);
        assert_eq!(calc_padded_len(256), 256);
        assert_eq!(calc_padded_len(257), 320);
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
        let mut raw = b64decode(&payload).unwrap();

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

        // bad version
        raw[0] = 0x01;
        assert_eq!(
            open(&ck, &b64encode(&raw), "alice", "bob").unwrap_err(),
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
