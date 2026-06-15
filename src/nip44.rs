//! RFC-007 D3.3: NIP-44 v2 encrypted payloads — the Nostr DM encryption.
//!
//! Consumes RFC-006's reserved `enc` slot with a *vetted* spec instead of
//! bespoke crypto (the `reuse > build` principle). NIP-44 v2 encrypts between
//! two secp256k1 keys — here, the D3.1 Nostr **transport** keys — so a wire DM
//! sent over Nostr is confidential to the relay.
//!
//! ## Construction (NIP-44 v2)
//!
//! - **conversation key** = `HKDF-Extract(salt = "nip44-v2", IKM = ecdh_x)` where
//!   `ecdh_x` is the x-coordinate of the secp256k1 ECDH point between my secret
//!   and their (x-only, even-y) public key. Symmetric: both parties derive the
//!   same key.
//! - **per-message keys** = `HKDF-Expand(conversation_key, info = nonce, 76)` →
//!   `chacha_key[32] ‖ chacha_nonce[12] ‖ hmac_key[32]`.
//! - **padding** — the plaintext is length-prefixed (2-byte BE) and zero-padded
//!   to a power-of-two-ish boundary so ciphertext length leaks only a coarse
//!   bucket, not the exact message size.
//! - **cipher** = ChaCha20 (stream) over the padded plaintext.
//! - **MAC** = `HMAC-SHA256(hmac_key, nonce ‖ ciphertext)`, verified in constant
//!   time before decryption.
//! - **payload** = `base64(0x02 ‖ nonce[32] ‖ ciphertext ‖ mac[32])`.
//!
//! Scope: this is the cryptographic core (encrypt/decrypt + conversation-key
//! derivation), faithful to the written spec and round-trip / symmetry / tamper
//! tested. **Cross-implementation interop is NOT yet proven against the official
//! `nip44.vectors.json`** — that vector test is a required follow-up before
//! claiming wire DMs interoperate with other NIP-44 implementations (flagged so
//! the gap is explicit, not silent).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secp256k1::{Parity, PublicKey, SecretKey, XOnlyPublicKey};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const VERSION: u8 = 0x02;
const SALT: &[u8] = b"nip44-v2";
const MIN_PLAINTEXT: usize = 1;
const MAX_PLAINTEXT: usize = 65535;

#[derive(Debug, PartialEq, Eq)]
pub enum Nip44Error {
    /// A secp256k1 key was malformed, or ECDH failed.
    Key,
    /// Plaintext length is outside `1..=65535`.
    PlaintextLen,
    /// Payload base64 / structure / version was invalid.
    BadPayload,
    /// The MAC did not verify (wrong key or tampered ciphertext).
    Mac,
    /// The decrypted padding was malformed.
    Padding,
    /// Decrypted bytes were not valid UTF-8.
    Utf8,
}

impl std::fmt::Display for Nip44Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Nip44Error::Key => "invalid secp256k1 key / ECDH failure",
            Nip44Error::PlaintextLen => "plaintext length out of range (1..=65535)",
            Nip44Error::BadPayload => "malformed NIP-44 payload",
            Nip44Error::Mac => "NIP-44 MAC verification failed",
            Nip44Error::Padding => "malformed NIP-44 padding",
            Nip44Error::Utf8 => "decrypted bytes are not valid UTF-8",
        };
        write!(f, "{s}")
    }
}

/// Derive the symmetric conversation key between my secret key and their x-only
/// public key. `HKDF-Extract(salt="nip44-v2", IKM = ecdh_x)`.
pub fn conversation_key(
    my_secp_sk: &[u8; 32],
    their_xonly: &[u8; 32],
) -> Result<[u8; 32], Nip44Error> {
    let sk = SecretKey::from_byte_array(*my_secp_sk).map_err(|_| Nip44Error::Key)?;
    let xonly = XOnlyPublicKey::from_byte_array(*their_xonly).map_err(|_| Nip44Error::Key)?;
    // NIP-44 lifts the x-only key to even-y for ECDH.
    let pk = PublicKey::from_x_only_public_key(xonly, Parity::Even);
    // shared_secret_point returns the 64-byte (x ‖ y); NIP-44 uses x only.
    let point = secp256k1::ecdh::shared_secret_point(&pk, &sk);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(SALT), &point[..32]);
    let mut ck = [0u8; 32];
    ck.copy_from_slice(&prk);
    Ok(ck)
}

/// NIP-44 padded length for an unpadded plaintext length (excludes the 2-byte
/// length prefix). Powers-of-two-ish bucketing so the ciphertext size leaks only
/// a coarse bucket.
pub fn calc_padded_len(unpadded: usize) -> usize {
    if unpadded <= 32 {
        return 32;
    }
    // 2^(floor(log2(unpadded-1)) + 1)
    let next_power = 1usize << ((unpadded - 1).ilog2() + 1);
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * ((unpadded - 1) / chunk + 1)
}

/// `[u16 BE unpadded_len] ‖ plaintext ‖ zero-pad` to `2 + calc_padded_len`.
fn pad(plaintext: &[u8]) -> Result<Vec<u8>, Nip44Error> {
    let n = plaintext.len();
    if !(MIN_PLAINTEXT..=MAX_PLAINTEXT).contains(&n) {
        return Err(Nip44Error::PlaintextLen);
    }
    let total = 2 + calc_padded_len(n);
    let mut buf = vec![0u8; total];
    buf[0..2].copy_from_slice(&(n as u16).to_be_bytes());
    buf[2..2 + n].copy_from_slice(plaintext);
    Ok(buf)
}

/// Reverse [`pad`]: validate the prefix + total length, return the plaintext.
fn unpad(buf: &[u8]) -> Result<Vec<u8>, Nip44Error> {
    if buf.len() < 2 {
        return Err(Nip44Error::Padding);
    }
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if !(MIN_PLAINTEXT..=MAX_PLAINTEXT).contains(&n) {
        return Err(Nip44Error::Padding);
    }
    if buf.len() != 2 + calc_padded_len(n) {
        return Err(Nip44Error::Padding);
    }
    Ok(buf[2..2 + n].to_vec())
}

/// HKDF-Expand the per-message keys: `chacha_key[32] ‖ chacha_nonce[12] ‖
/// hmac_key[32]`.
fn message_keys(conversation_key: &[u8; 32], nonce: &[u8; 32]) -> ([u8; 32], [u8; 12], [u8; 32]) {
    let hk = Hkdf::<Sha256>::from_prk(conversation_key).expect("32-byte PRK is valid");
    let mut okm = [0u8; 76];
    hk.expand(nonce, &mut okm).expect("76 < 255*32");
    let mut ck = [0u8; 32];
    let mut cn = [0u8; 12];
    let mut hm = [0u8; 32];
    ck.copy_from_slice(&okm[0..32]);
    cn.copy_from_slice(&okm[32..44]);
    hm.copy_from_slice(&okm[44..76]);
    (ck, cn, hm)
}

fn hmac(hmac_key: &[u8; 32], nonce: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("hmac accepts any key length");
    mac.update(nonce);
    mac.update(ciphertext);
    let out = mac.finalize().into_bytes();
    let mut t = [0u8; 32];
    t.copy_from_slice(&out);
    t
}

/// Encrypt `plaintext` under `conversation_key` with an explicit 32-byte
/// `nonce`. Returns the base64 NIP-44 payload. (Production callers use
/// [`encrypt`], which supplies a random nonce.)
pub fn encrypt_with_nonce(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
    plaintext: &str,
) -> Result<String, Nip44Error> {
    let (ck, cn, hm) = message_keys(conversation_key, nonce);
    let mut buf = pad(plaintext.as_bytes())?;
    ChaCha20::new(&ck.into(), &cn.into()).apply_keystream(&mut buf);
    let mac = hmac(&hm, nonce, &buf);

    let mut payload = Vec::with_capacity(1 + 32 + buf.len() + 32);
    payload.push(VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&buf);
    payload.extend_from_slice(&mac);
    Ok(B64.encode(&payload))
}

/// Encrypt `plaintext` under `conversation_key` with a fresh random nonce.
pub fn encrypt(conversation_key: &[u8; 32], plaintext: &str) -> Result<String, Nip44Error> {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    encrypt_with_nonce(conversation_key, &nonce, plaintext)
}

/// Decrypt a base64 NIP-44 payload under `conversation_key`. Constant-time MAC
/// check before decryption; fail-closed on any structural / MAC / padding error.
pub fn decrypt(conversation_key: &[u8; 32], payload_b64: &str) -> Result<String, Nip44Error> {
    let payload = B64
        .decode(payload_b64.as_bytes())
        .map_err(|_| Nip44Error::BadPayload)?;
    // version(1) + nonce(32) + ciphertext(>=34) + mac(32). The minimum
    // ciphertext is 2-byte prefix + 32-byte min pad = 34.
    if payload.len() < 1 + 32 + 34 + 32 || payload[0] != VERSION {
        return Err(Nip44Error::BadPayload);
    }
    let nonce: [u8; 32] = payload[1..33].try_into().unwrap();
    let mac_start = payload.len() - 32;
    let ciphertext = &payload[33..mac_start];
    let their_mac = &payload[mac_start..];

    let (ck, cn, hm) = message_keys(conversation_key, &nonce);
    // Constant-time MAC verification (hmac crate's verify is constant-time).
    let mut mac = HmacSha256::new_from_slice(&hm).expect("hmac accepts any key length");
    mac.update(&nonce);
    mac.update(ciphertext);
    mac.verify_slice(their_mac).map_err(|_| Nip44Error::Mac)?;

    let mut buf = ciphertext.to_vec();
    ChaCha20::new(&ck.into(), &cn.into()).apply_keystream(&mut buf);
    let plaintext = unpad(&buf)?;
    String::from_utf8(plaintext).map_err(|_| Nip44Error::Utf8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr_key::generate_transport_key;

    #[test]
    fn conversation_key_is_symmetric() {
        // a's (sk_a, pub_b) and b's (sk_b, pub_a) derive the same key.
        let (sk_a, pub_a) = generate_transport_key();
        let (sk_b, pub_b) = generate_transport_key();
        let ck_ab = conversation_key(&sk_a, &pub_b).unwrap();
        let ck_ba = conversation_key(&sk_b, &pub_a).unwrap();
        assert_eq!(ck_ab, ck_ba, "ECDH conversation key must be symmetric");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (sk_a, _pa) = generate_transport_key();
        let (_sb, pub_b) = generate_transport_key();
        let ck = conversation_key(&sk_a, &pub_b).unwrap();
        for msg in ["x", "hello over nostr", &"A".repeat(1000)] {
            let ct = encrypt(&ck, msg).unwrap();
            assert_eq!(decrypt(&ck, &ct).unwrap(), msg);
        }
    }

    #[test]
    fn the_other_party_decrypts() {
        // a encrypts to b; b decrypts with its own (sk_b, pub_a) — the real DM path.
        let (sk_a, pub_a) = generate_transport_key();
        let (sk_b, pub_b) = generate_transport_key();
        let ck_a = conversation_key(&sk_a, &pub_b).unwrap();
        let ck_b = conversation_key(&sk_b, &pub_a).unwrap();
        let ct = encrypt(&ck_a, "private to bob").unwrap();
        assert_eq!(decrypt(&ck_b, &ct).unwrap(), "private to bob");
    }

    #[test]
    fn deterministic_with_fixed_nonce() {
        let (sk_a, _pa) = generate_transport_key();
        let (_sb, pub_b) = generate_transport_key();
        let ck = conversation_key(&sk_a, &pub_b).unwrap();
        let nonce = [7u8; 32];
        assert_eq!(
            encrypt_with_nonce(&ck, &nonce, "same").unwrap(),
            encrypt_with_nonce(&ck, &nonce, "same").unwrap()
        );
    }

    #[test]
    fn tampered_ciphertext_fails_mac() {
        let (sk_a, _pa) = generate_transport_key();
        let (_sb, pub_b) = generate_transport_key();
        let ck = conversation_key(&sk_a, &pub_b).unwrap();
        let ct = encrypt(&ck, "tamperme").unwrap();
        let mut raw = B64.decode(&ct).unwrap();
        let n = raw.len();
        raw[n - 40] ^= 0xff; // flip a ciphertext byte (before the 32-byte MAC)
        let bad = B64.encode(&raw);
        assert_eq!(decrypt(&ck, &bad), Err(Nip44Error::Mac));
    }

    #[test]
    fn wrong_key_fails_mac() {
        let (sk_a, _pa) = generate_transport_key();
        let (_sb, pub_b) = generate_transport_key();
        let (sk_c, _pc) = generate_transport_key();
        let (_sd, pub_d) = generate_transport_key();
        let ck = conversation_key(&sk_a, &pub_b).unwrap();
        let other = conversation_key(&sk_c, &pub_d).unwrap();
        let ct = encrypt(&ck, "secret").unwrap();
        assert_eq!(decrypt(&other, &ct), Err(Nip44Error::Mac));
    }

    #[test]
    fn rejects_bad_version_and_short_payload() {
        let ck = [9u8; 32];
        assert_eq!(
            decrypt(&ck, &B64.encode([0x01u8; 200])),
            Err(Nip44Error::BadPayload)
        );
        assert_eq!(decrypt(&ck, "!!notbase64"), Err(Nip44Error::BadPayload));
        assert_eq!(
            decrypt(&ck, &B64.encode([0x02u8; 10])),
            Err(Nip44Error::BadPayload)
        );
    }

    #[test]
    fn empty_and_oversize_plaintext_rejected() {
        let ck = [3u8; 32];
        assert_eq!(encrypt(&ck, ""), Err(Nip44Error::PlaintextLen));
        let huge = "A".repeat(MAX_PLAINTEXT + 1);
        assert_eq!(encrypt(&ck, &huge), Err(Nip44Error::PlaintextLen));
    }

    #[test]
    fn padded_len_matches_spec_examples() {
        // Hand-verified against the NIP-44 algorithm.
        for (unpadded, expected) in [
            (1, 32),
            (16, 32),
            (32, 32),
            (33, 64),
            (37, 64),
            (65, 96),
            (100, 128),
        ] {
            assert_eq!(calc_padded_len(unpadded), expected, "len {unpadded}");
        }
        // Invariants for a sweep: result >= unpadded, multiple of 32, monotonic.
        let mut prev = 0;
        for n in 1..2000usize {
            let p = calc_padded_len(n);
            assert!(p >= n, "padded {p} < unpadded {n}");
            assert_eq!(p % 32, 0, "padded {p} not a multiple of 32");
            assert!(p >= prev, "padded len must be monotonic");
            prev = p;
        }
    }
}
