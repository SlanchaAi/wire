//! SPAKE2 PAKE + Short Authentication String (SAS).
//!
//! Pairing flow (the magic-wormhole pattern, applied to agent identity):
//!
//!   1. Operator A runs `wire init paul`. We generate a *low-entropy* code
//!      phrase like `73-2QXC4P` (~36 bits) and print it.
//!   2. Operator A says the code aloud to Operator B.
//!   3. Operator B runs `wire join 73-2QXC4P`.
//!   4. Both sides run SPAKE2 with the code phrase as the shared password.
//!      SPAKE2 elevates the low-entropy code into a *high-entropy* shared key
//!      without leaking anything brute-force-able to a passive eavesdropper
//!      OR to the relay we route messages through.
//!   5. Both sides derive a 6-digit SAS from the SPAKE2 transcript. Each
//!      operator's terminal shows the same digits ("384-217") iff they
//!      truly negotiated with each other. They read the digits aloud and
//!      both type `y` to confirm.
//!   6. After confirm: bootstrap payload (signed agent-card + relay slot
//!      coords) is exchanged authenticated-encrypted via ChaCha20-Poly1305
//!      under a key HKDF-derived from the SPAKE2 secret.
//!
//! SAS confirmation is the trust-establishment moment. An MITM that sat
//! between A and B during SPAKE2 would derive a *different* shared key
//! from each side, so the SAS digits would not match. That's why this is
//! safe even though the code phrase has only ~36 bits — brute-forcing
//! requires *interactive* presence in the handshake, which the SAS catches.
//!
//! v0.1 ships the offline crypto in this module + a self-test suite.
//! Wiring it through the relay (`wire init` opens a pair-slot, `wire join`
//! talks SPAKE2 across it) lands in iter 9.

use anyhow::{Result, anyhow, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::{Rng, RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::sync::Mutex;

/// Number of digits in a code phrase (e.g. `73-`).
const CODE_DIGIT_LEN: usize = 2;
/// Length of the base32 token after the digits (e.g. `-2QXC4P`).
const CODE_TOKEN_LEN: usize = 6;
/// RFC 4648 base32 alphabet — 32 chars, no lowercase, no 0/1 ambiguity.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Generate a fresh code phrase like `73-2QXC4P` (~36 bits entropy).
///
/// Format: `NN-XXXXXX` where NN is two random decimal digits and XXXXXX is
/// six random RFC-4648 base32 characters. ~6.6 + 30 = ~36.6 bits entropy.
/// Easy to read aloud; trivially copied by ear.
pub fn generate_code_phrase() -> String {
    let mut rng = OsRng;
    let digits = rng.gen_range(0..100);
    let mut token = String::with_capacity(CODE_TOKEN_LEN);
    for _ in 0..CODE_TOKEN_LEN {
        let idx = rng.gen_range(0..BASE32_ALPHABET.len());
        token.push(BASE32_ALPHABET[idx] as char);
    }
    format!("{:02}-{}", digits, token)
}

/// Validate a code phrase has the expected shape.
pub fn parse_code_phrase(s: &str) -> Result<&str> {
    let s = s.trim();
    let (digits, rest) = s
        .split_once('-')
        .ok_or_else(|| anyhow!("code phrase missing '-' separator: {s:?}"))?;
    if digits.len() != CODE_DIGIT_LEN || !digits.chars().all(|c| c.is_ascii_digit()) {
        bail!("code phrase digits must be {CODE_DIGIT_LEN} ASCII digits, got {digits:?}");
    }
    if rest.len() != CODE_TOKEN_LEN {
        bail!(
            "code phrase token must be {CODE_TOKEN_LEN} chars, got {} ({rest:?})",
            rest.len()
        );
    }
    if !rest.bytes().all(|b| BASE32_ALPHABET.contains(&b)) {
        bail!("code phrase token has non-base32 char: {rest:?}");
    }
    Ok(s)
}

/// One side of a SPAKE2 handshake. Created with the shared code phrase + a
/// pairing identity (e.g. relay pair-slot id) so distinct pairings can't be
/// confused.
pub struct PakeSide {
    /// `Spake2::start_symmetric` returns `(state, msg)`. `state` is consumed
    /// by `finish`, so we hold it under a Mutex for ergonomic .take().
    state: Mutex<Option<Spake2<Ed25519Group>>>,
    pub msg_out: Vec<u8>,
}

impl PakeSide {
    /// Create our side. `code_phrase` is the human-typed string; `pair_id`
    /// is a per-pairing identity (e.g. relay pair-slot id) to prevent
    /// crosstalk between concurrent pairings.
    pub fn new(code_phrase: &str, pair_id: &[u8]) -> Self {
        let parsed = parse_code_phrase(code_phrase).expect("invalid code phrase");
        let (state, msg_out) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(parsed.as_bytes()),
            &Identity::new(pair_id),
        );
        Self {
            state: Mutex::new(Some(state)),
            msg_out,
        }
    }

    /// Combine our state with the peer's `msg` to derive the shared SPAKE2 key.
    /// Returns 32 bytes of high-entropy shared secret.
    pub fn finish(&self, peer_msg: &[u8]) -> Result<[u8; 32]> {
        let state = self
            .state
            .lock()
            .expect("PakeSide mutex poisoned")
            .take()
            .ok_or_else(|| anyhow!("PakeSide.finish called twice"))?;
        let key = state
            .finish(peer_msg)
            .map_err(|e| anyhow!("SPAKE2 finish failed: {e:?}"))?;
        let mut out = [0u8; 32];
        let n = key.len().min(32);
        out[..n].copy_from_slice(&key[..n]);
        Ok(out)
    }
}

/// 6-digit SAS over the SPAKE2 shared key + the canonical (sorted) pair of
/// public keys. Symmetric: either side computes the same digits.
///
/// Why include the public keys: we want the SAS to also commit to the actual
/// agent identities being paired, not just the SPAKE2 result. An MITM who
/// somehow guessed the code phrase (~1 in 2^36 per attempt) would still fail
/// the SAS because they couldn't make us see the right Ed25519 public keys.
pub fn compute_sas_pake(spake_key: &[u8], pub_a: &[u8], pub_b: &[u8]) -> String {
    let (lo, hi) = if pub_a <= pub_b {
        (pub_a, pub_b)
    } else {
        (pub_b, pub_a)
    };
    let mut h = Sha256::new();
    h.update(b"wire/v1 sas");
    h.update(spake_key);
    h.update(lo);
    h.update(hi);
    let digest = h.finalize();
    let n = u32::from_be_bytes([digest[28], digest[29], digest[30], digest[31]]);
    format!("{:06}", n % 1_000_000)
}

/// HKDF-SHA256 derive a 32-byte ChaCha20-Poly1305 key from the SPAKE2 secret.
pub fn derive_aead_key(spake_key: &[u8], pair_id: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(pair_id), spake_key);
    let mut out = [0u8; 32];
    hk.expand(b"wire/v1 bootstrap-aead", &mut out)
        .expect("HKDF expand 32 bytes is infallible");
    out
}

/// Encrypt the bootstrap payload (signed agent-card + slot coords) under the
/// AEAD key. Returns `nonce || ciphertext` — caller transmits the whole blob
/// and recipient splits at byte 12.
pub fn seal_bootstrap(aead_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(aead_key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("seal failed: {e:?}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a bootstrap payload produced by `seal_bootstrap`.
pub fn open_bootstrap(aead_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 12 + 16 {
        bail!("bootstrap blob too short: {} bytes", blob.len());
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(aead_key));
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|e| anyhow!("open failed (auth tag mismatch?): {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_phrase_has_expected_shape() {
        let code = generate_code_phrase();
        let parsed = parse_code_phrase(&code).unwrap();
        assert_eq!(parsed, code);
        assert_eq!(code.len(), CODE_DIGIT_LEN + 1 + CODE_TOKEN_LEN);
        assert!(code.chars().nth(CODE_DIGIT_LEN) == Some('-'));
    }

    #[test]
    fn many_code_phrases_are_distinct() {
        // 36 bits of entropy — collisions in 1000 samples should be near zero.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let c = generate_code_phrase();
            assert!(seen.insert(c));
        }
    }

    #[test]
    fn parse_rejects_malformed_codes() {
        assert!(parse_code_phrase("foo").is_err());
        assert!(parse_code_phrase("12345-ABCDEF").is_err()); // too many digits
        assert!(parse_code_phrase("12-ABC").is_err()); // token too short
        assert!(parse_code_phrase("12-ABCDEF1").is_err()); // 1 not in base32 alphabet
        assert!(parse_code_phrase("12-abcdef").is_err()); // lowercase rejected
    }

    #[test]
    fn pake_two_sides_derive_same_secret() {
        let code = generate_code_phrase();
        let pair_id = b"pair-id-shared";
        let alice = PakeSide::new(&code, pair_id);
        let bob = PakeSide::new(&code, pair_id);
        let alice_secret = alice.finish(&bob.msg_out).unwrap();
        let bob_secret = bob.finish(&alice.msg_out).unwrap();
        assert_eq!(alice_secret, bob_secret, "SPAKE2 secrets diverged");
    }

    #[test]
    fn pake_wrong_code_diverges() {
        // Two parties with DIFFERENT code phrases — finish() either errors
        // (Ed25519Group rejects) or returns a different secret. Either way,
        // the test passes if the two derived secrets disagree.
        let pair_id = b"pair-id-same";
        let alice = PakeSide::new("11-ABCDEF", pair_id);
        let bob = PakeSide::new("99-ZZZZZZ", pair_id);
        let alice_result = alice.finish(&bob.msg_out);
        let bob_result = bob.finish(&alice.msg_out);
        let mismatch = match (alice_result, bob_result) {
            (Ok(a), Ok(b)) => a != b,
            _ => true, // either side erroring is also a mismatch
        };
        assert!(
            mismatch,
            "wrong code phrase should not produce matching secrets"
        );
    }

    #[test]
    fn pake_different_pair_id_diverges() {
        // Same code phrase but different pair_id — should NOT collide. This
        // protects against cross-talk between concurrent pairings on the
        // same relay.
        let code = "42-WIRE45"; // base32 alphabet: A-Z2-7, no 0/1
        let alice = PakeSide::new(code, b"pair-A");
        let bob = PakeSide::new(code, b"pair-B");
        let a = alice.finish(&bob.msg_out);
        let b = bob.finish(&alice.msg_out);
        let mismatch = match (a, b) {
            (Ok(x), Ok(y)) => x != y,
            _ => true,
        };
        assert!(mismatch, "different pair_id must NOT yield same secret");
    }

    #[test]
    fn pake_finish_called_twice_errors() {
        let code = generate_code_phrase();
        let alice = PakeSide::new(&code, b"x");
        let bob = PakeSide::new(&code, b"x");
        alice.finish(&bob.msg_out).unwrap();
        let err = alice.finish(&bob.msg_out).unwrap_err();
        assert!(err.to_string().contains("twice"), "got: {err}");
    }

    #[test]
    fn sas_is_6_digits_and_symmetric() {
        let key = [42u8; 32];
        let pub_a = [1u8; 32];
        let pub_b = [2u8; 32];
        let sas_ab = compute_sas_pake(&key, &pub_a, &pub_b);
        let sas_ba = compute_sas_pake(&key, &pub_b, &pub_a);
        assert_eq!(sas_ab.len(), 6);
        assert!(sas_ab.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(sas_ab, sas_ba, "SAS must be symmetric in (pub_a, pub_b)");
    }

    #[test]
    fn sas_changes_with_spake_key() {
        let pub_a = [1u8; 32];
        let pub_b = [2u8; 32];
        let sas1 = compute_sas_pake(&[1u8; 32], &pub_a, &pub_b);
        let sas2 = compute_sas_pake(&[2u8; 32], &pub_a, &pub_b);
        assert_ne!(sas1, sas2);
    }

    #[test]
    fn sas_changes_with_pubkeys() {
        let key = [42u8; 32];
        let pub_a = [1u8; 32];
        let pub_b = [2u8; 32];
        let pub_c = [3u8; 32];
        assert_ne!(
            compute_sas_pake(&key, &pub_a, &pub_b),
            compute_sas_pake(&key, &pub_a, &pub_c)
        );
    }

    #[test]
    fn aead_seal_open_round_trip() {
        let key = derive_aead_key(&[42u8; 32], b"pair-id");
        let plaintext = b"some bootstrap payload bytes";
        let sealed = seal_bootstrap(&key, plaintext).unwrap();
        let opened = open_bootstrap(&key, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn aead_open_with_wrong_key_fails() {
        let key1 = derive_aead_key(&[1u8; 32], b"x");
        let key2 = derive_aead_key(&[2u8; 32], b"x");
        let sealed = seal_bootstrap(&key1, b"secret").unwrap();
        let result = open_bootstrap(&key2, &sealed);
        assert!(result.is_err(), "wrong key must fail AEAD auth");
    }

    #[test]
    fn aead_open_with_truncated_blob_fails() {
        let key = derive_aead_key(&[42u8; 32], b"x");
        let result = open_bootstrap(&key, b"too short");
        assert!(result.is_err());
    }

    #[test]
    fn full_pake_to_sealed_payload_round_trip() {
        // Simulate the full handshake: paul + willard derive the same
        // SPAKE2 key, derive the same AEAD key, and successfully exchange
        // an encrypted bootstrap payload.
        let code = generate_code_phrase();
        let pair_id = b"e2e-pair";
        let paul = PakeSide::new(&code, pair_id);
        let willard = PakeSide::new(&code, pair_id);

        let paul_msg = paul.msg_out.clone();
        let willard_msg = willard.msg_out.clone();
        let paul_secret = paul.finish(&willard_msg).unwrap();
        let willard_secret = willard.finish(&paul_msg).unwrap();
        assert_eq!(paul_secret, willard_secret);

        let paul_aead_key = derive_aead_key(&paul_secret, pair_id);
        let willard_aead_key = derive_aead_key(&willard_secret, pair_id);
        assert_eq!(paul_aead_key, willard_aead_key);

        // Paul sends his signed agent-card to willard via AEAD.
        let paul_card_bytes = b"{\"did\":\"did:wire:paul\", ...}";
        let sealed = seal_bootstrap(&paul_aead_key, paul_card_bytes).unwrap();
        let opened = open_bootstrap(&willard_aead_key, &sealed).unwrap();
        assert_eq!(opened, paul_card_bytes);

        // Both compute the same 6-digit SAS over the SPAKE key + pubkeys.
        let pub_a = [9u8; 32];
        let pub_b = [10u8; 32];
        let sas_paul = compute_sas_pake(&paul_secret, &pub_a, &pub_b);
        let sas_willard = compute_sas_pake(&willard_secret, &pub_b, &pub_a);
        assert_eq!(sas_paul, sas_willard);
    }
}
