//! RFC-001 §1: operator / organization identity certs.
//!
//! Two cert kinds, both Ed25519 signatures over UTF-8 bytes of a DID:
//!
//! - **`op_cert`** — operator's root key signs the session DID,
//!   binding the session under the operator. Carried on the session's
//!   agent card alongside `op_did`.
//! - **`member_cert`** — org's root key signs an operator's `op_did`,
//!   binding the operator into the org. Carried on the session's
//!   agent card alongside the operator's `op_did`, as an entry in
//!   `org_memberships[]`.
//!
//! Both certs are leaf-level signatures: a single key-check verifies
//! one link. The trust chain `session_did → op_did → org_did` is two
//! independent verifications, not a chained walk. This matches the
//! NATS / OIDF / Keybase convergence noted in the RFC's prior-art
//! analysis (§Prior art): *membership = signed statement, not roster
//! lookup*.
//!
//! Verification is *cryptographic only*. Whether a pinned-and-verified
//! `op_did` or `org_did` actually grants `ORG_VERIFIED` is a separate
//! policy decision in `trust.rs` — gated on attestation status (DNS-TXT
//! or SSO, see amendments) and per-org operator opt-in (filtering
//! amendment §3). The split keeps the cryptographic floor honest:
//! "the cert verifies" is a fact about bytes; "we accept this cert as
//! authority" is a fact about operator policy.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

use crate::signing::{b64decode, b64encode};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertError {
    #[error("certificate base64 decode failed")]
    BadEncoding,
    #[error("certificate length is not 64 bytes")]
    BadLength,
    #[error("public key length is not 32 bytes")]
    BadKey,
    #[error("signature did not verify")]
    Rejected,
}

/// Sign `payload_did` with `signing_key`. Returns the base64 cert ready
/// to drop into `op_cert` or `member_cert`.
///
/// `signing_key` must be a 32-byte Ed25519 secret seed (same shape
/// `signing::generate_keypair` returns and `sign_agent_card` accepts).
pub fn sign_did_cert(signing_key: &[u8], payload_did: &str) -> Result<String, CertError> {
    if signing_key.len() < 32 {
        return Err(CertError::BadKey);
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&signing_key[..32]);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let sig = sk.sign(payload_did.as_bytes());
    Ok(b64encode(&sig.to_bytes()))
}

/// Verify `op_cert` (b64 Ed25519 signature) was produced by `op_pubkey`
/// over the UTF-8 bytes of `session_did`. Caller must independently
/// ensure `op_pubkey` is the correct key for the claimed `op_did`
/// (typically by looking it up in a pinned operator record or by
/// pulling it from the wireup registry's `GET /v1/op/<op_did>` endpoint).
pub fn verify_op_cert(
    op_pubkey: &[u8],
    op_cert_b64: &str,
    session_did: &str,
) -> Result<(), CertError> {
    verify_did_cert(op_pubkey, op_cert_b64, session_did)
}

/// Verify `member_cert` was produced by `org_pubkey` over the UTF-8
/// bytes of `op_did`. Caller must independently ensure `org_pubkey`
/// is the correct key for the claimed `org_did` (typically by checking
/// the wireup-registered org attestation, RFC-001 §2).
pub fn verify_member_cert(
    org_pubkey: &[u8],
    member_cert_b64: &str,
    op_did: &str,
) -> Result<(), CertError> {
    verify_did_cert(org_pubkey, member_cert_b64, op_did)
}

/// Canonical payload an op/org **succession** cert signs. Distinct from the
/// bare-DID payload `op_cert`/`member_cert` sign, so a succession cert can never
/// be replayed as — or mistaken for — an op/member cert (different signed bytes
/// → different signature domain). `kind` is `"op"` or `"org"`.
fn succession_payload(kind: &str, old_did: &str, new_did: &str) -> String {
    format!("wire-succession-v1|{kind}|{old_did}|{new_did}")
}

/// Sign a key-rotation **succession** statement (RFC-001 §T19/§T20): the OLD
/// key attests "`old_did` hands off to `new_did`". Because a wire DID commits
/// to its key, rotating the key mints a *new* DID — this cert is what lets a
/// peer who pinned `old_did` follow the handoff to `new_did`. The new key is
/// not part of this signature; the verifier separately checks that
/// `new_pubkey` commits to `new_did`.
pub fn sign_succession_cert(
    old_signing_key: &[u8],
    kind: &str,
    old_did: &str,
    new_did: &str,
) -> Result<String, CertError> {
    sign_did_cert(old_signing_key, &succession_payload(kind, old_did, new_did))
}

/// Verify a succession cert: `old_pubkey` (which the caller must independently
/// confirm commits to `old_did`) signed the canonical `old_did → new_did`
/// handoff for `kind`. A cert for a different `new_did`, `kind`, or signer
/// fails.
pub fn verify_succession_cert(
    old_pubkey: &[u8],
    cert_b64: &str,
    kind: &str,
    old_did: &str,
    new_did: &str,
) -> Result<(), CertError> {
    verify_did_cert(
        old_pubkey,
        cert_b64,
        &succession_payload(kind, old_did, new_did),
    )
}

/// Verify an Ed25519 signature (base64) by `pubkey` over an arbitrary UTF-8
/// `payload`. This is the generic primitive under `op_cert` / `member_cert` /
/// succession-cert verification; exposed for the same-machine attestation
/// (RFC-001 amendment #182), which signs a domain-separated payload *string*
/// (`wire-same-machine-v1|<fp_hex>|<session_did>`) rather than a bare DID. The
/// caller must independently confirm `pubkey` is the right key (here: the
/// inline `op_pubkey` already verified to commit to `op_did`).
pub fn verify_payload_sig(pubkey: &[u8], sig_b64: &str, payload: &str) -> Result<(), CertError> {
    verify_did_cert(pubkey, sig_b64, payload)
}

fn verify_did_cert(pubkey: &[u8], cert_b64: &str, payload_did: &str) -> Result<(), CertError> {
    if pubkey.len() != 32 {
        return Err(CertError::BadKey);
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(pubkey);
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| CertError::BadKey)?;

    let sig_bytes = b64decode(cert_b64).map_err(|_| CertError::BadEncoding)?;
    if sig_bytes.len() != 64 {
        return Err(CertError::BadLength);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    vk.verify(payload_did.as_bytes(), &sig)
        .map_err(|_| CertError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_card::{did_for_op, did_for_org, did_for_with_key};
    use crate::signing::generate_keypair;

    #[test]
    fn sign_verify_op_cert_roundtrip() {
        let (op_sk, op_pk) = generate_keypair();
        let (_, session_pk) = generate_keypair();
        let session_did = did_for_with_key("vesper-valley", &session_pk);
        let cert = sign_did_cert(&op_sk, &session_did).unwrap();
        verify_op_cert(&op_pk, &cert, &session_did).unwrap();
    }

    #[test]
    fn sign_verify_member_cert_roundtrip() {
        let (org_sk, org_pk) = generate_keypair();
        let (_, op_pk) = generate_keypair();
        let op_did = did_for_op("darby", &op_pk);
        let cert = sign_did_cert(&org_sk, &op_did).unwrap();
        verify_member_cert(&org_pk, &cert, &op_did).unwrap();
    }

    #[test]
    fn verify_op_cert_rejects_wrong_session_did() {
        // Cert binds session_a; presenting it for session_b must fail —
        // protects against an attacker re-using a leaked op_cert on a
        // session under their own keypair.
        let (op_sk, op_pk) = generate_keypair();
        let (_, sk_a) = generate_keypair();
        let (_, sk_b) = generate_keypair();
        let did_a = did_for_with_key("session-a", &sk_a);
        let did_b = did_for_with_key("session-b", &sk_b);
        let cert = sign_did_cert(&op_sk, &did_a).unwrap();
        assert_eq!(
            verify_op_cert(&op_pk, &cert, &did_b),
            Err(CertError::Rejected)
        );
    }

    #[test]
    fn verify_member_cert_rejects_wrong_op_did() {
        // Same shape, one tier up: a cert signed for op_a must not
        // verify for op_b. Protects against admin-mistake or rolled-back
        // membership replay.
        let (org_sk, org_pk) = generate_keypair();
        let (_, op_a_pk) = generate_keypair();
        let (_, op_b_pk) = generate_keypair();
        let op_a = did_for_op("darby", &op_a_pk);
        let op_b = did_for_op("willard", &op_b_pk);
        let cert = sign_did_cert(&org_sk, &op_a).unwrap();
        assert_eq!(
            verify_member_cert(&org_pk, &cert, &op_b),
            Err(CertError::Rejected)
        );
    }

    #[test]
    fn verify_op_cert_rejects_wrong_op_key() {
        // Cert was signed by op_alice; verifying against op_bob's
        // public key must fail.
        let (alice_sk, _) = generate_keypair();
        let (_, bob_pk) = generate_keypair();
        let (_, session_pk) = generate_keypair();
        let session_did = did_for_with_key("s", &session_pk);
        let cert = sign_did_cert(&alice_sk, &session_did).unwrap();
        assert_eq!(
            verify_op_cert(&bob_pk, &cert, &session_did),
            Err(CertError::Rejected)
        );
    }

    #[test]
    fn verify_op_cert_rejects_bad_base64() {
        let (_, pk) = generate_keypair();
        assert_eq!(
            verify_op_cert(&pk, "not-base64!", "did:wire:s"),
            Err(CertError::BadEncoding)
        );
    }

    #[test]
    fn verify_op_cert_rejects_short_cert() {
        let (_, pk) = generate_keypair();
        let short = b64encode(&[0u8; 32]);
        assert_eq!(
            verify_op_cert(&pk, &short, "did:wire:s"),
            Err(CertError::BadLength)
        );
    }

    #[test]
    fn verify_op_cert_rejects_short_pubkey() {
        let (sk, _) = generate_keypair();
        let cert = sign_did_cert(&sk, "did:wire:s").unwrap();
        let short_pk = vec![0u8; 16];
        assert_eq!(
            verify_op_cert(&short_pk, &cert, "did:wire:s"),
            Err(CertError::BadKey)
        );
    }

    #[test]
    fn sign_did_cert_rejects_short_signing_key() {
        let short_sk = vec![0u8; 16];
        assert_eq!(
            sign_did_cert(&short_sk, "did:wire:s"),
            Err(CertError::BadKey)
        );
    }

    #[test]
    fn op_and_org_cert_signing_are_indistinguishable_at_byte_level() {
        // Same primitive (ed25519 over UTF-8 DID bytes) — the op/org
        // distinction is purely semantic, encoded in which DID is being
        // signed and which field on the card the cert lands in. Documents
        // the invariant so future cert kinds can reuse `sign_did_cert`
        // without inventing a new primitive.
        let (op_sk, _op_pk) = generate_keypair();
        let (_, session_pk) = generate_keypair();
        let session_did = did_for_with_key("s", &session_pk);

        let (org_sk, _org_pk) = generate_keypair();
        let (_, op_pk) = generate_keypair();
        let op_did = did_for_op("darby", &op_pk);

        let op_cert = sign_did_cert(&op_sk, &session_did).unwrap();
        let member_cert = sign_did_cert(&org_sk, &op_did).unwrap();

        // Both are 64-byte ed25519 sigs, base64 encoded.
        assert_eq!(b64decode(&op_cert).unwrap().len(), 64);
        assert_eq!(b64decode(&member_cert).unwrap().len(), 64);
    }

    #[test]
    fn succession_cert_roundtrip_and_binding() {
        // Old op key signs the handoff to a new op_did; verifies under the old
        // pubkey for exactly that (kind, old_did, new_did) triple.
        let (old_sk, old_pk) = generate_keypair();
        let (_, new_pk) = generate_keypair();
        let old_did = did_for_op("darby", &old_pk);
        let new_did = did_for_op("darby", &new_pk);
        let cert = sign_succession_cert(&old_sk, "op", &old_did, &new_did).unwrap();
        verify_succession_cert(&old_pk, &cert, "op", &old_did, &new_did).unwrap();

        // Wrong new_did → reject (an attacker can't redirect the handoff).
        let (_, attacker_pk) = generate_keypair();
        let attacker_did = did_for_op("darby", &attacker_pk);
        assert_eq!(
            verify_succession_cert(&old_pk, &cert, "op", &old_did, &attacker_did),
            Err(CertError::Rejected)
        );
        // Wrong kind → reject (op handoff isn't an org handoff).
        assert_eq!(
            verify_succession_cert(&old_pk, &cert, "org", &old_did, &new_did),
            Err(CertError::Rejected)
        );
        // Wrong signer → reject.
        assert_eq!(
            verify_succession_cert(&new_pk, &cert, "op", &old_did, &new_did),
            Err(CertError::Rejected)
        );
    }

    #[test]
    fn succession_cert_is_domain_separated_from_op_cert() {
        // A succession cert (signs the tagged triple) must NOT verify as an
        // op_cert (signs a bare session DID), and vice versa — different signed
        // bytes mean the two cert kinds can't be confused/replayed across paths.
        let (old_sk, old_pk) = generate_keypair();
        let (_, new_pk) = generate_keypair();
        let old_did = did_for_op("darby", &old_pk);
        let new_did = did_for_op("darby", &new_pk);

        let succ = sign_succession_cert(&old_sk, "op", &old_did, &new_did).unwrap();
        // The succession cert is over `wire-succession-v1|op|old|new`, NOT over
        // `new_did` alone — so verify_op_cert(new_did) must reject it.
        assert_eq!(
            verify_op_cert(&old_pk, &succ, &new_did),
            Err(CertError::Rejected)
        );

        // And a real op_cert over new_did is not a valid succession cert.
        let op_cert = sign_did_cert(&old_sk, &new_did).unwrap();
        assert_eq!(
            verify_succession_cert(&old_pk, &op_cert, "op", &old_did, &new_did),
            Err(CertError::Rejected)
        );
    }

    #[test]
    fn org_did_payload_is_not_confused_with_member_cert_subject() {
        // Sanity: a cert signed over an org_did UTF-8 string is NOT
        // accepted as a member_cert binding that org_did — member_cert
        // binds op_did, not org_did. Catches a likely future-misuse
        // pattern.
        let (org_sk, org_pk) = generate_keypair();
        let (_, org_pk_for_did) = generate_keypair();
        let org_did = did_for_org("slanchaai", &org_pk_for_did);
        let (_, op_pk) = generate_keypair();
        let op_did = did_for_op("darby", &op_pk);

        // Attacker signs the org_did (wrong subject) and presents it as
        // a member_cert binding op_did.
        let bogus = sign_did_cert(&org_sk, &org_did).unwrap();
        assert_eq!(
            verify_member_cert(&org_pk, &bogus, &op_did),
            Err(CertError::Rejected)
        );
    }
}
