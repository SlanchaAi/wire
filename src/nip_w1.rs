//! RFC-007 D3.4 — NIP-W1: wire pairing over Nostr (**no-SPAKE2 variant**).
//!
//! NIP-W1 was originally sketched with SPAKE2 (`kind 21001/21002`), but wire
//! removed the SPAKE2/SAS flow post-RFC-005 and (operator decision, 2026-06-15)
//! does not reintroduce it. So pairing over Nostr reuses wire's **existing**
//! consent model instead of a PAKE:
//!
//! 1. Agent A (who knows B's npub) sends a **pair-request** — a Nostr event whose
//!    content is A's signed agent card (carrying the D3.1 nostr binding),
//!    **NIP-44-encrypted to B** and signed by A's secp transport key, `p`-tagged
//!    to B's npub.
//! 2. B decrypts it → stashes a pending-inbound pair. The existing bilateral
//!    **`wire accept`** gesture is the consent ceremony — no PAKE, no SAS.
//! 3. On accept, B replies with a **pair-ack** (same shape, B's card).
//!
//! Identity is the signed cards + cross-signed bindings; trust is the explicit
//! accept. This module is the **offline event codec** (build + open the
//! pair-request / pair-ack). The receiver consent gate + daemon routing
//! integration are separate, deferred slices.

use serde_json::{Value, json};

use crate::nip44::{self, Nip44Error};
use crate::nostr_event::{NostrEvent, NostrEventError, nostr_event_id, verify_transport};
use crate::nostr_key::{schnorr_sign_digest, xonly_from_secret};

/// Ephemeral-range kind for a wire pair-request over Nostr.
pub const PAIR_REQUEST_KIND: u32 = 21050;
/// Ephemeral-range kind for a wire pair-ack over Nostr.
pub const PAIR_ACK_KIND: u32 = 21051;

/// Which half of the pairing handshake an event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairKind {
    Request,
    Ack,
}

impl PairKind {
    fn kind(self) -> u32 {
        match self {
            PairKind::Request => PAIR_REQUEST_KIND,
            PairKind::Ack => PAIR_ACK_KIND,
        }
    }
    /// The `t` discriminator inside the encrypted payload (defence-in-depth: the
    /// inner tag must agree with the outer kind).
    fn tag(self) -> &'static str {
        match self {
            PairKind::Request => "pair_req",
            PairKind::Ack => "pair_ack",
        }
    }
    fn from_kind(kind: u32) -> Option<PairKind> {
        match kind {
            PAIR_REQUEST_KIND => Some(PairKind::Request),
            PAIR_ACK_KIND => Some(PairKind::Ack),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NipW1Error {
    /// The event's kind isn't a pairing kind.
    NotPairing,
    /// The transport layer (id / schnorr) didn't verify.
    Transport(NostrEventError),
    /// A secp key was malformed.
    Key,
    /// NIP-44 decryption failed (not addressed to me / tampered / wrong key).
    Decrypt(Nip44Error),
    /// The decrypted payload wasn't a valid pairing payload, or the inner tag
    /// disagreed with the outer kind.
    BadPayload,
}

impl std::fmt::Display for NipW1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NipW1Error::NotPairing => write!(f, "event kind is not a wire pairing kind"),
            NipW1Error::Transport(e) => write!(f, "pairing event transport: {e}"),
            NipW1Error::Key => write!(f, "malformed secp256k1 key"),
            NipW1Error::Decrypt(e) => write!(f, "pairing payload decrypt: {e}"),
            NipW1Error::BadPayload => write!(f, "malformed pairing payload"),
        }
    }
}

/// Build a NIP-44-encrypted pairing event carrying `my_card`, addressed to
/// `peer_xonly`, signed by my secp transport key (`my_secp_sk`). `created_at` is
/// supplied by the caller (unix seconds) to keep this pure/testable.
pub fn build_pair_event(
    pair: PairKind,
    my_secp_sk: &[u8; 32],
    peer_xonly: &[u8; 32],
    my_card: &Value,
    created_at: i64,
) -> Result<NostrEvent, NipW1Error> {
    let payload = json!({ "t": pair.tag(), "card": my_card }).to_string();
    let ck = nip44::conversation_key(my_secp_sk, peer_xonly).map_err(|_| NipW1Error::Key)?;
    let content = nip44::encrypt(&ck, &payload).map_err(NipW1Error::Decrypt)?;

    let my_xonly = xonly_from_secret(my_secp_sk).map_err(|_| NipW1Error::Key)?;
    let pubkey_hex = hex::encode(my_xonly);
    let tags = vec![vec!["p".to_string(), hex::encode(peer_xonly)]];
    let id = nostr_event_id(&pubkey_hex, created_at, pair.kind(), &tags, &content);
    let sig = schnorr_sign_digest(my_secp_sk, &id).map_err(|_| NipW1Error::Key)?;

    Ok(NostrEvent {
        id: hex::encode(id),
        pubkey: pubkey_hex,
        created_at,
        kind: pair.kind(),
        tags,
        content,
        sig: hex::encode(sig),
    })
}

/// Open a pairing event addressed to me (`my_secp_sk`). Verifies the transport
/// layer, NIP-44-decrypts the payload (the conversation key is symmetric, so my
/// secret + the sender's pubkey reproduce it), and parses it. Returns the
/// half-of-handshake and the **sender's signed agent card** — which the caller
/// must still verify (card signature + the D3.1 binding) before pinning.
/// **Fail-closed.**
pub fn open_pair_event(
    ev: &NostrEvent,
    my_secp_sk: &[u8; 32],
) -> Result<(PairKind, Value), NipW1Error> {
    let pair = PairKind::from_kind(ev.kind).ok_or(NipW1Error::NotPairing)?;
    // Transport authenticity: id + schnorr under the sender's npub.
    let sender_xonly = verify_transport(ev).map_err(NipW1Error::Transport)?;
    // NIP-44 decrypt (only succeeds if the event was sealed to MY key).
    let ck = nip44::conversation_key(my_secp_sk, &sender_xonly).map_err(|_| NipW1Error::Key)?;
    let plaintext = nip44::decrypt(&ck, &ev.content).map_err(NipW1Error::Decrypt)?;

    let v: Value = serde_json::from_str(&plaintext).map_err(|_| NipW1Error::BadPayload)?;
    // Inner tag must agree with the outer kind (no cross-kind confusion).
    if v.get("t").and_then(Value::as_str) != Some(pair.tag()) {
        return Err(NipW1Error::BadPayload);
    }
    let card = v.get("card").cloned().ok_or(NipW1Error::BadPayload)?;
    Ok((pair, card))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_card::{build_agent_card, sign_agent_card};
    use crate::nostr_key::generate_transport_key;
    use crate::signing::generate_keypair;

    fn a_signed_card(handle: &str) -> Value {
        let (sk, pk) = generate_keypair();
        sign_agent_card(&build_agent_card(handle, &pk, None, None, None), &sk)
    }

    #[test]
    fn request_roundtrips_a_to_b() {
        let (sk_a, _xa) = generate_transport_key();
        let (sk_b, xb) = generate_transport_key();
        let card_a = a_signed_card("slate-lotus");

        let ev = build_pair_event(PairKind::Request, &sk_a, &xb, &card_a, 1_700_000_000).unwrap();
        assert_eq!(ev.kind, PAIR_REQUEST_KIND);
        // p-tagged to B.
        assert_eq!(ev.tags[0], vec!["p".to_string(), hex::encode(xb)]);
        // content is NOT plaintext (it's NIP-44 ciphertext).
        assert!(!ev.content.contains("slate-lotus"));

        // B opens it → gets A's card back.
        let (pair, card) = open_pair_event(&ev, &sk_b).unwrap();
        assert_eq!(pair, PairKind::Request);
        assert_eq!(card, card_a);
    }

    #[test]
    fn ack_roundtrips_and_carries_kind() {
        let (sk_a, xa) = generate_transport_key();
        let (sk_b, _xb) = generate_transport_key();
        let card_b = a_signed_card("raven-kettle");
        let ev = build_pair_event(PairKind::Ack, &sk_b, &xa, &card_b, 1_700_000_001).unwrap();
        assert_eq!(ev.kind, PAIR_ACK_KIND);
        let (pair, card) = open_pair_event(&ev, &sk_a).unwrap();
        assert_eq!(pair, PairKind::Ack);
        assert_eq!(card, card_b);
    }

    #[test]
    fn a_third_party_cannot_decrypt() {
        let (sk_a, _xa) = generate_transport_key();
        let (_sk_b, xb) = generate_transport_key();
        let (sk_c, _xc) = generate_transport_key(); // eavesdropper
        let ev = build_pair_event(
            PairKind::Request,
            &sk_a,
            &xb,
            &a_signed_card("x"),
            1_700_000_000,
        )
        .unwrap();
        // C is not the addressee → NIP-44 MAC fails.
        assert!(matches!(
            open_pair_event(&ev, &sk_c),
            Err(NipW1Error::Decrypt(_))
        ));
    }

    #[test]
    fn tampered_content_fails_transport() {
        let (sk_a, _xa) = generate_transport_key();
        let (sk_b, xb) = generate_transport_key();
        let mut ev = build_pair_event(
            PairKind::Request,
            &sk_a,
            &xb,
            &a_signed_card("x"),
            1_700_000_000,
        )
        .unwrap();
        ev.content.push('A'); // id no longer matches the content
        assert!(matches!(
            open_pair_event(&ev, &sk_b),
            Err(NipW1Error::Transport(_))
        ));
    }

    #[test]
    fn non_pairing_kind_rejected() {
        let (sk_a, _xa) = generate_transport_key();
        let (sk_b, xb) = generate_transport_key();
        let mut ev = build_pair_event(
            PairKind::Request,
            &sk_a,
            &xb,
            &a_signed_card("x"),
            1_700_000_000,
        )
        .unwrap();
        // Re-sign under kind 1 so the transport still verifies but it's not a
        // pairing kind.
        ev.kind = 1;
        ev.id = hex::encode(nostr_event_id(
            &ev.pubkey,
            ev.created_at,
            ev.kind,
            &ev.tags,
            &ev.content,
        ));
        let sig = schnorr_sign_digest(&sk_a, &hex32(&ev.id)).unwrap();
        ev.sig = hex::encode(sig);
        assert_eq!(open_pair_event(&ev, &sk_b), Err(NipW1Error::NotPairing));
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().as_slice().try_into().unwrap()
    }
}
