//! `wire nostr …` — speak Nostr (RFC-007 D3.4).
//!
//! Ties the Nostr stack together into runnable commands: pair with a peer
//! (`pair`) and fetch what's addressed to you (`fetch`), over a real Nostr
//! relay, using this session's secp transport key (`wire enroll nostr`). This is
//! the user-facing capstone of the offline stack (binding → codec → relay
//! protocol → websocket → NIP-44 → NIP-W1); it deliberately does NOT touch the
//! daemon's send/pull hot path — auto-routing `transport: nostr` peers is a
//! separate integration.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::nip_w1::{self, PairKind};
use crate::nostr_event;
use crate::nostr_relay::Filter;
use crate::nostr_ws::NostrWs;

/// Decode a 64-char hex x-only key into 32 bytes.
fn parse_npub_hex(s: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s).map_err(|_| anyhow!("npub must be 64-char hex (x-only key)"))?;
    v.as_slice().try_into().map_err(|_| {
        anyhow!(
            "npub must be exactly 32 bytes (64 hex chars), got {}",
            v.len()
        )
    })
}

/// This session's secp transport secret, or a clear "enroll first" error.
fn require_transport_key() -> Result<[u8; 32]> {
    crate::config::read_nostr_key()
        .context("no Nostr transport key — run `wire enroll nostr` first")
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build a fresh multi-thread runtime for the one-shot async relay call.
fn block_on<F: std::future::Future>(fut: F) -> Result<F::Output> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    Ok(rt.block_on(fut))
}

pub(crate) fn cmd_nostr(cmd: super::NostrCommand) -> Result<()> {
    match cmd {
        super::NostrCommand::Pair { npub, relay, json } => cmd_pair(&npub, &relay, json),
        super::NostrCommand::Fetch { relay, limit, json } => cmd_fetch(&relay, limit, json),
        super::NostrCommand::Accept { npub, relay, json } => cmd_accept(&npub, &relay, json),
    }
}

/// The card's primary Ed25519 identity verify-key bytes (used to check its
/// nostr binding).
fn card_identity_pubkey(card: &Value) -> Result<Vec<u8>> {
    let b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("peer card missing verify_keys[*].key"))?;
    crate::signing::b64decode(b64).map_err(|_| anyhow!("peer card verify key is not valid base64"))
}

fn cmd_accept(npub: &str, relay: &str, as_json: bool) -> Result<()> {
    let nsk = require_transport_key()?;
    let peer = parse_npub_hex(npub)?;
    let my_xonly = crate::nostr_key::xonly_from_secret(&nsk)
        .map_err(|e| anyhow!("transport key unusable: {e}"))?;
    let my_card =
        crate::config::read_agent_card().context("no agent card — run `wire up` first")?;

    // Pull the peer's pair-request addressed to us.
    let filter = Filter {
        authors: vec![npub.to_string()],
        kinds: vec![nip_w1::PAIR_REQUEST_KIND],
        p_tags: vec![hex::encode(my_xonly)],
        limit: Some(20),
        ..Default::default()
    };
    let events = block_on(async {
        let mut ws = NostrWs::connect(relay)
            .await
            .with_context(|| format!("connect {relay}"))?;
        ws.pull(filter).await.context("pull pair-request")
    })??;

    // Find + open the first pair-request from this peer.
    let card = events
        .iter()
        .find_map(|ev| match nip_w1::open_pair_event(ev, &nsk) {
            Ok((PairKind::Request, card)) => Some(card),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no pair-request from {npub} found on {relay}"))?;

    // Verify the card: signature, then its nostr binding must resolve to the
    // EXACT npub that sent the request (ties the Nostr transport key to this
    // wire identity — no relaying someone else's card).
    crate::agent_card::verify_agent_card(&card)
        .map_err(|e| anyhow!("peer card signature invalid: {e}"))?;
    let id_pubkey = card_identity_pubkey(&card)?;
    let bound = crate::nostr_key::card_nostr_binding(&card, &id_pubkey)
        .map_err(|e| anyhow!("peer card nostr binding invalid: {e}"))?
        .ok_or_else(|| anyhow!("peer card carries no nostr binding — cannot tie it to {npub}"))?;
    if bound != peer {
        bail!("peer card's bound npub does not match the sender — refusing to pin");
    }

    let peer_did = card
        .get("did")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>")
        .to_string();

    // The explicit accept IS the consent: pin VERIFIED (same gate semantics as
    // `wire accept`; the #245 collision guard applies inside add_agent_card_pin).
    crate::config::update_trust(|t| {
        crate::trust::add_agent_card_pin(t, &card, Some("VERIFIED")).map_err(anyhow::Error::msg)
    })?;

    // Record the peer's Nostr reachability (npub + the relay we paired on) so a
    // later send can route to them over Nostr. Keyed by the peer's handle.
    let peer_handle = card
        .get("handle")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| crate::agent_card::display_handle_from_did(&peer_did).to_string());
    // Also record this relay as one WE are reachable on (we received + ack here)
    // so the daemon pull-loop pulls our inbound from it — see pin_self_nostr_relay.
    crate::config::update_relay_state(|rs| {
        crate::endpoints::pin_peer_nostr_transport(rs, &peer_handle, npub, relay)?;
        crate::endpoints::pin_self_nostr_relay(rs, relay)
    })?;

    // Send the pair-ack (our card) back over the relay.
    let ack = nip_w1::build_pair_event(PairKind::Ack, &nsk, &peer, &my_card, now_unix())
        .map_err(|e| anyhow!("build pair-ack: {e}"))?;
    let acked = block_on(async {
        let mut ws = NostrWs::connect(relay)
            .await
            .with_context(|| format!("connect {relay}"))?;
        ws.publish(&ack).await.context("publish pair-ack")
    })??;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "pinned": peer_did, "tier": "VERIFIED", "ack_sent": acked, "npub": npub, "relay": relay,
            }))?
        );
    } else {
        println!(
            "→ paired with {peer_did}\n  pinned VERIFIED; pair-ack {} via {relay}",
            if acked {
                "sent"
            } else {
                "NOT accepted by relay"
            }
        );
        println!(
            "  note: trust is established; routing wire messages over Nostr (vs the trust pin) is a separate step."
        );
    }
    Ok(())
}

fn cmd_pair(npub: &str, relay: &str, as_json: bool) -> Result<()> {
    let nsk = require_transport_key()?;
    let peer = parse_npub_hex(npub)?;
    let card = crate::config::read_agent_card().context("no agent card — run `wire up` first")?;

    let ev = nip_w1::build_pair_event(PairKind::Request, &nsk, &peer, &card, now_unix())
        .map_err(|e| anyhow!("build pair-request: {e}"))?;
    let event_id = ev.id.clone();

    let accepted = block_on(async {
        let mut ws = NostrWs::connect(relay)
            .await
            .with_context(|| format!("connect {relay}"))?;
        ws.publish(&ev).await.context("publish pair-request")
    })??;

    // Record this relay as one we're reachable on (the peer will ack + later
    // send to us here) so the daemon pull-loop services it.
    crate::config::update_relay_state(|rs| crate::endpoints::pin_self_nostr_relay(rs, relay))?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "sent": accepted, "event_id": event_id, "to_npub": npub, "relay": relay,
            }))?
        );
    } else if accepted {
        println!(
            "→ pair-request sent to {npub} via {relay}\n  event {event_id}\n  the peer accepts with `wire nostr accept <your-npub> --relay {relay}`."
        );
    } else {
        bail!("relay {relay} rejected the pair-request (OK=false)");
    }
    Ok(())
}

fn cmd_fetch(relay: &str, limit: usize, as_json: bool) -> Result<()> {
    let nsk = require_transport_key()?;
    let my_xonly = crate::nostr_key::xonly_from_secret(&nsk)
        .map_err(|e| anyhow!("transport key unusable: {e}"))?;
    // Fetching here means we treat this relay as one we're reachable on — record
    // it so the daemon pull-loop keeps servicing it without a manual fetch.
    crate::config::update_relay_state(|rs| crate::endpoints::pin_self_nostr_relay(rs, relay))?;
    let filter = Filter {
        p_tags: vec![hex::encode(my_xonly)],
        kinds: vec![
            nip_w1::PAIR_REQUEST_KIND,
            nip_w1::PAIR_ACK_KIND,
            1, // wire messages encoded as NIP-01 events
        ],
        limit: Some(limit),
        ..Default::default()
    };

    let events = block_on(async {
        let mut ws = NostrWs::connect(relay)
            .await
            .with_context(|| format!("connect {relay}"))?;
        ws.pull(filter).await.context("pull")
    })??;

    let mut items = Vec::new();
    for ev in &events {
        // Try the pairing path first; `NotPairing` means it's a plain message.
        let item = match nip_w1::open_pair_event(ev, &nsk) {
            Ok((pair, card)) => json!({
                "type": match pair { PairKind::Request => "pair_request", PairKind::Ack => "pair_ack" },
                "from_did": card.get("did").and_then(Value::as_str),
                "from_handle": card.get("handle").and_then(Value::as_str),
                "event_id": ev.id,
            }),
            Err(nip_w1::NipW1Error::NotPairing) => match nostr_event::verify_and_decode(ev) {
                Ok(wire) => json!({
                    "type": "message",
                    "from_did": wire.get("from").and_then(Value::as_str),
                    "kind": wire.get("kind"),
                    "event_id": ev.id,
                }),
                Err(_) => continue,
            },
            // A pairing-kind event not addressed to us / undecryptable — skip.
            Err(_) => continue,
        };
        items.push(item);
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({ "relay": relay, "items": items }))?
        );
    } else {
        println!("→ {} event(s) addressed to you on {relay}:", items.len());
        for it in &items {
            let t = it.get("type").and_then(Value::as_str).unwrap_or("?");
            let who = it
                .get("from_handle")
                .and_then(Value::as_str)
                .or_else(|| it.get("from_did").and_then(Value::as_str))
                .unwrap_or("<unknown>");
            println!("  [{t}] from {who}");
        }
        if items.is_empty() {
            println!("  (nothing — peers must publish to this relay + p-tag your npub)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_npub_hex_accepts_64_hex_and_rejects_otherwise() {
        let ok = "0".repeat(64);
        assert_eq!(parse_npub_hex(&ok).unwrap(), [0u8; 32]);
        // Wrong length.
        assert!(parse_npub_hex("00").is_err());
        assert!(parse_npub_hex(&"0".repeat(66)).is_err());
        // Non-hex.
        assert!(parse_npub_hex(&"z".repeat(64)).is_err());
    }
}
