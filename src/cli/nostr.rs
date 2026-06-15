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
    }
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

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "sent": accepted, "event_id": event_id, "to_npub": npub, "relay": relay,
            }))?
        );
    } else if accepted {
        println!(
            "→ pair-request sent to {npub} via {relay}\n  event {event_id}\n  peer accepts with `wire accept` once their session pulls it."
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
