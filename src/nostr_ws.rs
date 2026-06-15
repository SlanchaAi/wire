//! RFC-007 D3.2b-ii: `NostrWs` — the WebSocket transport that carries the
//! NIP-01 messages (`nostr_relay`) over `ws://` / `wss://` to a real Nostr relay.
//!
//! This is the network half of the Nostr binding; the pure event codec
//! (`nostr_event`) and the relay-message framing (`nostr_relay`) it builds on
//! are offline + unit-tested. `NostrWs` is intentionally a concrete async client
//! (publish + pull) rather than a `Transport` trait impl: the existing
//! HTTP-slot relay (`relay_client`) is synchronous, so unifying the two behind
//! one trait is a separate refactor (RFC-007 §1) deferred until there is a
//! second async transport to justify the abstraction.
//!
//! Delivery semantics:
//! - **publish** sends an `EVENT` and awaits the relay's `OK <id> <accepted>`.
//! - **pull** opens a `REQ` (e.g. a `#p` filter for events addressed to our
//!   npub), collects `EVENT`s until `EOSE`, then `CLOSE`s. Each event is
//!   transport-verified (`nostr_event::verify_and_decode`) before it is
//!   returned, so a relay cannot inject an event with a bad id/signature.
//!
//! Every relay read is bounded by a timeout so a silent or slow relay can't
//! wedge the caller.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::nostr_event::{NostrEvent, verify_and_decode};
use crate::nostr_relay::{ClientMessage, Filter, RelayMessage};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Default per-read timeout. A relay that doesn't answer within this window is
/// treated as unavailable for that operation.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// A connected Nostr relay WebSocket.
pub struct NostrWs {
    ws: Ws,
    relay_url: String,
    read_timeout: Duration,
}

impl NostrWs {
    /// Connect to a relay. `url` is `ws://…` or `wss://…`.
    pub async fn connect(url: &str) -> Result<Self> {
        let (ws, _resp) = tokio_tungstenite::connect_async(url)
            .await
            .with_context(|| format!("nostr relay connect {url}"))?;
        Ok(Self {
            ws,
            relay_url: url.to_string(),
            read_timeout: DEFAULT_READ_TIMEOUT,
        })
    }

    /// The relay URL this client is connected to.
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Override the per-read timeout (the default is 15s).
    pub fn with_read_timeout(mut self, t: Duration) -> Self {
        self.read_timeout = t;
        self
    }

    /// Publish `event`; await the relay's `OK`. Returns whether the relay
    /// accepted it. `NOTICE` / unrelated messages are skipped while waiting.
    pub async fn publish(&mut self, event: &NostrEvent) -> Result<bool> {
        let payload = ClientMessage::Event(event.clone()).to_json_string();
        self.ws
            .send(Message::Text(payload.into()))
            .await
            .context("send EVENT")?;
        loop {
            let text = self.recv_text().await?;
            if let Ok(RelayMessage::Ok {
                event_id, accepted, ..
            }) = RelayMessage::parse(&text)
                && event_id == event.id
            {
                return Ok(accepted);
            }
            // Any other message (NOTICE, a stray EVENT, parse error) — keep
            // waiting for OUR OK.
        }
    }

    /// Subscribe with `filter`, collect events until `EOSE`, then `CLOSE`.
    /// Returns only events whose NIP-01 id + schnorr signature verify
    /// (`verify_and_decode`) — the caller still verifies the inner wire
    /// signature + the D3.1 binding before trusting the message.
    pub async fn pull(&mut self, filter: Filter) -> Result<Vec<NostrEvent>> {
        let sub = "wire-pull";
        let req = ClientMessage::Req {
            sub_id: sub.to_string(),
            filters: vec![filter],
        }
        .to_json_string();
        self.ws
            .send(Message::Text(req.into()))
            .await
            .context("send REQ")?;

        let mut out = Vec::new();
        loop {
            let text = self.recv_text().await?;
            match RelayMessage::parse(&text) {
                // Keep only transport-sound events for our sub. A relay can hand
                // us anything; one that fails id/sig verification falls through to
                // `_` below and is silently dropped.
                Ok(RelayMessage::Event { sub_id, event })
                    if sub_id == sub && verify_and_decode(&event).is_ok() =>
                {
                    out.push(event);
                }
                Ok(RelayMessage::Eose(s)) if s == sub => break,
                Ok(RelayMessage::Closed { sub_id, message }) if sub_id == sub => {
                    bail!("relay closed subscription: {message}");
                }
                _ => {} // other subs / notices — ignore
            }
        }

        // Best-effort unsubscribe.
        let close = ClientMessage::Close(sub.to_string()).to_json_string();
        let _ = self.ws.send(Message::Text(close.into())).await;
        Ok(out)
    }

    /// Read the next text frame, skipping ping/pong/binary, bounded by the read
    /// timeout. Errors on close / timeout / transport error.
    async fn recv_text(&mut self) -> Result<String> {
        loop {
            let next = tokio::time::timeout(self.read_timeout, self.ws.next())
                .await
                .map_err(|_| anyhow!("relay read timed out after {:?}", self.read_timeout))?;
            match next {
                Some(Ok(Message::Text(t))) => return Ok(t.to_string()),
                Some(Ok(Message::Close(_))) | None => bail!("relay closed the connection"),
                Some(Ok(_)) => continue, // ping/pong/binary — skip
                Some(Err(e)) => return Err(anyhow!("relay read error: {e}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr_event::wire_to_nostr;
    use crate::nostr_key::generate_transport_key;
    use crate::signing::{generate_keypair, sign_message_v31};
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    fn an_event(content: &str) -> NostrEvent {
        let (sk, pk) = generate_keypair();
        let msg = json!({
            "timestamp": "2026-06-14T12:00:00Z",
            "from": "did:wire:slate-lotus-1",
            "kind": 1,
            "body": {"content": content},
        });
        let wire = sign_message_v31(&msg, &sk, &pk, "slate-lotus").unwrap();
        let (nsk, _x) = generate_transport_key();
        wire_to_nostr(&wire, &nsk).unwrap()
    }

    /// A minimal in-process NIP-01 relay mock: accepts one connection, stores
    /// published EVENTs, answers a REQ with the stored events + EOSE, OKs every
    /// publish. Enough to exercise NostrWs end-to-end without a subprocess.
    async fn spawn_mock_relay() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut stored: Vec<Value> = Vec::new();
            while let Some(Ok(msg)) = ws.next().await {
                let Message::Text(t) = msg else { continue };
                let v: Value = match serde_json::from_str(&t) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let arr = v.as_array().cloned().unwrap_or_default();
                match arr.first().and_then(Value::as_str) {
                    Some("EVENT") => {
                        let ev = arr[1].clone();
                        let id = ev
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        stored.push(ev);
                        let ok = json!(["OK", id, true, ""]).to_string();
                        ws.send(Message::Text(ok.into())).await.unwrap();
                    }
                    Some("REQ") => {
                        let sub = arr[1].as_str().unwrap_or("").to_string();
                        for ev in &stored {
                            let line = json!(["EVENT", sub, ev]).to_string();
                            ws.send(Message::Text(line.into())).await.unwrap();
                        }
                        let eose = json!(["EOSE", sub]).to_string();
                        ws.send(Message::Text(eose.into())).await.unwrap();
                    }
                    Some("CLOSE") => break,
                    _ => {}
                }
            }
        });
        format!("ws://{addr}")
    }

    #[tokio::test]
    async fn publish_then_pull_roundtrips_through_a_relay() {
        let url = spawn_mock_relay().await;
        let mut client = NostrWs::connect(&url)
            .await
            .unwrap()
            .with_read_timeout(Duration::from_secs(5));

        let ev = an_event("hello over the wire");
        // Publish → relay OKs it.
        assert!(client.publish(&ev).await.unwrap(), "relay should accept");

        // Pull → we get our event back, transport-verified.
        let got = client.pull(Filter::default()).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], ev);
        // And it decodes to the inner wire event.
        let wire = verify_and_decode(&got[0]).unwrap();
        assert_eq!(wire["body"]["content"], "hello over the wire");
    }

    #[tokio::test]
    async fn pull_drops_events_failing_transport_verification() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A hostile relay that injects one good event + one tampered one.
        let good = an_event("legit");
        let mut bad = an_event("forged");
        bad.content.push_str("tamper"); // id no longer matches → verify fails
        let good_c = good.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(Message::Text(t))) = ws.next().await {
                let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                if v.get(0).and_then(Value::as_str) == Some("REQ") {
                    let sub = v[1].as_str().unwrap().to_string();
                    for ev in [&good_c, &bad] {
                        ws.send(Message::Text(json!(["EVENT", sub, ev]).to_string().into()))
                            .await
                            .unwrap();
                    }
                    ws.send(Message::Text(json!(["EOSE", sub]).to_string().into()))
                        .await
                        .unwrap();
                }
            }
        });
        let mut client = NostrWs::connect(&format!("ws://{addr}"))
            .await
            .unwrap()
            .with_read_timeout(Duration::from_secs(5));
        let got = client.pull(Filter::default()).await.unwrap();
        // Only the sound event survives; the tampered one is dropped.
        assert_eq!(got, vec![good]);
    }
}
