//! Daemon-side SSE stream subscriber (R1 phase 2, v0.5.6).
//!
//! Opens a long-lived `GET /v1/events/:slot_id/stream` connection to the
//! relay using the operator's own slot_token, parses SSE `data:` lines as
//! they arrive, and pings a wake-channel for each event. The daemon's main
//! loop replaces `std::thread::sleep(interval)` with `recv_timeout(interval)`
//! against this channel, so a posted event traverses sender → relay →
//! subscriber → local inbox in ~10-50ms instead of waiting for the next
//! ~5s poll tick.
//!
//! Failure model: if the stream errors or disconnects, the subscriber
//! reconnects with exponential backoff (1s → 2s → 4s → 8s → 30s cap). The
//! daemon's regular polling loop is unaffected and continues as a safety
//! net — stream-down does NOT mean events-down. Operator running
//! `wire daemon` with no relay reachability sees both signals (stream
//! reconnect retries + poll errors) and can diagnose.
//!
//! Design note: this is a one-way wake signal, not the data path. The
//! actual `run_sync_pull` re-fetches via `list_events` so we get
//! signature verification, dedup, and inbox write through the exact same
//! code path as polling. The stream only changes WHEN pull runs, not HOW.

use anyhow::Result;
use std::io::{BufRead, BufReader};
use std::sync::mpsc::Sender;
use std::time::Duration;

/// Spawn the stream-subscriber thread. Returns immediately; the thread
/// runs until process exit. `wake_tx` is signaled on every received SSE
/// `data:` line (any event, no parsing of body). Errors during connect or
/// stream-read trigger reconnect-with-backoff, never panic.
pub fn spawn_stream_subscriber(wake_tx: Sender<()>) {
    std::thread::Builder::new()
        .name("wire-stream-sub".into())
        .spawn(move || run_subscriber(wake_tx))
        .expect("spawn wire-stream-sub thread");
}

fn run_subscriber(wake_tx: Sender<()>) {
    let mut backoff_secs = 1u64;
    loop {
        match connect_and_read(&wake_tx) {
            Ok(()) => {
                // Stream closed cleanly (e.g., server reload). Quick reconnect.
                backoff_secs = 1;
                eprintln!("daemon-stream: connection closed cleanly, reconnecting");
            }
            Err(e) => {
                eprintln!("daemon-stream: error {e:#}; reconnecting in {backoff_secs}s");
                std::thread::sleep(Duration::from_secs(backoff_secs));
                backoff_secs = (backoff_secs * 2).min(30);
            }
        }
    }
}

fn connect_and_read(wake_tx: &Sender<()>) -> Result<()> {
    // Re-read relay-state on each reconnect so a fresh slot allocation /
    // rotation picks up automatically without daemon restart.
    let state = crate::config::read_relay_state()?;
    let self_state = state
        .get("self")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let url = self_state
        .get("relay_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let slot_id = self_state
        .get("slot_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let slot_token = self_state
        .get("slot_token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if url.is_empty() || slot_id.is_empty() || slot_token.is_empty() {
        return Err(anyhow::anyhow!(
            "stream-sub: relay-state missing self.{{relay_url,slot_id,slot_token}} — sleep until next reconnect"
        ));
    }

    let stream_url = format!("{url}/v1/events/{slot_id}/stream");
    let client = reqwest::blocking::Client::builder()
        // No total timeout: stream is expected to stay open indefinitely.
        // TCP keepalive catches a hung connection (server crashed, network
        // black hole) — the BufReader::lines loop returns Err and the
        // outer reconnect-with-backoff kicks in.
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .build()?;

    let resp = client
        .get(&stream_url)
        .header("Accept", "text/event-stream")
        .bearer_auth(slot_token)
        .send()?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "stream-sub: server returned {} on connect",
            resp.status()
        ));
    }

    let reader = BufReader::new(resp);
    for line in reader.lines() {
        let line = line?;
        // SSE protocol: each event is one or more `field: value` lines
        // followed by a blank line. We only care about `data:` lines —
        // every event the relay sends is a `data: <json>` line. Any other
        // field (comments via `:keepalive`, etc.) is ignored. Empty line
        // is the event separator; benign to ignore.
        if line.starts_with("data:") {
            // Fire wake signal. If the main loop is busy, the channel
            // backs up to a small buffer; we don't block — drop on full
            // since multiple wakes coalesce into a single pull anyway.
            let _ = wake_tx.send(());
        }
    }
    Ok(())
}
