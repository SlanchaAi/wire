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
use std::time::{Duration, Instant};

/// Stream-state file written by `run_subscriber` on every state
/// transition. Surfaced via `tool_status` so an operator can tell
/// "stream alive" (live monitor will fire on inbound) from
/// "polling-only" (daemon up, monitor will wait until next poll). The
/// file is best-effort; missing/unreadable counts as "unknown" and the
/// reader degrades gracefully.
fn stream_state_path() -> Option<std::path::PathBuf> {
    crate::config::state_dir()
        .ok()
        .map(|d| d.join("stream_state.json"))
}

/// Write the current stream-state snapshot. Best-effort; an unwritable
/// state-dir does not block the subscriber loop. Schema-versioned so
/// future fields (per-event count, reconnect attempt index) can land
/// additively without breaking older readers.
fn write_stream_state(state: &str, last_event_at: Option<&str>, reconnects: u64) {
    if let Some(path) = stream_state_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let ts = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let body = serde_json::json!({
            "schema": "wire-daemon-stream-state-v1",
            "ts": ts,
            "state": state,
            "last_event_at": last_event_at,
            "reconnect_count": reconnects,
        });
        let _ = std::fs::write(&path, serde_json::to_vec_pretty(&body).unwrap_or_default());
    }
}

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

/// A clean-closed SSE stream that stayed open at least this long is treated as
/// a healthy long-lived stream → reconnect immediately. Shorter than that and
/// the close is "instant EOF" (a saturated relay accepting then dropping the
/// body), which gets the exponential backoff instead of a zero-delay re-spin.
/// Well under the 30s server keepalive so genuine streams always clear it.
const STREAM_HEALTHY_SECS: u64 = 10;

fn run_subscriber(wake_tx: Sender<()>) {
    let mut backoff_secs = 1u64;
    let mut reconnects: u64 = 0;
    let mut last_event_at: Option<String> = None;
    write_stream_state("connecting", last_event_at.as_deref(), reconnects);
    loop {
        // We wrap a closure so the connect-and-read inner can stamp
        // last_event_at into our outer scope on every wake without
        // restructuring the existing signature. The Vec<String> carries
        // at most one timestamp (latest); polled by reference below.
        let mut latest_event_ts: Vec<String> = Vec::new();
        // v0.14.3 (coral dogfood 2026-06-01): pass accumulated
        // `last_event_at` + `reconnects` so the "connected" write
        // inside connect_and_read preserves them. Pre-fix, every
        // successful reconnect overwrote stream_state.json with
        // `last_event_at:null, reconnect_count:0` even after
        // events had arrived + previous reconnects had occurred.
        // Operator surface always read "last event never" on
        // long-running daemons.
        let connected_at = Instant::now();
        let outcome = connect_and_read(
            &wake_tx,
            &mut latest_event_ts,
            last_event_at.as_deref(),
            reconnects,
        );
        let stayed_open = connected_at.elapsed();
        if let Some(ts) = latest_event_ts.into_iter().last() {
            last_event_at = Some(ts);
        }
        match outcome {
            Ok(()) => {
                reconnects += 1;
                // A long-lived stream closing (server reload) → reconnect fast.
                // But a relay that ACCEPTS the connection (HTTP 200) then drops
                // the body immediately — exactly what a concurrency-saturated
                // instance does — returns Ok(()) instantly, and resetting backoff
                // to 1 with no sleep span-loops the relay (amplifying the very
                // saturation that caused the close). Only fast-reconnect if the
                // stream actually stayed open; otherwise floor it with the same
                // backoff as the error path.
                if stayed_open >= Duration::from_secs(STREAM_HEALTHY_SECS) {
                    backoff_secs = 1;
                    eprintln!("daemon-stream: connection closed cleanly, reconnecting");
                    write_stream_state("reconnecting", last_event_at.as_deref(), reconnects);
                } else {
                    eprintln!(
                        "daemon-stream: stream closed after {stayed_open:?} (instant EOF — relay may be saturated); reconnecting in {backoff_secs}s"
                    );
                    write_stream_state("reconnecting", last_event_at.as_deref(), reconnects);
                    std::thread::sleep(Duration::from_secs(backoff_secs));
                    backoff_secs = (backoff_secs * 2).min(30);
                }
            }
            Err(e) => {
                reconnects += 1;
                // A stream that stayed healthy for a while and then died DIRTY
                // (mid-stream reset / relay restart surfacing as Err, not a clean
                // EOF) shouldn't carry backoff accrued from earlier instant
                // failures — otherwise repeated healthy-then-Err cycles ratchet
                // toward the 30s cap despite each connection being fine. Reset
                // first, mirroring the clean-close healthy path above.
                if stayed_open >= Duration::from_secs(STREAM_HEALTHY_SECS) {
                    backoff_secs = 1;
                }
                eprintln!("daemon-stream: error {e:#}; reconnecting in {backoff_secs}s");
                write_stream_state("error", last_event_at.as_deref(), reconnects);
                std::thread::sleep(Duration::from_secs(backoff_secs));
                backoff_secs = (backoff_secs * 2).min(30);
            }
        }
    }
}

fn connect_and_read(
    wake_tx: &Sender<()>,
    last_event_ts: &mut Vec<String>,
    accumulated_last_event_at: Option<&str>,
    accumulated_reconnects: u64,
) -> Result<()> {
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
    // v0.5.13: honor WIRE_INSECURE_SKIP_TLS_VERIFY on the stream sub too,
    // matching the rest of the wire HTTPS surface (issue #6).
    let client = {
        let cfg = crate::tls::shared_client_config();
        let mut b = reqwest::blocking::Client::builder()
            // v0.14.2 #177: same dual-roots config the rest of wire's
            // HTTPS surface uses. SSE used to build its own bare
            // client which inherited reqwest's default root source
            // (webpki only under #176's feature flag); now both
            // surfaces share `tls::shared_client_config`.
            .use_preconfigured_tls((*cfg).clone())
            // No total timeout: stream is expected to stay open indefinitely.
            // TCP keepalive catches a hung connection (server crashed, network
            // black hole) — the BufReader::lines loop returns Err and the
            // outer reconnect-with-backoff kicks in.
            // v0.14.2 (#162 fix #7): tightened TCP keepalive from 60s to
            // 30s so the kernel-level dead-connection check kicks in sooner
            // when the SSE upstream goes silent. reqwest's blocking client
            // doesn't expose a per-read body timeout (the obvious shape for
            // this) — `Client::timeout` is a total-request timeout, the
            // wrong primitive for a long-lived stream. A more surgical
            // per-read timeout via the underlying socket needs a custom
            // reader and is deferred to v0.15; tightening keepalive is the
            // observable improvement we can ship today. Honey-pine field
            // guide failure-mode #2 ("daemon alive but stream wedged") is
            // also surfaced via the new `stream_state.json` so callers can
            // detect the polling-only degradation without waiting for the
            // wedge to clear.
            .tcp_keepalive(Some(Duration::from_secs(30)));
        if std::env::var(crate::relay_client::INSECURE_SKIP_TLS_ENV)
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
        {
            b = b.danger_accept_invalid_certs(true);
        }
        b.build()?
    };

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

    // v0.14.2 (#162 fix #7): mark the stream "connected" once the
    // server has accepted the slot_token + the body read starts. The
    // outer loop transitions to "reconnecting" on clean close or
    // "error" on failure; this is the only place we can confidently
    // claim "stream is live and pulling events for monitor".
    //
    // v0.14.3 (coral dogfood 2026-06-01): preserve accumulated
    // last_event_at + reconnect counter instead of writing null/0
    // and clobbering history every reconnect.
    write_stream_state(
        "connected",
        accumulated_last_event_at,
        accumulated_reconnects,
    );
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
            // v0.14.2 (#162 fix #7): stamp the most-recent event-arrival
            // timestamp for `stream_state.json`. Push, don't replace;
            // outer loop reads .last() so we only keep the latest. Best-
            // effort format; failure here = no stamp this cycle.
            let now = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            if !now.is_empty() {
                last_event_ts.push(now);
            }
        }
    }
    Ok(())
}
