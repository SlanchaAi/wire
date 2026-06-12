//! MCP (Model Context Protocol) server over stdio.
//!
//! Spec: https://modelcontextprotocol.io/specification/2025-06-18
//!
//! Wire protocol: JSON-RPC 2.0, one message per line on stdin and stdout.
//! stderr is reserved for logs (clients display them as server-side diagnostics).
//!
//! Tools exposed:
//!
//! **Identity / messaging (always agent-safe)**
//!   - `wire_whoami`         — read self DID + fingerprint + capabilities
//!   - `wire_peers`          — list pinned peers + tiers
//!   - `wire_send`           — sign + queue an event to a peer
//!   - `wire_tail`           — read recent signed events from inbox
//!   - `wire_verify`         — verify a signed event JSON
//!
//! **Pairing (agent drives; operator gates via bilateral accept)**
//!   - `wire_init`           — idempotent identity creation; same handle = no-op,
//!     different handle = error (cannot re-key silently)
//!   - `wire_dial`           — initiate a pair by handle (`<handle>@<relay>`);
//!     the canonical pairing path
//!   - `wire_pending` / `wire_accept` / `wire_reject` — inbound bilateral gate
//!   - `wire_invite_mint` / `wire_invite_accept` — single-paste invite-URL pair
//!
//! The SAS / code-phrase / SPAKE2 ceremony (`wire_pair_initiate` / `_join` /
//! `_confirm` and their detached variants) was removed in the RFC-005
//! follow-on — `wire_dial` is the sole canonical pairing path.

use anyhow::Result;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};

/// Shared MCP-session state. Today: subscribed resource URIs + a writer
/// channel for unsolicited notifications (push). Future per-session cursors,
/// etc. go here.
#[derive(Clone, Default)]
pub struct McpState {
    /// Resource URIs the client has subscribed to. Wildcard support is
    /// intentionally NOT done — clients subscribe to specific URIs and
    /// receive `notifications/resources/updated` only for those URIs.
    pub subscribed: Arc<Mutex<HashSet<String>>>,
    /// Writer-channel sender for emitting unsolicited notifications
    /// (notifications/resources/list_changed, etc.). Populated by `run()`
    /// before tools are dispatched; None in unit tests.
    pub notif_tx: Arc<Mutex<Option<std::sync::mpsc::Sender<String>>>>,
}

const PROTOCOL_VERSION: &str = "2025-06-18";
const SERVER_NAME: &str = "wire";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run the MCP server until stdin closes.
///
/// Threading model (Goal 2.1):
///
/// - **Main thread**: reads stdin line-by-line, parses JSON-RPC, calls
///   `handle_request` to compute a response, hands it to the writer via the
///   mpsc channel.
/// - **Writer thread**: single owner of stdout. Drains responses + push
///   notifications from the channel, writes each as one line + flush. Single
///   writer = no interleaving between responses and notifications.
/// - **Watcher thread**: holds an `InboxWatcher::from_head` (starts at EOF —
///   each MCP session only sees fresh events). Polls every 2s. For each new
///   inbox event, checks the shared subscription set; if any matching
///   `wire://inbox/<peer>` or `wire://inbox/all` URI is subscribed, pushes
///   a `notifications/resources/updated` message into the channel.
///
/// v0.6.7: `detect_session_wire_home` moved to
/// `session::detect_session_wire_home` (shared with the CLI auto-detect at
/// `cli::run` entry). The mcp-only wrapper was removed; the regression test
/// now calls the session-module version directly.
pub fn run() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    // v0.6.1: auto-detect WIRE_HOME from cwd. If the operator already
    // set it (explicit override via `.mcp.json env.WIRE_HOME`), respect
    // that. Else: if the cwd maps to a `wire session` entry in the
    // registry, adopt that session's WIRE_HOME for this MCP process so
    // every subsequent tool call routes to the right inbox / outbox /
    // identity.
    //
    // v0.6.7: identical helper now also runs at CLI entry (cli::run),
    // so `wire whoami` / `wire monitor` from a session cwd resolve to
    // the same identity the MCP server uses. Before v0.6.7 the CLI
    // silently fell back to the default WIRE_HOME, leaving operators
    // unable to tell which identity their monitor was tailing.
    crate::session::maybe_adopt_session_wire_home("mcp");

    // v0.7.0-alpha.2: if auto-detect found no session for this cwd
    // (including via parent-walk), create one inline so every Claude
    // tab in a fresh project gets its own wire identity rather than
    // silently sharing the machine-wide default. Opt out via
    // `WIRE_AUTO_INIT=0`.
    crate::cli::maybe_auto_init_cwd_session("mcp");

    // v0.13: a session-keyed WIRE_HOME (sessions/by-key/<hash>) starts empty.
    // Bootstrap its identity on first MCP start — one-name init + federation
    // slot + phonebook claim — so each Claude session is its own reachable,
    // claimed identity. One-time per home (gated on is_initialized);
    // best-effort (offline → init-only, no claim). Skipped under
    // WIRE_MCP_SKIP_AUTO_UP (tests + manual-identity operators).
    ensure_session_bootstrapped();

    // v0.15.x: minting an identity isn't enough — without a running sync loop
    // the session is "born deaf" (never pulls inbound, never pushes outbound),
    // the #1 MCP first-run failure. `ensure_session_bootstrapped` only creates
    // identity (and early-returns for already-initialized homes), so arm the
    // daemon unconditionally here. Idempotent (singleton-guarded) and gated on
    // an existing identity + the same skip env bootstrap honors.
    if std::env::var("WIRE_MCP_SKIP_AUTO_UP").is_err()
        && crate::config::is_initialized().unwrap_or(false)
    {
        let _ = crate::ensure_up::ensure_daemon_running();
    }

    // v0.6.10: surface multi-agent identity collisions explicitly.
    // Two Claudes (or any MCP-host pair) launched in the same cwd
    // auto-detect into the same wire session and silently share an
    // inbox cursor. v0.6.7 made this invisible by design ("just adopt
    // the cwd's session"); operators hit it as "they look identical"
    // and burn hours debugging. The warning gives them a clear
    // remediation path the first time they see it.
    crate::session::warn_on_identity_collision(std::process::id(), "mcp");

    let state = McpState::default();
    let shutdown = Arc::new(AtomicBool::new(false));

    let (tx, rx) = mpsc::channel::<String>();

    // Expose the tx clone via state so tool handlers can push unsolicited
    // notifications (notifications/resources/list_changed after a pair pin).
    if let Ok(mut g) = state.notif_tx.lock() {
        *g = Some(tx.clone());
    }

    // Writer thread — single owner of stdout. Exits when all senders drop.
    let writer_handle = std::thread::spawn(move || {
        let stdout = std::io::stdout();
        let mut w = stdout.lock();
        while let Ok(line) = rx.recv() {
            if writeln!(w, "{line}").is_err() {
                break;
            }
            if w.flush().is_err() {
                break;
            }
        }
    });

    // Watcher thread — polls inbox every 2s and emits
    // notifications/resources/updated on grow. Observes `shutdown` so we
    // can exit cleanly on stdin EOF (otherwise its tx_w clone keeps the
    // writer thread blocked on rx.recv forever).
    let subs_w = state.subscribed.clone();
    let tx_w = tx.clone();
    let shutdown_w = shutdown.clone();
    let watcher_handle = std::thread::spawn(move || {
        let mut watcher = match crate::inbox_watch::InboxWatcher::from_head() {
            Ok(w) => w,
            Err(_) => return,
        };
        let poll_interval = Duration::from_secs(2);
        let mut next_poll = Instant::now() + poll_interval;
        loop {
            if shutdown_w.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
            if Instant::now() < next_poll {
                continue;
            }
            next_poll = Instant::now() + poll_interval;
            let subs_snapshot = match subs_w.lock() {
                Ok(g) => g.clone(),
                Err(_) => return,
            };

            let mut affected: HashSet<String> = HashSet::new();

            // ---- inbox events ----
            if !subs_snapshot.is_empty()
                && let Ok(events) = watcher.poll()
            {
                for ev in &events {
                    if subs_snapshot.contains("wire://inbox/all") {
                        affected.insert("wire://inbox/all".to_string());
                    }
                    let peer_uri = format!("wire://inbox/{}", ev.peer);
                    if subs_snapshot.contains(&peer_uri) {
                        affected.insert(peer_uri);
                    }
                }
            }

            for uri in affected {
                let notif = json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": uri}
                });
                if tx_w.send(notif.to_string()).is_err() {
                    return;
                }
            }
        }
    });

    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            // EOF — signal watcher to exit; clear the notif_tx Sender clone
            // that state holds (otherwise writer's rx.recv() never sees
            // all-senders-dropped); drop main tx; wait for worker threads.
            shutdown.store(true, Ordering::SeqCst);
            if let Ok(mut g) = state.notif_tx.lock() {
                *g = None;
            }
            drop(tx);
            let _ = watcher_handle.join();
            let _ = writer_handle.join();
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err = error_response(&Value::Null, -32700, &format!("parse error: {e}"));
                let _ = tx.send(err.to_string());
                continue;
            }
        };
        let response = handle_request(&request, &state);
        // Notifications (no `id`) get no response.
        if response.get("id").is_some() || response.get("error").is_some() {
            let _ = tx.send(response.to_string());
        }
    }
}

fn handle_request(req: &Value, state: &McpState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = match req.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => return error_response(&id, -32600, "missing method"),
    };
    match method {
        "initialize" => handle_initialize(&id),
        "notifications/initialized" => Value::Null, // notification — no reply
        "tools/list" => handle_tools_list(&id),
        "tools/call" => handle_tools_call(&id, req.get("params").unwrap_or(&Value::Null), state),
        "resources/list" => handle_resources_list(&id),
        "resources/read" => handle_resources_read(&id, req.get("params").unwrap_or(&Value::Null)),
        "resources/subscribe" => {
            handle_resources_subscribe(&id, req.get("params").unwrap_or(&Value::Null), state)
        }
        "resources/unsubscribe" => {
            handle_resources_unsubscribe(&id, req.get("params").unwrap_or(&Value::Null), state)
        }
        "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
        other => error_response(&id, -32601, &format!("method not found: {other}")),
    }
}

// ---------- resources (Goal 2) ----------
//
// MCP resources expose semi-static state for agents that want a "read this
// when relevant" surface instead of polling tools. v0.2 ships read-only;
// subscribe (push-notify on inbox grow) is v0.2.1 — requires a background
// watcher thread + async stdout writer.
//
// Resource URI scheme:
//   wire://inbox/<peer>    last 50 verified events for that pinned peer
//   wire://inbox/all       last 50 events across all peers, newest first

fn handle_resources_list(id: &Value) -> Value {
    let mut resources = vec![json!({
        "uri": "wire://inbox/all",
        "name": "wire inbox (all peers)",
        "description": "Most recent verified events from all pinned peers, JSONL.",
        "mimeType": "application/x-ndjson"
    })];

    if let Ok(trust) = crate::config::read_trust() {
        let agents = trust
            .get("agents")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let self_did = crate::config::read_agent_card()
            .ok()
            .and_then(|c| c.get("did").and_then(Value::as_str).map(str::to_string));
        for (handle, agent) in agents.iter() {
            let did = agent
                .get("did")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if Some(did.as_str()) == self_did.as_deref() {
                continue;
            }
            resources.push(json!({
                "uri": format!("wire://inbox/{handle}"),
                "name": format!("inbox from {handle}"),
                "description": format!("Recent verified events from did:wire:{handle}."),
                "mimeType": "application/x-ndjson"
            }));
        }
    }

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "resources": resources
        }
    })
}

fn handle_resources_subscribe(id: &Value, params: &Value, state: &McpState) -> Value {
    let uri = match params.get("uri").and_then(Value::as_str) {
        Some(u) => u.to_string(),
        None => return error_response(id, -32602, "missing 'uri'"),
    };
    // Validate the URI shape. Accept wire://inbox/<peer>, wire://inbox/all.
    // Anything else is rejected so we don't pile up dead subscriptions.
    let inbox_peer = parse_inbox_uri(&uri);
    if let Some(ref p) = inbox_peer
        && p.starts_with("__invalid__")
    {
        return error_response(
            id,
            -32602,
            "subscribe URI must be wire://inbox/<peer> or wire://inbox/all",
        );
    }
    if let Ok(mut g) = state.subscribed.lock() {
        g.insert(uri);
    }
    json!({"jsonrpc": "2.0", "id": id, "result": {}})
}

fn handle_resources_unsubscribe(id: &Value, params: &Value, state: &McpState) -> Value {
    let uri = match params.get("uri").and_then(Value::as_str) {
        Some(u) => u.to_string(),
        None => return error_response(id, -32602, "missing 'uri'"),
    };
    if let Ok(mut g) = state.subscribed.lock() {
        g.remove(&uri);
    }
    json!({"jsonrpc": "2.0", "id": id, "result": {}})
}

fn handle_resources_read(id: &Value, params: &Value) -> Value {
    let uri = match params.get("uri").and_then(Value::as_str) {
        Some(u) => u,
        None => return error_response(id, -32602, "missing 'uri'"),
    };
    let peer_opt = parse_inbox_uri(uri);
    match read_inbox_resource(peer_opt) {
        Ok(payload) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/x-ndjson",
                    "text": payload,
                }]
            }
        }),
        Err(e) => error_response(id, -32603, &e.to_string()),
    }
}

/// Parse `wire://inbox/<peer>` → Some(peer). `wire://inbox/all` → None.
/// Anything else → returns a marker that triggers "unknown URI" on read.
fn parse_inbox_uri(uri: &str) -> Option<String> {
    if let Some(rest) = uri.strip_prefix("wire://inbox/") {
        if rest == "all" {
            return None;
        }
        if !rest.is_empty() {
            return Some(rest.to_string());
        }
    }
    Some(format!("__invalid__{uri}"))
}

fn read_inbox_resource(peer_opt: Option<String>) -> Result<String, String> {
    const LIMIT: usize = 50;
    // Validate URI shape FIRST — an invalid URI is an error regardless of
    // whether the inbox dir exists yet.
    if let Some(ref p) = peer_opt
        && p.starts_with("__invalid__")
    {
        return Err(
            "unknown resource URI (must be wire://inbox/<peer> or wire://inbox/all)".into(),
        );
    }
    let inbox = crate::config::inbox_dir().map_err(|e| e.to_string())?;
    if !inbox.exists() {
        return Ok(String::new());
    }
    let trust = crate::config::read_trust().map_err(|e| e.to_string())?;

    let paths: Vec<std::path::PathBuf> = match peer_opt {
        Some(p) => {
            let path = inbox.join(format!("{p}.jsonl"));
            if !path.exists() {
                return Ok(String::new());
            }
            vec![path]
        }
        None => std::fs::read_dir(&inbox)
            .map_err(|e| e.to_string())?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("jsonl"))
            .collect(),
    };

    let mut events: Vec<(String, bool, Value)> = Vec::new();
    for path in paths {
        let body = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let peer = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        for line in body.lines() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let verified = crate::signing::verify_message_v31(&event, &trust).is_ok();
            events.push((peer.clone(), verified, event));
        }
    }
    // Newest last (JSONL append order is chronological); take tail LIMIT.
    let take_from = events.len().saturating_sub(LIMIT);
    let tail = &events[take_from..];

    // D1: our seed, to decrypt enc-bearing bodies for the agent reading this
    // resource. The on-disk JSONL stays verbatim ciphertext; only the response
    // body is decrypted (and a `dec: true` flag marks it).
    let seed: Option<[u8; 32]> = crate::config::read_private_key()
        .ok()
        .and_then(|v| v.get(..32).and_then(|s| <[u8; 32]>::try_from(s).ok()));

    let mut out = String::new();
    for (_peer, verified, mut event) in tail.iter().cloned() {
        // Decrypt for agent consumption (verify-gated inside open_event_body).
        if event.get("enc").and_then(Value::as_str)
            == Some(crate::enc::wire_x25519::ENC_DISCRIMINATOR)
            && let Some(ref s) = seed
            && let Ok(Some(plain)) = crate::enc::wire_x25519::open_event_body(&event, &trust, s)
            && let Some(obj) = event.as_object_mut()
        {
            obj.insert("body".into(), plain);
            obj.insert("dec".into(), json!(true));
        }
        if let Some(obj) = event.as_object_mut() {
            obj.insert("verified".into(), json!(verified));
        }
        out.push_str(&serde_json::to_string(&event).map_err(|e| e.to_string())?);
        out.push('\n');
    }
    Ok(out)
}

fn handle_initialize(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": false},
                "resources": {
                    "listChanged": false,
                    // Goal 2.1 (v0.2.1): subscribe shipped. A background watcher
                    // thread polls the inbox every 2s and pushes
                    // notifications/resources/updated via a writer-thread channel
                    // for any subscribed URI.
                    "subscribe": true
                }
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
            "instructions": "wire — agent-to-agent comms. Canonical verbs (v0.9+): wire_dial (initiate pair), wire_send (talk; auto-pairs on miss), wire_pending (see inbound requests), wire_accept (consent to a pending pair), wire_reject (refuse), wire_whois (inspect identity), wire_status (daemon + sync health). For cross-machine pairing pass `<handle>@<relay>` to wire_dial. Bilateral: the peer must also accept (wire_accept or wire_dial back) before capability flows in both directions. INBOUND pair requests from strangers land in pending-inbound: call wire_pending to enumerate, surface to operator, then wire_accept or wire_reject. NEVER auto-accept inbound pair requests without operator consent — accepting grants the peer authenticated write access to this agent's inbox. Resources: 'wire://inbox/<peer>' exposes each pinned peer's verified inbox (JSONL). ON SESSION START, DO THIS IMMEDIATELY (every wire session): (1) call wire_status to confirm the sync loop is healthy — `daemon_running:true` + `last_sync_age_seconds < 60`. The daemon is auto-started for you when this MCP server launches, so this is normally already true; if daemon_running is false, run `wire up` (or `wire service install` for a reboot-durable daemon). (2) arm a PERSISTENT stream-watcher on `wire monitor --json` — in Claude Code, the Monitor tool with persistent:true — so peer messages surface live mid-session. The monitor does NOT sync the relay; it only tails the inbox the daemon writes. Both are required. WHEN A PEER MESSAGE ARRIVES, reply to it in your own live context WITHOUT waiting for the operator to prompt you; this is how paired agents collaborate immediately. (Default filter strips pair_drop/pair_drop_ack/heartbeat noise.) v0.14.2: wire_send POSTs synchronously by default — response `status` is the actual relay verdict: `delivered` (event landed on peer's slot), `duplicate` (same event_id already on slot; peer can still pull), `peer_unknown` (peer not pinned — run wire_dial first), `slot_stale` (peer's slot rotated — run wire_dial to re-pair), or `transport_error` (TLS/DNS/relay-5xx; check `reason` field). Pass `queue:true` to opt back into the legacy outbox→daemon-push path for offline-buffer / pre-pair queueing. wire_pull is the symmetric receive primitive — call it to trigger an immediate relay GET instead of waiting for the daemon's 5s pull cycle; returns written[]/rejected[]/total_seen the same way `wire pull --json` does. See docs/AGENT_INTEGRATION.md for the full monitor recipe and THREAT_MODEL.md (T10/T14)."
        }
    })
}

fn handle_tools_list(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "tools": tool_defs(),
        }
    })
}

fn tool_defs() -> Vec<Value> {
    vec![
        json!({
            "name": "wire_whoami",
            "description": "Return this agent's DID, fingerprint, key_id, public key, and capabilities. Read-only.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }),
        json!({
            "name": "wire_peers",
            "description": "List pinned peers with their tier (UNTRUSTED/VERIFIED/ATTESTED) and advertised capabilities. Read-only.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }),
        json!({
            "name": "wire_here",
            "description": "\"Who am I and who can I talk to?\" — the cold-start orientation tool. Returns {self: {handle, did, persona, cwd, wire_home}, sister_sessions: [...], pinned_peers: [...]}. Sister sessions are other agents on THIS machine you can reach with wire_dial by their `session` name (no relay round-trip); pinned_peers are already-paired contacts. Call this first when wire_peers is empty and you need to find a dial target. Read-only.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }),
        json!({
            "name": "wire_status",
            "description": "v0.14.2 — daemon + sync-loop health check. Returns: daemon_running (pidfile pid alive), all_running_pids (pgrep for `wire daemon`), last_sync_age_seconds (age of the most recent successful daemon cycle; null if no cycle ever recorded), outbox_count, inbox_count, peer count. The daemon is auto-started for you on MCP launch; a healthy session shows daemon_running:true + last_sync_age_seconds < 60. Default `wire_send` is synchronous (its own status is the delivery verdict); only `queue:true` sends depend on the daemon to drain — a nonzero outbox_count with a stale last_sync means those are stuck. Read-only.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }),
        json!({
            "name": "wire_send",
            "description": "Sign and send an event to a peer. Synchronous by default (v0.14.2): the response `status` is the actual relay verdict — `delivered`, `duplicate`, `peer_unknown` (run wire_dial first), `slot_stale` (run wire_dial to re-pair), or `transport_error` (see `reason`). Pass `queue:true` to opt into the legacy outbox→daemon-push path (offline buffer / pre-pair). Returns event_id (SHA-256 of canonical body — content-addressed, so identical bodies dedupe). Body may be plain text or JSON. Concurrent sends to different peers are safe; same-peer sends serialize via a per-path lock.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "peer": {"type": "string", "description": "Peer handle (without did:wire: prefix). Must be a pinned peer; check wire_peers first."},
                    "kind": {"type": "string", "description": "Event kind: a name (decision, claim, ack, agent_card, trust_add_key, trust_revoke_key, wire_open, wire_close) or a numeric kind id."},
                    "body": {"type": "string", "description": "Event body. Plain text becomes a JSON string; valid JSON is parsed and embedded structurally."},
                    "time_sensitive_until": {"type": "string", "description": "Optional advisory deadline: duration (`30m`, `2h`, `1d`) or RFC3339 timestamp."}
                },
                "required": ["peer", "kind", "body"]
            }
        }),
        json!({
            "name": "wire_pull",
            "description": "v0.14.2: trigger an immediate, synchronous pull from this agent's relay slot(s). Returns the same shape as `wire pull --json`: written[] (events landed in inbox), rejected[] (failed signature / cursor verify / dedupe), total_seen, cursor_blocked, endpoints_pulled. **Use this when you want events NOW** instead of waiting for the daemon's 5s pull cycle. Symmetric to wire_send's sync POST. Read-only — only consults the relay's GET, no mutations beyond writing inbox.jsonl + advancing per-slot cursors. Idempotent: re-pulling with the same cursor returns nothing new.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }),
        json!({
            "name": "wire_tail",
            "description": "Read recent signed events from this agent's inbox. Each event has a 'verified' field (bool) — the Ed25519 signature was checked against the trust state before the daemon wrote the inbox. **Orientation (wire #79):** defaults to NEWEST-N (last `limit` events across all matched peers, sorted chronologically by timestamp). Pass `oldest: true` for FIFO behaviour (first-N, for inbox replay from the start).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "peer": {"type": "string", "description": "Optional peer handle to filter inbox by."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50, "description": "Max events to return."},
                    "oldest": {"type": "boolean", "default": false, "description": "Return the FIRST `limit` events (oldest-N) instead of the default last-N (newest-N)."}
                },
                "required": []
            }
        }),
        json!({
            "name": "wire_verify",
            "description": "Verify a signed event JSON against the local trust state. Returns {verified: bool, reason?: string}. Use this to validate events received out-of-band (not via the daemon).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "event": {"type": "string", "description": "JSON-encoded signed event."}
                },
                "required": ["event"]
            }
        }),
        json!({
            "name": "wire_init",
            "description": "Rarely needed — identity auto-bootstraps when this MCP server starts. Idempotent manual identity creation: already initialized → returns the existing identity (no-op); different handle → errors (delete config to re-key). The typed handle is vestigial under the one-name rule (your handle is DID-derived). If relay_url is passed and not yet bound, also allocates a relay slot.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "Short handle (becomes did:wire:<handle>). ASCII alphanumeric / '-' / '_' only."},
                    "name": {"type": "string", "description": "Optional display name (defaults to capitalized handle)."},
                    "relay_url": {"type": "string", "description": "Optional relay URL — if set, also binds a relay slot."}
                },
                "required": ["handle"]
            }
        }),
        json!({
            "name": "wire_invite_mint",
            "description": "Mint a single-paste invite URL (v0.4.0). Auto-inits this agent + auto-allocates a relay slot if needed. Hand the URL string to ONE peer (Discord/SMS/voice); when they call wire_invite_accept on it, the daemon completes the pair end-to-end with no SAS digits. Single-use by default; --uses N for multi-accept. TTL 24h by default. Returns {invite_url, ttl_secs, uses}.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "relay_url": {"type": "string", "description": "Override relay for first-time auto-allocate."},
                    "ttl_secs": {"type": "integer", "description": "Invite lifetime in seconds (default 86400)."},
                    "uses": {"type": "integer", "description": "Number of distinct peers that can accept before consumption (default 1)."}
                }
            }
        }),
        json!({
            "name": "wire_invite_accept",
            "description": "Accept a wire invite URL (v0.4.0). Auto-inits this agent + auto-allocates a relay slot if needed (zero prior setup OK). Pins issuer from URL contents, sends our signed agent-card to issuer's slot. Issuer's daemon completes the bilateral pin on next pull. Returns {paired_with, peer_handle, event_id, status}.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full wire://pair?v=1&inv=... URL."}
                },
                "required": ["url"]
            }
        }),
        // v0.5 — agentic hotline.
        json!({
            "name": "wire_add",
            "description": "Bilateral pair (v0.5.14). Resolve a peer handle (`nick@domain`) via the domain's `.well-known/wire/agent`, pin them locally, and deliver a signed pair-intro to their slot. THE PEER MUST ALSO RUN `wire add` (or `wire accept`) ON THEIR SIDE — bilateral-required as of v0.5.14, no auto-pin on receiver. Once both sides have gestured consent, capability flows in both directions. Use this for outgoing pair requests; for incoming pair_drops in the operator's pending-inbound queue, use `wire_accept` or `wire_reject` instead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "Peer handle like `nick@domain`."},
                    "relay_url": {"type": "string", "description": "Override resolver URL (default: `https://<domain>`)."}
                },
                "required": ["handle"]
            }
        }),
        // v0.10.1: canonical MCP names mirroring the operator-facing
        // verbs (wire dial / accept / reject / pending). Deprecated aliases
        // wire_pair_accept / wire_pair_reject / wire_pair_list_inbound were
        // removed from the catalog in RFC-005 Phase 2; calls to those names
        // now return a helpful redirect error (see dispatch).
        json!({
            "name": "wire_dial",
            "description": "v0.8 — go talk to this name. Accepts a character nickname (`noble-slate`), session name, card handle, or DID — or a federation handle (`<handle>@<relay>`). Resolves through the local addressing layer (pinned peers, local sister sessions) or routes federation via `.well-known/wire/agent`. Drives the right pair flow (already-pinned: no-op, local sister: disk-read --local-sister, federation: pair_drop). After this completes the peer is in `wire_peers` and `wire_send` to them works.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Peer name — character nickname / session / handle / DID / `<handle>@<relay>`."}
                },
                "required": ["name"]
            }
        }),
        json!({
            "name": "wire_accept",
            "description": "v0.9 — accept a pending-inbound pair request by character nickname or handle. Replaces deprecated wire_pair_accept. Pins the peer VERIFIED, ships our slot_token via pair_drop_ack, and deletes the pending record. Requires explicit operator consent — surface the request to the user before calling.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "peer": {"type": "string", "description": "Pending peer name (character nickname or card handle, from wire_pending)."}
                },
                "required": ["peer"]
            }
        }),
        json!({
            "name": "wire_reject",
            "description": "v0.9 — refuse a pending-inbound pair request without pairing. Replaces deprecated wire_pair_reject. Idempotent: succeeds with `rejected: false` if no record existed for that peer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "peer": {"type": "string", "description": "Pending peer name (character nickname or card handle)."}
                },
                "required": ["peer"]
            }
        }),
        json!({
            "name": "wire_pending",
            "description": "v0.9 — list pending-inbound pair requests waiting for operator consent. Returns the same flat array as legacy wire_pair_list_inbound. Use on session start (or in response to a `wire — pair request from X` OS toast) to surface inbound requests for accept/reject decisions.",
            "inputSchema": {"type": "object", "properties": {}}
        }),
        json!({
            "name": "wire_claim",
            "description": "Publish this agent in a relay's handle directory so others can reach it by `<persona>@<relay-domain>`. ONE-NAME RULE: the claimed handle is ALWAYS your DID-derived persona — you do not choose it. The `nick` arg is optional + advisory; a value that differs from your persona is ignored (response sets typed_nick_ignored=true). Auto-inits + auto-allocates a relay slot if needed. FCFS — same-DID re-claims allowed (used for profile/slot updates).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "nick": {"type": "string", "description": "Optional + advisory. Ignored if it differs from your DID-derived persona (one-name rule)."},
                    "relay_url": {"type": "string", "description": "Relay to claim on. Default = our relay."},
                    "public_url": {"type": "string", "description": "Public URL the relay should advertise to resolvers."}
                }
            }
        }),
        json!({
            "name": "wire_whois",
            "description": "Look up an agent profile. With no handle, returns the local agent's profile. With a `nick@domain` handle, resolves via that domain's `.well-known/wire/agent` and verifies the returned signed card.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "Optional `nick@domain`. Omit for self."},
                    "relay_url": {"type": "string", "description": "Override resolver URL."}
                }
            }
        }),
        json!({
            "name": "wire_profile_set",
            "description": "Edit a profile field on the local agent's signed agent-card. Field names: display_name, emoji, motto, vibe (array of strings), pronouns, avatar_url, handle (`nick@domain`), now (object). The card is re-signed atomically; the new profile is visible to anyone who resolves us via wire_whois. Use this to let the agent EXPRESS PERSONALITY — choose a motto, an emoji, a vibe.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "field": {"type": "string", "description": "One of: display_name, emoji, motto, vibe, pronouns, avatar_url, handle, now."},
                    "value": {"description": "String for most fields; array for vibe; object for now. Pass JSON null to clear a field."}
                },
                "required": ["field", "value"]
            }
        }),
        json!({
            "name": "wire_profile_get",
            "description": "Return the local agent's full profile (DID + handle + emoji + motto + vibe + pronouns + now). Cheap; no network. Use this to surface 'who am I' to the operator or to compose self-introductions to new peers.",
            "inputSchema": {"type": "object", "properties": {}}
        }),
        // ---- group chat (v0.13.4): a group is a shared relay-room slot; the
        // creator-signed roster carries member keys so members verify each
        // other without pairing. GroupTier (creator/member/introduced) is a
        // SEPARATE axis from bilateral peer trust. ----
        json!({
            "name": "wire_group_create",
            "description": "Create a group chat room (you become the creator). Allocates a shared relay slot whose token is the room key, signs the initial roster, and persists it locally. Returns {id, name, members, relay_url}. Use the returned id with the other wire_group_* tools.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string", "description": "Human label for the group."}},
                "required": ["name"]
            }
        }),
        json!({
            "name": "wire_group_add",
            "description": "Add a bilaterally-VERIFIED pinned peer to a group you created, as a Member. The peer must already be paired + VERIFIED (check wire_peers). Re-signs the roster and queues a signed group_invite to every member (run a normal push/let the daemon deliver). Creator-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group": {"type": "string", "description": "Group id or name."},
                    "peer": {"type": "string", "description": "Handle of a VERIFIED pinned peer."}
                },
                "required": ["group", "peer"]
            }
        }),
        json!({
            "name": "wire_group_send",
            "description": "Post a message to a group room (one signed event to the shared slot; every member reads it). You must have the group locally (created it, were added, or joined by code).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group": {"type": "string", "description": "Group id or name."},
                    "message": {"type": "string", "description": "Message text."}
                },
                "required": ["group", "message"]
            }
        }),
        json!({
            "name": "wire_group_tail",
            "description": "Read recent messages from a group room. Each message has a 'verified' bool (signature checked against the roster + room-announced joiner keys). Also surfaces join notices. Pulls the shared room slot.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group": {"type": "string", "description": "Group id or name."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 20, "description": "Max timeline entries to return."}
                },
                "required": ["group"]
            }
        }),
        json!({
            "name": "wire_group_list",
            "description": "List the groups this agent is in, with each group's members and their GroupTiers (creator/member/introduced). Read-only, local.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }),
        json!({
            "name": "wire_group_invite",
            "description": "Mint a shareable join code for a group — a self-contained token (room coords + signed roster). Anyone you give it to can wire_group_join to enter at Introduced tier. The code IS the room key; share only with people you want in the room.",
            "inputSchema": {
                "type": "object",
                "properties": {"group": {"type": "string", "description": "Group id or name."}},
                "required": ["group"]
            }
        }),
        json!({
            "name": "wire_group_join",
            "description": "Join a group from a code minted by wire_group_invite. Materializes the room locally, pins existing members on the creator's vouch, and announces you to the room so members verify your messages. No prior pairing needed.",
            "inputSchema": {
                "type": "object",
                "properties": {"code": {"type": "string", "description": "The `wire-group:` join code."}},
                "required": ["code"]
            }
        }),
    ]
}

fn handle_tools_call(id: &Value, params: &Value, _state: &McpState) -> Value {
    let name = match params.get("name").and_then(Value::as_str) {
        Some(n) => n,
        None => return error_response(id, -32602, "missing tool name"),
    };
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let result = match name {
        "wire_whoami" => tool_whoami(),
        "wire_status" => tool_status(),
        "wire_peers" => tool_peers(),
        "wire_here" => tool_here(),
        "wire_send" => tool_send(&args),
        "wire_pull" => tool_pull(),
        "wire_tail" => tool_tail(&args),
        "wire_verify" => tool_verify(&args),
        "wire_init" => tool_init(&args),
        "wire_invite_mint" => tool_invite_mint(&args),
        "wire_invite_accept" => tool_invite_accept(&args),
        // v0.5 — agentic hotline (handle + profile + zero-paste discovery).
        "wire_add" => tool_add(&args),
        // v0.5.14 — bilateral-required pair: inbound queue management.
        // v0.10.1: canonical names introduced; v0.14.x (RFC-005 Phase 2):
        // deprecated wire_pair_* alias surface removed from tools/list.
        // Calls to the old names return a helpful redirect error.
        "wire_accept" => tool_pair_accept(&args),
        "wire_reject" => tool_pair_reject(&args),
        "wire_pending" => tool_pair_list_inbound(),
        "wire_pair_accept" => Err("wire_pair_accept was renamed to wire_accept (v0.9+). \
             Use wire_accept instead."
            .into()),
        "wire_pair_reject" => Err("wire_pair_reject was renamed to wire_reject (v0.9+). \
             Use wire_reject instead."
            .into()),
        "wire_pair_list_inbound" => Err(
            "wire_pair_list_inbound was renamed to wire_pending (v0.9+). \
             Use wire_pending instead."
                .into(),
        ),
        "wire_dial" => tool_dial(&args),
        "wire_claim" => tool_claim_handle(&args),
        "wire_whois" => tool_whois(&args),
        "wire_profile_set" => tool_profile_set(&args),
        "wire_profile_get" => tool_profile_get(),
        // v0.13.4 — group chat (shared-room slot + introduce-on-vouch).
        "wire_group_create" => tool_group_create(&args),
        "wire_group_add" => tool_group_add(&args),
        "wire_group_send" => tool_group_send(&args),
        "wire_group_tail" => tool_group_tail(&args),
        "wire_group_list" => tool_group_list(),
        "wire_group_invite" => tool_group_invite(&args),
        "wire_group_join" => tool_group_join(&args),
        // Legacy alias kept for older agent prompts that reference `wire_join`.
        // The SAS code-phrase pair flow it pointed at is gone — redirect to the
        // canonical handle-dial path.
        "wire_join" => Err("wire_join (SAS code-phrase pairing) was removed. \
             Use wire_dial(\"<handle>@<relay>\") to pair by handle. \
             See docs/AGENT_INTEGRATION.md."
            .into()),
        other => Err(format!("unknown tool: {other}")),
    };

    match result {
        Ok(value) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string(&value).unwrap_or_else(|_| value.to_string())
                }],
                "isError": false
            }
        }),
        Err(message) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": message}],
                "isError": true
            }
        }),
    }
}

// ---------- tool implementations ----------

fn tool_whoami() -> Result<Value, String> {
    use crate::config;
    use crate::signing::{b64decode, fingerprint, make_key_id};

    if !config::is_initialized().map_err(|e| e.to_string())? {
        return Err("not initialized — operator must run `wire up` first".into());
    }
    let card = config::read_agent_card().map_err(|e| e.to_string())?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let handle = crate::agent_card::display_handle_from_did(&did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| "agent-card missing verify_keys[*].key".to_string())?;
    let pk_bytes = b64decode(pk_b64).map_err(|e| e.to_string())?;
    let fp = fingerprint(&pk_bytes);
    let key_id = make_key_id(&handle, &pk_bytes);
    let capabilities = card
        .get("capabilities")
        .cloned()
        .unwrap_or_else(|| json!(["wire/v3.2"]));
    // v0.12: surface the DID-derived persona (nickname + emoji + palette)
    // that the CLI `wire whoami`/`here` already emit, so agents and toasts
    // see the persona, not just the raw handle.
    let persona =
        serde_json::to_value(crate::character::Character::from_card(&card)).unwrap_or(Value::Null);
    // v0.14: surface the RFC-001 op claims (op_did / op_pubkey / op_cert /
    // org_memberships / schema_version) when enrolled, mirroring the CLI
    // `wire whoami --json` shape. Same `op_claims_from_card` helper as
    // CLI ⇒ MCP + CLI stay in lock-step as the inline set grows. Older
    // cards / unenrolled ⇒ no extra keys (no JSON null-spam).
    let mut payload = serde_json::Map::new();
    payload.insert("did".into(), json!(did));
    payload.insert("handle".into(), json!(handle));
    payload.insert("persona".into(), persona);
    payload.insert("fingerprint".into(), json!(fp));
    payload.insert("key_id".into(), json!(key_id));
    payload.insert("public_key_b64".into(), json!(pk_b64));
    payload.insert("capabilities".into(), capabilities);
    // RFC-008 §A: same `session_source` the CLI `wire whoami --json` emits —
    // which signal won session/home resolution — so an agent diagnosing a
    // wrong/shared identity over MCP sees the cause without shelling out.
    payload.insert(
        "session_source".into(),
        json!(crate::session::session_source()),
    );
    for (k, v) in crate::cli::op_claims_from_card(&card) {
        payload.insert(k, v);
    }
    Ok(Value::Object(payload))
}

fn tool_peers() -> Result<Value, String> {
    use crate::config;

    let trust = config::read_trust().map_err(|e| e.to_string())?;
    let agents = trust
        .get("agents")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    // v0.14.3 (coral dogfood 2026-06-01): use effective tier so the
    // MCP surface matches the CLI ones (wire status / wire peers /
    // wire here all switched to effective_tier in #199 + #201).
    // Pre-fix, agents calling wire_peers via MCP got raw
    // trust-promoted VERIFIED even when the bilateral handshake
    // never delivered the slot credentials → daemon can't push but
    // agent thought it could.
    let relay_state =
        config::read_relay_state().unwrap_or_else(|_| json!({"self": null, "peers": {}}));
    let mut self_did: Option<String> = None;
    if let Ok(card) = config::read_agent_card() {
        self_did = card.get("did").and_then(Value::as_str).map(str::to_string);
    }
    let mut peers = Vec::new();
    for (handle, agent) in agents.iter() {
        let did = agent
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if Some(did.as_str()) == self_did.as_deref() {
            continue;
        }
        // v0.12: include the persona (respecting the peer's advertised
        // override when their card carries one, else DID-derived) so MCP
        // callers render the nickname/emoji instead of the raw handle.
        let persona = match agent.get("card") {
            Some(c) => crate::character::Character::from_card(c),
            None => crate::character::Character::from_did(&did),
        };
        // v0.14: surface peer's inline op claims (when their pinned card
        // carries them) so paired agents see ORG_VERIFIED-source membership
        // without reading trust.json directly. Identical shape to the CLI
        // `wire peers --json` row; older peers ⇒ no extra keys.
        let peer_op_claims = agent
            .get("card")
            .map(crate::cli::op_claims_from_card)
            .unwrap_or_default();
        let mut row = serde_json::Map::new();
        row.insert("handle".into(), json!(handle));
        row.insert(
            "persona".into(),
            serde_json::to_value(&persona).unwrap_or(Value::Null),
        );
        row.insert("did".into(), json!(did));
        row.insert(
            "tier".into(),
            json!(crate::trust::effective_tier(&trust, &relay_state, handle)),
        );
        row.insert(
            "capabilities".into(),
            agent
                .get("card")
                .and_then(|c| c.get("capabilities"))
                .cloned()
                .unwrap_or_else(|| json!([])),
        );
        for (k, v) in peer_op_claims {
            row.insert(k, v);
        }
        peers.push(Value::Object(row));
    }
    Ok(json!(peers))
}

/// Run `wire group <args> --json` by spawning this same binary, inheriting the
/// MCP session's WIRE_* env so it resolves the same identity/home. Group ops are
/// infrequent, so this reuses the exact, tested CLI logic — including the
/// verification-sensitive invite/join paths — rather than duplicating it here.
fn group_cli_json(args: &[&str]) -> Result<Value, String> {
    let exe = std::env::current_exe().map_err(|e| format!("locating wire binary: {e}"))?;
    let out = std::process::Command::new(exe)
        .arg("group")
        .args(args)
        .arg("--json")
        .env("WIRE_QUIET_AUTOSESSION", "1") // suppress the adopt-session stderr line
        .output()
        .map_err(|e| format!("spawning `wire group`: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(err.trim().to_string());
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // Last JSON object line is the result (any adopt chatter went to stderr).
    let line = s
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .unwrap_or("{}");
    serde_json::from_str(line).map_err(|e| format!("parsing `wire group` output: {e}"))
}

fn tool_group_create(args: &Value) -> Result<Value, String> {
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .ok_or("missing 'name'")?;
    group_cli_json(&["create", name])
}

fn tool_group_add(args: &Value) -> Result<Value, String> {
    let group = args
        .get("group")
        .and_then(Value::as_str)
        .ok_or("missing 'group'")?;
    let peer = args
        .get("peer")
        .and_then(Value::as_str)
        .ok_or("missing 'peer'")?;
    group_cli_json(&["add", group, peer])
}

fn tool_group_send(args: &Value) -> Result<Value, String> {
    let group = args
        .get("group")
        .and_then(Value::as_str)
        .ok_or("missing 'group'")?;
    let message = args
        .get("message")
        .and_then(Value::as_str)
        .ok_or("missing 'message'")?;
    group_cli_json(&["send", group, message])
}

fn tool_group_tail(args: &Value) -> Result<Value, String> {
    let group = args
        .get("group")
        .and_then(Value::as_str)
        .ok_or("missing 'group'")?;
    if let Some(n) = args.get("limit").and_then(Value::as_u64) {
        group_cli_json(&["tail", group, "--limit", &n.to_string()])
    } else {
        group_cli_json(&["tail", group])
    }
}

fn tool_group_list() -> Result<Value, String> {
    group_cli_json(&["list"])
}

fn tool_group_invite(args: &Value) -> Result<Value, String> {
    let group = args
        .get("group")
        .and_then(Value::as_str)
        .ok_or("missing 'group'")?;
    group_cli_json(&["invite", group])
}

fn tool_group_join(args: &Value) -> Result<Value, String> {
    let code = args
        .get("code")
        .and_then(Value::as_str)
        .ok_or("missing 'code'")?;
    group_cli_json(&["join", code])
}

/// v0.14.2 (#162): daemon + sync-loop health check, MCP-side mirror of
/// `wire status`. Specifically engineered to answer the silent-send
/// question — "if I call wire_send right now, will the daemon actually
/// push it?". Returns the daemon-liveness section + last-sync metadata +
/// outbox/inbox depth so callers can branch on a stale or absent sync.
///
/// Read-only. No initialization gate — runs against an empty home
/// (returns `initialized:false` shape mirroring wire_whoami's
/// degraded-uninit path from #152).
fn tool_status() -> Result<Value, String> {
    use crate::config;

    let initialized = config::is_initialized().unwrap_or(false);
    if !initialized {
        return Ok(json!({
            "initialized": false,
            "daemon_running": false,
            "last_sync_age_seconds": Value::Null,
        }));
    }

    let snap = crate::ensure_up::daemon_liveness();
    let last_sync_age = crate::ensure_up::last_sync_age_seconds();
    let last_sync_record = crate::ensure_up::read_last_sync_record();

    let mut daemon = json!({
        "running": snap.pidfile_alive,
        "pid": snap.pidfile_pid,
        "all_running_pids": snap.pgrep_pids,
        "orphans": snap.orphan_pids,
    });
    if let crate::ensure_up::PidRecord::Json(d) = &snap.record {
        daemon["version"] = json!(d.version);
        daemon["bin_path"] = json!(d.bin_path);
        daemon["did"] = json!(d.did);
        daemon["relay_url"] = json!(d.relay_url);
        daemon["started_at"] = json!(d.started_at);
    }

    let (last_sync_at, last_sync_push_n, last_sync_pull_n, last_sync_rejected_n) =
        match last_sync_record {
            Some(rec) => (
                Some(rec.ts),
                Some(rec.push_n),
                Some(rec.pull_n),
                Some(rec.rejected_n),
            ),
            None => (None, None, None, None),
        };

    let outbox_count = config::outbox_dir()
        .and_then(|p| crate::cli::scan_jsonl_dir(&p))
        .map(|v| v.get("total_events").and_then(Value::as_u64).unwrap_or(0))
        .unwrap_or(0);
    let inbox_count = config::inbox_dir()
        .and_then(|p| crate::cli::scan_jsonl_dir(&p))
        .map(|v| v.get("total_events").and_then(Value::as_u64).unwrap_or(0))
        .unwrap_or(0);

    // v0.14.2 (#162 fix #2): total events queued but not yet pushed.
    // `pending_push_count > 0` + `stale_sync == true` = the
    // silent-send class — events queued, daemon not pushing.
    // v0.14.3 (coral dogfood 2026-06-01): also surface a per-peer
    // breakdown so MCP-side agents (and the CLI both share the
    // same derivation) can see which peer is wedged + at what
    // trust tier without re-walking the outbox.
    let pending_push_breakdown = config::compute_pending_push_breakdown();
    let pending_push_count: u64 = pending_push_breakdown.iter().map(|p| p.count).sum();

    // v0.14.2 (#162 fix #7): SSE stream-subscriber state so callers
    // can distinguish "stream alive (live monitor will fire on
    // inbound)" from "polling-only (daemon up, monitor will wait
    // until next poll cycle)". Best-effort read; missing file is
    // Value::Null (unknown).
    let stream_state = config::read_stream_state();

    Ok(json!({
        "initialized": true,
        "daemon": daemon,
        "daemon_running": snap.pidfile_alive,
        "last_sync_at": last_sync_at,
        "last_sync_age_seconds": last_sync_age,
        "last_sync_push_n": last_sync_push_n,
        "last_sync_pull_n": last_sync_pull_n,
        "last_sync_rejected_n": last_sync_rejected_n,
        "stale_sync": config::stale_sync(last_sync_age),
        "outbox_count": outbox_count,
        "inbox_count": inbox_count,
        "pending_push_count": pending_push_count,
        "pending_push_breakdown": pending_push_breakdown,
        "stream_state": stream_state,
    }))
}

fn tool_send(args: &Value) -> Result<Value, String> {
    use crate::config;
    use crate::signing::{b64decode, sign_message_v31};

    let peer = args
        .get("peer")
        .and_then(Value::as_str)
        .ok_or("missing 'peer'")?;
    let peer = crate::agent_card::bare_handle(peer);
    let kind = args
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("missing 'kind'")?;
    let body = args
        .get("body")
        .and_then(Value::as_str)
        .ok_or("missing 'body'")?;
    let deadline = args.get("time_sensitive_until").and_then(Value::as_str);
    // v0.14.2 (paul, 2026-06-01): opt back into the legacy outbox →
    // daemon-push pipeline. Default is synchronous POST so callers get
    // a real `delivered` / `duplicate` / `failed` verdict instead of
    // a `queued` lie. `queue: true` writes to outbox like pre-v0.14.2.
    let queue = args.get("queue").and_then(Value::as_bool).unwrap_or(false);

    if !config::is_initialized().map_err(|e| e.to_string())? {
        return Err("not initialized — operator must run `wire up` first".into());
    }
    let sk_seed = config::read_private_key().map_err(|e| e.to_string())?;
    let card = config::read_agent_card().map_err(|e| e.to_string())?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let handle = crate::agent_card::display_handle_from_did(&did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or("agent-card missing verify_keys[*].key")?;
    let pk_bytes = b64decode(pk_b64).map_err(|e| e.to_string())?;

    // Body parses as JSON if possible, else stays a string.
    let body_value: Value =
        serde_json::from_str(body).unwrap_or_else(|_| Value::String(body.to_string()));
    let kind_id = parse_kind(kind);

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    // v0.14.2 (#162 fix #4): canonicalize `to:` against the pinned
    // peer's full DID via the trust store. Bare-handle
    // `to:did:wire:<handle>` misses the long-fingerprint suffix
    // (`did:wire:sunlit-aurora-ec6f890d`) that pinned peers actually
    // publish — mismatch risks receiver rejection at canonical/cursor
    // verification. resolve_peer_did falls back to the bare form when
    // the peer isn't pinned yet (pre-pair queue best-effort).
    let trust_for_did = config::read_trust().unwrap_or_else(|_| json!({"agents": {}}));
    let to_did = crate::trust::resolve_peer_did(&trust_for_did, peer);
    let mut event = json!({
        // Parity with the CLI send skeleton (review finding #4): carry
        // schema_version so enc-bearing MCP events pass the same schema gate.
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now,
        "from": did,
        "to": to_did,
        "type": kind,
        "kind": kind_id,
        "body": body_value,
    });
    if let Some(deadline) = deadline {
        event["time_sensitive_until"] =
            json!(crate::cli::parse_deadline_until(deadline).map_err(|e| e.to_string())?);
    }
    // D1 (RFC-006): encrypt the body when the recipient is dh-capable. Binds the
    // event's own from/to; runs BEFORE signing. Plaintext for legacy peers.
    if let Some(peer_dh) = crate::enc::wire_x25519::peer_dh_pubkey(&trust_for_did, peer) {
        crate::enc::wire_x25519::seal_event_body(&mut event, &peer_dh, &sk_seed)
            .map_err(|e| e.to_string())?;
    }
    let signed =
        sign_message_v31(&event, &sk_seed, &pk_bytes, &handle).map_err(|e| e.to_string())?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    // v0.14.2 (paul, 2026-06-01): collapse send → outbox → push into
    // a synchronous POST by default. `queue: true` opts back into the
    // legacy outbox path for offline-buffer / batch / pre-pair queue
    // use cases.
    if !queue {
        let outcome = crate::send::attempt_deliver(peer, &signed).map_err(|e| e.to_string())?;
        let mut v = crate::send::delivery_json(&outcome, peer);
        // Carry the same daemon-health annotations the caller used to
        // get on the legacy `queued` response. With sync delivery
        // these are diagnostic-only (the verdict in `status` is the
        // authoritative answer), but they're cheap to compute and
        // existing consumers may key on them.
        let snap = crate::ensure_up::daemon_liveness();
        let last_sync_age = crate::ensure_up::last_sync_age_seconds();
        if let Some(obj) = v.as_object_mut() {
            obj.insert("daemon_seen".into(), json!(snap.pidfile_alive));
            obj.insert("last_sync_age_seconds".into(), json!(last_sync_age));
            obj.insert(
                "stale_sync".into(),
                json!(config::stale_sync(last_sync_age)),
            );
        }
        return Ok(v);
    }

    // Legacy --queue path. Outbox-write, daemon push loop drains.
    let line = serde_json::to_vec(&signed).map_err(|e| e.to_string())?;
    let outbox = config::append_outbox_record(peer, &line).map_err(|e| e.to_string())?;
    let snap = crate::ensure_up::daemon_liveness();
    let last_sync_age = crate::ensure_up::last_sync_age_seconds();
    // Honesty check mirror of the CLI: if the peer is BOTH
    // unpinned in trust AND has no pending pair (outbound or
    // inbound), the queued event has nowhere to go and will sit
    // in outbox forever. Surface the warning as a structured
    // `warning` field so MCP-side agents can branch on it instead
    // of treating `status:"queued"` as success.
    let peer_pinned_in_trust = trust_for_did
        .get("agents")
        .and_then(Value::as_object)
        .map(|a| a.contains_key(peer))
        .unwrap_or(false);
    let peer_in_relay_state = config::read_relay_state()
        .ok()
        .and_then(|s| s.get("peers").and_then(Value::as_object).cloned())
        .map(|peers| peers.contains_key(peer))
        .unwrap_or(false);
    let pending_inbound = crate::pending_inbound_pair::list_pending_inbound()
        .ok()
        .map(|v| v.iter().any(|p| p.peer_handle == peer))
        .unwrap_or(false);
    let unpushable = !peer_pinned_in_trust && !peer_in_relay_state && !pending_inbound;
    let mut out = json!({
        "event_id": event_id,
        "status": "queued",
        "peer": peer,
        "outbox": outbox.to_string_lossy(),
        "daemon_seen": snap.pidfile_alive,
        "last_sync_age_seconds": last_sync_age,
        "stale_sync": config::stale_sync(last_sync_age),
    });
    if unpushable {
        out["warning"] = json!(format!(
            "`{peer}` is not pinned and has no pending pair — the event will sit in outbox forever unless you pair first (wire_dial)."
        ));
    }
    Ok(out)
}

/// v0.14.2 (paul, post-#187): symmetric receive primitive. `wire_send`
/// became sync in #187; `wire_pull` is the mirror — trigger an
/// immediate relay GET on this agent's slot(s), write new events to
/// inbox, advance per-slot cursors, return the verdict. Thin wrapper
/// over `cli::run_sync_pull`; same code path the daemon's 5s pull
/// loop uses.
fn tool_pull() -> Result<Value, String> {
    crate::cli::run_sync_pull().map_err(|e| format!("{e:#}"))
}

fn tool_tail(args: &Value) -> Result<Value, String> {
    use crate::config;
    use crate::signing::verify_message_v31;

    let peer_filter = args.get("peer").and_then(Value::as_str);
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
    // wire #79: orientation parity with `wire tail` CLI — default newest-N,
    // `oldest=true` opts back into FIFO. Agents almost always want the
    // freshest inbox slice when re-tailing an established peer, not the
    // wire-init handshake noise.
    let oldest = args.get("oldest").and_then(Value::as_bool).unwrap_or(false);
    let inbox = config::inbox_dir().map_err(|e| e.to_string())?;
    if !inbox.exists() {
        return Ok(json!([]));
    }
    let trust = config::read_trust().map_err(|e| e.to_string())?;
    let seed = crate::enc::wire_x25519::self_seed_for_read();
    let entries: Vec<_> = std::fs::read_dir(&inbox)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "jsonl").unwrap_or(false)
                && match peer_filter {
                    Some(want) => p.file_stem().and_then(|s| s.to_str()) == Some(want),
                    None => true,
                }
        })
        .collect();

    // (timestamp, per-file line index, event with verified meta). Sort key
    // mirrors the CLI cmd_tail for cross-tool consistency.
    let mut collected: Vec<(String, usize, Value)> = Vec::new();
    for path in &entries {
        let body = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        for (idx, line) in body.lines().enumerate() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let verified = verify_message_v31(&event, &trust).is_ok();
            // D1: decrypt enc-bearing bodies for the agent (verify-gated).
            let mut event_with_meta = match &seed {
                Some(s) => crate::enc::wire_x25519::decrypt_event_for_read(&event, &trust, s),
                None => event.clone(),
            };
            if let Some(obj) = event_with_meta.as_object_mut() {
                obj.insert("verified".into(), json!(verified));
            }
            let ts = event
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            collected.push((ts, idx, event_with_meta));
        }
    }
    collected.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let total = collected.len();
    let window: Vec<Value> = if limit == 0 {
        collected.into_iter().map(|(_, _, e)| e).collect()
    } else if oldest {
        collected
            .into_iter()
            .take(limit)
            .map(|(_, _, e)| e)
            .collect()
    } else {
        let start = total.saturating_sub(limit);
        collected
            .into_iter()
            .skip(start)
            .map(|(_, _, e)| e)
            .collect()
    };
    Ok(Value::Array(window))
}

fn tool_verify(args: &Value) -> Result<Value, String> {
    use crate::config;
    use crate::signing::verify_message_v31;

    let event_str = args
        .get("event")
        .and_then(Value::as_str)
        .ok_or("missing 'event'")?;
    let event: Value =
        serde_json::from_str(event_str).map_err(|e| format!("invalid event JSON: {e}"))?;
    let trust = config::read_trust().map_err(|e| e.to_string())?;
    match verify_message_v31(&event, &trust) {
        Ok(()) => Ok(json!({"verified": true})),
        Err(e) => Ok(json!({"verified": false, "reason": e.to_string()})),
    }
}

// ---------- pairing tools ----------

/// v0.13: bootstrap a freshly-resolved session-keyed identity. Runs once per
/// session home (gated on `is_initialized`); no-op under WIRE_MCP_SKIP_AUTO_UP.
/// init (one-name) + federation slot via `ensure_self_with_relay`, then a
/// best-effort phonebook claim of the DID-derived persona. Network failures
/// are swallowed — the identity is still created locally; the claim retries on
/// a later start.
fn ensure_session_bootstrapped() {
    if std::env::var("WIRE_MCP_SKIP_AUTO_UP").is_ok() {
        return;
    }
    if crate::config::is_initialized().unwrap_or(false) {
        return; // this session home already has an identity
    }
    let (did, relay_url, slot_id, slot_token) =
        match crate::pair_invite::ensure_self_with_relay(None) {
            Ok(t) => t,
            Err(_) => return, // offline / relay down — init may have happened locally; skip claim
        };
    if let Ok(card) = crate::config::read_agent_card() {
        let persona = crate::agent_card::display_handle_from_did(&did).to_string();
        let client = crate::relay_client::RelayClient::new(&relay_url);
        let _ = client.handle_claim_v2(&persona, &slot_id, &slot_token, None, &card, None);
    }
}

fn tool_init(args: &Value) -> Result<Value, String> {
    let handle = args
        .get("handle")
        .and_then(Value::as_str)
        .ok_or("missing 'handle'")?;
    let name = args.get("name").and_then(Value::as_str);
    let relay = args.get("relay_url").and_then(Value::as_str);
    crate::init::init_self_idempotent(handle, name, relay).map_err(|e| e.to_string())
}

// ---------- invite-URL one-paste pair (v0.4.0) ----------

fn tool_invite_mint(args: &Value) -> Result<Value, String> {
    let relay_url = args.get("relay_url").and_then(Value::as_str);
    let ttl_secs = args.get("ttl_secs").and_then(Value::as_u64);
    let uses = args
        .get("uses")
        .and_then(Value::as_u64)
        .map(|u| u as u32)
        .unwrap_or(1);
    let url =
        crate::pair_invite::mint_invite(ttl_secs, uses, relay_url).map_err(|e| format!("{e:#}"))?;
    let ttl_resolved = ttl_secs.unwrap_or(crate::pair_invite::DEFAULT_TTL_SECS);
    Ok(json!({
        "invite_url": url,
        "ttl_secs": ttl_resolved,
        "uses": uses,
    }))
}

fn tool_invite_accept(args: &Value) -> Result<Value, String> {
    let url = args
        .get("url")
        .and_then(Value::as_str)
        .ok_or("missing 'url'")?;
    crate::pair_invite::accept_invite(url).map_err(|e| format!("{e:#}"))
}

/// wire_here (MCP): the cold-agent orientation answer — self + same-machine
/// sister sessions + pinned peers. Mirrors `wire here --json` exactly (shares
/// `cli::comms::here_summary`), so an MCP-only agent with an empty wire_peers
/// can discover a dial target instead of dead-ending.
fn tool_here() -> Result<Value, String> {
    crate::cli::here_summary().map_err(|e| format!("{e:#}"))
}

// ---------- v0.5 — agentic hotline tools ----------

/// wire_dial (MCP): mirror the CLI `dial` resolution ladder. The prior
/// wiring routed straight to `tool_add`, which reads a required `handle`
/// arg — but the wire_dial schema only provides `name`, so every dial
/// errored `missing 'handle'`. This reads `name` and routes:
///   • `<nick>@<relay>`  -> federation pair (via tool_add).
///   • already-pinned     -> no-op success (peer already reachable).
///   • otherwise          -> honest error. Bare-nickname / local-sister
///     resolution over MCP is not yet wired (CLI `wire dial` does it);
///     use `<nick>@<relay>` or `wire_send` (auto-pairs on miss).
fn tool_dial(args: &Value) -> Result<Value, String> {
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| args.get("handle").and_then(Value::as_str))
        .ok_or("missing 'name'")?;

    if name.contains('@') {
        // Federation path. Present `name` as the `handle` tool_add expects.
        let mut a = args.clone();
        if let Some(obj) = a.as_object_mut() {
            obj.insert("handle".into(), Value::String(name.to_string()));
        }
        return tool_add(&a);
    }

    // Bare nick: mirror the CLI `wire dial` resolution ladder via the shared
    // resolver — pinned peer (already reachable) or local sister (pair now).
    // Previously this dead-ended ("use wire_send, it auto-pairs") which is
    // circular — wire_send returns peer_unknown telling you to wire_dial.
    match crate::cli::resolve_name_to_target(name) {
        Ok(crate::cli::DialTarget::PinnedPeer {
            handle, did, tier, ..
        }) => Ok(json!({
            "name_input": name,
            "status": "already_pinned",
            "peer_handle": handle,
            "did": did,
            "tier": tier,
        })),
        Ok(crate::cli::DialTarget::LocalSister { session_name, .. }) => {
            let drop =
                crate::cli::add_local_sister_core(&session_name).map_err(|e| format!("{e:#}"))?;
            Ok(json!({
                "name_input": name,
                "status": "paired_local_sister",
                "peer_handle": drop.peer_handle,
                "paired_with": drop.paired_with_did,
                "event_id": drop.event_id,
                "delivered_via": drop.delivered_via,
            }))
        }
        // Unresolvable: surface the resolver's own did-you-mean message
        // (names pinned peers + sisters + the handle@relay federation form).
        Err(e) => Err(format!("{e:#}")),
    }
}

fn tool_add(args: &Value) -> Result<Value, String> {
    let handle = args
        .get("handle")
        .and_then(Value::as_str)
        .ok_or("missing 'handle'")?;
    let relay_override = args.get("relay_url").and_then(Value::as_str);

    let parsed = crate::pair_profile::parse_handle(handle).map_err(|e| format!("{e:#}"))?;

    // Ensure self has identity + relay slot (auto-inits if needed).
    let (our_did, our_relay, our_slot_id, our_slot_token) =
        crate::pair_invite::ensure_self_with_relay(relay_override).map_err(|e| format!("{e:#}"))?;

    // Resolve peer via .well-known.
    let resolved = crate::pair_profile::resolve_handle(&parsed, relay_override)
        .map_err(|e| format!("{e:#}"))?;
    let peer_card = resolved
        .get("card")
        .cloned()
        .ok_or("resolved missing card")?;
    let peer_did = resolved
        .get("did")
        .and_then(Value::as_str)
        .ok_or("resolved missing did")?
        .to_string();
    let peer_handle = crate::agent_card::display_handle_from_did(&peer_did).to_string();
    let peer_slot_id = resolved
        .get("slot_id")
        .and_then(Value::as_str)
        .ok_or("resolved missing slot_id")?
        .to_string();
    let peer_relay = resolved
        .get("relay_url")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| relay_override.map(str::to_string))
        .unwrap_or_else(|| format!("https://{}", parsed.domain));

    // Pin peer in trust + relay-state. slot_token arrives via ack later.
    let mut trust = crate::config::read_trust().map_err(|e| format!("{e:#}"))?;
    crate::trust::add_agent_card_pin(&mut trust, &peer_card, Some("VERIFIED"));
    crate::config::write_trust(&trust).map_err(|e| format!("{e:#}"))?;
    let mut relay_state = crate::config::read_relay_state().map_err(|e| format!("{e:#}"))?;
    let existing_token = relay_state
        .get("peers")
        .and_then(|p| p.get(&peer_handle))
        .and_then(|p| p.get("slot_token"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_default();
    relay_state["peers"][&peer_handle] = json!({
        "relay_url": peer_relay,
        "slot_id": peer_slot_id,
        "slot_token": existing_token,
    });
    crate::config::write_relay_state(&relay_state).map_err(|e| format!("{e:#}"))?;

    // Build + sign pair_drop event (no nonce — open-mode handle pair).
    let our_card = crate::config::read_agent_card().map_err(|e| format!("{e:#}"))?;
    let sk_seed = crate::config::read_private_key().map_err(|e| format!("{e:#}"))?;
    let our_handle_str = crate::agent_card::display_handle_from_did(&our_did).to_string();
    let pk_b64 = our_card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or("our card missing verify_keys[*].key")?;
    let pk_bytes = crate::signing::b64decode(pk_b64).map_err(|e| format!("{e:#}"))?;
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let event = json!({
        "timestamp": now,
        "from": our_did,
        "to": peer_did,
        "type": "pair_drop",
        "kind": 1100u32,
        "body": {
            "card": our_card,
            "relay_url": our_relay,
            "slot_id": our_slot_id,
            "slot_token": our_slot_token,
        },
    });
    let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &our_handle_str)
        .map_err(|e| format!("{e:#}"))?;

    let client = crate::relay_client::RelayClient::new(&peer_relay);
    let resp = client
        .handle_intro(&parsed.nick, &signed)
        .map_err(|e| format!("{e:#}"))?;
    let event_id = signed
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(json!({
        "handle": handle,
        "paired_with": peer_did,
        "peer_handle": peer_handle,
        "event_id": event_id,
        "drop_response": resp,
        "status": "drop_sent",
    }))
}

/// MCP `wire_accept` (v0.9+, formerly wire_pair_accept) — bilateral completion
/// of a pending-inbound pair request. The agent SHOULD have surfaced the
/// pending request to the operator before calling this; acceptance grants
/// peer authenticated write access to this agent's inbox.
fn tool_pair_accept(args: &Value) -> Result<Value, String> {
    let peer = args
        .get("peer")
        .and_then(Value::as_str)
        .ok_or("missing 'peer'")?;
    let nick = crate::agent_card::bare_handle(peer);
    let pending = crate::pending_inbound_pair::read_pending_inbound(nick)
        .map_err(|e| format!("{e:#}"))?
        .ok_or_else(|| {
            format!(
                "no pending pair request from {nick}. Call wire_pending to enumerate, \
                 or wire_add to send a fresh outbound pair request."
            )
        })?;

    // Pin trust with VERIFIED — operator-equivalent consent gesture (the
    // agent is acting on the operator's instruction to accept).
    let mut trust = crate::config::read_trust().map_err(|e| format!("{e:#}"))?;
    crate::trust::add_agent_card_pin(&mut trust, &pending.peer_card, Some("VERIFIED"));
    crate::config::write_trust(&trust).map_err(|e| format!("{e:#}"))?;

    // Record peer's relay coords + slot_token from the stored drop.
    let mut relay_state = crate::config::read_relay_state().map_err(|e| format!("{e:#}"))?;
    relay_state["peers"][&pending.peer_handle] = json!({
        "relay_url": pending.peer_relay_url,
        "slot_id": pending.peer_slot_id,
        "slot_token": pending.peer_slot_token,
    });
    crate::config::write_relay_state(&relay_state).map_err(|e| format!("{e:#}"))?;

    // Ship our slot_token via pair_drop_ack — Bug 2 fix: iterate the peer's
    // advertised endpoints in priority order, only fail if all are dead. The
    // pending record's `peer_endpoints` carries the full advertised list when
    // the pair_drop was written by a v0.5.17+ peer; fall back to a one-element
    // slice from the legacy triple for older records so we still hit the
    // failover helper with a valid input.
    let ack_endpoints: Vec<crate::endpoints::Endpoint> = if pending.peer_endpoints.is_empty() {
        vec![crate::endpoints::Endpoint::federation(
            pending.peer_relay_url.clone(),
            pending.peer_slot_id.clone(),
            pending.peer_slot_token.clone(),
        )]
    } else {
        pending.peer_endpoints.clone()
    };
    crate::pair_invite::send_pair_drop_ack(&pending.peer_handle, &ack_endpoints).map_err(|e| {
        format!(
            "pair_drop_ack send to {} (across {} endpoint(s)) failed: {e:#}",
            pending.peer_handle,
            ack_endpoints.len()
        )
    })?;

    crate::pending_inbound_pair::consume_pending_inbound(nick).map_err(|e| format!("{e:#}"))?;

    Ok(json!({
        "status": "bilateral_accepted",
        "peer_handle": pending.peer_handle,
        "peer_did": pending.peer_did,
        "peer_relay_url": pending.peer_relay_url,
        "via": "pending_inbound",
    }))
}

/// MCP `wire_reject` (v0.9+, formerly wire_pair_reject) — delete a
/// pending-inbound record without pairing. Peer never receives our
/// slot_token. Idempotent.
fn tool_pair_reject(args: &Value) -> Result<Value, String> {
    let peer = args
        .get("peer")
        .and_then(Value::as_str)
        .ok_or("missing 'peer'")?;
    let nick = crate::agent_card::bare_handle(peer);
    let existed =
        crate::pending_inbound_pair::read_pending_inbound(nick).map_err(|e| format!("{e:#}"))?;
    crate::pending_inbound_pair::consume_pending_inbound(nick).map_err(|e| format!("{e:#}"))?;
    Ok(json!({
        "peer": nick,
        "rejected": existed.is_some(),
        "had_pending": existed.is_some(),
    }))
}

/// MCP `wire_pending` (v0.9+, formerly wire_pair_list_inbound) — enumerate
/// pending-inbound pair requests for operator review. Flat array sorted
/// oldest-first.
fn tool_pair_list_inbound() -> Result<Value, String> {
    let items =
        crate::pending_inbound_pair::list_pending_inbound().map_err(|e| format!("{e:#}"))?;
    Ok(json!(items))
}

fn tool_claim_handle(args: &Value) -> Result<Value, String> {
    let typed = args.get("nick").and_then(Value::as_str);
    let relay_override = args.get("relay_url").and_then(Value::as_str);
    let public_url = args.get("public_url").and_then(Value::as_str);

    // Auto-init + ensure slot.
    let (_, our_relay, our_slot_id, our_slot_token) =
        crate::pair_invite::ensure_self_with_relay(relay_override).map_err(|e| format!("{e:#}"))?;
    let claim_relay = relay_override.unwrap_or(&our_relay);
    let card = crate::config::read_agent_card().map_err(|e| format!("{e:#}"))?;

    // One-name rule (v0.13.1): the claimed handle is ALWAYS the DID-derived
    // persona, so the phonebook entry can never drift from the agent-card
    // handle. `nick` is optional + advisory — a value that differs is ignored.
    // See cmd_claim for the rationale (closes the claim-path "two names" hole).
    let did = card.get("did").and_then(Value::as_str).unwrap_or_default();
    let canonical = crate::agent_card::display_handle_from_did(did).to_string();
    let nick = if canonical.is_empty() {
        typed.unwrap_or_default().to_string()
    } else {
        canonical
    };
    let typed_nick_ignored = typed.map(|t| t != nick).unwrap_or(false);

    let client = crate::relay_client::RelayClient::new(claim_relay);
    let resp = client
        .handle_claim(&nick, &our_slot_id, &our_slot_token, public_url, &card)
        .map_err(|e| format!("{e:#}"))?;
    Ok(json!({
        "nick": nick,
        "relay": claim_relay,
        "response": resp,
        "one_name": true,
        "typed_nick_ignored": typed_nick_ignored,
    }))
}

fn tool_whois(args: &Value) -> Result<Value, String> {
    if let Some(handle) = args.get("handle").and_then(Value::as_str) {
        // v0.14.x: mirror the CLI's resolution order. Bare nicks (no `@`)
        // route through the local resolver first (pinned peers + local
        // sister sessions); federation handles fall through to
        // `parse_handle` + remote resolution. Previously the MCP
        // surface only accepted federation-shaped handles and rejected
        // bare nicks with `missing '@' separator`, breaking
        // agent-side discovery of paired-but-not-federated peers.
        // Mirrors `cli::cmd_whois_local` for the local arms; mirrors
        // `cli::cmd_whois` for the federation arm.
        if !handle.contains('@')
            && let Ok(target) = crate::cli::resolve_name_to_target(handle)
        {
            return Ok(dial_target_to_whois_json(&target));
        }
        let parsed = crate::pair_profile::parse_handle(handle).map_err(|e| format!("{e:#}"))?;
        let relay_override = args.get("relay_url").and_then(Value::as_str);
        crate::pair_profile::resolve_handle(&parsed, relay_override).map_err(|e| format!("{e:#}"))
    } else {
        // Self. v0.14.x: surface inline op claims so MCP whois stays in
        // parity with `wire whoami --json` / CLI self-whois (#114 + #115
        // shared the same helper).
        let card = crate::config::read_agent_card().map_err(|e| format!("{e:#}"))?;
        let mut payload = serde_json::Map::new();
        payload.insert(
            "did".into(),
            card.get("did").cloned().unwrap_or(Value::Null),
        );
        payload.insert(
            "profile".into(),
            card.get("profile").cloned().unwrap_or(Value::Null),
        );
        for (k, v) in crate::cli::op_claims_from_card(&card) {
            payload.insert(k, v);
        }
        Ok(Value::Object(payload))
    }
}

/// Convert a `cli::DialTarget` (the CLI's local-resolver hit) into the
/// JSON shape MCP whois callers expect. Mirrors the human-readable arms
/// of `cli::cmd_whois_local` but keyed for programmatic consumption.
/// Surfaces inline op claims from the peer's pinned card via the same
/// `op_claims_from_card` helper used everywhere else in v0.14.x.
fn dial_target_to_whois_json(target: &crate::cli::DialTarget) -> Value {
    use crate::cli::DialTarget;
    match target {
        DialTarget::PinnedPeer {
            handle,
            did,
            nickname,
            emoji,
            tier,
        } => {
            let op_claims = crate::config::read_trust()
                .ok()
                .and_then(|t| {
                    t.get("agents")
                        .and_then(Value::as_object)
                        .and_then(|m| m.get(handle))
                        .and_then(|a| a.get("card").cloned())
                })
                .map(|c| crate::cli::op_claims_from_card(&c))
                .unwrap_or_default();
            let mut payload = serde_json::Map::new();
            payload.insert("kind".into(), json!("pinned_peer"));
            payload.insert("handle".into(), json!(handle));
            payload.insert("did".into(), json!(did));
            payload.insert("nickname".into(), json!(nickname));
            payload.insert("emoji".into(), json!(emoji));
            payload.insert("tier".into(), json!(tier));
            for (k, v) in op_claims {
                payload.insert(k, v);
            }
            Value::Object(payload)
        }
        DialTarget::LocalSister {
            session_name,
            handle,
            did,
            nickname,
            emoji,
        } => json!({
            "kind": "local_sister",
            "session_name": session_name,
            "handle": handle,
            "did": did,
            "nickname": nickname,
            "emoji": emoji,
        }),
    }
}

fn tool_profile_set(args: &Value) -> Result<Value, String> {
    let field = args
        .get("field")
        .and_then(Value::as_str)
        .ok_or("missing 'field'")?;
    let raw_value = args.get("value").cloned().ok_or("missing 'value'")?;
    // If value is a string that itself parses as JSON (e.g. "[\"rust\"]"),
    // unwrap it. Otherwise pass as-is. Lets agents send either typed values
    // or stringified JSON.
    let value = if let Some(s) = raw_value.as_str() {
        serde_json::from_str(s).unwrap_or(Value::String(s.to_string()))
    } else {
        raw_value
    };
    let new_profile =
        crate::pair_profile::write_profile_field(field, value).map_err(|e| format!("{e:#}"))?;
    Ok(json!({
        "field": field,
        "profile": new_profile,
    }))
}

fn tool_profile_get() -> Result<Value, String> {
    let card = crate::config::read_agent_card().map_err(|e| format!("{e:#}"))?;
    Ok(json!({
        "did": card.get("did").cloned().unwrap_or(Value::Null),
        "profile": card.get("profile").cloned().unwrap_or(Value::Null),
    }))
}

// ---------- helpers ----------

fn parse_kind(s: &str) -> u32 {
    if let Ok(n) = s.parse::<u32>() {
        return n;
    }
    for (id, name) in crate::signing::kinds() {
        if *name == s {
            return *id;
        }
    }
    1
}

fn error_response(id: &Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_method_returns_jsonrpc_error() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "nonsense"});
        let resp = handle_request(&req, &McpState::default());
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn initialize_advertises_tools_capability() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        let resp = handle_request(&req, &McpState::default());
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(resp["result"]["capabilities"]["tools"].is_object());
        assert_eq!(resp["result"]["serverInfo"]["name"], SERVER_NAME);
    }

    #[test]
    fn tools_list_includes_pairing_and_messaging() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let resp = handle_request(&req, &McpState::default());
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        for required in [
            "wire_whoami",
            "wire_peers",
            "wire_send",
            "wire_tail",
            "wire_verify",
            "wire_init",
            "wire_dial",
        ] {
            assert!(
                names.contains(&required),
                "missing required tool {required}"
            );
        }
        // The SAS code-phrase pair tools were removed (RFC-005 follow-on) —
        // they must NOT be advertised.
        for removed in [
            "wire_pair_initiate",
            "wire_pair_join",
            "wire_pair_check",
            "wire_pair_confirm",
            "wire_pair_initiate_detached",
            "wire_pair_join_detached",
            "wire_pair_list_pending",
            "wire_pair_confirm_detached",
            "wire_pair_cancel_pending",
        ] {
            assert!(
                !names.contains(&removed),
                "SAS pair tool {removed} must not be advertised after removal"
            );
        }
        // wire_join (the old direct alias for the SAS pair-join) is explicitly
        // NOT in the catalog. Calling it returns a deprecation pointing to
        // wire_dial (test below covers this).
        assert!(
            !names.contains(&"wire_join"),
            "wire_join must not be advertised — SAS pairing removed"
        );
    }

    #[test]
    fn agent_docs_match_advertised_tools() {
        // The agent-facing docs must not lie about the MCP surface:
        // advertising a tool that doesn't exist wastes an agent turn, and
        // omitting one hides a capability. Guard docs/PLUGIN.md (the plugin's
        // canonical tool reference) against drift from `tool_defs()` — the
        // authoritative catalog. Every advertised tool must be listed, and no
        // removed/never-existed "ghost" tool may appear in either agent doc.
        let advertised: Vec<String> = tool_defs()
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_string))
            .collect();
        let manifest = env!("CARGO_MANIFEST_DIR");
        let plugin = std::fs::read_to_string(format!("{manifest}/docs/PLUGIN.md"))
            .expect("read docs/PLUGIN.md");
        for name in &advertised {
            assert!(
                plugin.contains(name.as_str()),
                "docs/PLUGIN.md missing advertised MCP tool `{name}` — it drifted from tool_defs()"
            );
        }
        let integ = std::fs::read_to_string(format!("{manifest}/docs/AGENT_INTEGRATION.md"))
            .expect("read docs/AGENT_INTEGRATION.md");
        for (doc, body) in [
            ("docs/PLUGIN.md", &plugin),
            ("docs/AGENT_INTEGRATION.md", &integ),
        ] {
            for ghost in [
                "wire_up",
                "wire_pair_host",
                "wire_pair_join",
                "wire_pair_confirm",
                "wire_pair_accept",
                "wire_pair_reject",
                "wire_pair_list_inbound",
            ] {
                assert!(
                    !body.contains(ghost),
                    "{doc} advertises ghost MCP tool `{ghost}` (removed / never existed)"
                );
            }
        }
    }

    #[test]
    fn legacy_wire_join_call_returns_helpful_error() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "wire_join", "arguments": {}}
        });
        let resp = handle_request(&req, &McpState::default());
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("wire_dial"),
            "expected redirect to wire_dial, got: {text}"
        );
    }

    #[test]
    fn tools_list_canonical_present_deprecated_absent() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let resp = handle_request(&req, &McpState::default());
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();

        // Canonical names must be present.
        for required in ["wire_accept", "wire_reject", "wire_pending"] {
            assert!(
                names.contains(&required),
                "canonical tool {required} missing from tools/list"
            );
        }

        // Deprecated aliases must NOT be advertised (RFC-005 Phase 2).
        for removed in [
            "wire_pair_accept",
            "wire_pair_reject",
            "wire_pair_list_inbound",
        ] {
            assert!(
                !names.contains(&removed),
                "deprecated tool {removed} must not appear in tools/list"
            );
        }
    }

    #[test]
    fn deprecated_pair_accept_call_returns_helpful_error() {
        for (old_name, canonical) in [
            ("wire_pair_accept", "wire_accept"),
            ("wire_pair_reject", "wire_reject"),
            ("wire_pair_list_inbound", "wire_pending"),
        ] {
            let req = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": old_name, "arguments": {}}
            });
            let resp = handle_request(&req, &McpState::default());
            assert_eq!(
                resp["result"]["isError"], true,
                "calling {old_name} should return isError:true"
            );
            let text = resp["result"]["content"][0]["text"].as_str().unwrap();
            assert!(
                text.contains(canonical),
                "error for {old_name} should mention {canonical}, got: {text}"
            );
        }
    }

    #[test]
    fn initialize_advertises_resources_capability() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"});
        let resp = handle_request(&req, &McpState::default());
        let caps = &resp["result"]["capabilities"];
        assert!(
            caps["resources"].is_object(),
            "resources capability must be present, got {resp}"
        );
        assert_eq!(
            caps["resources"]["subscribe"], true,
            "subscribe shipped in v0.2.1"
        );
    }

    #[test]
    fn resources_read_with_bad_uri_errors() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {"uri": "http://example.com/not-a-wire-uri"}
        });
        let resp = handle_request(&req, &McpState::default());
        assert!(resp.get("error").is_some(), "expected error, got {resp}");
    }

    #[test]
    fn parse_inbox_uri_handles_variants() {
        assert_eq!(parse_inbox_uri("wire://inbox/paul"), Some("paul".into()));
        assert_eq!(parse_inbox_uri("wire://inbox/all"), None);
        assert!(
            parse_inbox_uri("wire://inbox/")
                .unwrap()
                .starts_with("__invalid__"),
            "empty peer must be invalid"
        );
        assert!(
            parse_inbox_uri("http://other")
                .unwrap()
                .starts_with("__invalid__"),
            "non-wire scheme must be invalid"
        );
    }

    #[test]
    fn ping_returns_empty_result() {
        let req = json!({"jsonrpc": "2.0", "id": 7, "method": "ping"});
        let resp = handle_request(&req, &McpState::default());
        assert_eq!(resp["id"], 7);
        assert!(resp["result"].is_object());
    }

    #[test]
    fn notification_returns_null_no_reply() {
        let req = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let resp = handle_request(&req, &McpState::default());
        assert_eq!(resp, Value::Null);
    }

    /// v0.6.1 regression: `detect_session_wire_home` must return the
    /// session's home dir when the cwd is in the registry AND the
    /// session dir exists on disk. The original v0.6.1 shipped with
    /// only an eprintln "verification" — this test asserts the
    /// observable return value so the env-set-but-not-consumed class
    /// of bug fails loudly.
    #[test]
    fn detect_session_wire_home_resolves_registered_cwd() {
        crate::config::test_support::with_temp_home(|| {
            // Set up sessions/registry.json + sessions/test-alpha/ under
            // the temp WIRE_HOME so session::read_registry +
            // session::session_dir resolve through it.
            let wire_home = std::env::var("WIRE_HOME").unwrap();
            let sessions_root = std::path::PathBuf::from(&wire_home).join("sessions");
            let session_home = sessions_root.join("test-alpha");
            std::fs::create_dir_all(&session_home).unwrap();
            let fake_cwd = "/tmp/fake-project-cwd-abc123";
            let registry = json!({"by_cwd": {fake_cwd: "test-alpha"}});
            std::fs::write(
                sessions_root.join("registry.json"),
                serde_json::to_vec_pretty(&registry).unwrap(),
            )
            .unwrap();

            // Hit happy path.
            let got = crate::session::detect_session_wire_home(std::path::Path::new(fake_cwd));
            assert_eq!(
                got.as_deref(),
                Some(session_home.as_path()),
                "registered cwd must resolve to session_home"
            );

            // Unregistered cwd → None.
            let nope = crate::session::detect_session_wire_home(std::path::Path::new(
                "/tmp/cwd-not-in-registry-xyz789",
            ));
            assert!(nope.is_none(), "unregistered cwd must return None");

            // Registered cwd but session dir missing → None (defensive:
            // stale registry entry pointing at a deleted session).
            let stale_cwd = "/tmp/stale-session-cwd";
            let stale_registry =
                json!({"by_cwd": {fake_cwd: "test-alpha", stale_cwd: "test-stale"}});
            std::fs::write(
                sessions_root.join("registry.json"),
                serde_json::to_vec_pretty(&stale_registry).unwrap(),
            )
            .unwrap();
            let stale_got =
                crate::session::detect_session_wire_home(std::path::Path::new(stale_cwd));
            assert!(
                stale_got.is_none(),
                "registered cwd whose session dir is missing must return None"
            );
        });
    }

    // v0.14.x: shape tests for `dial_target_to_whois_json`. The MCP whois
    // bare-nick fix routes through `cli::resolve_name_to_target` (returns
    // a `DialTarget`) and reshapes it for JSON-RPC consumption. These
    // tests pin the response shape so a future refactor of either side
    // (resolver or wire shape) catches the contract drift.

    #[test]
    fn dial_target_to_whois_json_pinned_peer_shape() {
        let target = crate::cli::DialTarget::PinnedPeer {
            handle: "slate-lotus".into(),
            did: "did:wire:slate-lotus-88232017".into(),
            nickname: Some("slate-lotus".into()),
            emoji: Some("🪴".into()),
            tier: "VERIFIED".into(),
        };
        crate::config::test_support::with_temp_home(|| {
            let out = dial_target_to_whois_json(&target);
            assert_eq!(out.get("kind").and_then(Value::as_str), Some("pinned_peer"));
            assert_eq!(
                out.get("handle").and_then(Value::as_str),
                Some("slate-lotus")
            );
            assert_eq!(out.get("tier").and_then(Value::as_str), Some("VERIFIED"));
            // op claims are absent when trust.json has no row for this
            // peer (the helper falls through to an empty map). No
            // spurious `null` op_did keys.
            assert!(out.get("op_did").is_none());
        });
    }

    #[test]
    fn dial_target_to_whois_json_local_sister_shape() {
        let target = crate::cli::DialTarget::LocalSister {
            session_name: "vesper-valley".into(),
            handle: "vesper-valley".into(),
            did: Some("did:wire:vesper-valley-deadbeef".into()),
            nickname: Some("vesper-valley".into()),
            emoji: Some("🦌".into()),
        };
        let out = dial_target_to_whois_json(&target);
        assert_eq!(
            out.get("kind").and_then(Value::as_str),
            Some("local_sister")
        );
        assert_eq!(
            out.get("session_name").and_then(Value::as_str),
            Some("vesper-valley")
        );
        assert_eq!(
            out.get("did").and_then(Value::as_str),
            Some("did:wire:vesper-valley-deadbeef")
        );
        // LocalSister carries no card → no op_claims path. Spot-check
        // no leakage from the PinnedPeer arm.
        assert!(out.get("tier").is_none());
        assert!(out.get("op_did").is_none());
    }
}
