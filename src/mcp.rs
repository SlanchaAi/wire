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
//! **Pairing (agent drives, but the user types the SAS digits back)**
//!   - `wire_init`           — idempotent identity creation; same handle = no-op,
//!     different handle = error (cannot re-key silently)
//!   - `wire_pair_initiate`  — host opens a pair-slot; returns code phrase
//!     agent shows to user out-of-band
//!   - `wire_pair_join`      — guest accepts a code phrase; both sides reach SAS-ready
//!   - `wire_pair_check`     — poll a pending session_id (used when initiate
//!     returned before peer was on the line)
//!   - `wire_pair_confirm`   — user types the 6 SAS digits back; mismatch aborts
//!
//! ## Why pairing is now agent-callable (T10 update)
//!
//! v0.1 originally refused `wire_init` / `wire_pair_*` over MCP entirely on
//! the theory that a fully-autonomous agent would skip the SAS confirmation.
//! The new design preserves the human gate by requiring the user to type the
//! 6-digit SAS back into chat — `wire_pair_confirm(session_id, typed_digits)`
//! compares against the cached SAS server-side, mismatch aborts the session.
//!
//! Defense-in-depth:
//!   1. SAS digits are returned as tool output the agent renders to the user.
//!      A malicious agent that fabricates digits in chat fails because the
//!      user's peer reads their independently-derived SAS over a side channel
//!      (voice / unrelated text channel). Mismatch on type-back aborts.
//!   2. The host runtime (Claude Desktop, etc.) is responsible for surfacing
//!      the type-back step to the actual user, not auto-filling. Wire cannot
//!      enforce this — see THREAT_MODEL.md T14.
//!
//! Concurrent multi-peer: each pair flow has its own session_id (the relay
//! pair_id) and its own `Mutex<PairSessionState>` in the in-memory store.
//! Pairing with N peers in parallel is fully supported.

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
/// v0.6.1: if WIRE_HOME isn't set in env, look up `$PWD` in the session
/// registry. If a session is registered for this cwd, return that
/// session's home dir; otherwise None.
///
/// Read-only — does NOT mutate env. The caller decides whether to apply.
fn detect_session_wire_home(cwd: &std::path::Path) -> Option<std::path::PathBuf> {
    let registry = crate::session::read_registry().ok()?;
    let cwd_str = cwd.to_string_lossy().into_owned();
    let session_name = registry.by_cwd.get(&cwd_str)?;
    let session_home = crate::session::session_dir(session_name).ok()?;
    if !session_home.exists() {
        return None;
    }
    Some(session_home)
}

pub fn run() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    // v0.6.1: auto-detect WIRE_HOME from cwd. If the operator already set
    // it (explicit override via `.mcp.json env.WIRE_HOME`), respect that.
    // Else: if the cwd maps to a `wire session` entry in the registry,
    // adopt that session's WIRE_HOME for this MCP process so every
    // subsequent tool call routes to the right inbox / outbox / identity.
    // Without this, two Claudes in different project dirs share the
    // default WIRE_HOME and race the cursor (issue #69 ergonomic ask
    // shipped from the v0.6.0 release thread).
    if std::env::var("WIRE_HOME").is_err()
        && let Ok(cwd) = std::env::current_dir()
        && let Some(home) = detect_session_wire_home(&cwd)
    {
        eprintln!(
            "wire mcp: auto-detected session for cwd `{}` → WIRE_HOME=`{}`",
            cwd.display(),
            home.display()
        );
        // SAFETY: we are at the very start of `run()`, BEFORE any worker
        // thread or watcher spawns; nothing else is reading env yet.
        unsafe {
            std::env::set_var("WIRE_HOME", &home);
        }
    }

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
        // Per-code fingerprint (status string) of the last seen pending-pair
        // snapshot. Used to detect transitions so we emit at most one
        // notification per actual change (not per poll).
        let mut prev_pending: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
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

            // ---- pending-pair state changes ----
            // Always poll (cheap dir read); only emit if subscribed.
            if let Ok(items) = crate::pending_pair::list_pending() {
                let mut cur: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                for p in &items {
                    cur.insert(p.code.clone(), p.status.clone());
                }
                // Detect any change vs. prev_pending: new code, removed code,
                // or status flip on existing code.
                let changed = cur.len() != prev_pending.len()
                    || cur.iter().any(|(k, v)| prev_pending.get(k) != Some(v))
                    || prev_pending.keys().any(|k| !cur.contains_key(k));
                if changed && subs_snapshot.contains("wire://pending-pair/all") {
                    affected.insert("wire://pending-pair/all".to_string());
                }
                prev_pending = cur;
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
    let mut resources = vec![
        json!({
            "uri": "wire://inbox/all",
            "name": "wire inbox (all peers)",
            "description": "Most recent verified events from all pinned peers, JSONL.",
            "mimeType": "application/x-ndjson"
        }),
        json!({
            "uri": "wire://pending-pair/all",
            "name": "wire pending pair sessions",
            "description": "All detached pair-host/pair-join sessions the local daemon is driving. Subscribe to receive notifications/resources/updated when status changes (notably polling → sas_ready: the agent should then surface the SAS digits to the user and call wire_pair_confirm with the typed-back digits).",
            "mimeType": "application/json"
        }),
    ];

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
    // Validate the URI shape. Accept wire://inbox/<peer>, wire://inbox/all,
    // wire://pending-pair/all. Anything else is rejected so we don't pile up
    // dead subscriptions.
    let inbox_peer = parse_inbox_uri(&uri);
    let is_pending = uri == "wire://pending-pair/all";
    if let Some(ref p) = inbox_peer
        && p.starts_with("__invalid__")
        && !is_pending
    {
        return error_response(
            id,
            -32602,
            "subscribe URI must be wire://inbox/<peer>, wire://inbox/all, or wire://pending-pair/all",
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
    // pending-pair takes priority over inbox parsing.
    if uri == "wire://pending-pair/all" {
        return match crate::pending_pair::list_pending() {
            Ok(items) => {
                let body = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "contents": [{
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": body,
                        }]
                    }
                })
            }
            Err(e) => error_response(id, -32603, &e.to_string()),
        };
    }
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

    let mut out = String::new();
    for (_peer, verified, mut event) in tail.iter().cloned() {
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
            "instructions": "wire — magic-wormhole for AI agents. Agents drive pairing via wire_pair_initiate/join/check; the user types the 6-digit SAS back into chat for wire_pair_confirm — this is the only human-in-loop step. v0.5.14 (zero-paste, bilateral-required): for `nick@domain` handles use wire_add; the peer MUST also run wire_add (or wire_pair_accept) on their side before capability flows. INBOUND pair requests from strangers land in pending-inbound: call wire_pair_list_inbound to enumerate, surface to operator, then wire_pair_accept or wire_pair_reject. Never auto-accept inbound pair requests without operator consent. Resources: 'wire://inbox/<peer>' exposes each pinned peer's verified inbox (JSONL). RECOMMENDED ON SESSION START: arm a persistent stream-watcher on `wire monitor` (or `wire monitor --json`) so peer messages surface mid-session instead of on next manual poll. In Claude Code that's the Monitor tool with persistent:true; in other harnesses background the process. Default filter strips pair_drop/pair_drop_ack/heartbeat noise — one stdout line per real event. See docs/AGENT_INTEGRATION.md for the full monitor recipe and THREAT_MODEL.md (T10/T14)."
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
            "name": "wire_send",
            "description": "Sign and queue an event to a peer. Returns event_id (SHA-256 of canonical body — content-addressed, so identical bodies produce identical event_ids and the daemon dedupes). Body may be plain text or a JSON-encoded structured value. Concurrent sends to multiple peers are safe (per-peer outbox files); concurrent sends to the same peer are serialized via a per-path lock.",
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
            "name": "wire_tail",
            "description": "Read recent signed events from this agent's inbox. Each event has a 'verified' field (bool) — the Ed25519 signature was checked against the trust state before the daemon wrote the inbox.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "peer": {"type": "string", "description": "Optional peer handle to filter inbox by."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50, "description": "Max events to return."}
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
            "description": "Idempotent identity creation. If already initialized with the same handle: returns the existing identity (no-op). If initialized with a different handle: errors — operator must explicitly delete config to re-key. If --relay is passed and not yet bound, also allocates a relay slot in one step.",
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
            "name": "wire_pair_initiate",
            "description": "Open a host-side pair-slot. AUTO-INITS the local identity if `handle` is provided and not yet inited (idempotent). Returns a code phrase the agent shows to the user out-of-band (voice / separate text channel) for the peer to paste into their wire_pair_join. Blocks up to max_wait_secs (default 30) for the peer to join, returning SAS inline if so — wire_pair_check is only needed when the host's 30s window closes before the peer joins. Multiple concurrent sessions supported (each call returns a distinct session_id).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "Auto-init this handle if local identity not yet created. Skipped if already inited."},
                    "relay_url": {"type": "string", "description": "Relay base URL. Defaults to the relay this agent's identity is already bound to."},
                    "max_wait_secs": {"type": "integer", "minimum": 0, "maximum": 60, "default": 30, "description": "How long to block waiting for peer to join before returning waiting-state. 0 = return immediately with code phrase only."}
                },
                "required": []
            }
        }),
        json!({
            "name": "wire_pair_join",
            "description": "Accept a code phrase from the host (the user types it in after the host shares it out-of-band). AUTO-INITS the local identity if `handle` is provided and not yet inited (idempotent). Returns SAS digits inline once SPAKE2 completes (typically <1s — host is already waiting). The user MUST then type the 6 SAS digits back into chat — pass them to wire_pair_confirm with the returned session_id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code_phrase": {"type": "string", "description": "Code phrase from the host (e.g. '73-2QXC4P')."},
                    "handle": {"type": "string", "description": "Auto-init this handle if local identity not yet created. Skipped if already inited."},
                    "relay_url": {"type": "string", "description": "Relay base URL. Defaults to the relay this agent's identity is already bound to."},
                    "max_wait_secs": {"type": "integer", "minimum": 0, "maximum": 60, "default": 30, "description": "How long to block waiting for SPAKE2 exchange to complete."}
                },
                "required": ["code_phrase"]
            }
        }),
        json!({
            "name": "wire_pair_check",
            "description": "Poll a pending pair session. Returns {state: 'waiting'|'sas_ready'|'finalized'|'aborted', sas?, peer_handle?}. Rarely needed — wire_pair_initiate now blocks 30s by default, covering most cases.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "max_wait_secs": {"type": "integer", "minimum": 0, "maximum": 60, "default": 8}
                },
                "required": ["session_id"]
            }
        }),
        json!({
            "name": "wire_pair_confirm",
            "description": "Verify the user typed the correct SAS digits, then finalize pairing (AEAD bootstrap exchange + pin peer). AUTO-SUBSCRIBES to wire://inbox/<peer> so the agent gets push notifications/resources/updated as new events arrive. The 6-digit SAS comes from the user via the agent's chat — the user reads digits from their peer (out-of-band side channel), then types them back into chat. Mismatch ABORTS this session permanently — start a fresh wire_pair_initiate. Accepts dashes/spaces ('384-217' or '384217' or '384 217').",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "user_typed_digits": {"type": "string", "description": "The 6 SAS digits the user typed back, e.g. '384217' or '384-217'."}
                },
                "required": ["session_id", "user_typed_digits"]
            }
        }),
        json!({
            "name": "wire_pair_initiate_detached",
            "description": "Detached variant of wire_pair_initiate: queues a host-side pair via the local `wire daemon` (auto-spawned if not running) and returns IMMEDIATELY with the code phrase. The daemon drives the handshake in the background. Subscribe to wire://pending-pair/all to get notifications/resources/updated when status → sas_ready, then call wire_pair_confirm_detached(code, digits). Use this if your agent prompt expects to surface the code first and confirm later (across multiple chat turns) rather than block 30s.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "Optional handle for auto-init (idempotent)."},
                    "relay_url": {"type": "string"}
                }
            }
        }),
        json!({
            "name": "wire_pair_join_detached",
            "description": "Detached variant of wire_pair_join. Same flow as wire_pair_initiate_detached but as guest: queues a pair-join on the local daemon. Returns immediately. Subscribe to wire://pending-pair/all for the eventual sas_ready notification.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {"type": "string"},
                    "code_phrase": {"type": "string"},
                    "relay_url": {"type": "string"}
                },
                "required": ["code_phrase"]
            }
        }),
        json!({
            "name": "wire_pair_list_pending",
            "description": "Return the local daemon's pending detached pair sessions (all states). Same shape as `wire pair-list` JSON. Cheap call — agent can poll, but prefer subscribing to wire://pending-pair/all for push notifications.",
            "inputSchema": {"type": "object", "properties": {}}
        }),
        json!({
            "name": "wire_pair_confirm_detached",
            "description": "Confirm a detached pair after SAS surfaces (status=sas_ready). The user must read the SAS digits aloud to their peer over a side channel; if they match the peer's digits, the user types digits back into chat — pass those to this tool. Mismatch ABORTS. The daemon picks up the confirmation on its next tick and finalizes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code_phrase": {"type": "string"},
                    "user_typed_digits": {"type": "string"}
                },
                "required": ["code_phrase", "user_typed_digits"]
            }
        }),
        json!({
            "name": "wire_pair_cancel_pending",
            "description": "Cancel a pending detached pair. Releases the relay slot and removes the local pending file. Safe to call regardless of current status (idempotent).",
            "inputSchema": {
                "type": "object",
                "properties": {"code_phrase": {"type": "string"}},
                "required": ["code_phrase"]
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
            "description": "Bilateral pair (v0.5.14). Resolve a peer handle (`nick@domain`) via the domain's `.well-known/wire/agent`, pin them locally, and deliver a signed pair-intro to their slot. THE PEER MUST ALSO RUN `wire add` (or `wire pair-accept`) ON THEIR SIDE — bilateral-required as of v0.5.14, no auto-pin on receiver. Once both sides have gestured consent, capability flows in both directions. Use this for outgoing pair requests; for incoming pair_drops in the operator's pending-inbound queue, use `wire_pair_accept` or `wire_pair_reject` instead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "Peer handle like `nick@domain`."},
                    "relay_url": {"type": "string", "description": "Override resolver URL (default: `https://<domain>`)."}
                },
                "required": ["handle"]
            }
        }),
        json!({
            "name": "wire_pair_accept",
            "description": "Accept a pending-inbound pair request (v0.5.14). When a stranger has run `wire add you@<your-relay>` against this agent's handle, their signed pair_drop sits in pending-inbound — see `wire_pair_list_inbound` to enumerate. Calling this command pins them VERIFIED, ships our slot_token via `pair_drop_ack`, and deletes the pending record. Requires explicit operator consent: the agent SHOULD surface the pending request to the user (e.g. via OS toast or in chat) before calling this, because accepting grants the peer authenticated write access to this agent's inbox. Errors if no pending record exists for the named peer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "peer": {"type": "string", "description": "Bare peer handle (without `@<relay>`). Match exactly what `wire_pair_list_inbound` returned in `peer_handle`."}
                },
                "required": ["peer"]
            }
        }),
        json!({
            "name": "wire_pair_reject",
            "description": "Refuse a pending-inbound pair request (v0.5.14). Deletes the pending record. The peer never receives our slot_token; from their side the pair stays pending until they time out or remove their outbound record. Idempotent — succeeds with `rejected: false` if no record existed for that peer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "peer": {"type": "string", "description": "Bare peer handle (without `@<relay>`)."}
                },
                "required": ["peer"]
            }
        }),
        json!({
            "name": "wire_pair_list_inbound",
            "description": "List pending-inbound pair requests (v0.5.14). Returns a flat array of `{peer_handle, peer_did, peer_relay_url, peer_slot_id, received_at, event_id}` records, oldest first. Each entry is a stranger who has run `wire add` against this agent's handle but hasn't been accepted yet. Use this on session start (or in response to a `wire — pair request from X` OS toast) to surface pending requests to the operator for accept/reject decisions.",
            "inputSchema": {"type": "object", "properties": {}}
        }),
        json!({
            "name": "wire_claim",
            "description": "Claim a nick on a relay's handle directory so other agents can reach this agent by `<nick>@<relay-domain>`. Auto-inits + auto-allocates a relay slot if needed. FCFS — same-DID re-claims allowed (used for profile/slot updates).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "nick": {"type": "string", "description": "2-32 chars, [a-z0-9_-], not in the reserved set."},
                    "relay_url": {"type": "string", "description": "Relay to claim on. Default = our relay."},
                    "public_url": {"type": "string", "description": "Public URL the relay should advertise to resolvers."}
                },
                "required": ["nick"]
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
    ]
}

fn handle_tools_call(id: &Value, params: &Value, state: &McpState) -> Value {
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
        "wire_peers" => tool_peers(),
        "wire_send" => tool_send(&args),
        "wire_tail" => tool_tail(&args),
        "wire_verify" => tool_verify(&args),
        "wire_init" => tool_init(&args),
        "wire_pair_initiate" => tool_pair_initiate(&args),
        "wire_pair_join" => tool_pair_join(&args),
        "wire_pair_check" => tool_pair_check(&args),
        "wire_pair_confirm" => tool_pair_confirm(&args, state),
        "wire_pair_initiate_detached" => tool_pair_initiate_detached(&args),
        "wire_pair_join_detached" => tool_pair_join_detached(&args),
        "wire_pair_list_pending" => tool_pair_list_pending(),
        "wire_pair_confirm_detached" => tool_pair_confirm_detached(&args),
        "wire_pair_cancel_pending" => tool_pair_cancel_pending(&args),
        "wire_invite_mint" => tool_invite_mint(&args),
        "wire_invite_accept" => tool_invite_accept(&args),
        // v0.5 — agentic hotline (handle + profile + zero-paste discovery).
        "wire_add" => tool_add(&args),
        // v0.5.14 — bilateral-required pair: inbound queue management.
        "wire_pair_accept" => tool_pair_accept(&args),
        "wire_pair_reject" => tool_pair_reject(&args),
        "wire_pair_list_inbound" => tool_pair_list_inbound(),
        "wire_claim" => tool_claim_handle(&args),
        "wire_whois" => tool_whois(&args),
        "wire_profile_set" => tool_profile_set(&args),
        "wire_profile_get" => tool_profile_get(),
        // Legacy alias kept for older agent prompts that reference `wire_join`.
        // Surfaces the operator-friendly error pointing to wire_pair_join.
        "wire_join" => Err(
            "wire_join was renamed to wire_pair_join (use code_phrase argument). \
             See docs/AGENT_INTEGRATION.md."
                .into(),
        ),
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
        return Err("not initialized — operator must run `wire init <handle>` first".into());
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
        .unwrap_or_else(|| json!(["wire/v3.1"]));
    Ok(json!({
        "did": did,
        "handle": handle,
        "fingerprint": fp,
        "key_id": key_id,
        "public_key_b64": pk_b64,
        "capabilities": capabilities,
    }))
}

fn tool_peers() -> Result<Value, String> {
    use crate::config;
    use crate::trust::get_tier;

    let trust = config::read_trust().map_err(|e| e.to_string())?;
    let agents = trust
        .get("agents")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
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
        peers.push(json!({
            "handle": handle,
            "did": did,
            "tier": get_tier(&trust, handle),
            "capabilities": agent.get("card").and_then(|c| c.get("capabilities")).cloned().unwrap_or_else(|| json!([])),
        }));
    }
    Ok(json!(peers))
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

    if !config::is_initialized().map_err(|e| e.to_string())? {
        return Err("not initialized — operator must run `wire init <handle>` first".into());
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

    let mut event = json!({
        "timestamp": now,
        "from": did,
        "to": format!("did:wire:{peer}"),
        "type": kind,
        "kind": kind_id,
        "body": body_value,
    });
    if let Some(deadline) = deadline {
        event["time_sensitive_until"] =
            json!(crate::cli::parse_deadline_until(deadline).map_err(|e| e.to_string())?);
    }
    let signed =
        sign_message_v31(&event, &sk_seed, &pk_bytes, &handle).map_err(|e| e.to_string())?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    let line = serde_json::to_vec(&signed).map_err(|e| e.to_string())?;
    let outbox = config::append_outbox_record(peer, &line).map_err(|e| e.to_string())?;

    Ok(json!({
        "event_id": event_id,
        "status": "queued",
        "peer": peer,
        "outbox": outbox.to_string_lossy(),
    }))
}

fn tool_tail(args: &Value) -> Result<Value, String> {
    use crate::config;
    use crate::signing::verify_message_v31;

    let peer_filter = args.get("peer").and_then(Value::as_str);
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
    let inbox = config::inbox_dir().map_err(|e| e.to_string())?;
    if !inbox.exists() {
        return Ok(json!([]));
    }
    let trust = config::read_trust().map_err(|e| e.to_string())?;
    let mut events = Vec::new();
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
    for path in entries {
        let body = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        for line in body.lines() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let verified = verify_message_v31(&event, &trust).is_ok();
            let mut event_with_meta = event.clone();
            if let Some(obj) = event_with_meta.as_object_mut() {
                obj.insert("verified".into(), json!(verified));
            }
            events.push(event_with_meta);
            if events.len() >= limit {
                return Ok(Value::Array(events));
            }
        }
    }
    Ok(Value::Array(events))
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

fn tool_init(args: &Value) -> Result<Value, String> {
    let handle = args
        .get("handle")
        .and_then(Value::as_str)
        .ok_or("missing 'handle'")?;
    let name = args.get("name").and_then(Value::as_str);
    let relay = args.get("relay_url").and_then(Value::as_str);
    crate::pair_session::init_self_idempotent(handle, name, relay).map_err(|e| e.to_string())
}

/// Resolve the relay URL: explicit arg wins, else the relay this agent's
/// identity is already bound to (from `wire init --relay` or a previous
/// pair_initiate). Errors if neither is set.
fn resolve_relay_url(args: &Value) -> Result<String, String> {
    if let Some(url) = args.get("relay_url").and_then(Value::as_str) {
        return Ok(url.to_string());
    }
    let state = crate::config::read_relay_state().map_err(|e| e.to_string())?;
    state["self"]["relay_url"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "no relay_url provided and no relay bound (call wire_init with relay_url, or pass relay_url here)".into())
}

/// If `handle` is provided and identity isn't yet initialized, call
/// `init_self_idempotent` so a single MCP call can do both. If handle is
/// missing and not initialized, surface a clear error pointing the agent at
/// wire_init. If already initialized under a different handle, the
/// idempotent init errors clearly (same as direct wire_init).
fn auto_init_if_needed(args: &Value) -> Result<(), String> {
    let initialized = crate::config::is_initialized().map_err(|e| e.to_string())?;
    if initialized {
        return Ok(());
    }
    let handle = args.get("handle").and_then(Value::as_str).ok_or(
        "not initialized — pass `handle` to auto-init, or call wire_init explicitly first",
    )?;
    let relay = args.get("relay_url").and_then(Value::as_str);
    crate::pair_session::init_self_idempotent(handle, None, relay)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn tool_pair_initiate(args: &Value) -> Result<Value, String> {
    use crate::pair_session::{
        pair_session_open, pair_session_wait_for_sas, store_insert, store_sweep_expired,
    };

    store_sweep_expired();
    // Auto-init if `handle` arg provided and not yet inited (idempotent).
    auto_init_if_needed(args)?;

    let relay_url = resolve_relay_url(args)?;
    let max_wait = args
        .get("max_wait_secs")
        .and_then(Value::as_u64)
        .unwrap_or(30)
        .min(60);

    let mut s = pair_session_open("host", &relay_url, None).map_err(|e| e.to_string())?;
    let code = s.code.clone();

    let sas_opt = if max_wait > 0 {
        pair_session_wait_for_sas(&mut s, max_wait, std::time::Duration::from_millis(250))
            .map_err(|e| e.to_string())?
    } else {
        None
    };

    let session_id = store_insert(s);

    let mut out = json!({
        "session_id": session_id,
        "code_phrase": code,
        "relay_url": relay_url,
    });
    match sas_opt {
        Some(sas) => {
            out["state"] = json!("sas_ready");
            out["sas"] = json!(sas);
            out["next"] = json!(
                "Show this SAS to the user and ask them to compare with their peer's SAS over a side channel (voice/text). \
                 Then ask the user to TYPE the 6 digits BACK INTO CHAT — pass that to wire_pair_confirm."
            );
        }
        None => {
            out["state"] = json!("waiting");
            out["next"] = json!(
                "Share the code_phrase with the user; ask them to read it to their peer (the peer pastes into wire_pair_join). \
                 Poll wire_pair_check(session_id) until state='sas_ready'."
            );
        }
    }
    Ok(out)
}

fn tool_pair_join(args: &Value) -> Result<Value, String> {
    use crate::pair_session::{
        pair_session_open, pair_session_wait_for_sas, store_insert, store_sweep_expired,
    };

    store_sweep_expired();
    auto_init_if_needed(args)?;

    let code = args
        .get("code_phrase")
        .and_then(Value::as_str)
        .ok_or("missing 'code_phrase'")?;
    let relay_url = resolve_relay_url(args)?;
    let max_wait = args
        .get("max_wait_secs")
        .and_then(Value::as_u64)
        .unwrap_or(30)
        .min(60);

    let mut s = pair_session_open("guest", &relay_url, Some(code)).map_err(|e| e.to_string())?;

    let sas_opt =
        pair_session_wait_for_sas(&mut s, max_wait, std::time::Duration::from_millis(250))
            .map_err(|e| e.to_string())?;

    let session_id = store_insert(s);

    let mut out = json!({
        "session_id": session_id,
        "relay_url": relay_url,
    });
    match sas_opt {
        Some(sas) => {
            out["state"] = json!("sas_ready");
            out["sas"] = json!(sas);
            out["next"] = json!(
                "Show this SAS to the user and ask them to compare with their peer's SAS over a side channel. \
                 Then ask the user to TYPE the 6 digits BACK INTO CHAT — pass that to wire_pair_confirm."
            );
        }
        None => {
            out["state"] = json!("waiting");
            out["next"] = json!("Poll wire_pair_check(session_id).");
        }
    }
    Ok(out)
}

fn tool_pair_check(args: &Value) -> Result<Value, String> {
    use crate::pair_session::{pair_session_wait_for_sas, store_get, store_sweep_expired};

    store_sweep_expired();
    let session_id = args
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or("missing 'session_id'")?;
    let max_wait = args
        .get("max_wait_secs")
        .and_then(Value::as_u64)
        .unwrap_or(8)
        .min(60);

    let arc = store_get(session_id)
        .ok_or_else(|| format!("no such session_id (expired or never opened): {session_id}"))?;
    let mut s = arc.lock().map_err(|e| e.to_string())?;

    if s.finalized {
        return Ok(json!({
            "state": "finalized",
            "session_id": session_id,
            "sas": s.formatted_sas(),
        }));
    }
    if let Some(reason) = s.aborted.clone() {
        return Ok(json!({
            "state": "aborted",
            "session_id": session_id,
            "reason": reason,
        }));
    }

    let sas_opt =
        pair_session_wait_for_sas(&mut s, max_wait, std::time::Duration::from_millis(250))
            .map_err(|e| e.to_string())?;

    Ok(match sas_opt {
        Some(sas) => json!({
            "state": "sas_ready",
            "session_id": session_id,
            "sas": sas,
            "next": "Have the user TYPE the 6 SAS digits BACK INTO CHAT, then pass to wire_pair_confirm."
        }),
        None => json!({
            "state": "waiting",
            "session_id": session_id,
        }),
    })
}

fn tool_pair_confirm(args: &Value, state: &McpState) -> Result<Value, String> {
    use crate::pair_session::{
        pair_session_confirm_sas, pair_session_finalize, store_get, store_remove,
    };

    let session_id = args
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or("missing 'session_id'")?;
    let typed = args
        .get("user_typed_digits")
        .and_then(Value::as_str)
        .ok_or(
            "missing 'user_typed_digits' — the user must type the 6 SAS digits back into chat",
        )?;

    let arc = store_get(session_id).ok_or_else(|| format!("no such session_id: {session_id}"))?;

    let confirm_err = {
        let mut s = arc.lock().map_err(|e| e.to_string())?;
        match pair_session_confirm_sas(&mut s, typed) {
            Ok(()) => None,
            Err(e) => Some((s.aborted.is_some(), e.to_string())),
        }
    };
    if let Some((aborted, msg)) = confirm_err {
        if aborted {
            store_remove(session_id);
        }
        return Err(msg);
    }

    let mut result = {
        let mut s = arc.lock().map_err(|e| e.to_string())?;
        pair_session_finalize(&mut s, 30).map_err(|e| e.to_string())?
    };
    store_remove(session_id);

    // ---- Post-pair auto-setup (Goal: zero friction after SAS) ----
    // 1. Auto-subscribe to wire://inbox/<peer> so clients that support
    //    resources/subscribe get push notifications/resources/updated.
    // 2. Spawn `wire daemon` if not already running so push/pull is automatic.
    // 3. Spawn `wire notify` if not already running so OS toasts fire on
    //    inbox grow (covers MCP hosts that lack resources/subscribe).
    // 4. Emit notifications/resources/list_changed via the writer channel so
    //    a client that called resources/list before pairing refreshes its view.
    let peer_handle = result["peer_handle"].as_str().unwrap_or("").to_string();
    let peer_uri = format!("wire://inbox/{peer_handle}");

    let mut auto = json!({
        "subscribed": false,
        "daemon": "unknown",
        "notify": "unknown",
        "resources_list_changed_emitted": false,
    });

    if !peer_handle.is_empty()
        && let Ok(mut g) = state.subscribed.lock()
    {
        g.insert(peer_uri.clone());
        auto["subscribed"] = json!(true);
    }

    auto["daemon"] = match crate::ensure_up::ensure_daemon_running() {
        Ok(true) => json!("spawned"),
        Ok(false) => json!("already_running"),
        Err(e) => json!(format!("spawn_error: {e}")),
    };
    auto["notify"] = match crate::ensure_up::ensure_notify_running() {
        Ok(true) => json!("spawned"),
        Ok(false) => json!("already_running"),
        Err(e) => json!(format!("spawn_error: {e}")),
    };

    if let Some(tx) = state.notif_tx.lock().ok().and_then(|g| g.clone()) {
        let notif = json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/list_changed",
        });
        if tx.send(notif.to_string()).is_ok() {
            auto["resources_list_changed_emitted"] = json!(true);
        }
    }

    result["auto"] = auto;
    result["next"] = json!(
        "Done. Daemon + notify running, subscribed to peer inbox. Use wire_send/wire_tail \
         freely; new events arrive via notifications/resources/updated (where supported) and \
         OS toasts (always)."
    );
    Ok(result)
}

// ---------- detached pair tools (daemon-orchestrated) ----------

fn tool_pair_initiate_detached(args: &Value) -> Result<Value, String> {
    auto_init_if_needed(args)?;
    let relay_url = resolve_relay_url(args)?;
    if std::env::var("WIRE_MCP_SKIP_AUTO_UP").is_err() {
        let _ = crate::ensure_up::ensure_daemon_running();
    }
    let code = crate::sas::generate_code_phrase();
    let code_hash = crate::pair_session::derive_code_hash(&code);
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let p = crate::pending_pair::PendingPair {
        code: code.clone(),
        code_hash,
        role: "host".to_string(),
        relay_url: relay_url.clone(),
        status: "request_host".to_string(),
        sas: None,
        peer_did: None,
        created_at: now,
        last_error: None,
        pair_id: None,
        our_slot_id: None,
        our_slot_token: None,
        spake2_seed_b64: None,
    };
    crate::pending_pair::write_pending(&p).map_err(|e| e.to_string())?;
    Ok(json!({
        "code_phrase": code,
        "relay_url": relay_url,
        "state": "queued",
        "next": "Share code_phrase with the user. Subscribe to wire://pending-pair/all; when notifications/resources/updated arrives, read the resource and surface the SAS digits to the user once status=sas_ready. Then call wire_pair_confirm_detached with code_phrase + user_typed_digits."
    }))
}

fn tool_pair_join_detached(args: &Value) -> Result<Value, String> {
    auto_init_if_needed(args)?;
    let relay_url = resolve_relay_url(args)?;
    let code_phrase = args
        .get("code_phrase")
        .and_then(Value::as_str)
        .ok_or("missing 'code_phrase'")?;
    let code = crate::sas::parse_code_phrase(code_phrase)
        .map_err(|e| e.to_string())?
        .to_string();
    let code_hash = crate::pair_session::derive_code_hash(&code);
    if std::env::var("WIRE_MCP_SKIP_AUTO_UP").is_err() {
        let _ = crate::ensure_up::ensure_daemon_running();
    }
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let p = crate::pending_pair::PendingPair {
        code: code.clone(),
        code_hash,
        role: "guest".to_string(),
        relay_url: relay_url.clone(),
        status: "request_guest".to_string(),
        sas: None,
        peer_did: None,
        created_at: now,
        last_error: None,
        pair_id: None,
        our_slot_id: None,
        our_slot_token: None,
        spake2_seed_b64: None,
    };
    crate::pending_pair::write_pending(&p).map_err(|e| e.to_string())?;
    Ok(json!({
        "code_phrase": code,
        "relay_url": relay_url,
        "state": "queued",
        "next": "Subscribe to wire://pending-pair/all; on sas_ready notification, surface digits to user and call wire_pair_confirm_detached."
    }))
}

fn tool_pair_list_pending() -> Result<Value, String> {
    let items = crate::pending_pair::list_pending().map_err(|e| e.to_string())?;
    Ok(json!({"pending": items}))
}

fn tool_pair_confirm_detached(args: &Value) -> Result<Value, String> {
    let code_phrase = args
        .get("code_phrase")
        .and_then(Value::as_str)
        .ok_or("missing 'code_phrase'")?;
    let typed = args
        .get("user_typed_digits")
        .and_then(Value::as_str)
        .ok_or("missing 'user_typed_digits'")?;
    let code = crate::sas::parse_code_phrase(code_phrase)
        .map_err(|e| e.to_string())?
        .to_string();
    let typed: String = typed.chars().filter(|c| c.is_ascii_digit()).collect();
    if typed.len() != 6 {
        return Err(format!(
            "expected 6 digits (got {} after stripping non-digits)",
            typed.len()
        ));
    }
    let mut p = crate::pending_pair::read_pending(&code)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no pending pair for code {code}"))?;
    if p.status != "sas_ready" {
        return Err(format!(
            "pair {code} not in sas_ready state (current: {})",
            p.status
        ));
    }
    let stored = p
        .sas
        .as_ref()
        .ok_or("pending file has status=sas_ready but no sas field")?
        .clone();
    if stored == typed {
        p.status = "confirmed".to_string();
        crate::pending_pair::write_pending(&p).map_err(|e| e.to_string())?;
        Ok(json!({
            "state": "confirmed",
            "code_phrase": code,
            "next": "Daemon will finalize on its next tick (~1s). Poll wire_peers or watch wire://pending-pair/all for the entry to disappear."
        }))
    } else {
        p.status = "aborted".to_string();
        p.last_error = Some(format!(
            "SAS digit mismatch (typed {typed}, expected {stored})"
        ));
        let client = crate::relay_client::RelayClient::new(&p.relay_url);
        let _ = client.pair_abandon(&p.code_hash);
        let _ = crate::pending_pair::write_pending(&p);
        crate::os_notify::toast(
            &format!("wire — pair aborted ({code})"),
            p.last_error.as_deref().unwrap_or("digits mismatch"),
        );
        Err(
            "digits mismatch — pair aborted. Re-issue with wire_pair_initiate_detached."
                .to_string(),
        )
    }
}

fn tool_pair_cancel_pending(args: &Value) -> Result<Value, String> {
    let code_phrase = args
        .get("code_phrase")
        .and_then(Value::as_str)
        .ok_or("missing 'code_phrase'")?;
    let code = crate::sas::parse_code_phrase(code_phrase)
        .map_err(|e| e.to_string())?
        .to_string();
    if let Some(p) = crate::pending_pair::read_pending(&code).map_err(|e| e.to_string())? {
        let client = crate::relay_client::RelayClient::new(&p.relay_url);
        let _ = client.pair_abandon(&p.code_hash);
    }
    crate::pending_pair::delete_pending(&code).map_err(|e| e.to_string())?;
    Ok(json!({"state": "cancelled", "code_phrase": code}))
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

// ---------- v0.5 — agentic hotline tools ----------

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

/// v0.5.14: MCP `wire_pair_accept` — bilateral completion of a
/// pending-inbound pair request. The agent SHOULD have surfaced the
/// pending request to the operator before calling this; acceptance
/// grants peer authenticated write access to this agent's inbox.
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
                "no pending pair request from {nick}. Call wire_pair_list_inbound to enumerate, \
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

    // Ship our slot_token via pair_drop_ack.
    crate::pair_invite::send_pair_drop_ack(
        &pending.peer_handle,
        &pending.peer_relay_url,
        &pending.peer_slot_id,
        &pending.peer_slot_token,
    )
    .map_err(|e| {
        format!(
            "pair_drop_ack send to {} @ {} slot {} failed: {e:#}",
            pending.peer_handle, pending.peer_relay_url, pending.peer_slot_id
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

/// v0.5.14: MCP `wire_pair_reject` — delete a pending-inbound record
/// without pairing. Peer never receives our slot_token. Idempotent.
fn tool_pair_reject(args: &Value) -> Result<Value, String> {
    let peer = args
        .get("peer")
        .and_then(Value::as_str)
        .ok_or("missing 'peer'")?;
    let nick = crate::agent_card::bare_handle(peer);
    let existed = crate::pending_inbound_pair::read_pending_inbound(nick)
        .map_err(|e| format!("{e:#}"))?;
    crate::pending_inbound_pair::consume_pending_inbound(nick)
        .map_err(|e| format!("{e:#}"))?;
    Ok(json!({
        "peer": nick,
        "rejected": existed.is_some(),
        "had_pending": existed.is_some(),
    }))
}

/// v0.5.14: MCP `wire_pair_list_inbound` — enumerate pending-inbound
/// pair requests for operator review. Flat array sorted oldest-first.
fn tool_pair_list_inbound() -> Result<Value, String> {
    let items = crate::pending_inbound_pair::list_pending_inbound()
        .map_err(|e| format!("{e:#}"))?;
    Ok(json!(items))
}

fn tool_claim_handle(args: &Value) -> Result<Value, String> {
    let nick = args
        .get("nick")
        .and_then(Value::as_str)
        .ok_or("missing 'nick'")?;
    let relay_override = args.get("relay_url").and_then(Value::as_str);
    let public_url = args.get("public_url").and_then(Value::as_str);

    // Auto-init + ensure slot.
    let (_, our_relay, our_slot_id, our_slot_token) =
        crate::pair_invite::ensure_self_with_relay(relay_override).map_err(|e| format!("{e:#}"))?;
    let claim_relay = relay_override.unwrap_or(&our_relay);
    let card = crate::config::read_agent_card().map_err(|e| format!("{e:#}"))?;
    let client = crate::relay_client::RelayClient::new(claim_relay);
    let resp = client
        .handle_claim(nick, &our_slot_id, &our_slot_token, public_url, &card)
        .map_err(|e| format!("{e:#}"))?;
    Ok(json!({
        "nick": nick,
        "relay": claim_relay,
        "response": resp,
    }))
}

fn tool_whois(args: &Value) -> Result<Value, String> {
    if let Some(handle) = args.get("handle").and_then(Value::as_str) {
        let parsed = crate::pair_profile::parse_handle(handle).map_err(|e| format!("{e:#}"))?;
        let relay_override = args.get("relay_url").and_then(Value::as_str);
        crate::pair_profile::resolve_handle(&parsed, relay_override).map_err(|e| format!("{e:#}"))
    } else {
        // Self.
        let card = crate::config::read_agent_card().map_err(|e| format!("{e:#}"))?;
        Ok(json!({
            "did": card.get("did").cloned().unwrap_or(Value::Null),
            "profile": card.get("profile").cloned().unwrap_or(Value::Null),
        }))
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
            "wire_pair_initiate",
            "wire_pair_join",
            "wire_pair_check",
            "wire_pair_confirm",
        ] {
            assert!(
                names.contains(&required),
                "missing required tool {required}"
            );
        }
        // wire_join (the old direct alias for pair-join, no SAS-typeback) is
        // explicitly NOT in the catalog. Calling it returns a deprecation
        // pointing to wire_pair_join (test below covers this).
        assert!(
            !names.contains(&"wire_join"),
            "wire_join must not be advertised — superseded by wire_pair_join"
        );
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
            text.contains("wire_pair_join"),
            "expected redirect to wire_pair_join, got: {text}"
        );
    }

    #[test]
    fn pair_confirm_missing_session_id_errors_cleanly() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "wire_pair_confirm", "arguments": {"user_typed_digits": "111111"}}
        });
        let resp = handle_request(&req, &McpState::default());
        assert_eq!(resp["result"]["isError"], true);
    }

    #[test]
    fn pair_confirm_unknown_session_errors_cleanly() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wire_pair_confirm",
                "arguments": {"session_id": "definitely-not-real", "user_typed_digits": "111111"}
            }
        });
        let resp = handle_request(&req, &McpState::default());
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no such session_id"), "got: {text}");
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
}
