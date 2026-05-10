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
//!                             different handle = error (cannot re-key silently)
//!   - `wire_pair_initiate`  — host opens a pair-slot; returns code phrase
//!                             agent shows to user out-of-band
//!   - `wire_pair_join`      — guest accepts a code phrase; both sides reach SAS-ready
//!   - `wire_pair_check`     — poll a pending session_id (used when initiate
//!                             returned before peer was on the line)
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
use std::io::{BufRead, BufReader, Write};

const PROTOCOL_VERSION: &str = "2025-06-18";
const SERVER_NAME: &str = "wire";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run the MCP server until stdin closes.
pub fn run() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(()); // EOF
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                write_response(
                    &mut writer,
                    &error_response(&Value::Null, -32700, &format!("parse error: {e}")),
                )?;
                continue;
            }
        };
        let response = handle_request(&request);
        // Notifications (no `id`) get no response.
        if response.get("id").is_some() || response.get("error").is_some() {
            write_response(&mut writer, &response)?;
        }
    }
}

fn write_response(w: &mut impl Write, response: &Value) -> Result<()> {
    let body = serde_json::to_string(response)?;
    writeln!(w, "{body}")?;
    w.flush()?;
    Ok(())
}

fn handle_request(req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = match req.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => return error_response(&id, -32600, "missing method"),
    };
    match method {
        "initialize" => handle_initialize(&id),
        "notifications/initialized" => Value::Null, // notification — no reply
        "tools/list" => handle_tools_list(&id),
        "tools/call" => handle_tools_call(&id, req.get("params").unwrap_or(&Value::Null)),
        "resources/list" => handle_resources_list(&id),
        "resources/read" => handle_resources_read(&id, req.get("params").unwrap_or(&Value::Null)),
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
    if let Some(ref p) = peer_opt {
        if p.starts_with("__invalid__") {
            return Err(
                "unknown resource URI (must be wire://inbox/<peer> or wire://inbox/all)".into(),
            );
        }
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
                    // Subscribe support is v0.2.1 — the current MCP server is a
                    // synchronous stdin loop, and pushing notifications/resources/updated
                    // requires a background watcher thread + async stdout writer. Read
                    // (poll-driven) is shipped now.
                    "subscribe": false
                }
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
            "instructions": "wire — magic-wormhole for AI agents. Agents drive pairing via wire_pair_initiate/join/check; the user types the 6-digit SAS back into chat for wire_pair_confirm — this is the only human-in-loop step. Resources: 'wire://inbox/<peer>' exposes each pinned peer's verified inbox (JSONL). See docs/AGENT_INTEGRATION.md and THREAT_MODEL.md (T10/T14)."
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
                    "body": {"type": "string", "description": "Event body. Plain text becomes a JSON string; valid JSON is parsed and embedded structurally."}
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
            "description": "Open a host-side pair-slot. Returns a code phrase the agent shows to the user out-of-band (voice, side text channel) for the peer to type into their wire_pair_join. Blocks up to max_wait_secs (default 8) for the peer to join, returning SAS digits inline if so; otherwise returns waiting-state and the agent should poll wire_pair_check. SUPPORTS multiple concurrent sessions (each call returns a distinct session_id).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "relay_url": {"type": "string", "description": "Relay base URL. Defaults to the relay this agent's identity is already bound to."},
                    "max_wait_secs": {"type": "integer", "minimum": 0, "maximum": 60, "default": 8, "description": "How long to block waiting for peer to join before returning waiting-state. 0 = return immediately with code phrase only."}
                },
                "required": []
            }
        }),
        json!({
            "name": "wire_pair_join",
            "description": "Accept a code phrase from the host (typed by the user). Returns SAS digits inline once SPAKE2 completes (typically <1s since host is already on the line). The user MUST then type the SAS digits back into chat — pass them to wire_pair_confirm with the returned session_id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code_phrase": {"type": "string", "description": "Code phrase from the host (e.g. '73-2QXC4P')."},
                    "relay_url": {"type": "string", "description": "Relay base URL. Defaults to the relay this agent's identity is already bound to."},
                    "max_wait_secs": {"type": "integer", "minimum": 0, "maximum": 60, "default": 30, "description": "How long to block waiting for SPAKE2 exchange to complete."}
                },
                "required": ["code_phrase"]
            }
        }),
        json!({
            "name": "wire_pair_check",
            "description": "Poll a pending pair session. Returns {state: 'waiting'|'sas_ready'|'finalized'|'aborted', sas?, peer_handle?}. Used after wire_pair_initiate returns waiting-state.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "max_wait_secs": {"type": "integer", "minimum": 0, "maximum": 60, "default": 4}
                },
                "required": ["session_id"]
            }
        }),
        json!({
            "name": "wire_pair_confirm",
            "description": "Verify the user typed the correct SAS digits, then finalize pairing (AEAD bootstrap exchange + pin peer). The 6-digit SAS comes from the user via the agent's chat — the user reads digits from their peer (out-of-band side channel), then types them back into chat. Mismatch ABORTS this session permanently — start a fresh wire_pair_initiate. Accepts dashes/spaces ('384-217' or '384217' or '384 217').",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "user_typed_digits": {"type": "string", "description": "The 6 SAS digits the user typed back, e.g. '384217' or '384-217'."}
                },
                "required": ["session_id", "user_typed_digits"]
            }
        }),
    ]
}

fn handle_tools_call(id: &Value, params: &Value) -> Value {
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
        "wire_pair_confirm" => tool_pair_confirm(&args),
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
    let handle = did.strip_prefix("did:wire:").unwrap_or(&did).to_string();
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
    let kind = args
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("missing 'kind'")?;
    let body = args
        .get("body")
        .and_then(Value::as_str)
        .ok_or("missing 'body'")?;

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
    let handle = did.strip_prefix("did:wire:").unwrap_or(&did).to_string();
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

    let event = json!({
        "timestamp": now,
        "from": did,
        "to": format!("did:wire:{peer}"),
        "type": kind,
        "kind": kind_id,
        "body": body_value,
    });
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

fn tool_pair_initiate(args: &Value) -> Result<Value, String> {
    use crate::pair_session::{
        pair_session_open, pair_session_wait_for_sas, store_insert, store_sweep_expired,
    };

    store_sweep_expired();
    let relay_url = resolve_relay_url(args)?;
    let max_wait = args
        .get("max_wait_secs")
        .and_then(Value::as_u64)
        .unwrap_or(8)
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
        .unwrap_or(4)
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

fn tool_pair_confirm(args: &Value) -> Result<Value, String> {
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

    // Confirm phase — borrow the guard, capture abort flag, release before
    // touching the store to avoid double-locking the store mutex on abort.
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

    // Finalize phase — re-acquire the guard for the bootstrap exchange.
    let result = {
        let mut s = arc.lock().map_err(|e| e.to_string())?;
        pair_session_finalize(&mut s, 30).map_err(|e| e.to_string())?
    };
    store_remove(session_id);
    Ok(result)
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
        let resp = handle_request(&req);
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn initialize_advertises_tools_capability() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        let resp = handle_request(&req);
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(resp["result"]["capabilities"]["tools"].is_object());
        assert_eq!(resp["result"]["serverInfo"]["name"], SERVER_NAME);
    }

    #[test]
    fn tools_list_includes_pairing_and_messaging() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let resp = handle_request(&req);
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
        let resp = handle_request(&req);
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
        let resp = handle_request(&req);
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
        let resp = handle_request(&req);
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no such session_id"), "got: {text}");
    }

    #[test]
    fn initialize_advertises_resources_capability() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"});
        let resp = handle_request(&req);
        let caps = &resp["result"]["capabilities"];
        assert!(
            caps["resources"].is_object(),
            "resources capability must be present, got {resp}"
        );
        assert_eq!(
            caps["resources"]["subscribe"], false,
            "subscribe is v0.2.1; v0.2 advertises subscribe=false"
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
        let resp = handle_request(&req);
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
        let resp = handle_request(&req);
        assert_eq!(resp["id"], 7);
        assert!(resp["result"].is_object());
    }

    #[test]
    fn notification_returns_null_no_reply() {
        let req = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let resp = handle_request(&req);
        assert_eq!(resp, Value::Null);
    }
}
