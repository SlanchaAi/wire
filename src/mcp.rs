//! MCP (Model Context Protocol) server over stdio.
//!
//! Spec: https://modelcontextprotocol.io/specification/2025-06-18
//!
//! Wire protocol: JSON-RPC 2.0, one message per line on stdin and stdout.
//! stderr is reserved for logs (clients display them as server-side diagnostics).
//!
//! Tools exposed (agent-safe only — see `docs/AGENT_INTEGRATION.md` for the
//! pairing security boundary):
//!   - `wire_whoami`     — read self DID + fingerprint + capabilities
//!   - `wire_peers`      — list pinned peers + tiers
//!   - `wire_send`       — sign + queue an event to a peer
//!   - `wire_tail`       — read recent signed events from inbox
//!   - `wire_verify`     — verify a signed event JSON
//!
//! NOT exposed (deliberately, this is a security feature):
//!   - `wire_init`       — pairing's keypair generation requires a human
//!   - `wire_join`       — SAS confirmation requires an aloud-readout the
//!                         operator vouches for
//!
//! An agent that wants to add a new peer asks the human; the human runs the
//! CLI subcommand. This is the trust model wire is built to provide.

use anyhow::Result;
use serde_json::{json, Value};
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
        "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
        other => error_response(&id, -32601, &format!("method not found: {other}")),
    }
}

fn handle_initialize(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": false}
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
            "instructions": "wire — magic-wormhole for AI agents. Pairing (wire init / wire join) is human-only and not exposed via MCP. Use wire_send / wire_tail / wire_peers / wire_verify / wire_whoami. See docs/AGENT_INTEGRATION.md."
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
            "description": "Sign and queue an event to a peer. Returns event_id (SHA-256 of canonical body — content-addressed, so identical bodies produce identical event_ids and the daemon dedupes). Body may be plain text or a JSON-encoded structured value.",
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
    ]
}

fn handle_tools_call(id: &Value, params: &Value) -> Value {
    let name = match params.get("name").and_then(Value::as_str) {
        Some(n) => n,
        None => return error_response(id, -32602, "missing tool name"),
    };
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

    let result = match name {
        "wire_whoami" => tool_whoami(),
        "wire_peers" => tool_peers(),
        "wire_send" => tool_send(&args),
        "wire_tail" => tool_tail(&args),
        "wire_verify" => tool_verify(&args),
        // Explicit refusal — these MUST NOT be agent-callable.
        "wire_init" | "wire_join" => Err(format!(
            "{name} is not exposed via MCP. Pairing requires human-in-loop SAS confirmation. \
             Ask the operator to run `wire {}` from a terminal.",
            name.strip_prefix("wire_").unwrap_or(name)
        )),
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
    let did = card.get("did").and_then(Value::as_str).unwrap_or("").to_string();
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
        let did = agent.get("did").and_then(Value::as_str).unwrap_or("").to_string();
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

    let peer = args.get("peer").and_then(Value::as_str).ok_or("missing 'peer'")?;
    let kind = args.get("kind").and_then(Value::as_str).ok_or("missing 'kind'")?;
    let body = args.get("body").and_then(Value::as_str).ok_or("missing 'body'")?;

    if !config::is_initialized().map_err(|e| e.to_string())? {
        return Err("not initialized — operator must run `wire init <handle>` first".into());
    }
    let sk_seed = config::read_private_key().map_err(|e| e.to_string())?;
    let card = config::read_agent_card().map_err(|e| e.to_string())?;
    let did = card.get("did").and_then(Value::as_str).unwrap_or("").to_string();
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
    let body_value: Value = serde_json::from_str(body).unwrap_or_else(|_| Value::String(body.to_string()));
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
    let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &handle).map_err(|e| e.to_string())?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    config::ensure_dirs().map_err(|e| e.to_string())?;
    let outbox = config::outbox_dir().map_err(|e| e.to_string())?.join(format!("{peer}.jsonl"));
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&outbox)
        .map_err(|e| format!("opening outbox: {e}"))?;
    let mut line = serde_json::to_vec(&signed).map_err(|e| e.to_string())?;
    line.push(b'\n');
    f.write_all(&line).map_err(|e| e.to_string())?;

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

    let event_str = args.get("event").and_then(Value::as_str).ok_or("missing 'event'")?;
    let event: Value = serde_json::from_str(event_str).map_err(|e| format!("invalid event JSON: {e}"))?;
    let trust = config::read_trust().map_err(|e| e.to_string())?;
    match verify_message_v31(&event, &trust) {
        Ok(()) => Ok(json!({"verified": true})),
        Err(e) => Ok(json!({"verified": false, "reason": e.to_string()})),
    }
}

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
    fn tools_list_does_not_include_init_or_join() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let resp = handle_request(&req);
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        for forbidden in ["wire_init", "wire_join"] {
            assert!(!names.contains(&forbidden), "{forbidden} should NOT be exposed via MCP");
        }
        for required in ["wire_whoami", "wire_peers", "wire_send", "wire_tail", "wire_verify"] {
            assert!(names.contains(&required), "missing required tool {required}");
        }
    }

    #[test]
    fn tools_call_init_or_join_returns_security_refusal() {
        for forbidden in ["wire_init", "wire_join"] {
            let req = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": forbidden, "arguments": {}}
            });
            let resp = handle_request(&req);
            assert_eq!(resp["result"]["isError"], true, "{forbidden} should error");
            let text = resp["result"]["content"][0]["text"].as_str().unwrap();
            assert!(
                text.contains("not exposed via MCP") && text.contains("human-in-loop"),
                "unexpected refusal text for {forbidden}: {text}"
            );
        }
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
