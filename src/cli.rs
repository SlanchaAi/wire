//! `wire` CLI surface.
//!
//! Every subcommand emits human-readable text by default and structured JSON
//! when `--json` is passed. Stable JSON shape is part of the API contract —
//! see `docs/AGENT_INTEGRATION.md`.
//!
//! Subcommand split (security boundary):
//!   - **agent-safe**: `whoami`, `peers`, `verify`, `send`, `tail`
//!   - **human-only**: `init`, `join` — these establish trust via SAS and
//!     must NOT be exposed to MCP / agent automation.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

use crate::{
    agent_card::{build_agent_card, sign_agent_card},
    config,
    signing::{
        fingerprint, generate_keypair, make_key_id, sign_message_v31, verify_message_v31,
    },
    trust::{add_self_to_trust, empty_trust, get_tier},
};

/// Top-level CLI.
#[derive(Parser, Debug)]
#[command(name = "wire", version, about = "Magic-wormhole for AI agents — bilateral signed-message bus", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a keypair, write self-card, and prepare to pair. (HUMAN-ONLY — DO NOT exec from agents.)
    Init {
        /// Short handle for this agent (becomes did:wire:<handle>).
        handle: String,
        /// Optional display name (defaults to capitalized handle).
        #[arg(long)]
        name: Option<String>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Pair with a peer using their SAS code phrase. (HUMAN-ONLY.)
    Join {
        /// SAS code phrase from peer's `wire init` output.
        code_phrase: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print this agent's identity (DID, fingerprint, mailbox slot).
    Whoami {
        #[arg(long)]
        json: bool,
    },
    /// List pinned peers with their tiers and capabilities.
    Peers {
        #[arg(long)]
        json: bool,
    },
    /// Sign and queue an event to a peer.
    Send {
        /// Peer handle (without `did:wire:` prefix).
        peer: String,
        /// Event kind name (`decision`, `claim`, etc.) or numeric kind id.
        kind: String,
        /// Event body — free-form text or `@/path/to/body.json` to load from file.
        body: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Stream signed events from peers.
    Tail {
        /// Optional peer filter; if omitted, tails all peers.
        peer: Option<String>,
        /// Emit JSONL (one event per line).
        #[arg(long)]
        json: bool,
        /// Maximum events to read before exiting (0 = stream until SIGINT).
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
    /// Verify a signed event from a JSON file or stdin (`-`).
    Verify {
        /// Path to event JSON, or `-` for stdin.
        path: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run the MCP (Model Context Protocol) server over stdio.
    /// This is how Claude Desktop / Claude Code / Cursor / etc. expose
    /// `wire_send`, `wire_tail`, etc. as native tools.
    Mcp,
    /// Run a relay server on this host.
    RelayServer {
        /// Bind address (e.g. `127.0.0.1:8770`).
        #[arg(long, default_value = "127.0.0.1:8770")]
        bind: String,
    },
    /// Allocate a slot on a relay; bind it to this agent's identity.
    BindRelay {
        /// Relay base URL, e.g. `http://127.0.0.1:8770`.
        url: String,
        #[arg(long)]
        json: bool,
    },
    /// Manually pin a peer's relay slot. (Replaces SAS pairing for v0.1 bootstrap;
    /// real `wire join` lands in the SPAKE2 iter.)
    AddPeerSlot {
        /// Peer handle (becomes did:wire:<handle>).
        handle: String,
        /// Peer's relay base URL.
        url: String,
        /// Peer's slot id.
        slot_id: String,
        /// Slot bearer token (shared between paired peers in v0.1).
        slot_token: String,
        #[arg(long)]
        json: bool,
    },
    /// Drain outbox JSONL files to peers' relay slots.
    Push {
        /// Optional peer filter; default = all peers with outbox entries.
        peer: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Pull events from our relay slot, verify, write to inbox.
    Pull {
        #[arg(long)]
        json: bool,
    },
    /// Pin a peer's signed agent-card from a file. (Manual out-of-band pairing
    /// — replaces SAS for v0.1 bootstrap; real `wire join` lands with SPAKE2.)
    Pin {
        /// Path to peer's signed agent-card JSON.
        card_file: String,
        #[arg(long)]
        json: bool,
    },
}

/// Entry point — parse and dispatch.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { handle, name, json } => cmd_init(&handle, name.as_deref(), json),
        Command::Join { code_phrase, json } => cmd_join(&code_phrase, json),
        Command::Whoami { json } => cmd_whoami(json),
        Command::Peers { json } => cmd_peers(json),
        Command::Send { peer, kind, body, json } => cmd_send(&peer, &kind, &body, json),
        Command::Tail { peer, json, limit } => cmd_tail(peer.as_deref(), json, limit),
        Command::Verify { path, json } => cmd_verify(&path, json),
        Command::Mcp => cmd_mcp(),
        Command::RelayServer { bind } => cmd_relay_server(&bind),
        Command::BindRelay { url, json } => cmd_bind_relay(&url, json),
        Command::AddPeerSlot { handle, url, slot_id, slot_token, json } => {
            cmd_add_peer_slot(&handle, &url, &slot_id, &slot_token, json)
        }
        Command::Push { peer, json } => cmd_push(peer.as_deref(), json),
        Command::Pull { json } => cmd_pull(json),
        Command::Pin { card_file, json } => cmd_pin(&card_file, json),
    }
}

// ---------- init ----------

fn cmd_init(handle: &str, name: Option<&str>, as_json: bool) -> Result<()> {
    if !handle.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        bail!("handle must be ASCII alphanumeric / '-' / '_' (got {handle:?})");
    }
    if config::is_initialized()? {
        bail!(
            "already initialized — config exists at {:?}. Delete it first if you want a fresh identity.",
            config::config_dir()?
        );
    }

    config::ensure_dirs()?;
    let (sk_seed, pk_bytes) = generate_keypair();
    config::write_private_key(&sk_seed)?;

    let card = build_agent_card(handle, &pk_bytes, name, None, None);
    let signed = sign_agent_card(&card, &sk_seed);
    config::write_agent_card(&signed)?;

    let mut trust = empty_trust();
    add_self_to_trust(&mut trust, handle, &pk_bytes);
    config::write_trust(&trust)?;

    let fp = fingerprint(&pk_bytes);
    let key_id = make_key_id(handle, &pk_bytes);

    // Note: real SAS code phrase generation (PGP-word-list style) lands in iter 5
    // alongside the SPAKE2 handshake. For now we emit the deterministic key_id
    // so an early adopter has a stable reference to read aloud.
    let placeholder_phrase = format!("{handle}-{fp}");

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "did": format!("did:wire:{handle}"),
                "fingerprint": fp,
                "key_id": key_id,
                "code_phrase_v0_placeholder": placeholder_phrase,
                "config_dir": config::config_dir()?.to_string_lossy(),
                "next_step": "ask your peer to run: wire join <their-side-of-the-handshake> (real PAKE in iter 5+)",
            }))?
        );
    } else {
        println!("generated did:wire:{handle} (ed25519:{key_id})");
        println!("config written to {}", config::config_dir()?.to_string_lossy());
        println!();
        println!("placeholder code phrase (real PAKE-derived phrase lands in iter 5):");
        println!("    {placeholder_phrase}");
        println!();
        println!("next step: have your peer run `wire join <code-phrase>` once relay + PAKE are wired in.");
    }
    Ok(())
}

// ---------- join (stub) ----------

fn cmd_join(_code_phrase: &str, as_json: bool) -> Result<()> {
    let msg = "wire join lands in iter 5 — needs SPAKE2 handshake + relay client. See docs/AGENT_INTEGRATION.md and BACKLOG.md.";
    if as_json {
        println!("{}", serde_json::to_string(&json!({"error": "not_yet_implemented", "iter": 5, "detail": msg}))?);
    } else {
        eprintln!("{msg}");
    }
    std::process::exit(2);
}

// ---------- whoami ----------

fn cmd_whoami(as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let card = config::read_agent_card()?;
    let did = card.get("did").and_then(Value::as_str).unwrap_or("").to_string();
    let handle = did.strip_prefix("did:wire:").unwrap_or(&did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;
    let fp = fingerprint(&pk_bytes);
    let key_id = make_key_id(&handle, &pk_bytes);
    let capabilities = card
        .get("capabilities")
        .cloned()
        .unwrap_or_else(|| json!(["wire/v3.1"]));

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "did": did,
                "handle": handle,
                "fingerprint": fp,
                "key_id": key_id,
                "public_key_b64": pk_b64,
                "capabilities": capabilities,
                "config_dir": config::config_dir()?.to_string_lossy(),
            }))?
        );
    } else {
        println!("{did} (ed25519:{key_id})");
        println!("fingerprint: {fp}");
        println!("capabilities: {capabilities}");
    }
    Ok(())
}

// ---------- peers ----------

fn cmd_peers(as_json: bool) -> Result<()> {
    let trust = config::read_trust()?;
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
            continue; // skip self-attestation
        }
        let tier = get_tier(&trust, handle);
        let capabilities = agent
            .get("card")
            .and_then(|c| c.get("capabilities"))
            .cloned()
            .unwrap_or_else(|| json!([]));
        peers.push(json!({
            "handle": handle,
            "did": did,
            "tier": tier,
            "capabilities": capabilities,
        }));
    }

    if as_json {
        println!("{}", serde_json::to_string(&peers)?);
    } else if peers.is_empty() {
        println!("no peers pinned (run `wire join <code>` to pair)");
    } else {
        for p in &peers {
            println!(
                "{:<20} {:<10} {}",
                p["handle"].as_str().unwrap_or(""),
                p["tier"].as_str().unwrap_or(""),
                p["did"].as_str().unwrap_or(""),
            );
        }
    }
    Ok(())
}

// ---------- send ----------

fn cmd_send(peer: &str, kind: &str, body_arg: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let sk_seed = config::read_private_key()?;
    let card = config::read_agent_card()?;
    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = did.strip_prefix("did:wire:").unwrap_or(did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;

    // Body: literal string, or @/path/to/body.json
    let body_value: Value = if let Some(path) = body_arg.strip_prefix('@') {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading body file {path:?}"))?;
        serde_json::from_str(&raw).unwrap_or(Value::String(raw))
    } else {
        Value::String(body_arg.to_string())
    };

    let kind_id = parse_kind(kind)?;

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
    let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &handle)?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    // For now we append to outbox JSONL and rely on a future daemon to push
    // to the relay. That's the file-system contract from AGENT_INTEGRATION.md.
    config::ensure_dirs()?;
    let outbox = config::outbox_dir()?.join(format!("{peer}.jsonl"));
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&outbox)
        .with_context(|| format!("opening outbox {outbox:?}"))?;
    let mut line = serde_json::to_vec(&signed)?;
    line.push(b'\n');
    f.write_all(&line)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "event_id": event_id,
                "status": "queued",
                "peer": peer,
                "outbox": outbox.to_string_lossy(),
            }))?
        );
    } else {
        println!("queued event {event_id} → {peer} (outbox: {})", outbox.display());
    }
    Ok(())
}

fn parse_kind(s: &str) -> Result<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }
    for (id, name) in crate::signing::kinds() {
        if *name == s {
            return Ok(*id);
        }
    }
    // Unknown name — default to kind 1 (decision) for v0.1.
    Ok(1)
}

// ---------- tail ----------

fn cmd_tail(peer: Option<&str>, as_json: bool, limit: usize) -> Result<()> {
    let inbox = config::inbox_dir()?;
    if !inbox.exists() {
        if !as_json {
            eprintln!("no inbox yet — daemon hasn't run, or no events received");
        }
        return Ok(());
    }
    let trust = config::read_trust()?;
    let mut count = 0usize;

    let entries: Vec<_> = std::fs::read_dir(&inbox)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "jsonl").unwrap_or(false)
                && match peer {
                    Some(want) => {
                        p.file_stem().and_then(|s| s.to_str()) == Some(want)
                    }
                    None => true,
                }
        })
        .collect();

    for path in entries {
        let body = std::fs::read_to_string(&path)?;
        for line in body.lines() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let verified = verify_message_v31(&event, &trust).is_ok();
            if as_json {
                let mut event_with_meta = event.clone();
                if let Some(obj) = event_with_meta.as_object_mut() {
                    obj.insert("verified".into(), json!(verified));
                }
                println!("{}", serde_json::to_string(&event_with_meta)?);
            } else {
                let ts = event.get("timestamp").and_then(Value::as_str).unwrap_or("?");
                let from = event.get("from").and_then(Value::as_str).unwrap_or("?");
                let kind = event.get("kind").and_then(Value::as_u64).unwrap_or(0);
                let kind_name = event.get("type").and_then(Value::as_str).unwrap_or("?");
                let summary = event
                    .get("body")
                    .map(|b| match b {
                        Value::String(s) => s.clone(),
                        _ => b.to_string(),
                    })
                    .unwrap_or_default();
                let mark = if verified { "✓" } else { "✗" };
                println!("[{ts} {from} kind={kind} {kind_name}] {summary} | sig {mark}");
            }
            count += 1;
            if limit > 0 && count >= limit {
                return Ok(());
            }
        }
    }
    Ok(())
}

// ---------- verify ----------

fn cmd_verify(path: &str, as_json: bool) -> Result<()> {
    let body = if path == "-" {
        let mut buf = String::new();
        use std::io::Read;
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
    };
    let event: Value = serde_json::from_str(&body)?;
    let trust = config::read_trust()?;
    match verify_message_v31(&event, &trust) {
        Ok(()) => {
            if as_json {
                println!("{}", serde_json::to_string(&json!({"verified": true}))?);
            } else {
                println!("verified ✓");
            }
            Ok(())
        }
        Err(e) => {
            let reason = e.to_string();
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({"verified": false, "reason": reason}))?
                );
            } else {
                eprintln!("FAILED: {reason}");
            }
            std::process::exit(1);
        }
    }
}

// ---------- mcp / relay-server stubs ----------

fn cmd_mcp() -> Result<()> {
    crate::mcp::run()
}

fn cmd_relay_server(bind: &str) -> Result<()> {
    // Default state dir for the relay process: $WIRE_HOME/state/wire-relay
    // (or `dirs::state_dir()/wire-relay`). Distinct from the CLI's state dir
    // so a single user can run both client and server on one machine.
    let state_dir = if let Ok(home) = std::env::var("WIRE_HOME") {
        std::path::PathBuf::from(home).join("state").join("wire-relay")
    } else {
        dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .ok_or_else(|| anyhow::anyhow!("could not resolve XDG_STATE_HOME — set WIRE_HOME"))?
            .join("wire-relay")
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(crate::relay_server::serve(bind, state_dir))
}

// ---------- bind-relay ----------

fn cmd_bind_relay(url: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let card = config::read_agent_card()?;
    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = did.strip_prefix("did:wire:").unwrap_or(did).to_string();

    let client = crate::relay_client::RelayClient::new(url);
    if !client.healthz().unwrap_or(false) {
        bail!("relay healthz failed at {url} — is the server running?");
    }
    let alloc = client.allocate_slot(Some(&handle))?;
    let mut state = config::read_relay_state()?;
    state["self"] = json!({
        "relay_url": url,
        "slot_id": alloc.slot_id,
        "slot_token": alloc.slot_token,
    });
    config::write_relay_state(&state)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "relay_url": url,
                "slot_id": alloc.slot_id,
                "slot_token_present": true,
            }))?
        );
    } else {
        println!("bound to relay {url}");
        println!("slot_id: {}", alloc.slot_id);
        println!("(slot_token written to {} mode 0600)", config::relay_state_path()?.display());
    }
    Ok(())
}

// ---------- add-peer-slot ----------

fn cmd_add_peer_slot(
    handle: &str,
    url: &str,
    slot_id: &str,
    slot_token: &str,
    as_json: bool,
) -> Result<()> {
    let mut state = config::read_relay_state()?;
    let peers = state["peers"]
        .as_object_mut()
        .ok_or_else(|| anyhow!("relay state missing 'peers' object"))?;
    peers.insert(
        handle.to_string(),
        json!({
            "relay_url": url,
            "slot_id": slot_id,
            "slot_token": slot_token,
        }),
    );
    config::write_relay_state(&state)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle,
                "relay_url": url,
                "slot_id": slot_id,
                "added": true,
            }))?
        );
    } else {
        println!("pinned peer slot for {handle} at {url} ({slot_id})");
    }
    Ok(())
}

// ---------- push ----------

fn cmd_push(peer_filter: Option<&str>, as_json: bool) -> Result<()> {
    let state = config::read_relay_state()?;
    let peers = state["peers"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    if peers.is_empty() {
        bail!("no peer slots pinned — run `wire add-peer-slot <handle> <url> <slot_id> <token>` first");
    }
    let outbox_dir = config::outbox_dir()?;
    if !outbox_dir.exists() {
        if as_json {
            println!("{}", serde_json::to_string(&json!({"pushed": [], "skipped": []}))?);
        } else {
            println!("outbox empty — nothing to push");
        }
        return Ok(());
    }

    let mut pushed = Vec::new();
    let mut skipped = Vec::new();

    for (peer_handle, slot_info) in peers.iter() {
        if let Some(want) = peer_filter {
            if peer_handle != want {
                continue;
            }
        }
        let outbox = outbox_dir.join(format!("{peer_handle}.jsonl"));
        if !outbox.exists() {
            continue;
        }
        let url = slot_info["relay_url"].as_str().ok_or_else(|| anyhow!("peer {peer_handle} missing relay_url"))?;
        let slot_id = slot_info["slot_id"].as_str().ok_or_else(|| anyhow!("peer {peer_handle} missing slot_id"))?;
        let slot_token = slot_info["slot_token"].as_str().ok_or_else(|| anyhow!("peer {peer_handle} missing slot_token"))?;
        let client = crate::relay_client::RelayClient::new(url);
        let body = std::fs::read_to_string(&outbox)?;
        for line in body.lines() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let event_id = event.get("event_id").and_then(Value::as_str).unwrap_or("").to_string();
            match client.post_event(slot_id, slot_token, &event) {
                Ok(resp) => {
                    if resp.status == "duplicate" {
                        skipped.push(json!({"peer": peer_handle, "event_id": event_id, "reason": "duplicate"}));
                    } else {
                        pushed.push(json!({"peer": peer_handle, "event_id": event_id}));
                    }
                }
                Err(e) => {
                    skipped.push(json!({"peer": peer_handle, "event_id": event_id, "reason": e.to_string()}));
                }
            }
        }
    }

    if as_json {
        println!("{}", serde_json::to_string(&json!({"pushed": pushed, "skipped": skipped}))?);
    } else {
        println!("pushed {} event(s); skipped {} ({})",
            pushed.len(),
            skipped.len(),
            if skipped.is_empty() { "none" } else { "see --json for detail" });
    }
    Ok(())
}

// ---------- pull ----------

fn cmd_pull(as_json: bool) -> Result<()> {
    let state = config::read_relay_state()?;
    let self_state = state.get("self").cloned().unwrap_or(Value::Null);
    if self_state.is_null() {
        bail!("self slot not bound — run `wire bind-relay <url>` first");
    }
    let url = self_state["relay_url"].as_str().ok_or_else(|| anyhow!("self.relay_url missing"))?;
    let slot_id = self_state["slot_id"].as_str().ok_or_else(|| anyhow!("self.slot_id missing"))?;
    let slot_token = self_state["slot_token"].as_str().ok_or_else(|| anyhow!("self.slot_token missing"))?;
    let last_event_id = self_state.get("last_pulled_event_id").and_then(Value::as_str).map(str::to_string);

    let client = crate::relay_client::RelayClient::new(url);
    let events = client.list_events(slot_id, slot_token, last_event_id.as_deref(), Some(1000))?;

    let trust = config::read_trust()?;
    let inbox_dir = config::inbox_dir()?;
    config::ensure_dirs()?;

    let mut written = Vec::new();
    let mut rejected = Vec::new();
    let mut last_seen: Option<String> = last_event_id.clone();

    for event in &events {
        let event_id = event.get("event_id").and_then(Value::as_str).unwrap_or("").to_string();
        last_seen = Some(event_id.clone());
        match crate::signing::verify_message_v31(event, &trust) {
            Ok(()) => {
                let from = event
                    .get("from")
                    .and_then(Value::as_str)
                    .map(|s| s.strip_prefix("did:wire:").unwrap_or(s).to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let path = inbox_dir.join(format!("{from}.jsonl"));
                use std::io::Write;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
                let mut line = serde_json::to_vec(event)?;
                line.push(b'\n');
                f.write_all(&line)?;
                written.push(json!({"event_id": event_id, "from": from}));
            }
            Err(e) => {
                rejected.push(json!({"event_id": event_id, "reason": e.to_string()}));
            }
        }
    }

    // Persist cursor.
    if let Some(eid) = last_seen {
        let mut state = state.clone();
        if let Some(self_obj) = state.get_mut("self").and_then(Value::as_object_mut) {
            self_obj.insert("last_pulled_event_id".into(), Value::String(eid));
        }
        config::write_relay_state(&state)?;
    }

    if as_json {
        println!("{}", serde_json::to_string(&json!({
            "written": written,
            "rejected": rejected,
            "total_seen": events.len(),
        }))?);
    } else {
        println!("pulled {} event(s); wrote {}; rejected {} (bad signature)",
            events.len(), written.len(), rejected.len());
    }
    Ok(())
}

// ---------- pin (manual out-of-band peer pairing) ----------

fn cmd_pin(card_file: &str, as_json: bool) -> Result<()> {
    let body = std::fs::read_to_string(card_file).with_context(|| format!("reading {card_file}"))?;
    let card: Value = serde_json::from_str(&body).with_context(|| format!("parsing {card_file}"))?;
    crate::agent_card::verify_agent_card(&card)
        .map_err(|e| anyhow!("peer card signature invalid: {e}"))?;

    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &card, Some("VERIFIED"));

    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = did.strip_prefix("did:wire:").unwrap_or(did).to_string();
    config::write_trust(&trust)?;

    if as_json {
        println!("{}", serde_json::to_string(&json!({
            "handle": handle,
            "did": did,
            "tier": "VERIFIED",
            "pinned": true,
        }))?);
    } else {
        println!("pinned {handle} ({did}) at tier VERIFIED");
    }
    Ok(())
}

// Integration tests for the CLI live in `tests/cli.rs` (cargo's tests/ dir).
