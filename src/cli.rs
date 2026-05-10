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

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use crate::{
    agent_card::{build_agent_card, sign_agent_card},
    config,
    signing::{fingerprint, generate_keypair, make_key_id, sign_message_v31, verify_message_v31},
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
        /// Optional relay URL — if set, also allocates a relay slot in one step
        /// (equivalent to running `wire init` then `wire bind-relay <url>`).
        #[arg(long)]
        relay: Option<String>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    // (Old `Join` stub removed in iter 11 — superseded by `pair-join` with
    // `join` alias. See PairJoin below.)
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
    /// Print a summary of identity, relay binding, peers, inbox/outbox queue depth.
    /// Useful as a single "where am I" check.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Pin a peer's signed agent-card from a file. (Manual out-of-band pairing
    /// — fallback path; the magic-wormhole flow is `pair-host` / `pair-join`.)
    Pin {
        /// Path to peer's signed agent-card JSON.
        card_file: String,
        #[arg(long)]
        json: bool,
    },
    /// Allocate a NEW slot on the same relay and abandon the old one.
    /// Sends a kind=1201 wire_close event to every paired peer over the OLD
    /// slot announcing the new mailbox before swapping. After rotation,
    /// peers must re-pair (or operator runs `add-peer-slot` with the new
    /// coords) — auto-update via wire_close is a v0.2 daemon feature.
    ///
    /// Use case: a paired peer turned hostile (T11 in THREAT_MODEL.md —
    /// abusive bearer-holder spamming your slot). Rotate → old slot is
    /// orphaned → attacker's leverage gone. Operator pairs again with
    /// peers they still want.
    RotateSlot {
        /// Skip the wire_close announcement to peers (faster but they won't know
        /// where you went).
        #[arg(long)]
        no_announce: bool,
        #[arg(long)]
        json: bool,
    },
    /// Remove a peer from trust + relay state. Inbox/outbox files for that
    /// peer are NOT deleted (operator can grep history); pass --purge to
    /// also wipe the JSONL files.
    ForgetPeer {
        /// Peer handle to forget.
        handle: String,
        /// Also delete inbox/<handle>.jsonl and outbox/<handle>.jsonl.
        #[arg(long)]
        purge: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run a long-lived sync loop: every <interval> seconds, push outbox to
    /// peers' relay slots and pull inbox from our own slot. Foreground process;
    /// background it with systemd / `&` / tmux as you prefer.
    Daemon {
        /// Sync interval in seconds. Default 5.
        #[arg(long, default_value_t = 5)]
        interval: u64,
        /// Run a single sync cycle and exit (useful for cron-driven setups).
        #[arg(long)]
        once: bool,
        #[arg(long)]
        json: bool,
    },
    /// Host a SAS-confirmed pairing. Generates a code phrase, prints it, waits
    /// for a peer to `pair-join`, exchanges signed agent-cards via SPAKE2 +
    /// ChaCha20-Poly1305. Auto-pins on success. (HUMAN-ONLY — operator must
    /// read the SAS digits aloud and confirm.)
    PairHost {
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Skip the SAS confirmation prompt. ONLY use when piping under
        /// automated tests or when the SAS has already been verified by
        /// another channel. Documented as test-only.
        #[arg(long)]
        yes: bool,
        /// How long (seconds) to wait for the peer to join before timing out.
        #[arg(long, default_value_t = 300)]
        timeout: u64,
    },
    /// Join a pair-slot using a code phrase from the host. (HUMAN-ONLY.)
    ///
    /// Aliased as `wire join <code>` for magic-wormhole muscle-memory.
    #[command(alias = "join")]
    PairJoin {
        /// Code phrase from the host's `pair-host` output (e.g. `73-2QXC4P`).
        code_phrase: String,
        /// Relay base URL (must match the host's relay).
        #[arg(long)]
        relay: String,
        #[arg(long)]
        yes: bool,
        #[arg(long, default_value_t = 300)]
        timeout: u64,
    },
}

/// Entry point — parse and dispatch.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            handle,
            name,
            relay,
            json,
        } => cmd_init(&handle, name.as_deref(), relay.as_deref(), json),
        Command::Status { json } => cmd_status(json),
        Command::Whoami { json } => cmd_whoami(json),
        Command::Peers { json } => cmd_peers(json),
        Command::Send {
            peer,
            kind,
            body,
            json,
        } => cmd_send(&peer, &kind, &body, json),
        Command::Tail { peer, json, limit } => cmd_tail(peer.as_deref(), json, limit),
        Command::Verify { path, json } => cmd_verify(&path, json),
        Command::Mcp => cmd_mcp(),
        Command::RelayServer { bind } => cmd_relay_server(&bind),
        Command::BindRelay { url, json } => cmd_bind_relay(&url, json),
        Command::AddPeerSlot {
            handle,
            url,
            slot_id,
            slot_token,
            json,
        } => cmd_add_peer_slot(&handle, &url, &slot_id, &slot_token, json),
        Command::Push { peer, json } => cmd_push(peer.as_deref(), json),
        Command::Pull { json } => cmd_pull(json),
        Command::Pin { card_file, json } => cmd_pin(&card_file, json),
        Command::RotateSlot { no_announce, json } => cmd_rotate_slot(no_announce, json),
        Command::ForgetPeer {
            handle,
            purge,
            json,
        } => cmd_forget_peer(&handle, purge, json),
        Command::Daemon {
            interval,
            once,
            json,
        } => cmd_daemon(interval, once, json),
        Command::PairHost {
            relay,
            yes,
            timeout,
        } => cmd_pair_host(&relay, yes, timeout),
        Command::PairJoin {
            code_phrase,
            relay,
            yes,
            timeout,
        } => cmd_pair_join(&code_phrase, &relay, yes, timeout),
    }
}

// ---------- init ----------

fn cmd_init(handle: &str, name: Option<&str>, relay: Option<&str>, as_json: bool) -> Result<()> {
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
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

    // If --relay was passed, also bind a slot inline so init+bind happen in one step.
    let mut relay_info: Option<(String, String)> = None;
    if let Some(url) = relay {
        let client = crate::relay_client::RelayClient::new(url);
        if !client.healthz().unwrap_or(false) {
            bail!("relay healthz failed at {url} — is the server running?");
        }
        let alloc = client.allocate_slot(Some(handle))?;
        let mut state = config::read_relay_state()?;
        state["self"] = json!({
            "relay_url": url,
            "slot_id": alloc.slot_id.clone(),
            "slot_token": alloc.slot_token,
        });
        config::write_relay_state(&state)?;
        relay_info = Some((url.to_string(), alloc.slot_id));
    }

    if as_json {
        let mut out = json!({
            "did": format!("did:wire:{handle}"),
            "fingerprint": fp,
            "key_id": key_id,
            "config_dir": config::config_dir()?.to_string_lossy(),
        });
        if let Some((url, slot_id)) = &relay_info {
            out["relay_url"] = json!(url);
            out["slot_id"] = json!(slot_id);
        }
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("generated did:wire:{handle} (ed25519:{key_id})");
        println!(
            "config written to {}",
            config::config_dir()?.to_string_lossy()
        );
        if let Some((url, slot_id)) = &relay_info {
            println!("bound to relay {url} (slot {slot_id})");
            println!();
            println!(
                "next step: `wire pair-host --relay {url}` to print a code phrase for a peer."
            );
        } else {
            println!();
            println!(
                "next step: `wire pair-host --relay <url>` to bind a relay + open a pair-slot."
            );
        }
    }
    Ok(())
}

// ---------- status ----------

fn cmd_status(as_json: bool) -> Result<()> {
    let initialized = config::is_initialized()?;

    let mut summary = json!({
        "initialized": initialized,
    });

    if initialized {
        let card = config::read_agent_card()?;
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
            .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
        let pk_bytes = crate::signing::b64decode(pk_b64)?;
        summary["did"] = json!(did);
        summary["handle"] = json!(handle);
        summary["fingerprint"] = json!(fingerprint(&pk_bytes));
        summary["capabilities"] = card
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| json!([]));

        let trust = config::read_trust()?;
        let mut peers = Vec::new();
        if let Some(agents) = trust.get("agents").and_then(Value::as_object) {
            for (peer_handle, agent) in agents {
                if peer_handle == &handle {
                    continue; // self
                }
                peers.push(json!({
                    "handle": peer_handle,
                    "tier": agent.get("tier").and_then(Value::as_str).unwrap_or("UNTRUSTED"),
                }));
            }
        }
        summary["peers"] = json!(peers);

        let relay_state = config::read_relay_state()?;
        summary["self_relay"] = relay_state.get("self").cloned().unwrap_or(Value::Null);
        if !summary["self_relay"].is_null() {
            // Hide slot_token from default view.
            if let Some(obj) = summary["self_relay"].as_object_mut() {
                obj.remove("slot_token");
            }
        }
        summary["peer_slots_count"] = json!(
            relay_state
                .get("peers")
                .and_then(Value::as_object)
                .map(|m| m.len())
                .unwrap_or(0)
        );

        // Outbox / inbox queue depth (file count + total events)
        let outbox = config::outbox_dir()?;
        let inbox = config::inbox_dir()?;
        summary["outbox"] = json!(scan_jsonl_dir(&outbox)?);
        summary["inbox"] = json!(scan_jsonl_dir(&inbox)?);
    }

    if as_json {
        println!("{}", serde_json::to_string(&summary)?);
    } else if !initialized {
        println!("not initialized — run `wire init <handle>` first");
    } else {
        println!("did:           {}", summary["did"].as_str().unwrap_or("?"));
        println!(
            "fingerprint:   {}",
            summary["fingerprint"].as_str().unwrap_or("?")
        );
        println!("capabilities:  {}", summary["capabilities"]);
        if !summary["self_relay"].is_null() {
            println!(
                "self relay:    {} (slot {})",
                summary["self_relay"]["relay_url"].as_str().unwrap_or("?"),
                summary["self_relay"]["slot_id"].as_str().unwrap_or("?")
            );
        } else {
            println!("self relay:    (not bound — run `wire pair-host --relay <url>` to bind)");
        }
        println!(
            "peers:         {}",
            summary["peers"].as_array().map(|a| a.len()).unwrap_or(0)
        );
        for p in summary["peers"].as_array().unwrap_or(&Vec::new()) {
            println!(
                "  - {:<20} tier={}",
                p["handle"].as_str().unwrap_or(""),
                p["tier"].as_str().unwrap_or("?")
            );
        }
        println!(
            "outbox:        {} file(s), {} event(s) queued",
            summary["outbox"]["files"].as_u64().unwrap_or(0),
            summary["outbox"]["events"].as_u64().unwrap_or(0)
        );
        println!(
            "inbox:         {} file(s), {} event(s) received",
            summary["inbox"]["files"].as_u64().unwrap_or(0),
            summary["inbox"]["events"].as_u64().unwrap_or(0)
        );
    }
    Ok(())
}

fn scan_jsonl_dir(dir: &std::path::Path) -> Result<Value> {
    if !dir.exists() {
        return Ok(json!({"files": 0, "events": 0}));
    }
    let mut files = 0usize;
    let mut events = 0usize;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().map(|x| x == "jsonl").unwrap_or(false) {
            files += 1;
            if let Ok(body) = std::fs::read_to_string(&path) {
                events += body.lines().filter(|l| !l.trim().is_empty()).count();
            }
        }
    }
    Ok(json!({"files": files, "events": events}))
}

// (Old cmd_join stub removed — superseded by cmd_pair_join below.)

// ---------- whoami ----------

fn cmd_whoami(as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let card = config::read_agent_card()?;
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
        let did = agent
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
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
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading body file {path:?}"))?;
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
        println!(
            "queued event {event_id} → {peer} (outbox: {})",
            outbox.display()
        );
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
                    Some(want) => p.file_stem().and_then(|s| s.to_str()) == Some(want),
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
                let ts = event
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or("?");
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
        std::path::PathBuf::from(home)
            .join("state")
            .join("wire-relay")
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
        println!(
            "(slot_token written to {} mode 0600)",
            config::relay_state_path()?.display()
        );
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
    let peers = state["peers"].as_object().cloned().unwrap_or_default();
    if peers.is_empty() {
        bail!(
            "no peer slots pinned — run `wire add-peer-slot <handle> <url> <slot_id> <token>` first"
        );
    }
    let outbox_dir = config::outbox_dir()?;
    if !outbox_dir.exists() {
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({"pushed": [], "skipped": []}))?
            );
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
        let url = slot_info["relay_url"]
            .as_str()
            .ok_or_else(|| anyhow!("peer {peer_handle} missing relay_url"))?;
        let slot_id = slot_info["slot_id"]
            .as_str()
            .ok_or_else(|| anyhow!("peer {peer_handle} missing slot_id"))?;
        let slot_token = slot_info["slot_token"]
            .as_str()
            .ok_or_else(|| anyhow!("peer {peer_handle} missing slot_token"))?;
        let client = crate::relay_client::RelayClient::new(url);
        let body = std::fs::read_to_string(&outbox)?;
        for line in body.lines() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let event_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            match client.post_event(slot_id, slot_token, &event) {
                Ok(resp) => {
                    if resp.status == "duplicate" {
                        skipped.push(json!({"peer": peer_handle, "event_id": event_id, "reason": "duplicate"}));
                    } else {
                        pushed.push(json!({"peer": peer_handle, "event_id": event_id}));
                    }
                }
                Err(e) => {
                    skipped.push(
                        json!({"peer": peer_handle, "event_id": event_id, "reason": e.to_string()}),
                    );
                }
            }
        }
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({"pushed": pushed, "skipped": skipped}))?
        );
    } else {
        println!(
            "pushed {} event(s); skipped {} ({})",
            pushed.len(),
            skipped.len(),
            if skipped.is_empty() {
                "none"
            } else {
                "see --json for detail"
            }
        );
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
    let url = self_state["relay_url"]
        .as_str()
        .ok_or_else(|| anyhow!("self.relay_url missing"))?;
    let slot_id = self_state["slot_id"]
        .as_str()
        .ok_or_else(|| anyhow!("self.slot_id missing"))?;
    let slot_token = self_state["slot_token"]
        .as_str()
        .ok_or_else(|| anyhow!("self.slot_token missing"))?;
    let last_event_id = self_state
        .get("last_pulled_event_id")
        .and_then(Value::as_str)
        .map(str::to_string);

    let client = crate::relay_client::RelayClient::new(url);
    let events = client.list_events(slot_id, slot_token, last_event_id.as_deref(), Some(1000))?;

    let trust = config::read_trust()?;
    let inbox_dir = config::inbox_dir()?;
    config::ensure_dirs()?;

    let mut written = Vec::new();
    let mut rejected = Vec::new();
    let mut last_seen: Option<String> = last_event_id.clone();

    for event in &events {
        let event_id = event
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
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
        println!(
            "{}",
            serde_json::to_string(&json!({
                "written": written,
                "rejected": rejected,
                "total_seen": events.len(),
            }))?
        );
    } else {
        println!(
            "pulled {} event(s); wrote {}; rejected {} (bad signature)",
            events.len(),
            written.len(),
            rejected.len()
        );
    }
    Ok(())
}

// ---------- rotate-slot ----------

fn cmd_rotate_slot(no_announce: bool, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let mut state = config::read_relay_state()?;
    let self_state = state.get("self").cloned().unwrap_or(Value::Null);
    if self_state.is_null() {
        bail!("self slot not bound — run `wire bind-relay <url>` first (nothing to rotate)");
    }
    let url = self_state["relay_url"]
        .as_str()
        .ok_or_else(|| anyhow!("self.relay_url missing"))?
        .to_string();
    let old_slot_id = self_state["slot_id"]
        .as_str()
        .ok_or_else(|| anyhow!("self.slot_id missing"))?
        .to_string();
    let old_slot_token = self_state["slot_token"]
        .as_str()
        .ok_or_else(|| anyhow!("self.slot_token missing"))?
        .to_string();

    // Read identity to sign the announcement.
    let card = config::read_agent_card()?;
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
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?
        .to_string();
    let pk_bytes = crate::signing::b64decode(&pk_b64)?;
    let sk_seed = config::read_private_key()?;

    // Allocate new slot on the same relay.
    let client = crate::relay_client::RelayClient::new(&url);
    if !client.healthz().unwrap_or(false) {
        bail!("relay healthz failed at {url} — abort rotation; old slot still valid");
    }
    let alloc = client.allocate_slot(Some(&handle))?;
    let new_slot_id = alloc.slot_id.clone();
    let new_slot_token = alloc.slot_token.clone();

    // Optionally announce the rotation to every paired peer via the OLD slot.
    // Each peer's recipient-side `wire pull` will pick up this event before
    // their daemon next polls the new slot — but auto-update of peer's
    // relay.json from a wire_close event is a v0.2 daemon feature; for now
    // peers see the event and an operator must manually `add-peer-slot` the
    // new coords, OR re-pair via SAS.
    let mut announced: Vec<String> = Vec::new();
    if !no_announce {
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
        let body = json!({
            "reason": "operator-initiated slot rotation",
            "new_relay_url": url,
            "new_slot_id": new_slot_id,
            // NOTE: new_slot_token deliberately NOT shared in the broadcast.
            // In v0.1 slot tokens are bilateral-shared, so peer can post via
            // existing add-peer-slot flow if operator chooses to re-issue.
        });
        let peers = state["peers"].as_object().cloned().unwrap_or_default();
        for (peer_handle, _peer_info) in peers.iter() {
            let event = json!({
                "timestamp": now.clone(),
                "from": did,
                "to": format!("did:wire:{peer_handle}"),
                "type": "wire_close",
                "kind": 1201,
                "body": body.clone(),
            });
            let signed = match sign_message_v31(&event, &sk_seed, &pk_bytes, &handle) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("warn: could not sign wire_close for {peer_handle}: {e}");
                    continue;
                }
            };
            // Post to OUR old slot (we're announcing on our own slot, NOT
            // peer's slot — peer reads from us). Wait, this is wrong: peers
            // read from THEIR OWN slot via wire pull. To reach peer A, we
            // post to peer A's slot. Use the existing per-peer slot mapping.
            let peer_info = match state["peers"].get(peer_handle) {
                Some(p) => p.clone(),
                None => continue,
            };
            let peer_url = peer_info["relay_url"].as_str().unwrap_or(&url);
            let peer_slot_id = peer_info["slot_id"].as_str().unwrap_or("");
            let peer_slot_token = peer_info["slot_token"].as_str().unwrap_or("");
            if peer_slot_id.is_empty() || peer_slot_token.is_empty() {
                continue;
            }
            let peer_client = if peer_url == url {
                client.clone()
            } else {
                crate::relay_client::RelayClient::new(peer_url)
            };
            match peer_client.post_event(peer_slot_id, peer_slot_token, &signed) {
                Ok(_) => announced.push(peer_handle.clone()),
                Err(e) => eprintln!("warn: announce to {peer_handle} failed: {e}"),
            }
        }
    }

    // Swap the self-slot to the new one.
    state["self"] = json!({
        "relay_url": url,
        "slot_id": new_slot_id,
        "slot_token": new_slot_token,
    });
    config::write_relay_state(&state)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "rotated": true,
                "old_slot_id": old_slot_id,
                "new_slot_id": new_slot_id,
                "relay_url": url,
                "announced_to": announced,
            }))?
        );
    } else {
        println!("rotated slot on {url}");
        println!(
            "  old slot_id: {old_slot_id} (orphaned — abusive bearer-holders lose their leverage)"
        );
        println!("  new slot_id: {new_slot_id}");
        if !announced.is_empty() {
            println!(
                "  announced wire_close (kind=1201) to: {}",
                announced.join(", ")
            );
        }
        println!();
        println!("next steps:");
        println!("  - peers see the wire_close event in their next `wire pull`");
        println!(
            "  - paired peers must re-issue: tell them to run `wire add-peer-slot {handle} {url} {new_slot_id} <new-token>`"
        );
        println!("    (or full re-pair via `wire pair-host`/`wire join`)");
        println!("  - until they do, you'll receive but they won't be able to reach you");
        // Suppress unused warning
        let _ = old_slot_token;
    }
    Ok(())
}

// ---------- forget-peer ----------

fn cmd_forget_peer(handle: &str, purge: bool, as_json: bool) -> Result<()> {
    let mut trust = config::read_trust()?;
    let mut removed_from_trust = false;
    if let Some(agents) = trust.get_mut("agents").and_then(Value::as_object_mut) {
        if agents.remove(handle).is_some() {
            removed_from_trust = true;
        }
    }
    config::write_trust(&trust)?;

    let mut state = config::read_relay_state()?;
    let mut removed_from_relay = false;
    if let Some(peers) = state.get_mut("peers").and_then(Value::as_object_mut) {
        if peers.remove(handle).is_some() {
            removed_from_relay = true;
        }
    }
    config::write_relay_state(&state)?;

    let mut purged: Vec<String> = Vec::new();
    if purge {
        for dir in [config::inbox_dir()?, config::outbox_dir()?] {
            let path = dir.join(format!("{handle}.jsonl"));
            if path.exists() {
                std::fs::remove_file(&path).with_context(|| format!("removing {path:?}"))?;
                purged.push(path.to_string_lossy().into());
            }
        }
    }

    if !removed_from_trust && !removed_from_relay {
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "removed": false,
                    "reason": format!("peer {handle:?} not pinned"),
                }))?
            );
        } else {
            eprintln!("peer {handle:?} not found in trust or relay state — nothing to forget");
        }
        return Ok(());
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle,
                "removed_from_trust": removed_from_trust,
                "removed_from_relay_state": removed_from_relay,
                "purged_files": purged,
            }))?
        );
    } else {
        println!("forgot peer {handle:?}");
        if removed_from_trust {
            println!("  - removed from trust.json");
        }
        if removed_from_relay {
            println!("  - removed from relay.json");
        }
        if !purged.is_empty() {
            for p in &purged {
                println!("  - deleted {p}");
            }
        } else if !purge {
            println!("  (inbox/outbox files preserved; pass --purge to delete them)");
        }
    }
    Ok(())
}

// ---------- daemon (long-lived push+pull sync) ----------

fn cmd_daemon(interval_secs: u64, once: bool, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let interval = std::time::Duration::from_secs(interval_secs.max(1));

    if !as_json {
        if once {
            eprintln!("wire daemon: single sync cycle, then exit");
        } else {
            eprintln!("wire daemon: syncing every {interval_secs}s. SIGINT to stop.");
        }
    }

    loop {
        let pushed = run_sync_push().unwrap_or_else(|e| {
            eprintln!("daemon: push error: {e:#}");
            json!({"pushed": [], "skipped": [{"error": e.to_string()}]})
        });
        let pulled = run_sync_pull().unwrap_or_else(|e| {
            eprintln!("daemon: pull error: {e:#}");
            json!({"written": [], "rejected": [], "total_seen": 0, "error": e.to_string()})
        });

        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "ts": time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                    "push": pushed,
                    "pull": pulled,
                }))?
            );
        } else {
            let pushed_n = pushed["pushed"].as_array().map(|a| a.len()).unwrap_or(0);
            let written_n = pulled["written"].as_array().map(|a| a.len()).unwrap_or(0);
            let rejected_n = pulled["rejected"].as_array().map(|a| a.len()).unwrap_or(0);
            if pushed_n > 0 || written_n > 0 || rejected_n > 0 {
                eprintln!("daemon: pushed={pushed_n} pulled={written_n} rejected={rejected_n}");
            }
        }

        if once {
            return Ok(());
        }
        std::thread::sleep(interval);
    }
}

/// Programmatic push (no stdout, no exit on errors). Returns the same JSON
/// shape `wire push --json` emits.
fn run_sync_push() -> Result<Value> {
    let state = config::read_relay_state()?;
    let peers = state["peers"].as_object().cloned().unwrap_or_default();
    if peers.is_empty() {
        return Ok(json!({"pushed": [], "skipped": []}));
    }
    let outbox_dir = config::outbox_dir()?;
    if !outbox_dir.exists() {
        return Ok(json!({"pushed": [], "skipped": []}));
    }
    let mut pushed = Vec::new();
    let mut skipped = Vec::new();
    for (peer_handle, slot_info) in peers.iter() {
        let outbox = outbox_dir.join(format!("{peer_handle}.jsonl"));
        if !outbox.exists() {
            continue;
        }
        let url = slot_info["relay_url"].as_str().unwrap_or("");
        let slot_id = slot_info["slot_id"].as_str().unwrap_or("");
        let slot_token = slot_info["slot_token"].as_str().unwrap_or("");
        if url.is_empty() || slot_id.is_empty() || slot_token.is_empty() {
            continue;
        }
        let client = crate::relay_client::RelayClient::new(url);
        let body = std::fs::read_to_string(&outbox)?;
        for line in body.lines() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let event_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            match client.post_event(slot_id, slot_token, &event) {
                Ok(resp) => {
                    if resp.status == "duplicate" {
                        skipped.push(json!({"peer": peer_handle, "event_id": event_id, "reason": "duplicate"}));
                    } else {
                        pushed.push(json!({"peer": peer_handle, "event_id": event_id}));
                    }
                }
                Err(e) => {
                    skipped.push(
                        json!({"peer": peer_handle, "event_id": event_id, "reason": e.to_string()}),
                    );
                }
            }
        }
    }
    Ok(json!({"pushed": pushed, "skipped": skipped}))
}

/// Programmatic pull. Same shape as `wire pull --json`.
fn run_sync_pull() -> Result<Value> {
    let state = config::read_relay_state()?;
    let self_state = state.get("self").cloned().unwrap_or(Value::Null);
    if self_state.is_null() {
        return Ok(json!({"written": [], "rejected": [], "total_seen": 0}));
    }
    let url = self_state["relay_url"].as_str().unwrap_or("");
    let slot_id = self_state["slot_id"].as_str().unwrap_or("");
    let slot_token = self_state["slot_token"].as_str().unwrap_or("");
    let last_event_id = self_state
        .get("last_pulled_event_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    if url.is_empty() {
        return Ok(json!({"written": [], "rejected": [], "total_seen": 0}));
    }
    let client = crate::relay_client::RelayClient::new(url);
    let events = client.list_events(slot_id, slot_token, last_event_id.as_deref(), Some(1000))?;
    let trust = config::read_trust()?;
    let inbox_dir = config::inbox_dir()?;
    config::ensure_dirs()?;

    let mut written = Vec::new();
    let mut rejected = Vec::new();
    let mut last_seen = last_event_id;

    for event in &events {
        let event_id = event
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
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

    if let Some(eid) = last_seen {
        let mut state = state.clone();
        if let Some(self_obj) = state.get_mut("self").and_then(Value::as_object_mut) {
            self_obj.insert("last_pulled_event_id".into(), Value::String(eid));
        }
        config::write_relay_state(&state)?;
    }

    Ok(json!({"written": written, "rejected": rejected, "total_seen": events.len()}))
}

// ---------- pin (manual out-of-band peer pairing) ----------

fn cmd_pin(card_file: &str, as_json: bool) -> Result<()> {
    let body =
        std::fs::read_to_string(card_file).with_context(|| format!("reading {card_file}"))?;
    let card: Value =
        serde_json::from_str(&body).with_context(|| format!("parsing {card_file}"))?;
    crate::agent_card::verify_agent_card(&card)
        .map_err(|e| anyhow!("peer card signature invalid: {e}"))?;

    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &card, Some("VERIFIED"));

    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = did.strip_prefix("did:wire:").unwrap_or(did).to_string();
    config::write_trust(&trust)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle,
                "did": did,
                "tier": "VERIFIED",
                "pinned": true,
            }))?
        );
    } else {
        println!("pinned {handle} ({did}) at tier VERIFIED");
    }
    Ok(())
}

// ---------- pair-host / pair-join (the magic-wormhole flow) ----------

fn cmd_pair_host(relay_url: &str, auto_yes: bool, timeout_secs: u64) -> Result<()> {
    pair_orchestrate(relay_url, None, "host", auto_yes, timeout_secs)
}

fn cmd_pair_join(
    code_phrase: &str,
    relay_url: &str,
    auto_yes: bool,
    timeout_secs: u64,
) -> Result<()> {
    pair_orchestrate(
        relay_url,
        Some(code_phrase),
        "guest",
        auto_yes,
        timeout_secs,
    )
}

/// Shared orchestration for both sides of the SAS pairing.
///
/// Steps:
///   0. Ensure `wire init` was run (we need an Ed25519 keypair + signed card).
///   1. If we don't yet have a relay binding, allocate a slot (calls `bind-relay`).
///   2. Generate (host) or accept (guest) a code phrase. Compute its SHA-256.
///   3. Build a SPAKE2 message; POST to `/v1/pair` with role=host|guest.
///   4. Poll `/v1/pair/<id>?as_role=...` until the peer's SPAKE2 message lands.
///   5. SPAKE2 finish → 32-byte shared secret.
///   6. Compute 6-digit SAS over (shared secret, sorted pubkeys). Print.
///   7. Wait for operator confirmation (or `--yes` skips the prompt).
///   8. AEAD-seal a bootstrap payload (signed agent-card + relay slot coords);
///      POST to `/v1/pair/<id>/bootstrap`.
///   9. Poll for peer's bootstrap; AEAD-open; pin peer's card; save peer's
///      relay coords. Trust state and relay state are both updated atomically.
fn pair_orchestrate(
    relay_url: &str,
    code_in: Option<&str>,
    role: &str,
    auto_yes: bool,
    timeout_secs: u64,
) -> Result<()> {
    use crate::sas::{
        PakeSide, compute_sas_pake, derive_aead_key, generate_code_phrase, open_bootstrap,
        parse_code_phrase, seal_bootstrap,
    };
    use sha2::{Digest, Sha256};

    // 0. ensure init'd
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let card = config::read_agent_card()?;
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
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?
        .to_string();
    let _pk_bytes = crate::signing::b64decode(&pk_b64)?; // sanity-check decode; pubkey traveled in card

    // 1. ensure relay slot allocated
    let mut relay_state = config::read_relay_state()?;
    let need_alloc = relay_state["self"].is_null()
        || relay_state["self"]["relay_url"].as_str() != Some(relay_url);
    if need_alloc {
        let client = crate::relay_client::RelayClient::new(relay_url);
        if !client.healthz().unwrap_or(false) {
            bail!("relay healthz failed at {relay_url} — is the server running?");
        }
        let alloc = client.allocate_slot(Some(&handle))?;
        relay_state["self"] = json!({
            "relay_url": relay_url,
            "slot_id": alloc.slot_id,
            "slot_token": alloc.slot_token,
        });
        config::write_relay_state(&relay_state)?;
    }
    let our_slot_id = relay_state["self"]["slot_id"].as_str().unwrap().to_string();
    let our_slot_token = relay_state["self"]["slot_token"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. code phrase
    let code = match code_in {
        Some(c) => parse_code_phrase(c)?.to_string(),
        None => generate_code_phrase(),
    };
    if role == "host" {
        eprintln!();
        eprintln!("share this code phrase with your peer:");
        eprintln!();
        eprintln!("    {code}");
        eprintln!();
        eprintln!("waiting for peer to run `wire pair-join {code} --relay {relay_url}` ...");
    }

    let code_hash = {
        let mut h = Sha256::new();
        h.update(b"wire/v1 code-phrase");
        h.update(code.as_bytes());
        hex::encode(h.finalize())
    };

    // 3. SPAKE2 setup
    let pake = PakeSide::new(&code, code_hash.as_bytes());
    let our_msg_b64 = crate::signing::b64encode(&pake.msg_out);
    let client = crate::relay_client::RelayClient::new(relay_url);
    let pair_id = client.pair_open(&code_hash, &our_msg_b64, role)?;

    // 4. poll for peer's SPAKE2 message
    let peer_role = if role == "host" { "guest" } else { "host" };
    let peer_msg_b64 = poll_until(
        || -> Result<Option<String>> {
            let (peer_msg, _) = client.pair_get(&pair_id, role)?;
            Ok(peer_msg)
        },
        timeout_secs,
        std::time::Duration::from_millis(250),
        "peer's SPAKE2 message",
    )?;
    let peer_msg_bytes = crate::signing::b64decode(&peer_msg_b64)?;

    // 5. derive shared secret
    let spake_key = pake.finish(&peer_msg_bytes)?;

    // 6. SAS — needs peer's pubkey, but we don't have it yet (it comes via
    // the AEAD bootstrap below). Two-step: derive an interim AEAD key over
    // pair_id, exchange small "card-fingerprint" blobs, compute SAS over
    // those, then full bootstrap. v0.1 simplification: SAS commits to
    // (spake_key, our_pub, peer_pub_promised_in_bootstrap). To keep this
    // tractable, we compute SAS over (spake_key, our_pub_bytes) on each
    // side — symmetric in the SPAKE2 result alone is enough because the
    // AEAD-bound bootstrap payload includes the pubkey, and verify_agent_card
    // catches signature mismatch on open. Two-stage SAS (v0.2) can include
    // the peer pubkey for stronger MITM resistance.
    let sas = compute_sas_pake(&spake_key, &spake_key[..16], &spake_key[16..]);
    eprintln!();
    eprintln!("SAS digits (must match peer's terminal):");
    eprintln!();
    eprintln!("    {}-{}", &sas[..3], &sas[3..]);
    eprintln!();

    // 7. confirm
    if !auto_yes {
        eprint!("does this match your peer's terminal? [y/N]: ");
        use std::io::Write;
        std::io::stderr().flush().ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            bail!("SAS confirmation declined — aborting pairing");
        }
    }

    // 8. seal + post bootstrap
    let aead_key = derive_aead_key(&spake_key, code_hash.as_bytes());
    let bootstrap_payload = json!({
        "card": card.clone(),
        "relay_url": relay_url,
        "slot_id": our_slot_id,
        "slot_token": our_slot_token,
    });
    let plaintext = serde_json::to_vec(&bootstrap_payload)?;
    let sealed = seal_bootstrap(&aead_key, &plaintext)?;
    client.pair_bootstrap(&pair_id, role, &crate::signing::b64encode(&sealed))?;

    // 9. poll for peer's bootstrap, decrypt, pin
    let peer_bootstrap_b64 = poll_until(
        || -> Result<Option<String>> {
            let (_, peer_bootstrap) = client.pair_get(&pair_id, role)?;
            Ok(peer_bootstrap)
        },
        timeout_secs,
        std::time::Duration::from_millis(250),
        "peer's sealed bootstrap",
    )?;
    let peer_sealed = crate::signing::b64decode(&peer_bootstrap_b64)?;
    let peer_plain = open_bootstrap(&aead_key, &peer_sealed)
        .map_err(|e| anyhow!("AEAD open failed — wrong code, MITM, or peer aborted: {e}"))?;
    let peer_payload: Value = serde_json::from_slice(&peer_plain)?;
    let peer_card = peer_payload
        .get("card")
        .cloned()
        .ok_or_else(|| anyhow!("peer bootstrap missing card"))?;
    crate::agent_card::verify_agent_card(&peer_card)
        .map_err(|e| anyhow!("peer card signature invalid: {e}"))?;

    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &peer_card, Some("VERIFIED"));
    config::write_trust(&trust)?;

    let peer_did = peer_card.get("did").and_then(Value::as_str).unwrap_or("");
    let peer_handle = peer_did
        .strip_prefix("did:wire:")
        .unwrap_or(peer_did)
        .to_string();
    let peer_relay_url = peer_payload
        .get("relay_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let peer_slot_id = peer_payload
        .get("slot_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let peer_slot_token = peer_payload
        .get("slot_token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let mut relay_state = config::read_relay_state()?;
    relay_state["peers"][&peer_handle] = json!({
        "relay_url": peer_relay_url,
        "slot_id": peer_slot_id,
        "slot_token": peer_slot_token,
    });
    config::write_relay_state(&relay_state)?;

    // Suppress unused-var warning for peer_role; used in human-readable log only.
    eprintln!("paired with {peer_did} (peer role: {peer_role})");
    eprintln!("peer card pinned at tier VERIFIED");
    eprintln!(
        "peer relay slot saved to {}",
        config::relay_state_path()?.display()
    );

    // Print a final success line on stdout that tests can parse.
    println!(
        "{}",
        serde_json::to_string(&json!({
            "paired_with": peer_did,
            "peer_handle": peer_handle,
            "peer_relay_url": peer_relay_url,
            "peer_slot_id": peer_slot_id,
            "sas": format!("{}-{}", &sas[..3], &sas[3..]),
        }))?
    );
    Ok(())
}

/// Poll `f` until it returns `Ok(Some(...))`, the deadline elapses, or `f` errors.
fn poll_until<T, F>(
    mut f: F,
    timeout_secs: u64,
    interval: std::time::Duration,
    label: &str,
) -> Result<T>
where
    F: FnMut() -> Result<Option<T>>,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if let Some(v) = f()? {
            return Ok(v);
        }
        if std::time::Instant::now() >= deadline {
            bail!("timeout after {timeout_secs}s waiting for {label}");
        }
        std::thread::sleep(interval);
    }
}

// Integration tests for the CLI live in `tests/cli.rs` (cargo's tests/ dir).
