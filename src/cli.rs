//! `wire` CLI surface.
//!
//! Every subcommand emits human-readable text by default and structured JSON
//! when `--json` is passed. Stable JSON shape is part of the API contract —
//! see `docs/AGENT_INTEGRATION.md`.
//!
//! Subcommand split:
//!   - **agent-safe**: `whoami`, `peers`, `verify`, `send`, `tail` — pure
//!     message-layer ops, no trust establishment.
//!   - **trust-establishing**: `init`, `pair-host`, `pair-join`. The CLI
//!     uses interactive `y/N` prompts here. The MCP equivalents
//!     (`wire_init`, `wire_pair_initiate`, `wire_pair_join`, `wire_pair_check`,
//!     `wire_pair_confirm`) preserve the human gate by requiring the user to
//!     type the 6 SAS digits back into chat — see `docs/THREAT_MODEL.md` T10/T14.

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
        /// Detach: write a pending-pair file, print the code phrase, and exit
        /// immediately. The running `wire daemon` does the handshake in the
        /// background; confirm SAS later via `wire pair-confirm <code> <digits>`.
        /// `wire pair-list` shows pending sessions. Default is foreground
        /// blocking behavior for backward compat.
        #[arg(long)]
        detach: bool,
        /// Emit JSON instead of text. Currently only meaningful with --detach.
        #[arg(long)]
        json: bool,
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
        /// Detach: see `pair-host --detach`.
        #[arg(long)]
        detach: bool,
        /// Emit JSON instead of text. Currently only meaningful with --detach.
        #[arg(long)]
        json: bool,
    },
    /// Confirm SAS digits for a detached pending pair. The daemon must be
    /// running for this to do anything — it picks up the confirmation on its
    /// next tick. Mismatch aborts the pair.
    PairConfirm {
        /// The code phrase the original `wire pair-host --detach` printed.
        code_phrase: String,
        /// 6 digits as displayed by `wire pair-list` (dashes/spaces stripped).
        digits: String,
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// List all pending detached pair sessions and their state.
    PairList {
        /// Emit JSON instead of the table.
        #[arg(long)]
        json: bool,
        /// Stream mode: never exit; print one JSON line per status transition
        /// (creation, status change, deletion) across all pending pairs.
        /// Compose with bash `while read` to react in shell. Implies --json.
        #[arg(long)]
        watch: bool,
        /// Poll interval in seconds for --watch.
        #[arg(long, default_value_t = 1)]
        watch_interval: u64,
    },
    /// Cancel a pending pair. Releases the relay slot and removes the pending file.
    PairCancel {
        code_phrase: String,
        #[arg(long)]
        json: bool,
    },
    /// Block until a pending pair reaches a target status (default sas_ready),
    /// or terminates (finalized = file removed, aborted, aborted_restart), or
    /// the timeout expires. Useful for shell scripts that want to drive the
    /// detached flow without polling pair-list themselves.
    ///
    /// Exit codes:
    ///   0 — reached target status (or finalized, if target was sas_ready)
    ///   1 — terminated abnormally (aborted, aborted_restart, no such code)
    ///   2 — timeout
    PairWatch {
        code_phrase: String,
        /// Target status to wait for. Default: sas_ready.
        #[arg(long, default_value = "sas_ready")]
        status: String,
        /// Max seconds to wait.
        #[arg(long, default_value_t = 300)]
        timeout: u64,
        /// Emit JSON on each status change (one per line) instead of just on exit.
        #[arg(long)]
        json: bool,
    },
    /// One-shot bootstrap. Inits identity (idempotent), opens pair-host or
    /// pair-join, then registers wire as an MCP server. Single command from
    /// nothing to paired and ready — no separate init/pair-host/setup steps.
    /// Operator still must confirm SAS digits.
    ///
    /// Examples:
    ///   wire pair paul                          # host a new pair on default relay
    ///   wire pair willard --code 58-NMTY7A      # join paul's pair
    Pair {
        /// Short handle for this agent (becomes did:wire:<handle>). Used by init
        /// step if no identity exists; ignored if already initialized.
        handle: String,
        /// Code phrase from peer's pair-host output. Omit to be the host
        /// (this command will print one for you to share).
        #[arg(long)]
        code: Option<String>,
        /// Relay base URL. Defaults to the laulpogan public-good relay.
        #[arg(long, default_value = "https://wire.laulpogan.com")]
        relay: String,
        /// Skip SAS prompt. Test-only.
        #[arg(long)]
        yes: bool,
        /// Pair-step timeout in seconds.
        #[arg(long, default_value_t = 300)]
        timeout: u64,
        /// Skip the post-pair `setup --apply` step (don't register wire as
        /// an MCP server in detected client configs).
        #[arg(long)]
        no_setup: bool,
        /// Run via the daemon-orchestrated detached path (auto-starts daemon,
        /// exits immediately, daemon does the handshake). Confirm via
        /// `wire pair-confirm <code> <digits>` from any terminal. See
        /// `pair-host --detach` for details.
        #[arg(long)]
        detach: bool,
    },
    /// Forget a half-finished pair-slot on the relay. Use this if `pair-host`
    /// or `pair-join` crashed (process killed, network blip, OOM) before SAS
    /// confirmation, leaving the relay-side slot stuck with "guest already
    /// registered" or "host already registered" until the 5-minute TTL expires.
    /// Either side can call. Idempotent.
    PairAbandon {
        /// The code phrase from the original pair-host (e.g. `58-NMTY7A`).
        code_phrase: String,
        /// Relay base URL.
        #[arg(long, default_value = "https://wire.laulpogan.com")]
        relay: String,
    },
    /// Detect known MCP host config locations (Claude Desktop, Claude Code,
    /// Cursor, project-local) and either print or auto-merge the wire MCP
    /// server entry. Default prints; pass `--apply` to actually modify config
    /// files. Idempotent — re-running is safe.
    Setup {
        /// Actually write the changes (default = print only).
        #[arg(long)]
        apply: bool,
    },
    /// Show an agent's profile. With no arg, prints local self. With a
    /// `nick@domain` arg, resolves via that domain's `.well-known/wire/agent`
    /// endpoint and verifies the returned signed card before display.
    Whois {
        /// Optional handle (`nick@domain`). Omit to show self.
        handle: Option<String>,
        #[arg(long)]
        json: bool,
        /// Override the relay base URL used for resolution (default:
        /// `https://<domain>` from the handle).
        #[arg(long)]
        relay: Option<String>,
    },
    /// Claim a nick on a relay's handle directory. Anyone can then reach
    /// this agent by `<nick>@<relay-domain>` via the relay's
    /// `.well-known/wire/agent` endpoint. FCFS; same-DID re-claims allowed.
    Claim {
        nick: String,
        /// Relay to claim the nick on. Default = relay our slot is on.
        #[arg(long)]
        relay: Option<String>,
        /// Public URL the relay should advertise to resolvers (default = relay).
        #[arg(long)]
        public_url: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Edit profile fields (display_name, emoji, motto, vibe, pronouns,
    /// avatar_url, handle, now). Re-signs the agent-card atomically.
    ///
    /// Examples:
    ///   wire profile set motto "compiles or dies trying"
    ///   wire profile set emoji "🦀"
    ///   wire profile set vibe '["rust","late-night","no-async-please"]'
    ///   wire profile set handle "coffee-ghost@anthropic.dev"
    ///   wire profile get
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Mint a one-paste invite URL. Anyone with this URL can pair to us in a
    /// single step (no SAS digits, no code typing). Auto-inits + auto-allocates
    /// a relay slot on first use. Default TTL 24h, single-use.
    Invite {
        /// Override the relay URL for first-time auto-allocation.
        #[arg(long, default_value = "https://wire.laulpogan.com")]
        relay: String,
        /// Invite lifetime in seconds (default 86400 = 24h).
        #[arg(long, default_value_t = 86_400)]
        ttl: u64,
        /// Number of distinct peers that can accept this invite before it's
        /// consumed (default 1).
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Accept a wire invite URL. Single-step pair — pins issuer, sends our
    /// signed card to issuer's slot. Auto-inits + auto-allocates if needed.
    Accept {
        /// The full invite URL (starts with `wire://pair?v=1&inv=...`).
        url: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Long-running event dispatcher. Watches inbox for new verified events
    /// and spawns the given shell command per event, passing the event JSON
    /// on stdin. Use to wire up autonomous reply loops:
    ///   wire reactor --on-event 'claude -p "respond via wire send"'
    /// Cursor persisted to `$WIRE_HOME/state/wire/reactor.cursor`.
    Reactor {
        /// Shell command to spawn per event. Event JSON written to its stdin.
        #[arg(long)]
        on_event: String,
        /// Only fire for events from this peer.
        #[arg(long)]
        peer: Option<String>,
        /// Only fire for events of this kind (numeric or name, e.g. 1 / decision).
        #[arg(long)]
        kind: Option<String>,
        /// Skip events whose verified flag is false (default true).
        #[arg(long, default_value_t = true)]
        verified_only: bool,
        /// Poll interval in seconds.
        #[arg(long, default_value_t = 2)]
        interval: u64,
        /// Process one sweep and exit.
        #[arg(long)]
        once: bool,
        /// Don't actually spawn — print one JSONL line per event for smoke-testing.
        #[arg(long)]
        dry_run: bool,
        /// Hard rate-limit: max events handler is fired for per peer per minute.
        /// 0 = unlimited. Default 6 — covers normal conversational tempo, kills
        /// LLM-vs-LLM feedback loops (which fire 10+/sec).
        #[arg(long, default_value_t = 6)]
        max_per_minute: u32,
        /// Anti-loop chain depth. Track event_ids this reactor emitted; if an
        /// incoming event body contains `(re:X)` where X is in our emitted log,
        /// skip — that's a reply-to-our-reply, depth ≥ 2. Disable with 0.
        #[arg(long, default_value_t = 1)]
        max_chain_depth: u32,
    },
    /// Watch the inbox for new verified events and fire an OS notification per
    /// event. Long-running; background under systemd / `&` / tmux. Cursor is
    /// persisted to `$WIRE_HOME/state/wire/notify.cursor` so restarts don't
    /// re-emit history.
    Notify {
        /// Poll interval in seconds.
        #[arg(long, default_value_t = 2)]
        interval: u64,
        /// Only notify for events from this peer (handle, no did: prefix).
        #[arg(long)]
        peer: Option<String>,
        /// Run a single sweep and exit (useful for cron / tests).
        #[arg(long)]
        once: bool,
        /// Suppress the OS notification call; print one JSON line per event to
        /// stdout instead (for piping into other tooling or smoke-testing
        /// without a desktop session).
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProfileAction {
    /// Set a profile field. Field names: display_name, emoji, motto, vibe,
    /// pronouns, avatar_url, handle, now. Values are strings except `vibe`
    /// (JSON array) and `now` (JSON object).
    Set {
        field: String,
        value: String,
        #[arg(long)]
        json: bool,
    },
    /// Show all profile fields. Equivalent to `wire whois`.
    Get {
        #[arg(long)]
        json: bool,
    },
    /// Clear a profile field.
    Clear {
        field: String,
        #[arg(long)]
        json: bool,
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
            detach,
            json,
        } => {
            if detach {
                cmd_pair_host_detach(&relay, json)
            } else {
                cmd_pair_host(&relay, yes, timeout)
            }
        }
        Command::PairJoin {
            code_phrase,
            relay,
            yes,
            timeout,
            detach,
            json,
        } => {
            if detach {
                cmd_pair_join_detach(&code_phrase, &relay, json)
            } else {
                cmd_pair_join(&code_phrase, &relay, yes, timeout)
            }
        }
        Command::PairConfirm {
            code_phrase,
            digits,
            json,
        } => cmd_pair_confirm(&code_phrase, &digits, json),
        Command::PairList {
            json,
            watch,
            watch_interval,
        } => cmd_pair_list(json, watch, watch_interval),
        Command::PairCancel { code_phrase, json } => cmd_pair_cancel(&code_phrase, json),
        Command::PairWatch {
            code_phrase,
            status,
            timeout,
            json,
        } => cmd_pair_watch(&code_phrase, &status, timeout, json),
        Command::Pair {
            handle,
            code,
            relay,
            yes,
            timeout,
            no_setup,
            detach,
        } => {
            if detach {
                cmd_pair_detach(&handle, code.as_deref(), &relay)
            } else {
                cmd_pair(&handle, code.as_deref(), &relay, yes, timeout, no_setup)
            }
        }
        Command::PairAbandon { code_phrase, relay } => cmd_pair_abandon(&code_phrase, &relay),
        Command::Invite {
            relay,
            ttl,
            uses,
            json,
        } => cmd_invite(&relay, ttl, uses, json),
        Command::Accept { url, json } => cmd_accept(&url, json),
        Command::Whois {
            handle,
            json,
            relay,
        } => cmd_whois(handle.as_deref(), json, relay.as_deref()),
        Command::Claim {
            nick,
            relay,
            public_url,
            json,
        } => cmd_claim(&nick, relay.as_deref(), public_url.as_deref(), json),
        Command::Profile { action } => cmd_profile(action),
        Command::Setup { apply } => cmd_setup(apply),
        Command::Reactor {
            on_event,
            peer,
            kind,
            verified_only,
            interval,
            once,
            dry_run,
            max_per_minute,
            max_chain_depth,
        } => cmd_reactor(
            &on_event,
            peer.as_deref(),
            kind.as_deref(),
            verified_only,
            interval,
            once,
            dry_run,
            max_per_minute,
            max_chain_depth,
        ),
        Command::Notify {
            interval,
            peer,
            once,
            json,
        } => cmd_notify(interval, peer.as_deref(), once, json),
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

        // Daemon liveness — check daemon.pid (written by pending_pair::cleanup_on_startup).
        let daemon_pid_path = config::state_dir()?.join("daemon.pid");
        let mut daemon = json!({"running": false, "pid": Value::Null});
        if daemon_pid_path.exists()
            && let Ok(s) = std::fs::read_to_string(&daemon_pid_path)
            && let Ok(pid) = s.trim().parse::<u32>()
        {
            let alive = {
                #[cfg(target_os = "linux")]
                {
                    std::path::Path::new(&format!("/proc/{pid}")).exists()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    std::process::Command::new("kill")
                        .args(["-0", &pid.to_string()])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                }
            };
            daemon = json!({"running": alive, "pid": pid});
        }
        summary["daemon"] = daemon;

        // Pending pair sessions — counts by status.
        let pending = crate::pending_pair::list_pending().unwrap_or_default();
        let mut counts: std::collections::BTreeMap<String, u32> = Default::default();
        for p in &pending {
            *counts.entry(p.status.clone()).or_default() += 1;
        }
        summary["pending_pairs"] = json!({
            "total": pending.len(),
            "by_status": counts,
        });
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
        let daemon_running = summary["daemon"]["running"].as_bool().unwrap_or(false);
        let daemon_pid = summary["daemon"]["pid"]
            .as_u64()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string());
        println!(
            "daemon:        {} (pid {})",
            if daemon_running { "running" } else { "DOWN" },
            daemon_pid
        );
        let pending_total = summary["pending_pairs"]["total"].as_u64().unwrap_or(0);
        if pending_total > 0 {
            print!("pending pairs: {pending_total}");
            if let Some(obj) = summary["pending_pairs"]["by_status"].as_object() {
                let parts: Vec<String> = obj
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v.as_u64().unwrap_or(0)))
                    .collect();
                if !parts.is_empty() {
                    print!(" ({})", parts.join(", "));
                }
            }
            println!();
        } else {
            println!("pending pairs: none");
        }
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
    // Append goes through `config::append_outbox_record` which holds a per-
    // path mutex so concurrent senders cannot interleave bytes mid-line.
    let line = serde_json::to_vec(&signed)?;
    let outbox = config::append_outbox_record(peer, &line)?;

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
        if let Some(want) = peer_filter
            && peer_handle != want
        {
            continue;
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

        // v0.4.0 invite-pair: detect + consume pair_drop events BEFORE the
        // trust check (sender isn't pinned yet by definition). Successful
        // consumption pins the sender; we then re-read trust so the event
        // passes verify and lands in the inbox normally.
        let drop_paired = matches!(
            crate::pair_invite::maybe_consume_pair_drop(event),
            Ok(Some(_))
        );
        let active_trust = if drop_paired {
            config::read_trust()?
        } else {
            trust.clone()
        };

        match crate::signing::verify_message_v31(event, &active_trust) {
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

    // Persist cursor. RE-READ relay state from disk: maybe_consume_pair_drop
    // (and any other in-loop side effect) may have added new peer pins during
    // the iteration. Using the stale snapshot from the loop's start would
    // silently wipe those out.
    if let Some(eid) = last_seen {
        let mut fresh = config::read_relay_state()?;
        if let Some(self_obj) = fresh.get_mut("self").and_then(Value::as_object_mut) {
            self_obj.insert("last_pulled_event_id".into(), Value::String(eid));
        }
        config::write_relay_state(&fresh)?;
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
    if let Some(agents) = trust.get_mut("agents").and_then(Value::as_object_mut)
        && agents.remove(handle).is_some()
    {
        removed_from_trust = true;
    }
    config::write_trust(&trust)?;

    let mut state = config::read_relay_state()?;
    let mut removed_from_relay = false;
    if let Some(peers) = state.get_mut("peers").and_then(Value::as_object_mut)
        && peers.remove(handle).is_some()
    {
        removed_from_relay = true;
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

    // Recover from prior crash: any pending pair in transient state had its
    // in-memory SPAKE2 secret lost when the previous daemon exited. Release
    // the relay slots and mark the files so the operator can re-issue.
    if let Err(e) = crate::pending_pair::cleanup_on_startup() {
        eprintln!("daemon: pending-pair cleanup_on_startup error: {e:#}");
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
        let pairs = crate::pending_pair::tick().unwrap_or_else(|e| {
            eprintln!("daemon: pending-pair tick error: {e:#}");
            json!({"transitions": []})
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
                    "pairs": pairs,
                }))?
            );
        } else {
            let pushed_n = pushed["pushed"].as_array().map(|a| a.len()).unwrap_or(0);
            let written_n = pulled["written"].as_array().map(|a| a.len()).unwrap_or(0);
            let rejected_n = pulled["rejected"].as_array().map(|a| a.len()).unwrap_or(0);
            let pair_transitions = pairs["transitions"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0);
            if pushed_n > 0 || written_n > 0 || rejected_n > 0 || pair_transitions > 0 {
                eprintln!(
                    "daemon: pushed={pushed_n} pulled={written_n} rejected={rejected_n} pair-transitions={pair_transitions}"
                );
            }
            // Loud per-transition logging so operator sees pair progress live.
            if let Some(arr) = pairs["transitions"].as_array() {
                for t in arr {
                    eprintln!(
                        "  pair {} : {} → {}",
                        t.get("code").and_then(Value::as_str).unwrap_or("?"),
                        t.get("from").and_then(Value::as_str).unwrap_or("?"),
                        t.get("to").and_then(Value::as_str).unwrap_or("?")
                    );
                    if let Some(sas) = t.get("sas").and_then(Value::as_str)
                        && t.get("to").and_then(Value::as_str) == Some("sas_ready")
                    {
                        eprintln!("    SAS digits: {}-{}", &sas[..3], &sas[3..]);
                        eprintln!(
                            "    Run: wire pair-confirm {} {}",
                            t.get("code").and_then(Value::as_str).unwrap_or("?"),
                            sas
                        );
                    }
                }
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

        // v0.4.0 invite-pair: detect + consume pair_drop events BEFORE the
        // trust check (sender isn't pinned yet by definition). Successful
        // consumption pins the sender; we then re-read trust so the event
        // passes verify and lands in the inbox normally.
        let drop_paired = matches!(
            crate::pair_invite::maybe_consume_pair_drop(event),
            Ok(Some(_))
        );
        let active_trust = if drop_paired {
            config::read_trust()?
        } else {
            trust.clone()
        };

        match crate::signing::verify_message_v31(event, &active_trust) {
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
        // Re-read: maybe_consume_pair_drop may have added a peer pin mid-loop.
        let mut fresh = config::read_relay_state()?;
        if let Some(self_obj) = fresh.get_mut("self").and_then(Value::as_object_mut) {
            self_obj.insert("last_pulled_event_id".into(), Value::String(eid));
        }
        config::write_relay_state(&fresh)?;
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
/// Now thin: delegates to `pair_session::pair_session_open` / `_try_sas` /
/// `_finalize`. CLI keeps its interactive y/N prompt; MCP uses
/// `pair_session_confirm_sas` instead.
fn pair_orchestrate(
    relay_url: &str,
    code_in: Option<&str>,
    role: &str,
    auto_yes: bool,
    timeout_secs: u64,
) -> Result<()> {
    use crate::pair_session::{pair_session_finalize, pair_session_open, pair_session_try_sas};

    let mut s = pair_session_open(role, relay_url, code_in)?;

    if role == "host" {
        eprintln!();
        eprintln!("share this code phrase with your peer:");
        eprintln!();
        eprintln!("    {}", s.code);
        eprintln!();
        eprintln!(
            "waiting for peer to run `wire pair-join {} --relay {relay_url}` ...",
            s.code
        );
    } else {
        eprintln!();
        eprintln!("joined pair-slot on {relay_url} — waiting for host's SPAKE2 message ...");
    }

    // Stage 2 — poll for SAS-ready with periodic progress heartbeat. The bare
    // pair_session_wait_for_sas helper is silent; the CLI wraps it in a loop
    // that emits a "waiting (Ns / Ts)" line every HEARTBEAT_SECS so operators
    // see the process is alive while the other side connects.
    const HEARTBEAT_SECS: u64 = 10;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let started = std::time::Instant::now();
    let mut last_heartbeat = started;
    let formatted = loop {
        if let Some(sas) = pair_session_try_sas(&mut s)? {
            break sas;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(anyhow!(
                "timeout after {timeout_secs}s waiting for peer's SPAKE2 message"
            ));
        }
        if now.duration_since(last_heartbeat).as_secs() >= HEARTBEAT_SECS {
            let elapsed = now.duration_since(started).as_secs();
            eprintln!("  ... still waiting ({elapsed}s / {timeout_secs}s)");
            last_heartbeat = now;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    };

    eprintln!();
    eprintln!("SAS digits (must match peer's terminal):");
    eprintln!();
    eprintln!("    {formatted}");
    eprintln!();

    // Stage 3 — operator confirmation. CLI uses interactive y/N for backward
    // compatibility; MCP uses pair_session_confirm_sas with the typed digits.
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
    s.sas_confirmed = true;

    // Stage 4 — seal+exchange bootstrap, pin peer.
    let result = pair_session_finalize(&mut s, timeout_secs)?;

    let peer_did = result["paired_with"].as_str().unwrap_or("");
    let peer_role = if role == "host" { "guest" } else { "host" };
    eprintln!("paired with {peer_did} (peer role: {peer_role})");
    eprintln!("peer card pinned at tier VERIFIED");
    eprintln!(
        "peer relay slot saved to {}",
        config::relay_state_path()?.display()
    );

    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

// (poll_until helper removed — pair flow now uses pair_session::pair_session_wait_for_sas
// and pair_session_finalize, both of which inline their own deadline loops.)

// ---------- pair — single-shot init + pair-* + setup ----------

fn cmd_pair(
    handle: &str,
    code: Option<&str>,
    relay: &str,
    auto_yes: bool,
    timeout_secs: u64,
    no_setup: bool,
) -> Result<()> {
    // Step 1 — idempotent identity. Safe if already initialized with the SAME handle;
    // bails loudly if a different handle is already set (operator must explicitly delete).
    let init_result = crate::pair_session::init_self_idempotent(handle, None, None)?;
    let did = init_result
        .get("did")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)")
        .to_string();
    let already = init_result
        .get("already_initialized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if already {
        println!("(identity {did} already initialized — reusing)");
    } else {
        println!("initialized {did}");
    }
    println!();

    // Step 2 — pair-host or pair-join based on code presence.
    match code {
        None => {
            println!("hosting pair on {relay} (no code = host) ...");
            cmd_pair_host(relay, auto_yes, timeout_secs)?;
        }
        Some(c) => {
            println!("joining pair with code {c} on {relay} ...");
            cmd_pair_join(c, relay, auto_yes, timeout_secs)?;
        }
    }

    // Step 3 — register wire as MCP server in detected client configs (idempotent).
    if !no_setup {
        println!();
        println!("registering wire as MCP server in detected client configs ...");
        if let Err(e) = cmd_setup(true) {
            // Non-fatal — pair succeeded, just print the warning.
            eprintln!("warn: setup --apply failed: {e}");
            eprintln!("      pair succeeded; you can re-run `wire setup --apply` manually.");
        }
    }

    println!();
    println!("pair complete. Next steps:");
    println!("  wire daemon start              # background sync of inbox/outbox vs relay");
    println!("  wire send <peer> claim <msg>   # send your peer something");
    println!("  wire tail                      # watch incoming events");
    Ok(())
}

// ---------- detached pair (daemon-orchestrated) ----------

/// `wire pair <handle> [--code <phrase>] --detach` — wraps init + detach
/// pair-host/-join into a single command. The non-detached variant lives in
/// `cmd_pair`; this one short-circuits to the daemon-orchestrated path.
fn cmd_pair_detach(handle: &str, code: Option<&str>, relay: &str) -> Result<()> {
    let init_result = crate::pair_session::init_self_idempotent(handle, None, None)?;
    let did = init_result
        .get("did")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)")
        .to_string();
    let already = init_result
        .get("already_initialized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if already {
        println!("(identity {did} already initialized — reusing)");
    } else {
        println!("initialized {did}");
    }
    println!();
    match code {
        None => cmd_pair_host_detach(relay, false),
        Some(c) => cmd_pair_join_detach(c, relay, false),
    }
}

fn cmd_pair_host_detach(relay_url: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let daemon_spawned = match crate::ensure_up::ensure_daemon_running() {
        Ok(b) => b,
        Err(e) => {
            if !as_json {
                eprintln!(
                    "warn: could not auto-start daemon: {e}; pair will queue but not advance"
                );
            }
            false
        }
    };
    let code = crate::sas::generate_code_phrase();
    let code_hash = crate::pair_session::derive_code_hash(&code);
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let p = crate::pending_pair::PendingPair {
        code: code.clone(),
        code_hash,
        role: "host".to_string(),
        relay_url: relay_url.to_string(),
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
    crate::pending_pair::write_pending(&p)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "state": "queued",
                "code_phrase": code,
                "relay_url": relay_url,
                "role": "host",
                "daemon_spawned": daemon_spawned,
            }))?
        );
    } else {
        if daemon_spawned {
            println!("(started wire daemon in background)");
        }
        println!("detached pair-host queued. Share this code with your peer:\n");
        println!("    {code}\n");
        println!("Next steps:");
        println!("  wire pair-list                                # check status");
        println!("  wire pair-confirm {code} <digits>   # when SAS shows up");
        println!("  wire pair-cancel  {code}            # to abort");
    }
    Ok(())
}

fn cmd_pair_join_detach(code_phrase: &str, relay_url: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let daemon_spawned = match crate::ensure_up::ensure_daemon_running() {
        Ok(b) => b,
        Err(e) => {
            if !as_json {
                eprintln!(
                    "warn: could not auto-start daemon: {e}; pair will queue but not advance"
                );
            }
            false
        }
    };
    let code = crate::sas::parse_code_phrase(code_phrase)?.to_string();
    let code_hash = crate::pair_session::derive_code_hash(&code);
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let p = crate::pending_pair::PendingPair {
        code: code.clone(),
        code_hash,
        role: "guest".to_string(),
        relay_url: relay_url.to_string(),
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
    crate::pending_pair::write_pending(&p)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "state": "queued",
                "code_phrase": code,
                "relay_url": relay_url,
                "role": "guest",
                "daemon_spawned": daemon_spawned,
            }))?
        );
    } else {
        if daemon_spawned {
            println!("(started wire daemon in background)");
        }
        println!("detached pair-join queued for code {code}.");
        println!(
            "Run `wire pair-list` to watch for SAS, then `wire pair-confirm {code} <digits>`."
        );
    }
    Ok(())
}

fn cmd_pair_confirm(code_phrase: &str, typed_digits: &str, as_json: bool) -> Result<()> {
    let code = crate::sas::parse_code_phrase(code_phrase)?.to_string();
    let typed: String = typed_digits
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    if typed.len() != 6 {
        bail!(
            "expected 6 digits (got {} after stripping non-digits)",
            typed.len()
        );
    }
    let mut p = crate::pending_pair::read_pending(&code)?
        .ok_or_else(|| anyhow!("no pending pair found for code {code}"))?;
    if p.status != "sas_ready" {
        bail!(
            "pair {code} not in sas_ready state (current: {}). Run `wire pair-list` to see what's going on.",
            p.status
        );
    }
    let stored = p
        .sas
        .as_ref()
        .ok_or_else(|| anyhow!("pending file has status=sas_ready but no sas field"))?
        .clone();
    if stored == typed {
        p.status = "confirmed".to_string();
        crate::pending_pair::write_pending(&p)?;
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "state": "confirmed",
                    "code_phrase": code,
                }))?
            );
        } else {
            println!("digits match. Daemon will finalize the handshake on its next tick.");
            println!("Run `wire peers` after a few seconds to confirm.");
        }
    } else {
        p.status = "aborted".to_string();
        p.last_error = Some(format!(
            "SAS digit mismatch (typed {typed}, expected {stored})"
        ));
        let client = crate::relay_client::RelayClient::new(&p.relay_url);
        let _ = client.pair_abandon(&p.code_hash);
        crate::pending_pair::write_pending(&p)?;
        crate::os_notify::toast(
            &format!("wire — pair aborted ({})", p.code),
            p.last_error.as_deref().unwrap_or("digits mismatch"),
        );
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "state": "aborted",
                    "code_phrase": code,
                    "error": "digits mismatch",
                }))?
            );
        }
        bail!("digits mismatch — pair aborted. Re-issue with a fresh `wire pair-host --detach`.");
    }
    Ok(())
}

fn cmd_pair_list(as_json: bool, watch: bool, watch_interval_secs: u64) -> Result<()> {
    if watch {
        return cmd_pair_list_watch(watch_interval_secs);
    }
    let items = crate::pending_pair::list_pending()?;
    if as_json {
        println!("{}", serde_json::to_string(&items)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("no pending pair sessions.");
        return Ok(());
    }
    println!(
        "{:<15} {:<8} {:<18} {:<10} NOTE",
        "CODE", "ROLE", "STATUS", "SAS"
    );
    for p in items {
        let sas = p
            .sas
            .as_ref()
            .map(|d| format!("{}-{}", &d[..3], &d[3..]))
            .unwrap_or_else(|| "—".to_string());
        let note = p
            .last_error
            .as_deref()
            .or(p.peer_did.as_deref())
            .unwrap_or("");
        println!(
            "{:<15} {:<8} {:<18} {:<10} {}",
            p.code, p.role, p.status, sas, note
        );
    }
    Ok(())
}

/// Stream-mode pair-list: never exits. Diffs per-code state every
/// `interval_secs` and prints one JSON line per transition (creation,
/// status flip, deletion). Useful for shell pipelines:
///
/// ```text
/// wire pair-list --watch | while read line; do
///     CODE=$(echo "$line" | jq -r .code)
///     STATUS=$(echo "$line" | jq -r .status)
///     ...
/// done
/// ```
fn cmd_pair_list_watch(interval_secs: u64) -> Result<()> {
    use std::collections::HashMap;
    use std::io::Write;
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    // Emit a snapshot synthetic event for every currently-pending pair on
    // startup so a consumer that arrives mid-flight sees the current state.
    let mut prev: HashMap<String, String> = HashMap::new();
    {
        let items = crate::pending_pair::list_pending()?;
        for p in &items {
            println!("{}", serde_json::to_string(&p)?);
            prev.insert(p.code.clone(), p.status.clone());
        }
        // Flush so the consumer's `while read` gets the snapshot promptly.
        let _ = std::io::stdout().flush();
    }
    loop {
        std::thread::sleep(interval);
        let items = match crate::pending_pair::list_pending() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mut cur: HashMap<String, String> = HashMap::new();
        for p in &items {
            cur.insert(p.code.clone(), p.status.clone());
            match prev.get(&p.code) {
                None => {
                    // New code appeared.
                    println!("{}", serde_json::to_string(&p)?);
                }
                Some(prev_status) if prev_status != &p.status => {
                    // Status flipped.
                    println!("{}", serde_json::to_string(&p)?);
                }
                _ => {}
            }
        }
        for code in prev.keys() {
            if !cur.contains_key(code) {
                // File disappeared → finalized or cancelled. Emit a synthetic
                // "removed" marker so the consumer sees the terminal event.
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "code": code,
                        "status": "removed",
                        "_synthetic": true,
                    }))?
                );
            }
        }
        let _ = std::io::stdout().flush();
        prev = cur;
    }
}

/// Block until a pending pair reaches `target_status` or terminates. Process
/// exit code carries the outcome (0 success, 1 terminated abnormally, 2
/// timeout) so shell scripts can branch directly.
fn cmd_pair_watch(
    code_phrase: &str,
    target_status: &str,
    timeout_secs: u64,
    as_json: bool,
) -> Result<()> {
    let code = crate::sas::parse_code_phrase(code_phrase)?.to_string();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut last_seen_status: Option<String> = None;
    loop {
        let p_opt = crate::pending_pair::read_pending(&code)?;
        let now = std::time::Instant::now();
        match p_opt {
            None => {
                // File gone — either finalized (success if target=sas_ready
                // since finalization implies it passed sas_ready) or never
                // existed. Distinguish by whether we ever saw it.
                if last_seen_status.is_some() {
                    if as_json {
                        println!(
                            "{}",
                            serde_json::to_string(&json!({"state": "finalized", "code": code}))?
                        );
                    } else {
                        println!("pair {code} finalized (file removed)");
                    }
                    return Ok(());
                } else {
                    if as_json {
                        println!(
                            "{}",
                            serde_json::to_string(&json!({"error": "no such pair", "code": code}))?
                        );
                    }
                    std::process::exit(1);
                }
            }
            Some(p) => {
                let cur = p.status.clone();
                if Some(cur.clone()) != last_seen_status {
                    if as_json {
                        // Emit per-transition line so scripts can stream.
                        println!("{}", serde_json::to_string(&p)?);
                    }
                    last_seen_status = Some(cur.clone());
                }
                if cur == target_status {
                    if !as_json {
                        let sas_str = p
                            .sas
                            .as_ref()
                            .map(|s| format!("{}-{}", &s[..3], &s[3..]))
                            .unwrap_or_else(|| "—".to_string());
                        println!("pair {code} reached {target_status} (SAS: {sas_str})");
                    }
                    return Ok(());
                }
                if cur == "aborted" || cur == "aborted_restart" {
                    if !as_json {
                        let err = p.last_error.as_deref().unwrap_or("(no detail)");
                        eprintln!("pair {code} {cur}: {err}");
                    }
                    std::process::exit(1);
                }
            }
        }
        if now >= deadline {
            if !as_json {
                eprintln!(
                    "timeout after {timeout_secs}s waiting for pair {code} to reach {target_status}"
                );
            }
            std::process::exit(2);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn cmd_pair_cancel(code_phrase: &str, as_json: bool) -> Result<()> {
    let code = crate::sas::parse_code_phrase(code_phrase)?.to_string();
    let p = crate::pending_pair::read_pending(&code)?
        .ok_or_else(|| anyhow!("no pending pair for code {code}"))?;
    let client = crate::relay_client::RelayClient::new(&p.relay_url);
    let _ = client.pair_abandon(&p.code_hash);
    crate::pending_pair::delete_pending(&code)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "state": "cancelled",
                "code_phrase": code,
            }))?
        );
    } else {
        println!("cancelled pending pair {code} (relay slot released, file removed).");
    }
    Ok(())
}

// ---------- pair-abandon — release stuck pair-slot ----------

fn cmd_pair_abandon(code_phrase: &str, relay_url: &str) -> Result<()> {
    // Accept either the raw phrase (e.g. "53-CKWIA5") or whatever the user
    // typed — normalize via the existing parser.
    let code = crate::sas::parse_code_phrase(code_phrase)?;
    let code_hash = crate::pair_session::derive_code_hash(code);
    let client = crate::relay_client::RelayClient::new(relay_url);
    client.pair_abandon(&code_hash)?;
    println!("abandoned pair-slot for code {code_phrase} on {relay_url}");
    println!("host can now issue a fresh code; guest can re-join.");
    Ok(())
}

// ---------- invite / accept — one-paste pair (v0.4.0) ----------

fn cmd_invite(relay: &str, ttl: u64, uses: u32, as_json: bool) -> Result<()> {
    let url = crate::pair_invite::mint_invite(Some(ttl), uses, Some(relay))?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "invite_url": url,
                "ttl_secs": ttl,
                "uses": uses,
                "relay": relay,
            }))?
        );
    } else {
        eprintln!("# Share this URL with one peer. Pasting it = pair complete on their side.");
        eprintln!("# TTL: {ttl}s. Uses: {uses}.");
        println!("{url}");
    }
    Ok(())
}

fn cmd_accept(url: &str, as_json: bool) -> Result<()> {
    let result = crate::pair_invite::accept_invite(url)?;
    if as_json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        let did = result
            .get("paired_with")
            .and_then(Value::as_str)
            .unwrap_or("?");
        println!("paired with {did}");
        println!(
            "you can now: wire send {} <kind> <body>",
            did.strip_prefix("did:wire:").unwrap_or(did)
        );
    }
    Ok(())
}

// ---------- whois / profile (v0.5) ----------

fn cmd_whois(handle: Option<&str>, as_json: bool, relay_override: Option<&str>) -> Result<()> {
    if let Some(h) = handle {
        let parsed = crate::pair_profile::parse_handle(h)?;
        // Special-case: if the supplied handle matches our own, skip the
        // network round-trip and print local.
        if config::is_initialized()? {
            let card = config::read_agent_card()?;
            let local_handle = card
                .get("profile")
                .and_then(|p| p.get("handle"))
                .and_then(Value::as_str)
                .map(str::to_string);
            if local_handle.as_deref() == Some(h) {
                return cmd_whois(None, as_json, None);
            }
        }
        // Remote resolution via .well-known/wire/agent on the handle's domain.
        let resolved = crate::pair_profile::resolve_handle(&parsed, relay_override)?;
        if as_json {
            println!("{}", serde_json::to_string(&resolved)?);
        } else {
            print_resolved_profile(&resolved);
        }
        return Ok(());
    }
    let card = config::read_agent_card()?;
    if as_json {
        let profile = card.get("profile").cloned().unwrap_or(Value::Null);
        println!(
            "{}",
            serde_json::to_string(&json!({
                "did": card.get("did").cloned().unwrap_or(Value::Null),
                "profile": profile,
            }))?
        );
    } else {
        print!("{}", crate::pair_profile::render_self_summary()?);
    }
    Ok(())
}

fn print_resolved_profile(resolved: &Value) {
    let did = resolved.get("did").and_then(Value::as_str).unwrap_or("?");
    let nick = resolved.get("nick").and_then(Value::as_str).unwrap_or("?");
    let relay = resolved
        .get("relay_url")
        .and_then(Value::as_str)
        .unwrap_or("");
    let slot = resolved
        .get("slot_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let profile = resolved
        .get("card")
        .and_then(|c| c.get("profile"))
        .cloned()
        .unwrap_or(Value::Null);
    println!("{did}");
    println!("  nick:         {nick}");
    if !relay.is_empty() {
        println!("  relay_url:    {relay}");
    }
    if !slot.is_empty() {
        println!("  slot_id:      {slot}");
    }
    let pick =
        |k: &str| -> Option<String> { profile.get(k).and_then(Value::as_str).map(str::to_string) };
    if let Some(s) = pick("display_name") {
        println!("  display_name: {s}");
    }
    if let Some(s) = pick("emoji") {
        println!("  emoji:        {s}");
    }
    if let Some(s) = pick("motto") {
        println!("  motto:        {s}");
    }
    if let Some(arr) = profile.get("vibe").and_then(Value::as_array) {
        let joined: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        println!("  vibe:         {}", joined.join(", "));
    }
    if let Some(s) = pick("pronouns") {
        println!("  pronouns:     {s}");
    }
}

fn cmd_claim(
    nick: &str,
    relay_override: Option<&str>,
    public_url: Option<&str>,
    as_json: bool,
) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    if !crate::pair_profile::is_valid_nick(nick) {
        bail!("nick {nick:?} invalid — must be 2..=32 chars, [a-z0-9_-], not reserved");
    }
    let relay_state = config::read_relay_state()?;
    let self_state = relay_state.get("self").cloned().unwrap_or(Value::Null);
    let default_relay = self_state
        .get("relay_url")
        .and_then(Value::as_str)
        .map(str::to_string);
    let relay_url = relay_override
        .map(str::to_string)
        .or(default_relay)
        .ok_or_else(|| anyhow!("no relay URL — pass --relay or run `wire bind-relay` first"))?;
    let slot_id = self_state
        .get("slot_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no slot allocated; run `wire bind-relay <url>` first"))?
        .to_string();
    let slot_token = self_state
        .get("slot_token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no slot_token in relay-state"))?
        .to_string();
    let card = config::read_agent_card()?;

    let client = crate::relay_client::RelayClient::new(&relay_url);
    let resp = client.handle_claim(nick, &slot_id, &slot_token, public_url, &card)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "nick": nick,
                "relay": relay_url,
                "response": resp,
            }))?
        );
    } else {
        println!(
            "claimed {nick} on {relay_url} — others can reach you at: {nick}@<this-relay-domain>"
        );
        println!("verify with: wire whois {nick}@<this-relay-domain>");
    }
    Ok(())
}

fn cmd_profile(action: ProfileAction) -> Result<()> {
    match action {
        ProfileAction::Set { field, value, json } => {
            // Try parsing the value as JSON; if that fails, treat it as a
            // bare string. Lets operators pass either `42` or `"hello"` or
            // `["rust","late-night"]` without quoting hell.
            let parsed: Value =
                serde_json::from_str(&value).unwrap_or(Value::String(value.clone()));
            let new_profile = crate::pair_profile::write_profile_field(&field, parsed)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "field": field,
                        "profile": new_profile,
                    }))?
                );
            } else {
                println!("profile.{field} set");
            }
        }
        ProfileAction::Get { json } => return cmd_whois(None, json, None),
        ProfileAction::Clear { field, json } => {
            let new_profile = crate::pair_profile::write_profile_field(&field, Value::Null)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "field": field,
                        "cleared": true,
                        "profile": new_profile,
                    }))?
                );
            } else {
                println!("profile.{field} cleared");
            }
        }
    }
    Ok(())
}

// ---------- setup — one-shot MCP host registration ----------

fn cmd_setup(apply: bool) -> Result<()> {
    use std::path::PathBuf;

    let entry = json!({"command": "wire", "args": ["mcp"]});
    let entry_pretty = serde_json::to_string_pretty(&json!({"wire": &entry}))?;

    // Detect probable MCP host config locations. Cross-platform — we only
    // touch the file if it already exists OR --apply was passed.
    let mut targets: Vec<(&str, PathBuf)> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        // Claude Code (CLI) — real config path is ~/.claude.json on all platforms (Linux/macOS/Windows).
        // The mcpServers map lives at the top level of that file.
        targets.push(("Claude Code", home.join(".claude.json")));
        // Legacy / alternate Claude Code XDG path — still try, harmless if absent.
        targets.push(("Claude Code (alt)", home.join(".config/claude/mcp.json")));
        // Claude Desktop macOS
        #[cfg(target_os = "macos")]
        targets.push((
            "Claude Desktop (macOS)",
            home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        ));
        // Claude Desktop Windows
        #[cfg(target_os = "windows")]
        if let Ok(appdata) = std::env::var("APPDATA") {
            targets.push((
                "Claude Desktop (Windows)",
                PathBuf::from(appdata).join("Claude/claude_desktop_config.json"),
            ));
        }
        // Cursor
        targets.push(("Cursor", home.join(".cursor/mcp.json")));
    }
    // Project-local — works for several MCP-aware tools
    targets.push(("project-local (.mcp.json)", PathBuf::from(".mcp.json")));

    println!("wire setup\n");
    println!("MCP server snippet (add this to your client's mcpServers):");
    println!();
    println!("{entry_pretty}");
    println!();

    if !apply {
        println!("Probable MCP host config locations on this machine:");
        for (name, path) in &targets {
            let marker = if path.exists() {
                "✓ found"
            } else {
                "  (would create)"
            };
            println!("  {marker:14}  {name}: {}", path.display());
        }
        println!();
        println!("Run `wire setup --apply` to merge wire into each config above.");
        println!(
            "Existing entries with a different command keep yours unchanged unless wire's exact entry is missing."
        );
        return Ok(());
    }

    let mut modified: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for (name, path) in &targets {
        match upsert_mcp_entry(path, "wire", &entry) {
            Ok(true) => modified.push(format!("✓ {name} ({})", path.display())),
            Ok(false) => skipped.push(format!("  {name} ({}): already configured", path.display())),
            Err(e) => skipped.push(format!("✗ {name} ({}): {e}", path.display())),
        }
    }
    if !modified.is_empty() {
        println!("Modified:");
        for line in &modified {
            println!("  {line}");
        }
        println!();
        println!("Restart the app(s) above to load wire MCP.");
    }
    if !skipped.is_empty() {
        println!();
        println!("Skipped:");
        for line in &skipped {
            println!("  {line}");
        }
    }
    Ok(())
}

/// Idempotent merge of an `mcpServers.<name>` entry into a JSON config file.
/// Returns Ok(true) if file was changed, Ok(false) if entry already matched.
fn upsert_mcp_entry(path: &std::path::Path, server_name: &str, entry: &Value) -> Result<bool> {
    let mut cfg: Value = if path.exists() {
        let body = std::fs::read_to_string(path).context("reading config")?;
        serde_json::from_str(&body).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };
    if !cfg.is_object() {
        cfg = json!({});
    }
    let root = cfg.as_object_mut().unwrap();
    let servers = root
        .entry("mcpServers".to_string())
        .or_insert_with(|| json!({}));
    if !servers.is_object() {
        *servers = json!({});
    }
    let map = servers.as_object_mut().unwrap();
    if map.get(server_name) == Some(entry) {
        return Ok(false);
    }
    map.insert(server_name.to_string(), entry.clone());
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).context("creating parent dir")?;
    }
    let out = serde_json::to_string_pretty(&cfg)? + "\n";
    std::fs::write(path, out).context("writing config")?;
    Ok(true)
}

// ---------- reactor — event-handler dispatch loop ----------

#[allow(clippy::too_many_arguments)]
fn cmd_reactor(
    on_event: &str,
    peer_filter: Option<&str>,
    kind_filter: Option<&str>,
    verified_only: bool,
    interval_secs: u64,
    once: bool,
    dry_run: bool,
    max_per_minute: u32,
    max_chain_depth: u32,
) -> Result<()> {
    use crate::inbox_watch::{InboxEvent, InboxWatcher};
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let cursor_path = config::state_dir()?.join("reactor.cursor");
    // event_ids THIS reactor's handler has caused to be sent (via wire send).
    // Used by chain-depth check — an incoming `(re:X)` where X is in this set
    // means peer is replying to something we just said → don't reply back.
    //
    // Persisted across restarts so a reactor that crashes mid-conversation
    // doesn't re-enter the loop. Reads on startup, writes after each
    // outbox-grow detection. Capped at 500 entries (LRU-ish — old entries
    // dropped from front of file).
    let emitted_path = config::state_dir()?.join("reactor-emitted.log");
    let mut emitted_ids: HashSet<String> = HashSet::new();
    if emitted_path.exists()
        && let Ok(body) = std::fs::read_to_string(&emitted_path)
    {
        for line in body.lines() {
            let t = line.trim();
            if !t.is_empty() {
                emitted_ids.insert(t.to_string());
            }
        }
    }
    // Outbox file paths the reactor watches for new sent-event_ids.
    let outbox_dir = config::outbox_dir()?;
    // (peer → file size we've already scanned). Lets us notice new outbox
    // appends without re-reading the whole file each sweep.
    let mut outbox_cursors: HashMap<String, u64> = HashMap::new();

    let mut watcher = InboxWatcher::from_cursor_file(&cursor_path)?;

    let kind_num: Option<u32> = match kind_filter {
        Some(k) => Some(parse_kind(k)?),
        None => None,
    };

    // Per-peer sliding window of dispatch instants for rate-limit check.
    let mut peer_dispatch_log: HashMap<String, VecDeque<Instant>> = HashMap::new();

    let dispatch = |ev: &InboxEvent,
                    peer_dispatch_log: &mut HashMap<String, VecDeque<Instant>>,
                    emitted_ids: &HashSet<String>|
     -> Result<bool> {
        if let Some(p) = peer_filter
            && ev.peer != p
        {
            return Ok(false);
        }
        if verified_only && !ev.verified {
            return Ok(false);
        }
        if let Some(want) = kind_num {
            let ev_kind = ev.raw.get("kind").and_then(Value::as_u64).map(|n| n as u32);
            if ev_kind != Some(want) {
                return Ok(false);
            }
        }

        // Chain-depth check: if the body contains `(re:<event_id>)` and that
        // event_id is in our emitted set, this is a reply to one of our
        // replies → loop suspected, skip.
        if max_chain_depth > 0 {
            let body_str = match &ev.raw["body"] {
                Value::String(s) => s.clone(),
                other => serde_json::to_string(other).unwrap_or_default(),
            };
            if let Some(referenced) = parse_re_marker(&body_str) {
                // Handler scripts usually truncate event_id (e.g. ${ID:0:12}).
                // Match emitted set by prefix to catch both full + truncated.
                let matched = emitted_ids.contains(&referenced)
                    || emitted_ids.iter().any(|full| full.starts_with(&referenced));
                if matched {
                    eprintln!(
                        "wire reactor: skip {} from {} — chain-depth (reply to our re:{})",
                        ev.event_id, ev.peer, referenced
                    );
                    return Ok(false);
                }
            }
        }

        // Per-peer rate-limit check (sliding 60s window).
        if max_per_minute > 0 {
            let now = Instant::now();
            let win = peer_dispatch_log.entry(ev.peer.clone()).or_default();
            while let Some(&front) = win.front() {
                if now.duration_since(front) > Duration::from_secs(60) {
                    win.pop_front();
                } else {
                    break;
                }
            }
            if win.len() as u32 >= max_per_minute {
                eprintln!(
                    "wire reactor: skip {} from {} — rate-limit ({}/min reached)",
                    ev.event_id, ev.peer, max_per_minute
                );
                return Ok(false);
            }
            win.push_back(now);
        }

        if dry_run {
            println!("{}", serde_json::to_string(&ev.raw)?);
            return Ok(true);
        }

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(on_event)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .env("WIRE_EVENT_PEER", &ev.peer)
            .env("WIRE_EVENT_ID", &ev.event_id)
            .env("WIRE_EVENT_KIND", &ev.kind)
            .spawn()
            .with_context(|| format!("spawning reactor handler: {on_event}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let body = serde_json::to_vec(&ev.raw)?;
            let _ = stdin.write_all(&body);
            let _ = stdin.write_all(b"\n");
        }
        std::mem::drop(child);
        Ok(true)
    };

    // Scan outbox files for newly-appended event_ids and add to emitted set.
    let scan_outbox = |emitted_ids: &mut HashSet<String>,
                       outbox_cursors: &mut HashMap<String, u64>|
     -> Result<usize> {
        if !outbox_dir.exists() {
            return Ok(0);
        }
        let mut added = 0;
        let mut new_ids: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&outbox_dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let peer = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let cur_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let start = *outbox_cursors.get(&peer).unwrap_or(&0);
            if cur_len <= start {
                outbox_cursors.insert(peer, start);
                continue;
            }
            let body = std::fs::read_to_string(&path).unwrap_or_default();
            let tail = &body[start as usize..];
            for line in tail.lines() {
                if let Ok(v) = serde_json::from_str::<Value>(line)
                    && let Some(eid) = v.get("event_id").and_then(Value::as_str)
                    && emitted_ids.insert(eid.to_string())
                {
                    new_ids.push(eid.to_string());
                    added += 1;
                }
            }
            outbox_cursors.insert(peer, cur_len);
        }
        if !new_ids.is_empty() {
            // Append new ids to disk, cap on-disk file at 500 entries.
            let mut all: Vec<String> = emitted_ids.iter().cloned().collect();
            if all.len() > 500 {
                all.sort();
                let drop_n = all.len() - 500;
                let dropped: HashSet<String> = all.iter().take(drop_n).cloned().collect();
                emitted_ids.retain(|x| !dropped.contains(x));
                all = emitted_ids.iter().cloned().collect();
            }
            let _ = std::fs::write(&emitted_path, all.join("\n") + "\n");
        }
        Ok(added)
    };

    let sweep = |watcher: &mut InboxWatcher,
                 emitted_ids: &mut HashSet<String>,
                 outbox_cursors: &mut HashMap<String, u64>,
                 peer_dispatch_log: &mut HashMap<String, VecDeque<Instant>>|
     -> Result<usize> {
        // Pick up any event_ids we sent since last sweep.
        let _ = scan_outbox(emitted_ids, outbox_cursors);

        let events = watcher.poll()?;
        let mut fired = 0usize;
        for ev in &events {
            match dispatch(ev, peer_dispatch_log, emitted_ids) {
                Ok(true) => fired += 1,
                Ok(false) => {}
                Err(e) => eprintln!("wire reactor: handler error for {}: {e}", ev.event_id),
            }
        }
        watcher.save_cursors(&cursor_path)?;
        Ok(fired)
    };

    if once {
        sweep(
            &mut watcher,
            &mut emitted_ids,
            &mut outbox_cursors,
            &mut peer_dispatch_log,
        )?;
        return Ok(());
    }
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    loop {
        if let Err(e) = sweep(
            &mut watcher,
            &mut emitted_ids,
            &mut outbox_cursors,
            &mut peer_dispatch_log,
        ) {
            eprintln!("wire reactor: sweep error: {e}");
        }
        std::thread::sleep(interval);
    }
}

/// Parse `(re:<event_id>)` marker out of an event body. Returns the
/// referenced event_id (full or prefix) if present. Tolerates spaces.
fn parse_re_marker(body: &str) -> Option<String> {
    let needle = "(re:";
    let i = body.find(needle)?;
    let rest = &body[i + needle.len()..];
    let end = rest.find(')')?;
    let id = rest[..end].trim().to_string();
    if id.is_empty() {
        return None;
    }
    Some(id)
}

// ---------- notify (Goal 2) ----------

fn cmd_notify(
    interval_secs: u64,
    peer_filter: Option<&str>,
    once: bool,
    as_json: bool,
) -> Result<()> {
    use crate::inbox_watch::InboxWatcher;
    let cursor_path = config::state_dir()?.join("notify.cursor");
    let mut watcher = InboxWatcher::from_cursor_file(&cursor_path)?;

    let sweep = |watcher: &mut InboxWatcher| -> Result<()> {
        let events = watcher.poll()?;
        for ev in events {
            if let Some(p) = peer_filter
                && ev.peer != p
            {
                continue;
            }
            if as_json {
                println!("{}", serde_json::to_string(&ev)?);
            } else {
                os_notify_inbox_event(&ev);
            }
        }
        watcher.save_cursors(&cursor_path)?;
        Ok(())
    };

    if once {
        return sweep(&mut watcher);
    }

    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    loop {
        if let Err(e) = sweep(&mut watcher) {
            eprintln!("wire notify: sweep error: {e}");
        }
        std::thread::sleep(interval);
    }
}

fn os_notify_inbox_event(ev: &crate::inbox_watch::InboxEvent) {
    let title = if ev.verified {
        format!("wire ← {}", ev.peer)
    } else {
        format!("wire ← {} (UNVERIFIED)", ev.peer)
    };
    let body = format!("{}: {}", ev.kind, ev.body_preview);
    crate::os_notify::toast(&title, &body);
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn os_toast(title: &str, body: &str) {
    eprintln!("[wire notify] {title}\n  {body}");
}

// Integration tests for the CLI live in `tests/cli.rs` (cargo's tests/ dir).
