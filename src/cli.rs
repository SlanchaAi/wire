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
    trust::{add_self_to_trust, empty_trust},
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
    ///
    /// Forms (P0.S 0.5.11):
    ///   wire send <peer> <body>              # kind defaults to "claim"
    ///   wire send <peer> <kind> <body>       # explicit kind (back-compat)
    ///   wire send <peer> -                   # body from stdin (kind=claim)
    ///   wire send <peer> @/path/to/body.json # body from file
    Send {
        /// Peer handle (without `did:wire:` prefix).
        peer: String,
        /// When `<body>` is omitted, this is the event body (kind defaults
        /// to `claim`). When both this and `<body>` are given, this is the
        /// event kind (`decision`, `claim`, etc., or numeric kind id) and
        /// the next positional is the body.
        kind_or_body: String,
        /// Event body — free-form text, `@/path/to/body.json` to load from
        /// a file, or `-` to read from stdin. Optional; omit to use
        /// `<kind_or_body>` as the body with kind=`claim`.
        body: Option<String>,
        /// Advisory deadline: duration (`30m`, `2h`, `1d`) or RFC3339 timestamp.
        #[arg(long)]
        deadline: Option<String>,
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
    /// Live tail of new inbox events across all pinned peers — one line per
    /// new event, handshake (pair_drop / pair_drop_ack / heartbeat) filtered
    /// by default.
    ///
    /// Designed to be left running in an agent harness's stream-watcher
    /// (Claude Code Monitor tool, etc.) so peer messages surface in the
    /// session as they arrive, not on next manual `wire pull`.
    ///
    /// See docs/AGENT_INTEGRATION.md for the recommended Monitor invocation
    /// template.
    Monitor {
        /// Only show events from this peer.
        #[arg(long)]
        peer: Option<String>,
        /// Emit JSONL (one InboxEvent per line) for tooling consumption.
        #[arg(long)]
        json: bool,
        /// Include handshake events (pair_drop, pair_drop_ack, heartbeat).
        /// Default filters them out as noise.
        #[arg(long)]
        include_handshake: bool,
        /// Poll interval in milliseconds. Lower = lower latency, higher CPU.
        #[arg(long, default_value_t = 500)]
        interval_ms: u64,
        /// Replay last N events from history before going live (0 = none).
        #[arg(long, default_value_t = 0)]
        replay: usize,
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
        /// v0.5.17: refuse non-loopback binds, skip phonebook listing,
        /// skip `.well-known/wire/agent` serving. The relay becomes
        /// invisible from outside the box — only same-machine processes
        /// can pair through it. Right call for within-machine agent
        /// coordination where you don't want metadata leaking to a
        /// public relay. Pair this with `wire session new` which probes
        /// `127.0.0.1:8771` and allocates a local slot automatically.
        #[arg(long)]
        local_only: bool,
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
        /// Inspect a paired peer's transport / attention / responder health.
        #[arg(long)]
        peer: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Publish or inspect auto-responder health for this slot.
    Responder {
        #[command(subcommand)]
        command: ResponderCommand,
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
        #[arg(long, default_value = "https://wireup.net")]
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
        #[arg(long, default_value = "https://wireup.net")]
        relay: String,
    },
    /// Accept a pending-inbound pair request (v0.5.14). Explicit alias for
    /// the bilateral-completion path that `wire add <peer>@<relay>` also
    /// drives — but doesn't require remembering the peer's relay domain
    /// (the relay coords come from the stored pair_drop). Errors if no
    /// pending-inbound record exists for that peer.
    PairAccept {
        /// Bare peer handle (without `@<relay>`).
        peer: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Reject a pending pair request (v0.5.14). When someone runs `wire add
    /// you@<your-relay>` against your handle, their signed pair_drop lands
    /// in pending-inbound — visible via `wire pair-list`. Run `wire pair-reject
    /// <peer>` to delete the record without pairing. The peer never receives
    /// our slot_token; from their side the pair stays pending until they
    /// time out.
    PairReject {
        /// Bare peer handle (without `@<relay>`).
        peer: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Programmatic-shape list of pending-inbound pair requests (v0.5.14).
    /// `--json` returns a flat array (matching the v0.5.13-and-earlier
    /// `pair-list --json` shape but for inbound). Use this in scripts that
    /// need to enumerate inbound pair requests without parsing the SPAKE2
    /// table format from `wire pair-list`.
    PairListInbound {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Manage isolated wire sessions on this machine (v0.5.16).
    ///
    /// Each session = its own DID + handle + relay slot + daemon + inbox/
    /// outbox tree. Use when multiple agents (e.g. Claude Code sessions
    /// in different projects) run on the same machine — without sessions
    /// they all share one identity and race the inbox cursor.
    ///
    /// Names are derived from `basename(cwd)` and cached in a registry,
    /// so re-entering the same project reuses the same identity.
    #[command(subcommand)]
    Session(SessionCommand),
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
    /// Zero-paste pair with a known handle. Resolves `nick@domain` via that
    /// domain's `.well-known/wire/agent`, then delivers a signed pair-intro
    /// to the peer's slot via `/v1/handle/intro`. Peer's daemon completes
    /// the bilateral pin on its next pull (sends back pair_drop_ack carrying
    /// their slot_token so we can `wire send` to them).
    Add {
        /// Peer handle (`nick@domain`).
        handle: String,
        /// Override the relay base URL used for resolution.
        #[arg(long)]
        relay: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// One-shot full bootstrap — `wire up <nick@relay-host>` does in one
    /// command what 0.5.10 took five (init + bind-relay + claim + daemon-
    /// background + remember-to-restart-on-login). Idempotent: re-run on
    /// an already-set-up box prints state without churn.
    ///
    /// Examples:
    ///   wire up paul@wireup.net           # full bootstrap
    ///   wire up paul-mac@wireup.net       # ditto, nick = paul-mac
    ///   wire up paul                      # bootstrap, default relay
    Up {
        /// Full handle in `nick@relay-host` form, or just `nick` (defaults
        /// to the configured public relay wireup.net).
        handle: String,
        /// Optional display name (defaults to capitalized nick).
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Diagnose wire setup health. Single command that surfaces every
    /// silent-fail class — daemon down or duplicated, relay unreachable,
    /// cursor stuck, pair rejections piling up, trust ↔ directory drift.
    /// Replaces today's 30-minute manual debug.
    ///
    /// Exit code non-zero if any FAIL findings.
    Doctor {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Show last N entries from pair-rejected.jsonl in the report.
        #[arg(long, default_value_t = 5)]
        recent_rejections: usize,
    },
    /// Atomic upgrade: kill every `wire daemon` process, spawn a fresh
    /// one from the current binary, write a new pidfile. Eliminates the
    /// "stale binary text in memory under a fresh symlink" bug class that
    /// burned 30 minutes today.
    Upgrade {
        /// Report drift without taking action (lists processes that would
        /// be killed + the version of each).
        #[arg(long)]
        check: bool,
        #[arg(long)]
        json: bool,
    },
    /// Install / inspect / remove a launchd plist (macOS) or systemd
    /// user unit (linux) that runs `wire daemon` on login + restarts
    /// on crash. Replaces today's "background it with tmux/&/systemd
    /// as you prefer" footgun.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Inspect or toggle the structured diagnostic trace
    /// (`$WIRE_HOME/state/wire/diag.jsonl`). Off by default. Enable per
    /// process via `WIRE_DIAG=1`, or per-machine via `wire diag enable`
    /// (writes the file knob a running daemon picks up automatically).
    Diag {
        #[command(subcommand)]
        action: DiagAction,
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
        #[arg(long, default_value = "https://wireup.net")]
        relay: String,
        /// Invite lifetime in seconds (default 86400 = 24h).
        #[arg(long, default_value_t = 86_400)]
        ttl: u64,
        /// Number of distinct peers that can accept this invite before it's
        /// consumed (default 1).
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// Register the invite at the relay's short-URL endpoint and print
        /// a `curl ... | sh` one-liner the peer can run on a fresh machine.
        /// Installs wire if missing, then accepts the invite, then pairs.
        #[arg(long)]
        share: bool,
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
pub enum DiagAction {
    /// Tail the last N entries from diag.jsonl.
    Tail {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Flip the file-based knob ON. Running daemons pick this up on
    /// the next emit call without restart.
    Enable,
    /// Flip the file-based knob OFF.
    Disable,
    /// Report whether diag is currently enabled + the file's size.
    Status {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum SessionCommand {
    /// Bootstrap a new isolated session in this machine's sessions root.
    /// With no name, derives one from `basename(cwd)` and caches it in
    /// the registry so re-running from the same project reuses it.
    /// Runs `init` + `claim` + spawns a session-local daemon, all inside
    /// the new session's WIRE_HOME. Output includes the `export
    /// WIRE_HOME=...` line operators paste into their shell to activate
    /// it.
    New {
        /// Optional session name. Default = derived from `basename(cwd)`.
        name: Option<String>,
        /// Relay URL for the session's slot allocation + handle claim.
        #[arg(long, default_value = "https://wireup.net")]
        relay: String,
        /// v0.5.17: also allocate a second slot on a same-machine local
        /// relay (defaults to `http://127.0.0.1:8771`). Within-machine
        /// sister-session traffic prefers this path: zero round-trip
        /// latency, zero metadata exposure to the public relay. Probes
        /// `<local-relay>/healthz` first; silently skips if the local
        /// relay isn't running.
        #[arg(long)]
        with_local: bool,
        /// v0.5.17: override the local relay URL probed by `--with-local`.
        /// Default is `http://127.0.0.1:8771` to match
        /// `wire relay-server --bind 127.0.0.1:8771 --local-only`.
        #[arg(long, default_value = "http://127.0.0.1:8771")]
        local_relay: String,
        /// Skip spawning the session-local daemon. Use when you want
        /// to drive sync explicitly from the agent or test rig.
        #[arg(long)]
        no_daemon: bool,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// List all sessions on this machine with their handle, DID,
    /// daemon liveness, and the cwd they're associated with.
    List {
        #[arg(long)]
        json: bool,
    },
    /// List sister sessions reachable via a same-machine local relay
    /// (v0.5.17 dual-slot). Groups sessions by the local-relay URL they
    /// share. Sessions without a Local-scope endpoint are listed
    /// separately so the operator can tell which are federation-only.
    /// Read-only — does not probe any relay or touch daemons.
    ListLocal {
        #[arg(long)]
        json: bool,
    },
    /// Print the `export WIRE_HOME=...` line for a session, so a shell
    /// can `eval $(wire session env <name>)` to activate it. With no
    /// name, resolves the cwd through the registry.
    Env {
        /// Session name. Default = derived from cwd via the registry.
        name: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Identify which session the current cwd maps to in the registry.
    /// Prints `(none)` if cwd isn't registered — `wire session new`
    /// would create one.
    Current {
        #[arg(long)]
        json: bool,
    },
    /// Tear down a session: kills its daemon (if running), deletes its
    /// state directory, and removes it from the registry. Requires
    /// `--force` because state loss is unrecoverable (keypair gone).
    Destroy {
        name: String,
        /// Confirm state-deleting operation.
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServiceAction {
    /// Write the launchd plist (macOS) or systemd user unit (linux) and
    /// load it. Idempotent — re-running re-bootstraps an existing service.
    Install {
        #[arg(long)]
        json: bool,
    },
    /// Unload + delete the service unit. Daemon keeps running until the
    /// next reboot or `wire upgrade`; this only changes the boot-time
    /// behaviour.
    Uninstall {
        #[arg(long)]
        json: bool,
    },
    /// Report whether the unit is installed + active.
    Status {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ResponderCommand {
    /// Publish this agent's auto-responder health.
    Set {
        /// One of: online, offline, oauth_locked, rate_limited, degraded.
        status: String,
        /// Optional operator-facing reason.
        #[arg(long)]
        reason: Option<String>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Read responder health for self, or for a paired peer.
    Get {
        /// Optional peer handle; omitted means this agent's own slot.
        peer: Option<String>,
        /// Emit JSON.
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
        Command::Status { peer, json } => {
            if let Some(peer) = peer {
                cmd_status_peer(&peer, json)
            } else {
                cmd_status(json)
            }
        }
        Command::Whoami { json } => cmd_whoami(json),
        Command::Peers { json } => cmd_peers(json),
        Command::Send {
            peer,
            kind_or_body,
            body,
            deadline,
            json,
        } => {
            // P0.S: smart-positional API. `wire send peer body` =
            // kind=claim. `wire send peer kind body` = explicit kind.
            let (kind, body) = match body {
                Some(real_body) => (kind_or_body, real_body),
                None => ("claim".to_string(), kind_or_body),
            };
            cmd_send(&peer, &kind, &body, deadline.as_deref(), json)
        }
        Command::Tail { peer, json, limit } => cmd_tail(peer.as_deref(), json, limit),
        Command::Monitor {
            peer,
            json,
            include_handshake,
            interval_ms,
            replay,
        } => cmd_monitor(peer.as_deref(), json, include_handshake, interval_ms, replay),
        Command::Verify { path, json } => cmd_verify(&path, json),
        Command::Responder { command } => match command {
            ResponderCommand::Set {
                status,
                reason,
                json,
            } => cmd_responder_set(&status, reason.as_deref(), json),
            ResponderCommand::Get { peer, json } => cmd_responder_get(peer.as_deref(), json),
        },
        Command::Mcp => cmd_mcp(),
        Command::RelayServer { bind, local_only } => cmd_relay_server(&bind, local_only),
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
            // P0.P (0.5.11): if the handle is in `nick@domain` form, route to
            // the zero-paste megacommand path — `wire pair slancha-spark@
            // wireup.net` does add + poll-for-ack + verify in one shot. The
            // SAS / code-based pair flow stays available for handles without
            // `@` (bootstrap pairing between two boxes that don't yet share a
            // relay directory).
            if handle.contains('@') && code.is_none() {
                cmd_pair_megacommand(&handle, Some(&relay), timeout, false)
            } else if detach {
                cmd_pair_detach(&handle, code.as_deref(), &relay)
            } else {
                cmd_pair(&handle, code.as_deref(), &relay, yes, timeout, no_setup)
            }
        }
        Command::PairAbandon { code_phrase, relay } => cmd_pair_abandon(&code_phrase, &relay),
        Command::PairAccept { peer, json } => cmd_pair_accept(&peer, json),
        Command::PairReject { peer, json } => cmd_pair_reject(&peer, json),
        Command::PairListInbound { json } => cmd_pair_list_inbound(json),
        Command::Session(cmd) => cmd_session(cmd),
        Command::Invite {
            relay,
            ttl,
            uses,
            share,
            json,
        } => cmd_invite(&relay, ttl, uses, share, json),
        Command::Accept { url, json } => cmd_accept(&url, json),
        Command::Whois {
            handle,
            json,
            relay,
        } => cmd_whois(handle.as_deref(), json, relay.as_deref()),
        Command::Add {
            handle,
            relay,
            json,
        } => cmd_add(&handle, relay.as_deref(), json),
        Command::Up {
            handle,
            name,
            json,
        } => cmd_up(&handle, name.as_deref(), json),
        Command::Doctor {
            json,
            recent_rejections,
        } => cmd_doctor(json, recent_rejections),
        Command::Upgrade { check, json } => cmd_upgrade(check, json),
        Command::Service { action } => cmd_service(action),
        Command::Diag { action } => cmd_diag(action),
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
        let normalized = url.trim_end_matches('/');
        let client = crate::relay_client::RelayClient::new(normalized);
        client.check_healthz()?;
        let alloc = client.allocate_slot(Some(handle))?;
        let mut state = config::read_relay_state()?;
        state["self"] = json!({
            "relay_url": normalized,
            "slot_id": alloc.slot_id.clone(),
            "slot_token": alloc.slot_token,
        });
        config::write_relay_state(&state)?;
        relay_info = Some((normalized.to_string(), alloc.slot_id));
    }

    let did_str = crate::agent_card::did_for_with_key(handle, &pk_bytes);
    if as_json {
        let mut out = json!({
            "did": did_str.clone(),
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
        println!("generated {did_str} (ed25519:{key_id})");
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
        // Prefer the explicit `handle` field added in v0.5.7. Fall back to
        // stripping the DID prefix (and the v0.5.7+ pubkey suffix) for
        // legacy cards.
        let handle = card
            .get("handle")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| crate::agent_card::display_handle_from_did(&did).to_string());
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
        let relay_state_for_tier = config::read_relay_state().unwrap_or_else(|_| json!({"peers": {}}));
        let mut peers = Vec::new();
        if let Some(agents) = trust.get("agents").and_then(Value::as_object) {
            for (peer_handle, _agent) in agents {
                if peer_handle == &handle {
                    continue; // self
                }
                // P0.Y (0.5.11): use effective tier — surfaces PENDING_ACK
                // for peers we've pinned but never received a pair_drop_ack
                // from, so the operator sees the "we can't send to them yet"
                // state instead of seeing a misleading VERIFIED.
                peers.push(json!({
                    "handle": peer_handle,
                    "tier": effective_peer_tier(&trust, &relay_state_for_tier, peer_handle),
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

        // P1.7 (0.5.11): daemon liveness now consults the structured
        // pidfile (P0.4) AND `pgrep -f "wire daemon"` to detect orphans
        // that the pidfile didn't record. Today's debug had a 4-day-old
        // 0.2.4 daemon (PID 54017) running while the pidfile pointed at
        // an unrelated dead PID — wire status said `daemon: DOWN` while
        // the box was actually full of stale-daemon-eating-events
        // behaviour. Catch THAT class here.
        let record = crate::ensure_up::read_pid_record("daemon");
        let pidfile_pid = record.pid();
        let pidfile_alive = pidfile_pid
            .map(|pid| {
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
            })
            .unwrap_or(false);

        // Cross-check with pgrep — surfaces orphan daemons not in pidfile.
        let pgrep_pids: Vec<u32> = std::process::Command::new("pgrep")
            .args(["-f", "wire daemon"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .filter_map(|s| s.parse::<u32>().ok())
                    .collect()
            })
            .unwrap_or_default();
        let orphan_pids: Vec<u32> = pgrep_pids
            .iter()
            .filter(|p| Some(**p) != pidfile_pid)
            .copied()
            .collect();

        let mut daemon = json!({
            "running": pidfile_alive,
            "pid": pidfile_pid,
            "all_running_pids": pgrep_pids,
            "orphans": orphan_pids,
        });
        if let crate::ensure_up::PidRecord::Json(d) = &record {
            daemon["version"] = json!(d.version);
            daemon["bin_path"] = json!(d.bin_path);
            daemon["did"] = json!(d.did);
            daemon["relay_url"] = json!(d.relay_url);
            daemon["started_at"] = json!(d.started_at);
            daemon["schema"] = json!(d.schema);
            if d.version != env!("CARGO_PKG_VERSION") {
                daemon["version_mismatch"] = json!({
                    "daemon": d.version.clone(),
                    "cli": env!("CARGO_PKG_VERSION"),
                });
            }
        } else if matches!(record, crate::ensure_up::PidRecord::LegacyInt(_)) {
            daemon["pidfile_form"] = json!("legacy-int");
            daemon["version_mismatch"] = json!({
                "daemon": "<pre-0.5.11>",
                "cli": env!("CARGO_PKG_VERSION"),
            });
        }
        summary["daemon"] = daemon;

        // Pending pair sessions — counts by status.
        let pending = crate::pending_pair::list_pending().unwrap_or_default();
        let mut counts: std::collections::BTreeMap<String, u32> = Default::default();
        for p in &pending {
            *counts.entry(p.status.clone()).or_default() += 1;
        }
        // v0.5.14: pending-inbound zero-paste pair_drops awaiting accept.
        let pending_inbound =
            crate::pending_inbound_pair::list_pending_inbound().unwrap_or_default();
        let inbound_handles: Vec<&str> = pending_inbound
            .iter()
            .map(|p| p.peer_handle.as_str())
            .collect();
        summary["pending_pairs"] = json!({
            "total": pending.len(),
            "by_status": counts,
            "inbound_count": pending_inbound.len(),
            "inbound_handles": inbound_handles,
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
        let daemon_version = summary["daemon"]["version"].as_str().unwrap_or("");
        let version_suffix = if !daemon_version.is_empty() {
            format!(" v{daemon_version}")
        } else {
            String::new()
        };
        println!(
            "daemon:        {} (pid {}{})",
            if daemon_running { "running" } else { "DOWN" },
            daemon_pid,
            version_suffix,
        );
        // P1.7: surface version mismatch + orphan procs loudly.
        if let Some(mm) = summary["daemon"].get("version_mismatch") {
            println!(
                "               !! version mismatch: daemon={} CLI={}. \
                 run `wire upgrade` to swap atomically.",
                mm["daemon"].as_str().unwrap_or("?"),
                mm["cli"].as_str().unwrap_or("?"),
            );
        }
        if let Some(orphans) = summary["daemon"]["orphans"].as_array()
            && !orphans.is_empty()
        {
            let pids: Vec<String> = orphans
                .iter()
                .filter_map(|v| v.as_u64().map(|p| p.to_string()))
                .collect();
            println!(
                "               !! orphan daemon process(es): pids {}. \
                 pgrep saw them but pidfile didn't — likely stale process from \
                 prior install. Multiple daemons race the relay cursor.",
                pids.join(", ")
            );
        }
        let pending_total = summary["pending_pairs"]["total"].as_u64().unwrap_or(0);
        let inbound_count = summary["pending_pairs"]["inbound_count"]
            .as_u64()
            .unwrap_or(0);
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
        } else if inbound_count == 0 {
            println!("pending pairs: none");
        }
        // v0.5.14: separate line for pending-inbound zero-paste requests.
        // Loud because each one is awaiting an operator gesture and the
        // capability hasn't flowed yet.
        if inbound_count > 0 {
            let handles: Vec<String> = summary["pending_pairs"]["inbound_handles"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            println!(
                "inbound pair requests ({inbound_count}): {} — `wire pair-list` to inspect, `wire pair-accept <peer>` to accept, `wire pair-reject <peer>` to refuse",
                handles.join(", "),
            );
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

// ---------- responder health ----------

fn responder_status_allowed(status: &str) -> bool {
    matches!(
        status,
        "online" | "offline" | "oauth_locked" | "rate_limited" | "degraded"
    )
}

fn relay_slot_for(peer: Option<&str>) -> Result<(String, String, String, String)> {
    let state = config::read_relay_state()?;
    let (label, slot_info) = match peer {
        Some(peer) => (
            peer.to_string(),
            state
                .get("peers")
                .and_then(|p| p.get(peer))
                .ok_or_else(|| {
                    anyhow!(
                        "unknown peer {peer:?} in relay state — pair with them first:\n  \
                         wire add {peer}@wireup.net   (or {peer}@<their-relay>)\n\
                         (`wire peers` lists who you've already paired with.)"
                    )
                })?,
        ),
        None => (
            "self".to_string(),
            state.get("self").filter(|v| !v.is_null()).ok_or_else(|| {
                anyhow!("self slot not bound — run `wire bind-relay <url>` first")
            })?,
        ),
    };
    let relay_url = slot_info["relay_url"]
        .as_str()
        .ok_or_else(|| anyhow!("{label} relay_url missing"))?
        .to_string();
    let slot_id = slot_info["slot_id"]
        .as_str()
        .ok_or_else(|| anyhow!("{label} slot_id missing"))?
        .to_string();
    let slot_token = slot_info["slot_token"]
        .as_str()
        .ok_or_else(|| anyhow!("{label} slot_token missing"))?
        .to_string();
    Ok((label, relay_url, slot_id, slot_token))
}

fn cmd_responder_set(status: &str, reason: Option<&str>, as_json: bool) -> Result<()> {
    if !responder_status_allowed(status) {
        bail!("status must be one of: online, offline, oauth_locked, rate_limited, degraded");
    }
    let (_label, relay_url, slot_id, slot_token) = relay_slot_for(None)?;
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let mut record = json!({
        "status": status,
        "set_at": now,
    });
    if let Some(reason) = reason {
        record["reason"] = json!(reason);
    }
    if status == "online" {
        record["last_success_at"] = json!(now);
    }
    let client = crate::relay_client::RelayClient::new(&relay_url);
    let saved = client.responder_health_set(&slot_id, &slot_token, &record)?;
    if as_json {
        println!("{}", serde_json::to_string(&saved)?);
    } else {
        let reason = saved
            .get("reason")
            .and_then(Value::as_str)
            .map(|r| format!(" — {r}"))
            .unwrap_or_default();
        println!(
            "responder {}{}",
            saved
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or(status),
            reason
        );
    }
    Ok(())
}

fn cmd_responder_get(peer: Option<&str>, as_json: bool) -> Result<()> {
    let (label, relay_url, slot_id, slot_token) = relay_slot_for(peer)?;
    let client = crate::relay_client::RelayClient::new(&relay_url);
    let health = client.responder_health_get(&slot_id, &slot_token)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "target": label,
                "responder_health": health,
            }))?
        );
    } else if health.is_null() {
        println!("{label}: responder health not reported");
    } else {
        let status = health
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let reason = health
            .get("reason")
            .and_then(Value::as_str)
            .map(|r| format!(" — {r}"))
            .unwrap_or_default();
        let last_success = health
            .get("last_success_at")
            .and_then(Value::as_str)
            .map(|t| format!(" (last_success: {t})"))
            .unwrap_or_default();
        println!("{label}: {status}{reason}{last_success}");
    }
    Ok(())
}

fn cmd_status_peer(peer: &str, as_json: bool) -> Result<()> {
    let (_label, relay_url, slot_id, slot_token) = relay_slot_for(Some(peer))?;
    let client = crate::relay_client::RelayClient::new(&relay_url);

    let started = std::time::Instant::now();
    let transport_ok = client.healthz().unwrap_or(false);
    let latency_ms = started.elapsed().as_millis() as u64;

    let (event_count, last_pull_at_unix) = client.slot_state(&slot_id, &slot_token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let attention = match last_pull_at_unix {
        Some(last) if now.saturating_sub(last) <= 300 => json!({
            "status": "ok",
            "last_pull_at_unix": last,
            "age_seconds": now.saturating_sub(last),
            "event_count": event_count,
        }),
        Some(last) => json!({
            "status": "stale",
            "last_pull_at_unix": last,
            "age_seconds": now.saturating_sub(last),
            "event_count": event_count,
        }),
        None => json!({
            "status": "never_pulled",
            "last_pull_at_unix": Value::Null,
            "event_count": event_count,
        }),
    };

    let responder_health = client.responder_health_get(&slot_id, &slot_token)?;
    let responder = if responder_health.is_null() {
        json!({"status": "not_reported", "record": Value::Null})
    } else {
        json!({
            "status": responder_health
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            "record": responder_health,
        })
    };

    let report = json!({
        "peer": peer,
        "transport": {
            "status": if transport_ok { "ok" } else { "error" },
            "relay_url": relay_url,
            "latency_ms": latency_ms,
        },
        "attention": attention,
        "responder": responder,
    });

    if as_json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        let transport_line = if transport_ok {
            format!("ok relay reachable ({latency_ms}ms)")
        } else {
            "error relay unreachable".to_string()
        };
        println!("transport      {transport_line}");
        match report["attention"]["status"].as_str().unwrap_or("unknown") {
            "ok" => println!(
                "attention      ok last pull {}s ago",
                report["attention"]["age_seconds"].as_u64().unwrap_or(0)
            ),
            "stale" => println!(
                "attention      stale last pull {}m ago",
                report["attention"]["age_seconds"].as_u64().unwrap_or(0) / 60
            ),
            "never_pulled" => println!("attention      never pulled since relay reset"),
            other => println!("attention      {other}"),
        }
        if report["responder"]["status"] == "not_reported" {
            println!("auto-responder not reported");
        } else {
            let record = &report["responder"]["record"];
            let status = record
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let reason = record
                .get("reason")
                .and_then(Value::as_str)
                .map(|r| format!(" — {r}"))
                .unwrap_or_default();
            println!("auto-responder {status}{reason}");
        }
    }
    Ok(())
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
    let handle = card
        .get("handle")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| crate::agent_card::display_handle_from_did(&did).to_string());
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

/// P0.Y (0.5.11): effective tier shown to operators. `wire add` pins a
/// peer's card into trust at VERIFIED immediately, but the bilateral pin
/// isn't complete until that peer's `pair_drop_ack` arrives carrying their
/// slot_token. Until then we CAN'T send to them. Displaying VERIFIED is
/// misleading — spark observed this in real usage.
///
/// Effective rules:
///   trust.tier == VERIFIED + relay_state.peers[h].slot_token empty -> "PENDING_ACK"
///   otherwise -> raw trust tier (UNTRUSTED / VERIFIED / etc.)
///
/// Strictly a display concern — trust state machine itself is untouched
/// so existing promote/demote logic still works.
fn effective_peer_tier(trust: &Value, relay_state: &Value, handle: &str) -> String {
    let raw = crate::trust::get_tier(trust, handle);
    if raw != "VERIFIED" {
        return raw.to_string();
    }
    let token = relay_state
        .get("peers")
        .and_then(|p| p.get(handle))
        .and_then(|p| p.get("slot_token"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if token.is_empty() {
        "PENDING_ACK".to_string()
    } else {
        raw.to_string()
    }
}

fn cmd_peers(as_json: bool) -> Result<()> {
    let trust = config::read_trust()?;
    let agents = trust
        .get("agents")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let relay_state = config::read_relay_state().unwrap_or_else(|_| json!({"peers": {}}));

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
        let tier = effective_peer_tier(&trust, &relay_state, handle);
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

/// R4 attentiveness pre-flight. Best-effort: any failure is silent.
///
/// Looks up `peer` in relay-state for slot_id + slot_token + relay_url, asks
/// the relay for the slot's `last_pull_at_unix`, and prints a warning to
/// stderr if the peer hasn't polled in > 5min (or never has). Threshold of
/// 300s is the same wire daemon polling cadence rule-of-thumb — a peer
/// hasn't crossed two heartbeats means probably degraded.
fn maybe_warn_peer_attentiveness(peer: &str) {
    let state = match config::read_relay_state() {
        Ok(s) => s,
        Err(_) => return,
    };
    let p = state.get("peers").and_then(|p| p.get(peer));
    let slot_id = match p.and_then(|p| p.get("slot_id")).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s,
        _ => return,
    };
    let slot_token = match p.and_then(|p| p.get("slot_token")).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s,
        _ => return,
    };
    let relay_url = match p.and_then(|p| p.get("relay_url")).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => match state
            .get("self")
            .and_then(|s| s.get("relay_url"))
            .and_then(Value::as_str)
        {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return,
        },
    };
    let client = crate::relay_client::RelayClient::new(&relay_url);
    let (_count, last_pull) = match client.slot_state(slot_id, slot_token) {
        Ok(t) => t,
        Err(_) => return,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match last_pull {
        None => {
            eprintln!(
                "phyllis: {peer}'s line is silent — relay sees no pulls yet. message will queue, but they may not be listening."
            );
        }
        Some(t) if now.saturating_sub(t) > 300 => {
            let mins = now.saturating_sub(t) / 60;
            eprintln!(
                "phyllis: {peer} hasn't picked up in {mins}m — message will queue, but they may be away."
            );
        }
        _ => {}
    }
}

pub(crate) fn parse_deadline_until(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if time::OffsetDateTime::parse(trimmed, &time::format_description::well_known::Rfc3339).is_ok()
    {
        return Ok(trimmed.to_string());
    }
    let (amount, unit) = trimmed.split_at(trimmed.len().saturating_sub(1));
    let n: i64 = amount
        .parse()
        .with_context(|| format!("deadline must be `30m`, `2h`, `1d`, or RFC3339: {input:?}"))?;
    if n <= 0 {
        bail!("deadline duration must be positive: {input:?}");
    }
    let duration = match unit {
        "m" => time::Duration::minutes(n),
        "h" => time::Duration::hours(n),
        "d" => time::Duration::days(n),
        _ => bail!("deadline must end in m, h, d, or be RFC3339: {input:?}"),
    };
    Ok((time::OffsetDateTime::now_utc() + duration)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()))
}

fn cmd_send(
    peer: &str,
    kind: &str,
    body_arg: &str,
    deadline: Option<&str>,
    as_json: bool,
) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let peer = crate::agent_card::bare_handle(peer);
    let sk_seed = config::read_private_key()?;
    let card = config::read_agent_card()?;
    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = crate::agent_card::display_handle_from_did(did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;

    // Body: literal string, `@/path/to/body.json`, or `-` for stdin.
    // P0.S (0.5.11): stdin support lets shells pipe in long content
    // without quoting/escaping ceremony, and supports heredocs naturally:
    //   wire send peer - <<EOF ... EOF
    let body_value: Value = if body_arg == "-" {
        use std::io::Read;
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .with_context(|| "reading body from stdin")?;
        // Try parsing as JSON first; fall back to string literal for
        // plain-text bodies.
        serde_json::from_str(raw.trim_end()).unwrap_or(Value::String(raw))
    } else if let Some(path) = body_arg.strip_prefix('@') {
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

    let mut event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now,
        "from": did,
        "to": format!("did:wire:{peer}"),
        "type": kind,
        "kind": kind_id,
        "body": body_value,
    });
    if let Some(deadline) = deadline {
        event["time_sensitive_until"] = json!(parse_deadline_until(deadline)?);
    }
    let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &handle)?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    // R4: best-effort attentiveness pre-flight. Look up the peer's slot
    // coords in relay-state and ask the relay how recently the peer pulled.
    // Warn on stderr if the peer hasn't pulled in >5min OR has never pulled.
    // Never blocks the send — the event still queues to outbox.
    maybe_warn_peer_attentiveness(peer);

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
                let deadline = event
                    .get("time_sensitive_until")
                    .and_then(Value::as_str)
                    .map(|d| format!(" deadline: {d}"))
                    .unwrap_or_default();
                println!("[{ts} {from} kind={kind} {kind_name}{deadline}] {summary} | sig {mark}");
            }
            count += 1;
            if limit > 0 && count >= limit {
                return Ok(());
            }
        }
    }
    Ok(())
}

// ---------- monitor (live-tail across all peers, harness-friendly) ----------

/// Events filtered out of `wire monitor` by default — pair handshake +
/// liveness pings. Operators almost never want these surfaced; an explicit
/// `--include-handshake` brings them back.
fn monitor_is_noise_kind(kind: &str) -> bool {
    matches!(kind, "pair_drop" | "pair_drop_ack" | "heartbeat")
}

/// Render a single InboxEvent for `wire monitor` output. JSON form emits the
/// full structured event for tooling consumption; the plain form is a tight
/// one-line summary suitable as a harness stream-watcher notification.
fn monitor_render(e: &crate::inbox_watch::InboxEvent, as_json: bool) -> Result<String> {
    if as_json {
        Ok(serde_json::to_string(e)?)
    } else {
        let eid_short: String = e.event_id.chars().take(12).collect();
        let body = e.body_preview.replace('\n', " ");
        let ts: String = e.timestamp.chars().take(19).collect();
        Ok(format!("[{ts}] {}/{} ({eid_short}) {body}", e.peer, e.kind))
    }
}

/// `wire monitor` — long-running line-per-event stream of new inbox events.
///
/// Built for agent harnesses that have an "every stdout line is a chat
/// notification" stream watcher (Claude Code Monitor tool, etc.). One
/// command, persistent, filtered. Replaces the manual `tail -F inbox/*.jsonl
/// | python parse | grep -v pair_drop` pipeline operators improvise on day
/// one of every wire session.
///
/// Default filter strips `pair_drop`, `pair_drop_ack`, and `heartbeat` —
/// pure handshake / liveness noise that operators almost never want
/// surfaced. Pass `--include-handshake` if you do.
///
/// Cursor: in-memory only. Starts from EOF (so a fresh `wire monitor`
/// doesn't drown the operator in replay), with optional `--replay N` to
/// emit the last N events first.
fn cmd_monitor(
    peer_filter: Option<&str>,
    as_json: bool,
    include_handshake: bool,
    interval_ms: u64,
    replay: usize,
) -> Result<()> {
    let inbox_dir = config::inbox_dir()?;
    if !inbox_dir.exists() {
        if !as_json {
            eprintln!(
                "wire monitor: inbox dir {inbox_dir:?} missing — has the daemon ever run?"
            );
        }
        // Still proceed — InboxWatcher::from_dir_head handles missing dir.
    }

    // Optional replay — read existing files and emit the last `replay` events
    // (post-filter) before going live. Useful when the harness restarts and
    // wants recent context.
    if replay > 0 && inbox_dir.exists() {
        let mut all: Vec<crate::inbox_watch::InboxEvent> = Vec::new();
        for entry in std::fs::read_dir(&inbox_dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let peer = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if let Some(filter) = peer_filter {
                if peer != filter {
                    continue;
                }
            }
            let body = std::fs::read_to_string(&path).unwrap_or_default();
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let signed: Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let ev = crate::inbox_watch::InboxEvent::from_signed(
                    &peer,
                    signed,
                    /* verified */ true,
                );
                if !include_handshake && monitor_is_noise_kind(&ev.kind) {
                    continue;
                }
                all.push(ev);
            }
        }
        // Sort by timestamp string (RFC3339-ish — lexicographic order matches
        // chronological for same-zoned timestamps).
        all.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let start = all.len().saturating_sub(replay);
        for ev in &all[start..] {
            println!("{}", monitor_render(ev, as_json)?);
        }
        use std::io::Write;
        std::io::stdout().flush().ok();
    }

    // Live loop. InboxWatcher::from_head() seeds cursors at current EOF, so
    // the first poll only returns events that arrived AFTER startup.
    let mut w = crate::inbox_watch::InboxWatcher::from_head()?;
    let sleep_dur = std::time::Duration::from_millis(interval_ms.max(50));

    loop {
        let events = w.poll()?;
        let mut wrote = false;
        for ev in events {
            if let Some(filter) = peer_filter {
                if ev.peer != filter {
                    continue;
                }
            }
            if !include_handshake && monitor_is_noise_kind(&ev.kind) {
                continue;
            }
            println!("{}", monitor_render(&ev, as_json)?);
            wrote = true;
        }
        if wrote {
            use std::io::Write;
            std::io::stdout().flush().ok();
        }
        std::thread::sleep(sleep_dur);
    }
}

#[cfg(test)]
mod tier_tests {
    use super::*;
    use serde_json::json;

    fn trust_with(handle: &str, tier: &str) -> Value {
        json!({
            "version": 1,
            "agents": {
                handle: {
                    "tier": tier,
                    "did": format!("did:wire:{handle}"),
                    "card": {"capabilities": ["wire/v3.1"]}
                }
            }
        })
    }

    #[test]
    fn pending_ack_when_verified_but_no_slot_token() {
        // P0.Y rule: after `wire add`, trust says VERIFIED but the peer's
        // slot_token hasn't arrived yet. Display PENDING_ACK so the
        // operator knows wire send won't work yet.
        let trust = trust_with("willard", "VERIFIED");
        let relay_state = json!({
            "peers": {
                "willard": {
                    "relay_url": "https://relay",
                    "slot_id": "abc",
                    "slot_token": "",
                }
            }
        });
        assert_eq!(
            effective_peer_tier(&trust, &relay_state, "willard"),
            "PENDING_ACK"
        );
    }

    #[test]
    fn verified_when_slot_token_present() {
        let trust = trust_with("willard", "VERIFIED");
        let relay_state = json!({
            "peers": {
                "willard": {
                    "relay_url": "https://relay",
                    "slot_id": "abc",
                    "slot_token": "tok123",
                }
            }
        });
        assert_eq!(
            effective_peer_tier(&trust, &relay_state, "willard"),
            "VERIFIED"
        );
    }

    #[test]
    fn raw_tier_passes_through_for_non_verified() {
        // PENDING_ACK should ONLY decorate VERIFIED. UNTRUSTED stays
        // UNTRUSTED regardless of slot_token state.
        let trust = trust_with("willard", "UNTRUSTED");
        let relay_state = json!({
            "peers": {"willard": {"slot_token": ""}}
        });
        assert_eq!(
            effective_peer_tier(&trust, &relay_state, "willard"),
            "UNTRUSTED"
        );
    }

    #[test]
    fn pending_ack_when_relay_state_missing_peer() {
        // After wire add, trust gets updated BEFORE relay_state.peers does.
        // If relay_state has no entry for the peer at all, the operator
        // still hasn't completed the bilateral pin — show PENDING_ACK.
        let trust = trust_with("willard", "VERIFIED");
        let relay_state = json!({"peers": {}});
        assert_eq!(
            effective_peer_tier(&trust, &relay_state, "willard"),
            "PENDING_ACK"
        );
    }
}

#[cfg(test)]
mod monitor_tests {
    use super::*;
    use crate::inbox_watch::InboxEvent;
    use serde_json::Value;

    fn ev(peer: &str, kind: &str, body: &str) -> InboxEvent {
        InboxEvent {
            peer: peer.to_string(),
            event_id: "abcd1234567890ef".to_string(),
            kind: kind.to_string(),
            body_preview: body.to_string(),
            verified: true,
            timestamp: "2026-05-15T23:14:07.123456Z".to_string(),
            raw: Value::Null,
        }
    }

    #[test]
    fn monitor_filter_drops_handshake_kinds_by_default() {
        // The whole point: pair_drop / pair_drop_ack / heartbeat are
        // protocol noise. If they leak into the operator's chat stream by
        // default, the recipe is useless ("wire monitor talks too much,
        // disabled it"). Burn this rule in.
        assert!(monitor_is_noise_kind("pair_drop"));
        assert!(monitor_is_noise_kind("pair_drop_ack"));
        assert!(monitor_is_noise_kind("heartbeat"));

        // Real-payload kinds — operator wants every one.
        assert!(!monitor_is_noise_kind("claim"));
        assert!(!monitor_is_noise_kind("decision"));
        assert!(!monitor_is_noise_kind("ack"));
        assert!(!monitor_is_noise_kind("request"));
        assert!(!monitor_is_noise_kind("note"));
        // Unknown future kinds shouldn't be filtered as noise either —
        // operator probably wants to see something they don't recognise,
        // not have it silently dropped (the P0.1 lesson at the UX layer).
        assert!(!monitor_is_noise_kind("future_kind_we_dont_know"));
    }

    #[test]
    fn monitor_render_plain_is_one_short_line() {
        let e = ev("willard", "claim", "real v8 train shipped 1350 steps");
        let line = monitor_render(&e, false).unwrap();
        // Must be single-line.
        assert!(!line.contains('\n'), "render must be one line: {line}");
        // Must include peer, kind, body fragment, short event_id.
        assert!(line.contains("willard"));
        assert!(line.contains("claim"));
        assert!(line.contains("real v8 train"));
        // Short event id (first 12 chars).
        assert!(line.contains("abcd12345678"));
        assert!(!line.contains("abcd1234567890ef"), "should truncate full id");
        // RFC3339-ish second precision.
        assert!(line.contains("2026-05-15T23:14:07"));
    }

    #[test]
    fn monitor_render_strips_newlines_from_body() {
        // Multi-line bodies (markdown lists, code, etc.) must collapse to
        // one line — otherwise a single message produces multiple
        // notifications in the harness, ruining the "one event = one line"
        // contract the Monitor tool relies on.
        let e = ev("spark", "claim", "line one\nline two\nline three");
        let line = monitor_render(&e, false).unwrap();
        assert!(!line.contains('\n'), "newlines must be stripped: {line}");
        assert!(line.contains("line one line two line three"));
    }

    #[test]
    fn monitor_render_json_is_valid_jsonl() {
        let e = ev("spark", "claim", "hi");
        let line = monitor_render(&e, true).unwrap();
        assert!(!line.contains('\n'));
        let parsed: Value = serde_json::from_str(&line).expect("valid JSONL");
        assert_eq!(parsed["peer"], "spark");
        assert_eq!(parsed["kind"], "claim");
        assert_eq!(parsed["body_preview"], "hi");
    }

    #[test]
    fn monitor_does_not_drop_on_verified_null() {
        // Spark's bug confession on 2026-05-15: their monitor pipeline ran
        // `select(.verified == true)` against inbox JSONL. Daemon writes
        // events with verified=null (verification happens at tail-time, not
        // write-time), so the filter silently rejected everything — same
        // anti-pattern as P0.1 at the JSON-jq level. Cost: 4 of my events
        // never surfaced for ~30min.
        //
        // wire monitor's render path must NOT consult `.verified` for any
        // filter decision. Lock that in here so a future "be conservative,
        // only emit verified" patch can't quietly land.
        let mut e = ev("spark", "claim", "from disk with verified=null");
        e.verified = false; // worst case — even if disk says unverified, emit
        let line = monitor_render(&e, false).unwrap();
        assert!(line.contains("from disk with verified=null"));
        // Noise filter operates purely on kind, never on verified.
        assert!(!monitor_is_noise_kind("claim"));
    }
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

fn cmd_relay_server(bind: &str, local_only: bool) -> Result<()> {
    // v0.5.17: --local-only refuses non-loopback binds. Catches the
    // "wait did I just bind a publicly-reachable local-only relay" mistake
    // at startup rather than discovering it via an empty phonebook later.
    if local_only {
        validate_loopback_bind(bind)?;
    }
    // Default state dir for the relay process: $WIRE_HOME/state/wire-relay
    // (or `dirs::state_dir()/wire-relay`). Distinct from the CLI's state dir
    // so a single user can run both client and server on one machine.
    // For --local-only, suffix with /local so a single operator can run
    // both a federation relay and a local-only relay without state collision.
    let base = if let Ok(home) = std::env::var("WIRE_HOME") {
        std::path::PathBuf::from(home)
            .join("state")
            .join("wire-relay")
    } else {
        dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .ok_or_else(|| anyhow::anyhow!("could not resolve XDG_STATE_HOME — set WIRE_HOME"))?
            .join("wire-relay")
    };
    let state_dir = if local_only { base.join("local") } else { base };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(crate::relay_server::serve_with_mode(
        bind,
        state_dir,
        crate::relay_server::ServerMode { local_only },
    ))
}

/// v0.5.17 loopback-bind guard. Refuses any address whose host portion
/// resolves to something outside `127.0.0.0/8` or `::1`. Specifically
/// rejects `0.0.0.0`, `::`, `0:0:0:0:0:0:0:0`, and any non-loopback
/// IPv4/IPv6 literal. Hostname-form addresses (e.g. `localhost`) are
/// accepted only if they resolve to a loopback address.
fn validate_loopback_bind(bind: &str) -> Result<()> {
    // Split host:port. IPv6 literals use `[::]:port` form.
    let host = if let Some(stripped) = bind.strip_prefix('[') {
        let close = stripped
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("malformed IPv6 bind {bind:?}"))?;
        stripped[..close].to_string()
    } else {
        bind.rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| bind.to_string())
    };
    use std::net::ToSocketAddrs;
    let probe = format!("{host}:0");
    let resolved: Vec<_> = probe
        .to_socket_addrs()
        .with_context(|| format!("resolving bind host {host:?}"))?
        .collect();
    if resolved.is_empty() {
        bail!("--local-only: bind host {host:?} resolved to no addresses");
    }
    for addr in &resolved {
        if !addr.ip().is_loopback() {
            bail!(
                "--local-only refuses non-loopback bind: {host:?} resolves to {} \
                 which is not in 127.0.0.0/8 or [::1]. Remove --local-only to bind \
                 publicly, or use 127.0.0.1 / [::1] / localhost.",
                addr.ip()
            );
        }
    }
    Ok(())
}

// ---------- bind-relay ----------

fn cmd_bind_relay(url: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let card = config::read_agent_card()?;
    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = crate::agent_card::display_handle_from_did(did).to_string();

    let normalized = url.trim_end_matches('/');
    let client = crate::relay_client::RelayClient::new(normalized);
    client.check_healthz()?;
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
    // v0.5.13 loud-fail: warn on outbox files that don't match a pinned peer.
    // Pre-v0.5.13 `wire send peer@relay` wrote to `peer@relay.jsonl` while
    // push only enumerated bare-handle files. After upgrade, stale FQDN-named
    // files sit on disk forever; warn so operator can `cat fqdn.jsonl >> handle.jsonl`.
    if outbox_dir.exists() {
        let pinned: std::collections::HashSet<String> = peers.keys().cloned().collect();
        for entry in std::fs::read_dir(&outbox_dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if pinned.contains(&stem) {
                continue;
            }
            // Try the bare-handle of the orphaned stem — if THAT matches a
            // pinned peer, the stem is a stale FQDN-suffixed file.
            let bare = crate::agent_card::bare_handle(&stem);
            if pinned.contains(bare) {
                eprintln!(
                    "wire push: WARN stale outbox file `{}.jsonl` not enumerated (pinned peer is `{bare}`). \
                     Merge with: `cat {} >> {}` then delete the FQDN file.",
                    stem,
                    path.display(),
                    outbox_dir.join(format!("{bare}.jsonl")).display(),
                );
            }
        }
    }
    if !outbox_dir.exists() {
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({"pushed": [], "skipped": []}))?
            );
        } else {
            println!("phyllis: nothing to dial out — write a message first with `wire send`");
        }
        return Ok(());
    }

    let mut pushed = Vec::new();
    let mut skipped = Vec::new();

    // v0.5.17: walk each peer's pinned endpoints in priority order (local
    // first if we share a local relay, federation second). Try POST on the
    // first endpoint; on transport failure, fall through to the next.
    // Falls back to the v0.5.16 legacy single-endpoint code path when the
    // peer record carries no `endpoints[]` array (back-compat).
    for (peer_handle, _) in peers.iter() {
        if let Some(want) = peer_filter
            && peer_handle != want
        {
            continue;
        }
        let outbox = outbox_dir.join(format!("{peer_handle}.jsonl"));
        if !outbox.exists() {
            continue;
        }
        let ordered_endpoints =
            crate::endpoints::peer_endpoints_in_priority_order(&state, peer_handle);
        if ordered_endpoints.is_empty() {
            // Unreachable peer (no federation endpoint AND our local
            // relay doesn't match the peer's). Skip with a loud reason
            // rather than silently dropping events.
            for line in std::fs::read_to_string(&outbox)
                .unwrap_or_default()
                .lines()
            {
                let event: Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let event_id = event
                    .get("event_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                skipped.push(json!({
                    "peer": peer_handle,
                    "event_id": event_id,
                    "reason": "no reachable endpoint pinned for peer",
                }));
            }
            continue;
        }
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

            let mut delivered = false;
            let mut last_err_reason: Option<String> = None;
            for endpoint in &ordered_endpoints {
                let client = crate::relay_client::RelayClient::new(&endpoint.relay_url);
                match client.post_event(&endpoint.slot_id, &endpoint.slot_token, &event) {
                    Ok(resp) => {
                        if resp.status == "duplicate" {
                            skipped.push(json!({
                                "peer": peer_handle,
                                "event_id": event_id,
                                "reason": "duplicate",
                                "endpoint": endpoint.relay_url,
                                "scope": serde_json::to_value(endpoint.scope).unwrap_or(json!("?")),
                            }));
                        } else {
                            pushed.push(json!({
                                "peer": peer_handle,
                                "event_id": event_id,
                                "endpoint": endpoint.relay_url,
                                "scope": serde_json::to_value(endpoint.scope).unwrap_or(json!("?")),
                            }));
                        }
                        delivered = true;
                        break;
                    }
                    Err(e) => {
                        // Local-first endpoint failed; record reason and
                        // try the next endpoint silently (operator sees
                        // the federation success). If every endpoint
                        // fails, the last reason is what gets reported.
                        last_err_reason =
                            Some(crate::relay_client::format_transport_error(&e));
                    }
                }
            }
            if !delivered {
                skipped.push(json!({
                    "peer": peer_handle,
                    "event_id": event_id,
                    "reason": last_err_reason.unwrap_or_else(|| "all endpoints failed".to_string()),
                }));
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

    // v0.5.17: pull from every endpoint in self.endpoints (federation +
    // optional local). Each endpoint has its own per-scope cursor so we
    // don't re-pull events we've already seen on that path. Events from
    // all endpoints feed into the same inbox JSONL via process_events;
    // dedup by event_id is the last line of defense.
    // Falls back to a single federation endpoint synthesized from the
    // top-level legacy fields when self.endpoints is absent (v0.5.16
    // back-compat).
    let endpoints = crate::endpoints::self_endpoints(&state);
    if endpoints.is_empty() {
        bail!("self.relay_url / slot_id / slot_token missing in relay_state.json");
    }

    let inbox_dir = config::inbox_dir()?;
    config::ensure_dirs()?;

    let mut total_seen = 0usize;
    let mut all_written: Vec<Value> = Vec::new();
    let mut all_rejected: Vec<Value> = Vec::new();
    let mut all_blocked = false;
    let mut all_advance_cursor_to: Option<String> = None;

    for endpoint in &endpoints {
        let cursor_key = endpoint_cursor_key(endpoint.scope);
        let last_event_id = self_state
            .get(&cursor_key)
            .and_then(Value::as_str)
            .map(str::to_string);
        let client = crate::relay_client::RelayClient::new(&endpoint.relay_url);
        let events = match client.list_events(
            &endpoint.slot_id,
            &endpoint.slot_token,
            last_event_id.as_deref(),
            Some(1000),
        ) {
            Ok(ev) => ev,
            Err(e) => {
                // One endpoint's failure shouldn't kill the whole pull.
                // The local-relay-down case in particular needs to
                // gracefully continue against federation.
                eprintln!(
                    "wire pull: endpoint {} ({:?}) errored: {}; continuing",
                    endpoint.relay_url,
                    endpoint.scope,
                    crate::relay_client::format_transport_error(&e),
                );
                continue;
            }
        };
        total_seen += events.len();
        let result = crate::pull::process_events(&events, last_event_id.clone(), &inbox_dir)?;
        all_written.extend(result.written.iter().cloned());
        all_rejected.extend(result.rejected.iter().cloned());
        if result.blocked {
            all_blocked = true;
        }
        // Advance per-endpoint cursor. The cursor key is scope-specific
        // so federation and local don't trample each other.
        if let Some(eid) = result.advance_cursor_to.clone() {
            if endpoint.scope == crate::endpoints::EndpointScope::Federation {
                all_advance_cursor_to = Some(eid.clone());
            }
            let key = cursor_key.clone();
            config::update_relay_state(|state| {
                if let Some(self_obj) = state.get_mut("self").and_then(Value::as_object_mut) {
                    self_obj.insert(key, Value::String(eid));
                }
                Ok(())
            })?;
        }
    }

    // Compatibility shim for the legacy single-cursor code paths below:
    // `result` used to come from one process_events call; we now have
    // per-endpoint results aggregated into the all_* accumulators.
    // Reconstruct a synthetic result for the remaining display logic.
    let result = crate::pull::PullResult {
        written: all_written,
        rejected: all_rejected,
        blocked: all_blocked,
        advance_cursor_to: all_advance_cursor_to,
    };
    let events_len = total_seen;

    // Cursor advance happened per-endpoint above; no aggregate cursor
    // write needed here.

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "written": result.written,
                "rejected": result.rejected,
                "total_seen": events_len,
                "cursor_blocked": result.blocked,
                "cursor_advanced_to": result.advance_cursor_to,
            }))?
        );
    } else {
        let blocking = result
            .rejected
            .iter()
            .filter(|r| r.get("blocks_cursor").and_then(Value::as_bool) == Some(true))
            .count();
        if blocking > 0 {
            println!(
                "pulled {} event(s); wrote {}; rejected {} ({} BLOCKING cursor — see `wire pull --json`)",
                events_len,
                result.written.len(),
                result.rejected.len(),
                blocking,
            );
        } else {
            println!(
                "pulled {} event(s); wrote {}; rejected {}",
                events_len,
                result.written.len(),
                result.rejected.len(),
            );
        }
    }
    Ok(())
}

/// v0.5.17: cursor key for an endpoint's per-scope read position.
/// Federation keeps the v0.5.16 legacy key `last_pulled_event_id` for
/// back-compat with on-disk relay_state files; local uses a
/// `_local` suffix.
fn endpoint_cursor_key(scope: crate::endpoints::EndpointScope) -> String {
    match scope {
        crate::endpoints::EndpointScope::Federation => "last_pulled_event_id".to_string(),
        crate::endpoints::EndpointScope::Local => "last_pulled_event_id_local".to_string(),
    }
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
    let handle = crate::agent_card::display_handle_from_did(&did).to_string();
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
    let normalized = url.trim_end_matches('/').to_string();
    let client = crate::relay_client::RelayClient::new(&normalized);
    client
        .check_healthz()
        .context("aborting rotation; old slot still valid")?;
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
                "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
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

    // R1 phase 2: spawn the SSE stream subscriber. On every event pushed
    // to our slot, the subscriber signals `wake_rx`; we use it as the
    // sleep-or-wake gate of the polling loop. Polling stays as the
    // safety net — stream errors fall back transparently to the existing
    // interval-based cadence.
    let (wake_tx, wake_rx) = std::sync::mpsc::channel::<()>();
    if !once {
        crate::daemon_stream::spawn_stream_subscriber(wake_tx);
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
        // Wait either for the next poll-interval tick OR for a stream
        // wake signal — whichever comes first. Drain any additional
        // wake-ups that accumulated during the previous cycle since one
        // pull catches up everything.
        let _ = wake_rx.recv_timeout(interval);
        while wake_rx.try_recv().is_ok() {}
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
                    // v0.5.13: flatten the anyhow chain so TLS / DNS / timeout
                    // errors aren't hidden behind the topmost-context URL string.
                    // Issue #6 highest-impact silent-fail fix.
                    let reason = crate::relay_client::format_transport_error(&e);
                    skipped.push(
                        json!({"peer": peer_handle, "event_id": event_id, "reason": reason}),
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
    let inbox_dir = config::inbox_dir()?;
    config::ensure_dirs()?;

    // P0.1 (0.5.11): shared cursor-blocking logic. Daemon's --once path
    // must match the CLI's `wire pull` semantics or version-skew bugs
    // re-emerge by another route.
    let result = crate::pull::process_events(&events, last_event_id, &inbox_dir)?;

    // P0.3 (0.5.11): same flock-protected RMW as cmd_pull.
    if let Some(eid) = &result.advance_cursor_to {
        let eid = eid.clone();
        config::update_relay_state(|state| {
            if let Some(self_obj) = state.get_mut("self").and_then(Value::as_object_mut) {
                self_obj.insert("last_pulled_event_id".into(), Value::String(eid));
            }
            Ok(())
        })?;
    }

    Ok(json!({
        "written": result.written,
        "rejected": result.rejected,
        "total_seen": events.len(),
        "cursor_blocked": result.blocked,
        "cursor_advanced_to": result.advance_cursor_to,
    }))
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
    let handle = crate::agent_card::display_handle_from_did(did).to_string();
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
    let spake2_items = crate::pending_pair::list_pending()?;
    let inbound_items = crate::pending_inbound_pair::list_pending_inbound()?;
    if as_json {
        // Backwards-compat: flat SPAKE2 array (the shape every existing
        // script + e2e test parses since v0.5.x). v0.5.14 inbound items
        // surface programmatically via `wire pair-list-inbound --json`
        // and via `wire status --json` `pending_pairs.inbound_*` fields.
        println!("{}", serde_json::to_string(&spake2_items)?);
        return Ok(());
    }
    if spake2_items.is_empty() && inbound_items.is_empty() {
        println!("no pending pair sessions.");
        return Ok(());
    }
    // v0.5.14: inbound section first — these need operator action right now.
    // SPAKE2 sessions are typically already mid-flow.
    if !inbound_items.is_empty() {
        println!("PENDING INBOUND (v0.5.14 zero-paste pair_drop awaiting your accept)");
        println!(
            "{:<20} {:<35} {:<25} NEXT STEP",
            "PEER", "RELAY", "RECEIVED"
        );
        for p in &inbound_items {
            println!(
                "{:<20} {:<35} {:<25} `wire pair-accept {peer}` to accept; `wire pair-reject {peer}` to refuse",
                p.peer_handle,
                p.peer_relay_url,
                p.received_at,
                peer = p.peer_handle,
            );
        }
        println!();
    }
    if !spake2_items.is_empty() {
        println!("SPAKE2 SESSIONS");
        println!(
            "{:<15} {:<8} {:<18} {:<10} NOTE",
            "CODE", "ROLE", "STATUS", "SAS"
        );
        for p in spake2_items {
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

fn cmd_invite(relay: &str, ttl: u64, uses: u32, share: bool, as_json: bool) -> Result<()> {
    let url = crate::pair_invite::mint_invite(Some(ttl), uses, Some(relay))?;

    // If --share, register the invite at the relay's short-URL endpoint and
    // build the one-curl onboarding line for the peer to paste.
    let share_payload: Option<Value> = if share {
        let client = reqwest::blocking::Client::new();
        let single_use = if uses == 1 { Some(1u32) } else { None };
        let body = json!({
            "invite_url": url,
            "ttl_seconds": ttl,
            "uses": single_use,
        });
        let endpoint = format!("{}/v1/invite/register", relay.trim_end_matches('/'));
        let resp = client.post(&endpoint).json(&body).send()?;
        if !resp.status().is_success() {
            let code = resp.status();
            let txt = resp.text().unwrap_or_default();
            bail!("relay {code} on /v1/invite/register: {txt}");
        }
        let parsed: Value = resp.json()?;
        let token = parsed
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("relay reply missing token"))?
            .to_string();
        let share_url = format!("{}/i/{}", relay.trim_end_matches('/'), token);
        let curl_line = format!("curl -fsSL {share_url} | sh");
        Some(json!({
            "token": token,
            "share_url": share_url,
            "curl": curl_line,
            "expires_unix": parsed.get("expires_unix"),
        }))
    } else {
        None
    };

    if as_json {
        let mut out = json!({
            "invite_url": url,
            "ttl_secs": ttl,
            "uses": uses,
            "relay": relay,
        });
        if let Some(s) = &share_payload {
            out["share"] = s.clone();
        }
        println!("{}", serde_json::to_string(&out)?);
    } else if let Some(s) = share_payload {
        let curl = s.get("curl").and_then(Value::as_str).unwrap_or("");
        eprintln!("# One-curl onboarding. Share this single line — installs wire if missing,");
        eprintln!("# accepts the invite, pairs both sides. TTL: {ttl}s. Uses: {uses}.");
        println!("{curl}");
    } else {
        eprintln!("# Share this URL with one peer. Pasting it = pair complete on their side.");
        eprintln!("# TTL: {ttl}s. Uses: {uses}.");
        println!("{url}");
    }
    Ok(())
}

fn cmd_accept(url: &str, as_json: bool) -> Result<()> {
    // If the user pasted an HTTP(S) short URL (e.g. https://wireup.net/i/AB12),
    // resolve it to the underlying wire://pair?... URL via ?format=url before
    // accepting. Saves them from having to know which URL shape goes where.
    let resolved = if url.starts_with("http://") || url.starts_with("https://") {
        let sep = if url.contains('?') { '&' } else { '?' };
        let resolve_url = format!("{url}{sep}format=url");
        let client = reqwest::blocking::Client::new();
        let resp = client
            .get(&resolve_url)
            .send()
            .with_context(|| format!("GET {resolve_url}"))?;
        if !resp.status().is_success() {
            bail!("could not resolve short URL {url} (HTTP {})", resp.status());
        }
        let body = resp.text().unwrap_or_default().trim().to_string();
        if !body.starts_with("wire://pair?") {
            bail!(
                "short URL {url} did not resolve to a wire:// invite. \
                 (got: {}{})",
                body.chars().take(80).collect::<String>(),
                if body.chars().count() > 80 { "…" } else { "" }
            );
        }
        body
    } else {
        url.to_string()
    };

    let result = crate::pair_invite::accept_invite(&resolved)?;
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
            crate::agent_card::display_handle_from_did(did)
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

/// `wire add <nick@domain>` — zero-paste pair. Resolve handle, build a
/// signed pair_drop event with our card + slot coords, deliver via the
/// peer relay's `/v1/handle/intro/<nick>` endpoint (no slot_token needed).
/// Peer's daemon completes the bilateral pin on its next pull and emits a
/// pair_drop_ack carrying their slot_token so we can send back.
fn cmd_add(handle_arg: &str, relay_override: Option<&str>, as_json: bool) -> Result<()> {
    let parsed = crate::pair_profile::parse_handle(handle_arg)?;

    // 1. Auto-init self if needed + ensure a relay slot.
    let (our_did, our_relay, our_slot_id, our_slot_token) =
        crate::pair_invite::ensure_self_with_relay(relay_override)?;
    if our_did == format!("did:wire:{}", parsed.nick) {
        // Lazy guard — actual self-add would also be caught by FCFS later.
        bail!("refusing to add self (handle matches own DID)");
    }

    // v0.5.14 bilateral-completion path: if a pair_drop from this peer is
    // already sitting in pending-inbound, the operator is now accepting it.
    // Pin trust, save relay coords + slot_token from the stored drop, ship
    // our own slot_token back via pair_drop_ack, delete the pending record.
    //
    // This branch is the OTHER half of the v0.5.14 fix to maybe_consume_pair_drop:
    // receiver-side auto-promote was removed there; operator consent flows
    // through here. After this branch returns, both sides are bilaterally
    // pinned and capability flows in both directions.
    if let Some(pending) = crate::pending_inbound_pair::read_pending_inbound(&parsed.nick)? {
        return cmd_add_accept_pending(
            handle_arg,
            &parsed.nick,
            &pending,
            &our_relay,
            &our_slot_id,
            &our_slot_token,
            as_json,
        );
    }

    // 2. Resolve peer via .well-known on their relay.
    let resolved = crate::pair_profile::resolve_handle(&parsed, relay_override)?;
    let peer_card = resolved
        .get("card")
        .cloned()
        .ok_or_else(|| anyhow!("resolved missing card"))?;
    let peer_did = resolved
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("resolved missing did"))?
        .to_string();
    let peer_handle = crate::agent_card::display_handle_from_did(&peer_did).to_string();
    let peer_slot_id = resolved
        .get("slot_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("resolved missing slot_id"))?
        .to_string();
    let peer_relay = resolved
        .get("relay_url")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| relay_override.map(str::to_string))
        .unwrap_or_else(|| format!("https://{}", parsed.domain));

    // 3. Pin peer in trust + relay-state. slot_token will arrive via ack.
    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &peer_card, Some("VERIFIED"));
    config::write_trust(&trust)?;
    let mut relay_state = config::read_relay_state()?;
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
        "slot_token": existing_token, // empty until pair_drop_ack lands
    });
    config::write_relay_state(&relay_state)?;

    // 4. Build signed pair_drop with our card + coords (no pair_nonce — this
    // is the v0.5 zero-paste open-mode path).
    let our_card = config::read_agent_card()?;
    let sk_seed = config::read_private_key()?;
    let our_handle = crate::agent_card::display_handle_from_did(&our_did).to_string();
    let pk_b64 = our_card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("our card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    // v0.5.17: advertise all our endpoints (federation + optional local)
    // to the peer in the pair_drop body. Back-compat: top-level
    // relay_url/slot_id/slot_token still point at the federation
    // endpoint so v0.5.16-and-earlier peers ingest unchanged.
    let our_relay_state = config::read_relay_state().unwrap_or_else(|_| json!({}));
    let our_endpoints = crate::endpoints::self_endpoints(&our_relay_state);
    let mut body = json!({
        "card": our_card,
        "relay_url": our_relay,
        "slot_id": our_slot_id,
        "slot_token": our_slot_token,
    });
    if !our_endpoints.is_empty() {
        body["endpoints"] = serde_json::to_value(&our_endpoints).unwrap_or(json!([]));
    }
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now,
        "from": our_did,
        "to": peer_did,
        "type": "pair_drop",
        "kind": 1100u32,
        "body": body,
    });
    let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &our_handle)?;

    // 5. Deliver via /v1/handle/intro/<nick> (auth-free; relay validates kind).
    let client = crate::relay_client::RelayClient::new(&peer_relay);
    let resp = client.handle_intro(&parsed.nick, &signed)?;
    let event_id = signed
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle_arg,
                "paired_with": peer_did,
                "peer_handle": peer_handle,
                "event_id": event_id,
                "drop_response": resp,
                "status": "drop_sent",
            }))?
        );
    } else {
        println!(
            "→ resolved {handle_arg} (did={peer_did})\n→ pinned peer locally\n→ intro dropped to {peer_relay}\nawaiting pair_drop_ack from {peer_handle} to complete bilateral pin."
        );
    }
    Ok(())
}

/// v0.5.14 bilateral-completion path for `wire add`. Called when the peer's
/// pair_drop is already sitting in `pending-inbound`. Pin trust, write relay
/// coords + slot_token from the stored drop, ship our slot_token back via
/// `pair_drop_ack`, delete the pending record. Symmetric with the SPAKE2
/// invite-URL path (which is already bilateral by virtue of the pre-shared
/// nonce).
fn cmd_add_accept_pending(
    handle_arg: &str,
    peer_nick: &str,
    pending: &crate::pending_inbound_pair::PendingInboundPair,
    _our_relay: &str,
    _our_slot_id: &str,
    _our_slot_token: &str,
    as_json: bool,
) -> Result<()> {
    // 1. Pin peer in trust with VERIFIED — operator gestured consent by running
    //    `wire add` against this handle while a drop was waiting.
    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &pending.peer_card, Some("VERIFIED"));
    config::write_trust(&trust)?;

    // 2. Record peer's relay coords + slot_token (already shipped to us in
    //    the original drop body; held back until now).
    // v0.5.17: pin all advertised endpoints (federation + optional local).
    // Falls back to a single federation entry when the record was written
    // by v0.5.16-era code that didn't carry endpoints[].
    let mut relay_state = config::read_relay_state()?;
    let endpoints_to_pin = if pending.peer_endpoints.is_empty() {
        vec![crate::endpoints::Endpoint::federation(
            pending.peer_relay_url.clone(),
            pending.peer_slot_id.clone(),
            pending.peer_slot_token.clone(),
        )]
    } else {
        pending.peer_endpoints.clone()
    };
    crate::endpoints::pin_peer_endpoints(
        &mut relay_state,
        &pending.peer_handle,
        &endpoints_to_pin,
    )?;
    config::write_relay_state(&relay_state)?;

    // 3. Ship our slot_token to peer via pair_drop_ack so they can write back.
    crate::pair_invite::send_pair_drop_ack(
        &pending.peer_handle,
        &pending.peer_relay_url,
        &pending.peer_slot_id,
        &pending.peer_slot_token,
    )
    .with_context(|| {
        format!(
            "pair_drop_ack send to {} @ {} slot {} failed",
            pending.peer_handle, pending.peer_relay_url, pending.peer_slot_id
        )
    })?;

    // 4. Delete the pending-inbound record now that bilateral is complete.
    crate::pending_inbound_pair::consume_pending_inbound(peer_nick)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle_arg,
                "paired_with": pending.peer_did,
                "peer_handle": pending.peer_handle,
                "status": "bilateral_accepted",
                "via": "pending_inbound",
            }))?
        );
    } else {
        println!(
            "→ accepted pending pair from {peer}\n→ pinned VERIFIED, slot_token recorded\n→ shipped our slot_token back via pair_drop_ack\nbilateral pair complete. Send with `wire send {peer} \"...\"`.",
            peer = pending.peer_handle,
        );
    }
    Ok(())
}

/// v0.5.14: explicit `wire pair-accept <peer>` — bilateral-completion path
/// for a pending-inbound pair request. Pin trust, write relay_state from the
/// stored pair_drop, send `pair_drop_ack` with our slot_token, delete the
/// pending record. Equivalent to running `wire add <peer>@<their-relay>`
/// when a pending-inbound record exists, but without needing to remember
/// the peer's relay domain.
fn cmd_pair_accept(peer_nick: &str, as_json: bool) -> Result<()> {
    let nick = crate::agent_card::bare_handle(peer_nick);
    let pending = crate::pending_inbound_pair::read_pending_inbound(nick)?.ok_or_else(|| {
        anyhow!(
            "no pending pair request from {nick}. Run `wire pair-list-inbound` to see who is waiting, \
             or use `wire add <peer>@<relay>` to send a fresh outbound pair request."
        )
    })?;
    let (_our_did, our_relay, our_slot_id, our_slot_token) =
        crate::pair_invite::ensure_self_with_relay(None)?;
    let handle_arg = format!("{}@{}", pending.peer_handle, pending.peer_relay_url);
    cmd_add_accept_pending(
        &handle_arg,
        nick,
        &pending,
        &our_relay,
        &our_slot_id,
        &our_slot_token,
        as_json,
    )
}

/// v0.5.14: programmatic access to pending-inbound for scripts.
/// `wire pair-list-inbound --json` returns a flat array of records.
fn cmd_pair_list_inbound(as_json: bool) -> Result<()> {
    let items = crate::pending_inbound_pair::list_pending_inbound()?;
    if as_json {
        println!("{}", serde_json::to_string(&items)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("no pending inbound pair requests.");
        return Ok(());
    }
    println!("{:<20} {:<35} {:<25} DID", "PEER", "RELAY", "RECEIVED");
    for p in items {
        println!(
            "{:<20} {:<35} {:<25} {}",
            p.peer_handle, p.peer_relay_url, p.received_at, p.peer_did,
        );
    }
    println!(
        "→ accept with `wire pair-accept <peer>`; refuse with `wire pair-reject <peer>`."
    );
    Ok(())
}

/// v0.5.14: `wire pair-reject <peer>` — drop a pending-inbound record
/// without pairing. No event is sent back to the peer; their side stays
/// pending until they time out or the operator-side data ages out.
fn cmd_pair_reject(peer_nick: &str, as_json: bool) -> Result<()> {
    let nick = crate::agent_card::bare_handle(peer_nick);
    let existed = crate::pending_inbound_pair::read_pending_inbound(nick)?;
    crate::pending_inbound_pair::consume_pending_inbound(nick)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "peer": nick,
                "rejected": existed.is_some(),
                "had_pending": existed.is_some(),
            }))?
        );
    } else if existed.is_some() {
        println!("→ rejected pending pair from {nick}\n→ pending-inbound record deleted; no ack sent.");
    } else {
        println!("no pending pair from {nick} — nothing to reject");
    }
    Ok(())
}

// ---------- session (v0.5.16) ----------
//
// Multi-session wire on one machine. See src/session.rs for the storage
// layout + naming rules. The CLI dispatcher here orchestrates child
// `wire` invocations with `WIRE_HOME` overridden to the session's dir;
// each session-local `init` / `claim` / `daemon` runs in its own world
// without cross-contamination via env vars in this process.

fn cmd_session(cmd: SessionCommand) -> Result<()> {
    match cmd {
        SessionCommand::New {
            name,
            relay,
            with_local,
            local_relay,
            no_daemon,
            json,
        } => cmd_session_new(
            name.as_deref(),
            &relay,
            with_local,
            &local_relay,
            no_daemon,
            json,
        ),
        SessionCommand::List { json } => cmd_session_list(json),
        SessionCommand::ListLocal { json } => cmd_session_list_local(json),
        SessionCommand::Env { name, json } => cmd_session_env(name.as_deref(), json),
        SessionCommand::Current { json } => cmd_session_current(json),
        SessionCommand::Destroy { name, force, json } => cmd_session_destroy(&name, force, json),
    }
}

fn resolve_session_name(name: Option<&str>) -> Result<String> {
    if let Some(n) = name {
        return Ok(crate::session::sanitize_name(n));
    }
    let cwd = std::env::current_dir().with_context(|| "reading cwd")?;
    let registry = crate::session::read_registry().unwrap_or_default();
    Ok(crate::session::derive_name_from_cwd(&cwd, &registry))
}

fn cmd_session_new(
    name_arg: Option<&str>,
    relay: &str,
    with_local: bool,
    local_relay: &str,
    no_daemon: bool,
    as_json: bool,
) -> Result<()> {
    let cwd = std::env::current_dir().with_context(|| "reading cwd")?;
    let mut registry = crate::session::read_registry().unwrap_or_default();
    let name = match name_arg {
        Some(n) => crate::session::sanitize_name(n),
        None => crate::session::derive_name_from_cwd(&cwd, &registry),
    };
    let session_home = crate::session::session_dir(&name)?;

    let already_exists = session_home.exists()
        && session_home
            .join("config")
            .join("wire")
            .join("agent-card.json")
            .exists();
    if already_exists {
        // Idempotent: re-register the cwd (if not already), refresh the
        // daemon if requested, surface the env-var line. Do not re-init
        // identity — that would clobber the keypair.
        registry
            .by_cwd
            .insert(cwd.to_string_lossy().into_owned(), name.clone());
        crate::session::write_registry(&registry)?;
        let info = render_session_info(&name, &session_home, &cwd)?;
        emit_session_new_result(&info, "already_exists", as_json)?;
        if !no_daemon {
            ensure_session_daemon(&session_home)?;
        }
        return Ok(());
    }

    std::fs::create_dir_all(&session_home)
        .with_context(|| format!("creating session dir {session_home:?}"))?;

    // Phase 1: init identity in the new session's WIRE_HOME.
    let init_status = run_wire_with_home(
        &session_home,
        &["init", &name, "--relay", relay],
    )?;
    if !init_status.success() {
        bail!(
            "`wire init {name} --relay {relay}` failed inside session dir {session_home:?}"
        );
    }

    // Phase 2: claim the handle on the relay. If FCFS rejects the name
    // (another machine has it), fall back to `<name>-<2hex>` until success
    // or 5 attempts exhausted. Failure here is fatal — the session is
    // unreachable without a claim.
    let mut claim_attempt = 0u32;
    let mut effective_handle = name.clone();
    loop {
        claim_attempt += 1;
        let status = run_wire_with_home(
            &session_home,
            &["claim", &effective_handle, "--relay", relay],
        )?;
        if status.success() {
            break;
        }
        if claim_attempt >= 5 {
            bail!(
                "5 failed attempts to claim a handle on {relay} for session {name}. \
                 Try `wire session destroy {name} --force` and re-run with a different name."
            );
        }
        // Use a fresh random-ish suffix on each retry. We piggyback on the
        // path-hash logic but mix in the attempt counter to avoid getting
        // stuck on the same colliding suffix.
        let attempt_path = cwd.join(format!("__attempt_{claim_attempt}"));
        let suffix = crate::session::derive_name_from_cwd(&attempt_path, &registry);
        // suffix here is the full derived name for attempt_path; we just
        // want a short token, so take the trailing hash if it has one,
        // else hash the attempt-path ourselves.
        let token = suffix
            .rsplit('-')
            .next()
            .filter(|t| t.len() == 4)
            .map(str::to_string)
            .unwrap_or_else(|| format!("{claim_attempt}"));
        effective_handle = format!("{name}-{token}");
    }

    // Persist the cwd → name mapping NOW so subsequent invocations from
    // this directory short-circuit to the "already_exists" branch.
    registry
        .by_cwd
        .insert(cwd.to_string_lossy().into_owned(), name.clone());
    crate::session::write_registry(&registry)?;

    // v0.5.17: --with-local probes the local relay and, if it's
    // reachable, allocates a second slot there. The session's
    // relay_state.json grows a `self.endpoints[]` array carrying both
    // endpoints; routing layer (cmd_push) prefers local for sister-
    // session peers that also have a local slot.
    if with_local {
        try_allocate_local_slot(&session_home, &effective_handle, relay, local_relay);
    }

    if !no_daemon {
        ensure_session_daemon(&session_home)?;
    }

    let info = render_session_info(&name, &session_home, &cwd)?;
    emit_session_new_result(&info, "created", as_json)
}

/// v0.5.17: probe the named local relay; if `/healthz` returns ok within
/// a short timeout, allocate a slot there and update the session's
/// `relay_state.json` `self.endpoints[]` to advertise both endpoints.
///
/// Failure to reach the local relay is NOT fatal — the session stays
/// federation-only. Logs to stderr on failure so operators can tell
/// the local relay isn't running, but doesn't abort the bootstrap.
fn try_allocate_local_slot(
    session_home: &std::path::Path,
    handle: &str,
    federation_relay: &str,
    local_relay: &str,
) {
    // Probe healthz with a tight timeout. Use a fresh client (don't
    // share the daemon-wide one) so the timeout is local to this call.
    let probe = match crate::relay_client::build_blocking_client(Some(
        std::time::Duration::from_millis(500),
    )) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wire session new: cannot build probe client for {local_relay}: {e:#}");
            return;
        }
    };
    let healthz_url = format!("{}/healthz", local_relay.trim_end_matches('/'));
    match probe.get(&healthz_url).send() {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            eprintln!(
                "wire session new: local relay probe at {healthz_url} returned {} — staying federation-only",
                resp.status()
            );
            return;
        }
        Err(e) => {
            eprintln!(
                "wire session new: local relay at {local_relay} unreachable ({}) — staying federation-only. \
                 Start one with `wire relay-server --bind 127.0.0.1:8771 --local-only`.",
                crate::relay_client::format_transport_error(&anyhow::Error::new(e))
            );
            return;
        }
    };

    // Allocate a slot on the local relay.
    let local_client = crate::relay_client::RelayClient::new(local_relay);
    let alloc = match local_client.allocate_slot(Some(handle)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "wire session new: local relay slot allocation failed: {e:#} — staying federation-only"
            );
            return;
        }
    };

    // Merge into the session's relay_state.json. We invoke wire via
    // run_wire_with_home for federation calls (subprocess isolation),
    // but the relay_state.json is a simple file we can edit directly
    // — and need to, because there's no `wire bind-relay --add-local`
    // command yet (could add later; out of scope for v0.5.17 MVP).
    let state_path = session_home
        .join("config")
        .join("wire")
        .join("relay-state.json");
    let mut state: serde_json::Value = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    // Read the existing federation self info (already written by
    // `wire init` + `wire bind-relay` path during session bootstrap).
    let fed_endpoint = state
        .get("self")
        .and_then(|s| {
            let url = s.get("relay_url").and_then(serde_json::Value::as_str)?;
            let slot_id = s.get("slot_id").and_then(serde_json::Value::as_str)?;
            let slot_token = s.get("slot_token").and_then(serde_json::Value::as_str)?;
            Some(crate::endpoints::Endpoint::federation(
                url.to_string(),
                slot_id.to_string(),
                slot_token.to_string(),
            ))
        });

    let local_endpoint = crate::endpoints::Endpoint::local(
        local_relay.trim_end_matches('/').to_string(),
        alloc.slot_id.clone(),
        alloc.slot_token.clone(),
    );

    let mut endpoints: Vec<crate::endpoints::Endpoint> = Vec::new();
    if let Some(f) = fed_endpoint.clone() {
        endpoints.push(f);
    }
    endpoints.push(local_endpoint);

    let self_obj = state
        .as_object_mut()
        .expect("relay_state root is an object")
        .entry("self")
        .or_insert_with(|| {
            serde_json::json!({
                "relay_url": federation_relay,
            })
        });
    if let Some(obj) = self_obj.as_object_mut() {
        obj.insert(
            "endpoints".into(),
            serde_json::to_value(&endpoints).unwrap_or(serde_json::Value::Null),
        );
    }

    if let Err(e) = std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&state).unwrap_or_default(),
    ) {
        eprintln!(
            "wire session new: persisting dual-slot relay_state at {state_path:?} failed: {e}"
        );
        return;
    }
    eprintln!(
        "wire session new: local slot allocated on {local_relay} (slot_id={})",
        alloc.slot_id
    );
}

fn render_session_info(
    name: &str,
    session_home: &std::path::Path,
    cwd: &std::path::Path,
) -> Result<serde_json::Value> {
    let card_path = session_home.join("config").join("wire").join("agent-card.json");
    let (did, handle) = if card_path.exists() {
        let card: Value = serde_json::from_slice(&std::fs::read(&card_path)?)?;
        let did = card
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let handle = card
            .get("handle")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                crate::agent_card::display_handle_from_did(&did).to_string()
            });
        (did, handle)
    } else {
        (String::new(), String::new())
    };
    Ok(json!({
        "name": name,
        "home_dir": session_home.to_string_lossy(),
        "cwd": cwd.to_string_lossy(),
        "did": did,
        "handle": handle,
        "export": format!("export WIRE_HOME={}", session_home.to_string_lossy()),
    }))
}

fn emit_session_new_result(
    info: &serde_json::Value,
    status: &str,
    as_json: bool,
) -> Result<()> {
    if as_json {
        let mut obj = info.clone();
        obj["status"] = json!(status);
        println!("{}", serde_json::to_string(&obj)?);
    } else {
        let name = info["name"].as_str().unwrap_or("?");
        let handle = info["handle"].as_str().unwrap_or("?");
        let home = info["home_dir"].as_str().unwrap_or("?");
        let did = info["did"].as_str().unwrap_or("?");
        let export = info["export"].as_str().unwrap_or("?");
        let prefix = if status == "already_exists" {
            "session already exists (re-registered cwd)"
        } else {
            "session created"
        };
        println!(
            "{prefix}\n  name:   {name}\n  handle: {handle}\n  did:    {did}\n  home:   {home}\n\nactivate with:\n  {export}"
        );
    }
    Ok(())
}

fn run_wire_with_home(
    session_home: &std::path::Path,
    args: &[&str],
) -> Result<std::process::ExitStatus> {
    let bin = std::env::current_exe().with_context(|| "locating self exe")?;
    let status = std::process::Command::new(&bin)
        .env("WIRE_HOME", session_home)
        .env_remove("RUST_LOG")
        .args(args)
        .status()
        .with_context(|| format!("spawning `wire {}`", args.join(" ")))?;
    Ok(status)
}

fn ensure_session_daemon(session_home: &std::path::Path) -> Result<()> {
    // Check if a daemon is already alive in this session's WIRE_HOME.
    // If so, no-op (let the existing process keep running).
    let pidfile = session_home
        .join("state")
        .join("wire")
        .join("daemon.pid");
    if pidfile.exists() {
        let bytes = std::fs::read(&pidfile).unwrap_or_default();
        let pid: Option<u32> =
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                v.get("pid").and_then(|p| p.as_u64()).map(|p| p as u32)
            } else {
                String::from_utf8_lossy(&bytes).trim().parse::<u32>().ok()
            };
        if let Some(p) = pid {
            let alive = {
                #[cfg(target_os = "linux")]
                {
                    std::path::Path::new(&format!("/proc/{p}")).exists()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    std::process::Command::new("kill")
                        .args(["-0", &p.to_string()])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                }
            };
            if alive {
                return Ok(());
            }
        }
    }

    // Spawn `wire daemon` detached. The existing `cmd_daemon` writes the
    // versioned pidfile; we just kick it off and return.
    let bin = std::env::current_exe().with_context(|| "locating self exe")?;
    let log_path = session_home.join("state").join("wire").join("daemon.log");
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening daemon log {log_path:?}"))?;
    let log_err = log_file.try_clone()?;
    std::process::Command::new(&bin)
        .env("WIRE_HOME", session_home)
        .env_remove("RUST_LOG")
        .args(["daemon", "--interval", "5"])
        .stdout(log_file)
        .stderr(log_err)
        .stdin(std::process::Stdio::null())
        .spawn()
        .with_context(|| "spawning session-local `wire daemon`")?;
    Ok(())
}

fn cmd_session_list(as_json: bool) -> Result<()> {
    let items = crate::session::list_sessions()?;
    if as_json {
        println!("{}", serde_json::to_string(&items)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("no sessions on this machine. `wire session new` to create one.");
        return Ok(());
    }
    println!(
        "{:<24} {:<24} {:<10} CWD",
        "NAME", "HANDLE", "DAEMON"
    );
    for s in items {
        println!(
            "{:<24} {:<24} {:<10} {}",
            s.name,
            s.handle.as_deref().unwrap_or("?"),
            if s.daemon_running { "running" } else { "down" },
            s.cwd.as_deref().unwrap_or("(no cwd registered)"),
        );
    }
    Ok(())
}

/// v0.5.19: `wire session list-local` — sister-session discovery.
///
/// For each on-disk session, read its `relay-state.json` and surface
/// the ones that have a Local-scope endpoint (allocated via
/// `wire session new --with-local`). Group by the local-relay URL so
/// the operator can see at a glance which sessions are mutually
/// reachable over the same loopback relay.
///
/// Read-only, no daemon contact. Useful as the prelude to teaming /
/// pairing same-box sister claudes (see also `wire session
/// pair-all-local` once implemented).
fn cmd_session_list_local(as_json: bool) -> Result<()> {
    let listing = crate::session::list_local_sessions()?;
    if as_json {
        println!("{}", serde_json::to_string(&listing)?);
        return Ok(());
    }

    if listing.local.is_empty() && listing.federation_only.is_empty() {
        println!(
            "no sessions on this machine. `wire session new --with-local` to create one \
             with a local-relay endpoint (start the relay first: \
             `wire relay-server --bind 127.0.0.1:8771 --local-only`)."
        );
        return Ok(());
    }

    if listing.local.is_empty() {
        println!(
            "no sister sessions reachable via a local relay. \
             Re-run `wire session new --with-local` to add a Local endpoint, or \
             start a local relay with `wire relay-server --bind 127.0.0.1:8771 --local-only`."
        );
    } else {
        // Stable iteration order: sort the relay URLs.
        let mut keys: Vec<&String> = listing.local.keys().collect();
        keys.sort();
        for relay_url in keys {
            let group = &listing.local[relay_url];
            println!("LOCAL RELAY: {relay_url}");
            println!(
                "  {:<24} {:<32} {:<10} CWD",
                "NAME", "HANDLE", "DAEMON"
            );
            for s in group {
                println!(
                    "  {:<24} {:<32} {:<10} {}",
                    s.name,
                    s.handle.as_deref().unwrap_or("?"),
                    if s.daemon_running { "running" } else { "down" },
                    s.cwd.as_deref().unwrap_or("(no cwd registered)"),
                );
            }
            println!();
        }
    }

    if !listing.federation_only.is_empty() {
        println!("federation-only (no local endpoint):");
        for s in &listing.federation_only {
            println!(
                "  {:<24} {:<32} {}",
                s.name,
                s.handle.as_deref().unwrap_or("?"),
                s.cwd.as_deref().unwrap_or("(no cwd registered)"),
            );
        }
    }
    Ok(())
}

fn cmd_session_env(name_arg: Option<&str>, as_json: bool) -> Result<()> {
    let name = resolve_session_name(name_arg)?;
    let session_home = crate::session::session_dir(&name)?;
    if !session_home.exists() {
        bail!(
            "no session named {name:?} on this machine. `wire session list` to enumerate, \
             `wire session new {name}` to create."
        );
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "name": name,
                "home_dir": session_home.to_string_lossy(),
                "export": format!("export WIRE_HOME={}", session_home.to_string_lossy()),
            }))?
        );
    } else {
        println!("export WIRE_HOME={}", session_home.to_string_lossy());
    }
    Ok(())
}

fn cmd_session_current(as_json: bool) -> Result<()> {
    let cwd = std::env::current_dir().with_context(|| "reading cwd")?;
    let registry = crate::session::read_registry().unwrap_or_default();
    let cwd_key = cwd.to_string_lossy().into_owned();
    let name = registry.by_cwd.get(&cwd_key).cloned();
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "cwd": cwd_key,
                "session": name,
            }))?
        );
    } else if let Some(n) = name {
        println!("{n}");
    } else {
        println!("(no session registered for this cwd)");
    }
    Ok(())
}

fn cmd_session_destroy(name_arg: &str, force: bool, as_json: bool) -> Result<()> {
    let name = crate::session::sanitize_name(name_arg);
    let session_home = crate::session::session_dir(&name)?;
    if !session_home.exists() {
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "name": name,
                    "destroyed": false,
                    "reason": "no such session",
                }))?
            );
        } else {
            println!("no session named {name:?} — nothing to destroy.");
        }
        return Ok(());
    }
    if !force {
        bail!(
            "destroying session {name:?} would delete its keypair + state irrecoverably. \
             Pass --force to confirm."
        );
    }

    // Kill the session-local daemon if alive.
    let pidfile = session_home
        .join("state")
        .join("wire")
        .join("daemon.pid");
    if let Ok(bytes) = std::fs::read(&pidfile) {
        let pid: Option<u32> =
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                v.get("pid").and_then(|p| p.as_u64()).map(|p| p as u32)
            } else {
                String::from_utf8_lossy(&bytes).trim().parse::<u32>().ok()
            };
        if let Some(p) = pid {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &p.to_string()])
                .output();
        }
    }

    std::fs::remove_dir_all(&session_home)
        .with_context(|| format!("removing session dir {session_home:?}"))?;

    // Strip from registry.
    let mut registry = crate::session::read_registry().unwrap_or_default();
    registry.by_cwd.retain(|_, v| v != &name);
    crate::session::write_registry(&registry)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "name": name,
                "destroyed": true,
            }))?
        );
    } else {
        println!("destroyed session {name:?}.");
    }
    Ok(())
}

// ---------- diag (structured trace) ----------

fn cmd_diag(action: DiagAction) -> Result<()> {
    let state = config::state_dir()?;
    let knob = state.join("diag.enabled");
    let log_path = state.join("diag.jsonl");
    match action {
        DiagAction::Tail { limit, json } => {
            let entries = crate::diag::tail(limit);
            if json {
                for e in entries {
                    println!("{}", serde_json::to_string(&e)?);
                }
            } else if entries.is_empty() {
                println!("wire diag: no entries (diag may be disabled — `wire diag enable`)");
            } else {
                for e in entries {
                    let ts = e["ts"].as_u64().unwrap_or(0);
                    let ty = e["type"].as_str().unwrap_or("?");
                    let pid = e["pid"].as_u64().unwrap_or(0);
                    let payload = e["payload"].to_string();
                    println!("[{ts}] pid={pid} {ty} {payload}");
                }
            }
        }
        DiagAction::Enable => {
            config::ensure_dirs()?;
            std::fs::write(&knob, "1")?;
            println!("wire diag: enabled at {knob:?}");
        }
        DiagAction::Disable => {
            if knob.exists() {
                std::fs::remove_file(&knob)?;
            }
            println!("wire diag: disabled (env WIRE_DIAG may still flip it on per-process)");
        }
        DiagAction::Status { json } => {
            let enabled = crate::diag::is_enabled();
            let size = std::fs::metadata(&log_path)
                .map(|m| m.len())
                .unwrap_or(0);
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "enabled": enabled,
                        "log_path": log_path,
                        "log_size_bytes": size,
                    }))?
                );
            } else {
                println!("wire diag status");
                println!("  enabled:    {enabled}");
                println!("  log:        {log_path:?}");
                println!("  log size:   {size} bytes");
            }
        }
    }
    Ok(())
}

// ---------- service (install / uninstall / status) ----------

fn cmd_service(action: ServiceAction) -> Result<()> {
    let (report, as_json) = match action {
        ServiceAction::Install { json } => (crate::service::install()?, json),
        ServiceAction::Uninstall { json } => (crate::service::uninstall()?, json),
        ServiceAction::Status { json } => (crate::service::status()?, json),
    };
    if as_json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("wire service {}", report.action);
        println!("  platform:  {}", report.platform);
        println!("  unit:      {}", report.unit_path);
        println!("  status:    {}", report.status);
        println!("  detail:    {}", report.detail);
    }
    Ok(())
}

// ---------- upgrade (atomic daemon swap) ----------

/// `wire upgrade` — kill all running `wire daemon` processes, spawn a
/// fresh one from the currently-installed binary, write a new versioned
/// pidfile. The fix for today's exact failure mode: a daemon process that
/// kept running OLD binary text in memory under a symlink that had since
/// been repointed at a NEW binary on disk.
///
/// Idempotent. If no stale daemon is running, just starts a fresh one
/// (same as `wire daemon &` but with the wait-until-alive guard from
/// ensure_up::ensure_daemon_running).
///
/// `--check` mode reports drift without acting — lists the processes
/// that WOULD be killed and the binary version of each.
fn cmd_upgrade(check_only: bool, as_json: bool) -> Result<()> {
    // 1. Identify all `wire daemon` processes.
    let pgrep_out = std::process::Command::new("pgrep")
        .args(["-f", "wire daemon"])
        .output();
    let running_pids: Vec<u32> = match pgrep_out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .filter_map(|s| s.parse::<u32>().ok())
            .collect(),
        _ => Vec::new(),
    };

    // 2. Read pidfile to surface what the daemon THINKS it is.
    let record = crate::ensure_up::read_pid_record("daemon");
    let recorded_version: Option<String> = match &record {
        crate::ensure_up::PidRecord::Json(d) => Some(d.version.clone()),
        crate::ensure_up::PidRecord::LegacyInt(_) => Some("<pre-0.5.11>".to_string()),
        _ => None,
    };
    let cli_version = env!("CARGO_PKG_VERSION").to_string();

    if check_only {
        let report = json!({
            "running_pids": running_pids,
            "pidfile_version": recorded_version,
            "cli_version": cli_version,
            "would_kill": running_pids,
        });
        if as_json {
            println!("{}", serde_json::to_string(&report)?);
        } else {
            println!("wire upgrade --check");
            println!("  cli version:      {cli_version}");
            println!("  pidfile version:  {}", recorded_version.as_deref().unwrap_or("(missing)"));
            if running_pids.is_empty() {
                println!("  running daemons:  none");
            } else {
                let pids: Vec<String> = running_pids.iter().map(|p| p.to_string()).collect();
                println!("  running daemons:  pids {}", pids.join(", "));
                println!("  would kill all + spawn fresh");
            }
        }
        return Ok(());
    }

    // 3. Kill every running wire daemon. Use SIGTERM first, then SIGKILL
    // after a brief grace period.
    let mut killed: Vec<u32> = Vec::new();
    for pid in &running_pids {
        // SIGTERM (15).
        let _ = std::process::Command::new("kill")
            .args(["-15", &pid.to_string()])
            .status();
        killed.push(*pid);
    }
    // Wait up to ~2s for graceful exit.
    if !killed.is_empty() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let still_alive: Vec<u32> = killed
                .iter()
                .copied()
                .filter(|p| process_alive_pid(*p))
                .collect();
            if still_alive.is_empty() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                // SIGKILL hold-outs.
                for pid in still_alive {
                    let _ = std::process::Command::new("kill")
                        .args(["-9", &pid.to_string()])
                        .status();
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    // 4. Remove stale pidfile so ensure_daemon_running doesn't think the
    //    old daemon is still owning it.
    let pidfile = config::state_dir()?.join("daemon.pid");
    if pidfile.exists() {
        let _ = std::fs::remove_file(&pidfile);
    }

    // 5. Spawn fresh daemon via ensure_up — atomically waits for
    //    process_alive + writes the versioned pidfile.
    let spawned = crate::ensure_up::ensure_daemon_running()?;

    let new_record = crate::ensure_up::read_pid_record("daemon");
    let new_pid = new_record.pid();
    let new_version: Option<String> = if let crate::ensure_up::PidRecord::Json(d) = &new_record {
        Some(d.version.clone())
    } else {
        None
    };

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "killed": killed,
                "spawned_fresh_daemon": spawned,
                "new_pid": new_pid,
                "new_version": new_version,
                "cli_version": cli_version,
            }))?
        );
    } else {
        if killed.is_empty() {
            println!("wire upgrade: no stale daemons running");
        } else {
            println!("wire upgrade: killed {} daemon(s) (pids {})",
                killed.len(),
                killed.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "));
        }
        if spawned {
            println!(
                "wire upgrade: spawned fresh daemon (pid {} v{})",
                new_pid.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string()),
                new_version.as_deref().unwrap_or(&cli_version),
            );
        } else {
            println!("wire upgrade: daemon was already running on current binary");
        }
    }
    Ok(())
}

fn process_alive_pid(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

// ---------- doctor (single-command diagnostic) ----------

/// One DoctorCheck = one verdict on one health dimension.
#[derive(Clone, Debug, serde::Serialize)]
pub struct DoctorCheck {
    /// Short stable identifier (`daemon`, `relay`, `pair_rejections`, ...).
    /// Stable across versions for tooling consumption.
    pub id: String,
    /// PASS / WARN / FAIL.
    pub status: String,
    /// One-line human summary.
    pub detail: String,
    /// Optional remediation hint shown after the failing line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl DoctorCheck {
    fn pass(id: &str, detail: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: "PASS".into(),
            detail: detail.into(),
            fix: None,
        }
    }
    fn warn(id: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: "WARN".into(),
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    fn fail(id: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: "FAIL".into(),
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

/// `wire doctor` — single-command diagnostic for the silent-fail classes
/// 0.5.11 ships fixes for. Surfaces what each fix produces (P0.1 cursor
/// blocks, P0.2 pair-rejection logs, P0.4 daemon version mismatch, etc.)
/// so operators don't have to know where each lives.
fn cmd_doctor(as_json: bool, recent_rejections: usize) -> Result<()> {
    let mut checks: Vec<DoctorCheck> = Vec::new();

    checks.push(check_daemon_health());
    checks.push(check_daemon_pid_consistency());
    checks.push(check_relay_reachable());
    checks.push(check_pair_rejections(recent_rejections));
    checks.push(check_cursor_progress());

    let fails = checks.iter().filter(|c| c.status == "FAIL").count();
    let warns = checks.iter().filter(|c| c.status == "WARN").count();

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "checks": checks,
                "fail_count": fails,
                "warn_count": warns,
                "ok": fails == 0,
            }))?
        );
    } else {
        println!("wire doctor — {} checks", checks.len());
        for c in &checks {
            let bullet = match c.status.as_str() {
                "PASS" => "✓",
                "WARN" => "!",
                "FAIL" => "✗",
                _ => "?",
            };
            println!("  {bullet} [{}] {}: {}", c.status, c.id, c.detail);
            if let Some(fix) = &c.fix {
                println!("      fix: {fix}");
            }
        }
        println!();
        if fails == 0 && warns == 0 {
            println!("ALL GREEN");
        } else {
            println!("{fails} FAIL, {warns} WARN");
        }
    }

    if fails > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Check: daemon running, exactly one instance, no orphans.
///
/// Today's debug surfaced PID 54017 (old-binary wire daemon running for 4
/// days, advancing cursor without pinning). `wire status` lied about it.
/// `wire doctor` must catch THIS class: multiple daemons running, OR
/// pid-file claims daemon down while a process is actually up.
fn check_daemon_health() -> DoctorCheck {
    // v0.5.13 (issue #2 bug A): doctor PASSed on orphan-only state while
    // `wire status` reported DOWN, disagreeing for 25 min. Doctor used
    // pgrep alone; status cross-checked the pidfile. Doctor now consults
    // BOTH so the two surfaces never disagree.
    let output = std::process::Command::new("pgrep")
        .args(["-f", "wire daemon"])
        .output();
    let pgrep_pids: Vec<u32> = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .filter_map(|s| s.parse::<u32>().ok())
            .collect(),
        _ => Vec::new(),
    };
    let pidfile_pid = crate::ensure_up::read_pid_record("daemon").pid();
    // Is the pidfile-claimed daemon actually alive?
    let pidfile_alive = pidfile_pid
        .map(|pid| {
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
        })
        .unwrap_or(false);
    let orphan_pids: Vec<u32> = pgrep_pids
        .iter()
        .filter(|p| Some(**p) != pidfile_pid)
        .copied()
        .collect();

    let fmt_pids = |xs: &[u32]| -> String {
        xs.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    match (pgrep_pids.len(), pidfile_alive, orphan_pids.is_empty()) {
        (0, _, _) => DoctorCheck::fail(
            "daemon",
            "no `wire daemon` process running — nothing pulling inbox or pushing outbox",
            "`wire daemon &` to start, or re-run `wire up <handle>@<relay>` to bootstrap",
        ),
        // Single daemon AND it matches the pidfile → healthy.
        (1, true, true) => DoctorCheck::pass(
            "daemon",
            format!(
                "one daemon running (pid {}, matches pidfile)",
                pgrep_pids[0]
            ),
        ),
        // Pidfile is alive but pgrep ALSO sees orphan processes.
        (n, true, false) => DoctorCheck::fail(
            "daemon",
            format!(
                "{n} `wire daemon` processes running (pids: {}); pidfile claims pid {} but pgrep also sees orphan(s): {}. \
                 The orphans race the relay cursor — they advance past events your current binary can't process. \
                 (Issue #2 exact class.)",
                fmt_pids(&pgrep_pids),
                pidfile_pid.unwrap(),
                fmt_pids(&orphan_pids),
            ),
            "`wire upgrade` kills all orphans and spawns a fresh daemon with a clean pidfile",
        ),
        // Pidfile is dead but processes ARE running → all are orphans.
        (n, false, _) => DoctorCheck::fail(
            "daemon",
            format!(
                "{n} `wire daemon` process(es) running (pids: {}) but pidfile {} — \
                 every running daemon is an orphan, advancing the cursor without coordinating with the current CLI. \
                 (Issue #2 exact class: doctor previously PASSed this state while `wire status` said DOWN.)",
                fmt_pids(&pgrep_pids),
                match pidfile_pid {
                    Some(p) => format!("claims pid {p} which is dead"),
                    None => "is missing".to_string(),
                },
            ),
            "`wire upgrade` to kill the orphan(s) and spawn a fresh daemon",
        ),
        // Multiple daemons all matching … impossible by construction; fall back to warn.
        (n, true, true) => DoctorCheck::warn(
            "daemon",
            format!(
                "{n} `wire daemon` processes running (pids: {}). Multiple daemons race the relay cursor.",
                fmt_pids(&pgrep_pids)
            ),
            "kill all-but-one: `pkill -f \"wire daemon\"; wire daemon &`",
        ),
    }
}

/// Check: structured pidfile matches running daemon. Spark's P0.4 5th
/// check. Surfaces version mismatch (daemon running old binary text in
/// memory under a current symlink — today's exact bug class), schema
/// drift (future format bumps), and identity contamination (daemon's
/// recorded DID doesn't match this box's configured DID).
fn check_daemon_pid_consistency() -> DoctorCheck {
    let record = crate::ensure_up::read_pid_record("daemon");
    match record {
        crate::ensure_up::PidRecord::Missing => DoctorCheck::pass(
            "daemon_pid_consistency",
            "no daemon.pid yet — fresh box or daemon never started",
        ),
        crate::ensure_up::PidRecord::Corrupt(reason) => DoctorCheck::warn(
            "daemon_pid_consistency",
            format!("daemon.pid is corrupt: {reason}"),
            "delete state/wire/daemon.pid; next `wire daemon &` will rewrite",
        ),
        crate::ensure_up::PidRecord::LegacyInt(pid) => DoctorCheck::warn(
            "daemon_pid_consistency",
            format!(
                "daemon.pid is legacy-int form (pid={pid}, no version/bin_path metadata). \
                 Daemon was started by a pre-0.5.11 binary."
            ),
            "run `wire upgrade` to kill the old daemon and start a fresh one with the JSON pidfile",
        ),
        crate::ensure_up::PidRecord::Json(d) => {
            let mut issues: Vec<String> = Vec::new();
            if d.schema != crate::ensure_up::DAEMON_PID_SCHEMA {
                issues.push(format!(
                    "schema={} (expected {})",
                    d.schema,
                    crate::ensure_up::DAEMON_PID_SCHEMA
                ));
            }
            let cli_version = env!("CARGO_PKG_VERSION");
            if d.version != cli_version {
                issues.push(format!(
                    "version daemon={} cli={cli_version}",
                    d.version
                ));
            }
            if !std::path::Path::new(&d.bin_path).exists() {
                issues.push(format!("bin_path {} missing on disk", d.bin_path));
            }
            // Cross-check DID + relay against current config (best-effort).
            if let Ok(card) = config::read_agent_card()
                && let Some(current_did) = card.get("did").and_then(Value::as_str)
                && let Some(recorded_did) = &d.did
                && recorded_did != current_did
            {
                issues.push(format!(
                    "did daemon={recorded_did} config={current_did} — identity drift"
                ));
            }
            if let Ok(state) = config::read_relay_state()
                && let Some(current_relay) = state
                    .get("self")
                    .and_then(|s| s.get("relay_url"))
                    .and_then(Value::as_str)
                && let Some(recorded_relay) = &d.relay_url
                && recorded_relay != current_relay
            {
                issues.push(format!(
                    "relay_url daemon={recorded_relay} config={current_relay} — relay-migration drift"
                ));
            }
            if issues.is_empty() {
                DoctorCheck::pass(
                    "daemon_pid_consistency",
                    format!(
                        "daemon v{} bound to {} as {}",
                        d.version,
                        d.relay_url.as_deref().unwrap_or("?"),
                        d.did.as_deref().unwrap_or("?")
                    ),
                )
            } else {
                DoctorCheck::warn(
                    "daemon_pid_consistency",
                    format!("daemon pidfile drift: {}", issues.join("; ")),
                    "`wire upgrade` to atomically restart daemon with current config".to_string(),
                )
            }
        }
    }
}

/// Check: bound relay's /healthz returns 200.
fn check_relay_reachable() -> DoctorCheck {
    let state = match config::read_relay_state() {
        Ok(s) => s,
        Err(e) => return DoctorCheck::fail(
            "relay",
            format!("could not read relay state: {e}"),
            "run `wire up <handle>@<relay>` to bootstrap",
        ),
    };
    let url = state
        .get("self")
        .and_then(|s| s.get("relay_url"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if url.is_empty() {
        return DoctorCheck::warn(
            "relay",
            "no relay bound — wire send/pull will not work",
            "run `wire bind-relay <url>` or `wire up <handle>@<relay>`",
        );
    }
    let client = crate::relay_client::RelayClient::new(url);
    match client.check_healthz() {
        Ok(()) => DoctorCheck::pass("relay", format!("{url} healthz=200")),
        Err(e) => DoctorCheck::fail(
            "relay",
            format!("{url} unreachable: {e}"),
            format!("network reachable to {url}? relay running? check `curl {url}/healthz`"),
        ),
    }
}

/// Check: count recent entries in pair-rejected.jsonl (P0.2 output). Every
/// entry there is a silent failure that, pre-0.5.11, would have left the
/// operator wondering why pairing didn't complete.
fn check_pair_rejections(recent_n: usize) -> DoctorCheck {
    let path = match config::state_dir() {
        Ok(d) => d.join("pair-rejected.jsonl"),
        Err(e) => return DoctorCheck::warn(
            "pair_rejections",
            format!("could not resolve state dir: {e}"),
            "set WIRE_HOME or fix XDG_STATE_HOME",
        ),
    };
    if !path.exists() {
        return DoctorCheck::pass(
            "pair_rejections",
            "no pair-rejected.jsonl — no recorded pair failures",
        );
    }
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) => return DoctorCheck::warn(
            "pair_rejections",
            format!("could not read {path:?}: {e}"),
            "check file permissions",
        ),
    };
    let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return DoctorCheck::pass(
            "pair_rejections",
            "pair-rejected.jsonl present but empty",
        );
    }
    let total = lines.len();
    let recent: Vec<&str> = lines.iter().rev().take(recent_n).rev().copied().collect();
    let mut summary: Vec<String> = Vec::new();
    for line in &recent {
        if let Ok(rec) = serde_json::from_str::<Value>(line) {
            let peer = rec.get("peer").and_then(Value::as_str).unwrap_or("?");
            let code = rec.get("code").and_then(Value::as_str).unwrap_or("?");
            summary.push(format!("{peer}/{code}"));
        }
    }
    DoctorCheck::warn(
        "pair_rejections",
        format!(
            "{total} pair failures recorded. recent: [{}]",
            summary.join(", ")
        ),
        format!(
            "inspect {path:?} for full details. Each entry is a pair-flow error that previously silently dropped — re-run `wire pair <handle>@<relay>` to retry."
        ),
    )
}

/// Check: cursor isn't stuck. We can't tell without polling — but we can
/// report the current cursor position so operators see if it changes.
/// Real "stuck" detection needs two pulls separated in time; defer that
/// behaviour to a `wire doctor --watch` mode.
fn check_cursor_progress() -> DoctorCheck {
    let state = match config::read_relay_state() {
        Ok(s) => s,
        Err(e) => return DoctorCheck::warn(
            "cursor",
            format!("could not read relay state: {e}"),
            "check ~/Library/Application Support/wire/relay.json",
        ),
    };
    let cursor = state
        .get("self")
        .and_then(|s| s.get("last_pulled_event_id"))
        .and_then(Value::as_str)
        .map(|s| s.chars().take(16).collect::<String>())
        .unwrap_or_else(|| "<none>".to_string());
    DoctorCheck::pass(
        "cursor",
        format!(
            "current cursor: {cursor}. P0.1 cursor blocking is active — see `wire pull --json` for cursor_blocked / rejected[].blocks_cursor entries."
        ),
    )
}

#[cfg(test)]
mod doctor_tests {
    use super::*;

    #[test]
    fn doctor_check_constructors_set_status_correctly() {
        // Silent-fail-prevention rule: pass/warn/fail must be visibly
        // distinguishable to operators. If any constructor lets the wrong
        // status through, `wire doctor` lies and we're back to today's
        // 30-minute debug.
        let p = DoctorCheck::pass("x", "ok");
        assert_eq!(p.status, "PASS");
        assert_eq!(p.fix, None);

        let w = DoctorCheck::warn("x", "watch out", "do this");
        assert_eq!(w.status, "WARN");
        assert_eq!(w.fix, Some("do this".to_string()));

        let f = DoctorCheck::fail("x", "broken", "fix it");
        assert_eq!(f.status, "FAIL");
        assert_eq!(f.fix, Some("fix it".to_string()));
    }

    #[test]
    fn check_pair_rejections_no_file_is_pass() {
        // Fresh-box case: no pair-rejected.jsonl yet. Must NOT report this
        // as a problem.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let c = check_pair_rejections(5);
            assert_eq!(c.status, "PASS", "no file should be PASS, got {c:?}");
        });
    }

    #[test]
    fn check_pair_rejections_with_entries_warns() {
        // Existence of rejections is itself a signal — even if each entry
        // is a "known good failure," the operator wants to know they
        // happened.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            crate::pair_invite::record_pair_rejection(
                "willard",
                "pair_drop_ack_send_failed",
                "POST 502",
            );
            let c = check_pair_rejections(5);
            assert_eq!(c.status, "WARN");
            assert!(c.detail.contains("1 pair failures"));
            assert!(c.detail.contains("willard/pair_drop_ack_send_failed"));
        });
    }
}

// ---------- up megacommand (full bootstrap) ----------

/// `wire up <nick@relay-host>` — single command from fresh box to ready-to-
/// pair. Composes the steps that today's onboarding walks operators through
/// one by one (init / bind-relay / claim / background daemon / arm monitor
/// recipe). Idempotent: every step checks current state and skips if done.
///
/// Argument parsing accepts:
///   - `<nick>@<relay-host>` — explicit relay
///   - `<nick>`              — defaults to wireup.net (the configured public
///                             relay)
fn cmd_up(handle_arg: &str, name: Option<&str>, as_json: bool) -> Result<()> {
    let (nick, relay_url) = match handle_arg.split_once('@') {
        Some((n, host)) => {
            let url = if host.starts_with("http://") || host.starts_with("https://") {
                host.to_string()
            } else {
                format!("https://{host}")
            };
            (n.to_string(), url)
        }
        None => (handle_arg.to_string(), crate::pair_invite::DEFAULT_RELAY.to_string()),
    };

    let mut report: Vec<(String, String)> = Vec::new();
    let mut step = |stage: &str, detail: String| {
        report.push((stage.to_string(), detail.clone()));
        if !as_json {
            eprintln!("wire up: {stage} — {detail}");
        }
    };

    // 1. init (or verify existing identity matches the requested nick).
    if config::is_initialized()? {
        let card = config::read_agent_card()?;
        let existing_did = card.get("did").and_then(Value::as_str).unwrap_or("");
        let existing_handle =
            crate::agent_card::display_handle_from_did(existing_did).to_string();
        if existing_handle != nick {
            bail!(
                "wire up: already initialized as {existing_handle:?} but you asked for {nick:?}. \
                 Either run with the existing handle (`wire up {existing_handle}@<relay>`) or \
                 delete `{:?}` to start fresh.",
                config::config_dir()?
            );
        }
        step("init", format!("already initialized as {existing_handle}"));
    } else {
        cmd_init(&nick, name, Some(&relay_url), /* as_json */ false)?;
        step("init", format!("created identity {nick} bound to {relay_url}"));
    }

    // 2. Ensure relay binding matches. cmd_init with --relay binds it; if
    // already initialized we may need to bind to the requested relay
    // separately (operator switched relays).
    let relay_state = config::read_relay_state()?;
    let bound_relay = relay_state
        .get("self")
        .and_then(|s| s.get("relay_url"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if bound_relay.is_empty() {
        // Identity exists but never bound to a relay — bind now.
        cmd_bind_relay(&relay_url, /* as_json */ false)?;
        step("bind-relay", format!("bound to {relay_url}"));
    } else if bound_relay != relay_url {
        step(
            "bind-relay",
            format!(
                "WARNING: identity bound to {bound_relay} but you specified {relay_url}. \
                 Keeping existing binding. Run `wire bind-relay {relay_url}` to switch."
            ),
        );
    } else {
        step("bind-relay", format!("already bound to {bound_relay}"));
    }

    // 3. Claim nick on the relay's handle directory. Idempotent — same-DID
    // re-claims are accepted by the relay.
    match cmd_claim(&nick, Some(&relay_url), None, /* as_json */ false) {
        Ok(()) => step("claim", format!("{nick}@{} claimed", strip_proto(&relay_url))),
        Err(e) => step(
            "claim",
            format!("WARNING: claim failed: {e}. You can retry `wire claim {nick}`."),
        ),
    }

    // 4. Background daemon — must be running for pull/push/ack to flow.
    match crate::ensure_up::ensure_daemon_running() {
        Ok(true) => step("daemon", "started fresh background daemon".to_string()),
        Ok(false) => step("daemon", "already running".to_string()),
        Err(e) => step(
            "daemon",
            format!("WARNING: could not start daemon: {e}. Run `wire daemon &` manually."),
        ),
    }

    // 5. Final summary — point operator at the next commands.
    let summary = format!(
        "ready. `wire pair <peer>@<relay>` to pair, `wire send <peer> \"<msg>\"` to send, \
         `wire monitor` to watch incoming events."
    );
    step("ready", summary.clone());

    if as_json {
        let steps_json: Vec<_> = report
            .iter()
            .map(|(k, v)| json!({"stage": k, "detail": v}))
            .collect();
        println!(
            "{}",
            serde_json::to_string(&json!({
                "nick": nick,
                "relay": relay_url,
                "steps": steps_json,
            }))?
        );
    }
    Ok(())
}

/// Strip http:// or https:// prefix for display in `wire up` step output.
fn strip_proto(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string()
}

// ---------- pair megacommand (zero-paste handle-based) ----------

/// `wire pair <nick@domain>` zero-shot. Dispatched from Command::Pair when
/// the handle is in `nick@domain` form. Wraps:
///
///   1. cmd_add — resolve, pin, drop intro
///   2. Wait up to `timeout_secs` for the peer's `pair_drop_ack` to arrive
///      (signalled by `peers.<handle>.slot_token` populating in relay state)
///   3. Verify bilateral pin: trust contains peer + relay state has token
///   4. Print final state — both sides VERIFIED + can `wire send`
///
/// On timeout: hard-errors with the specific stuck step so the operator
/// knows which side to chase. No silent partial success.
fn cmd_pair_megacommand(
    handle_arg: &str,
    relay_override: Option<&str>,
    timeout_secs: u64,
    _as_json: bool,
) -> Result<()> {
    let parsed = crate::pair_profile::parse_handle(handle_arg)?;
    let peer_handle = parsed.nick.clone();

    eprintln!("wire pair: resolving {handle_arg}...");
    cmd_add(handle_arg, relay_override, /* as_json */ false)?;

    eprintln!(
        "wire pair: intro delivered. waiting up to {timeout_secs}s for {peer_handle} \
         to ack (their daemon must be running + pulling)..."
    );

    // Trigger an immediate daemon-style pull so we don't wait the full daemon
    // interval. Best-effort — if it fails, we still fall through to the
    // polling loop.
    let _ = run_sync_pull();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let poll_interval = std::time::Duration::from_millis(500);

    loop {
        // Drain anything new from the relay (e.g. our pair_drop_ack landing).
        let _ = run_sync_pull();
        let relay_state = config::read_relay_state()?;
        let peer_entry = relay_state
            .get("peers")
            .and_then(|p| p.get(&peer_handle))
            .cloned();
        let token = peer_entry
            .as_ref()
            .and_then(|e| e.get("slot_token"))
            .and_then(Value::as_str)
            .unwrap_or("");

        if !token.is_empty() {
            // Bilateral pin complete — we have their slot_token, we can send.
            let trust = config::read_trust()?;
            let pinned_in_trust = trust
                .get("agents")
                .and_then(|a| a.get(&peer_handle))
                .is_some();
            println!(
                "wire pair: paired with {peer_handle}.\n  trust: {}  bilateral: yes (slot_token recorded)\n  next: `wire send {peer_handle} \"<msg>\"`",
                if pinned_in_trust { "VERIFIED" } else { "MISSING (bug)" }
            );
            return Ok(());
        }

        if std::time::Instant::now() >= deadline {
            // Timeout — surface the EXACT stuck step. Likely culprits:
            //   - peer daemon not running on their box
            //   - peer's relay slot is offline
            //   - their daemon is on an older binary that doesn't know
            //     pair_drop kind=1100 (the P0.1 class — now visible via
            //     wire pull --json on their side as a blocking rejection)
            bail!(
                "wire pair: timed out after {timeout_secs}s. \
                 peer {peer_handle} never sent pair_drop_ack. \
                 likely causes: (a) their daemon is down — ask them to run \
                 `wire status` and `wire daemon &`; (b) their binary is older \
                 than 0.5.x and doesn't understand pair_drop events — ask \
                 them to `wire upgrade`; (c) network / relay blip — re-run \
                 `wire pair {handle_arg}` to retry."
            );
        }

        std::thread::sleep(poll_interval);
    }
}

fn cmd_claim(
    nick: &str,
    relay_override: Option<&str>,
    public_url: Option<&str>,
    as_json: bool,
) -> Result<()> {
    if !crate::pair_profile::is_valid_nick(nick) {
        bail!(
            "phyllis: {nick:?} won't fit in the books — handles need 2-32 chars, lowercase [a-z0-9_-], not on the reserved list"
        );
    }
    // `wire claim` is the one-step bootstrap: auto-init + auto-allocate slot
    // + claim handle. Operator should never have to run init/bind-relay first.
    let (_did, relay_url, slot_id, slot_token) =
        crate::pair_invite::ensure_self_with_relay(relay_override)?;
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
        // Best-effort: derive the public domain from the relay URL. If
        // operator passed --public-url that's the canonical address; else
        // the relay URL itself. Falls back to a placeholder if both miss.
        let domain = public_url
            .unwrap_or(&relay_url)
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .split('/')
            .next()
            .unwrap_or("<this-relay-domain>")
            .to_string();
        println!("claimed {nick} on {relay_url} — others can reach you at: {nick}@{domain}");
        println!("verify with: wire whois {nick}@{domain}");
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
