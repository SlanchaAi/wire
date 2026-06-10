//! `wire` CLI surface.
//!
//! Every subcommand emits human-readable text by default and structured JSON
//! when `--json` is passed. Stable JSON shape is part of the API contract —
//! see `docs/AGENT_INTEGRATION.md`.
//!
//! Subcommand split:
//!   - **agent-safe**: `whoami`, `peers`, `verify`, `send`, `tail` — pure
//!     message-layer ops, no trust establishment.
//!   - **trust-establishing**: `init`, `dial`, `accept`/`reject`,
//!     `invite`/`accept-invite`. The bilateral gate (operator-side `accept`)
//!     preserves the human-in-loop step — see `docs/THREAT_MODEL.md` T10/T14.

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use crate::{
    agent_card::{build_agent_card, sign_agent_card},
    config,
    signing::{fingerprint, generate_keypair, make_key_id},
    trust::{add_self_to_trust, empty_trust},
};

mod comms;
mod group;
mod lifecycle;
mod mesh;
mod pairing;
mod relay;
mod setup;
mod status;
mod upgrade;

pub(crate) use comms::parse_deadline_until;
pub(crate) use relay::cmd_bind_relay;
pub use relay::error_smells_like_slot_4xx;
pub use relay::run_sync_pull;
pub use relay::run_sync_push;

// Re-exports for cross-module callers (comms.rs, mcp.rs, etc.).
pub(crate) use pairing::{DialTarget, resolve_name_to_target};
pub(crate) use pairing::{ResolveError, cmd_add_local_sister, resolve_peer_handle};

/// Top-level CLI.
#[derive(Parser, Debug)]
#[command(name = "wire", version, about = "Magic-wormhole for AI agents — bilateral signed-message bus", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a keypair, write self-card, and bind an inbound slot.
    /// (HUMAN-ONLY — DO NOT exec from agents.)
    ///
    /// v0.9: refuses to create a slotless session by default. Pre-v0.9
    /// the silent slotless state caused the 2026-05-23 silent-fail
    /// incident — pairing + sending succeeded but peers black-holed
    /// inbound. Operators must now name how the session is reachable:
    /// `--relay <url>` (binds a slot inline) or `--offline` (opt into
    /// slotless, acknowledge `wire bind-relay` is required before any
    /// pair or send).
    ///
    /// v0.13.1: folded into `wire up` and hidden. Your handle is your
    /// DID-derived persona (one-name rule), so the typed `handle` arg is a
    /// vestigial seed with no effect on identity. Kept callable for explicit
    /// offline keygen (`wire init x --offline`); everyone else uses `wire up`.
    #[command(hide = true)]
    Init {
        /// Vestigial seed — ignored; your handle is your DID-derived persona.
        handle: String,
        /// Optional display name (defaults to capitalized handle).
        #[arg(long)]
        name: Option<String>,
        /// Relay URL — binds an inbound slot in the same step. Required
        /// unless `--offline` is passed. Example:
        /// `--relay http://127.0.0.1:8771` (local), `--relay https://wireup.net`
        /// (federation).
        #[arg(long)]
        relay: Option<String>,
        /// v0.9: opt into a slotless session — keypair only, no inbound
        /// mailbox. You MUST run `wire bind-relay <url>` before any
        /// pair / send / dial; until then peers cannot reach you.
        /// Useful for offline keypair generation; rare in practice.
        #[arg(long, conflicts_with = "relay")]
        offline: bool,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print this agent's identity (DID, fingerprint, mailbox slot).
    Whoami {
        #[arg(long)]
        json: bool,
        /// Print just `<emoji> <nickname>` (e.g. `🦊 foxtrot-meadow`).
        /// Plain text, no ANSI escapes. Useful for piping into other tools.
        #[arg(long, conflicts_with = "json")]
        short: bool,
        /// Print `<emoji> <nickname>` wrapped in ANSI 256-color escapes.
        /// Drop into a Claude Code statusline command for live identity display.
        #[arg(long, conflicts_with_all = ["json", "short"])]
        colored: bool,
    },
    /// List pinned peers with their tiers and capabilities.
    Peers {
        #[arg(long)]
        json: bool,
    },
    /// v0.9.5: emit shell completion script to stdout. Pipe to your
    /// shell's completion dir to enable tab-completion of wire verbs
    /// + handles + flags.
    ///
    /// Example installs:
    ///   bash:       `wire completions bash > /etc/bash_completion.d/wire`
    ///   zsh:        `wire completions zsh > ~/.zsh/completions/_wire`
    ///   fish:       `wire completions fish > ~/.config/fish/completions/wire.fish`
    ///   pwsh:       `wire completions powershell > $PROFILE` (append)
    ///   elvish:     `wire completions elvish > ~/.elvish/lib/wire.elv`
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// v0.9.3: one-screen "you are here" view. Prints the current
    /// session's character + handle + cwd, plus a short list of
    /// neighbors (sister sessions on the local relay, pinned peers).
    /// Designed for the operator's quick "wait which Claude is this,
    /// and who's around?" question — no `--json` shuffling, no
    /// remembering `wire whoami` vs `wire peers` vs `wire session
    /// list-local`.
    Here {
        #[arg(long)]
        json: bool,
    },
    /// v0.9 canonical surface: list pending-inbound pair requests waiting
    /// for your consent. Operators reach for "what's pending?" not a
    /// longer table-dump verb.
    Pending {
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
        /// v0.10: skip the v0.9 auto-pair-on-miss behavior. Send fails
        /// loudly if the peer isn't pinned yet. Use when you want strict
        /// "no implicit dialing" semantics — scripts that error vs.
        /// performing a side-effecting pair as a fallback.
        #[arg(long)]
        no_auto_pair: bool,
        /// v0.14.2: opt back into the legacy outbox→daemon-push pipeline.
        /// By default `wire send` POSTs to the peer's relay slot
        /// synchronously and returns a real `delivered` / `duplicate` /
        /// `failed` verdict. With `--queue` the event is appended to
        /// `<outbox_dir>/<peer>.jsonl` and the daemon's push loop
        /// drains it later (pre-v0.14.2 behavior). Use for offline
        /// buffering, batch sends, or pre-pair queueing.
        #[arg(long)]
        queue: bool,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// v0.8 — "go talk to this name." The one verb operators reach for.
    ///
    /// `wire dial <name>` accepts a character nickname (`noble-slate`),
    /// a session name (`slancha-api`), a card handle, or a DID — whichever
    /// face you happen to know the peer by. Resolution order:
    ///
    /// 1. Already-pinned peer? → no-op (or send if a message was passed).
    /// 2. Local sister session? → bilateral pair via the disk-read
    ///    `--local-sister` path (no relay round-trip, no .well-known
    ///    lookup, no SAS digits).
    /// 3. Otherwise → bail with a clear hint pointing at federation
    ///    syntax (`wire dial <handle>@<relay>` for cross-machine peers).
    ///
    /// With an optional message, `wire dial <name> "<msg>"` also sends
    /// the message synchronously after the pair lands (#187 collapsed
    /// the legacy queue→push step into a single direct relay POST;
    /// the response carries the actual delivered/duplicate/etc.
    /// verdict). Idempotent: re-dialling a known peer just sends.
    Dial {
        /// Peer name. Character nickname (preferred), session name,
        /// card handle, or DID — anything that identifies the peer to
        /// you.
        name: String,
        /// Optional first message to send after the pair lands. Same
        /// semantics as the body argument to `wire send`. Defaults to
        /// kind=claim.
        message: Option<String>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Stream signed events from peers.
    ///
    /// Defaults to NEWEST-N orientation: with `--limit N`, prints the most
    /// recent N events across all matched peers, sorted chronologically
    /// (oldest of the window first, newest last — same orientation as Unix
    /// `tail`). Pass `--oldest` to flip back to first-N (FIFO) behaviour.
    /// `--limit 0` returns the full inbox in chronological order.
    Tail {
        /// Optional peer filter; if omitted, tails all peers.
        peer: Option<String>,
        /// Emit JSONL (one event per line).
        #[arg(long)]
        json: bool,
        /// Maximum events to print. 0 = print everything (oldest → newest).
        #[arg(long, default_value_t = 0)]
        limit: usize,
        /// Return the FIRST `--limit` events (oldest-N) instead of the
        /// default last-N (newest-N). No effect when `--limit` is 0.
        #[arg(long)]
        oldest: bool,
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
        /// v0.7.0-alpha.16: bind to a Unix Domain Socket instead of TCP.
        /// When set, --bind is ignored. Implies --local-only semantics
        /// (no phonebook, no .well-known). Socket is chmod 0600 (owner-
        /// rw only), giving SO_PEERCRED-equivalent same-uid trust for
        /// sister sessions. Unix only (Windows refuses).
        #[arg(long)]
        uds: Option<std::path::PathBuf>,
    },
    /// Allocate a slot on a relay; bind it to this agent's identity.
    ///
    /// v0.5.19 (issue #7): if any peers are pinned to this agent's
    /// current slot, this command refuses by default — silent migration
    /// silently black-holes their inbound messages. Pass
    /// `--migrate-pinned` to acknowledge the risk and proceed, or use
    /// `wire rotate-slot` (which emits a `wire_close` event to peers)
    /// for safe rotation.
    BindRelay {
        /// Relay base URL, e.g. `http://127.0.0.1:8770`.
        url: String,
        /// Endpoint scope: `federation` | `local` | `lan` | `uds`.
        /// Default inferred from the URL (loopback host -> local,
        /// `unix://` -> uds, otherwise federation). Pass explicitly when
        /// the inference is ambiguous (e.g. a federation relay on a
        /// loopback address in tests).
        #[arg(long)]
        scope: Option<String>,
        /// DESTRUCTIVE: drop all existing self slots and bind only this
        /// relay (the pre-v0.12 single-slot behavior). Default is
        /// ADDITIVE — the new slot is appended to `self.endpoints[]`,
        /// keeping any existing slots so pinned peers are not
        /// black-holed.
        #[arg(long)]
        replace: bool,
        /// Acknowledge that pinned peers will black-hole until they
        /// re-pin manually. Required for `--replace` (and same-relay
        /// rotation) when `state.peers` is non-empty; ignored on fresh
        /// boxes. Use `wire rotate-slot` instead for the supported
        /// same-relay rotation path.
        #[arg(long)]
        migrate_pinned: bool,
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
    /// — fallback path; the canonical flow is `wire dial <handle>@<relay>`.)
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
    /// v0.14.2 (#170): multi-session topology view — supervisor
    /// liveness + per-session daemon liveness + unmanaged `wire daemon`
    /// pids. `wire status` answers "is THIS session syncing?";
    /// `wire supervisor` answers "what is the supervisor (and every
    /// session's daemon) doing across the box?". Replaces the manual
    /// `pgrep -fl 'wire daemon' | cross-ref each per-session pidfile`
    /// dance honey-pine ran during her launchd diagnosis.
    Supervisor {
        /// Emit JSON instead of human-readable text. The shape matches
        /// the `SupervisorState` struct in `daemon_supervisor.rs`.
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
        /// v0.14.2 (#162): supervisor mode — read the session registry +
        /// fork-exec one child `wire daemon` per initialized session,
        /// each with its own WIRE_HOME pinned. Closes the launchd-blind
        /// session-isolation gap honey-pine reported: with no cwd
        /// context, a single launchd-spawned daemon resolves the
        /// default WIRE_HOME and silently skips every other session.
        /// Operator-facing: install this mode via `wire service install`
        /// — the plist now uses `--all-sessions` so every session syncs
        /// at login without the operator running N tmux panes.
        #[arg(long)]
        all_sessions: bool,
        /// v0.14.2 (#162): run the daemon loop pinned to a specific
        /// named session by setting WIRE_HOME for the process. The
        /// supervisor (`--all-sessions`) spawns children with this
        /// flag; operators can also use it directly for a one-session
        /// foreground daemon outside the supervisor.
        #[arg(long)]
        session: Option<String>,
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
    /// Manage this session's identity display layer (character override).
    /// v0.7.0-alpha.3: agents can rename themselves — operator or Claude
    /// itself picks a custom nickname + emoji that overrides the
    /// auto-derived hash-based defaults.
    Identity {
        #[command(subcommand)]
        cmd: IdentityCommand,
    },
    /// v0.6.3 (issues #18 / #19 / #20 / #21): orchestration verbs for the
    /// sister-session mesh. `wire mesh status` is the live view of every
    /// paired sister (alias for `wire session mesh-status`); `wire mesh
    /// broadcast` fans one signed event to every pinned peer.
    #[command(subcommand)]
    Mesh(MeshCommand),
    /// Group chat (v0.13.3): create a named group, add VERIFIED peers, and
    /// send/tail messages across the whole member set. Membership is a signed
    /// roster (group-scoped tiers, separate from bilateral peer trust).
    #[command(subcommand)]
    Group(GroupCommand),
    /// Mint operator / organization identities for the offline org-membership
    /// layer (RFC-001): `wire enroll op` / `org-create` / `org-add-member`.
    #[command(subcommand)]
    Enroll(EnrollCommand),
    /// Detect known MCP host config locations (Claude Desktop, Claude Code,
    /// Cursor, project-local) and either print or auto-merge the wire MCP
    /// server entry. Default prints; pass `--apply` to actually modify config
    /// files. Idempotent — re-running is safe.
    Setup {
        /// Actually write the changes (default = print only).
        #[arg(long)]
        apply: bool,
        /// Install a Claude Code statusLine showing your wire persona
        /// (liveness dot + emoji + nickname in the persona's accent color +
        /// cwd) instead of merging the MCP server. Writes a renderer script
        /// and merges a `statusLine` block into Claude Code's settings.json
        /// (honors $CLAUDE_CONFIG_DIR). Combine with --apply to write.
        #[arg(long)]
        statusline: bool,
        /// With --statusline: uninstall it (drop the statusLine key + remove
        /// the renderer script) instead of installing.
        #[arg(long)]
        remove: bool,
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
        /// Peer handle (`nick@domain`), OR a bare sister-session name
        /// when `--local-sister` is set.
        handle: String,
        /// Override the relay base URL used for resolution.
        #[arg(long)]
        relay: Option<String>,
        /// v0.6.6: pair with a sister session on this machine without
        /// touching federation. Looks up `handle` as a session name in
        /// `wire session list`, reads that session's agent-card +
        /// endpoints from disk, pins directly, then delivers the
        /// `pair_drop` to the sister's local-relay slot. No `.well-known`
        /// resolution; reserved nicks (`wire`, `slancha`, etc.) are
        /// addressable because they don't need a federation claim.
        #[arg(long)]
        local_sister: bool,
        #[arg(long)]
        json: bool,
    },
    /// Come online in one command — `wire up` does what used to take five
    /// (init + bind-relay + claim your persona + background daemon +
    /// restart-on-login). Idempotent: re-run on an already-set-up box prints
    /// state without churn.
    ///
    /// There is no name to choose: your handle IS your DID-derived persona
    /// (one-name rule). The optional argument is just which relay to use.
    ///
    /// Examples:
    ///   wire up                        # default public relay (wireup.net)
    ///   wire up @wireup.net            # explicit federation relay
    ///   wire up http://127.0.0.1:8771  # a local / self-hosted relay
    Up {
        /// Relay to bind + claim your persona on: `@wireup.net`, `wireup.net`,
        /// or a full URL. Omit for the default public relay. No nick — your
        /// handle is your DID-derived persona.
        relay: Option<String>,
        /// Optional display name for your profile card (cosmetic; distinct
        /// from your addressable handle/persona).
        #[arg(long)]
        name: Option<String>,
        /// Also additively dual-bind a LOCAL relay slot for fast same-box
        /// sister-session routing. Defaults to probing
        /// `http://127.0.0.1:8771`; pass a URL to override. Local relays
        /// carry no handle directory, so nothing is claimed there.
        #[arg(long)]
        with_local: Option<String>,
        /// Skip the opportunistic local dual-bind entirely.
        #[arg(long)]
        no_local: bool,
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
    /// Update + restart in one step (alias: `wire update`). ALWAYS checks
    /// crates.io for a newer published wire; if one exists it installs it
    /// (via `cargo install slancha-wire` when a Rust toolchain is on PATH,
    /// else by downloading + SHA-256-verifying the prebuilt release binary
    /// and replacing this one in place), then does the atomic daemon swap —
    /// kill every `wire daemon`, respawn from the (now-current) binary, write
    /// a fresh pidfile. No newer version → it skips the install and just
    /// restarts the daemon. `--check` reports what would happen (available
    /// update + processes that would be restarted) without doing it;
    /// `--local` skips the crates.io check and only restarts the daemon
    /// (offline, or running a local dev build).
    #[command(visible_alias = "update")]
    Upgrade {
        /// Report current vs latest + drift without taking action.
        #[arg(long)]
        check: bool,
        /// Skip the crates.io update check; just restart the daemon from the
        /// current binary (offline / local dev build).
        #[arg(long)]
        local: bool,
        /// Also kill `wire mcp` server subprocesses after the daemon swap so
        /// their MCP host (Claude Code / Claude.app / Copilot CLI) respawns
        /// them on the new binary. Without this, sister sessions keep
        /// running pre-upgrade MCP code until each one explicitly `/mcp`
        /// reconnects. Cross-session impact: kills every `wire mcp` found.
        #[arg(long = "restart-mcp")]
        restart_mcp: bool,
        /// v0.14.3 (closes the #198 follow-up): kill the daemons reported in
        /// `wire supervisor`'s `stale_binary_sessions` set — sister-session
        /// children alive on an old binary that the supervisor's
        /// existing-pidfile check intentionally protected from respawn. Once
        /// each is killed, the `--all-sessions` supervisor respawns it on
        /// the new binary on its next 10s registry poll. Cross-session
        /// impact: only sessions flagged stale are touched; in-sync siblings
        /// are spared. No-op (silent) when no supervisor is running OR no
        /// stale daemons exist.
        #[arg(long = "refresh-stale-children")]
        refresh_stale_children: bool,
        #[arg(long)]
        json: bool,
    },
    /// Hard-reset this machine to a clean wire state: kill daemons,
    /// remove service units, de-register the wire MCP entry from host
    /// configs, and wipe all wire dirs. `--purge` also removes the
    /// binary + shell lines. Requires --force or a typed confirmation.
    Nuke {
        /// Skip the typed confirmation (for automation / test harness).
        /// `--yes` is an accepted alias.
        #[arg(long, visible_alias = "yes")]
        force: bool,
        /// Also remove the `wire` binary + shell PATH/env lines.
        #[arg(long)]
        purge: bool,
        /// Print what would be removed and exit without changing anything.
        #[arg(long)]
        dry_run: bool,
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
    /// Claim your persona on a relay's handle directory. Anyone can then
    /// reach this agent by `<persona>@<relay-domain>` via the relay's
    /// `.well-known/wire/agent` endpoint. FCFS; same-DID re-claims allowed.
    ///
    /// ONE-NAME RULE (v0.13.1): the claimed handle is always your DID-derived
    /// persona. The `nick` arg is vestigial — if it differs it is ignored
    /// (like the typed name `wire init` / `wire up` already ignore), so your
    /// phonebook entry can never drift from your agent-card handle.
    ///
    /// v0.13.1: hidden — `wire up` claims your persona for you. Kept callable
    /// (idempotent re-claim) but not a user verb; there is no nick to choose.
    #[command(hide = true)]
    Claim {
        /// Vestigial: ignored if it differs from your DID-derived persona.
        nick: String,
        /// Relay to claim the nick on. Default = relay our slot is on.
        #[arg(long)]
        relay: Option<String>,
        /// Public URL the relay should advertise to resolvers (default = relay).
        #[arg(long)]
        public_url: Option<String>,
        /// v0.5.19 (#9.1): opt out of the relay's bulk `/v1/handles`
        /// directory listing. The handle stays claimed (FCFS still
        /// applies) and direct `.well-known/wire/agent?handle=X` lookup
        /// still resolves, so peers you share the handle with out-of-band
        /// can still pair. Bulk scrapers / phonebook crawlers will not
        /// see the nick. Use this for handles meant for known-peer
        /// pairing only — see issue #9.
        #[arg(long)]
        hidden: bool,
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
    #[command(hide = true)] // v0.9 deprecated
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
    /// v0.9: accept a pending-inbound pair request by character
    /// nickname or card handle.
    ///
    /// v0.9.4: the URL-vs-name smart-dispatch from v0.9 is gone. To
    /// accept a federation invite URL use `wire accept-invite <URL>`
    /// (split out as an explicit verb to eliminate the input-shape
    /// ambiguity). `wire accept <URL>` still works for back-compat
    /// but emits a deprecation banner pointing at `accept-invite`.
    Accept {
        /// Pending peer name (character nickname or card handle).
        target: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// v0.9.4: accept a federation invite URL minted by `wire invite`.
    /// Pins issuer, sends signed card to issuer's slot. Auto-inits +
    /// auto-allocates as needed.
    ///
    /// Split out from `wire accept` to eliminate the URL-vs-name
    /// smart-dispatch ambiguity (peer handles can legitimately collide
    /// with URL-shaped strings; the explicit verb removes the inference).
    #[command(alias = "invite-accept")]
    AcceptInvite {
        /// The full invite URL (starts with `wire://pair?v=1&inv=...`).
        url: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// v0.9: refuse a pending-inbound pair request without pairing.
    Reject {
        /// Peer name (character nickname or handle) from `wire pending`.
        peer: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
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
    /// Silence (or re-enable) all wire desktop toasts. Persistent across
    /// daemon restarts via a file at `<config_dir>/quiet`. `wire quiet on`
    /// = silence; `wire quiet off` = restore; `wire quiet status` = report.
    /// Same effect as exporting `WIRE_NO_TOASTS=1` (the env-var override
    /// is for launchd contexts where the daemon's env isn't writable from
    /// the operator's shell).
    Quiet {
        #[command(subcommand)]
        action: QuietAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum QuietAction {
    /// Touch `<config_dir>/quiet` — silences every wire desktop toast
    /// (pair_drop, monitor, inbox). Idempotent.
    On,
    /// Remove `<config_dir>/quiet` — re-enables toasts. Idempotent (no
    /// error if already off / file absent).
    Off,
    /// Report current state: `on` (file present) / `off` (file absent) /
    /// `forced-on-by-env` (`WIRE_NO_TOASTS=1` in env, overrides file).
    Status {
        /// Emit `{"state": "...", "via": "file"|"env"|"none"}` JSON
        /// instead of the human one-liner.
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

/// `wire enroll …` — mint the operator/org identities + certs the offline
/// org-membership layer (RFC-001) consumes. Keys are stored 0600 alongside
/// `private.key`. (Publishing these claims on the agent's own card — the
/// card-emit integration — is a separate follow-up.)
#[derive(Subcommand, Debug)]
pub enum EnrollCommand {
    /// Mint this machine's operator root key (`op.key`) and print its `op_did`.
    Op {
        /// Operator handle (display only; the op_did commits to the key).
        #[arg(long, default_value = "operator")]
        handle: String,
        #[arg(long)]
        json: bool,
    },
    /// Mint an organization root key and print its `org_did` + `org_pubkey`.
    OrgCreate {
        /// Org handle (display only; the org_did commits to the key).
        #[arg(long)]
        handle: String,
        #[arg(long)]
        json: bool,
    },
    /// Issue a membership cert: the named org signs an operator's `op_did`.
    /// Prints the `{org_did, org_pubkey, member_cert}` bundle for the operator
    /// to add to their card's `org_memberships[]`.
    OrgAddMember {
        /// The operator DID to vouch for (`did:wire:op:…`).
        op_did: String,
        /// Which org signs (its `org_did`).
        #[arg(long)]
        org: String,
        #[arg(long)]
        json: bool,
    },
    /// Rebuild the agent card with the **current** enrollment state and
    /// republish to the phonebook. Closes the enroll-after-`init` DX gap:
    /// claims are normally attached at card-build time, but an operator who
    /// enrolls AFTER `init` has a stored card that pre-dates the claims. Run
    /// this once after `wire enroll op` / `org-add-member` to surface them.
    /// Idempotent: not-enrolled rebuilds a claims-free card; not-bound prints
    /// "local only".
    Republish {
        #[arg(long)]
        json: bool,
    },
    /// Ingest a membership cert handed to this operator by an org owner.
    ///
    /// Closes the DX gap surfaced in #127 (slate-lotus 2026-05-30 audit):
    /// `wire enroll org-add-member` printed an `{org_did, org_pubkey,
    /// member_cert}` bundle but the receiver had no verb to store it —
    /// joining an org required hand-editing
    /// `<config>/wire/memberships.json`. This verb wraps the existing
    /// `config::add_membership` helper + verifies the cert against
    /// `org_pubkey` and this operator's `op_did` before storing, so a
    /// malformed / wrong-key bundle fails loudly instead of corrupting
    /// the next `wire enroll republish`.
    ///
    /// Accepts either a single `--bundle '<json>'` (the verbatim
    /// org-add-member output) or the three fields separately. Idempotent:
    /// re-running with the same `org_did` replaces the prior entry.
    AddMembership {
        /// Verbatim `org-add-member` output (overrides individual flags
        /// when set). Shape: `{"org_did":"…","org_pubkey":"…","member_cert":"…"}`.
        #[arg(long)]
        bundle: Option<String>,
        /// Required when `--bundle` is not set.
        #[arg(long)]
        org: Option<String>,
        /// Required when `--bundle` is not set. Base64.
        #[arg(long = "org-pubkey")]
        org_pubkey: Option<String>,
        /// Required when `--bundle` is not set. Base64-encoded Ed25519
        /// signature by `org_pubkey` over this operator's `op_did`.
        #[arg(long = "member-cert")]
        member_cert: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum IdentityCommand {
    /// Print the current character (DID-derived, the only name).
    /// Equivalent to `wire whoami --short` but scoped here for grouping.
    Show {
        #[arg(long)]
        json: bool,
    },
    /// List all identities on this machine — one row per session, with
    /// each session's character, DID, federation handle, and cwd. Same
    /// shape as `wire session list`, scoped here for the v0.7+ noun-
    /// CLI surface.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Promote this identity to FEDERATION lifecycle: claim your persona on
    /// the relay so peers can `wire dial <persona>@<relay-domain>` you.
    /// Re-claims with current display fields so the relay always serves the
    /// latest signed card. Equivalent to `wire claim`.
    ///
    /// v0.13.1: hidden — `wire up` publishes your persona for you, and the
    /// nick is vestigial (one-name rule). Kept callable for re-publish.
    #[command(hide = true)]
    Publish {
        /// Vestigial: ignored; your handle is your DID-derived persona.
        nick: String,
        /// Override the relay URL. Defaults to the session's bound relay
        /// from `wire init --relay <url>`. Public relay if unset.
        #[arg(long)]
        relay: Option<String>,
        /// Public-facing URL for the agent-card location (when the relay
        /// is behind a CDN with a different public domain).
        #[arg(long, alias = "public")]
        public_url: Option<String>,
        /// Skip listing in the relay's public phonebook. The card is
        /// still claimable + reachable; just doesn't appear in
        /// `wireup.net/phonebook` for stranger-discovery.
        #[arg(long)]
        hidden: bool,
        #[arg(long)]
        json: bool,
    },
    /// Destroy a session entirely — keys, agent-card, relay state, daemon.
    /// Equivalent to `wire session destroy <name>`, scoped here for the
    /// noun-CLI surface. Requires `--force` (the underlying command does).
    Destroy {
        /// Session name to destroy (use `wire identity list` to see).
        name: String,
        /// Bypass the confirmation prompt.
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
    /// Create an identity in an EXPLICIT lifecycle state (vs. the
    /// implicit `wire init` + `wire claim` flow).
    /// v0.7.0-alpha.20 closes the v0.7+ identity-first noun-CLI.
    ///
    /// `--anonymous` puts the identity in a tmpdir (auto-cleanup on
    /// next reboot). In-memory semantics not yet supported — the
    /// pragmatic shape is "tmpdir + sentinel + register-for-cleanup."
    /// For pure-RAM identities, see v1.0 vision.
    ///
    /// `--local` is the explicit form of today's default; identity
    /// persists to the machine-wide sessions root.
    Create {
        /// Session name. Defaults to derived from cwd (anonymous mode
        /// uses a random name).
        #[arg(long)]
        name: Option<String>,
        /// Create an ANONYMOUS identity (tmpdir-backed, dies on
        /// reboot, no federation). Mutually exclusive with --local.
        #[arg(long, conflicts_with = "local")]
        anonymous: bool,
        /// Create a LOCAL identity (machine-persistent, no federation).
        /// Default — explicit flag for clarity.
        #[arg(long)]
        local: bool,
        #[arg(long)]
        json: bool,
    },
    /// Promote an ANONYMOUS identity to LOCAL — move from tmpdir to
    /// the machine-wide sessions root + register in the cwd map.
    /// After persist, the identity survives reboot.
    /// v0.7.0-alpha.20.
    Persist {
        /// The anonymous identity's name (from `wire identity list`).
        name: String,
        /// Optional rename during persist. Default: keep the anon name.
        #[arg(long = "as", value_name = "NEW_NAME")]
        as_name: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Demote an identity ONE level in the lifecycle:
    ///   federation → local: removes the relay slot binding but keeps
    ///   the keypair + agent-card. Operator can later re-publish with
    ///   `wire identity publish`. v0.7.0-alpha.20.
    ///
    /// (local → anonymous is not exposed; the safer flow is destroy +
    /// recreate, since "demoting" a persistent identity to ephemeral
    /// has surprising semantics — what about the keypair? what about
    /// pinned peers? Better to be explicit with destroy.)
    Demote {
        /// Session name to demote.
        name: String,
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
        /// v0.7.0-alpha.9: also allocate a slot on a LAN-bound relay
        /// (must be running e.g. via `wire relay-server --bind <LAN-IP>:8771`).
        /// Lets other machines on the same network reach this session
        /// directly without round-tripping the public federation relay
        /// at https://wireup.net. LAN endpoint is published in the
        /// agent-card; opt-in per session (default off).
        #[arg(long)]
        with_lan: bool,
        /// v0.7.0-alpha.9: LAN-reachable relay URL (no auto-detect of
        /// LAN IP — operator must type the address). Example:
        /// `http://192.168.1.50:8771`. Required when `--with-lan` is set.
        #[arg(long)]
        lan_relay: Option<String>,
        /// v0.7.0-alpha.18: also allocate a slot on a Unix Domain Socket
        /// relay (must be running e.g. via `wire relay-server --uds
        /// /tmp/wire.sock`). Same-host, owner-uid-only path that
        /// bypasses the macOS firewall + Tailscale userspace-netstack
        /// class of issues entirely for sister-session traffic. UDS
        /// endpoint is published in the agent-card.
        #[arg(long)]
        with_uds: bool,
        /// v0.7.0-alpha.18: UDS socket path. Required when `--with-uds`
        /// is set. Example: `/tmp/wire.sock` or
        /// `~/.wire/local.sock`.
        #[arg(long)]
        uds_socket: Option<std::path::PathBuf>,
        /// Skip spawning the session-local daemon. Use when you want
        /// to drive sync explicitly from the agent or test rig.
        #[arg(long)]
        no_daemon: bool,
        /// v0.6.6: create a federation-free session — no nick claim on
        /// `--relay`, no federation slot allocation. Implies
        /// `--with-local`. The session exists only to coordinate with
        /// other sister sessions on this machine; it has no public
        /// address and cannot be reached from outside. Reserved nicks
        /// (`wire`, `slancha`, etc.) are allowed because nothing tries
        /// to publish them.
        #[arg(long)]
        local_only: bool,
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
    /// v0.6.0 (issue #12): mesh-pair every sister session against every
    /// other in O(N²) handshakes. For each unordered pair (A, B) that
    /// is not already paired, drives the bilateral flow end-to-end:
    /// `wire add` from A → B (queued + pushed), `wire accept` on
    /// B's side, then a final pull on A so the ack lands. Idempotent —
    /// re-running skips pairs already in `state.peers`.
    ///
    /// **Trust anchor:** the operator running this command owns every
    /// session listed in `wire session list-local` (they all live under
    /// the same `$WIRE_HOME/sessions/` directory the operator chose).
    /// That filesystem-permission boundary IS the consent for both
    /// sides — the bilateral SAS / network-level handshake assumes
    /// strangers; same-uid sister sessions are by definition not
    /// strangers. Cross-uid sister sessions are out of scope; today
    /// `wire session list-local` only enumerates this user's sessions.
    PairAllLocal {
        /// Seconds to wait between handshake stages for pair_drop /
        /// pair_drop_ack to propagate over the relay. Default 1s
        /// (local-relay is typically <100ms RTT). Bump if you see
        /// "pending-inbound never arrived" errors on a slow relay.
        #[arg(long, default_value_t = 1)]
        settle_secs: u64,
        /// Federation relay to bind each `wire add` against. Default
        /// `https://wireup.net`. Sister sessions should be bound to
        /// the same federation relay; the pair handshake routes through
        /// it for the .well-known resolution + pair_drop deposit.
        #[arg(long, default_value = "https://wireup.net")]
        federation_relay: String,
        #[arg(long)]
        json: bool,
    },
    /// v0.6.2 (issue #18): live view of the sister-session mesh on this
    /// machine. Enumerates every session in `wire session list-local`,
    /// walks each session's `relay.json#peers` to find which other sister
    /// sessions it has pinned, and probes the local relay for each edge's
    /// `last_pull_at_unix` to surface stale/silent peers. Text output is
    /// the pin matrix + per-edge health roll-up; JSON is `{sessions, edges,
    /// local_relay, summary}` so scripts can scrape.
    ///
    /// Read-only — does NOT touch peers or daemons, only the relay's
    /// public `/v1/slot/<id>/state` endpoint with the slot tokens we
    /// already hold. Silent on any probe failure (degrades to "no
    /// signal" rather than abort) so a half-broken mesh is still
    /// inspectable.
    MeshStatus {
        /// Threshold in seconds for "stale" classification on an edge.
        /// An edge whose receiver hasn't polled their slot in this long
        /// is flagged. Default 300s (5 min) — same as the per-send
        /// `phyllis` attentiveness nag.
        #[arg(long, default_value_t = 300)]
        stale_secs: u64,
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
    /// Attach an existing session to the current cwd in the registry,
    /// so subsequent auto-detect from this cwd resolves to that session
    /// instead of walking up to an ancestor's binding. Use when an
    /// ancestor dir (e.g. `~/Source`) is already registered and is
    /// shadowing per-project identities for cwds beneath it. Idempotent;
    /// re-binding to the same name is a no-op. Re-binding to a different
    /// name overwrites the prior entry with a stderr warning.
    Bind {
        /// Session name to bind. Must already exist (run `wire session
        /// new <name>` first if not). With no name, auto-derives from
        /// `basename(cwd)` and errors if no session of that name exists.
        name: Option<String>,
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

/// v0.6.3: top-level `wire mesh` verbs. Each verb operates on the current
/// session's view of the pinned peer set. `status` is the read-only
/// observability primitive (alias for `wire session mesh-status`);
/// Group-chat verbs (v0.13.3). Membership is a creator-signed roster
/// (`src/group.rs`); send fans a signed message over the member set.
#[derive(Subcommand, Debug)]
pub enum GroupCommand {
    /// Create a new group — you become the creator + sole member, roster signed.
    Create {
        /// Group name (human label).
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Add a bilaterally-VERIFIED pinned peer to a group you created (Member tier).
    Add {
        /// Group id or name.
        group: String,
        /// Peer handle (must be a VERIFIED pinned peer).
        peer: String,
        #[arg(long)]
        json: bool,
    },
    /// Send a message to every other member of a group (signed fan-out).
    Send {
        /// Group id or name.
        group: String,
        /// Message text.
        message: String,
        #[arg(long)]
        json: bool,
    },
    /// Show recent messages received for a group.
    Tail {
        /// Group id or name.
        group: String,
        /// Max messages to show.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// List your groups + their members and tiers.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Mint a shareable join code for a group (a self-contained token carrying
    /// the room coords + signed roster). Anyone you give it to can `wire group
    /// join <code>` to enter the room at Introduced tier. The code IS the room
    /// key — share it only with people you want in the room.
    Invite {
        /// Group id or name.
        group: String,
        #[arg(long)]
        json: bool,
    },
    /// Join a group from a code minted by `wire group invite`. Materializes the
    /// room locally, pins the existing members on the creator's vouch, and
    /// announces you to the room so members can verify your messages.
    Join {
        /// The `wire-group:` code (or bare base64 payload).
        code: String,
        #[arg(long)]
        json: bool,
    },
}

/// `broadcast` fans a signed event to every pinned peer in one call.
#[derive(Subcommand, Debug)]
pub enum MeshCommand {
    /// Alias for `wire session mesh-status`. Reports the N×N pin matrix +
    /// per-edge health roll-up across every sister session on this machine.
    Status {
        /// Threshold in seconds for "stale" classification on an edge.
        #[arg(long, default_value_t = 300)]
        stale_secs: u64,
        #[arg(long)]
        json: bool,
    },
    /// Fan one signed event to every pinned peer. Each peer receives a
    /// distinct `event_id` but every copy shares the same `broadcast_id`
    /// UUID so receivers can correlate them as a single broadcast.
    ///
    /// `--scope local` (default) only fans to peers reachable via a same-
    /// machine local relay. `--scope federation` only to public-relay
    /// peers. `--scope both` to every pinned peer.
    ///
    /// `--exclude <peer>` (repeatable) skips a specific handle. Useful
    /// for "ack-loop" prevention: a peer responding to a broadcast can
    /// exclude its own broadcaster when re-broadcasting.
    ///
    /// Body parsing follows `wire send`: literal string, `@/path` reads a
    /// file, `-` reads stdin (JSON if parseable, else literal).
    ///
    /// Pinned-peers-only by construction. NEVER broadcasts to non-paired
    /// peers — that would re-introduce the phonebook-scrape risk closed
    /// in v0.5.14 (T8).
    Broadcast {
        /// Event kind: `claim` (default), `decision`, `question`, `ack`,
        /// `heartbeat`. Same vocabulary as `wire send`.
        #[arg(long, default_value = "claim")]
        kind: String,
        /// `local`, `federation`, or `both`. Default `local`.
        #[arg(long, default_value = "local")]
        scope: String,
        /// Skip a specific peer handle. Repeatable.
        #[arg(long)]
        exclude: Vec<String>,
        /// Drop the broadcast event ID from the relay-side attentiveness
        /// nag (`phyllis`) — useful when broadcasting to many peers and
        /// the per-peer "X hasn't pulled in 5min" lines would be noise.
        #[arg(long)]
        noreply: bool,
        /// Body — string, `@/path` for a file, or `-` for stdin.
        body: String,
        #[arg(long)]
        json: bool,
    },
    /// v0.6.4 (issue #20): assign role tags to sister sessions for
    /// capability-aware addressing. Stored as `profile.role` on the
    /// signed agent-card — propagates over the existing pair / .well-
    /// known plumbing, no new persistence.
    ///
    /// First slice of the Layer-2 capability metadata umbrella (#13).
    /// `wire mesh route` (issue #21) will consume these tags to pick
    /// the right sister for a task.
    Role {
        #[command(subcommand)]
        action: MeshRoleAction,
    },
    /// v0.6.5 (issue #21): capability-match routing. Resolve a role tag
    /// to one sister session and deliver an event to that one peer.
    /// Closes the orchestration-primitive arc opened in v0.6.0 — operators
    /// can now address "the reviewer" instead of hard-coding a handle.
    ///
    /// Strategies:
    ///   - `round-robin` (default): per-role cursor, persisted at
    ///     `<state_dir>/mesh-route-cursor.json`. Alternates fairly.
    ///   - `first`: alphabetically-first matching sister. Deterministic.
    ///   - `random`: uniform random among matches. Stateless.
    ///
    /// Pinned-peers-only by construction (same posture as `broadcast`).
    /// Caller must already have the target sister pinned in
    /// `state.peers` — otherwise we can't sign + push. Run
    /// `wire session pair-all-local` first if the mesh isn't wired.
    Route {
        /// Role to match (operator-defined tag from `wire mesh role set`).
        role: String,
        /// `round-robin` (default), `first`, or `random`.
        #[arg(long, default_value = "round-robin")]
        strategy: String,
        /// Skip a specific sister handle. Repeatable.
        #[arg(long)]
        exclude: Vec<String>,
        /// Event kind: `claim` (default), `decision`, `question`, `ack`,
        /// `heartbeat`. Same vocabulary as `wire send` / broadcast.
        #[arg(long, default_value = "claim")]
        kind: String,
        /// Body — string, `@/path` for a file, or `-` for stdin.
        body: String,
        #[arg(long)]
        json: bool,
    },
}

/// v0.6.4: subcommands of `wire mesh role`.
#[derive(Subcommand, Debug)]
pub enum MeshRoleAction {
    /// Assign self to a role. Role is a free-form ASCII string
    /// (alphanumeric + `-` + `_`, max 32 chars). Operators agree on
    /// the vocabulary out-of-band — common starters: `planner`,
    /// `executor`, `reviewer`, `coder`, `tester`, `dispatcher`.
    Set {
        role: String,
        #[arg(long)]
        json: bool,
    },
    /// Read self or a peer's role. With no arg, prints self. With a
    /// handle, reads from the peer's pinned agent-card.
    Get {
        peer: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List roles across every sister session on this machine. Reads
    /// each session's agent-card by path — no network, no env mutation.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Remove self from any assigned role. Re-signs the card with
    /// `profile.role: null`.
    Clear {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServiceAction {
    /// Write the launchd plist (macOS) or systemd user unit (linux) and
    /// load it. Idempotent — re-running re-bootstraps an existing service.
    ///
    /// v0.5.22: with no flags, installs the `wire daemon` (your sync
    /// process). Pass `--local-relay` to install the loopback relay
    /// (`wire relay-server --bind 127.0.0.1:8771 --local-only`) — the
    /// transport sister-Claudes use to coordinate on the same machine
    /// (v0.5.17 dual-slot). The two services have distinct labels +
    /// log files, so you can install both.
    Install {
        /// Install the local-relay service instead of the daemon.
        #[arg(long)]
        local_relay: bool,
        #[arg(long)]
        json: bool,
    },
    /// Unload + delete the service unit. Daemon keeps running until the
    /// next reboot or `wire upgrade`; this only changes the boot-time
    /// behaviour.
    Uninstall {
        /// Uninstall the local-relay service instead of the daemon.
        #[arg(long)]
        local_relay: bool,
        #[arg(long)]
        json: bool,
    },
    /// Report whether the unit is installed + active.
    Status {
        /// Show status of the local-relay service instead of the daemon.
        #[arg(long)]
        local_relay: bool,
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
    // v0.6.7: when WIRE_HOME isn't explicitly set, look up the cwd in
    // the session registry and adopt that session's home for this
    // process. Brings the CLI to parity with the v0.6.1 MCP auto-
    // detect — `wire whoami` / `wire monitor` from a project cwd now
    // resolve to that project's session identity, not the machine
    // default. Suppress the stderr line with `WIRE_QUIET_AUTOSESSION=1`.
    //
    // MUST run before any thread spawn — call it FIRST, before
    // `Cli::parse` (which uses clap internals only) and before any
    // command dispatch (which may spawn workers).
    crate::session::maybe_adopt_session_wire_home("cli");
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            handle,
            name,
            relay,
            offline,
            json,
        } => cmd_init(
            Some(&handle),
            name.as_deref(),
            relay.as_deref(),
            offline,
            json,
        ),
        Command::Status { peer, json } => {
            if let Some(peer) = peer {
                status::cmd_status_peer(&peer, json)
            } else {
                status::cmd_status(json)
            }
        }
        Command::Whoami {
            json,
            short,
            colored,
        } => cmd_whoami(json_default(json), short, colored),
        Command::Peers { json } => comms::cmd_peers(json_default(json)),
        Command::Here { json } => comms::cmd_here(json_default(json)),
        Command::Completions { shell } => {
            // v0.9.5: print shell completion script to stdout. Operator
            // pipes into their shell's completion dir; tab completion
            // covers verbs (dial, send, pending, accept, etc.) AND
            // their flags. Peer-name dynamic completion is a future
            // shell-side enhancement; clap_complete only ships the
            // static grammar.
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "wire", &mut std::io::stdout());
            Ok(())
        }
        Command::Pending { json } => pairing::cmd_pair_list_inbound(json_default(json)),
        Command::Reject { peer, json } => pairing::cmd_pair_reject(&peer, json_default(json)),
        Command::Send {
            peer,
            kind_or_body,
            body,
            deadline,
            no_auto_pair,
            queue,
            json,
        } => {
            // P0.S: smart-positional API. `wire send peer body` =
            // kind=claim. `wire send peer kind body` = explicit kind.
            let (kind, body) = match body {
                Some(real_body) => (kind_or_body, real_body),
                None => ("claim".to_string(), kind_or_body),
            };
            comms::cmd_send(
                &peer,
                &kind,
                &body,
                deadline.as_deref(),
                no_auto_pair,
                queue,
                json_default(json),
            )
        }
        Command::Dial {
            name,
            message,
            json,
        } => pairing::cmd_dial(&name, message.as_deref(), json_default(json)),
        Command::Tail {
            peer,
            json,
            limit,
            oldest,
        } => comms::cmd_tail(peer.as_deref(), json, limit, oldest),
        Command::Monitor {
            peer,
            json,
            include_handshake,
            interval_ms,
            replay,
        } => comms::cmd_monitor(
            peer.as_deref(),
            json,
            include_handshake,
            interval_ms,
            replay,
        ),
        Command::Verify { path, json } => comms::cmd_verify(&path, json),
        Command::Responder { command } => match command {
            ResponderCommand::Set {
                status,
                reason,
                json,
            } => status::cmd_responder_set(&status, reason.as_deref(), json),
            ResponderCommand::Get { peer, json } => {
                status::cmd_responder_get(peer.as_deref(), json)
            }
        },
        Command::Mcp => relay::cmd_mcp(),
        Command::RelayServer {
            bind,
            local_only,
            uds,
        } => relay::cmd_relay_server(&bind, local_only, uds.as_deref()),
        Command::BindRelay {
            url,
            scope,
            replace,
            migrate_pinned,
            json,
        } => relay::cmd_bind_relay(&url, scope.as_deref(), replace, migrate_pinned, json),
        Command::AddPeerSlot {
            handle,
            url,
            slot_id,
            slot_token,
            json,
        } => relay::cmd_add_peer_slot(&handle, &url, &slot_id, &slot_token, json),
        Command::Push { peer, json } => relay::cmd_push(peer.as_deref(), json),
        Command::Pull { json } => relay::cmd_pull(json),
        Command::Pin { card_file, json } => pairing::cmd_pin(&card_file, json),
        Command::RotateSlot { no_announce, json } => relay::cmd_rotate_slot(no_announce, json),
        Command::ForgetPeer {
            handle,
            purge,
            json,
        } => relay::cmd_forget_peer(&handle, purge, json),
        Command::Supervisor { json } => status::cmd_supervisor(json),
        Command::Daemon {
            interval,
            once,
            all_sessions,
            session,
            json,
        } => relay::cmd_daemon(interval, once, all_sessions, session, json),
        Command::Session(cmd) => cmd_session(cmd),
        Command::Identity { cmd } => cmd_identity(cmd),
        Command::Mesh(cmd) => cmd_mesh(cmd),
        Command::Group(cmd) => cmd_group(cmd),
        Command::Enroll(cmd) => cmd_enroll(cmd),
        Command::Invite {
            relay,
            ttl,
            uses,
            share,
            json,
        } => pairing::cmd_invite(&relay, ttl, uses, share, json),
        Command::Accept { target, json } => {
            // `wire accept <name>` — canonical pending-pair consent step.
            // URL-shaped input is no longer accepted here; use `wire accept-invite <url>`.
            let j = json_default(json);
            if target.starts_with("wire://pair?") || target.starts_with("http") {
                anyhow::bail!(
                    "`wire accept` takes a peer name, not a URL. \
                     Use `wire accept-invite {target}` to accept an invite URL."
                );
            } else {
                pairing::cmd_pair_accept(&target, j)
            }
        }
        Command::AcceptInvite { url, json } => pairing::cmd_accept(&url, json_default(json)),
        Command::Whois {
            handle,
            json,
            relay,
        } => {
            // v0.8 smart route: `wire whois <nickname>` (no `@<relay>`)
            // resolves through the local identity layer (pinned peers
            // + local sister sessions). `wire whois <nick>@<relay>`
            // keeps the existing federation `.well-known/wire/agent`
            // path. `wire whois` (no arg) prints self via the original
            // path. The character nickname is the canonical operator-
            // facing name as of v0.8 — most callers should hit the
            // local route.
            match handle.as_deref() {
                Some(h) if !h.contains('@') => pairing::cmd_whois_local(h, json),
                other => pairing::cmd_whois(other, json, relay.as_deref()),
            }
        }
        Command::Add {
            handle,
            relay,
            local_sister,
            json,
        } => pairing::cmd_add(&handle, relay.as_deref(), local_sister, json),
        Command::Up {
            relay,
            name,
            with_local,
            no_local,
            json,
        } => setup::cmd_up(
            relay.as_deref(),
            name.as_deref(),
            with_local.as_deref(),
            no_local,
            json,
        ),
        Command::Doctor {
            json,
            recent_rejections,
        } => status::cmd_doctor(json, recent_rejections),
        Command::Upgrade {
            check,
            local,
            restart_mcp,
            refresh_stale_children,
            json,
        } => upgrade::cmd_upgrade(check, local, restart_mcp, refresh_stale_children, json),
        Command::Service { action } => upgrade::cmd_service(action),
        Command::Diag { action } => status::cmd_diag(action),
        Command::Claim {
            nick,
            relay,
            public_url,
            hidden,
            json,
        } => cmd_claim(&nick, relay.as_deref(), public_url.as_deref(), hidden, json),
        Command::Profile { action } => cmd_profile(action),
        Command::Setup {
            apply,
            statusline,
            remove,
        } => {
            if statusline {
                setup::cmd_setup_statusline(apply, remove)
            } else {
                setup::cmd_setup(apply)
            }
        }
        Command::Notify {
            interval,
            peer,
            once,
            json,
        } => comms::cmd_notify(interval, peer.as_deref(), once, json),
        Command::Nuke {
            force,
            purge,
            dry_run,
            json,
        } => lifecycle::cmd_nuke(force, purge, dry_run, json),
        Command::Quiet { action } => lifecycle::cmd_quiet(action),
    }
}

// ---------- init ----------

pub(super) fn cmd_init(
    handle: Option<&str>,
    name: Option<&str>,
    relay: Option<&str>,
    offline: bool,
    as_json: bool,
) -> Result<()> {
    // One-name rule: a typed handle (if any) is only a vanity seed — the
    // persona is derived from the keypair fingerprint, so it has no effect
    // on the resulting identity. `wire up` passes None (there is no name to
    // type); an explicit `wire init <handle>` passes Some and we surface the
    // "ignored in favor of persona" notice for transparency.
    if let Some(h) = handle
        && !h
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("handle must be ASCII alphanumeric / '-' / '_' (got {h:?})");
    }
    if config::is_initialized()? {
        bail!(
            "already initialized — config exists at {:?}. Delete it first if you want a fresh identity.",
            config::config_dir()?
        );
    }
    // v0.9.1 smart-default reachability. If the operator passed neither
    // --relay nor --offline, probe the conventional local relay at
    // http://127.0.0.1:8771 and auto-attach if healthy. Closes the
    // silent-slotless footgun WITHOUT the v0.9 rejection wall, which
    // forced operators through a three-flag decision tree on first
    // invocation. Bare `wire init <handle>` is now ergonomic again
    // whenever a local relay is running (the common dev setup).
    //
    // Probe order:
    //   1. --relay <url>          → use it
    //   2. --offline               → skip slot allocation (rare power-user)
    //   3. local relay reachable  → auto-attach + log to stderr
    //   4. otherwise               → bail with actionable options
    let mut resolved_relay: Option<String> = relay.map(str::to_string);
    if resolved_relay.is_none() && !offline {
        let default_local = "http://127.0.0.1:8771";
        let client = crate::relay_client::RelayClient::new(default_local);
        if client.check_healthz().is_ok() {
            eprintln!(
                "wire init: local relay at {default_local} reachable — auto-attaching. \
                 Use --relay <url> to pick a different relay, --offline to skip."
            );
            resolved_relay = Some(default_local.to_string());
        } else {
            // v0.9.5: interactive prompt for first-time operators
            // when the smart-default can't auto-attach. Detect TTY on
            // stdin AND stderr — only prompt for humans. CI / agents
            // / non-interactive shells fall through to the explicit
            // error wall (unchanged behavior since v0.9.1).
            use std::io::{BufRead, IsTerminal, Write};
            let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
            if interactive && std::env::var("WIRE_NO_INTERACTIVE").is_err() {
                eprintln!("wire init: no local relay reachable at {default_local}.");
                eprint!(
                    "  Bind to public federation relay https://wireup.net instead? \
                     [Y/n/offline/url]: "
                );
                let _ = std::io::stderr().flush();
                let mut input = String::new();
                let _ = std::io::stdin().lock().read_line(&mut input);
                let answer = input.trim();
                match answer {
                    "" | "y" | "Y" | "yes" | "YES" => {
                        eprintln!("wire init: binding to https://wireup.net");
                        resolved_relay = Some("https://wireup.net".to_string());
                    }
                    "n" | "N" | "no" | "NO" => {
                        bail!(
                            "wire init: declined federation default; re-run with --relay <url> or --offline."
                        );
                    }
                    "offline" | "OFFLINE" => {
                        eprintln!(
                            "wire init: proceeding offline. \
                             Run `wire bind-relay <url>` before pairing."
                        );
                        // Fall through with resolved_relay still None;
                        // the `offline` flag is conceptually set but
                        // the caller's local doesn't need updating —
                        // resolved_relay = None + offline behavior
                        // is identical for the rest of cmd_init.
                    }
                    url if url.starts_with("http://") || url.starts_with("https://") => {
                        eprintln!("wire init: binding to {url}");
                        resolved_relay = Some(url.to_string());
                    }
                    other => {
                        bail!(
                            "wire init: unrecognized answer `{other}` — \
                             expected Y/n/offline/<url>. Re-run with --relay or --offline."
                        );
                    }
                }
            } else {
                bail!(
                    "wire init: no relay specified and no local relay reachable at \
                     http://127.0.0.1:8771.\n\
                     Pick one (or just run `wire up`):\n\
                     • `wire service install --local-relay` — start the local relay, then re-run\n\
                     • `wire up @wireup.net` — bind to public federation in one command\n\
                     • `wire init --offline` — generate keypair only \
                     (peers cannot reach you until you `wire bind-relay <url>` later)"
                );
            }
        }
    }
    let relay = resolved_relay.as_deref();

    config::ensure_dirs()?;
    let (sk_seed, pk_bytes) = generate_keypair();
    config::write_private_key(&sk_seed)?;

    // v0.11 ONE-NAME: derive the character nickname from a synthetic DID
    // using the freshly-generated pubkey, then USE THE CHARACTER as the
    // canonical handle. The operator-typed `handle` arg becomes either:
    //   - identical to character (already-canonical input — no-op), OR
    //   - overridden in favor of character (operator-typed name was a
    //     vanity layer that would never have been federation-reachable).
    // Either way, agent-card.handle ends up == character, and every
    // downstream surface (relay phonebook, .well-known, dial/send) keys
    // on the same name an operator sees in their statusline.
    //
    // Per the v0.11 directive: "If you can't call someone via a name,
    // don't let them have it as a name." Operator-typed handles violated
    // that rule because the character was the displayed name but the
    // handle was the addressable one. Now they're the same string.
    // The seed string only fills the (immediately-discarded) handle portion
    // of a synthetic DID; the persona derives from the fp suffix regardless,
    // so any seed yields the same identity.
    let seed = handle.unwrap_or("agent");
    let synth_did = crate::agent_card::did_for_with_key(seed, &pk_bytes);
    let character = crate::character::Character::from_did(&synth_did);
    let canonical_handle: &str = &character.nickname;
    if let Some(typed) = handle
        && typed != canonical_handle
    {
        eprintln!(
            "wire init: one-name rule — typed `{typed}` ignored in favor of \
             DID-derived persona `{canonical_handle}`. Peers will reach you as `{canonical_handle}`."
        );
    }

    let card = build_agent_card(canonical_handle, &pk_bytes, name, None, None);
    // Card-emit (RFC-001 Phase 1b): attach operator/org claims if enrolled
    // (fail-soft no-op otherwise; signed below so the sig covers the claims).
    let card = crate::enroll::with_op_claims_if_enrolled(card)?;
    let signed = sign_agent_card(&card, &sk_seed);
    config::write_agent_card(&signed)?;

    let mut trust = empty_trust();
    add_self_to_trust(&mut trust, canonical_handle, &pk_bytes);
    config::write_trust(&trust)?;

    let fp = fingerprint(&pk_bytes);
    let key_id = make_key_id(canonical_handle, &pk_bytes);
    // Rebind `handle` for the rest of cmd_init so downstream prints,
    // relay-state writes, etc. all reference the canonical name.
    let handle = canonical_handle;

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
            println!("next step: `wire dial <handle>@{url}` to pair with a peer.");
        } else {
            println!();
            println!("next step: `wire dial <handle>@<relay>` to bind a relay + pair with a peer.");
        }
    }
    Ok(())
}

pub(crate) fn scan_jsonl_dir(dir: &std::path::Path) -> Result<Value> {
    if !dir.exists() {
        return Ok(json!({"files": 0, "events": 0}));
    }
    let mut files = 0usize;
    let mut events = 0usize;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        // v0.14.2: skip pushed-log audit files (`<peer>.pushed.jsonl`)
        // when scanning the outbox dir. Those are append-only audit
        // logs of "queued → pushed" lifecycle events (#162 fix #2);
        // counting them as outbox events inflates `outbox.events` in
        // `wire status` by orders of magnitude. Pre-fix, an operator
        // with 8328 events delivered across a peer's lifetime saw
        // "outbox: 71811 events queued" when actual unpushed work was
        // 11 events. Inbox scans are unaffected because the inbox dir
        // contains only `<peer>.jsonl`, never `.pushed.jsonl`.
        if path.extension().map(|x| x == "jsonl").unwrap_or(false)
            && !path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|n| n.ends_with(".pushed.jsonl"))
                .unwrap_or(false)
        {
            files += 1;
            if let Ok(body) = std::fs::read_to_string(&path) {
                events += body.lines().filter(|l| !l.trim().is_empty()).count();
            }
        }
    }
    Ok(json!({"files": files, "events": events}))
}

// (Old cmd_join stub removed — superseded by wire_dial / cmd_pair_accept.)

// ---------- whoami ----------

/// Return the current cwd with the user's home dir abbreviated to `~/`.
/// Used in whoami `--short` / `--colored` output so multi-window operators
/// see *what project* each Claude is working in alongside the character.
fn current_cwd_display() -> String {
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(_) => return String::from("?"),
    };
    if let Some(home) = dirs::home_dir()
        && let Ok(rel) = cwd.strip_prefix(&home)
    {
        // strip_prefix returns "" for cwd == home itself; show "~" then.
        let rel_str = rel.to_string_lossy();
        if rel_str.is_empty() {
            return String::from("~");
        }
        return format!("~/{rel_str}");
    }
    cwd.to_string_lossy().into_owned()
}

/// v0.14: extract the inline op claims from an agent card (or pinned
/// trust row) for surfacing on operator-facing read paths. Returns the
/// subset of fields actually present and non-null — operators read the
/// absence to mean "not enrolled / older peer".
///
/// Surfaced fields: `op_did`, `op_pubkey`, `op_cert`, `org_memberships`,
/// `schema_version`. All RFC-001-defined; all public commits, safe to
/// surface on every read verb. Centralized here so whoami / peers / whois
/// stay in lock-step as the inline set grows (e.g. `sso_attest` in v0.15).
///
/// `pub(crate)` so the MCP surface (`src/mcp.rs`) wires the same helper
/// into `tool_whoami` / `tool_peers` — agents reading MCP responses must
/// see the same op claims that operators see via CLI.
pub(crate) fn op_claims_from_card(card: &Value) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    for key in [
        "op_did",
        "op_pubkey",
        "op_cert",
        "org_memberships",
        "schema_version",
    ] {
        if let Some(v) = card.get(key)
            && !v.is_null()
        {
            out.insert(key.to_string(), v.clone());
        }
    }
    out
}

fn cmd_whoami(as_json: bool, short: bool, colored: bool) -> Result<()> {
    if !config::is_initialized()? {
        // v0.14.x: with per-session WIRE_HOME (`sessions/by-key/<hash>`), a
        // freshly-spawned session's home starts EMPTY until `wire up`. The
        // machine-readable consumers that poll whoami every render — statusline
        // scripts, the `.wire-name` cache refreshers — hit that uninitialized
        // state constantly. Bailing (exit 1, no stdout) made them crash on
        // empty stdin or freeze on a stale name. Degrade gracefully here,
        // matching `wire here --json`, so a missing identity is a parseable
        // signal rather than a hard failure. The bare interactive (tty, no
        // JSON) path keeps its actionable hint + exit 1.
        // Precedence mirrors the initialized path below: an explicit --short
        // / --colored beats the piped-stdout JSON default (`json_default`),
        // and bare interactive `wire whoami` still gets the actionable hint.
        if short {
            println!("(uninitialized) · {}", current_cwd_display());
            return Ok(());
        }
        if colored {
            println!(
                "\x1b[2m(uninitialized)\x1b[0m \x1b[2m·\x1b[0m {}",
                current_cwd_display()
            );
            return Ok(());
        }
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "initialized": false,
                    "cwd": current_cwd_display(),
                }))?
            );
            return Ok(());
        }
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
    // v0.11: character is purely DID-derived. No overrides — the
    // operator-rename verb is gone and display.json reads are stripped
    // because they introduced a second name that peers couldn't find.
    let character = crate::character::Character::from_did(&did);

    // v0.7.0-alpha.3: append the current cwd (home-abbreviated to `~/`)
    // so operators tab-flipping between multiple Claude windows see both
    // *who* this session is (character) and *what* it's working on (cwd).
    // The cwd is the OPERATOR's cwd, not WIRE_HOME — gives them the
    // anchor they're looking for: "🐅 winter-bay · ~/Source/wire".
    let cwd_display = current_cwd_display();

    // Fast paths used by statuslines, piping, scripts. No agent-card parsing
    // beyond did — these calls are hot (statusline polls ~300ms).
    if short {
        println!("{} · {}", character.short(), cwd_display);
        return Ok(());
    }
    if colored {
        println!("{} \x1b[2m·\x1b[0m {}", character.colored(), cwd_display);
        return Ok(());
    }

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
        // v0.11: character_override is always false now (no rename verb,
        // no display.json reads). Field stays for back-compat with v0.10
        // JSON consumers that key off it.
        let has_override = false;
        let mut payload = serde_json::Map::new();
        // Symmetric with the uninitialized branch above so consumers can
        // branch on a single key instead of probing for `did`.
        payload.insert("initialized".into(), json!(true));
        payload.insert("did".into(), json!(did));
        payload.insert("handle".into(), json!(handle));
        payload.insert("fingerprint".into(), json!(fp));
        payload.insert("key_id".into(), json!(key_id));
        payload.insert("public_key_b64".into(), json!(pk_b64));
        payload.insert("capabilities".into(), capabilities);
        payload.insert(
            "config_dir".into(),
            json!(config::config_dir()?.to_string_lossy()),
        );
        // RFC-008 §A: surface WHICH signal won session/home resolution, so an
        // operator diagnosing a wrong/shared identity sees the cause in one
        // command instead of a forensic deep-dive (cf. #210). Additive,
        // read-only; absent only on pre-RFC-008 binaries.
        payload.insert(
            "session_source".into(),
            json!(crate::session::session_source()),
        );
        payload.insert("persona".into(), serde_json::to_value(&character)?);
        payload.insert("persona_override".into(), json!(has_override));
        // v0.14: surface the RFC-001 op claims (when enrolled) on the
        // canonical operator read verb. Absent ⇒ pre-v0.14 card or not
        // yet enrolled. See `op_claims_from_card` rationale.
        for (k, v) in op_claims_from_card(&card) {
            payload.insert(k, v);
        }
        println!("{}", serde_json::to_string(&payload)?);
    } else {
        println!("{}", character.colored());
        println!("{did} (ed25519:{key_id})");
        println!("fingerprint: {fp}");
        println!("capabilities: {capabilities}");
        // v0.14: when enrolled, surface op_did + membership count so
        // the operator can spot at a glance whether the marquee identity
        // layer is active. Silent when not enrolled (no clutter for
        // pre-v0.14 cards).
        if let Some(op_did) = card.get("op_did").and_then(Value::as_str) {
            let memberships = card
                .get("org_memberships")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            let plural = if memberships == 1 { "" } else { "s" };
            println!("enrolled: {op_did} ({memberships} org membership{plural})");
        }
    }
    Ok(())
}

// ---------- identity (v0.7.0-alpha.3) ----------

fn cmd_enroll(cmd: EnrollCommand) -> Result<()> {
    match cmd {
        EnrollCommand::Op { handle, json } => {
            let (sk, pk) = crate::signing::generate_keypair();
            crate::config::write_op_key(&sk)?;
            crate::config::write_op_handle(&handle)?;
            let op_did = crate::agent_card::did_for_op(&handle, &pk);
            let op_pubkey = crate::signing::b64encode(&pk);
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({"op_did": op_did, "op_pubkey": op_pubkey}))?
                );
            } else {
                println!(
                    "→ operator enrolled\n  op_did:    {op_did}\n  op_pubkey: {op_pubkey}\n  key saved 0600 at {:?}",
                    crate::config::op_key_path()?
                );
            }
            Ok(())
        }
        EnrollCommand::OrgCreate { handle, json } => {
            let (sk, pk) = crate::signing::generate_keypair();
            let org_did = crate::agent_card::did_for_org(&handle, &pk);
            crate::config::write_org_key(&org_did, &sk)?;
            let org_pubkey = crate::signing::b64encode(&pk);
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({"org_did": org_did, "org_pubkey": org_pubkey}))?
                );
            } else {
                println!(
                    "→ organization created\n  org_did:    {org_did}\n  org_pubkey: {org_pubkey}\n  key saved 0600 at {:?}",
                    crate::config::org_key_path(&org_did)?
                );
            }
            Ok(())
        }
        EnrollCommand::OrgAddMember { op_did, org, json } => {
            if !crate::agent_card::is_op_did(&op_did) {
                bail!("not a valid operator DID (did:wire:op:<handle>-<32hex>): {op_did}");
            }
            let org_sk = crate::config::read_org_key(&org).with_context(|| {
                format!("no stored key for org {org} — run `wire enroll org-create` first")
            })?;
            let org_pk = ed25519_dalek::SigningKey::from_bytes(&org_sk)
                .verifying_key()
                .to_bytes();
            let member_cert = crate::enroll::issue_member_cert(&org_sk, &op_did)?;
            let org_pubkey = crate::signing::b64encode(&org_pk);
            // Store locally so card-emit can attach it (same-machine operator);
            // also printed below for the cross-machine share case.
            crate::config::add_membership(&org, &org_pubkey, &member_cert)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "org_did": org, "org_pubkey": org_pubkey, "member_cert": member_cert
                    }))?
                );
            } else {
                println!(
                    "→ membership issued for {op_did}\n  add to the operator's card org_memberships[]:\n  {{\"org_did\": \"{org}\", \"org_pubkey\": \"{org_pubkey}\", \"member_cert\": \"{member_cert}\"}}"
                );
            }
            Ok(())
        }
        EnrollCommand::AddMembership {
            bundle,
            org,
            org_pubkey,
            member_cert,
            json,
        } => cmd_enroll_add_membership(bundle, org, org_pubkey, member_cert, json),
        EnrollCommand::Republish { json } => {
            // Rebuild the on-disk card with current enrollment, then republish
            // via the same path `profile set` uses. Closes the enroll-after-init
            // DX gap (see `enroll::rebuild_card_with_current_claims`).
            let card = crate::enroll::rebuild_card_with_current_claims()?;
            let published = republish_card_to_phonebook();
            let op_did = card
                .get("op_did")
                .and_then(Value::as_str)
                .map(str::to_string);
            let n_memberships = card
                .get("org_memberships")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "op_did": op_did,
                        "org_memberships": n_memberships,
                        "published": published,
                    }))?
                );
            } else {
                match op_did {
                    Some(did) => println!(
                        "→ card rebuilt with current enrollment\n  op_did:    {did}\n  memberships: {n_memberships}"
                    ),
                    None => println!(
                        "→ card rebuilt — no operator enrolled (claims stripped if previously present)"
                    ),
                }
                print_profile_publish_result(&published);
            }
            Ok(())
        }
    }
}

/// Implementation of `wire enroll add-membership` (closes #127).
///
/// Validates the bundle before storing — a malformed / wrong-key cert
/// would corrupt the next `wire enroll republish` (the bundle is
/// attached verbatim to the agent card; a bad bundle propagates to
/// peers and gets rejected on `evaluate_card_membership`). Verifying
/// up-front means the failure is at ingest time, not at publish time.
fn cmd_enroll_add_membership(
    bundle: Option<String>,
    org: Option<String>,
    org_pubkey: Option<String>,
    member_cert: Option<String>,
    as_json: bool,
) -> Result<()> {
    // Resolve the three fields from either --bundle or the individual flags.
    let (org_did, org_pk_b64, cert_b64) = if let Some(b) = bundle {
        let v: Value = serde_json::from_str(&b).with_context(|| "parsing --bundle as JSON")?;
        let o = v
            .get("org_did")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("--bundle missing 'org_did'"))?
            .to_string();
        let p = v
            .get("org_pubkey")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("--bundle missing 'org_pubkey'"))?
            .to_string();
        let c = v
            .get("member_cert")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("--bundle missing 'member_cert'"))?
            .to_string();
        (o, p, c)
    } else {
        let o = org.ok_or_else(|| anyhow!("--org is required when --bundle is not set"))?;
        let p = org_pubkey
            .ok_or_else(|| anyhow!("--org-pubkey is required when --bundle is not set"))?;
        let c = member_cert
            .ok_or_else(|| anyhow!("--member-cert is required when --bundle is not set"))?;
        (o, p, c)
    };

    // Validate org_did shape — refuse before touching disk.
    if !crate::agent_card::is_org_did(&org_did) {
        bail!("not a valid organization DID (did:wire:org:<handle>-<32hex>): {org_did}");
    }

    // This operator must be enrolled — we need op_did to verify the cert
    // is FOR US, not for a different operator. A cert valid against some
    // other op_did would still verify on the org_pubkey but storing it
    // here would be a misattribution.
    let op_sk = crate::config::read_op_key().with_context(
        || "this operator is not enrolled — run `wire enroll op` first to mint op_did",
    )?;
    let op_handle = crate::config::read_op_handle()
        .ok()
        .flatten()
        .unwrap_or_else(|| "operator".to_string());
    let op_pk = ed25519_dalek::SigningKey::from_bytes(&op_sk)
        .verifying_key()
        .to_bytes();
    let op_did = crate::agent_card::did_for_op(&op_handle, &op_pk);

    // Decode + verify the cert against org_pubkey + this op_did. Failure
    // here is the load-bearing guard against the "stored bundle corrupts
    // republish" footgun.
    let org_pk_bytes =
        crate::signing::b64decode(&org_pk_b64).with_context(|| "decoding --org-pubkey (base64)")?;
    crate::identity::verify_member_cert(&org_pk_bytes, &cert_b64, &op_did)
        .map_err(|e| anyhow!("member_cert verification failed: {e:?} — bundle is not valid for this operator (op_did={op_did})"))?;

    // Idempotent store. add_membership retains-then-pushes so re-running
    // with the same org_did replaces the prior entry; multiple distinct
    // orgs accumulate.
    crate::config::add_membership(&org_did, &org_pk_b64, &cert_b64)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "stored": true,
                "org_did": org_did,
                "op_did": op_did,
                "note": "run `wire enroll republish` to attach the claim to your agent card and republish",
            }))?
        );
    } else {
        println!(
            "→ membership stored\n  org_did:  {org_did}\n  op_did:   {op_did}\n  next: `wire enroll republish` to attach + publish"
        );
    }
    Ok(())
}

fn cmd_identity(cmd: IdentityCommand) -> Result<()> {
    match cmd {
        // v0.11: IdentityCommand::Rename deleted. The character is the
        // one canonical name (DID-derived); a local-display rename
        // would create a second name peers can't find, violating the
        // "names must be findable" invariant. Aliases (if needed
        // later) become relay-claimed entries that ARE findable —
        // a different architectural shape from rename.
        IdentityCommand::Show { json } => cmd_whoami(json, !json, false),
        IdentityCommand::List { json } => cmd_session_list(json),
        IdentityCommand::Publish {
            nick,
            relay,
            public_url,
            hidden,
            json,
        } => cmd_claim(&nick, relay.as_deref(), public_url.as_deref(), hidden, json),
        IdentityCommand::Destroy { name, force, json } => cmd_session_destroy(&name, force, json),
        IdentityCommand::Create {
            name,
            anonymous,
            local: _,
            json,
        } => cmd_identity_create(name.as_deref(), anonymous, json),
        IdentityCommand::Persist {
            name,
            as_name,
            json,
        } => cmd_identity_persist(&name, as_name.as_deref(), json),
        IdentityCommand::Demote { name, json } => cmd_identity_demote(&name, json),
    }
}

/// v0.7.0-alpha.20: anonymous identity = sessions root remapped to a
/// per-invocation tmpdir. Operator gets a `WIRE_HOME=...` export they
/// paste into their shell; the identity lives there until reboot
/// clears /tmp. Persist promotes it to the real sessions root.
fn cmd_identity_create(name: Option<&str>, anonymous: bool, as_json: bool) -> Result<()> {
    if anonymous {
        // Generate a unique tmpdir for this anonymous identity.
        let rand_suffix = format!("{:08x}", rand::random::<u32>());
        let anon_name = name
            .map(crate::session::sanitize_name)
            .unwrap_or_else(|| format!("anon-{rand_suffix}"));
        let anon_root = std::env::temp_dir().join(format!("wire-anon-{rand_suffix}"));
        std::fs::create_dir_all(&anon_root)
            .with_context(|| format!("creating anon root {anon_root:?}"))?;
        // Run `wire init <name>` with WIRE_HOME = anon_root/sessions/<name>
        let session_home = anon_root.join("sessions").join(&anon_name);
        std::fs::create_dir_all(&session_home)?;
        let status = run_wire_with_home(&session_home, &["init", &anon_name, "--offline"])?;
        if !status.success() {
            bail!("anonymous identity init failed: {status}");
        }
        // Register the anonymous name in a SIDE registry so persist
        // can find it later. Stored at <anon_root>/anon-marker.json.
        let marker = anon_root.join("anon-marker.json");
        std::fs::write(
            &marker,
            serde_json::to_vec_pretty(&serde_json::json!({
                "name": anon_name,
                "session_home": session_home.to_string_lossy(),
                "created_at": time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                "kind": "anonymous",
            }))?,
        )?;
        let card = serde_json::from_slice::<Value>(&std::fs::read(
            session_home
                .join("config")
                .join("wire")
                .join("agent-card.json"),
        )?)?;
        let did = card
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "kind": "anonymous",
                    "name": anon_name,
                    "did": did,
                    "session_home": session_home.to_string_lossy(),
                    "anon_root": anon_root.to_string_lossy(),
                }))?
            );
        } else {
            println!("created anonymous identity `{anon_name}` ({did})");
            println!(
                "  session_home: {} (dies on reboot — /tmp)",
                session_home.display()
            );
            println!();
            println!("activate in this shell:");
            println!("  export WIRE_HOME={}", session_home.display());
            println!();
            println!("promote to persistent later with:");
            println!("  wire identity persist {anon_name}");
        }
        return Ok(());
    }
    // --local (or default): delegate to existing session new flow.
    let name_arg = name.map(|s| s.to_string());
    cmd_session_new(
        name_arg.as_deref(),
        "https://wireup.net",
        false,
        "http://127.0.0.1:8771",
        false,
        None,
        false,
        None,
        true, // no_daemon: identity create just allocates the identity, no daemon
        true, // local_only: explicit lifecycle
        as_json,
    )
}

/// v0.7.0-alpha.20: promote anonymous → local. Moves session dir from
/// tmpdir to the persistent sessions root + registers in the cwd map.
fn cmd_identity_persist(name: &str, as_name: Option<&str>, as_json: bool) -> Result<()> {
    // Find the anon-marker.json by scanning /tmp/wire-anon-*.
    let temp = std::env::temp_dir();
    let mut found: Option<(std::path::PathBuf, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(&temp)?.flatten() {
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.starts_with("wire-anon-"))
            .unwrap_or(false)
        {
            continue;
        }
        let marker = path.join("anon-marker.json");
        if let Ok(bytes) = std::fs::read(&marker)
            && let Ok(json) = serde_json::from_slice::<Value>(&bytes)
            && json.get("name").and_then(Value::as_str) == Some(name)
        {
            let session_home = json
                .get("session_home")
                .and_then(Value::as_str)
                .map(std::path::PathBuf::from)
                .ok_or_else(|| anyhow!("anon-marker {marker:?} missing session_home"))?;
            found = Some((path, session_home));
            break;
        }
    }
    let (anon_root, anon_session_home) = found.ok_or_else(|| {
        anyhow!(
            "no anonymous identity named `{name}` found in /tmp/wire-anon-* — \
             run `wire identity list` to see available identities"
        )
    })?;

    let new_name = as_name.unwrap_or(name);
    let new_session_home = crate::session::session_dir(new_name)?;
    if new_session_home.exists() {
        bail!(
            "target session `{new_name}` already exists at {new_session_home:?} — \
             pick a different name with --as <new-name>"
        );
    }

    // Move the session dir from tmpdir to persistent root.
    if let Some(parent) = new_session_home.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&anon_session_home, &new_session_home)
        .with_context(|| format!("rename {anon_session_home:?} → {new_session_home:?}"))?;

    // Clean up the (now-empty) anon root + marker.
    let _ = std::fs::remove_dir_all(&anon_root);

    // Register cwd → new_name (operator may have cd'd elsewhere; use the
    // session_home's grandparent as the conceptual "cwd" if no other).
    let cwd = std::env::current_dir().unwrap_or_else(|_| new_session_home.clone());
    let cwd_key = crate::session::normalize_cwd_key(&cwd);
    let new_name_for_reg = new_name.to_string();
    if let Err(e) = crate::session::update_registry(|reg| {
        reg.by_cwd.insert(cwd_key, new_name_for_reg);
        Ok(())
    }) {
        eprintln!("wire identity persist: failed to update registry: {e:#}");
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "kind": "persisted",
                "from_name": name,
                "to_name": new_name,
                "session_home": new_session_home.to_string_lossy(),
            }))?
        );
    } else {
        println!("persisted anonymous identity `{name}` → local session `{new_name}`");
        println!(
            "  session_home: {} (survives reboot)",
            new_session_home.display()
        );
        println!("  registered cwd: {}", cwd.display());
    }
    Ok(())
}

/// v0.7.0-alpha.20: demote federation → local. Removes the federation
/// slot binding from relay.json (and the legacy top-level fields). Keeps
/// the keypair + agent-card so re-publish later just calls `wire identity
/// publish` again. local → anonymous is NOT supported; destroy + recreate
/// is the safer path for that step-down.
fn cmd_identity_demote(name: &str, as_json: bool) -> Result<()> {
    let sessions = crate::session::list_sessions()?;
    let session = sessions
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| anyhow!("no session named `{name}` (run `wire identity list`)"))?;
    let relay_state_path = session
        .home_dir
        .join("config")
        .join("wire")
        .join("relay.json");
    if !relay_state_path.exists() {
        bail!("session `{name}` has no relay state — already demoted?");
    }
    let mut state: Value = serde_json::from_slice(&std::fs::read(&relay_state_path)?)?;
    let self_obj = state.get("self").cloned().unwrap_or(Value::Null);
    let had_fed = self_obj
        .get("relay_url")
        .and_then(Value::as_str)
        .map(|u| {
            u.starts_with("https://") || (u.starts_with("http://") && !u.contains("127.0.0.1"))
        })
        .unwrap_or(false);
    if !had_fed {
        if as_json {
            println!(
                "{}",
                serde_json::to_string(
                    &json!({"name": name, "status": "no-op", "reason": "no federation slot"})
                )?
            );
        } else {
            println!("session `{name}` has no federation slot — nothing to demote");
        }
        return Ok(());
    }
    // Strip federation: remove top-level relay_url/slot_id/slot_token,
    // remove federation-scope entries from endpoints[].
    if let Some(self_mut) = state
        .as_object_mut()
        .and_then(|m| m.get_mut("self"))
        .and_then(|s| s.as_object_mut())
    {
        self_mut.remove("relay_url");
        self_mut.remove("slot_id");
        self_mut.remove("slot_token");
        if let Some(eps) = self_mut.get_mut("endpoints").and_then(|e| e.as_array_mut()) {
            eps.retain(|ep| ep.get("scope").and_then(Value::as_str) != Some("federation"));
        }
    }
    std::fs::write(&relay_state_path, serde_json::to_vec_pretty(&state)?)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(
                &json!({"name": name, "status": "demoted", "from": "federation", "to": "local"})
            )?
        );
    } else {
        println!("demoted `{name}` from federation → local");
        println!("  relay slot binding removed; keypair + agent-card retained");
        println!("  re-publish with `wire identity publish <nick>`");
    }
    Ok(())
}

/// Thin wrapper — kept as a function for tests + back-compat with
/// the small handful of callsites that already use this name.
/// Implementation moved to `crate::trust::effective_tier` so the
/// canonical derivation is shared with `compute_pending_push_breakdown`.
pub(super) fn effective_peer_tier(trust: &Value, relay_state: &Value, handle: &str) -> String {
    crate::trust::effective_tier(trust, relay_state, handle)
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

pub(super) fn parse_kind(s: &str) -> Result<u32> {
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

// ---------- session (v0.5.16) ----------
//
// Multi-session wire on one machine. See src/session.rs for the storage
// layout + naming rules. The CLI dispatcher here orchestrates child
// `wire` invocations with `WIRE_HOME` overridden to the session's dir;
// each session-local `init` / `claim` / `daemon` runs in its own world
// without cross-contamination via env vars in this process.

// ---------- group chat (v0.13.3) ----------

fn cmd_group(cmd: GroupCommand) -> Result<()> {
    match cmd {
        GroupCommand::Create { name, json } => group::cmd_group_create(&name, json),
        GroupCommand::Add { group, peer, json } => group::cmd_group_add(&group, &peer, json),
        GroupCommand::Send {
            group,
            message,
            json,
        } => group::cmd_group_send(&group, &message, json),
        GroupCommand::Tail { group, limit, json } => group::cmd_group_tail(&group, limit, json),
        GroupCommand::List { json } => group::cmd_group_list(json),
        GroupCommand::Invite { group, json } => group::cmd_group_invite(&group, json),
        GroupCommand::Join { code, json } => group::cmd_group_join(&code, json),
    }
}

/// v0.6.3: top-level `wire mesh` verb dispatcher. Status aliases the
/// v0.6.2 session-namespaced handler; broadcast is the new primitive.
fn cmd_mesh(cmd: MeshCommand) -> Result<()> {
    match cmd {
        MeshCommand::Status { stale_secs, json } => cmd_session_mesh_status(stale_secs, json),
        MeshCommand::Broadcast {
            kind,
            scope,
            exclude,
            noreply,
            body,
            json,
        } => mesh::cmd_mesh_broadcast(&kind, &scope, &exclude, noreply, &body, json),
        MeshCommand::Role { action } => mesh::cmd_mesh_role(action),
        MeshCommand::Route {
            role,
            strategy,
            exclude,
            kind,
            body,
            json,
        } => mesh::cmd_mesh_route(&role, &strategy, &exclude, &kind, &body, json),
    }
}

fn cmd_session(cmd: SessionCommand) -> Result<()> {
    match cmd {
        SessionCommand::New {
            name,
            relay,
            with_local,
            local_relay,
            with_lan,
            lan_relay,
            with_uds,
            uds_socket,
            no_daemon,
            local_only,
            json,
        } => cmd_session_new(
            name.as_deref(),
            &relay,
            with_local,
            &local_relay,
            with_lan,
            lan_relay.as_deref(),
            with_uds,
            uds_socket.as_deref(),
            no_daemon,
            local_only,
            json,
        ),
        SessionCommand::List { json } => cmd_session_list(json),
        SessionCommand::ListLocal { json } => cmd_session_list_local(json),
        SessionCommand::PairAllLocal {
            settle_secs,
            federation_relay,
            json,
        } => cmd_session_pair_all_local(settle_secs, &federation_relay, json),
        SessionCommand::MeshStatus { stale_secs, json } => {
            cmd_session_mesh_status(stale_secs, json)
        }
        SessionCommand::Env { name, json } => cmd_session_env(name.as_deref(), json),
        SessionCommand::Current { json } => cmd_session_current(json),
        SessionCommand::Bind { name, json } => cmd_session_bind(name.as_deref(), json),
        SessionCommand::Destroy { name, force, json } => cmd_session_destroy(&name, force, json),
    }
}

fn cmd_session_bind(name_arg: Option<&str>, json: bool) -> Result<()> {
    let cwd = std::env::current_dir().with_context(|| "reading cwd")?;
    let cwd_str = crate::session::normalize_cwd_key(&cwd);

    let resolved_name = match name_arg {
        Some(n) => crate::session::sanitize_name(n),
        None => crate::session::sanitize_name(
            cwd.file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow!("cwd has no basename to derive session name from"))?,
        ),
    };

    let session_home = crate::session::session_dir(&resolved_name)?;
    if !session_home.exists() {
        bail!(
            "session `{resolved_name}` does not exist (looked at {}). Create it first with `wire session new {resolved_name}` or pass an existing name.",
            session_home.display()
        );
    }

    let prior = crate::session::read_registry()
        .ok()
        .and_then(|r| r.by_cwd.get(&cwd_str).cloned());
    if prior.as_deref() == Some(resolved_name.as_str()) {
        if json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "cwd": cwd_str,
                    "session": resolved_name,
                    "changed": false,
                }))?
            );
        } else {
            println!("cwd `{cwd_str}` already bound to session `{resolved_name}` (no change)");
        }
        return Ok(());
    }
    if let Some(prior_name) = &prior {
        eprintln!(
            "wire session bind: cwd `{cwd_str}` was bound to `{prior_name}`; overwriting with `{resolved_name}`."
        );
    }

    crate::session::update_registry(|reg| {
        reg.by_cwd.insert(cwd_str.clone(), resolved_name.clone());
        Ok(())
    })?;

    if json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "cwd": cwd_str,
                "session": resolved_name,
                "changed": true,
                "previous": prior,
            }))?
        );
    } else {
        println!("bound cwd `{cwd_str}` → session `{resolved_name}`");
        println!("(next `wire` invocation from this cwd will auto-detect into this session)");
    }
    Ok(())
}

fn resolve_session_name(name: Option<&str>) -> Result<String> {
    if let Some(n) = name {
        return Ok(crate::session::sanitize_name(n));
    }
    let cwd = std::env::current_dir().with_context(|| "reading cwd")?;
    let registry = crate::session::read_registry().unwrap_or_default();
    Ok(crate::session::derive_name_from_cwd(&cwd, &registry))
}

#[allow(clippy::too_many_arguments)] // 11 transport-mix flags; the v0.8 audit
// (.planning/research/codebase-audit-2026-05-23.md) recommends a config-struct
// refactor for v0.8. For v0.7.0 we ship the flag-explosion as-is.
fn cmd_session_new(
    name_arg: Option<&str>,
    relay: &str,
    with_local: bool,
    local_relay: &str,
    with_lan: bool,
    lan_relay: Option<&str>,
    with_uds: bool,
    uds_socket: Option<&std::path::Path>,
    no_daemon: bool,
    local_only: bool,
    as_json: bool,
) -> Result<()> {
    // v0.6.6: --local-only implies --with-local (a federation-free
    // session with no endpoints at all would be unaddressable).
    let with_local = with_local || local_only;
    // v0.7.0-alpha.9: --with-lan requires --lan-relay <url>.
    if with_lan && lan_relay.is_none() {
        bail!("--with-lan requires --lan-relay <url> (e.g. http://192.168.1.50:8771)");
    }
    // v0.7.0-alpha.18: --with-uds requires --uds-socket <path>.
    if with_uds && uds_socket.is_none() {
        bail!("--with-uds requires --uds-socket <path> (e.g. /tmp/wire.sock)");
    }
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

    // Phase 1: init identity in the new session's WIRE_HOME. For
    // federation-bound sessions we pass `--relay` so init also
    // allocates a federation slot in the same step; for `--local-only`
    // we run init with `--offline` (v0.9 requires explicit reachability
    // acknowledgement at init time) because cmd_session_new allocates
    // the local-relay slot itself via try_allocate_local_slot below.
    // The session is not actually slotless — init is just deferred to
    // the subsequent allocation pass.
    let init_args: Vec<&str> = if local_only {
        vec!["init", &name, "--offline"]
    } else {
        vec!["init", &name, "--relay", relay]
    };
    let init_status = run_wire_with_home(&session_home, &init_args)?;
    if !init_status.success() {
        let how = if local_only {
            format!("`wire init {name}` (local-only)")
        } else {
            format!("`wire init {name} --relay {relay}`")
        };
        bail!("{how} failed inside session dir {session_home:?}");
    }

    // Phase 2: claim the handle on the federation relay — SKIPPED when
    // `--local-only`. Local-only sessions have no public address and
    // accept reserved nicks (e.g. cwd-derived `wire`) because nothing
    // tries to publish them.
    let effective_handle = if local_only {
        name.clone()
    } else {
        let mut claim_attempt = 0u32;
        let mut effective = name.clone();
        loop {
            claim_attempt += 1;
            let status =
                run_wire_with_home(&session_home, &["claim", &effective, "--relay", relay])?;
            if status.success() {
                break;
            }
            if claim_attempt >= 5 {
                bail!(
                    "5 failed attempts to claim a handle on {relay} for session {name}. \
                     Try `wire session destroy {name} --force` and re-run with a different name, \
                     or use `--local-only` if you don't need a federation address."
                );
            }
            let attempt_path = cwd.join(format!("__attempt_{claim_attempt}"));
            let suffix = crate::session::derive_name_from_cwd(&attempt_path, &registry);
            let token = suffix
                .rsplit('-')
                .next()
                .filter(|t| t.len() == 4)
                .map(str::to_string)
                .unwrap_or_else(|| format!("{claim_attempt}"));
            effective = format!("{name}-{token}");
        }
        effective
    };

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
    //
    // v0.6.6 (--local-only): try_allocate_local_slot is the ONLY slot
    // allocation; a failed probe leaves the session with no endpoints,
    // which we surface as a hard error (the operator asked for local-
    // only but the local relay isn't running — fix that first).
    if with_local {
        try_allocate_local_slot(&session_home, &effective_handle, relay, local_relay);
        if local_only {
            // Verify the local slot landed. If the local relay was
            // unreachable, the session would be unreachable from
            // anywhere — surface that loudly instead of leaving an
            // orphaned session dir.
            let relay_state_path = session_home.join("config").join("wire").join("relay.json");
            let state: Value = std::fs::read(&relay_state_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_else(|| json!({"self": Value::Null, "peers": {}}));
            let endpoints = crate::endpoints::self_endpoints(&state);
            let has_local = endpoints
                .iter()
                .any(|e| e.scope == crate::endpoints::EndpointScope::Local);
            if !has_local {
                bail!(
                    "--local-only requested but local-relay probe at {local_relay} failed — \
                     ensure the local relay is running (`wire service install --local-relay`), \
                     then re-run `wire session new {name} --local-only`."
                );
            }
        }
    }

    // v0.7.0-alpha.9: also allocate a LAN-bound slot if requested.
    // Sits AFTER local because cmd_session_new's flow is "add endpoints
    // alongside existing self.endpoints[]" — order independent post-init.
    if with_lan && let Some(lan_url) = lan_relay {
        try_allocate_lan_slot(&session_home, &effective_handle, lan_url);
    }
    // v0.7.0-alpha.18: also allocate a UDS slot if requested.
    if with_uds && let Some(socket_path) = uds_socket {
        try_allocate_uds_slot(&session_home, &effective_handle, socket_path);
    }

    if !no_daemon {
        ensure_session_daemon(&session_home)?;
    }

    let info = render_session_info(&name, &session_home, &cwd)?;
    emit_session_new_result(&info, "created", as_json)
}

/// Coerce a JSON document whose root is valid JSON but not an object
/// (`[]`, `"x"`, `42`, `null`) back to `{}` so callers can mutate it
/// with `as_object_mut()` without panicking. The slot-allocation paths
/// load `relay.json` with a parse-failure fallback to `{}`, but a file
/// holding valid non-object JSON sailed past that fallback and hit the
/// `expect("relay_state root is an object")` below.
fn coerce_object_root(v: &mut serde_json::Value) {
    if !v.is_object() {
        *v = serde_json::json!({});
    }
}

#[cfg(test)]
mod coerce_object_root_tests {
    use super::coerce_object_root;
    use serde_json::json;

    #[test]
    fn non_object_roots_are_coerced_to_empty_object() {
        for mut corrupt in [
            json!([]),
            json!("corrupt"),
            json!(42),
            serde_json::Value::Null,
        ] {
            coerce_object_root(&mut corrupt);
            assert!(corrupt.is_object(), "root not coerced: {corrupt}");
        }
    }

    #[test]
    fn object_root_is_left_untouched() {
        let mut state = json!({"self": {"endpoints": [1, 2]}});
        coerce_object_root(&mut state);
        assert_eq!(state, json!({"self": {"endpoints": [1, 2]}}));
    }
}

/// v0.7.0-alpha.18: probe + allocate against a UDS-bound relay, then
/// merge the resulting Uds endpoint into `self.endpoints[]` so paired
/// sister sessions can route over the local socket instead of loopback
/// HTTP. Uses the hand-rolled `uds_request` HTTP/1.1 client from
/// alpha.17 — reqwest has no UDS support.
///
/// Non-fatal on probe/alloc failure (mirrors try_allocate_local_slot
/// and try_allocate_lan_slot semantics): session stays at existing
/// endpoint mix, operator can retry once the UDS relay is up.
#[cfg(unix)]
fn try_allocate_uds_slot(
    session_home: &std::path::Path,
    handle: &str,
    uds_socket: &std::path::Path,
) {
    // Probe healthz first so we fail fast with a clear stderr if the
    // socket doesn't exist OR isn't a wire relay.
    let healthz = match crate::relay_client::uds_request(uds_socket, "GET", "/healthz", &[], b"") {
        Ok((200, _)) => true,
        Ok((status, body)) => {
            eprintln!(
                "wire session new: UDS relay probe at {uds_socket:?} returned {status} ({}) — not publishing UDS endpoint",
                String::from_utf8_lossy(&body)
            );
            return;
        }
        Err(e) => {
            eprintln!(
                "wire session new: UDS relay at {uds_socket:?} unreachable ({e:#}) — \
                 not publishing UDS endpoint. Start one with `wire relay-server --uds <path>`."
            );
            return;
        }
    };
    if !healthz {
        return;
    }

    // Allocate a slot via the same hand-rolled HTTP/1.1 client.
    let alloc_body = serde_json::json!({"handle": handle}).to_string();
    let (status, body) = match crate::relay_client::uds_request(
        uds_socket,
        "POST",
        "/v1/slot/allocate",
        &[("Content-Type", "application/json")],
        alloc_body.as_bytes(),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "wire session new: UDS relay slot allocation request failed: {e:#} — not publishing UDS endpoint"
            );
            return;
        }
    };
    if status >= 300 {
        eprintln!(
            "wire session new: UDS relay slot allocation returned {status} ({}) — not publishing UDS endpoint",
            String::from_utf8_lossy(&body)
        );
        return;
    }
    let alloc: crate::relay_client::AllocateResponse = match serde_json::from_slice(&body) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("wire session new: UDS relay returned unparseable allocate response: {e:#}");
            return;
        }
    };

    let state_path = session_home.join("config").join("wire").join("relay.json");
    let mut state: serde_json::Value = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let mut endpoints: Vec<crate::endpoints::Endpoint> = state
        .get("self")
        .and_then(|s| s.get("endpoints"))
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    serde_json::from_value::<crate::endpoints::Endpoint>(v.clone()).ok()
                })
                .collect()
        })
        .unwrap_or_default();
    endpoints.push(crate::endpoints::Endpoint::uds(
        format!("unix://{}", uds_socket.display()),
        alloc.slot_id.clone(),
        alloc.slot_token.clone(),
    ));

    coerce_object_root(&mut state);
    let self_obj = state
        .as_object_mut()
        .expect("relay_state root coerced to object above")
        .entry("self")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !self_obj.is_object() {
        *self_obj = serde_json::Value::Object(serde_json::Map::new());
    }
    if let Some(obj) = self_obj.as_object_mut() {
        obj.insert(
            "endpoints".into(),
            serde_json::to_value(&endpoints).unwrap_or(serde_json::Value::Null),
        );
    }
    if let Err(e) = std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&state).expect("relay_state serializable"),
    ) {
        eprintln!("wire session new: failed to write {state_path:?}: {e}");
        return;
    }
    eprintln!(
        "wire session new: UDS slot allocated on unix://{} (slot_id={}) — sister sessions will see this endpoint in your agent-card",
        uds_socket.display(),
        alloc.slot_id
    );
}

#[cfg(not(unix))]
fn try_allocate_uds_slot(
    _session_home: &std::path::Path,
    _handle: &str,
    _uds_socket: &std::path::Path,
) {
    eprintln!(
        "wire session new: --with-uds is Unix-only (Windows lacks AF_UNIX in tokio/reqwest); ignoring"
    );
}

/// v0.7.0-alpha.9: probe + allocate against a LAN-bound relay, then
/// merge the resulting Lan endpoint into `self.endpoints[]` so peers
/// pulling the agent-card see a third reachable address.
///
/// Mirrors `try_allocate_local_slot` but tags the endpoint
/// `EndpointScope::Lan`. Non-fatal: if probe or alloc fails, the
/// session stays at whatever endpoint mix it already had — operators
/// can retry with `wire session new --with-lan --lan-relay <url>` once
/// the LAN relay is up.
fn try_allocate_lan_slot(session_home: &std::path::Path, handle: &str, lan_relay: &str) {
    let probe = match crate::relay_client::build_blocking_client(Some(
        std::time::Duration::from_millis(500),
    )) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wire session new: cannot build LAN probe client for {lan_relay}: {e:#}");
            return;
        }
    };
    let healthz_url = format!("{}/healthz", lan_relay.trim_end_matches('/'));
    match probe.get(&healthz_url).send() {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            eprintln!(
                "wire session new: LAN relay probe at {healthz_url} returned {} — not publishing LAN endpoint",
                resp.status()
            );
            return;
        }
        Err(e) => {
            eprintln!(
                "wire session new: LAN relay at {lan_relay} unreachable ({}) — not publishing LAN endpoint. \
                 Start one on the LAN-bound interface with `wire relay-server --bind <LAN-IP>:8771 --local-only`.",
                crate::relay_client::format_transport_error(&anyhow::Error::new(e))
            );
            return;
        }
    };

    let lan_client = crate::relay_client::RelayClient::new(lan_relay);
    let alloc = match lan_client.allocate_slot(Some(handle)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "wire session new: LAN relay slot allocation failed: {e:#} — not publishing LAN endpoint"
            );
            return;
        }
    };

    let state_path = session_home.join("config").join("wire").join("relay.json");
    let mut state: serde_json::Value = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    // Read existing endpoints array and add the LAN one. Preserve
    // federation / local entries already there.
    let mut endpoints: Vec<crate::endpoints::Endpoint> = state
        .get("self")
        .and_then(|s| s.get("endpoints"))
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    serde_json::from_value::<crate::endpoints::Endpoint>(v.clone()).ok()
                })
                .collect()
        })
        .unwrap_or_default();
    endpoints.push(crate::endpoints::Endpoint::lan(
        lan_relay.trim_end_matches('/').to_string(),
        alloc.slot_id.clone(),
        alloc.slot_token.clone(),
    ));

    coerce_object_root(&mut state);
    let self_obj = state
        .as_object_mut()
        .expect("relay_state root coerced to object above")
        .entry("self")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !self_obj.is_object() {
        *self_obj = serde_json::Value::Object(serde_json::Map::new());
    }
    if let Some(obj) = self_obj.as_object_mut() {
        obj.insert(
            "endpoints".into(),
            serde_json::to_value(&endpoints).unwrap_or(serde_json::Value::Null),
        );
    }
    if let Err(e) = std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&state).expect("relay_state serializable"),
    ) {
        eprintln!("wire session new: failed to write {state_path:?}: {e}");
        return;
    }
    eprintln!(
        "wire session new: LAN slot allocated on {lan_relay} (slot_id={}) — peers will see this endpoint in your agent-card",
        alloc.slot_id
    );
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
    _federation_relay: &str,
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

    // Merge into the session's relay.json. We invoke wire via
    // run_wire_with_home for federation calls (subprocess isolation),
    // but relay.json is a simple file we can edit directly
    // — and need to, because there's no `wire bind-relay --add-local`
    // command yet (could add later; out of scope for v0.5.17 MVP).
    //
    // v0.5.20 BUG FIX: previously joined `relay-state.json` here, which
    // does not exist (canonical filename is `relay.json` per
    // `config::relay_state_path`). The mis-named file write succeeded
    // but landed in a sibling path nothing else reads. Every
    // `wire session new --with-local` invocation silently degraded to
    // federation-only despite the "local slot allocated" stderr line.
    // Caught by deploying v0.5.19 on the dev laptop and inspecting the
    // session's relay.json — it had only the federation endpoint.
    let state_path = session_home.join("config").join("wire").join("relay.json");
    let mut state: serde_json::Value = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    // Read the existing federation self info (already written by
    // `wire init` + `wire bind-relay` path during session bootstrap).
    let fed_endpoint = state.get("self").and_then(|s| {
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

    // v0.6.6: when there's no federation endpoint (e.g. `--local-only`
    // bootstrap), the legacy top-level `relay_url` / `slot_id` /
    // `slot_token` fields must point at the LOCAL endpoint so callers
    // that read those legacy fields (send_pair_drop_ack, post-v0.6.6
    // ensure_self_with_relay fallback, v0.5.16-era back-compat readers)
    // still find a valid slot. Pre-v0.6.6 this branch wrote
    // `relay_url: federation_relay` with no slot_id, which produced
    // half-populated self state that broke wire-accept on local-only
    // sessions.
    let (legacy_relay, legacy_slot_id, legacy_slot_token) = match fed_endpoint.clone() {
        Some(f) => (f.relay_url, f.slot_id, f.slot_token),
        None => (
            local_relay.trim_end_matches('/').to_string(),
            alloc.slot_id.clone(),
            alloc.slot_token.clone(),
        ),
    };
    coerce_object_root(&mut state);
    let self_obj = state
        .as_object_mut()
        .expect("relay_state root coerced to object above")
        .entry("self")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    // The entry might be Value::Null (left by read_relay_state's default
    // template) — replace with an object before mutating.
    if !self_obj.is_object() {
        *self_obj = serde_json::Value::Object(serde_json::Map::new());
    }
    if let Some(obj) = self_obj.as_object_mut() {
        obj.insert("relay_url".into(), serde_json::Value::String(legacy_relay));
        obj.insert("slot_id".into(), serde_json::Value::String(legacy_slot_id));
        obj.insert(
            "slot_token".into(),
            serde_json::Value::String(legacy_slot_token),
        );
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
    let card_path = session_home
        .join("config")
        .join("wire")
        .join("agent-card.json");
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
            .unwrap_or_else(|| crate::agent_card::display_handle_from_did(&did).to_string());
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

fn emit_session_new_result(info: &serde_json::Value, status: &str, as_json: bool) -> Result<()> {
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
        // v0.7.0-alpha.2: subprocess MUST NOT recursively auto-init.
        // We already own the session; nested init would clobber state.
        .env("WIRE_AUTO_INIT", "0")
        .args(args)
        .status()
        .with_context(|| format!("spawning `wire {}`", args.join(" ")))?;
    Ok(status)
}

/// v0.7.0-alpha.2: idempotent per-cwd session creation.
///
/// When the auto-detect (`maybe_adopt_session_wire_home`) finds no
/// registered session for the current cwd — including via parent-walk —
/// this creates one inline so every Claude tab in a fresh project gets
/// its own wire identity rather than collapsing onto the machine-wide
/// default. Without this, multiple Claudes in unwired cwds all render
/// the same character (the default identity's character), defeating the
/// "every session looks different" promise.
///
/// Opt-out: `WIRE_AUTO_INIT=0` env var (e.g. set in shell profile or
/// `run_wire_with_home` subprocess context).
///
/// Best-effort: any failure (no home dir, name collision pathology,
/// `wire init` subprocess crash) is logged to stderr and we fall back
/// to default identity. Must not block MCP startup.
///
/// MUST be called BEFORE worker thread spawn (env::set_var safety).
pub fn maybe_auto_init_cwd_session(label: &str) {
    if std::env::var("WIRE_HOME").is_ok() {
        return; // explicit override OR auto-detect already won
    }
    if std::env::var("WIRE_AUTO_INIT").as_deref() == Ok("0") {
        return; // operator opt-out
    }
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(_) => return,
    };
    // Defensive: parent-walk re-check (maybe_adopt_session_wire_home
    // already runs but we want to be robust to ordering).
    if crate::session::detect_session_wire_home(&cwd).is_some() {
        return;
    }

    // v0.7.0-alpha.12 (review-fix #135): SINGLE global auto-init lock
    // (was per-name in alpha.3, briefly per-cwd in alpha.12-iter1).
    // Two different cwds with the same basename (e.g. /a/projx +
    // /b/projx) used to race outside the lock: both read empty
    // registry, both derived name="projx", per-name lock didn't help
    // because they queued on DIFFERENT locks (cwd-A and cwd-B).
    //
    // Single lock serializes ALL auto-init across the sessions_root.
    // Inside the lock: re-read registry, derive_name_from_cwd which
    // adds path-hash suffix when basename is occupied by another cwd
    // already committed to the registry. Different cwds get DIFFERENT
    // names guaranteed.
    //
    // Cost: parallel auto-inits in different cwds now serialize
    // (~hundreds of ms each when local relay is up). Acceptable —
    // auto-init runs once per cwd per machine; not a hot path.
    use fs2::FileExt;
    let sessions_root = match crate::session::sessions_root() {
        Ok(r) => r,
        Err(_) => return,
    };
    if let Err(e) = std::fs::create_dir_all(&sessions_root) {
        eprintln!("wire {label}: auto-init: failed to create sessions root {sessions_root:?}: {e}");
        return;
    }
    let lock_path = sessions_root.join(".auto-init.lock");
    let lock_file = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "wire {label}: auto-init: cannot open lockfile {lock_path:?}: {e} — falling back to default identity"
            );
            return;
        }
    };
    if let Err(e) = lock_file.lock_exclusive() {
        eprintln!(
            "wire {label}: auto-init: flock {lock_path:?} failed: {e} — falling back to default identity"
        );
        return;
    }
    // Lock acquired. Read registry + derive name now that all parallel
    // racers serialize through us — derive_name_from_cwd adds a
    // path-hash suffix if the basename is already claimed by another
    // cwd in the (now-stable) registry.
    let registry = crate::session::read_registry().unwrap_or_default();
    let name = crate::session::derive_name_from_cwd(&cwd, &registry);
    let session_home = match crate::session::session_dir(&name) {
        Ok(h) => h,
        Err(_) => {
            let _ = fs2::FileExt::unlock(&lock_file);
            return;
        }
    };
    let agent_card_path = session_home
        .join("config")
        .join("wire")
        .join("agent-card.json");
    let needs_init = !agent_card_path.exists();

    if needs_init {
        if let Err(e) = std::fs::create_dir_all(&session_home) {
            eprintln!(
                "wire {label}: auto-init: failed to create session dir {session_home:?}: {e}"
            );
            let _ = fs2::FileExt::unlock(&lock_file);
            return;
        }
        // v0.9: --offline; the surrounding session-spawn path runs
        // try_allocate_local_slot afterward to attach an inbound slot
        // when a local relay is available. Init itself stays slotless
        // because it's a precursor step, not the final state.
        match run_wire_with_home(&session_home, &["init", &name, "--offline"]) {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!(
                    "wire {label}: auto-init: `wire init {name}` exited non-zero ({status}) — falling back to default identity"
                );
                let _ = fs2::FileExt::unlock(&lock_file);
                return;
            }
            Err(e) => {
                eprintln!(
                    "wire {label}: auto-init: failed to spawn `wire init {name}`: {e:#} — falling back to default identity"
                );
                let _ = fs2::FileExt::unlock(&lock_file);
                return;
            }
        }
        // Best-effort: allocate a local-relay slot so this auto-init'd
        // session is addressable by sister sessions. Skipped silently when
        // the local relay isn't running (the function itself reports to
        // stderr). Auto-init'd sessions without endpoints can still
        // surface their character but cannot receive pair_drops until the
        // operator runs `wire bind-relay` or restarts the local relay.
        try_allocate_local_slot(
            &session_home,
            &name,
            "https://wireup.net",
            "http://127.0.0.1:8771",
        );
    } else {
        // Race loser path: peer already created the session. Surface
        // this honestly so the operator can see we adopted rather than
        // double-initialized.
        if std::env::var("WIRE_QUIET_AUTOSESSION").is_err() {
            eprintln!(
                "wire {label}: auto-init: session `{name}` already exists (concurrent mcp peer won the race) — adopting"
            );
        }
    }
    // v0.7.0-alpha.12 (review-fix #135 part 2): register cwd → name
    // BEFORE releasing the auto-init lock. Pre-fix released the lock
    // here and committed the registry update afterward — racers in
    // OTHER cwds with the same basename would acquire the lock,
    // read the registry (still without our entry), and derive the
    // SAME name we just claimed. Live regression test caught it:
    // two cwds /a/projx + /b/projx both got name "projx", both
    // mapped to the same identity. Update the registry WHILE STILL
    // holding the auto-init lock so the next racer sees our claim.
    let cwd_key = crate::session::normalize_cwd_key(&cwd);
    let name_for_reg = name.clone();
    if let Err(e) = crate::session::update_registry(|reg| {
        reg.by_cwd.insert(cwd_key, name_for_reg);
        Ok(())
    }) {
        eprintln!("wire {label}: auto-init: failed to update registry: {e:#}");
        // proceed — env var still gets set below
    }
    // NOW release the lock — racers waiting will see our registry
    // entry on their re-read.
    let _ = fs2::FileExt::unlock(&lock_file);

    if std::env::var("WIRE_QUIET_AUTOSESSION").is_err() {
        eprintln!(
            "wire {label}: auto-init: created session `{name}` for cwd `{}` → WIRE_HOME=`{}`",
            cwd.display(),
            session_home.display()
        );
    }
    // SAFETY: caller contract is "before any thread spawn." MCP::run
    // calls this immediately after `maybe_adopt_session_wire_home`.
    unsafe {
        std::env::set_var("WIRE_HOME", &session_home);
    }
}

fn ensure_session_daemon(session_home: &std::path::Path) -> Result<()> {
    // Check if a daemon is already alive in this session's WIRE_HOME.
    // If so, no-op (let the existing process keep running).
    let pidfile = session_home.join("state").join("wire").join("daemon.pid");
    if pidfile.exists() {
        let bytes = std::fs::read(&pidfile).unwrap_or_default();
        let pid: Option<u32> = if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
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
        "{:<22} {:<24} {:<24} {:<10} CWD",
        "PERSONA", "NAME", "HANDLE", "DAEMON"
    );
    for s in items {
        // ANSI-escape-wrapped character takes more visual width than its
        // displayed glyph count; pad based on the plain-text form, then
        // wrap in escapes so the column lines up across rows.
        let plain = s
            .character
            .as_ref()
            .map(|c| c.short())
            .unwrap_or_else(|| "?".to_string());
        let colored = s
            .character
            .as_ref()
            .map(|c| c.colored())
            .unwrap_or_else(|| "?".to_string());
        // Approximate display width: emoji renders as ~2 cells in most
        // terminals; the rest are 1 cell each. We pad to 18 displayed
        // chars (≈22 byte slots when counting emoji).
        let displayed_width = plain.chars().count() + 1; // +1 emoji-wide compensation
        let pad = 22usize.saturating_sub(displayed_width);
        println!(
            "{}{}  {:<24} {:<24} {:<10} {}",
            colored,
            " ".repeat(pad),
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
            println!("  {:<24} {:<32} {:<10} CWD", "NAME", "HANDLE", "DAEMON");
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

/// v0.6.0 (issue #12): orchestrate bilateral pair across every sister
/// session that has a Local-scope endpoint. Skips already-paired
/// pairs; reports a per-pair outcome JSON suitable for scripting.
///
/// Same-uid trust anchor: the caller owns every session enumerated by
/// `list_local_sessions`, so the operator running this command IS the
/// consent for both sides. The bilateral SAS / network-level handshake
/// assumes strangers; same-uid sister sessions are not strangers.
///
/// Per-pair flow (sequential to keep relay-side load + log clarity):
///   1. WIRE_HOME=A wire add <B-handle>@<host>  (writes pending-inbound on B)
///   2. WIRE_HOME=A wire push --json            (sends pair_drop to relay)
///   3. sleep settle_secs                       (pair_drop reaches B)
///   4. WIRE_HOME=B wire pull --json            (B receives pair_drop)
///   5. WIRE_HOME=B wire accept <A-bare>   (B pins A, sends ack)
///   6. WIRE_HOME=B wire push --json            (sends pair_drop_ack)
///   7. sleep settle_secs                       (ack reaches A)
///   8. WIRE_HOME=A wire pull --json            (A pins B)
fn cmd_session_pair_all_local(
    settle_secs: u64,
    federation_relay: &str,
    as_json: bool,
) -> Result<()> {
    use std::collections::BTreeSet;
    use std::time::Duration;

    let listing = crate::session::list_local_sessions()?;
    // Flatten + dedup by session NAME (same session can appear under
    // multiple local-relay URLs if it advertises two local endpoints;
    // rare, but pair each pair exactly once).
    let mut by_name: std::collections::BTreeMap<String, crate::session::LocalSessionView> =
        Default::default();
    for group in listing.local.into_values() {
        for s in group {
            by_name.entry(s.name.clone()).or_insert(s);
        }
    }
    let sessions: Vec<crate::session::LocalSessionView> = by_name.into_values().collect();

    if sessions.len() < 2 {
        let msg = format!(
            "{} sister session(s) with a local endpoint — need at least 2 to pair.",
            sessions.len()
        );
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "sessions": sessions.iter().map(|s| &s.name).collect::<Vec<_>>(),
                    "pairs_attempted": 0,
                    "pairs_succeeded": 0,
                    "pairs_skipped_already_paired": 0,
                    "pairs_failed": 0,
                    "note": msg,
                }))?
            );
        } else {
            println!("{msg}");
            if let Some(s) = sessions.first() {
                println!("  - {} ({})", s.name, s.cwd.as_deref().unwrap_or("?"));
            }
            println!("Use `wire session new --with-local` to add more.");
        }
        return Ok(());
    }

    let fed_host = host_of_url(federation_relay);
    if fed_host.is_empty() {
        bail!(
            "federation_relay `{federation_relay}` has no parseable host — \
             pass a full URL like `https://wireup.net`."
        );
    }

    // Enumerate unordered pairs deterministically by session name.
    let mut attempted = 0u32;
    let mut succeeded = 0u32;
    let mut skipped_already = 0u32;
    let mut failed = 0u32;
    let mut per_pair: Vec<Value> = Vec::new();

    for i in 0..sessions.len() {
        for j in (i + 1)..sessions.len() {
            let a = &sessions[i];
            let b = &sessions[j];
            attempted += 1;

            // Already-paired check: if A's relay-state has B's CARD
            // HANDLE in peers AND vice versa, skip. v0.11: peer keys
            // are character handles (not session names), so we use
            // each side's handle field (already on the LocalSessionView)
            // for the lookup rather than the session name.
            let a_handle = a.handle.as_deref().unwrap_or(a.name.as_str());
            let b_handle = b.handle.as_deref().unwrap_or(b.name.as_str());
            let a_pinned_b = session_has_peer(&a.home_dir, b_handle);
            let b_pinned_a = session_has_peer(&b.home_dir, a_handle);
            if a_pinned_b && b_pinned_a {
                skipped_already += 1;
                per_pair.push(json!({
                    "from": a.name,
                    "to": b.name,
                    "status": "already_paired",
                }));
                continue;
            }

            let pair_result = drive_bilateral_pair(
                &a.home_dir,
                &a.name,
                &b.home_dir,
                &b.name,
                &fed_host,
                federation_relay,
                settle_secs,
            );

            match pair_result {
                Ok(()) => {
                    succeeded += 1;
                    per_pair.push(json!({
                        "from": a.name,
                        "to": b.name,
                        "status": "paired",
                    }));
                }
                Err(e) => {
                    failed += 1;
                    let detail = format!("{e:#}");
                    per_pair.push(json!({
                        "from": a.name,
                        "to": b.name,
                        "status": "failed",
                        "error": detail,
                    }));
                }
            }

            // Brief settle between pairs so we don't slam the relay
            // with N(N-1) parallel requests.
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    let _ = BTreeSet::<String>::new(); // silence unused-import lint if any
    let summary = json!({
        "sessions": sessions.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
        "pairs_attempted": attempted,
        "pairs_succeeded": succeeded,
        "pairs_skipped_already_paired": skipped_already,
        "pairs_failed": failed,
        "results": per_pair,
    });
    if as_json {
        println!("{}", serde_json::to_string(&summary)?);
    } else {
        println!(
            "wire session pair-all-local: {} session(s), {} pair(s) attempted",
            sessions.len(),
            attempted
        );
        println!("  paired:                 {succeeded}");
        println!("  skipped (already pinned): {skipped_already}");
        println!("  failed:                 {failed}");
        for entry in summary["results"].as_array().unwrap_or(&vec![]) {
            let from = entry["from"].as_str().unwrap_or("?");
            let to = entry["to"].as_str().unwrap_or("?");
            let status = entry["status"].as_str().unwrap_or("?");
            let err = entry.get("error").and_then(Value::as_str).unwrap_or("");
            if err.is_empty() {
                println!("  {from:<24} ↔ {to:<24} {status}");
            } else {
                println!("  {from:<24} ↔ {to:<24} {status} — {err}");
            }
        }
    }
    Ok(())
}

/// Check whether `session_home`'s `relay.json` already lists `peer_name`
/// under `state.peers`. Best-effort — any read/parse error → false.
fn session_has_peer(session_home: &std::path::Path, peer_name: &str) -> bool {
    val_session_relay_state(session_home)
        .and_then(|v| v.get("peers").cloned())
        .and_then(|p| p.get(peer_name).cloned())
        .is_some()
}

/// Read a session's `relay.json` directly without mutating the process'
/// WIRE_HOME env (which would race other threads / processes). Returns
/// `None` on any read or parse error — callers treat missing state as
/// "no peers / no endpoints" rather than aborting.
fn val_session_relay_state(session_home: &std::path::Path) -> Option<Value> {
    let path = session_home.join("config").join("wire").join("relay.json");
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// v0.6.2 (issue #18): produce a live view of the sister-session mesh.
/// One probe per directed edge against the relay backing that edge's
/// priority-1 endpoint; output groups by undirected pair.
fn cmd_session_mesh_status(stale_secs: u64, as_json: bool) -> Result<()> {
    use std::collections::BTreeMap;

    // Flatten by session NAME — same dedup logic as pair-all-local so a
    // session advertising two local endpoints doesn't get double-counted.
    let listing = crate::session::list_local_sessions()?;
    let mut by_name: BTreeMap<String, crate::session::LocalSessionView> = BTreeMap::new();
    for group in listing.local.into_values() {
        for s in group {
            by_name.entry(s.name.clone()).or_insert(s);
        }
    }
    let sessions: Vec<crate::session::LocalSessionView> = by_name.into_values().collect();
    let federation_only = listing.federation_only;

    if sessions.is_empty() {
        let msg = "no sister sessions with a local endpoint on this machine.".to_string();
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "sessions": [],
                    "edges": [],
                    "local_relay": null,
                    "federation_only": federation_only.iter().map(|f| &f.name).collect::<Vec<_>>(),
                    "summary": {
                        "session_count": 0,
                        "edge_count": 0,
                        "healthy": 0,
                        "stale": 0,
                        "asymmetric": 0,
                    },
                    "note": msg,
                }))?
            );
        } else {
            println!("{msg}");
            println!("Use `wire session new --with-local` to create one.");
        }
        return Ok(());
    }

    // Build a name → session-state map: relay_state + reachable handle set.
    struct SessionState {
        view: crate::session::LocalSessionView,
        relay_state: Value,
        local_relay_url: Option<String>,
    }
    let mut sstates: Vec<SessionState> = Vec::with_capacity(sessions.len());
    for s in sessions {
        let relay_state = val_session_relay_state(&s.home_dir)
            .unwrap_or_else(|| json!({"self": Value::Null, "peers": {}}));
        let local_relay_url = s.local_endpoints.first().map(|e| e.relay_url.clone());
        sstates.push(SessionState {
            view: s,
            relay_state,
            local_relay_url,
        });
    }

    // Probe each unique local-relay URL once for healthz so the operator
    // sees one liveness line per local relay, not one per edge.
    let mut local_relays: BTreeMap<String, bool> = BTreeMap::new();
    for s in &sstates {
        if let Some(url) = &s.local_relay_url
            && !local_relays.contains_key(url)
        {
            let healthy = probe_relay_healthz(url);
            local_relays.insert(url.clone(), healthy);
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Edges: walk every unordered pair, surface bilateral state + each
    // direction's last_pull. Probe priority-1 endpoint (local preferred
    // by `peer_endpoints_in_priority_order`).
    let mut edges: Vec<Value> = Vec::new();
    let mut healthy_count = 0u32;
    let mut stale_count = 0u32;
    let mut asymmetric_count = 0u32;

    for i in 0..sstates.len() {
        for j in (i + 1)..sstates.len() {
            let a = &sstates[i];
            let b = &sstates[j];
            // v0.11: relay-state.peers is keyed by the peer's CARD HANDLE
            // (DID-derived character), not the session name. Look the
            // peer up by its handle (with a session-name fallback for
            // pre-v0.11 sessions that haven't re-init'd yet).
            let b_key = b.view.handle.as_deref().unwrap_or(b.view.name.as_str());
            let a_key = a.view.handle.as_deref().unwrap_or(a.view.name.as_str());
            let a_to_b = probe_directed_edge(&a.relay_state, b_key, now);
            let b_to_a = probe_directed_edge(&b.relay_state, a_key, now);

            let bilateral = a_to_b.pinned && b_to_a.pinned;
            // Scope = the most-local scope available in either direction.
            // (If a→b is local and b→a is federation, the asymmetric
            // detail surfaces below; the headline scope is the better.)
            let scope = match (a_to_b.scope.as_deref(), b_to_a.scope.as_deref()) {
                (Some("local"), _) | (_, Some("local")) => "local",
                (Some("federation"), _) | (_, Some("federation")) => "federation",
                _ => "unknown",
            };

            // Health: stale if either direction's last_pull is older than
            // `stale_secs`, or never observed when both sides are pinned.
            let mut status = if bilateral { "healthy" } else { "asymmetric" };
            if bilateral {
                let either_stale = [&a_to_b, &b_to_a].iter().any(|d| match d.silent_secs {
                    Some(s) => s > stale_secs,
                    None => d.probed,
                });
                if either_stale {
                    status = "stale";
                }
            }

            match status {
                "healthy" => healthy_count += 1,
                "stale" => stale_count += 1,
                "asymmetric" => asymmetric_count += 1,
                _ => {}
            }

            edges.push(json!({
                "from": a.view.name,
                "to": b.view.name,
                "bilateral": bilateral,
                "scope": scope,
                "status": status,
                "directions": {
                    a.view.name.clone(): direction_summary(&a_to_b),
                    b.view.name.clone(): direction_summary(&b_to_a),
                },
            }));
        }
    }

    let summary = json!({
        "sessions": sstates.iter().map(|s| json!({
            "name": s.view.name,
            "handle": s.view.handle,
            "cwd": s.view.cwd,
            "daemon_running": s.view.daemon_running,
            "local_relay": s.local_relay_url,
        })).collect::<Vec<_>>(),
        "edges": edges,
        "local_relays": local_relays.iter().map(|(url, healthy)| json!({
            "url": url,
            "healthy": healthy,
        })).collect::<Vec<_>>(),
        "federation_only": federation_only.iter().map(|f| &f.name).collect::<Vec<_>>(),
        "summary": {
            "session_count": sstates.len(),
            "edge_count": edges.len(),
            "healthy": healthy_count,
            "stale": stale_count,
            "asymmetric": asymmetric_count,
            "stale_threshold_secs": stale_secs,
        },
    });

    if as_json {
        println!("{}", serde_json::to_string(&summary)?);
        return Ok(());
    }

    println!(
        "wire mesh: {} session(s), {} edge(s)",
        sstates.len(),
        edges.len()
    );
    for (url, healthy) in &local_relays {
        let tick = if *healthy { "✓" } else { "✗" };
        println!("  local-relay {url} {tick}");
    }
    if !federation_only.is_empty() {
        print!("  federation-only sessions:");
        for f in &federation_only {
            print!(" {}", f.name);
        }
        println!();
    }

    // Pin matrix: sessions × sessions, cell = scope code or "self" / "—".
    let names: Vec<&str> = sstates.iter().map(|s| s.view.name.as_str()).collect();
    let col_w = names.iter().map(|n| n.len()).max().unwrap_or(8).max(7) + 1;
    print!("\n{:>col_w$}", "", col_w = col_w);
    for n in &names {
        print!("{n:>col_w$}");
    }
    println!();
    for (i, row) in names.iter().enumerate() {
        print!("{row:>col_w$}");
        for (j, col) in names.iter().enumerate() {
            let cell = if i == j {
                "self".to_string()
            } else {
                let d = probe_directed_edge(&sstates[i].relay_state, col, now);
                match d.scope.as_deref() {
                    Some("local") => "local".to_string(),
                    Some("federation") => "fed".to_string(),
                    _ => "—".to_string(),
                }
            };
            print!("{cell:>col_w$}");
        }
        println!();
    }

    println!("\nHealth (stale threshold: {stale_secs}s):");
    for e in &edges {
        let from = e["from"].as_str().unwrap_or("?");
        let to = e["to"].as_str().unwrap_or("?");
        let scope = e["scope"].as_str().unwrap_or("?");
        let status = e["status"].as_str().unwrap_or("?");
        let mark = match status {
            "healthy" => "✓",
            "stale" => "⚠",
            "asymmetric" => "!",
            _ => "?",
        };
        let dirs = e["directions"].as_object().cloned().unwrap_or_default();
        let mut details: Vec<String> = Vec::new();
        for (who, d) in &dirs {
            let silent = d.get("silent_secs").and_then(Value::as_u64);
            let pinned = d.get("pinned").and_then(Value::as_bool).unwrap_or(false);
            let probed = d.get("probed").and_then(Value::as_bool).unwrap_or(false);
            let label = match (pinned, probed, silent) {
                (false, _, _) => format!("{who} has not pinned"),
                (true, false, _) => format!("{who} pinned but no endpoint to probe"),
                (true, true, Some(s)) if s <= stale_secs => format!("{who} fresh ({s}s)"),
                (true, true, Some(s)) => format!("{who} silent {s}s"),
                (true, true, None) => format!("{who} never pulled"),
            };
            details.push(label);
        }
        println!(
            "  {mark} {from} ↔ {to}  scope={scope} {status:>10}  [{}]",
            details.join(" | ")
        );
    }
    Ok(())
}

#[derive(Default)]
struct DirectedEdge {
    pinned: bool,
    scope: Option<String>,
    last_pull_at_unix: Option<u64>,
    silent_secs: Option<u64>,
    probed: bool,
    event_count: usize,
}

/// Probe a single directed edge from `from_state`'s view of `to_name`.
/// Picks the priority-1 endpoint (local preferred when reachable) and
/// asks the relay for that slot's `last_pull_at_unix`. Silent on probe
/// failure (the function records `probed = true`, `last_pull = None`,
/// which the caller treats as "never pulled, route exists" = stale).
fn probe_directed_edge(from_state: &Value, to_name: &str, now: u64) -> DirectedEdge {
    let pinned = from_state
        .get("peers")
        .and_then(|p| p.get(to_name))
        .is_some();
    if !pinned {
        return DirectedEdge::default();
    }
    let endpoints = crate::endpoints::peer_endpoints_in_priority_order(from_state, to_name);
    let ep = match endpoints.into_iter().next() {
        Some(e) => e,
        None => {
            return DirectedEdge {
                pinned: true,
                ..Default::default()
            };
        }
    };
    let scope = Some(
        match ep.scope {
            crate::endpoints::EndpointScope::Local => "local",
            crate::endpoints::EndpointScope::Lan => "lan",
            crate::endpoints::EndpointScope::Uds => "uds",
            crate::endpoints::EndpointScope::Federation => "federation",
        }
        .to_string(),
    );
    let client = crate::relay_client::RelayClient::new(&ep.relay_url);
    let (count, last) = client
        .slot_state(&ep.slot_id, &ep.slot_token)
        .unwrap_or((0, None));
    let silent = last.map(|t| now.saturating_sub(t));
    DirectedEdge {
        pinned: true,
        scope,
        last_pull_at_unix: last,
        silent_secs: silent,
        probed: true,
        event_count: count,
    }
}

fn direction_summary(d: &DirectedEdge) -> Value {
    json!({
        "pinned": d.pinned,
        "scope": d.scope,
        "probed": d.probed,
        "last_pull_at_unix": d.last_pull_at_unix,
        "silent_secs": d.silent_secs,
        "event_count": d.event_count,
    })
}

/// Best-effort GET `<url>/healthz`. Returns true iff status 2xx.
fn probe_relay_healthz(url: &str) -> bool {
    let probe_url = format!("{}/healthz", url.trim_end_matches('/'));
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client.get(&probe_url).send() {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    }
}

/// Drive one bilateral pair handshake between two sister sessions
/// using their session home dirs as `WIRE_HOME`. Sequential 8-step
/// flow so failures bubble up at the offending step, not buried in
/// a parallel race. See `cmd_session_pair_all_local` docstring.
///
/// v0.6.6: step 1 (the `wire add`) uses `--local-sister` instead of
/// federation `.well-known/wire/agent` resolution. Reads B's card +
/// endpoints directly off disk under `b_home` and pins them. This
/// makes pair-all-local work for sister sessions whose federation
/// handle is unclaimable (reserved nicks like `wire` / `slancha`) and
/// for sessions created with `wire session new --local-only`
/// (no federation slot at all). The `_federation_relay` / `_fed_host`
/// parameters are retained for callers that want to log them but
/// the handshake itself no longer touches federation.
fn drive_bilateral_pair(
    a_home: &std::path::Path,
    a_name: &str,
    b_home: &std::path::Path,
    b_name: &str,
    _fed_host: &str,
    _federation_relay: &str,
    settle_secs: u64,
) -> Result<()> {
    use std::time::Duration;
    let bin = std::env::current_exe().context("locating self exe")?;

    let run = |home: &std::path::Path, args: &[&str]| -> Result<()> {
        let out = std::process::Command::new(&bin)
            .env("WIRE_HOME", home)
            .env_remove("RUST_LOG")
            .args(args)
            .output()
            .with_context(|| format!("spawning `wire {}`", args.join(" ")))?;
        if !out.status.success() {
            bail!(
                "`wire {}` failed: stderr={}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    };

    // v0.11: each session's agent-card.handle is the DID-derived
    // character, not the session name. wire-accept lookups key on the
    // CARD HANDLE, so we discover each side's canonical handle from
    // its agent-card on disk before driving the pair flow.
    let read_card_handle = |home: &std::path::Path| -> Result<String> {
        let card_path = home.join("config").join("wire").join("agent-card.json");
        let bytes = std::fs::read(&card_path)
            .with_context(|| format!("reading agent-card at {card_path:?}"))?;
        let card: Value = serde_json::from_slice(&bytes)?;
        card.get("handle")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("agent-card at {card_path:?} missing `handle` field"))
    };
    let a_handle = read_card_handle(a_home)
        .with_context(|| format!("session {a_name} (a): read agent-card.handle"))?;
    let b_handle = read_card_handle(b_home)
        .with_context(|| format!("session {b_name} (b): read agent-card.handle"))?;

    // 1. A initiates via --local-sister (uses the session NAME for
    // the registry lookup; cmd_add_local_sister auto-resolves
    // session→handle internally).
    run(a_home, &["add", b_name, "--local-sister", "--json"])
        .with_context(|| format!("step 1/8: {a_name} `wire add {b_name} --local-sister`"))?;

    // 3. settle so pair_drop reaches B's slot
    std::thread::sleep(Duration::from_secs(settle_secs));

    // 4. B pulls pair_drop → 5. B accept (pins A by CARD HANDLE,
    // not by session name — under v0.11 these differ) → 6. B push ack
    run(b_home, &["pull", "--json"]).with_context(|| format!("step 4/8: {b_name} `wire pull`"))?;
    run(b_home, &["accept", &a_handle, "--json"]).with_context(|| {
        format!("step 5/8: {b_name} `wire accept {a_handle}` (a session={a_name})")
    })?;
    run(b_home, &["push", "--json"]).with_context(|| format!("step 6/8: {b_name} `wire push`"))?;

    // 7. settle so ack reaches A's slot
    std::thread::sleep(Duration::from_secs(settle_secs));

    // 8. A pulls ack (pins B by CARD HANDLE)
    run(a_home, &["pull", "--json"]).with_context(|| format!("step 8/8: {a_name} `wire pull`"))?;
    // suppress unused warning when both handles are consumed
    let _ = &b_handle;

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
    let cwd_key = crate::session::normalize_cwd_key(&cwd);
    // Backward-compat: O(n) normalized scan on read-miss. Mirrors the
    // same pattern in session::derive_name_from_cwd /
    // detect_session_wire_home — handles both consistent-casing and
    // cross-casing upgraders (see session.rs for the full rationale).
    let name = registry
        .by_cwd
        .get(&cwd_key)
        .or_else(|| {
            registry
                .by_cwd
                .iter()
                .find(|(k, _)| {
                    crate::session::normalize_cwd_key(std::path::Path::new(k)) == cwd_key
                })
                .map(|(_, v)| v)
        })
        .cloned();
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
    let pidfile = session_home.join("state").join("wire").join("daemon.pid");
    if let Ok(bytes) = std::fs::read(&pidfile) {
        let pid: Option<u32> = if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
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

/// v0.9.1: should this command emit JSON by default?
///
/// - `explicit=true` → operator passed `--json`, always JSON.
/// - non-interactive stdout (pipe, capture, agent shell) → JSON, so
///   captured output parses cleanly without operators remembering to
///   append `--json`. Mirrors `gh`, `kubectl`, etc.
/// - interactive TTY → human format (false).
/// - `WIRE_NO_AUTO_JSON=1` opts out (back-compat for v0.9 scripts
///   that parsed the human text by accident).
fn json_default(explicit: bool) -> bool {
    if explicit {
        return true;
    }
    if std::env::var("WIRE_NO_AUTO_JSON").is_ok() {
        return false;
    }
    use std::io::IsTerminal;
    !std::io::stdout().is_terminal()
}

pub(super) fn process_alive_pid(pid: u32) -> bool {
    // v0.7.3: delegate to the cross-platform helper. See
    // `platform::process_alive` for the per-OS dispatch — Windows now
    // uses `tasklist /FI "PID eq <n>"` instead of `kill -0`, which
    // gave a hard-coded false on Windows pre-v0.7.3.
    crate::platform::process_alive(pid)
}

// ---------- v0.9.2 string-distance + helpful-miss helpers ----------

/// Iterative Levenshtein distance between two strings, case-insensitive.
/// O(m*n) time, O(min(m, n)) space — fine for the short names wire
/// resolves against (typically <30 chars).
fn levenshtein_ci(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.to_ascii_lowercase().chars().collect();
    let b: Vec<char> = b.to_ascii_lowercase().chars().collect();
    let (a, b) = if a.len() < b.len() { (a, b) } else { (b, a) };
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];
    for j in 1..=n {
        curr[0] = j;
        for i in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[i] = std::cmp::min(
                std::cmp::min(curr[i - 1] + 1, prev[i] + 1),
                prev[i - 1] + cost,
            );
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

/// Return up to `max_results` names from `pool` whose edit distance to
/// `needle` is ≤ `max_distance`, sorted by distance ascending. Used for
/// "did you mean" suggestions on resolution miss.
pub fn closest_candidates(
    needle: &str,
    pool: &[String],
    max_distance: usize,
    max_results: usize,
) -> Vec<String> {
    let mut scored: Vec<(usize, &String)> = pool
        .iter()
        .map(|c| (levenshtein_ci(needle, c), c))
        .filter(|(d, _)| *d <= max_distance)
        .collect();
    scored.sort_by_key(|(d, _)| *d);
    scored
        .into_iter()
        .take(max_results)
        .map(|(_, c)| c.clone())
        .collect()
}

/// Extract just the host portion from `https://host:port/path` → `host`.
/// Returns empty string if the URL is malformed.
pub(super) fn host_of_url(url: &str) -> String {
    let no_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    no_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Collect every name that `resolve_name_to_target` would currently
/// match: pinned-peer handles, pinned-peer character nicknames, sister
/// session names, sister character nicknames, sister handles. Used for
/// the `did_you_mean` pool on resolution miss.
pub(super) fn known_local_names() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(trust) = config::read_trust() {
        // (debug eprintln removed; left bug-trail in commit message)
        // trust.agents is an object keyed by handle, NOT an array —
        // shape is `{handle: {did, public_keys, tier}, ...}`. Iterate
        // the object's keys (which ARE the handles) plus each entry's
        // did for the DID-derived character nickname.
        if let Some(agents) = trust.get("agents").and_then(Value::as_object) {
            for (handle, agent) in agents {
                names.push(handle.clone());
                if let Some(did) = agent.get("did").and_then(Value::as_str) {
                    let ch = crate::character::Character::from_did(did);
                    names.push(ch.nickname);
                }
            }
        }
    }
    if let Ok(sessions) = crate::session::list_sessions() {
        for s in sessions {
            names.push(s.name.clone());
            if let Some(h) = &s.handle {
                names.push(h.clone());
            }
            if let Some(ch) = &s.character {
                names.push(ch.nickname.clone());
            }
        }
    }
    names.sort();
    names.dedup();
    names
}
pub(super) fn cmd_claim(
    nick: &str,
    relay_override: Option<&str>,
    public_url: Option<&str>,
    hidden: bool,
    as_json: bool,
) -> Result<()> {
    // `wire claim` is the one-step bootstrap: auto-init + auto-allocate slot
    // + claim handle. Operator should never have to run init/bind-relay first.
    let (_did, relay_url, slot_id, slot_token) =
        crate::pair_invite::ensure_self_with_relay(relay_override)?;
    let card = config::read_agent_card()?;

    // v0.13.1 one-name enforcement: the handle you claim in the phonebook
    // MUST equal your DID-derived persona, so the directory entry can never
    // drift from your agent-card handle. A typed nick that differs is ignored
    // (mirrors how `wire init` coerces the typed name). This closes the
    // claim-path reopening of the v0.11 "two names" footgun — before this,
    // `wire claim coffee-ghost` published coffee-ghost@relay -> your DID while
    // your card said e.g. outback-sandpiper. The typed `nick` arg is now
    // vestigial, exactly like the one `wire init` / `wire up` already accept.
    let did = card.get("did").and_then(Value::as_str).unwrap_or_default();
    let canonical = crate::agent_card::display_handle_from_did(did).to_string();
    if !canonical.is_empty() && nick != canonical && !as_json {
        eprintln!(
            "wire claim: typed `{nick}` ignored — one-name rule. Claiming your persona `{canonical}`."
        );
    }
    let nick = if canonical.is_empty() {
        nick
    } else {
        canonical.as_str()
    };
    if !crate::pair_profile::is_valid_nick(nick) {
        bail!(
            "phyllis: {nick:?} won't fit in the books — handles need 2-32 chars, lowercase [a-z0-9_-], not on the reserved list"
        );
    }

    let client = crate::relay_client::RelayClient::new(&relay_url);
    // v0.5.19 (#9.1): forward the `discoverable` flag. None for default
    // (back-compat); Some(false) for `--hidden`. Relays older than
    // v0.5.19 ignore the field, so this is safe to always send.
    let discoverable = if hidden { Some(false) } else { None };
    let resp =
        client.handle_claim_v2(nick, &slot_id, &slot_token, public_url, &card, discoverable)?;

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
            let published = republish_card_to_phonebook();
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "field": field,
                        "profile": new_profile,
                        "published_to": published,
                    }))?
                );
            } else {
                println!("profile.{field} set");
                print_profile_publish_result(&published);
            }
        }
        ProfileAction::Get { json } => return pairing::cmd_whois(None, json, None),
        ProfileAction::Clear { field, json } => {
            let new_profile = crate::pair_profile::write_profile_field(&field, Value::Null)?;
            let published = republish_card_to_phonebook();
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "field": field,
                        "cleared": true,
                        "profile": new_profile,
                        "published_to": published,
                    }))?
                );
            } else {
                println!("profile.{field} cleared");
                print_profile_publish_result(&published);
            }
        }
    }
    Ok(())
}

/// Best-effort: re-publish the (freshly re-signed) agent-card to every relay
/// this identity already holds a federation slot on, so a `wire profile`
/// edit reaches the public phonebook immediately instead of waiting for the
/// next `wire up`. Silent no-op when the identity holds no federation slot
/// (offline / local-only). `discoverable: None` makes the relay PRESERVE the
/// prior setting, so a `--hidden` agent stays hidden across the re-claim.
/// Returns the relay URLs the card was published to.
fn republish_card_to_phonebook() -> Vec<String> {
    let Ok(card) = config::read_agent_card() else {
        return Vec::new();
    };
    let did = card.get("did").and_then(Value::as_str).unwrap_or_default();
    let persona = crate::agent_card::display_handle_from_did(did).to_string();
    if persona.is_empty() {
        return Vec::new();
    }
    let Ok(state) = config::read_relay_state() else {
        return Vec::new();
    };
    let mut published = Vec::new();
    for ep in crate::endpoints::self_endpoints(&state) {
        if ep.scope != crate::endpoints::EndpointScope::Federation
            || ep.slot_id.is_empty()
            || ep.slot_token.is_empty()
        {
            continue;
        }
        let client = crate::relay_client::RelayClient::new(&ep.relay_url);
        if client
            .handle_claim_v2(&persona, &ep.slot_id, &ep.slot_token, None, &card, None)
            .is_ok()
        {
            published.push(ep.relay_url.clone());
        }
    }
    published
}

fn print_profile_publish_result(published: &[String]) {
    if published.is_empty() {
        println!(
            "  (local only — not bound to a federation relay; run `wire up` to publish to the phonebook)"
        );
    } else {
        println!("  published to phonebook: {}", published.join(", "));
    }
}

#[cfg(test)]
mod scan_jsonl_dir_tests {
    use super::*;

    #[test]
    fn scan_jsonl_dir_excludes_pushed_audit_files() {
        // Pre-fix `wire status` reported `outbox.events` as the sum of
        // both the live outbox files AND the audit-only `*.pushed.jsonl`
        // lifecycle logs. On a long-running operator's box that turned
        // "11 events queued" into "71811 events queued" — confusing
        // and load-bearing-wrong for the silent-send detection class.
        let dir = tempfile::tempdir().unwrap();
        // Live outbox: one peer, 2 events.
        std::fs::write(
            dir.path().join("alice.jsonl"),
            "{\"event_id\":\"a\"}\n{\"event_id\":\"b\"}\n",
        )
        .unwrap();
        // Audit log: one peer, 100 events. Must NOT count.
        let many: String = (0..100)
            .map(|i| format!("{{\"event_id\":\"x{i}\",\"ts\":\"...\"}}\n"))
            .collect();
        std::fs::write(dir.path().join("alice.pushed.jsonl"), many).unwrap();
        let result = scan_jsonl_dir(dir.path()).unwrap();
        assert_eq!(
            result["events"], 2,
            "events count must include only live outbox lines, not pushed-log audit lines"
        );
        assert_eq!(
            result["files"], 1,
            "files count must reflect 1 live outbox file (the .pushed.jsonl audit log doesn't count as a queued-events surface)"
        );
    }

    #[test]
    fn scan_jsonl_dir_zero_when_only_pushed_log_present() {
        // Edge case: a peer who's drained their queue still has an
        // append-only `<peer>.pushed.jsonl` file but no `<peer>.jsonl`.
        // Should report zero events, zero files — there's no pending
        // outbox work.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("alice.pushed.jsonl"),
            "{\"event_id\":\"a\"}\n",
        )
        .unwrap();
        let result = scan_jsonl_dir(dir.path()).unwrap();
        assert_eq!(result["events"], 0);
        assert_eq!(result["files"], 0);
    }

    #[test]
    fn scan_jsonl_dir_returns_zero_for_missing_dir() {
        let result = scan_jsonl_dir(std::path::Path::new("/nonexistent")).unwrap();
        assert_eq!(result["events"], 0);
        assert_eq!(result["files"], 0);
    }
}

// v0.14: tests for op-claims surfacing on operator read verbs.
// Pure-over-Value helper; no I/O, no filesystem fixtures needed.
#[cfg(test)]
mod op_claims_surfacing_tests {
    use super::*;

    #[test]
    fn op_claims_extracts_present_non_null_fields() {
        let card = json!({
            "did": "did:wire:foo-deadbeef",
            "handle": "foo",
            "op_did": "did:wire:op:foo-aaaa",
            "op_pubkey": "PKB64==",
            "op_cert": "SIGB64==",
            "org_memberships": [{"org_did": "did:wire:org:slancha-bbbb"}],
            "schema_version": "v3.2",
        });
        let claims = op_claims_from_card(&card);
        assert_eq!(claims.len(), 5);
        assert_eq!(
            claims.get("op_did").and_then(Value::as_str),
            Some("did:wire:op:foo-aaaa")
        );
        assert!(
            claims
                .get("org_memberships")
                .and_then(Value::as_array)
                .is_some()
        );
    }

    #[test]
    fn op_claims_empty_on_pre_v014_card() {
        // A pre-v0.14 card has none of the inline op_* fields. The
        // helper must return an EMPTY map so older peers surface
        // identically on every read verb (no `null`-spam in JSON,
        // no new lines in human output).
        let card = json!({
            "did": "did:wire:bar-cafebabe",
            "handle": "bar",
            "capabilities": ["wire/v3.1"],
        });
        assert!(op_claims_from_card(&card).is_empty());
    }

    #[test]
    fn op_claims_skips_explicit_null_fields() {
        // Defensive: a card where republish has serialized op_did as
        // `null` (e.g., post-unenroll rebuild) must not surface a
        // `null` field — operators read absence to mean "not enrolled".
        let card = json!({
            "did": "did:wire:baz-12341234",
            "op_did": Value::Null,
            "org_memberships": Value::Null,
            "schema_version": "v3.2",
        });
        let claims = op_claims_from_card(&card);
        assert_eq!(claims.len(), 1);
        assert!(claims.get("op_did").is_none());
        assert!(claims.get("org_memberships").is_none());
        assert_eq!(
            claims.get("schema_version").and_then(Value::as_str),
            Some("v3.2")
        );
    }
}

#[cfg(test)]
mod enroll_add_membership_tests {
    use super::*;
    use crate::enroll::issue_member_cert;
    use crate::signing::{b64encode, generate_keypair};

    fn seed_op() -> ([u8; 32], [u8; 32], String) {
        let (sk, pk) = generate_keypair();
        crate::config::write_op_key(&sk).unwrap();
        crate::config::write_op_handle("opfoo").unwrap();
        let op_did = crate::agent_card::did_for_op("opfoo", &pk);
        (sk, pk, op_did)
    }

    #[test]
    fn add_membership_happy_path_stores_and_is_idempotent() {
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let (_op_sk, _op_pk, op_did) = seed_op();
            let (org_sk, org_pk) = generate_keypair();
            let org_did = crate::agent_card::did_for_org("acme", &org_pk);
            let cert = issue_member_cert(&org_sk, &op_did).unwrap();
            let bundle = json!({
                "org_did": org_did,
                "org_pubkey": b64encode(&org_pk),
                "member_cert": cert,
            })
            .to_string();
            cmd_enroll_add_membership(Some(bundle.clone()), None, None, None, true).unwrap();
            let stored = config::read_memberships().unwrap();
            assert_eq!(stored.len(), 1);
            assert_eq!(
                stored[0].get("org_did").and_then(Value::as_str),
                Some(org_did.as_str())
            );
            // Idempotent: re-running with the same org_did replaces, not duplicates.
            cmd_enroll_add_membership(Some(bundle), None, None, None, true).unwrap();
            assert_eq!(config::read_memberships().unwrap().len(), 1);
        });
    }

    #[test]
    fn add_membership_rejects_cert_for_wrong_op_did() {
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let (_op_sk, _op_pk, _op_did) = seed_op();
            let (org_sk, org_pk) = generate_keypair();
            let org_did = crate::agent_card::did_for_org("acme", &org_pk);
            // Cert signed for a DIFFERENT op_did. Verify must refuse.
            let other_did = "did:wire:op:ghost-deadbeefdeadbeefdeadbeefdeadbeef";
            let cert = issue_member_cert(&org_sk, other_did).unwrap();
            let bundle = json!({
                "org_did": org_did,
                "org_pubkey": b64encode(&org_pk),
                "member_cert": cert,
            })
            .to_string();
            let err = cmd_enroll_add_membership(Some(bundle), None, None, None, true).unwrap_err();
            assert!(
                err.to_string().contains("verification failed"),
                "got: {err:#}"
            );
            // And nothing landed on disk.
            assert!(config::read_memberships().unwrap().is_empty());
        });
    }

    #[test]
    fn add_membership_rejects_when_not_enrolled() {
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            // No op key written → we don't know our own op_did → refuse.
            let (org_sk, org_pk) = generate_keypair();
            let org_did = crate::agent_card::did_for_org("acme", &org_pk);
            let cert = issue_member_cert(&org_sk, "did:wire:op:anybody-aaaa").unwrap();
            let bundle = json!({
                "org_did": org_did,
                "org_pubkey": b64encode(&org_pk),
                "member_cert": cert,
            })
            .to_string();
            let err = cmd_enroll_add_membership(Some(bundle), None, None, None, true).unwrap_err();
            assert!(err.to_string().contains("not enrolled"), "got: {err:#}");
        });
    }

    #[test]
    fn add_membership_rejects_malformed_org_did() {
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let _ = seed_op();
            let bundle = json!({
                "org_did": "did:wire:not-an-org",
                "org_pubkey": "AAAA",
                "member_cert": "AAAA",
            })
            .to_string();
            let err = cmd_enroll_add_membership(Some(bundle), None, None, None, true).unwrap_err();
            assert!(
                err.to_string().contains("not a valid organization DID"),
                "got: {err:#}"
            );
        });
    }
}
