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

use crate::config;

mod comms;
mod demo;
mod group;
mod identity;
mod lifecycle;
mod mesh;
mod pairing;
mod relay;
mod session;
mod setup;
mod status;
mod upgrade;

pub(crate) use comms::here_summary;
pub(crate) use comms::parse_deadline_until;
pub(crate) use relay::cmd_bind_relay;
pub use relay::error_smells_like_slot_4xx;
pub use relay::run_sync_pull;
pub use relay::run_sync_push;
pub use session::maybe_auto_init_cwd_session;

// Re-exports for cross-module callers (comms.rs, mcp.rs, etc.).
pub(crate) use pairing::{DialTarget, resolve_name_to_target};
pub(crate) use pairing::{
    ResolveError, add_local_sister_core, cmd_add_local_sister, resolve_peer_handle,
};
// Re-exports for identity family: setup.rs calls super::cmd_init / super::cmd_claim;
// comms.rs + pairing.rs call super::op_claims_from_card; mcp.rs calls crate::cli::op_claims_from_card.
pub(crate) use identity::op_claims_from_card;
pub(super) use identity::{cmd_claim, cmd_init};

/// Top-level CLI.
#[derive(Parser, Debug)]
#[command(
    name = "wire",
    version,
    about = "Magic-wormhole for AI agents — bilateral signed-message bus",
    long_about = None,
    after_help = "\x1b[1mStart here:\x1b[0m\n  \
        wire up                     come online (one command)\n  \
        wire dial <name> \"hi\"       reach a peer and send\n  \
        wire tail                   read replies\n  \
        wire here                   who am I, who's around?\n  \
        wire doctor                 something off? full health check\n\
        \nThe ~40 verbs below are mostly plumbing — the five above cover daily use.\n\
        Guide: https://github.com/SlanchaAi/wire"
)]
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
    /// Emit a shell completion script to stdout.
    ///
    /// Pipe to your shell's completion dir to enable tab-completion of
    /// wire verbs + handles + flags.
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
    /// One-screen "you are here" — your character, handle, cwd, and neighbors.
    ///
    /// Prints the current session's character + handle + cwd, plus a short
    /// list of neighbors (sister sessions on the local relay, pinned peers).
    /// Designed for the operator's quick "wait which Claude is this,
    /// and who's around?" question — no `--json` shuffling, no
    /// remembering `wire whoami` vs `wire peers` vs `wire session
    /// list-local`.
    Here {
        #[arg(long)]
        json: bool,
    },
    /// List pending-inbound pair requests waiting for your consent.
    ///
    /// Operators reach for "what's pending?" not a longer table-dump verb.
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
    /// Fan a single signed message out to every org-mate tagged with a project
    /// (RFC-001 §6 client-side project routing).
    ///
    /// Recipients = every pinned peer at effective tier **>= ORG_VERIFIED**
    /// whose card carries `project == <project>`. The tier floor is the trust
    /// gate; `project` is unsigned routing metadata (it picks who, never grants
    /// trust). Delivery is N synchronous one-to-one pushes — wire has no
    /// broadcast primitive. Zero matching peers is a no-op success.
    ///
    /// Set your own project tag with `wire project <tag>`; peers see it on your
    /// card once they pin (or re-pull) it.
    SendProject {
        /// Project tag to fan out to (must match peers' card `project`).
        project: String,
        /// Event body — free-form text, `@/path/to/body.json`, or `-` for stdin.
        body: String,
        /// Event kind (`claim`, `decision`, … or numeric id). Default `claim`.
        #[arg(long, default_value = "claim")]
        kind: String,
        /// Advisory deadline: duration (`30m`, `2h`, `1d`) or RFC3339 timestamp.
        #[arg(long)]
        deadline: Option<String>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show, set, or clear this session's project routing tag (RFC-001 §6).
    ///
    /// `wire project` prints the current tag; `wire project <tag>` sets it;
    /// `wire project --clear` removes it. The tag is unsigned metadata on your
    /// agent-card — peers who pin your card use it to target
    /// `wire send-project <tag>` fan-outs. Set it before pairing (or re-pair
    /// after) so the change reaches peers.
    Project {
        /// New project tag. Omit to print the current tag.
        tag: Option<String>,
        /// Clear the project tag instead of setting one.
        #[arg(long, conflicts_with = "tag")]
        clear: bool,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// "Go talk to this name." The one verb operators reach for.
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
    /// Manually pin a peer's relay slot from out-of-band coordinates.
    /// Plumbing — prefer `wire dial` (which resolves + pairs for you).
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
    /// Multi-session topology: supervisor + every session's daemon liveness.
    ///
    /// Supervisor liveness + per-session daemon liveness + unmanaged
    /// `wire daemon` pids. `wire status` answers "is THIS session syncing?";
    /// `wire supervisor` answers "what is the supervisor (and every
    /// session's daemon) doing across the box?".
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
    /// Orchestration verbs for the
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
    /// Trust an organization by its domain (RFC-001 §2 DNS-TXT floor):
    /// `wire org bind <domain>` / `wire org list` / `wire org forget <org_did>`.
    #[command(subcommand)]
    Org(OrgCommand),
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
    /// Federation backend of `wire dial` — prefer `wire dial`.
    ///
    /// Zero-paste pair with a known handle: resolves `nick@domain` via that
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
    /// See wire work in one command — an ephemeral two-agent round-trip.
    ///
    /// Boots a throwaway local relay, mints two temporary identities, pairs
    /// them, and sends a signed message end-to-end — then tears it all down.
    /// No install of a relay, no second terminal, no copy-pasting a persona.
    /// The fastest way to watch two agents talk before setting wire up for
    /// real. Nothing it creates outlives the command.
    Demo {
        /// Emit a JSON result summary instead of the narrated walkthrough.
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
        /// Confirm nuking a machine with a LIVE operator install
        /// (registry-bound sessions). The unit/process/MCP teardown is
        /// machine-global even under a temp WIRE_HOME, so a bound
        /// default registry refuses without this flag.
        #[arg(long)]
        really_this_machine: bool,
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
    /// Accept a pending-inbound pair request by character
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
    /// Accept a federation invite URL minted by `wire invite`.
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
    /// Refuse a pending-inbound pair request without pairing.
    Reject {
        /// Peer name (character nickname or handle) from `wire pending`.
        peer: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Block a peer DID so it can never be org-auto-paired or surface an
    /// org-notify prompt (RFC-001 §T16 rogue-admin containment).
    ///
    /// Pass a **session DID** (`did:wire:<handle>-<8hex>`) to mute one session,
    /// or an **operator DID** (`did:wire:op:<handle>-<32hex>`) to mute every
    /// session that operator runs — the lever for cutting off a single
    /// adversary a compromised org admin vouched into the roster, without
    /// leaving the org. Local-only; idempotent; survives roster epoch bumps.
    ///
    /// A block gates the org-easing path, NOT a deliberate bilateral SAS pair:
    /// if you knowingly `wire dial` + SAS-verify a blocked peer, that explicit
    /// gesture wins. Unblock with `wire unblock-peer <did>`.
    BlockPeer {
        /// The DID to block (session `did:wire:…` or operator `did:wire:op:…`).
        did: String,
        /// Optional note recorded alongside the block (why / who).
        #[arg(long)]
        note: Option<String>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove a DID from the local block-list (undo `wire block-peer`).
    UnblockPeer {
        /// The DID to unblock.
        did: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// List the DIDs on the local block-list (RFC-001 §T16).
    Blocked {
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
    /// Rotate the operator root key (RFC-001 §T20). Mints a fresh op keypair —
    /// which, because the op_did commits to the key, is a NEW op_did — and
    /// emits a succession cert: the old key signing the `old_op_did → new_op_did`
    /// handoff. Use after a suspected op-key compromise.
    ///
    /// After rotating you MUST re-enroll: every org you're in re-issues your
    /// member_cert against the new op_did (`wire enroll org-add-member
    /// <new_op_did>`), then `wire enroll republish`. Receiver-side automatic
    /// trust-migration from the succession cert is deferred (T20); the cert +
    /// the new op_did are recorded in `succession.jsonl` for that follow-up.
    RotateOpKey {
        #[arg(long)]
        json: bool,
    },
    /// Rotate an organization root key (RFC-001 §T19). Mints a fresh org keypair
    /// (a NEW org_did) and emits a succession cert (old org key signs the
    /// `old_org_did → new_org_did` handoff). Use after a suspected org-key
    /// compromise.
    ///
    /// After rotating you re-issue every member_cert with the new key and
    /// republish the org's DNS-TXT binding to the new org_did. The new key is
    /// stored under the new org_did; the old key file is left in place for you
    /// to delete.
    RotateOrgKey {
        /// The current `org_did` to rotate (from `wire enroll org-create`).
        org_did: String,
        #[arg(long)]
        json: bool,
    },
}

/// `wire org …` — trust organizations by their domain (RFC-001 §2 DNS-TXT
/// floor). Binding resolves `_wire-org.<domain>` to an `org_did` and records a
/// per-org inbound policy; a peer with a verified `member_cert` for a bound org
/// then reaches `ORG_VERIFIED` under the chosen mode.
#[derive(Subcommand, Debug)]
pub enum OrgCommand {
    /// Resolve `_wire-org.<domain>` (DNS-TXT, over DoH) and trust the org it
    /// binds. The org's identity is now rooted in a domain it demonstrably
    /// controls — not a bare keypair.
    Bind {
        /// The org's domain, e.g. `acme.com`.
        domain: String,
        /// Inbound mode for members: `notify` (default — one tap to
        /// ORG_VERIFIED) or `auto` (Option A — pin ORG_VERIFIED with no tap;
        /// amplifies a rogue-admin's blast radius, so opt in deliberately).
        #[arg(long, default_value = "notify")]
        mode: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// List the organizations currently trusted (org_did + inbound mode).
    List {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Stop trusting an organization (remove its per-org policy by `org_did`).
    Forget {
        /// The `org_did` to forget (from `wire org list`).
        org_did: String,
        /// Emit JSON.
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
        } => identity::cmd_whoami(json_default(json), short, colored),
        Command::Peers { json } => comms::cmd_peers(json_default(json)),
        Command::Here { json } => comms::cmd_here(json_default(json)),
        Command::Demo { json } => demo::cmd_demo(json_default(json)),
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
        Command::BlockPeer { did, note, json } => {
            pairing::cmd_block_peer(&did, note, json_default(json))
        }
        Command::UnblockPeer { did, json } => pairing::cmd_unblock_peer(&did, json_default(json)),
        Command::Blocked { json } => pairing::cmd_blocked(json_default(json)),
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
        Command::SendProject {
            project,
            body,
            kind,
            deadline,
            json,
        } => comms::cmd_send_project(
            &project,
            &kind,
            &body,
            deadline.as_deref(),
            json_default(json),
        ),
        Command::Project { tag, clear, json } => {
            identity::cmd_project(tag.as_deref(), clear, json_default(json))
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
        Command::Identity { cmd } => identity::cmd_identity(cmd),
        Command::Mesh(cmd) => cmd_mesh(cmd),
        Command::Group(cmd) => cmd_group(cmd),
        Command::Enroll(cmd) => identity::cmd_enroll(cmd),
        Command::Org(cmd) => identity::cmd_org(cmd),
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
        } => identity::cmd_claim(&nick, relay.as_deref(), public_url.as_deref(), hidden, json),
        Command::Profile { action } => identity::cmd_profile(action),
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
            really_this_machine,
            json,
        } => lifecycle::cmd_nuke(force, purge, dry_run, really_this_machine, json),
        Command::Quiet { action } => lifecycle::cmd_quiet(action),
    }
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
        } => session::cmd_session_new(
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
        SessionCommand::List { json } => session::cmd_session_list(json),
        SessionCommand::ListLocal { json } => session::cmd_session_list_local(json),
        SessionCommand::PairAllLocal {
            settle_secs,
            federation_relay,
            json,
        } => session::cmd_session_pair_all_local(settle_secs, &federation_relay, json),
        SessionCommand::MeshStatus { stale_secs, json } => {
            cmd_session_mesh_status(stale_secs, json)
        }
        SessionCommand::Env { name, json } => session::cmd_session_env(name.as_deref(), json),
        SessionCommand::Current { json } => session::cmd_session_current(json),
        SessionCommand::Bind { name, json } => cmd_session_bind(name.as_deref(), json),
        SessionCommand::Destroy { name, force, json } => {
            session::cmd_session_destroy(&name, force, json)
        }
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

pub(super) fn run_wire_with_home(
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

/// Check whether `session_home`'s `relay.json` already lists `peer_name`
/// under `state.peers`. Best-effort — any read/parse error → false.
pub(super) fn session_has_peer(session_home: &std::path::Path, peer_name: &str) -> bool {
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
