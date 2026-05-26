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
    // (Old `Join` stub removed in iter 11 — superseded by `pair-join` with
    // `join` alias. See PairJoin below.)
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
    /// for your consent. Aliases the legacy `pair-list-inbound` verb
    /// but with the shorter, intent-first name. Operators reach for
    /// "what's pending?" not "what's in my pair-list-inbound table?"
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
    /// With an optional message, `wire dial <name> "<msg>"` also queues
    /// and pushes the message after the pair completes. Idempotent: re-
    /// dialling a known peer just sends.
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
    #[command(hide = true)] // v0.9 deprecated
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
    #[command(hide = true)] // v0.9 deprecated
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
    #[command(hide = true)] // v0.9 deprecated
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
    #[command(hide = true)] // v0.9 deprecated
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
    #[command(hide = true)] // v0.9 deprecated
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
    #[command(hide = true)] // v0.9 deprecated
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
    ///
    /// v0.10: hidden from --help. Federation pair flow is now
    /// `wire dial <handle>@<relay>` + `wire accept-invite <URL>`.
    /// `wire pair` stays callable for back-compat scripts; v1.0 removes.
    #[command(hide = true)] // v0.10 deprecated — use `wire dial <h>@<relay>`
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
    #[command(hide = true)] // v0.9 deprecated
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
    #[command(hide = true)] // v0.9 deprecated
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
    #[command(hide = true)] // v0.9 deprecated
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
    #[command(hide = true)] // v0.9 deprecated
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
    /// nickname or card handle. Replaces the verbose `wire pair-accept
    /// <peer>`.
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
    /// v0.9: refuse a pending-inbound pair request without pairing. Aliases
    /// the legacy `wire pair-reject <peer>`.
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
    /// `wire add` from A → B (queued + pushed), `wire pair-accept` on
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
                cmd_status_peer(&peer, json)
            } else {
                cmd_status(json)
            }
        }
        Command::Whoami {
            json,
            short,
            colored,
        } => cmd_whoami(json_default(json), short, colored),
        Command::Peers { json } => cmd_peers(json_default(json)),
        Command::Here { json } => cmd_here(json_default(json)),
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
        Command::Pending { json } => cmd_pair_list_inbound(json_default(json)),
        Command::Reject { peer, json } => cmd_pair_reject(&peer, json_default(json)),
        Command::Send {
            peer,
            kind_or_body,
            body,
            deadline,
            no_auto_pair,
            json,
        } => {
            // P0.S: smart-positional API. `wire send peer body` =
            // kind=claim. `wire send peer kind body` = explicit kind.
            let (kind, body) = match body {
                Some(real_body) => (kind_or_body, real_body),
                None => ("claim".to_string(), kind_or_body),
            };
            cmd_send(
                &peer,
                &kind,
                &body,
                deadline.as_deref(),
                no_auto_pair,
                json_default(json),
            )
        }
        Command::Dial {
            name,
            message,
            json,
        } => cmd_dial(&name, message.as_deref(), json_default(json)),
        Command::Tail { peer, json, limit } => cmd_tail(peer.as_deref(), json, limit),
        Command::Monitor {
            peer,
            json,
            include_handshake,
            interval_ms,
            replay,
        } => cmd_monitor(
            peer.as_deref(),
            json,
            include_handshake,
            interval_ms,
            replay,
        ),
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
        Command::RelayServer {
            bind,
            local_only,
            uds,
        } => cmd_relay_server(&bind, local_only, uds.as_deref()),
        Command::BindRelay {
            url,
            scope,
            replace,
            migrate_pinned,
            json,
        } => cmd_bind_relay(&url, scope.as_deref(), replace, migrate_pinned, json),
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
        Command::PairAccept { peer, json } => {
            let j = json_default(json);
            deprecation_warn("pair-accept", &format!("accept {peer}"), j);
            cmd_pair_accept(&peer, j)
        }
        Command::PairReject { peer, json } => {
            let j = json_default(json);
            deprecation_warn("pair-reject", &format!("reject {peer}"), j);
            cmd_pair_reject(&peer, j)
        }
        Command::PairListInbound { json } => {
            let j = json_default(json);
            deprecation_warn("pair-list-inbound", "pending", j);
            cmd_pair_list_inbound(j)
        }
        Command::Session(cmd) => cmd_session(cmd),
        Command::Identity { cmd } => cmd_identity(cmd),
        Command::Mesh(cmd) => cmd_mesh(cmd),
        Command::Group(cmd) => cmd_group(cmd),
        Command::Invite {
            relay,
            ttl,
            uses,
            share,
            json,
        } => cmd_invite(&relay, ttl, uses, share, json),
        Command::Accept { target, json } => {
            // v0.9.4: smart-dispatch retired. `wire accept` always means
            // pair-accept by name. URL-shaped input gets a deprecation
            // banner pointing at `wire accept-invite <URL>` and then
            // (for back-compat with v0.9 scripts) routes to the invite
            // accept path one last time. v1.0 will reject URLs here.
            let j = json_default(json);
            if target.starts_with("wire://pair?") {
                deprecation_warn("accept-url", "accept-invite <url>", j);
                cmd_accept(&target, j)
            } else {
                cmd_pair_accept(&target, j)
            }
        }
        Command::AcceptInvite { url, json } => cmd_accept(&url, json_default(json)),
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
                Some(h) if !h.contains('@') => cmd_whois_local(h, json),
                other => cmd_whois(other, json, relay.as_deref()),
            }
        }
        Command::Add {
            handle,
            relay,
            local_sister,
            json,
        } => cmd_add(&handle, relay.as_deref(), local_sister, json),
        Command::Up {
            relay,
            name,
            with_local,
            no_local,
            json,
        } => cmd_up(
            relay.as_deref(),
            name.as_deref(),
            with_local.as_deref(),
            no_local,
            json,
        ),
        Command::Doctor {
            json,
            recent_rejections,
        } => cmd_doctor(json, recent_rejections),
        Command::Upgrade { check, local, json } => cmd_upgrade(check, local, json),
        Command::Service { action } => cmd_service(action),
        Command::Diag { action } => cmd_diag(action),
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
                cmd_setup_statusline(apply, remove)
            } else {
                cmd_setup(apply)
            }
        }
        Command::Notify {
            interval,
            peer,
            once,
            json,
        } => cmd_notify(interval, peer.as_deref(), once, json),
    }
}

// ---------- init ----------

fn cmd_init(
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
        let relay_state_for_tier =
            config::read_relay_state().unwrap_or_else(|_| json!({"peers": {}}));
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

        // v0.5.19: liveness snapshot through a single helper so this
        // surface and `wire doctor` agree by construction. Issue #2:
        // doctor PASSed while status said DOWN for 25 min because each
        // computed liveness independently. ensure_up::daemon_liveness
        // is the only path now.
        let snap = crate::ensure_up::daemon_liveness();
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
            daemon["schema"] = json!(d.schema);
            if d.version != env!("CARGO_PKG_VERSION") {
                daemon["version_mismatch"] = json!({
                    "daemon": d.version.clone(),
                    "cli": env!("CARGO_PKG_VERSION"),
                });
            }
        } else if matches!(snap.record, crate::ensure_up::PidRecord::LegacyInt(_)) {
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
        return format!("~/{}", rel_str);
    }
    cwd.to_string_lossy().into_owned()
}

fn cmd_whoami(as_json: bool, short: bool, colored: bool) -> Result<()> {
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
                "persona": character,
                "persona_override": has_override,
            }))?
        );
    } else {
        println!("{}", character.colored());
        println!("{did} (ed25519:{key_id})");
        println!("fingerprint: {fp}");
        println!("capabilities: {capabilities}");
    }
    Ok(())
}

// ---------- identity (v0.7.0-alpha.3) ----------

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
    let cwd_key = cwd.to_string_lossy().into_owned();
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
        // v0.7.0-alpha.6: prefer peer's published character override
        // (display.nickname / display.emoji on their pinned agent-card).
        // Falls back to auto-derived if peer hasn't renamed themselves
        // OR runs an older wire that doesn't publish the field.
        let character = if did.is_empty() {
            None
        } else {
            let card_obj = agent.get("card");
            Some(match card_obj {
                Some(card) => crate::character::Character::from_card(card),
                None => crate::character::Character::from_did(&did),
            })
        };
        peers.push(json!({
            "handle": handle,
            "did": did,
            "tier": tier,
            "capabilities": capabilities,
            "persona": character,
        }));
    }

    if as_json {
        println!("{}", serde_json::to_string(&peers)?);
    } else if peers.is_empty() {
        println!("no peers pinned (run `wire join <code>` to pair)");
    } else {
        // v0.7.0-alpha.8 (review-fix #3): reuse the character we ALREADY
        // computed above (from peer's agent-card, honoring override) so
        // text and JSON output never diverge. Pre-alpha.8 the text loop
        // recomputed via Character::from_did (no override) — operators
        // saw different identities depending on --json flag.
        for p in &peers {
            let char_json = &p["persona"];
            let (colored_char, plain_len): (String, usize) = match char_json {
                serde_json::Value::Null => ("?".to_string(), 1),
                v => match serde_json::from_value::<crate::character::Character>(v.clone()) {
                    Ok(c) => {
                        let plain = c.short().chars().count() + 1; // +1 emoji-wide compensation
                        (c.colored(), plain)
                    }
                    Err(_) => ("?".to_string(), 1),
                },
            };
            let pad = 22usize.saturating_sub(plain_len);
            println!(
                "{}{}  {:<20} {:<10} {}",
                colored_char,
                " ".repeat(pad),
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
    // v0.10: when true, refuse to auto-pair on miss; fail loudly so
    // scripts can branch on the error instead of accepting an implicit
    // side effect.
    no_auto_pair: bool,
    as_json: bool,
) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let peer_in = crate::agent_card::bare_handle(peer).to_string();
    // v0.7.0-alpha.2/.5: nickname-as-handle resolution. Exact handle
    // match wins; nickname (DID-hash auto-derived) is the fallback.
    // Ambiguous nicknames (two pinned peers DID-hash to the same
    // adj-noun pair) fail loudly with disambiguation; unknown handles
    // pass through (matches existing `wire send` semantics — queue
    // first, deliver best-effort).
    let peer = match resolve_peer_handle(&peer_in) {
        Ok(Some(resolved)) if resolved != peer_in => {
            eprintln!("wire send: resolved nickname `{peer_in}` → peer `{resolved}`");
            resolved
        }
        Ok(Some(canonical)) => canonical, // exact handle match
        Ok(None) => peer_in,              // unknown — pass through, downstream errors
        Err(ResolveError::Ambiguous(candidates)) => bail!(
            "nickname `{peer_in}` is ambiguous — matches {} pinned peers: {}. \
             Disambiguate by passing the peer handle (one of those listed) instead of the nickname.",
            candidates.len(),
            candidates.join(", ")
        ),
        Err(ResolveError::NotFound) => peer_in, // (unreachable for this fn but defensive)
    };

    // v0.9 auto-pair-on-miss: if the resolved peer isn't pinned yet but
    // matches a local sister session, pair first (disk-read --local-sister
    // path) then continue. Closes the "wire send returns queued but
    // peer never receives because we were never paired" silent-fail
    // class. Equivalent to `wire dial <name>` followed by `wire send
    // <name> ...` in one step.
    let peer_is_pinned = config::read_relay_state()
        .ok()
        .and_then(|s| s.get("peers").and_then(Value::as_object).cloned())
        .map(|peers| peers.contains_key(&peer))
        .unwrap_or(false);
    if !peer_is_pinned && let Some(sister_name) = crate::session::resolve_local_sister(&peer) {
        if no_auto_pair {
            bail!(
                "wire send: `{peer}` resolves to local sister `{sister_name}` but is not pinned, \
                 and --no-auto-pair was passed. Run `wire dial {peer}` first, \
                 then re-run send."
            );
        }
        eprintln!(
            "wire send: `{peer}` not pinned yet — auto-pairing via local-sister `{sister_name}` first. \
             Pass --no-auto-pair to refuse implicit dialing."
        );
        cmd_add_local_sister(&sister_name, true).map_err(|e| {
            anyhow!("wire send: auto-pair to local sister `{sister_name}` failed: {e:#}")
        })?;
    }

    let peer = peer.as_str();
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

// ---------- here (v0.9.3 you-are-here view) ----------

/// `wire here` — one-screen "you are this session, your neighbors are
/// these." Combines what `wire whoami`, `wire peers`, and `wire session
/// list-local` would otherwise force the operator to call separately.
fn cmd_here(as_json: bool) -> Result<()> {
    let initialized = config::is_initialized().unwrap_or(false);

    // Self identity.
    let (self_did, self_handle, self_character) = if initialized {
        let card = config::read_agent_card().ok();
        let did = card
            .as_ref()
            .and_then(|c| c.get("did").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        let handle = if did.is_empty() {
            String::new()
        } else {
            crate::agent_card::display_handle_from_did(&did).to_string()
        };
        let character = if did.is_empty() {
            None
        } else {
            // v0.11: DID-derived only. No display.json overrides.
            Some(crate::character::Character::from_did(&did))
        };
        (did, handle, character)
    } else {
        (String::new(), String::new(), None)
    };

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let wire_home = std::env::var("WIRE_HOME").unwrap_or_default();

    // Sister sessions (same-machine).
    let mut sisters: Vec<Value> = Vec::new();
    if let Ok(listing) = crate::session::list_local_sessions() {
        for group in listing.local.values() {
            for s in group {
                if s.handle.as_deref() == Some(self_handle.as_str()) {
                    continue; // skip self
                }
                let ch = s.did.as_deref().map(crate::character::Character::from_did);
                sisters.push(json!({
                    "session": s.name,
                    "handle": s.handle,
                    "persona": ch,
                }));
            }
        }
    }

    // Pinned peers (trust ring agents).
    let mut peers: Vec<Value> = Vec::new();
    if initialized
        && let Ok(trust) = config::read_trust()
        && let Some(agents) = trust.get("agents").and_then(Value::as_object)
    {
        for (handle, agent) in agents {
            if handle == &self_handle {
                continue; // skip self
            }
            let did = agent.get("did").and_then(Value::as_str).unwrap_or("");
            let ch = if did.is_empty() {
                None
            } else {
                Some(crate::character::Character::from_did(did))
            };
            peers.push(json!({
                "handle": handle,
                "did": did,
                "tier": agent.get("tier").and_then(Value::as_str).unwrap_or("UNKNOWN"),
                "persona": ch,
            }));
        }
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "self": {
                    "handle": self_handle,
                    "did": self_did,
                    "persona": self_character,
                    "cwd": cwd,
                    "wire_home": wire_home,
                },
                "sister_sessions": sisters,
                "pinned_peers": peers,
            }))?
        );
        return Ok(());
    }

    // Human format.
    if !initialized {
        println!("not initialized — run `wire init <handle>` to bootstrap.");
        return Ok(());
    }
    let glyph = self_character
        .as_ref()
        .map(crate::character::emoji_with_fallback)
        .unwrap_or_else(|| "?".to_string());
    let nick = self_character
        .as_ref()
        .map(|c| c.nickname.clone())
        .unwrap_or_default();
    println!("you are {glyph} {nick}  ({self_handle})");
    if !cwd.is_empty() {
        println!("  cwd:    {cwd}");
    }
    // Helper closure that mirrors emoji_with_fallback over a JSON-encoded
    // character object (because we already collected sisters/peers into
    // Value rows above). Looks up the canonical emoji-name and falls
    // back to that — never repeats the nickname inside the brackets.
    let render_glyph = |character: &Value| -> String {
        let emoji = character
            .get("emoji")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let nickname = character
            .get("nickname")
            .and_then(Value::as_str)
            .unwrap_or("?");
        if crate::character::terminal_supports_emoji() {
            return emoji.to_string();
        }
        // Synthesize a minimal Character so emoji_with_fallback's
        // lookup table picks the right ASCII tag.
        let synth = crate::character::Character {
            nickname: nickname.to_string(),
            emoji: emoji.to_string(),
            palette: crate::character::Palette {
                primary_hex: String::new(),
                accent_hex: String::new(),
                ansi256_primary: 0,
                ansi256_accent: 0,
            },
        };
        crate::character::emoji_with_fallback(&synth)
    };
    if !sisters.is_empty() {
        println!();
        println!("sister sessions on this machine:");
        for s in &sisters {
            let session = s["session"].as_str().unwrap_or("?");
            let ch_nick = s["persona"]["nickname"].as_str().unwrap_or("?");
            let glyph = render_glyph(&s["persona"]);
            println!("  {glyph} {ch_nick}  ({session})");
        }
    }
    if !peers.is_empty() {
        println!();
        println!("pinned peers:");
        for p in &peers {
            let handle = p["handle"].as_str().unwrap_or("?");
            let tier = p["tier"].as_str().unwrap_or("");
            let ch_nick = p["persona"]["nickname"].as_str().unwrap_or("?");
            let glyph = render_glyph(&p["persona"]);
            println!("  {glyph} {ch_nick}  ({handle})  [{tier}]");
        }
    }
    if sisters.is_empty() && peers.is_empty() {
        println!();
        println!(
            "no neighbors yet — `wire session new` to add a sister, or `wire dial <peer>` to reach out."
        );
    }
    Ok(())
}

// ---------- dial / whois (v0.8 canonical addressing) ----------

/// `wire dial <name> [message]` — the one verb operators reach for.
/// Resolves any name (nickname/handle/session/DID) to a peer and
/// drives the right pair flow + optional first message. See the
/// `Command::Dial` doc for the resolution ladder.
///
/// v0.9: when `name` contains `@<relay>`, route through the federation
/// `wire add <handle>@<relay>` path (`.well-known/wire/agent` resolution
/// plus cross-machine pair_drop). No more bail with "federation isn't
/// implemented yet" — one verb across both orbits.
fn cmd_dial(name: &str, message: Option<&str>, as_json: bool) -> Result<()> {
    if name.contains('@') {
        // Federation path. cmd_add already auto-detects (per v0.7.4)
        // when input has `@` and routes through the .well-known
        // resolver + pair_drop deposit. After it returns, the peer
        // is in pending-outbound; bilateral completes when the peer
        // accepts. Optionally send the first message after the add.
        cmd_add(name, None, false, true)
            .map_err(|e| anyhow!("wire dial: federation pair to `{name}` failed: {e:#}"))?;
        if let Some(msg) = message {
            // Peer handle for send = the nick part before the `@`.
            let bare = name.split('@').next().unwrap_or(name);
            cmd_send(bare, "claim", msg, None, false, as_json)?;
        }
        return Ok(());
    }

    // v0.9.2 helpful-miss: in JSON mode, a resolution miss returns
    // success with `{found: false, candidates: [...]}` instead of
    // erroring. Agents can branch on `found` without wrapping in a
    // try/catch.
    let resolution = match resolve_name_to_target(name) {
        Ok(r) => r,
        Err(e) if as_json => {
            let pool = known_local_names();
            let suggestions = closest_candidates(name, &pool, 3, 3);
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "name_input": name,
                    "found": false,
                    "candidates": suggestions,
                    "error": format!("{e:#}"),
                }))?
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut steps: Vec<Value> = Vec::new();

    match &resolution {
        DialTarget::PinnedPeer { handle, .. } => {
            steps.push(json!({
                "step": "resolved",
                "kind": "already_pinned",
                "handle": handle,
            }));
        }
        DialTarget::LocalSister { session_name, .. } => {
            steps.push(json!({
                "step": "resolved",
                "kind": "local_sister",
                "session": session_name,
            }));
            // Drive the bilateral pair via the disk-read sister path.
            // cmd_add_local_sister already handles "already paired"
            // gracefully (its internal state.peers check returns the
            // existing pin instead of re-issuing a pair_drop), so
            // re-dialling is idempotent.
            cmd_add_local_sister(session_name, true).map_err(|e| {
                anyhow!("dial: local-sister pair to `{session_name}` failed: {e:#}")
            })?;
            steps.push(json!({
                "step": "paired",
                "via": "local_sister",
            }));
        }
    }

    let send_handle = match &resolution {
        DialTarget::PinnedPeer { handle, .. } => handle.clone(),
        DialTarget::LocalSister { handle, .. } => handle.clone(),
    };

    let send_result = if let Some(msg) = message {
        let r = cmd_send(&send_handle, "claim", msg, None, false, true);
        match &r {
            Ok(()) => steps.push(json!({"step": "sent", "to": send_handle, "kind": "claim"})),
            Err(e) => steps.push(json!({"step": "send_failed", "error": format!("{e:#}")})),
        }
        Some(r)
    } else {
        None
    };

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "name_input": name,
                "resolved_handle": send_handle,
                "steps": steps,
            }))?
        );
    } else {
        println!("wire dial: resolved `{name}` → handle `{send_handle}`");
        for s in &steps {
            let step = s.get("step").and_then(Value::as_str).unwrap_or("?");
            println!("  - {step}");
        }
        if message.is_some() {
            println!("  (use `wire tail {send_handle}` to read replies)");
        }
    }
    if let Some(Err(e)) = send_result {
        return Err(e);
    }
    Ok(())
}

/// `wire whois <name>` — resolve any local name (nickname/session/
/// handle/DID) to the full identity row. The inspector for the
/// canonical addressing layer. For federation `handle@relay-domain`
/// resolution see `cmd_whois` (line 5536+) — the dispatcher chooses
/// based on whether the input contains `@`.
fn cmd_whois_local(name: &str, as_json: bool) -> Result<()> {
    // v0.9.2 helpful-miss: in JSON mode, a resolution miss returns
    // success (exit 0) with `{found: false, candidates: [...]}` so
    // agents don't need try/catch around `wire whois <name>`. In
    // human mode, the bail's did-you-mean line points at the
    // closest candidate.
    let resolution = match resolve_name_to_target(name) {
        Ok(r) => r,
        Err(e) if as_json => {
            let pool = known_local_names();
            let suggestions = closest_candidates(name, &pool, 3, 3);
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "name_input": name,
                    "found": false,
                    "candidates": suggestions,
                    "error": format!("{e:#}"),
                }))?
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    match resolution {
        DialTarget::PinnedPeer {
            handle,
            did,
            nickname,
            emoji,
            tier,
        } => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "kind": "pinned_peer",
                        "handle": handle,
                        "did": did,
                        "nickname": nickname,
                        "emoji": emoji,
                        "tier": tier,
                    }))?
                );
            } else {
                let n = nickname.as_deref().unwrap_or("(no character)");
                let e = emoji.as_deref().unwrap_or("?");
                println!("{e} {n}");
                println!("  handle:   {handle}");
                println!("  did:      {did}");
                println!("  tier:     {tier}");
                println!("  reach:    pinned peer (already in trust ring + slot pinned)");
            }
        }
        DialTarget::LocalSister {
            session_name,
            handle,
            did,
            nickname,
            emoji,
        } => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "kind": "local_sister",
                        "session_name": session_name,
                        "handle": handle,
                        "did": did,
                        "nickname": nickname,
                        "emoji": emoji,
                    }))?
                );
            } else {
                let n = nickname.as_deref().unwrap_or("(no character)");
                let e = emoji.as_deref().unwrap_or("?");
                println!("{e} {n}");
                println!("  session:  {session_name}");
                println!("  handle:   {handle}");
                println!(
                    "  did:      {}",
                    did.as_deref().unwrap_or("(card unreadable)")
                );
                println!("  reach:    local sister on this machine — `wire dial {n}` pairs us");
            }
        }
    }
    Ok(())
}

enum DialTarget {
    PinnedPeer {
        handle: String,
        did: String,
        nickname: Option<String>,
        emoji: Option<String>,
        tier: String,
    },
    LocalSister {
        session_name: String,
        handle: String,
        did: Option<String>,
        nickname: Option<String>,
        emoji: Option<String>,
    },
}

/// Resolution order: pinned peers first (already in our trust ring),
/// then local sister sessions (on-disk discovery). Case-insensitive
/// match against handle, character nickname, session name, or DID.
fn resolve_name_to_target(name: &str) -> Result<DialTarget> {
    let needle = name.trim();
    if needle.is_empty() {
        bail!("empty name");
    }

    // 1. Pinned peers — `wire peers` data. trust.agents is an object
    // keyed by handle (not an array); iterate as a map.
    if config::is_initialized().unwrap_or(false) {
        let trust = config::read_trust().unwrap_or(serde_json::Value::Null);
        if let Some(agents) = trust.get("agents").and_then(Value::as_object) {
            for (handle_key, agent) in agents {
                let did = agent.get("did").and_then(Value::as_str).unwrap_or("");
                if did.is_empty() {
                    continue;
                }
                let handle = handle_key.clone();
                let character = crate::character::Character::from_did(did);
                let tier = agent
                    .get("tier")
                    .and_then(Value::as_str)
                    .unwrap_or("UNKNOWN")
                    .to_string();
                let matches = handle.eq_ignore_ascii_case(needle)
                    || did.eq_ignore_ascii_case(needle)
                    || character.nickname.eq_ignore_ascii_case(needle);
                if matches {
                    return Ok(DialTarget::PinnedPeer {
                        handle,
                        did: did.to_string(),
                        nickname: Some(character.nickname),
                        emoji: Some(character.emoji.to_string()),
                        tier,
                    });
                }
            }
        }
    }

    // 2. Local sister sessions.
    if let Some(session_name) = crate::session::resolve_local_sister(needle) {
        let sessions = crate::session::list_sessions().unwrap_or_default();
        let s = sessions.iter().find(|s| s.name == session_name);
        if let Some(s) = s {
            return Ok(DialTarget::LocalSister {
                session_name: s.name.clone(),
                handle: s.handle.clone().unwrap_or_else(|| s.name.clone()),
                did: s.did.clone(),
                nickname: s.character.as_ref().map(|c| c.nickname.clone()),
                emoji: s.character.as_ref().map(|c| c.emoji.to_string()),
            });
        }
    }

    // v0.9.2: fuzzy did-you-mean suggestion on resolution miss. Walks
    // the union of pinned-peer handles + character nicknames + sister
    // session names + sister character nicknames, returns up to 3 names
    // within Levenshtein distance 3 of the operator's typed name.
    let pool = known_local_names();
    let suggestions = closest_candidates(name, &pool, 3, 3);
    if suggestions.is_empty() {
        bail!(
            "no peer matched `{name}`.\n\
             Tried: pinned peers (`wire peers`) + local sister sessions \
             (`wire session list-local`).\n\
             For cross-machine federation: `wire dial <handle>@<relay-domain>`."
        );
    }
    bail!(
        "no peer matched `{name}`.\n\
         Did you mean: {}?\n\
         List all: `wire peers`, `wire session list-local`.",
        suggestions
            .iter()
            .map(|s| format!("`{s}`"))
            .collect::<Vec<_>>()
            .join(", ")
    );
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

/// Resolve a pinned peer's persona (the DID-derived nickname + emoji,
/// respecting an advertised override on their card). `None` if the peer
/// isn't in trust or can't be resolved — callers fall back to the handle.
fn resolve_persona(peer_handle: &str) -> Option<crate::character::Character> {
    let trust = config::read_trust().ok()?;
    let agent = trust.get("agents").and_then(|a| a.get(peer_handle))?;
    if let Some(card) = agent.get("card") {
        Some(crate::character::Character::from_card(card))
    } else {
        let did = agent.get("did").and_then(Value::as_str)?;
        Some(crate::character::Character::from_did(did))
    }
}

/// "emoji nickname" label for a peer, falling back to the raw handle.
fn persona_label(peer_handle: &str) -> String {
    match resolve_persona(peer_handle) {
        Some(ch) => format!("{} {}", ch.emoji, ch.nickname),
        None => peer_handle.to_string(),
    }
}

/// Render a single InboxEvent for `wire monitor` output. JSON form emits the
/// full structured event for tooling consumption; the plain form is a tight
/// one-line summary suitable as a harness stream-watcher notification.
///
/// Kept PURE (no trust I/O) so it stays deterministic and cheap per event.
/// Persona enrichment for `--json` belongs at InboxEvent construction in
/// `inbox_watch` (a follow-up), not here.
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
    if !inbox_dir.exists() && !as_json {
        eprintln!("wire monitor: inbox dir {inbox_dir:?} missing — has the daemon ever run?");
    }
    // Still proceed — InboxWatcher::from_dir_head handles missing dir.

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
            if let Some(filter) = peer_filter
                && peer != filter
            {
                continue;
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
                    &peer, signed, /* verified */ true,
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
        // Never die silently. wisp-blossom (Win10) saw `wire monitor` exit 1
        // with ZERO bytes on stdout+stderr when a cursor-block (untrusted
        // signer's pair event) tripped the watcher — a silent death looks
        // identical to "still watching" and breaks the sister-collab model.
        // Surface the reason and KEEP watching instead of propagating a fatal
        // `?` that some callers swallow.
        let events = match w.poll() {
            Ok(evs) => evs,
            Err(e) => {
                eprintln!("wire monitor: poll error (continuing to watch): {e:#}");
                std::thread::sleep(sleep_dur);
                continue;
            }
        };
        let mut wrote = false;
        for ev in events {
            if let Some(filter) = peer_filter
                && ev.peer != filter
            {
                continue;
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
        assert!(
            !line.contains("abcd1234567890ef"),
            "should truncate full id"
        );
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

fn cmd_relay_server(bind: &str, local_only: bool, uds: Option<&std::path::Path>) -> Result<()> {
    // v0.7.0-alpha.16: --uds <path> takes the UDS transport path,
    // overriding --bind. Implies --local-only semantics. Routed to a
    // separate serve_uds entry point with a manual hyper accept loop
    // (axum 0.7's `serve` is TcpListener-only).
    if let Some(socket_path) = uds {
        let base = if let Ok(home) = std::env::var("WIRE_HOME") {
            std::path::PathBuf::from(home)
                .join("state")
                .join("wire-relay")
                .join("uds")
        } else {
            dirs::state_dir()
                .or_else(dirs::data_local_dir)
                .ok_or_else(|| anyhow::anyhow!("could not resolve XDG_STATE_HOME — set WIRE_HOME"))?
                .join("wire-relay")
                .join("uds")
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return runtime.block_on(crate::relay_server::serve_uds(
            socket_path.to_path_buf(),
            base,
        ));
    }
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
/// resolves to something outside `127.0.0.0/8` or `::1`.
///
/// v0.7.0-alpha.11: relaxed to also accept RFC 1918 private IPv4
/// (10/8, 172.16/12, 192.168/16) so `wire relay-server --bind
/// <LAN-IP>:8772 --local-only` works for the alpha.9 LAN feature.
///
/// v0.7.0-alpha.15: also accept RFC 6598 CGNAT (100.64.0.0/10), which
/// is the IP range Tailscale uses for tailnet addresses. Lets operators
/// pair wire across machines using their tailnet IPs (e.g. Mac at
/// 100.96.234.16, Spark at 100.91.57.17) — Tailscale handles
/// auth + encryption + NAT traversal, wire handles protocol + identity.
/// Sidesteps host firewall config entirely (utun interface bypass).
///
/// Still refuses: public IPv4/IPv6, wildcards (0.0.0.0/::), link-local,
/// multicast, broadcast. Those would publish a "local-only" relay to
/// the global internet — the v0.5.17 security gate's whole point.
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
    use std::net::{IpAddr, ToSocketAddrs};
    let probe = format!("{host}:0");
    let resolved: Vec<_> = probe
        .to_socket_addrs()
        .with_context(|| format!("resolving bind host {host:?}"))?
        .collect();
    if resolved.is_empty() {
        bail!("--local-only: bind host {host:?} resolved to no addresses");
    }
    for addr in &resolved {
        let ip = addr.ip();
        let is_acceptable = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || {
                    // RFC 6598 CGNAT / Tailscale range: 100.64.0.0/10
                    let octets = v4.octets();
                    octets[0] == 100 && (64..=127).contains(&octets[1])
                }
            }
            IpAddr::V6(v6) => v6.is_loopback(), // ULA + Tailscale-v6 deferred
        };
        if !is_acceptable {
            bail!(
                "--local-only refuses non-private bind: {host:?} resolves to {} \
                 which is not loopback (127/8, ::1), RFC 1918 private \
                 (10/8, 172.16/12, 192.168/16), or RFC 6598 CGNAT/Tailscale \
                 (100.64.0.0/10). Remove --local-only to bind publicly.",
                ip
            );
        }
    }
    Ok(())
}

// ---------- bind-relay ----------

fn parse_scope(s: &str) -> Result<crate::endpoints::EndpointScope> {
    use crate::endpoints::EndpointScope;
    match s.to_lowercase().as_str() {
        "federation" | "fed" => Ok(EndpointScope::Federation),
        "local" => Ok(EndpointScope::Local),
        "lan" => Ok(EndpointScope::Lan),
        "uds" => Ok(EndpointScope::Uds),
        other => bail!("unknown --scope `{other}` (expected federation|local|lan|uds)"),
    }
}

/// v0.12: bind a relay slot. ADDITIVE by default — the new slot is
/// appended to `self.endpoints[]`, keeping any existing slots so an agent
/// can hold a local relay AND a federation relay simultaneously without
/// black-holing pinned peers. `--replace` restores the pre-v0.12
/// destructive single-slot behavior (guarded by issue #7).
fn cmd_bind_relay(
    url: &str,
    scope: Option<&str>,
    replace: bool,
    migrate_pinned: bool,
    as_json: bool,
) -> Result<()> {
    use crate::endpoints::{Endpoint, self_endpoints};

    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let card = config::read_agent_card()?;
    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = crate::agent_card::display_handle_from_did(did).to_string();

    let normalized_raw = url.trim_end_matches('/');
    // Refuse to record/publish a relay endpoint that embeds userinfo —
    // `https://<handle>@<host>` 4xxes every inbound event POST. Strip and
    // warn so operators learn the right shape without losing the call.
    let normalized_owned = strip_relay_url_userinfo(normalized_raw);
    let normalized = normalized_owned.as_str();
    // Belt-and-suspenders: confirm the post-strip URL is clean before any
    // persist / publish. A future code path that bypasses the strip filter
    // MUST NOT be able to leak userinfo into the signed agent-card.
    assert_relay_url_clean_for_publish(normalized)?;
    let new_scope = match scope {
        Some(s) => parse_scope(s)?,
        None => crate::endpoints::infer_scope_from_url(normalized),
    };

    let existing = config::read_relay_state().unwrap_or_else(|_| json!({}));
    let pinned: Vec<String> = existing
        .get("peers")
        .and_then(|p| p.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();

    let existing_eps = self_endpoints(&existing);
    let is_rebind_same = existing_eps.iter().any(|e| e.relay_url == normalized);

    // Destructive paths that black-hole pinned peers (issue #7):
    //   • `--replace` drops every other slot.
    //   • re-binding the SAME relay rotates that slot in place.
    // An additive bind of a NEW relay keeps existing slots, so peers stay
    // reachable — no acknowledgement required. This is the v0.12 default
    // that unblocks simultaneous local + remote.
    let destructive = replace || is_rebind_same;
    if destructive && !pinned.is_empty() && !migrate_pinned {
        let list = pinned.join(", ");
        let why = if replace {
            "`--replace` drops your other slot(s)"
        } else {
            "re-binding the same relay rotates its slot"
        };
        bail!(
            "bind-relay would black-hole {n} pinned peer(s): {list}. {why}; they are \
             pinned to your CURRENT slot and would keep pushing to a slot you no longer \
             read.\n\n\
             SAFE PATHS:\n\
             • Default (omit `--replace`) ADDITIVELY binds a NEW relay, keeping existing \
             slots — no black-hole.\n\
             • `wire rotate-slot` — same-relay rotation that emits wire_close to peers.\n\
             • `wire bind-relay {url} --migrate-pinned` — proceed anyway; re-pair each \
             peer out-of-band.\n\n\
             Issue #7 (silent black-hole on relay change) caught this.",
            n = pinned.len(),
        );
    }

    let client = crate::relay_client::RelayClient::new(normalized);
    client.check_healthz()?;
    let alloc = client.allocate_slot(Some(&handle))?;

    if destructive && !pinned.is_empty() {
        eprintln!(
            "wire bind-relay: {mode} with {n} pinned peer(s) — they will black-hole \
             until they re-pin: {peers}",
            mode = if replace { "replacing" } else { "rotating" },
            n = pinned.len(),
            peers = pinned.join(", "),
        );
    }

    // Write the new slot via the single source of truth for the self-slot
    // shape. Additive by default; --replace starts from an empty self so
    // only this slot remains.
    let mut state = existing;
    if replace {
        state["self"] = Value::Null;
    }
    crate::endpoints::upsert_self_endpoint(
        &mut state,
        Endpoint {
            relay_url: normalized.to_string(),
            slot_id: alloc.slot_id.clone(),
            slot_token: alloc.slot_token.clone(),
            scope: new_scope,
        },
    );
    config::write_relay_state(&state)?;
    let eps = self_endpoints(&state);

    let scope_str = format!("{new_scope:?}").to_lowercase();
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "relay_url": normalized,
                "slot_id": alloc.slot_id,
                "scope": scope_str,
                "endpoints": eps.len(),
                "additive": !replace,
                "slot_token_present": true,
            }))?
        );
    } else {
        println!(
            "bound {scope_str} slot on {normalized} (slot {})",
            alloc.slot_id
        );
        println!(
            "self now has {n} endpoint(s): {list}",
            n = eps.len(),
            list = eps
                .iter()
                .map(|e| format!("{}({:?})", e.relay_url, e.scope))
                .collect::<Vec<_>>()
                .join(", "),
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
    use crate::endpoints::{Endpoint, infer_scope_from_url, pin_peer_endpoints};
    let mut state = config::read_relay_state()?;

    // E3 (v0.13.2): ADD this slot to the peer's endpoint set — don't REPLACE
    // the whole entry. The old flat `peers.insert` clobbered an existing
    // peer's federation endpoint when pinning a local slot, silently dropping
    // the federation route (glossy-magnolia + wisp-blossom repro: pinning a
    // loopback slot made the peer flat loopback-only). Mirror bind-relay's
    // additive semantics: upsert by relay_url into the peer's endpoints[].
    let new_ep = Endpoint {
        relay_url: url.to_string(),
        slot_id: slot_id.to_string(),
        slot_token: slot_token.to_string(),
        scope: infer_scope_from_url(url),
    };
    let mut endpoints: Vec<Endpoint> = state
        .get("peers")
        .and_then(|p| p.get(handle))
        .and_then(|e| e.get("endpoints"))
        .and_then(|a| serde_json::from_value::<Vec<Endpoint>>(a.clone()).ok())
        .unwrap_or_default();
    // Back-compat: seed from legacy flat fields when the peer predates endpoints[].
    if endpoints.is_empty()
        && let Some(peer) = state.get("peers").and_then(|p| p.get(handle))
        && let (Some(ru), Some(si), Some(st)) = (
            peer.get("relay_url").and_then(Value::as_str),
            peer.get("slot_id").and_then(Value::as_str),
            peer.get("slot_token").and_then(Value::as_str),
        )
    {
        endpoints.push(Endpoint {
            relay_url: ru.to_string(),
            slot_id: si.to_string(),
            slot_token: st.to_string(),
            scope: infer_scope_from_url(ru),
        });
    }
    // Upsert by relay_url: refresh in place if already pinned, else append.
    if let Some(existing) = endpoints
        .iter_mut()
        .find(|e| e.relay_url == new_ep.relay_url)
    {
        *existing = new_ep;
    } else {
        endpoints.push(new_ep);
    }
    let n = endpoints.len();
    pin_peer_endpoints(&mut state, handle, &endpoints)?;
    config::write_relay_state(&state)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle,
                "relay_url": url,
                "slot_id": slot_id,
                "added": true,
                "endpoint_count": n,
            }))?
        );
    } else {
        println!(
            "pinned peer slot for {handle} at {url} ({slot_id}) — peer now has {n} endpoint(s)"
        );
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
            for line in std::fs::read_to_string(&outbox).unwrap_or_default().lines() {
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
                        last_err_reason = Some(crate::relay_client::format_transport_error(&e));
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
        crate::endpoints::EndpointScope::Lan => "last_pulled_event_id_lan".to_string(),
        crate::endpoints::EndpointScope::Uds => "last_pulled_event_id_uds".to_string(),
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
    // v0.9: route through self_primary_endpoint so v0.5.17+ sessions
    // (which write only self.endpoints[]) can rotate. Pre-v0.9 read
    // top-level legacy fields directly and bailed for those sessions.
    let primary = crate::endpoints::self_primary_endpoint(&state)
        .ok_or_else(|| anyhow!("self has no resolvable inbound endpoint to rotate"))?;
    let url = primary.relay_url.clone();
    let old_slot_id = primary.slot_id.clone();
    let old_slot_token = primary.slot_token.clone();

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
        //
        // v0.13.2 (wisp-blossom): if the stream subscriber thread has gone
        // away, `wake_rx` is Disconnected and `recv_timeout` returns
        // INSTANTLY — which would busy-spin the sync loop (hammering push/pull
        // + the relay with zero delay). Fall back to a plain sleep so a dead
        // stream degrades to normal polling and never kills or pegs the
        // daemon. (Realizes the "decouple stream from sync" hardening — a
        // stream failure must never affect the push/pull loop.)
        match wake_rx.recv_timeout(interval) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(interval);
            }
        }
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
                    skipped
                        .push(json!({"peer": peer_handle, "event_id": event_id, "reason": reason}));
                }
            }
        }
    }
    Ok(json!({"pushed": pushed, "skipped": skipped}))
}

/// Programmatic pull. Same shape as `wire pull --json`.
///
/// v0.9: routes through `endpoints::self_primary_endpoint` so sessions
/// created via `wire session new --with-local` (which only writes
/// `self.endpoints[]`, not the legacy top-level fields) actually pull.
/// Pre-v0.9 this function read only the top-level fields and silently
/// returned `{}` for any v0.5.17+ session.
fn run_sync_pull() -> Result<Value> {
    let state = config::read_relay_state()?;
    if state.get("self").map(Value::is_null).unwrap_or(true) {
        return Ok(json!({"written": [], "rejected": [], "total_seen": 0}));
    }
    // E2 (v0.13.2): pull EVERY self endpoint, not just the primary. A session
    // that bound a local slot (additive) alongside its federation slot used to
    // have the daemon pull ONLY the primary (federation) endpoint — the local
    // slot was never serviced, so same-box loopback delivery silently never
    // happened until a manual restart re-seeded the (startup-only) stream
    // subscriber. Now each endpoint is pulled with its OWN cursor.
    let endpoints = crate::endpoints::self_endpoints(&state);
    if endpoints.is_empty() {
        return Ok(json!({"written": [], "rejected": [], "total_seen": 0}));
    }
    let inbox_dir = config::inbox_dir()?;
    config::ensure_dirs()?;

    // Per-slot cursors live at `self.cursors.<slot_id>`. The legacy global
    // `self.last_pulled_event_id` is migrated as the cursor for the PRIMARY
    // slot only (a federation event id won't match a local slot's log); other
    // slots start from None and `process_events` dedups against the inbox.
    let self_obj = state.get("self").cloned().unwrap_or(Value::Null);
    let legacy_cursor = self_obj
        .get("last_pulled_event_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let primary_slot = crate::endpoints::self_primary_endpoint(&state).map(|e| e.slot_id);
    let mut cursors: serde_json::Map<String, Value> = self_obj
        .get("cursors")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let mut all_written: Vec<Value> = Vec::new();
    let mut all_rejected: Vec<Value> = Vec::new();
    let mut total_seen = 0usize;
    let mut blocked_any = false;

    for ep in &endpoints {
        if ep.relay_url.is_empty() {
            continue;
        }
        let cursor = cursors
            .get(&ep.slot_id)
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                if Some(&ep.slot_id) == primary_slot.as_ref() {
                    legacy_cursor.clone()
                } else {
                    None
                }
            });
        let client = crate::relay_client::RelayClient::new(&ep.relay_url);
        // One endpoint erroring (relay down, slot gone) must NOT stop the
        // others — a dead local relay shouldn't black-hole federation pulls.
        let events =
            match client.list_events(&ep.slot_id, &ep.slot_token, cursor.as_deref(), Some(1000)) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "daemon: pull error on {} slot {} (continuing): {e:#}",
                        ep.relay_url, ep.slot_id
                    );
                    continue;
                }
            };
        total_seen += events.len();
        // P0.1 shared cursor-blocking logic (matches `wire pull`). A block on
        // one slot only stalls THAT slot's cursor; other slots keep flowing.
        let result = crate::pull::process_events(&events, cursor, &inbox_dir)?;
        if let Some(eid) = &result.advance_cursor_to {
            cursors.insert(ep.slot_id.clone(), Value::String(eid.clone()));
        }
        blocked_any |= result.blocked;
        all_written.extend(result.written);
        all_rejected.extend(result.rejected);
    }

    // P0.3 flock-protected RMW: persist per-slot cursors + keep the legacy
    // global cursor in sync with the primary slot for back-compat with older
    // binaries that only read `last_pulled_event_id`.
    let primary_cursor = primary_slot
        .as_ref()
        .and_then(|s| cursors.get(s))
        .and_then(Value::as_str)
        .map(str::to_string);
    config::update_relay_state(|state| {
        if let Some(self_obj) = state.get_mut("self").and_then(Value::as_object_mut) {
            self_obj.insert("cursors".into(), Value::Object(cursors.clone()));
            if let Some(pc) = &primary_cursor {
                self_obj.insert("last_pulled_event_id".into(), Value::String(pc.clone()));
            }
        }
        Ok(())
    })?;

    Ok(json!({
        "written": all_written,
        "rejected": all_rejected,
        "total_seen": total_seen,
        "cursor_blocked": blocked_any,
        "endpoints_pulled": endpoints.len(),
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
/// Extract just the host portion from `https://host:port/path` → `host`.
/// Returns empty string if the URL is malformed.
fn host_of_url(url: &str) -> String {
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

/// v0.5.19 (#9.4): is this relay domain on the known-good list, or the
/// operator's own relay? Used to suppress the cross-relay phishing
/// warning in `wire add` for the happy path.
fn is_known_relay_domain(peer_domain: &str, our_relay_url: &str) -> bool {
    // Hard-coded known-good list. wireup.net is the default relay.
    const KNOWN_GOOD: &[&str] = &["wireup.net", "wire.laulpogan.com"];
    let peer_domain = peer_domain.trim().to_ascii_lowercase();
    if KNOWN_GOOD.iter().any(|k| *k == peer_domain) {
        return true;
    }
    // Operator's OWN relay is implicitly trusted — they're already
    // bound to it; pairing same-relay peers is the common case.
    let our_host = host_of_url(our_relay_url).to_ascii_lowercase();
    if !our_host.is_empty() && our_host == peer_domain {
        return true;
    }
    false
}

/// v0.6.6: pair with a sister session on this machine without federation.
/// Reads the sister's agent-card + endpoints from disk, pins them into our
/// trust + relay_state, builds the same `pair_drop` event the federation
/// path would emit, then POSTs it directly to the sister's local-relay slot.
/// No `.well-known/wire/agent` resolution. Reserved-nick sessions (like
/// the cwd-derived `wire`) are addressable because the local relay never
/// needed a public claim for sister coordination.
/// v0.7.0-alpha.2/3: resolve an input (session name or character nickname)
/// to a local sister session.
///
/// `wire add --local-sister <name-or-nickname>` and adjacent commands take
/// either form. Exact session-name matches always win; nickname matches
/// are a fallback so operators can type "winter-bay" instead of "wire".
/// When a nickname is ambiguous (two sessions share it, e.g. auto-derived
/// for one + override on another), returns `Err(ResolveError::Ambiguous)`
/// with the candidate list so the caller can surface a disambiguation
/// hint instead of silently picking one.
fn resolve_local_session<'a>(
    sessions: &'a [crate::session::SessionInfo],
    input: &str,
) -> Result<&'a crate::session::SessionInfo, ResolveError> {
    // Exact session-name match always wins, even if a nickname elsewhere
    // also matches. Predictable for scripts and operator muscle memory.
    if let Some(s) = sessions.iter().find(|s| s.name == input) {
        return Ok(s);
    }
    let nick_matches: Vec<&crate::session::SessionInfo> = sessions
        .iter()
        .filter(|s| {
            s.character
                .as_ref()
                .map(|c| c.nickname == input)
                .unwrap_or(false)
        })
        .collect();
    match nick_matches.len() {
        0 => Err(ResolveError::NotFound),
        1 => Ok(nick_matches[0]),
        _ => Err(ResolveError::Ambiguous(
            nick_matches.iter().map(|s| s.name.clone()).collect(),
        )),
    }
}

#[derive(Debug)]
enum ResolveError {
    NotFound,
    Ambiguous(Vec<String>),
}

/// v0.7.0-alpha.2/.5: resolve a peer input (handle or character nickname)
/// to a pinned peer's canonical handle.
///
/// `wire send <peer>` accepts either the handle the peer registered with
/// or their character nickname (DID-hash-derived). Exact handle match
/// always wins. When a nickname matches multiple peers (theoretically
/// possible via DID-hash collision in the (adj, noun) space), returns
/// `Ambiguous` so the caller can surface a disambiguation hint instead
/// of silently picking one.
///
/// Only AUTO-DERIVED peer characters are matchable; operator-chosen
/// overrides on the peer's side live in their local `display.json` and
/// aren't yet published via agent-card. (That's the v0.7+ federation
/// lifecycle work — peers publishing overrides so we resolve by what
/// they call themselves, not just what their DID hashes to.)
fn resolve_peer_handle(input: &str) -> Result<Option<String>, ResolveError> {
    let trust = match config::read_trust() {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let agents = match trust.get("agents").and_then(|a| a.as_object()) {
        Some(a) => a,
        None => return Ok(None),
    };
    if agents.contains_key(input) {
        return Ok(Some(input.to_string()));
    }
    let mut nick_matches: Vec<String> = Vec::new();
    for (handle, agent) in agents.iter() {
        // v0.7.0-alpha.6: prefer peer's published display nickname over
        // auto-derived. Allows `wire send <their-chosen-name>` not just
        // `wire send <their-did-hash-derived-name>`.
        let character = match agent.get("card") {
            Some(card) => crate::character::Character::from_card(card),
            None => match agent.get("did").and_then(Value::as_str) {
                Some(did) => crate::character::Character::from_did(did),
                None => continue,
            },
        };
        if character.nickname == input {
            nick_matches.push(handle.clone());
        }
    }
    match nick_matches.len() {
        0 => Ok(None),
        1 => Ok(Some(nick_matches.into_iter().next().unwrap())),
        _ => Err(ResolveError::Ambiguous(nick_matches)),
    }
}

fn cmd_add_local_sister(sister_name: &str, as_json: bool) -> Result<()> {
    // 1. Locate sister session by name OR character nickname.
    let sessions = crate::session::list_sessions()?;
    let sister = match resolve_local_session(&sessions, sister_name) {
        Ok(s) => s,
        Err(ResolveError::NotFound) => bail!(
            "no sister session named `{sister_name}` (matched by session name or character nickname). \
             Run `wire session list` to see what's available."
        ),
        Err(ResolveError::Ambiguous(candidates)) => bail!(
            "nickname `{sister_name}` is ambiguous — matches {} sessions: {}. \
             Disambiguate by passing the session name (one of those listed) instead of the nickname.",
            candidates.len(),
            candidates.join(", ")
        ),
    };
    // If we matched via nickname (not exact name), surface that so the
    // operator sees what we resolved to. Quiet when names match exactly.
    if sister.name != sister_name {
        eprintln!(
            "wire add: resolved nickname `{sister_name}` → session `{}`",
            sister.name
        );
    }

    // 2. Refuse self-pair — operator owns both sides, but a self-loop
    // breaks the bilateral state machine.
    let our_card = config::read_agent_card()
        .map_err(|_| anyhow!("not initialized — run `wire init <handle>` first"))?;
    let our_did = our_card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing did"))?
        .to_string();
    if let Some(sister_did) = sister.did.as_deref()
        && sister_did == our_did
    {
        bail!("refusing to add self (`{sister_name}` is this very session)");
    }

    // 3. Read sister's agent-card + relay state from disk.
    let sister_card_path = sister
        .home_dir
        .join("config")
        .join("wire")
        .join("agent-card.json");
    let sister_card: Value = serde_json::from_slice(
        &std::fs::read(&sister_card_path)
            .with_context(|| format!("reading sister card {sister_card_path:?}"))?,
    )
    .with_context(|| format!("parsing sister card {sister_card_path:?}"))?;
    let sister_relay_state: Value = std::fs::read(
        sister
            .home_dir
            .join("config")
            .join("wire")
            .join("relay.json"),
    )
    .ok()
    .and_then(|b| serde_json::from_slice(&b).ok())
    .unwrap_or_else(|| json!({"self": Value::Null, "peers": {}}));

    let sister_did = sister_card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("sister card missing did"))?
        .to_string();
    let sister_handle = crate::agent_card::display_handle_from_did(&sister_did).to_string();

    // Pull sister's full endpoint set; we want the local one for delivery
    // and we'll pin all of them so OUR pushes prefer local-first per the
    // existing routing logic.
    let sister_endpoints = crate::endpoints::self_endpoints(&sister_relay_state);
    if sister_endpoints.is_empty() {
        bail!(
            "sister `{sister_name}` has no endpoints in its relay.json — recreate with `wire session new --local-only` or `--with-local`"
        );
    }
    let sister_local = sister_endpoints
        .iter()
        .find(|e| e.scope == crate::endpoints::EndpointScope::Local);
    let delivery_endpoint = match sister_local {
        Some(e) => e.clone(),
        None => sister_endpoints[0].clone(),
    };

    // 4. Ensure WE have a slot to advertise back. For local-only sessions
    // this is the local slot; for dual-slot sessions, federation is fine.
    // `ensure_self_with_relay(None)` defaults to wireup.net which is wrong
    // for pure local-only — instead, pick our own existing federation
    // endpoint if present, else fall back to whatever's first.
    let our_relay_state = config::read_relay_state()?;
    let our_endpoints = crate::endpoints::self_endpoints(&our_relay_state);
    if our_endpoints.is_empty() {
        bail!(
            "this session has no endpoints — run `wire session new --local-only` or `wire bind-relay` first"
        );
    }
    let our_advertised = our_endpoints
        .iter()
        .find(|e| e.scope == crate::endpoints::EndpointScope::Federation)
        .cloned()
        .unwrap_or_else(|| our_endpoints[0].clone());

    // 5. Pin sister into our trust (VERIFIED — operator-owned siblings) +
    // relay_state.peers with their full endpoint set. slot_token lands
    // via pair_drop_ack as usual.
    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &sister_card, Some("VERIFIED"));
    config::write_trust(&trust)?;
    let mut relay_state = config::read_relay_state()?;
    crate::endpoints::pin_peer_endpoints(&mut relay_state, &sister_handle, &sister_endpoints)?;
    config::write_relay_state(&relay_state)?;

    // 6. Build the same pair_drop event the federation path emits, with
    // our card + endpoints in the body so the sister can pin us back.
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
    let mut body = json!({
        "card": our_card,
        "relay_url": our_advertised.relay_url,
        "slot_id": our_advertised.slot_id,
        "slot_token": our_advertised.slot_token,
    });
    body["endpoints"] = serde_json::to_value(&our_endpoints).unwrap_or(json!([]));
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now,
        "from": our_did,
        "to": sister_did,
        "type": "pair_drop",
        "kind": 1100u32,
        "body": body,
    });
    let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &our_handle)?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    // 7. Deliver direct to sister's local slot. Skip /v1/handle/intro
    // (the federation handle indexer) — we already know the slot coords
    // from disk, so post_event is sufficient.
    let client = crate::relay_client::RelayClient::new(&delivery_endpoint.relay_url);
    client
        .post_event(
            &delivery_endpoint.slot_id,
            &delivery_endpoint.slot_token,
            &signed,
        )
        .with_context(|| format!("delivering pair_drop to `{sister_name}`'s local slot"))?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": sister_name,
                "paired_with": sister_did,
                "peer_handle": sister_handle,
                "event_id": event_id,
                "delivered_via": match delivery_endpoint.scope {
                    crate::endpoints::EndpointScope::Local => "local",
                    crate::endpoints::EndpointScope::Lan => "lan",
                    crate::endpoints::EndpointScope::Uds => "uds",
                    crate::endpoints::EndpointScope::Federation => "federation",
                },
                "status": "drop_sent",
            }))?
        );
    } else {
        let scope = match delivery_endpoint.scope {
            crate::endpoints::EndpointScope::Local => "local",
            crate::endpoints::EndpointScope::Lan => "lan",
            crate::endpoints::EndpointScope::Uds => "uds",
            crate::endpoints::EndpointScope::Federation => "federation",
        };
        println!(
            "→ found sister `{sister_name}` (did={sister_did})\n→ pinned peer locally\n→ pair_drop delivered to {scope} slot on {}\nawaiting pair_drop_ack from {sister_handle} to complete bilateral pin.",
            delivery_endpoint.relay_url
        );
    }
    Ok(())
}

fn cmd_add(
    handle_arg: &str,
    relay_override: Option<&str>,
    local_sister: bool,
    as_json: bool,
) -> Result<()> {
    // v0.7.4: nickname-friendly local-sister resolution. Whether the
    // operator passed `--local-sister` explicitly OR just typed a bare
    // name (no `@<relay>`), try to resolve through the local sessions
    // registry so character nicknames AND session names AND card
    // handles all work as input. Closes the "I only know this peer by
    // its character name" ergonomic gap that forced operators into
    // `wire session list-local | grep <nick> | awk` dances.
    if local_sister {
        let resolved = crate::session::resolve_local_sister(handle_arg)
            .unwrap_or_else(|| handle_arg.to_string());
        return cmd_add_local_sister(&resolved, as_json);
    }
    if !handle_arg.contains('@')
        && let Some(resolved) = crate::session::resolve_local_sister(handle_arg)
    {
        eprintln!(
            "wire add: `{handle_arg}` resolved to local sister session `{resolved}` \
             — routing via --local-sister (disk-read card, no relay lookup)."
        );
        return cmd_add_local_sister(&resolved, as_json);
    }
    if !handle_arg.contains('@') {
        bail!(
            "`{handle_arg}` doesn't match any local sister session and has no \
             @<relay> suffix for federation.\n\
             — Local sisters: `wire session list-local` (operator types name OR \
             character nickname)\n\
             — Federation:    `wire add <handle>@<relay-domain>` (e.g. \
             `wire add alice@wireup.net`)"
        );
    }
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

    // v0.5.19 (#9.4): cross-relay phishing guardrail.
    //
    // Threat: operator wants to add `boss@wireup.net` but types
    // `boss@evil-relay.example` (typo, malicious link, look-alike domain).
    // The .well-known resolution returns whoever claimed the nick on the
    // *typo* relay, the bilateral gate still completes (the attacker
    // accepts the pair on their side), and the operator pins the
    // attacker as "boss". v0.5.14 bilateral gate doesn't catch this —
    // there's no asymmetry to detect when the attacker WANTS to be
    // paired.
    //
    // Mitigation: warn loudly when the peer's relay domain is novel
    // (not the operator's own relay, not in a small known-good set).
    // Doesn't block — operators have legitimate reasons to pair across
    // relays. The signal lands in shell history so a phished operator
    // can find it in retrospect.
    if !is_known_relay_domain(&parsed.domain, &our_relay) {
        eprintln!(
            "wire add: WARN unfamiliar relay domain `{}`.",
            parsed.domain
        );
        eprintln!(
            "  This is NOT `wireup.net` (the default), NOT your own relay (`{}`), ",
            host_of_url(&our_relay)
        );
        eprintln!(
            "  and not on the known-good list. If you meant `{}@wireup.net`, ",
            parsed.nick
        );
        eprintln!(
            "  run `wire add {}@wireup.net` instead. Otherwise verify with your",
            parsed.nick
        );
        eprintln!("  peer out-of-band that they actually run a relay at this domain");
        eprintln!("  before relying on the pair. (See issue #9.4.)");
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
    // Additive re-pin (v0.13.2, E3 token-bleed fix). The old code REPLACED the
    // whole peer entry with a flat federation-only one, seeding the token from
    // the entry's TOP-LEVEL `slot_token`. Two bugs (glossy-magnolia repro):
    //   1. re-dialing a peer that had a local endpoint (from add-peer-slot)
    //      CLOBBERED that local endpoint.
    //   2. after a local add-peer-slot the top-level token was the LOCAL token,
    //      so the federation endpoint inherited a stale LOCAL bearer →
    //      federation delivery would 401.
    // Fix: merge the federation endpoint into the peer's endpoints[] (preserve
    // the local one), and seed its token ONLY from a prior FEDERATION endpoint
    // on the same relay (re-dialing an already-acked peer), never a local one —
    // empty until the pair_drop_ack lands otherwise.
    let mut endpoints: Vec<crate::endpoints::Endpoint> = relay_state
        .get("peers")
        .and_then(|p| p.get(&peer_handle))
        .and_then(|e| e.get("endpoints"))
        .and_then(|a| serde_json::from_value::<Vec<crate::endpoints::Endpoint>>(a.clone()).ok())
        .unwrap_or_default();
    let fed_token = endpoints
        .iter()
        .find(|e| {
            e.relay_url == peer_relay && e.scope == crate::endpoints::EndpointScope::Federation
        })
        .map(|e| e.slot_token.clone())
        .unwrap_or_default();
    let fed_ep = crate::endpoints::Endpoint {
        relay_url: peer_relay.clone(),
        slot_id: peer_slot_id.clone(),
        slot_token: fed_token, // empty until pair_drop_ack lands
        scope: crate::endpoints::EndpointScope::Federation,
    };
    if let Some(existing) = endpoints
        .iter_mut()
        .find(|e| e.relay_url == fed_ep.relay_url)
    {
        *existing = fed_ep;
    } else {
        endpoints.push(fed_ep);
    }
    crate::endpoints::pin_peer_endpoints(&mut relay_state, &peer_handle, &endpoints)?;
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
        println!("no pending pair requests — your inbox is clear.");
        return Ok(());
    }
    // v0.9.3: conversational output. Tabular data is for --json. Humans
    // get one short sentence per pending peer, each rendered with the
    // peer's character (DID-derived emoji + nickname) so they can match
    // the speaker against their statusline / mesh-status view at a
    // glance. The "next step" sentence at the bottom names the exact
    // verbs to run.
    let plural = if items.len() == 1 { "" } else { "s" };
    println!("{} pending pair request{plural}:\n", items.len());
    for p in &items {
        let ch = crate::character::Character::from_did(&p.peer_did);
        let glyph = crate::character::emoji_with_fallback(&ch);
        // ASCII-friendly arrow if the operator's terminal can't render
        // emoji (the same routine drives the fallback).
        println!(
            "  {glyph} {nick}  ({handle})  wants to pair with you",
            nick = ch.nickname,
            handle = p.peer_handle,
        );
    }
    println!();
    println!(
        "→ to accept any: `wire accept <name>`  (e.g. `wire accept {first}`)",
        first = items
            .first()
            .map(|p| {
                let ch = crate::character::Character::from_did(&p.peer_did);
                ch.nickname
            })
            .unwrap_or_else(|| "<name>".to_string())
    );
    println!("→ to refuse:    `wire reject <name>`");
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
        println!(
            "→ rejected pending pair from {nick}\n→ pending-inbound record deleted; no ack sent."
        );
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

// ---------- group chat (v0.13.3) ----------

fn cmd_group(cmd: GroupCommand) -> Result<()> {
    match cmd {
        GroupCommand::Create { name, json } => cmd_group_create(&name, json),
        GroupCommand::Add { group, peer, json } => cmd_group_add(&group, &peer, json),
        GroupCommand::Send {
            group,
            message,
            json,
        } => cmd_group_send(&group, &message, json),
        GroupCommand::Tail { group, limit, json } => cmd_group_tail(&group, limit, json),
        GroupCommand::List { json } => cmd_group_list(json),
        GroupCommand::Invite { group, json } => cmd_group_invite(&group, json),
        GroupCommand::Join { code, json } => cmd_group_join(&code, json),
    }
}

/// This agent's (did, handle) from its signed card.
/// This agent's signing identity for group ops: (did, handle, key_id, pk_b64).
fn group_self() -> Result<(String, String, String, String)> {
    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing did — run `wire up` first"))?
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
    let key_id = make_key_id(&handle, &pk_bytes);
    Ok((did, handle, key_id, pk_b64))
}

/// Relay to host a group room on — prefer the federation endpoint (remote
/// members can reach it), fall back to LAN, then local, then any.
fn group_room_relay_url() -> Result<String> {
    use crate::endpoints::EndpointScope;
    let state = config::read_relay_state()?;
    let eps = crate::endpoints::self_endpoints(&state);
    let pick = eps
        .iter()
        .find(|e| e.scope == EndpointScope::Federation)
        .or_else(|| eps.iter().find(|e| e.scope == EndpointScope::Lan))
        .or_else(|| eps.iter().find(|e| e.scope == EndpointScope::Local))
        .or_else(|| eps.first());
    match pick {
        Some(e) if !e.relay_url.is_empty() => Ok(e.relay_url.clone()),
        _ => bail!("no relay endpoint on this identity — run `wire up --relay <url>` first"),
    }
}

/// Sign a `group_invite` (carrying the full creator-signed Group) and queue it
/// to every other member's outbox. The daemon/push delivers; the recipient's
/// `ingest_group_invites` materializes the room + introduce-pins members.
fn distribute_group_invite(group: &crate::group::Group, self_did: &str) -> Result<usize> {
    let (_, self_handle, _, pk_b64) = group_self()?;
    let sk_seed = config::read_private_key()?;
    let pk_bytes = crate::signing::b64decode(&pk_b64)?;
    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let group_json = serde_json::to_value(group)?;
    let mut delivered = 0usize;
    for handle in group.other_member_handles(self_did) {
        let event = json!({
            "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
            "timestamp": now_iso,
            "from": self_did,
            "to": format!("did:wire:{handle}"),
            "type": "group_invite",
            "kind": parse_kind("group_invite")?,
            "body": group_json,
        });
        let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &self_handle)
            .map_err(|e| anyhow!("signing group_invite for `{handle}`: {e:?}"))?;
        let line = serde_json::to_vec(&signed)?;
        if config::append_outbox_record(&handle, &line).is_ok() {
            delivered += 1;
        }
    }
    Ok(delivered)
}

/// Introduce-pin a member's key on the creator's vouch: ensure
/// `trust.agents[handle]` carries this key so the member's group messages
/// verify, WITHOUT granting bilateral trust. Never lowers an existing tier
/// (a directly-VERIFIED peer stays VERIFIED); only adds the key if missing.
/// Returns `true` iff it actually changed `trust` (new entry or added key) —
/// callers use this to decide whether to persist.
fn introduce_pin(
    trust: &mut Value,
    handle: &str,
    did: &str,
    key_id: &str,
    key: &str,
    group_id: &str,
) -> bool {
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let agents = trust
        .as_object_mut()
        .expect("trust is an object")
        .entry("agents")
        .or_insert_with(|| json!({}));
    let key_rec = json!({"key_id": key_id, "key": key, "added_at": now, "active": true});
    match agents.get_mut(handle) {
        Some(existing) => {
            // Already pinned (maybe at a higher bilateral tier) — just ensure
            // the key is present. Do NOT touch the tier.
            let keys = existing
                .as_object_mut()
                .and_then(|o| o.get_mut("public_keys"))
                .and_then(Value::as_array_mut);
            if let Some(keys) = keys {
                let have = keys
                    .iter()
                    .any(|k| k.get("key_id").and_then(Value::as_str) == Some(key_id));
                if !have {
                    keys.push(key_rec);
                    return true;
                }
            }
            false
        }
        None => {
            // First sight — pin at bilateral UNTRUSTED (disjoint from GroupTier).
            agents[handle] = json!({
                "tier": "UNTRUSTED",
                "did": did,
                "public_keys": [key_rec],
                "introduced_via": group_id,
                "pinned_at": now,
            });
            true
        }
    }
}

/// Scan the inbox for `group_invite` events from pinned creators, verify them
/// (event signature + roster `creator_sig`), materialize/refresh the local
/// group at its highest epoch, and introduce-pin every other member. Lazy:
/// runs at the top of group send/tail/list so a member just-pulled an invite
/// is immediately usable. Skips groups this agent created.
fn ingest_group_invites() -> Result<()> {
    let inbox = config::inbox_dir()?;
    if !inbox.exists() {
        return Ok(());
    }
    let (self_did, ..) = group_self()?;
    let trust_now = config::read_trust().unwrap_or_else(|_| json!({"agents": {}}));
    // group_id -> highest-epoch verified roster seen in the inbox.
    let mut best: std::collections::HashMap<String, crate::group::Group> =
        std::collections::HashMap::new();

    for entry in std::fs::read_dir(&inbox)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        for line in std::fs::read_to_string(&path).unwrap_or_default().lines() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if event.get("type").and_then(Value::as_str) != Some("group_invite") {
                continue;
            }
            // Event-level: the invite must be from a pinned peer (the creator)
            // with a valid signature.
            if verify_message_v31(&event, &trust_now).is_err() {
                continue;
            }
            let Some(body) = event.get("body") else {
                continue;
            };
            let group: crate::group::Group = match serde_json::from_value(body.clone()) {
                Ok(g) => g,
                Err(_) => continue,
            };
            if group.creator_did == self_did {
                continue; // never overwrite a group I created
            }
            // The invite's sender must be the group's creator.
            let from_did = event.get("from").and_then(Value::as_str).unwrap_or("");
            if from_did != group.creator_did {
                continue;
            }
            // Roster integrity: creator_sig must verify against the creator's
            // independently-pinned key (we paired with the creator → have it).
            let creator_handle = crate::agent_card::display_handle_from_did(&group.creator_did);
            let creator_key = trust_now
                .get("agents")
                .and_then(|a| a.get(creator_handle))
                .and_then(|a| a.get("public_keys"))
                .and_then(Value::as_array)
                .and_then(|ks| ks.first())
                .and_then(|k| k.get("key"))
                .and_then(Value::as_str)
                .and_then(|b| crate::signing::b64decode(b).ok());
            let Some(creator_key) = creator_key else {
                continue;
            };
            if !group.verify(&creator_key) {
                continue;
            }
            match best.get(&group.id) {
                Some(prev) if prev.epoch >= group.epoch => {}
                _ => {
                    best.insert(group.id.clone(), group);
                }
            }
        }
    }

    if best.is_empty() {
        return Ok(());
    }
    let mut trust = config::read_trust()?;
    for group in best.values() {
        // Don't regress a locally-known group to a stale epoch.
        if let Ok(local) = crate::group::load_group(&group.id)
            && local.epoch >= group.epoch
        {
            continue;
        }
        crate::group::save_group(group)?;
        for m in &group.members {
            if m.did == self_did || m.key.is_empty() {
                continue;
            }
            introduce_pin(&mut trust, &m.handle, &m.did, &m.key_id, &m.key, &group.id);
        }
    }
    config::write_trust(&trust)?;
    Ok(())
}

fn cmd_group_create(name: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    let (did, handle, key_id, pk_b64) = group_self()?;
    let relay_url = group_room_relay_url()?;
    // Allocate the shared group-room slot on the relay.
    let client = crate::relay_client::RelayClient::new(&relay_url);
    let room = client
        .allocate_slot(Some(&format!("group:{name}")))
        .with_context(|| format!("allocating group room on {relay_url}"))?;
    let id = format!("g{:016x}", rand::random::<u64>());
    let mut group = crate::group::Group::new(id.clone(), name.to_string(), handle, did.clone());
    group.set_room(relay_url, room.slot_id, room.slot_token);
    group.set_member_keys(&did, key_id, pk_b64)?;
    let sk = config::read_private_key()?;
    group.sign(&sk)?;
    crate::group::save_group(&group)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "id": id, "name": name, "members": 1, "relay_url": group.relay_url
            }))?
        );
    } else {
        println!(
            "created group `{name}` (id {id}) — room on {}. You are the creator.",
            group.relay_url
        );
        println!("  add peers: `wire group add {id} <peer>`   talk: `wire group send {id} \"hi\"`");
    }
    Ok(())
}

fn cmd_group_add(group_ref: &str, peer: &str, as_json: bool) -> Result<()> {
    let (self_did, ..) = group_self()?;
    let mut group = crate::group::resolve_group(group_ref)?;
    if group.creator_did != self_did {
        bail!("only the group creator can add members (the creator signs the roster)");
    }
    // T22 consent: a Member must be a peer you bilaterally VERIFIED.
    let bare = crate::agent_card::bare_handle(peer).to_string();
    let trust = config::read_trust()?;
    let agent = trust
        .get("agents")
        .and_then(|a| a.get(&bare))
        .ok_or_else(|| {
            anyhow!("`{bare}` is not a pinned peer — pair first (`wire dial {bare}@<relay>`)")
        })?;
    let tier = agent
        .get("tier")
        .and_then(Value::as_str)
        .unwrap_or("UNTRUSTED");
    if tier != "VERIFIED" {
        bail!(
            "`{bare}` is {tier}, not VERIFIED — only verified peers can be added as Members (T22 consent)"
        );
    }
    let peer_did = agent
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("trust entry for `{bare}` is missing a did"))?
        .to_string();
    // Capture the peer's signing key from trust so the creator can vouch for it
    // in the signed roster (members introduce-pin it to verify this peer).
    let key = agent
        .get("public_keys")
        .and_then(Value::as_array)
        .and_then(|ks| {
            ks.iter()
                .find(|k| k.get("active").and_then(Value::as_bool).unwrap_or(true))
        })
        .ok_or_else(|| anyhow!("no active pinned key for `{bare}` in trust"))?;
    let peer_key_id = key
        .get("key_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let peer_pk = key
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    group.add_member(
        bare.clone(),
        peer_did.clone(),
        crate::group::GroupTier::Member,
    )?;
    group.set_member_keys(&peer_did, peer_key_id, peer_pk)?;
    let sk = config::read_private_key()?;
    group.sign(&sk)?;
    crate::group::save_group(&group)?;
    // Distribute the refreshed signed roster (room coords + everyone's keys) to
    // ALL members so each can post + verify the others.
    let delivered = distribute_group_invite(&group, &self_did).unwrap_or(0);
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "group": group.id, "added": bare, "epoch": group.epoch,
                "members": group.members.len(), "invites_queued": delivered
            }))?
        );
    } else {
        println!(
            "added `{bare}` to `{}` — now {} member(s), epoch {} ({delivered} invite(s) queued; run `wire push`)",
            group.name,
            group.members.len(),
            group.epoch
        );
    }
    Ok(())
}

fn cmd_group_send(group_ref: &str, message: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    ingest_group_invites()?;
    let (self_did, self_handle, _, pk_b64) = group_self()?;
    let group = crate::group::resolve_group(group_ref)?;
    // Membership for SEND is room-token possession: having the group locally
    // (with its slot_token) is the capability. The signed roster gates who you
    // can VERIFY, not whether you may post — a code-redeemed joiner isn't in the
    // creator-signed roster but legitimately holds the room key.
    if group.slot_id.is_empty() || group.relay_url.is_empty() {
        bail!(
            "group `{}` has no room slot (legacy/partial group)",
            group.name
        );
    }
    let sk_seed = config::read_private_key()?;
    let pk_bytes = crate::signing::b64decode(&pk_b64)?;
    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now_iso,
        "from": self_did,
        "to": format!("did:wire:group:{}", group.id),
        "type": "group_msg",
        "kind": parse_kind("group_msg")?,
        "body": {
            "group_id": group.id,
            "group_name": group.name,
            "epoch": group.epoch,
            "text": message,
        },
    });
    let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &self_handle)
        .map_err(|e| anyhow!("signing group_msg: {e:?}"))?;
    // Post the one message to the shared group slot.
    let client = crate::relay_client::RelayClient::new(&group.relay_url);
    client
        .post_event(&group.slot_id, &group.slot_token, &signed)
        .with_context(|| {
            format!(
                "posting to group room {} on {}",
                group.slot_id, group.relay_url
            )
        })?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "group": group.id, "epoch": group.epoch, "status": "posted",
                "members": group.members.len()
            }))?
        );
    } else {
        println!(
            "group `{}`: posted to the room ({} member(s))",
            group.name,
            group.members.len()
        );
    }
    Ok(())
}

fn cmd_group_tail(group_ref: &str, limit: usize, as_json: bool) -> Result<()> {
    ingest_group_invites()?;
    let group = crate::group::resolve_group(group_ref)?;
    if group.slot_id.is_empty() || group.relay_url.is_empty() {
        bail!(
            "group `{}` has no room slot (legacy/partial group)",
            group.name
        );
    }
    let mut trust = config::read_trust().unwrap_or_else(|_| json!({"agents": {}}));
    let client = crate::relay_client::RelayClient::new(&group.relay_url);
    // Pull the shared room; cap generously then show the last `limit`.
    let fetch = if limit == 0 {
        1000
    } else {
        (limit * 4).min(1000)
    };
    let events = client
        .list_events(&group.slot_id, &group.slot_token, None, Some(fetch))
        .with_context(|| {
            format!(
                "pulling group room {} on {}",
                group.slot_id, group.relay_url
            )
        })?;

    // Pass 1: introduce-pin anyone who announced a join. A `group_join` carries
    // the joiner's card and must self-consistently sign under it; posting to the
    // room requires the room token, so possession is the authorization (pinned
    // at bilateral UNTRUSTED, group tier Introduced). This lets their later
    // group messages verify even though they're not in the creator-signed roster.
    let mut trust_changed = false;
    for event in &events {
        if event.get("type").and_then(Value::as_str) != Some("group_join") {
            continue;
        }
        if let Some((h, did, kid, key)) = group_join_pin_material(event)
            && introduce_pin(&mut trust, &h, &did, &kid, &key, &group.id)
        {
            trust_changed = true;
        }
    }
    if trust_changed {
        let _ = config::write_trust(&trust);
    }

    // Pass 2: build the timeline — group messages (verified against the
    // now-augmented trust) interleaved with join notices.
    enum Line {
        Msg {
            from: String,
            text: String,
            verified: bool,
        },
        Join {
            who: String,
        },
    }
    let mut timeline: Vec<(String, Line)> = Vec::new();
    for event in &events {
        let ty = event.get("type").and_then(Value::as_str).unwrap_or("");
        let body = match event.get("body") {
            Some(Value::String(s)) => serde_json::from_str::<Value>(s).ok(),
            Some(v) => Some(v.clone()),
            None => None,
        };
        let Some(body) = body else { continue };
        if body.get("group_id").and_then(Value::as_str) != Some(group.id.as_str()) {
            continue;
        }
        let ts = event
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let from_did = event.get("from").and_then(Value::as_str).unwrap_or("");
        let from_handle = crate::agent_card::display_handle_from_did(from_did).to_string();
        match ty {
            "group_msg" => {
                let text = body
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let verified = verify_message_v31(event, &trust).is_ok();
                timeline.push((
                    ts,
                    Line::Msg {
                        from: from_handle,
                        text,
                        verified,
                    },
                ));
            }
            "group_join" => timeline.push((ts, Line::Join { who: from_handle })),
            _ => {}
        }
    }
    timeline.sort_by(|a, b| a.0.cmp(&b.0));
    let start = if limit > 0 {
        timeline.len().saturating_sub(limit)
    } else {
        0
    };
    let recent = &timeline[start..];
    if as_json {
        let arr: Vec<Value> = recent
            .iter()
            .map(|(ts, l)| match l {
                Line::Msg {
                    from,
                    text,
                    verified,
                } => {
                    json!({"ts": ts, "type": "msg", "from": from, "text": text, "verified": verified})
                }
                Line::Join { who } => json!({"ts": ts, "type": "join", "from": who}),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(
                &json!({"group": group.id, "name": group.name, "messages": arr})
            )?
        );
    } else if recent.is_empty() {
        println!("group `{}`: no messages yet", group.name);
    } else {
        for (ts, l) in recent {
            let short_ts: String = ts.chars().take(19).collect();
            match l {
                Line::Msg {
                    from,
                    text,
                    verified,
                } => {
                    let mark = if *verified { "✓" } else { "✗" };
                    println!("[{short_ts}] {} {mark}: {text}", persona_label(from));
                }
                Line::Join { who } => println!("[{short_ts}] {} joined", persona_label(who)),
            }
        }
    }
    Ok(())
}

/// Validate a `group_join` room event and extract the joiner's pin material:
/// (handle, did, key_id, key_b64). The event MUST self-consistently sign under
/// the key in the card it carries — so a forged join (card A, signed by key B)
/// is rejected. Authorization to be in the room is proven by the post itself
/// (it required the room token).
fn group_join_pin_material(event: &Value) -> Option<(String, String, String, String)> {
    let body = match event.get("body") {
        Some(Value::String(s)) => serde_json::from_str::<Value>(s).ok()?,
        Some(v) => v.clone(),
        None => return None,
    };
    let card = body.get("joiner_card")?;
    // Verify the event signs under the card it carries (one-entry trust).
    let mut tmp = json!({"agents": {}});
    crate::trust::add_agent_card_pin(&mut tmp, card, Some("UNTRUSTED"));
    if verify_message_v31(event, &tmp).is_err() {
        return None;
    }
    let did = card.get("did").and_then(Value::as_str)?.to_string();
    let handle = card
        .get("handle")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| crate::agent_card::display_handle_from_did(&did).to_string());
    let (kid_full, krec) = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.iter().next())?;
    let key_id = kid_full
        .strip_prefix("ed25519:")
        .unwrap_or(kid_full)
        .to_string();
    let key = krec.get("key").and_then(Value::as_str)?.to_string();
    Some((handle, did, key_id, key))
}

/// `wire group invite <group>` — mint a self-contained join code (the serialized
/// signed group: room coords + roster + member keys). The code IS the room key.
fn cmd_group_invite(group_ref: &str, as_json: bool) -> Result<()> {
    let group = crate::group::resolve_group(group_ref)?;
    if group.slot_id.is_empty() || group.relay_url.is_empty() {
        bail!(
            "group `{}` has no room slot — nothing to invite into",
            group.name
        );
    }
    if group.creator_sig.is_empty() {
        bail!(
            "group `{}` roster is unsigned — add a member or recreate before inviting",
            group.name
        );
    }
    let payload = serde_json::to_vec(&group)?;
    let code = format!("wire-group:{}", crate::signing::b64encode(&payload));
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({"group": group.id, "name": group.name, "code": code}))?
        );
    } else {
        println!(
            "join code for `{}` — share ONLY with people you want in the room (it IS the room key):\n",
            group.name
        );
        println!("{code}\n");
        println!("they run:  wire group join <code>");
    }
    Ok(())
}

/// `wire group join <code>` — redeem a join code: verify the roster, materialize
/// the room locally, introduce-pin existing members, and announce ourselves to
/// the room so members verify our messages. Lands at group tier Introduced.
fn cmd_group_join(code: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    let raw = code.trim();
    let b64 = raw.strip_prefix("wire-group:").unwrap_or(raw);
    let payload =
        crate::signing::b64decode(b64).map_err(|_| anyhow!("invalid join code (not base64)"))?;
    let group: crate::group::Group = serde_json::from_slice(&payload)
        .map_err(|_| anyhow!("invalid join code (not a group payload)"))?;
    if group.slot_id.is_empty() || group.relay_url.is_empty() {
        bail!("join code carries no room coords");
    }
    // Verify the roster against the creator's key carried IN the roster (TOFU on
    // the code — you obtained it over a trusted channel). Rejects a tampered code.
    let creator_key = group
        .members
        .iter()
        .find(|m| m.did == group.creator_did)
        .map(|m| m.key.clone())
        .filter(|k| !k.is_empty())
        .and_then(|k| crate::signing::b64decode(&k).ok())
        .ok_or_else(|| anyhow!("join code is missing the creator's key"))?;
    if !group.verify(&creator_key) {
        bail!("join code failed its signature check (tampered or corrupt)");
    }
    let (self_did, self_handle, _, _) = group_self()?;
    if group.creator_did == self_did {
        bail!("you created group `{}` — you're already in it", group.name);
    }

    // Materialize locally + introduce-pin existing members so we can verify them.
    crate::group::save_group(&group)?;
    let mut trust = config::read_trust()?;
    for m in &group.members {
        if m.did == self_did || m.key.is_empty() {
            continue;
        }
        introduce_pin(&mut trust, &m.handle, &m.did, &m.key_id, &m.key, &group.id);
    }
    config::write_trust(&trust)?;

    // Announce ourselves to the room (carry our card) so members introduce-pin us.
    let card = config::read_agent_card()?;
    let sk_seed = config::read_private_key()?;
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;
    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now_iso,
        "from": self_did,
        "to": format!("did:wire:group:{}", group.id),
        "type": "group_join",
        "kind": parse_kind("group_join")?,
        "body": {
            "group_id": group.id,
            "group_name": group.name,
            "epoch": group.epoch,
            "joiner_card": card,
            "text": "joined",
        },
    });
    let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &self_handle)
        .map_err(|e| anyhow!("signing group_join: {e:?}"))?;
    let client = crate::relay_client::RelayClient::new(&group.relay_url);
    let announced = client
        .post_event(&group.slot_id, &group.slot_token, &signed)
        .is_ok();

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "group": group.id, "name": group.name, "joined": true,
                "members": group.members.len(), "announced": announced
            }))?
        );
    } else {
        println!(
            "joined group `{}` ({} member(s)) at Introduced tier.",
            group.name,
            group.members.len()
        );
        if announced {
            println!("  announced to the room — members will verify your messages.");
        } else {
            println!(
                "  ⚠ couldn't reach the room relay to announce; retry a `wire group send` so members can verify you."
            );
        }
        println!(
            "  read: `wire group tail {}`   talk: `wire group send {} \"hi\"`",
            group.id, group.id
        );
    }
    Ok(())
}

fn cmd_group_list(as_json: bool) -> Result<()> {
    let groups = crate::group::list_groups()?;
    if as_json {
        let arr: Vec<Value> = groups
            .iter()
            .map(|g| {
                json!({
                    "id": g.id,
                    "name": g.name,
                    "epoch": g.epoch,
                    "members": g.members.iter().map(|m| json!({"handle": m.handle, "tier": m.tier.as_str()})).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string(&json!({"groups": arr}))?);
    } else if groups.is_empty() {
        println!("no groups yet — create one with `wire group create <name>`");
    } else {
        for g in &groups {
            println!(
                "{} ({}) — {} member(s), epoch {}",
                g.name,
                g.id,
                g.members.len(),
                g.epoch
            );
            for m in &g.members {
                println!("    {} [{}]", m.handle, m.tier.as_str());
            }
        }
    }
    Ok(())
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
        } => cmd_mesh_broadcast(&kind, &scope, &exclude, noreply, &body, json),
        MeshCommand::Role { action } => cmd_mesh_role(action),
        MeshCommand::Route {
            role,
            strategy,
            exclude,
            kind,
            body,
            json,
        } => cmd_mesh_route(&role, &strategy, &exclude, &kind, &body, json),
    }
}

/// v0.6.5 (issue #21): capability-match routing. Walks sister sessions,
/// filters by `profile.role` + `--exclude` + must-be-pinned-in-our-peers,
/// picks ONE via the requested strategy, then signs + pushes the event
/// to that peer. Pinned-peers-only by construction (same as broadcast).
fn cmd_mesh_route(
    role: &str,
    strategy: &str,
    exclude: &[String],
    kind: &str,
    body_arg: &str,
    as_json: bool,
) -> Result<()> {
    use std::time::Instant;

    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }
    let strategy = strategy.to_ascii_lowercase();
    if !matches!(strategy.as_str(), "round-robin" | "first" | "random") {
        bail!("unknown strategy `{strategy}` — use round-robin | first | random");
    }

    // Our pinned-peer set: only these handles are addressable. mesh-route
    // refuses to invent a recipient, same posture as broadcast.
    let state = config::read_relay_state()?;
    let pinned: std::collections::BTreeSet<String> = state["peers"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    let exclude_set: std::collections::HashSet<&str> = exclude.iter().map(String::as_str).collect();

    // Enumerate every sister on the box, read each one's role from its
    // signed agent-card. Filter: matching role AND pinned AND not
    // excluded. `list_sessions` returns the cross-session view (using the
    // v0.6.4 inside-session sessions_root fallback).
    let sessions = crate::session::list_sessions()?;
    let mut candidates: Vec<(String, Option<String>)> = Vec::new(); // (handle, did)
    for s in &sessions {
        let handle = match s.handle.as_ref() {
            Some(h) => h.clone(),
            None => continue,
        };
        if exclude_set.contains(handle.as_str()) {
            continue;
        }
        if !pinned.contains(&handle) {
            continue;
        }
        let card_path = s
            .home_dir
            .join("config")
            .join("wire")
            .join("agent-card.json");
        let card_role = std::fs::read(&card_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|c| {
                c.get("profile")
                    .and_then(|p| p.get("role"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
        if card_role.as_deref() == Some(role) {
            candidates.push((handle, s.did.clone()));
        }
    }

    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    candidates.dedup_by(|a, b| a.0 == b.0);

    if candidates.is_empty() {
        bail!(
            "no pinned sister with role=`{role}` (run `wire mesh role list` to see what's available)"
        );
    }

    let chosen = match strategy.as_str() {
        "first" => candidates[0].clone(),
        "random" => {
            use rand::Rng;
            let idx = rand::thread_rng().gen_range(0..candidates.len());
            candidates[idx].clone()
        }
        "round-robin" => {
            // Cursor persisted at <state_dir>/mesh-route-cursor.json:
            // `{role: last_picked_handle}`. Next pick = first candidate
            // alphabetically AFTER last_picked, wrapping around when no
            // candidate is greater.
            let cursor_path = mesh_route_cursor_path()?;
            let mut cursors: std::collections::BTreeMap<String, String> =
                read_mesh_route_cursors(&cursor_path);
            let last = cursors.get(role).cloned();
            let pick = match last {
                None => candidates[0].clone(),
                Some(last_h) => candidates
                    .iter()
                    .find(|(h, _)| h.as_str() > last_h.as_str())
                    .cloned()
                    .unwrap_or_else(|| candidates[0].clone()),
            };
            cursors.insert(role.to_string(), pick.0.clone());
            write_mesh_route_cursors(&cursor_path, &cursors)?;
            pick
        }
        _ => unreachable!(),
    };

    let (chosen_handle, _chosen_did) = chosen;

    // Body parsing follows wire send / mesh broadcast.
    let body_value: Value = if body_arg == "-" {
        use std::io::Read;
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .with_context(|| "reading body from stdin")?;
        serde_json::from_str(raw.trim_end()).unwrap_or(Value::String(raw))
    } else if let Some(path) = body_arg.strip_prefix('@') {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading body file {path:?}"))?;
        serde_json::from_str(&raw).unwrap_or(Value::String(raw))
    } else {
        Value::String(body_arg.to_string())
    };

    let sk_seed = config::read_private_key()?;
    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing did"))?
        .to_string();
    let handle = crate::agent_card::display_handle_from_did(&did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;

    let kind_id = parse_kind(kind)?;
    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now_iso,
        "from": did,
        "to": format!("did:wire:{chosen_handle}"),
        "type": kind,
        "kind": kind_id,
        "body": json!({
            "content": body_value,
            "routed_via": {
                "role": role,
                "strategy": strategy,
            },
        }),
    });
    let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &handle)
        .map_err(|e| anyhow!("sign_message_v31 failed: {e:?}"))?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    let line = serde_json::to_vec(&signed)?;
    config::append_outbox_record(&chosen_handle, &line)?;

    let endpoints = crate::endpoints::peer_endpoints_in_priority_order(&state, &chosen_handle);
    if endpoints.is_empty() {
        bail!(
            "no reachable endpoint pinned for `{chosen_handle}` (the role matched, but we can't push)"
        );
    }
    let start = Instant::now();
    let mut delivered = false;
    let mut last_err: Option<String> = None;
    let mut via_scope: Option<String> = None;
    for ep in &endpoints {
        // v0.7.0-alpha.19: scheme-aware dispatch — `unix://` endpoints
        // route via uds_request, others via reqwest. Allows peers with
        // UDS-tagged endpoints in their agent-card to receive events
        // over the local socket instead of loopback HTTP.
        match crate::relay_client::post_event_to_endpoint(ep, &signed) {
            Ok(_) => {
                delivered = true;
                via_scope = Some(
                    match ep.scope {
                        crate::endpoints::EndpointScope::Local => "local",
                        crate::endpoints::EndpointScope::Lan => "lan",
                        crate::endpoints::EndpointScope::Uds => "uds",
                        crate::endpoints::EndpointScope::Federation => "federation",
                    }
                    .to_string(),
                );
                break;
            }
            Err(e) => last_err = Some(format!("{e:#}")),
        }
    }
    let rtt_ms = start.elapsed().as_millis() as u64;

    let summary = json!({
        "role": role,
        "strategy": strategy,
        "routed_to": chosen_handle,
        "event_id": event_id,
        "delivered": delivered,
        "delivered_via": via_scope,
        "rtt_ms": rtt_ms,
        "candidates": candidates.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>(),
        "error": last_err,
    });

    if as_json {
        println!("{}", serde_json::to_string(&summary)?);
    } else if delivered {
        let via = via_scope.as_deref().unwrap_or("?");
        println!("wire mesh route: {role} → {chosen_handle} ({rtt_ms}ms, {via})");
    } else {
        let err = last_err.as_deref().unwrap_or("no endpoints reachable");
        bail!("delivery to `{chosen_handle}` failed: {err}");
    }
    Ok(())
}

fn mesh_route_cursor_path() -> Result<std::path::PathBuf> {
    Ok(config::state_dir()?.join("mesh-route-cursor.json"))
}

fn read_mesh_route_cursors(path: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_mesh_route_cursors(
    path: &std::path::Path,
    cursors: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
    }
    let body = serde_json::to_vec_pretty(cursors)?;
    std::fs::write(path, body).with_context(|| format!("writing {path:?}"))?;
    Ok(())
}

/// v0.6.4 (issue #20): mesh role tag dispatcher. Wraps the existing
/// `profile.role` persistence (re-uses `pair_profile::write_profile_field`)
/// behind a discoverability-friendlier surface, plus cross-session
/// enumeration for the list path.
fn cmd_mesh_role(action: MeshRoleAction) -> Result<()> {
    match action {
        MeshRoleAction::Set { role, json } => {
            validate_role_tag(&role)?;
            let new_profile =
                crate::pair_profile::write_profile_field("role", Value::String(role.clone()))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "role": role,
                        "profile": new_profile,
                    }))?
                );
            } else {
                println!("self role = {role} (signed into agent-card)");
            }
        }
        MeshRoleAction::Get { peer, json } => {
            let (who, role) = match peer.as_deref() {
                None => {
                    let card = config::read_agent_card()?;
                    let role = card
                        .get("profile")
                        .and_then(|p| p.get("role"))
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    let who = card
                        .get("did")
                        .and_then(Value::as_str)
                        .map(|d| crate::agent_card::display_handle_from_did(d).to_string())
                        .unwrap_or_else(|| "self".to_string());
                    (who, role)
                }
                Some(handle) => {
                    let bare = crate::agent_card::bare_handle(handle).to_string();
                    let trust = config::read_trust()?;
                    let role = trust
                        .get("agents")
                        .and_then(|a| a.get(&bare))
                        .and_then(|a| a.get("card"))
                        .and_then(|c| c.get("profile"))
                        .and_then(|p| p.get("role"))
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    (bare, role)
                }
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "handle": who,
                        "role": role,
                    }))?
                );
            } else {
                match role {
                    Some(r) => println!("{who}: {r}"),
                    None => println!("{who}: (unset)"),
                }
            }
        }
        MeshRoleAction::List { json } => {
            let mut self_did: Option<String> = None;
            if let Ok(card) = config::read_agent_card() {
                self_did = card.get("did").and_then(Value::as_str).map(str::to_string);
            }
            let sessions = crate::session::list_sessions()?;
            let mut rows: Vec<Value> = Vec::new();
            for s in &sessions {
                let card_path = s
                    .home_dir
                    .join("config")
                    .join("wire")
                    .join("agent-card.json");
                let role = std::fs::read(&card_path)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                    .and_then(|c| {
                        c.get("profile")
                            .and_then(|p| p.get("role"))
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    });
                let is_self = match (&self_did, &s.did) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                };
                rows.push(json!({
                    "name": s.name,
                    "handle": s.handle,
                    "role": role,
                    "self": is_self,
                }));
            }
            rows.sort_by(|a, b| {
                a["name"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["name"].as_str().unwrap_or(""))
            });
            if json {
                println!("{}", serde_json::to_string(&json!({"sessions": rows}))?);
            } else if rows.is_empty() {
                println!("no sister sessions on this machine.");
            } else {
                println!("SISTER ROLES (this machine):");
                for r in &rows {
                    let name = r["name"].as_str().unwrap_or("?");
                    let role = r["role"].as_str().unwrap_or("(unset)");
                    let marker = if r["self"].as_bool().unwrap_or(false) {
                        "    ← you"
                    } else {
                        ""
                    };
                    println!("  {name:<24} {role}{marker}");
                }
            }
        }
        MeshRoleAction::Clear { json } => {
            let new_profile = crate::pair_profile::write_profile_field("role", Value::Null)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "cleared": true,
                        "profile": new_profile,
                    }))?
                );
            } else {
                println!("self role cleared");
            }
        }
    }
    Ok(())
}

/// v0.6.4: role tag must be ASCII alphanumeric + `-` + `_`, 1-32 chars.
/// No vocabulary check — operators choose the taxonomy (planner /
/// reviewer / dispatcher / your-custom-tag). The constraint is purely
/// to keep the tag safe for filenames / URLs / shell args.
fn validate_role_tag(role: &str) -> Result<()> {
    if role.is_empty() {
        bail!("role must not be empty (use `wire mesh role --clear` to unset)");
    }
    if role.len() > 32 {
        bail!("role too long ({} chars; max 32)", role.len());
    }
    for c in role.chars() {
        if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            bail!("role contains illegal char {c:?} (allowed: A-Z a-z 0-9 - _)");
        }
    }
    Ok(())
}

/// v0.6.3 (issue #19): fan one signed event to every pinned peer.
///
/// **Routing.** Each recipient gets its own signed event (Ed25519 over the
/// canonical event including `to:`, so per-recipient signing is required;
/// the cost is one sign per peer = ~50µs each, dominated by relay RTT).
/// Per-recipient pushes happen in parallel via `std::thread::scope` so
/// broadcast-to-5 takes ~1× RTT, not 5×.
///
/// **Scope filter.** Default `local` — only peers reachable via a same-
/// machine local relay (priority-1 endpoint has `scope=local`). This is
/// the lowest-blast-radius default: local-only broadcasts cannot escape
/// the operator's machine. `federation` flips to public-relay peers
/// only; `both` removes the filter.
///
/// **Pinned-peers-only.** Walks `state.peers` — never .well-known
/// resolution, never trust["agents"] expansion. Closes #8-class
/// phonebook-scrape vectors by construction: an attacker pinning a
/// hostile handle has to first be pinned bidirectionally by the
/// operator, and even then `--exclude` is the loud opt-out.
fn cmd_mesh_broadcast(
    kind: &str,
    scope_str: &str,
    exclude: &[String],
    _noreply: bool,
    body_arg: &str,
    as_json: bool,
) -> Result<()> {
    use std::time::Instant;

    if !config::is_initialized()? {
        bail!("not initialized — run `wire init <handle>` first");
    }

    let scope = match scope_str {
        "local" => crate::endpoints::EndpointScope::Local,
        "federation" => crate::endpoints::EndpointScope::Federation,
        "both" => {
            // Sentinel: we don't actually have a `Both` variant on the
            // scope enum; use a tri-state below. Treat as Local for the
            // typed match and special-case it via the bool below.
            crate::endpoints::EndpointScope::Local
        }
        other => bail!("unknown scope `{other}` — use local | federation | both"),
    };
    let any_scope = scope_str == "both";

    let state = config::read_relay_state()?;
    let peers = state["peers"].as_object().cloned().unwrap_or_default();
    if peers.is_empty() {
        bail!("no peers pinned — run `wire accept <invite-url>` or `wire pair-accept` first");
    }

    let exclude_set: std::collections::HashSet<&str> = exclude.iter().map(String::as_str).collect();

    // Walk the pinned-peer set, filter by scope + exclude. Keep the
    // priority-ordered endpoint list for each match so the push can
    // try local first then fall through to federation (when scope=both).
    struct Target {
        handle: String,
        endpoints: Vec<crate::endpoints::Endpoint>,
    }
    let mut targets: Vec<Target> = Vec::new();
    let mut skipped_wrong_scope: Vec<String> = Vec::new();
    let mut skipped_excluded: Vec<String> = Vec::new();
    for handle in peers.keys() {
        if exclude_set.contains(handle.as_str()) {
            skipped_excluded.push(handle.clone());
            continue;
        }
        let ordered = crate::endpoints::peer_endpoints_in_priority_order(&state, handle);
        let filtered: Vec<crate::endpoints::Endpoint> = ordered
            .into_iter()
            .filter(|ep| any_scope || ep.scope == scope)
            .collect();
        if filtered.is_empty() {
            skipped_wrong_scope.push(handle.clone());
            continue;
        }
        targets.push(Target {
            handle: handle.clone(),
            endpoints: filtered,
        });
    }

    if targets.is_empty() {
        bail!(
            "no peers matched scope=`{scope_str}` after exclude filter ({} excluded, {} wrong-scope)",
            skipped_excluded.len(),
            skipped_wrong_scope.len()
        );
    }

    // Load signing material once; share across per-peer signatures.
    let sk_seed = config::read_private_key()?;
    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing did"))?
        .to_string();
    let handle = crate::agent_card::display_handle_from_did(&did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;

    let body_value: Value = if body_arg == "-" {
        use std::io::Read;
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .with_context(|| "reading body from stdin")?;
        serde_json::from_str(raw.trim_end()).unwrap_or(Value::String(raw))
    } else if let Some(path) = body_arg.strip_prefix('@') {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading body file {path:?}"))?;
        serde_json::from_str(&raw).unwrap_or(Value::String(raw))
    } else {
        Value::String(body_arg.to_string())
    };

    let kind_id = parse_kind(kind)?;
    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    let broadcast_id = generate_broadcast_id();
    let target_count = targets.len();

    // Build + sign every event up front (sequential, ~50µs/sig). Then
    // queue to outbox + push to relay in parallel per-peer. Returns
    // a per-peer outcome we then sort by handle for deterministic output.
    let mut signed_per_peer: Vec<(String, Vec<crate::endpoints::Endpoint>, Value, String)> =
        Vec::with_capacity(targets.len());
    for t in &targets {
        let body = json!({
            "content": body_value,
            "broadcast_id": broadcast_id,
            "broadcast_target_count": target_count,
        });
        let event = json!({
            "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
            "timestamp": now_iso,
            "from": did,
            "to": format!("did:wire:{}", t.handle),
            "type": kind,
            "kind": kind_id,
            "body": body,
        });
        let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &handle)
            .map_err(|e| anyhow!("sign_message_v31 failed for `{}`: {e:?}", t.handle))?;
        let event_id = signed["event_id"].as_str().unwrap_or("").to_string();
        signed_per_peer.push((t.handle.clone(), t.endpoints.clone(), signed, event_id));
    }

    // Persist to per-peer outbox FIRST (sequential — `append_outbox_record`
    // holds a per-path mutex; writes are independent across handles but
    // we want the side-effect ordering deterministic).
    for (peer, _, signed, _) in &signed_per_peer {
        let line = serde_json::to_vec(signed)?;
        config::append_outbox_record(peer, &line)?;
    }

    // Per-peer parallel push. Each thread tries the priority-ordered
    // endpoint list; first 2xx wins. Aggregate (peer, delivered, rtt_ms,
    // error_opt) over a channel.
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel::<Value>();
    std::thread::scope(|s| {
        for (peer, endpoints, signed, event_id) in &signed_per_peer {
            let tx = tx.clone();
            let peer = peer.clone();
            let event_id = event_id.clone();
            let endpoints = endpoints.clone();
            let signed = signed.clone();
            s.spawn(move || {
                let start = Instant::now();
                let mut delivered = false;
                let mut last_err: Option<String> = None;
                let mut delivered_via: Option<String> = None;
                for ep in &endpoints {
                    // v0.7.0-alpha.19: scheme-aware dispatch (UDS via
                    // uds_request, else reqwest). Same as cmd_send's
                    // single-peer path above; this is the parallel
                    // multi-peer broadcast loop.
                    match crate::relay_client::post_event_to_endpoint(ep, &signed) {
                        Ok(_) => {
                            delivered = true;
                            delivered_via = Some(
                                match ep.scope {
                                    crate::endpoints::EndpointScope::Local => "local",
                                    crate::endpoints::EndpointScope::Lan => "lan",
                                    crate::endpoints::EndpointScope::Uds => "uds",
                                    crate::endpoints::EndpointScope::Federation => "federation",
                                }
                                .to_string(),
                            );
                            break;
                        }
                        Err(e) => last_err = Some(format!("{e:#}")),
                    }
                }
                let rtt_ms = start.elapsed().as_millis() as u64;
                let _ = tx.send(json!({
                    "peer": peer,
                    "event_id": event_id,
                    "delivered": delivered,
                    "delivered_via": delivered_via,
                    "rtt_ms": rtt_ms,
                    "error": last_err,
                }));
            });
        }
    });
    drop(tx);

    let mut results: Vec<Value> = rx.iter().collect();
    results.sort_by(|a, b| {
        a["peer"]
            .as_str()
            .unwrap_or("")
            .cmp(b["peer"].as_str().unwrap_or(""))
    });

    let delivered = results
        .iter()
        .filter(|r| r["delivered"].as_bool().unwrap_or(false))
        .count();
    let failed = results.len() - delivered;

    let summary = json!({
        "broadcast_id": broadcast_id,
        "kind": kind,
        "scope": scope_str,
        "target_count": target_count,
        "delivered": delivered,
        "failed": failed,
        "skipped_excluded": skipped_excluded,
        "skipped_wrong_scope": skipped_wrong_scope,
        "results": results,
    });

    if as_json {
        println!("{}", serde_json::to_string(&summary)?);
        return Ok(());
    }

    println!("wire mesh broadcast: scope={scope_str} → {target_count} pinned peer(s)");
    for r in &results {
        let peer = r["peer"].as_str().unwrap_or("?");
        let delivered = r["delivered"].as_bool().unwrap_or(false);
        let rtt = r["rtt_ms"].as_u64().unwrap_or(0);
        let via = r["delivered_via"].as_str().unwrap_or("");
        if delivered {
            println!("  {peer:<24} ✓ delivered ({rtt}ms, {via})");
        } else {
            let err = r["error"].as_str().unwrap_or("?");
            println!("  {peer:<24} ✗ failed — {err}");
        }
    }
    if !skipped_excluded.is_empty() {
        println!("  excluded: {}", skipped_excluded.join(", "));
    }
    if !skipped_wrong_scope.is_empty() {
        println!(
            "  skipped (wrong scope): {}",
            skipped_wrong_scope.join(", ")
        );
    }
    println!("broadcast_id: {broadcast_id}");
    Ok(())
}

/// Random 16-byte UUID-shaped id for correlating a broadcast's recipient
/// events. Not strictly UUID v4 (no version/variant bits set) — receivers
/// correlate by string equality, the shape is for human readability.
fn generate_broadcast_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    let h = hex::encode(buf);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32],
    )
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
    let cwd_str = cwd.to_string_lossy().into_owned();

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

    let self_obj = state
        .as_object_mut()
        .expect("relay_state root is an object")
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

    let self_obj = state
        .as_object_mut()
        .expect("relay_state root is an object")
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
    // half-populated self state that broke pair-accept on local-only
    // sessions.
    let (legacy_relay, legacy_slot_id, legacy_slot_token) = match fed_endpoint.clone() {
        Some(f) => (f.relay_url, f.slot_id, f.slot_token),
        None => (
            local_relay.trim_end_matches('/').to_string(),
            alloc.slot_id.clone(),
            alloc.slot_token.clone(),
        ),
    };
    let self_obj = state
        .as_object_mut()
        .expect("relay_state root is an object")
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
    let cwd_key = cwd.to_string_lossy().into_owned();
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
///   5. WIRE_HOME=B wire pair-accept <A-bare>   (B pins A, sends ack)
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
        print!("{:>col_w$}", n, col_w = col_w);
    }
    println!();
    for (i, row) in names.iter().enumerate() {
        print!("{:>col_w$}", row, col_w = col_w);
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
            print!("{:>col_w$}", cell, col_w = col_w);
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
    // character, not the session name. pair-accept lookups key on the
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

    // 4. B pulls pair_drop → 5. B pair-accept (pins A by CARD HANDLE,
    // not by session name — under v0.11 these differ) → 6. B push ack
    run(b_home, &["pull", "--json"]).with_context(|| format!("step 4/8: {b_name} `wire pull`"))?;
    run(b_home, &["pair-accept", &a_handle, "--json"]).with_context(|| {
        format!("step 5/8: {b_name} `wire pair-accept {a_handle}` (a session={a_name})")
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
            let size = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
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
    let kind = |local_relay: bool| {
        if local_relay {
            crate::service::ServiceKind::LocalRelay
        } else {
            crate::service::ServiceKind::Daemon
        }
    };
    let (report, as_json) = match action {
        ServiceAction::Install { local_relay, json } => {
            (crate::service::install_kind(kind(local_relay))?, json)
        }
        ServiceAction::Uninstall { local_relay, json } => {
            (crate::service::uninstall_kind(kind(local_relay))?, json)
        }
        ServiceAction::Status { local_relay, json } => {
            (crate::service::status_kind(kind(local_relay))?, json)
        }
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

// ---------- update (self-update from crates.io / prebuilt release) ----------

const CRATE_NAME: &str = "slancha-wire";

/// (target-triple, binary-extension) of the GitHub release asset for THIS
/// platform — names mirror `.github/workflows/release.yml`. `None` if no
/// prebuilt is published for this target.
fn release_asset_triple() -> Option<(&'static str, &'static str)> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return Some(("x86_64-pc-windows-msvc", ".exe"));
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return Some(("aarch64-apple-darwin", ""));
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return Some(("x86_64-apple-darwin", ""));
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return Some(("x86_64-unknown-linux-musl", ""));
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return Some(("aarch64-unknown-linux-musl", ""));
    }
    #[allow(unreachable_code)]
    None
}

/// Latest stable version published on crates.io.
fn fetch_latest_published_version() -> Result<String> {
    let url = format!("https://crates.io/api/v1/crates/{CRATE_NAME}");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let resp = client
        .get(&url)
        // crates.io rejects requests without a descriptive User-Agent (403).
        .header(
            "User-Agent",
            format!("wire/{} (self-update)", env!("CARGO_PKG_VERSION")),
        )
        .send()?;
    if !resp.status().is_success() {
        bail!("crates.io returned {} for {CRATE_NAME}", resp.status());
    }
    let v: Value = resp.json()?;
    v.get("crate")
        .and_then(|c| {
            c.get("max_stable_version")
                .or_else(|| c.get("newest_version"))
        })
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("crates.io response missing crate.max_stable_version"))
}

/// True iff `latest` is strictly newer than `current` (numeric major.minor.patch;
/// pre-release suffixes ignored).
fn version_is_newer(latest: &str, current: &str) -> bool {
    let parse = |s: &str| -> (u64, u64, u64) {
        let core = s.split('-').next().unwrap_or(s);
        let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        (
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
        )
    };
    parse(latest) > parse(current)
}

fn cargo_on_path() -> bool {
    std::process::Command::new("cargo")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Download the prebuilt release binary for `latest` and replace THIS binary
/// in place — the toolchain-free update path (for boxes with no `cargo`).
fn self_update_from_release(latest: &str) -> Result<()> {
    let (triple, ext) = release_asset_triple().ok_or_else(|| {
        anyhow!(
            "no prebuilt release binary for this platform — install a Rust toolchain and re-run, \
             or `cargo install {CRATE_NAME}`"
        )
    })?;
    let base =
        format!("https://github.com/SlanchaAi/wire/releases/download/v{latest}/wire-{triple}{ext}");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    let resp = client
        .get(&base)
        .header("User-Agent", "wire-self-update")
        .send()?;
    if !resp.status().is_success() {
        bail!("downloading {base} returned {}", resp.status());
    }
    let bytes = resp.bytes()?;

    // Verify the SHA-256 sidecar if present (best-effort; absence is non-fatal).
    if let Ok(sha) = client
        .get(format!("{base}.sha256"))
        .header("User-Agent", "wire-self-update")
        .send()
        && sha.status().is_success()
    {
        let expected = sha
            .text()?
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        if !expected.is_empty() {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&bytes);
            let actual = hex::encode(h.finalize());
            if expected != actual {
                bail!(
                    "SHA-256 mismatch — expected {expected}, got {actual} (aborting, binary NOT replaced)"
                );
            }
        }
    }

    let exe = std::env::current_exe().context("locating current exe")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("current exe has no parent dir"))?;
    let tmp = dir.join(format!(".wire-update-{}", std::process::id()));
    std::fs::write(&tmp, &bytes).with_context(|| format!("writing {tmp:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        // Unix: rename over the running binary — the running process keeps the
        // old inode; the new file takes the path for the next invocation.
        std::fs::rename(&tmp, &exe).with_context(|| format!("replacing {exe:?}"))?;
    }
    #[cfg(windows)]
    {
        // Windows can't overwrite a running .exe — rename it aside first
        // (allowed even while running), then move the new one into place.
        let old = exe.with_extension("old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(&exe, &old)
            .with_context(|| format!("renaming running exe {exe:?} aside"))?;
        std::fs::rename(&tmp, &exe).with_context(|| format!("installing new exe at {exe:?}"))?;
    }
    Ok(())
}

/// Outcome of the crates.io self-update step (the front half of `wire upgrade`).
struct UpdateOutcome {
    current: String,
    latest: String,
    /// A newer stable version is published.
    available: bool,
    /// We actually installed it this run.
    installed: bool,
    /// How it was installed ("cargo install" / "prebuilt release binary").
    via: Option<&'static str>,
}

/// Check crates.io for a newer published wire and, when `install` is true,
/// self-install it (cargo if a toolchain is on PATH, else the prebuilt release
/// binary). The front half of `wire upgrade`; `install=false` is check-only.
fn self_update_step(install: bool) -> Result<UpdateOutcome> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let latest = fetch_latest_published_version().context("checking crates.io for latest wire")?;
    let available = version_is_newer(&latest, &current);
    if !install || !available {
        return Ok(UpdateOutcome {
            current,
            latest,
            available,
            installed: false,
            via: None,
        });
    }
    let via = if cargo_on_path() {
        eprintln!(
            "wire upgrade: {current} → {latest} — installing via `cargo install {CRATE_NAME}` …"
        );
        let status = std::process::Command::new("cargo")
            .args([
                "install",
                CRATE_NAME,
                "--version",
                &latest,
                "--force",
                "--locked",
            ])
            .status()
            .context("running cargo install")?;
        if !status.success() {
            bail!("`cargo install {CRATE_NAME}` failed");
        }
        "cargo install"
    } else {
        eprintln!(
            "wire upgrade: {current} → {latest} — no `cargo` on PATH, downloading the prebuilt release binary …"
        );
        self_update_from_release(&latest)?;
        "prebuilt release binary"
    };
    Ok(UpdateOutcome {
        current,
        latest,
        available,
        installed: true,
        via: Some(via),
    })
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
///
/// Session-scoped upgrade kill set (v0.13.2, B fix): THIS session's own daemon
/// (`my_pid`, from its pidfile — reliable even when the OS process scan can't
/// see it, as on Windows) plus TRUE orphans (found `wire daemon` pids owned by
/// no session), EXCLUDING sibling sessions' daemons. Pure + unit-tested so the
/// session-scoping is locked — the box-wide predecessor accumulated daemons.
fn upgrade_kill_set(
    my_pid: Option<u32>,
    found_daemon_pids: &[u32],
    owned_session_pids: &std::collections::HashSet<u32>,
) -> Vec<u32> {
    let mut k: Vec<u32> = Vec::new();
    if let Some(p) = my_pid {
        k.push(p);
    }
    for &p in found_daemon_pids {
        if !owned_session_pids.contains(&p) && Some(p) != my_pid {
            k.push(p); // true orphan — owned by no session
        }
    }
    k.sort_unstable();
    k.dedup();
    k
}

#[cfg(test)]
mod upgrade_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn upgrade_kill_set_is_session_scoped() {
        // owned: my daemon 100, sibling session daemon 200.
        let owned: HashSet<u32> = [100, 200].into_iter().collect();
        // found by the process scan: mine (100), sibling (200), a true orphan (999).
        let k = upgrade_kill_set(Some(100), &[100, 200, 999], &owned);
        assert!(k.contains(&100), "must kill my own daemon (to replace it)");
        assert!(k.contains(&999), "must sweep a true orphan");
        assert!(!k.contains(&200), "must SPARE a sibling session's daemon");

        // CRITICAL: even when the process scan returns EMPTY (Windows CIM can't
        // match the quoted command line), my own daemon is still killed via its
        // pidfile pid — this is the B-accumulation fix.
        assert_eq!(
            upgrade_kill_set(Some(100), &[], &owned),
            vec![100],
            "own daemon killed even when the process scan is empty"
        );

        // Uninitialized session (no own daemon): only true orphans.
        assert_eq!(upgrade_kill_set(None, &[999], &HashSet::new()), vec![999]);
    }
}

fn cmd_upgrade(check_only: bool, local: bool, as_json: bool) -> Result<()> {
    // 0. (v0.13.3 — merged `update`) ALWAYS check crates.io first and, unless
    // this is a --check or --local run, self-install a newer release BEFORE the
    // daemon swap below — the respawn then picks up the new on-disk binary. A
    // crates.io/network failure must NOT block the restart, so it degrades to a
    // warning. `--local` skips it entirely (offline / local dev build).
    let update: Option<UpdateOutcome> = if local {
        None
    } else {
        match self_update_step(!check_only) {
            Ok(o) => Some(o),
            Err(e) => {
                if !check_only {
                    eprintln!("wire upgrade: update check skipped — {e:#}");
                }
                None
            }
        }
    };
    if let Some(o) = &update
        && o.installed
    {
        eprintln!(
            "wire upgrade: installed {} (was {}, via {}); restarting the daemon on the new binary.",
            o.latest,
            o.current,
            o.via.unwrap_or("self-update")
        );
    }

    // 1. Identify all running wire processes. v0.7.3: walks `pgrep -f`
    // on unix / `Get-CimInstance Win32_Process` on Windows via the
    // shared `platform::find_processes_by_cmdline`. Covers both the
    // long-lived sync `wire daemon` *and* the `wire relay-server`
    // local-only loopback — the pre-v0.7.3 upgrade only swept daemons
    // and left stale relay-server children pinned on the old binary,
    // forcing operators to `pkill -f relay-server` manually after
    // every version bump.
    let daemon_pids: Vec<u32> = crate::platform::find_processes_by_cmdline("wire daemon");
    let relay_pids: Vec<u32> = crate::platform::find_processes_by_cmdline("wire relay-server");
    let running_pids: Vec<u32> = daemon_pids
        .iter()
        .chain(relay_pids.iter())
        .copied()
        .collect();

    // 2. Read pidfile to surface what the daemon THINKS it is.
    let record = crate::ensure_up::read_pid_record("daemon");
    let recorded_version: Option<String> = match &record {
        crate::ensure_up::PidRecord::Json(d) => Some(d.version.clone()),
        crate::ensure_up::PidRecord::LegacyInt(_) => Some("<pre-0.5.11>".to_string()),
        _ => None,
    };
    let cli_version = env!("CARGO_PKG_VERSION").to_string();

    // 2b. v0.13.2 (B fix — session-scoped upgrade). `wire upgrade` now
    // refreshes THIS session's daemon, not the whole box. The old box-wide
    // design (kill every `wire daemon` process, wipe every session's pidfile,
    // respawn every session) was wrong for a multi-session / shared-relay box
    // AND broke on Windows: the CIM scan can't match the quoted
    // `"...\wire.exe" daemon` command line (no contiguous `wire daemon`), so it
    // found nothing to kill, then the respawn loop ACCUMULATED daemons
    // (glossy-magnolia: 2->5->8->11). The kill set is now:
    //   (a) THIS session's own daemon, via its pidfile pid — reliable and
    //       CIM-independent; plus
    //   (b) TRUE orphans: `wire daemon` pids owned by NO session.
    // It SPARES sibling sessions' daemons AND the shared loopback relay-server
    // (killing it would break every same-box session's routing).
    let my_daemon_pid = record.pid();
    let owned_session_pids: std::collections::HashSet<u32> = crate::session::list_sessions()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| crate::session::session_daemon_pid(&s.home_dir))
        .collect();
    let kill_set = upgrade_kill_set(my_daemon_pid, &daemon_pids, &owned_session_pids);
    // relay_pids are intentionally NOT killed — the local relay is shared.

    if check_only {
        // v0.6.8: also surface session-level state + PATH dupes in --check.
        let sessions_with_daemons: Vec<String> = crate::session::list_sessions()
            .unwrap_or_default()
            .iter()
            .filter(|s| s.daemon_running)
            .map(|s| s.name.clone())
            .collect();
        let mut path_dupes: Vec<String> = Vec::new();
        if let Ok(path) = std::env::var("PATH") {
            let mut seen: std::collections::HashSet<std::path::PathBuf> =
                std::collections::HashSet::new();
            for dir in path.split(':') {
                let candidate = std::path::PathBuf::from(dir).join("wire");
                if candidate.exists() {
                    let canon = candidate.canonicalize().unwrap_or(candidate);
                    if seen.insert(canon.clone()) {
                        path_dupes.push(canon.to_string_lossy().into_owned());
                    }
                }
            }
        }
        // v0.7.3: enumerate which service units WOULD be refreshed.
        // Read-only — `status_kind` doesn't touch anything.
        let installed_service_kinds: Vec<&'static str> = [
            (crate::service::ServiceKind::Daemon, "daemon"),
            (crate::service::ServiceKind::LocalRelay, "local-relay"),
        ]
        .into_iter()
        .filter_map(|(k, label)| {
            crate::service::status_kind(k)
                .ok()
                .filter(|r| r.status != "absent")
                .map(|_| label)
        })
        .collect();
        let (update_latest, update_available) = match &update {
            Some(o) => (Some(o.latest.clone()), o.available),
            None => (None, false),
        };
        let report = json!({
            "running_pids": running_pids,
            "running_daemons": daemon_pids,
            "running_relay_servers": relay_pids,
            "pidfile_version": recorded_version,
            "cli_version": cli_version,
            "latest_published": update_latest,
            "update_available": update_available,
            "would_kill": kill_set,
            "would_refresh_services": installed_service_kinds,
            "session_daemons_running": sessions_with_daemons,
            "path_binaries": path_dupes,
            "path_duplicate_warning": path_dupes.len() > 1,
        });
        if as_json {
            println!("{}", serde_json::to_string(&report)?);
        } else {
            println!("wire upgrade --check");
            println!("  cli version:      {cli_version}");
            match (&update_latest, update_available) {
                (Some(l), true) => println!("  latest published: {l}  (UPDATE AVAILABLE)"),
                (Some(l), false) => println!("  latest published: {l}  (up to date)"),
                (None, _) => println!("  latest published: (crates.io check skipped)"),
            }
            println!(
                "  pidfile version:  {}",
                recorded_version.as_deref().unwrap_or("(missing)")
            );
            if running_pids.is_empty() {
                println!("  running daemons:  none");
                println!("  running relays:   none");
            } else {
                if daemon_pids.is_empty() {
                    println!("  running daemons:  none");
                } else {
                    let p: Vec<String> = daemon_pids.iter().map(|p| p.to_string()).collect();
                    println!("  running daemons:  pids {}", p.join(", "));
                }
                if relay_pids.is_empty() {
                    println!("  running relays:   none");
                } else {
                    let p: Vec<String> = relay_pids.iter().map(|p| p.to_string()).collect();
                    println!("  running relays:   pids {}", p.join(", "));
                }
                println!("  would kill all + spawn fresh");
            }
            if !installed_service_kinds.is_empty() {
                println!(
                    "  would refresh:    {} installed service unit(s) → new binary path",
                    installed_service_kinds.join(", ")
                );
            }
            if !sessions_with_daemons.is_empty() {
                println!(
                    "  session daemons:  {} (would respawn under new binary)",
                    sessions_with_daemons.join(", ")
                );
            }
            if path_dupes.len() > 1 {
                println!(
                    "  PATH warning:     {} distinct `wire` binaries on PATH:",
                    path_dupes.len()
                );
                for b in &path_dupes {
                    println!("                      {b}");
                }
                println!("                    operators should remove the stale ones");
            }
        }
        return Ok(());
    }

    // 3. Terminate the kill set. Graceful first, then FORCE-kill any survivor.
    //
    // v0.13.2 (B fix #2): the force-kill must NOT be gated on graceful having
    // "succeeded". On Windows, `taskkill /PID /T` WITHOUT `/F` is a no-op for a
    // windowless daemon (it returns failure), so the rc9 logic — which only
    // force-killed pids that graceful had reported killing — force-killed
    // NOTHING, and the daemon survived every `wire upgrade` (glossy: pidfile
    // pids 3676/25236/24660 all survived → accumulation). Now we attempt
    // graceful best-effort, grace-wait, then force-kill EVERY pid still alive
    // regardless of the graceful result. Force-kill (`taskkill /F /T` /
    // SIGKILL) is the load-bearing step.
    for pid in &kill_set {
        let _ = crate::platform::kill_process(*pid, false); // best-effort graceful
    }
    if !kill_set.is_empty() {
        // Brief grace for platforms where graceful works (Unix SIGTERM).
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
        while std::time::Instant::now() < deadline && kill_set.iter().any(|p| process_alive_pid(*p))
        {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // Force-kill every survivor — this is what actually kills the
        // windowless daemon on Windows.
        for pid in &kill_set {
            if process_alive_pid(*pid) {
                let _ = crate::platform::kill_process(*pid, true);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200)); // settle
    }
    // Report what's actually gone (drives the "no stale" message + JSON).
    let killed: Vec<u32> = kill_set
        .iter()
        .copied()
        .filter(|p| !process_alive_pid(*p))
        .collect();

    // 4. Remove stale pidfile so ensure_daemon_running doesn't think the
    //    old daemon is still owning it.
    let pidfile = config::state_dir()?.join("daemon.pid");
    if pidfile.exists() {
        let _ = std::fs::remove_file(&pidfile);
    }

    // 4b. v0.13.2: session-scoped — only THIS session's pidfile is wiped
    // (already removed at step 4 above). We deliberately DO NOT touch sibling
    // sessions' pidfiles: their daemons were spared, so wiping their pidfiles
    // would make them look down and the old box-wide respawn would spawn
    // duplicates (the accumulation bug). Each sibling refreshes itself on its
    // own `wire upgrade`.

    // 4c. v0.6.8 PATH duplicate-binary detection. If `wire` resolves to
    // multiple distinct files on $PATH, surface the conflict — operators
    // get bitten when an old binary at /usr/local/bin shadows a fresh
    // ~/.local/bin install (or vice versa). Warning only; no auto-fix.
    let mut path_dupes: Vec<String> = Vec::new();
    if let Ok(path) = std::env::var("PATH") {
        let mut seen: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        for dir in path.split(':') {
            let candidate = std::path::PathBuf::from(dir).join("wire");
            if candidate.exists() {
                let canon = candidate.canonicalize().unwrap_or(candidate);
                if seen.insert(canon.clone()) {
                    path_dupes.push(canon.to_string_lossy().into_owned());
                }
            }
        }
    }
    let path_warning = if path_dupes.len() > 1 {
        Some(format!(
            "WARN: {} distinct `wire` binaries on PATH — old versions can shadow the fresh install:\n  {}",
            path_dupes.len(),
            path_dupes.join("\n  ")
        ))
    } else {
        None
    };

    // 4d. v0.7.3 NEW: refresh installed service units so they point at
    // the freshly-installed binary path. Without this step, an upgrade
    // would: kill the old daemon, leave the launchd plist /
    // systemd unit / Windows scheduled task pointing at the OLD
    // binary path (or, worse, an old binary location that's been
    // unlinked), and then the OS's auto-respawn would either fail or
    // bring the OLD binary back from the dead. Reinstalling rewrites
    // the unit with `std::env::current_exe()` (the freshly-resolved
    // path of the running upgrade-driver process) and re-bootstraps /
    // re-enables / re-registers so the next OS-driven start uses it.
    //
    // Only refreshes units that are already installed — does NOT
    // install services the operator never opted into.
    let mut service_refreshes: Vec<Value> = Vec::new();
    for kind in [
        crate::service::ServiceKind::Daemon,
        crate::service::ServiceKind::LocalRelay,
    ] {
        let already_installed = crate::service::status_kind(kind)
            .map(|r| r.status != "absent")
            .unwrap_or(false);
        if !already_installed {
            continue;
        }
        match crate::service::install_kind(kind) {
            Ok(rep) => service_refreshes.push(json!({
                "kind": rep.kind,
                "platform": rep.platform,
                "status": rep.status,
                "unit_path": rep.unit_path,
                "action": "refreshed",
            })),
            Err(e) => service_refreshes.push(json!({
                "kind": format!("{kind:?}"),
                "action": "refresh_failed",
                "error": format!("{e:#}"),
            })),
        }
    }

    // 5. Spawn fresh daemon via ensure_up — atomically waits for
    //    process_alive + writes the versioned pidfile. (If the Daemon
    //    service was refreshed above, it has already started a fresh
    //    process under the new binary; ensure_daemon_running notices
    //    and short-circuits to "already running".)
    let spawned = crate::ensure_up::ensure_daemon_running()?;

    // 5b. v0.13.2: session-scoped — no sibling respawn. `ensure_daemon_running`
    // above already respawned THIS session's daemon; sibling sessions were
    // spared (never killed), so there is nothing to respawn for them. Each
    // refreshes itself on its own `wire upgrade`.
    let session_respawns: Vec<Value> = Vec::new();

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
                "found_daemons": daemon_pids,
                "spared_relay_servers": relay_pids,
                "service_refreshes": service_refreshes,
                "spawned_fresh_daemon": spawned,
                "new_pid": new_pid,
                "new_version": new_version,
                "cli_version": cli_version,
                "session_respawns": session_respawns,
                "path_binaries": path_dupes,
                "path_warning": path_warning,
            }))?
        );
    } else {
        if killed.is_empty() {
            println!("wire upgrade: no stale wire processes running");
        } else {
            let killed_list = killed
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            // Session-scoped: report what was actually killed, and that the
            // shared relay-server was SPARED (not killed) — the old wording
            // lumped the spared relay into the killed count and read like it
            // had been terminated (glossy-magnolia nit).
            if relay_pids.is_empty() {
                println!(
                    "wire upgrade: killed {} daemon(s) [{killed_list}]",
                    killed.len()
                );
            } else {
                let relay_list = relay_pids
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "wire upgrade: killed {} daemon(s) [{killed_list}]; spared {} shared relay-server(s) [{relay_list}]",
                    killed.len(),
                    relay_pids.len()
                );
            }
        }
        if !service_refreshes.is_empty() {
            println!(
                "wire upgrade: refreshed {} installed service unit(s) to point at the new binary:",
                service_refreshes.len()
            );
            for r in &service_refreshes {
                let kind = r.get("kind").and_then(Value::as_str).unwrap_or("?");
                let action = r.get("action").and_then(Value::as_str).unwrap_or("?");
                let status = r.get("status").and_then(Value::as_str).unwrap_or("");
                let platform = r.get("platform").and_then(Value::as_str).unwrap_or("");
                if action == "refreshed" {
                    println!("                    - {kind}: {action} ({status}, {platform})");
                } else {
                    let err = r.get("error").and_then(Value::as_str).unwrap_or("");
                    println!("                    - {kind}: {action} ({err})");
                }
            }
        }
        if spawned {
            println!(
                "wire upgrade: spawned fresh daemon (pid {} v{})",
                new_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                new_version.as_deref().unwrap_or(&cli_version),
            );
        } else {
            println!("wire upgrade: daemon was already running on current binary");
        }
        if !session_respawns.is_empty() {
            println!(
                "wire upgrade: refreshed {} session daemon(s):",
                session_respawns.len()
            );
            for r in &session_respawns {
                let h = r["session_home"].as_str().unwrap_or("?");
                let s = r["status"].as_str().unwrap_or("?");
                let label = std::path::Path::new(h)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_else(|| h.to_string());
                println!("  {label:<24} {s}");
            }
        }
        if let Some(msg) = &path_warning {
            eprintln!("wire upgrade: {msg}");
        }
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

fn process_alive_pid(pid: u32) -> bool {
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

/// Collect every name that `resolve_name_to_target` would currently
/// match: pinned-peer handles, pinned-peer character nicknames, sister
/// session names, sister character nicknames, sister handles. Used for
/// the `did_you_mean` pool on resolution miss.
fn known_local_names() -> Vec<String> {
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

/// v0.9.2 deprecation banner with two ergonomic guards:
/// 1. Suppress in JSON mode (the caller is expected to fold the
///    deprecation note into its JSON output instead).
/// 2. Cache once-per-shell-session via a marker env var; subsequent
///    invocations in the same shell stay silent.
///
/// `verb` is the legacy verb name, `replacement` is the canonical one.
fn deprecation_warn(verb: &str, replacement: &str, json_mode: bool) {
    if json_mode {
        return;
    }
    // Pull a marker from environment of THIS process. Persistent across
    // multiple wire invocations only when the shell sets and exports
    // WIRE_DEPRECATION_NAGGED — operators rarely do, so practically
    // this nags once per `wire foo` invocation. The single-process
    // dedup matters most for scripts that call multiple deprecated
    // verbs in one wire run, which is currently impossible (one verb
    // per process) but documented for future loop-style wire shells.
    let key = format!("WIRE_DEPRECATION_NAGGED_{}", verb.replace('-', "_"));
    if std::env::var(&key).is_ok() {
        return;
    }
    // SAFETY: deprecation_warn is called from sync dispatcher code paths
    // before any worker thread spawns; env::set_var in Rust 2024 is
    // safe at that point. Pattern matches maybe_adopt_session_wire_home.
    unsafe {
        std::env::set_var(&key, "1");
    }
    eprintln!(
        "wire {verb}: DEPRECATED in v0.9 — use `wire {replacement}`. \
         Will be removed in v1.0 (target 2026-Q3). \
         Suppress: set WIRE_DEPRECATION_NAGGED_{}=1.",
        verb.replace('-', "_")
    );
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
    let checks: Vec<DoctorCheck> = vec![
        check_daemon_health(),
        check_daemon_pid_consistency(),
        check_relay_reachable(),
        check_pair_rejections(recent_rejections),
        check_cursor_progress(),
    ];

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
    // `wire status` reported DOWN, disagreeing for 25 min. v0.5.19 (#2
    // hardening): every surface routes through ensure_up::daemon_liveness
    // so they share one view of the world. No more parallel liveness
    // logic to drift out of sync.
    let snap = crate::ensure_up::daemon_liveness();
    let pgrep_pids = &snap.pgrep_pids;
    let pidfile_pid = snap.pidfile_pid;
    let pidfile_alive = snap.pidfile_alive;
    let orphan_pids = &snap.orphan_pids;

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
                fmt_pids(pgrep_pids),
                pidfile_pid.unwrap(),
                fmt_pids(orphan_pids),
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
                fmt_pids(pgrep_pids),
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
                fmt_pids(pgrep_pids)
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
///
/// v0.5.19 (#2 hardening): also surfaces stale pidfiles — a well-formed
/// JSON pid record whose recorded `pid` is no longer a live OS process.
/// Pre-hardening this check PASSed in that state (it only validated
/// content, not liveness), letting `wire status: DOWN` and
/// `wire doctor: PASS` disagree for 25 min in incident #2.
fn check_daemon_pid_consistency() -> DoctorCheck {
    let snap = crate::ensure_up::daemon_liveness();
    match &snap.record {
        crate::ensure_up::PidRecord::Missing => DoctorCheck::pass(
            "daemon_pid_consistency",
            "no daemon.pid yet — fresh box or daemon never started",
        ),
        crate::ensure_up::PidRecord::Corrupt(reason) => DoctorCheck::warn(
            "daemon_pid_consistency",
            format!("daemon.pid is corrupt: {reason}"),
            "delete state/wire/daemon.pid; next `wire daemon &` will rewrite",
        ),
        crate::ensure_up::PidRecord::LegacyInt(pid) => {
            // Legacy pidfile: still surface liveness so a dead legacy pid
            // doesn't quietly PASS this check while status says DOWN.
            let pid = *pid;
            if !crate::ensure_up::pid_is_alive(pid) {
                return DoctorCheck::warn(
                    "daemon_pid_consistency",
                    format!(
                        "daemon.pid (legacy-int) points at pid {pid} which is not running. \
                         Stale pidfile from a crashed pre-0.5.11 daemon. \
                         (Issue #2: this surface used to PASS while `wire status` said DOWN.)"
                    ),
                    "`wire upgrade` (kills any orphan + spawns a fresh daemon with JSON pidfile)",
                );
            }
            DoctorCheck::warn(
                "daemon_pid_consistency",
                format!(
                    "daemon.pid is legacy-int form (pid={pid}, no version/bin_path metadata). \
                     Daemon was started by a pre-0.5.11 binary."
                ),
                "run `wire upgrade` to kill the old daemon and start a fresh one with the JSON pidfile",
            )
        }
        crate::ensure_up::PidRecord::Json(d) => {
            // v0.5.19 liveness gate: if the recorded pid is dead, the
            // pidfile is stale and the rest of the content drift checks
            // are moot — `wire upgrade` is the answer regardless.
            if !snap.pidfile_alive {
                return DoctorCheck::warn(
                    "daemon_pid_consistency",
                    format!(
                        "daemon.pid records pid {pid} (v{version}) but that process is not running — \
                         pidfile is stale. `wire status` will report DOWN, but pre-v0.5.19 doctor \
                         silently PASSed this state and ignored any live orphan daemons (#2 root cause).",
                        pid = d.pid,
                        version = d.version,
                    ),
                    "`wire upgrade` to clean up the stale pidfile + spawn a fresh daemon \
                     (kills any orphan daemon advancing the cursor without coordination)",
                );
            }
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
                issues.push(format!("version daemon={} cli={cli_version}", d.version));
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
        Err(e) => {
            return DoctorCheck::fail(
                "relay",
                format!("could not read relay state: {e}"),
                "run `wire up <handle>@<relay>` to bootstrap",
            );
        }
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
        Err(e) => {
            return DoctorCheck::warn(
                "pair_rejections",
                format!("could not resolve state dir: {e}"),
                "set WIRE_HOME or fix XDG_STATE_HOME",
            );
        }
    };
    if !path.exists() {
        return DoctorCheck::pass(
            "pair_rejections",
            "no pair-rejected.jsonl — no recorded pair failures",
        );
    }
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) => {
            return DoctorCheck::warn(
                "pair_rejections",
                format!("could not read {path:?}: {e}"),
                "check file permissions",
            );
        }
    };
    let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return DoctorCheck::pass("pair_rejections", "pair-rejected.jsonl present but empty");
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
        Err(e) => {
            return DoctorCheck::warn(
                "cursor",
                format!("could not read relay state: {e}"),
                "check ~/Library/Application Support/wire/relay.json",
            );
        }
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
///   - `<nick>`              — defaults to wireup.net (the configured
///     public relay)
fn cmd_up(
    relay_arg: Option<&str>,
    name: Option<&str>,
    with_local: Option<&str>,
    no_local: bool,
    as_json: bool,
) -> Result<()> {
    // No nick to parse — your handle is your DID-derived persona (one-name
    // rule). The optional arg is only which relay to bind/claim on. Accepts
    // `@host`, bare `host`, or a full URL; defaults to the public relay.
    let relay_url = match relay_arg {
        Some(r) => {
            let r = r.trim_start_matches('@');
            if r.starts_with("http://") || r.starts_with("https://") {
                r.to_string()
            } else {
                format!("https://{r}")
            }
        }
        None => crate::pair_invite::DEFAULT_RELAY.to_string(),
    };

    // Strip any URL userinfo (`<handle>@<host>`) before doing any state-
    // mutating work — otherwise the malformed endpoint gets persisted in
    // `relay_state` AND published in the signed agent-card, where every
    // inbound POST to it 4xxes. Mirrors `cmd_up`'s already-bound branch,
    // which has always ignored the userinfo on the "keeping existing
    // binding" warning path.
    let relay_url = strip_relay_url_userinfo(&relay_url);

    let mut report: Vec<(String, String)> = Vec::new();
    let mut step = |stage: &str, detail: String| {
        report.push((stage.to_string(), detail.clone()));
        if !as_json {
            eprintln!("wire up: {stage} — {detail}");
        }
    };

    // 1. init (or note existing identity). No typed name — cmd_init(None)
    // generates the persona from the freshly-minted keypair (one-name rule).
    if config::is_initialized()? {
        step("init", "already initialized".to_string());
    } else {
        cmd_init(
            None,
            name,
            Some(&relay_url),
            false,
            /* as_json */ false,
        )?;
        step("init", format!("created identity bound to {relay_url}"));
    }

    // Canonical persona handle — the one name we claim and are addressed by.
    let canonical = {
        let card = config::read_agent_card()?;
        let did = card.get("did").and_then(Value::as_str).unwrap_or("");
        crate::agent_card::display_handle_from_did(did).to_string()
    };
    step("identity", format!("persona is `{canonical}`"));

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
        // Fresh box (no pinned peers yet) — migrate_pinned irrelevant.
        // Pass `false` so the safety check kicks in if state was non-empty.
        cmd_bind_relay(
            &relay_url, /* scope */ None, // infer from URL (federation for wireup.net)
            /* replace */ false, /* migrate_pinned */ false, /* as_json */ false,
        )?;
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
    match cmd_claim(
        &canonical,
        Some(&relay_url),
        None,
        /* hidden */ false,
        /* as_json */ false,
    ) {
        Ok(()) => step(
            "claim",
            format!("{canonical}@{} claimed", strip_proto(&relay_url)),
        ),
        Err(e) => step(
            "claim",
            format!("WARNING: claim failed: {e}. You can retry `wire claim {canonical}`."),
        ),
    }

    // 3b. Opportunistic local dual-slot (additive). Gives same-box sister
    // sessions sub-millisecond loopback routing alongside the federation
    // slot. Local relays carry no handle directory — nothing to claim
    // there; sister discovery is via `wire session list-local`.
    if no_local {
        step("local-slot", "skipped (--no-local)".to_string());
    } else {
        let local_url = with_local
            .unwrap_or("http://127.0.0.1:8771")
            .trim_end_matches('/');
        let already_local = crate::endpoints::self_endpoints(
            &config::read_relay_state().unwrap_or_else(|_| json!({})),
        )
        .iter()
        .any(|e| e.relay_url == local_url);
        if relay_url.trim_end_matches('/') == local_url || already_local {
            step("local-slot", "already covered".to_string());
        } else if crate::relay_client::RelayClient::new(local_url)
            .check_healthz()
            .is_ok()
        {
            match cmd_bind_relay(
                local_url,
                Some("local"),
                /* replace */ false,
                /* migrate_pinned */ false,
                /* as_json */ false,
            ) {
                Ok(()) => step(
                    "local-slot",
                    format!("dual-bound local relay {local_url} for sister routing"),
                ),
                Err(e) => step("local-slot", format!("skipped local relay: {e}")),
            }
        } else {
            step(
                "local-slot",
                format!(
                    "no local relay reachable at {local_url} — federation only \
                     (sisters resolve via session-list)"
                ),
            );
        }
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
    let summary =
        "ready. `wire pair <peer>@<relay>` to pair, `wire send <peer> \"<msg>\"` to send, \
         `wire monitor` to watch incoming events."
            .to_string();
    step("ready", summary.clone());

    if as_json {
        let steps_json: Vec<_> = report
            .iter()
            .map(|(k, v)| json!({"stage": k, "detail": v}))
            .collect();
        println!(
            "{}",
            serde_json::to_string(&json!({
                "nick": canonical,
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

/// Strip URL userinfo (`https://<userinfo>@<host>...`) from a relay URL,
/// warning to stderr if any was stripped. Returns the cleaned URL.
///
/// Bug 1 this fixes: `wire up <handle>@<relay>` and `wire bind-relay
/// <handle>@<relay>` previously prepended `https://` to the literal arg,
/// recording and publishing the endpoint as `https://<handle>@<relay>` —
/// handle parsed as URL userinfo. Every inbound event POST to that
/// endpoint (pair_drop_ack, messages) gets a 4xx (Cloudflare 400 on
/// wireup.net) because the upstream rejects the userinfo on plain
/// GETs/POSTs. Bilateral pairing can't complete; messages sit
/// undelivered. Also surfaced cosmetically (Bug 3) as a doubled-handle
/// echo at the claim step (`<nick>@<nick>@<host>`) because `strip_proto`
/// left the userinfo in.
///
/// Behavior: strip-and-warn rather than hard-reject. In v0.11+ the handle
/// is DID-derived (one-name rule), so the userinfo isn't *needed* — but
/// `<handle>@<relay>` is literally the wire dial-address format
/// (`wire dial coral-weasel@wireup.net`), so an operator who types
/// `wire up <handle>@<relay>` is making a natural-by-analogy mistake, not
/// a hostile request. Mirrors `cmd_up`'s already-bound branch, which has
/// always ignored the userinfo prefix when keeping an existing clean
/// slot. The hard invariant either way: a userinfo-bearing URL must
/// never reach `self.endpoints[]` or the published agent-card.
fn strip_relay_url_userinfo(url: &str) -> String {
    // Locate the authority segment: everything after `://` (or the whole
    // string if there is no scheme yet), up to the first `/`, `?`, or `#`.
    let authority_start = url.find("://").map(|i| i + 3).unwrap_or(0);
    let rest = &url[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];

    let Some(at_pos) = authority.find('@') else {
        return url.to_string();
    };

    let userinfo = &authority[..at_pos];
    let host = &authority[at_pos + 1..];
    let scheme = &url[..authority_start];
    let tail = &rest[authority_end..];
    let cleaned = format!("{scheme}{host}{tail}");

    eprintln!(
        "wire: ignoring `{userinfo}@` prefix on relay URL `{url}` — \
         in v0.11+ your handle is DID-derived (one-name rule), so the relay URL \
         is just the bare relay. Binding to `{cleaned}` instead."
    );

    cleaned
}

/// Hard assertion that a URL about to be persisted to `relay_state` /
/// published in the signed agent-card carries no userinfo. The
/// `strip_relay_url_userinfo` filter at every public entry point already
/// removes it; this is the belt-and-suspenders check at the actual mutation
/// site — a future code path that bypasses the entry filter must NOT be
/// able to leak a malformed endpoint into a signed card or the persisted
/// relay state.
fn assert_relay_url_clean_for_publish(url: &str) -> Result<()> {
    let authority_start = url.find("://").map(|i| i + 3).unwrap_or(0);
    let rest = &url[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains('@') {
        bail!(
            "internal invariant violated: relay URL `{url}` still carries userinfo at \
             the persist/publish boundary — `strip_relay_url_userinfo` must be called \
             before this point. Refusing to publish a malformed endpoint."
        );
    }
    Ok(())
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
    cmd_add(
        handle_arg,
        relay_override,
        /* local_sister */ false,
        /* as_json */ false,
    )?;

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
                if pinned_in_trust {
                    "VERIFIED"
                } else {
                    "MISSING (bug)"
                }
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
        ProfileAction::Get { json } => return cmd_whois(None, json, None),
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

// ---------- setup — one-shot MCP host registration ----------

fn cmd_setup(apply: bool) -> Result<()> {
    use std::path::PathBuf;

    // The `env` mapping forwards Claude Code's per-session id into the MCP
    // server. CRITICAL for per-session identity: the MCP server process does
    // NOT inherit CLAUDE_CODE_SESSION_ID (Claude Code sets it for Bash-tool
    // subprocesses only), and the MCP `initialize` handshake carries no session
    // id — so without this, the server can't tell sessions apart, falls back to
    // cwd-detection, and every Claude session under a shared parent dir
    // collapses onto ONE identity. Claude Code expands `${CLAUDE_CODE_SESSION_ID}`
    // from its own env at MCP launch; wire's `resolve_session_key` reads
    // WIRE_SESSION_ID first, so each session becomes its own `by-key/<hash>`.
    let entry = json!({
        "command": "wire",
        "args": ["mcp"],
        "env": {"WIRE_SESSION_ID": "${CLAUDE_CODE_SESSION_ID}"}
    });
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

        // GitHub Copilot (VS Code) — User settings
        #[cfg(target_os = "macos")]
        targets.push((
            "VS Code (GitHub Copilot)",
            home.join("Library/Application Support/Code/User/settings.json"),
        ));
        #[cfg(target_os = "linux")]
        targets.push((
            "VS Code (GitHub Copilot)",
            home.join(".config/Code/User/settings.json"),
        ));
        #[cfg(target_os = "windows")]
        if let Ok(appdata) = std::env::var("APPDATA") {
            targets.push((
                "VS Code (GitHub Copilot)",
                PathBuf::from(appdata).join("Code/User/settings.json"),
            ));
        }

        // VS Code Insiders variant
        #[cfg(target_os = "macos")]
        targets.push((
            "VS Code Insiders",
            home.join("Library/Application Support/Code - Insiders/User/settings.json"),
        ));
        #[cfg(target_os = "linux")]
        targets.push((
            "VS Code Insiders",
            home.join(".config/Code - Insiders/User/settings.json"),
        ));
        #[cfg(target_os = "windows")]
        if let Ok(appdata) = std::env::var("APPDATA") {
            targets.push((
                "VS Code Insiders",
                PathBuf::from(appdata).join("Code - Insiders/User/settings.json"),
            ));
        }
    }
    // Workspace-local VS Code settings (GitHub Copilot workspace config)
    targets.push((
        "VS Code (workspace)",
        PathBuf::from(".vscode/settings.json"),
    ));
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
///
/// Supports two config formats:
/// - Standard MCP: `{"mcpServers": {"wire": {...}}}`
/// - VS Code: `{"mcp": {"servers": {"wire": {...}}}}`
fn upsert_mcp_entry(path: &std::path::Path, server_name: &str, entry: &Value) -> Result<bool> {
    let mut cfg: Value = if path.exists() {
        let body = std::fs::read_to_string(path).context("reading config")?;
        if body.trim().is_empty() {
            json!({})
        } else {
            // Refuse to default a non-empty-but-unparseable file to `{}` —
            // doing so would overwrite the whole file with just our entry.
            // VS Code's settings.json is JSONC (// comments, trailing commas)
            // which serde_json can't parse; surface it so the caller lists
            // this target under "Skipped" and the user adds wire manually.
            serde_json::from_str(&body).with_context(|| {
                format!(
                    "{} is not strict JSON (comments / trailing commas?); \
                     add the wire MCP entry manually to avoid overwriting it",
                    path.display()
                )
            })?
        }
    } else {
        json!({})
    };
    if !cfg.is_object() {
        cfg = json!({});
    }

    // Detect VS Code settings.json (contains "mcp.servers" instead of "mcpServers")
    let is_vscode = path.to_string_lossy().contains("Code/User/settings.json")
        || path.to_string_lossy().contains(".vscode/settings.json")
        || path.to_string_lossy().contains("Code - Insiders");

    let root = cfg.as_object_mut().unwrap();

    if is_vscode {
        // VS Code format: {"mcp": {"servers": {"wire": {...}}}}
        let mcp = root.entry("mcp".to_string()).or_insert_with(|| json!({}));
        if !mcp.is_object() {
            *mcp = json!({});
        }
        let mcp_obj = mcp.as_object_mut().unwrap();
        let servers = mcp_obj
            .entry("servers".to_string())
            .or_insert_with(|| json!({}));
        if !servers.is_object() {
            *servers = json!({});
        }
        let map = servers.as_object_mut().unwrap();
        if map.get(server_name) == Some(entry) {
            return Ok(false);
        }
        map.insert(server_name.to_string(), entry.clone());
    } else {
        // Standard MCP format: {"mcpServers": {"wire": {...}}}
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
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).context("creating parent dir")?;
    }
    let out = serde_json::to_string_pretty(&cfg)? + "\n";
    std::fs::write(path, out).context("writing config")?;
    Ok(true)
}

// ---------- setup --statusline ----------

/// Bundled Claude Code statusLine renderer (persona emoji + nickname + cwd,
/// pidfile+tasklist liveness). Embedded at compile time; written to the
/// Claude config dir on `wire setup --statusline --apply`.
const STATUSLINE_RENDERER: &str = include_str!("../assets/wire-statusline.sh");

/// `wire setup --statusline [--apply] [--remove]` — install/remove a Claude
/// Code statusLine that renders this session's wire persona. Honors
/// `$CLAUDE_CONFIG_DIR` (default `~/.claude`). Writes the renderer script and
/// merges a `statusLine` block into settings.json, preserving existing keys
/// and refusing to clobber a settings.json that exists but isn't valid JSON.
fn cmd_setup_statusline(apply: bool, remove: bool) -> Result<()> {
    use std::path::PathBuf;
    let cfg_dir: PathBuf = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".claude")))
        .ok_or_else(|| anyhow!("cannot locate Claude config dir (set $CLAUDE_CONFIG_DIR)"))?;
    let settings_path = cfg_dir.join("settings.json");
    let script_path = cfg_dir.join("wire-statusline.sh");
    // Resolve the shell invocation. On Windows a bare `bash` resolves to
    // System32\bash.exe (WSL) — wrong environment, Windows paths invalid,
    // statusline breaks — so we emit the absolute git-bash path. On Unix a
    // bare `bash <script>` is correct. Script path is quoted for spaces.
    let (command, command_warn) = statusline_command(&script_path);

    println!("wire setup --statusline\n");
    println!("Claude config dir: {}", cfg_dir.display());
    println!("  renderer:  {}", script_path.display());
    println!("  settings:  {}", settings_path.display());
    if let Some(w) = &command_warn {
        println!("  ⚠ {w}");
    }
    println!();

    if remove {
        if !apply {
            println!("Would REMOVE the statusLine key from settings.json and delete the renderer.");
            println!("Run `wire setup --statusline --remove --apply` to do it.");
            return Ok(());
        }
        let dropped = remove_statusline_entry(&settings_path)?;
        let script_gone = if script_path.exists() {
            std::fs::remove_file(&script_path).is_ok()
        } else {
            false
        };
        println!(
            "Removed: statusLine key {} · renderer {}",
            if dropped { "dropped" } else { "absent" },
            if script_gone { "deleted" } else { "absent" }
        );
        return Ok(());
    }

    if !apply {
        println!("Would write the renderer above and merge into settings.json:");
        println!();
        println!("  \"statusLine\": {{ \"type\": \"command\", \"command\": \"{command}\" }}");
        println!();
        println!("Resulting statusline:  ● <emoji> <nickname> · <cwd>");
        println!("Run `wire setup --statusline --apply` to install.");
        println!("(Existing settings.json keys are preserved; an invalid settings.json aborts.)");
        return Ok(());
    }

    if let Some(parent) = script_path.parent() {
        std::fs::create_dir_all(parent).context("creating Claude config dir")?;
    }
    std::fs::write(&script_path, STATUSLINE_RENDERER).context("writing renderer script")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&script_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&script_path, perms);
        }
    }
    let changed = upsert_statusline_entry(&settings_path, &command)?;
    println!("✓ renderer written: {}", script_path.display());
    if changed {
        println!("✓ merged statusLine into: {}", settings_path.display());
    } else {
        println!(
            "  settings.json already configured: {}",
            settings_path.display()
        );
    }
    println!();
    println!("Restart Claude Code (or reopen the session) to see your persona in the statusline.");
    Ok(())
}

/// Merge a `statusLine` command block into a Claude settings.json, preserving
/// all other keys. Returns Ok(true) if changed. Refuses to clobber a file that
/// exists but is not valid JSON.
fn upsert_statusline_entry(path: &std::path::Path, command: &str) -> Result<bool> {
    let mut cfg: Value = if path.exists() {
        let body = std::fs::read_to_string(path).context("reading settings.json")?;
        if body.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&body).context(
                "settings.json exists but is not valid JSON — refusing to clobber; fix or remove it first",
            )?
        }
    } else {
        json!({})
    };
    if !cfg.is_object() {
        bail!("settings.json root is not a JSON object — refusing to clobber");
    }
    let desired = json!({"type": "command", "command": command});
    let root = cfg.as_object_mut().unwrap();
    if root.get("statusLine") == Some(&desired) {
        return Ok(false);
    }
    root.insert("statusLine".to_string(), desired);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).context("creating parent dir")?;
    }
    let out = serde_json::to_string_pretty(&cfg)? + "\n";
    std::fs::write(path, out).context("writing settings.json")?;
    Ok(true)
}

/// Drop the `statusLine` key from settings.json. Ok(true) if a key was removed,
/// Ok(false) if file/key absent. Refuses to edit invalid JSON.
fn remove_statusline_entry(path: &std::path::Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let body = std::fs::read_to_string(path).context("reading settings.json")?;
    if body.trim().is_empty() {
        return Ok(false);
    }
    let mut cfg: Value = serde_json::from_str(&body)
        .context("settings.json is not valid JSON — refusing to edit")?;
    let Some(root) = cfg.as_object_mut() else {
        return Ok(false);
    };
    if root.remove("statusLine").is_none() {
        return Ok(false);
    }
    let out = serde_json::to_string_pretty(&cfg)? + "\n";
    std::fs::write(path, out).context("writing settings.json")?;
    Ok(true)
}

/// Build the `statusLine.command` string for this platform. Returns the
/// command plus an optional warning to surface to the operator.
fn statusline_command(script_path: &std::path::Path) -> (String, Option<String>) {
    #[cfg(windows)]
    {
        match resolve_git_bash() {
            Some(bash) => (format!("\"{}\" \"{}\"", bash, script_path.display()), None),
            None => (
                format!("bash \"{}\"", script_path.display()),
                Some(
                    "could not locate git-bash; using bare `bash`. On Windows that may resolve to \
                     WSL (System32\\bash.exe) and the statusline will be blank — install Git for \
                     Windows or set statusLine.command to your git-bash bash.exe path."
                        .to_string(),
                ),
            ),
        }
    }
    #[cfg(unix)]
    {
        (format!("bash \"{}\"", script_path.display()), None)
    }
}

/// Locate the git-bash `bash.exe` on Windows, avoiding the WSL launcher at
/// `System32\bash.exe`. Claude Code's statusLine command needs the real
/// git-bash so the renderer runs in a POSIX-ish env with valid paths.
#[cfg(windows)]
fn resolve_git_bash() -> Option<String> {
    use std::path::PathBuf;
    // 1. `where.exe bash` — take the first hit that is NOT under System32
    //    (that one is the WSL `bash.exe` launcher).
    if let Ok(out) = std::process::Command::new("where.exe").arg("bash").output()
        && out.status.success()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let p = line.trim();
            if !p.is_empty() && !p.to_lowercase().contains("\\system32\\") {
                return Some(p.to_string());
            }
        }
    }
    // 2. Common Git-for-Windows install locations.
    let candidates = [
        std::env::var("ProgramFiles")
            .ok()
            .map(|p| format!("{p}\\Git\\bin\\bash.exe")),
        std::env::var("ProgramFiles(x86)")
            .ok()
            .map(|p| format!("{p}\\Git\\bin\\bash.exe")),
        std::env::var("LocalAppData")
            .ok()
            .map(|p| format!("{p}\\Programs\\Git\\bin\\bash.exe")),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|c| PathBuf::from(c).exists())
}

#[cfg(test)]
mod statusline_tests {
    use super::*;

    #[test]
    fn statusline_merge_preserves_keys_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"theme":"dark","model":"opus"}"#).unwrap();
        // First merge changes the file but keeps existing keys.
        assert!(upsert_statusline_entry(&path, "bash /x.sh").unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["model"], "opus");
        assert_eq!(v["statusLine"]["type"], "command");
        assert_eq!(v["statusLine"]["command"], "bash /x.sh");
        // Identical re-merge = no change.
        assert!(!upsert_statusline_entry(&path, "bash /x.sh").unwrap());
        // Remove drops ONLY statusLine.
        assert!(remove_statusline_entry(&path).unwrap());
        let v2: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v2["theme"], "dark");
        assert!(v2.get("statusLine").is_none());
        // Remove again = no-op.
        assert!(!remove_statusline_entry(&path).unwrap());
    }

    #[test]
    fn statusline_merge_refuses_to_clobber_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "this is not json {").unwrap();
        let err = upsert_statusline_entry(&path, "bash /x.sh").unwrap_err();
        assert!(
            format!("{err:#}").contains("not valid JSON"),
            "err: {err:#}"
        );
        // File left untouched.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "this is not json {"
        );
    }

    #[test]
    fn statusline_creates_settings_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        assert!(upsert_statusline_entry(&path, "bash /x.sh").unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["statusLine"]["command"], "bash /x.sh");
    }
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
    let who = persona_label(&ev.peer);
    let title = if ev.verified {
        format!("wire ← {who}")
    } else {
        format!("wire ← {who} (UNVERIFIED)")
    };
    let body = format!("{}: {}", ev.kind, ev.body_preview);
    crate::os_notify::toast(&title, &body);
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn os_toast(title: &str, body: &str) {
    eprintln!("[wire notify] {title}\n  {body}");
}

// Integration tests for the CLI live in `tests/cli.rs` (cargo's tests/ dir).

#[cfg(test)]
mod relay_url_tests {
    use super::*;

    #[test]
    fn strip_relay_url_userinfo_strips_handle_and_returns_cleaned() {
        // Bug 1: `wire up <handle>@<relay>` and `wire bind-relay
        // <handle>@<relay>` previously persisted/published the endpoint as
        // `https://<handle>@<relay>` — handle stuck in URL userinfo. Every
        // inbound event POST to that endpoint 4xxed (Cloudflare 400 on
        // wireup.net); bilateral pairing couldn't complete.
        //
        // Strip+warn (not hard-reject): mirrors cmd_up's already-bound
        // branch, which has always ignored the userinfo on the "keeping
        // existing binding" warning path. `<handle>@<relay>` is also
        // literally the wire dial-address format — natural by analogy.

        assert_eq!(
            strip_relay_url_userinfo("https://copilot-agent@wireup.net"),
            "https://wireup.net",
            "https URL with handle userinfo is stripped to the bare host"
        );
        assert_eq!(
            strip_relay_url_userinfo("http://copilot-agent@127.0.0.1:8771"),
            "http://127.0.0.1:8771",
            "http + port + userinfo is stripped, port preserved"
        );
        // user:password@host — both halves of userinfo are dropped.
        assert_eq!(strip_relay_url_userinfo("https://u:p@host"), "https://host");
        // Authority with port + userinfo.
        assert_eq!(
            strip_relay_url_userinfo("https://nick@host:8443"),
            "https://host:8443"
        );
        // Schemeless `<handle>@<host>` — strips correctly. (cmd_up's
        // bare-host normalize prepends https:// before calling, but the
        // function is robust to either input.)
        assert_eq!(strip_relay_url_userinfo("nick@wireup.net"), "wireup.net");
        // Path / query / fragment AFTER the authority are preserved.
        assert_eq!(
            strip_relay_url_userinfo("https://nick@wireup.net/v1/events?x=1#frag"),
            "https://wireup.net/v1/events?x=1#frag"
        );
    }

    #[test]
    fn strip_relay_url_userinfo_passes_clean_urls_through_unchanged() {
        // Bare host (https / http, with and without port, with path / query).
        for ok in [
            "https://wireup.net",
            "http://wireup.net",
            "http://127.0.0.1:8771",
            "https://relay.example.com:9443/v1/wire",
            "https://wireup.net/?env=prod",
            // Path / query containing `@` is fine — it's not in the authority.
            "https://wireup.net/users/me@example.com",
            "https://wireup.net/?to=me@example.com",
            // Fragment with @ — fine.
            "https://wireup.net/#contact@me",
            // IPv6 literal (no @ in authority).
            "http://[::1]:8771",
            // Schemeless bare host — also fine.
            "wireup.net",
            "wireup.net:8443",
        ] {
            assert_eq!(
                strip_relay_url_userinfo(ok),
                ok,
                "clean URL `{ok}` must pass through unchanged"
            );
        }
    }

    #[test]
    fn assert_relay_url_clean_for_publish_blocks_userinfo_at_persist_site() {
        // Belt-and-suspenders: even if a future code path bypasses
        // strip_relay_url_userinfo at the entry, the persist/publish
        // boundary must refuse a userinfo URL. This is the second line
        // of defense that keeps a malformed endpoint out of the SIGNED
        // agent-card and the persisted relay_state.
        assert!(assert_relay_url_clean_for_publish("https://wireup.net").is_ok());
        assert!(assert_relay_url_clean_for_publish("http://127.0.0.1:8771").is_ok());
        assert!(
            assert_relay_url_clean_for_publish("https://wireup.net/?to=me@example.com").is_ok()
        );

        let err = assert_relay_url_clean_for_publish("https://nick@wireup.net")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("invariant violated"),
            "persist-site failure must be flagged as an internal invariant violation, not user error: {err}"
        );
        assert!(
            err.contains("strip_relay_url_userinfo"),
            "error must name the upstream filter so the caller can audit the bypass: {err}"
        );
        // user:password@host is just as bad — userinfo is userinfo.
        assert!(assert_relay_url_clean_for_publish("https://u:p@host").is_err());
        // Authority with port + userinfo.
        assert!(assert_relay_url_clean_for_publish("https://nick@host:8443").is_err());
    }

    #[test]
    fn strip_proto_no_longer_doubles_handle_after_userinfo_fix() {
        // Bug 3 (cosmetic): `wire up <handle>@<relay>` echoed `claimed
        // <nick>@<nick>@<relay>` because strip_proto left the userinfo in.
        // With Bug 1's strip+warn in cmd_up, the claim step receives a
        // bare host — strip_proto returns `<host>` and the echo is
        // `<nick>@<host>` exactly once. Verified end-to-end here:
        let after_strip = strip_relay_url_userinfo("https://nick@wireup.net");
        assert_eq!(after_strip, "https://wireup.net");
        assert_eq!(strip_proto(&after_strip), "wireup.net");
        // And the doubled-echo failure mode that motivated the fix:
        assert!(
            strip_proto("https://nick@wireup.net").contains('@'),
            "strip_proto preserves userinfo by design; the userinfo guard upstream is what prevents the doubled echo"
        );
    }
}
