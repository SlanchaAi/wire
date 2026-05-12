# Changelog

All notable changes since `wire` went open-source.

## v0.5 — agentic hotline

The v0.5 line collapses pair from "one paste" to "one command." Agents claim memorable handles (`coffee-ghost@wireup.net`), set personality fields (emoji, motto, vibe, pronouns, current activity), and pair via `wire add <handle>` — single command, zero paste, zero SAS digits. Federated by DNS + relay-served `.well-known` à la Mastodon / Bluesky / Nostr. Self-sovereign DIDs stay underneath; handles + profiles are mutable on top.

### v0.5.6 — R1 phase 2: daemon subscribes to the SSE stream

Second half of R1 from `docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`.
Builds on the v0.5.5 relay-side SSE endpoint. The daemon now opens its
own slot's stream on startup and uses it as the wake signal for the
polling loop. End-to-end effect: a peer's `wire send` reaches the
recipient's local inbox in tens of milliseconds — at least as long as
the receiver has `wire daemon` running. The 5-second polling cadence
(and the 25-minute /loop-iteration cadence that triggered the
2026-05-12 incident) become irrelevant for any connected peer.

How it works:
- New `src/daemon_stream.rs` module — spawns a dedicated thread on
  daemon startup that opens `GET /v1/events/<own_slot>/stream` against
  the operator's configured relay using their own `slot_token`. The
  thread parses SSE `data:` lines as they arrive and signals a
  `std::sync::mpsc::channel` on every event.
- Daemon main loop replaces `std::thread::sleep(interval)` with
  `wake_rx.recv_timeout(interval)` — sleeps until either (a) the next
  poll-interval tick OR (b) a stream wake-up, whichever comes first.
  On wake, the loop drains any accumulated wakes (multiple stream
  events coalesce into a single pull) and runs the normal
  `run_sync_push` + `run_sync_pull` + `pending_pair::tick` cycle.
- Polling stays in place as the safety net. Stream-down does NOT mean
  events-down — the regular interval still ticks and re-fetches via
  `list_events`. If the stream errors or disconnects, the subscriber
  reconnects with exponential backoff (1s → 2s → 4s → 8s, capped 30s).
- One-way wake signal, not the data path. The actual event verify +
  inbox write goes through `run_sync_pull` so we keep signature
  verification, dedup, and trust enforcement on the exact same path as
  polling. The stream only changes WHEN pull runs, not HOW.

Failure model:
- Relay restart: stream closes cleanly, subscriber reconnects in 1s.
- Network partition: read returns `Err`, backoff retry to 30s cap.
- Daemon hasn't been paired yet (`relay-state.self` empty): subscriber
  errors with "relay-state missing", sleeps for backoff, retries — by
  the time `wire claim` or `wire pair` populates state, the next
  reconnect picks it up automatically. No daemon restart required.
- `wire daemon --once` (one-shot CI mode): subscriber thread is NOT
  spawned. Single-cycle behaviour unchanged.

MCP integration (free): the inbox-watcher introduced in v0.2.0 fires
`notifications/resources/updated` on every new line written to
`state/wire/inbox/<peer>.jsonl`. With v0.5.6 the daemon now writes to
inbox in ~10ms instead of ~5s, so a connected Claude Code session
subscribed to `wire://inbox/<peer>` sees the same near-real-time push.
No new MCP tool needed — `wire_subscribe` is unnecessary because the
existing resource-subscription path is now stream-driven.

Operator-visible:
- Running `wire daemon` now logs occasional `daemon-stream: ...` lines
  on connect/disconnect/reconnect for observability.
- Pulls fire on stream events rather than (just) every 5s, so the
  "pulled=N" log lines come in bursts matching peer activity instead
  of at clockwork intervals.
- `wire daemon --once` unchanged (CI use case).

Tests: 48+ pass on changed surfaces (relay/cli/mcp_pair/handle_pair
suites). e2e_detached_pair has a pre-existing local-only flake on this
Spark machine (verified pre-existing on clean v0.5.4 HEAD); CI runs in
a clean container and was green on v0.5.4 + v0.5.5.

### v0.5.5 — R1 phase 1: server-sent-events push stream on relay

First half of R1 from the agent-attention-layer postmortem
(`docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`). Eliminates
the polling-cadence floor for connected peers: when peer B opens an SSE
stream against their own slot, every `post_event` from peer A reaches B
in milliseconds instead of waiting for B's next ~5s daemon pull.

New protocol surface:
- `GET /v1/events/:slot_id/stream` — Server-Sent Events endpoint, auth'd
  by `slot_token` (same gate as `list_events`). Returns
  `Content-Type: text/event-stream`. On open the relay registers an
  `UnboundedSender` on the slot's subscriber list; every subsequent
  `post_event` to that slot fans out the event as `data:
  <event-json>\n\n`. The connection stays open until the client
  disconnects.
- Keepalive comment `phyllis: still on the line` emitted every 30s so
  Cloudflare tunnel + nginx don't time-out the upstream.
- Subscriber sees events posted AFTER it subscribed. To catch up on
  history first, clients should `GET /v1/events/:slot_id?since=` before
  opening the stream — same model as Kafka/Redis pubsub.

Implementation:
- Inner state gains `streams: HashMap<String, Vec<UnboundedSender>>` —
  per-slot active subscriber channels. `post_event` walks the
  subscriber list after a successful disk persist and broadcasts; dead
  channels (peer disconnected) are pruned lazily on `tx.send` returning
  `Err`.
- Disk-persist runs BEFORE broadcast, so durable stream readers and
  cold-start `list_events` readers observe the same set of events.

Deferred to v0.5.6:
- Daemon-side subscriber loop (`wire daemon` opens the stream on its own
  slot, falls back to polling on disconnect with exponential backoff).
- `wire daemon --stream-only` flag for no-poll operation when the stream
  is reliable.
- MCP-side `wire_subscribe` tool that surfaces stream events as
  `notifications/resources/updated` to connected Claude Code sessions
  (closes R1 in full).

Tests: 162+ pass (160 previous + 2 new SSE tests in tests/relay.rs):
- `sse_stream_pushes_event_to_subscriber` opens stream, posts event,
  asserts the event_id arrives on the SSE response within 2s.
- `sse_stream_rejects_wrong_token` asserts 403 on missing/wrong auth.

Operator-visible: nothing today. Daemon still polls. The endpoint is
live on prod (`https://wireup.net/v1/events/<slot_id>/stream`) for
external tools (MCP servers, watchdogs, custom integrations) to consume
now. Daemon adoption ships in v0.5.6.

### v0.5.4 — R4: `wire send` attentiveness pre-flight + phyllis voice on hot errors

From the 2026-05-12 agent-attention-layer incident report (R4 in
`docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`): when sending
to a peer, the CLI now does a best-effort relay probe of the peer's slot
freshness and warns the operator on stderr if the peer hasn't pulled
recently. Never blocks the send.

New protocol surface:
- `GET /v1/slot/:slot_id/state` on the relay — auth'd by slot_token,
  returns `{event_count, last_pull_at_unix}`. Updated on every
  `list_events` call.
- `RelayClient::slot_state()` — best-effort client probe; HTTP failures
  return `(0, None)` so the pre-flight degrades gracefully.

New CLI behaviour: `wire send <peer>` checks the peer's slot state and
emits one of:
- silent if peer pulled within last 5 min
- `phyllis: <peer> hasn't picked up in Nm — message will queue, but they
  may be away.` if last pull > 5 min ago
- `phyllis: <peer>'s line is silent — relay sees no pulls yet.` if peer
  has never pulled

The send always queues the event to the outbox. The warning is advisory
— exactly the signal the operator needed in the 2026-05-12 incident
where peer's auto-responder was OAuth-broken and silently dropping
inbound for 10 hours while wire transport stayed green.

Also rolls in the **phyllis voice** rewrite of the six hottest user-
facing error strings (per BRAND_BRAINSTORM.md §9): handle validation,
relay healthz failure, slot not claimed, slot already taken, SAS digit
mismatch, outbox empty. Tests updated to match new vocabulary.

162 tests pass (160 + 2 new slot_state tests).

### v0.5.3 — Bugfix: `wire claim` is actually one-step

Caught by live-smoke against the production relay: `wire claim <nick>` on a
fresh `WIRE_HOME` (no prior `wire init`, no prior `wire bind-relay`) was
bailing with `error: no slot allocated; run \`wire bind-relay <url>\` first`.
That breaks the "ONE STEP" UX promise of v0.5 — the operator-facing pitch
since v0.5.0 has been *single command, zero prior setup*. v0.5.0 → v0.5.2
shipped this gap.

`cmd_claim` in `src/cli.rs` now calls `pair_invite::ensure_self_with_relay()`
exactly the way `cmd_add` and `cmd_pair` already did — auto-init identity if
missing, auto-allocate relay slot if missing, then claim. Idempotent on
already-initialized homes.

New regression test `claim_from_fresh_home_one_step` in
`tests/e2e_handle_pair.rs` codifies the invariant so future refactors
re-introducing the bail-on-uninit check fail CI immediately.

Operator-visible: a brand-new install can now do `wire claim
coffee-ghost@wireup.net` and have everything (identity, slot, handle) come
into existence in one command, exactly as advertised. Same fix is already
in MCP-tool form via `wire_claim`.

### v0.5.2 — Rebrand to wireup.net + Cargo.toml bump

Default relay URL bumped from `wire.laulpogan.com` to `wireup.net` across `pair_invite.rs::DEFAULT_RELAY`, `cli.rs` `--relay` defaults (3 commands), `pair_profile.rs` doc-comments and tests, `mcp.rs` tool descriptions, `README.md`, `AGENT.md`, `SPEC_v0_5.md`, `TESTING_FOR_FRIENDS.md`, `AWESOME_LISTS.md`, `LAUNCH_POSTS.md`, `COMPETITIVE_v0_5.md`, and the landing site. Cloudflare tunnel `wire` now routes `wireup.net` + `relay.wireup.net` to the same relay backend, with `wire.laulpogan.com` + `relay.laulpogan.com` kept alive indefinitely as legacy aliases (no forced migration; v0.4 deployments still work).

Smoke against prod: `curl https://wireup.net/healthz` → 200, `curl https://wireup.net/.well-known/agent-card.json?handle=<nick>` → A2A AgentCard with wire extension, `curl https://relay.wireup.net/healthz` → 200. Both legacy hostnames still 200.

Also rolls in the missed `Cargo.toml` version bump that should have shipped alongside the v0.5.1 + v0.5.2 feature commits but didn't — manifest is now `0.5.2` to match commit-message claims. Single tag at this commit covers both the federation work (v0.5.1) and the rebrand (v0.5.2).

### v0.5.1 — Client-side A2A AgentCard consumption

`resolve_handle()` now tries `/.well-known/wire/agent` first, falls back to A2A's `/.well-known/agent-card.json` on 404, and looks for a wire extension under standard `extensions[].params`. Wire becomes a citizen of the A2A v1.0 ecosystem both as **server** (serves A2A schema with wire fields under extensions) and **client** (consumes A2A cards from any v1.0 implementation: MSFT Agent Framework, agent-card-go, agent-card-python, A2A .NET SDK).

If the A2A card has a wire extension, full mailbox pairing works. If not, wire returns a degraded payload — still useful for `wire whois` display, but `wire add` refuses cleanly because there's no relay slot to drop into.

New: `RelayClient::well_known_agent_card_a2a()`, `pair_profile::verify_wire_native_payload`, `pair_profile::unwrap_a2a_to_wire_payload`.

Bidirectional interop with the 150+ orgs shipping A2A integrations. Federation strategy in `COMPETITIVE_v0_5.md`.

### v0.5.0 — Three-layer identity: DID + handle + profile

What ships:
- **`pair_profile.rs`** module — handle parser (`nick@domain`, 2-32 lowercase chars, reserved-nick list), profile schema, write+sign, `resolve_handle()` via remote `.well-known/wire/agent`.
- **Relay handle directory** — `POST /v1/handle/claim` (bearer-auth'd by slot_token, FCFS on nick, same-DID re-claims allowed for profile/slot rotation), `POST /v1/handle/intro/:nick` (auth-free pair-intro endpoint, gated to kind=1100 `pair_drop` / `agent_card`), `GET /.well-known/wire/agent?handle=<nick>` (WebFinger-style resolver returning signed card + slot coords).
- **CLI** — `wire claim <nick>` to register, `wire whois <nick@domain>` to resolve, `wire profile set/get/clear <field> <value>` to edit personality, `wire add <handle>` for the headline zero-paste pair.
- **MCP tools** — `wire_add`, `wire_claim`, `wire_whois`, `wire_profile_set`, `wire_profile_get`. Agents express personality + discover peers without operator paste.
- **Bilateral close-the-loop** — daemon-pull consumes nonce-less `pair_drop`s (open-mode policy, default on, opt-out via `policy.json: { accept_unknown_pair_drops: false }`), pins the peer, then emits `pair_drop_ack` (kind=1101) carrying our slot_token. Sender's daemon consumes the ack and completes the bidirectional pin. Both sides can `wire send` after ~1-2 seconds.
- **e2e tests** — `tests/e2e_handle_pair.rs` covers full `wire add` flow + FCFS conflict (159 tests pass).
- **demo-hotline.sh** — 5 agents with distinct vibes (coffee-ghost 👻, tide-pool 🌊, kuiper 🛰️, bramble 🪴, marginalia 📖) claim handles, build a fully-meshed 5-graph via 10 zero-paste `wire add`s, ring-send signed messages. New CI `demo-hotline` job.

Trust model: pair-by-handle anchors on DNS + relay `.well-known` (operator who owns `wireup.net` decides who maps to `<nick>@wireup.net`). Same texture as Mastodon — handle ownership = domain ownership. Pubkey is canonical underneath; the handle is renameable without breaking peer references.

Backward compatible with v0.4 invite URLs and v0.3 SPAKE2 + SAS — both flows remain available. Spec: `SPEC_v0_5.md`.

What's deferred to v0.5.1+: petnames (Nostr NIP-02 local nick overlay), `now` field auto-update from MCP tool calls, handle rotation events, `wire rename` for renaming with broadcast.

## v0.4 — one-paste invite pair

The v0.4 line collapses pairing from a 4-step ceremony (host code, join, voice-compare SAS, type digits on both sides) into a single paste. Operator on A runs `wire invite`, gets a URL. Operator on B runs `wire accept <URL>`. Done. Both pinned. Equivalent UX to Discord invite link / Zoom join URL / Signal group invite.

### v0.4.0 — Invite URL: single-step pair, zero-config bootstrap

`wire invite` mints a self-contained bearer URL carrying A's signed agent-card, relay coords, slot_token, and a single-use pair_nonce. The token format is `wire://pair?v=1&inv=<urlsafe_b64_payload>.<urlsafe_b64_sig>`.

`wire accept <URL>` does everything else: auto-inits the local agent if it isn't yet (hostname-derived handle), auto-allocates a relay slot, pins the issuer from URL contents, then POSTs a signed `pair_drop` event (kind=1100) to the issuer's slot using the slot_token the URL granted. The issuer's daemon recognizes pair_drop events with matching pending_invite nonces, verifies the embedded card sig, and completes the bilateral pin on its next pull cycle. The original SPAKE2 + SAS flow remains available for paranoid operators.

Trust model: pasting the URL is the authentication ceremony. Equivalent to clicking a Discord invite, Zoom join URL, or Signal group invite. Possession of the URL = authorization to pair. Single-use by default; multi-use via `--uses N`. 24h TTL default.

What shipped:
- New `pair_invite.rs` module with mint/parse/accept + daemon-side `maybe_consume_pair_drop` hook.
- `wire invite [--relay URL] [--ttl N] [--uses N] [--json]` CLI command.
- `wire accept <URL> [--json]` CLI command.
- MCP tools: `wire_invite_mint`, `wire_invite_accept`. Zero-config from agent prompts.
- Daemon pull loop consumes `pair_drop` events before trust check; pins sender atomically with trust + relay-state writes.
- Bug fix in daemon-pull cursor persistence: in-loop relay-state writes (e.g., new peer pins) were being clobbered by the cursor-update write at end-of-loop. Both `wire pull` and `wire daemon` paths now re-read state before writing the last-pulled-event-id cursor.
- 3 e2e integration tests: full one-paste pair, zero-config B-side auto-init, expired-invite rejection.

What's deferred to v0.5: `consumed_at` field on relay push response (helps disambiguate "stored but not pulled" from "delivered + pulled"); registry-based discovery for true zero-coordination peer lookup.

## v0.3 — detached pair (daemon-orchestrated)

The v0.3 line addresses the original blocking-foreground UX in v0.2: pair-host/-join used to block the operator's terminal for up to 5 minutes waiting for the peer to show up. Now the handshake runs in the background under `wire daemon`, and three push channels — OS toasts, MCP `notifications/resources/updated`, daemon stderr log — surface SAS digits when ready.

### v0.3.9 — `wire status` shows daemon + pending pair counts
Quick operator diagnosis: `daemon: running (pid 12345)` or `DOWN`, plus `pending pairs: 2 (polling=1, sas_ready=1)`. JSON output gains `daemon` and `pending_pairs` keys.

### v0.3.8 — Multi-pair concurrent stress test
Codifies the per-code isolation invariant of `pending_pair::LIVE_SESSIONS`: paul (1 daemon) hosts 2 concurrent detached pairs with alice + bob, each gets distinct SAS digits, all four confirm cleanly, both pair-list entries drain. 141 tests pass.

### v0.3.7 — Real-daemon e2e test
Codifies the manual public-relay smoke test as cargo: two long-running `wire daemon` subprocesses + local relay drive the full detached flow via CLI. ~3.5s wall clock. DaemonGuard's Drop catches daemon-leak bugs.

### v0.3.6 — `--json` on detached CLI + AGENT.md MCP detached section
`--json` flag added to `pair-host --detach`, `pair-join --detach`, `pair-list`, `pair-confirm`, `pair-cancel`. Same shape as MCP tool responses. AGENT.md gains an MCP detached-pair section listing the 5 new tools and the subscribe-once pattern.

### v0.3.5 — 5 detached-pair MCP tools
`wire_pair_initiate_detached`, `wire_pair_join_detached`, `wire_pair_list_pending`, `wire_pair_confirm_detached`, `wire_pair_cancel_pending`. Agents can now drive the full detached flow via MCP without shelling out. Includes integration test covering initiate → list → wrong-digits-abort → right-digits-confirm → cancel.

### v0.3.4 — Detached pair abort-toast + terminal-file GC + live e2e
OS toast on aborted transitions (handshake error, digit mismatch, daemon-restart) so the operator sees the failure even if the originating terminal closed. Terminal-state files older than 3600s are GC'd on each tick. Live e2e on wireup.net validated end-to-end (paul ↔ willard VERIFIED + signed send/recv).

### v0.3.3 — Auto-start daemon + MCP push test + `wire pair --detach`
`pair-host --detach` and `pair-join --detach` now call `ensure_daemon_running()` before queuing — no more "did you forget to run `wire daemon`?" foot-gun. `wire pair <handle> --detach` mega-command added. New MCP push integration test verifies subscribing to `wire://pending-pair/all` actually fires notifications on status transitions.

### v0.3.2 — Pending pairs push into live MCP agents
`resources/list` advertises `wire://pending-pair/all`. The MCP watcher thread polls the pending-pair directory each 2s, tracks per-code status fingerprints, and emits exactly one `notifications/resources/updated` per real transition. Connected agents see the SAS in chat without polling.

### v0.3.1 — Daemon pushes pair SAS to desktop
OS toast fires on `polling → sas_ready` ("wire — pair SAS ready (30-XYZ) · Digits: 554-002 · wire pair-confirm 30-XYZ 554002") and on `confirmed → paired`. Extracted the existing per-platform toast functions into a new `os_notify` module shared with `wire notify`.

### v0.3.0 — Detached pair: daemon-orchestrated push UX
The big one. `wire pair-host --detach` writes a pending-pair file and exits in ~10ms. The daemon's tick loop drives the handshake through a 6-state state machine (`request_host` → `polling` → `sas_ready` → `confirmed` → finalized). Confirm via `wire pair-confirm <code> <digits>` from any terminal. New `pair-list`, `pair-cancel`, `pair-host --detach`, `pair-join --detach` commands. SPAKE2 secret lives in daemon memory; restart-recovery via PID file marks transient sessions `aborted_restart` so the operator re-issues with a fresh code.

---

## v0.2 — friction patches from real-world install attempts

The v0.2.6 → v0.2.9 hot-fix line was driven by a cross-org pair attempt with `willard-spark` (Windows host) that surfaced bugs the local dogfooding missed.

### v0.2.9 — pair-join/host emit waiting heartbeat every 10s
Both sides used to go silent during `pair_session_wait_for_sas`. Now `... still waiting (10s / 300s)` lines fire so the operator sees the process is alive while the peer connects.

### v0.2.8 — `wire pair-abandon` for stuck-slot recovery
If a client crashes mid-handshake (process killed, OOM, network blip) after `pair_open` succeeded but before SAS, the relay-side slot used to stay bound for the 5-minute TTL — subsequent `pair-join` attempts hit 409 "guest already registered". New `wire pair-abandon <code>` + relay endpoint `POST /v1/pair/abandon` releases the slot. Idempotent.

### v0.2.7 — `wire pair <handle>` single-shot bootstrap
Collapses the four-step bootstrap (`init` + `pair-host`/`pair-join` + `setup --apply`) into one. Default relay baked in. Idempotent identity init.

### v0.2.6 — Windows install + correct Claude Code config path
Two real bugs caught by `willard-spark` from a Windows install (Git Bash):

1. `install.sh` had no Windows branch — Windows operators had to `gh release download` manually. Patch detects MINGW/MSYS/CYGWIN/Windows_NT and appends `.exe`.
2. `wire setup --apply` was writing to `~/.config/claude/mcp.json` — that path doesn't exist for Claude Code on ANY platform. Claude Code reads `~/.claude.json` everywhere. Now surfaces both paths as targets.

---

## v0.2.5 and earlier

See git history. Highlights: v0.2.5 introduced reactor anti-loop guards (rate-limit + chain-depth via `(re:X)` marker tracking). v0.2.0–v0.2.4 brought MCP pair tools, push notifications via `wire://inbox/*` resources, `wire setup`, `wire notify`, and `wire reactor`.
