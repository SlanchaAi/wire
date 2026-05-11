# Changelog

All notable changes since `wire` went open-source.

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
OS toast on aborted transitions (handshake error, digit mismatch, daemon-restart) so the operator sees the failure even if the originating terminal closed. Terminal-state files older than 3600s are GC'd on each tick. Live e2e on wire.laulpogan.com validated end-to-end (paul ↔ willard VERIFIED + signed send/recv).

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
