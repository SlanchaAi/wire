# Design — Remove backwards compatibility (de-deprecation) + `wire nuke`

**Date:** 2026-06-05
**Status:** design, pending review
**Target version:** v0.15.0 (breaking — acceptable: no production users)

## Goal

Deprecated command surface confuses agents: the MCP tool list advertises legacy `wire_pair_*` tools alongside the canonical verbs, so an agent picks the wrong one. Remove **all** backwards-compatibility surface (agent + operator + on-disk), and ship a `wire nuke` clean-slate command so target machines can be wiped and re-tested fresh.

No production users → no migration required. We break old on-disk state freely; `wire nuke` is the reset.

## Approach: phased, gated (Approach 2)

Four phases, each its **own PR**, all landing under **v0.15.0**.

### Per-phase merge gate (HARD)

A phase does **not** merge until ALL of:
1. Full gate green in the `test-env` container (`fmt` + `clippy -D warnings` + `test`).
2. CI green (incl. `install-smoke` + demos).
3. **Fresh-environment install + smoke on all three OSes: macOS, Linux, Windows.**
   - Linux: fresh Docker container + `install-smoke` CI job (Ubuntu).
   - macOS: this host with a fresh `WIRE_HOME` + CI `macos-14` build.
   - Windows: new `windows-latest` `install-smoke` CI job **+ operator confirmation on `DESKTOP-1LK5VSJ`** (the runtime here cannot execute Windows locally — Windows coverage is CI + human).
4. **Person review** of the diff.

### Phases (in order)

1. **`wire nuke`** — additive. Ship first so we can wipe targets and test every later phase from a clean slate.
2. **Remove deprecated MCP tools** — the agent-confusion fix (primary motivation).
3. **Remove deprecated CLI verbs + `deprecation_warn` shim** — operator surface.
4. **Remove legacy on-disk data shims in `session.rs`** — biggest code simplification, riskiest (load-bearing resolution logic that caused the #170 fork-storm); isolated capstone.

---

## Phase 1 — `wire nuke`

### Behavior

`wire nuke` resets the machine to a clean wire state. It composes existing primitives:

`wire nuke` is **hard by default** (the name demands it; precedent: `rustup self uninstall`, `docker system prune -a`). Two modes.

**Default `wire nuke` — hard reset (everything wire did to the machine, binary kept):**

1. **Service teardown** — `service::uninstall_kind(ServiceKind::Daemon)` + `service::uninstall_kind(ServiceKind::LocalRelay)`. Cross-platform via the existing impl (launchd bootout + plist rm / `systemctl --user disable --now` + unit rm / `schtasks /Delete`).
2. **Kill survivors** — terminate any remaining `wire daemon` (supervisor + children) and `relay-server` processes not covered by unit teardown (pidfile-driven where possible; `pkill -f` fallback).
3. **De-register from host MCP configs** — remove the `wire` server entry that `wire setup` wrote into each host's config (Claude Code / Cursor / Copilot / OpenCode `mcpServers` / OpenCode `mcp.*`), reusing the `adapters/harness.rs` registry in reverse (a `remove_mcp_entry` counterpart to `upsert_mcp_entry`). **Critical: without this, a "fresh" machine still shows the agent a dead `wire` MCP server — the exact confusion this whole effort removes.** Preserve sibling keys; only drop the `wire` entry.
4. **Delete state** — remove `session::sessions_root()` (all session homes), `config::config_dir()` + `config::state_dir()` (default config/state/trust/inbox/cursors), `dirs::cache_dir()/wire/` (toast-dedup), and wire logs (`~/Library/Logs/wire-*.log` on macOS; equivalents elsewhere).
5. **Keep the `wire` binary** — you need it to run nuke and to re-test without re-downloading.

**`wire nuke --purge` — total uninstall (rustup-style, "never installed"):**

Everything above, **plus**: remove the `wire` binary from PATH and scrub shell-config lines (`PATH` entries, `source` of any wire env, install.sh-added lines). **Windows caveat:** a running `.exe` can't delete itself — on Windows, `--purge` prints the one manual `del` command for the binary instead of failing (same wall `rustup` hits).

### Safety (consensus pattern: enumerate → typed-confirm → default No)

- **`--dry-run`** — print the full kill/unit/path/MCP-entry list that *would* be removed; do nothing. Implemented before the confirm so it's always a safe preview.
- **Interactive (TTY, no `--force`)** — print the same enumeration, then require the operator to type `nuke` to proceed. Default is abort.
- **`--force` / `--yes`** — skip the prompt for automation (and the cross-platform test harness).
- **Non-TTY without `--force`** — refuse with a message (never silently destroy in a pipe).
- **`--json`** — `{removed_paths[], removed_units[], removed_mcp_entries[], killed_pids[], binary_removed}` for scripting.
- Targets the **machine-wide** sessions root + default dirs (full reset), not a single `WIRE_HOME`.

### Surface

- New top-level subcommand `Nuke { force: bool, purge: bool, dry_run: bool, json: bool }` in `cli.rs`, dispatched to `cmd_nuke`.
- NOT exposed as an MCP tool (destructive; operator-only).
- New `service`/`adapters` helper `remove_mcp_entry(host)` mirroring `upsert_mcp_entry`, covered by the same per-host shape tests.

### Tests

- Unit: path-set computation under a temp home; confirm-gating logic (pure, injectable confirmation); `--dry-run` removes nothing; `remove_mcp_entry` drops only the `wire` key and preserves siblings (per-host shape, mirroring the `upsert_mcp_entry` tests).
- Manual fresh-env, on **macOS + Linux + Windows**:
  1. install → `wire setup` (registers MCP host entry) → `wire up` →
  2. `wire nuke --dry-run` shows the full removal list, changes nothing →
  3. `wire nuke --force` → confirm: state gone, service units removed, **MCP host entry gone**, binary intact, a subsequent `wire up` works clean →
  4. `wire nuke --purge --force` → confirm binary + shell lines gone (Windows: prints the manual `del` line).

---

## Phase 2 — Remove deprecated MCP tools

Remove from the MCP tool registry + handlers (`src/mcp.rs`):
- `wire_pair_accept`, `wire_pair_reject`, `wire_pair_list_inbound`
- `wire_pair_initiate`, `wire_pair_join`, `wire_pair_confirm`

Plus:
- Drop the "Legacy MCP tools … still callable but DEPRECATED" clause from the server `instructions` string (mcp.rs:548) so the agent only ever sees canonical verbs.
- Remove the now-dead handler functions + any `tool_pair_*` dispatch arms.
- Keep canonical: `wire_dial`, `wire_send`, `wire_pending`, `wire_accept`, `wire_reject`, `wire_whois`, `wire_status`, `wire_pull`, etc.

Tests: assert the tools/list response contains none of the removed names; existing canonical-verb tests stay green.

## Phase 3 — Remove deprecated CLI verbs + shim

- Remove the 15 `#[command(hide = true)] // v0.x deprecated` subcommands in `cli.rs` (the `pair-accept`/`pair-reject`/`pair-list-inbound`/`pair-initiate`/`pair-join`/`pair-confirm`/`add`(legacy)/etc. set — exact list enumerated in the plan phase).
- Remove the `deprecation_warn()` helper (cli.rs:~13523) and its call sites (cli.rs:~1897-1930).
- Update any docs/help that referenced them; `docs-lint` already blocks the deprecated phrases.

Tests: CLI integration tests for removed verbs deleted; `wire <removed-verb>` now exits "unknown subcommand" (clap default).

## Phase 4 — Remove legacy on-disk data shims (`session.rs` + friends)

The capstone. Remove dual-layout / legacy-format handling now that no old state needs reading:
- Legacy **v0.6 top-level `sessions/<name>`** layout — keep only `sessions/by-key/<hash>`. (`find_session_home_by_name`, `sessions_root` inside-session resolution, etc.)
- Legacy **bare-integer pidfile** parsing — keep JSON `DaemonPid` only.
- Legacy **`did:wire:<handle>`** (no fingerprint) DID form — `agent_card.rs` back-compat strip.
- Legacy **flat endpoint fields** fallback — `session.rs` `self_endpoints`/`peer_endpoints` back-compat.
- `WIRE_QUIET_AUTOSESSION` v0.9-script back-compat — evaluate; likely keep (it's an env knob, not a format).

Each removal `gitnexus_impact`-checked first. This PR is where the fork-storm-adjacent resolution code lives, so it gets the most thorough test-env + cross-OS validation.

Tests: delete the legacy-layout/legacy-pidfile tests; confirm by-key path fully covered; fresh `wire up` + pair + send + daemon lifecycle green on all three OSes (the legacy removal can't be exercised by old state since nuke wiped it — so the gate is "fresh flow still works end-to-end").

---

## Out of scope

- No migration tooling (no users).
- Default `wire nuke` keeps the binary; only `--purge` removes it (so re-test loops don't require reinstall).
- No change to canonical verbs, protocol (v3.2 constant), or trust ladder.

## Open questions

- (resolved) Spec location → `.planning/` (crate-excluded).
- (resolved) Scope → all three tiers + `wire nuke`.
- (resolved) `nuke` blast radius → full machine reset, **hard by default**, incl. MCP-host de-registration.
- (resolved) two modes: default `nuke` keeps the binary; `wire nuke --purge` removes binary + shell lines (rustup-style).
- (resolved) safety: `--dry-run` + typed-`nuke` confirm + `--force`/`--yes`, default No.
