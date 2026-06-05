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

1. **Service teardown** — `service::uninstall_kind(ServiceKind::Daemon)` + `service::uninstall_kind(ServiceKind::LocalRelay)`. Cross-platform via the existing impl (launchd bootout + plist rm / `systemctl --user disable --now` + unit rm / `schtasks /Delete`).
2. **Kill survivors** — terminate any remaining `wire daemon` (supervisor + children) and `relay-server` processes not covered by unit teardown (pidfile-driven where possible; `pkill -f` fallback).
3. **Delete state** — remove:
   - `session::sessions_root()` (all session homes)
   - `config::config_dir()` and `config::state_dir()` (default-session config/state/trust/inbox/cursors)
   - `dirs::cache_dir()/wire/` (toast-dedup)
   - wire logs (`~/Library/Logs/wire-*.log` on macOS; equivalents elsewhere)
4. **Keep the `wire` binary** — nuke resets *state + services*, not the install. (You need `wire` to run nuke and to re-test without re-downloading.)

### Safety

- Requires `--force` to run non-interactively. Without `--force` in a TTY: print the exact path/unit list and require a typed confirmation (`nuke`); abort otherwise. Non-TTY without `--force`: refuse with a message.
- `--json` prints `{removed_paths[], removed_units[], killed_pids[]}` for scripting.
- Honors `WIRE_HOME` only insofar as the dir fns do; nuke targets the **machine-wide** sessions root + default dirs (full reset), not a single `WIRE_HOME`.

### Surface

- New top-level subcommand `Nuke { force: bool, json: bool }` in `cli.rs`, dispatched to `cmd_nuke`.
- NOT exposed as an MCP tool (destructive; operator-only).

### Tests

- Unit: path-set computation under a temp home; `--force` gating logic (pure, injectable confirmation).
- Manual fresh-env: install → `wire up` → `wire nuke --force` → confirm state gone + services removed + binary intact + a subsequent `wire up` works clean. Run on macOS, Linux, Windows.

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
- No removal of the `wire` binary by `nuke`.
- No change to canonical verbs, protocol (v3.2 constant), or trust ladder.

## Open questions

- (resolved) Spec location → `.planning/` (crate-excluded).
- (resolved) Scope → all three tiers + `wire nuke`.
- (resolved) `nuke` blast radius → full machine reset.
- (assumed, flag if wrong) `nuke` keeps the binary.
