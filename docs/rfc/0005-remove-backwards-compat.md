# RFC-005: Remove backwards compatibility (de-deprecation) + `wire nuke`

**Status:** Implemented <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** Phase 1 [#220], Phase 2 [#231], Phase 3 [#232], Phase 4 [#233], SAS-flow removal [#236]

> **Status update (2026-06-07):** Shipped — Phases 1–4 + the full SAS code-phrase pairing removal (dial is now the sole pairing path). All deprecated MCP/CLI aliases, the SAS flow, legacy pidfile/DID formats, and the dead v3.1-card / pre-v0.5.19 / v0.4-profile version-tolerance shims are gone; breadcrumbs advertise only canonical verbs. **Two items in Phase 4's scope turned out to be LIVE code, not dead shims** — the v0.6 *named* session layout (`wire session new/list/…` use it; by-key is a parallel, not replacement, layout) and the flat peer-endpoint fields (the live invite flow reads/writes them). Removing those is a representation *consolidation*, not cruft removal, and carries the #170/#174 fork-storm risk — moved to **[RFC-006](0006-consolidate-dual-representations.md)**.
**Author:** Claude Code agent (paired w/ @laulpogan)
**Date:** 2026-06-05
**Target:** v0.15.0 (breaking — no production users)
**Question this answers:** How do we stop the deprecated command surface from confusing agents, without leaving a maze of compat shims — and how do operators wipe a machine to test the breaking changes fresh?

---

## TL;DR

- The MCP tool list advertises **legacy `wire_pair_*` tools alongside the canonical verbs**, so an agent sees both and picks the wrong one. Remove all backwards-compatibility surface — agent (MCP), operator (CLI), and on-disk (legacy formats).
- No production users → **break freely, no migration.** Ship a `wire nuke` clean-slate command (Phase 1, **already shipped** in #220) so machines can be wiped and re-tested.
- Lands as **v0.15.0** across **four gated phases**, each its own PR, each requiring: test-env container + CI green + fresh install/smoke on **macOS + Linux + Windows** + person review before merge.
- `wire nuke` is **hard by default** (kill daemons → remove service units → **de-register the `wire` MCP entry from host configs** → wipe all wire dirs; keeps binary) with `--purge` for full binary+shell removal. Safety: `--dry-run` → typed-`nuke` confirm → `--force`/`--yes`.

## Motivation

Agents drive wire through the MCP tool surface. Today that surface still exposes six deprecated pairing tools — `wire_pair_accept`, `wire_pair_reject`, `wire_pair_list_inbound`, `wire_pair_initiate`, `wire_pair_join`, `wire_pair_confirm` (`src/mcp.rs`) — superseded since v0.9 by `wire_accept` / `wire_reject` / `wire_pending` / `wire_dial`. The server `instructions` string even tells the model both exist ("Legacy MCP tools … still callable but DEPRECATED — prefer canonical"). An LLM choosing a tool from a list of near-synonyms picks wrong; that is the concrete failure.

Underneath the MCP surface there are two more compat layers: 15 `#[command(hide = true)] // deprecated` CLI subcommands (`src/cli.rs`), and on-disk legacy-format shims in `src/session.rs` / `src/agent_card.rs` (v0.6 top-level session layout, bare-integer pidfiles, `did:wire:<handle>` no-fingerprint DIDs, flat endpoint fields). The on-disk shims are the load-bearing resolution code that produced the #170/#162 multi-session fork-storm — carrying dead format-variants there is both clutter and risk.

Because there are no production users, none of this needs a migration. The only thing missing is a way to reset a machine whose on-disk state the new code no longer reads: `wire nuke`.

## Design

Four phases, each its own PR, all under v0.15.0.

**Per-phase merge gate (HARD):** test-env container green (`fmt` + `clippy -D warnings` + `test`) → CI green (incl. `install-smoke` + `install-smoke-windows` + demos) → fresh-environment install/smoke on **macOS + Linux + Windows** → person review.

### Phase 1 — `wire nuke` (shipped, #220)

Additive; ships first so later phases can wipe targets. Two modes:

- **Default `wire nuke` — hard reset (machine-wide):** `service::uninstall_kind` (launchd/systemd/schtasks) for daemon + local-relay → kill survivor daemon/supervisor/relay processes → **de-register the `wire` MCP entry from every host config** (Claude Code / Cursor / Copilot / VS Code / OpenCode), via new `remove_*` counterparts to the `upsert_*` adapters in `src/adapters/harness.rs` → wipe `sessions_root` + config/state/cache + logs. **Keeps the binary** (you need it to re-test).
- **`wire nuke --purge`:** also removes the `wire` binary + scrubs shell PATH/env lines (Windows prints the manual `del` — a running `.exe` can't self-delete).
- **Safety:** `--dry-run` (enumerate, change nothing) → typed-`nuke` confirm → `--force`/`--yes`; non-TTY without `--force` refuses; `--json` report.
- Implementation: pure `NukePlan::compute`/`execute`/`should_proceed` in `src/nuke.rs`; CLI in `src/cli.rs`.

### Phase 2 — Remove deprecated MCP tools (the agent-confusion fix)

Remove the six `wire_pair_*` tools from the MCP registry + handlers, and drop the "Legacy MCP tools …" clause from the `instructions` string (`src/mcp.rs`), so the agent only ever sees canonical verbs. Keep `wire_dial`/`wire_send`/`wire_pending`/`wire_accept`/`wire_reject`/`wire_whois`/`wire_status`/`wire_pull`.

### Phase 3 — Remove deprecated CLI verbs + the deprecation shim

Remove the 15 `#[command(hide = true)]` deprecated subcommands and the `deprecation_warn()` helper + call sites (`src/cli.rs`). A removed verb becomes a clap "unknown subcommand."

### Phase 4 — Remove legacy on-disk data shims (capstone)

Delete dual-layout / legacy-format handling now that no old state must be read: v0.6 top-level `sessions/<name>` layout (keep only `by-key/<hash>`), bare-integer pidfiles (keep JSON `DaemonPid`), `did:wire:<handle>` no-fingerprint DIDs, flat endpoint-field fallbacks. Riskiest — this is the resolution code behind the fork-storm — so it gets the most thorough cross-OS validation. Each removal `gitnexus_impact`-checked first.

## Security

- **Net reduction in surface.** Removing deprecated MCP tools and CLI verbs shrinks the callable API; removing legacy format-parsers removes code paths. No new trust path, no protocol bump (v3.2 constant), no trust-ladder change.
- **`wire nuke` is destructive and machine-wide.** It is intentionally not sandboxed by `WIRE_HOME`: `launchctl bootout` uses a global label and process-kill is host-wide, so a throwaway `HOME` does **not** contain it (verified — the Phase-1 smoke tore down the dev host's services). Mitigation is the `--dry-run` → typed-`nuke` confirm → `--force` ladder. Open question: whether the typed confirm is guard enough or nuke warrants a second factor. It mutates only local state + the operator's own host MCP configs; it touches no peer, relay, or trust material.
- Cross-ref `docs/THREAT_MODEL.md`. Nuke does not exfiltrate (local-only) and removes, never adds, capability.

## Out of scope

- Migration tooling (no users).
- Default `wire nuke` removing the binary — only `--purge` does, so re-test loops don't need a reinstall.
- Changing canonical verbs, the protocol (v3.2), or the trust ladder.

## Acceptance criteria

1. **Agent sees only canonical verbs** — after Phase 2, the MCP `tools/list` response contains none of the six `wire_pair_*` names, and the `instructions` string names no deprecated tool. Measured: assertion test on the tools/list payload. Owner: Phase 2 PR.
2. **No deprecated CLI verbs** — after Phase 3, `wire <removed-verb>` exits "unknown subcommand"; `grep '#\[command(hide = true)] // .*deprecated'` over `src/cli.rs` returns nothing. Owner: Phase 3 PR.
3. **Fresh end-to-end flow works on all three OSes after the legacy-shim removal** — Phase 4's `install-smoke` (Linux + Windows) + macOS run: `up → pair → send → daemon lifecycle → nuke → re-up` all green. Owner: Phase 4 PR.
4. **KILL CRITERION** — if removing the on-disk shims (Phase 4) cannot be done without re-introducing the multi-session resolution ambiguity that caused #170 (i.e., the by-key-only path can't cover a case the dual-layout did), Phase 4 is abandoned and the legacy session/pidfile shims stay; Phases 1–3 still ship.

## Open questions

- **Nuke second factor?** Is typed-`nuke` + `--force` enough for an unsandboxable machine-wide reset, or add a second confirmation? Decision point: before Phase 2 review. Owner: maintainer.
- **`wire up --no-local` is not truly offline** — it claims the handle on the shared relay and exits non-zero on a 409 (surfaced by the Phase-1 Windows smoke). Fold an offline/claim-optional fix into a later phase, or track separately? Owner: maintainer.

## Alternatives considered

- **Do nothing / keep deprecating gently.** Rejected: the confusion is active now, and "deprecated but callable" is precisely what misleads the agent — hiding from `--help` doesn't hide from the MCP tool list.
- **Agent surface only (remove MCP tools, keep CLI + on-disk shims).** Reasonable and lower-risk, but the operator chose the full sweep given no users; the on-disk shims are also dead weight on the fork-storm-adjacent code.
- **One big breaking PR.** Rejected: tangles the risky `session.rs` change with everything else and is unreviewable; phased PRs ship the agent fix early and quarantine the risk.
