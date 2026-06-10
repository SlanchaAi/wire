# Session log — 2026-06-09 — fabel mission: fix / test / simplify

Mission brief: `.claude/PROMPT_FABEL.md`. Three workstreams, all complete. Three stacked PRs open, none merged (human gate).

## PR stack (merge bottom-up)

1. **#239 `fix/cli-error-paths`** ← main — 5 bug fixes + 9 regression tests
2. **#240 `refactor/cli-split`** ← #239 — cli.rs 15,758 → 12-module tree, mod.rs 2,641
3. **#241 `test/cli-backfill`** ← #240 — 3 integration tests

Every PR carries container-gate evidence (`test-env/run.sh`, full `--all-targets --test-threads=1`, bare exit codes). All green.

## Workstream A — bugs found + fixed (TDD where reachable)

| Bug | Fix commit | Test |
|---|---|---|
| `parse_deadline_until` split_at panic on multi-byte final char (`30分`) — reachable from CLI + mcp.rs | 392409b | `cli::comms::deadline_tests` (4) |
| `introduce_pin` panic on valid-non-object trust.json root mid `group tail` | 392409b | `cli::group::introduce_pin_tests` (3) |
| 3× `try_allocate_*_slot` panic on valid-non-object relay.json mid `session new` | c6c6bc4 | `cli::session::coerce_object_root_tests` (2) |
| `cmd_group_tail` silently dropped `write_trust` failure | b8af036 | — (IO-failure only; root container ignores perms) |
| `cmd_group_add` collapsed distribute errors to `invites_queued: 0` | b8af036 | — (same) |

**Audited, NOT fixed (documented posture / separate efforts):** `cmd_up` degraded-bootstrap exit-0 (looks deliberate, compat risk); `cmd_push` all-skipped exit-0 (text honest); supervisor pidfile TOCTOU windows (daemon_supervisor.rs:184-199, ensure_up.rs:478-491 — real but small; fix = O_EXCL refactor, separate scoped PR); MCP `wire_accept` procedural consent (design posture per prior retraction); send-verdict pipeline and one-name rule audited CLEAN.

## Workstream C — the split

`src/cli.rs` (15,758 lines) → `src/cli/` tree: mod.rs 2,641 (clap surface + dispatch + shared helpers + re-exports), status 2,028, relay 1,885, upgrade 1,443, session 1,432, pairing 1,429, identity 1,260, comms 1,176, group 838, setup 817, mesh 714, lifecycle 274. One module per commit, gated. Zero caller edits outside src/cli/ (mod.rs `pub use` re-exports). Plan: `docs/superpowers/plans/2026-06-09-cli-split.md`.

**Verification machinery that caught real mistakes:**
- **Test-count invariant (exactly 425 lib tests)** caught the comms subagent co-deleting `tier_tests` (4 tests) while claiming it left them — restored verbatim (92f0420).
- **pub-API audit** caught the relay subagent narrowing `pub fn run_sync_push` to private (`lib.rs` has `pub mod cli` → that was public API) — restored (c22e755).
- **Whole-split sorted-line multiset diff** (pre-split cli.rs vs concatenated src/cli/*.rs, visibility-prefix-stripped): all 155 differing lines were qualified-path rewires or the include_str depth fix. No content lost.

**Traps for future moves of this kind:**
- `git mv` doesn't create target dirs; `include_str!` is file-relative (../ → ../../ when nesting).
- Subagents WILL co-delete physically-interleaved neighbors and report success — give them an exact-count invariant and verify yourself.
- Re-export visibility rule: item must be ≥ re-export (`pub(super)` inside child < `pub(super)` in mod.rs → widen item to `pub(crate)`).
- clippy `items_after_test_module` fires when a moved fn lands after a moved test mod — reorder within the new file only.

## Workstream B — tests added

9 unit (with fixes, #239) + 3 integration (#241): deadline multi-byte CLI regression, deadline garbage, group list empty-state (first tests/cli.rs group coverage).

## Known host flake (pre-existing, not introduced)

`send_deadline_writes_signed_time_sensitive_until` fails on THIS host (passes in container): send exits 0 but outbox lands outside `WIRE_HOME` when cwd has live `wire session` registry state. Matches the known shared-host-state flake category (see memory `feedback_run_wire_tests_isolated_env`). Flagged in #241 body. Candidate real bug: WIRE_HOME should probably beat session-registry cwd resolution in spawned subprocesses — worth a scoped look, NOT bundled into this stack.

## Artifacts

- `.claude/PROMPT_FABEL.md` — mission brief
- `docs/superpowers/plans/2026-06-09-cli-split.md` — split plan (committed in #240)
- PRs #239 / #240 / #241 — the work
- This file
