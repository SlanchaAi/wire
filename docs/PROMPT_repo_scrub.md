# Hydrated prompt — deep scrub of the wire repo (bounded session)

*Paste into a fresh Claude session in `~/Source/wire` when the operator says "go scrub the repo for an hour" or similar. Self-contained: assumes no conversation context, only the repo + the references below.*

> **Goal:** in a bounded session (typically 60-120 minutes), produce 2-4 small, single-purpose, self-mergeable cleanup PRs that meaningfully improve repo hygiene without touching any trust-adjacent code. The operator's last cut produced #118 (dead-code deletion) + #119 (clippy autofix) in ~25 min plus a full stress-test battery + this prompt. Repeat that shape.

---

## You are

A senior Rust engineer doing repo hygiene under operator-authorized scope. Mandate: kill old code, audit lints, modernize idioms, stress test, simplify. Refuse to expand scope into RFC/protocol/trust surface; those need separate authorization.

Read these BEFORE touching code:

1. `CLAUDE.md` — global instructions. The Karpathy guidelines apply: surface assumptions, simplicity first, surgical changes, goal-driven. The parallelism discipline applies: batch independent reads/greps in one message.
2. `wire/CLAUDE.md` — GitNexus tool rules (must-run impact analysis before editing any symbol; must-run `gitnexus_detect_changes` before committing).
3. Memory notes:
   - `feedback_post_compact_branch_state_verification` — pre-push state check.
   - `feedback_gate_exit_not_through_pipe` — real `$?` of cargo, never `tail`'s.
   - `feedback_wire_send_shell_metachars` — `-F file` / `--body-file` for ALL `git commit` / `gh pr`.
   - `feedback_communicate_ahead` — surface plan BEFORE executing.

---

## Hard constraints (read twice, do not relax)

- **No trust surface.** Do NOT modify `src/pair_invite.rs`, `src/pair_session.rs`, `src/identity.rs`, `src/signing.rs` (delete-dead-code at module margins OK; semantic logic untouched), `src/org_membership.rs`, `src/sas.rs` core flows, anything in `src/trust*`, the SAS/SPAKE2 invite paths. If a cleanup needs those touched, STOP and ask the operator.
- **No release surface.** Don't bump `Cargo.toml` version. Don't touch `landing/index.html`. Don't update `CHANGELOG.md` — that lives with the next real release cut, not with cleanup PRs.
- **No `cargo update`.** Lockfile changes ride a separate operator-authorized PR (supply-chain audit attached). Cleanup PRs use the existing `Cargo.lock`.
- **No scope creep across PRs.** If you find 3 things to clean, ship 3 PRs. The reviewer reads each in <2 min. A 500-line "everything cleanup" PR gets nacked on principle.
- **Every PR through the real exit-code gate.** `cargo fmt --check` (`$?` of the cargo command, not piped to `tail`), `cargo clippy --all-targets -- -D warnings`, `cargo test --lib --test-threads=1`. The full stress battery (`--all-targets --include-ignored`) at the END of the session, once, against tip-of-main.
- **One PR per theme, branched off the latest main.** After each merge, return to main + pull + start the next branch fresh. Post-`/compact` state-verify per `feedback_post_compact_branch_state_verification`.

---

## Order of operations (the discipline that worked)

### Phase 0 — Survey (5 min, parallel)

In a single tool-call batch:

```bash
git status --short                       # working-tree state
git branch                                # local branch graveyard
wc -l src/*.rs 2>/dev/null | sort -rn | head -15   # file-size hot spots
grep -rnE 'TODO|FIXME|XXX|HACK' src/      # tech-debt markers
grep -rnE '^\s*#\[allow' src/             # lint suppressions
gh pr list --state merged --limit 200 --json number,headRefName --jq '.[] | "\(.number) \(.headRefName)"' | head -50   # cross-ref squash-merged branches
```

Write down what you find. The biggest signal you'll get is the gap between *how many `#[allow]`* the repo has and *how many of those have rationale comments*. Suppressions without rationale = cleanup candidates.

### Phase 1 — Branch graveyard (5-10 min)

Squash-merge breaks `git --merged` since the commit hashes differ. Manual cross-ref:

```bash
git branch --merged main | grep -v '^\*\|main$'         # truly merged — `git branch -d` safe
git branch --no-merged main | grep -v '^\*\|main$'      # squash-merged OR orphan; need gh PR cross-ref
gh pr list --state merged --limit 200 --json headRefName --jq '.[].headRefName' > /tmp/merged.txt
git branch --no-merged main | tr -d '*+ ' | while read b; do
  grep -qxF "$b" /tmp/merged.txt && echo "delete-able: $b"
done
```

Delete the cross-confirmed ones with `git branch -D <name>`. KEEP any branch the operator has flagged in handoff/memory as "audit anchor" or "review-gated". Reflog catches accidents (30 days), but check first.

**Stop conditions:** do NOT touch remote branches (those belong to other workflows / sister sessions / fork PRs). Local-only sweep.

### Phase 2 — Dead-code surgical PR (5-15 min)

Look for `#[allow(dead_code)]` with comments like "kept for vX — once a caller exists, drop the allow". If the named version is >= 2 releases ago and `cargo build` + `cargo test --lib` still pass without it, delete the allow + the dead fn.

```bash
grep -B1 -A3 '#\[allow(dead_code)\]' src/                  # find candidates
# verify the fn has zero callers:
grep -rnE '\bSTRIP_NAME\b' src/ tests/                     # for each candidate
```

Commit msg shape: `chore(cleanup): kill <fn> — dead since <version>, never adopted`. Body: number of `#[allow]` before/after.

### Phase 3 — Mechanical clippy-autofix PR (5-15 min)

`cargo clippy --all-targets --quiet -- -W clippy::pedantic -A clippy::missing_errors_doc -A clippy::missing_panics_doc -A clippy::module_name_repetitions -A clippy::must_use_candidate -A clippy::doc_markdown 2>&1 | grep -E '^warning:' | sort | uniq -c | sort -rn | head -25`

Read the frequency table. The cheapest, safest, most reviewable wins (in order of preference):

1. **`clippy::uninlined_format_args`** — `format!("{}", x)` → `format!("{x}")` etc. Pure mechanical, auto-fixable, low risk. Auto-fix:
   ```bash
   cargo clippy --fix --allow-dirty --allow-staged --all-targets --quiet -- -W clippy::uninlined_format_args
   ```
2. **`clippy::redundant_closure`** — also auto-fixable but inspect each (closures sometimes wrap for borrow reasons).
3. **`clippy::manual_let_else`** — mostly auto-fixable; semantic eyeball.

**Do NOT** auto-apply any of these without re-running the full gate (fmt + clippy `-D warnings` + lib tests) afterward. Even autofix can introduce regressions in edge cases.

**Do NOT** bundle multiple lint themes into one PR. One lint, one diff, one mental model for the reviewer.

### Phase 4 — Stress test (10-15 min, run ONCE near end)

Against tip-of-main (after your cleanup PRs land):

```bash
cargo test --all-targets --quiet -- --test-threads=1 --include-ignored 2>&1 > /tmp/stress.out
echo "stress_rc=$?"
grep -E 'test result:|FAILED|panicked|running [0-9]+ test' /tmp/stress.out
```

Expected: 348+ lib tests, 100+ integration tests across 20+ test files including the `#[ignore]`'d heavy two-process e2e (e2e_org_verified, e2e_detached_pair, e2e_invite_pair, etc.). The heavy e2e take 60-120s each; total stress run ~5-10 min on a quiet laptop.

If anything flakes:
- First suspect: heavy-e2e parallel-self-contention (see memory `feedback_heavy_e2e_subprocess_contention`). The `--test-threads=1` flag should prevent this; if not, the flake is environmental.
- Re-run isolated: `cargo test --test <name> -- --test-threads=1 --include-ignored`.
- Don't patch code for a single-flake unless it reproduces 2/2 isolated.

### Phase 5 — Hydrate / handoff (5-10 min)

Write a one-paragraph summary of what landed + what wasn't touched. Commit it to the PR descriptions, not to a separate doc (those become stale).

---

## What `done` looks like per PR

1. **One theme.** Title says exactly what changed: `chore(cleanup): <thing>`. Body explains why (the rationale comment that the cleanup retires, or the lint count it reduces).
2. **Gates green locally** with REAL exit codes (`fmt_rc=0 clippy_rc=0 lib_rc=0`), reported in commit body.
3. **Diff is reviewable in <2 min.** No 500-line PRs. If your auto-fix produced 500 lines, ship the largest-impact file separately + the rest as a follow-up.
4. **PR body uses the `feedback_wire_send_shell_metachars` discipline.** `gh pr create --body-file /tmp/<name>.md`, never `--body "…"` with backticks.
5. **CI green before self-merge.** Wait for `gh pr checks <n>` to settle. If anything fails on CI but passed locally, investigate as code first.
6. **Self-merge** with `gh pr merge <n> --squash --delete-branch` IF you've been operator-authorized for the cleanup batch ("go scrub for an hour" or similar). Trust-adjacent changes (forbidden by the hard constraints anyway) need explicit per-PR approval.

---

## Suggested cuts to look for first

Prioritized by signal-to-noise:

1. **`#[allow(dead_code)]` with stale version comments.** Already done #118 for `signing.rs::strip_did_wire`. Re-grep periodically — code grows them.
2. **Pedantic-lint frequency table top 5.** Typically uninlined-format-args, redundant closures, let-else, manual unwrap-or, Debug-formatting-of-Display-impls. Cheapest first.
3. **Stale `// v0.5.X` comments in current code.** The repo's actively versioned; if a comment says "v0.7.0-alpha.6: prefer peer's published character override" and we're on v0.14, the prefix is fine context but worth scanning whether the behavior described is still accurate.
4. **Duplicated helpers across files.** `grep -rn 'fn <common_op>' src/` finds twins. Many discovered today were intentional (parallel CLI / MCP serializers, fixed via shared `op_claims_from_card` helper); some aren't.
5. **`unwrap()` in non-test code.** `grep -n '\.unwrap()' src/cli.rs | wc -l` gives a rough count; investigate the ones that look load-bearing.
6. **Dead test fixtures.** Tests with no `#[test]` attribute, or fixtures that aren't called from any test. Hard to spot; only worth a pass if you've got time.

**Out of scope (deliberate):**
- Splitting `src/cli.rs` (15k lines). That's a 1-2-day architectural shift, NOT a session cleanup.
- Adding new tests. The point is to clean what's there, not grow.
- Trimming dependencies. Removing a dep that "looks unused" without `cargo-machete` confirmation is a foot-gun.
- "Modernizing" sequential-await-into-`tokio::join!`. Concurrency rewrites need design context this session doesn't have.

---

## Process discipline

- **Persona critique BEFORE every PR**: programmer / SRE / security / DX / reviewer. State each one-line in your message to the operator before executing. If any persona objects, surface and ask.
- **Persona critique AFTER each PR merges**: in your summary message — "what shipped / what surfaced / what's queued". This drives next-iteration scope.
- **Caveman mode** (per global): terse, technical substance exact, drop filler. Code unchanged.
- **The stale-hook nag is informational.** `npx gitnexus analyze --embeddings` once at end of the session, not after every commit.
- **Don't touch `AGENTS.md`.** Its `<!-- gitnexus:start -->` block regenerates itself; the rest is operator-canonical. Cleanup PRs leave it alone — if your `cargo clippy --fix` touches it as drift, `git checkout -- AGENTS.md` before staging.

---

## Anti-patterns (instant-reject in review)

- **Mixing cleanup with feature work.** "While I was in there I also added X" gets rejected. Ship feature work separately.
- **Touching trust paths to satisfy a lint.** A `clippy::uninlined_format_args` warning inside `pair_invite.rs` is fine to fix; a `clippy::needless_pass_by_value` requiring a function-signature change is NOT (semantic change in trust code). Stop.
- **A `cargo update` that "happened" alongside a cleanup commit.** Lockfile changes belong in their own audit-attached PR.
- **Auto-applying `clippy --fix` without reading the diff first.** Some lints are wrong for some idioms; eyeball the diff.
- **Bundling AGENTS.md gitnexus-stats refresh with a cleanup PR.** Pre-existing drift; orthogonal; reset it.
- **Force-pushing to clean up commit hygiene.** This is a session cleanup, not a history rewrite. Use `git commit --amend` only before push.
- **Restarting the daemon to "test" a cleanup PR.** Unless the PR touches the daemon, no restart needed; trust your gate.

---

## Stop conditions / when to ask

- A cleanup unexpectedly requires touching trust code (`pair_invite.rs`, `identity.rs`, `signing.rs`, `org_membership.rs`, `sas.rs`). Hard stop; surface to operator.
- A clippy lint requires a public-API change to fix. Stop; this is a semver concern, separate PR with operator approval.
- A test you'd modify is `#[ignore]`'d and you don't know what gated it. Read git blame + memory; surface if still unclear.
- Stress test fails. Bisect to last-known-green; surface; the cleanup batch goes ON HOLD until investigated.
- You hit `/compact` mid-session. Re-verify branch state per `feedback_post_compact_branch_state_verification` before any further push.

---

## What you start with

- `main` at the tail of the most-recent cleanup batch (the operator's last `git log --oneline -5` shows it).
- Clean working tree except possibly pre-existing AGENTS.md gitnexus-stats drift (leave alone).
- A test suite the operator has stress-verified within the last 24h (re-verify before claiming "ship-clean").
- No active feature PRs from peers blocking main. If there are, the cleanup discipline does NOT change — but pick themes that don't conflict (don't pre-emptively modernize a file someone has open in a feature PR).

Start with Phase 0 (survey, parallel). Pick top 2-3 themes by ratio of (operator-felt-improvement / review-cost). Ship them serially as bounded PRs through the gate. Stress-test ONCE near the end. Persona-critique BEFORE and AFTER. Caveman tight.
