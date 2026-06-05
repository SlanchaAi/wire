# RFC-006: Session-key precedence + WIRE_HOME pin observability

**Status:** Draft
**Tracking:** #210
**Author:** slate-lotus
**Date:** 2026-06-03 (renumbered 2026-06-05 — RFC-005 slot taken by `0005-remove-backwards-compat.md`)
**Target:** v0.14.x (surface honesty) → v0.15 (precedence flip, gated, lands with paul's RFC-005 Phase 4 cut)
**Question this answers:** When an operator's shell pins `WIRE_HOME` in env before launching an agent host (Claude Code / Codex / Copilot), why does it silently override the session-key resolution chain, and how does the operator find out which signal won?

---

## Relationship to RFC-005 (remove-backwards-compat + wire nuke)

Paul's [RFC-005](0005-remove-backwards-compat.md) Phase 4 deletes the legacy `sessions/<name>` *layout reader* (the v0.6 top-level cwd-derived home, plus `did:wire:<handle>` no-fingerprint DIDs and flat endpoint shims). That closes the "wire chose cwd-shape on its own when no `WIRE_HOME` was set" failure path entirely.

This RFC is **orthogonal**: it targets the case where `WIRE_HOME` IS set in env — by a stale operator shell profile, IDE wrapper, or launcher script — and silently overrides the session-key chain regardless of the path's shape. Phase 4 removes the layout; the env-var override at `src/session.rs:1141` survives Phase 4 unchanged, so a shell-pin `WIRE_HOME=…\sessions\willard\config\wire` after Phase 4 either points to a nuked path (wire creates an empty home there → still bypasses session-key) or to nothing (same outcome).

The detection-shape angle of the original draft (§B legacy-cwd-shape regex) is **withdrawn** — paul deletes the shape, regex is moot. The §A surface-honesty piece and §C precedence-flip piece below remain load-bearing and complementary to paul's Phase 4. Target both for the v0.15.0 cut.

## TL;DR

- Today: `WIRE_HOME` env presence silently short-circuits the session-key resolution chain at `src/session.rs:1141`, BEFORE `resolve_session_key()` is consulted. Operator can't tell which signal won; symptom is identity collapse across distinct agent-host sessions. Reported as #210.
- Two-layer fix:
    1. **§A — `session_source` field on `wire whoami --json`** (v0.14.x, pure-additive): surfaces which signal won the resolution race. Operator immediately sees `env:WIRE_HOME` vs `env:CLAUDE_CODE_SESSION_ID` vs `pidfile` vs `mint` etc.
    2. **§C — Precedence flip** (v0.15, gated, lands with paul's RFC-005 Phase 4 in the same breaking cut): session-key env vars beat `WIRE_HOME` in agent-host context. `WIRE_HOME_FORCE=1` reverts to today's WIRE_HOME-wins ordering for operators who deliberately pin (multi-tab fleet share by design).
- §B (legacy-cwd-shape detection warning) **withdrawn** — paul's RFC-005 Phase 4 deletes the shape itself.
- Kill criterion: §C v0.15 flip breaking any unanticipated operator's tooling → revert §C, keep §A. §A is pure-additive, has no rollback risk, ships ahead of v0.15 regardless.

## Motivation

### The collision shape

In v0.13.5, bright-camellia shipped the PID-file parent-walk adapter so the wire MCP server could derive its session id even when Claude Code didn't forward `CLAUDE_CODE_SESSION_ID` into the MCP child env. Quoted on the wire mesh (2026-05-25):

> cwd resolution is gone entirely now, so it can't collapse even if misconfigured

True for *new* operators starting clean on v0.13.5. False for operators who carry a pre-v0.13.5 workaround in shell profile, wrapper script, IDE config, or muscle memory.

The pre-v0.13.5 workaround was:

```powershell
# Pin WIRE_HOME before launching claude so the MCP server boots as the
# project-specific identity instead of the global default kelp-sable.
$env:WIRE_HOME = (wire session env | sls 'WIRE_HOME=(.+)').Matches.Groups[1].Value
& claude.exe @args
```

This wraps the `claude` command, runs `wire session env` to get the cwd-derived session's home, exports it, then launches Claude Code. Every shell child inside Claude Code — including every `wire whoami` from the Bash/PowerShell tool, every wire MCP server spawned by `.mcp.json` — inherits `WIRE_HOME` pointing at the cwd-derived `sessions/<sanitized-cwd-basename>/` home.

`maybe_adopt_session_wire_home` at `src/session.rs:1140`:

```rust
pub fn maybe_adopt_session_wire_home(label: &str) {
    if std::env::var("WIRE_HOME").is_ok() {
        return;  // ← short-circuits before resolve_session_key() is consulted
    }
    let (home, why) = if let Some((key, source)) = resolve_session_key() {
        // by-key home derivation — never reached when WIRE_HOME is set
        ...
```

So the v0.13.5 session-key chain (`WIRE_SESSION_ID` > `CLAUDE_CODE_SESSION_ID` > … > PID-file parent-walk) **never gets a turn** if the legacy pin is in env.

### Operator-visible cost

- All N Claude Code tabs in the same cwd → same persona (`kelp-sable` on willard's box).
- N wire MCP server processes + N daemon processes accumulating, all bound to the same `sessions/willard/` home, racing the same inbox cursor.
- `wire whoami --json` returns the same DID from every tab, no signal that resolution short-circuited at the env-pin layer.
- Upgrading from v0.12.x → v0.13.5+ silently keeps the operator in the broken state. There is no migration prompt because there is no detection.

### Why this is wire-side, not just stale-profile

A stale shell profile is the operator's responsibility, but wire could detect the situation and surface it. Today wire is silent. Three honest answers wire could ship without changing operator-controlled contracts:

1. Tell the operator which signal won the resolution race (`session_source` on `whoami`).
2. Detect a near-certain-stale pattern (cwd-derived `WIRE_HOME` shape + session-key env var present) and warn.
3. (Eventually, gated, opt-out-able) Prefer the session-key over a stale-shaped pin.

## Design

### §A: `session_source` on `wire whoami --json` (v0.14.x — pure additive)

Add one field. No schema break — clients ignoring unknown fields keep working.

```json
{
  "did": "did:wire:slate-lotus-88232017",
  "handle": "slate-lotus",
  "config_dir": "C:\\…\\sessions\\by-key\\0c38ce498aa9d955\\config\\wire",
  "session_source": "env:CLAUDE_CODE_SESSION_ID",
  ...
}
```

Possible values (exhaustive, lowercase, stable for tooling):

| value | meaning |
|---|---|
| `env:WIRE_HOME` | `WIRE_HOME` env set; short-circuit at `session.rs:1141` |
| `env:WIRE_SESSION_ID` | session-key chain resolved on `WIRE_SESSION_ID` |
| `env:CLAUDE_CODE_SESSION_ID` | session-key chain resolved on `CLAUDE_CODE_SESSION_ID` |
| `env:CODEX_SESSION_ID` | session-key chain resolved on Codex CLI adapter |
| `env:COPILOT_AGENT_SESSION_ID` | session-key chain resolved on Copilot CLI adapter |
| `env:VSCODE_GIT_REPOSITORY_ROOT` | VS Code workspace adapter |
| `pidfile` | `~/.claude/sessions/<pid>.json` parent-walk (PID-file adapter) |
| `mint` | per-process key minted at MCP startup (no session id found) |
| `cwd-detect` | legacy `detect_session_wire_home` from `session_registry.json` |
| `cwd-derive` | legacy `derive_name_from_cwd` (sanitized basename) |

Implementation: thread the `source` label out of `resolve_session_key()` (already returned, just not surfaced) AND out of `maybe_adopt_session_wire_home`'s `why` string (already computed, just not stored). Stash on `process::IDENTITY_STATE` (existing `OnceCell`-style singleton — confirm during impl) and read on `cmd_whoami`.

### §B: Legacy-pin deprecation warning — **WITHDRAWN**

The original draft's §B detected a cwd-derived legacy `WIRE_HOME` path shape (`sessions/<name>/config/wire` excluding `by-key/<hex>`) and emitted a deprecation warning. Paul's [RFC-005 Phase 4](0005-remove-backwards-compat.md) deletes the entire `sessions/<name>` layout reader, so the legacy shape no longer exists as a wire-resolved layout. The shape-detection regex becomes moot. Detail preserved below in case a partial re-introduction is warranted; treat as struck-through for v0.15 planning.

<details><summary>Original §B detail (struck — see paul's RFC-005 Phase 4)</summary>

When `maybe_adopt_session_wire_home` short-circuits on `WIRE_HOME`, check:

1. Does the path match the cwd-derived legacy shape? Regex over the absolute path:
   ```
   .*/sessions/[^/]+/config/wire$
   ```
   where `<name>` segment is NOT `by-key`. By-key homes match `.*/sessions/by-key/[0-9a-f]{16}` — operator-explicit modern pin, exempt from warning.

2. Is a session-key env var present? `WIRE_SESSION_ID` OR `CLAUDE_CODE_SESSION_ID` OR `CODEX_SESSION_ID` OR `COPILOT_AGENT_SESSION_ID` non-empty + non-`${…}`.

3. If both, emit one-time stderr warning:
   ```
   wire warning: WIRE_HOME points to a cwd-derived legacy home
   (`<path>`), but a session-key env var (CLAUDE_CODE_SESSION_ID) is
   set. Pre-v0.13.5 operator workarounds (shell-profile pinning of
   WIRE_HOME from `wire session env`) silently override the
   v0.13.5+ session-keyed resolution chain. To migrate: unset
   WIRE_HOME in your shell profile. See RFC-005 / #210.
   Suppress this warning: WIRE_QUIET_LEGACY_PIN=1.
   ```

4. Gate visibility identically to the existing autosession line at `session.rs:1212-1219` — interactive stderr OR `WIRE_VERBOSE=1`.

Suppression: `WIRE_QUIET_LEGACY_PIN=1` — operator-explicit "yes I'm pinned legacy, don't tell me again."

</details>

### §C: Precedence flip (v0.15 — gated, lands with paul's RFC-005 Phase 4)

Reverse the order in `maybe_adopt_session_wire_home`:

```rust
pub fn maybe_adopt_session_wire_home(label: &str) {
    // v0.15: session-key env vars beat legacy-shaped WIRE_HOME.
    // WIRE_HOME pointing at a by-key home (operator explicit, modern)
    // OR set with WIRE_HOME_FORCE=1 (operator explicit, legacy-shape
    // override) still wins. Pre-v0.13.5 cwd-derived pin loses to the
    // session-key chain.
    let wire_home_env = std::env::var("WIRE_HOME").ok();
    let session_key = resolve_session_key();

    let prefer_session_key = match (&wire_home_env, &session_key) {
        (Some(path), Some(_)) =>
            is_legacy_cwd_shape(path)
            && std::env::var("WIRE_HOME_FORCE").is_err(),
        _ => false,
    };

    if let Some(path) = wire_home_env && !prefer_session_key {
        // legacy path: WIRE_HOME wins
        return;
    }
    // session-key path
    ...
}
```

Where `is_legacy_cwd_shape(path)` matches `.*/sessions/[^/]+/config/wire` excluding the `by-key/<hex>` shape.

`WIRE_HOME_FORCE=1`: opt-out for operators who deliberately legacy-pin (e.g. running a fleet where multiple tabs DO share a single legacy home by design). Honest contract: "I know my WIRE_HOME looks legacy-shaped; I want it to win anyway."

### §D: Migration path

v0.14.x:
- Ship §A (whoami source field) only. Pure additive. No behavior change. Operator runs `wire whoami --json | jq .session_source` and immediately knows whether their identity came from `env:WIRE_HOME` or the session-key chain.

v0.15:
- Default to §C precedence flip, lands alongside paul's RFC-005 Phase 4. `WIRE_HOME_FORCE=1` reverts to today's WIRE_HOME-first ordering for deliberate fleet-share pins.
- Operators whose shell profile pins a stale `WIRE_HOME`: their next agent-host session resolves to the session-key by-key home instead of the env pin. Old per-session inbox state at the pinned path is untouched on disk; the new session just stops using it. Migration is observably different identity (likely a new persona), not data loss.
- For operators who ALSO get nuked by `wire nuke` (paul's RFC-005 Phase 1): pinned `WIRE_HOME` may point at a wiped path — wire creates an empty home there. The §C flip makes the session-key path win instead of the empty home, which is the desired outcome.

## Security

- **No new attack surface.** Both layers are local-process introspection; no network, no signature flow change.
- **Identity-clarity invariant:** §A makes which signal resolved identity *observable* — strict improvement over "silent winner."
- **Operator-explicit pin contract:** preserved. `WIRE_HOME` pointing at a by-key home OR set with `WIRE_HOME_FORCE=1` always wins. The flip in §C only deprecates the cwd-derived legacy shape, which was a workaround pattern, never a stable contract.
- **Cross-session identity merge** (the bug being fixed): silent today, observable under §A, warned under §B, blocked under §C. Threat surface shrinks at every layer.
- **No threat model entry change required.** Cross-reference `docs/THREAT_MODEL.md` — this is a UX/observability fix on the existing resolution chain, not a trust-tier change.

## Out of scope

- **Auto-migration / auto-unset of `WIRE_HOME` from operator shell profile.** Wire MUST NOT modify shell startup files. Warning + RFC link is the limit.
- **Removing the legacy `sessions/<name>/config/wire` home layout.** Existing data preserved; only resolution priority changes. Compaction of orphan legacy homes is a separate RFC.
- **Codex / Copilot / VS Code adapter behavior changes.** Out of scope here — they ride the same `resolve_session_key` chain and benefit transparently from §A and §B without code changes in their adapter paths.
- **Cross-platform behavior on Linux + macOS.** Same logic, no OS branch needed — `WIRE_HOME` semantics are uniform across platforms.

## Acceptance criteria

- **AC-LP1 (surface honesty):** `wire whoami --json` emits a `session_source` field whose value is one of the enumerated 10 source labels for every successful invocation. Measured: unit test snapshots one example per branch. Owner: implementor.
- ~~**AC-LP2 (legacy-pin warning):**~~ **WITHDRAWN** — §B replaced by paul's RFC-005 Phase 4 layout deletion. Not gated, not tested.
- **AC-LP3 (precedence flip, v0.15):** With both `WIRE_HOME=<legacy-shape>` AND `CLAUDE_CODE_SESSION_ID=<uuid>` set, `wire whoami --json | jq .config_dir` resolves to `sessions/by-key/<hash>` derived from the UUID. Setting `WIRE_HOME_FORCE=1` reverts to the legacy pin. Measured: integration test. Owner: implementor.
- **AC-LP4 (back-compat for explicit by-key pin):** With `WIRE_HOME=<sessions/by-key/<hex>>` AND any combination of session-key env vars, `wire whoami --json | jq .config_dir` resolves to the pinned `by-key` home. Measured: integration test. Owner: implementor.
- **KILL CRITERION:** If §C lands in v0.15 and any fleet operator on the wire mesh reports unexpected identity change between v0.14.x → v0.15 that is NOT a legacy-shape pin (i.e., a genuine breakage), §C is reverted in the next point release. §A and §B remain — they are pure-additive and have no rollback risk.

## Open questions

- **Q1 — should §B warning fire for non-Claude-Code session-key envs?** E.g., `CODEX_SESSION_ID` set without `CLAUDE_CODE_SESSION_ID`. **Current proposal:** yes — the pattern (legacy-shape WIRE_HOME + ANY session-key env) is the diagnostic signal. Owner: @laulpogan to confirm before §B implementation.
- **Q2 — should `wire setup --apply` auto-strip a legacy `WIRE_HOME` from `.mcp.json`?** Could combine with this RFC's §B warning by, on `wire setup --apply`, scanning `~/.claude.json` + project `.mcp.json` for explicit `"env": {"WIRE_HOME": "..."}` entries that match the legacy shape and offering to remove them. Owner: @bright-camellia (owner of `wire setup`) to scope.
- **Q3 — should the `wire session env` verb itself be deprecated?** It's the canonical way operators end up with the legacy `WIRE_HOME` pin. The verb predates the v0.13.5 by-key resolution; arguably it should either (a) refuse with a deprecation message, (b) print the `by-key` home instead. Decision point: depends on whether any current tooling consumes `wire session env` output. Owner: needs grep across SlanchaAi tooling + paul's plugin marketplace registry.
- **Q4 — what does §C do for an MCP server (`label == "mcp"`) under a legacy-shape `WIRE_HOME` pin without `WIRE_HOME_FORCE`?** Strict reading of §C: it ignores the pin and runs the session-key chain (or mints per-process). Risk: legacy MCP servers running under deliberate explicit fleet-share pin break unexpectedly. Mitigation: §B's warning in v0.14.x gives one full version of lead time. Owner: implementor to call out in PR description.
- **Q5 — should `wire doctor` proactively grep known shell-profile locations for legacy `WIRE_HOME` pins?** §B catches the pin at every `wire` invocation, but §B fires only if the operator already ran a `wire` command in a tainted shell. A `wire doctor` profile-grep would surface the latent pin even on a clean install before the first `wire whoami`. The lookup table:
  - **Windows:** `$PROFILE.CurrentUserCurrentHost` for both pwsh and `powershell.exe` (PS7 + PS5 use DIFFERENT paths: `Documents\PowerShell\` vs `Documents\WindowsPowerShell\`, often duplicated under `OneDrive\Documents\` when OneDrive syncs Documents), Windows Terminal `settings.json` `startupActions` strings, `cmd.exe` AutoRun reg key (`HKCU:\Software\Microsoft\Command Processor\AutoRun`).
  - **macOS/Linux:** `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile`, `~/.config/fish/config.fish`, `/etc/profile.d/*.sh` (read-only check), `/etc/environment`.
  - Grep predicate: line matches `WIRE_HOME[=\s]+` AND the value parses to a path matching the cwd-derived legacy shape (excludes by-key paths). Report path + line number per match. Operator-readable, no auto-modification (preserves the "wire does not modify operator's shell startup files" invariant from §Out of scope).
  Concrete scenario this catches (2026-06-03 willard's box, #210): operator switches their primary terminal app (e.g. command prompt → Windows Terminal launching PS7), and only then does the legacy `claude` wrapper in `OneDrive\Documents\PowerShell\Microsoft.PowerShell_profile.ps1` start running. The pin existed for weeks but was dormant under the previous launch path. `wire doctor` profile-grep surfaces it the moment `doctor` is run, not the moment the symptom manifests across the operator's whole fleet of CC tabs. Owner: bright-camellia (owner of `wire doctor`) to scope cost vs §B's existing runtime-detect.

## Alternatives considered

- **Do nothing.** Operator reads CHANGELOG, fixes own shell profile. Cost: every new wire operator who carries a pre-v0.13.5 pin pattern hits the silent-collapse failure mode, wastes hours debugging. The cost compounds linearly with operator-onboarding rate. Rejected: the diagnostic gap is real, not theoretical (closes #210 head-on).
- **Auto-strip `WIRE_HOME` from shell profile.** Wire would inspect `$PROFILE` / `.bashrc` / `.zshrc` and rewrite. Rejected: violates the "wire does not modify operator's shell startup files" invariant. Surface honesty + warning is the proper limit.
- **Hard error on legacy-shape `WIRE_HOME` + session-key env var.** Refuse to start until operator resolves. Rejected: too aggressive; breaks operators with deliberate legacy pins. The `WIRE_HOME_FORCE=1` escape hatch already covers that case in §C; hard erroring is gratuitous.
- **Detect at `wire setup` time only.** §B's warning lives only in `wire setup` output. Rejected: most operators rarely re-run `wire setup`; the warning needs to fire at every `wire` invocation that hits the legacy short-circuit so operators see it in their actual workflow.
- **Surface `session_source` only via a new `wire doctor` check.** Skip §A; have `wire doctor` report. Rejected: `whoami` is the primary identity-introspection verb; surface-honesty there matters more than in `doctor`. Both can have it; `whoami` is non-negotiable.

## Sources

- #210 — regression reproducer + root-cause trace on willard's box.
- `src/session.rs:1140-1203` — `maybe_adopt_session_wire_home` short-circuit at line 1141.
- `src/session.rs:839-865` — `resolve_session_key` chain.
- `src/session.rs:874-877` — `valid_session_key` placeholder guard (excludes `${…}` literals).
- `src/session.rs:879-904` — PID-file parent-walk adapter (the v0.13.5 fix this RFC restores precedence to).
- wire mesh, 2026-05-25 — bright-camellia "v0.13.5 SHIPPED — cwd resolution gone entirely now" announcement.
- `docs/rfc/0001-identity-layer.amendment-same-machine.md` — PR #188 (this session's prior work) — same observability theme, different layer (per-op attestation envelope).
