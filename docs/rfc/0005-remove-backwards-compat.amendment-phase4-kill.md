# RFC-005 Amendment — Phase 4 KILL_CRITERION FIRE: 2 of 4 "legacy shims" preserved as live load-bearing code

**Status:** Resolved <!-- amendment-companion to RFC-005 §Phase 4 -->
**Date:** 2026-06-06
**Tracking:** PR #233 (Phase 4 DONE_WITH_CONCERNS), parent RFC-005 (#220)
**Resolves:** RFC-005 §Phase 4 design premise misread — captures the kill-criterion fire so future maintainers don't re-attempt the abandoned removals
**Verdict:** **Phase 4 shipped 2 of 4 shim removals; the other 2 are live canonical code, not dead.**

---

## The premise that fired

RFC-005 §Phase 4 listed four "legacy on-disk shims" as removal targets:

1. v0.6 top-level `sessions/<name>` layout (keep only `by-key/<hash>`)
2. Bare-integer pidfiles (keep JSON `DaemonPid`)
3. `did:wire:<handle>` no-fingerprint DIDs (keep `did:wire:<handle>-<8hex>`)
4. Flat endpoint-field fallbacks (keep `endpoints[]`)

Phase 4 went DONE_WITH_CONCERNS with **only items 2 and 3 removed.** Items 1 and 4 triggered the RFC's own KILL_CRITERION:

> §AC-4 **KILL CRITERION** — if removing the on-disk shims (Phase 4) cannot be done without re-introducing the multi-session resolution ambiguity that caused #170 (i.e., the by-key-only path can't cover a case the dual-layout did), Phase 4 is abandoned and the legacy session/pidfile shims stay; Phases 1–3 still ship.

The KILL_CRITERION is doing its job. This amendment documents *why* it fired, so the next operator reading RFC-005 cold doesn't try the same removal.

## What landed (PR #233, sound)

### Bare-integer pidfile removal (`4cce5be`)

- `PidRecord::LegacyInt` deleted from the pidfile parser
- 3 `cli.rs` match arms + the tolerance test removed
- Non-JSON pidfiles now read as `Corrupt` (which is the right failure mode — a stale bare-int file is no longer a valid wire daemon record)
- Test fixture converted to JSON
- **Production reader/writer audit: ZERO callers found** — confirmed dead

### No-suffix DID builder removal (`0281fa7`)

- `agent_card::did_for` (pre-v0.5.7 `did:wire:<handle>` form, no pubkey suffix) deleted
- `did_for_with_key` is the only remaining constructor; every production callsite goes through it (verified via grep + the #206 enroll work cleanup)
- `display_handle_from_did` is preserved (load-bearing PARSE helper — must accept legacy `did:wire:<handle>` strings still present in old peer cards)
- **Production caller audit: ZERO callers** for the builder — confirmed dead

## What's preserved — and why the RFC premise was wrong

### v0.6 top-level `sessions/<name>` layout — STAYS

The RFC framed `sessions_root/<name>` as a "v0.6 legacy shim" superseded by `sessions/by-key/<hash>`. This is a **misread of the codepath**:

- `sessions_root/<name>` is the **canonical OPERATOR-session layout** — driven by `wire session new`, `wire session env`, `wire session destroy`, `wire session list`, `identity promote`, and the bare-CLI auto-init path (`maybe_auto_init_cwd_session` in `src/cli.rs`).
- `sessions/by-key/<hash>` is a **parallel layout** for agent-host auto-resolution — driven by `WIRE_SESSION_ID` / `CLAUDE_CODE_SESSION_ID` adoption (`maybe_adopt_session_wire_home` at `src/session.rs:1158`).
- The two are **not redundant.** Each owns a distinct ownership domain: name-driven (operator-explicit) vs key-driven (agent-host-derived).

By-key-only would break:
- Every `wire session *` CLI verb (operators rely on the name as the human-readable handle)
- Bare-CLI auto-init outside any agent host (no session-id env var → must derive a name → must land in `<name>/` layout)
- The pair-all-local + sister-session mesh paths that enumerate `sessions_root/*` and skip `by-key/` (per `session.rs:510` — `if name == "by-key" { skip }`)
- The #170 / #174 fork-storm class regressions that the dual-layout was the FIX for, not the cause

**Verdict:** Live, canonical, NOT a shim.

### Flat / legacy endpoint-field fallbacks — STAYS

The RFC framed `relay_url` + `slot_id` + `slot_token` top-level fields as a "legacy shim" superseded by `endpoints[]`. This is also a misread:

- `endpoints[]` is the v0.5.17+ shape (scope-tagged Federation/Local/Lan).
- The flat top-level fields are the v0.1–v0.5.16 shape and **live readers** for older agent cards still present in peer trust state on the wire mesh today (pinned peers minted on v0.5.16, cards stashed in `trust.json` going back to v0.2.5).
- Removing the flat-field reader would silently drop every pre-v0.5.17 peer card on `wire pull` / `wire status` — a regression scoped exactly to operators who paired before May 2026 and haven't re-paired since.

**Verdict:** Live alternative-canonical reader, NOT a shim. The path forward is documented migration (v1.0 cuts the flat fields with a 1-version deprecation window), not silent removal.

## Lessons (for the next maintainer reading RFC-005 cold)

1. **"Legacy" and "dead" are not synonyms.** A code path can be v0.1-shaped and still load-bearing for v0.13.5 peers. RFC-005 §Phase 4 conflated the two.
2. **The kill-criterion is load-bearing.** §AC-4 was written specifically to catch this; without it, Phase 4 would have shipped a stealth regression for pre-v0.5.17 pairings.
3. **Phases 1–3 + the 2-of-4 wins ship cleanly.** Phase 4 going DONE_WITH_CONCERNS is the right outcome, not a failure mode.
4. **The remaining legacy code paths are documented + tested.** A future "actually remove these" effort needs a separate RFC with a real migration plan + a deprecation cycle (one wire version with a warning before removal). Naive removal is unsafe.

## What this amendment is NOT

- A retreat from the RFC-005 design goal (canonical surface, kill the agent-confusion gap). Phases 1–3 + the 2-of-4 Phase 4 wins delivered the bulk of that.
- A claim that `sessions/<name>` + flat endpoint fields are aesthetically clean. They're not. They're load-bearing, which is a different property.
- A blocker for v1.0 cleanup. A v1.0 RFC with a deprecation window can legitimately retire these paths once the operator base has migrated.

## Sources

- PR #233 (Phase 4 DONE_WITH_CONCERNS) — the kill-criterion fire in practice
- RFC-005 §Phase 4 + §AC-4 — the kill-criterion that fired
- `src/session.rs:510` — the `by-key` skip-marker in `list_local` (proves the two layouts coexist by design)
- `src/cli.rs::maybe_auto_init_cwd_session` — the canonical `<name>/`-layout auto-init path
- #170 / #174 — the fork-storm class regressions the dual-layout fixes
