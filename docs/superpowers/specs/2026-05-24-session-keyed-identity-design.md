# wire v0.13 — session-keyed identity (design spec)

- **Date:** 2026-05-24
- **Status:** Draft for review
- **Author:** outback-sandpiper (Claude Code) + operator
- **Supersedes:** the v0.5.16 cwd-registry + machine-wide-default session model

## Problem

wire began as one identity per machine (a single `WIRE_HOME`). Per-cwd sessions
(v0.5.16) were added as an overlay: `wire session new` creates an isolated
`WIRE_HOME` per project, and `detect_session_wire_home(cwd)` maps `cwd →
session` via a registry keyed by the raw `cwd.to_string_lossy()` path string
(`session.rs:611`). The original single identity remained as the **fallback**.

This produces a class of bugs, all rooted in the same place:

- **Windows "every session same handle":** the `by_cwd` key is an un-normalized
  path string. On Windows the lookup key (Claude's cwd) and the stored key
  differ in drive-letter case (`C:`/`c:`) and separators, so every lookup
  misses → falls through to the **one shared default** → every session
  collapses onto the same identity.
- **Ancestor-shadowing / "two Claudes identical":** same silent-collapse via a
  different detection miss.

The collision sink is the silent fallback to a shared default whenever cwd
detection misses.

## Goals

1. Each session deterministically gets its **own unique** wire identity — no
   cwd dependence, no path-string matching, **no shared default at all**.
2. Host-**agnostic** core, with a Claude Code adapter and the path left open
   for other hosts (Cursor, Desktop, future).
3. Stable identity across a host session's **resume** where the host exposes a
   durable session id.

## Non-goals

- Changing the wire protocol, signing, or pairing semantics (all key off DID,
  unchanged).
- Project-persistent identity by default (available opt-in; see §4).
- Removing the CLI. wire *is* a CLI binary; `wire mcp` / `relay-server` /
  `daemon` / `up` are CLI subcommands. What we drop is the **default messaging
  identity**, not the CLI (see §3).
- Garbage-collecting orphaned session identities — explicitly **deferred** (§5).

## Design

### §1 — Session-key resolution chain (host-agnostic, adapter-extensible)

wire core gains `resolve_session_key() -> SessionKey`, walked in order:

1. **`WIRE_SESSION_ID`** — explicit universal override. Any harness can set it.
   The host-agnostic escape hatch and the recommended integration point.
2. **Known-host adapters** — `CLAUDE_CODE_SESSION_ID` (verified present + stable
   per-conversation; it is the same value the auto-memory system keys off, so
   Claude Code resumes are stable). Additional hosts are pure additions to the
   chain — it stays open.
3. **Generic fallback** — a per-process id generated once at startup, stable for
   that process's lifetime (= one host session).

`SessionKey` carries its source (`override | host:<name> | process`) so
downstream logic can treat ephemeral vs durable keys differently.

**Both the MCP server and terminal CLI commands run this same chain**, so within
one Claude Code session the `wire mcp` server and any `wire <verb>` the agent
runs in that session resolve the **same** `CLAUDE_CODE_SESSION_ID` → the **same**
identity. CLI and MCP are automatically consistent within a session.

### §2 — Identity per key, not per cwd

`WIRE_HOME = <sessions_root>/by-key/<hash>/` where `hash = sha256(session_key)`
truncated to **16 hex** (64 bits — collision-safe at this scale; never
shorter). No cwd lookup, no path normalization → **the Windows bug cannot
exist** (nothing to normalize or miss). Home dirs are `0700`.

### §3 — No default identity (MCP-only identity model)

There is **no machine-wide default**. Every identity is session-keyed. This
removes the collision sink entirely — there is nothing for a detection miss to
collapse onto, because there is no detection-by-cwd and no shared fallback.

Consequence for bare CLI **messaging** (`wire send` / `wire whoami` from a shell
with no host session and no `WIRE_SESSION_ID`): it has no session and must
target one explicitly (`WIRE_SESSION_ID=…`, `WIRE_HOME=…`, or `--session <name>`)
— or it operates on a `process`-source ephemeral identity. There is no longer a
zero-config terminal identity. In practice this is rare: inside Claude Code the
CLI inherits `CLAUDE_CODE_SESSION_ID` (§1), and **ops/infra commands**
(`relay-server`, `daemon`, `up`, `session`, `doctor`) never needed a *messaging*
identity — they act on the machine or take an explicit session name.

The legacy machine-wide default identity is **retired** (not converted to a
base). Existing setups migrate via the §6 bridge.

### §4 — Local-only by default + single daemon + opt-in cwd pin

- **Local-only by default.** A session-keyed identity allocates only a
  local-relay slot (`127.0.0.1:8771`); it does **not** auto-claim a nick on the
  federation relay. The public phonebook is not flooded with one-shot personas.
  Federation presence is an explicit promotion.
- **Single machine-wide daemon** syncs all session homes under
  `by-key/`, instead of one daemon per session — no daemon swarm.
- **cwd-registry → opt-in pin.** `wire session pin` records `cwd → session-key`
  for operators who *want* project-persistent identity (and federation
  promotion). The default path (§1) never touches cwd. Only pinned/promoted
  identities appear in the phonebook.

### §5 — GC: deferred (accepted accumulation)

Session-keyed identities are ephemeral (one per session ever), so homes under
`by-key/` accumulate. **GC is explicitly deferred** — for now this is fine and
even useful: it inflates the local session/identity count (an adoption signal)
and there is no resource pressure at current scale. A future `wire session gc`
(TTL-based prune of stale `by-key/` homes + local-slot release) is noted as
follow-up, not built in v0.13. Because §4 keeps ephemeral sessions local-only,
accumulation stays **off the public phonebook** — it's local clutter, not
directory pollution, so deferring GC costs nothing public.

### §6 — Resume stability

A persisted `session-key → home` map means a resumed session with the same host
session id reuses its identity + pairings. Verified: `CLAUDE_CODE_SESSION_ID` is
stable per conversation (equals the durable auto-memory `originSessionId`), so
Claude Code resumes are stable. Hosts that regenerate their id per launch
degrade gracefully to a fresh identity — wire makes **no false promise**; the
`WIRE_SESSION_ID` override gives explicit stability to any harness.

### §7 — Security: same-uid trust domain

Keying identity off an env var means any **same-uid** process that sets
`WIRE_SESSION_ID` / `CLAUDE_CODE_SESSION_ID` can assume the session (its
`WIRE_HOME` holds the Ed25519 private key). This is within wire's existing
**same-uid local-mesh trust anchor** (the within-system model already trusts
same-uid filesystem access) and is therefore acceptable — stated explicitly.
Cross-uid isolation relies on `0700` homes + OS file permissions, unchanged.
The §2 hash is long enough (64 bits) that distinct keys cannot collide into
each other's homes.

## Migration

**Bridge, don't force-re-key.** On first v0.13 run, if a resolved session-key
has no home yet AND the current cwd matches an existing v0.5.16 registry entry,
**adopt** that registry's identity for this key (one-time bridge), preserving
the identities we just re-keyed (outback-sandpiper + the local mesh). After the
bridge, the session is key-resolved; subsequent distinct sessions in the same
cwd get their own keys (intended — distinct windows = distinct identities). The
retired machine-default identity is reachable only via explicit
`WIRE_HOME`/`--session` if needed.

## Behavior change to call out

Two Claude windows in the **same project** previously shared one identity (the
bug, but occasionally relied upon). Under v0.13 they are **distinct** by design.
Workflows that wanted "same project = one shared agent" use §4 pinning.

## Testing

- Unit: `resolve_session_key()` chain order (override > host > process);
  `WIRE_HOME` derivation determinism; hash collision-resistance.
- Integration: two distinct session keys → two distinct homes/identities (no
  collision); same key twice → same home (resume stability); CLI + MCP in one
  session (same `CLAUDE_CODE_SESSION_ID`) → same identity.
- Integration: bare CLI with no session + no `WIRE_SESSION_ID` → clear "no
  session, target one explicitly" error (no silent default).
- Integration: session-keyed identity allocates a local slot only, no
  federation claim.
- **Windows verification (REQUIRED, cannot be done on macOS):** two sessions in
  the same project on Windows get distinct identities (original bug gone). Per
  the deploy-artifacts-need-target-test rule, must be checked on real Windows
  before claiming the bug fixed.

## Rollout

v0.13 (minor — behavior change). Ships via the existing tag → release/crates/fly
pipeline. The bridge keeps existing setups working; no operator action for the
common case.

## Open questions for review

1. Single machine-wide daemon vs lazy per-session daemons — spec assumes single
   daemon; confirm.
2. `process`-source (generic, no host var) sessions: local-only AND ephemeral
   (not persisted past process), or persisted-for-process-lifetime only? Spec
   says process-lifetime only.
3. GC is deferred — agreed, but worth a one-line tracking issue so it isn't lost.
