# Wire v0.7.0-alpha.20 — Holistic Codebase Audit

Performed 2026-05-23 after shipping PR #26's 20 alpha commits (identity layer + character + auto-init + LAN + UDS + identity lifecycle CLI). Five parallel research agents covered: transport/relay, identity/pair flow, CLI/MCP surface, session/config/state, cross-cutting concerns. Synthesized below.

**Headline question:** if you were starting wire from scratch today knowing what we know now, what would you do differently?

**Headline answer:** wire's *protocol layer* (signing, canonical JSON, trust state machine, SPAKE2 + SAS, character determinism) is well-engineered and would stay. wire's *plumbing* (file IO scatter, monolithic cli.rs + relay_server.rs, pair-flow proliferation, public API surface) shows the wear of incremental growth. Three structural cuts would clean up 60% of the friction. Don't throw it out; refactor.

---

## TL;DR

- **Ship v0.7.0 (drop the alpha) as-is.** The identity-first work is done, characters are delightful, three-scope routing solves a real problem, the threat model is locked. Branch is ready.
- **v0.8 should invest in structure, not features.** Three high-leverage refactors below. Each pays itself back within one feature cycle.
- **Real risk:** by v0.9, cli.rs (10k lines) + relay_server.rs (2.3k lines) + 5-file-per-session state layer compound into unmaintainable territory. The window to refactor cleanly is now, before v1.0 lock-in.

---

## What's working (preserve, lean into)

| Area | Why it's load-bearing |
|---|---|
| **Signing + canonical JSON** | `canonical.rs` is the foundation; Nostr-style hash-then-sign decouples signing from semantics; test coverage validates ordering, no-whitespace, nested stability |
| **Character system** | Deterministic DID-derived nickname + emoji + 256-color palette; operator override doesn't perturb palette; sanitized on read; sentinel for malformed cards. Defensive in the right way. |
| **Trust state machine** | One-way promotion (UNTRUSTED → VERIFIED → ATTESTED → TRUSTED) with audit-trail metadata; bilateral asymmetry explicitly modeled |
| **Per-cwd isolation + registry-as-source-of-truth** | Each cwd → session_name → WIRE_HOME tree; transparent to operator; alpha.12 closed the name-derivation race cleanly |
| **Pull-loop cursor semantics** | Partitioned terminal vs transient rejection; transient blocks cursor for forward-compat; test coverage exists |
| **Atomic write pattern** | tmp + rename via `write_agent_card` / `write_registry` / `write_display_overrides` (alpha.8) prevents 0-byte corruption mid-SIGKILL |
| **--json everywhere on CLI** | Stable API contract for agents; not retrofit, baked in from v0.1 |
| **Threat model discipline** | THREAT_MODEL.md tracks 11 named threats with status; evolves with features; v0.5.14 bilateral consent locked T2/T4 |
| **Service install (macOS + Linux)** | Native tooling shellouts (launchd + systemd); idempotent; linger nag for headless SSH; v0.5.23 phantom-log fix shows operator-focus |
| **Single global auto-init flock** | alpha.12 refactor from per-name to global lock + register-inside-lock pattern is correct. Cwd-collision race closed. |

---

## Showing wear (with severity)

### HIGH — structural debt blocking v0.8 work

1. **`cli.rs` at 10,154 lines with 71 `cmd_*` functions, monolithic.** Not spaghetti (well-structured), but cognitive load is real. Parallel work is hard. Test colocality is impossible. Flag explosion on `wire session new` (11 flags) is the most visible symptom.
2. **`relay_server.rs` at 2,300+ lines bundles 5 concerns:** in-memory state, disk persistence, HTTP handler dispatch, counter collection, token validation. Lock-unlock sequences scattered across handlers; `post_event` acquires the same lock 3 times. Single `Arc<Mutex<Inner>>` serializes ALL access (no read-write separation).
3. **State layer scatter:** 5+ separate JSON files per session (agent-card, private.key, trust, relay, display) with inconsistent IO patterns. `write_relay_state()` has TWO call patterns — wrapped in flock'd `update_relay_state()` (safe) vs direct `fs::write` (unprotected). ~10–12 unprotected call sites (cli.rs, pair_invite.rs, pair_session.rs). Latent race surface for multi-daemon/multi-CLI scenarios.
4. **Public API surface is unintentional.** `lib.rs` re-exports 54 items across 6 namespaces; most are internal orchestration (`session`, `endpoints`, `daemon_stream`, `service`). Pre-v1.0 this constrains every refactor — any move risks downstream breakage.

### MEDIUM — feature debt accumulating

5. **Pair flow has 4+ variants** (SAS/SPAKE2, invite-URL, bilateral pair-drop, local-sister) without a unifying abstraction. All four are "exchange signed envelopes + establish bilateral trust"; only the consent gate varies.
6. **Identity model conflates 3+ layers** (DID, Handle, display.nickname, profile.* blob). Character system (alpha.4+) and `pair_profile` (older) both touch display semantics but live in different files with different schemas.
7. **Backward-compat cruft.** Three versions of handle_claim. Legacy top-level relay_url + slot_id + slot_token alongside endpoints[] array. v0.5.14 bilateral gate gates *after* slot token already leaked at pair-init time.
8. **Verb-CLI vs Noun-CLI tension.** `wire init` + `wire claim` (verbs) coexist with `wire identity create` + `wire identity publish` (nouns). Both work; both confuse.
9. **Test gaps for multi-machine flows.** 200 tests cover same-box pairing + relay + daemon. NO tests for: `maybe_auto_init_cwd_session`, `cmd_session_new` flag combinations, `cmd_identity_*` commands, cross-machine character lifecycle, `--with-lan` end-to-end, `--with-uds` integration.
10. **Auto-init lives in cli.rs but is called from both cli + mcp.** Module-dependency inversion (mcp imports cli). Should be in `session::` module.

### LOW — papercuts worth noting

11. **`unsafe env::set_var` contract enforced by comment only.** Safe in practice (mcp::run calls before thread spawn); fragile if future code shifts the call site.
12. **Symlink + macOS firmlink resolution still raw-string** in cwd → session_name mapping. Two symlink targets → two duplicate sessions for the same project.
13. **Daemon SSE stream subscriber spawns threads with `expect()`**, silent fall-back to polling on thread-spawn failure. No observability hook.
14. **HTTP-as-protocol-substrate** doing 3 round-trips for SPAKE2 + bootstrap exchange. Binary format would shave ~40% off wire size + enable streaming.
15. **`macaroon.rs` is future-scaffold with 0 call sites.** Either plumb it or drop it.
16. **Character determinism brittle under list-length changes** (alpha.4 doubled lists; pre-alpha.4 DIDs now render different characters). No `character_v1` / `character_v2` versioning.
17. **Windows is an orphan.** UDS Unix-only, service.rs bails on non-(macOS|linux). README claims cross-platform.

---

## If I were designing wire from scratch today

Five structural cuts that would land most of the wins:

### 1. State layer → SQLite (eliminates 3 race classes)

Replace the 5-JSON-file-per-session pattern with `<session_home>/config/wire/state.db` (SQLite WAL mode). Tables: `identity`, `endpoints`, `trust`, `peers`, `display`, `slots`, `cwd_sessions` (registry). Keep `private.key` as a separate 0600 file (secret material).

Gains:
- No more flock ceremony (`update_registry`, `update_relay_state` — both replaced by SQLite transactions)
- No more tmp+rename (atomic by construction)
- No more `write_relay_state` vs `update_relay_state` two-pattern split (eliminates the 10+ unprotected call sites)
- Indexed cwd lookups instead of read-every-cwd registry scans
- ALTER TABLE for forward-compat schema evolution
- Foundation for query-based features ("list pinned peers in this trust tier")

Cost: sqlite crate dep + migration script for existing sessions.

### 2. Module split for cli.rs + relay_server.rs

```
src/cli/
  mod.rs (top-level Command enum + dispatch only)
  session.rs   (~1500 lines: session new/list/destroy/pair-all-local/...)
  identity.rs  (~800 lines: rename/show/list/create/persist/publish/demote/destroy)
  message.rs   (~600 lines: send/tail/verify/whois)
  mesh.rs      (~500 lines: broadcast/role/route/status)
  pair.rs      (~1000 lines: pair-host/pair-join/pair-accept/invite/accept)
  relay.rs     (~400 lines: relay-server/bind-relay/rotate-slot)
  ...

src/relay/
  mod.rs (lib entry)
  state.rs       (Inner struct + slot/token/pair lifecycle data)
  handlers.rs    (HTTP handlers — JSON parsing + dispatch, no logic)
  persistence.rs (disk IO: append, reload, cleanup, counter snapshots)
  auth.rs        (bearer token validation, today scattered)
  router.rs      (axum Router assembly)
```

Each module 1-2k lines max. Tests colocate. Parallel work unblocked. Lock granularity becomes per-domain (slot reads don't block handle claims).

Cost: ~3-5 days of mechanical move + verification. Zero behavior change.

### 3. Collapse pair flow under one signed-envelope-exchange abstraction

```rust
struct PairEnvelope {
    from_card: AgentCard,
    from_endpoints: Vec<Endpoint>,
    timestamp: i64,
    signature: Signature,
}

trait ConsentGate {
    fn try_open(&self, envelope: &PairEnvelope) -> Result<TrustWrite>;
}

// Implementations: SasGate, UrlBearerGate, OperatorConfirmGate, LocalSisterGate
```

Replaces:
- `pair_session.rs` (SAS state machine)
- `pair_invite.rs` (URL mint flow)
- `pending_pair.rs` / `pending_inbound_pair.rs` (operator-confirm flow)
- the cmd_add_local_sister path

One canonical envelope schema, four pluggable gates. Test surface: one canonical path × four gate implementations vs four separate state machines.

Cost: ~5-7 days. Highest risk refactor — this is the protocol core. Worth doing only when there's appetite for protocol cleanup, not before.

### 4. Narrow public API to 5 namespaces for v1.0

`lib.rs` re-exports today:
- ✅ Keep: `signing`, `canonical`, `agent_card`, `trust`, `character` (the protocol kernel)
- ❌ Make private: `session`, `endpoints`, `daemon_stream`, `service`, `mcp`, `config`, `pair_session`, `pair_invite`, `pair_profile`, `pending_pair`, `pending_inbound_pair`, `pull`, `relay_client`, `relay_server`

Cost: 1-2 days. Zero external impact (nothing depends on wire as a library yet). Frees future refactors.

### 5. Move auto-init out of cli, eliminate `unsafe env::set_var`

Move `maybe_auto_init_cwd_session` to `session::auto_init_for_cwd()`. Have it RETURN the session_home; don't mutate env vars. Callers (cli, mcp) decide whether/how to set WIRE_HOME.

Cost: half a day. Removes the documented-but-not-enforced safety contract.

---

## v0.8 refactor priority (ranked by ROI)

| Priority | Refactor | Effort | Pays back when |
|---|---|---|---|
| **P0** | Module split for cli.rs + relay_server.rs | 3-5 days | next feature you add — parallel work + test locality |
| **P0** | State layer → SQLite | 5-7 days | next concurrency bug avoided (the 10+ unprotected write_relay_state sites are a ticking incident) |
| **P0** | Narrow public API to 5 namespaces | 1-2 days | v1.0 cut — locks in compatibility surface |
| **P1** | Move auto-init out of cli, drop unsafe env::set_var | 0.5 days | next time someone moves the mcp::run call order |
| **P1** | `character_v2` versioning so list expansions don't shift existing DIDs' characters | 1 day | next time word lists grow |
| **P1** | Audit + close unprotected write_relay_state call sites (interim until SQLite ships) | 1 day | now (preventive) |
| **P2** | Collapse pair flow under signed-envelope-exchange + gates | 5-7 days | next pair-variant feature you'd add (Bluetooth? QR code? OAuth-style?) |
| **P2** | Verb→noun CLI deprecation cycle | 1 day impl + 1 release window | v1.0 — reduces operator cognitive load forever |
| **P3** | Windows-as-first-class (named pipes, event log service) | 7-10 days | v1.0 cross-platform claim becomes honest |
| **P3** | Binary wire format (CBOR/protobuf) | 5-7 days | when packet size or parsing cost matters (post v1.0) |

P0 = ship in v0.8. P1 = ship in v0.8 or v0.8.x. P2 = ship in v0.9. P3 = ship when needed.

---

## What wire is becoming (architectural shape)

The codebase is converging on a shape that wasn't fully visible at v0.5 but is now clear:

- **A protocol-layer kernel** (signing + canonical + trust + agent-card + character + pair envelopes) that's stable, well-tested, and could legitimately be a separate crate.
- **A relay-layer service** (state + persistence + HTTP handlers + counters) that wants to be its own deployable; today it's bundled in the same binary as the client.
- **An operator-facing CLI** (`wire identity`, `wire session`, `wire mesh`) that's the right surface for humans + a thin wrapper for MCP agents.
- **A transport substrate menu** (Federation / Local / Lan / UDS) that the routing layer abstracts over. Operators pick; wire stays substrate-agnostic.

That separation maps to the **kernel ↔ service ↔ surface** layering wire has been growing toward. Making it explicit (modules + APIs) is what v0.8 should do.

The character system is the most novel piece. It's a small idea (display layer derived from cryptographic identity) but it solves a real human problem (multi-Claude disambiguation) that no other agent protocol I know of has tackled with similar care. Lean into it for v1.0 marketing — it's the most operator-delightful thing wire ships.

---

## Honest take

Wire is not broken. The protocol works, the threat model is locked, the operator UX is thoughtful, and the v0.7+ identity-first work delivered on every claim.

What it has is the wear of a project that grew from "let two agents pair via SAS" to "federated multi-machine multi-transport identity layer with character display" in ~6 months of fast-iteration. The protocol layer absorbed the growth gracefully; the plumbing layer is creaking. The three P0 refactors (module split, SQLite, narrowed public API) are the cheapest way to set up v0.8+ for the next 6 months without slowing feature work.

If I had a free hand: I'd ship v0.7.0 as-is, spend two weeks on the P0 refactors, then resume feature work from a cleaner base. That's the pragmatic plan; "redesign from scratch" rarely produces shippable work, and wire's architecture is fundamentally sound. The structure is what needs the love.

---

## Critique round (second pass)

Sending the audit through 5 hostile personas surfaced real iterations. Captured here so future readers don't take the first-pass conclusions at face value.

**1. Sequence the P0s, don't parallel-fire.** First pass treated three P0s as a batch. They're not — different durations, different risk profiles, different prerequisites. Revised order:

| Order | Refactor | Why first |
|---|---|---|
| 1st | **Narrow public API to 5 namespaces** (1-2 days) | Cheapest. Zero behavior change. Frees the other two refactors from breaking external surface contracts. Should ship in the same release as v0.7.0 if possible. |
| 2nd | **Module split** (3-5 days) | Mechanical. Zero behavior change. Unblocks parallel work + test locality. Run AFTER the API narrow so the module boundary work is also a chance to mark visibility. |
| 3rd | **State layer → SQLite** (7-10 days, revised UP from 5-7) | Highest cost, highest risk. Needs migration safety story (dual-read mode, rollback). Should ship in v0.8.x not v0.8.0 — bench first, prove the win, then commit. |

**2. SQLite section was over-confident.** First pass said "no more flock ceremony." Wrong — SQLite uses its own OS-level file locks; WAL mode reduces contention but doesn't eliminate it. Multi-daemon writes to the same db file still serialize. The win is the locking *shape* (clean transactions, no manual flock helpers), not lock-freedom. Plus operational tax: PRAGMA tuning, WAL checkpoint cadence, sqlite version compat. **Recommendation:** benchmark write-contention with 5 daemons + 20 sessions before committing the migration. If JSON+flock is within 2× SQLite throughput at expected concurrency, don't bother — the wins are correctness (no unprotected `write_relay_state` calls) which can also be solved by an audit + wrapper. SQLite is a structural answer to a correctness problem; might be over-engineered.

**3. Migration safety story missing.** v0.8 SQLite migration must include:
- Dual-read mode (read both JSON and SQLite during transition; SQLite wins on conflict)
- One-shot migration command (`wire session migrate-to-sqlite`) with `--dry-run`
- Rollback path: if migration fails mid-session, restore from a `.pre-migrate-backup/` snapshot
- Version-compat: v0.7 binaries reading v0.8 SQLite files should fail gracefully ("session needs older wire — pin v0.7 or upgrade")

Without these, the migration is operator-hostile.

**4. Public API narrow needs deprecation cycle.** First pass said "nothing depends on wire as a library yet." Probably true today but operators DO `cargo doc --open` and look at the re-exports. Hard-removing `pub use endpoints::*` in v0.8 will break anyone who copy-pasted that import. Soft-deprecate first (`#[deprecated(note = "wire::endpoints will be private in v0.9")]` for one release), then remove.

**5. Operator pain validation gap.** Audit ranked wear items by gut feel + agent consensus, not by actual incident frequency. What does the operator incident log show? If "two Claudes in same cwd" was the highest-frequency real issue (v0.6.10's collision warning) and "atomic write of agent-card" was theoretical (no SIGKILL incidents reported), then prioritize accordingly. The audit lacked this data. **Action:** before committing P0 budget, do a 1-day pass through GitHub issues + Slack/Discord support logs + the CHANGELOG's bug-fix entries to quantify which classes of wear actually bite.

**6. Protocol-layer claim of "well-engineered" was trust-but-don't-audit.** The audit cited test coverage + threat model existence as evidence; didn't actually re-read canonical.rs or signing.rs against attack vectors (Bleichenbacher-style malleability, signature stripping in JSON nesting, etc.). Wire's protocol layer is probably fine — it's been live for months and built on libraries (ed25519-dalek, spake2) with their own audit history — but the audit's "preserve" recommendation is based on absence-of-known-bugs, not presence-of-positive-audit. **Recommendation:** before v1.0 ship, separate paid security-audit pass (Cure53 / Trail of Bits / NCC Group / independent crypto auditor) focused on the protocol crate. Out of scope for v0.8 work.

**7. Drop the brand-marketing line.** "Lean into character system for v1.0 marketing" doesn't belong in a codebase audit. Cut from synthesis. Belongs in `.planning/marketing/` if anywhere.

### Net change to P0 priority

After critique:

| Priority | Refactor | Effort | Window |
|---|---|---|---|
| **P0 (do for v0.7.0 if possible)** | Narrow public API to 5 namespaces + soft-deprecate the rest | 1-2 days | v0.7.0 patch release |
| **P0 (v0.8.0)** | Module split for cli.rs + relay_server.rs | 3-5 days | v0.8.0 |
| **P1 (v0.8.x, post-bench)** | State layer → SQLite (only if write-contention bench justifies) | 7-10 days + migration | v0.8.x |
| **P1 (v0.8.0)** | Audit + wrap unprotected `write_relay_state` calls (interim correctness fix; ships even if SQLite doesn't) | 1 day | v0.8.0 |
| **P0 (pre-v1.0)** | External security audit of protocol crate | Engaged separately | pre-v1.0 |

The critique round's biggest insight: **the audit was too confident on SQLite specifically.** Module split + API narrow are uncontroversial wins. SQLite migration is a real bet that should be bench-validated before being committed to a release plan. The interim "audit + wrap unprotected writes" gets correctness without the structural change.
