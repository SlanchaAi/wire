# RFC-006: Consolidate the dual session-layout + endpoint representations

**Status:** Accepted (direction) — 2026-06-13: collapse is a **1.0 format-freeze gate** (@laulpogan, "push to 1.0" decision). Implementation gated on the surface map + kill criteria below. <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** RFC-005 follow-on (the two items its Phase 4 could not remove because they're live)
**Author:** Claude Code agent (paired w/ @laulpogan)
**Date:** 2026-06-07 (decision + Part-B surface map appended 2026-06-13)
**Target:** v0.16 / pre-1.0 (breaking; requires a one-time `wire nuke` / re-pair, acceptable pre-GA)

---

## Decision (2026-06-13) — collapse before 1.0, Part B first, with a critical scope correction

1.0 freezes the on-disk + wire formats (see `ROAD_TO_1.0.md`). You cannot 1.0 on
the dual session resolver (the #170/#174 fork-storm class), and you cannot
collapse *after* 1.0 without breaking the on-disk promise. So: **collapse, pre-1.0.**
Part B (endpoints) lands first as the lower-risk half; Part A (the sessions
resolver) follows under its kill criterion.

### ⚠️ Part-B scope correction (surface map, 2026-06-13)

A code survey before implementing Part B found that **`relay_url` / `slot_id` /
`slot_token` are NOT a single thing to delete** — they appear in two distinct
roles, and only ONE is the dual-representation hazard:

- **HAZARD (collapse this):** the per-peer **routing pin** in
  `relay.json#peers[<handle>]` carries *both* a structured `endpoints[]` array
  AND synthesized top-level flat fields; `pin_peer_endpoints` writes both, and
  `peer_endpoints_in_priority_order` / `self_endpoints` synthesize one from the
  other (`endpoints.rs` ~164/240). *This* is the "stale flat field beats fresh
  array" routing hazard. → **collapse to `endpoints[]`-only here.**
- **LEGITIMATE WIRE FORMAT (do NOT touch — these are frozen 1.0 surfaces):**
  - the relay's HTTP allocate/handle responses (`relay_server.rs` — `{slot_id,
    slot_token}`, `{relay_url, …}`) — the relay API;
  - the **invite-URL payload** (`InvitePayload { relay_url, slot_id, slot_token,
    … }`, `pair_invite.rs`) — the invite wire format;
  - `wire send --json` delivery output (`send.rs` `delivery_json` — `relay_url`,
    `slot_id`) — the frozen CLI surface;
  - the A2A interop shim (`pair_profile.rs`).

  These flat coords are the actual API/format at those boundaries, not a
  redundant copy. A naive "remove all flat fields" **breaks the protocol, the
  invite URL, and `--json`** — the opposite of a format-freeze.

### Part B implementation (scoped)

1. `pin_peer_endpoints` (`endpoints.rs`) stops writing the redundant top-level
   flat fields into `peers[<handle>]`; it writes `endpoints[]` only.
2. The invite-accept path (`pair_invite.rs`) constructs an `endpoints[]` entry
   for the pinned peer instead of (or in addition to, then drop) flat fields —
   the invite *payload* keeps its flat coords (frozen format); only the pinned
   *routing state* it produces moves to `endpoints[]`.
3. `peer_endpoints_in_priority_order` reads `endpoints[]`; the per-peer flat
   synthesis fallback (`endpoints.rs` ~164) is deleted. (`self_endpoints`' flat
   synthesis is retained until Part A / a self-slot migration — self state is a
   separate collapse with its own back-compat window.)
4. **Migration:** breaking for peers pinned the old way → `wire nuke` + re-pair
   (RFC-005 Phase 1 shipped `wire nuke` for exactly this).

### Kill criterion for Part B (unchanged intent, made concrete)

If `pin_peer_endpoints` cannot stop emitting flat fields **without** breaking
`e2e_invite_pair` / `e2e_bilateral` / `e2e_handle_pair` / `e2e_mesh` /
`e2e_group` (routing must survive on `endpoints[]` alone), **abandon Part B**
and keep the dual peer-pin. The 2026-06-13 daemon-survival fix relies on
`self_endpoints()` synthesizing the *sister's* flat fields — Part B leaves
`self_endpoints` synthesis intact, so that path is unaffected; verify this in
the mesh/local-sister e2e before merge.

### Full peer-flat READER inventory (2026-06-13 survey) — the implementation checklist

"No users / free to rebuild" (operator, 2026-06-13) removes the migration
ceremony — no `wire nuke`, no old flat-only pins to tolerate, delete freely. But
a second survey found the blocker isn't the *write* — it's that **~10 sites read
the peer flat fields directly**, several on the routing hot path. You cannot drop
the flat write until every reader uses `endpoints[]`, or routing breaks. The
collapse is therefore a **reader refactor**, ordered: migrate readers → then drop
the write + synthesis.

**Recommended:** add one canonical resolver — `peer_primary_endpoint(state,
handle) -> Option<Endpoint>` (and/or reuse `peer_endpoints_in_priority_order`) —
and route EVERY site below through it. Then delete the flat write in
`pin_peer_endpoints` + the synthesis fallback in `peer_endpoints_in_priority_order`.

Peer-flat reader sites to migrate (grep `get("relay_url"|"slot_id"|"slot_token")`, peer scope):
- `src/send.rs:164` — `attempt_deliver` (SYNC send hot path) ← highest risk
- `src/daemon_stream.rs:135` — streaming pull/subscribe path ← highest risk
- `src/pair_invite.rs:530, 801, 913` — pairing / pair_drop handling
- `src/cli/comms.rs:121` — `maybe_warn_peer_attentiveness`
- `src/cli/status.rs:1223/1267/1435/1467` — `wire status`/`doctor` surface
- `src/cli/session.rs:522`, `src/cli/identity.rs:984`, `src/cli/pairing.rs:554`
- (self-slot readers — `"self"` scope — are Part B.2 / Part A; leave for now, the
  #263 daemon-survival fix depends on `self_endpoints()` flat synthesis.)

Writer to collapse AFTER readers are migrated:
- `src/endpoints.rs::pin_peer_endpoints` — currently writes `endpoints[]` AND
  fills flat `relay_url`/`slot_id`/`slot_token` (lines ~336–355). Drop the flat
  fills; write `endpoints[]` only.
- `src/endpoints.rs::peer_endpoints_in_priority_order` — delete the "Back-compat
  … synthesize from top-level legacy fields" block (~173–188).

Gate (kill criterion): `cargo build` + `e2e_invite_pair` / `e2e_bilateral` /
`e2e_handle_pair` / `e2e_mesh` / `e2e_group` (`-- --ignored --test-threads=1`) +
`hello-world-validate.sh` local-sister round-trip all green. If routing can't
survive on `endpoints[]` alone, abandon and keep the dual peer-pin.

> Status: **Part B IMPLEMENTED** — #268 collapsed the writer (`pin_peer_endpoints`
> writes `endpoints[]` only), deleted the priority-order synthesis fallback, added
> the canonical `peer_primary_endpoint` resolver, and migrated the hot-path readers
> (send/daemon/status/CLI-dial). A follow-up cleanup (`fix/rfc006-partb-stale-peer-flat-reads`)
> closed three stragglers #268's reader list missed — all reading peer flat fields
> the writer no longer emits: the MCP `tool_dial` token carry-forward (a real
> regression — re-dial wiped the peer's reply token), the `cli/relay.rs`
> re-resolve `relay_url` fallback (dead), and the `trust.rs` PENDING_ACK
> `slot_token` check (dead) — and added `peer_federation_token` as the one
> canonical token reader both dial paths share so they can't drift again.
> **Remaining: Part A self-slot flat collapse** (deferred — the #263 daemon-survival
> fix depends on `self_endpoints()` flat synthesis; its own slice).
**Question this answers:** wire stores two things two ways — sessions (named dir vs by-key hash) and peer endpoints (array vs flat fields). The de-deprecation (RFC-005) removed every *dead* legacy format but had to leave these because current code actively reads/writes both. How do we collapse each to a single representation without reintroducing the #170/#174 multi-session fork-storm?

---

## TL;DR

- Two **dual representations** survive RFC-005 because both halves are live, not because they're old:
  1. **Sessions:** `sessions/<name>/` (operator-named, used by `wire session new/list/env/destroy`) **and** `sessions/by-key/<hash>/` (content-addressed, used by agent-host auto-resolution via `WIRE_SESSION_ID`/`CLAUDE_CODE_SESSION_ID`).
  2. **Peer endpoints:** a structured `endpoints[]` array **and** flat top-level `relay_url`/`slot_id`/`slot_token` fields, kept in sync by back-compat synthesis.
- Carrying both is the exact ambiguity that caused the **#170/#174 fork-storm** (a resolver that picked the wrong layout spawned 100+ daemons) and makes the pinning/routing code hard to reason about.
- **Proposal:** make **by-key the single session store** with names as a registry *index* into it (not a parallel directory tree); make **`endpoints[]` the single peer-routing source** and drop the flat fields. One-time migration is a `wire nuke` + re-init / re-pair (RFC-005 Phase 1 shipped `wire nuke` precisely so this is cheap pre-GA).
- **This is breaking and touches the resolver that fork-stormed — it ships behind a hard KILL CRITERION**, not as a "just delete it" sweep.

## Motivation

RFC-005 set out to remove all backwards compatibility. It succeeded for everything dead (SAS flow, deprecated MCP/CLI aliases, legacy pidfile/DID formats, v3.1-card / pre-v0.5.19 / v0.4-profile tolerance). It hit a wall on two items because they are **not old — they are the present, expressed two ways**:

1. **Session layout.** `find_session_home_by_name` / `sessions_root` resolve *both* `sessions/<name>` and `sessions/by-key/<hash>`. `wire session new` writes the named form; agent hosts resolve the by-key form from `WIRE_SESSION_ID`. The #174 hotfix exists because a resolver assumed the named (v0.6) layout and broke by-key sessions, and #170's supervisor fork-stormed off the resulting "session not found / wrong home" confusion. **Two coexisting layouts + one resolver = standing fork-storm risk.**

2. **Peer endpoints.** `pin_peer_endpoints` writes the structured `endpoints[]` array; the live invite flow (`pair_invite.rs`) and older pins also read/write flat top-level `relay_url`/`slot_id`/`slot_token`. `peer_endpoints_in_priority_order` / `self_endpoints` synthesize one from the other. Two sources of truth for "where do I send to this peer" is a routing-correctness hazard (a stale flat field can win over a fresh array entry, or vice versa).

No production users exist, so a breaking migration is free — the blocker is purely *can we collapse the representation without breaking the live resolver/router*.

## Design

### Part A — Sessions: by-key store + name index

- **Single on-disk store:** every session lives at `sessions/by-key/<hash>/` (hash derived from the session DID). There is no `sessions/<name>/` directory tree.
- **Names become a registry index, not a layout.** The existing `registry.json` (already `by_cwd` + name→… maps) gains the authoritative `name → key` mapping. `wire session new <name>` mints a by-key home and records the name→key entry; `wire session list/env/destroy` resolve names *through the index* to the one by-key home.
- **One resolver.** `find_session_home_by_name(name)` becomes: look up `name → key` in the registry, return `sessions/by-key/<key>/`. No dual-layout branch. Agent-host resolution (`WIRE_SESSION_ID` → key) and operator resolution (`name` → key via index) converge on the same store. This removes the branch the #174 hotfix was patching.
- **Migration:** breaking — `wire nuke` + re-init. (Optionally a `wire session migrate` that walks `sessions/<name>` dirs and re-homes them under by-key + writes the index; only worth building if we decide some pre-v0.16 state must survive — default is nuke.)

### Part B — Peer endpoints: `endpoints[]` only

- **Single source:** `relay.json#peers[<handle>].endpoints[]` is the only routing source. Drop the top-level `relay_url`/`slot_id`/`slot_token` flat fields from the self-slot and peer-pin write paths.
- **Pinning:** `pin_peer_endpoints` writes only the array. The invite-accept path (`pair_invite.rs`) constructs an `endpoints[]` entry instead of flat fields.
- **Routing:** `peer_endpoints_in_priority_order` reads the array directly; the legacy-field synthesis (`endpoints.rs` ~241/271/383) is deleted.
- **Migration:** breaking — peers must re-pair (their flat-field-only pins won't route). `wire nuke` covers it; a forced re-pair is the alternative.

## Security

- **Fork-storm class (#170/#174) is the headline risk.** Collapsing to one session resolver *reduces* it (no layout ambiguity), but the change is *in* that resolver, so the implementation must be proven against the multi-session e2e (mesh/group/by-key/named) before merge. See acceptance criteria.
- **Routing correctness.** A single endpoint source removes the "stale flat field beats fresh array" hazard. Mis-migration could mis-route to a dead slot — caught by the bilateral/invite e2e (push-to-dead-slot returns 200 but peer never sees us; doctor staleness signal flags it).
- No trust-model, protocol (v3.2), or key-rotation change. Cross-ref `docs/THREAT_MODEL.md`.

## Out of scope

- A general pre-v0.16 migration tool (default is `wire nuke`; build `wire session migrate` only if a concrete need surfaces).
- Renaming/restructuring `registry.json`'s existing maps beyond adding the authoritative `name → key`.
- Any change to canonical pairing (dial/invite/bilateral), protocol, or trust ladder.

## Acceptance criteria

1. **One session store, one resolver.** After Part A: `grep` finds no code path that resolves `sessions/<name>` as a directory; `find_session_home_by_name` has a single (index-lookup) branch. Measured: code inspection + the dual-layout test deleted. Owner: Part A PR.
2. **Multi-session fork-storm does not return.** `wire daemon --all-sessions` over a fixture of N named + N by-key sessions spawns exactly one daemon per *eligible* session (per the RFC-005 idle filter), never a storm. Measured: a supervisor integration test asserting daemon count == eligible-session count; the mesh/group/by-key/named e2e all green on `--test-threads=1`. Owner: Part A PR.
3. **One endpoint source, routing intact.** After Part B: no top-level `relay_url`/`slot_id`/`slot_token` on the write paths; `peer_endpoints_in_priority_order` reads only `endpoints[]`. The `e2e_invite_pair` / `e2e_bilateral` / `e2e_handle_pair` / `e2e_mesh` / `e2e_group` targets pass (canonical pairing + routing survive). Owner: Part B PR.
4. **KILL CRITERION.** If, in Part A, the named→key index cannot make operator (`wire session new/list`) and agent-host (`WIRE_SESSION_ID`) resolution converge on one store **without** reintroducing a wrong-home / "session not found" path (the #174 failure class) — i.e. the dual-layout resolver can't be collapsed to one branch while keeping all multi-session e2e green — **abandon Part A** (the two layouts stay) and ship only Part B. Likewise abandon Part B if the live invite flow can't be ported to `endpoints[]` without breaking invite e2e.

## Open questions

- **Migration tool or nuke-only?** Default `wire nuke`. Build `wire session migrate` only if there's pre-v0.16 state worth preserving. Decision point: before Part A implementation. Owner: maintainer.
- **Part order / independence.** A and B are independent (sessions vs endpoints); ship as two PRs. Either can be abandoned via its kill criterion without blocking the other. Confirm both are wanted, or just one.
- **Name collisions in the index.** `wire session new <name>` when `<name>` already maps to a key — overwrite, error, or suffix? (Today the named-dir layout would just reuse the dir.) Owner: Part A design.

## Alternatives considered

- **Keep both representations (status quo).** Valid — they work today, and RFC-005 left them deliberately. Rejected as the *default* only because the operator asked to consolidate; the dual session resolver remains a standing fork-storm-class risk and the dual endpoint source a routing hazard. "Do nothing" is a legitimate outcome if either kill criterion fires.
- **Consolidate sessions onto the *named* layout instead of by-key.** Rejected: agent-host auto-resolution is keyed off content-addressable DIDs (`WIRE_SESSION_ID`), which is the dominant runtime path; names are a human convenience that indexes cleanly into by-key, not vice-versa.
- **One big PR for A+B.** Rejected: they're independent, each carries its own kill criterion, and the session resolver (A) is the fork-storm-adjacent one that deserves an isolated, heavily-gated change.
