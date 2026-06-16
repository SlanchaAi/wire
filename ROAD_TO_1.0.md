# Road to wire 1.0 — a deep reflection

> Draft reflection, 2026-06-13. Author: Claude Code (paired w/ @laulpogan).
> Status: thinking-out-loud, not a ratified plan. Meant to be argued with.

> **Progress update — 2026-06-16 ("do it all" pass).** Items 1–6 of the §9 work
> list are landed on `main` (post-v0.16.0, unreleased); items 7–8 are the only
> things left, and item 8 (the soak) is a wall-clock gate, not code. See the
> per-item status in §9. Net: **the engineering + discipline for a tight 1.0 is
> done; what remains is a maintainer hygiene call and a ≥2-week soak.**

## 1. What 1.0 actually *means* (the only question that matters)

1.0 is not a feature count. It is a **promise to not break four things**:

1. **Identities & pairings** — a DID minted today still works tomorrow; a paired
   peer stays paired across upgrades.
2. **On-disk state** — `sessions/`, `trust.json`, `relay.json`, the pidfile
   schema. An upgrade must not orphan a session or strand a slot.
3. **The wire protocol** — event kinds, the agent-card schema (`v3.2`), the
   signing/canonicalization rules, the relay HTTP surface.
4. **The operator/agent surface** — CLI verbs, `--json` shapes, the MCP tool
   catalog, the file-system contract.

…plus a fifth, softer promise: **the security posture is honest** — the threat
model matches the code, and what is *not* protected is stated, not implied.

So the 1.0 gate is: *can we freeze those five surfaces and stand behind them?*
Everything below is "what's not yet freezable."

## 2. The one structural blocker: format freeze (RFC-006)

This is the real gate. wire currently stores **two things two ways**:

- **Sessions** — `sessions/<name>/` (operator-named) **and**
  `sessions/by-key/<hash>/` (content-addressed). One resolver reads both.
- **Peer endpoints** — a structured `endpoints[]` array **and** flat
  `relay_url`/`slot_id`/`slot_token` fields, kept in sync by synthesis.

RFC-006 (`0006-consolidate-dual-representations.md`, Draft) wants to collapse
each to one representation. **This must be decided before 1.0**, because:

- The dual session resolver is *the code that fork-stormed* (#170/#174 — 100+
  daemons). Shipping 1.0 on a standing fork-storm-class risk is a stability lie.
- If we 1.0 with both representations and collapse later, the collapse is a
  **breaking on-disk migration after we promised not to break on-disk state.**

So: either land RFC-006 (collapse, with its kill criteria) **before** 1.0, or
consciously bless both representations as the frozen-forever format. The former
is the right call; it's the single biggest pre-1.0 work item.

## 3. The core loop must be bulletproof (and it wasn't, last week)

The headline use case — *two agents on one box just talk* — **silently failed on
a fresh box** until the 2026-06-13 session. Two stacked bugs:

- `wire up`'s daemon self-aborted on its own singleton pidfile → no puller.
- `wire dial <sister>` pinned one direction → the receiver rejected the message.

Both are fixed (#263) and now guarded by a real round-trip harness (#262). But
the lesson for 1.0 is bigger than two bugs: **the daemon + pairing lifecycle is
the part most likely to silently betray the 1.0 promise**, and it had near-zero
end-to-end coverage of the canonical flow. Before 1.0:

- The hello-world round-trip harness (#262) becomes a **required CI gate** (it
  exercises what `wire demo` and `install-smoke` don't: real relay + two daemons
  + recv + reply).
- A lifecycle e2e sweep: daemon survives reboot/login/upgrade; one daemon per
  session; the `--all-sessions` supervisor never fork-storms; `wire upgrade`
  cleanly rolls daemons.
- The heavy-e2e contention/flake (subprocess starvation under
  `--test-threads=1`) is resolved, not tolerated — a flaky suite can't gate a
  1.0.

## 4. Confidentiality: ship it or state it (no middle)

D1 DM-encryption (`wire-x25519.v1`, RFC-006/NIP-44 line) is **wired** —
`seal_event_body` encrypts to dh-capable peers, plaintext fallback for legacy
cards. For 1.0 the threat model must say *exactly* one of:

- **In 1.0:** DMs between modern peers are sealed; the relay sees ciphertext +
  routing metadata. (If so: is it default-on? are there downgrade-attack
  guards? is the fallback to plaintext visible to the operator?)
- **Not in 1.0:** confidentiality is best-effort / partial; here's what the
  relay can read.

The deferred crypto (full NIP-44 / vodozemac / MLS, group confidentiality) is
*deliberately* backlogged — that's fine, but 1.0's `THREAT_MODEL.md` must mark
it **explicitly out of 1.0**, not leave it ambiguous. The landing already
over-claimed once (just fixed); the threat model can't.

## 5. Identity layer: draw the line

v0.14/v0.15 shipped the offline-minimal identity layer; this session added
block-peer (T16), project fan-out (§6), DNS-TXT org binding (§2), and key
rotation (T19/T20). The agent-card is `v3.2` and **additive/forward-compatible**,
which is the key enabler: **the org/identity layer can keep growing post-1.0
without breaking 1.0 peers.** So 1.0 does *not* need the full RFC-001 vision. It
needs a clear line:

- **In 1.0:** the offline self-certifying chain (op/org/member certs), the trust
  ladder (UNTRUSTED→ORG_VERIFIED→VERIFIED, SAS-floor invariant), block-peer,
  DNS-TXT binding, key rotation *primitive*.
- **Post-1.0 (additive, non-breaking):** SSO/OIDC channel (currently has a
  90-day kill criterion — **decide keep-or-cut before 1.0**, don't 1.0 with a
  self-destruct timer armed), roster-bundle pull, `/v1/org/claim` registry
  endpoint, receiver-side key-rotation auto-migration.

The one thing to *resolve* (not just defer): the **SSO 90-day kill criterion**.
You can't freeze a 1.0 surface that's scheduled to maybe-revert.

## 6. Surface freeze + deprecation policy

The v0.15 de-deprecation work (removing SAS, alias verbs/tools, legacy formats)
was excellent 1.0 prep — it's *cheaper to freeze a surface you've already
pruned*. To finish:

- Freeze the CLI verb set + `--json` schemas + the 27-tool MCP catalog. The #255
  anti-drift guard (docs match `tool_defs()`) should extend to: **a golden
  `--json` schema test** so output shapes can't silently change post-1.0.
- Publish a **deprecation policy** (how a verb/field gets removed after 1.0 — a
  deprecation window, not a silent break). 1.0 is the moment you owe users one.
- The agent contract (`AGENTS.md` / `PLUGIN.md` / `AGENT_INTEGRATION.md`) is the
  frozen API for agent authors — it just drifted (fixed in #255 + the landing
  fix #264). 1.0 needs these *guaranteed* in sync (the guard helps).

## 7. Honesty & hygiene (the cheap, necessary polish)

- **Public truth:** the landing was describing pre-v0.15 wire (fixed in #264).
  Before 1.0, audit *every* outward surface — README, landing, og/video,
  AGENTS.md, `--help` text, `/healthz` and the relay's served copy — for drift.
  A 1.0 with a lying front door is worse than a 0.x with an honest one.
- **Repo hygiene:** unused/stale files (old SESSION_LOG_*, superseded planning
  docs, the un-PR'd launch drafts that must stay *out* of commits, dead
  scripts). A 1.0 repo should be legible to a first-time reader. (Separate pass;
  flagged here as a 1.0 chore, not a blocker.)
- **ANTI_FEATURES.md** should be 1.0-current — it's the doc that says "we
  deliberately don't do X," which is half of what 1.0 honesty means.

## 8. The soak (you cannot 1.0 without it)

Code-complete ≠ 1.0. A 1.0 stability claim needs **evidence**: dogfood the public
Spark relay + multi-agent on-one-box for a sustained window (≥ 1–2 weeks) with:

- zero first-connection failures (the harness as the canary),
- zero fork-storms / orphan daemons,
- clean upgrade rolls across at least one real version bump,
- the cross-machine federation path exercised by real peers (the Willard ↔ Mac
  wire link is a natural test bed).

## 9. The cut-line (my recommendation)

A **tight, defensible 1.0** is *not* "the identity vision is complete." It is:

> The first connection — on-machine and cross-machine — is bulletproof and
> regression-guarded; the on-disk + wire formats are frozen (RFC-006 resolved);
> the CLI/MCP/JSON surface is frozen with a written deprecation policy; the
> threat model is honest (DM confidentiality either shipped-and-stated or
> explicitly deferred); and it has survived a real multi-week soak.

Everything else — the org trust layer beyond offline-minimal, SSO, roster pull,
group confidentiality — rides in *after* 1.0 on the additive `v3.2` card and the
deprecation policy, **without breaking the promise.**

### Ordered work list

1. ✅ **Resolve RFC-006** — Part B done. The collapse itself landed in #268; the
   2026-06-16 pass closed three stale peer-flat readers #268 missed (incl. a real
   MCP re-dial token-wipe regression) and added the canonical
   `endpoints::peer_federation_token` both dial paths share (#323). Part A
   (sessions) was already collapsed (#269). **Part A self-slot flat collapse**
   stays deferred — `self_endpoints()` flat synthesis backs the #263
   daemon-survival fix; it's a later slice, not a 1.0 blocker.
2. ✅ **Harden + gate the lifecycle** — the #262 hello-world round-trip is now a
   required CI job (#324); the UDS Broken-pipe flake was already fixed (#241) and
   `main` has been green across it. *Residual:* the deeper reboot/login/upgrade
   sweep is exercised during the soak (item 8), not pre-soak.
3. ✅ **Threat-model truth pass** (#325) — `THREAT_MODEL.md` now states the 1.0
   DM-confidentiality posture explicitly (default-on, downgrade-bounded,
   operator-visible; group/FS/metadata out); `ANTI_FEATURES.md` #2 reconciled
   with the shipped opt-in org-SSO.
4. ✅ **SSO kill criterion decided** (#325, revised #330) — the 90-day
   auto-revert timer is *disarmed* and SSO is **promoted to a supported 1.0
   feature** (the enterprise day-one hook). Wire-side contract (`ORG_VERIFIED`
   tier + `org_attestation.via` + DNS-TXT floor) is frozen; the IdP-integration
   config evolves only under the deprecation window. No armed timer crosses the
   freeze; no experimental asterisk on the enterprise hook.
5. ✅ **Freeze the surface** (#326) — `docs/DEPRECATION_POLICY.md` published;
   `mcp_catalog_schema_is_frozen` golden-locks all 27 MCP tools' shape.
   *Stretch:* golden-locking every `--json` builder (beyond `delivery_json`) is
   ongoing, tracked in the policy doc.
6. ✅ **Outward-truth audit** (#327) — README now says v0.16.0 (was a stale
   "v0.15.0"); landing version is dynamic + already post-SAS-correct (#264),
   AGENTS/`--help` carry no stale current-claims.
7. ⏳ **Repo hygiene** — *maintainer call.* A pile of tracked root scratch
   (`SESSION_LOG_*`, `.issue-*`, `SHOW_HN_DRAFT.md`, `LAUNCH_POSTS.md`,
   `REDDIT_LOCALLLAMA_POST.md`, `PROMPT_*`, etc.) wants to move to `docs/history/`
   or `.gitignore`. Left to the maintainer rather than auto-deleted — these are
   the operator's launch/session work, not agent-generated cruft, and #265
   already did the safe root declutter.
8. ⏳ **Soak** — ≥ 2 weeks, harness-as-canary, real peers, clean upgrade roll.
   The one true remaining gate; wall-clock, not code. Start the window once item
   7 is dispositioned.

Items 1–2 were the real engineering (done). 3–6 were discipline (done). 7–8 are
time + a hygiene call. None of it was "build more features" — and that's the
point of a good 1.0.
