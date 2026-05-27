# RFC-001: Operator / Organization / Project identity layer

**Status:** Discussion <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** [#73](https://github.com/SlanchaAi/wire/issues/73)
**Author:** swift-harbor (Copilot CLI agent, paired w/ @dthoma1) — v2 from slate-lotus's skeleton
**Date:** 2026-05-27
**Target:** v0.14 (invasive — not a v0.13.x patch)
**Question this answers:** How should wire express operator / organization / project identity to reduce pairing friction inside trust scopes without weakening the v0.5.14 phonebook-scrape closure?

---

## TL;DR

- Add three optional, **orthogonal-axis** claims to `agent-card.json`: `op_did` (operator), `org_did` (organization), `project` (routing tag). DID-derived session handle stays the one canonical name.
- Express **orgs as a flavor of `wire group`** (v0.13.3): creator-signed roster, replaced by org-signed roster; attested via a DNS-TXT floor on the org's domain.
- Introduce **`ORG_VERIFIED`** between `INTRODUCED` and `VERIFIED` on the bilateral tier ladder. Org membership *eases* pairing, **never substitutes for bilateral SAS** — the v0.5.14 cryptographic invariant is preserved.
- Default ease-of-pair mechanism: **signed-card-on-discovery + one-tap accept** (Option B). Operator gets one notification per new org-mate session, taps once, reaches `ORG_VERIFIED`. Optional opt-in upgrade: **eager auto-pair** (Option A) for orgs that explicitly trade the tap for zero-friction.
- Liveness: heartbeat on agent-card; relay marks slot stale after 24 h; roster GCs entries after 7 d. Project is a routing tag, **never a trust scope**.

## Motivation

Wire v0.13 nailed per-session-isolated identity: each Claude Code, Codex, or Copilot CLI session gets its own session-keyed DID under `sessions/by-key/<hash>/`, with a per-session relay slot and phonebook claim. That isolation is the right floor; it leaves three coordination patterns expensively expressed at the application layer:

1. **Operator.** One human (`@dthoma1`) runs N sessions across N machines and N agent hosts. Nothing links them. "Send to all my sessions" doesn't exist; cross-session enumeration is manual. The operator pairs *each session* with each peer individually — SAS dance per session-pair.
2. **Organization.** N operators who already trust each other socially (same team, same project) re-run the bilateral SPAKE2+SAS dance for every new pair and every new session. Friction grows as N² × sessions_per_operator. For a 5-operator team with 4 sessions each: 5 × 4 = 20 sessions, 20 × 19 ÷ 2 = **190 SAS dances** to fully mesh.
3. **Project.** Same operator wears different hats (e.g., `print-shop` vs `lora-training` vs `trading`). Today the only routing scope is the peer DID; project-level fan-out (`wire send --project print-shop all-mates`) has no primitive.

End-state goal (per operator framing): **ease-of-pair within trust scopes, expressed as identity claims wire can verify and routing tags wire can fan out**. This RFC is the design space for that goal — not a build spec, but concrete enough that v0.14 implementation can start from it.

## Design

### 1. Identity claims (agent-card delta)

Three new optional fields on `agent-card.json` (current schema `v3.1`, see `src/agent_card.rs:134`). Bump to `v3.2`:

```json
{
  "schema_version": "v3.2",
  "did":         "did:wire:swift-harbor-4092b577",
  "handle":      "swift-harbor",
  "capabilities": ["wire/v3.2", "org/v1"],
  "op_did":      "did:wire:op:darby-<32hex>",          // NEW: operator anchor
  "op_cert":     "<base64 ed25519 sig: op_did over session did>",
  "org_memberships": [                                  // NEW: zero or more
    {
      "org_did":   "did:wire:org:slanchaai-<32hex>",
      "member_cert": "<base64 ed25519 sig: org_did over op_did>"
    }
  ],
  "project":     "wire-codex-integration",              // NEW: opaque routing tag, unsigned
  "verify_keys": { ... },
  "endpoints":   [ ... ],
  "signature":   "<self-sig over canonical card>"
}
```

Semantics:

- **`op_did`** is the operator's root identity, separate from any session DID. A short-lived enrollment cert (`op_cert`) signed by the operator's root key binds the session DID under the operator. Verifier checks: `verify(op_did_pubkey, op_cert, session_did)`.
- **`org_memberships`** is a list (the same operator can sit in multiple orgs simultaneously). Each entry carries an org-signed `member_cert` binding `op_did → org_did`. Verifier checks: `verify(org_did_pubkey, member_cert, op_did)` AND `op_did` appears in this card's `op_cert` chain.
- **`project`** is opaque metadata with no signature. Routing tag only. Carrying it in the card lets routing decisions happen client-side without an extra protocol round-trip; it is **never trust-bearing**.

`op_did` and `org_did` use a new DID-method prefix `did:wire:op:` and `did:wire:org:` so they cannot be confused with session DIDs. The `<32hex>` tail is the first 32 hex digits of `sha256(pubkey)` — same construction as the session DID but doubled to make collision search 2^128 instead of 2^32.

**Critical invariant (closes Q-Reuse).** New claims are **orthogonal axes**. They do not introduce a free-choice display name diverging from the DID-derived session handle — v0.13.1's one-name invariant (see `src/cli.rs:13131`) still holds. The agent-card's `handle` field continues to come deterministically from the DID; `op_did` / `org_did` add context but not aliasing.

### 2. Org-claim attestation (non-FCFS)

Handles are FCFS today (`src/cli.rs:13131` — claim by first publish). Orgs grant ease-of-pair access; FCFS would be a takeover vector. The wireup registry MUST refuse `POST /v1/org/claim` without ≥1 of:

- **DNS-TXT (floor; required).** `_wire-org.<domain> IN TXT "did:wire:org:<id>"`. Operator proves domain control; cheap, federation-neutral, no GitHub dependency.
- **`did:web:<domain>` (optional, additive).** When set, the resolved well-known doc must list the `org_did`. Lets organizations bind their org-DID to the domain via the standard DID-Web pattern; useful for tooling that already speaks DID-Web.

GitHub-org verification is **deferred to v0.15** — convenient but adds GitHub as a trust-path dependency for what is a wire-layer security property, and slate-lotus's skeleton flagged the discomfort.

Org-claim is **single-relay** for v0.14: one canonical relay per org_did, recorded at claim time. Cross-relay org federation is v0.15+ scope; mixing two relays' org_did namespaces before we have a clear conflict-resolution rule risks silent name collisions.

### 3. Org as enriched `wire group` (substrate)

`wire group` (v0.13.3, `src/group.rs`) already gives the load-bearing primitives:

- Creator-signed canonical roster (`creator_sig`)
- Group-scoped tier disjoint from bilateral tier (`GroupTier::{Creator, Member, Introduced}`)
- Epoch bumps on every roster mutation, ordering revocations
- Introduce-pinning at `Tier::UNTRUSTED` (member-of-member ⇒ verify-only, never auto-promote)

An org is **a `wire group` whose:**

- `creator_did` is replaced by `org_did` (a `did:wire:org:` DID, not a session DID).
- `creator_sig` over the roster is replaced by `org_sig` (signed by the org_did's key, persisted at claim time on the registry).
- `Member.tier` default is a new `GroupTier::OrgMember` (analogue of `Member`, but rosters issued by an attested `org_did` rather than a personal `creator_did`).
- `members[].member_cert` ties roster entries back to operator anchors, so an operator's multiple sessions all resolve to the same `op_did` and inherit the org's vouch.

Concretely: each org gets a `groups/<org_id>.json` analogous to today's group file, but its rooted attestation lives on the wireup registry. Local clients pull the signed bundle, verify against the registered org pubkey, and use the roster as a pre-resolved member directory.

### 4. Ease-of-pair: two-track design

Per operator addendum: **auto-pair is not a hard requirement; treat it as the strong form of "ease-of-pair within trust scopes."** A lighter design that gets most of the friction win without weakening consent is preferred. This RFC develops both and recommends Option B as the default with Option A as opt-in.

#### Option B (default): signed-card-on-discovery + one-tap accept

The friction we are removing is **not the SAS-readout step itself**, it is the **N²-pair-discovery problem** and the **out-of-band SAS-comparison call**. Eliminate the latter by making the org bundle the trusted SAS source:

1. Operator A is enrolled in `org:slanchaai`. A's sessions advertise their cards (with `org_memberships`) to A's relay slot as today.
2. Operator B's session pulls the org's signed roster bundle from the registry. The roster carries each org-mate's `op_did` + `session_did` + agent-card hash + pre-computed SAS digits (signed by `org_did`).
3. When A's new session announces, B's daemon notices a roster hit and **enqueues a single pending-inbound** (one per session-pair, lifetime-deduplicated) carrying the org-vouched SAS.
4. B's operator gets a notification: *"swift-harbor (new session of darby@slanchaai) — SAS 384-217 (org-signed). [accept]"*. **One tap** confirms; B's daemon writes the same `pair_drop_ack` it would in today's bilateral flow.
5. Result: `Tier::ORG_VERIFIED` on both sides. Climbing to `VERIFIED` still requires the out-of-band SAS readout.

The cryptographic gate is preserved because the SAS digits in the bundle are computed over the *real* member pubkeys signed by the *real* org_did key. A rogue admin (or compromised registry) can only sign roster entries for keypairs they hold — and those keypairs are the threat surface they own anyway. The operator's "one tap" is *consent for `ORG_VERIFIED`*, not a substitute for the SAS check.

This reuses the existing `pending-inbound-pairs` queue (`src/pending_inbound_pair.rs`) — no new transport primitive, no new wire kind.

#### Option A (opt-in upgrade): eager auto-pair

For orgs where even the one-tap is too much (e.g., automation pipelines where the human is not on-keyboard), the operator can set a **per-org auto-pair policy** (`wire org set <org_did> --auto-pair`). When set:

1. As in Option B, B's daemon receives the roster bundle and notices A's new session.
2. Instead of enqueuing a pending-inbound, B's daemon directly emits `pair_drop_ack` and pins A at `ORG_VERIFIED`.
3. No notification, no tap. Strictly bounded: only members of orgs B explicitly opted-in to; only at `ORG_VERIFIED` tier; never `VERIFIED`.

**Why Option A is opt-in, not default.** Even with per-org consent, eager auto-pair amplifies the rogue-admin blast radius (Threat T16 below). Default-deny preserves the v0.5.14 closure for operators who never enable the policy — they pay one tap per session-pair, equivalent to today's "accept pending-inbound" workflow but with the SAS pre-resolved.

#### Why not Option A as default

The maintainer guardrail says `ORG_VERIFIED < VERIFIED, always`. That guardrail makes Option A *safe-by-construction* at the tier ceiling, but it does not make it *frictionless to receive misuse*: an attacker who compromises an admin can spam every org member's `ORG_VERIFIED` inbox without any per-receiver gate. Option B's one tap is the receiver's chance to decline the spam *before* it acquires the `ORG_VERIFIED` write capability. The friction cost of one tap per session-pair is small (≈ one notification per onboarding day for a 10-person org); the security cost of removing it is paid every day in defending against admin compromise.

### 5. Tier ladder

```
UNTRUSTED → INTRODUCED → ORG_VERIFIED → VERIFIED → (ATTESTED, TRUSTED — reserved)
```

`Tier::ORG_VERIFIED` is added between `INTRODUCED` and `VERIFIED` (extend the enum in `src/trust.rs`). Granted when:

1. Peer presents a valid `org_memberships` entry with verified `member_cert`, AND
2. Either: receiver has previously consented per-org (Option B path), OR receiver has set per-org `auto-pair` policy (Option A path).

Promotion remains one-way. `Tier::VERIFIED` continues to require bilateral SPAKE2+SAS (the v0.5.14 invariant). A bilaterally-SAS-paired peer that *also* happens to be in a shared org is recorded at `VERIFIED`, not downgraded.

**Two new tiers are not needed.** `INTRODUCED` already covers the introduce-pinning case (group-mate at no-tap, verify-only). `ORG_VERIFIED` is the new attested-org-cert case. The reserved `ATTESTED` slot stays free for future high-assurance attestations (key-transparency log, hardware-attested keys).

### 6. Project routing

`project` is a string tag on outbound events. Daemon fan-out:

```
wire send --project print-shop all-mates "..."
  → recipients = {peers where peers.tier >= ORG_VERIFIED AND peers.project == "print-shop"}
```

Fan-out is **client-side**. The relay sees N individual pushes, not a broadcast primitive — preserving "every event is to one slot." Project is **metadata only**, never trust-bearing; this prevents abuse where a peer claims `project = "infra-admin"` to escalate routing privileges. If a future use case needs trust-scoped projects, file a follow-up RFC; do not retrofit it into this one.

### 7. Liveness / roster GC

Sessions are ephemeral; org rosters are long-lived. Without a TTL story, a year-old org roster has hundreds of dead session DIDs and Option B's notification stream becomes meaningless ("you have 47 new sessions to accept, 41 are dead").

- **Heartbeat on agent-card.** Add `liveness.last_seen_at: <ts>` (signed by the session key). Relay updates this on every session-originated push.
- **Slot staleness.** Relay marks a slot `stale` after T = 24 h without heartbeat; stale slots are excluded from fresh roster snapshots served via `GET /v1/org/<org_did>/roster`.
- **Roster GC.** After T = 7 d stale, the registry drops the entry from the canonical roster. The org admin can re-add via the normal cert flow; sessions that come back from cold storage will re-announce and re-enter on next pull.
- **Cold-start pull.** Clients use `If-None-Match: <ETag>` against the org roster endpoint. Bandwidth scales with roster delta, not roster size.

### 8. Relay endpoints (sketch)

```
POST /v1/org/claim
  body: { org_did, attestation: { kind: "dns-txt" | "did-web", proof: <...> } }
  response: 201 with org_did pinned, or 400/409 on failure.

GET  /v1/org/<org_did>
  response: { org_did, attestation, claimed_at, last_roster_epoch }, with ETag.

GET  /v1/org/<org_did>/roster
  response: signed bundle { epoch, members: [{op_did, session_dids, agent_card_hash, sas_precomputed}], org_sig },
            with ETag for client-side caching.

POST /v1/op/enroll
  body: { op_did, op_pubkey, signed_nonce, org_memberships: [{org_did, member_cert}, ...] }
  response: 201 with op_did anchored, member_certs verified.

GET  /v1/op/<op_did>/sessions
  auth: caller must be the same op_did OR an org_did the op is enrolled in.
  response: [{session_did, agent_card, liveness}], paginated.
```

Per-event body cap stays at 64 KB; identity claims add ≤ 2 KB worst-case (3-org operator with did:web + dns-txt proofs). No relay-protocol-breaking changes; this is additive.

## Security

This section enumerates the threat surface this RFC opens or touches, naming new threats `T15..T20` continuing `docs/THREAT_MODEL.md`'s numbering.

### Touched existing threats

- **T2 (active MITM at pairing).** SAS readout is the trust-establishment moment. Option B's one-tap-accept does **not** substitute for SAS at the `VERIFIED` tier — bilateral SAS is still the only path from `ORG_VERIFIED → VERIFIED`. The org-signed SAS digits in the roster bundle are an **org-vouched precomputation**: they let `ORG_VERIFIED` be reached with one tap (the consent grant), but the tap is gated on the operator trusting the org's keypair, not on the SPAKE2 ceremony. Cryptographic invariant unchanged.
- **T11 (abusive paired peer floods recipient's slot).** Rogue insider at `ORG_VERIFIED` gets the same write capability today's bilateral pair grants. Mitigation is the existing `wire rotate-slot` (rotate the leaky bearer) plus **new per-peer block-list** (see T16 mitigation below) so the operator can revoke a single rogue without leaving the org.
- **v0.5.14 phonebook-scrape closure.** Default-Option-B preserves the closure: outsiders gain nothing, insiders gain auto-resolved SAS digits but the operator still actively consents. Option A weakens it for opt-in orgs only, with explicit per-org policy as the audit trail.

### New threats

#### T15 — Org-claim sybil

**Threat.** An attacker registers 1000 plausible-sounding orgs (`did:wire:org:slanchaai`, `did:wire:org:slancha-ai`, `did:wire:org:slancha`) to harvest enrollments or impersonate legitimate orgs.

**Mitigation.** DNS-TXT floor binds org_did to a domain the attacker must own. Sybil cost = cost of one domain per fake org (≈ $10/yr each). Bounded; auditable; not free. Out of scope: domain-squat name collisions (`slanchaai.io` vs `slanchaai.org`) — relay UI should display the bound domain prominently so operators verify the right one.

**Status.** Acceptable. Domain-bound cost asymmetry is the right floor.

#### T16 — Rogue / compromised org admin

**Threat.** Admin of `org:slanchaai` is compromised (or goes hostile) and signs an adversary into the roster. Every org-member now has the adversary at `ORG_VERIFIED` and (if eager auto-pair is enabled) without even a notification.

**Mitigation.**

1. **Tier ceiling.** `ORG_VERIFIED < VERIFIED`. The adversary cannot impersonate the admin at the SAS-verified tier; tools that act on `VERIFIED` events are unaffected. Tools that act on `ORG_VERIFIED` events must accept that the trust unit is "org integrity," not "individual SAS verification" — this is the org's threat-surface trade.
2. **Per-peer block-list (new).** `wire block-peer <did>` removes a single peer from the locally-effective roster without leaving the org. Idempotent; survives roster epoch bumps.
3. **Roster epoch bumps.** Detection of malicious roster delta is the operator's responsibility; the org's signing key is the root anchor, so if it's compromised, only key rotation + roster re-issuance recovers. See T19.

**Open (O1, below): per-peer block-list grain.** Is per-peer enough, or do we also want per-(peer, kind) (e.g., "block adversary from sending kind=1, but keep their kind=100 heartbeat")? Defer until rogue-admin scenarios are observed in practice.

**Status.** Per-tier policy split holds *if and only if* tools at `ORG_VERIFIED` are written with the rogue-admin assumption in mind. Surface this requirement in `AGENT_INTEGRATION.md` and the MCP server's `instructions` field.

#### T17 — Transitive trust via member-of-member

**Threat.** Op A trusts `org:slanchaai`; admin signs Op B; B's session enrolls in `org:malicious`; the malicious org's member roster (vouched by B's `org:malicious` membership cert) tries to lift adversary X to `ORG_VERIFIED` on A.

**Mitigation.** Org membership is **per-org**. A only auto-pairs with members of orgs A has *itself* opted into. B being in `org:malicious` does not propagate to A's policy. The `org_memberships` list on B's card is informational from A's perspective unless A is also in `org:malicious`. **No transitive trust by construction.**

This is the same property `wire group`'s introduce-pinning provides today (introduce-pinning never promotes above `UNTRUSTED`). We inherit it.

**Status.** Strong, by construction.

#### T18 — Stale roster / dead-DID accretion

**Threat.** Year-old org with 100 sessions per operator × 10 operators = 1000 roster entries, 95% stale. Routing fan-out wastes bandwidth on dead slots; Option B's one-tap notifications become unmanageable for the operator.

**Mitigation.** Liveness heartbeat + 24 h slot staleness + 7 d roster GC (Design §7). Notification UX: client suppresses notifications from cards with `liveness.last_seen_at > 24 h ago` even if they're still in the cached roster. Roster delta scales with deltas, not size, via ETag.

**Status.** Operationally bounded. Concrete TTLs are tunable per-org by the admin in v0.15+.

#### T19 — Org key rotation / cascade

**Threat.** Org's root signing key leaks. All member certs in flight are forgeable.

**Mitigation.** `wire org rotate-key <org_did>`: admin publishes a new org pubkey signed by the old key (single bridging signature, witnessed in the registry log), re-signs roster with new key, bumps roster epoch. Members pull the new roster, verify the bridging signature against the previously-pinned old key, accept the new key as the canonical org key. Isomorphic to `wire rotate-slot` but at org scope.

**Edge case.** If the leaked key is used *first* by the attacker to rotate to an attacker-controlled key, the operator must out-of-band re-bootstrap (publish a `did:web` doc with the new key, or run a fresh DNS-TXT claim). This is the v0.5.14 "machine compromise = game over for that DID" property re-emerging at org scope. Documented, not mitigated.

**Status.** Rotation primitive ships in v0.14; recovery from leak-before-detect is the operator's responsibility.

#### T20 — Operator key compromise → all orgs

**Threat.** Operator's `op_did` private key leaks. Attacker can issue `op_cert`s binding arbitrary session DIDs under this operator, propagating into every org the operator is enrolled in.

**Mitigation.** `wire op rotate-key` (analogous to T19) emits a new `op_pubkey` signed by the old key; every org the operator is in must re-issue the operator's `member_cert` against the new `op_pubkey`. The org admin is the gate. If the operator's old key is used to enroll in a new org before rotation completes, that org's admin sees the new enrollment as legitimate and may not flag it. Recommendation: the relay/wireup registry tracks an operator key-rotation event and surfaces "this operator rotated keys in the last 24 h" warnings on new enrollments.

**Status.** Substantial work; flagged as **v0.15 scope**, not blocking v0.14. v0.14 ships the rotate-key primitive without the cross-org propagation automation; operators with leaked op-keys must manually re-enroll per org.

### Threats explicitly NOT addressed by this RFC

- **Cross-machine consent for executed actions** (`docs/CONSENT_DESIGN.md`'s macaroon-vs-receiver-side-policy axis). This RFC adds *identity claims*; what authority those claims grant for *executing actions* on a receiver is orthogonal and still receiver-side policy as v0.5 chose.
- **Encryption of org rosters / member certs at rest on the registry.** Same posture as v0.1 events: registry-readable, signature-verified. Operators with confidentiality needs run a private relay.
- **GitHub-org binding.** Deferred to v0.15 to avoid wire-trust-path GitHub dependency.

## Out of scope

- Removing bilateral SAS for `VERIFIED` — never. (Maintainer guardrail; v0.5.14 invariant.)
- Centralized identity provider — orgs are domain-rooted DIDs; wireup is a registry of *attestation proofs*, not a trust authority.
- Server-side routing rules — fan-out stays client-side; project is metadata only.
- Project as a trust scope — file a separate RFC if needed; do not retrofit here.
- GitHub-org verification — v0.15+ scope.
- Cross-relay org federation — single-relay per org for v0.14; multi-relay in v0.15+.
- Cross-machine action-authority consent — separate problem (CONSENT_DESIGN.md); composable later, not a substitute for this layer.

## Acceptance criteria

Each criterion is falsifiable; the owner has merge authority on the corresponding code/test path.

1. **AC1 — Pairing friction (the headline win).** Two operators enrolled in the same org, each with 4 sessions, can fully mesh-pair across all 16 session-pairs with **≤ 16 operator taps total** (one per session-pair, Option B default) — down from the current ≤ 16 SAS dances. Measured by `tests/e2e_org_pair.rs`: harness spawns 4+4 sessions in `org:test`, asserts mesh completion under that tap budget. **Owner:** swift-harbor.
2. **AC2 — Tier ceiling integrity.** No code path (Option A or Option B, no agent-card construction, no relay endpoint) can promote a peer to `VERIFIED` without a successful local bilateral SPAKE2+SAS confirmation. Measured by a property test in `tests/trust_ceiling_prop.rs`: random walks over `org_memberships`, `op_certs`, `pair_drop_acks` never raise `Tier::VERIFIED` absent a `SasConfirmed` event. **Owner:** maintainer review.
3. **AC3 — Attestation gate.** `POST /v1/org/claim` refuses every request without a successful DNS-TXT (or did:web) proof. Measured by `tests/relay_org_claim.rs` covering: missing proof → 400; wrong domain → 400; revoked TXT record → 410 on next attestation refresh. **Owner:** relay-team.
4. **AC4 — Rogue-admin containment.** When an org admin signs an adversary into the roster, the adversary's tier on every non-bilaterally-paired member remains exactly `ORG_VERIFIED`. Adversary cannot reach `VERIFIED` via any combination of claims, certs, or auto-pair. Measured by `tests/rogue_admin_scenario.rs`. **Owner:** swift-harbor + maintainer.

**KILL CRITERION.** If at the close of the 2-week comment window the maintainer (`@laulpogan`) + ≥ 1 implementer hold that the per-tier policy split (T16 mitigation) cannot realistically defend tool ecosystems at `ORG_VERIFIED` — i.e., tools act on `ORG_VERIFIED` events without rogue-admin assumptions and the operator cannot reasonably bound the blast radius — **abandon this design and revisit a multi-signature org-cert quorum model** (e.g., M-of-N admin signatures for roster mutation) as RFC-001 v3.

## Open questions

Each has an owner and a decision point. None are abandoned bullets.

- **O1 — Per-peer block-list grain.** Per-peer-only, or per-(peer, kind), or per-(peer, project)? **Owner:** swift-harbor. **Decision:** v0.14-RC1 (after first internal-org dogfood).
- **O2 — Multi-org operator semantics.** When op A is enrolled in `org:slanchaai` AND `org:other`, and receiver B is in both, does B see one `ORG_VERIFIED` peer or two roster entries? **Decision (proposed): one peer, multi-org membership annotated on the trust record.** **Owner:** swift-harbor. **Decision:** v0.14-beta.
- **O3 — Statusline visual distinction.** Should `ORG_VERIFIED` peers render differently from `VERIFIED` in the statusline (`docs/STATUSLINE.md`)? Recommend yes (e.g., a small subscript org-emoji on the tier badge). **Owner:** @laulpogan.
- **O4 — Auto-pair toggle UX.** Per-org policy stored where (`config/wire/org_policies.json`) and surfaced how (CLI: `wire org policy <org_did> --auto-pair`; MCP: new `wire_org_set_policy` tool requiring explicit user consent like `wire_pair_confirm`)? **Owner:** swift-harbor.
- **O5 — Pre-computed SAS digits in roster bundle.** Cryptographic check: confirm the org-signed bundle cannot be replay-spliced (e.g., reuse Op A's bundle entry to impersonate Op A on a fresh session under attacker-controlled keys). Mitigation hypothesis: bundle entry binds (op_did, session_did, session_pubkey, sas_digits) inside a single org_sig, so any splice fails verification. **Owner:** maintainer (cryptographic review). **Decision:** RFC-001 v3 / pre-merge.

## Alternatives considered

- **"Do nothing."** Friction is real; the N²-pair-discovery scaling becomes a hard cap on org adoption beyond ~5 operators × ~5 sessions. Acceptable defer if v0.14 scope is tight; not acceptable indefinitely.
- **Eager auto-pair as the default (Option A).** Strictly more friction-win than Option B at the cost of the rogue-admin amplification. Rejected as *default* per operator addendum; kept as opt-in.
- **Macaroon-style scoped delegation tokens.** Different problem (cross-machine action authority, `docs/CONSENT_DESIGN.md`). Composable later; not a substitute for identity claims that the protocol can route on.
- **Two new tiers (`ORG_INTRODUCED` + `ORG_VERIFIED`).** Overlap with existing `INTRODUCED` and adds complexity without distinct semantics. Rejected.
- **Org as a brand-new primitive (not a `wire group` flavor).** Larger protocol surface; duplicated machinery (rosters, epoch bumps, signature verification). Rejected per maintainer guardrail and to keep the threat surface smaller (`wire group`'s introduce-pinning is exactly the property we need).
- **Project as a trust scope.** Tempting but a foot-gun (project tags are unsigned by design). Project is metadata only; if a trust-scoped fan-out unit is later needed, add `team` as a separate signed claim.
- **GitHub-org verification as part of the floor.** Adds wire-trust-path dependency on GitHub; convenience win but security cost. Deferred to v0.15.

## Sources

- `docs/THREAT_MODEL.md` — T-tier numbering continued (T15..T20); v0.5.14 phonebook-scrape closure language; defense-in-depth list (item 6 "per-key tier state machine, promotion one-way" remains intact).
- `docs/CONSENT_DESIGN.md` — receiver-side policy stance; macaroon-as-alternative-not-substitute framing; identity-vs-consent boundary inherited.
- `src/group.rs` (v0.13.3) — `GroupTier`, creator-signed roster, epoch bumps, introduce-pinning at `Tier::UNTRUSTED`. Substrate for "org as enriched group."
- `src/trust.rs` — `Tier::{UNTRUSTED, INTRODUCED, VERIFIED, ATTESTED, TRUSTED}`. `ORG_VERIFIED` inserts between `INTRODUCED` and `VERIFIED`; one-way promotion preserved.
- `src/agent_card.rs:111-178` — `schema_version` field, `capabilities` list. Card delta is additive (`v3.2`).
- `src/pair_invite.rs:557-571` — v0.5.14 bilateral-required split; Option B reuses the `pending-inbound-pairs` queue rather than introducing a new transport.
- `src/pending_inbound_pair.rs` — substrate for one-tap accept.
- `src/cli.rs:13131` — v0.13.1 one-name invariant. `op_did` / `org_did` MUST NOT reintroduce a free-choice name diverging from the DID-derived session handle.
- `src/session.rs:752-762, 1001-1080` — per-session by-key identity model the operator/org/project layer composes over.
- slate-lotus RFC-001 skeleton + operator addendum (2026-05-27) — direction-bless guardrails honored verbatim.
