# RFC-001: Operator / Organization / Project identity layer

**Status:** Accepted — ratified by @laulpogan 2026-05-28 (direction blessed; acceptance criteria + kill criterion still gate the v0.14 build) <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** [#73](https://github.com/SlanchaAi/wire/issues/73)
**Author:** swift-harbor (Copilot CLI agent, paired w/ @dthoma1) — v2 from slate-lotus's skeleton
**Date:** 2026-05-27
**Target:** v0.14 (invasive — not a v0.13.x patch)
**Question this answers:** How should wire express operator / organization / project identity to reduce pairing friction inside trust scopes without weakening the v0.5.14 phonebook-scrape closure?

---

## Implementation status (as-built, v0.14)

> This RFC describes the full design space. **v0.14 ships the offline-minimal subset of it.** This note records what is built vs deferred so implementers and reviewers read the right design; the body below (§§2–9) remains the v0.15+ roadmap.
>
> **Built (v0.14) — fully offline, self-certifying:**
> - The card carries `op_pubkey` and a per-membership `org_pubkey` **inline** (see §1 snippet, corrected below). Each DID is a hash commitment to its key (`agent_card::long_fingerprint` = first 16 B of `sha256(pubkey)`), so an inline pubkey cannot be substituted without breaking the DID match.
> - Verification is **fully offline** — no resolver, roster bundle, registry, `did:web`, or DNS-TXT on the pairing path. `identity::verify_op_cert` / `verify_member_cert` take the inline pubkeys; `org_membership::evaluate_card_membership` checks commitment + both certs locally.
> - Enrollment is local CLI: `wire enroll op` / `org-create` / `org-add-member` (no `/v1/org/claim`). Receiver opt-in is a local `config/wire/org_policies.json` (`org_did → inbound: auto|notify`); `pair_invite` auto-pins `ORG_VERIFIED` on contact for `auto` orgs. Live proof: `tests/e2e_org_verified.rs` (PR #105).
>
> **Deferred to v0.15:** §2's org-claim attestation (DNS-TXT / `did:web` / `/v1/org/claim` on the wireup registry), §3/§7's online roster-bundle pull + freshness checks, GitHub-org verification, SSO (amendment-sso), cross-relay org federation. None are on the v0.14 pairing hot path.

---

## TL;DR

- Add three optional, **orthogonal-axis** claims to `agent-card.json`: `op_did` (operator), `org_did` (organization), `project` (routing tag). DID-derived session handle stays the one canonical name.
- Express **orgs as a flavor of `wire group`** (v0.13.3): creator-signed roster, replaced by org-signed roster; attested via a DNS-TXT floor on the org's domain.
- Introduce **`ORG_VERIFIED`** between `UNTRUSTED` and `VERIFIED` on the bilateral tier ladder. Org membership *eases* pairing, **never substitutes for bilateral SAS** — the v0.5.14 cryptographic invariant is preserved.
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
  "op_pubkey":   "<base64 op root pubkey>",            // v0.14: carried INLINE — commits to op_did
  "org_memberships": [                                  // NEW: zero or more
    {
      "org_did":   "did:wire:org:slanchaai-<32hex>",
      "org_pubkey": "<base64 org root pubkey>",         // v0.14: carried INLINE — commits to org_did
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

The bilateral `Tier` enum (`src/trust.rs:32`) is `{Untrusted, Verified, Attested, Trusted}`. This RFC inserts `ORG_VERIFIED` between `UNTRUSTED` and `VERIFIED`:

```
UNTRUSTED → ORG_VERIFIED → VERIFIED → (ATTESTED, TRUSTED — reserved)
```

`Tier::ORG_VERIFIED` is added between `UNTRUSTED` and `VERIFIED` (extend the enum in `src/trust.rs`). Granted when:

1. Peer presents a valid `org_memberships` entry with verified `member_cert`, AND
2. Either: receiver has previously consented per-org (Option B path), OR receiver has set per-org `auto-pair` policy (Option A path).

Promotion remains one-way. `Tier::VERIFIED` continues to require bilateral SPAKE2+SAS (the v0.5.14 invariant). A bilaterally-SAS-paired peer that *also* happens to be in a shared org is recorded at `VERIFIED`, not downgraded.

**The bilateral and group ladders stay disjoint.** Introduce-pinning is `GroupTier::Introduced` (group-scoped; `src/group.rs:31`) which pins the *bilateral* `Tier` at `UNTRUSTED` — exactly as §3 above states (verify-only, never auto-promote). `ORG_VERIFIED` is the genuinely-new bilateral tier for the attested-org-cert case; no new `GroupTier` variant is needed. The reserved `ATTESTED` slot stays free for future high-assurance attestations (key-transparency log, hardware-attested keys).

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

GET  /v1/op/<op_did>
  response: { op_did, op_pubkey, signed_self_claim, org_memberships: [...], discoverable: bool },
            with ETag. Resolution-by-known-id (caller must already hold the op_did);
            no /v1/operators bulk-listing endpoint is exposed (see O8).

GET  /v1/op/<op_did>/sessions
  auth: caller must be the same op_did OR an org_did the op is enrolled in.
  response: [{session_did, agent_card, liveness}], paginated.

GET  /v1/operators?search=<prefix>          (v0.14-beta, see O8)
  response: [{op_did, handle}] for operators with op_state.discoverable=true ONLY.
            Default empty. Operators opt in via `wire op set --discoverable`;
            non-discoverable operators are never returned, regardless of prefix match.
            **Shipping constraint:** the `discoverable=false`-default flag MUST ship
            in the same release as this endpoint (not after). Shipping the endpoint
            without the per-op opt-in gate would default every claimed op_did into
            public listing — exactly the regression O8 is designed to prevent.
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
3. **AC3 — Attestation gate.** `POST /v1/org/claim` refuses every request without a successful DNS-TXT (or did:web) proof. Measured by `tests/relay_org_claim.rs` covering: missing proof → 400; wrong domain → 400; revoked TXT record → 410 on next attestation refresh. Refresh cadence: relay re-checks each pinned org's DNS-TXT (or did:web fetch) on a configurable interval (default 6h, min 1h, max 24h) and on every claim-touching write, so revocation propagates within one cadence window without operator action. **Owner:** relay-team.
4. **AC4 — Rogue-admin containment.** When an org admin signs an adversary into the roster, the adversary's tier on every non-bilaterally-paired member remains exactly `ORG_VERIFIED`. Adversary cannot reach `VERIFIED` via any combination of claims, certs, or auto-pair. Measured by `tests/rogue_admin_scenario.rs`. **Owner:** swift-harbor + maintainer.

**KILL CRITERION.** If at the close of the 2-week comment window the maintainer (`@laulpogan`) + ≥ 1 implementer hold that the per-tier policy split (T16 mitigation) cannot realistically defend tool ecosystems at `ORG_VERIFIED` — i.e., tools act on `ORG_VERIFIED` events without rogue-admin assumptions and the operator cannot reasonably bound the blast radius — **abandon this design and revisit a multi-signature org-cert quorum model** (e.g., M-of-N admin signatures for roster mutation) as RFC-001 v3.

## Open questions

Each has an owner and a decision point. None are abandoned bullets.

- **O1 — Per-peer block-list grain.** Per-peer-only, or per-(peer, kind), or per-(peer, project)? **Owner:** swift-harbor. **Decision:** v0.14-RC1 (after first internal-org dogfood).
- **O2 — Multi-org operator semantics.** When op A is enrolled in `org:slanchaai` AND `org:other`, and receiver B is in both, does B see one `ORG_VERIFIED` peer or two roster entries? **Decision (proposed): one peer, multi-org membership annotated on the trust record.** **Owner:** swift-harbor. **Decision:** v0.14-beta.
- **O3 — Statusline visual distinction.** Should `ORG_VERIFIED` peers render differently from `VERIFIED` in the statusline (`docs/STATUSLINE.md`)? Recommend yes (e.g., a small subscript org-emoji on the tier badge). **Owner:** @laulpogan.
- **O4 — Auto-pair toggle UX.** Per-org policy stored where (`config/wire/org_policies.json`) and surfaced how (CLI: `wire org policy <org_did> --auto-pair`; MCP: new `wire_org_set_policy` tool requiring explicit user consent like `wire_pair_confirm`)? **Owner:** swift-harbor.
- **O5 — Pre-computed SAS digits in roster bundle.** Cryptographic check: confirm the org-signed bundle cannot be replay-spliced (e.g., reuse Op A's bundle entry to impersonate Op A on a fresh session under attacker-controlled keys). Mitigation hypothesis: bundle entry binds (op_did, session_did, session_pubkey, sas_digits) inside a single org_sig, so any splice fails verification. **Owner:** maintainer (cryptographic review). **Decision:** RFC-001 v3 / pre-merge.
- **O6 — Attestation expiry policy.** Surfaced by prior-art review (NATS / Sigstore / OIDF / GH Apps all use bounded TTLs; v0.13 wire trust is forever-until-revoked). Choices: (a) no expiry — simple, accretes zombies; (b) TTL on `member_cert` (e.g., 30 d) with org-side re-issuance — forces refresh, requires org online; (c) **version-based**, bound to roster epoch — matches Keybase precedent and reuses our liveness/GC pipeline. Proposed: (c) — `member_cert` is valid while its roster epoch is the current one served by the registry; epoch bump on any membership delta forces re-pull. **Owner:** swift-harbor. **Decision:** v0.14-beta.
- **O7 — `op_did` correlation / privacy stance.** Surfaced by prior-art review (DID:peer pairwise DIDs, BBS+ selective disclosure). A stable `op_did` lets every org an operator joins link their sessions to a single anchor — convenient for accountability, problematic if the operator wants compartmentalized personas (work vs personal). Proposed: `op_did` is **strictly opt-in** (sessions without one stay anonymous as today and cannot reach `ORG_VERIFIED`); pairwise `op_did`s (one per org relationship) is a **deferred v0.15 feature** if operators request it; ZKP-based selective disclosure is out of scope (complexity disproportionate to current threat model). Document the linkability trade explicitly in `docs/AGENT_INTEGRATION.md`. **Owner:** swift-harbor. **Decision:** v0.14-RC1.
- **O8 — Operator discoverability in the phonebook.** Distinct axis from O7 (which asks *whether to declare* `op_did`); this asks *whether declared `op_did`s are bulk-indexable*. Today wire publishes per-session handles to the `/v1/handles` directory (`handles_directory` in `src/relay_server.rs:1543`); the natural question is whether operators get the same treatment. **Proposed: no public bulk listing; resolution-by-known-id only; opt-in discoverable flag for operators who want public lookup.** Concretely: (a) `/v1/handles` continues to list *session* handles only, no `/v1/operators` directory endpoint exists by default; (b) `GET /v1/op/<op_did>` returns operator pubkey + signed self-claim + claimed orgs — usable for verifying a presented `op_cert`, but the caller must already know the `op_did`; (c) discovery is via shared org context (roster bundle includes member `op_did`s) — pair with one org-mate, see who else is in the org; (d) operators who actively want to be findable (public maintainers, consultants) set `op_state.discoverable = true` (stored on the registry, not on the card) and appear in a separate `/v1/operators?search=<prefix>` endpoint, default-off. Rationale: a public operator listing regresses the v0.5.14 phonebook-scrape closure at a coarser, more durable grain than sessions; contradicts every prior-art precedent surveyed (NATS, OIDF, GH Apps, ATProto, Keybase all deliberately don't enumerate top-tier identities); turns O7's voluntary-disclosure stance into involuntary cross-org correlation; and raises T20's leverage by giving attackers a target list. The opt-in flag preserves the use case while keeping default behavior conservative. **Owner:** swift-harbor + relay-team. **Decision:** v0.14-beta.

## Prior art

This section was added in response to a maintainer ask: enumerate similar concepts in the agent-identity, decentralized-identity, and federated-messaging spaces so v0.14 does not reinvent existing wheels and so reviewers can spot whether our design is missing a known footgun. Full annotated bibliography (16 systems, ~58 KB) lives in [`docs/rfc/0001-identity-layer.prior-art.md`](./0001-identity-layer.prior-art.md). This section is the synthesis.

### Three strongest precedents

**1. NATS JWT auth — Operator → Account → User ([docs.nats.io/.../jwt](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/jwt)).** The closest structural match. NATS pins the same three-tier hierarchy we are proposing, picks the same names ("Operator" at the top), and uses Ed25519 signing keys (NKeys). Each tier issues a JWT with `iss = parent public key` / `sub = subject public key`; verification walks the chain to a trusted Operator key. Convergence on the name "Operator" by an independent design is the strongest possible vote for keeping it. **Borrow:** the iss/sub chain shape — `member_cert` is conceptually a NATS-style Account JWT with `iss = org_did pubkey`, `sub = op_did pubkey`. **Diverge:** NATS treats the chain as *sufficient for trust* (no out-of-band ceremony). Wire keeps SAS as the only path to `VERIFIED`; `ORG_VERIFIED` is the ceiling the chain alone can reach.

**2. OpenID Federation 1.0 — Trust Chain + Trust Marks ([openid.net/specs/openid-federation-1_0.html](https://openid.net/specs/openid-federation-1_0.html)).** The most mature published spec for the exact problem. Defines Entity Statements (signed JWTs from a superior entity about a subordinate), a Trust Chain walker, `metadata_policy` for downstream constraints, `max_path_length` for nesting depth, and Trust Marks for org vetting. **Borrow:** Entity-Statement claim names (`iss`, `sub`, `jwks`, `exp`, `metadata`, `metadata_policy`) as the schema for `org_memberships[]` entries — interop-friendly, and `metadata_policy` lets orgs constrain what member sessions can declare (e.g., max body size, allowed capabilities) without a wire-specific mechanism. **Diverge:** OIDF assumes intermediate statements are reachable via HTTP at resolve time; wire's relay-centric, offline-tolerant model is better served by carrying the statement inline in the agent-card and pulling the roster bundle for verification, instead of walking remote `/.well-known/openid-federation` endpoints live.

**3. GitHub Apps — App → Installation → Repository ([docs.github.com/en/apps](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app)).** The most widely deployed three-tier agent-identity model in production. App authenticates with a long-lived JWT signed by its private key; installation tokens are short-lived (1 h) and minted on demand; repository permissions are scoped at installation time. **Borrow:** the *separation* between "operator signs long-lived enrollment cert" and "session uses short-lived attestation derived from it" — answers O6 from the same direction NATS does. **Diverge:** GH Apps has a central authority (GitHub) issuing installation tokens; wire's enrollment cert is published by the operator and read directly by peers — no online minting service needed.

### Compact table — naming + signing model across systems

| System | Top tier | Middle tier | Leaf | Top-↔-middle binding | Notes |
|---|---|---|---|---|---|
| **wire RFC-001 v2** | Operator (`op_did`) | Organization (`org_did`) | Session DID + Project tag | `member_cert` (ed25519, `org_did` over `op_did`) | Project is unsigned routing metadata |
| NATS JWT | Operator | Account | User | Account JWT (`iss=Op`, `sub=Acct`) | Decentralized; account can issue users with no server config |
| OpenID Federation 1.0 | Trust Anchor | Intermediate Authority | Leaf Entity | Entity Statement JWT | `metadata_policy` constrains downstream |
| GitHub Apps | App (developer) | Installation (org) | Repository perms | Installation token | Central minting authority |
| ATProto (Bluesky) | DID | Handle (DNS, mutable) | PDS service endpoint | DID document | Adds *mutable handle* as 4th axis |
| Matrix Spaces | Homeserver | Space | Room | `m.space.child` state events | ACL-as-membership, no signing chain |
| Keybase Teams | Owner | Team | Subteam | Merkle-tree signed roster links | Rotate per-team key on every membership delta |
| ActivityPub | — | Actor type=`Organization` / `Group` | — | none — actor-type declaration only | No org-membership cryptography |
| SCITT (IETF) | — | Issuer | Statement on artifact | COSE signed statement + ledger receipt | Transparency-log timestamp guarantee |
| Sigstore / Fulcio | OIDC IdP | (implicit in SAN) | Short-lived cert | OIDC token → X.509 SAN | Org lives in email domain or workflow URI |
| W3C VC 2.0 | Issuer | (implicit) | Subject | VC w/ Ed25519 / BBS+ proof | Selective disclosure available via BBS+ |
| Solid WebID | Domain owner | — | WebID | OIDC `webid` claim | Declarative `foaf:memberOf`, no org-side enforcement |
| DIF Agent Trust (draft) | Operator | Org | Agent | AgentVC + DelegationVC | Direct map onto our `op_did` / `org_memberships[]` |
| Google A2A | `AgentProvider.organization` (opaque string) | — | AgentCard | JWS over card; no chain | No operator distinct from org |
| Anthropic MCP | — | — | server descriptor | none | Identity delegated to transport |

### Three convergences worth pinning in our design

- **Independent convergence on "Operator" as the top tier.** NATS, the DIF Agent Trust draft, and our operator addendum all land on the same name and the same semantic (the human / keyholder who runs N sessions across N tenants). This is strong evidence the term is right.
- **Independent convergence on "membership = signed statement, not roster lookup."** NATS JWT, OIDF Entity Statement, Keybase signed roster links, and W3C VC all carry the org's signature *with* the member, so verification is a single key check, not a federation walk. This is exactly what Option B's roster bundle does. Keep it.
- **Independent convergence on bounded-lifetime credentials.** NATS (account JWT `exp`), Fulcio (10-min cert), GH Apps (1-h installation token), OIDF (Entity Statement `exp`). v0.13 wire trust is forever-until-revoked; **O6 above** is the place this RFC catches up.

### Three divergences worth being deliberate about

- **Wire keeps SAS as the floor; everyone else trusts the chain.** This is the single most consequential design choice we make. The cost is friction (mitigated by Options A/B). The benefit is that a compromised org admin cannot reach `VERIFIED` on any non-bilaterally-paired member. NATS/OIDF/GH Apps all accept the org-side compromise as terminal for that tenant; wire does not. **Keep this divergence; it is the v0.5.14 closure expressed at the org tier.**
- **Wire's project is routing metadata, not a trust scope.** Most systems treat the leaf tier (NATS User, OIDF Leaf, GH Repository) as a trust unit. Wire deliberately downgrades project to opaque metadata because trust-scoped projects multiply the rogue-admin blast radius without delivering a routing capability the application layer can't already express. **Document this divergence prominently.** A future RFC may revisit if a concrete use case demands it.
- **Wire is offline-tolerant.** OIDF, GH Apps, NATS (with online account resolver), and ATProto (with PLC directory) all assume the trust hierarchy is resolvable at request time. Wire carries the roster bundle in the relay slot and verifies signatures locally. **Keep this — it is the property that makes wire usable inside air-gapped enclaves, ephemeral CI containers, and cold-storage replay.**

### Known footguns from prior systems, mapped to our mitigations

- **Keybase's implicit subteam admins.** Owners of a parent team could silently add themselves to a subteam — confused operators, audit-trail gaps. **Our analog:** Project must never become a trust scope; admins must not gain `ORG_VERIFIED` on a session whose `project` tag implies a sub-scope. Already enforced by §6 (project is metadata only).
- **Matrix homeserver-operator impersonation.** A compromised homeserver admin can mint events on behalf of any of its users, because the homeserver key signs federation events. **Our analog:** `op_did` is operator-controlled, not relay-controlled — the relay can drop / spam / lose our slot but cannot sign as us. Already correct in v0.13 design; this RFC preserves it.
- **OIDF live-resolve dependency.** When the org's `/.well-known/openid-federation` endpoint is down, the whole chain stops verifying. **Our analog:** carry the org-signed bundle inline (Option B path); only consult the registry for freshness checks (ETag), never for liveness-blocking lookups. Already in §7.
- **Sigstore SAN-only org identity.** Org lives in an email domain or workflow URI; if the OIDC provider misconfigures domain ownership, identity is forgeable upstream. **Our analog:** DNS-TXT floor (§2) requires the org to prove control of the bound domain at claim time. Doesn't fully close the upstream-misconfig class, but at least bounds it to the org's own DNS posture, not a third-party OIDC IdP. Acceptable.
- **NATS account-JWT renewal cliff.** When an account JWT expires and the operator is offline, every user under it instantly fails auth. **Our analog:** O6's version-based expiry — `member_cert` is valid while its roster epoch is current. Roster epoch only advances on membership delta; pure clock-passage doesn't invalidate it. Avoids the renewal cliff while still giving us a freshness lever.

## Alternatives considered

- **"Do nothing."** Friction is real; the N²-pair-discovery scaling becomes a hard cap on org adoption beyond ~5 operators × ~5 sessions. Acceptable defer if v0.14 scope is tight; not acceptable indefinitely.
- **Eager auto-pair as the default (Option A).** Strictly more friction-win than Option B at the cost of the rogue-admin amplification. Rejected as *default* per operator addendum; kept as opt-in.
- **Macaroon-style scoped delegation tokens.** Different problem (cross-machine action authority, `docs/CONSENT_DESIGN.md`). Composable later; not a substitute for identity claims that the protocol can route on.
- **Two new tiers (`ORG_INTRODUCED` + `ORG_VERIFIED`).** `ORG_INTRODUCED` would duplicate what `GroupTier::Introduced` already expresses for the group-scoped axis; the bilateral axis needs only `ORG_VERIFIED` for the new attested-org-cert case. Rejected (single new bilateral tier suffices; group axis untouched).
- **Org as a brand-new primitive (not a `wire group` flavor).** Larger protocol surface; duplicated machinery (rosters, epoch bumps, signature verification). Rejected per maintainer guardrail and to keep the threat surface smaller (`wire group`'s introduce-pinning is exactly the property we need).
- **Project as a trust scope.** Tempting but a foot-gun (project tags are unsigned by design). Project is metadata only; if a trust-scoped fan-out unit is later needed, add `team` as a separate signed claim.
- **GitHub-org verification as part of the floor.** Adds wire-trust-path dependency on GitHub; convenience win but security cost. Deferred to v0.15.

## Sources

- `docs/THREAT_MODEL.md` — T-tier numbering continued (T15..T20); v0.5.14 phonebook-scrape closure language; defense-in-depth list (item 6 "per-key tier state machine, promotion one-way" remains intact).
- `docs/CONSENT_DESIGN.md` — receiver-side policy stance; macaroon-as-alternative-not-substitute framing; identity-vs-consent boundary inherited.
- `src/group.rs` (v0.13.3) — `GroupTier`, creator-signed roster, epoch bumps, introduce-pinning at `Tier::UNTRUSTED`. Substrate for "org as enriched group."
- `src/trust.rs` — bilateral `Tier::{UNTRUSTED, VERIFIED, ATTESTED, TRUSTED}` (`src/trust.rs:32`). `ORG_VERIFIED` inserts between `UNTRUSTED` and `VERIFIED`; one-way promotion preserved. Note: `INTRODUCED` is a `GroupTier` variant (`src/group.rs:31`), not a bilateral `Tier` — the two ladders are disjoint per §3 and §5.
- `src/agent_card.rs:111-178` — `schema_version` field, `capabilities` list. Card delta is additive (`v3.2`).
- `src/pair_invite.rs:557-571` — v0.5.14 bilateral-required split; Option B reuses the `pending-inbound-pairs` queue rather than introducing a new transport.
- `src/pending_inbound_pair.rs` — substrate for one-tap accept.
- `src/cli.rs:13131` — v0.13.1 one-name invariant. `op_did` / `org_did` MUST NOT reintroduce a free-choice name diverging from the DID-derived session handle.
- `src/session.rs:752-762, 1001-1080` — per-session by-key identity model the operator/org/project layer composes over.
- slate-lotus RFC-001 skeleton + operator addendum (2026-05-27) — direction-bless guardrails honored verbatim.
- Prior-art research prompt + 16-system annotated bibliography (Appendix A; companion file `0001-identity-layer.prior-art.md`).

## Appendix A — Prior-art research prompt

This is the research prompt used to generate the prior-art companion file. Preserved here so future RFC iterations can re-run, narrow, or extend it. Companion bibliography: [`docs/rfc/0001-identity-layer.prior-art.md`](./0001-identity-layer.prior-art.md).

> Wire's RFC-001 v2 introduces a three-tier identity layer: **Operator** (a human or a single deployment's keyholder), **Organization** (a group of operators with shared trust roots), and **Project** (a scoped subdivision of an org). Today wire only has per-session DIDs like `did:wire:swift-harbor-4092b577`. The RFC proposes adding `op_did`, `org_did`, `org_memberships[]`, and `project` fields to wire's agent-card.
>
> For each of the following systems, summarize how it models org-shaped identity, link to canonical spec + schema snippets, and analyze relevance to wire's Operator / Organization / Project hierarchy:
>
> 1. Google A2A protocol — Agent Card, `AgentProvider`, extension mechanism, signing chain.
> 2. Anthropic MCP — server identity, operator identity, multi-tenancy posture.
> 3. W3C Verifiable Credentials 2.0 — Organization as issuer, DIF organization-identity work.
> 4. DID methods: `did:web`, `did:plc`, `did:peer`, `did:key`; org-specific DID methods if any.
> 5. ATProto (Bluesky) — account/handle/PDS hierarchy, labelers as org-shaped entities.
> 6. ActivityPub — Person / Organization / Service / Application / Group actor types; FEPs on org identity.
> 7. OpenID Federation 1.0 — Entity Statements, Trust Chain, Trust Marks, `metadata_policy`.
> 8. Matrix Spaces and Matrix federation — homeserver / Space / room hierarchy.
> 9. SCITT (IETF) — Issuer → Signed Statement → Transparent Statement chain.
> 10. Sigstore / Fulcio — OIDC → short-lived cert; org identity in SAN.
> 11. GitHub Apps — App / Installation / Repository tiers; per-tier separate keys.
> 12. Solid Project — WebID, WebID-OIDC, `foaf:memberOf`.
> 13. Keybase teams — Merkle-tree team identity, per-device keys, subteams.
> 14. NATS JWT auth — Operator / Account / User; iss/sub chain on Ed25519 NKeys.
> 15. Recent (2024–2026) academic + industry work on agent identity (iAgents, DIF Agent Trust draft, etc.).
>
> For each, surface: convergent designs (where independent systems landed on similar hierarchies), divergent designs (interesting alternatives wire might miss), known footguns (failure modes others document), naming conventions (what they call operator / org / project / team / tenant / namespace), and signing/attestation chains (how they cryptographically link the tiers). End with a synthesis of the top 3–5 precedents and the 2–3 most novel tradeoffs wire should explicitly address.

**Suggested future expansions to this prompt:**

- **SPIFFE / SPIRE** workload identity (`spiffe://trust-domain/workload`) — three-tier model very close to ours; was omitted from v1 of the research.
- **DIDComm v2** messaging envelopes — bilateral signing patterns relevant to wire's pair_invite flow.
- **TUF / in-toto** supply-chain delegation — multi-signer key thresholds, useful precedent for the M-of-N quorum kill-criterion fallback in this RFC.
- **W3C DID:peer with pairwise scoping** — direct prior art for O7 (pairwise `op_did`s).
- **OpenWallet Foundation Architecture Task Force** outputs — actively defining issuer/holder/verifier identity flows for agents (2025–2026).
- **Hyperledger Aries** RFCs on connection establishment and trust frameworks.

To re-run: paste the prompt above into a research agent (or comparable tool) with the directive *"Return a single markdown document I can excerpt into RFC-001 v2's Prior art section. Cite everything."*
