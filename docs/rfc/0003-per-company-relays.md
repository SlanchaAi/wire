# RFC-003: Per-company relays — federation topology, A2A landing, apex-domain routing

**Status:** Draft
**Tracking:** [PR — this docs PR]
**Author:** coral-weasel (Slancha, with operator direction)
**Date:** 2026-05-31
**Target:** v0.15 (DNS-TXT issuer binding lands with SSO) → v0.16 (cross-relay discovery) → v0.17 (first-class apex routing)
**Question this answers:** As companies start running their own relays (slancha-fleet on `slancha.ai`, willard-fleet on a willard-controlled domain, etc.), what is wire's federation topology, how does it stay A2A-compatible, and can the apex domain (`slancha.ai`) coexist with a website AND serve wire's HTTP surface the way it already serves email?

---

## TL;DR

- **Direction: hybrid topology.** `wireup.net` stays the public-good common ground; companies that want per-org-relay autonomy bind their own (Cloudflare-Tunnel-to-Spark pattern by default, fly.io / VPS optional). Mesh between company relays optional; default federation flows through wireup as the discovery anchor until a peer is pinned.
- **Org binding via DNS-TXT, not relay-URL hardcoding.** `_wire-org.<domain> TXT "did=<org_did>; relay=<https://...>; sso_iss=<...>; sso_iss_pubkey=<base64>; v=1"` is the truth. The HTTP relay is the cached/optimized path; if it goes down, the DNS-TXT pin still resolves the org. Same record shape as RFC-001 §A SSO amendment — repurposed for per-org-relay routing even before SSO ships.
- **Apex coexists with a website.** Recommended: subdomain-split for the HTTP API (`relay.slancha.ai`) + DNS-TXT at the apex (`slancha.ai`) carrying the org binding. Operator UX still reads "feels like email" (`coral-weasel@slancha.ai`) because the DNS-TXT resolver maps apex → relay subdomain at pair-time. Apex-as-API path (`slancha.ai/wire/*`) is a v0.17+ optional escape valve, NOT the default.
- **A2A stays compatible.** Wire's `.well-known/agent-card.json` already serves the A2A v1.0 AgentCard per #91. Per-company-relay is a SUPERSET of A2A's per-domain-agent model — anything A2A can express, wire can express AND attach inline `op_did` + `org_membership` claims to. No fork.
- **Operational cost.** Per company: < 30 min onboarding, < $5/mo recurring (Cloudflare Tunnel free + Spark / fly shared baseline). Same shape as `forge.laulpogan.com` per global CLAUDE.md.

## Motivation

The slancha-fleet ↔ willard-fleet cross-org membership exchange started on 2026-05-31 (this session's wire traffic). Both fleets currently rely on `wireup.net` as the common-ground relay. As more companies stand up org_dids and want their members to auto-pair within the org, the natural question — surfaced by the operator — is: should each company run its own relay?

Today's state (audited 2026-05-31, see survey table in `docs/PROMPT_per_company_relay_planning.md`):

- Multi-homing: shipped (v0.12 `wire bind-relay`). An agent CAN live on multiple relays today.
- Federation handle syntax `<nick>@<domain>`: shipped (`pair_profile::parse_handle`).
- Cross-relay handle resolution via WebFinger-style `.well-known/wire/agent`: shipped (`pair_profile::resolve_handle`).
- A2A `.well-known/agent-card.json`: shipped (#91, Wire-as-A2A-Citizen extension).
- Federation pair_drop: shipped (`/v1/handle/intro/:nick` on the destination relay).
- **Per-org-relay binding (which relay does org X live at?):** unshipped. RFC-001 §A SSO amendment design only.
- **Cross-relay phonebook aggregation:** unshipped.
- **Cross-relay trust delegation (does relay X's claim about peer Y propagate to relay Z?):** unshipped.
- **Apex-domain-as-email routing (slancha.ai hosts both website + wire surface):** undesigned.

The gap between "per-company-relay works architecturally" and "operators can READ a per-company-relay topology" is the design surface this RFC closes.

Pain points without this RFC:

1. Operators wanting per-org relay autonomy stand them up ad-hoc, with no shared trust model → balkanization.
2. Each company invents its own apex-routing layout → cross-fleet discovery breaks.
3. A2A compatibility (#91) drifts because wire's per-company-relay extensions aren't disciplined against A2A's federation primitives.
4. Trust topology becomes implicit; a malicious relay can claim membership in an org it doesn't anchor.

## Design

### 1. Topology: hybrid (default-hub + optional-direct)

Three pure shapes, then the chosen hybrid:

**Hub-and-spoke** — wireup.net is the sole anchor; every cross-fleet pair goes through it. Pro: simple discovery, single trust root, one relay's `/healthz` is the SLA bottom-line. Con: SPOF, wireup operator (Slancha) has implicit ratification power over every fleet's identity. Rejected for v0.15+.

**Mesh** — every company federates direct. Discovery via DNS / `.well-known`. Pro: no SPOF, sovereign per-company. Con: O(N²) discovery cost at the operator UX layer (each company must know about each other to even pair); balkanization risk; phonebook discovery requires fan-out.

**Hybrid (DEFAULT-HUB + OPTIONAL-DIRECT)** — wireup.net remains the default discovery anchor + the public phonebook; companies that want per-org relay autonomy spin one up + bind their org_did to it via DNS-TXT; cross-fleet pairs flow either through wireup.net (default) OR direct relay-to-relay (operator opt-in via `wire bind-relay`). Pro: graceful migration path (no flag day), keeps wireup as the public-good discovery surface, allows sovereign-fleet escape valve. Con: two trust paths to reason about (which is fine — wire's tier ladder is already two-axis-aware).

**Accepted: hybrid.**

### 2. Org-to-relay binding: DNS-TXT (RFC-001 §A shape)

Same `_wire-org.<domain>` TXT record shape as the SSO amendment, EXTENDED with a `relay=` field:

```
_wire-org.slancha.ai. IN TXT "did=did:wire:org:slancha-fleet-88a3042ebdeab5960ffc1f4cd5b529a0; relay=https://relay.slancha.ai; sso_iss=https://accounts.google.com; sso_iss_pubkey=<base64>; v=1"
```

Semantics:

- `did=<org_did>` — the org_did this domain anchors. **Truth.** A relay claiming to host `slancha-fleet` is verified by the receiver dialing `_wire-org.slancha.ai` and checking the TXT record's `did` matches.
- `relay=<url>` — the HTTP relay endpoint where this org's members publish/pull. **Cached pointer.** If unreachable, peers fall back to wireup.net's federated path (`/v1/handle/intro/:nick` at the WebFinger-resolved relay-of-record).
- `sso_iss=<...>` / `sso_iss_pubkey=<base64>` — RFC-001 §A SSO amendment fields. Optional for per-company-relay (omit when no SSO connector binds); required when v0.15 SSO ships.
- `v=1` — schema version, monotonic. v2 will signal future extensions; readers default to v=1 semantics if absent.

Read cadence: bind/refresh time, default 6h (per SSO amendment AC3), minimum 1h, maximum 24h. **NEVER on the pairing hot path.** Receivers cache the TXT pin under `<config_dir>/dns_org_pins/<domain>.json` keyed by `domain → (did, relay, fetched_at, ttl_until)`.

Failure modes:

- DNS unreachable / NXDOMAIN → org_did unverified, pair_drop falls through to default-deny pending (RFC-001 §A floor).
- DNS-TXT record's `did=` does NOT match the org_did claimed in the inline membership cert → REJECT (substitution attack vector).
- DNS-TXT record's `relay=` differs from the relay the peer's card publishes endpoints on → operator warning + use the DNS-TXT value as truth (DNS is the slower-changing source).

### 3. Apex-domain-as-email coexistence

The operator's intuition: `slancha.ai` already hosts email (`paul@slancha.ai`, routed via MX). Can it host wire's federation handle (`coral-weasel@slancha.ai`) too, without conflicting with `https://slancha.ai`'s website?

**Recommended: subdomain-split HTTP + apex DNS-TXT pin.**

- HTTP relay: `https://relay.slancha.ai` (subdomain).
- DNS-TXT pin: `_wire-org.slancha.ai TXT "did=...; relay=https://relay.slancha.ai; ..."`.
- Federation handle parsed at apex: `coral-weasel@slancha.ai` → `parse_handle` reads `slancha.ai`, the resolver dials `_wire-org.slancha.ai`, finds `relay=https://relay.slancha.ai`, fetches `https://relay.slancha.ai/.well-known/wire/agent?handle=coral-weasel`, gets the card.

**Why subdomain split:**

- No conflict with `https://slancha.ai`'s website framework (Next.js / Astro / static) catching `/.well-known/*` or `/v1/*` accidentally.
- TLS termination separation: website's cert at `slancha.ai` is independent of relay's cert at `relay.slancha.ai`. Cloudflare Universal SSL covers both.
- Apex outage (website-driven) does NOT take the relay down, and vice-versa, IF they share Cloudflare Tunnel as TLS edge but have separate origin services.
- Operator UX (`coral-weasel@slancha.ai`) preserved via the DNS-TXT redirection — the apex IS the human-readable identifier, the subdomain is the HTTP backplane.

**Alternative considered: apex-path routing** (`https://slancha.ai/wire/*` for HTTP API, `https://slancha.ai/*` for website). Rejected as v0.15-default because:

- Website framework must explicitly NOT catch `/wire/*` and `/.well-known/wire/*`. Operator-error-prone (the website's catch-all routes change with framework upgrades).
- Single TLS origin = single point of misconfiguration (cert rotation breaks both).
- A `/wire/*`-mounted relay is harder to migrate to a subdomain later (existing peers' pinned endpoints break).

Apex-path routing is a **v0.17+ optional escape valve** for operators who explicitly want it AND accept the framework-coupling.

### 4. A2A parity matrix

Wire is A2A v1.0-compatible per #91 (Wire-as-A2A-Citizen extension). The matrix below DEFENDS per-company-relay against A2A divergence:

| Surface | A2A v1.0 | Wire | Verdict |
|---|---|---|---|
| Discovery | `.well-known/agent-card.json` per domain | `.well-known/agent-card.json` (shipped #91) + `.well-known/wire/agent?handle=<nick>` (wire-native WebFinger style) | **Compatible.** Wire serves A2A AgentCard alongside its handle-directory endpoint. |
| Identity binding | TLS as sole trust root | TLS + inline `op_pubkey` + `org_pubkey` + (v0.15) DNS-TXT issuer pin | **Wire strictly stronger.** A2A clients see wire as a valid A2A agent; wire clients get extra commitments. |
| Trust delegation | None (each agent TLS-anchored only) | `org_membership` cert chain inline; receivers verify offline against pinned `org_pubkey` | **Wire extends.** A2A has no equivalent; wire adds a layer A2A doesn't contradict. |
| Pairing UX | Implicit at first AgentCard fetch | Bilateral SAS (SPAKE2) for VERIFIED OR org_membership-auto-pin for ORG_VERIFIED | **Wire extends.** A2A clients dialing wire get the AgentCard immediately (no SAS — they're A2A-tier); wire-to-wire dialers get the SAS gesture for VERIFIED, org auto-pair for ORG_VERIFIED. |
| Per-company hosting | Native (each org at its domain) | Hybrid (wireup default + optional per-company) | **Wire matches when bound.** Per-company-relay is the per-domain shape A2A assumes. |

**Verdict: no fork.** Per-company-relay extends A2A's per-domain hosting model with wire's inline trust commitments. A v0.15-conformant wire relay IS a v1.0-conformant A2A agent surface, plus extras.

### 5. Cross-relay trust delegation: NONE, by design

A relay does NOT speak for any identity except as a transport. Receivers verify:

- The peer's card signature (Ed25519 on the canonical bytes).
- The op_cert chain (`identity::verify_op_cert` against inline `op_pubkey`).
- The org_membership cert (`identity::verify_member_cert` against inline `org_pubkey`).
- The DNS-TXT binding when present (`_wire-org.<domain>` → `did=<org_did>` matches inline claim).

A claim like "relay X says peer Y is a member of org Z" is NEVER trusted. The relay is a transport that delivers signed cards; receivers re-verify every signature offline against pinned material. This is the **offline-self-certifying invariant** from RFC-001 §"Implementation status (as-built, v0.14)" — non-negotiable.

Consequence: cross-relay trust = aggregation of pinned-org_pubkeys + pinned-DNS-TXT-records on the receiver side. No relay-to-relay attestation chain.

### 6. Phasing

- **v0.14.x (now, no code):** wireup.net stays canonical. Operators with sovereign-fleet ambitions can spin up `wire relay-server` at their own domain TODAY and bind peers via `wire bind-relay`. Documented in section 9 of `docs/PROMPT_per_company_relay_planning.md`.
- **v0.15 (SSO connectors land):** RFC-001 §A DNS-TXT issuer binding ships as part of the SSO connector PR foundation. The same DNS-TXT shape carries `relay=` for per-company-relay binding. Auto-pair lane verifies the org_did ↔ relay binding offline at bind time, NOT on the pairing hot path.
- **v0.16 (cross-relay discovery):** Operator-side fan-out — `wire whois <nick>@<unknown-domain>` reads `_wire-org.<domain>` to find the relay, then dials `.well-known/wire/agent` there. CLI verb additive; no relay-side aggregation (would create SPOF).
- **v0.17 (apex-path routing primitive, optional):** First-class support for `<nick>@<apex-domain>` where the operator explicitly mounts wire at `/.well-known/wire/*` + `/v1/wire/*` on the apex. Reverse-proxy + Cloudflare-Worker reference configs. Opt-in only; subdomain-split remains the default.

## Security

Cross-relay introduces or amplifies these surfaces. Severity (L/M/H), mitigation status (shipped / amendment / TBD):

- **Cross-relay phishing** (H — amendment). Malicious relay claims `did:wire:op:operator-FAKE` is hosted at `evil.example`. Receivers without DNS-TXT pin to verify org binding can be tricked into auto-pairing. Mitigation: DNS-TXT floor per RFC-001 §A is non-negotiable. v0.15 ships the floor; pre-v0.15 receivers don't auto-pair across relays they haven't manually trusted.
- **Cross-relay trust laundering** (M — shipped). Relay X publishes "wireup.net says peer Y is a member of org Z," but wireup never said that. Mitigation: receivers verify inline op_cert + org_membership signatures offline against pinned pubkeys; relay said-so is NEVER trusted. Shipped via RFC-001 §A offline-self-certifying invariant.
- **Relay outage = identity outage for that company** (M — shipped). If `relay.slancha.ai` is down, slancha-fleet members can't be discovered via the slancha.ai DNS-TXT path. Mitigation: multi-homing (every member CAN publish to wireup.net too, fallback discovery). Documented in operator runbook (section 9 of planning prompt). v0.16 cross-relay-discovery makes the fallback automatic.
- **Apex-domain conflicts** (M — TBD). Website framework eats `/.well-known/wire/agent` accidentally; wire surface vanishes from apex. Mitigation: subdomain-split as the default (this RFC's recommendation), reserves apex for DNS-TXT only. Monitoring `/.well-known/wire/agent?handle=<canary-nick>` from a remote dialer catches the regression in CI.
- **DNS hijack at apex** (H — TBD). Attacker gets `_wire-org.slancha.ai` TXT pointing to a malicious relay. Mitigation: DNSSEC encouraged (slancha.ai operators MUST enable); receivers cache the TXT + warn on rotation (sudden `relay=` change requires explicit operator re-confirmation). DNSSEC enforcement is a v0.16 hardening candidate.
- **Cross-relay rate limits + abuse** (M — TBD). A misbehaving relay floods another's `/v1/handle/intro/:nick`. Existing wireup rate limits per relay; cross-relay needs an inter-relay abuse-quota story. Deferred to v0.16.

Threat model deltas vs the v0.14 single-relay-anchor world are positive on net (DNS-TXT pin is a stronger root than implicit wireup-trust), but the H-severity DNS-hijack risk demands DNSSEC discipline.

## Out of scope

- **Cross-relay phonebook aggregation at the relay tier.** Each relay's `/v1/handles` stays local. Aggregation, if ever, is an OPTIONAL operator-side fan-out (v0.16). A relay aggregating other relays' phonebooks creates SPOF + abuse vectors.
- **Org-key rotation.** v0.14's `org_did` is forever (no key-rotation primitive). RFC-001 §"Key rotation" is unresolved. This RFC inherits that limitation; per-company-relay does NOT solve it.
- **Apex-path routing as default.** v0.17 escape valve only; never the recommended shape.
- **Cross-relay trust delegation.** Relays are transport, not trust authorities. Forever.
- **Federation between wire and non-A2A protocols** (Matrix, ActivityPub, ATProto). Wire-as-A2A-Citizen is the only federation bridge this RFC contemplates.
- **The slancha.ai relay deployment itself.** The recipe in `docs/PROMPT_per_company_relay_planning.md` §9 is reference; operator triggers separately.

## Acceptance criteria

≤4 falsifiable, time-bound:

1. **Time-to-first-pair between two company relays, fresh-install both sides: < 60s p50 by 2026-12-31.** Measured by a recorded benchmark from a fresh-install slancha.ai member dialing a fresh-install willard-fleet member via the cross-relay path. Owner: coral-weasel.
2. **Cross-relay phonebook discovery latency, 3 relays in mesh: < 2s p95 by 2026-12-31.** Measured by `wire whois <nick>@<domain>` fan-out across 3 pinned relays + the WebFinger resolve. Owner: coral-weasel.
3. **Org_did → relay binding resolution: ZERO network calls on the pairing hot path.** Always. Non-negotiable. Verified by a property test on `maybe_consume_pair_drop` that asserts no `reqwest::Client` / DNS resolver calls within the hot path. Owner: code-review-time.
4. **Per-company-relay onboarding: < 30 min, < $5/mo recurring.** Measured by a clean-room walkthrough of section 9's recipe + 30-day cost tally on the reference Spark / fly deployment. Owner: coral-weasel + first operator who tries it.

**KILL CRITERION:** if A2A v1.x compatibility requires forking wire's `.well-known/wire/agent` from `.well-known/agent-card.json` (i.e., we can't serve both at the same surface), per-company-relay regresses. Abandon RFC-003 + adopt straight A2A federation instead. (Read: do NOT contort wire to keep per-company-relay if doing so breaks A2A interop — A2A is the bigger pond and #91 was the right bet.)

## Open questions

- **Q1: Should slancha.ai relay run a SUBSET of wireup.net's endpoints?** A "company-scoped relay" might serve only `/v1/handle/intro/:nick` + `/.well-known/wire/agent` + `/healthz`, omitting the public `/v1/handles` directory. Decision needed before v0.15. Owner: coral-weasel + operator. Decision point: spec lands in `docs/research/per-company-relays.md` per the planning prompt.
- **Q2: Does cross-relay trust REQUIRE bilateral acknowledgement?** Or is "I bind my org to this relay via DNS-TXT" sufficient? Today the answer is the latter (DNS-TXT is the truth). But a paired relay-to-relay handshake (e.g., wireup.net pre-validates slancha.ai before federating) might raise the SLA bar. Decision needed before v0.16. Owner: systems-designer persona in the planning-prompt's spec.
- **Q3: org_did MIGRATION between relays.** If slancha-fleet moves from slancha.ai to a different apex (`slanchaai.io`?), how do existing peers re-resolve? DNS-TXT update at old apex pointing to new (`relay=https://...`)? Cert chain? Open. Decision needed before v0.17. Owner: coral-weasel.
- **Q4: Cross-relay rate-limit / abuse model.** A misbehaving relay floods another's intro endpoint. Existing per-relay limits suffice short-term; longer-term, an inter-relay abuse quota / federation block-list? Open. Owner: SRE persona in the planning-prompt's spec.

## Alternatives considered

- **Hub-and-spoke** — rejected (wireup as sole trust root creates SPOF + Slancha-as-ratifier dynamic that mis-aligns with sovereign-fleet posture). See Design §1.
- **Mesh** — rejected as default (O(N²) discovery cost + balkanization). Still available as opt-in via `wire bind-relay` to peer relays directly. See Design §1.
- **A2A federation only (no wire-native cross-relay)** — rejected. A2A's trust model is TLS-only; wire's inline-pubkey + org_membership commitments are strictly stronger and the marquee differentiator. Keeping wire-native cross-relay + serving A2A AgentCard at the same surface is the right shape (#91 already proved compatible). Re-evaluate via the KILL CRITERION if A2A v1.x diverges.
- **Apex-path routing as default** (`slancha.ai/wire/*`) — rejected for default; v0.17 escape valve only. Operator-error-prone, single TLS origin, painful migration. See Design §3.
- **Relay-to-relay attestation chain** (relay X vouches for relay Y) — rejected. Receivers MUST verify offline against pinned material; relay said-so is forever distrusted. Aligns with the offline-self-certifying invariant. See Design §5.

## References

- `docs/rfc/0001-identity-layer.md` — RFC-001 identity layer (ratified, implemented v0.14).
- `docs/rfc/0001-identity-layer.amendment-sso.md` — §A DNS-TXT issuer binding (amendment, v0.15 target).
- `docs/A2A_EXTENSION.md` (per #91) — Wire-as-A2A-Citizen extension spec.
- `docs/PROMPT_per_company_relay_planning.md` (this PR) — the planning prompt that produces the implementation spec.
- A2A v1.0 spec (Google Agent2Agent, public).
- Global CLAUDE.md "Public uplink — laulpogan.com via Cloudflare" — the Cloudflare-Tunnel-to-Spark pattern referenced for slancha.ai relay provisioning.

---

**This RFC is the FRAME for the v0.15 / v0.16 / v0.17 code PRs that follow.** The planning prompt at `docs/PROMPT_per_company_relay_planning.md` drives production of the implementation spec (`docs/research/per-company-relays.md`). After spec ratification, the per-company-relay deployment recipe in §9 of the prompt is the operator's hand-off; the SSO connector prompt (`docs/PROMPT_v0.15_sso_connectors.md`) absorbs the DNS-TXT shape from §2 of this RFC.
