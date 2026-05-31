# Hydrated prompt — per-company relay architecture: design deep-dive + A2A landing + apex-domain-as-email routing

*Paste into a fresh Claude session in `~/Source/wire` to drive the per-company-relay planning artifact. Self-contained; assumes no conversation context, only the repo + the references below.*

> **Goal:** produce a research-spec-quality artifact (`docs/research/per-company-relays.md`) that locks the architectural direction for wire's federation topology before any infra goes up. Operator-triggered today (2026-05-31) after the slancha-fleet ↔ willard-fleet cross-org membership exchange started — the natural next ask is "stand up a slancha.ai relay," but the design space is large enough that infra-first risks locking in a topology that doesn't compose with A2A or with future SSO. Hydrate, persona-critique, ship the spec; THEN provision the relay if the spec lands clean.

---

## You are

A senior systems designer with prior context on wire's RFC-001 identity layer (v0.14), A2A v1.0 (Google's Agent-to-Agent protocol the wire-as-A2A-citizen extension landed via #91), and federation topologies generally (Matrix, ActivityPub, ATProto, email). Output: a research brief that fits the `research-spec` skill discipline (trust priors, persona-critique, KPI gate). NOT code. NOT a deployment runbook. A SPEC the operator can read, react to, then hand back as concrete v0.15/v0.16 PR work.

Read these in order BEFORE touching the spec:

1. `docs/rfc/0001-identity-layer.md` + `0001-identity-layer.amendment-sso.md` — the ratified identity layer + the §A DNS-TXT issuer-binding amendment that anchors org_did at a domain.
2. `docs/A2A_EXTENSION.md` (or whatever #91 landed as) — the Wire-as-A2A-Citizen extension spec.
3. `src/relay_server.rs` — the shipped relay surface (1530 = `handles_directory`, 1780-1900 = `.well-known/wire/agent` + A2A `agent-card.json`, 415 = `/v1/handle/intro/:nick`).
4. `src/relay_client.rs` (`well_known_agent_card_a2a` at 659) + `src/pair_profile.rs::resolve_handle` (line 263) — the client side of cross-relay handle resolution.
5. Memory notes: `project_wire_identity_unify_and_multihome` (v0.12 multi-homing — bind-relay shape); `project_wire_positioning_lock` (Future-A locked direction); `project_wire_transport_substrate_research` (substrate-agnostic stance); `project_wire_handle_relay_userinfo_bug` (apex/userinfo gotcha already seen).
6. `docs/THREAT_MODEL.md` if present — current trust + threat model (cross-relay introduces new threats).
7. A2A v1.0 spec, public — read the federation/discovery sections specifically.

---

## What "cross-relay" actually means today (the survey to ground the spec)

Run this first; the spec must NOT mis-claim shipped surface. Honest state per 2026-05-31:

| Surface | Shipped? | File:line | Gap (if any) |
|---|---|---|---|
| Federation handle syntax `<nick>@<domain>` | ✅ | `pair_profile.rs:117` | none |
| Cross-relay handle resolution (`.well-known/wire/agent?handle=<nick>`) | ✅ | `pair_profile.rs:263`, `relay_server.rs:1893` | WebFinger-style; no caching contract |
| A2A `.well-known/agent-card.json` (A2A v1.0) | ✅ | `relay_server.rs:1786-1795`, `relay_client.rs:659` (#91) | served per-card; not org-scoped |
| Federation pair_drop (`POST /v1/handle/intro/:nick`) | ✅ | `relay_server.rs:415` | destination relay-scoped only |
| Per-relay phonebook directory (`/v1/handles`) | ✅ | `relay_server.rs:437,1530` | local-only; **no cross-relay aggregation** |
| Multi-homing (one agent on multiple relays) | ✅ | v0.12 `bind-relay` (PRs #45, #46) | additive only; no preferred-relay hint |
| Cross-relay trust delegation | ❌ | n/a | explicit pin only — no "relay X says peer Y is a member of org Z" chain |
| Per-org-relay routing (`slancha-fleet → slancha.ai`) | ❌ | n/a | RFC-001 §A SSO amendment design only, no code |
| Apex-domain-as-email routing (`nick@slancha.ai`) | ❌ | n/a | `relay_server.rs:1780-` serves under apex if bound, but doesn't coexist with a website on apex; **must design** |
| Cross-relay phonebook aggregation | ❌ | n/a | each relay's `/v1/handles` is local |
| Org_did → DNS-TXT pin discovery (RFC-001 §A floor) | ❌ | n/a | amendment, not built |

The spec MUST cite this table and discriminate "design existing in code" from "design existing only in RFC" from "no design at all."

---

## Required spec sections

The output goes to `docs/research/per-company-relays.md`. Structure:

### 1. Executive summary (3 paragraphs max)

- What problem per-company relays solve (and what they don't).
- The recommended topology (one of: hub-and-spoke / mesh / hybrid).
- The cost: ops footprint per company, trust topology shifts, A2A divergence (if any).

### 2. The topology trilemma

Three pure shapes, then the hybrid:

- **Hub-and-spoke** (wireup.net = hub, company relays = spokes). Every cross-fleet pair goes via wireup. Simple discovery, single trust root, single-point-of-failure.
- **Mesh** (every company federates direct). Discovery via DNS / well-known. No SPOF. N² discovery cost; balkanization risk.
- **Hybrid** (default hub, optional direct). Common ground stays at wireup.net; companies that want to direct-federate do so explicitly via `wire bind-relay` to each other's apex.

For each: shipped support today (cite table above), gaps, KPIs (next section), trust topology graph.

### 3. KPIs (per `kpi-rules.md` if `research-spec` skill is available)

≤4 falsifiable, time-bound, threshold-set. Reject vanity. Examples to aim for:

- "Time-to-first-pair between two company relays, fresh install both sides: < 60s p50 by 2026-12-31."
- "Cross-relay phonebook discovery latency, 3 relays in mesh: < 2s p95 by 2026-12-31."
- "Org_did → relay binding resolution: zero network calls on the pairing hot path (offline-self-certifying invariant from RFC-001)."
- "Operational footprint for a company adopting per-company-relay: < 30 min onboarding, < $5/mo recurring (Cloudflare Tunnel + Spark / fly.io baseline)."

### 4. Apex-domain-as-email routing

The operator asked specifically: can `slancha.ai` host BOTH the company website AND the wire relay, the way `slancha.ai` hosts email (`paul@slancha.ai` resolves via MX) without conflicting with `https://slancha.ai`'s web content?

Analyze:

- **Path-prefix routing.** Web on `slancha.ai/*`, wire on `slancha.ai/wire/*`. Operator's website framework must not catch `/wire/...`. Cloudflare Worker / reverse proxy can split per-path.
- **Well-known coexistence.** `slancha.ai/.well-known/wire/agent`, `slancha.ai/.well-known/agent-card.json` (A2A), `slancha.ai/.well-known/wire-org` (DNS-TXT mirror) — all need to coexist with whatever else lives at well-known on the apex.
- **Subdomain split.** `relay.slancha.ai` for the HTTP API, `slancha.ai` for web + redirect well-known. Simplest; loses the "feels like email" UX.
- **DNS-TXT as the truth, HTTP as the optional path.** `_wire-org.slancha.ai TXT "did=...; sso_iss=...; sso_iss_pubkey=...; relay=https://relay.slancha.ai"` — DNS-TXT carries the relay pointer, so wire reads "the org_did slancha-fleet lives at the relay URL in the TXT record." This is the RFC-001 §A SSO amendment's exact mechanism, REPURPOSED for per-org relay binding even before SSO ships.
- **Federation handle UX comparison.** `coral-weasel@slancha.ai` vs `coral-weasel@relay.slancha.ai`. Email-style is operator-readable; subdomain-style is HTTP-framework-trivial.

Pick one as the recommendation, justify in 1-2 paragraphs, list 3 reasons not to.

### 5. A2A parity matrix

A2A v1.0 federation model vs wire's per-company-relay model. Rows:

- Discovery: A2A `.well-known/agent-card.json`; wire `.well-known/wire/agent`. Wire is A2A-compatible per #91 — already serves the A2A AgentCard alongside its native handle format.
- Identity binding: A2A relies on TLS as the sole trust root; wire ADDS inline pubkeys + (future) DNS-TXT issuer binding. Wire is stronger.
- Trust delegation: A2A has none — agents are TLS-rooted only. Wire has org_membership inline + cross-relay attestation paths (§A amendment).
- Pairing UX: A2A has no equivalent of bilateral SAS — pairing is implicit at first agent-card-fetch. Wire's SAS is stronger; wire's auto-pair-via-org_membership (v0.14) bridges to A2A-ease.
- Per-company-relay implication: A2A naturally fits per-company hosting (each org runs its agent at its domain). Wire's per-company-relay model is a SUPERSET — anything A2A can express, wire can express AND attach inline op_did + org_membership claims to.

Verdict per row: where does wire diverge from A2A, where does it embed A2A, where does it strictly extend.

### 6. Threat model deltas

Per-company-relays introduce or amplify:

- **Cross-relay phishing.** A malicious relay claims `did:wire:op:operator-FAKE` is hosted at `evil.example`. Receivers without DNS-TXT pin to verify org binding can be tricked. Mitigation: DNS-TXT floor per RFC-001 §A is non-negotiable.
- **Cross-relay trust laundering.** A relay X publishes "wireup.net says this peer is a member of org Y," but wireup.net never said that. Mitigation: receivers verify inline op_did + org_membership signatures, never trust relay-said-so.
- **Relay outage = identity outage for that company.** If `slancha.ai` is down, slancha-fleet can't be discovered. Mitigation: multi-homing (every member can publish to wireup.net too, fallback discovery).
- **Apex-domain conflicts.** Web framework eats `/.well-known/wire/agent` accidentally; wire surface vanishes. Mitigation: monitoring, healthcheck endpoint, well-known reservation in framework configs.
- **DNS hijack at apex.** Attacker gets `_wire-org.slancha.ai` TXT pointing to a malicious relay. Mitigation: DNSSEC encouraged; receivers cache the TXT + warn on rotation.

Each threat: severity (low/med/high), mitigation status (shipped / amendment / TBD), KPI tie-in.

### 7. Persona critiques (5 parallel reviewers, per `research-spec/personas.md` if available)

- **Systems designer** — does the topology compose? Mesh-vs-hub trade-offs read right?
- **Programmer / Rust engineer** — what new code surface ships? Are the trait seams stable?
- **SRE / operator** — operational footprint per company? Failure modes? Monitoring?
- **Security / cryptographer** — DNS-TXT root acceptable? Cross-relay attestation chain water-tight?
- **A2A interop engineer** — does this stay A2A-compatible or fork? Adoption story?

Each persona writes 3-5 nitpicks. BLOCKER / MAJOR / MINOR tagging per `revision-plan.md` template.

### 8. Implementation phasing

Sequenced phases mapped to wire version numbers:

- **v0.14.x (now)**: wireup.net stays canonical; multi-homing already works. Operators can bind to slancha.ai TODAY via `wire bind-relay` once slancha.ai's `wire relay-server` is up. No code change.
- **v0.15 (with SSO connectors)**: RFC-001 §A DNS-TXT issuer binding lands. `_wire-org.slancha.ai TXT` carries `org_did + relay_url + sso_iss + sso_iss_pubkey`. Receivers pin the binding; auto-pair lane verifies offline. **Required before slancha-fleet auto-pair becomes a real production claim.**
- **v0.16 (cross-relay discovery)**: Cross-relay phonebook aggregation lands as an OPTIONAL operator-side feature (not relay-side; aggregating in the relay creates SPOF). CLI `wire whois <nick>` fans out across pinned relays.
- **v0.17 (apex-routing primitive)**: First-class support for `<nick>@<apex-domain>` where apex serves a website AND wire surface. Reverse-proxy reference config; cloudflare-worker reference impl.

Phasing rationale per step. NOT all of this ships at once.

### 9. Concrete slancha.ai deployment recipe (v0.14.x — no code needed)

Walk-through for the operator post-spec-acceptance. Cite the global CLAUDE.md Cloudflare-Tunnel pattern (`forge.laulpogan.com`); SHIP-able as `relay.slancha.ai`-shaped under the Cloudflare-Tunnel-to-Spark pattern OR as `slancha.ai/wire/*`-shaped under Cloudflare Workers + path routing.

Include: DNS records, tunnel UUID generation, systemd unit shape, healthcheck endpoint, time-to-first-pair test from a fresh-install peer.

### 10. Open questions / Stop conditions

- Should slancha.ai's relay run a SUBSET of wireup.net's endpoints (e.g., only `/v1/handle/intro/:nick` + `/.well-known/wire/agent`, no public phonebook) — "company-scoped relay"?
- Does cross-relay trust REQUIRE bilateral acknowledgement, or is "I bind my org to this relay via DNS-TXT" sufficient?
- How does an org_did MIGRATE relays without becoming inaccessible? (org_did = forever; relay URL = mutable; mismatch handling).
- Cross-relay rate limits + abuse model — distinct from single-relay.

Each: BLOCKING-for-v0.15 or DEFERRED-to-v0.17. If BLOCKING, the spec lists the decision and surfaces to operator.

---

## Process

- **Persona-critique BEFORE drafting** each section. State each persona's stance on the section's topic in a sentence; if any persona objects, restructure.
- **Trust priors on every cited claim.** [P, primary-source, score 0-100] per global CLAUDE.md research discipline. RFC-001 is primary, score 95. A2A v1.0 spec is primary, score 90. Memory notes are secondary, score 60-70.
- **KPI gate** before declaring section 3 done. ≤4 KPIs, falsifiable, time-bound.
- **Five-persona parallel review** before declaring the spec done. Synthesize their nitpicks into `revision-plan.md`. Apply BLOCKER+MAJOR. Skip MINOR if time-pressured.
- **Do NOT ship infrastructure as part of this prompt.** The recipe in section 9 is reference; the operator triggers the actual `wire relay-server` spin-up separately.
- **Do NOT modify production code as part of this prompt.** Section 8 phasing is descriptive, not prescriptive of immediate PRs.
- **Caveman mode active per global** — terse, technical substance exact.

---

## What "done" looks like

`docs/research/per-company-relays.md` exists with all 10 sections populated. KPIs ≤4 each falsifiable. Persona critiques applied. Citations use trust-prior format. The operator can read the file in 20 minutes and walk away knowing:

1. What topology wire will run (one of hub-spoke / mesh / hybrid, named).
2. What apex-domain UX is recommended (one of path-prefix / subdomain / DNS-TXT-anchored, named).
3. How close we are to A2A landing (the parity matrix as a scorecard).
4. What ships in v0.15 vs v0.16 vs v0.17 (the phasing).
5. The slancha.ai relay deployment recipe (ready-to-run, no further design).
6. The threats they accept by going per-company-relay (the deltas + mitigations).

Per `research-spec` skill: the spec is NOT a plan, it's a frame the next session uses to write plans.

---

## Anti-patterns (instant-reject in review)

- **Skipping the survey table.** Claiming surface ships when it doesn't (e.g., "cross-relay phonebook aggregation works in v0.14") loses operator trust + corrupts downstream planning.
- **Hub-and-spoke worship.** wireup.net as a single trust root is the EASY answer; the spec must defend whichever topology is chosen, not the most-shippable.
- **Defaulting to A2A-divergence.** Wire is A2A-compatible per #91 today; the spec must NOT recommend forking unless the case is airtight.
- **DNS-TXT hand-waving.** §A amendment specifies `did=<org_did>; sso_iss=<issuer>; sso_iss_pubkey=<base64>; v=1` — the spec cites the format verbatim, not a paraphrase.
- **Treating apex-routing as a UX cosmetic.** It's a TLS-and-routing question; operational risk is real (apex outage = website AND relay down).
- **Invented numbers.** No "100ms p50 cross-relay latency" without a benchmark plan. Use `[TBD: needs verification]` per global CLAUDE.md.
- **Confusing slancha-fleet (the org_did) with slancha.ai (the relay).** They're distinct: the org_did commits to a key; the relay is a transport. The spec must keep them disjoint in language.

---

## Stop conditions / when to ask

- Operator hasn't expressed preference between hub-spoke / mesh / hybrid. The spec defaults to **hybrid** unless explicitly told otherwise; surface the assumption.
- A2A v1.0 spec changes mid-flight (the A2A working group is active). If the wire-as-A2A-citizen extension needs to bump, surface BEFORE locking the parity matrix.
- DNS-TXT amendment hasn't been ratified (§A is amendment, not ratified RFC-001 §). Spec assumes ratification path; surface the gap.
- Cross-relay trust model touches `pair_invite.rs` or `org_membership.rs` (trust paths). Per repo-scrub-prompt anti-patterns: do NOT propose code in trust paths without separate operator approval.
- KPI #3 (offline-self-certifying invariant) is non-negotiable. If a section's recommendation breaks it, STOP and re-architect.

---

## What you start with

- `main` at the v0.14.1-tail (post `release: v0.14.1` merge). 
- A live slancha-fleet org_did already minted (`did:wire:org:slancha-fleet-88a3042ebdeab5960ffc1f4cd5b529a0`) — this is the FIRST real test case for per-company-relay binding. Cross-org membership exchange with willard-fleet is in-flight (slate-lotus replied 2026-05-31 with the audit; reciprocal mints queued).
- The slancha.ai domain is owned + DNS-managed.
- A2A v1.0 compatibility shipped (#91); the wire-as-A2A-citizen extension spec is the canonical reference.

Start with section 1 (executive summary) AFTER you've drafted sections 2 + 5 + 6 + 8 — the exec summary is the synthesis, not the prologue. Then ladder forward through the rest. KPI gate at section 3 stops drafting until they're falsifiable. Persona review at section 7 applied to the whole artifact. Then the slancha.ai recipe in section 9 is the operator's hand-off.

The spec is the FRAME for the v0.15 / v0.16 / v0.17 code PRs that follow. Not those PRs themselves.
