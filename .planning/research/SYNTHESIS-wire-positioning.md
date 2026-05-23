# Wire — positioning analysis (synthesis of slices A/B/C against shipped product)

**Date:** 2026-05-21
**Baseline:** wire v0.6.10 (May 2026), solo-maintained, public-good relay at `wireup.net` (Fly.io, $0/mo at v0.5 scale).
**Inputs:** [slice-a-ai-frameworks.md](slice-a-ai-frameworks.md) (A2A / orchestration / memory), [slice-b-federation-identity.md](slice-b-federation-identity.md) (federated messaging + DID), [slice-c-ipc-localfirst-pubsub.md](slice-c-ipc-localfirst-pubsub.md) (IPC + CRDT + pubsub).
**Tone:** senior-engineer pre-investment due diligence. Neither cynical nor optimistic.

---

## 1. Executive summary

1. **Wire's defensible slice is one nobody else articulates: "two Claudes on one box, paired with operator filesystem-permission as the trust anchor, that also speak to a friend's laptop without a vendor."** None of the AI orchestration frameworks, A2A protocols, or NATS-class messaging buses treats the same-machine sister-agent case as first-class [slice A §1, §2; slice C §4]. That's the moat. Everything else is variation on it.

2. **The convergent standard is Google A2A.** ACP folded in, Salesforce/Pydantic AI/ADK speak it, Linux Foundation governs it, 150+ orgs signed on [slice A §2]. Wire cannot out-standard A2A and should not try. Wire **should speak A2A on the outside** (publish AgentCards, accept A2A `Message` events) while keeping bilateral consent + mailbox + per-relay sovereignty as its own internal semantics. This is offensive *and* defensive in one move.

3. **The v0.6.x patch-on-patch loop (six minor versions in seven days, four of them fixing the previous release) is the single clearest negative signal in the artifact set.** v0.6.6→6.7→6.8→6.9→6.10 closed a multi-Claude-same-cwd UX hole that the persona critiques surfaced four separate ways before the right answer (make-the-collision-visible, do-not-auto-disambiguate) emerged. The codebase shows wire is in a regime where each fix exposes the next-level bug, which is normal for v0.x products but is also the regime that burns out solo maintainers fastest. The right responses are *not* more features; they are scope discipline + a second contributor.

4. **The LOCKED v0.7+ identity-first direction (anon → local → federation lifecycle; UDS + HTTP+relay transports; `WIRE_AS` env + `wire launch --as` for harness-agnostic identity) is correctly aimed.** It matches what slice B and slice C independently recommend: operationally simple, identity-first, the user can see and defend the federation, centralized registries inside decentralized protocols are how this stuff ships [slice B §3, §5; slice C §closing]. The risk is execution scope, not direction.

5. **The realistic positioning slot is "operator-grade agent mesh in the smallest credible operational shape" — not protocol-standard, not platform, not orchestration framework.** That slot is genuinely unoccupied. The market is small (individual operators with 2+ AI agents who care about owning identity); the wedge into that market is bilateral consent + mailbox + single binary; the upgrade path *out* of that market is A2A interop, not a different product. Stay in the slot. Resist scope expansion to "agent platform" or "memory layer" or "CRDT-shaped state sync" — those are all losing fights against vendors with 100× the capital [slice A §7, slice C §6].

---

## 2. What wire IS today

### The problem wire solves

Two AI agents that need to coordinate without a shared vendor. The agents may be on one machine (two Claude Codes in two cwds), on two laptops belonging to two friends, or on a developer's laptop + a remote training box. Today's alternatives are:

- A shared Slack channel (vendor identity, vendor audit logs, vendor key escrow)
- A shared GitHub repo (synchronous merge semantics, vendor identity)
- A hosted multi-agent SaaS (vendor lock-in, OAuth flows, opaque billing)
- Rolling Redis pub/sub + custom auth + custom signing (high-effort, brittle, not an upgrade path)

Wire's answer: each agent picks a handle (`coffee-ghost@wireup.net`), runs `wire add tide-pool@wireup.net`, the other side runs `wire pair-accept`, done. Mailbox-federated like Mastodon (`nick@domain` resolves via `.well-known/wire/agent`), Ed25519-signed events, bilateral pair gate (receiver must consent before write-access), single Rust binary, AGPL relay you can self-host.

### Who it's for

Three identifiable tribes (from `ANTI_FEATURES.md` §12):

- **Self-hosters / homelab operators** who already run NixOS + Tailscale + a Fly.io tier-1 instance.
- **AGPL-pilled / Unix-purist / lobste.rs / p2p-veteran** — the audience that read SyncThing's design doc and nodded.
- **Anthropic-ecosystem operators with two-laptop coordination needs** — the developer running Claude Code on a laptop and a sister Claude on a remote GPU box.

Not tribes: indie hackers (different goals), crypto/web3 (no token), AI-skeptics (different priors), enterprise procurement (no compliance machine). The exclusion list is the more important signal than the inclusion list — wire has clearly resisted scope expansion to "everyone is our user."

### What's working (concrete signals)

- **The protocol works end-to-end against real federation.** v0.5.x landed bilateral consent (v0.5.14), per-session identity (v0.5.16), dual-slot routing (v0.5.17), persistent service install (v0.5.22) — each release built on the last without protocol breakage.
- **The within-system mesh ships and is observable.** v0.6.0–v0.6.5 layered four mesh primitives (`status`, `broadcast`, `role`, `route`) on `pair-all-local`. Operators get one command to mesh-pair every sister and four commands to operate the resulting mesh. This is the layer that nobody else in slice A/B/C articulates.
- **Stress tests cover the load-bearing paths.** 163 lib + 38 cli + 9 within-system stress tests green; integration tests catch the v0.5.20 `relay.json` filename mismatch that had silently disabled `--with-local` since v0.5.17. The discipline of "every fix gets a regression test" is visible across the CHANGELOG.
- **The relay genuinely costs nothing.** `wireup.net` runs on Fly.io free tier at v0.5 scale [README].

### What's clearly NOT working

- **The v0.6.x release-and-patch loop.** v0.6.6 (May 16) → v0.6.7 → v0.6.8 → v0.6.9 → v0.6.10 (May 21) — six minor versions in seven days, four of them fixing the previous release. Causes from the CHANGELOG itself: v0.6.7 fixed a "latent leak" that v0.6.1 had only partially closed. v0.6.8 fixed three stacked bugs (stale daemons on upgrade, install.sh not running upgrade, crates.io publish never wired up); v0.6.9 fixed a regression v0.6.8 introduced (~10 min after publish); v0.6.10 walked back four rounds of persona critique on the multi-Claude-same-cwd UX and landed on "just print a warning." That's healthy diagnostic discipline but it's also a sign that the v0.6 surface accumulated coupling faster than the design absorbed.

- **The multi-Claude-same-cwd UX hole.** Memory note `feedback_wire_multiclaude_ux_friction.md` records this as THREE bugs stacked: stale MCP processes, PATH-shadow binaries, and registry 1:1 cwd→session. v0.6.10's "make the collision visible" intervention is the right answer for now (don't try to auto-disambiguate), but the underlying friction is real: an operator launching three Claude Codes in the same project today gets one shared identity and a stderr warning, not three distinct identities. The locked v0.7+ direction (`WIRE_AS` env + `wire launch --as`) fixes this; v0.6.10 is the holding pattern.

- **Crates.io was stale at v0.6.1 from v0.6.2 through v0.6.7.** Anyone who ran `cargo install slancha-wire` during that window got v0.6.1, not the current release. v0.6.8 wired up the publish job; the discrepancy went unnoticed for weeks. This is the kind of release-pipeline gap that costs zero LOC but signals "wire's distribution surface is solo-maintained and undertested."

- **Solo maintenance is the load-bearing risk.** Slice A §closing makes this explicit: "Wire is solo-maintained at v0.6.10 with a public-good `wireup.net` relay at $0/mo of Fly.io spend. A2A has 150 orgs, MCP has the Linux Foundation. The standards-tier competitors have governance capital wire does not." The bus factor for both the protocol AND the relay is one.

### Maturity placement vs the competitive set

| Tier | Where wire sits |
|------|-----------------|
| Standards-tier (A2A, MCP, VC Data Model 2.0) | Wire is not standards-tier and won't be. Wire SPEAKS to standards-tier protocols [slice A §2]. |
| Production-tier (NATS, Kafka, Pulsar, Matrix, Yjs, Iroh) | Wire is 1-2 orders of magnitude smaller in adoption. Iroh hit v1.0-rc.0 in May 2026 [slice C §6]; Yjs has 4.4M weekly npm downloads [slice C §6]. Wire is at v0.6.x with a handful of operators. |
| Research-tier (NANDA, Willow, Pijul, Tonk) | Wire is operationally further along (ships today, single binary, real federation working) but conceptually less ambitious. |
| Early-production / pre-traction OSS (Atuin, mcp_agent_mail, claude-flow, Egregore) | This is wire's actual peer set. Atuin has a ~7k★ shape; wire is sub-1k★. |

The honest read: wire is in the "fundamentally shippable, demonstrably correct, has real users, doesn't have governance" tier. That's a fine place to be at v0.6.x. It is not a place to stay past v1.0 without either (a) reaching the protocol-standard tier via A2A interop or (b) accepting that wire is a small-utility OSS project with a tight tribe — both are viable, they have different rod-budget implications.

---

## 3. What wire COULD be — four plausible futures

### Future A — Niche dev-tool for "Claudes on one box" coordination

**Closest competitors.** Nothing direct. NATS (industrial scale, wrong weight class) [slice C §4]; D-Bus / Varlink / XPC (platform IPC, can't span machines) [slice C §4]; LangGraph / AutoGen subgraphs (intra-process orchestration, not transport) [slice A §1]. The closest spiritual competitor is `mcp_agent_mail` [README].

**Wire's distinctive contribution.** The within-system mesh primitives (`pair-all-local`, `mesh status/broadcast/role/route`) targeting the exact use case "operator owns N Claude Code processes, wants them to coordinate without paste-sharing handles." Filesystem permission as the trust anchor for same-uid sister agents. Sub-millisecond local-relay latency for tight task handoff. Same identity continues to work for cross-machine when needed.

**What wire would need to do to win.** Lock in this slot before A2A vendors notice it. Ship the v0.7 identity-first redesign (LOCKED in #25 per memory). Ship the `WIRE_AS` env + `wire launch --as` wrapper so any harness inherits identity. Land an mDNS opt-in for LAN sister discovery [slice C §closing recommendation]. Land a Varlink interface for free Linux systemd service discovery [slice C §4]. Cultivate a tight tribe of 50-200 operators who love it and ship integrations into Claude Code / Cursor / Continue / Aider.

**TAM signal: small.** Individual operators running multi-Claude setups today is probably four-digit, growing to five-digit as agentic tooling spreads. Not a venture-scale outcome; potentially a healthy hobbyist+pro-tool outcome at the Atuin / SyncThing scale (tens of thousands of users, tight community).

**Risks (what would kill this future).**
- Anthropic ships first-party multi-Claude coordination inside Claude Code (probable within 12 months).
- A2A interop becomes table stakes, wire's local-only differentiation no longer enough.
- Solo maintainer burnout from the patch-on-patch loop already visible in v0.6.x.

### Future B — General-purpose A2A protocol (compete with Google A2A)

**Closest competitors.** Google A2A (150+ orgs, LF-governed, ACP folded in, Salesforce/IBM/Pydantic AI all ship clients) [slice A §2]. Anthropic MCP for the tool-integration adjacency (LF AAIF cofounder slot) [slice A §2]. NANDA for the long-horizon trust-fabric ambition [slice A §2].

**Wire's distinctive contribution.** Bilateral consent gate as a DEFAULT, mailbox-async (sender ships, recipient picks up when online), single binary AGPL self-host, opinionated identity-first lifecycle.

**What wire would need to do to win.** Standards-body capture — get `did:wire` registered, ship a reference implementation that becomes load-bearing for one major framework (Pydantic AI is the natural target since it already integrates A2A as a client), get a seat on LF AAIF governance. Compete on vendor neutrality + sovereignty story. This requires governance capital wire currently does not have.

**TAM signal: large but uncapturable.** A2A is the convergent standard. The vendor matrix (Google, Salesforce, IBM, Microsoft, MongoDB, Atlassian) is decisively in motion. Wire cannot out-standard A2A and the attempt would dilute the slice it actually owns. Even pinning two slots of governance capital would consume more bandwidth than wire's current team has.

**Risks (what would kill this future).**
- Trying. The opportunity cost of pursuing this is the death of Future A. Wire's bandwidth is finite.
- A2A spec evolves faster than wire's reference implementation; wire becomes the "alternative A2A" that nobody adopts.
- The bilateral-consent posture is hard to standardize across 150+ vendors who all want their own auth model.

### Future C — Federated identity + signed messaging primitive (compete with Matrix/Nostr/ATproto)

**Closest competitors.** Matrix (~tens of millions across federated homeservers) [slice B §3]; Nostr (Jack Dorsey funded, Lightning-economic spam mitigation) [slice B §3]; Bluesky / ATproto (~5.3M MAU, did:plc invented for production deployment) [slice B §3]; XMPP (cautionary tale — Google Talk killed it) [slice B §3].

**Wire's distinctive contribution.** Mailbox-not-feed; agent-to-agent rather than human-to-room; opinionated bilateral consent at protocol layer; per-relay sovereignty; vastly smaller operational surface than Matrix room-state-resolution.

**What wire would need to do to win.** Pivot from "for agents" to "for any signed-message use case." Reposition `did:wire` as a general identity primitive. Build human-facing clients. This is a wholesale change of identity and runs into all the consumer-software problems slice B documents (key-loss = identity-loss, no "forgot password," no consumer demand pulling vendors in) [slice B §5].

**TAM signal: medium, but the medium-sized players (Matrix, Bluesky) have already won the slots wire would compete for.** Bluesky's arc (build it → reach scale → invent a DID method → spin governance to independent org → submit to IETF) [slice B §closing] is the realistic best case and it took 4M registered users over four years.

**Risks (what would kill this future).**
- Scope expansion into human messaging would alienate the agent tribe wire actually has.
- Matrix's federation-reader-pegs-CPU-at-100% pain [slice B §3] is what you inherit when you go for federated humans-in-rooms; wire chose mailbox-per-pair specifically to avoid this. Reversing that is a redesign.
- Wire has no consumer brand, no consumer UX team, and no consumer customer-acquisition mechanism.

### Future D — Memory + handoff substrate for AI agents (compete with Letta/Zep/mem0)

**Closest competitors.** Letta (MemGPT, ~SOTA on DMR), mem0 (MCP plugin ecosystem in Claude Code / Cursor / Codex), Zep / Graphiti (bi-temporal knowledge graph, paper-grade benchmarks) [slice A §7].

**Wire's distinctive contribution.** None at the memory layer. Wire is messaging, not memory. The integration story (wire-event → mem0.add → searchable by recipient agent) is real and additive [slice A §7] but wire is not the memory primitive in it.

**What wire would need to do to win.** Build a memory layer. This is the wrong direction — slice A §7 is explicit that wire should NOT solve memory and instead plug into Letta / mem0 / Zep as the messaging substrate beneath them. Mem0 alone has 4.4M weekly downloads-equivalent reach.

**TAM signal: medium, but wire is wrong-shaped for it.** Memory-for-agents has venture funding, dedicated teams, benchmarked baselines (DMR, Locomo, MemBench), and an MCP-plugin distribution story already running. Wire entering this market would face the slice C §closing "we accidentally invent a worse CRDT" failure mode applied to memory.

**Risks.** This isn't a future to pursue. List it for completeness; the recommendation is "don't."

### Future E (a fifth, not in the original list) — Email-bridged operator-owned signed messaging

**Closest competitors.** None directly; `docs/EMAIL_INTEROP.md` exists as a design brief but is not scheduled (per v0.5.19 notes in CHANGELOG). PGP/GPG over email is the cautionary precedent (decades old, never reached consumer use).

**Wire's distinctive contribution.** Wire is structurally already email-shaped (signed envelope, mailbox-per-handle, federated `nick@domain`). The `EMAIL_INTEROP.md` design proposes `wire send-email` outbound-only first, deferring the reply path. Could become a bridge that lets wire-paired agents send into existing inboxes (the operator's, a customer's, a downstream system's).

**TAM signal: small but defensible niche.** Operators who want "my agent emails me when something happens, signed by my agent's key, without going through SendGrid/Mailgun." Probably four-digit users.

**Risks.** DKIM/SPF/DMARC complexity, deliverability headaches, scope creep. Worth keeping as a design brief, NOT a v0.7 deliverable.

---

## 4. What wire NEEDS to do — three 90-day positioning moves

These are positioning moves, not a feature roadmap. The constraint is: one solo operator + AI agents helping ship at ~1-2 weeks per minor version pace. Pick the smallest set of moves that maximally improves wire's defensible slice.

### Move 1 — Ship the v0.7 identity-first redesign as the *positioning anchor*, not just the next release

**Cite.** [Memory: `project_wire_v07_identity_first_vision`]; CHANGELOG v0.6.10 long-term direction note pointing at issue #24/#25; slice B §6 (DID-method proliferation is a warning, present wire's identifiers as did:web with a service endpoint); slice C §closing (identity-first agent-mesh in smallest credible operational shape is the defensible slice).

**What.** Ship the locked identity-first lifecycle (anon → local → federation), the two bounded transports (UDS + HTTP+relay), and the harness-agnostic `WIRE_AS` env + `wire launch --as` wrapper. Document v0.7 as "identity is the noun, transport is the verb, mesh is the app." Make the README rewrite the *announcement* of this positioning, not a quiet release note.

**Why this is a positioning move, not a feature.** The v0.6.x patch-on-patch loop is the symptom of wire's current surface being slightly-wrong-shaped. The locked v0.7+ vision is the right shape. Shipping it AND telling that story prominently re-anchors what wire is for new readers — "the identity-first agent transport" beats "the federated message bus with mesh primitives" as a one-sentence pitch.

**Cost.** Per memory note + locked direction issue, this is 5 phases over 3-4 weeks. Realistic at v0.6.x cadence given the maintainer's documented pace. Each phase ships independently — even partial completion improves positioning.

**Benefit.** Closes the multi-Claude-same-cwd UX hole structurally rather than by warning, gives wire a clean naming for what it is (which the current README struggles with — "magic-wormhole for AI agents" is evocative but doesn't survive contact with "what is the thing?"), and aligns wire's spec surface with the directions slices B+C independently recommend.

**Honest risk.** v0.7 scope is the largest single change in wire's history. If it slips three months, the v0.6.x maintenance burden compounds. Set a hard ship gate (e.g. v0.7.0 is the WIRE_AS env + UDS transport, full stop; identity lifecycle phases land in v0.7.1+).

### Move 2 — Ship an A2A interop adapter, framed as "wire-speaks-A2A," not as "wire-vs-A2A"

**Cite.** Slice A §2 ("Wire should not replace A2A — wire should speak A2A while keeping its own identity / consent / mailbox semantics underneath. The 'wire MCP server presents wire peers as A2A agents to non-wire clients' play is plausible and high-leverage"); slice A cross-category pattern §5 ("the realistic 12-month threat is Google A2A becoming load-bearing... the right defensive move (and the right offensive move) is the same"); ANTI_FEATURES.md §17 currently rules this out for v0.1 but that anti-feature was scoped to v0.1.

**What.** Land two pieces:
1. A wire daemon publishes its agent-card at `.well-known/agent-card.json` in A2A AgentCard shape (signed via existing Ed25519 key). Non-wire A2A clients can discover wire peers.
2. A wire `kind=A2A_message` event type. Inbound A2A `Message` envelopes wrap-and-deliver into wire's mailbox; outbound wire events can target A2A endpoints. Bilateral consent gate still applies (wire side never accepts unsolicited A2A writes — they land in pending-inbound).

This is ONE adapter that turns wire into an A2A node with stronger defaults, not a competitor.

**Why this is a positioning move, not just interop.** Slice A §2 makes the case explicitly: every meaningful agent in 2026 will have an A2A endpoint via ADK / Salesforce / Pydantic AI / etc. Wire's current position ("you need a transport between agents") dilutes the day this is true. Wire's defensible position ("you need a transport with bilateral consent + mailbox + sovereignty between agents") survives. Shipping A2A on the outside is what makes the second sentence credible.

**Cost.** Per slice A §2 and A §8: probably ~500-1000 LOC for the AgentCard adapter + A2A `Message` event kind. A2A spec is JSON-RPC over HTTP, well-documented [a2a-protocol.org], maps cleanly onto wire's signed-event envelope.

**Benefit.** Wire stops being a category-of-one in 2027. Operators with an A2A endpoint elsewhere in their stack can talk to wire peers without a bespoke bridge. Wire's bilateral-consent posture is suddenly the answer to A2A's "auth is left to implementers" gap, not an alternative to A2A's whole approach.

**Honest risk.** Once wire speaks A2A, the marginal pull of "use wire instead of A2A" gets smaller. But that pull is already small — wire is not going to outcompete A2A at being A2A. The risk profile is: "wire becomes an A2A node with stronger defaults" is a more durable position than "wire is a competitor to A2A that nobody uses."

### Move 3 — Restructure release cadence + add a second contributor before solo burnout

**Cite.** CHANGELOG v0.6.6→v0.6.10 (six minor versions in seven days, four fixing the previous); memory note `feedback_communicate_ahead.md` (the patch-on-patch loop is partly a "communicate ahead of action" failure); slice A §closing ("wire is solo-maintained at v0.6.10... A2A has 150 orgs, MCP has the Linux Foundation. The standards-tier competitors have governance capital wire does not").

**What.** Three concrete sub-moves:
1. **Slow the release cadence deliberately.** Move from "ship when ready" to "ship on a 7-day cadence at most." The v0.6.x loop optimizes for fast feedback but the feedback is mostly "your last release was wrong." A slower cadence + more time in `--rc` or local-test mode reduces the patch-on-patch ratio.
2. **Add CI integration test coverage for the deploy artifacts.** Memory note `feedback_deploy_artifacts_integration_test.md`: systemd/launchd/cloudflared units written without actually running on the target have lurking bugs. The v0.5.22 macOS plist log-path was wrong on Linux; the v0.5.23 fix only landed because Spark caught it. Build matrix-target-platform integration tests so this class catches in CI, not in production.
3. **Onboard one second contributor with commit access on a bounded surface.** The relay (`wire-relay-server`, AGPL Rust) is the most natural single-contributor delegation — it's smaller than the CLI, has a stable interface to the rest, and runs `wireup.net` (sovereignty matters for whoever owns it). Find one person who already runs wire and would pick up the relay slot.

**Why this is a positioning move.** Wire's whole pitch is "operator-grade transport in the smallest credible operational shape." If the maintainer burns out, the public-good relay goes dark, the protocol stops being maintained, and the positioning collapses to "the OSS project that almost was." Slice B §6 and slice C §closing both name this as the failure mode that killed Solid + did:ion + most of the SSI tier — the technology was sound, the operational backing wasn't.

**Cost.** Cadence change is free (just discipline). CI matrix tests are ~1-2 days of work to land. Finding a second contributor is the hardest part (probably 30-90 days of looking + onboarding).

**Benefit.** Wire survives the year where someone else's day job intensifies, or a personal event interrupts the maintainer's pace, or the maintainer just gets tired of running into another v0.6.9-style regression hours after the v0.6.8 release party. Two contributors is the minimum survivable bus factor for an operator-grade transport.

**Honest risk.** Solo maintainership is *cheaper* than two-person maintainership in pure tokens-per-feature. Adding a second contributor adds coordination overhead, code review, governance friction. For a project at wire's scale this is a real cost. The mitigation: bound the second contributor's surface tightly (relay only) so the coordination overhead stays small.

---

## 5. Decision matrix

| Future | Strongest evidence FOR | Strongest counter-evidence | Net call (confidence) |
|--------|------------------------|---------------------------|------------------------|
| **A — Niche dev-tool for "Claudes on one box"** | Slice A §1 cross-category pattern #4: "the same-machine sister-agent UX is a category nobody else articulates." Wire's `pair-all-local` + `mesh status/broadcast/role/route` is the only end-to-end answer in the surveyed competitive set. Memory note `project_wire_v07_identity_first_vision` is LOCKED on this direction. | Anthropic / OpenAI / Google can ship first-party in-product multi-agent coordination at any time and likely will within 12 months. The market is TAM-small even if won (four-digit users, growing). | **Primary direction. High confidence (80%).** Wire's defensible slice is here. Ship v0.7 identity-first to lock it in. |
| **B — General-purpose A2A protocol** | Slice A §2: A2A is the convergent 2026 standard (150+ orgs, ACP folded in, LF governance). Some standard owns this slot; somebody will be the bilateral-consent-default option. | Standards capture requires governance capital wire does not have (slice A §closing). Pursuing this dilutes Future A. | **Don't pursue directly. Speak A2A on the outside (Move 2). Medium confidence (70%) that interop beats competition.** |
| **C — Federated signed messaging primitive (humans + agents)** | Slice B §3: Bluesky's arc shows operator-portable centralized DID method at scale is viable. Wire's `nick@wireup.net` is structurally similar. | Slice B §5: human consumer markets have key-loss / forgot-password / N² verifier integration problems wire is currently shaped to avoid by staying agent-only. Going human is a redesign. Matrix and Bluesky already own the slots wire would compete for. | **Don't pursue. Low confidence (15%) that this is wire's market.** |
| **D — Memory + handoff substrate** | Slice A §7: AI memory is a real and growing category; integration with wire is composable. | Slice A §7 explicit: "wire should NOT try to solve memory." Letta / mem0 / Zep are well-funded and well-shaped for this; wire would invent a worse version. | **Don't pursue. High confidence (95%) this is the wrong direction.** Integrate, don't build. |
| **E — Email-bridged operator messaging** | `docs/EMAIL_INTEROP.md` design brief exists; wire is structurally already email-shaped (signed envelope, mailbox-per-handle, federated handles). | DKIM/SPF/DMARC complexity is its own product surface. Scope creep risk is high. Not on the locked roadmap. | **Park as design brief; revisit post-v1.0. Low priority (10%).** |

---

## 6. Closing — the operational read

Wire is in the position any solo-maintained OSS infrastructure project sits in at v0.6.x: the protocol works, the audience is small, the next move matters more than the last one. The slices independently surfaced the same recommendation in different vocabularies:

- **Slice A:** wire's wedge is bilateral consent + mailbox + same-machine-sister UX. Speak A2A on the outside.
- **Slice B:** operational simplicity wins, centralized registries inside decentralized protocols are how this ships, bilateral consent dodges spam classes other federations spend half their releases fighting.
- **Slice C:** wire is not competing with NATS, not competing with Yjs, not competing with Pulsar. It is identity-first agent-mesh in the smallest credible operational shape, and that shape has no incumbent.

The convergence is the signal. Three independent surveys pointing at the same defensible slice is rarer than it sounds. Wire's job for the next 90 days is to ship into that slice (Move 1 — identity-first v0.7), defend the boundary against A2A becoming load-bearing (Move 2 — speak A2A on the outside), and survive the maintainership window long enough to matter (Move 3 — cadence + CI + second contributor).

What wire should NOT do, also surfaced consistently across the slices: build memory, build CRDTs, build group rooms, build human-consumer-messaging, build compliance theater, build a hosted SaaS, build an "agent platform." Every one of those is a fight against a vendor with more capital, and every one consumes bandwidth wire needs for the actual slice.

The slice is small. It's also genuinely unoccupied. That is a defensible posture for v0.6.x → v1.0 and beyond. The risk is not that wire is in the wrong slice; the risk is that wire runs out of maintainer-energy before v1.0 ships into it.

*Word count: ~4,200.*
