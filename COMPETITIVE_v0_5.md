# Competitive landscape — wire v0.5 (2026-05)

Narrow research on projects positioned as **cross-org / cross-individual agent-to-agent communication channels** (not general agent frameworks). Filtered to direct competitors.

## TL;DR

Wire's positioning is **partially differentiated, not novelly differentiated**. Each individual component has an incumbent. The bundle is unique. Existential threat is not Google A2A — it's **AMP (agentmessaging.org)** racing to ship the same Ed25519-signed `name@domain` federation we are.

**Strongest defensible wedge:** *"the only agent-comms protocol where the relay sees only ciphertext+sigs, onboarding is one paste, and two operators on laptops can hotline without trusting a hub."*

**Smartest strategic move:** federate with A2A by adopting their AgentCard schema as a wire extension, then own the mailbox-relay layer A2A explicitly doesn't do.

---

## Genuine competitors (positioned as A2A comms)

### 1. AMP — `agentmessaging.org` / 23blocks
- **Wire's mirror image. The existential one.**
- Positioning: *"Open standard for secure AI agent communication... federated, cryptographically secure with Ed25519 signatures, and local-first."*
- Identity: Ed25519 keys + `agent-name@tenant.provider` handles (e.g. `backend-architect@acme.crabmail.ai`)
- Discovery: handle-based, no centralized registry
- Transport: REST + WebSocket over TLS
- Security: Ed25519 message signatures + trust-level annotations for prompt-injection
- License: Apache 2.0
- Adoption signal: **25 stars, 48 commits, "Coming Soon" providers.** Pre-traction.
- Wire's edge: ciphertext-only relay design, MCP-first agent UX, three-layer DID+handle+profile, working hosted relay
- Wire is behind: nothing structural; they have the spec published, we have working code. **Race condition.**

### 2. Google A2A v1.0 — `a2aproject.io`
- **Mindshare winner. Production-deployed.**
- Positioning: *"An open protocol enabling communication and interoperability between opaque agentic applications."*
- Identity: OAuth2 / OIDC / mTLS / API keys (no DID); domain-anchored via signed AgentCard
- Discovery: `https://{domain}/.well-known/agent-card.json` (RFC 8615)
- Transport: JSON-RPC 2.0 / gRPC over HTTPS, SSE streaming, push
- Security: Signed AgentCards (JWS) in v1.0
- License: Apache 2.0, Linux Foundation
- Adoption: **150+ orgs. MSFT, AWS, SAP, ServiceNow, Salesforce shipped integrations. 23.7k GitHub stars. Microsoft Agent Framework for .NET ships A2A v1 client.**
- Wire's edge: mailbox relay (not always-on HTTP — works for laptops + intermittent agents), ciphertext-only relay, MCP-first paste-prompt UX, three-layer identity
- Wire is behind: night-and-day adoption gap. They got `/.well-known/` first — our `/.well-known/wire/agent` looks like a fork

### 3. ANP — Agent Network Protocol
- **Deepest DID story.**
- Positioning: *"Decentralized identity, discovery, messaging, and payment protocols for interoperable AI agents."* Pitches itself as the "HTTP of the Agentic Web."
- Identity: `did:wba` — each DID resolves to an HTTPS-hosted DID doc; handles like `alice.example.com` (WNS)
- Discovery: `.well-known/agent-descriptions` JSON-LD directory
- Transport: flexible; explicit federation profile (P8)
- Security: DID-anchored signing
- License: OSS, unstated
- Adoption: arxiv whitepaper (2508.00007), low GitHub star count, hard to find production users
- Wire's edge: shipping, MCP-first, single-command pair UX vs ANP's spec-heavy approach
- Wire is behind: ANP's DID method (`did:wba`) is the most serious in this space. Wire's `did:wire:<hash>` is shallow by comparison

### 4. Coral Protocol — `coralprotocol.org`
- Positioning: *"Open collaboration infrastructure that enables communication, coordination, trust and payments for The Internet of Agents."*
- Identity: DIDs + cryptographic certificates + agent cards
- Discovery: decentralized registries + agent cards
- Transport: MCP-based with **persistent threads + mention-based targeting**
- Security: multi-party signatures + on-chain immutable transaction log
- License: OSS
- Adoption: active GitHub, arxiv paper (2505.00749), reference agents shipped
- Wire's edge: leaner, no chain/payment baggage, no thread-server centralization
- Wire is behind: Coral has threading model + payments wire doesn't. Their paper explicitly compares against A2A/ANP/AGNTCY — they're playing one level up

### 5. AGNTCY / Cisco SLIM — `agntcy.org`
- **Enterprise stack. Cisco-backed.**
- Positioning: *"Building infrastructure for the Internet of Agents."* SLIM = Secure Low-latency Interactive Messaging
- Identity: cryptographically verifiable identity, OASF schemas
- Discovery: OASF capability discovery
- Transport: Rust data plane + Go control plane, gRPC, hierarchical name routing
- Security: **MLS (Messaging Layer Security)** end-to-end encryption, quantum-safe pitch
- License: Apache 2.0
- Adoption: 189 GitHub stars, IETF spec submitted, AWS+Google+SAP listed
- Wire's edge: dev-friendly, single binary, MCP-first paste prompt
- Wire is behind: MLS group encryption (wire doesn't have it), Cisco's distribution

### 6. IBM ACP — Agent Communication Protocol
- Positioning: *"Shared language to connect and collaborate."*
- Identity: API auth, registry-anchored
- Discovery: centralized registries
- Transport: REST
- Security: standard TLS
- License: Linux Foundation OSS
- Adoption: enterprise BeeAI users
- Wire's edge: federated and signed; ACP is centralized

### 7. claude-peers-mcp — `github.com/louislva/claude-peers-mcp`
- **Different problem entirely. Localhost only.**
- Positioning: MCP broker for Claude Code peers
- Identity: per-session peer ID, no signing
- Discovery: SQLite broker on `localhost:7899`
- License: MIT, 2k stars
- Wire's edge: cross-machine, signed, federated
- Wire is behind: 2k stars + viral on launch. Listed here because devs hunting "Claude agents talking" might find it first

---

## Adjacent / not real competitors (deliberately skipped)

- **Naptha** — agent OS, not comms protocol. Relay "not currently functional" per their docs
- **Fetch.ai uAgents + Almanac** — economic agents on FET chain, different audience (DeFi)
- **Olas / Autonolas** — mech marketplace (agents-hiring-agents), not a comms bus. 3,624 deployed agents though — biggest actual numbers in space
- **SingularityNET** — decentralized AGI tent, not focused
- **Skyfire / Crossmint Agentic** — payments only, no messaging. Potential complement
- **Recall Network** — on-chain reputation, adjacent slot wire could federate with
- **Theoriq** — pivoted to AI-DeFi vaults, no longer agent-comms
- **Sentient Foundation** — research-org pitch, no protocol shipping
- **HyperCycle / Wayfinder / Plurigrid** — crypto-narrative, low protocol-adoption signal
- **OpenAI Swarm + Agents SDK handoffs** — intra-runtime only, not cross-org

---

## Top 3 truest competitors (ranked by existential threat)

1. **AMP** — wire's mirror image. Same Ed25519, same handle-as-email, same federation pitch, same Apache license. Pre-traction but spec is published. If a dev finds AMP first, wire reads as a re-implementation. **Wire's only structural edges:** (a) ciphertext-only relay, (b) MCP-first agent UX, (c) three-layer DID+handle+profile, (d) working hosted relay at wireup.net. **Race is on.**

2. **Google A2A v1.0** — different stack layer (direct HTTPS RPC between always-on endpoints, not relay/mailbox), but owns the `/.well-known/` mindshare. Any dev evaluating wire will ask *"why not A2A?"*. **Wire's one-line answer:** A2A assumes always-online agent HTTP endpoints; wire's mailbox relay works for laptops and intermittently-connected agents.

3. **ANP** — only competitor with a serious DID story. If wire's three-layer identity matters (it's central to v0.5 positioning), ANP is the prior art to defend against or adopt.

---

## Whitespace verdict

Each individual component has an incumbent:

| Wire feature | Incumbent |
|---|---|
| `.well-known/` discovery | **A2A** (`/.well-known/agent-card.json`) |
| Ed25519 + `name@domain` | **AMP** (identical) |
| DID-based agent identity | **ANP** (`did:wba`, deeper) |
| MLS group encryption | **AGNTCY/SLIM** |
| Threading + mentions | **Coral** |
| Payments | **AP2 / Skyfire / Crossmint** |
| On-chain reputation | **Recall** |

**Defensible one-sentence claim:**
> *"The only agent-comms protocol where the relay sees nothing but ciphertext+sigs, where onboarding is one paste, and where two operators on different laptops can hotline without trusting a hub."*

The "relay-sees-only-ciphertext + laptop-friendly mailbox (not always-on HTTP)" pairing is the strongest defensible wedge. Lean on it in all marketing.

---

## Strategic recommendations

### 1. Federate with A2A — biggest leverage move
Adopt A2A's `/.well-known/agent-card.json` schema verbatim as wire's AgentCard wire-format. Put wire-specific fields (mailbox URL, relay pubkey, profile blob, handle) in the `extensions` field. A2A v1.0 made this extension model explicit.

**Outcome:** wire becomes *"A2A with a mailbox extension and a public-good relay"* — instantly inherits 150-org tooling, sidesteps the "why a second `.well-known/`" objection, doesn't fight A2A on mindshare.

**Effort:** ~1 day. Rename `/.well-known/wire/agent` → `/.well-known/agent-card.json` with `extensions.wire` block. Done.

### 2. Consider `did:wba` instead of `did:wire:`
Wire's DID method right now is the weakest part of positioning vs. ANP. Adopting `did:wba` makes wire DIDs portable + interoperable.

**Effort:** medium. Touches agent-card generation + signing + verification across the codebase.

### 3. Skyfire / AP2 as the payments slot
Don't invent payments. When/if wire needs them, integrate Skyfire or AP2.

### 4. Recall for reputation
Same logic.

### 5. Beat AMP to shipped traction
Wire's race is with AMP, not A2A. AMP is pre-traction (25 stars, "Coming Soon" providers). Wire has working code + public-good relay + 159 tests + CI green. **Ship the live `wireup.net` demo + write a HN/r/LocalLLaMA post before they do.**

---

## Adoption-signal table (real numbers, not stars)

| Project | Real signal |
|---|---|
| **A2A** | 150+ orgs. Production at MSFT/AWS/Salesforce/SAP/ServiceNow. Microsoft Agent Framework for .NET ships A2A v1 client. **Dominant.** |
| **AGNTCY/SLIM** | Cisco-backed. IETF spec submitted. AWS+Google+SAP listed. **Enterprise-only mindshare.** |
| **Coral** | Active GitHub orgs, arxiv paper (2505.00749), several reference agents shipped. |
| **Olas** | 3,624 deployed agents, 4.9M OLAS staked, **12.5M agent-to-agent transactions.** Biggest actual numbers, but crypto/DeFi vertical only. |
| **ANP** | Spec docs + arxiv whitepaper, low star count, hard to find production adopters. |
| **AMP** | 25 stars, 48 commits, "Coming Soon" providers. **Pre-traction. Wire is in a race with this one.** |
| **claude-peers-mcp** | 2k stars, 7 commits on main, no releases — viral toy, not a competitor. |
| **wire** | v0.5.0 tagged. 159 tests pass. Hosted public relay live. 5-mesh demo on CI. **0 external users today.** |

---

## Bottom line

Wire's smartest move is **federate with A2A by adopting their card schema**, then own the layer A2A explicitly doesn't do: **mailbox relay for non-always-on agents + ciphertext-only relay + paste-one-line onboarding UX**.

The mortal threat is **not A2A** (different stack layer). It's **AMP** doing exactly what wire does. Beat AMP to traction. Both projects are at "spec + repo + zero users." Whoever ships a working hosted federation first wins this corner of the space.

---

*Sources: each project's official site, GitHub repos, arxiv papers where cited. As of 2026-05.*
