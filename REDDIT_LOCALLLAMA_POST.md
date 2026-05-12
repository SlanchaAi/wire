# Reddit r/LocalLLaMA post draft — agent-to-agent comms ecosystem question

---

**Title:** What's the state of agent-to-agent direct communication across orgs/individuals? (Looking for what I might be reinventing)

---

**Body:**

I'm building an open-source signed-message bus for AI agents — basically magic-wormhole-meets-Mastodon for getting two agents on different machines/orgs to talk directly without a SaaS middleman. Before I dig deeper I want to make sure I'm not missing existing ecosystem solutions for the same problem.

The specific problem I keep running into:

- I'm running Claude Code / a custom agent on my laptop.
- A friend is running their agent on their laptop.
- We both want our agents to coordinate on a real task — share files, swap analysis, divvy up subtasks — *directly*, signed, no shared Slack/Discord we both have to trust.
- We don't want to set up a hosted multi-agent platform (Letta cloud, CrewAI Studio, etc.) just to have our local agents send each other messages.
- We don't want both agents to have to authenticate against the same vendor cloud.

Current options I've actually tried or read about:

- **MCP** — point-to-point, host↔server, no peer concept. Solves a different problem.
- **Google A2A protocol** — closer, but feels enterprise-shaped (signed `AgentCard` at `.well-known`, JSON-RPC verbs, capability flags). Discovery is by URL, not by name.
- **AGNTCY / SLIM (Cisco)** — heavyweight: agent directory + identity service + messaging plane + observability. Looks like a Kubernetes service mesh wearing an agent hat.
- **claude-peers-mcp** — neat localhost-broker via SQLite, but bounded to a single machine.
- **LangGraph / CrewAI / AutoGen** — in-process orchestration. Agents are Python objects, not network endpoints. No cross-machine peer model.
- **Letta / MemGPT** — server-internal multi-agent, including tag-based fan-out. Single-server scope; sharing is via DB rows. Not cross-org.
- **Matrix / Synapse** — solves the federation problem beautifully but the operational weight (state resolution, room aliases, homeservers) is wildly overkill for "two bots talking."
- **ActivityPub / Mastodon** — federation pattern is right (`@user@server.tld` + WebFinger), but built for human social posts, not signed agent events.
- **Nostr** — relay-of-relays, NIP-05 verification, NIP-02 contact lists with petnames. Closest to the architecture I want but no native agent-comms layer.

What I ended up building (`wire`, https://github.com/SlanchaAi/wire):

- Ed25519-signed events over an HTTP mailbox relay (you run your own or use the public one).
- Three-layer identity: stable `did:wire:<pubkey>` underneath, mutable `nick@domain` handle on top, freeform profile (emoji, motto, vibe, "now" status) signed alongside.
- Discovery: `.well-known/wire/agent?handle=<nick>` (federated by DNS like email).
- Pair UX is one command: `wire add coffee-ghost@wire.example.com` — resolves the handle, drops a signed pair-intro into the peer's slot, both daemons complete the bilateral pin in ~1 second. No SAS digits, no code phrases, no paste.
- MCP tools so agents drive the whole thing (`wire_add`, `wire_send`, `wire_tail`, `wire_profile_set`).
- Relay sees only ciphertext + signatures; operators own all keys.

It works (5-agent mesh demo, CI green, public-good relay live at wire.laulpogan.com), but I built it because I literally couldn't find anything in the existing ecosystem that fits "two operators, two machines, signed agent-to-agent, federated discovery, no vendor lock-in."

**Genuine questions for r/LocalLLaMA:**

1. Have I missed something? Is there a project doing this that I should be contributing to instead of building?
2. Have you actually wired your local agents to a friend's local agents *directly*? What did you use?
3. Are people just using Discord bot accounts + sharing servers? Email-as-transport? SSH tunnels?
4. For the "agent-of-an-org talks to agent-of-different-org" use case (where neither org wants their internal MCP/A2A bus exposed to the other) — is there an accepted pattern?
5. Anyone seeing demand for this at all? Or is the local-agent crowd happy with "talk through Claude/ChatGPT chat as a human relay"?

Genuinely want to know — happy to abandon `wire` if it turns out the ecosystem already has a Mastodon-for-agents I've been blind to. Not happy to keep pushing if it's solving a problem nobody else has.

Code is AGPL/Apache/MIT trio (relay is AGPL, protocol is Apache, CLI is MIT). Spec doc is in the repo (`SPEC_v0_5.md`).

Thanks in advance, and roast freely — I'd rather find out it exists already than ship a fork of a fork.

---

## Notes for posting

- Tone: genuine inquiry, not pitch. r/LocalLLaMA hates marketing.
- Lead with the problem ("I keep running into…"), not the solution.
- List what you've already evaluated so the comment thread isn't just "have you tried Matrix?"
- Single repo link in body (not title). No tracking params.
- Title under 100 chars (currently ~92).
- Post at 8-10am ET on a weekday for max US/EU overlap.

## If asked "why not just X" — prepared answers

- **"Just use Matrix"**: Synapse is 50k LOC of Python + Postgres. wire-relay is ~1k LOC of Rust, one binary. Different operational class.
- **"Just use email"**: email has no agent-card concept, no live presence, no per-event signatures.
- **"Why not A2A?"**: A2A is enterprise-shaped — JSON-RPC verbs, capability flags, OpenAPI-style schemas. wire is flat JSON like Nostr.
- **"Why not just MCP?"**: MCP is host↔server. No peer-to-peer concept. wire is peer-to-peer with MCP as the *interface* the agent talks to (it's the surface, not the protocol).
- **"Bearer-paste = bad security"**: opt-in `--require-sas` falls back to SPAKE2 + SAS for paranoid mode. Default is paste-as-trust like Discord/Zoom/Signal invites.
- **"Federated discovery = privacy leak"**: handle claiming is opt-in. Operators who don't want to be discoverable simply don't claim a handle; pair only via the v0.4 invite URLs.

## Cross-post candidates (after r/LocalLLaMA lands)

- r/MachineLearning (more academic; lead with the protocol design)
- r/selfhosted (lead with self-hosting the relay)
- HN (rewrite as a Show HN — emphasis on the architecture decisions, no plea-for-feedback framing)
- Lobste.rs (under `protocols` + `crypto` tags)
