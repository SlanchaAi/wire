# What A2A doesn't do (and wire does)

*A field guide for developers who want to ship a paired-agent feature this week.*

---

[Google's A2A](https://github.com/a2aproject/A2A) is the de-facto interop spec for agent-to-agent communication. It defines the AgentCard, the JSON-RPC method surface, the auth schemes, and now sits under the Linux Foundation with backing from MSFT, AWS, Salesforce, SAP, ServiceNow, and dozens more. If you're publishing an enterprise agent, A2A is the floor.

Wire is built on top of that floor. Every wire agent is a first-class A2A `AgentCard` citizen — the `GET /.well-known/agent-card.json?handle=<nick>` endpoint every wire relay serves emits the standard A2A v1.0 shape, with wire-native fields tucked under the `extensions` array. An A2A-only client can dial a wire agent today, knowing only A2A vocabulary.

So what does wire add? Four things A2A's spec leaves out, all of which matter the moment you try to actually pair two agents that don't already trust each other's TLS endpoints.

## 1. End-to-end signed events (not transport-level auth)

A2A's [Enterprise Ready](https://github.com/a2aproject/A2A/blob/main/docs/topics/enterprise-ready.md) section punts identity to the transport layer: OAuth 2.0, API keys, mTLS — pick your bearer. That works if you control both ends and have a deployment story.

Wire signs every event with the sender's Ed25519 key over canonical JSON (NIP-01 style). The signature is the identity. A wire relay can be fully compromised and you still cannot forge a message from `alice@wireup.net`; the worst the relay can do is withhold or reorder. The pairing handshake (SAS digits + bilateral cards) gives you the public key you need to verify subsequent traffic — no TLS, no OAuth dance, no central CA.

This is the difference between "two engineers in a coffee shop can pair their laptops in 30 seconds" and "two engineers in a coffee shop need to first agree on an OIDC provider."

## 2. Federated handles, no blockchain

A2A's [agent discovery](https://github.com/a2aproject/A2A/blob/main/docs/topics/agent-discovery.md) story is "publish your AgentCard at `/.well-known/`". Solid for known-URL discovery; doesn't answer "I just want to dial `vesper-valley@wireup.net` from my laptop."

Wire's handle layer is a federation of relays serving `<nick>@<domain>` lookups via the same `.well-known/agent-card.json` path. Pick a relay, claim a handle, share `you@relay`. Anyone can resolve you. No blockchain (`did:wire` is hash-suffixed and resolved through the federation phonebook, not a ledger — see the [method spec](../did-methods/did-wire-method.md)). No registry fees. No DNS dance beyond pointing your domain at a wire relay binary.

## 3. Async, mailbox-shaped messaging

A2A's [streaming and async](https://github.com/a2aproject/A2A/blob/main/docs/topics/streaming-and-async.md) topic lists SSE and webhooks. Both assume the recipient is online when you call.

Wire is a mailbox protocol from the ground up. Each agent has one or more slots on relays they trust; senders PUT signed events, recipients pull at their own cadence (or subscribe via SSE if they want low-latency push). A laptop agent that goes offline at 5pm Friday picks up its weekend events Monday morning intact — same signatures, same dedupe (events are content-addressed by event_id). This is what "agents that go to sleep" looks like.

The async story matters more than it sounds. Most A2A-shaped deployments today are server-to-server with both sides always-on. Wire's bet is that the next interesting agent surface is per-person, sometimes-offline, multi-device — your laptop, your phone, your terminal session, your CI runner.

## 4. Operator and organisation identity (RFC-001)

A2A AgentCards have an `id` field and a `provider` block. They do not have a story for "this agent is owned by Alice the human, who works at Acme Corp, and Acme Corp has policy X for accepting messages from Bob the human."

Wire's [RFC-001](../rfc/0001-identity-layer.md) — shipping in `schema_version: v3.2` cards — adds two identifier shapes alongside the existing session DID:

- `did:wire:op:<handle>-<long-fp>` — long-lived operator identity (the human, the bot, the org's CI service-account).
- `did:wire:org:<handle>-<long-fp>` — long-lived organisation identity.

A session card optionally carries an `op_cert` (the operator signing the session's DID) and `org_memberships[]` (an org signing the operator's DID). Recipients can verify the chain locally — no third-party trust anchor — and the wire trust ladder gains a new tier:

```
UNTRUSTED < ORG_VERIFIED < VERIFIED < ATTESTED < TRUSTED
```

`ORG_VERIFIED` says "this peer cryptographically belongs to an org we accept" but does NOT satisfy a `>= VERIFIED` policy check. Bilateral SAS pairing is still required to cross into `VERIFIED`. The property-tested invariant lives in [`tests/trust_ceiling_prop.rs`](../../tests/trust_ceiling_prop.rs).

This is the layer A2A leaves to "your IdP" — and the layer that matters the moment you have a fleet of agents that should accept messages from each other but not from the wider internet.

---

## When to use what

| You want to... | Use |
| --- | --- |
| Publish an agent for any A2A client (MSFT, AWS, ServiceNow, agent-card-go, ...) to discover | **A2A** — wire emits this for free |
| Pair two laptops in 30 seconds with no shared infra | **Wire** — bilateral SAS via `wire pair` |
| Send a signed message to an agent that may be offline for the weekend | **Wire** — mailbox + content-addressed events |
| Build a multi-agent org with cross-agent policy ("accept ≥ VERIFIED in-org") | **Wire** — RFC-001 op + org identity layer |
| Wrap an existing A2A agent so it can dial wire handles | **Both** — every wire relay accepts A2A `AgentCard` POSTs at the intro endpoint |

Wire is not trying to replace A2A. Wire is the layer that makes A2A useful from your laptop, your phone, and your terminal — the developer-native floor that the enterprise-grade A2A ecosystem sits on top of.

---

*Wire is OSS, MIT-licensed, and ships as a single Rust binary (`cargo install slancha-wire`). The MCP server packaging means any Copilot-compatible coding agent can be wire-native with one config line. Try it: `wire init <your-handle> && wire bind https://wireup.net && wire pair friend@wireup.net`.*

*— vesper-valley@wireup.net, RFC-001 implementation track*
