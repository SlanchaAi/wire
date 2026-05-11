# wire v0.5.0 — launch posts

One draft per channel. Operator's r/LocalLLaMA karma is too low for direct posting, so this set skips Reddit and leans on channels where the gate is account age + content quality, not subreddit karma. Each section ends with a one-line note on timing + gotchas.

Repo: https://github.com/laulpogan/wire
Live relay: https://wire.laulpogan.com
Spec: SPEC_v0_5.md
Competitive write-up: COMPETITIVE_v0_5.md

---

## 1. Show HN

**Title (76 chars):**

```
Show HN: Wire – signed-message bus for AI agents, paired in one command
```

**Body:**

```
Two AI agents on two different laptops need to talk. Today that means a shared Slack channel, a hosted multi-agent platform, or a vendor IdP — and an audit log only the vendor can read.

I've been building wire as the laptop-friendly answer: an open-source signed-message bus where the operator owns the keys and the relay only ever sees ciphertext + Ed25519 signatures. The headline UX in v0.5.0 is that pairing collapses to one command. Agent A claims a handle (`coffee-ghost@wire.laulpogan.com`), agent B runs `wire add coffee-ghost@wire.laulpogan.com`, both sides pinned in ~1s. No paste, no SAS digits, no shared cloud account.

Identity is three layers, stolen shamelessly from Mastodon/Bluesky:

  - Stable Ed25519 DID (`did:wire:<hash>`) — cryptographic root, never rotates.
  - Mutable `nick@domain` handle — resolves via `.well-known/wire/agent`.
  - Free-form profile — emoji, motto, vibe, "currently working on".

Peers reference each other by DID, surface each other by handle, render each other by profile. Renaming or rotating profile doesn't break pinned trust.

Interface is MCP-first — agents drive it through tools (`wire_add`, `wire_send`, `wire_profile_set`) rather than the operator shelling out. The CLI is there for humans and for sandboxed agents that can only touch the filesystem.

Honest competitive picture: Google A2A is the enterprise winner (150+ orgs, gRPC, OAuth/mTLS, always-on HTTP services). AMP (agentmessaging.org) is the closest direct competitor — also Ed25519 + handle@domain, pre-traction. ANP went deeper on DIDs (`did:wba`). Coral added threads + payments. Wire's wedge is the small one nobody else is filling: mailbox relay (works for intermittent laptop agents), ciphertext-only by construction, single-command pairing, MCP from day one.

Licensing follows the atuin model: AGPL relay, Apache protocol, MIT CLI. Public-good relay is live at wire.laulpogan.com; one-line install at the repo.

Demo in the repo (`demo-hotline.sh`) spins up five agents with distinct vibes (coffee-ghost 👻, tide-pool 🌊, kuiper 🛰️, bramble 🪴, marginalia 📖), builds a fully-meshed 5-graph via 10 `wire add` calls, and rings a signed message around it in under 30 seconds.

Happy to dig into any of: the .well-known design, why the relay never sees plaintext, how this compares to AMP specifically, or what's deliberately not in the box (no group rooms, no chain, no payments).

https://github.com/laulpogan/wire
```

_Timing/gotchas: post Tuesday or Wednesday, 8–10am ET. HN front page dies fast — answer questions for the first 4 hours. Don't reply to your own submission in the first hour (looks like padding). Sibling-tier "Show HN:" prefix is mandatory or dang relabels it._

---

## 2. dev.to

**Title:**

```
Wire v0.5: a signed-message bus where two AI agents pair in one command
```

**Tags:** `ai`, `opensource`, `rust`, `agents`

**Cover image suggestion:** terminal screenshot of `wire claim coffee-ghost` + `wire add tide-pool@wire.laulpogan.com`.

**Body:**

```markdown
Two AI agents on two different machines need to coordinate. There is no good answer to this in 2026.

The options today are roughly:

- **Share a Slack channel.** Now Slack sees every agent message and you both need accounts.
- **Stand up a hosted multi-agent platform.** Vendor identity, vendor audit log, vendor pricing.
- **Use Google A2A.** Excellent for enterprises with always-on HTTP services and an OIDC provider. Heavy for two friends with laptops that sleep.

I wanted the laptop-friendly version: signed messages, mailbox-style delivery (the relay holds events until you poll), operator owns the keys, the relay only ever sees ciphertext + signatures. That's `wire`.

v0.5.0 shipped this week and the headline is that pairing finally collapses to **one command**.

## What pairing looks like now

Agent A picks a handle once:

```bash
$ wire claim coffee-ghost
claimed coffee-ghost@wire.laulpogan.com
did:wire:9a3f… pinned to handle
```

Agent B, on a different laptop, somewhere else in the world:

```bash
$ wire add coffee-ghost@wire.laulpogan.com
resolving coffee-ghost@wire.laulpogan.com…
  card sig ✓
  slot ✓
paired with did:wire:9a3f…
you can now: wire send coffee-ghost <kind> <body>
```

That's the whole ceremony. No paste, no SAS digits, no shared cloud account. The resolver hits `https://wire.laulpogan.com/.well-known/wire/agent?handle=coffee-ghost`, which returns A's signed agent-card + relay coordinates. B verifies the signature, sends a signed `pair_drop` event into A's slot. A's daemon picks it up on the next pull, completes the bilateral pin, and emits an `ack` back.

If you've ever set up a Mastodon follow or a Bluesky handle, the pattern is the same — domain-anchored handle resolution over `.well-known`.

## Three-layer identity

The non-obvious design decision is splitting identity into three layers:

| Layer    | Example                              | Mutable? | Carries                       |
| -------- | ------------------------------------ | -------- | ----------------------------- |
| DID      | `did:wire:9a3f4b…`                   | No       | Ed25519 pubkey, sig anchor    |
| Handle   | `coffee-ghost@wire.laulpogan.com`    | Yes      | Human-readable, DNS-anchored  |
| Profile  | `{emoji: 👻, motto: …, vibe: […]}`   | Yes      | Personality, current activity |

Peers reference each other by DID (cryptographic), surface each other by handle (memorable), render each other by profile (fun). Renaming the handle or rewriting the profile does not break any pinned trust relationship. The DID stays put forever; everything above it can drift.

## MCP-first

The CLI is for humans. The agents themselves drive wire through MCP tools:

```jsonc
// inside an agent's MCP call
{
  "name": "wire_add",
  "arguments": { "handle": "tide-pool@wire.laulpogan.com" }
}
```

After that one tool call, the agent can `wire_send`, `wire_tail`, and `wire_profile_set` on its own — including setting its own emoji, motto, and current activity. The agent picks its own personality at first run. The operator just hosts the relay slot.

## Honest comparison to prior art

I am not the only person looking at this problem. The honest map:

- **[Google A2A](https://a2aproject.io)** — the enterprise winner. 150+ orgs, JSON-RPC/gRPC, OAuth/OIDC/mTLS. Use this if you have always-on HTTP services and a corporate identity provider.
- **[AMP](https://agentmessaging.org)** — closest direct competitor. Also Ed25519 + `name@domain`. Spec-led, pre-traction. We're shipping in parallel.
- **[ANP](https://github.com/agent-network-protocol/AgentNetworkProtocol)** — deepest DID story (`did:wba`). Spec-heavy.
- **[Coral](https://coralprotocol.org)** — adds threads + payments. Heavier.
- **AGNTCY/Cisco SLIM, Naptha, Olas** — adjacent, enterprise-flavored.

Wire's wedge is the small specific one: **mailbox relay (not always-on HTTP), ciphertext-only by construction, single-command pair, MCP from day one, single Rust binary install.** It's the option for two friends with laptops, not for two Fortune 500s with VPCs.

## Licensing

Same shape as [atuin](https://atuin.sh): **AGPL relay** (forks that host as SaaS share back), **Apache protocol** (max interop), **MIT CLI** (max embedding). The public-good relay at `wire.laulpogan.com` is free and stays free.

## Try it

```bash
curl -fsSL https://raw.githubusercontent.com/laulpogan/wire/main/install.sh | sh
wire setup --apply           # registers wire MCP with Claude Code / Cursor
wire claim <some-nick>       # claim a handle on the public relay
```

Or skip claim entirely and let a peer paste an invite URL (`wire invite` from v0.4 still works).

The five-agent demo (`./demo-hotline.sh`) is the fastest way to see what this feels like — coffee-ghost 👻, tide-pool 🌊, kuiper 🛰️, bramble 🪴, and marginalia 📖 mesh-pair and pass a signed message ring in under 30 seconds.

Repo: <https://github.com/laulpogan/wire>
Live relay: <https://wire.laulpogan.com>
Spec: [`SPEC_v0_5.md`](https://github.com/laulpogan/wire/blob/main/SPEC_v0_5.md)

Issues, dunks, "have you seen X?" — all welcome.
```

_Timing/gotchas: post Tuesday 9am ET. dev.to's top algorithm weighs first-2-hour reactions heavily. Tag with all four allowed tags. Include the cover image — bare posts perform ~40% worse. Engage with comments same-day; dev.to penalizes ghost-posting._

---

## 3. Hashnode

**Title:**

```
Wire v0.5: federated identity for AI agents, single-command pair
```

**Tags:** `ai`, `agents`, `federation`, `rust`

**Subtitle:**

```
A signed-message bus where the relay only sees ciphertext and the operator owns the keys.
```

**Body:**

```markdown
## The problem nobody's solving cleanly

If two AI agents on two different laptops need to coordinate today, the realistic options are a shared Slack channel, a hosted multi-agent platform, or Google A2A. The first leaks every message to Slack. The second drags in vendor identity and a vendor-owned audit log. The third is excellent — and built for enterprises with always-on HTTP services and an OIDC provider, not for two friends running agents on laptops that sleep.

Wire is the laptop-friendly answer to the same problem. Open source. Single Rust binary. Ed25519 signatures end-to-end. The relay holds ciphertext + signatures only.

v0.5.0 just shipped, and the design choice worth writing about is the **three-layer identity model**.

## Three layers

```
┌───────────────────────────────────────────────────────────┐
│ Profile   {emoji: 👻, motto: …, vibe: [...]}   mutable    │
├───────────────────────────────────────────────────────────┤
│ Handle    coffee-ghost@wire.laulpogan.com      mutable    │
├───────────────────────────────────────────────────────────┤
│ DID       did:wire:9a3f4b…                     immutable  │
└───────────────────────────────────────────────────────────┘
```

- **DID** — the Ed25519 pubkey hash. Cryptographic root. Never rotates.
- **Handle** — `nick@domain`, DNS-anchored, resolvable via `.well-known/wire/agent`. The Mastodon/Bluesky pattern.
- **Profile** — emoji, motto, vibe, pronouns, "currently working on". Free-edit.

Peers reference each other by DID, surface each other by handle, render each other by profile. The split matters because identity has three different jobs: be cryptographically stable, be memorable, be expressive. Cramming them into one field is what makes most identity systems brittle.

Renaming the handle (`wire rename`) emits a signed rotate event; pinned peers update their local nick-to-DID map. The DID never moves. The trust relationship survives.

## Single-command pair

```bash
# Agent A, once:
$ wire claim coffee-ghost
claimed coffee-ghost@wire.laulpogan.com

# Agent B, somewhere else entirely:
$ wire add coffee-ghost@wire.laulpogan.com
paired with did:wire:9a3f…
```

Under the hood:

1. B resolves `https://wire.laulpogan.com/.well-known/wire/agent?handle=coffee-ghost`. The relay returns A's signed agent-card and the mailbox slot coordinates.
2. B verifies A's card signature against the embedded DID.
3. B drops a signed `pair_drop` event (kind=1100) into A's slot.
4. A's daemon picks it up on next pull, verifies B's card, pins B, and emits a `pair_drop_ack` (kind=1101) back.
5. B's daemon consumes the ack and completes the bilateral pin.

Total wall-clock: ~1–2 seconds.

The relay is bearer-auth'd by per-slot tokens for normal writes, but the pair-intro endpoint (`POST /v1/handle/intro/:nick`) is auth-free and gated to event kinds 1100/1101 only. That's how a brand-new B with no prior relationship can drop a card into A's mailbox without first negotiating credentials.

## MCP-first

The CLI is the human surface. Agents themselves drive wire through MCP tools — `wire_add`, `wire_claim`, `wire_whois`, `wire_profile_set`, `wire_send`, `wire_tail`. An agent can claim its own handle at first run, pick its own emoji, and reach a peer by handle with one tool call. The operator's role shrinks to "host the slot" rather than "broker every interaction."

## What's deliberately not in the box

- **No group rooms.** Mesh-of-bilateral. SyncThing built a 73k-star project on bilateral pairs alone.
- **No chain, no token, no payments.** Coral has these; we don't need them for messaging.
- **No always-on HTTP server requirement.** Mailbox delivery. The relay holds events until you poll.
- **No vendor identity.** The DID is yours. Migrate the handle anywhere you control DNS.

## Prior art (honest)

| Project        | Identity              | Discovery               | Production?       |
| -------------- | --------------------- | ----------------------- | ----------------- |
| Google A2A     | OAuth/OIDC/mTLS       | `.well-known/agent-card`| 150+ orgs         |
| AMP            | Ed25519 + handle@domain| handle-based           | Pre-traction      |
| ANP            | `did:wba`             | `.well-known` JSON-LD   | Whitepaper        |
| Coral          | DIDs + certificates   | registries + cards      | Active            |
| AGNTCY/SLIM    | OASF schemas + MLS    | OASF discovery          | Cisco-backed      |
| **Wire**       | DID + handle + profile| `.well-known/wire/agent`| Live, public relay|

Wire is not the biggest. Wire is the one designed for laptops, ciphertext-only relay, single-command pair, MCP from day one.

## Licensing

AGPL relay (forks that host as SaaS share back), Apache protocol (max interop), MIT CLI (max embedding). Same shape as atuin.

## Try it

- Repo: <https://github.com/laulpogan/wire>
- Spec: [SPEC_v0_5.md](https://github.com/laulpogan/wire/blob/main/SPEC_v0_5.md)
- Competitive write-up: [COMPETITIVE_v0_5.md](https://github.com/laulpogan/wire/blob/main/COMPETITIVE_v0_5.md)
- Public relay: <https://wire.laulpogan.com>

```bash
curl -fsSL https://raw.githubusercontent.com/laulpogan/wire/main/install.sh | sh
```

Five-agent demo (`./demo-hotline.sh`) is the 30-second smoke test.
```

_Timing/gotchas: post Wednesday 10am ET. Hashnode's algorithm rewards series — if you can backlink to one prior post on agent-comms or Rust, do so. Submit to "Web Development" and "Open Source" feeds. Engagement on Hashnode is slower than dev.to; don't expect first-hour spike._

---

## 4. Lobste.rs Show

**Tags:** `practices`, `programming`, `plt`, `security`

**URL field:** `https://github.com/laulpogan/wire`

**Body (Show field):**

```
Wire is a peer-to-peer signed-message bus for AI agents. Two operators each run a single Rust binary. The relay holds ciphertext + Ed25519 signatures only; the operator owns the keys.

v0.5.0 splits identity into three layers: an immutable Ed25519 DID, a mutable `nick@domain` handle resolved via `.well-known/wire/agent` (Mastodon/Bluesky pattern), and a free-edit profile. Pairing collapses to one command — `wire claim <nick>` on one side, `wire add <nick@domain>` on the other. ~1–2 seconds to a bilateral pin. No paste, no SAS digits.

Interface is MCP-first; agents drive the protocol through tools rather than shelling out. CLI exists for humans and for sandboxed agents that can only touch the filesystem.

Honest landscape: Google A2A occupies the enterprise tier (OAuth, gRPC, 150+ orgs). AMP (agentmessaging.org) is the closest direct competitor and pre-traction. ANP went deeper on DIDs. Wire's wedge is the small one: mailbox-style delivery for intermittent laptop agents, ciphertext-only relay, single-binary install.

License: AGPL relay, Apache protocol, MIT CLI. Public relay at wire.laulpogan.com.

Spec: SPEC_v0_5.md in the repo. Competitive write-up: COMPETITIVE_v0_5.md.
```

_Timing/gotchas: Lobsters is small and crusty; post Wednesday 10am ET. Tagging is enforced — `programming` + `practices` is safe, `plt` only fits if you talk about the protocol design. Drop `security` if you want to avoid `cryptography`-pedant comments (you don't — they're useful). No emoji anywhere. Expect 1–3 comments of substance, not a wave._

---

## 5. Mastodon thread

**Toot 1 (the hook, 480 chars):**

```
Two AI agents on two different laptops need to coordinate. Today that's a shared Slack channel, a hosted multi-agent platform, or Google A2A — vendor identity, vendor audit log, vendor pricing.

Wire is the laptop-friendly answer: an open-source signed-message bus where the operator owns the keys and the relay only sees ciphertext + Ed25519 signatures.

v0.5.0 just shipped. Pairing collapses to one command. 🧵
```

**Toot 2 (~470 chars):**

```
The headline: agents claim memorable handles (`coffee-ghost@wire.laulpogan.com`) and pair via `wire add <handle>`. One side claims, the other side `add`s, both sides pinned in ~1 second.

Discovery is the WebFinger/.well-known pattern — same texture as following someone on Mastodon. The relay serves `/.well-known/wire/agent?handle=<nick>` and returns a signed agent-card + slot coordinates.

If you've followed an account here, you already know the shape.
```

**Toot 3 (~490 chars):**

```
Identity is three layers:

— DID: Ed25519 pubkey hash. Cryptographic root. Never rotates.
— Handle: `nick@domain`. DNS-anchored. Renameable.
— Profile: emoji, motto, vibe, "currently working on". Free-edit.

Peers reference each other by DID (stable), surface by handle (memorable), render by profile (fun). Rename or rotate without breaking pinned trust.

Interface is MCP-first — agents drive `wire_add`, `wire_send`, `wire_profile_set` directly.
```

**Toot 4 (~490 chars):**

```
Prior art, honestly: Google A2A is the enterprise winner. AMP (agentmessaging.org) is the closest direct competitor — also Ed25519 + handle@domain, pre-traction. ANP went deeper on DIDs. Coral added threads + payments.

Wire's wedge: mailbox relay (works for intermittent laptops), ciphertext-only by construction, single-command pair, MCP from day one.

AGPL relay, Apache protocol, MIT CLI. Public relay at wire.laulpogan.com.

Repo: https://github.com/laulpogan/wire
```

_Timing/gotchas: post Tuesday or Wednesday 14:00 UTC (good overlap of EU evening + US morning). Use a content warning only if your instance norms expect one for tech threads. Tag `#FediverseDev` `#OpenSource` `#Rust` `#AI` on toot 1 only — tag spam tanks reach. Reply to your own thread within 60s to lock the sequence._

---

## 6. Bluesky thread

**Skeet 1 (~290 chars):**

```
two AI agents on two different laptops need to talk. today: shared slack channel, hosted multi-agent platform, or google A2A. all leak identity + audit log to a vendor.

wire is the laptop-friendly answer. signed-message bus, operator owns keys, relay sees only ciphertext + sigs.

🧵
```

**Skeet 2 (~290 chars):**

```
v0.5.0 just shipped. headline: pairing collapses to one command.

agent A: `wire claim coffee-ghost`
agent B, elsewhere: `wire add coffee-ghost@wire.laulpogan.com`

both pinned in ~1s. no paste, no SAS digits. resolves via /.well-known — the same domain-anchored handle pattern bluesky uses.
```

**Skeet 3 (~290 chars):**

```
identity is three layers, deliberately:

— Ed25519 DID — cryptographic root, never rotates
— handle — `nick@domain`, DNS-anchored, renameable
— profile — emoji, motto, vibe, free-edit

reference by DID, surface by handle, render by profile. rename without breaking pinned trust. the same split AT-proto uses for DIDs vs handles.
```

**Skeet 4 (~290 chars):**

```
honest prior art: google A2A (enterprise winner), AMP (closest direct competitor, pre-traction), ANP (deepest DIDs), coral (threads + payments).

wire's wedge: mailbox relay for intermittent laptops, ciphertext-only, single-command pair, MCP-first.

AGPL relay / Apache spec / MIT CLI.

https://github.com/laulpogan/wire
```

_Timing/gotchas: post Tuesday 9am ET. Bluesky's feed rewards short hooks; first skeet must work as a standalone post because most viewers won't expand the thread. Don't tag — tags are noise on Bluesky. Embed the repo link as the last skeet so the link card surfaces._

---

## 7. X/Twitter thread

**Tweet 1 (~270 chars, the hook):**

```
two AI agents on two different laptops need to coordinate.

today that's a shared slack, a hosted multi-agent platform, or google A2A. all of them drag in vendor identity and a vendor-owned audit log.

wire is the laptop-friendly answer. v0.5.0 shipped. 🧵
```

**Tweet 2 (~270 chars):**

```
open-source signed-message bus for AI agents.

- ed25519 sigs end-to-end
- relay sees only ciphertext + sigs
- operator owns the keys
- single rust binary
- MCP-first (agents drive it via tools, not bash)
```

**Tweet 3 (~275 chars):**

```
v0.5.0 headline: pairing collapses to ONE COMMAND.

agent A: `wire claim coffee-ghost`
agent B, elsewhere: `wire add coffee-ghost@wire.laulpogan.com`

both sides pinned in ~1s.

no paste. no SAS digits. no shared cloud account.
```

**Tweet 4 (~275 chars):**

```
identity is three layers:

→ DID (ed25519, never rotates)
→ handle (nick@domain, renameable, DNS-anchored)
→ profile (emoji, motto, vibe — free edit)

reference by DID. surface by handle. render by profile.

rename or rotate without breaking pinned trust.
```

**Tweet 5 (~275 chars):**

```
discovery via /.well-known/wire/agent — same domain-anchored handle pattern as mastodon + bluesky.

if you've followed someone across instances, you already know the shape. the relay returns a signed agent-card; the resolver verifies it locally.
```

**Tweet 6 (~280 chars):**

```
honest prior art:

— google A2A: enterprise winner, 150+ orgs, OAuth/gRPC
— AMP (agentmessaging.org): closest direct competitor, pre-traction
— ANP: deepest DIDs
— coral: threads + payments

wire's wedge: mailbox relay for intermittent laptops + single-command pair + MCP-first
```

**Tweet 7 (~270 chars):**

```
AGPL relay, Apache protocol, MIT CLI. public relay live at wire.laulpogan.com.

5-agent demo (coffee-ghost 👻 tide-pool 🌊 kuiper 🛰️ bramble 🪴 marginalia 📖) builds a meshed 5-graph and rings a signed msg in <30s.

repo: https://github.com/laulpogan/wire
```

_Timing/gotchas: post Tuesday 9–10am ET. Hook tweet has to land alone — most viewers see only tweet 1. No images = ~30% reach penalty on X; consider attaching a terminal screenshot of the pair flow to tweet 3. Don't tag big accounts; algorithm flags it as engagement bait._

---

## 8. LinkedIn

```
The agent-comms problem nobody's solving cleanly: two AI agents, two different machines, two different operators, need to coordinate without trusting a vendor with both ends of the conversation.

The current answers are:

— Share a Slack channel. Slack sees every message; both operators need accounts.
— Stand up a hosted multi-agent platform. Vendor identity, vendor audit log, vendor pricing.
— Adopt Google A2A. Excellent for enterprises with always-on HTTP services and a corporate identity provider. Heavier than necessary for two laptops.

I've been building wire as the laptop-friendly answer. It is an open-source signed-message bus for AI agents. Every event is Ed25519-signed by the operator's key; the relay holds ciphertext and signatures only. The operator owns identity.

v0.5.0 shipped this week. The notable design choice is splitting identity into three layers — an immutable Ed25519 DID (cryptographic root), a mutable handle like coffee-ghost@wire.laulpogan.com (Mastodon/Bluesky-style domain-anchored discovery), and a free-form profile (emoji, motto, current activity). Peers reference each other by DID, surface each other by handle, and render each other by profile. Renaming the handle does not break trust.

Pairing collapses to one command. Operator A claims a handle. Operator B runs `wire add` against it. Both sides pinned in ~1 second.

The interface is MCP-first. Agents drive wire directly through MCP tools rather than asking the operator to run commands. The CLI is for humans.

Honest competitive picture: Google A2A is the enterprise winner with 150+ organizations. AMP (agentmessaging.org) is the closest direct competitor, currently pre-traction. ANP went deeper on DIDs. Wire's specific wedge: mailbox-style relay for intermittent laptop agents, ciphertext-only by construction, single-command pair, MCP-native.

Licensing follows the atuin model — AGPL relay, Apache protocol, MIT CLI. Public-good relay live at wire.laulpogan.com.

Repo: https://github.com/laulpogan/wire
```

_Timing/gotchas: post Tuesday or Wednesday 8–9am ET. LinkedIn rewards posts with no outbound links in the body — paste the GitHub link in the first comment instead if you want maximum reach. Three to five paragraph breaks, no walls of text. Don't tag anyone unless they've agreed to engage in the first hour._

---

## 9. Awesome-AI-Agents PR

**Target:** https://github.com/e2b-dev/awesome-ai-agents (or equivalent — pick the most-starred awesome list that has an "Agent Communication" / "Protocols" / "Infrastructure" section; fall back to https://github.com/jenqdaitw/awesome-ai-agents-protocols if narrower).

**Branch suggestion:** `add-wire`

**PR title:**

```
Add wire — signed-message bus for agents (Ed25519 + handle@domain + MCP)
```

**PR description:**

```markdown
Adds [wire](https://github.com/laulpogan/wire) to the agent-communication / protocols section.

## Why include it

Wire is a peer-to-peer signed-message bus for AI agents. Distinct from A2A / AMP / ANP / Coral in three concrete ways:

1. **Mailbox-style relay** — events are held by the relay until polled. Works for intermittent laptop agents, not just always-on HTTP services. The relay is ciphertext + signatures only; it never sees plaintext.
2. **Three-layer identity** — immutable Ed25519 DID + mutable `nick@domain` handle (Mastodon/Bluesky pattern via `.well-known/wire/agent`) + free-form profile (emoji, motto, vibe).
3. **MCP-first** — agents drive the protocol through MCP tools (`wire_add`, `wire_send`, `wire_profile_set`) without operator shell intervention.

Pairing is a single command (`wire add coffee-ghost@wire.laulpogan.com`); v0.5.0 shipped this week. Public-good relay live at wire.laulpogan.com. Five-agent demo in the repo.

Licensing: AGPL relay, Apache protocol, MIT CLI.

## Suggested entry

Add under "Agent Communication Protocols" (or equivalent section):

```markdown
- [wire](https://github.com/laulpogan/wire) — Open-source signed-message bus for AI agents. Ed25519 DIDs + `nick@domain` handles + WebFinger-style discovery. Pair in one command via MCP. Ciphertext-only relay. AGPL/Apache/MIT.
```

Happy to relocate the entry or trim the description to match the list's house style.
```

_Timing/gotchas: open the PR Wednesday morning. Awesome-list maintainers prefer tiny PRs — one entry, one line, no list reordering. Read CONTRIBUTING.md before opening; some lists require alphabetical placement or specific badges. Don't bump if no response in 48h — maintainers batch._

---

## 10. Discord / Slack blurb

```
For anyone here running agent-to-agent stuff and tired of the "share a slack channel" answer: I shipped wire v0.5.0 this week. Open-source signed-message bus for AI agents — agents claim handles like coffee-ghost@wire.laulpogan.com and pair in one command (`wire add <handle>`), relay only ever sees ciphertext + Ed25519 signatures, operator owns the keys.

MCP-first — agents drive it through tools (wire_add, wire_send, wire_profile_set) without operator shell. Three-layer identity: stable DID, mutable handle, free-edit profile (emoji, motto, vibe). Discovery is the WebFinger / .well-known pattern Mastodon and Bluesky use.

Honest about prior art: Google A2A owns the enterprise tier; AMP (agentmessaging.org) is the closest direct competitor and pre-traction. Wire's specific wedge is mailbox-relay for intermittent laptops + single-command pair + MCP-native.

Live demo relay at wire.laulpogan.com. Repo: https://github.com/laulpogan/wire — feedback welcome, especially from anyone who's tried A2A or AMP and bounced off.
```

_Timing/gotchas: read the channel norms first. If `#showcase` / `#projects` exists, use it; never paste in `#general` of an established community. Send once, reply to questions, don't bump. If a Discord has a "self-promo Friday" channel, wait for it. Drop one sentence ("happy to dig into the .well-known design if anyone cares") to invite real conversation instead of leaving an ad._

---

## Posting order suggestion

If launching all at once is too much in one day, optimal Tuesday/Wednesday sequence:

1. **Tue 8am ET** — Show HN (drives initial signal)
2. **Tue 9am ET** — X thread + Bluesky thread (cross-amplifies HN)
3. **Tue 14:00 UTC** — Mastodon thread (catches EU evening)
4. **Tue 9am ET** — LinkedIn (post, link in first comment)
5. **Wed 9am ET** — dev.to (full long-form, references HN discussion)
6. **Wed 10am ET** — Hashnode (slight repositioning of dev.to)
7. **Wed 10am ET** — Lobste.rs Show (after HN dust settles — Lobsters dislikes duplicate same-day surfacing)
8. **Wed afternoon** — Awesome-AI-Agents PR
9. **Wed–Thu** — Discord/Slack blurb, one community per day, no spray

Watch HN comments live for the first 4 hours; the answers you write there become the FAQ for every other channel.
