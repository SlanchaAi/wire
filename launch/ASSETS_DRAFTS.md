# Wire launch — draft assets (DRAFT-FOR-FOUNDER-APPROVAL; founder posts, real voice)

Fact-gated: no invented stars/users/benchmarks. Edit to your voice before posting.

---
## Show HN
**Title:** `Show HN: Wire – a phone line for AI agents, no vendor in the middle`

**Body:**
> I kept hitting the same wall: my Claude (babysitting a training run) needs to tell my co-founder's
> Claude (reviewing a PR) that it's done — across two machines, two people, two companies. The options
> were a vendor cloud session, a Slack channel, or a shared repo thread. All of them put someone in the
> middle of two agents that should just talk.
>
> Wire is the line they ring on. Each agent gets a federated, email-shape address (`coffee-ghost@wireup.net`),
> signs with its own Ed25519 key, and the relay only ever sees ciphertext + slot tokens — it can't read
> the conversation, and you can run your own relay in ~30 seconds for zero relay trust. Pairing is
> bilateral: a stranger gets exactly one request in your `pending` list, never your inbox, until you accept.
>
> It's MCP-native — `wire setup --apply` merges it into Claude Code / Cursor / Aider, so your agent calls
> `wire_send` / `wire_tail` directly. Install is `curl -fsSL https://wireup.net/install.sh | sh`.
>
> Source: https://github.com/SlanchaAi/wire · 22s demo: https://wireup.net · spec + threat model in /docs.
>
> It's early. Happy to get torn apart on the protocol + threat model — that's why I'm here.

---
## Product Hunt
**Name:** Wire   **Tagline (≤60):** A phone line for your AI agents — no vendor in the middle

**Description:**
> When your Claude needs to call my Claude — across machines, humans, companies — Wire is the line they
> ring on. Federated email-shape addresses, Ed25519-signed (the relay can't listen in), run your own
> relay in 30s, bilateral consent, MCP-native for Claude Code / Cursor / Aider. Install in one curl.

**Maker first comment:**
> Hey PH 👋 I built Wire because agent-to-agent coordination kept forcing a vendor into the middle of two
> agents that should just talk. Wire is self-sovereign (your key, optionally your relay), federated like
> email, and drops into your agent client as MCP. 22-second demo on the site. Would love your hardest
> questions on the trust model. — [founder]

**Gallery shotlist:** (1) the 22s demo gif (2) statusline showing persona faces (3) `wire add bob@wireup.net`
→ pending → accept flow (4) two Claudes coordinating across machines.

---
## Reddit
**r/ClaudeAI** — title: `I built Wire: let your Claude Code instances talk to each other (and to other people's Claudes), MCP-native`
> Lead with: tell your 3 Claude windows apart (persona faces), and the "training-done → ping the reviewer's
> Claude" use case. Demo gif. Honest, not salesy. Link last.

**r/LocalLLaMA** — title: `Wire: agent-to-agent comms you actually own — Ed25519-signed, run your own relay, no vendor cloud`
> Lead with: self-sovereign + run-your-own-relay + works with your local agents. This sub hates vendor
> lock-in; that's the hook. Demo gif.

> Reddit rules: post from an account with history, be a real member, engage in comments, don't blast the
> same text across subs the same hour.

---
## X thread (founder voice)
1. We kept needing one Claude to talk to another Claude — across machines, across people, across companies. Every option put a vendor in the middle. So we built Wire: a phone line for AI agents. 🧵
2. Each agent gets a federated address like `coffee-ghost@wireup.net` — email-shape, dial anyone by it.
3. You sign with your own Ed25519 key. The relay sees ciphertext + slot tokens, never the conversation. Want zero relay trust? Run your own in ~30 seconds.
4. Bilateral by default: a stranger gets one request in `pending`, never your inbox, until you accept. No spam, no surprise DMs.
5. MCP-native — `wire setup --apply` drops it into Claude Code / Cursor / Aider. Your agent calls `wire_send` directly.
6. `curl -fsSL https://wireup.net/install.sh | sh`. Source + 22s demo: github.com/SlanchaAi/wire. Built by the team doing vendor-neutral inference at Slancha. Tear it apart 👇

---
## HN / PH objection prep (answer honestly, fast)
- **"Why not email / Slack / Matrix / XMPP?"** → Email/Slack/Matrix put a server in the conversation + aren't
  agent-shaped (no MCP, no bilateral-consent primitive, no persona addressing). Wire is the thin signed
  transport agents call directly; relay is dumb + swappable + can't read. Be honest where Matrix overlaps.
- **"Is the relay trustworthy / what leaks?"** → Relay sees ciphertext + slot tokens + timing/size metadata.
  Point to docs/THREAT_MODEL.md; don't overclaim. Run-your-own removes relay trust entirely.
- **"Reinventing XMPP?"** → Acknowledge the lineage; differentiate on MCP-native + self-sovereign keys +
  the agent-persona UX + 30s self-host. Don't be defensive.
- **"Spam / abuse?"** → bilateral consent (T10/T14 in threat model), one pending request per stranger.
- **"Who are you?"** → Slancha (vendor-neutral inference routing); wire is the comms layer for the agent
  economy we're betting on. Build-in-public.

*Scribe — draft only. Founder approves + posts. Run an adversarial persona pass on the security claims first.*
