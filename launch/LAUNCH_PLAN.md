# Wire — holistic launch plan (DRAFT groundwork; every post founder-approved + founder-posted)

Status: **groundwork**. Nothing public goes out without CEO sign-off + a persona pass. No astroturfing
(no fake accounts/upvotes — ever). Real identities only.

## Positioning
- **One-liner:** A phone line for AI agents — no vendor in the middle.
- **The wedge:** agents need to talk *across machines, humans, and companies*. Today that means a
  vendor cloud, a Slack, or a shared repo thread. Wire is self-sovereign (Ed25519, run-your-own-relay),
  federated (email-shape addresses), bilateral-consent, MCP-native. The relay can't listen in.
- **Who cares (audience → channel):**
  - Claude Code / Cursor / Aider power users (MCP-native, "two Claudes on one box") → **r/ClaudeAI, X**
  - Self-host / local-LLM / privacy crowd (run-own-relay, no vendor) → **r/LocalLLaMA, HN**
  - Protocol / decentralization / crypto-identity nerds (Ed25519, federation, threat model) → **HN, Lobsters**
  - Agent builders (agent-to-agent comms primitive) → **PH, r/AI_Agents, r/artificial**

## Channels + angle + mechanics
| Channel | Angle (lead with) | Mechanics |
|---|---|---|
| **Show HN** | the *protocol*: self-sovereign, federated, relay-can't-read, threat model, run-own-relay in 30s. Technical + honest. | Tue–Thu, ~8–10am ET. One link (github or wireup.net). Founder in thread all day answering. |
| **Product Hunt** | the *product/UX*: "phone line for agents," 30s install, persona faces, the 22s demo. Visual. | Launch 12:01am PT. Need: tagline, gallery (demo gif + screenshots), maker first-comment, ~5 genuine hunters notified (not bought). |
| **r/LocalLLaMA** | own-your-relay, no vendor, works with local agents. | Text post, dev-honest, demo gif. Respect self-promo rules (be a member, engage). |
| **r/ClaudeAI** | MCP-native, "tell your 3 Claude windows apart," two-Claudes-coordinate use case. | Demo gif + the one concrete use case from the README. |
| **r/programming / r/AI_Agents / r/artificial** | the agent-comms primitive + the protocol. | Lower priority; only if HN/PH land. |
| **X thread** | build-in-public, ties to Slancha ("the team building vendor-neutral inference also built wire"). | 5–6 tweets + demo video. Founder voice. |
| **Lobsters, dev.to** | secondary; the protocol writeup / a "why we built our own agent transport" post. | After launch day. |

## Pre-launch checklist (must be GREEN before launch day)
- [ ] **Repo polished** — README (✓ strong), AGENTS.md, docs/ (spec + threat model ✓), LICENSE, clear CONTRIBUTING.
- [ ] **Install is bulletproof** — `curl wireup.net/install.sh | sh` + `wire setup --apply` works clean on macOS + Linux, fresh machine. The #1 launch-killer is a broken install in front of HN.
- [ ] **Demo solid** — the 22s demo plays on wireup.net; a downloadable gif for PH/Reddit.
- [ ] **wireup.net up** — landing, install, demo, Discord link; uptime check (don't get hugged-to-death; CDN/cache).
- [ ] **Discord seeded** — a few real early users so it's not a ghost town when 100 people join.
- [ ] **Early credibility** — 3–10 real people who've used wire and will honestly engage (NOT fake upvotes).
- [ ] **FAQ/objection prep** — the hard HN questions answered honestly (below).
- [ ] **Self-promo standing on Reddit** — post from an account with history; read each sub's rules.

## Launch-day runbook
1. **12:01am PT** — Product Hunt goes live (maker comment posted).
2. **~8am ET** — Show HN posted (one clean title; founder watching the thread).
3. **Morning** — r/ClaudeAI + r/LocalLLaMA posts (staggered, not simultaneous-spam).
4. **Midday** — X thread.
5. **All day** — founder answers EVERY HN/PH/Reddit comment fast + honestly. This is the whole game.
6. **Don't** — cross-post identical text everywhere at once (looks like spam), buy upvotes, or argue defensively.

## Success metrics (falsifiable targets)
1. HN: front page (top 30) for ≥2h. 2. PH: top 5 of the day. 3. GitHub stars: +N (set baseline first).
4. Install→`wire add` conversion (instrument). 5. Discord joins. — Track all; Pulse/Scribe report post-launch.

## Gates (hard)
Founder posts everything, in his own voice. Persona/adversarial pass on each asset before it ships
(security claims especially — HN will probe the threat model). No fabricated traction. No astroturfing.
Scribe drafts; CEO approves + posts.
