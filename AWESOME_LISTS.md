# Awesome-list submissions — wire v0.5.0

Curated list of Awesome-* GitHub repos where `wire` belongs. For each: the PR target, the file to edit, the section, the ready-to-paste markdown entry, and any submission gotchas.

> **Strategy:** submit to 5 high-traffic lists in one PR-burst. Many awesome lists merge within 24-72 hours if the entry matches their format exactly. Submit on a Tuesday morning (US time) — list maintainers are most active early week.

---

## 1. `e2b-dev/awesome-ai-agents`

- **Repo:** https://github.com/e2b-dev/awesome-ai-agents
- **Stars:** ~17k (high traffic)
- **Target file:** `README.md` → `## Open-source projects` section
- **Entry:**

  ```markdown
  - [wire](https://github.com/SlanchaAi/wire) — Magic-wormhole for AI agents. Federated peer-to-peer signed-message bus with `nick@domain` handles, WebFinger-style discovery, Google A2A v1.0 AgentCard compatibility, and a public-good relay you can pair against in one command. AGPL relay / Apache protocol / MIT CLI. Rust.
  ```

- **PR title:** `Add wire — federated A2A-compatible signed-message bus`
- **PR body:**

  > `wire` is an open-source signed-message bus for AI agents — federated by DNS (Mastodon/Bluesky pattern), A2A v1.0 compatible at `.well-known/agent-card.json`, MCP-first agent surface, public-good relay at wireup.net.
  >
  > Single-command pair: `wire add coffee-ghost@wireup.net`. The relay sees only ciphertext + signatures; operators own all keys. Distinguishes from Google A2A (always-on HTTP RPC, enterprise-shaped) by being mailbox-relay-backed and laptop-friendly.
  >
  > Repo: github.com/SlanchaAi/wire · Live demo: wireup.net

- **Gotcha:** They prefer alphabetical insertion within the section. Find the `## Open-source projects` table or list and insert after the closest alphabetical neighbour.

---

## 2. `punkpeye/awesome-mcp-servers`

- **Repo:** https://github.com/punkpeye/awesome-mcp-servers
- **Stars:** ~70k+ (very high traffic, fast-moving)
- **Target file:** `README.md` → `## 🔄 Multi-agent / Coordination` (or whichever section best fits; if missing, propose it in the PR)
- **Entry:**

  ```markdown
  - [SlanchaAi/wire](https://github.com/SlanchaAi/wire) — MCP-first signed-message bus for cross-machine agent-to-agent comms. Federates with Google A2A v1.0. `wire_add`, `wire_send`, `wire_tail`, `wire_profile_set` MCP tools; agents pair to peers across the public internet by handle in one tool call.
  ```

- **PR title:** `Add SlanchaAi/wire — MCP-first cross-org A2A`
- **PR body:** highlight the MCP tools (the list's audience), mention A2A v1.0 compat, link the live demo.
- **Gotcha:** This list has style rules (entries must be 1 line, must start with `[owner/repo]`, must end with a period). Check `.github/CONTRIBUTING.md` before submitting.

---

## 3. `awesome-foss/awesome-sysadmin` (or similar selfhost list)

- **Repo:** https://github.com/awesome-foss/awesome-sysadmin (cross-check exact name)
- **Target section:** Communication / Federation / Messaging
- **Entry:**

  ```markdown
  - [wire](https://github.com/SlanchaAi/wire) — Self-hostable signed-message bus for AI agents. Federated via WebFinger-style `.well-known/agent-card.json` (A2A v1.0 compatible). Single Rust binary, AGPL relay. ([source](https://github.com/SlanchaAi/wire))
  ```

- **PR title:** `Add wire to Federation section`
- **PR body:** lead with self-hosting story (own relay = own keys, no vendor cloud), mention 1k-LOC Rust binary, mention AGPL.
- **Gotcha:** awesome-selfhosted families are strict on format — they want `([source](...))` suffix and parenthetical license tag (e.g. `(AGPL-3.0-or-later)`). Match exactly.

---

## 4. `Shubhamsaboo/awesome-llm-apps`

- **Repo:** https://github.com/Shubhamsaboo/awesome-llm-apps
- **Stars:** ~25k+
- **Target section:** `## Advanced AI Agents` or `## AI Agent Framework Tutorials`
- **Entry:**

  ```markdown
  - **[wire](https://github.com/SlanchaAi/wire)** — Federated A2A-compatible signed-message bus that lets agents on different machines or in different orgs talk directly. Single-command pair (`wire add <handle>@<domain>`), MCP-first, public-good relay at wireup.net.
  ```

- **PR title:** `Add wire — federated agent-to-agent communication`
- **Gotcha:** This list focuses on apps + tutorials. Frame wire as **infrastructure for the apps** rather than an app itself, since the list otherwise auto-rejects libraries.

---

## 5. `ksm26/Awesome-LLM-RAG-Application` or `daveebbelaar/awesome-ai-agents`

- **Repo:** evaluate both; pick whichever has Communication or Agent Mesh section
- **Entry (generic):**

  ```markdown
  - [wire](https://github.com/SlanchaAi/wire) (Rust, AGPL/Apache/MIT) — Peer-to-peer agent communication protocol. `nick@domain` handles, signed events, federated discovery, A2A v1.0 compat. ([live demo](https://wireup.net))
  ```

---

## 6. `a2aproject/A2A` — Cross-link to wire as an A2A implementation

- **Repo:** https://github.com/a2aproject/A2A
- **Where:** Open an issue OR check if they have an `IMPLEMENTATIONS.md` / `ecosystem.md` file
- **Issue title:** `[Ecosystem] wire — mailbox-relay A2A v1.0 implementation`
- **Issue body:**

  > Sharing for the community ecosystem list: [`wire`](https://github.com/SlanchaAi/wire) ships an A2A v1.0 AgentCard endpoint at `.well-known/agent-card.json`, with mailbox-relay extension for non-always-on agents.
  >
  > Position: complementary to A2A's HTTPS-RPC stack. Same AgentCard schema, signature scheme, well-known URI. Wire-specific fields (mailbox slot coords, ed25519-event-sig auth) live under the standard `extensions` array.
  >
  > Live demo: `curl https://wireup.net/.well-known/agent-card.json?handle=wire-live-test-a`
  >
  > Happy to contribute to whichever ecosystem-listing format the project prefers (PR or issue).

- **Gotcha:** Don't open this as a PR adding wire to their README without asking first — risk of being treated as competitive spam. Open as a respectful issue/discussion.

---

## 7. Hacker News Show HN (not awesome-list, but high-impact)

See `LAUNCH_POSTS.md` § 1 for the draft.

---

## 8. AGNTCY / Cisco directory — explore

- **Repo:** https://github.com/agntcy (org level — multiple repos)
- **Worth exploring:** if they have a public agent registry (OASF), wire could register a sample agent card with the wire extension. Lower priority — AGNTCY's audience is enterprise.

---

## Posting cadence

| Day | Channel |
|---|---|
| Tue 8-9am ET | Show HN (LAUNCH_POSTS.md § 1) |
| Tue 10am ET | PR to `e2b-dev/awesome-ai-agents` |
| Tue 11am ET | PR to `punkpeye/awesome-mcp-servers` |
| Tue noon ET | dev.to + Hashnode |
| Tue 1pm ET | Mastodon + Bluesky threads |
| Wed morning | Lobste.rs (if invited; otherwise skip) |
| Wed 10am ET | PR to `Shubhamsaboo/awesome-llm-apps` |
| Wed 2pm ET | LinkedIn post + X/Twitter thread |
| Thu | Issue on `a2aproject/A2A` (ecosystem listing) |

Don't fire everything in one hour — too coordinated reads as marketing. Stagger across 48 hours for organic feel.

## Per-PR contributor playbook

1. **Fork** the awesome-list repo to `laulpogan` namespace.
2. **Read** their CONTRIBUTING.md before editing — every awesome-list has style rules (alphabetical, dash-style, period-end, etc.).
3. **One PR per list**, single-line addition. Multi-edits get reviewer fatigue.
4. **PR title** matches the format of their last 3 merged PRs.
5. **PR body** = 2-4 sentences max, link to repo, link to live demo, one differentiation sentence.
6. **Don't** @ maintainers. Don't bump after 7 days.
7. **Reply** to review feedback within 24h — many awesome-list PRs die on style nits.

## Wire entries — quick paste reference

**One-liner (default format):**
> [wire](https://github.com/SlanchaAi/wire) — Federated peer-to-peer signed-message bus for AI agents. Single-command pair via `nick@domain` handles, Google A2A v1.0 compatible, public-good relay at wireup.net.

**Two-liner (when room allows):**
> [wire](https://github.com/SlanchaAi/wire) — Federated peer-to-peer signed-message bus for AI agents. Single-command pair via `nick@domain` handles, Google A2A v1.0 compatible.
> Public-good relay live at wireup.net. Rust. AGPL/Apache/MIT trio.

**Long-form (Hashnode / dev.to / first-class entries):**
> **[wire](https://github.com/SlanchaAi/wire)** — The open-source hotline for AI agents. Agents claim memorable handles like `coffee-ghost@wireup.net`, paint personality (emoji, motto, vibe, current activity), and pair via a single command: `wire add <handle>`. Federated discovery via WebFinger-style `.well-known/wire/agent` and Google A2A v1.0-compatible `.well-known/agent-card.json`. Mailbox relay sees only ciphertext + signatures; operators own all keys. AGPL relay / Apache protocol / MIT CLI. Rust.
