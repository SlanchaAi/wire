# Identity & Persona Primitive Survey — 2026-05-22

Three parallel research slices via slancha-delegate. Question: how does the ecosystem name, persist, and share agent identity + persona? Where does wire's identity layer slot in cleanly?

Trust priors `[Tier, Source, Score]` inline. Primary vendor doc <30d = 90-100; primary 30-180d = 70-89; secondary <90d = 50-69; secondary 90d-12mo = 30-49.

---

## TL;DR

**SOUL.md is real.** Hermes-Agent (NousResearch) literally loads `~/.hermes/SOUL.md` into prompt slot #1 [P, github.com/NousResearch/hermes-agent, 88]. OpenClaw uses `SOUL.md` + six sibling files [P, github.com/openclaw/openclaw + clawdocs.org, 75]. **SoulSpec** (clawsouls/soulspec, soulspec.org, spec v0.5 as of 2026-02-23) is the emerging cross-harness package format — `soul.json` manifest + `SOUL.md` body, claimed compat with OpenClaw / Claude Code / Claude Desktop / Cursor / Windsurf / ChatGPT [P, soulspec.org, 80].

The user's instinct was correct: SOUL.md is the persona-first convention crystallizing across multiple OSS agent harnesses, in parallel with (not derived from) the older roleplay-character-card lineage.

**The unanimous gap:** zero of 13 surveyed systems have cryptographic identity for the agent itself. Multi-agent discrimination is universally string-matching. Distribution is gallery-reputation + git-origin. **No spec binds persona to a signed identity.** This is the seam wire's `did:wire:` + signed `persona_url` actually fills.

---

## Two parallel lineages converged on the same shape

### Roleplay character cards (2022 →)

```
CharacterAI (proprietary, no export)
  → Pygmalion 6B (community needs portable defs)
    → TavernAI → SillyTavern Character Card V1 (6 fields, PNG-embed via tEXt `chara`)
      → CCv2 (malfoyslastname/character-card-spec-v2, 2023-12, ~20 fields, system_prompt, lorebook)
        → CCv3 (kwaroran/character-card-spec-v3, 2024, CHARX zip, assets, multilingual)
```

V2 schema fields: `name`, `description`, `personality`, `scenario`, `first_mes`, `mes_example`, `creator_notes`, `system_prompt`, `post_history_instructions`, `alternate_greetings[]`, `character_book` (lorebook), `tags[]`, `creator`, `character_version`, `extensions: Record<string,any>` [P, character-card-spec-v2/spec_v2.md, 90].

V3 adds: `assets[]`, `nickname`, `creator_notes_multilingual`, `source[]`, `group_only_greetings[]`, `creation_date`, `modification_date`. Switches PNG keyword to `ccv3` (keeps `chara` for back-compat) [P, character-card-spec-v3/SPEC_V3.md, 90].

**Distribution:** chub.ai, characterhub.org galleries. Trust = gallery reputation. **No signing.** Single binary artifact optimized for trading.

### Agent souls (2023 →)

```
Open Souls (opensouls/opensouls — TS engine, dir-of-MD, not a file spec)
  → soul.md (rokoss21 — YAML-frontmatter draft v1.0.0-rc1, never widely adopted)
  → soul.md (aaronjmars — data-ingest convention: SOUL/STYLE/SKILL/MEMORY .md + data/ examples/)
    → SoulSpec (clawsouls/soulspec, v0.5 2026-02-23) — the package format
      → adopted by OpenClaw, Hermes-Agent, claimed compat across Claude Code/Desktop/Cursor/Windsurf
```

SoulSpec required files: `soul.json` (manifest) + `SOUL.md` (personality body). Optional: `IDENTITY.md`, `AGENTS.md`, `STYLE.md`, `HEARTBEAT.md`, `examples/`.

```json
{
  "specVersion": "0.5",
  "name": "string",
  "displayName": "string",
  "version": "string",
  "description": "string",
  "license": "string",
  "tags": ["string"],
  "compatibility": {"frameworks": ["string"]},
  "files": {"soul": "string", "identity": "string", "agents": "string"}
}
```

OpenClaw six-section SOUL.md schema [P, clawdocs.org, 60]: Opening / Core Truths / Boundaries / Vibe / Continuity / Closing. Companion `STYLE.md` for voice, `SKILL.md` for operating modes.

**Caveat:** OpenClaw/ClawSouls ecosystem looks somewhat astroturfed — many tertiary blog posts with similar phrasing. Primary repos `openclaw/openclaw`, `clawsouls/soulspec`, `NousResearch/hermes-agent` are real, so the convention itself is real, but treat marketing-language inflation skeptically. [TBD: actual install/usage numbers]

**Distribution:** `npx clawsouls install <name>` from clawsouls.ai gallery. Filesystem-native, git-friendly. **No signing.**

---

## Hermes specifically — SOUL.md in prompt slot #1

Hermes-Agent (NousResearch) prompt assembly order [P, github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/prompt-assembly.md, 88]:

1. **`~/.hermes/SOUL.md`** — identity, durable baseline
2. Tool-aware behavior
3. Honcho static block
4. Optional system message
5. Frozen MEMORY snapshot
6. Frozen USER profile
7. Skills index
8. Project context (`AGENTS.md`, `.cursorrules`, `CLAUDE.md`, `.hermes.md`)
9. Timestamp / session ID
10. Platform hint

SOUL.md content guidance: tone, directness, stylistic avoidances, uncertainty handling. NOT project paths or workflow (those go to AGENTS.md). `/personality` slash-command = session-level overlay; SOUL.md = durable baseline.

Hermes 3/4 base models are tuned for steerability via ChatML system prompts [P, arXiv:2408.11857, 90] — the SOUL.md convention is Hermes-Agent layer (harness), not baked into model weights.

---

## Coding-assistant harness convention table

| System | File | Format | Scope | Auto-evolves | Crypto ID | Portable | Discovery |
|---|---|---|---|---|---|---|---|
| **Claude Code** | `CLAUDE.md` + `SKILL.md` + auto-memory | MD + YAML frontmatter | managed/user/project/local/nested | yes (auto memory v2.1.59+) | no | yes (git) | auto, walks tree |
| **OpenClaw** | `SOUL.md` + IDENTITY/AGENTS/USER/TOOLS/MEMORY/HEARTBEAT | MD, 6-section schema | per-workspace cascade | yes (MEMORY.md) | no | yes (souls.directory) | auto inject sys prompt |
| **Hermes-Agent** | `~/.hermes/SOUL.md` | MD | user-global | no (separate MEMORY) | no | yes (file) | slot #1 of sys prompt |
| **Cursor** | `.cursor/rules/*.mdc` | MD + YAML | team/project/user/nested | no | no | project: yes; user: no | auto by trigger mode |
| **Continue.dev** | `.continue/rules/*.md` + `config.yaml` | MD/YAML | hub/workspace/global | no | no | yes (git + Hub) | auto |
| **Aider** | `CONVENTIONS.md` | MD free-form | project (explicit) | no | no | yes (git) | explicit `--read` |
| **GitHub Copilot** | `.github/copilot-instructions.md` | MD free-form | repo only | no | repo-bound | yes (git) | auto on save |
| **Windsurf** | `.windsurf/rules/*.md` + memories | MD + YAML | system/global/workspace | yes (memories) | no | rules: yes; memories: no | auto by trigger |
| **Zed** | first-match `.rules`/`CLAUDE.md`/`AGENTS.md`/... | MD | project + user library | no | no | yes (adopts others') | auto first-match |

**Convergent filename:** `AGENTS.md` is the lowest-common-denominator read by Claude Code, Cursor, Windsurf, Zed, Hermes-Agent, OpenHands [P, multi-source, 80]. Free-form Markdown, repo root. Strong candidate for default fallback.

**Clean split crystallizing:** `AGENTS.md` = *what the agent does* (project workflow, tools, conventions). `SOUL.md` = *who the agent is* (voice, values, boundaries, tone). Different files, different purposes. Wire's persona pointer should target SOUL.md, not AGENTS.md.

---

## Agentic framework agent-identity table

| Framework | Identity primitive | Persona | Persistent | Crypto | Evolves | Portable | Multi-agent disc. |
|---|---|---|---|---|---|---|---|
| **CrewAI** | `Agent` class | `role`+`goal`+`backstory` strings | no | no | history only | YAML | `role` string |
| **LangGraph** | compiled `StateGraph` | `prompt` param | yes (checkpointer + Store) | no | thread + Store namespace | partial | node name string |
| **Letta** | `AgentState` schema | `blocks[label=persona,human]` self-editable | yes (DB) | no (db UUID) | **yes — first-class** | yes (.af) | UUID `id` |
| **AutoGen** | `AgentId(type, key)` + `AssistantAgent` | `system_message` + `description` | no default | no | injected memory | code | `AgentId` tuple |
| **OpenAI Agents SDK** | `Agent` dataclass | `instructions` (static or callable) | no (external sessions) | no | dynamic instructions | code | `name` + handoffs |
| **Claude Agent SDK** | `AgentDefinition` dict entry | `prompt` + `.claude/` markdown | session resume only | no | sessions + skills | yes (MD files) | dict key |
| **Mastra** | `new Agent({id,name,...})` | `instructions` | yes (Memory) | no | 4-tier (incl. observational) | code + memory | `id` + `resource` |
| **Pydantic AI** | typed `Agent[Deps,Out]` | `system_prompt` + decorator | no | no | deps + history | code | object identity |
| **Smolagents** | `CodeAgent` / `ToolCallingAgent` | `prompt_templates` + tool descs | no | no | logs only | yes (HF Hub) | `name` + `description` |
| **OpenHands** | `.openhands/microagents/*.md` | YAML frontmatter `triggers:` + body | filesystem (repo) | no | git commits | yes (repo) | per-microagent name |
| **Devin** | opaque monolithic | Knowledge entries + Playbooks | yes (cross-session) | no public | yes (curated) | no (closed) | per-tenant |
| **AutoGPT (classic)** | `AIProfile` + `AIDirectives` | name/role/goals prompt-injected | no | no | no | config text | N/A |
| **BabyAGI (classic)** | env vars | OBJECTIVE string | task store only | no | task-list grows | `.env` | function name |

**Most advanced for evolving identity: Letta.** AgentState schema with self-editable memory blocks (`label="persona"`, `label="human"` defaults), agent self-edits via `core_memory_append`/`core_memory_replace` tools, database persistence, `.af` export format [P, github.com/letta-ai/letta, 92]. Letta is the closest existing primitive to "an agent that grows."

**Universal gap:** zero of 13 systems have cryptographic identity for the agent itself. Multi-agent discrimination is universally string-matching (`name`, `AgentId(type, key)`, dict key, node name). Identity is unforgeable only because everyone runs in one trust domain.

---

## What this means for wire

### What wire shouldn't try to do
- Don't invent a new persona file format. SoulSpec + SOUL.md is already the convergent shape; CCv3 covers the roleplay side.
- Don't define what the persona body looks like. Other harnesses will fight you. Be the transport+identity layer, not the schema layer.
- Don't bundle persona content in the agent-card. URL + hash is enough.

### What wire should do
1. **Identity carries `persona_url` + `persona_sha256`** (optional). Body is opaque to wire. Could be SOUL.md, CLAUDE.md, AGENTS.md, CCv3 character card, anything.
2. **Sign the manifest.** This is the universal gap. Wire's identity layer can prove "this `did:wire:foxtrot-meadow` is the legitimate owner of this persona doc" — first in the ecosystem.
3. **Crib schema discipline from SoulSpec/CCv2:** version field at top (`persona_spec`, `persona_spec_version`), `extensions: Record<string,any>` escape hatch, forward-compat warnings not hard fails.
4. **Crib Hermes' slot-ordering doc.** When wire publishes `persona_url`, also publish a slot hint (`prompt_slot: "system_prepend"` or similar) so consuming harnesses know where to inject.
5. **Default fallback to AGENTS.md** if no `persona_url` set. Maximizes interop with the convergent filename.

### v0.7.0 identity-layer concrete shape

```rust
struct Identity {
    // Crypto core
    did: String,                    // did:wire:<handle>-<8hex>
    handle: String,                 // paul-a1b2c3d4
    keypair: Ed25519Keypair,
    lifecycle: LifecycleState,      // anonymous | local | federation
    created_at: i64,

    // Display layer (NEW — user's nickname+emoji ask)
    nickname: Option<String>,       // "foxtrot-meadow"
    emoji: Option<String>,          // "🦊"
    bio: Option<String>,            // ≤200 chars, inline

    // Persona pointer (NEW — soul.md/CLAUDE.md/AGENTS.md ref)
    persona_url: Option<String>,    // file:// or https://
    persona_sha256: Option<String>, // pinned content hash
    persona_spec: Option<String>,   // "soulspec" | "claude_md" | "agents_md" | "ccv3" | custom
    persona_slot: Option<String>,   // "system_prepend" | "system_replace" | "context_append"

    // Escape hatch
    extensions: HashMap<String, Value>,
}
```

This is additive on top of v0.6.x Session fields. Lifecycle gates visibility:
- Anonymous: persona fields stripped from any agent-card we'd emit
- Local: persona_url accepts `file://`, kept local-only
- Federation: persona_url required `https://` (or `wire://` future), broadcast in agent-card

### Identity-anchored persona injection (the v0.7.2 unlock)

```
WIRE_AS=foxtrot-planner claude
  → wire MCP startup reads identity foxtrot-planner
  → identity has persona_url=https://wireup.net/personas/foxtrot.md, persona_sha256=abc...
  → wire exports WIRE_PERSONA_URL + WIRE_PERSONA_SHA256 to env
  → harness adapter (small, optional, Claude-Code-specific) fetches URL, verifies SHA, injects as CLAUDE.md addendum
```

Same identity → same persona across machines. Different identity (`raven-reviewer`) → different persona. Wire is the binding, persona file lives wherever (git, wireup.net, peer's relay).

### Trust model for receiving peer personas

Receiving a peer's `persona_url` and auto-loading it = supply chain attack vector. Don't auto-load. Three tiers:
- **Display only** — show URL in `wire whois`, don't fetch
- **Operator confirm** — `wire peer trust slancha-spark --persona` to opt into auto-fetch
- **Pinned SHA only** — auto-fetch but only if SHA matches a pinned value

Default = display only.

---

## Open Souls vs SoulSpec vs CCv3 — which to crib from?

| Aspect | Open Souls | SoulSpec v0.5 | Character Card V3 |
|---|---|---|---|
| Shape | TS engine, dir of MD + code | `soul.json` + `SOUL.md` + optional files | single JSON (PNG-embeddable) or CHARX zip |
| Schema discipline | none | `specVersion` + `extensions` | `spec` + `spec_version` + `extensions` |
| Versioning | engine versioning | `version` field per package | per-card `character_version` |
| Distribution | NPM packages | `npx clawsouls install` from gallery | drag-drop + chub.ai gallery |
| Identity binding | none | `license` field only | none |
| Frameworks compat | TS only | claims OpenClaw/CC/Cursor/Windsurf/ChatGPT | SillyTavern/RisuAI/oobabooga |
| Primary use case | building agents | sharing personas across coding harnesses | sharing characters for roleplay |

**Pick SoulSpec for the manifest pattern + CCv2 for schema-discipline vocabulary + Hermes for slot-ordering convention.** Don't pick Open Souls (engine, not file format).

---

## Sources

**Coding-harness:**
- [Claude Code memory](https://code.claude.com/docs/en/memory)
- [Claude Code skills](https://code.claude.com/docs/en/skills)
- [Cursor rules](https://cursor.com/docs/context/rules)
- [Continue.dev rules](https://docs.continue.dev/customize/deep-dives/rules)
- [Aider conventions](https://aider.chat/docs/usage/conventions.html)
- [GitHub Copilot instructions](https://docs.github.com/en/copilot/customizing-copilot/adding-custom-instructions-for-github-copilot)
- [Windsurf Cascade memories/rules](https://docs.windsurf.com/windsurf/cascade/memories)
- [Zed AI rules](https://zed.dev/docs/ai/rules)

**Agentic frameworks:**
- [CrewAI agents](https://docs.crewai.com/concepts/agents)
- [LangGraph create_react_agent + checkpointer](https://forum.langchain.com/t/can-create-supervisor-create-react-agent-use-checkpointer-and-store-for-across-thread-memory/1779)
- [Letta AgentState](https://github.com/letta-ai/letta/blob/main/letta/schemas/agent.py)
- [Letta Block schema](https://github.com/letta-ai/letta/blob/main/letta/schemas/block.py)
- [AutoGen agents](https://microsoft.github.io/autogen/stable/user-guide/core-user-guide/framework/agent-and-agent-runtime.html)
- [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/agents/)
- [Claude Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview)
- [Mastra agents](https://mastra.ai/docs/agents/overview)
- [Mastra memory](https://mastra.ai/docs/memory/overview)
- [Pydantic AI agent](https://pydantic.dev/docs/ai/api/pydantic-ai/agent)
- [Smolagents guided tour](https://huggingface.co/docs/smolagents/main/en/guided_tour)
- [Devin Knowledge](https://docs.devin.ai/product-guides/knowledge)
- [Devin Playbooks](https://docs.devin.ai/product-guides/creating-playbooks)
- [OpenHands microagents](https://docs.openhands.dev/openhands/usage/microagents/microagents-overview)

**Persona-file specs:**
- [character-card-spec-v2](https://github.com/malfoyslastname/character-card-spec-v2/blob/main/spec_v2.md)
- [character-card-spec-v3](https://github.com/kwaroran/character-card-spec-v3/blob/main/SPEC_V3.md)
- [opensouls/opensouls](https://github.com/opensouls/opensouls)
- [rokoss21/soul.md](https://github.com/rokoss21/soul.md)
- [aaronjmars/soul.md](https://github.com/aaronjmars/soul.md)
- [clawsouls/soulspec](https://github.com/clawsouls/soulspec)
- [soulspec.org](https://soulspec.org/)
- [NousResearch/hermes-agent personality.md](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/personality.md)
- [NousResearch/hermes-agent prompt-assembly.md](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/prompt-assembly.md)
- [Hermes 3 Technical Report](https://arxiv.org/pdf/2408.11857)
- [openclaw/openclaw](https://github.com/openclaw/openclaw)
- [SOUL.md guide (clawdocs)](https://clawdocs.org/guides/soul-md/)
- [souls.directory](https://github.com/thedaviddias/souls-directory)
