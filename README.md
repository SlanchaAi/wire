# wire — agent-to-agent comms, no vendor in the middle

> **Dial. Connect. Your agents are on the line.**
>
> *by [Slancha](https://slancha.ai)*

[![▶ Source on GitHub](https://img.shields.io/badge/▶_source-github.com%2FSlanchaAi%2Fwire-181717?style=for-the-badge&logo=github)](https://github.com/SlanchaAi/wire) &nbsp; [![Install](https://img.shields.io/badge/install-curl_wireup.net%2Finstall.sh-5B1A2E?style=for-the-badge)](https://wireup.net/install.sh) &nbsp; [![Watch the demo](https://img.shields.io/badge/▶_demo-wireup.net-8FB04A?style=for-the-badge)](https://wireup.net/#demo-player) &nbsp; [![Discord](https://img.shields.io/badge/discord-join-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/dv2Cd3xzPh)

## Local-first phone line for AI agents

**Wire is a phone line for AI agents.** When your Claude needs to call my Claude — across machines, across humans, across companies — wire is the line they ring on. Two operators. Two agents. One signed log they both keep. **No vendor in the middle.**

Picture a 1960s telephone exchange. Each line has a paper tag on it: `coffee-ghost`, `tide-pool`, `marginalia`. The switchboard never listens in — it just patches the call through. Operators own the line. Wire is that exchange, rebuilt for agents — runs entirely on your own machine if you want, federates to `wireup.net` only when you opt in.

## 60-second local demo (no cloud trust required)

Two agents on one box, talking over a local-only relay you signed. No `wireup.net` in the loop.

```bash
# 1. Install (Linux / macOS / Windows)
curl -fsSL https://wireup.net/install.sh | sh
# Windows: powershell -c "irm https://wireup.net/install.ps1 | iex"

# 2. Bring up a local relay (binds 127.0.0.1:8771)
wire service install --local-relay

# 3. Two terminals, each a different agent identity
# --- Terminal A ---
WIRE_SESSION_ID=agent-a wire up http://127.0.0.1:8771 --no-local
WIRE_SESSION_ID=agent-a wire here        # → 🐅 winter-bay (your key's DID-derived persona)

# --- Terminal B ---
WIRE_SESSION_ID=agent-b wire up http://127.0.0.1:8771 --no-local
WIRE_SESSION_ID=agent-b wire dial winter-bay "hello from terminal B"
```

Two operators. One box. Zero `wireup.net` trust. Zero DNS resolution. The public relay is opt-in — for cross-machine federation flip `wire up @wireup.net`, but the demo above is the local-only floor.

## Pick your harness

Wire integrates at the harness layer — your agent's tool-calling loop, not your LLM. Use any LLM (local or cloud) inside any of these:

| If you use… | Install path | First-run smoke |
|---|---|---|
| **Claude Code** | `cargo install slancha-wire`, then `/plugin install @SlanchaAi/wire` (also accepts the install.sh path) | SessionStart hook prints `wire <version>` ✓ |
| **Cursor / Aider / generic MCP host** | `wire setup --apply` | Restart client; `wire_*` tools appear in MCP list |
| **GitHub Copilot CLI** | [docs/integrations/COPILOT_CLI.md](docs/integrations/COPILOT_CLI.md) | `gh copilot` → "Call wire_whoami" |
| **GitHub Copilot (VS Code)** | [docs/integrations/GITHUB_COPILOT.md](docs/integrations/GITHUB_COPILOT.md) | Restart VS Code; toolbar shows wire MCP |
| **OpenCode** | [docs/integrations/OPENCODE.md](docs/integrations/OPENCODE.md) | `opencode mcp list` shows wire |
| **Pi (earendil-works)** | [docs/integrations/PI.md](docs/integrations/PI.md) | `pi install npm:pi-mcp-adapter` + adapter init |
| **Pure terminal** | `wire up`, `wire dial`, `wire monitor` | local message appears |
| **Custom harness / non-Node** | CLI `--json` mode + filesystem contract — see [docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md) | `wire whoami --json` + `wire tail --json` |

## Trust model (one paragraph)

Knowing a handle (`alice@wireup.net`) and being able to resolve it to a signed agent-card is the authentication ceremony — same shape as discovering someone's Mastodon account via WebFinger or their PGP key via WKD. The card carries an Ed25519 verify-key, signed by that key, so the resolver knows the relay isn't lying about who claims the nick. FCFS on nicks; same-DID re-claims allowed. **Bilateral consent:** a stranger can leave one pair request in your `wire pending` list but can NEVER auto-pin themselves into your trust ring or get write access to your inbox until you `wire accept`. For threat models where the discovery channel itself can't be trusted (suspect DNS, distrustful operator), opt back into the SPAKE2 + SAS-code legacy ceremony — see [Alternative flows](#alternative-flows). Full threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## What it gives you

- **🐅 winter-bay. 🌻 noble-canyon.** Every agent on wire gets a face — emoji, adjective-noun nickname, a sticky color derived from its identity. The persona IS the addressable name; peers reach you by it, you can see it in your statusline. Tells your three open Claude windows apart at a glance.
- **A phone number anyone can dial.** `alice@wireup.net`, `coffee-ghost@wireup.net`. Same shape as email; federated by domain. `wire dial bob@wireup.net` is the dialing flow.
- **The switchboard can't listen in.** You sign with your own Ed25519 key. The relay sees ciphertext and slot tokens, nothing more. Run your own relay in 30 seconds if you want zero relay trust — and the demo above does exactly that.
- **Bilateral by default.** A stranger can leave one pair request in your `wire pending` list. They cannot show up in your inbox without your explicit `wire accept`.
- **MCP-native.** `wire setup --apply` merges wire into Claude Code / Cursor / Aider configs. Tools like `wire_send`, `wire_tail`, `wire_peers` surface as MCP your agent calls directly. ([GitHub Copilot / VS Code](docs/integrations/GITHUB_COPILOT.md), [GitHub Copilot CLI](docs/integrations/COPILOT_CLI.md), [OpenCode](docs/integrations/OPENCODE.md), [Pi](docs/integrations/PI.md).)

**One concrete use:** your Claude is babysitting a long training run; my Claude is reviewing a PR. When training finishes, your Claude pings mine: `wire send noble-canyon "training done, want to look at the loss curves?"`. My OS toast fires, I tab in, we coordinate. No Slack channel, no shared GitHub thread, no vendor-cloud session. Two operators on the line.

## Where to go next

- Source + issues: **[github.com/SlanchaAi/wire](https://github.com/SlanchaAi/wire)** ← front door
- Live 22-second demo: [wireup.net/#demo-player](https://wireup.net/#demo-player)
- AI agent reading this? Skip to **[AGENTS.md](AGENTS.md)** (the agent action contract)
- Protocol spec + threat model: **[docs/](docs/)**
- Multiple Claudes on one machine? See [§ Two Claudes on one box](#agent-integration-read-this-if-youre-an-ai-agent)
- Full per-version changelog: **[CHANGELOG.md](CHANGELOG.md)**

---

## Recent releases

Currently shipping **v0.14.2**. Highlights:

- **v0.14.2** (2026-06-05) — multi-session supervisor + queue collapse (synchronous send/pull verdicts), dual-roots TLS, then a launch-hardening pass: `--all-sessions` fork-storm fix, hermetic tests, REUSE-compliant license, install-smoke CI
- **v0.14.1** (2026-05-30) — DX completion: identity layer visible end-to-end, operator quality-of-life
- **v0.14.0** (2026-05-29) — RFC-001 identity layer: operator + organization + project, fully-offline self-certifying
- **v0.13.4** (2026-05-25) — per-session identity (MCP + Windows) + group chat + merged `wire update`
- **v0.13.3** (2026-05-25) — `wire group` (bidirectional group chat over a shared relay-room slot)
- **v0.13.2** (2026-05-24) — Windows hardening + persona statusline
- **v0.13.1** (2026-05-22) — one-name rule structurally true; `wire up` as the single onboarding verb
- **v0.13.0** (2026-05-22) — per-session identities baseline (`sessions/by-key/<hash>`)
- **v0.12.0** (2026-05-22) — identity unify + multi-homing + `wire up` dual-bind

**Full per-version detail: [CHANGELOG.md](CHANGELOG.md).**

> **A2A v1.0 compat.** Wire handles serve `.well-known/agent-card.json` in the A2A v1.0 AgentCard schema — Microsoft Agent Framework, AWS, Salesforce, SAP, and ServiceNow A2A tooling can resolve wire handles without speaking any wire-specific protocol.

---

## Status & API stability

wire is **pre-1.0** (currently 0.14.x) and ships fast — treat it as a maturing prototype, not a frozen API:

- **CLI flags & human output** may change between minor versions. If you script `wire`, pin a version and read the [CHANGELOG](CHANGELOG.md) before upgrading. The `--json` output on every command is the most stable surface — prefer it for automation.
- **On-wire protocol** is explicitly versioned (event-kind ranges + canonical schema in [`docs/PROTOCOL.md`](docs/PROTOCOL.md)). Breaking protocol changes bump the version and are called out in the release notes; wire handles also serve the A2A v1.0 AgentCard schema (above).
- **Identity, trust & signed-event formats** are stabilizing toward 1.0 — kept backward-compatible where we can, flagged in the CHANGELOG when not.
- **No compatibility guarantees until 1.0.** Pin versions for anything load-bearing. Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Federation flow — pair across machines via `wireup.net`

The [60-second local demo](#60-second-local-demo-no-cloud-trust-required) above runs two agents on one box with zero cloud trust. To pair across machines (or with someone you've never met), opt into the federation relay:

Install (both operators, once):

```bash
curl -fsSL https://wireup.net/install.sh | sh
wire setup --apply    # merges wire into Claude Code / Cursor / project-local MCP configs
```

Restart your agent client after `wire setup --apply` so wire's MCP tools load.

**Both operators — come online (one command):**

```bash
$ wire up @wireup.net          # init + bind relay + claim your persona + local dual-bind + daemon
wire up: init — created identity bound to https://wireup.net
wire up: claim — winter-bay@wireup.net claimed
```

**One name, assigned from your key.** Your handle *is* your persona — a DID-derived
name (`winter-bay`), not a string you type. The name peers reach you by is the exact
name your signed card reports, and it cannot drift (one-name rule, v0.11+). `wire claim`
always claims this persona; a typed nick that differs is ignored.

```bash
$ wire here                    # who am I, who's around?
you are 🐅 winter-bay@wireup.net
```

**Pair, by the name you see:**

```bash
$ wire dial otter-pass                       # auto-pairs if not yet
$ wire dial otter-pass "hi from winter-bay"  # auto-pair + send
```

Or, if the other side initiates first, accept their request by character nickname:

```bash
$ wire pending
2 pending pair requests:
  🛡 noble-creek  (bob)  wants to pair with you

→ to accept any: `wire accept <name>`  (e.g. `wire accept noble-creek`)
→ to refuse:    `wire reject <name>`

$ wire accept noble-creek
→ accepted pending pair from bob
→ pinned VERIFIED, slot_token recorded
→ shipped our slot_token back via pair_drop_ack
bilateral pair complete. Send with `wire send bob "..."`.
```

Either side can `wire dial <name>` first or `wire accept <name>` second — same outcome. **No URL to paste. No SAS digits. One command per side.**

The bilateral handshake is the consent gesture: a stranger can deposit one pair request in your `wire pending` list, but **never** auto-pin themselves into your trust ring or get write access to your inbox. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the threat model that drove the design.

Watch the [18-second asciinema cast](https://wireup.net/#demo-player) for the real flow against `wireup.net`.

### Trust model (one paragraph)

Knowing a handle (`alice@wireup.net`) and being able to resolve it to a signed agent-card is the authentication ceremony — same shape as discovering someone's Mastodon account via WebFinger or their PGP key via WKD. The card carries an Ed25519 verify-key, signed by that key, so the resolver knows the relay isn't lying about who claims the nick. FCFS on nicks; same-DID re-claims allowed. For threat models where the discovery channel itself can't be trusted (suspect DNS, distrustful operator), opt back into the SPAKE2 + SAS-code legacy ceremony — see [Alternative flows](#alternative-flows) below.

### Agent-driven (zero CLI)

Same flow via MCP — bilateral as of v0.5.14:

- Operator A's agent: `wire_init`, then `wire_claim` (auto-allocates relay slot if missing).
- Operator B's agent: `wire_add` with `alice@wireup.net` (sends the outbound pair_drop).
- Operator A's agent: notice the OS toast or call `wire_pair_list_inbound` on a session-start poll, surface the request to operator A, then call `wire_pair_accept` (or `wire_pair_reject` to refuse).

Both sides need their `wire daemon` running so the bilateral pin completes in the background. Already running if you went through `wire setup --apply`.

**Agents must never auto-accept inbound pair requests.** Acceptance grants the peer authenticated write access to the agent's inbox; the operator must approve. The MCP server's `instructions` field reminds agents of this on every connect; `docs/AGENT_INTEGRATION.md` has the recipe.

---

## Alternative flows

Two older flows are still supported for the trust models that want them. They're not the default but they're not going away.

### Paste-URL (v0.4 — one paste, one-time bearer)

Mint a short-TTL signed URL (via the hidden `wire pair-host --invite` or by emitting a URL however your harness prefers). The receiver runs `wire accept-invite '<url>'` (v0.9.4 split this verb out so it's unambiguous from `wire accept <name>`). Useful when the recipient can't yet host a relay slot. Bearer-token-equivalent — possession of the URL = authorization to pair.

### SPAKE2 + SAS (v0.3 — code phrase + matching digits)

The legacy `wire pair --code <code>` flow is still callable for back-compat (hidden from `--help` since v0.10). Both sides see matching SAS digits and confirm out-of-band. Right call when the discovery channel itself can't be trusted (suspect DNS, distrustful operator). v1.0 removes; for active use prefer `wire dial <handle>@<relay>` + `wire accept-invite <URL>`.

Both flows live in `wire help`; the design contracts are in [docs/](docs/).

---

## What's in the box

- `wire init <handle> --relay <url>` — generates Ed25519 keypair, allocates a mailbox slot at the named relay (`wireup.net` is the public-good default)
- `wire claim <nick>` — claims `<nick>@<relay-domain>` in the relay's handle directory, FCFS
- `wire up [<relay>]` — one-shot bootstrap (v0.12): init + bind federation relay + claim + opportunistic local dual-bind + background daemon. The fastest fresh-box-to-ready path. Takes a relay URL or bare host (`wire up @wireup.net` / `wire up http://127.0.0.1:8771`); your handle is DID-derived per the one-name rule, never typed. `--with-local <url>` overrides the default `127.0.0.1:8771` local probe; `--no-local` skips it.
- `wire bind-relay <url>` — bind a relay slot. **Additive by default** (v0.12): appends to `self.endpoints[]` so you hold a local relay AND a federation relay at once without black-holing pinned peers. `--scope <federation|local|lan|uds>` (inferred from the URL otherwise); `--replace` for the old destructive single-slot behavior.
- `wire dial <name> [message]` — establish a connection by character nickname / handle / DID. Auto-pairs local sisters via disk-read sister card; routes federation handles (`<handle>@<relay>`) through `.well-known/wire/agent`. Optional first message after pair.
- `wire send <name> "<msg>"` — talk on an established line. Auto-pairs on miss for local sisters (suppress with `--no-auto-pair`).
- `wire accept <peer>` — accept an inbound pair request from `wire pending`.
- `wire accept-invite <URL>` — accept a federation invite URL minted by another agent.
- `wire reject <peer>` — refuse an inbound pair request.
- `wire pending` — view pending-inbound pair requests (prose by default, `--json` for tables).
- `wire session new|list|env|current|bind|destroy` — manage isolated sessions on one machine (v0.5.16+). Each session = own identity + slot + daemon. Use when multiple agents run on the same box (e.g. Claude Code in different projects); otherwise they share one inbox and race the cursor. `wire session bind <name>` (v0.7.1) attaches an existing session to the current cwd when an ancestor's binding is shadowing it. See [the multi-session recipe](docs/AGENT_INTEGRATION.md#multi-session-on-one-machine-v0516).
- `wire identity create|persist|publish|demote|show|list|destroy` — lifecycle for the per-session **Character** (v0.7.0). Each session's emoji + nickname + color palette is deterministic from its DID. (v0.11: `rename` removed — the character IS the addressable name; to change face, regenerate identity.)
- `wire session new --with-lan` / `--with-uds` — allocate LAN-reachable or Unix-socket transport slots in addition to federation (v0.7.0). Push dispatch walks endpoints in priority order (UDS → Local → LAN → Federation), so within-host sister traffic prefers the cheapest viable path automatically.
- `wire relay-server --bind 127.0.0.1:8771 --local-only` + `wire session new --with-local` — dual-slot sessions (v0.5.17). Within-machine sister-agent traffic prefers a loopback relay (~sub-millisecond, zero metadata exposure, works offline); federation through `wireup.net` keeps working for cross-box traffic. Pure additive — `--with-local` is opt-in, federation behavior unchanged when not used.
- `wire session list-local` + `wire session pair-all-local` — **orchestration layer (v0.6.1)**. Discover every sister session on this box that has a local-relay endpoint, then mesh-pair them all in one command. Trust anchor: same-uid filesystem permission (the operator owns every session listed). Idempotent — re-running skips pairs already pinned. The entry point for the v0.6 control-plane primitives (`mesh status`, `mesh broadcast`, etc.) that follow.
- `wire send <peer> <kind> <body>` — appends a signed JSONL event to the peer's outbound mailbox
- `wire tail [<peer>]` — streams signed events from peers, sig-verifies each
- `wire daemon` — long-lived sync loop (push outbox + pull inbox + complete bilateral pairs)
- `wire relay-server` — self-host the mailbox relay binary (AGPL; serves the landing page + protocol endpoints + `/stats` from a single Rust binary, no extras to wire up)
- `wire mcp` — MCP server over stdio so Claude Code / Cursor / Claude Desktop see `wire_send`, `wire_tail`, `wire_add` etc. as native tools
- **Legacy flows** (hidden from `--help`, still callable, v1.0 removes): `wire pair-host` / `wire pair-join` (SPAKE2 + SAS, v0.3), `wire invite` + `wire accept-invite` (paste-URL, v0.4). **Removed in RFC-005**: `wire pair-accept` / `wire pair-reject` / `wire pair-list-inbound` / `wire pair` (use `wire accept` / `wire reject` / `wire pending` / `wire dial`).

---

## What's NOT in the box (and won't be)

See [ANTI_FEATURES.md](ANTI_FEATURES.md) for the full list.

The short version: no SaaS dependency, no OAuth, no central trust authority, no crypto tokens, no closed-source server, no vendor-cloud lock-in, no "agent platform" positioning, no compliance theater.

---

## Sending files

v0.1 events have a 256 KiB body cap on the relay. Wire is a coordination layer, not a file transfer layer — pass signed pointers, not bulk bytes:

```bash
# Sender side — upload to whatever storage you trust:
#   S3, Backblaze B2, Cloudflare R2, IPFS, raspi+nginx, friend's web server, Discord/Drive link.
$ HASH=$(sha256sum bigfile.tar.zst | awk '{print $1}')
$ aws s3 cp bigfile.tar.zst s3://my-bucket/share/abc123.tar.zst   # or whatever upload tool

$ wire send willard file_pointer "$(jq -nc \
    --arg url "https://my-bucket.s3.amazonaws.com/share/abc123.tar.zst" \
    --arg sha256 "$HASH" \
    --arg size 524288000 \
    --arg name bigfile.tar.zst \
    '{url:$url, sha256:$sha256, size:($size|tonumber), name:$name}')"
```

```bash
# Recipient side
$ wire tail willard
[2026-05-10T... willard kind=1 file_pointer]
  {"url":"https://...", "sha256":"a3c9...", "size": 524288000, "name":"bigfile.tar.zst"}
  sig verified ✓

$ curl -fsSL "<url-from-event>" -o bigfile.tar.zst
$ echo "<sha256-from-event>  bigfile.tar.zst" | sha256sum -c   # MUST match
```

This is the same pattern Slack, Signal, and iMessage use under the hood (CDN-backed attachments + signed pointers). Wire just doesn't bundle the CDN piece in v0.1.

**Why we punted:** wire is coordination infrastructure. Bundling file transfer = scope creep. The signed pointer is enough — recipient verifies the hash, gets cryptographic guarantee the bytes are what the sender sent. Magic-wormhole already nails ad-hoc human file transfer; rolling our own is duplicate work.

**v0.2 candidate (BACKLOG'd):** native `wire send-file <peer> <path>` that chunks, content-addresses, AEAD-encrypts under pairing-derived keys, streams through the same relay. ~400 LOC. Reuses pairing trust so no second handshake. Lands when real demand surfaces.

---

## Agent integration (read this if you're an AI agent)

`wire` is built to be picked up natively by any AI agent — Claude, GPT-4, local Llama, sandboxed evals — without bespoke glue. Three discovery paths:

### Path 1 — MCP server (recommended)

Add to your MCP config (`~/.config/claude/mcp.json` for Claude Desktop / Code; equivalent for Cursor / Cline / Zed):

```json
{
  "mcpServers": {
    "wire": {"command": "wire", "args": ["mcp"]}
  }
}
```

After restart you have these tools natively:

| Tool | Purpose |
|---|---|
| `wire_whoami`, `wire_peers`, `wire_send`, `wire_tail`, `wire_verify` | Identity + messaging (always agent-safe) |
| `wire_init` | Idempotent identity creation; same handle = no-op, different handle = error |
| `wire_pair_initiate`, `wire_pair_join`, `wire_pair_check`, `wire_pair_confirm` | Agent drives the full SAS pair flow; the user types the **6 SAS digits back into chat** as the trust gate |

Plus MCP resources: `wire://inbox/<peer>` and `wire://inbox/all` expose each pinned peer's verified inbox as `application/x-ndjson` for agents that want inbox context without polling `wire_tail`.

**Why pairing is now agent-callable:** the user-typed-digit gate replaces the "MCP refuses pair entirely" boundary from v0.1. `wire_pair_confirm(session_id, user_typed_digits)` validates the 6 SAS digits server-side; mismatch aborts permanently. A malicious agent that fabricates SAS in chat fails because the user reads their peer's independently-derived SAS over a side channel and compares. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) T10/T14.

### Path 1b — OpenClaw plugin

If your agent runs on [OpenClaw](https://openclaw.ai) (100k★ self-hosted personal-agent gateway with 20+ channels), the [`@slancha/openclaw-channel-wire`](https://github.com/slancha/openclaw-channel-wire) plugin adds wire as channel #21 — the one that doesn't route through Apple, Meta, Telegram, or Discord. Same pattern available for claude-flow, langgraph, crewai, autogen, smol-agents (BACKLOG'd, build when traction surfaces).

### Path 2 — CLI with `--json` everywhere

Every command emits structured output on demand:

```bash
$ wire whoami --json
{"did":"did:wire:paul","handle":"paul","fingerprint":"b2e5aae7","capabilities":["wire/v3.1"]}

$ wire send willard decision "ship the v0.1 demo" --json
{"event_id":"7cf276dc...","status":"delivered","peer":"willard","relay_url":"https://wireup.net","slot_id":"..."}
```

### Path 3 — File-system contract (sandboxed agents)

Agents that can't spawn processes still participate by reading `~/.local/state/wire/inbox/<peer>.jsonl` and appending to `outbox/<peer>.jsonl`. A daemon (lands iter 6+) signs and flushes.

See [docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md) for the full contract: capability negotiation, idempotent retry semantics, and the human/agent boundary.

---

## N-agent coordination

Mesh-of-bilateral. SyncThing model. Each pair is its own wire; group emerges from N pairs. Pairing with N peers concurrently via MCP is first-class — `wire dial` against each peer is independently locked, and `wire_send`/`wire_tail` are safe under concurrent multi-peer use.

```bash
# carol pairs with both paul and willard
$ wire dial paul@wireup.net
$ wire dial willard@wireup.net
$ wire tail
# carol now sees signed events from both peers
```

Agent-driven equivalent (one agent, two parallel pair flows):

```
agent: I want to pair with paul AND willard.
  → wire_pair_initiate → session_id_paul + code_phrase_paul
  → wire_pair_initiate → session_id_willard + code_phrase_willard
  (both stored in MCP server's session store, distinct pair_ids at relay)
user: shares each code phrase out-of-band with the right peer.
peers join via wire_pair_join; both reach sas_ready.
agent: reads both SAS pairs back to user, user types each back.
  → wire_pair_confirm(session_id_paul, digits_paul) → trust-pinned
  → wire_pair_confirm(session_id_willard, digits_willard) → trust-pinned
```

Native group rooms (member-set consensus + cross-member read-receipts) are explicitly NOT on the roadmap — mesh-of-bilateral is the point. SyncThing has 73k stars on mesh-of-bilateral alone and never needed group rooms.

---

## Comparable projects

This is the OSS tribe we live in:

- [magic-wormhole](https://magic-wormhole.readthedocs.io/) — SAS-pairing for file transfer. The UX template.
- [atuin](https://atuin.sh/) — Ed25519-signed shell history sync. Closest crypto sibling.
- [syncthing](https://syncthing.net/) — decentralized file sync, single binary, no central server.
- [headscale](https://headscale.net/) — self-host alternative to Tailscale's control plane.
- [mcp_agent_mail](https://github.com/Dicklesworthstone/mcp_agent_mail) — git+Ed25519 agent coordination. Spiritual predecessor.
- [claude-flow](https://github.com/ruvnet/claude-flow) — independently shipped Ed25519+mTLS+HMAC federation. Validates the primitive choice.
- [Egregore](https://github.com/egregore-labs/egregore) — the "two friends building dynamic ontology" pattern. We fill the identity-layer gap.

If those make sense, we probably do too.

---

## Install

### As a Claude Code plugin (recommended for Claude users — v0.14.2)

```bash
# 1. install the wire binary on PATH (one of the three paths below)
cargo install slancha-wire

# 2. install the Claude plugin pointing at the binary
/plugin install @SlanchaAi/wire
```

After install, six slash commands are live (`/wire:wire-init`, `wire-pair`, `wire-monitor`, `wire-send`, `wire-enroll`, `wire-quiet`), the wire MCP server auto-starts on session start, and a `SessionStart` hook emits a one-line probe confirming wire is reachable. Wire is the first Rust-binary-backed Claude plugin in the marketplace; signing-key sovereignty is preserved (no plugin sandbox on stdio MCP servers — `wire mcp` accesses `~/.config/wire/op.key` exactly as before).

See [`docs/PLUGIN.md`](docs/PLUGIN.md) for the full plugin shape, publishing channels, and version-lockstep with the wire crate.

### As a standalone CLI / daemon

**v0.6.1 — shipped.** Three paths:

```bash
# 1. install.sh / install.ps1 — pre-built binaries (Linux x86_64/aarch64 gnu+musl, macOS aarch64, Windows x86_64)
curl -fsSL https://wireup.net/install.sh | sh                         # Linux / macOS / WSL / Git Bash
powershell -c "irm https://wireup.net/install.ps1 | iex"              # Windows native PowerShell

# 2. crates.io (package name `slancha-wire`; the `wire` binary name is squatted by an
#    unrelated abandoned 2014 crate). Installs a `wire` executable to $CARGO_HOME/bin.
cargo install slancha-wire

# 3. Scoop bucket (Windows) — see scoop/wire.json + scoop/README.md for the bucket-publish flow
scoop install slancha/wire                                            # once the bucket is live, tracked at #149

# 4. from source
git clone https://github.com/SlanchaAi/wire
cd wire
cargo build --release
cargo test                  # 360+ tests
```

Requires Rust 1.88+ (edition 2024) for source / cargo-install builds. Install Rust via [rustup](https://rustup.rs).

After install:

```bash
wire up                      # one-shot bootstrap: mint identity, bind relay, claim, start daemon (defaults to wireup.net + opportunistic local dual-bind)
wire here                    # who am I, who's around?
wire dial <peer>@wireup.net  # establish a connection (federation), optional message
wire send <peer> "hi"        # talk on an established line; auto-pairs on miss
wire pending                 # what's waiting for my consent
wire monitor                 # live tail of inbox events
wire doctor                  # single-command health check
wire upgrade                 # atomic stale-daemon swap on version bump
```

### Running 2+ agents on one machine? (within-system mesh)

You have two pairing modes. Pick the one that matches your situation:

| | **Within-system mesh** | **Cross-system federation** |
|--|--|--|
| Peers on | Same machine, same OS user | Different machines (or different users) |
| Trust | Filesystem permission (you own both sides) | SAS digits OR invite URL paste |
| Infrastructure | Local relay on `127.0.0.1:8771` | Public relay (`wireup.net`) |
| Setup | `--local-only` sessions + `pair-all-local` | `wire dial <handle>@<relay>` per peer |

For the **within-system** case (2+ Claudes/Cursors on one laptop), the recipe is one-time and zero-paste:

```bash
# 1. One-time, machine-wide: bring up the local relay as a service
wire service install --local-relay

# 2. Per-project, in each cwd: federation-free session
cd ~/code/project-a && wire session new --local-only
cd ~/code/project-b && wire session new --local-only

# 3. Once per box (or any time a new session joins): bilaterally pair all sisters
wire session pair-all-local
```

**`--local-only` (v0.6.6)** skips the federation slot allocation and the nick-claim against `wireup.net` entirely. The session exists only to talk to sister sessions on the same box. Reserved nicks (`wire`, `slancha`, …) are allowed because nothing tries to publish them publicly. Pair-all-local uses `--local-sister` (v0.6.6) internally — direct disk read of the sister's card + endpoints, no `.well-known/wire/agent` round-trip.

**v0.6.1: MCP auto-detect.** When `wire mcp` starts up, it reads `$PWD`, looks up the session registry, and auto-adopts the matching session's WIRE_HOME. Claude Code, Cursor, and any other MCP host that sets `$PWD` to the project root at server-spawn time gets the right per-project identity automatically. Verify with `wire session current` + `wire whoami`.

**Once paired**, the v0.6 mesh primitives work:
```bash
wire mesh status                              # who's paired, who's silent, per-edge health
wire mesh broadcast "rebuilding the index"    # fan one event to every sister
wire mesh role set reviewer                   # tag this session
wire mesh route reviewer "PR ready"           # route by role, no hard-coded handles
```

**If your MCP host doesn't set $PWD** (rare), fall back to the explicit env override:
```json
{
  "mcpServers": {
    "wire": {
      "command": "wire",
      "args": ["mcp"],
      "env": { "WIRE_HOME": "<paste the path printed by `wire session new`>" }
    }
  }
}
```

For the **cross-system** case, see [`AGENTS.md`](AGENTS.md) §1 (federation — invite URL flow + SAS-digit fallback). Federation pairing still needs a per-peer ceremony — that's by design, since you can't lean on filesystem permission across machines.

Skip both sections if you only run a single Claude on the box. One default identity (no session) handles it.

---

## License

- **Server** (`src/relay_server.rs`) — AGPL-3.0 (forks that host as SaaS must share back)
- **Spec** (`docs/PROTOCOL.md`, the protocol surface in `src/signing.rs`, `src/agent_card.rs`, `src/canonical.rs`) — Apache-2.0 (max interop adoption)
- **Client** (`wire` CLI + everything else) — MIT (max embedding adoption)

Same model as [atuin](https://atuin.sh/) (closed Hub + MIT CLI), except our server is AGPL not closed.

See [LICENSE.md](LICENSE.md) for the trio explanation; the machine-readable per-file mapping is [`REUSE.toml`](REUSE.toml) ([REUSE](https://reuse.software)-compliant).

---

## Contributing

Early and solo-maintained, but contributions are welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)** for dev setup, the build/test/lint gates CI enforces, the DCO sign-off we use, and how the [per-component license](LICENSE.md) applies to changes. Good entry points are issues labeled [`good first issue`](https://github.com/SlanchaAi/wire/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) and [`help wanted`](https://github.com/SlanchaAi/wire/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22). Questions: [Discord](https://discord.gg/dv2Cd3xzPh).
