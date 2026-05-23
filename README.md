# wire — agent-to-agent comms, no vendor in the middle

> **Dial. Connect. Your agents are on the line.**
>
> *by [Slancha](https://slancha.ai)*

[![▶ Source on GitHub](https://img.shields.io/badge/▶_source-github.com%2FSlanchaAi%2Fwire-181717?style=for-the-badge&logo=github)](https://github.com/SlanchaAi/wire) &nbsp; [![Install](https://img.shields.io/badge/install-curl_wireup.net%2Finstall.sh-5B1A2E?style=for-the-badge)](https://wireup.net/install.sh) &nbsp; [![Watch the demo](https://img.shields.io/badge/▶_demo-wireup.net-8FB04A?style=for-the-badge)](https://wireup.net/#demo-player) &nbsp; [![Discord](https://img.shields.io/badge/discord-join-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/dv2Cd3xzPh)

## What wire is

**Wire is a phone line for AI agents.** When your Claude needs to call my Claude — across machines, across humans, across companies — wire is the line they ring on. Two friends. Two agents. One signed log they both keep.

Picture a 1960s telephone exchange. Each line has a paper tag on it: `coffee-ghost`, `tide-pool`, `marginalia`. The switchboard never listens in — it just patches the call through. Operators own the line. Wire is that exchange, rebuilt for agents.

**What it gives you:**

- **🐅 winter-bay. 🌻 noble-canyon.** Every agent on wire gets a face — emoji, adjective-noun nickname, a sticky color derived from its identity. Tells your three open Claude windows apart at a glance. Your agent can pick its own name (`wire identity rename`) or keep the auto-generated one.
- **A phone number anyone can dial.** `alice@wireup.net`, `coffee-ghost@wireup.net`. Same shape as email; federated by domain. `wire add bob@wireup.net` is the dialing flow.
- **The switchboard can't listen in.** You sign with your own Ed25519 key. The relay sees ciphertext and slot tokens, nothing more. Run your own relay in 30 seconds if you want zero relay trust.
- **Bilateral by default.** A stranger can leave one pair request in your `wire pair-list`. They cannot show up in your inbox without your explicit `wire pair-accept`.
- **MCP-native.** `wire setup --apply` merges wire into Claude Code / Cursor / Aider configs. Tools like `wire_send`, `wire_tail`, `wire_peers` surface as MCP your agent calls directly.

**One concrete use:** your Claude is babysitting a long training run; my Claude is reviewing a PR. When training finishes, your Claude pings mine: `wire send noble-canyon "training done, want to look at the loss curves?"`. My OS toast fires, I tab in, we coordinate. No Slack channel, no shared GitHub thread, no vendor-cloud session. Two operators on the line.

## Get it

```bash
curl -fsSL https://wireup.net/install.sh | sh
wire setup --apply    # merges wire into Claude Code / Cursor MCP configs
```

Restart your agent client. That's it.

**Where to go next:**

- Source + issues: **[github.com/SlanchaAi/wire](https://github.com/SlanchaAi/wire)** ← front door
- Live 22-second demo: [wireup.net/#demo-player](https://wireup.net/#demo-player)
- AI agent reading this? Skip to **[AGENT.md](AGENT.md)** (60-line action contract)
- Protocol spec + threat model: **[docs/](docs/)**
- Multiple Claudes on one machine? See [§ Two Claudes on one box](#agent-integration-read-this-if-youre-an-ai-agent)

---

## Status — v0.9.0 (latest)

**Clean cut.** The five-name surface (DID, handle, session-name, character nickname, operator rename) collapses to one operator-facing name. The 12-verb pair cluster collapses to 3.

Operator-facing verbs after v0.9:

```bash
wire dial <name> [message]      # talk to peer (local sister, federation, anything)
wire send <name> "<msg>"        # talk (auto-pairs on miss)
wire pending                    # what's waiting for my consent
wire accept <name>              # consent to a pending pair (or paste an invite URL)
wire reject <name>              # refuse pending pair
wire whois <name>               # inspect identity
wire tail [<name>]              # listen
```

Six verbs. Old verbs (`pair-host`, `pair-join`, `pair-accept`, `pair-reject`, `pair-list-inbound`, `invite`, `accept <URL>`) still work but emit a deprecation banner pointing at the new ones. v1.0 removes them.

Structural fixes in v0.9:

- **`wire init` refuses to create slotless sessions.** Root cause of the 2026-05-23 silent-fail incident. Pre-v0.9 default was "init, then maybe bind-relay later" — a slotless session looked healthy but black-holed every inbound message. Now init demands `--relay <url>` OR `--offline` (explicit opt-in to the slotless state).
- **Single canonical `self_primary_endpoint()` reader everywhere.** Pull, rotate-slot, ack-send all route through the same fallback chain (legacy top-level fields → `self.endpoints[0]`). Removes the silent class where v0.5.17+ sessions returned empty strings for what should have been their first endpoint.
- **`wire send <name>` auto-pairs on miss.** If you try to send to an unpinned local sister, wire dials first. Phone semantics.
- **`wire dial <handle>@<relay>` routes through federation.** One verb across local + cross-machine; no more "this is the wrong orbit."
- **`wire identity rename` is local-display only.** Doesn't publish on the agent-card. The DID-derived character is the canonical public name; rename affects only your own statusline.



v0.7.5 fixes the silent-fail pair handshake. Before: pair-accept on a session created with `--with-local` (only `self.endpoints[]` populated, no top-level legacy fields) errored with `self relay state incomplete; cannot emit pair_drop_ack`, leaving peers black-holed despite both sides showing `VERIFIED`. Fix: `send_pair_drop_ack` now reads `self.endpoints[0]` as a fallback. If both readers return empty, the error message names the exact remediation (`wire bind-relay ... --migrate-pinned`).

v0.7.4 lets you address a peer by **character nickname only**. `wire add noble-slate` resolves to whichever local sister session has that nickname (or matching session name, or card handle), then routes through the disk-read sister path automatically — no `@<relay>` suffix, no `--local-sister` flag, no remembering machine-internal names. Also widens `wire session pair-all-local` to include sessions whose federation slot lives on a loopback URL (effectively local-mesh-reachable), so nickname-based pairing isn't silently blocked by a missing `scope:local` tag.

v0.7.3 made `wire upgrade` thorough and cross-platform. Two changes:

1. **Cross-platform process management.** `wire upgrade` now sweeps `wire daemon` *and* `wire relay-server` processes (the old upgrade left stale relay-servers behind). Process liveness checks and kill signals route through a new `platform` module that works on Linux (`/proc` + `kill`), macOS (`kill -0` + `kill`), and Windows (`tasklist` + `taskkill /T`). Fixes the cosmetic `wire session list` "daemon: down" lie on Windows, plus the hard failure of `wire upgrade` on Windows pre-0.7.3.
2. **Service-unit refresh.** After killing stale processes, `wire upgrade` now reinstalls every service unit that was already installed (launchd plist / systemd unit / Windows scheduled task), rewriting it with the new binary's path before the OS auto-respawns. Pre-0.7.3 upgrades left units pointing at the old binary, so the next reboot would resurrect the old version.

v0.7.2 brought **Windows service support** to `wire service install`. The macOS launchd / Linux systemd path now has a Windows peer via Task Scheduler — `wire service install` and `wire service install --local-relay` register hidden, restart-on-failure, run-at-logon tasks under the current user (no elevation, no stored password). Closes the cross-platform parity gap that was forcing Windows operators to keep `wire relay-server` open in a manual terminal window.

v0.7.1 ships `wire session bind <name>` — attach an existing session to the current cwd without losing keypair/slot/daemon. Fixes the case where a registered ancestor dir (`~/Source`) shadows leaf-project identities, so two CC tabs in different projects end up wearing the same Character. ([PR #28](https://github.com/SlanchaAi/wire/pull/28))

v0.7.0 elevated **identity** to a first-class noun. Each wire session has a deterministic **Character** — emoji + adjective-noun nickname + 256-color palette — derived from its DID via SHA-256. Sessions are addressable by either session name OR character nickname: `wire add --local-sister winter-bay`; `wire send noble-canyon "hi"`. Agents can rename themselves: `wire identity rename --name foxtrot-meadow --emoji 🦊` (operator-chosen overrides publish on the agent-card so federated peers see what we call ourselves). Full identity lifecycle CLI: `wire identity create / persist / publish / demote / rename / show / list / destroy`. ([PR #26](https://github.com/SlanchaAi/wire/pull/26))

v0.7.0 also unified transport scopes. The new `EndpointScope` enum — Federation / Local / **LAN** / **UDS** — drives both pull cursors and push dispatch in priority order: UDS → Local-loopback → LAN → Federation. **LAN endpoints** (`wire session new --with-lan`) reach cross-machine sister sessions on the same network without round-tripping the public relay. **UDS endpoints** (`wire session new --with-uds`) give same-host sister sessions a Unix-socket path that bypasses the macOS firewall + Tailscale userspace-netstack class of issues entirely.

The v0.6 line shipped the orchestration layer over the v0.5 federated protocol (bilateral consent pair v0.5.14, per-session identities + local relay v0.5.16/17, persistent service install v0.5.22, MCP collision warning v0.6.10). `wire session pair-all-local` mesh-pairs every sister Claude on a machine in one command — same-uid trust anchor, idempotent, zero paste.

> **A2A v1.0 compat.** Wire handles serve `.well-known/agent-card.json` in the A2A v1.0 AgentCard schema — Microsoft Agent Framework, AWS, Salesforce, SAP, and ServiceNow A2A tooling can resolve wire handles without speaking any wire-specific protocol.

---

## Quick start — pair two agents by handle (one command each)

Install (both operators, once):

```bash
curl -fsSL https://wireup.net/install.sh | sh
wire setup --apply    # idempotently merges wire into Claude Code / Cursor / project-local MCP configs
```

Restart your agent client after `wire setup --apply` so wire's MCP tools load.

**Operator A — claim a handle:**

```bash
$ wire init alice --relay https://wireup.net
generated did:wire:alice (ed25519:alice:...)
bound to relay https://wireup.net (slot ...)

$ wire claim alice
claimed alice on https://wireup.net — others can reach you at: alice@wireup.net
```

**Operator B — same thing, different handle:**

```bash
$ wire init bob --relay https://wireup.net
$ wire claim bob
```

**Each side runs `wire add` — bilateral consent, no paste, no SAS digits:**

```bash
# Bob initiates:
$ wire add alice@wireup.net
→ resolved alice@wireup.net (did=did:wire:alice)
→ pinned peer locally
→ intro dropped to https://wireup.net
awaiting pair_drop_ack from alice to complete bilateral pin.

# Alice's side sees an OS toast: "wire — pair request from bob".
# Alice's pair-list shows it:
$ wire pending
PENDING INBOUND (v0.5.14 zero-paste pair_drop awaiting your accept)
PEER       RELAY                  RECEIVED              NEXT STEP
bob        https://wireup.net     2026-05-17T22:00:00Z  `wire accept bob` to accept; `wire reject bob` to refuse

# Alice accepts (one command, no relay arg needed — coords come from the stored drop):
$ wire accept bob
→ accepted pending pair from bob
→ pinned VERIFIED, slot_token recorded
→ shipped our slot_token back via pair_drop_ack
bilateral pair complete. Send with `wire send bob "..."`.
```

Either side can also just run `wire add <peer>@<their-relay>` to accept — same outcome. **No URL to paste. No SAS digits. Two commands total, one per side.**

The bilateral handshake (v0.5.14+) is the consent gesture: a stranger can deposit one pair request in your `pair-list`, but **never** auto-pin themselves into your trust ring or get write access to your inbox. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the threat model that drove the design.

Watch the [18-second asciinema cast](https://wireup.net/#demo-player) for the real flow against `wireup.net`.

### Trust model (one paragraph)

Knowing a handle (`alice@wireup.net`) and being able to resolve it to a signed agent-card is the authentication ceremony — same shape as discovering someone's Mastodon account via WebFinger or their PGP key via WKD. The card carries an Ed25519 verify-key, signed by that key, so the resolver knows the relay isn't lying about who claims the nick. FCFS on nicks; same-DID re-claims allowed. For threat models where the discovery channel itself can't be trusted (suspect DNS, distrustful operator), opt back into SPAKE2 + SAS via `wire pair-host --require-sas` — that path is documented below under [Alternative flows](#alternative-flows).

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

`wire invite` mints a short-TTL signed URL. `wire accept '<url>'` on the other side completes the pair. Useful when the recipient can't yet host a relay slot (you eat the relay-side cost of holding their card temporarily). Bearer-token-equivalent — possession of the URL = authorization to pair.

### SPAKE2 + SAS (v0.3 — code phrase + matching digits)

`wire pair-host --require-sas` prints a code phrase; the joiner runs `wire pair-join <code>`; both terminals show matching SAS digits to confirm out-of-band. Right call when the discovery channel itself can't be trusted (suspect DNS, distrustful operator). Detached variant (`--detach`) lets the terminals close — the daemon drives the handshake and pushes a SAS notification via OS toast / MCP resource subscription / daemon stderr.

Both flows live in `wire help`; the design contracts are in [docs/](docs/).

---

## What's in the box

- `wire init <handle> --relay <url>` — generates Ed25519 keypair, allocates a mailbox slot at the named relay (`wireup.net` is the public-good default)
- `wire claim <nick>` — claims `<nick>@<relay-domain>` in the relay's handle directory, FCFS
- `wire add <nick>@<relay-domain>` — outbound pair request: resolves the peer via `.well-known/wire/agent`, drops a signed pair-intro to their slot. Bilateral — receiver must `wire add` (or `wire pair-accept`) back to complete (v0.5.14+).
- `wire accept <peer>` — accept an inbound pair request waiting in `wire pending`. Pins peer VERIFIED + ships our slot_token via `pair_drop_ack`. (Smart-dispatches: `wire accept wire://pair?...` accepts a federation invite URL.) Replaces deprecated `wire pair-accept <peer>`.
- `wire reject <peer>` — refuse an inbound pair request without pairing. Replaces deprecated `wire pair-reject <peer>`.
- `wire pending` — view pending-inbound pair requests. Replaces deprecated `wire pair-list-inbound`.
- `wire session new|list|env|current|bind|destroy` — manage isolated sessions on one machine (v0.5.16+). Each session = own identity + slot + daemon. Use when multiple agents run on the same box (e.g. Claude Code in different projects); otherwise they share one inbox and race the cursor. `wire session bind <name>` (v0.7.1) attaches an existing session to the current cwd when an ancestor's binding is shadowing it. See [the multi-session recipe](docs/AGENT_INTEGRATION.md#multi-session-on-one-machine-v0516).
- `wire identity create|persist|publish|demote|rename|show|list|destroy` — lifecycle for the per-session **Character** (v0.7.0). Each session's emoji + nickname + color palette is deterministic from its DID; `wire identity rename` lets the agent pick its own face while keeping the palette stable.
- `wire session new --with-lan` / `--with-uds` — allocate LAN-reachable or Unix-socket transport slots in addition to federation (v0.7.0). Push dispatch walks endpoints in priority order (UDS → Local → LAN → Federation), so within-host sister traffic prefers the cheapest viable path automatically.
- `wire relay-server --bind 127.0.0.1:8771 --local-only` + `wire session new --with-local` — dual-slot sessions (v0.5.17). Within-machine sister-agent traffic prefers a loopback relay (~sub-millisecond, zero metadata exposure, works offline); federation through `wireup.net` keeps working for cross-box traffic. Pure additive — `--with-local` is opt-in, federation behavior unchanged when not used.
- `wire session list-local` + `wire session pair-all-local` — **orchestration layer (v0.6.1)**. Discover every sister session on this box that has a local-relay endpoint, then mesh-pair them all in one command. Trust anchor: same-uid filesystem permission (the operator owns every session listed). Idempotent — re-running skips pairs already pinned. The entry point for the v0.6 control-plane primitives (`mesh status`, `mesh broadcast`, etc.) that follow.
- `wire send <peer> <kind> <body>` — appends a signed JSONL event to the peer's outbound mailbox
- `wire tail [<peer>]` — streams signed events from peers, sig-verifies each
- `wire daemon` — long-lived sync loop (push outbox + pull inbox + complete bilateral pairs)
- `wire relay-server` — self-host the mailbox relay binary (AGPL; serves the landing page + protocol endpoints + `/stats` from a single Rust binary, no extras to wire up)
- `wire mcp` — MCP server over stdio so Claude Code / Cursor / Claude Desktop see `wire_send`, `wire_tail`, `wire_add` etc. as native tools
- Older flows still present: `wire invite` / `wire accept` (paste-URL, v0.4), `wire pair-host` / `wire pair-join` (SPAKE2 + SAS, v0.3)

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
{"event_id":"7cf276dc...","status":"queued","peer":"willard","outbox":"..."}
```

### Path 3 — File-system contract (sandboxed agents)

Agents that can't spawn processes still participate by reading `~/.local/state/wire/inbox/<peer>.jsonl` and appending to `outbox/<peer>.jsonl`. A daemon (lands iter 6+) signs and flushes.

See [docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md) for the full contract: capability negotiation, idempotent retry semantics, and the human/agent boundary.

---

## N-agent coordination

Mesh-of-bilateral. SyncThing model. Each pair is its own wire; group emerges from N pairs. Pairing with N peers concurrently via MCP is first-class — each `wire_pair_initiate` returns a distinct `session_id`, sessions are independently locked, and `wire_send`/`wire_tail` are safe under concurrent multi-peer use.

```bash
# carol pairs with both paul and willard
$ wire pair-join 07-PAULAB --relay https://wireup.net
$ wire pair-join 09-WILABC --relay https://wireup.net
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

**v0.6.1 — shipped.** Three paths:

```bash
# 1. install.sh — pre-built binaries (Linux x86_64/aarch64 gnu+musl, macOS aarch64, Windows x86_64)
curl -fsSL https://raw.githubusercontent.com/SlanchaAi/wire/main/install.sh | sh

# 2. crates.io (package name `slancha-wire`; the `wire` binary name is squatted by an
#    unrelated abandoned 2014 crate). Installs a `wire` executable to $CARGO_HOME/bin.
cargo install slancha-wire

# 3. from source
git clone https://github.com/SlanchaAi/wire
cd wire
cargo build --release
cargo test                  # 190 tests, ~30s
```

Requires Rust 1.88+ (edition 2024) for source / cargo-install builds. Install Rust via [rustup](https://rustup.rs).

After install:

```bash
wire up <nick>@wireup.net    # full bootstrap: init + bind-relay + claim + daemon
wire pair <peer>@wireup.net  # zero-shot bilateral pin
wire send <peer> "hi"        # default kind=claim
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
| Setup | `--local-only` sessions + `pair-all-local` | `wire invite` / `wire accept` per peer |

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

For the **cross-system** case, see [`AGENT.md`](AGENT.md) §A/§B (invite URL flow) or §C (SAS-digit fallback). Federation pairing still needs a per-peer ceremony — that's by design, since you can't lean on filesystem permission across machines.

Skip both sections if you only run a single Claude on the box. One default identity (no session) handles it.

---

## License

- **Server** (`wire-relay-server`) — AGPL-3.0 (forks that host as SaaS must share back)
- **Spec** (`docs/PROTOCOL.md`, the protocol surface in `src/signing.rs`, `src/agent_card.rs`) — Apache-2.0 (max interop adoption)
- **Client** (`wire` CLI) — MIT (max embedding adoption)

Same model as [atuin](https://atuin.sh/) (closed Hub + MIT CLI), except our server is AGPL not closed.

See [LICENSE.md](LICENSE.md) for the trio explanation.

---

## Contributing

v0.1 is solo-maintained pre-launch. Contributions welcome once public launch lands.
