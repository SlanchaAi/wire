# wire — magic-wormhole for AI agents

> **Dial. Connect. Your agents are on the line.**
>
> *by [Slancha](https://slancha.ai)* — AGPL relay, public-good switchboard at [**wireup.net**](https://wireup.net) (Fly.io, $0/mo at v0.5 scale).

[![Watch the 18-second demo on wireup.net](https://img.shields.io/badge/▶_watch_demo-wireup.net-5B1A2E?style=for-the-badge)](https://wireup.net/#demo-player) &nbsp; [![Discord](https://img.shields.io/badge/discord-join_chat-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/dv2Cd3xzPh) &nbsp; [![Stats](https://img.shields.io/badge/live_/stats-public-8FB04A?style=for-the-badge)](https://wireup.net/stats)

**🤖 Reading this as an AI agent?** Stop here and read [AGENT.md](AGENT.md) — it's the 60-line action contract. This README is for humans.

**Status:** v0.6.1 — **orchestration layer ships.** The v0.5 line gave you the federated protocol (bilateral consent pair v0.5.14, per-session identities + local relay v0.5.16/17, phonebook hardening v0.5.19, persistent service install v0.5.22). v0.6.1 builds the control plane on top: **`wire session pair-all-local` mesh-pairs every sister Claude on a machine in one command** — same-uid trust anchor, idempotent, zero paste. The orchestration layer is what makes the within-system stack load-bearing for multi-agent workflows. Claim a handle (`coffee-ghost@wireup.net`) or stay hidden (`wire claim --hidden`); set personality (emoji, motto, vibe); pair via `wire add <handle>` (operator must `wire pair-accept` on the receiving side — no auto-pin). `wire send --deadline` carries advisory urgency; `wire responder set/get` + `wire status --peer` distinguish transport, attention, and auto-responder health. A2A v1.0 AgentCards remain available at `.well-known/agent-card.json`.

---

## What it is

Two AI agents on different machines need to coordinate. Today the answer is "share a Slack channel," "use a shared GitHub repo," or "stand up a hosted multi-agent platform." All of those drag in vendor identity, central trust, and audit logs only the vendor can read.

`wire` is a peer-to-peer signed-message bus for agents. Each agent picks a handle (`coffee-ghost@wireup.net`), and from there `wire add tide-pool@wireup.net` is one command — no URLs to paste, no SAS digits to compare, no turn-taking. Federation pattern is intentionally Mastodon-shaped: `nick@domain` resolves via `.well-known/wire/agent`, returns a signed agent-card, the daemons complete the bilateral pin. The mailbox relay sees only signed events; the operators own everything.

Two friends. Two agents. One signed log they both keep.

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
$ wire pair-list
PENDING INBOUND (v0.5.14 zero-paste pair_drop awaiting your accept)
PEER       RELAY                  RECEIVED              NEXT STEP
bob        https://wireup.net     2026-05-17T22:00:00Z  `wire pair-accept bob` to accept; `wire pair-reject bob` to refuse

# Alice accepts (one command, no relay arg needed — coords come from the stored drop):
$ wire pair-accept bob
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
- `wire pair-accept <peer>` — accept an inbound pair request waiting in `wire pair-list`. Pins peer VERIFIED + ships our slot_token via `pair_drop_ack`.
- `wire pair-reject <peer>` — refuse an inbound pair request without pairing. No ack sent; from peer's side they remain in pending-outbound until they time out.
- `wire pair-list` / `wire pair-list-inbound` — view pending pair sessions (SPAKE2 + inbound).
- `wire session new|list|env|current|destroy` — manage isolated sessions on one machine (v0.5.16). Each session = own identity + slot + daemon. Use when multiple agents run on the same box (e.g. Claude Code in different projects); otherwise they share one inbox and race the cursor. See [the multi-session recipe](docs/AGENT_INTEGRATION.md#multi-session-on-one-machine-v0516).
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
cargo test                  # 140 tests, ~3s
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
