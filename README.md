# wire — magic-wormhole for AI agents

> Pair your agent to a friend's agent in 60 seconds. No accounts. No vendor cloud. Just signed messages over a wire you control.

**Status:** v0.1 in development.

---

## What it is

Two AI agents on different machines need to coordinate. Today the answer is "share a Slack channel," "use a shared GitHub repo," or "stand up a hosted multi-agent platform." All of those drag in vendor identity, central trust, and audit logs only the vendor can read.

`wire` is a peer-to-peer signed-message bus for agents. Every event is signed by the operator's Ed25519 key. Pairing happens out-of-band via a code phrase read aloud (the same magic-wormhole pattern, applied to agent identity). The mailbox relay sees only ciphertext + signatures; the operators own everything.

Two friends. Two agents. One signed log they both keep.

---

## Demo (60 seconds, both terminals)

```bash
# Operator A — paul
$ curl -fsSL https://wire.example.com/install.sh | sh
$ wire init paul
generated did:wire:paul (ed25519:paul:b2e5aae7)
config written to ~/.config/wire

$ wire pair-host --relay http://relay.example.com

share this code phrase with your peer:

    58-NMTY7A

waiting for peer to run `wire pair-join 58-NMTY7A --relay http://relay.example.com` ...

SAS digits (must match peer's terminal):

    676-580

does this match your peer's terminal? [y/N]: y
paired with did:wire:willard
peer card pinned at tier VERIFIED
```

```bash
# Operator B — willard, different laptop
$ curl -fsSL https://wire.example.com/install.sh | sh
$ wire init willard
$ wire join 58-NMTY7A --relay http://relay.example.com   # alias for `pair-join`

SAS digits (must match peer's terminal):

    676-580

does this match your peer's terminal? [y/N]: y
paired with did:wire:paul
```

```bash
# Op A sends
$ wire send willard decision "ship the v0.1 demo"
$ wire push                                               # flush outbox to relay

# Op B receives
$ wire pull                                               # poll relay, verify, write inbox
$ wire tail
[2026-05-10T03:46:01Z paul kind=1 decision] ship the v0.1 demo | sig ✓
```

That's the whole loop. No GitHub account. No OAuth login. No vendor IdP. Both sides own a complete signed log of every exchange.

**Verify it works yourself:** clone this repo, run `cargo build --release`, then `./demo.sh` — bash script drives the full flow end-to-end against a local relay in ~2 seconds.

---

## What's in the box

- `wire init <handle>` — generates Ed25519 keypair, allocates mailbox slot at default relay, prints SAS code phrase
- `wire join <SAS-code>` — PAKE handshake with peer, exchanges agent-cards, writes first signed heartbeat
- `wire send <peer> <type> <body>` — appends signed JSONL event to peer's outbound mailbox
- `wire tail [<peer>]` — streams signed events from peers, sig-verifies each
- `wire relay-server` — self-host the mailbox relay (AGPL; ChaCha20 + Ed25519 only)
- `wire daemonize` — opt-in systemd/launchd unit (foreground-first by default)

---

## What's NOT in the box (and won't be)

See [ANTI_FEATURES.md](ANTI_FEATURES.md) for the full list.

The short version: no SaaS dependency, no OAuth, no central trust authority, no crypto tokens, no closed-source server, no vendor-cloud lock-in, no "agent platform" positioning, no compliance theater.

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

After restart you have these tools natively: `wire_whoami`, `wire_peers`, `wire_send`, `wire_tail`, `wire_verify`. Pairing tools (`wire_init`, `wire_join`) are **deliberately not exposed** — SAS confirmation requires a human, and a malicious upstream input must not be able to talk an agent into autonomous trust establishment.

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

Mesh-of-bilateral. SyncThing model. Each pair is its own wire; group emerges from N pairs.

```bash
# carol pairs with both paul and willard
$ wire join paul-7-crossover-clockwork
$ wire join willard-9-thunder-storm
$ wire tail
# carol now sees signed events from both peers
```

Native group rooms with member-set consensus + cross-member read-receipts are deferred to v0.2+ if real demand surfaces. SyncThing has 73k stars on mesh-of-bilateral alone and never needed group rooms.

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

**v0.1 in development.** Production binary not yet shipped.

`wire` is written in Rust and ships as a single static binary (no Python, no node, no runtime). The release path will be `curl -fsSL https://wire.example.com/install.sh | sh` (atuin / restic / zellij pattern).

For developers reading the protocol now:

```bash
git clone <this-repo>
cd wire
cargo build --release       # protocol crate (lib only at this point)
cargo test                  # 44 tests, ~20ms
```

Requires Rust 1.85+ (edition 2024). Install via [rustup](https://rustup.rs).

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
