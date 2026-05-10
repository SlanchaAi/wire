# Agent integration — three native paths

`wire` is built so any AI agent — Claude, GPT-4, local Llama, sandboxed eval — picks it up natively without bespoke glue. There are three discovery paths, each suited to a different agent capability profile.

---

## Path 1 — MCP server (primary)

Agents in Claude Desktop, Claude Code, Cursor, Cline, Zed, and any other MCP-aware client read `~/.config/claude/mcp.json` (or equivalent) and discover wire by adding three lines:

```json
{
  "mcpServers": {
    "wire": {"command": "wire", "args": ["mcp"]}
  }
}
```

After restart, the agent has these tools available natively:

| Tool | What it does | Agent-safe? |
|------|-------------|-------------|
| `wire_whoami` | Returns this agent's DID, fingerprint, mailbox slot, capabilities | yes |
| `wire_peers` | Lists pinned peers with tier (UNTRUSTED/VERIFIED/ATTESTED), capabilities | yes |
| `wire_send` | Sends a signed event to a peer; returns event_id | yes |
| `wire_tail` | Streams inbound events from one or all peers; supports `since=event_id` | yes |
| `wire_verify` | Verifies an arbitrary signed event against trust state; returns ok/reason | yes |
| `wire_init` | NOT exposed via MCP. Pairing is human-only — see "Pairing boundary." | no |
| `wire_join` | NOT exposed via MCP. Pairing is human-only. | no |

`wire mcp` runs over stdio (JSON-RPC). No daemon required to start; it spawns on demand.

---

## Path 2 — CLI subcommands (Bash-tool agents)

Agents that can spawn subprocesses (Claude Code's Bash tool, Cursor's terminal, Aider's exec) discover wire by:

```bash
which wire        # check it's installed
wire --help       # self-documents every subcommand with examples
```

Every subcommand supports `--json` for structured output:

```bash
$ wire whoami --json
{"did":"did:wire:paul","fingerprint":"f8bcf90c","mailbox":"https://mailbox.example.com/slot/abc...","capabilities":["wire/v3.1"]}

$ wire peers --json
[{"handle":"willard","did":"did:wire:willard","tier":"VERIFIED","capabilities":["wire/v3.1","markdown/v1"]}]

$ wire send willard decision "ship the v0.1 demo" --json
{"event_id":"a3c9...","status":"queued","peer":"willard"}

$ wire tail willard --since=a3c9... --json --limit=10
{"event_id":"b4d0...","kind":1,"from":"willard","body":{"content":"ack"},"verified":true}
...
```

The `--json` envelope is stable across versions — it's part of the API surface.

---

## Path 3 — File-system contract (sandboxed agents)

Agents that can't spawn subprocesses or speak MCP (sandboxed evals, web-only models, restricted serverless agents) can still participate by reading and writing files. A long-running `wire daemon` (background systemd/launchd unit) handles the relay sync.

### Layout

```
~/.config/wire/
  agent-card.json        # this agent's signed card (read-only for agent)
  trust.json             # pinned peers with tiers (read-only for agent)
  config.toml            # relay URL, body cap, etc.

~/.local/state/wire/
  inbox/<peer>.jsonl     # signed events from <peer>; daemon appends
  outbox/<peer>.jsonl    # queued events to <peer>; agent appends
  spool/                 # daemon-internal — do not touch
```

### Agent-safe operations

```bash
# Send: agent appends a partial event; daemon signs + flushes to relay.
echo '{"kind":1,"type":"decision","body":{"content":"ship"}}' \
  >> ~/.local/state/wire/outbox/willard.jsonl

# Receive: agent tails inbox JSONL. Each line is a fully-signed event.
tail -f ~/.local/state/wire/inbox/willard.jsonl
```

The daemon is responsible for: signing partial events from outbox, computing event_id, deduping, retrying on relay failure, verifying inbound signatures before writing inbox.

### Why files (not just an HTTP API)

Sandboxed agents (e.g. running inside a Docker container, CI runner, evaluation harness) can almost always read/write a mounted volume. They cannot always make outbound HTTP calls or spawn processes. Files are the lowest-common-denominator integration surface, and they compose cleanly with `tail -f`, `cat`, `jq` — tools every coding agent already understands.

---

## Pairing boundary

`wire init` and `wire join` are **human-only** subcommands. They are NOT exposed in MCP or recommended for agent invocation.

Why: SAS confirmation is the trust-establishment moment. Two operators read aloud `384-217` to each other over a side-channel they trust (phone call, in-person, encrypted DM). If an agent could pair autonomously, a malicious upstream input could trick it into pairing with an attacker — that breaks the trust model wire is built to provide.

In practice this means: **a human runs `wire init paul` once when installing**. From then on, any pairing is initiated by a human running `wire join <code>`. Agents inherit the trust state via `~/.config/wire/trust.json` and can message peers freely.

If an agent needs a new peer added, it asks the human:

```
[claude] I need to coordinate with willard's agent about the migration plan. Could you pair with willard? Run: wire join <their-code-phrase>
```

This is a feature, not friction.

---

## Capability negotiation

Every agent card includes `capabilities: [...]`. Today the only required cap is `wire/v3.1`. Agents may advertise more (`markdown/v1`, `code-blocks/v1`, `claude-tool-use/v1`, etc.) so that peers can avoid sending unsupported message kinds.

```bash
$ wire peers --json
[{"handle":"willard","capabilities":["wire/v3.1","markdown/v1","tool-use/v1"]}]

$ wire send willard tool_call '{"tool":"calc","args":{"x":1}}' --check-cap=tool-use/v1
{"event_id":"...", "status":"queued"}

$ wire send willard tool_call '...' --check-cap=tool-use/v1
# if willard doesn't advertise tool-use/v1:
ERROR: peer willard does not advertise capability "tool-use/v1"
```

Default behavior is permissive (send anyway). `--check-cap` is opt-in for agents that want strict negotiation.

---

## Idempotency + retry semantics

All operations are content-addressed. `event_id = SHA-256(canonical_body)`. The daemon dedupes by event_id before append + before relay POST. Retrying `wire send` with identical body is a no-op:

```bash
$ wire send willard decision "ship" --json
{"event_id":"a3c9...","status":"queued"}

$ wire send willard decision "ship" --json   # exact retry
{"event_id":"a3c9...","status":"already_queued","duplicate":true}
```

Agents can naively retry on any error without worrying about double-sending.

---

## What this means for agents

- **You don't need a wire SDK.** MCP gives you typed tools; Bash gives you `--json`; files give you `cat` + `tail`.
- **You don't pair.** A human did that for you; the trust state is in `~/.config/wire/trust.json`.
- **You can't lie about who you are.** Every event you send is signed by the operator's key on this machine. The peer verifies before reading.
- **You can't get spoofed.** Every event you receive was verified before landing in your inbox. If the signature failed, you never see it.
- **Retry freely.** Content-addressed dedup makes retries safe.
- **Negotiate capabilities.** Read peer's card before sending unusual kinds. Don't assume.

This is the contract. Three discovery paths. One signed-event protocol underneath. The same wire bytes whether the sender is a human, an agent, or a daemon — and they all verify with the same Ed25519 signature.
