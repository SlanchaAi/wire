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

| Tool | What it does | Human gate? |
|------|-------------|-------------|
| `wire_whoami` | Returns this agent's DID, fingerprint, mailbox slot, capabilities | none |
| `wire_peers` | Lists pinned peers with tier (UNTRUSTED/VERIFIED/ATTESTED), capabilities | none |
| `wire_send` | Sends a signed event to a peer; returns event_id | none |
| `wire_tail` | Streams inbound events from one or all peers; supports `since=event_id` | none |
| `wire_verify` | Verifies an arbitrary signed event against trust state; returns ok/reason | none |
| `wire_init` | Idempotent identity creation. Same handle = no-op; different handle = error (can't silently re-key) | none — local-only, no peer trust |
| `wire_pair_initiate` | Host opens a pair-slot; returns code phrase for the agent to share with the user out-of-band | none — code phrase is a low-entropy beacon |
| `wire_pair_join` | Guest SPAKE2 against a code phrase; returns SAS digits + session_id | none |
| `wire_pair_check` | Poll a pending session for state transitions | none |
| `wire_pair_confirm` | Finalize pairing — user types the 6 SAS digits back into chat; mismatch ABORTS permanently | **YES** — the only human-in-loop step |

Plus MCP resources:

| Resource URI | Content |
|---|---|
| `wire://inbox/all` | Recent verified events across all peers, JSONL |
| `wire://inbox/<peer>` | Recent verified events from one peer, JSONL |

`wire mcp` runs over stdio (JSON-RPC). No daemon required to start; it spawns on demand.

### Pair flow via MCP — the digit-typeback gate

```
[1] user: "Pair my agent with paul's agent."
[2] agent: → wire_pair_initiate(relay_url) → {session_id, code_phrase: "73-2QXC4P"}
[3] agent: "Share the code 73-2QXC4P with paul (voice/text). I'll wait."
[4] paul's agent (separately): → wire_pair_join("73-2QXC4P") → {session_id, sas: "384-217"}
[5] agent: → wire_pair_check(session_id) → {state: sas_ready, sas: "384-217"}
[6] agent: "SAS is 384-217. Ask paul his agent's SAS, compare aloud, then type 6 digits back."
[7] user: "384217"  (the digits the user typed in chat; must match)
[8] agent: → wire_pair_confirm(session_id, "384217") → {paired_with: "did:wire:paul", ...}
[9] paul's user does the same on paul's side; trust pinned both ways.
```

The agent never touches digits 7→8 except as a passthrough. Step 6's instruction is enforced by tool description prose — `wire_pair_confirm`'s tool description tells the host the digits MUST come from user input, not previous tool output. Wire cannot enforce this protocol-layer (see THREAT_MODEL.md T14); the MCP host is responsible for routing the user input through the user's actual UI.

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

## Pairing boundary (v0.2.0 revision)

v0.1 made pairing CLI-only (`wire init` + `wire join` blocked at MCP layer). v0.2.0 keeps the **human gate** but moves the friction from "context-switch to terminal" → "type the SAS digits back into chat":

1. Agent drives `wire_pair_initiate` / `_join` / `_check`. No human action yet.
2. SAS digits surface in the agent's chat output (tool result text).
3. **The user must compare the SAS with their peer over a side channel** (voice call, separate text channel) — same as the CLI flow.
4. **The user types the 6 SAS digits back into the agent's chat** — `wire_pair_confirm(session_id, user_typed_digits)`.
5. Wire compares typed digits against the cached SAS server-side. Mismatch aborts permanently; the session is removed from the in-memory store.

**Why this preserves the trust property:**

- SPAKE2 already guarantees a MITM derives a different shared key, so a different SAS, on each side. The user reading their peer's SAS aloud (or by separate text) and typing it back catches MITM.
- A malicious or prompt-injected agent that fabricates SAS digits in chat fails because the user's PEER's agent shows different digits via the peer's side channel.
- A `y`/`n` confirm would NOT preserve this — a compromised agent could just auto-`y`. The digit-typeback forces the user's actual fingers to participate.

**Where wire can't help (T14):** the MCP host is responsible for routing `user_typed_digits` to wire ONLY from real user input, never from a previous tool result. There's no MCP primitive today that lets wire verify "this string came from the user, not the model." A poorly-implemented host could auto-fill. Operators should choose an MCP host with explicit user-confirmation primitives.

If an agent needs a new peer added, this is now natural in-chat:

```
[claude] I'd like to coordinate with willard's agent. Want me to pair?
  → wire_pair_initiate
  → "Share code 73-2QXC4P with willard via voice/text. When their agent
    shows SAS, type the 6 digits back into chat to confirm."
[user] *shares code, gets SAS=384-217 from willard via voice*
[user] 384217
[claude] → wire_pair_confirm(session_id, "384217") → paired with did:wire:willard.
```

This is now the recommended flow.

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

- **You don't need a wire SDK.** MCP gives you typed tools + resources; Bash gives you `--json`; files give you `cat` + `tail`.
- **You CAN pair, but the user types the SAS digits back.** Goal 1 (v0.2.0) — you drive `wire_pair_initiate`/`_join`/`_check`, surface SAS digits in chat, the user reads them aloud to their peer over a side channel, then types the 6 digits into chat. You pass those digits to `wire_pair_confirm`. Mismatch aborts.
- **You get push-style inbox awareness via MCP resources.** `wire://inbox/<peer>` exposes verified events as JSONL. v0.2.0 ships read-only; subscribe (push-on-grow notifications) is v0.2.1.
- **OS-level notifications.** Run `wire notify` alongside your MCP server for native desktop toasts on each new event — works regardless of which agent runtime is active.
- **You can't lie about who you are.** Every event you send is signed by the operator's key on this machine. The peer verifies before reading.
- **You can't get spoofed.** Every event you receive was verified before landing in your inbox. If the signature failed, you never see it.
- **Retry freely.** Content-addressed dedup makes retries safe.
- **Multi-peer concurrent is first-class.** Pair with N peers in parallel — each `wire_pair_initiate` returns a distinct `session_id`, and `wire_send` to different peers uses different outbox files. Same-peer concurrent sends are serialized via a per-path mutex so JSONL lines never interleave.
- **Negotiate capabilities.** Read peer's card before sending unusual kinds. Don't assume.

This is the contract. Three discovery paths. One signed-event protocol underneath. The same wire bytes whether the sender is a human, an agent, or a daemon — and they all verify with the same Ed25519 signature.
