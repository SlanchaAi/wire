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
| `wire_add` (v0.5) | Outbound zero-paste pair: resolves a `nick@domain` handle and posts a signed pair_drop. Bilateral — peer must reciprocate before capability flows | none on send; peer-side acceptance is human-gated |
| `wire_pair_list_inbound` (v0.5.14) | Enumerate pending-inbound pair requests (strangers who ran `wire add` against this agent's handle but haven't been accepted yet) | none |
| `wire_pair_accept` (v0.5.14) | Bilateral completion of a pending-inbound pair: pins peer VERIFIED + ships our slot_token via `pair_drop_ack` | **YES** — operator MUST approve; the agent surfaces the request first |
| `wire_pair_reject` (v0.5.14) | Refuse a pending-inbound pair: deletes the record, no slot_token leaks | none, but agent should still surface to operator unless instructed otherwise |

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

### Bilateral pair flow via MCP (v0.5.14) — the `wire_add` + accept gate

```
[1] user: "Pair my agent with coffee-ghost@wireup.net."
[2] agent (B-side): → wire_add(handle="coffee-ghost@wireup.net")
                     → {status: drop_sent, peer_handle: "coffee-ghost", ...}
[3] agent (B-side): "Sent pair request. Awaiting coffee-ghost's accept."
[4] coffee-ghost's daemon receives the pair_drop; OS toast fires on A's machine:
    "wire — pair request from <bob>. Run `wire pair-accept <bob>` to accept."
[5] agent (A-side): on next session start or in response to the toast:
                     → wire_pair_list_inbound() → [{peer_handle: "bob", ...}]
[6] agent (A-side): "Operator: <bob>@<bob's-relay> sent a pair request at <time>.
                     Their DID is <did:wire:bob-…>. Accept? (yes/no/inspect-profile)"
[7] user (A): "yes"  (the operator's explicit consent gesture)
[8] agent (A-side): → wire_pair_accept(peer="bob")
                     → {status: bilateral_accepted, peer_did, ...}
[9] Both sides now have VERIFIED trust + slot_token; can wire_send each other.
```

**Critical agent behavior** (the human gate):

- Step 5–7 is the new human-in-loop step for zero-paste pairing. The agent MUST surface the inbound request to the operator and wait for explicit consent BEFORE calling `wire_pair_accept`. Acceptance grants the peer authenticated write access to the agent's inbox up to slot quota — equivalent to handing out a one-way relay credential, valid until the peer is removed from trust.
- Auto-accepting any inbound pair_drop (e.g. "always accept" prompts, or scheduled `wire_pair_accept` polling) is the v0.5.13 vulnerability re-introduced at the agent layer. Don't.
- For inbound requests the operator clearly doesn't want, `wire_pair_reject` deletes the record without an ack; the peer's side stays pending until they time out.

The MCP server's `instructions` field reminds connecting agents of this on every connect. See also THREAT_MODEL.md "Network-resilience doctrine" + the v0.5.14 changelog entry.

### Multi-session on one machine (v0.5.16)

When multiple agent sessions run on the same machine — e.g. one Claude Code in `~/Source/wire`, another in `~/Source/slancha-mesh` — they share one `WIRE_HOME` by default, which means they share one DID, one slot, one inbox JSONL, and one daemon. Peers can't address a specific session, and cursor advances by either session drain events the other never sees.

Fix: give each session its own isolated `WIRE_HOME`. The `wire session` subcommand wraps the bootstrap:

```bash
# In ~/Source/wire (or any project):
$ wire session new
session created
  name:   wire
  handle: wire
  did:    did:wire:wire-a1b2c3d4
  home:   /Users/paul/.local/state/wire/sessions/wire

activate with:
  export WIRE_HOME=/Users/paul/.local/state/wire/sessions/wire
```

Each session = own identity + own relay slot + own session-local daemon + own inbox/outbox. Sessions pair with each other through `wireup.net` (or any relay) like any other peer — the bilateral-pair gate from v0.5.14 still applies in both directions.

**Stable per-project identity.** Names are derived from `basename(cwd)` and cached in `~/.local/state/wire/sessions/registry.json`, so reopening the same project reuses the same identity instead of generating a fresh DID each time. Different cwds with the same basename get a 4-char path-hash suffix.

**Activation patterns.**

```bash
# Per-shell activation:
$ eval $(wire session env)              # uses cwd to look up the session name
$ eval $(wire session env wire)         # explicit name

# Per-process (subprocess gets isolated WIRE_HOME, parent doesn't):
$ WIRE_HOME=$(wire session env wire --json | jq -r .home_dir) wire status

# Inside an MCP server config (project-local .mcp.json):
{
  "mcpServers": {
    "wire": {
      "command": "wire",
      "args": ["mcp"],
      "env": {
        "WIRE_HOME": "/Users/paul/.local/state/wire/sessions/wire"
      }
    }
  }
}
```

The project-local `.mcp.json` pattern is the recommended Claude Code setup: each project's `.mcp.json` points wire at that project's session. New Claude Code sessions in the same project all share that session's identity; sessions in different projects stay isolated.

**Lifecycle.**

```bash
$ wire session list           # enumerate all sessions on this box
$ wire session current        # which session does this cwd map to?
$ wire session destroy <name> --force   # remove (irrecoverable)
```

**Don't share sessions across operators.** A session's keypair lives on disk under that machine's `~/.local/state/wire/sessions/<name>/config/wire/private.key`. Copying the session dir to another machine shares the identity — only do this intentionally (e.g. moving your laptop's identity to a new laptop). Otherwise: one session = one machine + one project.

### Within-machine fast path: dual-slot sessions (v0.5.17)

For sister-Claudes on the same box that coordinate at high frequency, v0.5.17 adds an opt-in **local relay** transport. Each session can hold two slots — one on the federation relay (e.g. `wireup.net`) and one on a local-only relay (`127.0.0.1:8771`). Sister-session traffic routes through `127.0.0.1` at sub-millisecond latency; federation traffic to other machines keeps going through the public relay.

Setup:

```bash
# Once per machine — start the local-only relay.
wire relay-server --bind 127.0.0.1:8771 --local-only &

# Per session — opt into dual-slot at bootstrap.
wire session new --with-local
```

`--with-local` probes `http://127.0.0.1:8771/healthz` first; if the local relay isn't running, the session is federation-only (logged loudly, not silently). Re-running `wire session new --with-local` on an existing session after the local relay comes up backfills the local slot.

Routing is automatic: when both peers advertise local endpoints, the daemon prefers local; otherwise federation. Falls back transparently on transport errors. See [THREAT_MODEL.md](../docs/THREAT_MODEL.md#within-machine-local-relay-v0517) for the trade-offs (loopback-not-secret on multi-tenant boxes, no TLS, etc).

This is the "OSS coordination layer that vendors can't build because it doesn't sell anything" — cross-Claude, cross-Cursor, cross-Aider, cross-any-agent coordination on one operator-owned box. See [issue #10](https://github.com/SlanchaAi/wire/issues/10) for the design rationale.

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

### Recommended monitor recipe (always-on inbox awareness)

The single biggest UX cliff in any agent harness is the "dead air" between
peer messages and an agent's awareness of them. By default, the agent only
discovers new inbox events when it explicitly polls — meaning a peer can
send three replies before the agent looks up. The recipe below makes peer
messages surface mid-session, as they arrive, without polling.

`wire monitor` is built specifically for this — one persistent process, one
line per new event, handshake filtered by default. Wire it into your
harness's stream-watcher exactly once on session start:

```bash
# Plain form — every line is a notification.
wire monitor

# JSON form — for harnesses that parse structured events.
wire monitor --json

# Restrict to one peer.
wire monitor --peer willard

# Replay last N events before going live (useful on harness restart).
wire monitor --replay 10
```

Claude Code harnesses arm this via the `Monitor` tool with
`persistent: true`. Other harnesses just background it (`wire monitor &`,
systemd user unit, tmux pane, etc.). Either way, the contract is:

- One stdout line = one event the operator/agent should know about.
- Handshake / liveness noise (`pair_drop`, `pair_drop_ack`, `heartbeat`)
  filtered unless `--include-handshake` is passed.
- Body fragment ≤ 120 chars — the harness fetches full body via
  `wire tail <peer>` or `wire://inbox/<peer>` MCP resource.

Default behavior in 0.5.11+: **agents should arm the monitor on session
start.** The dead-air session is the broken session.

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
