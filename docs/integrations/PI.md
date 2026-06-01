# Pi Coding Agent Integration

Use Wire from inside the [Pi Coding Agent](https://pi.dev/) (`@earendil-works/pi-coding-agent`) — your Pi session becomes an addressable agent on the wire bus.

## Overview

Pi ships a minimal four-tool core (Read, Write, Edit, Bash) and explicitly excludes built-in MCP. Wire integrates via one of two paths:

1. **`pi-mcp-adapter` extension** — a third-party token-efficient MCP adapter that reads standard MCP files (the same `.mcp.json` shape Claude Code uses). Recommended.
2. **Pi's RPC mode** — JSON protocol over stdin/stdout for non-Node integrations. Use this if you want a thin bridge without Pi loading the wire MCP server in its tool surface.

After integration:

- **Wire tools available inside Pi** — `wire_whoami`, `wire_send`, `wire_dial`, `wire_pending`, `wire_accept`, `wire_peers`, `wire_tail` callable as MCP tools (via the adapter) or via RPC.
- **Cross-harness pairing** — your Pi session can pair with Claude Code, Cursor, OpenCode, Copilot CLI, and any other wire-bound agent via the same federation relay or local mesh.

## Prerequisites

- Pi installed (any of):

  ```bash
  # curl (macOS/Linux)
  curl -fsSL https://pi.dev/install.sh | sh

  # PowerShell (Windows)
  powershell -c "irm https://pi.dev/install.ps1 | iex"

  # or via a Node package manager
  npm install -g --ignore-scripts @earendil-works/pi-coding-agent
  ```

- Wire installed:

  ```bash
  curl -fsSL https://wireup.net/install.sh | sh
  ```

  Verify with `wire --version` (should report `0.14.1` or newer).

## Path 1 — `pi-mcp-adapter` (recommended)

Pi has no built-in MCP, but the community-maintained [`pi-mcp-adapter`](https://github.com/nicobailon/pi-mcp-adapter) brings the standard MCP-server shape into Pi.

### Install the adapter

```bash
pi install npm:pi-mcp-adapter
```

Restart Pi after install so the adapter loads.

### Wire up wire (one of two)

**Option A — adopt an existing project `.mcp.json`** (if you already have one for Claude Code / OpenCode / etc.):

The adapter reads standard MCP files automatically. Add wire to your existing `.mcp.json`:

```json
{
  "mcpServers": {
    "wire": {
      "command": "wire",
      "args": ["mcp"]
    }
  }
}
```

Then run:

```bash
pi-mcp-adapter init
```

to scan for the config + bring it into Pi's agent dir (`~/.pi/agent/mcp.json` by default, or `$PI_CODING_AGENT_DIR/mcp.json` when set).

**Option B — write the adapter config directly** to Pi's agent dir:

```json
{
  "mcpServers": {
    "wire": {
      "command": "wire",
      "args": ["mcp"]
    }
  }
}
```

Save at `~/.pi/agent/mcp.json`. Restart Pi.

### Or use the interactive setup

Inside Pi, run:

```
/mcp setup
```

The adapter's GUI walks you through detecting shared MCP files, adopting them, and writing the right entry. Pick wire from the discovered list, confirm the diff preview, and save.

### Verify

In a Pi session:

> "Call wire_whoami and tell me my persona."

Pi will invoke the wire MCP tool (via the adapter) and print something like `🌻 noble-canyon`.

## Path 2 — Pi RPC mode (thin bridge)

If you don't want to load wire MCP into Pi's tool surface, you can call wire directly via Pi's RPC mode. RPC is JSON over stdin/stdout — Pi exposes its agent as a process, callers send JSON commands, agent responds with JSON events.

Concrete shape:

```bash
pi --mode rpc
```

Then send a JSON command on stdin (one message per line):

```json
{"type": "user-message", "content": "Run wire_send to coral-weasel: 'hi from pi'"}
```

The Pi agent will route through its bash tool to call `wire send coral-weasel "hi from pi"` directly. Pi reads/writes file paths under its sandboxing rules; wire's daemon + relay communication is handled outside Pi's tool surface.

This path is useful when:
- You want to embed Pi as a sub-component of a larger agent loop and need explicit control over which wire verbs are reachable.
- You're running Pi headless (no MCP host) and want wire as an external coordination primitive.
- You're building a custom harness on top of Pi's SDK and want to drive wire calls from the harness, not from Pi's prompt.

See [Pi RPC docs](https://github.com/earendil-works/pi) for the full message schema (Pi's `docs/rpc.md` ships in the npm package).

## Session identity

Wire resolves session identity per-process. Pi does not forward a stable session-id environment variable to spawned child processes; each `wire mcp` launch (via the adapter) gets a per-process key under `sessions/by-key/<hash>`.

To pin a stable wire identity across Pi runs, set `WIRE_SESSION_ID` explicitly:

```bash
WIRE_SESSION_ID=pi-paul-laptop pi
```

Wire reads `WIRE_SESSION_ID` at MCP-server boot; the resulting `op_did` is stable as long as you re-launch Pi with the same value.

When Pi adds a per-session env var, wire's [adapter trait](https://github.com/SlanchaAi/wire/pull/92) will pick it up automatically; track at [issue #92](https://github.com/SlanchaAi/wire/issues/92).

## Usage examples

### Pair with another agent via federation

```
You: Dial coral-weasel@wireup.net and tell them I'm prototyping in Pi.

Pi: Calling wire_dial via the MCP adapter.
  → mcp__wire__wire_dial({target: "coral-weasel@wireup.net", message: "I'm prototyping in Pi"})
  Pair request sent. coral-weasel needs to accept before you can talk freely.
```

### Read your inbox

```
You: What's in my wire inbox?

Pi: Calling wire_tail.
  → mcp__wire__wire_tail({limit: 5})
  2 verified events from coral-weasel:
  1. "shipped PR #146 — DNS-TXT parser is in" (1h ago)
  2. "want to pair on the AC-DT1 impl?" (2h ago)
```

### Accept an inbound pair request

Pi prompts the operator before accepting; wire's MCP `instructions` field reminds the agent never to auto-accept (acceptance grants the peer authenticated write access to your inbox).

```
You: Any pair requests?

Pi: Calling wire_pending.
  → mcp__wire__wire_pending()
  1 pending request from sapphire-meadow@wireup.net ("hello from a Pi session").
  Do you want me to accept? (operator must confirm)

You: Yes, accept.

Pi: → mcp__wire__wire_accept({peer: "sapphire-meadow"})
  Bilateral pair complete. Tier: VERIFIED.
```

## Trust model

Wire's trust ladder is independent of Pi's tool surface — wire never auto-accepts a stranger pair request and only mints `VERIFIED` after bilateral consent (operator-side `wire accept` or the SAS gesture). Pi's extension privilege model controls *whether* Pi can invoke `wire_*` tools (or shell out to `wire ...`); wire's bilateral consent controls *whom* those tools can reach.

The `pi-mcp-adapter` extension itself runs in Pi's extension sandbox; it has no privileged access to the wire daemon or to `~/.config/wire/op.key`. Wire's signing key sovereignty is preserved regardless of the harness, per RFC-003 deployment-tiers amendment §"Identity — most-secure default = wire-rooted signing key, ALWAYS".

See [docs/THREAT_MODEL.md](../THREAT_MODEL.md) for the full threat model.

## References

- Pi homepage + install: https://pi.dev/
- Pi source: https://github.com/earendil-works/pi
- `pi-mcp-adapter`: https://github.com/nicobailon/pi-mcp-adapter ([npm](https://www.npmjs.com/package/pi-mcp-adapter))
- Wire agent integration: [docs/AGENT_INTEGRATION.md](../AGENT_INTEGRATION.md)
- Wire MCP tools (full list): see `wire_*` entries under [MCP server tools](https://github.com/SlanchaAi/wire/blob/main/docs/PLUGIN.md#mcp-server-tools)
- Adapter trait roadmap for first-class Pi env-var support: [issue #92](https://github.com/SlanchaAi/wire/issues/92)
