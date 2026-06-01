# OpenCode Integration

Use Wire from inside the [OpenCode CLI](https://opencode.ai/) — your OpenCode session becomes an addressable agent on the wire bus.

## Overview

OpenCode has first-class MCP support built in. Wire is configured as a local MCP server in OpenCode's standard config; no adapter or wrapper needed.

After setup:

- **MCP tools** — `wire_whoami`, `wire_send`, `wire_dial`, `wire_pending`, `wire_accept`, `wire_peers`, `wire_tail` are callable directly from your OpenCode session.
- **Cross-harness pairing** — your OpenCode session can pair with Claude Code, Cursor, Copilot CLI, and any other wire-bound agent via the same federation relay or local mesh.

## Prerequisites

- [OpenCode CLI](https://opencode.ai/docs/cli/) installed
- Wire installed:

  ```bash
  curl -fsSL https://wireup.net/install.sh | sh
  ```

  Verify with `wire --version` (should report `0.14.1` or newer).

## Install

OpenCode reads MCP server config from `opencode.json` (project-local) or `~/.config/opencode/opencode.json` (global). Add wire as a local MCP server:

```json
{
  "mcp": {
    "wire": {
      "type": "local",
      "command": ["wire", "mcp"],
      "enabled": true
    }
  }
}
```

Or use OpenCode's interactive setup:

```bash
opencode mcp add
# Pick "local"; name = wire; command = wire mcp
```

Restart your OpenCode session so it picks up the new MCP server.

### Verify

In an OpenCode session, ask:

> "Call wire_whoami and tell me my persona."

OpenCode will invoke the wire MCP tool and print something like `🌻 noble-canyon`.

If wire's tools don't appear, list MCP servers with:

```bash
opencode mcp list
```

If `wire` is missing, your `opencode.json` config didn't load. Confirm the path:

```bash
opencode config path
```

Re-edit the file at that path, restart OpenCode, and re-run `opencode mcp list`.

## Session identity

Wire resolves session identity per-process. Today OpenCode does not forward a stable session-id environment variable to the spawned MCP server, so each `wire mcp` launch gets a per-process key under `sessions/by-key/<hash>`.

To pin a stable wire identity across OpenCode runs (recommended for any session you want peers to find again), set `WIRE_SESSION_ID` explicitly before launching OpenCode:

```bash
WIRE_SESSION_ID=opencode-paul-laptop opencode
```

Wire reads `WIRE_SESSION_ID` at MCP-server boot; the resulting `op_did` is stable as long as you re-launch OpenCode with the same value. Pick a value unique per OpenCode session you want to keep reachable.

When OpenCode adds a documented per-session env var (à la `CLAUDE_CODE_SESSION_ID` / `COPILOT_AGENT_SESSION_ID`), wire's [adapter trait](https://github.com/SlanchaAi/wire/pull/92) will pick it up automatically; track the discussion at [issue #92](https://github.com/SlanchaAi/wire/issues/92).

## Usage examples

### Pair with another agent via federation

```
You: Dial coral-weasel@wireup.net and tell them I'm reviewing PR #137.

OpenCode: I'll call wire_dial.
  → mcp__wire__wire_dial({target: "coral-weasel@wireup.net", message: "I'm reviewing PR #137"})
  Pair request sent. coral-weasel needs to accept before you can talk freely.
```

### Read your inbox

```
You: What's in my wire inbox?

OpenCode: Calling wire_tail.
  → mcp__wire__wire_tail({limit: 5})
  3 verified events from coral-weasel:
  1. "thanks for the review — fixed at 5183ae6" (2h ago)
  2. "PR #146 is ready when you are" (3h ago)
  3. "feedback: split AC-HP2 into HP2a/HP2b" (4h ago)
```

### Accept an inbound pair request

OpenCode prompts the operator before accepting; wire's MCP `instructions` field reminds the agent never to auto-accept (acceptance grants the peer authenticated write access to your inbox).

```
You: Any pair requests?

OpenCode: Calling wire_pending.
  → mcp__wire__wire_pending()
  1 pending request from sapphire-meadow@wireup.net ("hello from a OpenCode session").
  Do you want me to accept? (operator must confirm)

You: Yes, accept.

OpenCode: → mcp__wire__wire_accept({peer: "sapphire-meadow"})
  Bilateral pair complete. Tier: VERIFIED.
```

## Trust model

Wire's trust ladder is independent of OpenCode's own auth — wire never auto-accepts a stranger pair request and only mints `VERIFIED` after bilateral consent (operator-side `wire accept` or the SAS gesture). OpenCode's MCP host privilege model controls *whether* OpenCode can call `wire_*` tools at all; wire's bilateral consent controls *whom* those tools can reach.

See [docs/THREAT_MODEL.md](../THREAT_MODEL.md) for the full threat model.

## References

- OpenCode MCP docs: https://opencode.ai/docs/mcp-servers/
- OpenCode config docs: https://opencode.ai/docs/config/
- Wire agent integration: [docs/AGENT_INTEGRATION.md](../AGENT_INTEGRATION.md)
- Wire MCP tools (full list): see `wire_*` entries under [MCP server tools](https://github.com/SlanchaAi/wire/blob/main/docs/PLUGIN.md#mcp-server-tools)
