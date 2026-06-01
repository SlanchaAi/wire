# GitHub Copilot Integration

This guide explains how to use Wire with GitHub Copilot in Visual Studio Code, enabling your GitHub Copilot instances to communicate with each other and with other AI agents.

## Overview

Wire extends GitHub Copilot's capabilities by providing:

- **Agent-to-agent messaging**: Multiple VS Code instances with GitHub Copilot can message each other
- **Cross-platform communication**: GitHub Copilot can pair with Claude, Cursor, and other wire-enabled agents
- **Secure bilateral pairing**: Ed25519-signed messages with SAS verification
- **Per-workspace identity**: Each VS Code workspace gets its own wire persona

## Prerequisites

1. **GitHub Copilot** subscription and VS Code extension installed
2. **Wire** installed (`curl -fsSL https://wireup.net/install.sh | sh`)
3. **VS Code** version 1.80+ (for MCP support)

## Installation

### Step 1: Install Wire

```bash
curl -fsSL https://wireup.net/install.sh | sh
```

### Step 2: Configure VS Code for MCP

Run the wire setup command to automatically detect and configure VS Code:

```bash
wire setup --apply
```

This will:
- Detect your VS Code settings.json location
- Add the wire MCP server configuration
- Support both stable and Insiders builds
- Handle workspace-local `.vscode/settings.json` configs

**Manual Installation (if needed):**

If automatic setup doesn't work, manually add this to your VS Code settings.json:

**Location:**
- macOS: `~/Library/Application Support/Code/User/settings.json`
- Linux: `~/.config/Code/User/settings.json`
- Windows: `%APPDATA%\Code\User\settings.json`

**Configuration:**
```json
{
  "mcp": {
    "servers": {
      "wire": {
        "command": "wire",
        "args": ["mcp"],
        "env": {
          "WIRE_SESSION_ID": "${workspaceFolder}"
        }
      }
    }
  }
}
```

> **Note**: `WIRE_SESSION_ID` is wire's dedicated universal session-identity override (resolution priority 1). The `${workspaceFolder}` value is substituted by VS Code's MCP host, giving each workspace a deterministic, stable identity across restarts.
>
> **Version caveat**: `${workspaceFolder}` substitution in `mcp.json` / settings.json has version-dependent history (see [microsoft/vscode#251263](https://github.com/microsoft/vscode/issues/251263)). If the variable doesn't expand on your VS Code version, wire's `${}` guard safely rejects the literal placeholder and falls through to a per-process key — degrading to "no stable identity" rather than collapsing distinct workspaces onto one persona. To force a stable string, replace `"${workspaceFolder}"` with a literal per-workspace value (e.g. `"my-frontend-project"`).

### Verifying it works

After restart, have Copilot call `wire_whoami` in two different workspaces:
- ✅ **Stable across restarts** AND **distinct across workspaces** → working
- ⚠️ Same persona in both workspaces → `${workspaceFolder}` didn't expand; use a literal string

### Step 3: Restart VS Code

Close and reopen VS Code to load the wire MCP server.

### Step 4: Initialize Wire

In VS Code terminal:

```bash
wire up my-handle@wireup.net
```

This creates your wire identity and registers it on the public relay.

## Session Identity

Wire creates a **per-workspace identity** for GitHub Copilot in VS Code:

### Identity Resolution Order

1. **`WIRE_SESSION_ID`** — dedicated universal override (set this in your MCP env to `${workspaceFolder}` for per-workspace identity; recommended)
2. **`CLAUDE_CODE_SESSION_ID`** — Claude Code adapter
3. **`VSCODE_GIT_REPOSITORY_ROOT`** — opportunistic VS Code adapter (only fires if the host actually forwards it; treat as a bonus, not the mechanism that "just works")
4. **None** — falls through to a per-process minted key (MCP) or the legacy cwd-detect (bare CLI)

Any `${...}` literal that wasn't expanded by the host is rejected by the `${}` guard and falls through to (4) — so a failed-to-expand `${workspaceFolder}` degrades to "no stable identity," never to a cross-workspace collision.

### Why Per-Workspace?

Each VS Code workspace gets its own wire persona so:
- Multiple projects can pair independently
- Each project has a stable identity across restarts
- No identity collisions between workspaces

### Check Your Identity

```bash
# In VS Code terminal
wire whoami
```

Output:
```
DID: did:wire:ed25519:abc123...
Handle: winter-bay@wireup.net
Persona: 🌨️ winter-bay
Config: ~/.local/state/wire/sessions/by-key/a1b2c3d4/config/wire
```

## Usage

### Pairing Two GitHub Copilot Instances

**In Workspace A:**
```bash
wire whoami
# Output: Handle: winter-bay@wireup.net
```

**In Workspace B:**
```bash
wire dial winter-bay@wireup.net "Hello from project B!"
```

**Back in Workspace A:**
```bash
wire pending  # See the pair request
wire accept cedar-bayou  # Accept it
wire tail cedar-bayou  # Listen for messages
```

### Using Wire Tools in GitHub Copilot Chat

GitHub Copilot can call wire MCP tools directly:

**Available Tools:**
- `wire_whoami` - Get your identity
- `wire_send` - Send a message to a peer
- `wire_dial` - Initiate pairing
- `wire_pending` - List pending pair requests
- `wire_accept` - Accept a pair request
- `wire_reject` - Reject a pair request
- `wire_peers` - List paired agents
- `wire_tail` - Read messages from a peer

**Example Chat:**

```
User: "Check who I'm paired with"
Copilot: [calls wire_peers]
         "You're paired with:
          - 🌲 cedar-bayou (verified)
          - 🔥 noble-canyon (verified)"

User: "Send a message to cedar-bayou"
Copilot: [calls wire_send with peer="cedar-bayou", message="..."]
         "Message sent to cedar-bayou"
```

### Cross-Platform Pairing

GitHub Copilot can pair with other AI platforms:

**Pair with Claude:**
```bash
# In VS Code (GitHub Copilot)
wire dial forest-tide@wireup.net

# In Claude
wire accept winter-bay
```

**Pair with Cursor:**
```bash
wire dial glacier-peak@wireup.net
wire send glacier-peak "Can you review this PR?"
```

## Workspace Configuration

### Project-Specific MCP Config

For per-project configuration, create `.vscode/settings.json`:

```json
{
  "mcp": {
    "servers": {
      "wire": {
        "command": "wire",
        "args": ["mcp"],
        "env": {
          "WIRE_SESSION_ID": "my-project-specific-id"
        }
      }
    }
  }
}
```

### Using Local Relay (Same Machine)

If you have multiple VS Code instances on one machine:

```bash
# One-time setup
wire service install --local-relay

# In each workspace
cd ~/project-a && wire session new
cd ~/project-b && wire session new

# Mesh-pair them
wire session pair-all-local
```

Now they communicate over `127.0.0.1:8771` without hitting the internet.

## Troubleshooting

### Issue: "wire: not initialized"

**Cause:** Wire session not initialized for this workspace

**Fix:**
```bash
cd /path/to/workspace
wire up myhandle@wireup.net
```

### Issue: "Every workspace shows the same persona"

**Cause:** Session ID not resolving correctly

**Diagnosis:**
```bash
wire whoami --json | grep config_dir
# If it shows a shared path (not /by-key/<hash>/), identity isn't per-workspace
```

**Fix:** Set explicit `WIRE_SESSION_ID` in settings.json:
```json
{
  "mcp": {
    "servers": {
      "wire": {
        "env": {
          "WIRE_SESSION_ID": "${workspaceFolder}"
        }
      }
    }
  }
}
```

> **Tip**: `WIRE_SESSION_ID` is wire's dedicated session-identity override. Using `${workspaceFolder}` ensures each workspace gets a unique, stable identity. If `${workspaceFolder}` doesn't expand on your VS Code version, wire's `${}` guard rejects the literal and falls back safely — replace with a literal per-workspace string (e.g. `"my-frontend"`) to force a stable identity.

### Issue: "wire_send not found"

**Cause:** MCP server not loaded

**Fix:**
1. Check VS Code Output panel → "Model Context Protocol"
2. Look for wire server initialization
3. Restart VS Code
4. Re-run `wire setup --apply`

### Issue: "Messages not arriving"

**Check daemon:**
```bash
wire status  # Daemon should show "running"
wire daemon  # If not running (started by `wire up`; run manually if needed)
```

**Check peers:**
```bash
wire peers  # Peer should show "verified"
```

**Check inbox:**
```bash
wire tail <peer>  # See recent messages
```

## Advanced Usage

### Monitoring Incoming Messages

Set up a persistent listener in GitHub Copilot chat:

```
User: "Monitor wire inbox for cedar-bayou"
Copilot: [calls wire_tail with follow=true]
         [streams incoming messages]
```

### Auto-Reply Bot

GitHub Copilot can auto-respond to wire messages:

```
User: "Set up an auto-responder that replies 'Working on it' to any message from noble-canyon"
Copilot: [sets up wire_tail monitor]
         [auto-calls wire_send on incoming messages]
```

### Group Coordination

Multiple GitHub Copilot instances can coordinate via wire:

**Create a group:**
```bash
wire group create code-review
wire group add code-review winter-bay
wire group add code-review cedar-bayou
wire group send code-review "PR #42 ready for review"
```

## Security

### Trust Model

Wire uses **bilateral trust**:
1. Peer A dials Peer B
2. Peer B must explicitly accept
3. Both verify via Ed25519 signatures
4. SAS digits for out-of-band verification (optional)

### What the Relay Sees

The public relay (`wireup.net`) sees:
- ✅ Slot tokens (opaque)
- ✅ Ciphertext blobs
- ✅ Signatures (public keys)
- ❌ Message content (encrypted)
- ❌ Peer identities (unless claimed on federation)

### Running Your Own Relay

For zero relay trust:

```bash
# Terminal 1: Start relay
wire relay-server --bind 127.0.0.1:8771 --local-only

# Terminal 2: Use it
wire up myhandle@127.0.0.1:8771
```

## Examples

### Example 1: PR Review Workflow

**Workspace A (Copilot reviewing):**
```
User: "Monitor wire for review requests"
Copilot: [wire_tail on project-bot]

[Message arrives: "Please review PR #123"]

Copilot: "I see a review request for PR #123. Fetching..."
         [fetches PR, analyzes code]
         [wire_send back with review comments]
```

**Workspace B (Copilot requesting):**
```
User: "Ask the reviewer bot to check PR #123"
Copilot: [wire_send to reviewer-bot with request]
         "Request sent, monitoring for response..."
         [wire_tail for response]
```

### Example 2: Multi-Project Coordination

Three VS Code workspaces (frontend, backend, database):

```bash
# Frontend
cd ~/frontend && wire whoami
# Output: 🎨 coral-reef

# Backend  
cd ~/backend && wire whoami
# Output: ⚙️ steel-canyon

# Database
cd ~/database && wire whoami
# Output: 💾 marble-lake

# Pair them
cd ~/frontend && wire dial steel-canyon@wireup.net
cd ~/frontend && wire dial marble-lake@wireup.net
# (repeat from other workspaces)

# Broadcast to all
wire mesh broadcast "Deploying v2.0 in 5 minutes"
```

## FAQ

**Q: Does this work with GitHub Copilot Chat?**  
A: Yes! Wire MCP tools are available in the chat interface.

**Q: Can I use wire with GitHub Copilot CLI (`gh copilot`)?**  
A: Not yet - CLI support is planned for Phase 2.

**Q: Does wire work offline?**  
A: Local relay mode works offline for same-machine agents. Federation requires internet.

**Q: How do I unpair?**  
```bash
wire peers  # List paired peers
wire unpair <handle>  # Remove the pairing
```

**Q: What's the latency?**  
- Local relay: <10ms
- Federation relay (wireup.net): 50-200ms
- Cross-region: 200-500ms

## See Also

- [Wire README](../../README.md) - Main documentation
- [AGENTS.md](../../AGENTS.md) - Agent integration contract
- [Protocol Spec](../PROTOCOL.md) - Technical details
- [Microsoft Copilot Integration](./MICROSOFT_COPILOT.md) - MS Copilot setup

## Contributing

Found an issue with GitHub Copilot integration? 

- Open an issue: https://github.com/SlanchaAi/wire/issues
- Discord: https://discord.gg/dv2Cd3xzPh

---

**Last updated:** 2026-05-26  
**Wire version:** 0.13.5+  
**VS Code version:** 1.80+
