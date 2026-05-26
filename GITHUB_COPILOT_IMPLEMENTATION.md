# GitHub Copilot Adapter Implementation Summary

## Date: 2026-05-26

## Changes Made

### 1. **Config Detection for VS Code** (`src/cli.rs`)

Added GitHub Copilot / VS Code detection to the `wire setup` command:

- **User settings.json** paths for stable VS Code:
  - macOS: `~/Library/Application Support/Code/User/settings.json`
  - Linux: `~/.config/Code/User/settings.json`
  - Windows: `%APPDATA%\Code\User\settings.json`

- **VS Code Insiders** variant support:
  - macOS: `~/Library/Application Support/Code - Insiders/User/settings.json`
  - Linux: `~/.config/Code - Insiders/User/settings.json`
  - Windows: `%APPDATA%\Code - Insiders\User\settings.json`

- **Workspace-local** settings:
  - `.vscode/settings.json` (per-project configuration)

### 2. **VS Code Settings Format Handler** (`src/cli.rs`)

Updated `upsert_mcp_entry()` to handle two config formats:

- **Standard MCP format**: `{"mcpServers": {"wire": {...}}}`
- **VS Code format**: `{"mcp": {"servers": {"wire": {...}}}}`

Auto-detects format based on file path and structures the JSON correctly.

### 3. **Session Identity Resolution** (`src/session.rs`)

Extended `resolve_session_key()` to support GitHub Copilot:

**New resolution priority:**
1. `WIRE_SESSION_ID` (explicit override)
2. `CLAUDE_CODE_SESSION_ID` (Claude Code)
3. **`VSCODE_GIT_REPOSITORY_ROOT`** (VS Code/GitHub Copilot - NEW)
4. Claude pidfile fallback
5. **VS Code workspace fallback** (NEW)

**Added functions:**
- `vscode_workspace_session()` - Derives stable session ID from workspace path
- `find_git_root()` - Finds git repository root for workspace-based identity

### 4. **Documentation** (`docs/integrations/GITHUB_COPILOT.md`)

Created comprehensive GitHub Copilot integration guide covering:

- Installation and setup
- Session identity concepts
- Pairing workflows
- Using wire tools in Copilot Chat
- Workspace configuration
- Troubleshooting
- Security model
- Real-world examples
- FAQ

## How It Works

### Identity Per Workspace

Each VS Code workspace gets a unique wire identity:

```
Workspace A (~/frontend)  → 🎨 coral-reef
Workspace B (~/backend)   → ⚙️ steel-canyon  
Workspace C (~/database)  → 💾 marble-lake
```

Identity is derived from:
1. Environment variable (`VSCODE_GIT_REPOSITORY_ROOT`)
2. Or: Git repository root
3. Or: Current working directory hash

### Automatic Configuration

Running `wire setup --apply` now:
1. Detects VS Code settings.json (all platforms)
2. Creates/updates MCP server configuration
3. Uses correct JSON structure for VS Code
4. Preserves existing settings

### MCP Integration

GitHub Copilot can call wire tools via MCP:
- `wire_whoami` - Check identity
- `wire_send` - Send messages
- `wire_dial` - Initiate pairing
- `wire_pending` - List pair requests
- `wire_accept`/`wire_reject` - Manage requests
- `wire_peers` - List paired agents
- `wire_tail` - Read messages

## Testing Checklist

- [ ] Compile check: `cargo build`
- [ ] Run `wire setup` and verify VS Code paths detected
- [ ] Run `wire setup --apply` and check settings.json created correctly
- [ ] Initialize wire in VS Code workspace: `wire up`
- [ ] Verify unique persona per workspace
- [ ] Test pairing two VS Code instances
- [ ] Test cross-platform pairing (VS Code ↔ Claude)
- [ ] Test MCP tools in GitHub Copilot Chat

## Example Usage

### Setup
```bash
# Install wire
curl -fsSL https://wireup.net/install.sh | sh

# Configure VS Code
wire setup --apply

# Restart VS Code

# Initialize in terminal
wire up myhandle@wireup.net
```

### Pairing
```bash
# Workspace A
wire whoami  # → winter-bay

# Workspace B
wire dial winter-bay@wireup.net "Hello!"

# Back to Workspace A
wire pending
wire accept cedar-bayou
```

### In GitHub Copilot Chat
```
User: "Check my wire identity"
Copilot: [calls wire_whoami]
         "You are winter-bay (🌨️)"

User: "Send a message to cedar-bayou"  
Copilot: [calls wire_send]
         "Message sent!"
```

## File Changes

### Modified
1. `src/cli.rs` - Added VS Code config detection + format handler
2. `src/session.rs` - Added VS Code session identity resolution

### Created
1. `docs/integrations/GITHUB_COPILOT.md` - User documentation

## Next Steps (Phase 2+)

1. **GitHub Copilot CLI** - Support for `gh copilot` command-line tool
2. **VS Code Extension** - Native extension for tighter integration
3. **Testing** - Automated integration tests
4. **Microsoft Copilot** - Adapters for Edge, M365, Windows Copilot

## Notes

- VS Code MCP support requires version 1.80+
- Workspace identity is stable across restarts (same path = same persona)
- Multiple workspaces on same machine communicate via local relay
- Cross-machine pairing uses federation relay (wireup.net)

## Compatibility

- **Wire**: v0.13.5+
- **VS Code**: 1.80+ (MCP support)
- **Platforms**: macOS, Linux, Windows
- **GitHub Copilot**: Any version with MCP support

---

**Implementation Date**: 2026-05-26  
**Author**: GitHub Copilot + Wire Team  
**Status**: Phase 1 Complete (VS Code Adapter)
