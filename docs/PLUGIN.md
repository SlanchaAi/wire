# Wire as a Claude plugin

Wire is publishable as a [Claude Code plugin](https://code.claude.com/docs/en/plugins.md). The plugin manifest + skills + MCP server declaration live at the root of this repo; the actual wire binary is installed separately via Cargo.

## Install (end-user UX)

Two steps:

```bash
# 1. Install the wire binary (Rust toolchain or prebuilt release)
cargo install slancha-wire

# 2. Install the Claude plugin pointing at the binary
/plugin install @SlanchaAi/wire
```

Once installed, the plugin's `SessionStart` hook probes wire availability and emits a one-line status to Claude Code. The wire MCP server (`wire mcp`) is declared in `.mcp.json` and Claude Code starts it automatically.

### Plugin slash commands

The plugin ships six skills, all namespaced under `/wire:`:

| Command | Purpose |
|---|---|
| `/wire:wire-init` | Initialize wire — mint session DID + Ed25519 keypair, optionally bind a public relay |
| `/wire:wire-pair` | Pair this session with another wire agent (bilateral, signed, with optional SAS) |
| `/wire:wire-monitor` | Arm the persistent inbox watcher per wire MCP session-start directive |
| `/wire:wire-send` | Send a signed message to a paired peer (auto-pair on miss) |
| `/wire:wire-enroll` | Enroll operator + organization identity (RFC-001 v0.14 identity layer) |
| `/wire:wire-quiet` | Silence wire desktop toasts (file + env-based kill switches) |

### MCP server tools

Claude Code auto-starts `wire mcp` on session start (declared in `.mcp.json`). Available tools:

- `mcp__wire__wire_init`, `wire_up`, `wire_dial`, `wire_pending`, `wire_accept`, `wire_reject`
- `mcp__wire__wire_send`, `wire_tail`, `wire_peers`, `wire_whoami`, `wire_whois`
- `mcp__wire__wire_pair_*` (deprecated; canonical verbs are the bare-named ones above)
- `mcp__wire__wire_group_*` (group chat; v0.13.3+)
- `mcp__wire__wire_invite_mint`, `wire_invite_accept` (SPAKE2 invite path)

Resource: `wire://inbox/<peer>` exposes each pinned peer's verified inbox as JSONL.

## Publishing channels

The plugin is publishable via three paths (all working from the same `.claude-plugin/plugin.json` manifest):

### 1. Direct GitHub install (works today)

```bash
/plugin install @SlanchaAi/wire
```

Pulls the latest commit from `main`. No marketplace listing required.

### 2. Community marketplace (`claude-plugins-community`)

Submit at https://platform.claude.com/plugins/submit or https://claude.ai/settings/plugins/submit. Automated + safety review; gets the plugin discoverable in the community marketplace within days.

### 3. Official marketplace (`claude-plugins-official`)

Anthropic-curated. No application process — only Anthropic decides. Not under Slancha's control.

The three channels coexist. Community submission is recommended as the first public publish path; the direct-GitHub-install works immediately for any wire user who knows the repo URL.

## Versioning

`plugin.json`'s `version` field is the explicit semver tag. Users get updates only when Slancha bumps it. The plugin version typically tracks the wire crate version (v0.14.1 ↔ plugin v0.14.1) — keeping them in lock-step makes "/plugin install wire@0.14.1" + "cargo install slancha-wire@0.14.1" a single-version operator UX.

Omitting the `version` field would make Claude Code use the git commit SHA — every commit is a new version. Slancha pins explicit semver for predictable rollouts.

## Plugin development

To work on the plugin scaffold without affecting end-user sessions:

```bash
# Install the LOCAL plugin manifest (not from GitHub)
/plugin install file:///Users/laul_pogan/Source/wire

# Or symlink from your test session's plugin dir
ln -s ~/Source/wire ~/.claude/plugins/wire
```

Edit `.claude-plugin/plugin.json`, `.mcp.json`, `skills/*/SKILL.md`, or `hooks/scripts/*.sh` — changes pick up on next session start.

## Wire-rooted signing key sovereignty

The wire binary, when started by the plugin's MCP server declaration, reads/writes `~/.config/wire/op.key` (and `~/Library/Application Support/wire/sessions/by-key/<hash>/config/wire/` per-session under Claude Code). No plugin-system sandbox constraints on stdio MCP servers — the signing key stays on the operator's disk, full sovereignty. Per RFC-003 deployment-tiers amendment §"Identity — most-secure default = wire-rooted signing key, ALWAYS", wire identity is always wire-rooted; SSO (when v0.15 connectors ship) is additive attestation.

## Reference

- Plugin overview: https://code.claude.com/docs/en/plugins.md
- Plugin reference: https://code.claude.com/docs/en/plugins-reference.md
- MCP in Claude Code: https://code.claude.com/docs/en/mcp.md
- Wire RFC-001 (identity): `docs/rfc/0001-identity-layer.md`
- Wire RFC-003 (per-company relays): `docs/rfc/0003-per-company-relays.md`
