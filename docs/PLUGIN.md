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

Claude Code auto-starts `wire mcp` on session start (declared in `.mcp.json`). Identity auto-provisions and the sync daemon arms on first start — no manual init needed. Tools (all prefixed `mcp__wire__` over MCP):

- **Orient / read** — `wire_whoami`, `wire_here` (who am I, who's around?), `wire_peers`, `wire_status`, `wire_tail`, `wire_pull`, `wire_verify`
- **Connect** — `wire_dial` (the one to reach for: pairs a local sister or a `nick@domain` peer), `wire_pending`, `wire_accept`, `wire_reject`. `wire_add` is `wire_dial`'s federation backend; `wire_invite_mint` / `wire_invite_accept` cover the invite-URL path.
- **Talk** — `wire_send`
- **Identity (rarely needed — auto-provisioned)** — `wire_init`, `wire_claim`, `wire_whois`, `wire_profile_set`, `wire_profile_get`
- **Group chat** — `wire_group_create`, `wire_group_add`, `wire_group_invite`, `wire_group_join`, `wire_group_list`, `wire_group_send`, `wire_group_tail`

This list is verified against the live catalog by a test (`agent_docs_match_advertised_tools`) — it fails CI if a tool is added/removed without updating these docs.

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

## Plugin install vs `wire setup` — pick one

The plugin's `.mcp.json` declares the wire MCP server entry. If you previously ran `wire setup --apply` (which writes the same entry into `~/.claude.json`), you'll end up with two `mcpServers.wire` entries — global + plugin-scoped. Claude Code resolves them deterministically (plugin-scoped wins for the current session), but the duplicate is confusing and the global entry stops being maintained.

**Recommended after plugin install:**

```bash
# Remove the global entry the older `wire setup` wrote, since the plugin owns it now.
python3 - <<'EOF'
import json, os
p = os.path.expanduser("~/.claude.json")
with open(p) as f: d = json.load(f)
if "wire" in d.get("mcpServers", {}):
    del d["mcpServers"]["wire"]
    with open(p, "w") as f: json.dump(d, f, indent=2)
    print("removed global mcpServers.wire (plugin now provides it)")
else:
    print("no global mcpServers.wire to remove")
EOF
```

A future `wire setup --apply` will detect a plugin install and skip writing the global entry; pre-v0.14.2 `wire setup` doesn't yet know about the plugin path. Tracking in v0.14.2 backlog.

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
