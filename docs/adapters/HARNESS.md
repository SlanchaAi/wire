# Writing a harness adapter

Wire's `wire setup` command auto-detects + auto-installs the wire MCP
server entry into every harness (Claude Code, Cursor, OpenCode, Pi,
GitHub Copilot CLI, VS Code, …) it knows about. Adding a new harness
is a **one-file change + one test** — that's the contract this guide
walks through.

## The contract

Every harness adapter is a static record:

```rust
pub struct HarnessAdapter {
    pub name: &'static str,
    pub paths_fn: fn() -> Vec<PathBuf>,
    pub upsert_fn: fn(&Path, &str, &Value) -> Result<bool>,
}
```

- **`name`** — operator-facing label printed by `wire setup`.
  Examples: `"Claude Code"`, `"OpenCode"`, `"Pi"`.
- **`paths_fn`** — returns every probable config path on the running
  platform. May be empty if the host doesn't ship on the current OS.
  Honor `$XDG_CONFIG_HOME` and per-platform conventions inside.
- **`upsert_fn`** — atomically merges wire's MCP entry into the
  host's config file at `path`. Returns:
  - `Ok(true)` if the file was modified
  - `Ok(false)` if the exact entry was already present (idempotent)
  - `Err` on unrecoverable parse / I/O failure

The registry lives at [`src/adapters/harness.rs`][harness.rs] in the
`HARNESS_ADAPTERS` const. `cli::cmd_setup` walks it.

[harness.rs]: ../../src/adapters/harness.rs

## Three pre-built shapes

You almost never need to write a new `upsert_fn`. Three shapes
cover every MCP-aware host we've seen:

### 1. `upsert_standard` — `{"mcpServers": {"<name>": {...}}}`

The Claude Code shape. Used by Claude Code, Cursor, Claude Desktop,
GitHub Copilot CLI, Pi, and the project-local `.mcp.json`
convention.

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

### 2. `upsert_vscode` — `{"mcp": {"servers": {"<name>": {...}}}}`

Top-level `mcp` key, `servers` intermediate. Used by VS Code's
User `settings.json`, VS Code Insiders, and `.vscode/settings.json`.

```json
{
  "mcp": {
    "servers": {
      "wire": {
        "command": "wire",
        "args": ["mcp"]
      }
    }
  }
}
```

### 3. `upsert_opencode` — `{"mcp": {"<name>": {...combined...}}}`

OpenCode's custom shape. Three differences vs. standard:
- Top-level `mcp` (not `mcpServers`)
- No `servers` intermediate (cf. VS Code)
- `command` is a **single combined array** (`[binary, ...args]`)
- Each entry carries `"type": "local"` and `"enabled": true`

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

## Adding a new harness — step by step

### Step 1: Write the path resolver

```rust
fn my_harness_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(custom) = std::env::var("MY_HARNESS_CONFIG_DIR") {
        out.push(PathBuf::from(custom).join("mcp.json"));
    }
    if let Some(home) = dirs::home_dir() {
        out.push(home.join(".my-harness/mcp.json"));
    }
    out
}
```

Honor the host's documented env override (if any) before the home-dir
default. Empty Vec is the right answer if the host doesn't ship on
this OS (`#[cfg(target_os = "...")]` gating is fine).

### Step 2: Pick the upsert shape

If your harness uses `{"mcpServers": {...}}` (the most common shape),
reuse `upsert_standard`. If it's VS Code style, reuse `upsert_vscode`.
If it's a snowflake like OpenCode, write a new `upsert_*` fn alongside
the three existing ones and document the three-way diff in the doc
comment.

### Step 3: Register

Add an entry to `HARNESS_ADAPTERS` in `src/adapters/harness.rs`:

```rust
HarnessAdapter {
    name: "My Harness",
    paths_fn: my_harness_paths,
    upsert_fn: upsert_standard,
},
```

That's it. `wire setup` now detects + applies to your harness.

### Step 4: Add a test

In the same file's `#[cfg(test)] mod tests` block:

```rust
#[test]
fn upsert_my_harness_works_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcp.json");
    let entry = standard_entry();
    assert!(upsert_standard(&path, "wire", &entry).unwrap());
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(v["mcpServers"]["wire"]["command"], "wire");
    assert!(!upsert_standard(&path, "wire", &entry).unwrap(), "idempotent");
}
```

The existing `registry_includes_every_v0_14_2_published_harness`
test asserts the canonical list. If you're adding (not removing) a
name, that test still passes. If you're removing, add a migration
note.

## Invariants every adapter must hold

- **Sibling-key preservation.** The operator's existing
  `theme: "dark"` / `providers.openai.apiKey: "..."` / other unrelated
  config must survive `wire setup --apply`. The `upsert_*` fns
  guarantee this; reuse them.
- **Idempotence.** A second `wire setup --apply` with the same wire
  entry returns `Ok(false)` and doesn't rewrite the file. Tests must
  assert this directly.
- **JSONC refusal.** VS Code `settings.json` is JSONC (`// comments`,
  trailing commas). serde_json can't parse that. Return `Err` with a
  diagnostic mentioning "not strict JSON" so the operator-facing
  output lists the target under "Skipped" and the user edits the
  file by hand. Do NOT default to `{}` (that would silently
  overwrite the operator's whole config).

## Three things this guide deliberately does NOT cover

- **SSO / IdP provider adapters.** Category 2 in #92, deferred to a
  separate PR coordinating with swift-harbor + slate-lotus.
- **Plugin / extension adapters.** Category 3 in #92, deferred to
  the `did:wire` method + A2A bridge work.
- **Runtime negotiation.** All three adapter categories above are
  for the static-shape "where do I write the wire MCP entry" path.
  The runtime bridge (how MCP messages flow through pi-mcp-adapter,
  opencode's MCP host, etc.) is the harness's concern, not wire's.

## Reference: existing adapters

| Adapter | Shape | Paths |
|---|---|---|
| Claude Code | `upsert_standard` | `~/.claude.json`, `~/.config/claude/mcp.json` |
| Claude Desktop | `upsert_standard` | `~/Library/Application Support/Claude/...` (macOS), `%APPDATA%/Claude/...` (Win) |
| Cursor | `upsert_standard` | `~/.cursor/mcp.json` |
| VS Code (Copilot) | `upsert_vscode` | `~/Library/Application Support/Code/User/settings.json` (macOS), `~/.config/Code/User/settings.json` (linux), `%APPDATA%/Code/...` (Win) |
| VS Code Insiders | `upsert_vscode` | Same as VS Code but `Code - Insiders` |
| GitHub Copilot CLI | `upsert_standard` | `$XDG_CONFIG_HOME/copilot/mcp-config.json`, `~/.copilot/mcp-config.json` |
| Pi | `upsert_standard` | `$PI_CODING_AGENT_DIR/mcp.json`, `~/.pi/agent/mcp.json` |
| OpenCode | `upsert_opencode` | `$XDG_CONFIG_HOME/opencode/opencode.json`, `~/.config/opencode/opencode.json` |
| VS Code workspace | `upsert_vscode` | `.vscode/settings.json` (project-local) |
| project-local | `upsert_standard` | `.mcp.json` (project-local) |
| OpenCode project-local | `upsert_opencode` | `opencode.json` (project-local) |
