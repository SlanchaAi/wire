//! Harness adapters — per-host MCP-config registration contract.
//!
//! Each adapter is a small static record declaring (1) the probable
//! on-disk config paths the host reads at startup, and (2) which JSON
//! shape upsert function to merge wire's MCP entry with.
//!
//! ## The contract
//!
//! ```ignore
//! pub struct HarnessAdapter {
//!     pub name: &'static str,
//!     pub paths_fn: fn() -> Vec<PathBuf>,
//!     pub upsert_fn: fn(&Path, &str, &Value) -> Result<bool>,
//! }
//! ```
//!
//! - `name` — operator-facing label printed by `wire setup`.
//! - `paths_fn` — returns every probable config path on the running
//!   platform. May be empty (the host isn't installed on this OS).
//!   Honor `$XDG_CONFIG_HOME` + per-platform conventions inside.
//! - `upsert_fn` — atomically merges the provided MCP entry into the
//!   host's config file at `path`. Returns `Ok(true)` if the file was
//!   changed, `Ok(false)` if the exact entry was already present
//!   (idempotent), `Err` on unrecoverable I/O / parse failure.
//!
//! ## Adding a new harness — three-step recipe
//!
//! 1. Write a `paths_fn` returning the host's probable config paths.
//! 2. Pick (or write) an `upsert_fn`. Three pre-built shapes ship:
//!    - [`upsert_standard`] for `{"mcpServers": {"<name>": {...}}}` —
//!      Claude Code, Cursor, Claude Desktop, GitHub Copilot CLI, Pi,
//!      project-local `.mcp.json`.
//!    - [`upsert_vscode`] for `{"mcp": {"servers": {"<name>": {...}}}}` —
//!      VS Code (Copilot), VS Code Insiders, `.vscode/settings.json`.
//!    - [`upsert_opencode`] for `{"mcp": {"<name>": {"type":"local",
//!      "command":["<bin>",...args], "enabled":true}}}` — OpenCode.
//! 3. Add a [`HarnessAdapter`] entry to [`HARNESS_ADAPTERS`].
//! 4. Add a test in the local `tests` module covering the new path
//!    detection + shape.
//!
//! Walkthrough: `docs/adapters/HARNESS.md`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Value, json};

/// One harness this build can register the wire MCP server with.
pub struct HarnessAdapter {
    /// Operator-facing label printed by `wire setup`.
    pub name: &'static str,
    /// Returns every probable config path on the running platform.
    /// May be empty when the host isn't shipped for the current OS.
    pub paths_fn: fn() -> Vec<PathBuf>,
    /// Atomic merge of `(server_name, entry)` into the host's
    /// config file at `path`. Returns `Ok(true)` on change,
    /// `Ok(false)` on no-op (entry already exact).
    pub upsert_fn: fn(&Path, &str, &Value) -> Result<bool>,
}

/// The registry. Walked by `cli::cmd_setup` in order — first match
/// wins for display order, every match upserts. Adding a harness is
/// one entry here + one test below.
pub const HARNESS_ADAPTERS: &[HarnessAdapter] = &[
    HarnessAdapter {
        name: "Claude Code",
        paths_fn: claude_code_paths,
        upsert_fn: upsert_standard,
    },
    HarnessAdapter {
        name: "Claude Code (alt)",
        paths_fn: claude_code_alt_paths,
        upsert_fn: upsert_standard,
    },
    HarnessAdapter {
        name: "Claude Desktop",
        paths_fn: claude_desktop_paths,
        upsert_fn: upsert_standard,
    },
    HarnessAdapter {
        name: "Cursor",
        paths_fn: cursor_paths,
        upsert_fn: upsert_standard,
    },
    HarnessAdapter {
        name: "VS Code (GitHub Copilot)",
        paths_fn: vscode_paths,
        upsert_fn: upsert_vscode,
    },
    HarnessAdapter {
        name: "VS Code Insiders",
        paths_fn: vscode_insiders_paths,
        upsert_fn: upsert_vscode,
    },
    HarnessAdapter {
        name: "GitHub Copilot CLI",
        paths_fn: copilot_cli_paths,
        upsert_fn: upsert_standard,
    },
    HarnessAdapter {
        name: "Pi",
        paths_fn: pi_paths,
        upsert_fn: upsert_standard,
    },
    HarnessAdapter {
        name: "OpenCode",
        paths_fn: opencode_paths,
        upsert_fn: upsert_opencode,
    },
    HarnessAdapter {
        name: "VS Code (workspace)",
        paths_fn: vscode_workspace_paths,
        upsert_fn: upsert_vscode,
    },
    HarnessAdapter {
        name: "project-local (.mcp.json)",
        paths_fn: project_mcp_paths,
        upsert_fn: upsert_standard,
    },
    HarnessAdapter {
        name: "OpenCode (project-local)",
        paths_fn: opencode_project_paths,
        upsert_fn: upsert_opencode,
    },
];

// ---------- per-host path resolvers ----------

fn claude_code_paths() -> Vec<PathBuf> {
    dirs::home_dir()
        .into_iter()
        .map(|h| h.join(".claude.json"))
        .collect()
}

fn claude_code_alt_paths() -> Vec<PathBuf> {
    dirs::home_dir()
        .into_iter()
        .map(|h| h.join(".config/claude/mcp.json"))
        .collect()
}

#[cfg(target_os = "macos")]
fn claude_desktop_paths() -> Vec<PathBuf> {
    dirs::home_dir()
        .into_iter()
        .map(|h| h.join("Library/Application Support/Claude/claude_desktop_config.json"))
        .collect()
}

#[cfg(target_os = "windows")]
fn claude_desktop_paths() -> Vec<PathBuf> {
    std::env::var("APPDATA")
        .ok()
        .map(|appdata| PathBuf::from(appdata).join("Claude/claude_desktop_config.json"))
        .into_iter()
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn claude_desktop_paths() -> Vec<PathBuf> {
    // Claude Desktop doesn't ship on linux/BSD as of v0.14.x.
    Vec::new()
}

fn cursor_paths() -> Vec<PathBuf> {
    dirs::home_dir()
        .into_iter()
        .map(|h| h.join(".cursor/mcp.json"))
        .collect()
}

#[cfg(target_os = "macos")]
fn vscode_paths() -> Vec<PathBuf> {
    dirs::home_dir()
        .into_iter()
        .map(|h| h.join("Library/Application Support/Code/User/settings.json"))
        .collect()
}

#[cfg(target_os = "linux")]
fn vscode_paths() -> Vec<PathBuf> {
    dirs::home_dir()
        .into_iter()
        .map(|h| h.join(".config/Code/User/settings.json"))
        .collect()
}

#[cfg(target_os = "windows")]
fn vscode_paths() -> Vec<PathBuf> {
    std::env::var("APPDATA")
        .ok()
        .map(|appdata| PathBuf::from(appdata).join("Code/User/settings.json"))
        .into_iter()
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn vscode_paths() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(target_os = "macos")]
fn vscode_insiders_paths() -> Vec<PathBuf> {
    dirs::home_dir()
        .into_iter()
        .map(|h| h.join("Library/Application Support/Code - Insiders/User/settings.json"))
        .collect()
}

#[cfg(target_os = "linux")]
fn vscode_insiders_paths() -> Vec<PathBuf> {
    dirs::home_dir()
        .into_iter()
        .map(|h| h.join(".config/Code - Insiders/User/settings.json"))
        .collect()
}

#[cfg(target_os = "windows")]
fn vscode_insiders_paths() -> Vec<PathBuf> {
    std::env::var("APPDATA")
        .ok()
        .map(|appdata| PathBuf::from(appdata).join("Code - Insiders/User/settings.json"))
        .into_iter()
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn vscode_insiders_paths() -> Vec<PathBuf> {
    Vec::new()
}

fn copilot_cli_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        out.push(PathBuf::from(xdg).join("copilot/mcp-config.json"));
    }
    if let Some(home) = dirs::home_dir() {
        out.push(home.join(".copilot/mcp-config.json"));
    }
    out
}

fn pi_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(pi_dir) = std::env::var("PI_CODING_AGENT_DIR") {
        out.push(PathBuf::from(pi_dir).join("mcp.json"));
    }
    if let Some(home) = dirs::home_dir() {
        out.push(home.join(".pi/agent/mcp.json"));
    }
    out
}

fn opencode_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        out.push(PathBuf::from(xdg).join("opencode/opencode.json"));
    }
    if let Some(home) = dirs::home_dir() {
        out.push(home.join(".config/opencode/opencode.json"));
    }
    out
}

fn vscode_workspace_paths() -> Vec<PathBuf> {
    vec![PathBuf::from(".vscode/settings.json")]
}

fn project_mcp_paths() -> Vec<PathBuf> {
    vec![PathBuf::from(".mcp.json")]
}

fn opencode_project_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("opencode.json")]
}

// ---------- per-shape upsert functions ----------

/// Shared loader: read existing JSON file (or default to empty),
/// guard against non-JSON / non-object roots. Used by every upsert
/// shape so all three behave identically on parse / IO failure.
fn read_config_value(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(json!({}));
    }
    let body = std::fs::read_to_string(path).context("reading config")?;
    if body.trim().is_empty() {
        return Ok(json!({}));
    }
    let parsed: Value = serde_json::from_str(&body).with_context(|| {
        format!(
            "{} is not strict JSON (comments / trailing commas?); \
             add the wire MCP entry manually to avoid overwriting it",
            path.display()
        )
    })?;
    if parsed.is_object() {
        Ok(parsed)
    } else {
        Ok(json!({}))
    }
}

/// Shared writer: atomic-ish write of the merged config. Creates the
/// parent dir on demand. All three upsert shapes share this so file
/// permissions + newline conventions stay consistent.
fn write_config_value(path: &Path, cfg: &Value) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).context("creating parent dir")?;
    }
    let out = serde_json::to_string_pretty(cfg)? + "\n";
    std::fs::write(path, out).context("writing config")?;
    Ok(())
}

/// Standard MCP shape: `{"mcpServers": {"<name>": {"command":
/// "<bin>", "args": [...]}}}`. Used by Claude Code, Cursor, Claude
/// Desktop, GitHub Copilot CLI, Pi, and the project-local
/// `.mcp.json` convention.
pub fn upsert_standard(path: &Path, server_name: &str, entry: &Value) -> Result<bool> {
    let mut cfg = read_config_value(path)?;
    let root = cfg.as_object_mut().unwrap();
    let servers = root
        .entry("mcpServers".to_string())
        .or_insert_with(|| json!({}));
    if !servers.is_object() {
        *servers = json!({});
    }
    let map = servers.as_object_mut().unwrap();
    if map.get(server_name) == Some(entry) {
        return Ok(false);
    }
    map.insert(server_name.to_string(), entry.clone());
    write_config_value(path, &cfg)?;
    Ok(true)
}

/// VS Code shape: `{"mcp": {"servers": {"<name>": {...}}}}`. Used by
/// VS Code (User settings.json), VS Code Insiders, and the
/// `.vscode/settings.json` workspace convention.
pub fn upsert_vscode(path: &Path, server_name: &str, entry: &Value) -> Result<bool> {
    let mut cfg = read_config_value(path)?;
    let root = cfg.as_object_mut().unwrap();
    let mcp = root.entry("mcp".to_string()).or_insert_with(|| json!({}));
    if !mcp.is_object() {
        *mcp = json!({});
    }
    let mcp_obj = mcp.as_object_mut().unwrap();
    let servers = mcp_obj
        .entry("servers".to_string())
        .or_insert_with(|| json!({}));
    if !servers.is_object() {
        *servers = json!({});
    }
    let map = servers.as_object_mut().unwrap();
    if map.get(server_name) == Some(entry) {
        return Ok(false);
    }
    map.insert(server_name.to_string(), entry.clone());
    write_config_value(path, &cfg)?;
    Ok(true)
}

/// OpenCode shape: `{"mcp": {"<name>": {"type": "local", "command":
/// ["<bin>", ...args], "enabled": true}}}`. Three differences vs.
/// standard: top-level `mcp` (not `mcpServers`); no `servers`
/// intermediate; `command` is a single combined array, not the
/// `{command, args}` pair.
pub fn upsert_opencode(path: &Path, server_name: &str, entry: &Value) -> Result<bool> {
    let mut cfg = read_config_value(path)?;
    let root = cfg.as_object_mut().unwrap();
    // Map standard {command, args} → OpenCode combined command array.
    let cmd_str = entry
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("wire");
    let args_arr: Vec<Value> = entry
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut combined: Vec<Value> = vec![Value::String(cmd_str.to_string())];
    combined.extend(args_arr);
    let opencode_entry = json!({
        "type": "local",
        "command": combined,
        "enabled": true,
    });
    let mcp = root.entry("mcp".to_string()).or_insert_with(|| json!({}));
    if !mcp.is_object() {
        *mcp = json!({});
    }
    let map = mcp.as_object_mut().unwrap();
    if map.get(server_name) == Some(&opencode_entry) {
        return Ok(false);
    }
    map.insert(server_name.to_string(), opencode_entry);
    write_config_value(path, &cfg)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standard_entry() -> Value {
        json!({"command": "wire", "args": ["mcp"]})
    }

    #[test]
    fn registry_includes_every_v0_14_2_published_harness() {
        // The published-v0.14.2 docs (PI.md + OPENCODE.md +
        // README.md integrations list) commit to these adapters
        // existing. Adding a harness is fine; removing one needs a
        // deliberate doc + migration story.
        let names: Vec<&str> = HARNESS_ADAPTERS.iter().map(|a| a.name).collect();
        for required in [
            "Claude Code",
            "Cursor",
            "VS Code (GitHub Copilot)",
            "GitHub Copilot CLI",
            "Pi",
            "OpenCode",
        ] {
            assert!(
                names.contains(&required),
                "registry missing required adapter `{required}`"
            );
        }
    }

    #[test]
    fn upsert_standard_writes_mcpservers_shape_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let entry = standard_entry();
        assert!(upsert_standard(&path, "wire", &entry).unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["wire"]["command"], "wire");
        assert_eq!(v["mcpServers"]["wire"]["args"][0], "mcp");
        assert!(
            !upsert_standard(&path, "wire", &entry).unwrap(),
            "idempotent"
        );
    }

    #[test]
    fn upsert_vscode_writes_mcp_servers_intermediate_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let entry = standard_entry();
        assert!(upsert_vscode(&path, "wire", &entry).unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcp"]["servers"]["wire"]["command"], "wire");
        assert!(v.get("mcpServers").is_none());
        assert!(!upsert_vscode(&path, "wire", &entry).unwrap(), "idempotent");
    }

    #[test]
    fn upsert_opencode_writes_combined_command_and_enabled_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");
        let entry = standard_entry();
        assert!(upsert_opencode(&path, "wire", &entry).unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let wire = &v["mcp"]["wire"];
        assert_eq!(wire["type"], "local");
        assert_eq!(wire["enabled"], true);
        assert_eq!(wire["command"][0], "wire");
        assert_eq!(wire["command"][1], "mcp");
        assert!(v.get("mcpServers").is_none());
        assert!(
            !upsert_opencode(&path, "wire", &entry).unwrap(),
            "idempotent"
        );
    }

    #[test]
    fn upsert_preserves_sibling_keys_across_all_three_shapes() {
        // Author-friction guarantee: a host's existing config keys
        // survive a `wire setup --apply` run.
        let dir = tempfile::tempdir().unwrap();
        let entry = standard_entry();
        for sub in ["standard.json", "vscode.json", "opencode.json"] {
            let path = dir.path().join(sub);
            std::fs::write(
                &path,
                r#"{"theme":"dark","providers":{"openai":{"apiKey":"sk-test"}}}"#,
            )
            .unwrap();
            // Pick the matching upsert by filename.
            let upsert: fn(&Path, &str, &Value) -> Result<bool> = if sub == "standard.json" {
                upsert_standard
            } else if sub == "vscode.json" {
                upsert_vscode
            } else {
                upsert_opencode
            };
            assert!(upsert(&path, "wire", &entry).unwrap());
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(v["theme"], "dark");
            assert_eq!(v["providers"]["openai"]["apiKey"], "sk-test");
        }
    }

    #[test]
    fn upsert_refuses_to_overwrite_unparseable_json() {
        // JSONC files (VS Code settings.json with comments / trailing
        // commas) are common. We must NOT replace them with our own
        // `{...wire only...}` content. Instead return Err so the
        // caller surfaces the target under "Skipped" and the
        // operator edits the file by hand.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "// theme override\n{\"theme\":\"dark\",}").unwrap();
        let entry = standard_entry();
        let err = upsert_vscode(&path, "wire", &entry).unwrap_err();
        // The Err message must mention the JSON parse problem so the
        // operator knows why we didn't write.
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not strict JSON"),
            "expected 'not strict JSON' diagnostic, got: {msg}"
        );
        // File must be unchanged.
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("// theme override"));
    }
}
