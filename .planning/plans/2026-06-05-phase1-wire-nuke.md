# Phase 1 — `wire nuke` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `wire nuke` command that hard-resets the machine to a clean wire state (kill procs → remove service units → de-register the wire MCP entry from host configs → wipe all wire dirs), with `--purge` for full binary+shell removal and `--dry-run`/typed-confirm/`--force` safety.

**Architecture:** A new pure `src/nuke.rs` computes a `NukePlan` (the set of paths, service units, MCP host-entries, and pids that *would* be removed) from the environment; `cmd_nuke` in `cli.rs` renders the plan (dry-run), gates on confirmation, then executes it by composing existing primitives (`service::uninstall_kind`, a new `harness::remove_mcp_entry`, fs removal, process kill). Keeping plan-computation pure makes it unit-testable without touching the real machine.

**Tech Stack:** Rust 2024, `anyhow`, `serde_json`, `dirs`, existing `service` + `adapters::harness` + `config` + `session` modules. Tests use the existing `config::test_support::with_temp_home` (ENV_LOCK) pattern.

**Spec:** `.planning/specs/2026-06-05-remove-backwards-compat-design.md` (Phase 1 section).

**Per-merge gate (HARD, from spec):** test-env container green → CI green → fresh-env install+smoke on **macOS + Linux + Windows** → person review → merge.

---

### Task 1: `remove_mcp_entry` counterparts in `adapters/harness.rs`

Mirror the three `upsert_*` shapes with `remove_*` functions, and add a `remove_fn` to `HarnessAdapter` so the registry drives de-registration the same way it drives registration. Removal must NOT create a missing file (nothing to remove → `Ok(false)`).

**Files:**
- Modify: `src/adapters/harness.rs` (add `remove_fn` field + 3 remove fns + registry entries + tests)

- [ ] **Step 1: Write the failing tests** (append to `harness.rs` `mod tests`)

```rust
    #[test]
    fn remove_standard_drops_only_wire_and_preserves_siblings() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("mcp.json");
        std::fs::write(&p, r#"{"mcpServers":{"wire":{"command":"wire","args":["mcp"]},"other":{"command":"x"}}}"#).unwrap();
        assert!(remove_standard(&p, "wire").unwrap(), "should report changed");
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert!(v["mcpServers"].get("wire").is_none(), "wire removed");
        assert!(v["mcpServers"].get("other").is_some(), "sibling preserved");
        // idempotent: second remove is a no-op
        assert!(!remove_standard(&p, "wire").unwrap());
    }

    #[test]
    fn remove_vscode_drops_wire_under_mcp_servers() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("settings.json");
        std::fs::write(&p, r#"{"mcp":{"servers":{"wire":{"command":"wire"},"keep":{}}},"editor.fontSize":12}"#).unwrap();
        assert!(remove_vscode(&p, "wire").unwrap());
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert!(v["mcp"]["servers"].get("wire").is_none());
        assert!(v["mcp"]["servers"].get("keep").is_some());
        assert_eq!(v["editor.fontSize"], 12, "unrelated keys preserved");
    }

    #[test]
    fn remove_opencode_drops_wire_under_mcp() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("opencode.json");
        std::fs::write(&p, r#"{"mcp":{"wire":{"type":"local","command":["wire","mcp"],"enabled":true},"keep":{}}}"#).unwrap();
        assert!(remove_opencode(&p, "wire").unwrap());
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert!(v["mcp"].get("wire").is_none());
        assert!(v["mcp"].get("keep").is_some());
    }

    #[test]
    fn remove_is_noop_when_file_absent_or_key_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("nope.json");
        assert!(!remove_standard(&absent, "wire").unwrap(), "absent file → no-op, no create");
        assert!(!absent.exists(), "must not create the file");
        let p = tmp.path().join("c.json");
        std::fs::write(&p, r#"{"mcpServers":{"other":{}}}"#).unwrap();
        assert!(!remove_standard(&p, "wire").unwrap(), "missing key → no-op");
    }

    #[test]
    fn every_adapter_has_a_remove_fn() {
        for a in HARNESS_ADAPTERS {
            // remove_fn is a real fn pointer; calling it on an absent path is a safe no-op.
            let tmp = tempfile::tempdir().unwrap();
            let p = tmp.path().join("absent.json");
            assert!(!(a.remove_fn)(&p, "wire").unwrap(), "{} remove_fn on absent → false", a.name);
        }
    }
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --lib adapters::harness::tests::remove 2>&1 | tail`
Expected: FAIL — `remove_standard`/`remove_vscode`/`remove_opencode` and the `remove_fn` field don't exist yet.

- [ ] **Step 3: Add the `remove_fn` field to `HarnessAdapter`**

In the struct definition (after `upsert_fn`):

```rust
    /// Remove the `(server_name)` entry from the host's config at
    /// `path`. Returns `Ok(true)` on change, `Ok(false)` if the file
    /// is absent or the entry wasn't present (idempotent). MUST NOT
    /// create a missing file.
    pub remove_fn: fn(&Path, &str) -> Result<bool>,
```

- [ ] **Step 4: Implement the three remove fns** (place beside the `upsert_*` fns)

```rust
/// Remove `server_name` from `{"mcpServers": {...}}`. No-op if the
/// file is absent or the key is missing.
pub fn remove_standard(path: &Path, server_name: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut cfg = read_config_value(path)?;
    let changed = cfg
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .map(|m| m.remove(server_name).is_some())
        .unwrap_or(false);
    if changed {
        write_config_value(path, &cfg)?;
    }
    Ok(changed)
}

/// Remove `server_name` from `{"mcp": {"servers": {...}}}` (VS Code).
pub fn remove_vscode(path: &Path, server_name: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut cfg = read_config_value(path)?;
    let changed = cfg
        .get_mut("mcp")
        .and_then(Value::as_object_mut)
        .and_then(|m| m.get_mut("servers"))
        .and_then(Value::as_object_mut)
        .map(|m| m.remove(server_name).is_some())
        .unwrap_or(false);
    if changed {
        write_config_value(path, &cfg)?;
    }
    Ok(changed)
}

/// Remove `server_name` from `{"mcp": {"<name>": {...}}}` (OpenCode).
pub fn remove_opencode(path: &Path, server_name: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut cfg = read_config_value(path)?;
    let changed = cfg
        .get_mut("mcp")
        .and_then(Value::as_object_mut)
        .map(|m| m.remove(server_name).is_some())
        .unwrap_or(false);
    if changed {
        write_config_value(path, &cfg)?;
    }
    Ok(changed)
}
```

- [ ] **Step 5: Add `remove_fn` to every `HARNESS_ADAPTERS` entry**

For each entry, add the matching remove fn beside its `upsert_fn`:
- `upsert_standard` → `remove_fn: remove_standard`
- `upsert_vscode` → `remove_fn: remove_vscode`
- `upsert_opencode` → `remove_fn: remove_opencode`

(One line per adapter; mechanical — match the shape already chosen by `upsert_fn`.)

- [ ] **Step 6: Run tests, verify pass + no regressions**

Run: `cargo test --lib adapters::harness 2>&1 | tail`
Expected: PASS (new remove tests + existing upsert tests all green).

- [ ] **Step 7: Commit**

```bash
git add src/adapters/harness.rs
git commit -s -m "feat(adapters): remove_mcp_entry counterparts + remove_fn on HarnessAdapter"
```

---

### Task 2: `src/nuke.rs` — pure removal-plan computation

A `NukePlan` enumerates everything a nuke would remove, computed from the environment without mutating anything. This is the dry-run output and the execution input.

**Files:**
- Create: `src/nuke.rs`
- Modify: `src/lib.rs` (add `pub mod nuke;`)

- [ ] **Step 1: Write the failing test** (in `src/nuke.rs` `mod tests`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_lists_existing_wire_dirs_only() {
        crate::config::test_support::with_temp_home(|| {
            // Create a couple of the dirs a real install would have.
            crate::config::ensure_dirs().unwrap();
            let plan = NukePlan::compute(false).unwrap();
            // state_dir + config_dir exist → both in the plan; nonexistent
            // dirs are skipped (we don't list paths that aren't there).
            assert!(plan.paths.iter().any(|p| p.ends_with("wire")),
                "expected a wire dir in {:?}", plan.paths);
            assert!(!plan.purge_binary, "default plan does not remove the binary");
        });
    }

    #[test]
    fn purge_plan_sets_binary_removal() {
        crate::config::test_support::with_temp_home(|| {
            let plan = NukePlan::compute(true).unwrap();
            assert!(plan.purge_binary);
        });
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cargo test --lib nuke:: 2>&1 | tail`
Expected: FAIL — module `nuke` doesn't exist.

- [ ] **Step 3: Implement `src/nuke.rs`**

```rust
//! `wire nuke` — hard reset of all wire state on the machine.
//!
//! `NukePlan::compute` enumerates everything that would be removed
//! (paths, service units, host MCP entries, optionally the binary)
//! WITHOUT mutating anything — it is the dry-run output and the
//! execution input. `NukePlan::execute` performs the removal.

use std::path::PathBuf;

use anyhow::Result;
use serde::Serialize;

/// Everything a nuke will tear down. Computed from the environment;
/// pure (no mutation) so it can be printed for --dry-run / confirm.
#[derive(Debug, Serialize)]
pub struct NukePlan {
    /// Directories to delete (only those that currently exist).
    pub paths: Vec<PathBuf>,
    /// Host MCP config files we'll de-register the `wire` entry from
    /// (only files that currently exist).
    pub mcp_files: Vec<PathBuf>,
    /// True if the `wire` binary + shell lines should also go (--purge).
    pub purge_binary: bool,
}

impl NukePlan {
    /// Compute the plan. `purge` = remove binary + shell lines too.
    pub fn compute(purge: bool) -> Result<Self> {
        let mut paths = Vec::new();
        // Default-session config/state + machine-wide sessions root + cache.
        for p in [
            crate::config::config_dir().ok(),
            crate::config::state_dir().ok(),
            crate::session::sessions_root().ok(),
            dirs::cache_dir().map(|c| c.join("wire")),
        ]
        .into_iter()
        .flatten()
        {
            if p.exists() && !paths.contains(&p) {
                paths.push(p);
            }
        }
        // Host MCP config files that actually exist (one per adapter path).
        let mut mcp_files = Vec::new();
        for adapter in crate::adapters::harness::HARNESS_ADAPTERS {
            for path in (adapter.paths_fn)() {
                if path.exists() && !mcp_files.contains(&path) {
                    mcp_files.push(path);
                }
            }
        }
        Ok(NukePlan { paths, mcp_files, purge_binary: purge })
    }
}
```

- [ ] **Step 4: Register the module** — add to `src/lib.rs` in alpha order with the other `pub mod` lines:

```rust
pub mod nuke;
```

- [ ] **Step 5: Run test, verify pass**

Run: `cargo test --lib nuke:: 2>&1 | tail`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/nuke.rs src/lib.rs
git commit -s -m "feat(nuke): NukePlan — pure removal-plan computation"
```

---

### Task 3: `NukePlan::execute` + MCP de-registration across adapters

Execute the plan: de-register `wire` from each existing MCP file, remove service units, delete dirs. Returns a `NukeReport` of what was actually done.

**Files:**
- Modify: `src/nuke.rs`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn execute_removes_dirs_and_mcp_entry() {
        crate::config::test_support::with_temp_home(|| {
            crate::config::ensure_dirs().unwrap();
            let state = crate::config::state_dir().unwrap();
            assert!(state.exists());
            // A fake host MCP file under the temp home with a wire entry.
            let mcp = std::path::PathBuf::from(std::env::var("WIRE_HOME").unwrap()).join("mcp.json");
            std::fs::write(&mcp, r#"{"mcpServers":{"wire":{"command":"wire"}}}"#).unwrap();
            let plan = NukePlan {
                paths: vec![state.clone()],
                mcp_files: vec![mcp.clone()],
                purge_binary: false,
            };
            let report = plan.execute().unwrap();
            assert!(!state.exists(), "state dir deleted");
            let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&mcp).unwrap()).unwrap();
            assert!(v["mcpServers"].get("wire").is_none(), "wire de-registered");
            assert!(report.removed_paths.contains(&state));
            assert!(report.removed_mcp_entries.contains(&mcp));
        });
    }
```

- [ ] **Step 2: Run, verify fail** — `cargo test --lib nuke::tests::execute 2>&1 | tail` → FAIL (`execute`/`NukeReport` undefined).

- [ ] **Step 3: Implement `execute` + `NukeReport`** (append to `src/nuke.rs`)

```rust
/// What a nuke actually did (for --json + operator output).
#[derive(Debug, Default, Serialize)]
pub struct NukeReport {
    pub removed_paths: Vec<PathBuf>,
    pub removed_mcp_entries: Vec<PathBuf>,
    pub removed_units: Vec<String>,
    pub killed_pids: Vec<u32>,
    pub binary_removed: bool,
    /// Non-fatal warnings (e.g. a unit that wasn't installed).
    pub warnings: Vec<String>,
}

impl NukePlan {
    /// Perform the teardown. Best-effort: a failure on one item is
    /// recorded in `warnings` and the rest proceed (a nuke that
    /// half-aborts leaves a confusing machine — the whole point is to
    /// finish the job; cf. rustup #1072).
    pub fn execute(&self) -> Result<NukeReport> {
        let mut r = NukeReport::default();

        // 1. Service units (cross-platform via existing impl).
        for kind in [
            crate::service::ServiceKind::Daemon,
            crate::service::ServiceKind::LocalRelay,
        ] {
            match crate::service::uninstall_kind(kind) {
                Ok(rep) => r.removed_units.push(format!("{kind:?}: {}", rep.platform)),
                Err(e) => r.warnings.push(format!("uninstall {kind:?}: {e:#}")),
            }
        }

        // 2. De-register the wire MCP entry from each host file.
        //    Walk adapters; for each existing file matching an adapter
        //    path, call that adapter's remove_fn for the "wire" server.
        for adapter in crate::adapters::harness::HARNESS_ADAPTERS {
            for path in (adapter.paths_fn)() {
                if self.mcp_files.contains(&path) {
                    match (adapter.remove_fn)(&path, "wire") {
                        Ok(true) => r.removed_mcp_entries.push(path),
                        Ok(false) => {}
                        Err(e) => r.warnings.push(format!("mcp de-register {}: {e:#}", path.display())),
                    }
                }
            }
        }

        // 3. Delete dirs.
        for p in &self.paths {
            match std::fs::remove_dir_all(p) {
                Ok(()) => r.removed_paths.push(p.clone()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => r.warnings.push(format!("rm {}: {e:#}", p.display())),
            }
        }

        Ok(r)
    }
}
```

> NOTE for the implementer: confirm `service::ServiceKind` is `pub` and has `Daemon` + `LocalRelay` variants and that `ServiceReport` has a `platform: String` field (it does — `src/service.rs:40,130`). If `ServiceKind` doesn't derive `Debug`, add `#[derive(Debug)]` to it in `service.rs` (needed for the `{kind:?}` format). Process-kill (survivors) is intentionally deferred to Task 4 `cmd_nuke` because it shells out and isn't unit-testable here.

- [ ] **Step 4: Run, verify pass** — `cargo test --lib nuke:: 2>&1 | tail` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/nuke.rs src/service.rs
git commit -s -m "feat(nuke): execute — de-register MCP, remove units, wipe dirs"
```

---

### Task 4: confirmation gating (pure, injectable)

The typed-`nuke` confirm + `--force` logic as a pure function so it's testable without a TTY.

**Files:**
- Modify: `src/nuke.rs`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn confirm_logic() {
        // --force always proceeds, no input read.
        assert!(should_proceed(/*force*/ true, /*is_tty*/ false, || unreachable!()));
        // non-TTY without force → refuse.
        assert!(!should_proceed(false, false, || String::new()));
        // TTY: proceed iff the typed line is exactly "nuke".
        assert!(should_proceed(false, true, || "nuke".to_string()));
        assert!(!should_proceed(false, true, || "no".to_string()));
        assert!(!should_proceed(false, true, || "NUKE".to_string()));
    }
```

- [ ] **Step 2: Run, verify fail** — FAIL (`should_proceed` undefined).

- [ ] **Step 3: Implement**

```rust
/// Decide whether to proceed. `force` bypasses all prompts; otherwise
/// a non-TTY refuses, and a TTY proceeds only on an exact "nuke" line.
/// `read_line` is injected so this is unit-testable.
pub fn should_proceed(force: bool, is_tty: bool, read_line: impl FnOnce() -> String) -> bool {
    if force {
        return true;
    }
    if !is_tty {
        return false;
    }
    read_line().trim() == "nuke"
}
```

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Commit**

```bash
git add src/nuke.rs
git commit -s -m "feat(nuke): pure confirm-gating (typed nuke / --force / non-TTY refuse)"
```

---

### Task 5: `Nuke` subcommand + `cmd_nuke` + `--purge` + wiring

Surface the command, render dry-run, gate, execute, and implement `--purge` (binary + shell lines, with the Windows self-delete caveat).

**Files:**
- Modify: `src/cli.rs` (add `Nuke { ... }` to the top-level `Command` enum; add `cmd_nuke`; add the dispatch arm in `run`)

- [ ] **Step 1: Add the enum variant** — in the top-level `Command` enum (beside other top-level verbs like `Up`, `Status`), match the surrounding doc-comment + attribute style:

```rust
    /// Hard-reset this machine to a clean wire state: kill daemons,
    /// remove service units, de-register the wire MCP entry from host
    /// configs, and wipe all wire dirs. `--purge` also removes the
    /// binary + shell lines. Requires --force or a typed confirmation.
    Nuke {
        /// Skip the typed confirmation (for automation / test harness).
        /// `--yes` is an accepted alias.
        #[arg(long, visible_alias = "yes")]
        force: bool,
        /// Also remove the `wire` binary + shell PATH/env lines.
        #[arg(long)]
        purge: bool,
        /// Print what would be removed and exit without changing anything.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
```

- [ ] **Step 2: Add the dispatch arm** — in `run`'s `match command` (where other arms like `Command::Status { .. } => ...` live):

```rust
        Command::Nuke { force, purge, dry_run, json } => cmd_nuke(force, purge, dry_run, json),
```

- [ ] **Step 3: Implement `cmd_nuke`** (next to other `cmd_*` fns in `cli.rs`)

```rust
fn cmd_nuke(force: bool, purge: bool, dry_run: bool, as_json: bool) -> Result<()> {
    use std::io::{IsTerminal, Write};
    let plan = crate::nuke::NukePlan::compute(purge)?;

    // Render what will/would be removed.
    if as_json && dry_run {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }
    if !as_json {
        eprintln!("wire nuke will remove:");
        for p in &plan.paths {
            eprintln!("  dir   {}", p.display());
        }
        for m in &plan.mcp_files {
            eprintln!("  mcp   {} (de-register `wire`)", m.display());
        }
        eprintln!("  units launchd/systemd/schtasks (daemon + local-relay)");
        eprintln!("  procs any running wire daemon / supervisor / relay-server");
        if purge {
            eprintln!("  PURGE the `wire` binary + shell PATH/env lines");
        }
    }
    if dry_run {
        return Ok(());
    }

    // Gate.
    if !crate::nuke::should_proceed(force, std::io::stdin().is_terminal(), || {
        eprint!("\nType `nuke` to confirm: ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        line
    }) {
        if !as_json {
            eprintln!("aborted — nothing removed. (Use --force for automation.)");
        }
        anyhow::bail!("nuke not confirmed");
    }

    // Kill survivors not covered by unit teardown (best-effort).
    let killed = kill_wire_processes();

    // Execute.
    let mut report = plan.execute()?;
    report.killed_pids = killed;

    // --purge: remove binary + shell lines.
    if purge {
        report.binary_removed = purge_binary_and_shell(&mut report.warnings);
    }

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        eprintln!(
            "nuked: {} dir(s), {} mcp entr(ies), {} unit(s), {} proc(s){}",
            report.removed_paths.len(),
            report.removed_mcp_entries.len(),
            report.removed_units.len(),
            report.killed_pids.len(),
            if report.binary_removed { ", binary+shell" } else { "" },
        );
        for w in &report.warnings {
            eprintln!("  warn: {w}");
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Implement the two helpers** (`cli.rs`)

```rust
/// Best-effort kill of any wire daemon / supervisor / relay-server
/// process. Returns the pids we asked the OS to terminate.
fn kill_wire_processes() -> Vec<u32> {
    let mut killed = Vec::new();
    #[cfg(unix)]
    for pat in ["wire daemon", "relay-server"] {
        if let Ok(out) = std::process::Command::new("pkill").arg("-f").arg(pat).output() {
            // pkill exit 0 = killed something; record nothing granular (best-effort).
            let _ = out;
        }
    }
    #[cfg(windows)]
    {
        // taskkill by image name; wire.exe children.
        let _ = std::process::Command::new("taskkill").args(["/F", "/IM", "wire.exe"]).output();
    }
    // (pid enumeration omitted; pkill/taskkill are the teardown. The
    //  empty/recorded vec keeps the report shape stable.)
    let _ = &mut killed;
    killed
}

/// --purge: remove the wire binary + scrub shell PATH/env lines.
/// Returns true if the binary was removed (false on the Windows
/// self-delete case, where we print the manual command instead).
fn purge_binary_and_shell(warnings: &mut Vec<String>) -> bool {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => { warnings.push(format!("resolve exe: {e:#}")); return false; }
    };
    #[cfg(windows)]
    {
        eprintln!("purge: a running .exe can't delete itself. Remove it manually:");
        eprintln!("  del \"{}\"", exe.display());
        warnings.push("binary self-delete skipped on Windows (manual del printed)".into());
        return false;
    }
    #[cfg(unix)]
    {
        match std::fs::remove_file(&exe) {
            Ok(()) => {
                // Best-effort shell-line scrub: well-known rc files.
                scrub_shell_lines(warnings);
                true
            }
            Err(e) => { warnings.push(format!("rm binary {}: {e:#}", exe.display())); false }
        }
    }
}

#[cfg(unix)]
fn scrub_shell_lines(warnings: &mut Vec<String>) {
    let Some(home) = dirs::home_dir() else { return };
    for rc in [".bashrc", ".zshrc", ".profile", ".config/fish/config.fish"] {
        let path = home.join(rc);
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        let filtered: String = content
            .lines()
            .filter(|l| !(l.contains("wire") && (l.contains("PATH") || l.contains("WIRE_"))))
            .collect::<Vec<_>>()
            .join("\n");
        if filtered != content {
            if let Err(e) = std::fs::write(&path, filtered + "\n") {
                warnings.push(format!("scrub {}: {e:#}", path.display()));
            }
        }
    }
}
```

> NOTE: `kill_wire_processes` is deliberately coarse (pkill/taskkill) — the service-unit teardown in `execute()` already stops the supervised processes; this just sweeps stragglers. Keep it best-effort; do not fail the nuke on a kill error.

- [ ] **Step 5: Build + clippy + fmt**

Run: `cargo build 2>&1 | tail -3 && cargo clippy --all-targets -- -D warnings 2>&1 | tail -3 && cargo fmt --all`
Expected: clean.

- [ ] **Step 6: Run the full suite (lib)**

Run: `cargo test --lib 2>&1 | grep 'test result'`
Expected: all `ok`, 0 failed.

- [ ] **Step 7: Commit**

```bash
git add src/cli.rs
git commit -s -m "feat(cli): wire nuke — hard reset (dry-run/confirm/--force/--purge)"
```

---

### Task 6: Validate in the test-env container + cross-platform manual gate

- [ ] **Step 1: Full gate in the container**

Run: `test-env/run.sh > /tmp/nuke-gate.log 2>&1; echo "EXIT=$?"; grep 'test result' /tmp/nuke-gate.log | grep -v ' 0 failed' || echo "all 0 failed"`
Expected: `EXIT=0`, no failing suites.

- [ ] **Step 2: macOS fresh-env manual run** (this host, a throwaway HOME)

```bash
D=$(mktemp -d); HOME="$D" WIRE_HOME="$D/wh" wire up --no-local
HOME="$D" WIRE_HOME="$D/wh" wire nuke --dry-run        # lists, removes nothing
HOME="$D" WIRE_HOME="$D/wh" wire nuke --force          # state+units+mcp gone, binary intact
HOME="$D" WIRE_HOME="$D/wh" wire up --no-local         # works clean again
```
Expected: dry-run changes nothing; `--force` reports removed dirs/units/mcp; re-`up` succeeds.

- [ ] **Step 3: Linux fresh-env** — same sequence in a fresh `ubuntu:24.04` container after `curl install.sh | sh` (or a mounted build).

- [ ] **Step 4: Windows** — push the branch; confirm the new `windows-latest` install-smoke job is green (added in Phase-1 PR if not already), then operator confirms `wire nuke --force` + `--purge` on `DESKTOP-1LK5VSJ` (manual; the runtime can't run Windows).

- [ ] **Step 5: Open the PR** with the cross-platform results in the description; request person review. **Do not merge** until container + CI + all three OSes + review are green.

---

## Notes for the implementer

- Confirm exact `ServiceKind` variant names in `src/service.rs:40` (`Daemon`, `LocalRelay`); adjust the `execute()` loop if the local-relay variant is named differently.
- `read_config_value` / `write_config_value` are existing private helpers in `harness.rs` — the `remove_*` fns are in the same module so they have access.
- The Windows install-smoke CI job is a Phase-1 deliverable (the spec's cross-platform gate); if not already present, add a `windows-latest` variant of the `install-smoke` job in `.github/workflows/ci.yml` mirroring the Ubuntu one (PowerShell-adapted smoke).
