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
        Ok(NukePlan {
            paths,
            mcp_files,
            purge_binary: purge,
        })
    }

    /// Perform the teardown. Best-effort: a failure on one item is
    /// recorded in `warnings` and the rest proceed (a nuke that
    /// half-aborts leaves a confusing machine — the whole point is to
    /// finish the job; cf. rustup #1072).
    pub fn execute(&self) -> Result<NukeReport> {
        self.execute_with(|kind| crate::service::uninstall_kind(kind).map(|rep| rep.platform))
    }

    /// `execute` with the service-unit teardown injected. The unit
    /// uninstall is the ONE machine-global step that no temp `WIRE_HOME`
    /// can scope — calling the real thing from a unit test boots the
    /// operator's live launchd daemon out from under them (it did,
    /// 2026-06-11: every host `cargo test --lib` removed the dev box's
    /// `sh.slancha.wire.daemon` unit and killed its process tree — THE
    /// recurring "wire is mysteriously down" engine). Tests pass a stub;
    /// only `execute()` reaches launchctl/systemd/schtasks.
    fn execute_with<U>(&self, uninstall_unit: U) -> Result<NukeReport>
    where
        U: Fn(crate::service::ServiceKind) -> Result<String>,
    {
        let mut r = NukeReport::default();

        // 1. Service units (cross-platform via existing impl).
        for kind in [
            crate::service::ServiceKind::Daemon,
            crate::service::ServiceKind::LocalRelay,
        ] {
            match uninstall_unit(kind) {
                Ok(platform) => r.removed_units.push(format!("{kind:?}: {platform}")),
                Err(e) => r.warnings.push(format!("uninstall {kind:?}: {e:#}")),
            }
        }

        // 2. De-register the wire MCP entry from each host file.
        //    For each file in the plan, try every adapter's remove_fn
        //    (each is a no-op / Ok(false) on files it doesn't own).
        //    First adapter that reports Ok(true) wins; the rest skip.
        'files: for path in &self.mcp_files {
            for adapter in crate::adapters::harness::HARNESS_ADAPTERS {
                match (adapter.remove_fn)(path, "wire") {
                    Ok(true) => {
                        r.removed_mcp_entries.push(path.clone());
                        continue 'files;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        r.warnings
                            .push(format!("mcp de-register {}: {e:#}", path.display()));
                        continue 'files;
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

/// Parse `(cwd, session-name)` bindings out of a session registry's raw
/// bytes. Malformed/empty input → no bindings (the guard then stays
/// silent, matching a machine with no operator install).
pub fn parse_registry_bindings(bytes: &[u8]) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Vec::new();
    };
    let Some(by_cwd) = v.get("by_cwd").and_then(|m| m.as_object()) else {
        return Vec::new();
    };
    by_cwd
        .iter()
        .filter_map(|(cwd, name)| name.as_str().map(|n| (cwd.clone(), n.to_string())))
        .collect()
}

/// Read the cwd→session bindings of the machine's DEFAULT registry —
/// `WIRE_HOME` deliberately ignored, because nuke's unit/process/MCP
/// teardown is machine-global no matter what home the caller resolved.
/// Any read failure → empty (no install worth guarding).
pub fn default_registry_bindings() -> Vec<(String, String)> {
    let Ok(root) = crate::session::default_sessions_root() else {
        return Vec::new();
    };
    match std::fs::read(root.join("registry.json")) {
        Ok(bytes) => parse_registry_bindings(&bytes),
        Err(_) => Vec::new(),
    }
}

/// Operator-machine guard. `wire nuke` tears down MACHINE-GLOBAL
/// surfaces — launchd/systemd units, host MCP configs, every running
/// wire daemon — regardless of `WIRE_HOME`, so an agent or test harness
/// invoking it under a temp home still takes the operator's live
/// install down with it (this killed a dev box's daemon during v0.15
/// testing). Registry cwd bindings only exist when an operator
/// deliberately bound sessions, so they are the "live install" signal.
/// Returns the refusal message, or `None` to proceed.
pub fn host_guard_refusal(bound: &[(String, String)], really: bool) -> Option<String> {
    if really || bound.is_empty() {
        return None;
    }
    let mut msg = format!(
        "refusing to nuke: this machine has a live wire install ({} registry-bound session(s)):\n",
        bound.len()
    );
    for (cwd, name) in bound {
        msg.push_str(&format!("  {name}  ←  {cwd}\n"));
    }
    msg.push_str(
        "nuke removes launchd/systemd units, MCP registrations, and kills every wire daemon \
         machine-wide — even when WIRE_HOME points elsewhere.\n\
         If you really mean this machine, re-run with --really-this-machine.",
    );
    Some(msg)
}

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
            assert!(
                plan.paths.iter().any(|p| p.ends_with("wire")),
                "expected a wire dir in {:?}",
                plan.paths
            );
            assert!(
                !plan.purge_binary,
                "default plan does not remove the binary"
            );
        });
    }

    #[test]
    fn purge_plan_sets_binary_removal() {
        crate::config::test_support::with_temp_home(|| {
            let plan = NukePlan::compute(true).unwrap();
            assert!(plan.purge_binary);
        });
    }

    #[test]
    fn confirm_logic() {
        // --force always proceeds, no input read.
        assert!(should_proceed(
            /*force*/ true,
            /*is_tty*/ false,
            || unreachable!()
        ));
        // non-TTY without force → refuse.
        assert!(!should_proceed(false, false, String::new));
        // TTY: proceed iff the typed line is exactly "nuke".
        assert!(should_proceed(false, true, || "nuke".to_string()));
        assert!(!should_proceed(false, true, || "no".to_string()));
        assert!(!should_proceed(false, true, || "NUKE".to_string()));
    }

    #[test]
    fn execute_removes_dirs_and_mcp_entry() {
        crate::config::test_support::with_temp_home(|| {
            crate::config::ensure_dirs().unwrap();
            let state = crate::config::state_dir().unwrap();
            assert!(state.exists());
            // A fake host MCP file under the temp home with a wire entry.
            let mcp =
                std::path::PathBuf::from(std::env::var("WIRE_HOME").unwrap()).join("mcp.json");
            std::fs::write(&mcp, r#"{"mcpServers":{"wire":{"command":"wire"}}}"#).unwrap();
            let plan = NukePlan {
                paths: vec![state.clone()],
                mcp_files: vec![mcp.clone()],
                purge_binary: false,
            };
            // Stub the unit teardown — NEVER call `execute()` (the real
            // launchctl path) from a test; it boots the host's live
            // daemon out. See `execute_with`'s doc.
            let report = plan.execute_with(|_kind| Ok("stub".to_string())).unwrap();
            assert_eq!(report.removed_units.len(), 2, "both unit kinds attempted");
            assert!(!state.exists(), "state dir deleted");
            let v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&mcp).unwrap()).unwrap();
            assert!(v["mcpServers"].get("wire").is_none(), "wire de-registered");
            assert!(report.removed_paths.contains(&state));
            assert!(report.removed_mcp_entries.contains(&mcp));
        });
    }

    // ---- host guard ----

    #[test]
    fn host_guard_silent_with_no_bindings() {
        // Fresh machine / CI runner: default registry empty → no guard.
        assert_eq!(host_guard_refusal(&[], false), None);
        assert_eq!(host_guard_refusal(&[], true), None);
    }

    #[test]
    fn host_guard_refuses_bound_machine_without_flag() {
        let bound = vec![(
            "/Users/op/Source/wire".to_string(),
            "slancha-wire".to_string(),
        )];
        let msg = host_guard_refusal(&bound, false).expect("guard must refuse");
        // The refusal must name what it's protecting and the override.
        assert!(msg.contains("slancha-wire"));
        assert!(msg.contains("/Users/op/Source/wire"));
        assert!(msg.contains("--really-this-machine"));
    }

    #[test]
    fn host_guard_passes_with_explicit_flag() {
        let bound = vec![("/x".to_string(), "s".to_string())];
        assert_eq!(host_guard_refusal(&bound, true), None);
    }

    #[test]
    fn registry_bindings_parse_shapes() {
        // Real shape.
        let bytes = br#"{"by_cwd":{"/a":"one","/b":"two"}}"#;
        let mut got = parse_registry_bindings(bytes);
        got.sort();
        assert_eq!(
            got,
            vec![
                ("/a".to_string(), "one".to_string()),
                ("/b".to_string(), "two".to_string())
            ]
        );
        // Empty map, missing key, non-object, garbage → no bindings.
        assert!(parse_registry_bindings(br#"{"by_cwd":{}}"#).is_empty());
        assert!(parse_registry_bindings(br"{}").is_empty());
        assert!(parse_registry_bindings(br#"{"by_cwd":42}"#).is_empty());
        assert!(parse_registry_bindings(b"not json").is_empty());
        // Non-string values are skipped, string ones kept.
        assert_eq!(
            parse_registry_bindings(br#"{"by_cwd":{"/a":1,"/b":"two"}}"#),
            vec![("/b".to_string(), "two".to_string())]
        );
    }
}
