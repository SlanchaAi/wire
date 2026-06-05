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
            let report = plan.execute().unwrap();
            assert!(!state.exists(), "state dir deleted");
            let v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&mcp).unwrap()).unwrap();
            assert!(v["mcpServers"].get("wire").is_none(), "wire de-registered");
            assert!(report.removed_paths.contains(&state));
            assert!(report.removed_mcp_entries.contains(&mcp));
        });
    }
}
