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
}
