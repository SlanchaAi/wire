//! Background-process bootstrapper for the MCP path.
//!
//! Post-pair, an agent shouldn't have to ask the user "start the daemon?" —
//! `wire_pair_confirm` invokes [`ensure_daemon_running`] + [`ensure_notify_running`]
//! so push/pull and OS toasts are already armed by the time the agent surfaces
//! "paired ✓" back to chat.
//!
//! ## Idempotency
//!
//! Each subcommand writes its pid to `$WIRE_HOME/state/wire/<name>.pid` on
//! spawn. The next call reads the pid and skips spawning if `/proc/<pid>`
//! still exists. Stale pid files (process died) are silently overwritten.
//!
//! ## Detachment (Unix)
//!
//! Spawned with stdio nulled. Since `wire mcp` runs without a controlling
//! TTY (it's a stdio MCP server, not a login shell), the spawned children
//! inherit no TTY → no SIGHUP arrives when the parent exits, so they
//! survive a Claude Code restart cycle. PIDs are reaped by init.
//!
//! Worst case: a child dies; the next `wire_pair_confirm` call respawns it.
//! No data is lost (outbox/inbox is on disk, content-addressed dedupe).

use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::Result;

/// Ensure a `wire daemon --interval 5` process is alive. Returns `Ok(true)`
/// if a fresh process was spawned, `Ok(false)` if one was already running.
pub fn ensure_daemon_running() -> Result<bool> {
    ensure_background("daemon", &["daemon", "--interval", "5"])
}

/// Ensure a `wire notify --interval 2` process is alive (OS toasts on
/// every new verified inbox event). Returns true if newly spawned.
pub fn ensure_notify_running() -> Result<bool> {
    ensure_background("notify", &["notify", "--interval", "2"])
}

fn pid_file(name: &str) -> Result<PathBuf> {
    Ok(crate::config::state_dir()?.join(format!("{name}.pid")))
}

fn ensure_background(name: &str, args: &[&str]) -> Result<bool> {
    // Test escape hatch — tests/mcp_pair.rs spawns wire mcp with this env
    // var set so wire_pair_confirm doesn't fork persistent daemon/notify
    // processes that survive the test's temp WIRE_HOME.
    if std::env::var("WIRE_MCP_SKIP_AUTO_UP").is_ok() {
        return Ok(false);
    }

    let pid_path = pid_file(name)?;

    // Skip spawn if existing pid is still alive.
    if let Ok(s) = std::fs::read_to_string(&pid_path)
        && let Ok(pid) = s.trim().parse::<u32>()
        && process_alive(pid)
    {
        return Ok(false);
    }

    crate::config::ensure_dirs()?;
    let exe = std::env::current_exe()?;
    let child = Command::new(&exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    std::fs::write(&pid_path, child.id().to_string())?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(not(target_os = "linux"))]
fn process_alive(pid: u32) -> bool {
    // macOS / others: signal-0 check via `kill -0 <pid>` exit status.
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_alive_self() {
        assert!(process_alive(std::process::id()));
    }

    #[test]
    fn process_alive_zero_is_false_or_self() {
        // pid 0 means "the calling process's process group" for signals,
        // but kill -0 0 on Linux usually returns success for permissions
        // (signaling own group). On macOS, behavior varies. Don't pin this
        // edge case — just verify a pid we know shouldn't exist.
        assert!(!process_alive(99_999_999));
    }
}
