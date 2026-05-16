//! Background-process bootstrapper for the MCP path.
//!
//! Post-pair, an agent shouldn't have to ask the user "start the daemon?" —
//! `wire_pair_confirm` invokes [`ensure_daemon_running`] + [`ensure_notify_running`]
//! so push/pull and OS toasts are already armed by the time the agent surfaces
//! "paired ✓" back to chat.
//!
//! ## Idempotency
//!
//! Each subcommand writes its pid record to `$WIRE_HOME/state/wire/<name>.pid`
//! on spawn. The next call reads the record and skips spawning if the pid is
//! still alive. Stale pid files (process died) are silently overwritten.
//!
//! ## Pid-file shape (P0.4, 0.5.11)
//!
//! The pid file used to be a raw integer (`12345\n`). Today's debug surfaced
//! a process running an OLD binary text in memory under a current symlink,
//! and `wire status` had no way to detect that. The pid file is now a
//! versioned JSON record:
//!
//! ```json
//! {
//!   "schema": "wire-daemon-pid-v1",
//!   "pid": 12345,
//!   "bin_path": "/usr/local/bin/wire",
//!   "version": "0.5.11",
//!   "started_at": "2026-05-16T01:23:45Z",
//!   "did": "did:wire:paul-mac",
//!   "relay_url": "https://wireup.net"
//! }
//! ```
//!
//! Readers are TOLERANT of the legacy int form for one transition cycle —
//! `read_daemon_pid` falls through to raw-int parse when JSON decode fails
//! and reports `version: None` so callers can degrade gracefully.
//!
//! ## Wait-until-alive
//!
//! On spawn, we wait briefly for the child to be alive before persisting the
//! pid file. A concurrent CLI seeing the file pointing at a not-yet-bound
//! PID is the "daemon reports running but can't accept connections" race
//! spark flagged in our P0.4 design call.
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
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema string written into every JSON pid file. Bumped if the pid-file
/// shape ever changes incompatibly. Readers warn on unknown schema.
pub const DAEMON_PID_SCHEMA: &str = "wire-daemon-pid-v1";

/// Versioned daemon pid record — the JSON form written by 0.5.11+.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonPid {
    /// Schema discriminator. Always `wire-daemon-pid-v1` for now.
    pub schema: String,
    pub pid: u32,
    /// Absolute path of the binary that was exec'd. Catches today's exact
    /// bug: a stale 0.2.4 daemon process kept running under a symlink that
    /// was repointed at 0.5.10 — `wire --version` says 0.5.10 but the
    /// running daemon's text in memory is still 0.2.4.
    pub bin_path: String,
    /// CARGO_PKG_VERSION captured at spawn. Compared against the CLI's
    /// own version on every invocation; mismatch = loud warn.
    pub version: String,
    /// RFC3339 timestamp of spawn.
    pub started_at: String,
    /// Self DID — catches multi-identity contamination (one user, two wire
    /// identities on same host, daemon launched as wrong one). Cheap
    /// field, expensive bug.
    pub did: Option<String>,
    /// Relay this daemon was bound to at spawn. Catches daemon-bound-to-
    /// old-relay-after-migration drift.
    pub relay_url: Option<String>,
}

/// Result of reading a pid file. Distinguishes legacy-int (no metadata)
/// from JSON (full metadata) so callers can degrade gracefully.
#[derive(Debug, Clone)]
pub enum PidRecord {
    Json(DaemonPid),
    LegacyInt(u32),
    Missing,
    Corrupt(String),
}

impl PidRecord {
    pub fn pid(&self) -> Option<u32> {
        match self {
            PidRecord::Json(d) => Some(d.pid),
            PidRecord::LegacyInt(p) => Some(*p),
            _ => None,
        }
    }
}

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

/// Read a pid file, tolerating both JSON and legacy-int forms. Never
/// panics — corrupt input becomes `PidRecord::Corrupt`.
pub fn read_pid_record(name: &str) -> PidRecord {
    let path = match pid_file(name) {
        Ok(p) => p,
        Err(_) => return PidRecord::Missing,
    };
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(_) => return PidRecord::Missing,
    };
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return PidRecord::Missing;
    }
    // JSON form first.
    if trimmed.starts_with('{') {
        match serde_json::from_str::<DaemonPid>(trimmed) {
            Ok(d) => return PidRecord::Json(d),
            Err(e) => return PidRecord::Corrupt(format!("JSON parse: {e}")),
        }
    }
    // Legacy raw-int form — keep readable for one transition cycle so a
    // 0.5.11 daemon can take over from a 0.5.10 leftover without
    // operator intervention.
    match trimmed.parse::<u32>() {
        Ok(pid) => PidRecord::LegacyInt(pid),
        Err(e) => PidRecord::Corrupt(format!("expected int or JSON: {e}")),
    }
}

/// Write a JSON pid record. P0.4: replaces the raw-int write.
fn write_pid_record(name: &str, record: &DaemonPid) -> Result<()> {
    let path = pid_file(name)?;
    let body = serde_json::to_vec_pretty(record)?;
    std::fs::write(&path, body)?;
    Ok(())
}

/// Build a `DaemonPid` for a freshly-spawned child. Reads bin_path,
/// current binary version, identity DID, and bound relay URL.
fn build_pid_record(pid: u32) -> DaemonPid {
    let bin_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let version = env!("CARGO_PKG_VERSION").to_string();
    let started_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let (did, relay_url) = identity_for_pid_record();
    DaemonPid {
        schema: DAEMON_PID_SCHEMA.to_string(),
        pid,
        bin_path,
        version,
        started_at,
        did,
        relay_url,
    }
}

/// Best-effort: pull DID + relay_url from the configured identity. None
/// fields are written as `null` so the file stays well-formed even before
/// the operator runs `wire init`.
fn identity_for_pid_record() -> (Option<String>, Option<String>) {
    let did = crate::config::read_agent_card()
        .ok()
        .and_then(|card| {
            card.get("did")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    let relay_url = crate::config::read_relay_state()
        .ok()
        .and_then(|state| {
            state
                .get("self")
                .and_then(|s| s.get("relay_url"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    (did, relay_url)
}

/// Wait briefly for `process_alive(pid)` to be true. Returns true if the
/// child went live within the budget. Default budget is 500ms — enough for
/// std::process::Command::spawn to fork + exec on any reasonable platform.
fn wait_until_alive(pid: u32, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if process_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    process_alive(pid)
}

fn ensure_background(name: &str, args: &[&str]) -> Result<bool> {
    // Test escape hatch — tests/mcp_pair.rs spawns wire mcp with this env
    // var set so wire_pair_confirm doesn't fork persistent daemon/notify
    // processes that survive the test's temp WIRE_HOME.
    if std::env::var("WIRE_MCP_SKIP_AUTO_UP").is_ok() {
        return Ok(false);
    }

    // Skip spawn if existing pid is still alive.
    if let Some(pid) = read_pid_record(name).pid()
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

    // P0.4: wait until the child is actually alive before persisting the
    // pid file. Otherwise a concurrent CLI sees the file pointing at a
    // PID that isn't yet bound to anything — "daemon reports running but
    // can't accept connections" race.
    let pid = child.id();
    if !wait_until_alive(pid, Duration::from_millis(500)) {
        anyhow::bail!(
            "spawned `wire {}` (pid {pid}) did not appear alive within 500ms",
            args.join(" ")
        );
    }

    let record = build_pid_record(pid);
    write_pid_record(name, &record)?;
    Ok(true)
}

/// Check the running daemon's version against the CLI's CARGO_PKG_VERSION.
/// Returns Some(stale_version) if they disagree, None if they match (or no
/// daemon, or legacy-int pidfile without version info).
///
/// Called by `wire status` + `wire doctor`. The intent is loud, non-fatal
/// warning — don't BLOCK CLI invocations on version mismatch (operator may
/// be running a one-shot debug while daemon is old), but DO make it
/// impossible to miss.
pub fn daemon_version_mismatch() -> Option<String> {
    let record = read_pid_record("daemon");
    let pid = record.pid()?;
    if !process_alive(pid) {
        return None;
    }
    match record {
        PidRecord::Json(d) => {
            if d.version != env!("CARGO_PKG_VERSION") {
                Some(d.version)
            } else {
                None
            }
        }
        PidRecord::LegacyInt(_) => {
            // Legacy pidfile = pre-0.5.11 daemon writing raw int. By
            // definition older than this CLI, so flag it.
            Some("<pre-0.5.11>".to_string())
        }
        _ => None,
    }
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
        assert!(!process_alive(99_999_999));
    }

    #[test]
    fn pid_record_round_trips_via_json_form() {
        // P0.4 contract: a record written by 0.5.11 must be readable by
        // 0.5.11. If serde gets out of sync with the file format, every
        // single CLI invocation breaks silently.
        crate::config::test_support::with_temp_home(|| {
            crate::config::ensure_dirs().unwrap();
            let record = DaemonPid {
                schema: DAEMON_PID_SCHEMA.to_string(),
                pid: 12345,
                bin_path: "/usr/local/bin/wire".to_string(),
                version: "0.5.11".to_string(),
                started_at: "2026-05-16T01:23:45Z".to_string(),
                did: Some("did:wire:paul-mac".to_string()),
                relay_url: Some("https://wireup.net".to_string()),
            };
            write_pid_record("daemon", &record).unwrap();
            let read = read_pid_record("daemon");
            match read {
                PidRecord::Json(d) => assert_eq!(d, record),
                other => panic!("expected JSON record, got {other:?}"),
            }
        });
    }

    #[test]
    fn pid_record_tolerates_legacy_int_form() {
        // The whole point of LegacyInt: a 0.5.11 daemon must be able to
        // take over from a 0.5.10 leftover without operator intervention.
        // If this assertion fails, every operator with a 0.5.10 daemon
        // running has to manually delete their pidfile on upgrade.
        crate::config::test_support::with_temp_home(|| {
            crate::config::ensure_dirs().unwrap();
            let path = super::pid_file("daemon").unwrap();
            std::fs::write(&path, "98765").unwrap();
            let read = read_pid_record("daemon");
            match read {
                PidRecord::LegacyInt(pid) => assert_eq!(pid, 98765),
                other => panic!("expected LegacyInt, got {other:?}"),
            }
        });
    }

    #[test]
    fn pid_record_corrupt_reports_corrupt_not_panic() {
        // Today's debug had a stale pidfile pointing at a dead PID. The
        // reader was tolerant. A future bug might write garbage; the reader
        // must not panic — it must report Corrupt so wire doctor can
        // surface it visibly.
        crate::config::test_support::with_temp_home(|| {
            crate::config::ensure_dirs().unwrap();
            let path = super::pid_file("daemon").unwrap();
            std::fs::write(&path, "not-a-pid-or-json {{{").unwrap();
            let read = read_pid_record("daemon");
            assert!(matches!(read, PidRecord::Corrupt(_)), "got {read:?}");
        });
    }

    #[test]
    fn daemon_version_mismatch_returns_none_when_no_pidfile() {
        crate::config::test_support::with_temp_home(|| {
            assert_eq!(daemon_version_mismatch(), None);
        });
    }
}
