//! Background-process bootstrapper for the MCP path.
//!
//! Post-pair, an agent shouldn't have to ask the user "start the daemon?" —
//! the MCP accept/dial tools invoke [`ensure_daemon_running`] so push/pull is
//! already armed by the time the agent surfaces "paired ✓" back to chat. OS
//! toasts for inbound messages are folded into the daemon's own sync loop
//! (see `cli::comms::notify_sweep_new_events`), so arming the daemon arms
//! toasts too — no separate notify process.
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
//! The JSON `DaemonPid` form is the only supported on-disk format;
//! `read_pid_record` reports anything else as `Corrupt`.
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
//! Worst case: a child dies; the next accept/dial call respawns it.
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

/// Result of reading a pid file. JSON (full metadata) is the only
/// supported on-disk form; anything else is `Corrupt`.
#[derive(Debug, Clone)]
pub enum PidRecord {
    Json(DaemonPid),
    Missing,
    Corrupt(String),
}

impl PidRecord {
    pub fn pid(&self) -> Option<u32> {
        match self {
            PidRecord::Json(d) => Some(d.pid),
            _ => None,
        }
    }
}

/// Ensure a `wire daemon --interval 5` process is alive. Returns `Ok(true)`
/// if a fresh process was spawned, `Ok(false)` if one was already running.
pub fn ensure_daemon_running() -> Result<bool> {
    ensure_background("daemon", &["daemon", "--interval", "5"])
}

fn pid_file(name: &str) -> Result<PathBuf> {
    Ok(crate::config::state_dir()?.join(format!("{name}.pid")))
}

/// Snapshot of daemon liveness state read through ONE consistent
/// view. Consumed by `wire status`, `wire doctor`'s `daemon` check,
/// and `daemon_pid_consistency` so all three surfaces agree by
/// construction — issue #2 root cause was three call sites that
/// each computed liveness independently and disagreed for 25 min.
#[derive(Debug, Clone)]
pub struct DaemonLiveness {
    /// PID claimed by `daemon.pid` (None if missing/corrupt).
    pub pidfile_pid: Option<u32>,
    /// True iff `pidfile_pid` is currently a live process.
    pub pidfile_alive: bool,
    /// Every PID matching `pgrep -f "wire daemon"`. Empty if pgrep is
    /// unavailable (non-Unix systems, missing util) — the consumer
    /// must not treat empty as "no daemons" without considering this.
    pub pgrep_pids: Vec<u32>,
    /// PIDs in `pgrep_pids` that do NOT match `pidfile_pid`. These are
    /// orphan daemons racing the cursor with the pidfile-recorded one.
    pub orphan_pids: Vec<u32>,
    /// Full parsed pidfile record (Json / Missing / Corrupt).
    pub record: PidRecord,
}

/// True iff `pid` is currently a live OS process. Delegates to the
/// platform-aware check (`/proc` on Linux, `kill -0` on other Unix,
/// `tasklist` on Windows) so callers never disagree across OSes. The old
/// local `kill -0` path false-negatived on Windows (no `kill`), making
/// `wire status`/`doctor` report the daemon DOWN while it was alive.
pub fn pid_is_alive(pid: u32) -> bool {
    crate::platform::process_alive(pid)
}

/// Read the daemon pid file + pgrep in one shot, producing a snapshot
/// every caller can interpret identically. The point of this helper
/// is that three independent callers used to compute liveness three
/// different ways (#2): pidfile-pid-alive (cmd_status), pgrep-only
/// (early check_daemon_health), neither (check_daemon_pid_consistency).
/// Now all three flow through the same `DaemonLiveness`.
pub fn daemon_liveness() -> DaemonLiveness {
    let record = read_pid_record("daemon");
    let pidfile_pid = record.pid();
    let pidfile_alive = pidfile_pid.map(pid_is_alive).unwrap_or(false);
    // Platform-aware cmdline scan (Unix `pgrep`, Windows PowerShell CIM).
    // Field stays named `pgrep_pids` for callers; on Windows the old direct
    // `pgrep` shell-out returned empty (no such tool), masking live daemons.
    let pgrep_pids: Vec<u32> = crate::platform::find_processes_by_cmdline("wire daemon");
    // A2 (v0.13.2): on a multi-session box EVERY session runs its own daemon,
    // so the old "any `wire daemon` whose pid != my pidfile = orphan" rule
    // flagged sibling sessions' LEGITIMATE daemons as orphans — `wire doctor`
    // FAILed on the very multi-agent-per-box setup wire exists for. A true
    // orphan is a wire daemon owned by NO session: exclude every session's
    // pidfile pid, not just this session's.
    let known_session_pids: std::collections::HashSet<u32> = crate::session::list_sessions()
        .map(|sessions| {
            sessions
                .iter()
                .filter_map(|s| crate::session::session_daemon_pid(&s.home_dir))
                .collect()
        })
        .unwrap_or_default();
    // v0.14.2 (#170 follow-up): also exclude the `wire daemon --all-sessions`
    // supervisor. It's pgrep-matched by the "wire daemon" cmdline scan but
    // ISN'T orphaned — it has its own pidfile at `sessions_root/supervisor.pid`
    // and legitimately owns the orchestration role. Pre-fix the supervisor
    // showed up under `!! orphan daemon process(es)` on every `wire status`
    // even though it was the load-bearing process keeping every session
    // daemon alive — confusing operators into thinking it was stale.
    let supervisor_pid: Option<u32> = crate::session::sessions_root()
        .ok()
        .map(|root| root.join("supervisor.pid"))
        .filter(|p| p.exists())
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|p| pid_is_alive(*p));
    // v0.15.1: scope the orphan check to daemons that serve OUR WIRE_HOME.
    // `pgrep "wire daemon"` is machine-global, but a daemon only "races
    // our relay cursor" if it points at the SAME state tree. Pre-fix, a
    // fresh install / any non-default WIRE_HOME ran the global scan but
    // built its exclusion set (known_session_pids, supervisor) from the
    // CURRENT home's sessions_root — so the operator's real default-home
    // daemons all showed up as "orphan daemon process(es)... Multiple
    // daemons race the relay cursor" on the very first `wire status`,
    // even though they touch a completely different home.
    let our_home = std::env::var("WIRE_HOME").ok();
    let orphan_pids: Vec<u32> = pgrep_pids
        .iter()
        .copied()
        .filter(|p| {
            is_orphan_for_home(
                *p,
                pidfile_pid,
                &known_session_pids,
                supervisor_pid,
                our_home.as_deref(),
                crate::session::read_wire_home_from_pid(*p).as_deref(),
            )
        })
        .collect();
    DaemonLiveness {
        pidfile_pid,
        pidfile_alive,
        pgrep_pids,
        orphan_pids,
        record,
    }
}

/// Pure orphan predicate (pid-home reader injected for testability).
///
/// `pid` is a true orphan — a `wire daemon` racing OUR relay cursor with
/// no legitimate owner — iff ALL hold:
/// - it is not our own pidfile pid,
/// - it is not any registered session's daemon pid,
/// - it is not the `--all-sessions` supervisor,
/// - AND it serves the SAME WIRE_HOME as us (`pid_home == our_home`,
///   where `None == None` means both serve the default home).
///
/// The home check is the v0.15.1 fix: it is strictly subtractive (only
/// ever removes a candidate), so it can never invent an orphan — it just
/// stops a daemon for a *different* home (the operator's real install,
/// seen by the machine-global `pgrep` from inside a fresh/temp home) from
/// being mislabeled as racing our cursor. A pid whose home can't be read
/// on this platform (`pid_home == None` on Windows) only matches when our
/// home is also unreadable/default — the safe direction for the noise.
fn is_orphan_for_home(
    pid: u32,
    pidfile_pid: Option<u32>,
    known_session_pids: &std::collections::HashSet<u32>,
    supervisor_pid: Option<u32>,
    our_home: Option<&str>,
    pid_home: Option<&str>,
) -> bool {
    Some(pid) != pidfile_pid
        && !known_session_pids.contains(&pid)
        && Some(pid) != supervisor_pid
        && pid_home == our_home
}

/// Read a pid file. Only the JSON `DaemonPid` form is supported; any
/// other content is reported as `Corrupt`. Never panics.
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
    match serde_json::from_str::<DaemonPid>(trimmed) {
        Ok(d) => PidRecord::Json(d),
        Err(e) => PidRecord::Corrupt(format!("JSON parse: {e}")),
    }
}

/// Write a JSON pid record. P0.4: replaces the raw-int write.
fn write_pid_record(name: &str, record: &DaemonPid) -> Result<()> {
    let path = pid_file(name)?;
    let body = serde_json::to_vec_pretty(record)?;
    std::fs::write(&path, body)?;
    Ok(())
}

/// Daemon-startup: claim the `daemon.pid` file for THIS process.
///
/// A daemon started directly (`wire daemon`, not via `ensure_background`)
/// must write its own versioned-JSON pidfile so `wire status` / doctor /
/// the singleton guard can see it. Idempotent: if the pidfile already
/// records our PID we leave it untouched. (Historically this lived in
/// `pending_pair::cleanup_on_startup` alongside the now-removed SAS
/// pending-pair recovery; the pidfile write was never SAS-specific.)
pub fn write_self_daemon_pid() -> Result<()> {
    write_self_role_pid("daemon")
}

/// Long-running-role startup: claim the `<role>.pid` file for THIS
/// process inside the active `WIRE_HOME`. Same on-disk JSON shape as
/// `daemon.pid`, just keyed by role.
///
/// #247 finding 4: the per-role pidfile is what lets the cross-platform
/// identity-collision check map another wire process's PID back to the
/// `WIRE_HOME` it serves. Windows has no portable way to read another
/// process's environment, so the env-based POSIX path
/// (`/proc/<pid>/environ` / `ps -E`) doesn't translate — but every
/// inbox-owning long-running role (daemon / mcp / monitor / notify)
/// living under `<WIRE_HOME>/state/wire/<role>.pid` IS a portable
/// signal: a Windows waiter walks `list_sessions()` × roles, matches
/// the candidate PID against each pidfile, and reads off the session's
/// home. The POSIX path keeps its env-based fast path; this gives
/// Windows the same coverage without an `NtQueryInformationProcess`
/// FFI dep.
///
/// Idempotent: if the pidfile already records our PID we leave it
/// alone.
pub fn write_self_role_pid(role: &str) -> Result<()> {
    let path = pid_file(role)?;
    let my_pid = std::process::id();
    if path.exists()
        && let Ok(s) = std::fs::read_to_string(&path)
        && let Ok(rec) = serde_json::from_str::<DaemonPid>(s.trim())
        && rec.pid == my_pid
    {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    write_pid_record(role, &build_pid_record(my_pid))
}

/// Schema string written into every JSON last-sync file. Bumped if the
/// shape ever changes incompatibly. Readers tolerate any schema string +
/// fall back to "unknown last_sync" when they don't recognize it.
pub const LAST_SYNC_FILE_SCHEMA: &str = "wire-daemon-last-sync-v1";

/// Versioned record written by `wire daemon` after each successful sync
/// cycle. Readers (`wire status`, `mcp__wire__wire_status`,
/// `mcp__wire__wire_send` annotations) inspect it to surface
/// "is the sync loop alive RIGHT NOW?" — distinct from "is there a
/// process with `wire daemon` in its cmdline?" (the existing pidfile-
/// alive check), which can be true while the loop has been wedged for
/// minutes. v0.14.2 (#162): closes the silent-send class where the MCP
/// surface reports `status:"queued"` while no one is actually pushing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LastSyncRecord {
    /// Schema discriminator. `wire-daemon-last-sync-v1`.
    pub schema: String,
    /// RFC3339 UTC timestamp of the most recently completed cycle.
    pub ts: String,
    /// Number of outbox events pushed in this cycle.
    pub push_n: usize,
    /// Number of inbox events pulled (verified + written) in this cycle.
    pub pull_n: usize,
    /// Number of inbox events rejected by signature/cursor checks.
    pub rejected_n: usize,
}

fn last_sync_file() -> Result<PathBuf> {
    Ok(crate::config::state_dir()?.join("last_sync.json"))
}

/// Write the last-sync record. Called by `cmd_daemon` after each cycle
/// (including --once). Best-effort: any error logs to stderr but does NOT
/// abort the daemon loop — a wedged pidfile path shouldn't take the sync
/// loop down with it.
pub fn write_last_sync_record(push_n: usize, pull_n: usize, rejected_n: usize) {
    let record = LastSyncRecord {
        schema: LAST_SYNC_FILE_SCHEMA.to_string(),
        ts: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        push_n,
        pull_n,
        rejected_n,
    };
    let _ = (|| -> Result<()> {
        let path = last_sync_file()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_vec_pretty(&record)?;
        std::fs::write(&path, body)?;
        Ok(())
    })()
    .map_err(|e| eprintln!("daemon: last-sync persist error (non-fatal): {e:#}"));
}

/// Read the last-sync record. Returns `None` if missing/corrupt — every
/// caller should treat that as "unknown sync state, daemon may never
/// have run" and surface it accordingly.
pub fn read_last_sync_record() -> Option<LastSyncRecord> {
    let path = last_sync_file().ok()?;
    let body = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&body).ok()
}

/// Convenience: the wall-clock age (in whole seconds) of the most recent
/// sync, or `None` if no record exists / the timestamp can't be parsed.
/// Negative ages (clock skew between daemon + reader) are clamped to 0.
pub fn last_sync_age_seconds() -> Option<u64> {
    let rec = read_last_sync_record()?;
    let parsed =
        time::OffsetDateTime::parse(&rec.ts, &time::format_description::well_known::Rfc3339)
            .ok()?;
    let delta = time::OffsetDateTime::now_utc() - parsed;
    let secs = delta.whole_seconds();
    Some(secs.max(0) as u64)
}

/// Inspect the daemon singleton state. Returns `Some(pid)` iff the
/// pidfile names a live `wire daemon` process — i.e., a singleton is
/// currently held by another in-flight daemon. Returns `None` if the
/// pidfile is missing, corrupt, or names a dead process.
///
/// v0.14.2 (#162): foreground `wire daemon` (the operator-typed kind,
/// not the `ensure_background` spawn path) didn't write its own
/// pidfile, so subsequent `ensure_daemon_running()` calls couldn't
/// see it and would spawn duplicates. The duplicate-pull race is
/// safe — per-path outbox locks prevent corruption — but it wastes
/// relay polls and confuses operator diagnosis ("why are there 3
/// daemons?"). The singleton helpers below let `cmd_daemon` claim
/// the slot at startup + write its own pidfile, closing the gap.
pub fn daemon_singleton_holder() -> Option<u32> {
    // Exclude our OWN pid: `ensure_background` records the spawned daemon's pid
    // in the "daemon" pidfile right after spawn (the P0.4 alive-confirmation
    // write), and the daemon's own startup singleton check then reads that same
    // pidfile. Without this self-exclusion the daemon sees its own pid as a live
    // "other" holder, logs "another daemon is already running", and exits — so a
    // freshly-`wire up`'d session ends up with NO running daemon and the first
    // connection silently never completes (the receiver never pulls). A
    // manually-started daemon dodged this only because nothing pre-wrote its
    // pid. Self is never "another" daemon.
    let me = std::process::id();
    match read_pid_record("daemon").pid() {
        Some(pid) if pid != me && pid_is_alive(pid) => Some(pid),
        _ => None,
    }
}

/// Claim the daemon-pid singleton by writing this process's pid +
/// metadata to the pidfile. Callers should first check
/// `daemon_singleton_holder()` — if Some, bail rather than overwrite.
///
/// Returns a `DaemonPidGuard` that removes the pidfile when dropped,
/// so a graceful exit (SIGINT → normal Drop chain) cleans up.
pub fn claim_daemon_singleton() -> Result<DaemonPidGuard> {
    crate::config::ensure_dirs()?;
    let pid = std::process::id();
    let record = build_pid_record(pid);
    write_pid_record("daemon", &record)?;
    let path = pid_file("daemon")?;
    Ok(DaemonPidGuard {
        path,
        owned_pid: pid,
    })
}

/// Drop guard for a claimed daemon-pid singleton. On drop, removes
/// the pidfile only if it still names the pid we wrote — protects
/// against the case where another daemon raced in after we exited
/// the singleton check but before we wrote, and we don't want to
/// wipe their record on our exit.
pub struct DaemonPidGuard {
    path: PathBuf,
    owned_pid: u32,
}

impl Drop for DaemonPidGuard {
    fn drop(&mut self) {
        // Only remove if the file still names US. If another wire
        // daemon raced in and overwrote, leave their record alone.
        if let Ok(body) = std::fs::read_to_string(&self.path) {
            let still_ours = serde_json::from_str::<DaemonPid>(body.trim())
                .map(|d| d.pid == self.owned_pid)
                .unwrap_or_else(|_| {
                    body.trim()
                        .parse::<u32>()
                        .map(|p| p == self.owned_pid)
                        .unwrap_or(false)
                });
            if still_ours {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
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
        .and_then(|card| card.get("did").and_then(Value::as_str).map(str::to_string));
    let relay_url = crate::config::read_relay_state().ok().and_then(|state| {
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
    // var set so wire_accept/wire_dial don't fork persistent daemon/notify
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
    let mut cmd = Command::new(&exe);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::null());
    // Capture the spawned daemon's stderr to a logfile instead of /dev/null so
    // a daemon that dies on startup leaves a trace (otherwise its death is
    // invisible — exactly the silent-fail class this guards). Best-effort: fall
    // back to null if the log can't be opened.
    let stderr_log = crate::config::state_dir()
        .ok()
        .map(|d| d.join(format!("{name}-spawn.log")));
    match stderr_log
        .as_ref()
        .and_then(|p| std::fs::File::create(p).ok())
    {
        Some(f) => {
            cmd.stderr(Stdio::from(f));
        }
        None => {
            cmd.stderr(Stdio::null());
        }
    }

    let child = cmd.spawn()?;

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
/// daemon).
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
        _ => None,
    }
}

fn process_alive(pid: u32) -> bool {
    crate::platform::process_alive(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_alive_self() {
        assert!(process_alive(std::process::id()));
    }

    #[test]
    fn orphan_excludes_daemon_serving_a_different_home() {
        // The v0.15.1 regression: a fresh install (our_home = temp) runs
        // a machine-global pgrep that sees the operator's real default-home
        // daemon (pid_home = None). It must NOT be flagged as an orphan
        // racing our cursor.
        let empty = std::collections::HashSet::new();
        assert!(!is_orphan_for_home(
            42,
            None,
            &empty,
            None,
            Some("/tmp/fresh/home"), // we run under a temp WIRE_HOME
            None,                    // the real daemon serves the default home
        ));
        // A foreign Some-home daemon is likewise not ours.
        assert!(!is_orphan_for_home(
            42,
            None,
            &empty,
            None,
            Some("/tmp/fresh/home"),
            Some("/Users/op/other/home"),
        ));
    }

    #[test]
    fn orphan_flags_unowned_daemon_on_same_home() {
        // A genuine orphan: same home as us, not our pidfile, not a known
        // session, not the supervisor → still flagged (feature preserved).
        let empty = std::collections::HashSet::new();
        // Both default home (None == None).
        assert!(is_orphan_for_home(42, Some(7), &empty, Some(9), None, None));
        // Both the same explicit home.
        assert!(is_orphan_for_home(
            42,
            None,
            &empty,
            None,
            Some("/h"),
            Some("/h")
        ));
    }

    #[test]
    fn orphan_excludes_self_session_and_supervisor_even_on_same_home() {
        let mut known = std::collections::HashSet::new();
        known.insert(100u32);
        // our own pidfile pid
        assert!(!is_orphan_for_home(7, Some(7), &known, Some(9), None, None));
        // a registered session daemon
        assert!(!is_orphan_for_home(
            100,
            Some(7),
            &known,
            Some(9),
            None,
            None
        ));
        // the supervisor
        assert!(!is_orphan_for_home(9, Some(7), &known, Some(9), None, None));
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
