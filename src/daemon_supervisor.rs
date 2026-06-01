//! `wire daemon --all-sessions` — multi-session supervisor.
//!
//! ## Why
//!
//! honey-pine's 2026-06-01 dogfood (#162) surfaced a launchd-vs-session
//! isolation gap: the `sh.slancha.wire.daemon` launchd unit invokes
//! `wire daemon --interval 5` with **no cwd context**. With WIRE_HOME
//! unset, the daemon resolves to the *default* session WIRE_HOME and
//! silently skips every other initialized session. Operators with
//! multiple per-project sessions (slancha-mesh, wire, etc.) saw their
//! shell `wire status` report `running:false` even with the launchd
//! daemon perfectly alive — same daemon, different state tree.
//!
//! Her working remedy was `launchctl bootout` + `nohup wire daemon`
//! from the project cwd. That works for one session but doesn't scale
//! to N. The architectural fix is a supervisor that owns the
//! multi-session orchestration: one supervisor process per launchd
//! unit, N child `wire daemon --session <name>` processes — each with
//! its own pinned `WIRE_HOME` and its own pidfile under that session's
//! state dir. `wire status` from any cwd then sees its session's child
//! pid and reports truthfully.
//!
//! ## Model
//!
//! - **Fork-exec, not threads.** Each session's daemon needs its own
//!   `WIRE_HOME`. We set it via the child process env so the daemon
//!   code path stays unchanged. Threads would mean global mutable
//!   `WIRE_HOME` and cross-session races.
//! - **Idempotent spawn.** Before spawning a child for session S,
//!   check `daemon_singleton_holder()` on that session's home. If a
//!   live daemon already exists (operator ran `wire daemon` directly
//!   in S's cwd, or supervisor restarted and the old child is still
//!   alive), leave it alone.
//! - **Reap via polling, not SIGCHLD.** macOS launchd-supervised
//!   processes already get SIGCHLD overhead; `try_wait` polling on a
//!   short interval is simpler and bug-free across platforms.
//! - **Backoff on rapid failure.** A child that exits within 10s of
//!   spawn doubles its respawn delay (1s → 60s cap). Prevents a broken
//!   session (corrupt key, missing relay) from fork-bombing.
//! - **Don't exit on zero sessions.** Sleep and re-poll the registry —
//!   new sessions get picked up without supervisor restart.
//! - **Adopt orphaned children on supervisor restart.** When launchd
//!   relaunches the supervisor, the previous supervisor's children
//!   keep running (correct: they're still syncing). New supervisor
//!   sees their pidfiles, skips re-spawning, and lets them keep going
//!   until their next natural exit (then it spawns a fresh child).
//!
//! ## Invariants
//!
//! - One supervisor per launchd unit per machine. Singleton guard on
//!   `sessions_root()/supervisor.pid` (separate from per-session
//!   daemon pidfiles).
//! - Child env contains exactly one wire-relevant variable:
//!   `WIRE_HOME=<session-home>`. Any other inherited WIRE_* vars are
//!   stripped so the operator's shell config doesn't leak in.
//! - Per-session daemon code is *unchanged* — supervisor is a pure
//!   orchestrator.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::json;

/// How often the supervisor re-reads the session registry. Tradeoff: a
/// new session created at `wire session new` waits up to this many
/// seconds before its daemon comes up. 10s strikes a balance — fast
/// enough that operators don't notice, slow enough that registry
/// fork-execs don't dominate.
const REGISTRY_POLL_SECS: u64 = 10;

/// Initial respawn delay after a child exits unexpectedly. Doubles on
/// each rapid failure (exit within `RAPID_FAIL_WINDOW`) up to
/// `MAX_BACKOFF`.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const RAPID_FAIL_WINDOW: Duration = Duration::from_secs(10);

/// State the supervisor tracks per session it has spawned a child for.
struct ChildState {
    child: Child,
    spawned_at: Instant,
}

/// Entrypoint for `wire daemon --all-sessions`. Loops forever; only
/// returns Err on a setup error (e.g. cannot resolve sessions_root).
pub fn run_supervisor(interval_secs: u64, as_json: bool) -> Result<()> {
    // Supervisor singleton — one per machine. Separate pidfile from the
    // per-session daemon pidfile so the two layers can't collide.
    let pid_path = supervisor_pid_path()?;
    if let Some(existing) = read_alive_supervisor_pid(&pid_path)? {
        let msg = json!({
            "status": "skipped",
            "reason": "supervisor already running",
            "holder_pid": existing,
        });
        if as_json {
            println!("{msg}");
        } else {
            eprintln!(
                "wire daemon --all-sessions: another supervisor is already running (pid {existing}); not starting a second one."
            );
        }
        return Ok(());
    }
    write_supervisor_pid(&pid_path)?;
    let _cleanup = SupervisorPidGuard {
        path: pid_path.clone(),
    };

    if !as_json {
        eprintln!(
            "wire daemon --all-sessions: supervisor up. interval={interval_secs}s, registry-poll={REGISTRY_POLL_SECS}s. SIGINT to stop."
        );
    } else {
        println!(
            "{}",
            json!({
                "status": "supervisor_started",
                "interval_secs": interval_secs,
                "registry_poll_secs": REGISTRY_POLL_SECS,
            })
        );
    }

    let mut children: HashMap<String, ChildState> = HashMap::new();
    // Per-session backoff that survives a child's reap → respawn → reap
    // cycle. Distinguishes "session crashes hard repeatedly" from
    // "child exited cleanly and we're spawning a fresh one".
    let mut session_last_exit: HashMap<String, Instant> = HashMap::new();
    let mut session_backoff: HashMap<String, Duration> = HashMap::new();

    loop {
        // 1. Reap any exited children. Detect rapid failures + update
        //    per-session backoff so the next spawn waits.
        let mut exited: Vec<String> = Vec::new();
        for (name, state) in children.iter_mut() {
            if let Ok(Some(status)) = state.child.try_wait() {
                let lived = state.spawned_at.elapsed();
                let rapid = lived < RAPID_FAIL_WINDOW;
                eprintln!(
                    "supervisor: child '{name}' exited (status={status:?}, lived={}s, rapid={rapid})",
                    lived.as_secs()
                );
                let next_backoff = if rapid {
                    let prev = session_backoff
                        .get(name)
                        .copied()
                        .unwrap_or(INITIAL_BACKOFF);
                    (prev * 2).min(MAX_BACKOFF)
                } else {
                    INITIAL_BACKOFF
                };
                session_backoff.insert(name.clone(), next_backoff);
                session_last_exit.insert(name.clone(), Instant::now());
                exited.push(name.clone());
            }
        }
        for n in exited {
            children.remove(&n);
        }

        // 2. Read registry, identify wanted sessions.
        let wanted: Vec<crate::session::SessionInfo> =
            crate::session::list_sessions().unwrap_or_default();

        // 3. Kill children whose session has been removed from the
        //    registry since last poll. (Operator ran `wire session
        //    forget` or similar.)
        let wanted_names: std::collections::HashSet<String> =
            wanted.iter().map(|s| s.name.clone()).collect();
        let to_kill: Vec<String> = children
            .keys()
            .filter(|n| !wanted_names.contains(n.as_str()))
            .cloned()
            .collect();
        for name in to_kill {
            if let Some(mut state) = children.remove(&name) {
                eprintln!("supervisor: session '{name}' gone from registry; terminating its child");
                let _ = state.child.kill();
                let _ = state.child.wait();
            }
        }

        // 4. Spawn missing children, respecting backoff + existing
        //    pidfiles (operator-spawned daemons coexist).
        for info in wanted {
            if info.did.is_none() {
                continue;
            }
            if children.contains_key(&info.name) {
                continue;
            }
            // Backoff gate: if this session is in a rapid-fail loop,
            // wait the remaining backoff before respawning.
            if let Some(last_exit) = session_last_exit.get(&info.name) {
                let wait = session_backoff
                    .get(&info.name)
                    .copied()
                    .unwrap_or(INITIAL_BACKOFF);
                if last_exit.elapsed() < wait {
                    continue;
                }
            }
            // Singleton check: an operator-spawned `wire daemon` may
            // already own this session. Leave it alone — re-checking
            // next poll is cheap.
            if existing_daemon_for_session(&info.home_dir)? {
                continue;
            }
            match spawn_child_for_session(&info.name, &info.home_dir, interval_secs) {
                Ok(child) => {
                    eprintln!(
                        "supervisor: spawned child for session '{}' (pid {})",
                        info.name,
                        child.id()
                    );
                    children.insert(
                        info.name.clone(),
                        ChildState {
                            child,
                            spawned_at: Instant::now(),
                        },
                    );
                }
                Err(e) => {
                    eprintln!(
                        "supervisor: spawn failed for session '{}': {e:#}",
                        info.name
                    );
                    // Treat spawn failure as a rapid failure so the
                    // backoff curve kicks in.
                    let prev = session_backoff
                        .get(&info.name)
                        .copied()
                        .unwrap_or(INITIAL_BACKOFF);
                    session_backoff.insert(info.name.clone(), (prev * 2).min(MAX_BACKOFF));
                    session_last_exit.insert(info.name.clone(), Instant::now());
                }
            }
        }

        std::thread::sleep(Duration::from_secs(REGISTRY_POLL_SECS));
    }
}

/// Spawn `wire daemon --interval <i>` as a child with `WIRE_HOME`
/// pinned via env. Strips inherited WIRE_* env so the operator's
/// shell config (test overrides like `WIRE_DAEMON_NO_SINGLETON=1`)
/// can't leak in.
///
/// v0.14.2 #170 hotfix: the original implementation also passed
/// `--session <character-name>` as a belt-and-suspenders check.
/// That broke 127 of 133 sessions on a real multi-session box —
/// `cmd_daemon`'s `--session` handler calls
/// `session::session_dir(name)` which resolves
/// `sessions_root/<name>`, correct for v0.6 top-level layout but
/// WRONG for v0.13's `by-key/<hash>` layout where the character
/// name is *derived* from the card DID, not the directory name.
/// Children bailed → supervisor fork-bombed (10s poll × 60s
/// backoff × 127 failing sessions). WIRE_HOME env alone is the
/// correct contract: every daemon code path flows through
/// `state_dir()` / `config_dir()` which honor it. No second
/// source of truth.
fn spawn_child_for_session(
    name: &str,
    home_dir: &std::path::Path,
    interval_secs: u64,
) -> Result<Child> {
    let exe = std::env::current_exe().context("resolving current exe for child fork")?;
    let mut cmd = Command::new(&exe);
    cmd.args(["daemon", "--interval", &interval_secs.to_string()]);
    // Strip WIRE_* env so operator shell-vars don't leak into the
    // child. Then pin WIRE_HOME exactly.
    let leaks: Vec<String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("WIRE_"))
        .map(|(k, _)| k)
        .collect();
    for k in leaks {
        cmd.env_remove(&k);
    }
    cmd.env("WIRE_HOME", home_dir);
    // Children inherit stdout/stderr → land in the launchd log file
    // (StandardOutPath in the plist). Operators see "supervisor:
    // spawned ..." lines interleaved with each session's daemon log.
    cmd.spawn().with_context(|| {
        format!(
            "fork-exec `wire daemon` for session '{name}' (binary {} WIRE_HOME={})",
            exe.display(),
            home_dir.display()
        )
    })
}

/// True iff this session's `daemon.pid` names a live process. Used by
/// the supervisor to coexist with operator-spawned `wire daemon`
/// invocations: if the operator already started one in a tmux pane,
/// we skip the spawn and let theirs own the cursor.
fn existing_daemon_for_session(home_dir: &std::path::Path) -> Result<bool> {
    let pid_path = home_dir.join("state").join("wire").join("daemon.pid");
    if !pid_path.exists() {
        return Ok(false);
    }
    let body = match std::fs::read_to_string(&pid_path) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    // Pidfile is either JSON `{"pid": <n>, ...}` (v0.5.11+) or a bare
    // integer (legacy). Try JSON+pid-field first; if that yields
    // None (parse failed OR JSON had no pid field, e.g. a bare
    // integer body parses as JSON number with no `.pid`), fall
    // through to the bare-int path.
    let pid = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("pid").and_then(serde_json::Value::as_u64))
        .or_else(|| body.trim().parse::<u64>().ok());
    Ok(pid
        .map(|p| crate::ensure_up::pid_is_alive(p as u32))
        .unwrap_or(false))
}

/// Read-only snapshot of the supervisor's current topology — supervisor
/// liveness + per-session daemon liveness + orphan pids the supervisor
/// is not currently managing. Used by `wire supervisor` (the CLI
/// counterpart to single-session `wire status`) so operators can ask
/// "what is the multi-session supervisor doing?" in one command
/// instead of cross-referencing `pgrep` against per-session pidfiles
/// by hand.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SupervisorState {
    /// Pid the `supervisor.pid` file names; None if file missing.
    pub supervisor_pid: Option<u32>,
    /// True iff that pid is currently a live process.
    pub supervisor_alive: bool,
    /// Per-session liveness across every initialized session, in
    /// `list_sessions()` order.
    pub sessions: Vec<SupervisedSession>,
    /// `wire daemon` pids found via cmdline-scan that are NOT mapped
    /// to any session's pidfile AND are not the supervisor itself.
    /// Could be legacy operator-spawned daemons, leftover children
    /// from a crashed prior supervisor, or daemons serving the
    /// default WIRE_HOME (no `--all-sessions`). Operators see them
    /// here so they can decide whether to kill.
    pub unmanaged_pids: Vec<u32>,
}

/// One session as seen by the supervisor.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SupervisedSession {
    /// Session name (`info.name` from `session::list_sessions`).
    pub name: String,
    /// `home_dir` filesystem path.
    pub home_dir: String,
    /// Pid the session's `daemon.pid` records; None if file missing.
    pub daemon_pid: Option<u32>,
    /// True iff that pid is currently a live process.
    pub daemon_alive: bool,
    /// Seconds since the session's daemon last completed a sync
    /// cycle (read from `last_sync.json`); None if never recorded.
    pub last_sync_age_seconds: Option<u64>,
}

/// Build a `SupervisorState` snapshot. Pure read; no fork / no
/// pidfile mutation. Best-effort on every component (filesystem
/// errors yield None / empty rather than failing the whole call).
pub fn read_supervisor_state() -> Result<SupervisorState> {
    let pid_path = supervisor_pid_path()?;
    let supervisor_pid = read_supervisor_pid(&pid_path);
    let supervisor_alive = supervisor_pid
        .map(crate::ensure_up::pid_is_alive)
        .unwrap_or(false);

    // Per-session liveness — walk list_sessions, read each home's
    // pidfile + last_sync.
    let sessions: Vec<SupervisedSession> = crate::session::list_sessions()
        .unwrap_or_default()
        .into_iter()
        .map(|info| {
            let daemon_pid = crate::session::session_daemon_pid(&info.home_dir);
            let daemon_alive = daemon_pid
                .map(crate::ensure_up::pid_is_alive)
                .unwrap_or(false);
            // last_sync.json lives under <home>/state/wire/last_sync.json.
            let last_sync_age_seconds = read_session_last_sync_age(&info.home_dir);
            SupervisedSession {
                name: info.name,
                home_dir: info.home_dir.to_string_lossy().into_owned(),
                daemon_pid,
                daemon_alive,
                last_sync_age_seconds,
            }
        })
        .collect();

    // Unmanaged pids: every `wire daemon` cmdline scan hit that isn't
    // (a) the supervisor itself, (b) any session's pidfile pid.
    let all_daemon_pids: std::collections::HashSet<u32> =
        crate::platform::find_processes_by_cmdline("wire daemon")
            .into_iter()
            .collect();
    let known_session_pids: std::collections::HashSet<u32> = sessions
        .iter()
        .filter_map(|s| if s.daemon_alive { s.daemon_pid } else { None })
        .collect();
    let mut unmanaged_pids: Vec<u32> = all_daemon_pids
        .into_iter()
        .filter(|p| Some(*p) != supervisor_pid && !known_session_pids.contains(p))
        .collect();
    unmanaged_pids.sort_unstable();

    Ok(SupervisorState {
        supervisor_pid,
        supervisor_alive,
        sessions,
        unmanaged_pids,
    })
}

/// Read `supervisor.pid` without the liveness check (the snapshot
/// builder runs the check itself, separated so an absent file is
/// just `None` rather than an Err).
fn read_supervisor_pid(path: &std::path::Path) -> Option<u32> {
    if !path.exists() {
        return None;
    }
    let body = std::fs::read_to_string(path).ok()?;
    body.trim().parse::<u32>().ok()
}

/// Read `<home>/state/wire/last_sync.json`'s timestamp and return
/// "seconds since now". None on absent / unreadable / unparseable.
fn read_session_last_sync_age(home_dir: &std::path::Path) -> Option<u64> {
    let path = home_dir.join("state").join("wire").join("last_sync.json");
    let body = std::fs::read_to_string(&path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let ts = v.get("ts").and_then(serde_json::Value::as_str)?;
    let parsed =
        time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339).ok()?;
    let age = (time::OffsetDateTime::now_utc() - parsed).whole_seconds();
    if age < 0 {
        // Clock skew: timestamp is in the future. Treat as fresh.
        Some(0)
    } else {
        Some(age as u64)
    }
}

fn supervisor_pid_path() -> Result<PathBuf> {
    let root = crate::session::sessions_root()
        .context("resolving sessions_root for supervisor pidfile")?;
    std::fs::create_dir_all(&root).with_context(|| format!("creating {root:?}"))?;
    Ok(root.join("supervisor.pid"))
}

fn read_alive_supervisor_pid(path: &std::path::Path) -> Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(path).ok();
    let pid = body.as_deref().and_then(|s| s.trim().parse::<u32>().ok());
    match pid {
        Some(p) if crate::ensure_up::pid_is_alive(p) => Ok(Some(p)),
        _ => Ok(None),
    }
}

fn write_supervisor_pid(path: &std::path::Path) -> Result<()> {
    let pid = std::process::id();
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("writing supervisor pidfile {path:?}"))?;
    Ok(())
}

struct SupervisorPidGuard {
    path: PathBuf,
}

impl Drop for SupervisorPidGuard {
    fn drop(&mut self) {
        // Only remove if it still names us — same pattern as
        // DaemonPidGuard in ensure_up.rs.
        if let Ok(body) = std::fs::read_to_string(&self.path)
            && let Ok(pid) = body.trim().parse::<u32>()
            && pid == std::process::id()
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_alive_supervisor_pid_returns_none_when_missing() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("supervisor.pid");
        assert_eq!(read_alive_supervisor_pid(&p).unwrap(), None);
    }

    #[test]
    fn read_alive_supervisor_pid_returns_none_for_dead_pid() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("supervisor.pid");
        // pid 999999 is almost certainly not running.
        std::fs::write(&p, "999999").unwrap();
        assert_eq!(read_alive_supervisor_pid(&p).unwrap(), None);
    }

    #[test]
    fn read_alive_supervisor_pid_returns_pid_for_self() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("supervisor.pid");
        let our_pid = std::process::id();
        std::fs::write(&p, our_pid.to_string()).unwrap();
        assert_eq!(read_alive_supervisor_pid(&p).unwrap(), Some(our_pid));
    }

    #[test]
    fn pid_guard_only_removes_when_pid_still_matches() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("supervisor.pid");
        // Write a foreign pid into the file, then drop a guard for
        // our pid. The guard should leave the foreign pidfile alone.
        std::fs::write(&p, "12345").unwrap();
        {
            let _g = SupervisorPidGuard { path: p.clone() };
        }
        assert!(p.exists(), "guard removed a pidfile that didn't name us");
    }

    #[test]
    fn pid_guard_removes_when_pid_matches() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("supervisor.pid");
        let our_pid = std::process::id();
        std::fs::write(&p, our_pid.to_string()).unwrap();
        {
            let _g = SupervisorPidGuard { path: p.clone() };
        }
        assert!(!p.exists(), "guard left our own pidfile behind");
    }

    #[test]
    fn existing_daemon_for_session_returns_false_when_pidfile_missing() {
        let tmp = tempdir().unwrap();
        // home_dir has no state/wire/daemon.pid
        assert!(!existing_daemon_for_session(tmp.path()).unwrap());
    }

    #[test]
    fn existing_daemon_for_session_returns_false_for_dead_pid() {
        let tmp = tempdir().unwrap();
        let state = tmp.path().join("state").join("wire");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("daemon.pid"), "999999").unwrap();
        assert!(!existing_daemon_for_session(tmp.path()).unwrap());
    }

    #[test]
    fn existing_daemon_for_session_returns_true_for_self_pid() {
        let tmp = tempdir().unwrap();
        let state = tmp.path().join("state").join("wire");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("daemon.pid"), std::process::id().to_string()).unwrap();
        assert!(existing_daemon_for_session(tmp.path()).unwrap());
    }
}
