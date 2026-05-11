//! Daemon-orchestrated detached pair sessions.
//!
//! Problem: `wire pair-host` and `wire pair-join` block for the full pair
//! timeout (300s default) waiting for the peer to show up. If the operator's
//! terminal closes or the process is killed, the handshake dies — and on the
//! relay side leaves a stuck slot that needs `wire pair-abandon` to clean.
//!
//! Solution: pair-host/-join write a "pending pair" descriptor file and exit
//! in milliseconds. The `wire daemon` (already running for inbox sync) picks
//! up pending files each tick, runs the handshake, and transitions state
//! through the file. Operator confirms SAS via `wire pair-confirm <code>
//! <digits>` from any process; daemon finalizes on the next tick.
//!
//! State flow (status field on the file):
//!   request_host / request_guest
//!     ↓  daemon registers on relay, stores PakeSide in memory
//!   polling
//!     ↓  daemon polls for peer's SPAKE2 message; on arrival computes SAS
//!   sas_ready  (file now has `sas` field set; operator sees it via pair-list)
//!     ↓  `wire pair-confirm` validates typed digits, sets status=confirmed
//!   confirmed
//!     ↓  daemon finalizes (peer card exchange, trust pin); deletes file
//!   (gone)
//!
//! Terminal failure states: `aborted` (any error or user cancel),
//! `aborted_restart` (daemon restarted mid-handshake; PakeSide lost from
//! memory; operator must re-issue).
//!
//! In-memory PakeSide is the single point of fragility: it's not persisted,
//! so daemon restart drops live sessions. `cleanup_on_startup` releases the
//! relay slot and marks the file `aborted_restart` so the operator knows.
//! Daemon restarts are rare; this is an acceptable tradeoff vs. forking the
//! `spake2` crate to expose its internal scalar.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use crate::pair_session::{
    PairSessionState, pair_session_confirm_sas, pair_session_finalize, pair_session_open,
    pair_session_try_sas,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPair {
    /// The shared code phrase (e.g. "30-UE2BZG").
    pub code: String,
    /// SHA-256 of the domain-tagged code. Used to call pair_abandon on
    /// failure paths without re-deriving.
    pub code_hash: String,
    /// "host" or "guest".
    pub role: String,
    pub relay_url: String,
    /// See state machine in module docs.
    pub status: String,
    /// SAS digits (6-char string) once daemon computes them. None until then.
    #[serde(default)]
    pub sas: Option<String>,
    /// Set after pair_session_finalize completes.
    #[serde(default)]
    pub peer_did: Option<String>,
    /// ISO-8601 UTC.
    pub created_at: String,
    /// Last error message if status=aborted or aborted_restart.
    #[serde(default)]
    pub last_error: Option<String>,
}

pub fn pending_dir() -> Result<PathBuf> {
    let d = crate::config::state_dir()?.join("pending-pair");
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

fn pending_path(code: &str) -> Result<PathBuf> {
    // Codes are alphanumeric + dash; sanitize defensively.
    let safe: String = code
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok(pending_dir()?.join(format!("{safe}.json")))
}

pub fn write_pending(p: &PendingPair) -> Result<()> {
    let path = pending_path(&p.code)?;
    let body = serde_json::to_string_pretty(p)?;
    std::fs::write(&path, body)?;
    Ok(())
}

pub fn read_pending(code: &str) -> Result<Option<PendingPair>> {
    let path = pending_path(code)?;
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&path)?;
    Ok(Some(serde_json::from_str(&body)?))
}

pub fn delete_pending(code: &str) -> Result<()> {
    let path = pending_path(code)?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

pub fn list_pending() -> Result<Vec<PendingPair>> {
    let dir = pending_dir()?;
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let body = std::fs::read_to_string(entry.path())?;
            if let Ok(p) = serde_json::from_str::<PendingPair>(&body) {
                out.push(p);
            }
        }
    }
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(out)
}

/// In-memory map of code → live PairSessionState. Lost on daemon restart;
/// see `cleanup_on_startup` for recovery.
static LIVE_SESSIONS: OnceLock<Mutex<HashMap<String, PairSessionState>>> = OnceLock::new();

fn live() -> &'static Mutex<HashMap<String, PairSessionState>> {
    LIVE_SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Tracks "is this daemon process the same one that opened the live sessions?"
/// — a PID file at `$WIRE_HOME/state/wire/daemon.pid` containing the PID of
/// the daemon process that owns the in-memory `LIVE_SESSIONS` map. On startup:
/// if the PID file exists AND that PID is alive → previous daemon is somehow
/// still running (refuse, or no-op cleanup); if PID file exists but PID dead
/// → previous daemon crashed, run cleanup. If no PID file → first run, no
/// pending sessions could have a live state anyway, skip cleanup. Then write
/// our own PID.
fn daemon_pid_file() -> Result<PathBuf> {
    Ok(crate::config::state_dir()?.join("daemon.pid"))
}

fn process_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::process::Command;
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Run on daemon startup. Only marks pending files aborted_restart if the
/// previous daemon (according to PID file) is no longer alive. Idempotent
/// for the same daemon process (writes its own PID, then re-running this
/// function on subsequent calls is a no-op).
pub fn cleanup_on_startup() -> Result<()> {
    let pid_file = daemon_pid_file()?;
    let my_pid = std::process::id();
    let prev_alive = if pid_file.exists() {
        if let Ok(s) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = s.trim().parse::<u32>() {
                if pid == my_pid {
                    // We are the daemon that wrote this PID — already initialized.
                    return Ok(());
                }
                process_alive(pid)
            } else {
                false
            }
        } else {
            false
        }
    } else {
        // No previous daemon recorded — anything stale must be from a much
        // older process that already exited. Treat as "previous daemon dead"
        // so we clean up rather than leak.
        false
    };

    if !prev_alive {
        for mut p in list_pending()? {
            if p.status == "polling" || p.status == "request_host" || p.status == "request_guest"
            {
                let client = crate::relay_client::RelayClient::new(&p.relay_url);
                let _ = client.pair_abandon(&p.code_hash);
                p.status = "aborted_restart".to_string();
                p.last_error = Some(
                    "daemon restarted while session was mid-handshake; in-memory SPAKE2 state lost. Re-issue with a fresh code phrase.".to_string(),
                );
                write_pending(&p)?;
                // Push so operator knows a session got wiped on restart.
                crate::os_notify::toast(
                    &format!("wire — pair aborted on restart ({})", p.code),
                    "Daemon restarted mid-handshake. Re-issue: wire pair-host --detach",
                );
            }
        }
    }

    if let Some(parent) = pid_file.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let _ = std::fs::write(&pid_file, my_pid.to_string());
    Ok(())
}

/// Terminal-state TTL: aborted / aborted_restart files older than this get
/// silently deleted in `tick()`. Keeps `pair-list` output tidy without losing
/// short-term diagnostic value.
const TERMINAL_TTL_SECS: i64 = 3600;

/// One daemon tick. Walks every pending file and advances it one step in the
/// state machine. Each file's failures are isolated — a single broken file
/// doesn't stop processing of the rest. Also GCs old terminal-state files.
pub fn tick() -> Result<Value> {
    let mut transitions: Vec<Value> = Vec::new();
    let now = time::OffsetDateTime::now_utc();
    for mut p in list_pending()? {
        let prev_status = p.status.clone();

        // GC long-dead terminal files.
        if (p.status == "aborted" || p.status == "aborted_restart")
            && let Ok(created) = time::OffsetDateTime::parse(
                &p.created_at,
                &time::format_description::well_known::Rfc3339,
            )
            && (now - created).whole_seconds() > TERMINAL_TTL_SECS
        {
            let _ = delete_pending(&p.code);
            continue;
        }

        if let Err(e) = process_one(&mut p) {
            p.last_error = Some(format!("{e:#}"));
            p.status = "aborted".to_string();
            // Best-effort abandon on relay so we don't leak a slot.
            let client = crate::relay_client::RelayClient::new(&p.relay_url);
            let _ = client.pair_abandon(&p.code_hash);
            let _ = write_pending(&p);
            live().lock().unwrap().remove(&p.code);
            // Push: operator should know without checking pair-list.
            let title = format!("wire — pair aborted ({})", p.code);
            let body = p
                .last_error
                .clone()
                .unwrap_or_else(|| "(no detail)".to_string());
            crate::os_notify::toast(&title, &body);
        }
        if p.status != prev_status {
            transitions.push(json!({
                "code": p.code,
                "from": prev_status,
                "to": p.status,
                "sas": p.sas,
                "peer_did": p.peer_did,
            }));
        }
    }
    Ok(json!({"transitions": transitions}))
}

fn process_one(p: &mut PendingPair) -> Result<()> {
    match p.status.as_str() {
        "request_host" => {
            let s = pair_session_open("host", &p.relay_url, Some(&p.code))?;
            live().lock().unwrap().insert(p.code.clone(), s);
            p.status = "polling".to_string();
            write_pending(p)?;
        }
        "request_guest" => {
            let s = pair_session_open("guest", &p.relay_url, Some(&p.code))?;
            live().lock().unwrap().insert(p.code.clone(), s);
            p.status = "polling".to_string();
            write_pending(p)?;
        }
        "polling" => {
            let mut sessions = live().lock().unwrap();
            let s = sessions
                .get_mut(&p.code)
                .ok_or_else(|| anyhow!("no live session for {} (daemon restart?)", p.code))?;
            if pair_session_try_sas(s)?.is_some() {
                p.status = "sas_ready".to_string();
                p.sas = s.sas.clone();
                write_pending(p)?;
                // Push to the operator's desktop so they don't have to remember
                // to `wire pair-list`. Failures are swallowed in os_notify::toast.
                let formatted = p
                    .sas
                    .as_ref()
                    .map(|d| format!("{}-{}", &d[..3], &d[3..]))
                    .unwrap_or_default();
                let title = format!("wire — pair SAS ready ({})", p.code);
                let body = format!(
                    "Digits: {formatted}\nCompare with peer, then:\nwire pair-confirm {} {}",
                    p.code,
                    p.sas.as_deref().unwrap_or("")
                );
                crate::os_notify::toast(&title, &body);
            }
        }
        "confirmed" => {
            // Operator typed matching digits via `wire pair-confirm`. Daemon
            // owns the live PairSessionState and must drive the final SPAKE2
            // bootstrap exchange itself.
            let mut sessions = live().lock().unwrap();
            let s = sessions.get_mut(&p.code).ok_or_else(|| {
                anyhow!(
                    "no live session for {} (status=confirmed but session lost; daemon restart between sas_ready and confirmed)",
                    p.code
                )
            })?;
            let digits = p
                .sas
                .clone()
                .ok_or_else(|| anyhow!("status=confirmed but sas missing"))?;
            pair_session_confirm_sas(s, &digits)?;
            // 30s timeout for the bootstrap exchange — both sides should already
            // be in the same tick window. If this fails, status flips to aborted.
            let outcome = pair_session_finalize(s, 30)?;
            p.peer_did = outcome
                .get("peer_did")
                .and_then(Value::as_str)
                .map(str::to_string);
            sessions.remove(&p.code);
            delete_pending(&p.code)?;
            // Push a "paired" toast — closes the loop for the operator.
            let title = format!("wire — paired ({})", p.code);
            let body = format!(
                "Peer: {}\n`wire peers` to confirm.",
                p.peer_did.as_deref().unwrap_or("?")
            );
            crate::os_notify::toast(&title, &body);
        }
        // sas_ready (operator hasn't confirmed yet), aborted, aborted_restart:
        // terminal-from-daemon's-POV — nothing to do.
        _ => {}
    }
    Ok(())
}
