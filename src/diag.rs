//! P2.10 (0.5.11): structured diagnostic trace.
//!
//! Optional append-only JSONL log at
//! `$WIRE_HOME/state/wire/diag.jsonl`. Every meaningful wire op
//! (pull, push, pair transition, daemon spawn, schema rejection)
//! emits one line. The previous "what is this binary actually
//! doing right now" question required pgrep + strace + dtruss —
//! now it's `wire diag tail`.
//!
//! Off by default. Enable per-process via env `WIRE_DIAG=1`, or
//! per-machine via writing the file `$WIRE_HOME/state/wire/diag.enabled`
//! (any non-empty content). Either signal flips emit() from a no-op
//! to a real write — the env knob is good for one-off CLI sessions,
//! the file knob is good for daemons that operators want to keep
//! tracing across restarts without modifying their launchd plist.
//!
//! Cost: a single `OpenOptions::append(true)` + `write_all` per
//! event when enabled, no-op otherwise. The hot path checks one env
//! var + one file metadata stat.

use serde_json::Value;

/// Maximum diag.jsonl size before rotation. 8 MiB is enough to keep
/// ~50,000 typical-shape entries while staying under operator-friendly
/// `tail`/`grep` budgets. Past this, the file is renamed to
/// `diag.jsonl.1` (clobbering any prior rotation) and a new file
/// starts. One generation of history is enough — diag is a debugging
/// breadcrumb trail, not an archive.
const ROTATE_AT_BYTES: u64 = 8 * 1024 * 1024;

/// True if diag emission is enabled for THIS process invocation.
///
/// Checked on every call (not cached) so an operator can toggle the
/// file-based knob mid-session without restarting their daemon.
pub fn is_enabled() -> bool {
    if std::env::var("WIRE_DIAG")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    if let Ok(state) = crate::config::state_dir()
        && state.join("diag.enabled").exists()
    {
        return true;
    }
    false
}

/// Append a structured diag entry. No-op when disabled. Never panics,
/// never propagates an error — diag is a best-effort breadcrumb, not
/// a load-bearing channel. If the write fails, we'd rather lose the
/// trace line than break the operation we were instrumenting.
pub fn emit(event_type: &str, payload: Value) {
    if !is_enabled() {
        return;
    }
    let state = match crate::config::state_dir() {
        Ok(s) => s,
        Err(_) => return,
    };
    if std::fs::create_dir_all(&state).is_err() {
        return;
    }
    let path = state.join("diag.jsonl");
    // Rotation: rename to .1 if we'd cross the limit. Lossy single-
    // generation — fine for a breadcrumb log.
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() >= ROTATE_AT_BYTES
    {
        let _ = std::fs::rename(&path, state.join("diag.jsonl.1"));
    }
    let line = serde_json::json!({
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "pid": std::process::id(),
        "version": env!("CARGO_PKG_VERSION"),
        "type": event_type,
        "payload": payload,
    });
    let bytes = match serde_json::to_vec(&line) {
        Ok(mut b) => {
            b.push(b'\n');
            b
        }
        Err(_) => return,
    };
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(&bytes);
    }
}

/// Read the last `n` lines from diag.jsonl. Returns parsed JSON lines;
/// malformed entries are skipped silently. Used by `wire doctor --tail
/// diag` (or `wire diag tail`).
pub fn tail(n: usize) -> Vec<Value> {
    let path = match crate::config::state_dir() {
        Ok(s) => s.join("diag.jsonl"),
        Err(_) => return Vec::new(),
    };
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<Value> = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let start = out.len().saturating_sub(n);
    out.drain(..start);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diag_is_noop_when_disabled() {
        crate::config::test_support::with_temp_home(|| {
            // Default state: WIRE_DIAG unset, diag.enabled file absent.
            assert!(!is_enabled());
            emit("pull", json!({"events": 3}));
            let state = crate::config::state_dir().unwrap();
            let diag = state.join("diag.jsonl");
            assert!(!diag.exists(), "diag must not write when disabled");
        });
    }

    #[test]
    fn diag_emits_when_env_var_set() {
        crate::config::test_support::with_temp_home(|| {
            crate::config::ensure_dirs().unwrap();
            // SAFETY: test_support::with_temp_home holds ENV_LOCK.
            unsafe { std::env::set_var("WIRE_DIAG", "1") };
            emit("pull", json!({"events": 2, "rejected": 0}));
            unsafe { std::env::remove_var("WIRE_DIAG") };
            let lines = tail(10);
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0]["type"], "pull");
            assert_eq!(lines[0]["payload"]["events"], 2);
            assert!(lines[0]["ts"].as_u64().is_some());
            assert!(lines[0]["pid"].as_u64().is_some());
        });
    }

    #[test]
    fn diag_emits_when_file_knob_present() {
        // File knob: operators can flip diag on for a running daemon
        // without restarting it.
        crate::config::test_support::with_temp_home(|| {
            crate::config::ensure_dirs().unwrap();
            let state = crate::config::state_dir().unwrap();
            std::fs::write(state.join("diag.enabled"), "1").unwrap();
            assert!(is_enabled());
            emit("push", json!({"peer": "willard"}));
            let lines = tail(10);
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0]["type"], "push");
        });
    }

    #[test]
    fn diag_tail_returns_last_n_entries_in_order() {
        crate::config::test_support::with_temp_home(|| {
            crate::config::ensure_dirs().unwrap();
            unsafe { std::env::set_var("WIRE_DIAG", "1") };
            for i in 0..5u32 {
                emit("test", json!({"i": i}));
            }
            unsafe { std::env::remove_var("WIRE_DIAG") };
            let lines = tail(3);
            assert_eq!(lines.len(), 3);
            // Order preserved.
            assert_eq!(lines[0]["payload"]["i"], 2);
            assert_eq!(lines[1]["payload"]["i"], 3);
            assert_eq!(lines[2]["payload"]["i"], 4);
        });
    }
}
