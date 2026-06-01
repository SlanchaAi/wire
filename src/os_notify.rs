//! Cross-platform best-effort desktop notifications.
//!
//! Each backend shells out to the native binary (notify-send / osascript /
//! powershell). Failures are swallowed — we'd rather lose a toast than crash
//! the caller. Used by both `wire notify` (inbox events) and the daemon's
//! pending-pair tick (SAS-ready, pair-confirmed).
//!
//! ## Once-only across every wire process on the host
//!
//! Pre-v0.14.2: dedup was an in-process `Mutex<HashMap>` with 30s TTL.
//! That fell apart catastrophically once #170's `--all-sessions`
//! supervisor put **134 wire daemons** on a single box: every daemon
//! polled its own inbox, every daemon fired its own toast, the operator
//! saw the same "pair complete" notification 134 times within seconds.
//!
//! v0.14.2: every toast — both [`toast`] (now content-keyed) and
//! [`toast_dedup`] (explicit-key) — first acquires a process-shared
//! "first-emit" claim via an atomic `O_CREAT|O_EXCL` filesystem touch
//! file under `<cache_dir>/wire/toast-dedup/<sha256(key)>.touch`. The
//! filesystem is the dedup primitive — no flock, no race window. Once
//! a touch file exists, no wire process anywhere on the host re-emits
//! the same toast — **ever**. Operators who want to reset (e.g., to
//! re-see a notification class after a code change) `rm -rf` the dir.
//!
//! The in-process `Mutex<HashMap>` survives as a fast-path inside one
//! process so the per-toast fs-stat doesn't dominate the loop, but the
//! filesystem claim is the actual guarantee.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Default TTL for the in-process toast-dedup LRU. Overridable via
/// `WIRE_TOAST_DEDUP_TTL_SECS` (set to `0` to disable dedup entirely —
/// useful when chasing notification regressions).
const DEFAULT_DEDUP_TTL_SECS: u64 = 30;

fn dedup_ttl() -> Duration {
    let secs = std::env::var("WIRE_TOAST_DEDUP_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_DEDUP_TTL_SECS);
    Duration::from_secs(secs)
}

fn dedup_cache() -> &'static Mutex<HashMap<String, Instant>> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Pure decision: should we emit a toast for `key` right now? Mutates the
/// supplied cache (recording the new "shown_at" if we return `true`, and
/// opportunistically evicting expired entries so the map doesn't grow
/// unbounded across a long-running daemon).
///
/// Behaviour:
/// - `ttl == Duration::ZERO` → dedup disabled, always emit (cache untouched).
/// - `key` absent or its entry expired → emit + record `now`.
/// - `key` present and entry not yet expired → suppress.
pub(crate) fn should_emit_with(
    cache: &mut HashMap<String, Instant>,
    key: &str,
    now: Instant,
    ttl: Duration,
) -> bool {
    if ttl.is_zero() {
        return true;
    }
    cache.retain(|_, shown_at| now.duration_since(*shown_at) < ttl);
    match cache.get(key) {
        Some(_) => false,
        None => {
            cache.insert(key.to_string(), now);
            true
        }
    }
}

/// Idempotent variant of [`toast`]: emits at most once per `key`,
/// **forever, across every wire process on the host**.
///
/// `key` should encode whatever uniquely identifies the notification's
/// underlying event. For inbox toasts: `format!("{peer}:{event_id}")`.
/// For pending-pair state transitions: `format!("pair:{code}:{status}")`.
///
/// Two-stage check:
/// 1. In-process LRU (Mutex<HashMap>, 30s TTL by default — controlled
///    via `WIRE_TOAST_DEDUP_TTL_SECS`). Fast-path so a busy daemon
///    polling its own inbox doesn't stat the filesystem on every
///    inbound event.
/// 2. **Cross-process atomic claim** via `O_CREAT|O_EXCL` on a
///    sha256-named file under `<cache_dir>/wire/toast-dedup/`. Once
///    the file exists, no wire process anywhere on the host emits
///    again for that key. No TTL — operators rm the directory to
///    reset.
pub fn toast_dedup(key: &str, title: &str, body: &str) {
    if toasts_disabled() {
        return;
    }
    let now = Instant::now();
    let ttl = dedup_ttl();
    let emit_in_proc = {
        let mut guard = dedup_cache().lock().unwrap();
        should_emit_with(&mut guard, key, now, ttl)
    };
    if !emit_in_proc {
        return;
    }
    if !claim_cross_process(key) {
        return;
    }
    emit_toast(title, body);
}

/// Cross-process atomic "are we the first emitter for this key?"
/// claim. Computes
/// `<cache_dir>/wire/toast-dedup/<sha256(key)>.touch` and tries to
/// create it with `O_CREAT|O_EXCL`. Returns `true` iff we won the
/// race (or the dedup-dir is unreachable and we should fall back to
/// the in-process check alone). Returns `false` only when we
/// observe an `AlreadyExists` for the same key — a confirmed prior
/// claim.
///
/// Fail-soft: any other filesystem error (perms, EROFS, …) → return
/// `true` so the toast still fires. We'd rather see a duplicate
/// once than miss a notification entirely.
fn claim_cross_process(key: &str) -> bool {
    let path = match cross_process_dedup_path(key) {
        Some(p) => p,
        None => return true,
    };
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => true,
    }
}

fn cross_process_dedup_path(key: &str) -> Option<PathBuf> {
    let cache = dirs::cache_dir()?.join("wire").join("toast-dedup");
    std::fs::create_dir_all(&cache).ok()?;
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    let hex = hex::encode(h.finalize());
    Some(cache.join(format!("{hex}.touch")))
}

/// v0.14.x kill switch: the operator silences ALL wire desktop toasts by
/// either (a) `wire quiet on` — which touches `<config_dir>/quiet` — or
/// (b) exporting `WIRE_NO_TOASTS=1` in the daemon's environment (e.g. via
/// `launchctl setenv WIRE_NO_TOASTS 1` then `wire upgrade --local`).
///
/// Checked at every `toast`/`toast_dedup` entry. The file check is a
/// per-call `fs::metadata` stat (cheap; bounded by the 30s dedup TTL); the
/// env check is a `std::env::var`. Either match ⇒ no-op return; nothing
/// shells out to `osascript`/`notify-send`/`powershell`.
///
/// Intentionally bypasses dedup — disabled means disabled, no leakage.
/// Note: callers that DROP a notification because of this guard MUST NOT
/// also bail their downstream side effects (pending stash still runs,
/// receive path still pins per policy, etc.) — the toast is the ONLY
/// thing suppressed.
fn toasts_disabled() -> bool {
    if std::env::var("WIRE_NO_TOASTS").is_ok_and(|v| !v.is_empty() && v != "0") {
        return true;
    }
    if let Ok(cfg) = crate::config::config_dir()
        && cfg.join("quiet").exists()
    {
        return true;
    }
    false
}

/// Test-only escape hatch: empty the in-process dedup cache.
#[cfg(test)]
pub(crate) fn _reset_dedup_cache_for_tests() {
    dedup_cache().lock().unwrap().clear();
}

/// Bare toast — fires once per (title, body) content across every
/// wire process on the host. Defers to [`toast_dedup`] with a
/// content-hash key so legacy call sites that don't have a stable
/// event-id key still get the cross-process once-only guarantee.
///
/// v0.14.x kill switch (`wire quiet on` / `WIRE_NO_TOASTS=1`) is
/// honored here too — disabled means disabled, no leakage.
pub fn toast(title: &str, body: &str) {
    let key = format!("content:{title}\u{1f}{body}");
    toast_dedup(&key, title, body);
}

#[cfg(target_os = "linux")]
fn emit_toast(title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .arg("--app-name=wire")
        .arg("--icon=mail-message-new")
        .arg(title)
        .arg(body)
        .output();
}

#[cfg(target_os = "macos")]
fn emit_toast(title: &str, body: &str) {
    let safe = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "display notification \"{}\" with title \"{}\"",
        safe(body),
        safe(title),
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output();
}

#[cfg(target_os = "windows")]
fn emit_toast(title: &str, body: &str) {
    eprintln!("[wire notify] {title}\n  {body}");
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn emit_toast(title: &str, body: &str) {
    eprintln!("[wire notify] {title}\n  {body}");
}

#[cfg(test)]
mod tests {
    use super::*;

    // v0.14.x kill-switch tests. `toasts_disabled` is process-state-leaky
    // (env var + filesystem), so each test sets its own WIRE_HOME tempdir
    // and clears the env var explicitly. Run under --test-threads=1 (CI
    // default since #111) to avoid env-mutation races.
    #[test]
    fn disabled_false_in_clean_env_and_dir() {
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: tests are gated to --test-threads=1.
        unsafe {
            std::env::remove_var("WIRE_NO_TOASTS");
            std::env::set_var("WIRE_HOME", tmp.path());
        }
        assert!(!toasts_disabled());
    }

    #[test]
    fn disabled_true_when_env_set() {
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("WIRE_HOME", tmp.path());
            std::env::set_var("WIRE_NO_TOASTS", "1");
        }
        assert!(toasts_disabled());
        unsafe {
            std::env::remove_var("WIRE_NO_TOASTS");
        }
    }

    #[test]
    fn disabled_true_when_quiet_flag_file_present() {
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::remove_var("WIRE_NO_TOASTS");
            std::env::set_var("WIRE_HOME", tmp.path());
        }
        let cfg = tmp.path().join("config").join("wire");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(cfg.join("quiet"), b"").unwrap();
        assert!(toasts_disabled());
    }

    #[test]
    fn env_var_zero_string_does_not_silence() {
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("WIRE_HOME", tmp.path());
            std::env::set_var("WIRE_NO_TOASTS", "0");
        }
        // "0" / empty is operator-explicit "off"; respect it.
        assert!(!toasts_disabled());
        unsafe {
            std::env::remove_var("WIRE_NO_TOASTS");
        }
    }

    #[test]
    fn first_emission_for_a_key_passes() {
        let mut cache = HashMap::new();
        let t0 = Instant::now();
        assert!(should_emit_with(
            &mut cache,
            "evt-1",
            t0,
            Duration::from_secs(30),
        ));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn repeat_within_ttl_is_suppressed() {
        let mut cache = HashMap::new();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(30);
        assert!(should_emit_with(&mut cache, "evt-1", t0, ttl));
        let later = t0 + Duration::from_secs(5);
        assert!(!should_emit_with(&mut cache, "evt-1", later, ttl));
    }

    #[test]
    fn repeat_after_ttl_re_emits() {
        let mut cache = HashMap::new();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(30);
        assert!(should_emit_with(&mut cache, "evt-1", t0, ttl));
        let later = t0 + Duration::from_secs(31);
        assert!(should_emit_with(&mut cache, "evt-1", later, ttl));
    }

    #[test]
    fn different_keys_each_emit() {
        let mut cache = HashMap::new();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(30);
        assert!(should_emit_with(&mut cache, "evt-1", t0, ttl));
        assert!(should_emit_with(&mut cache, "evt-2", t0, ttl));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn zero_ttl_disables_dedup() {
        let mut cache = HashMap::new();
        let t0 = Instant::now();
        assert!(should_emit_with(&mut cache, "evt-1", t0, Duration::ZERO));
        assert!(should_emit_with(&mut cache, "evt-1", t0, Duration::ZERO));
        assert!(cache.is_empty(), "zero-ttl must not touch the cache");
    }

    #[test]
    fn expired_entries_are_garbage_collected_on_access() {
        let mut cache = HashMap::new();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(30);
        assert!(should_emit_with(&mut cache, "stale-1", t0, ttl));
        assert!(should_emit_with(&mut cache, "stale-2", t0, ttl));
        let later = t0 + Duration::from_secs(120);
        assert!(should_emit_with(&mut cache, "fresh", later, ttl));
        assert_eq!(
            cache.len(),
            1,
            "expired keys must be evicted on the next emit"
        );
        assert!(cache.contains_key("fresh"));
    }

    #[test]
    fn toast_dedup_public_api_suppresses_repeat() {
        _reset_dedup_cache_for_tests();
        let key = "wire-test::toast_dedup_public_api_suppresses_repeat";
        toast_dedup(key, "first", "body");
        let len_after_first = dedup_cache().lock().unwrap().len();
        toast_dedup(key, "second", "body");
        let len_after_second = dedup_cache().lock().unwrap().len();
        assert_eq!(
            len_after_first, len_after_second,
            "second emission with the same key must not grow the cache",
        );
        assert_eq!(len_after_first, 1);
    }
}
