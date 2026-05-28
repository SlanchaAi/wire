//! Cross-platform best-effort desktop notifications.
//!
//! Each backend shells out to the native binary (notify-send / osascript /
//! powershell). Failures are swallowed — we'd rather lose a toast than crash
//! the caller. Used by both `wire notify` (inbox events) and the daemon's
//! pending-pair tick (SAS-ready, pair-confirmed).
//!
//! Idempotency (issue #81): callers with a stable identity for the
//! underlying notification (an inbox `event_id`, a pending-pair `(code,
//! status)` transition, …) should use [`toast_dedup`] instead of [`toast`].
//! Repeated emissions within the dedup window are dropped — a single
//! un-acked event becomes one toast, not one toast per monitor tick.
//!
//! Dedup is in-process only (a `Mutex<HashMap>` keyed by `(key)` with TTL).
//! Cross-process dedup (multiple `wire monitor` instances on the same host)
//! is a documented v2 follow-up — see the issue's "Edge cases" section.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

/// Idempotent variant of [`toast`]: emits at most once per `key` per TTL
/// window (default 30s, see `WIRE_TOAST_DEDUP_TTL_SECS`).
///
/// `key` should encode whatever uniquely identifies the notification's
/// underlying event. For inbox toasts: `format!("{peer}:{event_id}")`. For
/// pending-pair state transitions: `format!("pair:{code}:{status}")`.
pub fn toast_dedup(key: &str, title: &str, body: &str) {
    let now = Instant::now();
    let ttl = dedup_ttl();
    let emit = {
        let mut guard = dedup_cache().lock().unwrap();
        should_emit_with(&mut guard, key, now, ttl)
    };
    if emit {
        toast(title, body);
    }
}

/// Test-only escape hatch: empty the in-process dedup cache.
#[cfg(test)]
pub(crate) fn _reset_dedup_cache_for_tests() {
    dedup_cache().lock().unwrap().clear();
}

#[cfg(target_os = "linux")]
pub fn toast(title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .arg("--app-name=wire")
        .arg("--icon=mail-message-new")
        .arg(title)
        .arg(body)
        .output();
}

#[cfg(target_os = "macos")]
pub fn toast(title: &str, body: &str) {
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
pub fn toast(title: &str, body: &str) {
    eprintln!("[wire notify] {title}\n  {body}");
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn toast(title: &str, body: &str) {
    eprintln!("[wire notify] {title}\n  {body}");
}

#[cfg(test)]
mod tests {
    use super::*;

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
