//! Multi-session wire on one machine (v0.5.16).
//!
//! Problem: multiple Claude Code (or any agent harness) sessions on the
//! same machine share a single `WIRE_HOME`, which means they share the
//! same DID, same relay slot, same inbox JSONL, and same daemon. Peers
//! have no way to address a specific session, and the operator can't
//! tell which session sent what.
//!
//! Solution: a `wire session` subcommand that bootstraps **isolated**
//! per-session `WIRE_HOME` trees. Each session gets its own identity,
//! handle, relay slot, daemon, and inbox/outbox. Sessions pair with each
//! other through the public relay (`wireup.net`) like any other peer —
//! no protocol changes. The bilateral-pair gate from v0.5.14 still
//! applies in both directions.
//!
//! Storage layout:
//!
//! ```text
//! ~/.local/state/wire/sessions/
//!   registry.json                — cwd → session_name map
//!   <session-name>/               — full WIRE_HOME tree per session
//!     config/wire/...
//!     state/wire/...
//! ```
//!
//! Naming: derived from `basename(cwd)` so re-opening the same project
//! reuses the same session identity. Collisions across two different
//! paths with the same basename get a 4-char SHA-256 path-hash suffix.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::endpoints::{Endpoint, EndpointScope, self_endpoints};

/// Root directory under which all session WIRE_HOMEs live.
///
/// Honors `WIRE_HOME` for testing (sessions root becomes
/// `$WIRE_HOME/sessions/`); otherwise:
///   - Linux: `$XDG_STATE_HOME/wire/sessions/` (typically
///     `~/.local/state/wire/sessions/`).
///   - macOS / other Unix without XDG: falls back to
///     `dirs::data_local_dir() / wire / sessions /`, which on macOS is
///     `~/Library/Application Support/wire/sessions/`. This mirrors
///     `config::state_dir`'s fallback so the two surfaces resolve to
///     compatible roots on every platform.
pub fn sessions_root() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("WIRE_HOME") {
        return Ok(PathBuf::from(home).join("sessions"));
    }
    let state = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .ok_or_else(|| {
            anyhow!(
                "could not resolve XDG_STATE_HOME (or platform-equivalent local data dir) — \
                 set WIRE_HOME or run on a platform with `dirs` support"
            )
        })?;
    Ok(state.join("wire").join("sessions"))
}

/// Full filesystem path for the named session's WIRE_HOME root.
/// Inside this dir the standard wire layout applies: `config/wire/...`
/// and `state/wire/...`.
pub fn session_dir(name: &str) -> Result<PathBuf> {
    Ok(sessions_root()?.join(sanitize_name(name)))
}

/// Registry tracks `cwd → session_name` so repeated `wire session new`
/// from the same project reuses the same identity instead of creating
/// a fresh one each time. Lives at `<sessions_root>/registry.json`.
pub fn registry_path() -> Result<PathBuf> {
    Ok(sessions_root()?.join("registry.json"))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionRegistry {
    /// `cwd_absolute_path → session_name`. Absent if cwd has not been
    /// associated with a session yet.
    #[serde(default)]
    pub by_cwd: HashMap<String, String>,
}

pub fn read_registry() -> Result<SessionRegistry> {
    let path = registry_path()?;
    if !path.exists() {
        return Ok(SessionRegistry::default());
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading session registry {path:?}"))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing session registry {path:?}"))
}

pub fn write_registry(reg: &SessionRegistry) -> Result<()> {
    let path = registry_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {parent:?}"))?;
    }
    let body = serde_json::to_vec_pretty(reg)?;
    std::fs::write(&path, body)
        .with_context(|| format!("writing session registry {path:?}"))?;
    Ok(())
}

/// Sanitize an arbitrary string to a session-name-safe form: lowercase
/// ASCII alphanumeric + `-` + `_`, replace other chars with `-`,
/// dedupe consecutive dashes, trim leading/trailing dashes, max 32 chars.
pub fn sanitize_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for c in raw.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '-' || c == '_';
        let ch = if ok { c.to_ascii_lowercase() } else { '-' };
        if ch == '-' {
            if !prev_dash && !out.is_empty() {
                out.push('-');
            }
            prev_dash = true;
        } else {
            out.push(ch);
            prev_dash = false;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        return "wire-session".to_string();
    }
    if trimmed.len() > 32 {
        return trimmed[..32].trim_end_matches('-').to_string();
    }
    trimmed
}

/// Short hash suffix derived from the full absolute path of the cwd.
/// Used to disambiguate two different projects whose basenames collide
/// (e.g. `~/Source/wire` and `~/Archive/wire`).
fn path_hash_suffix(cwd: &Path) -> String {
    let bytes = cwd.as_os_str().to_string_lossy().into_owned();
    let mut h = Sha256::new();
    h.update(bytes.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..2]) // 4 hex chars
}

/// Derive a stable session name for the given cwd. Resolution order:
///
/// 1. If the registry already maps this cwd → name, return that name.
/// 2. Else: candidate = sanitize(basename(cwd)). If the candidate is
///    already mapped to a DIFFERENT cwd in the registry, append a
///    4-char path-hash suffix to avoid collision.
/// 3. If still a collision: append a numeric suffix `-2`, `-3`, ...
///    until unique.
pub fn derive_name_from_cwd(cwd: &Path, registry: &SessionRegistry) -> String {
    let cwd_key = cwd.to_string_lossy().into_owned();
    if let Some(existing) = registry.by_cwd.get(&cwd_key) {
        return existing.clone();
    }
    let base = cwd
        .file_name()
        .and_then(|s| s.to_str())
        .map(sanitize_name)
        .unwrap_or_else(|| "wire-session".to_string());
    let occupied: std::collections::HashSet<String> = registry.by_cwd.values().cloned().collect();
    if !occupied.contains(&base) {
        return base;
    }
    let with_hash = format!("{}-{}", base, path_hash_suffix(cwd));
    if !occupied.contains(&with_hash) {
        return with_hash;
    }
    // Highly unlikely (would require a SHA-256 prefix collision plus an
    // existing entry to claim it). Numeric tiebreaker as final fallback.
    for n in 2..1000 {
        let candidate = format!("{base}-{n}");
        if !occupied.contains(&candidate) {
            return candidate;
        }
    }
    // Pathological fallback — every numbered slot is taken.
    format!("{base}-{}-overflow", path_hash_suffix(cwd))
}

/// Summary of one on-disk session for `wire session list`.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub name: String,
    /// First cwd associated with this session in the registry. `None`
    /// if the session was created without registry tracking (manual
    /// `wire session new <name>`).
    pub cwd: Option<String>,
    pub home_dir: PathBuf,
    pub did: Option<String>,
    pub handle: Option<String>,
    /// True if a `daemon.pid` file exists AND the recorded PID is
    /// actually a live process (best-effort, not POSIX-portable but
    /// matches the existing `wire status` / `wire doctor` checks).
    pub daemon_running: bool,
}

/// Enumerate every on-disk session by reading `sessions_root()`. Cross-
/// references the registry so each entry's `cwd` is filled in when known.
pub fn list_sessions() -> Result<Vec<SessionInfo>> {
    let root = sessions_root()?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let registry = read_registry().unwrap_or_default();
    // Reverse lookup: name → cwd. Used to annotate each SessionInfo.
    let mut name_to_cwd: HashMap<String, String> = HashMap::new();
    for (cwd, name) in &registry.by_cwd {
        name_to_cwd.insert(name.clone(), cwd.clone());
    }

    let mut out = Vec::new();
    for entry in std::fs::read_dir(&root)?.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        // Skip the registry sidecar.
        if name == "registry.json" {
            continue;
        }
        let card_path = path.join("config").join("wire").join("agent-card.json");
        let (did, handle) = read_card_identity(&card_path);
        let daemon_running = check_daemon_live(&path);
        out.push(SessionInfo {
            name: name.clone(),
            cwd: name_to_cwd.get(&name).cloned(),
            home_dir: path,
            did,
            handle,
            daemon_running,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn read_card_identity(card_path: &Path) -> (Option<String>, Option<String>) {
    let bytes = match std::fs::read(card_path) {
        Ok(b) => b,
        Err(_) => return (None, None),
    };
    let v: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let did = v.get("did").and_then(|x| x.as_str()).map(str::to_string);
    let handle = v
        .get("handle")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .or_else(|| {
            did.as_ref().map(|d| {
                crate::agent_card::display_handle_from_did(d).to_string()
            })
        });
    (did, handle)
}

fn check_daemon_live(session_home: &Path) -> bool {
    // Pidfile lives at <session_home>/state/wire/daemon.pid. Use the
    // existing ensure_up reader by temporarily pointing at the path; we
    // can't change env mid-process race-free, so re-implement the pid
    // extraction directly here from the JSON structure.
    let pidfile = session_home
        .join("state")
        .join("wire")
        .join("daemon.pid");
    let bytes = match std::fs::read(&pidfile) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // Try the structured form first.
    let pid_opt: Option<u32> = if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        v.get("pid").and_then(|p| p.as_u64()).map(|p| p as u32)
    } else {
        // Legacy integer form.
        String::from_utf8_lossy(&bytes).trim().parse::<u32>().ok()
    };
    let pid = match pid_opt {
        Some(p) => p,
        None => return false,
    };
    is_process_live(pid)
}

fn is_process_live(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Read a session's `relay.json` and return its `self.endpoints[]`
/// array (v0.5.17 dual-slot). Empty Vec on any read/parse error — this
/// is a best-effort discovery helper, not a verification tool. A pre-
/// v0.5.17 session writes only the legacy flat fields; `self_endpoints`
/// promotes those to a federation-only Endpoint, so the result is
/// still meaningful for legacy sessions.
///
/// v0.5.20 BUG FIX: this used to join `relay-state.json`, which is
/// not the canonical filename (`config::relay_state_path` returns
/// `relay.json`). The mis-named read silently no-op'd and
/// `list-local` always returned an empty `local` map as a result.
/// Companion to the `cli.rs::try_allocate_local_slot` filename fix
/// in the same release — that helper had the symmetric write-side
/// bug, so the local endpoint never got persisted in the first place.
pub fn read_session_endpoints(session_home: &Path) -> Vec<Endpoint> {
    let path = session_home
        .join("config")
        .join("wire")
        .join("relay.json");
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let val: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    self_endpoints(&val)
}

/// Stripped view of a Local endpoint for tooling output. Drops
/// `slot_token` because it is a bearer credential — exposing it
/// through `wire session list-local --json` would risk accidental
/// leak via logs, screenshots, or piped output. Routing code uses
/// the full `Endpoint` from `relay.json` directly; this type
/// is for human/JSON observation only.
#[derive(Debug, Clone, Serialize)]
pub struct LocalEndpointView {
    pub relay_url: String,
    pub slot_id: String,
}

/// One row of `wire session list-local` output: a session that has a
/// Local-scope endpoint plus metadata to render it.
#[derive(Debug, Clone, Serialize)]
pub struct LocalSessionView {
    pub name: String,
    pub handle: Option<String>,
    pub did: Option<String>,
    pub cwd: Option<String>,
    pub home_dir: PathBuf,
    pub daemon_running: bool,
    /// All Local-scope endpoints this session advertises (token redacted).
    /// Most sessions have exactly one; multiple is permitted for multi-
    /// relay setups.
    pub local_endpoints: Vec<LocalEndpointView>,
}

/// Sessions with no Local endpoint — shown separately so the operator
/// knows they exist but are federation-only.
#[derive(Debug, Clone, Serialize)]
pub struct FederationOnlySessionView {
    pub name: String,
    pub handle: Option<String>,
    pub cwd: Option<String>,
}

/// Result shape for `wire session list-local`. `local` is grouped by
/// the local-relay URL so output can render each cluster of mutually-
/// reachable sister sessions together. `federation_only` lists the rest.
#[derive(Debug, Clone, Serialize)]
pub struct LocalSessionListing {
    pub local: HashMap<String, Vec<LocalSessionView>>,
    pub federation_only: Vec<FederationOnlySessionView>,
}

/// Build the listing for `wire session list-local` from current on-disk
/// state. Read-only; no daemon contact, no relay probe.
pub fn list_local_sessions() -> Result<LocalSessionListing> {
    let sessions = list_sessions()?;
    let mut local: HashMap<String, Vec<LocalSessionView>> = HashMap::new();
    let mut federation_only: Vec<FederationOnlySessionView> = Vec::new();

    for s in sessions {
        let endpoints = read_session_endpoints(&s.home_dir);
        let local_eps: Vec<Endpoint> = endpoints
            .into_iter()
            .filter(|e| matches!(e.scope, EndpointScope::Local))
            .collect();
        if local_eps.is_empty() {
            federation_only.push(FederationOnlySessionView {
                name: s.name.clone(),
                handle: s.handle.clone(),
                cwd: s.cwd.clone(),
            });
            continue;
        }
        // Redacted view: drop slot_token before exposing through CLI.
        let redacted: Vec<LocalEndpointView> = local_eps
            .iter()
            .map(|e| LocalEndpointView {
                relay_url: e.relay_url.clone(),
                slot_id: e.slot_id.clone(),
            })
            .collect();
        // Group by relay_url. A session with two Local endpoints (rare —
        // would mean two loopback relays) appears under each.
        for ep in &local_eps {
            local
                .entry(ep.relay_url.clone())
                .or_default()
                .push(LocalSessionView {
                    name: s.name.clone(),
                    handle: s.handle.clone(),
                    did: s.did.clone(),
                    cwd: s.cwd.clone(),
                    home_dir: s.home_dir.clone(),
                    daemon_running: s.daemon_running,
                    local_endpoints: redacted.clone(),
                });
        }
    }
    // Sort each group by session name so output is deterministic.
    for group in local.values_mut() {
        group.sort_by(|a, b| a.name.cmp(&b.name));
    }
    federation_only.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(LocalSessionListing {
        local,
        federation_only,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_handles_unicode_and_long_names() {
        assert_eq!(sanitize_name("paul-mac"), "paul-mac");
        assert_eq!(sanitize_name("Paul Mac!"), "paul-mac");
        assert_eq!(sanitize_name("ünìcødë"), "n-c-d"); // ascii-only fallback
        assert_eq!(sanitize_name(""), "wire-session");
        assert_eq!(sanitize_name("---"), "wire-session");
        let long: String = "a".repeat(100);
        assert_eq!(sanitize_name(&long).len(), 32);
    }

    #[test]
    fn derive_name_returns_basename_when_no_collision() {
        let reg = SessionRegistry::default();
        assert_eq!(
            derive_name_from_cwd(Path::new("/Users/paul/Source/wire"), &reg),
            "wire"
        );
        assert_eq!(
            derive_name_from_cwd(Path::new("/Users/paul/Source/slancha-mesh"), &reg),
            "slancha-mesh"
        );
    }

    #[test]
    fn derive_name_returns_stored_name_when_cwd_already_registered() {
        let mut reg = SessionRegistry::default();
        reg.by_cwd.insert(
            "/Users/paul/Source/wire".to_string(),
            "wire-special".to_string(),
        );
        assert_eq!(
            derive_name_from_cwd(Path::new("/Users/paul/Source/wire"), &reg),
            "wire-special"
        );
    }

    #[test]
    fn read_session_endpoints_handles_missing_relay_state() {
        let tmp = tempfile::tempdir().unwrap();
        // No relay.json under <home>/config/wire/ — should yield empty.
        let endpoints = read_session_endpoints(tmp.path());
        assert!(endpoints.is_empty());
    }

    #[test]
    fn read_session_endpoints_parses_dual_slot_form() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config").join("wire");
        std::fs::create_dir_all(&cfg).unwrap();
        let body = serde_json::json!({
            "self": {
                "relay_url": "https://wireup.net",
                "slot_id": "fed-slot",
                "slot_token": "fed-tok",
                "endpoints": [
                    {
                        "relay_url": "https://wireup.net",
                        "slot_id": "fed-slot",
                        "slot_token": "fed-tok",
                        "scope": "federation"
                    },
                    {
                        "relay_url": "http://127.0.0.1:8771",
                        "slot_id": "loop-slot",
                        "slot_token": "loop-tok",
                        "scope": "local"
                    }
                ]
            }
        });
        std::fs::write(cfg.join("relay.json"), serde_json::to_vec(&body).unwrap())
            .unwrap();
        let endpoints = read_session_endpoints(tmp.path());
        assert_eq!(endpoints.len(), 2);
        let local_count = endpoints
            .iter()
            .filter(|e| matches!(e.scope, EndpointScope::Local))
            .count();
        assert_eq!(local_count, 1);
        let local = endpoints
            .iter()
            .find(|e| matches!(e.scope, EndpointScope::Local))
            .unwrap();
        assert_eq!(local.relay_url, "http://127.0.0.1:8771");
        assert_eq!(local.slot_id, "loop-slot");
    }

    // NOTE: list_local_sessions is integration-tested via tests/cli.rs
    // using a subprocess that sets WIRE_HOME per-process. We do not test
    // it in-module because env mutation races other parallel unit tests
    // (Rust 2024 marks std::env::set_var unsafe for that reason). The
    // grouping logic is straightforward enough that the integration
    // test plus the read_session_endpoints unit tests above provide
    // adequate coverage.

    #[test]
    fn derive_name_appends_path_hash_when_basename_collides() {
        let mut reg = SessionRegistry::default();
        reg.by_cwd.insert(
            "/Users/paul/Source/wire".to_string(),
            "wire".to_string(),
        );
        // Different cwd, same basename → must get a hash suffix.
        let name = derive_name_from_cwd(Path::new("/Users/paul/Archive/wire"), &reg);
        assert!(name.starts_with("wire-"));
        assert_eq!(name.len(), "wire-".len() + 4); // 4 hex chars
        assert_ne!(name, "wire");
    }
}
