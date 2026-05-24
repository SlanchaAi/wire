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
    if let Ok(home_str) = std::env::var("WIRE_HOME") {
        let home = PathBuf::from(&home_str);
        let direct = home.join("sessions");
        if direct.exists() {
            return Ok(direct);
        }
        // v0.6.4: inside-session fallback. When WIRE_HOME is set by the
        // MCP auto-detect or `wire session env`, it points at one
        // session's home (`<root>/sessions/<name>`) — *not* the root
        // holding every session. Without this fallback, `wire mesh
        // status` / `mesh role list` / `mesh broadcast` invoked from
        // inside a session see zero sister sessions even though the
        // operator can plainly see them with `wire session list`.
        //
        // Walk up to the nearest ancestor named `sessions` and return it.
        // Handles BOTH the legacy `sessions/<name>` layout (parent named
        // `sessions`) and the v0.13 `sessions/by-key/<hash>` layout (parent
        // `by-key`, grandparent `sessions`). The old one-level parent check
        // matched only the legacy layout, so an inside-session WIRE_HOME on
        // v0.13 made sessions_root() point at a nonexistent nested dir —
        // list-local / mesh / pair-all-local then saw zero sisters even
        // though they were on disk. A WIRE_HOME with no `sessions` ancestor
        // (plain test dir, custom location) falls through to the v0.6.3
        // `<WIRE_HOME>/sessions/` behavior.
        let mut anc = Some(home.as_path());
        while let Some(p) = anc {
            if p.file_name().and_then(|s| s.to_str()) == Some("sessions") {
                return Ok(p.to_path_buf());
            }
            anc = p.parent();
        }
        return Ok(direct);
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
    let bytes =
        std::fs::read(&path).with_context(|| format!("reading session registry {path:?}"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing session registry {path:?}"))
}

pub fn write_registry(reg: &SessionRegistry) -> Result<()> {
    let path = registry_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
    }
    let body = serde_json::to_vec_pretty(reg)?;
    // v0.7.0-alpha.8 (review-fix #7): atomic write via tmp+rename so
    // concurrent unflocked readers (detect_session_wire_home,
    // list_sessions, cmd_peers) never observe a 0-byte / truncated
    // registry mid-write. Pre-alpha.8 used std::fs::write which
    // truncates first — race window where readers saw empty JSON and
    // fell back to default identity for the write duration.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body).with_context(|| format!("writing tmp session registry {tmp:?}"))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("atomic rename {tmp:?} → {path:?}"))?;
    Ok(())
}

/// v0.7.0-alpha.3: flock'd read-modify-write of the session registry.
///
/// `write_registry` alone is not safe under concurrency — multiple MCP
/// processes auto-initing in parallel each read an old snapshot, mutate
/// their copy, and write back, losing N-1 updates. This helper acquires
/// an exclusive flock on a sibling lockfile, re-reads inside the lock,
/// applies the caller's modifier, writes atomically, and releases.
///
/// Modeled on `config::update_relay_state`. Lock contention is bounded:
/// modifications are pure HashMap operations, write is whole-file at
/// roughly the registry size (KBs, not MBs).
pub fn update_registry<F>(modifier: F) -> Result<()>
where
    F: FnOnce(&mut SessionRegistry) -> Result<()>,
{
    use fs2::FileExt;
    let path = registry_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
    }
    let lock_path = path.with_extension("lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening {lock_path:?}"))?;
    lock_file
        .lock_exclusive()
        .with_context(|| format!("flock {lock_path:?}"))?;
    // Re-read INSIDE the lock — any prior snapshot would race.
    let mut reg = read_registry().unwrap_or_default();
    let result = modifier(&mut reg);
    let write_result = if result.is_ok() {
        write_registry(&reg)
    } else {
        Ok(())
    };
    let _ = fs2::FileExt::unlock(&lock_file);
    result?;
    write_result?;
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
    /// Display character (nickname + emoji + color palette) derived from
    /// the session's DID. `None` when the session has no agent-card yet
    /// (pre-init). Lazy-computed at read time; never persisted to disk.
    pub character: Option<crate::character::Character>,
}

/// Enumerate every on-disk session by reading `sessions_root()`. Cross-
/// references the registry so each entry's `cwd` is filled in when known.
/// v0.7.4: true iff the URL targets a loopback host (127.0.0.0/8 or
/// [::1] or `localhost`). Used to detect "this Federation-scope slot
/// is actually on a loopback relay" — those sessions are local-mesh
/// candidates even though they're not tagged `local`.
///
/// Best-effort string match; we don't need full URL parsing for this
/// because the relay URL is wire-controlled and follows a predictable
/// shape (`http://<host>[:<port>][/path]`).
fn url_is_loopback(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let after_scheme = match lower.split_once("://") {
        Some((_, rest)) => rest,
        None => lower.as_str(),
    };
    // Bracketed IPv6 literal: `[::1]:8771` keeps brackets in host slice.
    if let Some(rest) = after_scheme.strip_prefix('[') {
        return rest
            .split_once(']')
            .map(|(host, _)| host == "::1")
            .unwrap_or(false);
    }
    let host = after_scheme.split(['/', ':']).next().unwrap_or("");
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
}

/// v0.7.4: resolve an operator-typed name to a local sister session.
/// Input may be the session NAME (e.g. `slancha-api`), the card
/// HANDLE (usually equal to the name), or the character NICKNAME
/// (e.g. `noble-slate`). Returns the session NAME suitable for the
/// `--local-sister` add path. Case-insensitive. None on no match.
///
/// Designed for `wire add <input>` ergonomics — the operator should
/// be able to type whatever face wire put on the peer (statusline
/// nickname, session list emoji+name) and have wire find it.
pub fn resolve_local_sister(input: &str) -> Option<String> {
    let needle = input.trim();
    if needle.is_empty() {
        return None;
    }
    let sessions = list_sessions().ok()?;
    for s in &sessions {
        if s.name.eq_ignore_ascii_case(needle) {
            return Some(s.name.clone());
        }
        if let Some(h) = &s.handle
            && h.eq_ignore_ascii_case(needle)
        {
            return Some(s.name.clone());
        }
        if let Some(ch) = &s.character
            && ch.nickname.eq_ignore_ascii_case(needle)
        {
            return Some(s.name.clone());
        }
    }
    None
}

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

    // Build a SessionInfo from a home dir, labeled `name`. v0.11: character
    // is purely DID-derived (local display.json overrides removed).
    let mk = |path: PathBuf, name: String| -> SessionInfo {
        let card_path = path.join("config").join("wire").join("agent-card.json");
        let (did, handle) = read_card_identity(&card_path);
        let daemon_running = check_daemon_live(&path);
        let character = did.as_deref().map(crate::character::Character::from_did);
        SessionInfo {
            cwd: name_to_cwd.get(&name).cloned(),
            name,
            home_dir: path,
            did,
            handle,
            daemon_running,
            character,
        }
    };

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
        // v0.13: session homes live under `by-key/<hash>`, not at the top
        // level. Descend one level so same-box discovery (`list-local` /
        // `pair-all-local`) sees them — the `by-key` dir itself is a
        // container, not a session. Without this, EVERY v0.13 session was
        // invisible to the local mesh, silently forcing same-box sisters
        // onto federation instead of fast loopback routing.
        if name == "by-key" {
            for sub in std::fs::read_dir(&path)?.flatten() {
                let sub_path = sub.path();
                if !sub_path.is_dir() {
                    continue;
                }
                let hash = sub_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string();
                let mut info = mk(sub_path, hash);
                // Prefer the persona handle as the display name when the home
                // is initialized; fall back to the by-key hash otherwise.
                if let Some(h) = info.handle.clone() {
                    info.name = h;
                }
                out.push(info);
            }
            continue;
        }
        out.push(mk(path, name));
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
            did.as_ref()
                .map(|d| crate::agent_card::display_handle_from_did(d).to_string())
        });
    (did, handle)
}

fn check_daemon_live(session_home: &Path) -> bool {
    // Pidfile lives at <session_home>/state/wire/daemon.pid. Use the
    // existing ensure_up reader by temporarily pointing at the path; we
    // can't change env mid-process race-free, so re-implement the pid
    // extraction directly here from the JSON structure.
    let pidfile = session_home.join("state").join("wire").join("daemon.pid");
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
    // v0.7.3: delegate to the shared platform helper. The previous
    // implementation shelled out to `kill -0` on non-Linux, which
    // unconditionally failed on Windows (no `kill` binary) and made
    // `wire session list` report every daemon as `down` regardless of
    // actual liveness.
    crate::platform::process_alive(pid)
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
    let path = session_home.join("config").join("wire").join("relay.json");
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
            .filter(|e| {
                // v0.7.4: include any session whose endpoint URL is a
                // loopback address even if it's tagged Federation, not
                // Local. This catches the legitimate-but-misshapen case
                // where `wire init --relay http://127.0.0.1:8771` was run
                // without `--with-local`, leaving the session with a
                // loopback federation slot that's effectively local-mesh-
                // reachable. Pre-v0.7.4 the strict scope-only filter
                // silently excluded those sessions from `pair-all-local`,
                // making nickname-based pairing fail for no operator-
                // visible reason.
                matches!(e.scope, EndpointScope::Local)
                    || (matches!(e.scope, EndpointScope::Federation)
                        && url_is_loopback(&e.relay_url))
            })
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

/// v0.6.7: cwd → session WIRE_HOME lookup. Read-only.
///
/// When `WIRE_HOME` isn't set in env, look up `cwd` in the session
/// registry. If a session is registered for this cwd AND its home
/// directory still exists, return that home dir; otherwise None.
///
/// Used by both `wire mcp` (v0.6.1) and the CLI entry point (v0.6.7)
/// so a `wire whoami` / `wire monitor` invocation from a project cwd
/// adopts that project's session identity automatically, instead of
/// silently falling back to the machine default. The CLI parity is
/// load-bearing: without it, the user-visible identity diverges
/// between MCP and the terminal, and monitors pull machine-wide
/// inboxes when the operator expected a per-session view.
pub fn detect_session_wire_home(cwd: &std::path::Path) -> Option<PathBuf> {
    let registry = read_registry().ok()?;
    // v0.7.0-alpha.2: walk up parent dirs. Subdirs of a registered cwd
    // inherit their parent's wire identity (e.g.
    // `~/Source/slancha-business/tools/recon` → `slancha-business` session).
    // Without this, subdirs all fell back to the machine-wide default
    // identity, which silently collapsed multiple Claude sessions onto the
    // same DID + character.
    let mut probe: Option<&std::path::Path> = Some(cwd);
    while let Some(path) = probe {
        let path_str = path.to_string_lossy().into_owned();
        if let Some(session_name) = registry.by_cwd.get(&path_str) {
            let session_home = session_dir(session_name).ok()?;
            if session_home.exists() {
                return Some(session_home);
            }
        }
        probe = path.parent();
    }
    None
}

/// v0.13: resolve a stable per-session key — host-agnostic, with a Claude
/// Code adapter and the path left open for other hosts. Order:
///   1. `WIRE_SESSION_ID` — explicit universal override (any harness).
///   2. `CLAUDE_CODE_SESSION_ID` — Claude Code adapter (stable per
///      conversation; the same id the auto-memory system keys off).
///   3. `None` — caller falls back to legacy cwd-detect (bare CLI /
///      pre-v0.13 hosts). Future host adapters slot in before this.
///
/// Returns `(key, source-label)`.
pub fn resolve_session_key() -> Option<(String, &'static str)> {
    for (var, source) in [
        ("WIRE_SESSION_ID", "override"),
        ("CLAUDE_CODE_SESSION_ID", "claude-code"),
    ] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim();
            if !v.is_empty() {
                return Some((v.to_string(), source));
            }
        }
    }
    None
}

/// v0.13: the WIRE_HOME for a resolved session key —
/// `<sessions_root>/by-key/<hash>` where `hash` is the first 16 hex of
/// SHA-256(key). Deterministic and cwd-independent, so two sessions never
/// collide and there is no path-string to mis-normalize (the Windows bug
/// cannot occur). 64 bits is collision-safe at this scale.
pub fn session_home_for_key(key: &str) -> Result<PathBuf> {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    let digest = h.finalize();
    let hash = hex::encode(&digest[..8]); // 16 hex chars / 64 bits
    Ok(sessions_root()?.join("by-key").join(hash))
}

/// v0.6.10: warn at MCP/CLI startup if another `wire mcp` process is
/// already running with the same effective `WIRE_HOME`. Closes the
/// "two Claudes in same cwd silently share an identity" failure mode
/// that wasted hours of operator debugging time: today the collision
/// is invisible (both Claudes resolve to the same wire session via
/// v0.6.7 auto-detect, race the inbox cursor, "look identical" from
/// the operator's view). This surfaces it explicitly with a clear
/// remediation path.
///
/// Best-effort: any subprocess / env-read failure is silent (the
/// collision check should never block startup). Cross-platform via
/// `ps -E -p <pid>` on macOS, `/proc/<pid>/environ` on Linux. Windows
/// returns empty (no collision detected).
pub fn warn_on_identity_collision(self_pid: u32) {
    let our_wire_home = match std::env::var("WIRE_HOME") {
        Ok(h) => h,
        Err(_) => return,
    };

    let pgrep_out = match std::process::Command::new("pgrep")
        .args(["-f", "wire mcp"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return,
    };

    let other_pids: Vec<u32> = String::from_utf8_lossy(&pgrep_out.stdout)
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
        .filter(|&p| p != self_pid)
        .collect();

    let mut colliders: Vec<u32> = Vec::new();
    for pid in &other_pids {
        if let Some(their_home) = read_wire_home_from_pid(*pid)
            && their_home == our_wire_home
        {
            colliders.push(*pid);
        }
    }

    if colliders.is_empty() {
        return;
    }

    eprintln!(
        "wire mcp: WARNING — {} other wire mcp process(es) already using WIRE_HOME=`{}` (pid {})",
        colliders.len(),
        our_wire_home,
        colliders
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!(
        "  Multiple agents sharing one identity will race the inbox cursor; messages may be lost."
    );
    eprintln!("  To use a separate identity:");
    eprintln!("    1. Close the other agent(s), OR");
    eprintln!("    2. `wire session new <name> --local-only` to create a fresh identity, then");
    eprintln!(
        "    3. Restart THIS agent's launcher with `export WIRE_HOME=<path printed by step 2>`"
    );
}

/// Best-effort cross-platform read of another process's `WIRE_HOME`.
/// Linux: parses `/proc/<pid>/environ` (NUL-separated KEY=VAL).
/// macOS: `ps -E -p <pid>` (whitespace-separated KEY=VAL prefix).
/// Windows / other: returns `None` (collision detection no-ops).
fn read_wire_home_from_pid(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/{pid}/environ");
        let bytes = std::fs::read(&path).ok()?;
        for entry in bytes.split(|&b| b == 0) {
            let s = match std::str::from_utf8(entry) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if let Some(val) = s.strip_prefix("WIRE_HOME=") {
                return Some(val.to_string());
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ps")
            .args(["-E", "-p", &pid.to_string(), "-o", "command="])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&output.stdout);
        for tok in s.split_whitespace() {
            if let Some(val) = tok.strip_prefix("WIRE_HOME=") {
                return Some(val.to_string());
            }
        }
        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// v0.6.7: apply `detect_session_wire_home` for the current process.
///
/// If `WIRE_HOME` is unset and the current cwd maps to an existing
/// session, set `WIRE_HOME` for the rest of this process and emit a
/// one-liner to stderr so the operator knows which identity is in
/// use. Noop when `WIRE_HOME` is already set (explicit override wins).
///
/// `label` distinguishes the caller in the stderr line (`mcp` vs
/// `cli`). Set `WIRE_QUIET_AUTOSESSION=1` to suppress the stderr line
/// while keeping the env-var application active.
///
/// MUST be called BEFORE any worker thread or async task spawns —
/// `env::set_var` is unsafe in Rust 2024 because of thread-safety
/// guarantees, and our use is safe only at process entry.
pub fn maybe_adopt_session_wire_home(label: &str) {
    if std::env::var("WIRE_HOME").is_ok() {
        return;
    }
    // v0.13: prefer the host-agnostic session key (WIRE_SESSION_ID >
    // CLAUDE_CODE_SESSION_ID). Each session gets its own WIRE_HOME under
    // `by-key/<hash>` — no cwd lookup, no shared default, no Windows path
    // collapse. Falls back to legacy cwd-detect only when no session key is
    // present (bare CLI / pre-v0.13 hosts).
    let (home, why) = if let Some((key, source)) = resolve_session_key() {
        match session_home_for_key(&key) {
            Ok(h) => {
                // by-key homes are created lazily on first resolution.
                if let Err(e) = std::fs::create_dir_all(&h) {
                    eprintln!(
                        "wire {label}: could not create session home {}: {e}",
                        h.display()
                    );
                    return;
                }
                (h, format!("session key ({source})"))
            }
            Err(_) => return,
        }
    } else {
        let cwd = match std::env::current_dir() {
            Ok(c) => c,
            Err(_) => return,
        };
        match detect_session_wire_home(&cwd) {
            Some(h) => (h, format!("cwd `{}`", cwd.display())),
            None => return,
        }
    };
    // v0.9.1: emit the chatter ONLY when stderr is an interactive TTY.
    // When wire is invoked from a non-interactive parent (Claude Code's
    // Bash tool, scripts, daemons), the auto-detect line is captured
    // alongside command output and pollutes both — wasting agent
    // context tokens and breaking JSON parsers that read combined
    // streams. WIRE_VERBOSE=1 forces the line on; WIRE_QUIET_AUTOSESSION
    // still forces it off for back-compat with v0.9 scripts.
    use std::io::IsTerminal;
    let quiet_env = std::env::var("WIRE_QUIET_AUTOSESSION").is_ok();
    let verbose_env = std::env::var("WIRE_VERBOSE").is_ok();
    let interactive = std::io::stderr().is_terminal();
    if !quiet_env && (interactive || verbose_env) {
        eprintln!(
            "wire {label}: adopted {why} → WIRE_HOME=`{}`",
            home.display()
        );
    }
    // SAFETY: caller contract is "before any thread spawn." All
    // production sites (cli::run, mcp::run) call this as the first
    // step in their respective entry points.
    unsafe {
        std::env::set_var("WIRE_HOME", &home);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_sessions_sees_by_key_homes_and_root_resolves_from_inside() {
        // Regression (v0.13.2): v0.13 moved session homes under
        // `sessions/by-key/<hash>`, but (1) list_sessions only scanned the
        // top level so by-key homes were invisible, and (2) sessions_root()'s
        // inside-session fallback only walked ONE level up (expecting parent
        // `sessions`), so an inside-session WIRE_HOME resolved to a bogus
        // nested dir. Together they made same-box discovery (list-local /
        // pair-all-local) return zero sisters under v0.13.
        let _guard = crate::config::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let tmp = std::env::temp_dir().join(format!("wire-bykey-{}", rand::random::<u32>()));
        let _ = std::fs::remove_dir_all(&tmp);
        let root = tmp.join("sessions");
        let home = root.join("by-key").join("abc123def4567890");
        let cfg = home.join("config").join("wire");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join("agent-card.json"),
            r#"{"did":"did:wire:test-persona-6e301ab1","handle":"test-persona","verify_keys":{}}"#,
        )
        .unwrap();

        // (1) sessions_root() must find the real root even when WIRE_HOME
        //     points INSIDE the by-key home.
        // SAFETY: ENV_LOCK is held, serializing all env access.
        unsafe { std::env::set_var("WIRE_HOME", &home) };
        assert_eq!(
            sessions_root().unwrap(),
            root,
            "sessions_root must resolve the root from inside a by-key home"
        );

        // (2) list_sessions() must enumerate the by-key home, labeled by handle.
        let sessions = list_sessions().unwrap();
        let found = sessions
            .iter()
            .any(|s| s.handle.as_deref() == Some("test-persona"));
        unsafe { std::env::remove_var("WIRE_HOME") };
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            found,
            "by-key home must be enumerated: {:?}",
            sessions.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn session_home_for_key_is_deterministic_distinct_and_well_formed() {
        let a1 = session_home_for_key("sess-aaa").unwrap();
        let a2 = session_home_for_key("sess-aaa").unwrap();
        let b = session_home_for_key("sess-bbb").unwrap();
        assert_eq!(a1, a2, "same key -> same home (resume stability)");
        assert_ne!(a1, b, "distinct keys -> distinct homes (no collision)");
        let leaf = a1.file_name().unwrap().to_str().unwrap();
        assert_eq!(leaf.len(), 16, "16 hex chars / 64 bits");
        assert!(leaf.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            a1.parent().unwrap().file_name().unwrap().to_str().unwrap(),
            "by-key"
        );
    }

    #[test]
    fn url_is_loopback_recognises_v4_v6_and_localhost_v0_7_4() {
        assert!(url_is_loopback("http://127.0.0.1:8771"));
        assert!(url_is_loopback("http://127.1.2.3"));
        assert!(url_is_loopback("http://localhost:9000"));
        assert!(url_is_loopback("https://localhost/v1"));
        assert!(url_is_loopback("http://[::1]:8771"));
        // Case-insensitive.
        assert!(url_is_loopback("HTTP://LOCALHOST:8771"));
        // Non-loopback negatives — must NOT be flagged.
        assert!(!url_is_loopback("https://wireup.net"));
        assert!(!url_is_loopback("http://192.168.1.50:8771"));
        assert!(!url_is_loopback("http://10.0.0.5"));
        assert!(!url_is_loopback("https://relay.example.com"));
    }

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
        std::fs::write(cfg.join("relay.json"), serde_json::to_vec(&body).unwrap()).unwrap();
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
        reg.by_cwd
            .insert("/Users/paul/Source/wire".to_string(), "wire".to_string());
        // Different cwd, same basename → must get a hash suffix.
        let name = derive_name_from_cwd(Path::new("/Users/paul/Archive/wire"), &reg);
        assert!(name.starts_with("wire-"));
        assert_eq!(name.len(), "wire-".len() + 4); // 4 hex chars
        assert_ne!(name, "wire");
    }
}
