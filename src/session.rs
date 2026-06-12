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
    default_sessions_root()
}

/// The machine's DEFAULT sessions root — `sessions_root()` with the
/// `WIRE_HOME` override deliberately ignored. This is where the real
/// operator install lives even when the calling process runs under a
/// temp/test `WIRE_HOME`. Used by `wire nuke`'s host guard, whose whole
/// point is to see past the caller's env to what the machine-global
/// teardown would actually hit.
pub fn default_sessions_root() -> Result<PathBuf> {
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
///
/// Resolves the *legacy v0.6 top-level* layout only — joins the
/// session name directly onto `sessions_root`. Operator-facing CLI
/// paths that accept a user-typed session name should use
/// [`find_session_home_by_name`] instead, which also handles the
/// v0.13 `by-key/<hash>` layout where the on-disk dir name is a hash
/// and the user-facing name is the persona handle derived from the
/// card.
pub fn session_dir(name: &str) -> Result<PathBuf> {
    Ok(sessions_root()?.join(sanitize_name(name)))
}

/// Operator-facing session-name → home_dir resolver. Handles BOTH
/// layouts wire has shipped:
///
/// 1. **v0.6 top-level**: `sessions_root/<name>` — the user-typed
///    name IS the directory name. [`session_dir`] is the direct
///    primitive.
/// 2. **v0.13 by-key/<hash>**: the on-disk dir is a 16-hex hash but
///    operators type the persona handle (`coral-weasel`,
///    `agate-nimbus`) — derived from the card's DID. [`list_sessions`]
///    surfaces those entries with `SessionInfo.name = handle`, so we
///    can walk it and match.
///
/// Order: try the literal top-level path first (fast, no enumeration),
/// then fall back to a `list_sessions` walk for the by-key handle
/// case. Returns `Ok(None)` when neither layout has a match — the
/// caller decides whether to error or no-op.
///
/// v0.14.2 (#170 follow-up from #174's PR body): operators running
/// `wire daemon --session foo` from a tmux pane on a v0.13 box hit
/// `session 'foo' not found` because the literal path didn't exist.
/// That's #174's exact failure mode (supervisor case, now fixed via
/// env-pinned WIRE_HOME) reapplied to the operator-facing CLI path.
pub fn find_session_home_by_name(name: &str) -> Result<Option<PathBuf>> {
    // 1. Legacy literal lookup.
    let direct = session_dir(name)?;
    if direct.exists() {
        return Ok(Some(direct));
    }
    // 2. v0.13 by-key walk: list_sessions overrides SessionInfo.name to
    // the handle when the card is present; match against either the
    // overridden name or the raw by-key hash.
    let sanitized = sanitize_name(name);
    for info in list_sessions().unwrap_or_default() {
        if info.name == name
            || info.name == sanitized
            || info
                .home_dir
                .file_name()
                .and_then(|s| s.to_str())
                .map(|f| f == name)
                .unwrap_or(false)
        {
            return Ok(Some(info.home_dir));
        }
    }
    Ok(None)
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

/// v0.13.6: case-insensitive cwd-registry key on Windows.
///
/// Issue #30 (Willard repro): on Windows, two terminals in the "same"
/// project under different drive/path casing (`C:\Foo\Bar` vs
/// `C:\foo\bar`) hashed to DIFFERENT registry keys — the second
/// terminal's `wire whoami` missed the registry lookup, derived a
/// phantom name, and silently fell back to the legacy default identity
/// (e.g. `did:wire:willard`). Both terminals collapsed onto one shared
/// DID, every pairing attempt between them was a self-pair, and
/// bilateral handshake could never complete.
///
/// Fix: on Windows, lowercase the cwd before reading from OR writing to
/// the cwd→session map. Two paths that resolve to the same on-disk
/// directory now produce the same registry key regardless of how the
/// shell / launcher capitalized them.
///
/// On case-sensitive filesystems (Linux / macOS HFS+ / case-sensitive
/// APFS / NTFS in case-sensitive mode) the path is returned as-is —
/// distinct casings legitimately point at distinct directories.
///
/// Used at every read and write of `SessionRegistry.by_cwd` so old
/// non-canonical entries written by v0.13.5 still resolve under v0.13.6+
/// later, and new entries written under v0.13.6+ are immediately canonical.
pub fn normalize_cwd_key(path: &Path) -> String {
    let s = path.to_string_lossy().into_owned();
    if cfg!(windows) { s.to_lowercase() } else { s }
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
    let cwd_key = normalize_cwd_key(cwd);
    // Backward compat: O(n) normalized scan on read-miss.
    //
    // Per @laulpogan / coral-weasel correction on #67: a verbatim fallback
    // (try the raw lookup string if the normalized lookup misses) only
    // handles consistent-casing upgraders — it can't recover a
    // mixed-case stored key (`C:\Users\Willard\...`) from a different-
    // case lookup (`c:\users\willard\...`) because both raw and
    // normalized lookup strings derive from the LOOKUP path; the
    // stored key's original casing is unrecoverable from the lookup
    // alone.
    //
    // The O(n) scan handles both cases:
    //   - Consistent casing: normalize(stored) == cwd_key on the FIRST
    //     `.get` (no scan needed; happy path is O(1)).
    //   - Cross casing: stored "C:\Users\Willard" normalizes to
    //     "c:\users\willard" == cwd_key → the scan resolves it.
    //
    // O(n) is over the per-machine session count (typically <20),
    // hit only on the rare upgrader-misses-normalized-lookup case.
    // New writes are normalized (see cli.rs insert sites) so the
    // scan-cost shrinks to zero as old entries get touched.
    if let Some(existing) = registry.by_cwd.get(&cwd_key).or_else(|| {
        registry
            .by_cwd
            .iter()
            .find(|(k, _)| normalize_cwd_key(Path::new(k)) == cwd_key)
            .map(|(_, v)| v)
    }) {
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
                // E8 (v0.13.2): skip uninitialized by-key homes. maybe_adopt_
                // session_wire_home creates the home dir on first resolution —
                // before any identity exists — so transient/probe session keys
                // that never `wire up` leave empty or agent-card-less homes.
                // Without this filter they surfaced as phantom "?"-handle
                // sisters in list-local, degrading the very discovery rc3
                // fixed. No DID == no identity == not a session.
                if info.did.is_none() {
                    continue;
                }
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

/// Read a session home's daemon pid from `<home>/state/wire/daemon.pid`
/// (path-based; does NOT consult WIRE_HOME). None if absent/corrupt. Used to
/// enumerate which daemon pids legitimately belong to a session so orphan
/// detection doesn't flag a sibling session's daemon (A2).
pub fn session_daemon_pid(session_home: &Path) -> Option<u32> {
    let pidfile = session_home.join("state").join("wire").join("daemon.pid");
    let bytes = std::fs::read(&pidfile).ok()?;
    // Pidfile is the JSON `{"pid": <n>, ...}` form (v0.5.11+). Anything
    // else reads as "no daemon".
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("pid").and_then(|p| p.as_u64()))
        .map(|p| p as u32)
}

fn check_daemon_live(session_home: &Path) -> bool {
    session_daemon_pid(session_home)
        .map(is_process_live)
        .unwrap_or(false)
}

/// Walk every initialized session and read its `daemon.pid`; return a
/// map from `pid → session_name`. Used by `wire status`'s orphan-pid
/// annotation (#173 follow-up) so a supervisor child's pid — which
/// no longer carries `--session <name>` in its cmdline post-#174 — is
/// still correctly attributed to the session whose home it serves.
///
/// Cost: one filesystem read per session per status invocation. On a
/// 133-session box that's 133 small reads (a few ms total) — bounded
/// + acceptable. The map is fresh per call; no caching, no staleness.
pub fn pid_to_session_map() -> HashMap<u32, String> {
    let mut out = HashMap::new();
    let sessions = match list_sessions() {
        Ok(v) => v,
        Err(_) => return out,
    };
    for info in sessions {
        if let Some(pid) = session_daemon_pid(&info.home_dir) {
            out.insert(pid, info.name);
        }
    }
    out
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
        // Same O(n) normalized scan as derive_name_from_cwd: handles both
        // consistent-casing and cross-casing upgraders. See the comment
        // on derive_name_from_cwd for the rationale.
        let path_str = normalize_cwd_key(path);
        if let Some(session_name) = registry.by_cwd.get(&path_str).or_else(|| {
            registry
                .by_cwd
                .iter()
                .find(|(k, _)| normalize_cwd_key(Path::new(k)) == path_str)
                .map(|(_, v)| v)
        }) {
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
///   3. `CODEX_SESSION_ID` — OpenAI Codex CLI adapter. Stable per Codex
///      thread (the same UUIDv7 emitted in `thread.started` and used as
///      the rollout-file suffix under `$CODEX_HOME/sessions/`). Codex
///      does not yet forward this var to MCP children out of the box —
///      operators must set it via `[mcp_servers.<name>.env]` in
///      `~/.codex/config.toml` (or upstream Codex must add it to the
///      MCP child env). Wiring the name in advance means once Codex
///      ships the env, wire picks it up with zero further code change.
///   4. `COPILOT_AGENT_SESSION_ID` — GitHub Copilot CLI (`gh copilot` /
///      `copilot`) adapter. Set by the Copilot CLI host for every
///      session; stable per conversation; UUID-shaped.
///   5. `VSCODE_GIT_REPOSITORY_ROOT` — VS Code/GitHub Copilot workspace-based
///      identity (stable per workspace).
///   6. `None` — caller falls back to legacy cwd-detect (bare CLI /
///      pre-v0.13 hosts). Future host adapters slot in before this.
///
/// Returns `(key, source-label)`.
pub fn resolve_session_key() -> Option<(String, &'static str)> {
    for (var, source) in [
        ("WIRE_SESSION_ID", "override"),
        ("CLAUDE_CODE_SESSION_ID", "claude-code"),
        ("CODEX_SESSION_ID", "codex-cli"),
        ("COPILOT_AGENT_SESSION_ID", "copilot-cli"),
        ("VSCODE_GIT_REPOSITORY_ROOT", "vscode-workspace"),
    ] {
        if let Ok(v) = std::env::var(var)
            && valid_session_key(&v)
        {
            return Some((v.trim().to_string(), source));
        }
    }
    // Claude Code adapter (host-agnostic fallback). On some platforms the MCP
    // server process does not inherit CLAUDE_CODE_SESSION_ID and the MCP
    // `initialize` handshake carries no session id, so the env checks above
    // miss. Claude Code, however, writes `~/.claude/sessions/<pid>.json`
    // ({"sessionId":..., "cwd":...}) for each live session, named by the
    // owning `claude` process PID. Walk our parent-process chain to that
    // process and read its sessionId — deterministic, race-free, env-free.
    if let Some(sid) = claude_code_session_from_pidfile() {
        return Some((sid, "claude-code-pidfile"));
    }

    None
}

/// A session key from the environment is usable only if it is non-empty and is
/// NOT an unexpanded `${...}` placeholder. A host that writes
/// `"env": {"WIRE_SESSION_ID": "${CLAUDE_CODE_SESSION_ID}"}` but doesn't expand
/// it (Windows Claude Code passes the literal when the var is absent) would
/// otherwise have wire hash the literal — collapsing every session onto one
/// identity. Treat any `${...}` value as unset so resolution falls through to
/// the PID-file adapter / per-process mint instead of a shared bogus persona.
fn valid_session_key(v: &str) -> bool {
    let v = v.trim();
    !v.is_empty() && !v.contains("${")
}

/// Recover the Claude Code session id from the per-session PID-file when it
/// isn't available via the environment. Claude Code writes
/// `~/.claude/sessions/<pid>.json` = `{"sessionId": "...", "cwd": "...", ...}`
/// for each live session, keyed by the owning `claude` process PID. The MCP
/// server we run inside is a descendant of that process, so we walk our
/// parent chain and return the `sessionId` of the first ancestor that has a
/// PID-file. Cross-platform: the file exists on macOS/Linux/Windows alike.
fn claude_code_session_from_pidfile() -> Option<String> {
    let dir = dirs::home_dir()?.join(".claude").join("sessions");
    let mut pid = std::process::id();
    // Chains are shallow (MCP server -> launcher -> claude); 16 is generous.
    for _ in 0..16 {
        let f = dir.join(format!("{pid}.json"));
        if let Ok(txt) = std::fs::read_to_string(&f)
            && let Ok(v) = serde_json::from_str::<Value>(&txt)
            && let Some(s) = v.get("sessionId").and_then(Value::as_str)
        {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
        pid = parent_pid(pid)?;
    }
    None
}

/// Best-effort parent-PID lookup. Linux: `/proc/<pid>/status`. macOS: `ps`.
/// Windows: PowerShell CIM (no extra crate). Returns `None` on any failure,
/// which simply ends the walk.
#[cfg(target_os = "linux")]
fn parent_pid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn parent_pid(pid: u32) -> Option<u32> {
    let out = std::process::Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(target_os = "windows")]
fn parent_pid(pid: u32) -> Option<u32> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').ParentProcessId"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn parent_pid(_pid: u32) -> Option<u32> {
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

/// Long-running `wire <subcommand>` invocations that own the inbox
/// cursor and therefore race each other under a shared `WIRE_HOME`.
/// Keep this list in sync with [`warn_on_identity_collision`]'s pgrep
/// predicate and the call-site list in `cli::run` / `mcp::run`.
///
/// Note: `pair-host` (and the rest of the SAS code-phrase flow) was removed
/// in RFC-005 follow-on, so it is naturally absent from this list.
///
/// Short-lived commands (`whoami`, `status`, `send`, `peers`, …) are
/// intentionally absent — they write atomically and don't race, and
/// warning on every one would spam any operator running scripts.
pub const INBOX_OWNING_SUBCOMMANDS: &[&str] = &["mcp", "daemon", "monitor", "notify"];

/// v0.6.10: warn at MCP/CLI startup if another long-running `wire`
/// process is already running with the same effective `WIRE_HOME`.
/// Closes the "two Claudes in same cwd silently share an identity"
/// failure mode that wasted hours of operator debugging time: today
/// the collision is invisible (both Claudes resolve to the same wire
/// session via v0.6.7 auto-detect, race the inbox cursor, "look
/// identical" from the operator's view). This surfaces it explicitly
/// with a clear remediation path.
///
/// `role` is the calling subcommand label (`"mcp"`, `"daemon"`,
/// `"monitor"`, …) — used in the warning's leading tag so operators
/// can tell which surface is observing the collision. Detection
/// itself spans every inbox-owning role: a `wire daemon` colliding
/// with an existing `wire mcp` warns just the same as an mcp/mcp
/// pair.
///
/// Best-effort: any subprocess / env-read failure is silent (the
/// collision check should never block startup). Cross-platform via
/// `ps -E -p <pid>` on macOS, `/proc/<pid>/environ` on Linux. Windows
/// returns empty (no collision detected).
pub fn warn_on_identity_collision(self_pid: u32, role: &str) {
    let our_wire_home = match std::env::var("WIRE_HOME") {
        Ok(h) => h,
        Err(_) => return,
    };

    // Single pgrep call with an alternation predicate. `pgrep -f`
    // matches against the full argv string, so `wire (mcp|daemon|…)`
    // catches every inbox-owning subcommand in one shot. Falls back to
    // silent no-op on platforms without pgrep (Windows) — the env-read
    // path below also returns None there, so detection is end-to-end
    // unsupported on Windows. Future: a powershell adapter for
    // identity collisions, tracked in #29 / #30.
    let predicate = format!("wire ({})", INBOX_OWNING_SUBCOMMANDS.join("|"));
    let pgrep_out = match std::process::Command::new("pgrep")
        .args(["-f", &predicate])
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

    let other_homes: Vec<(u32, Option<String>)> = other_pids
        .iter()
        .map(|p| (*p, read_wire_home_from_pid(*p)))
        .collect();

    let colliders = find_colliders(&our_wire_home, &other_homes);

    if colliders.is_empty() {
        return;
    }

    emit_collision_warning(role, &our_wire_home, &colliders);
}

/// Pure decision: from a snapshot of `(pid, their_wire_home)` for
/// every other wire process on the host, return the pids whose
/// `WIRE_HOME` exactly matches ours. Missing-home entries (process
/// died, env unreadable on this platform) are skipped, never counted.
pub(crate) fn find_colliders(
    our_wire_home: &str,
    other_homes: &[(u32, Option<String>)],
) -> Vec<u32> {
    other_homes
        .iter()
        .filter_map(|(pid, their_home)| match their_home {
            Some(h) if h == our_wire_home => Some(*pid),
            _ => None,
        })
        .collect()
}

/// Render the collision warning. Extracted so the format is unit-
/// testable without mocking a real pgrep / cross-process env read.
pub(crate) fn emit_collision_warning(role: &str, our_wire_home: &str, colliders: &[u32]) {
    eprintln!(
        "wire {role}: WARNING — {} other wire process(es) already using WIRE_HOME=`{}` (pid {})",
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
///
/// Also used by `ensure_up::daemon_liveness` to scope the orphan-daemon
/// check to processes serving the same WIRE_HOME.
pub(crate) fn read_wire_home_from_pid(pid: u32) -> Option<String> {
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
/// `cli`). Output only appears on interactive TTYs; set `WIRE_VERBOSE=1`
/// to force it on in non-interactive contexts.
///
/// MUST be called BEFORE any worker thread or async task spawns —
/// `env::set_var` is unsafe in Rust 2024 because of thread-safety
/// guarantees, and our use is safe only at process entry.
/// Process-global record of WHICH signal won session/home resolution,
/// captured at adoption time by [`maybe_adopt_session_wire_home`]. Read by
/// `wire whoami --json` (`session_source`) so an operator can see in one
/// command whether identity came from an explicit `WIRE_HOME`, a host
/// session-id adapter, the Claude-Code pidfile fallback, a minted
/// per-process key, or the machine default. Post-hoc re-derivation is
/// unreliable — minting sets `WIRE_SESSION_ID` and `WIRE_HOME` is always set
/// after adoption — so the winning source MUST be captured here, once.
static SESSION_SOURCE: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// The signal that won session/home resolution for this process. One of:
/// `env:WIRE_HOME`, `env:WIRE_HOME_FORCE` (RFC-008 §C legacy-shape force),
/// `override` (`WIRE_SESSION_ID`), `claude-code`, `claude-code-pidfile`,
/// `codex-cli`, `copilot-cli`, `vscode-workspace`, `minted`,
/// `machine-default`, or `unknown` if adoption never ran.
pub fn session_source() -> &'static str {
    SESSION_SOURCE.get().copied().unwrap_or("unknown")
}

/// RFC-008 §C — does this `WIRE_HOME` path point at the modern operator-
/// explicit `sessions/by-key/<16-hex-hash>` shape, or at an older/foreign
/// path?
///
/// The precedence flip in `maybe_adopt_session_wire_home` uses this to keep
/// **explicit modern pins** winning (operator deliberately joining two CC
/// tabs to one fleet-shared home, IDE config pinning a by-key path on
/// purpose) while letting the **session-key chain** beat a stale pre-v0.13.5
/// shell-profile `WIRE_HOME` pointing at the cwd-derived legacy layout
/// (paul's RFC-005 Phase 4 deletes the LAYOUT reader, but a shell-set env
/// var pointing at the path lingers across upgrades — that's the #210
/// regression). A non-by-key-shape `WIRE_HOME` loses to a present
/// session-key env var unless the operator opts back into legacy
/// ordering via `WIRE_HOME_FORCE=1`.
///
/// Match rule: `/by-key/<16-hex>` substring anywhere in the path (anchored
/// to a `by-key` segment with a `/` or `\` separator). Cross-platform: works
/// for both `/` and `\` separators by checking both.
fn is_by_key_shape(path: &str) -> bool {
    for needle in ["/by-key/", "\\by-key\\"] {
        if let Some(pos) = path.find(needle) {
            let after = &path[pos + needle.len()..];
            // Hash is the first path segment after `by-key/`. Take up to
            // the next separator (or end of string).
            let hash = after.split(['/', '\\']).next().unwrap_or("");
            // Wire writes exactly 16 lowercase hex chars
            // (`session_home_for_key`); reject anything else as malformed
            // → treat as legacy for safety.
            // Lowercase-only: wire emits `hex::encode(...)` which is
            // lowercase. `is_ascii_hexdigit` accepts both cases, so guard
            // explicitly against uppercase to keep the test pin from
            // `is_by_key_shape_rejects_legacy_and_malformed` honest.
            if hash.len() == 16
                && hash
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
            {
                return true;
            }
        }
    }
    false
}

pub fn maybe_adopt_session_wire_home(label: &str) {
    // RFC-008 §C — precedence flip for the agent-host case. Before §C:
    // presence of `WIRE_HOME` in env unconditionally short-circuited the
    // session-key chain, so a stale pre-v0.13.5 shell-profile pin (#210
    // reproducer) silently overrode CLAUDE_CODE_SESSION_ID. After §C:
    // WIRE_HOME still wins for the OPERATOR-EXPLICIT cases (by-key-shape
    // modern pin OR WIRE_HOME_FORCE=1 legacy-shape override). A
    // non-by-key-shape WIRE_HOME without WIRE_HOME_FORCE=1 LOSES to a
    // present session-key env var. Closes the silent-override path
    // without breaking the deliberate-fleet-share contract.
    if let Ok(pin) = std::env::var("WIRE_HOME") {
        let force = std::env::var("WIRE_HOME_FORCE").is_ok();
        let by_key = is_by_key_shape(&pin);
        if by_key {
            // Modern operator-explicit pin. Always wins.
            let _ = SESSION_SOURCE.set("env:WIRE_HOME");
            return;
        }
        if force {
            // Legacy-shape pin + explicit operator opt-back-in. Surface the
            // force so operators reading whoami can tell the override is
            // active (not silent).
            let _ = SESSION_SOURCE.set("env:WIRE_HOME_FORCE");
            return;
        }
        // Legacy-shape pin without WIRE_HOME_FORCE. Check if a session-key
        // env var is present; if so, it WINS (the §C flip). If no
        // session-key resolves either, fall through to honor the pin
        // (preserves the bare-pin path).
        if resolve_session_key().is_some() {
            // Session-key chain takes over. Clear WIRE_HOME from env so
            // downstream resolution writes the session-key by-key home
            // instead of layering on top of the stale pin.
            //
            // SAFETY: caller contract is "before any thread spawn." All
            // production sites (cli::run, mcp::run) call this fn as the
            // first step in their respective entry points.
            unsafe {
                std::env::remove_var("WIRE_HOME");
            }
            // Audible warning to stderr (gated on interactive TTY +
            // WIRE_VERBOSE, matching the existing autosession line below).
            // Suppress with WIRE_QUIET_AUTOSESSION=1 (same gate as the
            // autosession chatter).
            use std::io::IsTerminal;
            let quiet = std::env::var("WIRE_QUIET_AUTOSESSION").is_ok();
            let verbose = std::env::var("WIRE_VERBOSE").is_ok();
            let interactive = std::io::stderr().is_terminal();
            if !quiet && (interactive || verbose) {
                eprintln!(
                    "wire {label}: WIRE_HOME ({pin}) is legacy-shape and a session-key env var is present — the session-key resolution chain wins (RFC-008 §C precedence flip). Set WIRE_HOME_FORCE=1 to opt back into legacy ordering. See RFC-008 / #210."
                );
            }
            // Fall through to the session-key resolution block below; it
            // will set SESSION_SOURCE to its own adapter label via the
            // existing `let _ = SESSION_SOURCE.set(source);` call.
        } else {
            // No session-key. Fall back to honoring the pin (legacy shape
            // but only signal present). Same as pre-§C behavior for this
            // case.
            let _ = SESSION_SOURCE.set("env:WIRE_HOME");
            return;
        }
    }
    // v0.13: prefer the host-agnostic session key (WIRE_SESSION_ID >
    // CLAUDE_CODE_SESSION_ID). Each session gets its own WIRE_HOME under
    // `by-key/<hash>` — no cwd lookup, no shared default, no Windows path
    // collapse. Falls back to legacy cwd-detect only when no session key is
    // present (bare CLI / pre-v0.13 hosts).
    let (home, why) = if let Some((key, source)) = resolve_session_key() {
        match session_home_for_key(&key) {
            Ok(h) => {
                // v0.13.2 (E8): do NOT create the home here. Creating it
                // unconditionally on every resolution — before any identity
                // exists — left a permanent empty home for every transient /
                // probe session key that never `wire up`d, accumulating
                // forever and surfacing as phantom "?" sisters in list-local.
                // The home is created lazily by `ensure_dirs` on the first
                // real write (init / claim / send), so an uninitialized
                // session leaves no trace on disk. (Write paths already
                // tolerate a non-existent WIRE_HOME — the test harness runs
                // every test against one.)
                let _ = SESSION_SOURCE.set(source);
                (h, format!("session key ({source})"))
            }
            Err(_) => return,
        }
    } else if label == "mcp" {
        // v0.13.4 (operator directive: per-session ONLY, never cwd). The MCP
        // server must NEVER cwd-resolve — that fallback is what collapsed every
        // Claude session sharing a launch dir (`~/Source`, `C:\Users\<user>`)
        // onto a single persona. A stdio MCP server is one process per Claude
        // session, so when no session id reached us (the
        // `${CLAUDE_CODE_SESSION_ID}` env-forward is missing or didn't expand)
        // we MINT a per-process key: distinct per session, never a shared cwd
        // identity. With the env-forward in place this branch isn't reached —
        // the session id resolves above.
        let minted = format!(
            "mcp-proc-{:016x}{:016x}",
            rand::random::<u64>(),
            rand::random::<u64>()
        );
        match session_home_for_key(&minted) {
            Ok(h) => {
                // Pin it for the process so every later resolve is consistent.
                unsafe {
                    std::env::set_var("WIRE_SESSION_ID", &minted);
                }
                let _ = SESSION_SOURCE.set("minted");
                (
                    h,
                    "minted per-process key (no session id; cwd disabled for MCP)".to_string(),
                )
            }
            Err(_) => return,
        }
    } else {
        // CLI with no session id. Per the per-session-only directive we do NOT
        // cwd-resolve here either — cwd identity is the collision trap (agents
        // shell out to the CLI, and any cwd-derived identity risks the wrong /
        // shared persona). Under Claude Code the CLI always carries
        // CLAUDE_CODE_SESSION_ID (resolved above), so this only hits a bare
        // terminal outside an agent host — which gets the stable machine-default
        // identity (set WIRE_SESSION_ID / WIRE_HOME for an explicit one). No cwd.
        let _ = SESSION_SOURCE.set("machine-default");
        return;
    };
    // v0.9.1: emit the chatter ONLY when stderr is an interactive TTY.
    // When wire is invoked from a non-interactive parent (Claude Code's
    // Bash tool, scripts, daemons), the auto-detect line is captured
    // alongside command output and pollutes both — wasting agent
    // context tokens and breaking JSON parsers that read combined
    // streams. WIRE_VERBOSE=1 forces the line on.
    use std::io::IsTerminal;
    let verbose_env = std::env::var("WIRE_VERBOSE").is_ok();
    let interactive = std::io::stderr().is_terminal();
    if interactive || verbose_env {
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
    fn valid_session_key_rejects_empty_and_unexpanded_placeholder() {
        assert!(valid_session_key("4129275d-cc5c-4d2a"));
        assert!(valid_session_key("mcp-proc-deadbeef"));
        assert!(!valid_session_key(""));
        assert!(!valid_session_key("   "));
        // The load-bearing guard: an unexpanded MCP-config placeholder must NOT
        // be hashed — that's the all-sessions-collapse (soft-spruce) bug.
        assert!(!valid_session_key("${CLAUDE_CODE_SESSION_ID}"));
        assert!(!valid_session_key("  ${CLAUDE_CODE_SESSION_ID}  "));
    }

    #[test]
    fn resolve_session_key_vscode_adapter_and_placeholder_guard() {
        // Per-adapter test for the VS Code / GitHub Copilot path added in #59.
        // Holds two invariants the integration depends on:
        //
        //   (a) When VSCODE_GIT_REPOSITORY_ROOT is set to a real workspace
        //       path, that key wins resolution and two distinct workspace
        //       paths produce two distinct session homes — proves the
        //       per-workspace-identity contract documented in
        //       docs/integrations/GITHUB_COPILOT.md.
        //
        //   (b) When the env entry is the unexpanded literal "${workspaceFolder}"
        //       (host failed to substitute), the ${} guard rejects it and the
        //       fn falls through — proves the safe-degradation property
        //       (no-identity, NOT cross-workspace collision).
        //
        // Mirrors the WIRE_SESSION_ID / CLAUDE_CODE_SESSION_ID semantics so any
        // future adapter added to the env-check loop inherits the same gates.
        let _guard = crate::config::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        // Snapshot + clear every env var resolve_session_key consults so this
        // test is hermetic regardless of the harness environment.
        let prev_override = std::env::var_os("WIRE_SESSION_ID");
        let prev_claude = std::env::var_os("CLAUDE_CODE_SESSION_ID");
        let prev_codex = std::env::var_os("CODEX_SESSION_ID");
        let prev_copilot = std::env::var_os("COPILOT_AGENT_SESSION_ID");
        let prev_vscode = std::env::var_os("VSCODE_GIT_REPOSITORY_ROOT");
        // SAFETY: ENV_LOCK is held, serializing all env access.
        unsafe {
            std::env::remove_var("WIRE_SESSION_ID");
            std::env::remove_var("CLAUDE_CODE_SESSION_ID");
            std::env::remove_var("CODEX_SESSION_ID");
            std::env::remove_var("COPILOT_AGENT_SESSION_ID");
            std::env::remove_var("VSCODE_GIT_REPOSITORY_ROOT");
        }

        // (a) Two distinct workspace paths -> two distinct, stable session homes.
        unsafe { std::env::set_var("VSCODE_GIT_REPOSITORY_ROOT", "/home/dev/frontend") };
        let r1 = resolve_session_key();
        assert!(
            matches!(&r1, Some((k, src)) if k == "/home/dev/frontend" && *src == "vscode-workspace"),
            "VSCODE_GIT_REPOSITORY_ROOT must win resolution and be labeled vscode-workspace; got {r1:?}"
        );
        let home_a = session_home_for_key(&r1.as_ref().unwrap().0).unwrap();

        unsafe { std::env::set_var("VSCODE_GIT_REPOSITORY_ROOT", "/home/dev/backend") };
        let r2 = resolve_session_key();
        let home_b = session_home_for_key(&r2.as_ref().unwrap().0).unwrap();
        assert_ne!(
            home_a, home_b,
            "distinct workspace roots must map to distinct session homes (no cross-workspace persona collision)"
        );

        // Same path again -> same home (resume stability).
        unsafe { std::env::set_var("VSCODE_GIT_REPOSITORY_ROOT", "/home/dev/frontend") };
        let home_a2 = session_home_for_key(&resolve_session_key().unwrap().0).unwrap();
        assert_eq!(
            home_a, home_a2,
            "same workspace root must yield the same home across calls"
        );

        // (b) Unexpanded ${workspaceFolder} literal MUST NOT be accepted.
        //     With every other adapter still cleared, resolution must fall
        //     through to None (or the claude pidfile path, which is absent in
        //     this test env) — never hash the literal.
        unsafe { std::env::set_var("VSCODE_GIT_REPOSITORY_ROOT", "${workspaceFolder}") };
        let r_guard = resolve_session_key();
        assert!(
            !matches!(&r_guard, Some((k, _)) if k.contains("${")),
            "unexpanded ${{workspaceFolder}} literal must be rejected by the ${{}} guard; got {r_guard:?}"
        );
        // Same guard for the other adapter slots.
        unsafe {
            std::env::remove_var("VSCODE_GIT_REPOSITORY_ROOT");
            std::env::set_var("WIRE_SESSION_ID", "${workspaceFolder}");
        }
        let r_guard2 = resolve_session_key();
        assert!(
            !matches!(&r_guard2, Some((k, _)) if k.contains("${")),
            "unexpanded ${{workspaceFolder}} in WIRE_SESSION_ID must also be rejected; got {r_guard2:?}"
        );

        // Restore any env we displaced.
        // SAFETY: ENV_LOCK still held.
        unsafe {
            std::env::remove_var("WIRE_SESSION_ID");
            std::env::remove_var("CLAUDE_CODE_SESSION_ID");
            std::env::remove_var("CODEX_SESSION_ID");
            std::env::remove_var("COPILOT_AGENT_SESSION_ID");
            std::env::remove_var("VSCODE_GIT_REPOSITORY_ROOT");
            if let Some(v) = prev_override {
                std::env::set_var("WIRE_SESSION_ID", v);
            }
            if let Some(v) = prev_claude {
                std::env::set_var("CLAUDE_CODE_SESSION_ID", v);
            }
            if let Some(v) = prev_codex {
                std::env::set_var("CODEX_SESSION_ID", v);
            }
            if let Some(v) = prev_copilot {
                std::env::set_var("COPILOT_AGENT_SESSION_ID", v);
            }
            if let Some(v) = prev_vscode {
                std::env::set_var("VSCODE_GIT_REPOSITORY_ROOT", v);
            }
        }
    }

    #[test]
    fn resolve_session_key_copilot_cli_adapter_and_priority() {
        // Per-adapter test for the GitHub Copilot CLI path (Phase 2 of #59):
        // resolve_session_key reads COPILOT_AGENT_SESSION_ID (set by the
        // `gh copilot` / `copilot` CLI host on every session) as a TARGETED
        // env adapter — exactly like CLAUDE_CODE_SESSION_ID. Holds three
        // invariants:
        //
        //   (a) Set to a real id -> that key wins resolution and two distinct
        //       conversations map to two distinct session homes (per-
        //       conversation identity contract).
        //   (b) WIRE_SESSION_ID overrides COPILOT_AGENT_SESSION_ID (priority
        //       1 trumps priority 3).
        //   (c) Unexpanded ${...} literal is rejected by the ${} guard —
        //       falls through to the None path, never hashed (mirrors the
        //       guard inherited from CLAUDE_CODE_SESSION_ID / WIRE_SESSION_ID
        //       / VSCODE_GIT_REPOSITORY_ROOT).
        let _guard = crate::config::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        // Snapshot every env var resolve_session_key consults so the test is
        // hermetic regardless of harness environment (this test literally
        // runs under Copilot CLI, where COPILOT_AGENT_SESSION_ID is set).
        let prev_override = std::env::var_os("WIRE_SESSION_ID");
        let prev_claude = std::env::var_os("CLAUDE_CODE_SESSION_ID");
        let prev_codex = std::env::var_os("CODEX_SESSION_ID");
        let prev_copilot = std::env::var_os("COPILOT_AGENT_SESSION_ID");
        let prev_vscode = std::env::var_os("VSCODE_GIT_REPOSITORY_ROOT");
        // SAFETY: ENV_LOCK is held, serializing all env access.
        unsafe {
            std::env::remove_var("WIRE_SESSION_ID");
            std::env::remove_var("CLAUDE_CODE_SESSION_ID");
            std::env::remove_var("CODEX_SESSION_ID");
            std::env::remove_var("COPILOT_AGENT_SESSION_ID");
            std::env::remove_var("VSCODE_GIT_REPOSITORY_ROOT");
        }

        // (a) COPILOT_AGENT_SESSION_ID set -> wins resolution; distinct ids
        //     map to distinct session homes.
        unsafe {
            std::env::set_var(
                "COPILOT_AGENT_SESSION_ID",
                "3869478a-33cc-4c33-82ee-b6403a24d734",
            )
        };
        let r1 = resolve_session_key();
        assert!(
            matches!(&r1, Some((k, src)) if k == "3869478a-33cc-4c33-82ee-b6403a24d734" && *src == "copilot-cli"),
            "COPILOT_AGENT_SESSION_ID must win resolution and be labeled copilot-cli; got {r1:?}"
        );
        let home_a = session_home_for_key(&r1.as_ref().unwrap().0).unwrap();

        unsafe {
            std::env::set_var(
                "COPILOT_AGENT_SESSION_ID",
                "deadbeef-0000-0000-0000-000000000000",
            )
        };
        let r2 = resolve_session_key();
        let home_b = session_home_for_key(&r2.as_ref().unwrap().0).unwrap();
        assert_ne!(
            home_a, home_b,
            "distinct Copilot CLI session ids must map to distinct session homes"
        );

        // (b) WIRE_SESSION_ID at priority 1 overrides COPILOT_AGENT_SESSION_ID
        //     at priority 3. Operator's explicit universal override always wins.
        unsafe { std::env::set_var("WIRE_SESSION_ID", "operator-override") };
        let r_override = resolve_session_key();
        assert!(
            matches!(&r_override, Some((k, src)) if k == "operator-override" && *src == "override"),
            "WIRE_SESSION_ID must beat COPILOT_AGENT_SESSION_ID; got {r_override:?}"
        );
        unsafe { std::env::remove_var("WIRE_SESSION_ID") };

        // (c) Unexpanded ${...} literal is rejected by the ${} guard.
        //     `gh copilot` shouldn't ship literal placeholders in
        //     COPILOT_AGENT_SESSION_ID, but if some future config-forwarding
        //     path does, the guard must reject it (same as for the other
        //     adapters) so we never hash the literal and collapse sessions.
        unsafe { std::env::set_var("COPILOT_AGENT_SESSION_ID", "${SOME_PLACEHOLDER}") };
        let r_guard = resolve_session_key();
        assert!(
            !matches!(&r_guard, Some((k, _)) if k.contains("${")),
            "unexpanded ${{...}} in COPILOT_AGENT_SESSION_ID must be rejected by the ${{}} guard; got {r_guard:?}"
        );

        // Restore any env we displaced.
        // SAFETY: ENV_LOCK still held.
        unsafe {
            std::env::remove_var("WIRE_SESSION_ID");
            std::env::remove_var("CLAUDE_CODE_SESSION_ID");
            std::env::remove_var("CODEX_SESSION_ID");
            std::env::remove_var("COPILOT_AGENT_SESSION_ID");
            std::env::remove_var("VSCODE_GIT_REPOSITORY_ROOT");
            if let Some(v) = prev_override {
                std::env::set_var("WIRE_SESSION_ID", v);
            }
            if let Some(v) = prev_claude {
                std::env::set_var("CLAUDE_CODE_SESSION_ID", v);
            }
            if let Some(v) = prev_codex {
                std::env::set_var("CODEX_SESSION_ID", v);
            }
            if let Some(v) = prev_copilot {
                std::env::set_var("COPILOT_AGENT_SESSION_ID", v);
            }
            if let Some(v) = prev_vscode {
                std::env::set_var("VSCODE_GIT_REPOSITORY_ROOT", v);
            }
        }
    }

    #[test]
    fn resolve_session_key_codex_cli_adapter_and_priority() {
        // Per-adapter test for the OpenAI Codex CLI path (#__pr_codex__).
        // resolve_session_key reads CODEX_SESSION_ID as a TARGETED env adapter
        // — exactly like CLAUDE_CODE_SESSION_ID and COPILOT_AGENT_SESSION_ID.
        // Until Codex itself forwards the thread id to MCP child env, operators
        // wire it via `[mcp_servers.<name>.env]` in `~/.codex/config.toml`;
        // landing the adapter now means once Codex ships the env it works
        // with zero further code change. Holds three invariants:
        //
        //   (a) Set to a real thread id -> that key wins resolution and two
        //       distinct threads map to two distinct session homes
        //       (per-thread identity contract).
        //   (b) WIRE_SESSION_ID overrides CODEX_SESSION_ID (priority 1
        //       trumps priority 3); CLAUDE_CODE_SESSION_ID also outranks
        //       CODEX_SESSION_ID (priority 2 trumps priority 3) — the
        //       Codex adapter slots between Claude Code and Copilot.
        //   (c) Unexpanded ${...} literal is rejected by the ${} guard,
        //       falling through rather than collapsing all sessions
        //       (mirrors the guard inherited from every other adapter).
        let _guard = crate::config::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        // Snapshot every env var resolve_session_key consults so the test is
        // hermetic regardless of harness environment.
        let prev_override = std::env::var_os("WIRE_SESSION_ID");
        let prev_claude = std::env::var_os("CLAUDE_CODE_SESSION_ID");
        let prev_codex = std::env::var_os("CODEX_SESSION_ID");
        let prev_copilot = std::env::var_os("COPILOT_AGENT_SESSION_ID");
        let prev_vscode = std::env::var_os("VSCODE_GIT_REPOSITORY_ROOT");
        // SAFETY: ENV_LOCK is held, serializing all env access.
        unsafe {
            std::env::remove_var("WIRE_SESSION_ID");
            std::env::remove_var("CLAUDE_CODE_SESSION_ID");
            std::env::remove_var("CODEX_SESSION_ID");
            std::env::remove_var("COPILOT_AGENT_SESSION_ID");
            std::env::remove_var("VSCODE_GIT_REPOSITORY_ROOT");
        }

        // (a) CODEX_SESSION_ID set -> wins resolution over the no-id baseline;
        //     distinct thread ids map to distinct session homes.
        unsafe { std::env::set_var("CODEX_SESSION_ID", "019e66ad-277e-7be3-bdd9-b7708e069f3b") };
        let r1 = resolve_session_key();
        assert!(
            matches!(&r1, Some((k, src)) if k == "019e66ad-277e-7be3-bdd9-b7708e069f3b" && *src == "codex-cli"),
            "CODEX_SESSION_ID must win resolution and be labeled codex-cli; got {r1:?}"
        );
        let home_a = session_home_for_key(&r1.as_ref().unwrap().0).unwrap();

        unsafe { std::env::set_var("CODEX_SESSION_ID", "019e66b6-14de-7142-b43a-1861fe59e945") };
        let r2 = resolve_session_key();
        let home_b = session_home_for_key(&r2.as_ref().unwrap().0).unwrap();
        assert_ne!(
            home_a, home_b,
            "distinct Codex thread ids must map to distinct session homes"
        );

        // Same id again -> same home (resume stability — same thread reconnects
        // to the same persona).
        unsafe { std::env::set_var("CODEX_SESSION_ID", "019e66ad-277e-7be3-bdd9-b7708e069f3b") };
        let home_a2 = session_home_for_key(&resolve_session_key().unwrap().0).unwrap();
        assert_eq!(
            home_a, home_a2,
            "same Codex thread id must yield the same home across calls"
        );

        // (b) WIRE_SESSION_ID at priority 1 overrides CODEX_SESSION_ID at
        //     priority 3 (operator explicit override always wins).
        unsafe { std::env::set_var("WIRE_SESSION_ID", "operator-override") };
        let r_override = resolve_session_key();
        assert!(
            matches!(&r_override, Some((k, src)) if k == "operator-override" && *src == "override"),
            "WIRE_SESSION_ID must beat CODEX_SESSION_ID; got {r_override:?}"
        );
        unsafe { std::env::remove_var("WIRE_SESSION_ID") };

        // CLAUDE_CODE_SESSION_ID at priority 2 also beats CODEX_SESSION_ID at
        // priority 3. (Earlier adapters get to claim the host they were
        // designed for; Codex slots in after Claude Code.)
        unsafe { std::env::set_var("CLAUDE_CODE_SESSION_ID", "claude-wins-over-codex") };
        let r_claude_wins = resolve_session_key();
        assert!(
            matches!(&r_claude_wins, Some((k, src)) if k == "claude-wins-over-codex" && *src == "claude-code"),
            "CLAUDE_CODE_SESSION_ID must beat CODEX_SESSION_ID; got {r_claude_wins:?}"
        );
        unsafe { std::env::remove_var("CLAUDE_CODE_SESSION_ID") };

        // (c) Unexpanded ${...} literal is rejected by the ${} guard.
        //     If a host's config-forwarding ever ships a literal placeholder,
        //     the guard rejects it (same as for every other adapter) so we
        //     never hash the literal and collapse sessions.
        unsafe { std::env::set_var("CODEX_SESSION_ID", "${SOME_PLACEHOLDER}") };
        let r_guard = resolve_session_key();
        assert!(
            !matches!(&r_guard, Some((k, _)) if k.contains("${")),
            "unexpanded ${{...}} in CODEX_SESSION_ID must be rejected by the ${{}} guard; got {r_guard:?}"
        );

        // Restore any env we displaced.
        // SAFETY: ENV_LOCK still held.
        unsafe {
            std::env::remove_var("WIRE_SESSION_ID");
            std::env::remove_var("CLAUDE_CODE_SESSION_ID");
            std::env::remove_var("CODEX_SESSION_ID");
            std::env::remove_var("COPILOT_AGENT_SESSION_ID");
            std::env::remove_var("VSCODE_GIT_REPOSITORY_ROOT");
            if let Some(v) = prev_override {
                std::env::set_var("WIRE_SESSION_ID", v);
            }
            if let Some(v) = prev_claude {
                std::env::set_var("CLAUDE_CODE_SESSION_ID", v);
            }
            if let Some(v) = prev_codex {
                std::env::set_var("CODEX_SESSION_ID", v);
            }
            if let Some(v) = prev_copilot {
                std::env::set_var("COPILOT_AGENT_SESSION_ID", v);
            }
            if let Some(v) = prev_vscode {
                std::env::set_var("VSCODE_GIT_REPOSITORY_ROOT", v);
            }
        }
    }

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
    fn find_session_home_by_name_resolves_both_layouts() {
        // #44 / #170 follow-up: v0.6 top-level sessions (dir name ==
        // operator-typed name) and v0.13 by-key sessions (dir name is
        // a hash, operator types the persona handle from the card)
        // must BOTH resolve via `find_session_home_by_name`. Pre-fix
        // (`session_dir(name)` only) the v0.13 by-key case bailed
        // with "session not found" even though `wire session list`
        // showed it.
        let _guard = crate::config::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let tmp = std::env::temp_dir().join(format!("wire-find-{}", rand::random::<u32>()));
        let _ = std::fs::remove_dir_all(&tmp);
        let root = tmp.join("sessions");

        // Legacy v0.6 top-level: a dir named `legacy-pane` directly
        // under sessions_root.
        let legacy_home = root.join("legacy-pane");
        let legacy_cfg = legacy_home.join("config").join("wire");
        std::fs::create_dir_all(&legacy_cfg).unwrap();
        std::fs::write(
            legacy_cfg.join("agent-card.json"),
            r#"{"did":"did:wire:legacy-pane-aaaa1111","handle":"legacy-pane","verify_keys":{}}"#,
        )
        .unwrap();

        // v0.13 by-key: dir name is a hash, card's handle is `coral-weasel`.
        let bykey_home = root.join("by-key").join("3049827d92d4fbd5");
        let bykey_cfg = bykey_home.join("config").join("wire");
        std::fs::create_dir_all(&bykey_cfg).unwrap();
        std::fs::write(
            bykey_cfg.join("agent-card.json"),
            r#"{"did":"did:wire:coral-weasel-0616dc6c","handle":"coral-weasel","verify_keys":{}}"#,
        )
        .unwrap();

        // SAFETY: ENV_LOCK is held.
        unsafe { std::env::set_var("WIRE_HOME", &root) };

        // Legacy lookup: operator types the literal dir name.
        let legacy = super::find_session_home_by_name("legacy-pane").unwrap();
        assert_eq!(
            legacy.as_deref(),
            Some(legacy_home.as_path()),
            "v0.6 top-level layout: legacy-pane must resolve to its top-level dir"
        );

        // by-key lookup: operator types the persona handle, not the hash.
        let bykey = super::find_session_home_by_name("coral-weasel").unwrap();
        assert_eq!(
            bykey.as_deref(),
            Some(bykey_home.as_path()),
            "v0.13 by-key layout: coral-weasel must resolve to its by-key/<hash> dir"
        );

        // by-key lookup via the hash itself also works (some tooling
        // may pass the raw dir name).
        let by_hash = super::find_session_home_by_name("3049827d92d4fbd5").unwrap();
        assert_eq!(
            by_hash.as_deref(),
            Some(bykey_home.as_path()),
            "v0.13 by-key layout: hash dir name must also resolve"
        );

        // Negative: an unknown name returns None, not an error.
        let missing = super::find_session_home_by_name("never-existed").unwrap();
        assert_eq!(missing, None, "unknown session must return None");

        unsafe { std::env::remove_var("WIRE_HOME") };
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn pid_to_session_map_builds_from_session_pidfiles() {
        // #173 follow-up (#174 hotfix removed --session arg from
        // supervisor children): wire status orphan annotation now
        // maps pid → session via per-session pidfiles. Walk should
        // find each session whose `<home>/state/wire/daemon.pid`
        // contains a valid pid, and IGNORE sessions whose pidfile
        // is absent or unreadable.
        let _guard = crate::config::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let tmp = std::env::temp_dir().join(format!("wire-p2s-{}", rand::random::<u32>()));
        let _ = std::fs::remove_dir_all(&tmp);
        let root = tmp.join("sessions");
        // Three by-key sessions. Two have pidfiles, one doesn't.
        let mk_session = |key: &str, handle: &str| -> PathBuf {
            let home = root.join("by-key").join(key);
            let cfg = home.join("config").join("wire");
            std::fs::create_dir_all(&cfg).unwrap();
            std::fs::write(
                cfg.join("agent-card.json"),
                format!(
                    r#"{{"did":"did:wire:{handle}-6e301ab1","handle":"{handle}","verify_keys":{{}}}}"#
                ),
            )
            .unwrap();
            home
        };
        let h1 = mk_session("abc123def4567890", "alpha-aurora");
        let h2 = mk_session("def456abc7890123", "beta-blossom");
        let _h3 = mk_session("0000aaaabbbbcccc", "gamma-gorge");
        // h1 / h2 get JSON pidfiles; h3 gets none.
        let state1 = h1.join("state").join("wire");
        let state2 = h2.join("state").join("wire");
        std::fs::create_dir_all(&state1).unwrap();
        std::fs::create_dir_all(&state2).unwrap();
        std::fs::write(state1.join("daemon.pid"), r#"{"pid": 12345}"#).unwrap();
        std::fs::write(state2.join("daemon.pid"), r#"{"pid": 67890}"#).unwrap();

        // SAFETY: ENV_LOCK is held, serializing all env access.
        unsafe { std::env::set_var("WIRE_HOME", &h1) };
        let map = super::pid_to_session_map();
        unsafe { std::env::remove_var("WIRE_HOME") };
        let _ = std::fs::remove_dir_all(&tmp);

        // h1 / h2 present, h3 absent. SessionInfo.name is the handle
        // derived from the card when the home is initialized
        // (list_sessions's mk helper overrides name = handle in that
        // case; by-key hash is only the fallback for uninitialized
        // homes). That's exactly the production label `wire status`
        // already prints for sessions.
        assert_eq!(
            map.get(&12345).map(String::as_str),
            Some("alpha-aurora"),
            "pid 12345 should map to the handle for h1"
        );
        assert_eq!(
            map.get(&67890).map(String::as_str),
            Some("beta-blossom"),
            "pid 67890 should map (JSON pidfile form, handle for h2)"
        );
        // Sanity: no entry for an unrelated pid.
        assert!(
            !map.contains_key(&99999),
            "synthetic missing pid should not appear in the map"
        );
    }

    #[test]
    fn session_home_for_key_is_deterministic_distinct_and_well_formed() {
        // session_home_for_key reads WIRE_HOME (via sessions_root); hold the
        // shared env lock so a parallel env-mutating test can't change it
        // between calls and make a1 != a2 (flaky race).
        let _guard = crate::config::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
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
    fn normalize_cwd_key_case_handling_matches_platform_filesystem() {
        // Issue #30 Willard repro: on Windows, two terminals in the "same"
        // project under different casings of the same path
        // (`C:\Foo\Bar` vs `C:\foo\bar`) hashed to DIFFERENT registry keys
        // pre-fix → the second terminal missed the registry lookup, fell
        // back to the legacy default identity, and both terminals collapsed
        // onto a shared DID. Fix: normalize the cwd key case-insensitively
        // on Windows, case-sensitively elsewhere (so distinct-on-disk paths
        // on case-sensitive filesystems remain distinct).
        let upper = Path::new("/Users/paul/Source/WIRE");
        let lower = Path::new("/Users/paul/Source/wire");
        if cfg!(windows) {
            assert_eq!(
                normalize_cwd_key(upper),
                normalize_cwd_key(lower),
                "on Windows, distinct casings of the same path MUST normalize \
                 to the same key (NTFS is case-insensitive by default)"
            );
        } else {
            assert_ne!(
                normalize_cwd_key(upper),
                normalize_cwd_key(lower),
                "on case-sensitive filesystems, distinct casings ARE distinct \
                 directories and MUST stay distinct keys"
            );
        }
        // Trivial sanity: same input always produces same output.
        assert_eq!(normalize_cwd_key(lower), normalize_cwd_key(lower));
    }

    #[test]
    fn derive_name_no_regression_exact_match_still_resolves() {
        // Cross-platform no-regression check for the v0.13.6 lookup
        // changes: an exact-match (same casing stored AND looked up)
        // entry MUST continue to resolve on the fast path — the new
        // O(n) normalized-scan fallback is only reached on the initial
        // .get miss.
        //
        // Honest scope (per coral-weasel's #67 review): this test does
        // NOT exercise the case-folding fallback on Linux/macOS — the
        // normalizer is a no-op there, so the first `.get` hits and
        // the scan never runs. The case-folding behavior is inherently
        // Windows-only; that path is covered by
        // derive_name_finds_registered_cwd_under_alternate_casing_on_windows
        // which executes on Windows CI.
        let mut reg = SessionRegistry::default();
        let stored = "/Users/Paul/Source/Wire-v0_13_5-Era";
        reg.by_cwd
            .insert(stored.to_string(), "wire-legacy".to_string());

        // Lookup under the EXACT stored path: must resolve on the
        // fast `.get` path regardless of platform.
        assert_eq!(
            derive_name_from_cwd(Path::new(stored), &reg),
            "wire-legacy",
            "exact-match v0.13.5 entry MUST still resolve under v0.13.6+"
        );
    }

    #[test]
    fn derive_name_scan_fallback_runs_when_initial_get_misses() {
        // Cross-platform proof that the O(n) normalized-scan fallback
        // engages on a .get miss. We can't trigger the *case-folding*
        // case on Linux/macOS (normalizer is a no-op), but we CAN
        // exercise the scan branch by storing under a key the
        // normalized lookup definitely won't hit, and verifying that
        // the .find()-based fallback resolves it.
        //
        // Setup: store under a key that's identical to the lookup
        // BUT with a trailing slash difference (so `.get` exact-match
        // misses, but our normalize_cwd_key — which preserves the
        // trailing slash — also misses; then we rely on the .find()
        // iterator). This is a contrived setup that proves the scan
        // branch is reachable; it does NOT test case-folding (Windows
        // only).
        //
        // A simpler way to exercise the same logic: store under one
        // path, look up under a different path that normalizes to the
        // SAME key. Without case-folding, the only way to do that is
        // to mutate normalize_cwd_key. Since we can't do that in a
        // test, this test instead pins the *no-false-positive* side:
        // a path with no matching stored entry must NOT resolve.
        let mut reg = SessionRegistry::default();
        reg.by_cwd.insert(
            "/Users/paul/Source/project-a".to_string(),
            "project-a".to_string(),
        );

        // Distinct path → no match → falls through to basename
        // derivation. Proves the scan doesn't fabricate matches.
        let derived = derive_name_from_cwd(Path::new("/Users/paul/Source/project-b"), &reg);
        assert_eq!(
            derived, "project-b",
            "non-matching lookup must fall through to basename derivation, \
             NOT fabricate a match via the scan"
        );
    }

    #[cfg(windows)]
    #[test]
    fn derive_name_finds_registered_cwd_under_alternate_casing_on_windows() {
        // Direct integration check for the Willard repro on Windows: an
        // existing registry entry written under one casing MUST resolve
        // when the lookup arrives under a different casing of the same
        // path.
        //
        // Trace through the v0.13.6 read-side O(n) normalized scan:
        //   - Stored key: "C:\Users\Willard\ComfyUI\claude-integration"
        //   - Lookup cwd: "c:\users\willard\comfyui\claude-integration"
        //   - cwd_key  = normalize(lookup) = "c:\users\..." (already lower)
        //   - .get(&cwd_key)  → MISS (stored has mixed casing)
        //   - .iter().find(normalize(stored) == cwd_key) → HIT
        //     (normalize("C:\Users\...") == "c:\users\..." == cwd_key)
        //   - Returns "claude-integration" ← the fix.
        //
        // Pre-fix this returned the basename → phantom hash-suffix → identity
        // collision (the original Willard report).
        let mut reg = SessionRegistry::default();
        reg.by_cwd.insert(
            r"C:\Users\Willard\ComfyUI\claude-integration".to_string(),
            "claude-integration".to_string(),
        );
        let from_lower_cwd = Path::new(r"c:\users\willard\comfyui\claude-integration");
        assert_eq!(
            derive_name_from_cwd(from_lower_cwd, &reg),
            "claude-integration",
            "Windows lookup MUST find the registered entry regardless of \
             how the shell capitalized the cwd, via the normalized scan"
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

    // ---------- identity-collision warning (issue #29/#30 — broaden to
    // every inbox-cursor-owning subcommand, not just `wire mcp`). ----------

    #[test]
    fn inbox_owning_subcommands_covers_each_runtime_role() {
        // Lock the role list down — any addition / removal here must
        // come with an updated call site (cli::cmd_daemon, cmd_monitor,
        // cmd_notify, mcp::run) and an updated rendezvous in the pgrep
        // predicate. The pgrep predicate is built from this list at
        // call time, so adding "watch" here automatically extends
        // detection — but the warning is only fired if a call site
        // also invokes warn_on_identity_collision with that role.
        assert!(INBOX_OWNING_SUBCOMMANDS.contains(&"mcp"));
        assert!(INBOX_OWNING_SUBCOMMANDS.contains(&"daemon"));
        assert!(INBOX_OWNING_SUBCOMMANDS.contains(&"monitor"));
        assert!(INBOX_OWNING_SUBCOMMANDS.contains(&"notify"));
        // pair-host (SAS code-phrase flow) was removed in RFC-005 follow-on
        // and must not appear in the list.
        assert!(!INBOX_OWNING_SUBCOMMANDS.contains(&"pair-host"));
    }

    #[test]
    fn find_colliders_returns_only_same_home_pids() {
        let our_home = "/tmp/wire-home-A";
        let others = vec![
            (101, Some("/tmp/wire-home-A".to_string())), // collide
            (102, Some("/tmp/wire-home-B".to_string())), // distinct home
            (103, None),                                 // env-unreadable, skip
            (104, Some("/tmp/wire-home-A".to_string())), // collide
        ];
        let colliders = find_colliders(our_home, &others);
        assert_eq!(colliders, vec![101, 104]);
    }

    #[test]
    fn find_colliders_no_match_returns_empty() {
        let our_home = "/tmp/wire-home-A";
        let others = vec![
            (101, Some("/tmp/wire-home-B".to_string())),
            (102, Some("/tmp/wire-home-C".to_string())),
            (103, None),
        ];
        assert!(find_colliders(our_home, &others).is_empty());
    }

    #[test]
    fn find_colliders_empty_input_is_empty() {
        assert!(find_colliders("/tmp/anywhere", &[]).is_empty());
    }

    #[test]
    fn find_colliders_ignores_substring_matches() {
        // `WIRE_HOME=/wire-A` must NOT collide with `WIRE_HOME=/wire-A/sub`.
        // Exact-match semantics protect against parent/child confusion.
        let our_home = "/tmp/wire-A";
        let others = vec![
            (201, Some("/tmp/wire-A/sub".to_string())),
            (202, Some("/wire-A".to_string())), // distinct path
            (203, Some("/tmp/wire-A".to_string())), // real collision
        ];
        assert_eq!(find_colliders(our_home, &others), vec![203]);
    }

    #[test]
    fn collision_warning_format_includes_role_home_and_pids() {
        // Sanity-check the first warning line by reconstructing it
        // exactly the way `emit_collision_warning` does. If anyone
        // changes the format, this test must change with it — that's
        // the point: the format is a documented operator-facing
        // surface (Willard's #30 cited the older wording verbatim
        // when filing the bug).
        let role = "daemon";
        let home = "/tmp/by-key/abc123";
        let colliders = vec![4242u32, 4243u32];
        let expected_head = format!(
            "wire {role}: WARNING — {n} other wire process(es) already using WIRE_HOME=`{home}` (pid {pids})",
            n = colliders.len(),
            pids = colliders
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        );
        assert_eq!(
            expected_head,
            "wire daemon: WARNING — 2 other wire process(es) already using WIRE_HOME=`/tmp/by-key/abc123` (pid 4242, 4243)"
        );
        // Exercise the renderer so it can't bit-rot via dead-code
        // pruning. Output goes to stderr; under libtest it's captured.
        emit_collision_warning(role, home, &colliders);
    }

    /// RFC-008 §C — `is_by_key_shape` must distinguish modern operator-
    /// explicit `sessions/by-key/<16-hex>` pins from every other path
    /// shape (legacy cwd-derived `sessions/<name>/config/wire`, foreign
    /// paths, malformed by-key dirs). Fast — used at every wire startup
    /// when WIRE_HOME is set — so this asserts cross-platform path-sep
    /// handling without allocating.
    #[test]
    fn is_by_key_shape_recognizes_modern_pin() {
        // Linux/macOS modern shape.
        assert!(is_by_key_shape(
            "/home/dev/.local/state/wire/sessions/by-key/0c38ce498aa9d955"
        ));
        // Windows modern shape (escaped backslashes).
        assert!(is_by_key_shape(
            "C:\\Users\\Willard\\AppData\\Local\\wire\\sessions\\by-key\\0c38ce498aa9d955"
        ));
        // With trailing path segments (e.g. /config/wire suffix).
        assert!(is_by_key_shape(
            "/home/dev/.local/state/wire/sessions/by-key/abcdef0123456789/config/wire"
        ));
        assert!(is_by_key_shape(
            "C:\\wire\\sessions\\by-key\\abcdef0123456789\\config\\wire"
        ));
    }

    #[test]
    fn is_by_key_shape_rejects_legacy_and_malformed() {
        // Legacy cwd-derived shape (the #210 case).
        assert!(!is_by_key_shape(
            "C:\\Users\\Willard\\AppData\\Local\\wire\\sessions\\willard\\config\\wire"
        ));
        assert!(!is_by_key_shape(
            "/home/dev/.local/state/wire/sessions/projx/config/wire"
        ));
        // Foreign path, no `by-key/` at all.
        assert!(!is_by_key_shape("/tmp/some-fleet-shared-dir"));
        // by-key with wrong hash length (8 hex — too short).
        assert!(!is_by_key_shape("/wire/sessions/by-key/abcdef01"));
        // by-key with non-hex chars in hash.
        assert!(!is_by_key_shape("/wire/sessions/by-key/not-a-hex-hash"));
        // by-key with uppercase hex (wire writes lowercase only).
        assert!(!is_by_key_shape("/wire/sessions/by-key/0C38CE498AA9D955"));
        // by-key with hash too long (32 hex).
        assert!(!is_by_key_shape(
            "/wire/sessions/by-key/0c38ce498aa9d9550c38ce498aa9d955"
        ));
        // Empty path.
        assert!(!is_by_key_shape(""));
    }

    /// RFC-008 §C — verify a path containing `by-key` as a partial
    /// substring (NOT as a path segment) is correctly rejected. Catches a
    /// regex-style regression where the matcher splits on the wrong
    /// delimiter.
    #[test]
    fn is_by_key_shape_substring_not_segment_rejected() {
        // `by-key` appears, but NOT as a path segment — should reject.
        assert!(!is_by_key_shape(
            "/wire/sessions/foo-by-key-bar/0c38ce498aa9d955"
        ));
        // by-key/ but no hash after (just the bare dir).
        assert!(!is_by_key_shape("/wire/sessions/by-key/"));
        assert!(!is_by_key_shape("/wire/sessions/by-key"));
    }
}
