//! On-disk state for `wire`.
//!
//! Layout:
//!   `$XDG_CONFIG_HOME/wire/` (defaults to `~/.config/wire/`)
//!     - `private.key`     — 32-byte raw Ed25519 seed (mode 0600)
//!     - `agent-card.json` — signed self-card (mode 0644, public)
//!     - `trust.json`      — pinned peers + tiers
//!     - `config.toml`     — relay URL, body cap, etc. (created lazily)
//!
//!   `$XDG_STATE_HOME/wire/` (defaults to `~/.local/state/wire/`)
//!     - `inbox/<peer>.jsonl`  — verified inbound events
//!     - `outbox/<peer>.jsonl` — agent-appended outbound events (daemon flushes)
//!     - `spool/`              — daemon-internal staging
//!
//! All paths are configurable via `WIRE_HOME` env var (overrides both dirs to
//! `$WIRE_HOME/{config,state}/`). Used by the test harness to keep tests
//! isolated from the operator's real config.

use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Root configuration directory. Honors `WIRE_HOME` for testing.
///
/// With `WIRE_HOME=/tmp/foo`, returns `/tmp/foo/config/wire`.
/// Without it, returns the XDG default (e.g. `~/.config/wire/`).
pub fn config_dir() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("WIRE_HOME") {
        return Ok(PathBuf::from(home).join("config").join("wire"));
    }
    dirs::config_dir()
        .map(|d| d.join("wire"))
        .ok_or_else(|| anyhow!("could not resolve XDG_CONFIG_HOME — set WIRE_HOME"))
}

/// Root state directory (rotating data — inbox/outbox/spool).
///
/// With `WIRE_HOME=/tmp/foo`, returns `/tmp/foo/state/wire`.
pub fn state_dir() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("WIRE_HOME") {
        return Ok(PathBuf::from(home).join("state").join("wire"));
    }
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .map(|d| d.join("wire"))
        .ok_or_else(|| anyhow!("could not resolve XDG_STATE_HOME — set WIRE_HOME"))
}

pub fn private_key_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("private.key"))
}
pub fn agent_card_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("agent-card.json"))
}
pub fn trust_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("trust.json"))
}
pub fn config_toml_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}
pub fn inbox_dir() -> Result<PathBuf> {
    Ok(state_dir()?.join("inbox"))
}
pub fn outbox_dir() -> Result<PathBuf> {
    Ok(state_dir()?.join("outbox"))
}

/// Per-outbox-path mutex registry. Serializes intra-process appends so that
/// concurrent `wire_send` calls (e.g. multiple agents driving the same MCP
/// server) cannot interleave bytes mid-line. POSIX `O_APPEND` is atomic only
/// for writes ≤ PIPE_BUF (typically 4096 bytes); wire events can exceed that
/// (per-event cap is 256 KiB).
///
/// **Inter-process scope (CLI vs MCP-server vs daemon):** v0.1 does not take
/// an OS-level flock — the daemon only reads the outbox + a cursor file, and
/// concurrent CLI `wire send` invocations against a running MCP server are
/// rare enough we accept the risk for now. v0.2 BACKLOG: switch to
/// `fs2::FileExt::lock_exclusive` for cross-process safety.
static OUTBOX_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

fn outbox_lock(path: &Path) -> Arc<Mutex<()>> {
    let registry = OUTBOX_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = registry.lock().expect("OUTBOX_LOCKS poisoned");
    g.entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Append a single JSONL record to the outbox for `peer`, holding the
/// per-path mutex to keep concurrent appenders from interleaving lines.
///
/// `record_bytes` should be the full canonical JSON of the signed event,
/// without trailing newline (the helper appends it). All bytes are written
/// in one `write_all` while the lock is held.
///
/// The `peer` arg is normalized to its bare handle (`bob@relay.example` →
/// `bob`) so the outbox filename is always `<bare_handle>.jsonl`. This is
/// the canonical form the push enumerator and daemon reader expect; the
/// normalization at this chokepoint guarantees correctness for every
/// future caller, even if they forget to `bare_handle()` first. The
/// original silent-fail of v0.5.11 was a caller that passed the FQDN
/// form (issue #2 — 25-minute message-loss incident, surface fix in
/// v0.5.13). This defense-in-depth makes the on-disk contract self-
/// enforcing instead of caller-policed.
/// v0.14.2 (#162 fix #2): append a "pushed" record to the per-peer
/// lifecycle log when `run_sync_push` confirms a relay POST landed
/// (either as `ok` or as the idempotent `duplicate` — the relay has the
/// event either way). The log sits next to the outbox JSONL at
/// `<outbox_dir>/<peer>.pushed.jsonl` and carries one
/// `{"ts":"...","event_id":"..."}` line per push.
///
/// Readers (`tool_status`, `wire_status` CLI, `wire_tail` lifecycle
/// surface) join outbox events to this log by `event_id` to expose the
/// `queued → pushed` lifecycle that fix #2 surfaces.
///
/// NOT pruned in v0.14.2. The log grows monotonically; for high-volume
/// operators a v0.15+ pruner (entries older than `<config_dir>/lifecycle_retention_days`)
/// is tracked at the issue. Best-effort: errors log but don't abort
/// the daemon push loop — a wedged disk shouldn't kill sync.
pub fn append_pushed_log(peer: &str, event_id: &str, ts: &str) -> Result<PathBuf> {
    ensure_dirs()?;
    let normalized = crate::agent_card::bare_handle(peer);
    let path = outbox_dir()?.join(format!("{normalized}.pushed.jsonl"));
    let lock = outbox_lock(&path);
    let _g = lock.lock().expect("pushed-log per-path mutex poisoned");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening pushed-log {path:?}"))?;
    let line = serde_json::to_string(&serde_json::json!({
        "ts": ts,
        "event_id": event_id,
    }))?;
    f.write_all(line.as_bytes())
        .with_context(|| format!("appending to {path:?}"))?;
    f.write_all(b"\n")?;
    Ok(path)
}

/// Total queued-but-not-yet-pushed events across all peers. Walks
/// each per-peer outbox file, counts event_ids missing from the
/// per-peer pushed log. Cheap (one disk read per peer) and bounded by
/// `trust.agents`.
///
/// v0.14.2 (#162 fix #2): the diagnostic for the "silent send" class —
/// `pending_push_count > 0` + `stale_sync` = events queued, daemon not
/// pushing. Was originally inline in `tool_status`; extracted so the
/// CLI `wire status` surface and any future doctor/web check stay in
/// agreement by construction.
pub fn compute_pending_push_count() -> u64 {
    compute_pending_push_breakdown()
        .iter()
        .map(|p| p.count)
        .sum()
}

/// Per-peer breakdown of queued-but-not-pushed events. Populates
/// the new `daemon.pending_push_breakdown` field in `wire status`
/// and the human-readable expansion of the "pending push:" line.
///
/// Each entry carries the peer handle, the trust tier (so the
/// surface can say "stuck on orchid-savanna (PENDING_ACK — pair
/// never completed)"), and the unpushed event count.
///
/// **Why tier?** A peer at `PENDING_ACK` has events queued that
/// won't push until pair-accept completes (a #166-class wedge).
/// A peer at `VERIFIED` with events queued + `stale_sync` is the
/// #162 silent-send class. Operators need the tier to know which
/// path to fix.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingPushPerPeer {
    pub peer: String,
    pub tier: String,
    pub count: u64,
}

pub fn compute_pending_push_breakdown() -> Vec<PendingPushPerPeer> {
    let trust = match read_trust() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let agents = match trust.get("agents").and_then(serde_json::Value::as_object) {
        Some(a) => a.clone(),
        None => return Vec::new(),
    };
    // Read relay_state once so the effective-tier lookup doesn't
    // hammer the disk per peer. Missing file → empty peers map; the
    // effective_tier helper handles that case fine.
    let relay_state = read_relay_state().unwrap_or_else(|_| serde_json::json!({"peers": {}}));
    let mut out: Vec<PendingPushPerPeer> = Vec::new();
    for (peer_handle, _agent) in agents.iter() {
        let pushed_ids = read_pushed_event_ids(peer_handle);
        let outbox_path = match outbox_dir() {
            Ok(d) => d.join(format!("{peer_handle}.jsonl")),
            Err(_) => continue,
        };
        let body = match fs::read_to_string(&outbox_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mut count: u64 = 0;
        for line in body.lines() {
            if let Some(eid) = serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| {
                    v.get("event_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                })
                && !pushed_ids.contains(&eid)
            {
                count += 1;
            }
        }
        if count > 0 {
            // Use effective tier (relay_state-aware) — daemon
            // can't push to a peer with no slot_token even if
            // trust.json says VERIFIED, and the PENDING_ACK hint
            // is the actionable answer for that case.
            let tier = crate::trust::effective_tier(&trust, &relay_state, peer_handle);
            out.push(PendingPushPerPeer {
                peer: peer_handle.clone(),
                tier,
                count,
            });
        }
    }
    // Stable, deterministic order — largest backlog first, peer name
    // as tiebreak. JSON consumers + the human line both rely on it.
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.peer.cmp(&b.peer)));
    out
}

/// Read `$WIRE_HOME/state/wire/stream_state.json` written by the
/// daemon's SSE subscriber. `Value::Null` when the file is absent or
/// unreadable — callers should treat that as "stream subscriber
/// hasn't reported in yet" (cold start, or daemon predates #168).
pub fn read_stream_state() -> serde_json::Value {
    state_dir()
        .ok()
        .and_then(|d| fs::read_to_string(d.join("stream_state.json")).ok())
        .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
        .unwrap_or(serde_json::Value::Null)
}

/// True when no sync has happened within the freshness window. None
/// (= never synced here) is treated as stale. Shared between MCP +
/// CLI so the boolean flips at the same moment in both surfaces.
pub fn stale_sync(last_sync_age_seconds: Option<u64>) -> bool {
    match last_sync_age_seconds {
        Some(age) => age > 60,
        None => true,
    }
}

/// Read the set of event_ids already recorded as pushed for `peer`.
/// Cheap (single file read + parse); callers that need bulk lifecycle
/// data should read the file directly. Returns an empty set on
/// missing/unreadable file.
pub fn read_pushed_event_ids(peer: &str) -> std::collections::HashSet<String> {
    let normalized = crate::agent_card::bare_handle(peer);
    let path = match outbox_dir() {
        Ok(d) => d.join(format!("{normalized}.pushed.jsonl")),
        Err(_) => return std::collections::HashSet::new(),
    };
    let body = match fs::read_to_string(&path) {
        Ok(b) => b,
        Err(_) => return std::collections::HashSet::new(),
    };
    body.lines()
        .filter_map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()?
                .get("event_id")?
                .as_str()
                .map(str::to_string)
        })
        .collect()
}

pub fn append_outbox_record(peer: &str, record_bytes: &[u8]) -> Result<PathBuf> {
    ensure_dirs()?;
    let normalized = crate::agent_card::bare_handle(peer);
    let path = outbox_dir()?.join(format!("{normalized}.jsonl"));
    let lock = outbox_lock(&path);
    let _g = lock.lock().expect("outbox per-path mutex poisoned");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening outbox {path:?}"))?;
    let mut buf = Vec::with_capacity(record_bytes.len() + 1);
    buf.extend_from_slice(record_bytes);
    buf.push(b'\n');
    f.write_all(&buf)
        .with_context(|| format!("appending to {path:?}"))?;
    Ok(path)
}

/// Whether `wire init` has already been run (private key + card both present).
pub fn is_initialized() -> Result<bool> {
    Ok(private_key_path()?.exists() && agent_card_path()?.exists())
}

/// Create directory tree with restrictive permissions on the config dir.
pub fn ensure_dirs() -> Result<()> {
    let cfg = config_dir()?;
    fs::create_dir_all(&cfg).with_context(|| format!("creating {cfg:?}"))?;
    fs::create_dir_all(state_dir()?)?;
    fs::create_dir_all(inbox_dir()?)?;
    fs::create_dir_all(outbox_dir()?)?;
    set_dir_mode_0700(&cfg)?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode_0700(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_: &Path) -> Result<()> {
    Ok(())
}

/// Write a private key file with mode 0600.
pub fn write_private_key(seed: &[u8; 32]) -> Result<()> {
    let path = private_key_path()?;
    fs::write(&path, seed).with_context(|| format!("writing {path:?}"))?;
    set_file_mode_0600(&path)?;
    Ok(())
}

#[cfg(unix)]
fn set_file_mode_0600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode_0600(_: &Path) -> Result<()> {
    Ok(())
}

/// Read the saved private key seed (32 bytes).
pub fn read_private_key() -> Result<[u8; 32]> {
    let path = private_key_path()?;
    let bytes = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "private key file has wrong length ({} != 32)",
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

// ── RFC-001 operator / organization key storage ───────────────────────────
// Operator + org root private keys live alongside the session `private.key`,
// same 0600 raw-32-byte-seed convention. These anchor the offline identity
// layer's `op_did` / `org_did` (each DID commits to its key).

pub fn op_key_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("op.key"))
}

/// Sanitize a DID into a safe filename component (DIDs carry `:`).
fn did_filename(did: &str) -> String {
    did.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn org_key_path(org_did: &str) -> Result<PathBuf> {
    Ok(config_dir()?
        .join("orgs")
        .join(format!("{}.key", did_filename(org_did))))
}

fn write_seed_0600(path: &Path, seed: &[u8; 32]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, seed).with_context(|| format!("writing {path:?}"))?;
    set_file_mode_0600(path)?;
    Ok(())
}

fn read_seed(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("reading {path:?}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "key file {path:?} has wrong length ({} != 32)",
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

pub fn write_op_key(seed: &[u8; 32]) -> Result<()> {
    write_seed_0600(&op_key_path()?, seed)
}
pub fn read_op_key() -> Result<[u8; 32]> {
    read_seed(&op_key_path()?)
}
pub fn write_org_key(org_did: &str, seed: &[u8; 32]) -> Result<()> {
    write_seed_0600(&org_key_path(org_did)?, seed)
}
pub fn read_org_key(org_did: &str) -> Result<[u8; 32]> {
    read_seed(&org_key_path(org_did)?)
}

pub fn succession_log_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("succession.jsonl"))
}

/// Append a key-rotation succession record (RFC-001 §T19/§T20 audit trail).
/// Append-only JSONL at `config/wire/succession.jsonl`; one line per rotation
/// carrying the `old_did → new_did` handoff + the bridging cert.
pub fn append_succession_record(
    kind: &str,
    old_did: &str,
    new_did: &str,
    cert: &str,
) -> Result<()> {
    let path = succession_log_path()?;
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = serde_json::to_string(&serde_json::json!({
        "kind": kind,
        "old_did": old_did,
        "new_did": new_did,
        "cert": cert,
        "at_unix": at_unix,
    }))?;
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {path:?}"))?;
    writeln!(f, "{line}")?;
    set_file_mode_0600(&path)?;
    Ok(())
}

pub fn op_meta_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("op.json"))
}

/// Persist the operator handle chosen at `wire enroll op`. The op_did derives
/// from handle + op key; card-emit re-derives it at card-build time.
pub fn write_op_handle(handle: &str) -> Result<()> {
    let path = op_meta_path()?;
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({ "handle": handle }))?,
    )?;
    set_file_mode_0600(&path)?;
    Ok(())
}

pub fn read_op_handle() -> Result<Option<String>> {
    let Ok(bytes) = fs::read(op_meta_path()?) else {
        return Ok(None);
    };
    let v: Value = serde_json::from_slice(&bytes)?;
    Ok(v.get("handle").and_then(Value::as_str).map(str::to_string))
}

pub fn memberships_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("memberships.json"))
}

/// Append an org membership the operator holds (org_did / org_pubkey /
/// member_cert) for card-emit to attach. Replaces any existing entry for the
/// same org_did (re-issued certs supersede).
pub fn add_membership(org_did: &str, org_pubkey: &str, member_cert: &str) -> Result<()> {
    let mut list = read_memberships()?;
    list.retain(|m| m.get("org_did").and_then(Value::as_str) != Some(org_did));
    list.push(serde_json::json!({
        "org_did": org_did, "org_pubkey": org_pubkey, "member_cert": member_cert
    }));
    let path = memberships_path()?;
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(&path, serde_json::to_vec_pretty(&Value::Array(list))?)?;
    Ok(())
}

/// Read the operator's stored org memberships (empty if none/malformed).
pub fn read_memberships() -> Result<Vec<Value>> {
    let Ok(bytes) = fs::read(memberships_path()?) else {
        return Ok(vec![]);
    };
    Ok(serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default())
}

pub fn write_agent_card(card: &Value) -> Result<()> {
    let path = agent_card_path()?;
    let body = serde_json::to_vec_pretty(card)?;
    // v0.7.0-alpha.8 (review-fix #7): atomic write via tmp+rename so
    // a power-loss / SIGKILL mid-write doesn't leave a 0-byte agent-
    // card that `is_initialized()` claims is fine but `read_agent_card`
    // can't parse. `cmd_identity_rename` made this a hot path; the
    // pre-existing fs::write pattern was a corruption risk every call.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, body).with_context(|| format!("writing tmp {tmp:?}"))?;
    fs::rename(&tmp, &path).with_context(|| format!("atomic rename {tmp:?} → {path:?}"))?;
    Ok(())
}

pub fn read_agent_card() -> Result<Value> {
    let path = agent_card_path()?;
    let body = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
    Ok(serde_json::from_slice(&body)?)
}

// ---------- display overrides (v0.7.0-alpha.3) ----------

/// Path to `display.json` — operator-chosen character nickname + emoji
/// override. Sidecar to agent-card. NOT signed (display-only, local-only).
///
/// Format: `{"nickname": "foxtrot-meadow", "emoji": "🦊"}` — both fields
/// optional, omitted means use the auto-derived value.
pub fn display_overrides_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("display.json"))
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DisplayOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emoji: Option<String>,
}

pub fn read_display_overrides() -> Result<DisplayOverrides> {
    read_display_overrides_at(&display_overrides_path()?)
}

pub fn read_display_overrides_at(path: &Path) -> Result<DisplayOverrides> {
    if !path.exists() {
        return Ok(DisplayOverrides::default());
    }
    let body = fs::read(path).with_context(|| format!("reading {path:?}"))?;
    Ok(serde_json::from_slice(&body)?)
}

pub fn write_display_overrides(overrides: &DisplayOverrides) -> Result<()> {
    let path = display_overrides_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
    }
    let body = serde_json::to_vec_pretty(overrides)?;
    // v0.7.0-alpha.8 (review-fix #7): atomic write — consistent with
    // write_agent_card now that they share the cmd_identity_rename
    // call path.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, body).with_context(|| format!("writing tmp {tmp:?}"))?;
    fs::rename(&tmp, &path).with_context(|| format!("atomic rename {tmp:?} → {path:?}"))?;
    Ok(())
}

pub fn write_trust(trust: &Value) -> Result<()> {
    let path = trust_path()?;
    let body = serde_json::to_vec_pretty(trust)?;
    fs::write(&path, body).with_context(|| format!("writing {path:?}"))?;
    Ok(())
}

pub fn read_trust() -> Result<Value> {
    let path = trust_path()?;
    if !path.exists() {
        return Ok(crate::trust::empty_trust());
    }
    let body = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
    Ok(serde_json::from_slice(&body)?)
}

// ---------- relay binding state ----------

/// Path to `relay.json` — holds our own slot binding and pinned peer slots.
/// Contains slot-tokens, so always written mode 0600.
pub fn relay_state_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("relay.json"))
}

pub fn read_relay_state() -> Result<Value> {
    let path = relay_state_path()?;
    if !path.exists() {
        return Ok(serde_json::json!({"self": Value::Null, "peers": {}}));
    }
    let body = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
    Ok(serde_json::from_slice(&body)?)
}

/// Atomic, lock-serialized write of the full relay-state. Every direct caller
/// (foreground `wire dial`, the background daemon, MCP) funnels through here,
/// so a foreground write can neither TEAR nor lost-update against the daemon.
/// Holds the same `relay.lock` flock as [`update_relay_state`] and writes via
/// tmp+rename.
///
/// Bug #3 (v0.13.2): the old raw `fs::write` here was non-atomic and lockless.
/// A foreground `wire dial` and the daemon both rewrote `relay.json`
/// concurrently, interleaving bytes and leaving trailing garbage ("trailing
/// characters at line N") that made the file unparseable — breaking all
/// push/pull until hand-repaired. Surfaced on Windows (file-sharing
/// semantics make the interleave easy to hit) but the race was cross-platform.
pub fn write_relay_state(state: &Value) -> Result<()> {
    use fs2::FileExt;
    let lock_path = relay_state_lock_path()?;
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
    }
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening {lock_path:?}"))?;
    lock_file
        .lock_exclusive()
        .with_context(|| format!("flock {lock_path:?}"))?;
    let r = write_relay_state_unlocked(state);
    let _ = fs2::FileExt::unlock(&lock_file);
    r
}

/// Atomic relay-state write WITHOUT taking `relay.lock` — the caller must
/// already hold it (only [`update_relay_state`], which writes inside its own
/// locked transaction). tmp+rename so a concurrent reader sees either the old
/// or new whole file, never a partial one.
fn write_relay_state_unlocked(state: &Value) -> Result<()> {
    let path = relay_state_path()?;
    let body = serde_json::to_vec_pretty(state)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &body).with_context(|| format!("writing tmp {tmp:?}"))?;
    set_file_mode_0600(&tmp)?;
    fs::rename(&tmp, &path).with_context(|| format!("atomic rename {tmp:?} → {path:?}"))?;
    Ok(())
}

/// Path to the flock file that serialises concurrent read-modify-write
/// transactions against `relay.json`. Separate file because flock on the
/// data file itself races with file replacement (fs::write truncates +
/// rewrites — atomic-ish but the lock identity disappears).
fn relay_state_lock_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("relay.lock"))
}

/// Atomic read-modify-write against `relay.json`. Holds an exclusive
/// `fs2::FileExt::lock_exclusive` for the whole transaction so concurrent
/// `wire` processes (multiple daemons, CLI vs daemon, CLI vs MCP) cannot
/// race the cursor or peer-pin entries.
///
/// P0.3 (0.5.11). Today's debug had three concurrent `wire` processes
/// (stale 0.2.4 daemon, fresh 0.5.10 daemon, and the CLI) racing the
/// `self.last_pulled_event_id` cursor — one would advance it past an
/// event, another would later rewind via stale snapshot. flock makes
/// that impossible.
///
/// Lock timeout: blocks indefinitely (well-behaved processes release in
/// < 1ms). Use sparingly outside short RMW windows — long holds will
/// stall every other `wire` process.
pub fn update_relay_state<F>(modifier: F) -> Result<()>
where
    F: FnOnce(&mut Value) -> Result<()>,
{
    use fs2::FileExt;
    let lock_path = relay_state_lock_path()?;
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
    }
    // Open / create the lock file. Holding a handle keeps the file
    // alive for the lifetime of the transaction.
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening {lock_path:?}"))?;
    lock_file
        .lock_exclusive()
        .with_context(|| format!("flock {lock_path:?}"))?;

    // Read fresh state INSIDE the lock — any prior snapshot would be a
    // race window. Then run the modifier. Then write atomically.
    let mut state = read_relay_state()?;
    let result = modifier(&mut state);
    let write_result = if result.is_ok() {
        // We already hold relay.lock — use the unlocked writer to avoid
        // re-acquiring the same flock (which would deadlock).
        write_relay_state_unlocked(&state)
    } else {
        Ok(())
    };
    // RAII: drop releases the lock. Explicit unlock for clarity + to
    // ensure unlock happens even if Drop ordering ever changes.
    let _ = fs2::FileExt::unlock(&lock_file);
    result?;
    write_result?;
    Ok(())
}

/// Test-only helpers. Lives outside `tests` mod so other modules' tests
/// can share the same WIRE_HOME isolation. Tests run in-process and share
/// process-wide env state, so all WIRE_HOME mutators must use this lock or
/// they race each other.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    pub static ENV_LOCK: Mutex<()> = Mutex::new(());

    pub fn with_temp_home<F: FnOnce()>(f: F) {
        // Recover from poison so one failing test doesn't cascade-fail the rest.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = std::env::temp_dir().join(format!("wire-test-{}", rand::random::<u32>()));
        // SAFETY: ENV_LOCK serializes all callers, so no concurrent env access.
        unsafe { std::env::set_var("WIRE_HOME", &tmp) };
        let _ = std::fs::remove_dir_all(&tmp);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        unsafe { std::env::remove_var("WIRE_HOME") };
        let _ = std::fs::remove_dir_all(&tmp);
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn did_filename_sanitizes_did_punctuation() {
        assert_eq!(
            did_filename("did:wire:org:slanchaai-abc123"),
            "did_wire_org_slanchaai-abc123"
        );
        // No path-traversal characters survive into the filename.
        let f = did_filename("did:wire:org:x/../../etc");
        assert!(!f.contains('/') && !f.contains('.'));
    }

    #[test]
    fn op_and_org_key_roundtrip() {
        with_temp_home(|| {
            let op_seed = [7u8; 32];
            write_op_key(&op_seed).unwrap();
            assert_eq!(read_op_key().unwrap(), op_seed);

            let org_did = "did:wire:org:slanchaai-deadbeef";
            let org_seed = [9u8; 32];
            write_org_key(org_did, &org_seed).unwrap();
            assert_eq!(read_org_key(org_did).unwrap(), org_seed);
        });
    }

    fn with_temp_home<F: FnOnce()>(f: F) {
        super::test_support::with_temp_home(f)
    }

    #[test]
    fn config_dir_honors_wire_home() {
        with_temp_home(|| {
            let dir = config_dir().unwrap();
            assert!(dir.ends_with("wire"), "got {dir:?}");
            assert!(dir.to_string_lossy().contains("wire-test-"));
        });
    }

    #[test]
    fn ensure_dirs_creates_layout() {
        with_temp_home(|| {
            ensure_dirs().unwrap();
            assert!(config_dir().unwrap().is_dir());
            assert!(state_dir().unwrap().is_dir());
            assert!(inbox_dir().unwrap().is_dir());
            assert!(outbox_dir().unwrap().is_dir());
        });
    }

    #[test]
    fn private_key_roundtrip() {
        with_temp_home(|| {
            ensure_dirs().unwrap();
            let seed = [42u8; 32];
            write_private_key(&seed).unwrap();
            let read_back = read_private_key().unwrap();
            assert_eq!(seed, read_back);
        });
    }

    #[test]
    fn agent_card_roundtrip() {
        with_temp_home(|| {
            ensure_dirs().unwrap();
            let card = json!({"did": "did:wire:paul", "name": "Paul"});
            write_agent_card(&card).unwrap();
            let read_back = read_agent_card().unwrap();
            assert_eq!(card, read_back);
        });
    }

    #[test]
    fn trust_returns_empty_when_missing() {
        with_temp_home(|| {
            ensure_dirs().unwrap();
            let t = read_trust().unwrap();
            assert_eq!(t["version"], 1);
            assert!(t["agents"].is_object());
        });
    }

    #[test]
    fn update_relay_state_writes_through_lock() {
        // P0.3 smoke: update_relay_state runs the modifier and persists the
        // result. Doesn't exercise concurrent flock contention (that needs
        // multi-process orchestration; deferred to an e2e test) but at least
        // proves the happy path works end-to-end through the new lock
        // wrapper.
        with_temp_home(|| {
            ensure_dirs().unwrap();
            // Seed initial state.
            let initial = json!({"self": null, "peers": {}});
            write_relay_state(&initial).unwrap();
            // Run an update.
            super::update_relay_state(|state| {
                state["self"] = json!({
                    "relay_url": "https://test",
                    "slot_id": "abc",
                    "slot_token": "tok",
                });
                Ok(())
            })
            .unwrap();
            // Verify persisted.
            let after = read_relay_state().unwrap();
            assert_eq!(after["self"]["relay_url"], "https://test");
            assert_eq!(after["self"]["slot_id"], "abc");
        });
    }

    #[test]
    fn write_relay_state_never_tears_under_concurrency() {
        // Bug #3 regression: many writers hammering relay.json with
        // alternating long/short bodies. With the old raw fs::write a
        // concurrent reader caught torn bytes ("trailing characters") and
        // failed to parse. The atomic tmp+rename + flock must guarantee every
        // read sees a complete, parseable file. (Threads share one process +
        // WIRE_HOME; the flock serializes them just as it would processes.)
        with_temp_home(|| {
            ensure_dirs().unwrap();
            write_relay_state(&json!({"self": null, "peers": {}})).unwrap();
            let handles: Vec<_> = (0..8)
                .map(|w| {
                    std::thread::spawn(move || {
                        for j in 0..25 {
                            let body = if j % 2 == 0 {
                                json!({"self": {"w": w, "j": j, "pad": "x".repeat(2048)}})
                            } else {
                                json!({"self": {"w": w}})
                            };
                            write_relay_state(&body).unwrap();
                            // Reader must ALWAYS parse — never a torn file.
                            read_relay_state().expect("relay.json must always parse");
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            assert!(read_relay_state().unwrap().get("self").is_some());
        });
    }

    #[test]
    fn update_relay_state_modifier_error_does_not_clobber() {
        // P0.3 contract: if the modifier returns Err, the state on disk
        // must NOT be overwritten — partial work shouldn't half-land. The
        // operator's prior state should survive the failed RMW.
        with_temp_home(|| {
            ensure_dirs().unwrap();
            let initial = json!({"self": {"relay_url": "https://prior"}, "peers": {}});
            write_relay_state(&initial).unwrap();
            let result = super::update_relay_state(|state| {
                // Trash the state mid-modifier...
                state["self"] = json!({"relay_url": "https://NEVER_PERSIST"});
                // ...then fail. Write must NOT happen.
                anyhow::bail!("simulated mid-RMW error")
            });
            assert!(result.is_err());
            let after = read_relay_state().unwrap();
            assert_eq!(
                after["self"]["relay_url"], "https://prior",
                "state on disk must not reflect aborted modifier"
            );
        });
    }

    #[test]
    fn is_initialized_true_only_after_both_files_written() {
        with_temp_home(|| {
            ensure_dirs().unwrap();
            assert!(!is_initialized().unwrap());
            write_private_key(&[0u8; 32]).unwrap();
            assert!(!is_initialized().unwrap()); // card still missing
            write_agent_card(&json!({"did": "did:wire:paul"})).unwrap();
            assert!(is_initialized().unwrap());
        });
    }

    #[cfg(unix)]
    #[test]
    fn append_outbox_record_normalizes_fqdn_to_bare_handle() {
        // Regression for issue #2 (v0.5.11 silent-fail): if a caller
        // passes the FQDN form (`bob@relay.example`), the file MUST
        // still land at `bob.jsonl` so `wire push` enumerates it.
        with_temp_home(|| {
            let path_fqdn = append_outbox_record("bob@wireup.net", b"{\"kind\":1100}").unwrap();
            let path_bare = append_outbox_record("bob", b"{\"kind\":1100}").unwrap();
            // Both calls must land in the SAME file — the bare handle one.
            assert_eq!(path_fqdn, path_bare, "FQDN form should normalize to bare");
            assert!(
                path_fqdn.file_name().unwrap().to_string_lossy() == "bob.jsonl",
                "expected bob.jsonl, got {path_fqdn:?}"
            );
            // And the FQDN-named file MUST NOT exist.
            let outbox = outbox_dir().unwrap();
            assert!(
                !outbox.join("bob@wireup.net.jsonl").exists(),
                "FQDN-named file must not be created"
            );
            // The bare file should have BOTH writes.
            let body = std::fs::read_to_string(&path_bare).unwrap();
            assert_eq!(body.matches("kind").count(), 2, "got: {body}");
        });
    }

    #[test]
    fn pending_push_breakdown_attributes_per_peer_with_tier() {
        with_temp_home(|| {
            ensure_dirs().unwrap();
            // Seed trust.json with three peers at different tiers.
            let trust = json!({
                "agents": {
                    "alpha-fox":   {"tier": "VERIFIED"},
                    "beta-newt":   {"tier": "PENDING_ACK"},
                    "gamma-otter": {"tier": "UNTRUSTED"},
                }
            });
            write_trust(&trust).unwrap();
            // Seed relay.json so alpha (VERIFIED) has
            // bilateral_completed_at set → effective tier stays
            // VERIFIED. Without this, effective_tier would
            // demote alpha to PENDING_ACK (no slot_token) and the
            // fixture would mislead about what's tested.
            let relay = json!({
                "self": null,
                "peers": {
                    "alpha-fox": {
                        "bilateral_completed_at": "2026-06-01T00:00:00Z"
                    }
                }
            });
            write_relay_state(&relay).unwrap();
            // Seed per-peer outboxes: alpha has 2 events, 1 pushed
            // (1 unpushed). beta has 3 events, 0 pushed. gamma has
            // 0 events. The breakdown should:
            // - include alpha with count=1 tier=VERIFIED
            // - include beta with count=3 tier=PENDING_ACK
            // - NOT include gamma (count=0)
            // - sort largest backlog first → beta then alpha
            let out = outbox_dir().unwrap();
            std::fs::write(
                out.join("alpha-fox.jsonl"),
                "{\"event_id\":\"a1\"}\n{\"event_id\":\"a2\"}\n",
            )
            .unwrap();
            std::fs::write(
                out.join("alpha-fox.pushed.jsonl"),
                "{\"event_id\":\"a1\"}\n",
            )
            .unwrap();
            std::fs::write(
                out.join("beta-newt.jsonl"),
                "{\"event_id\":\"b1\"}\n{\"event_id\":\"b2\"}\n{\"event_id\":\"b3\"}\n",
            )
            .unwrap();
            let bd = compute_pending_push_breakdown();
            assert_eq!(bd.len(), 2, "got: {bd:?}");
            assert_eq!(bd[0].peer, "beta-newt");
            assert_eq!(bd[0].tier, "PENDING_ACK");
            assert_eq!(bd[0].count, 3);
            assert_eq!(bd[1].peer, "alpha-fox");
            assert_eq!(bd[1].tier, "VERIFIED");
            assert_eq!(bd[1].count, 1);
            // Aggregate wrapper still matches.
            assert_eq!(compute_pending_push_count(), 4);
        });
    }

    #[test]
    fn private_key_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        with_temp_home(|| {
            ensure_dirs().unwrap();
            write_private_key(&[1u8; 32]).unwrap();
            let mode = fs::metadata(private_key_path().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "got {:o}", mode & 0o777);
        });
    }
}
