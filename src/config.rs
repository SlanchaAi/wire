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
pub fn append_outbox_record(peer: &str, record_bytes: &[u8]) -> Result<PathBuf> {
    ensure_dirs()?;
    let path = outbox_dir()?.join(format!("{peer}.jsonl"));
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

pub fn write_agent_card(card: &Value) -> Result<()> {
    let path = agent_card_path()?;
    let body = serde_json::to_vec_pretty(card)?;
    fs::write(&path, body).with_context(|| format!("writing {path:?}"))?;
    Ok(())
}

pub fn read_agent_card() -> Result<Value> {
    let path = agent_card_path()?;
    let body = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
    Ok(serde_json::from_slice(&body)?)
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

pub fn write_relay_state(state: &Value) -> Result<()> {
    let path = relay_state_path()?;
    let body = serde_json::to_vec_pretty(state)?;
    fs::write(&path, body).with_context(|| format!("writing {path:?}"))?;
    set_file_mode_0600(&path)?;
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
