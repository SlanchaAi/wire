//! Inbox tail-watcher — the event source for both `wire notify` (OS-level
//! toasts) and the MCP `wire://inbox/<peer>` resources.
//!
//! Implementation choice: polling, not OS-level inotify/FSEvents. Reasons:
//!   - Cross-platform with zero extra deps.
//!   - The relay daemon already polls every N seconds, so end-to-end
//!     latency is dominated by daemon poll, not inotify-vs-stat overhead.
//!   - JSONL files grow append-only; `metadata().len()` is the only thing
//!     we need to check. A `stat()` syscall is ~microseconds.
//!
//! Cursor strategy: per-consumer. `wire notify` persists its cursor to
//! `$WIRE_HOME/state/wire/notify.cursor` so restarts don't re-emit history.
//! The MCP server keeps cursors in-memory (each new MCP session starts from
//! EOF — agents that want history can call wire_tail explicitly).
//!
//! Event shape: `InboxEvent` contains everything the notifier or agent UI
//! needs to render a single-line toast: peer, kind, short body preview,
//! verified flag, event_id, timestamp. The full event is also retained so
//! resources/read can return it unmodified.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Truncate body previews to this many characters for the OS toast / chat
/// hint. Full body is still available via `InboxEvent::raw`.
const BODY_PREVIEW_CHARS: usize = 120;

/// One delivered event surfaced by a watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxEvent {
    pub peer: String,
    pub event_id: String,
    pub kind: String,
    pub body_preview: String,
    pub verified: bool,
    pub timestamp: String,
    /// Full signed event JSON for tools that want it (e.g. MCP resources/read).
    pub raw: Value,
}

impl InboxEvent {
    fn from_signed(peer: &str, signed: Value, verified: bool) -> Self {
        let event_id = signed
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let kind = signed
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                signed
                    .get("kind")
                    .map(|k| k.to_string())
                    .unwrap_or_default()
            });
        let timestamp = signed
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let body_raw = signed.get("body").cloned().unwrap_or(Value::Null);
        let body_str = match &body_raw {
            Value::String(s) => s.clone(),
            other => serde_json::to_string(other).unwrap_or_default(),
        };
        let body_preview: String = body_str.chars().take(BODY_PREVIEW_CHARS).collect();
        InboxEvent {
            peer: peer.to_string(),
            event_id,
            kind,
            body_preview,
            verified,
            timestamp,
            raw: signed,
        }
    }
}

/// Polling watcher for the inbox directory.
///
/// Tracks one cursor per `<peer>.jsonl` file. `poll()` is a single sweep —
/// callers wrap in their own loop with whatever interval makes sense (sub-
/// second for OS toast latency, longer for batchy use cases).
pub struct InboxWatcher {
    cursors: HashMap<String, u64>,
    inbox_dir: PathBuf,
}

impl InboxWatcher {
    /// Watcher with explicit inbox dir + cursor-from-file. Resumes from saved
    /// per-peer cursors; new peer files emit from byte 0 the first time
    /// they're seen, so the operator never misses an event between daemon
    /// writes and notifier restart.
    pub fn from_dir_and_cursor(inbox_dir: PathBuf, cursor_path: &Path) -> Result<Self> {
        let cursors = if cursor_path.exists() {
            let bytes = std::fs::read(cursor_path)
                .with_context(|| format!("reading cursor file {cursor_path:?}"))?;
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            HashMap::new()
        };
        Ok(Self { cursors, inbox_dir })
    }

    /// Watcher with explicit inbox dir, starting from EOF on every peer
    /// file that exists at construction time. Used by MCP — agents that want
    /// history call wire_tail. Peer files created AFTER construction emit
    /// from byte 0 (they represent new conversations starting).
    pub fn from_dir_head(inbox_dir: PathBuf) -> Result<Self> {
        let mut cursors = HashMap::new();
        if inbox_dir.exists() {
            for entry in std::fs::read_dir(&inbox_dir)?.flatten() {
                let path = entry.path();
                if path.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                    continue;
                }
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    cursors.insert(stem.to_string(), len);
                }
            }
        }
        Ok(Self { cursors, inbox_dir })
    }

    /// Convenience: use the configured wire inbox dir + cursor at the given
    /// path. Equivalent to `from_dir_and_cursor(config::inbox_dir()?, cursor_path)`.
    pub fn from_cursor_file(cursor_path: &Path) -> Result<Self> {
        Self::from_dir_and_cursor(crate::config::inbox_dir()?, cursor_path)
    }

    /// Convenience: configured inbox dir, fresh from EOF.
    pub fn from_head() -> Result<Self> {
        Self::from_dir_head(crate::config::inbox_dir()?)
    }

    /// Persist cursors to disk so a restart of `wire notify` doesn't re-emit
    /// already-seen events. JSON shape: `{"peer1": 1234, "peer2": 5678}`.
    pub fn save_cursors(&self, cursor_path: &Path) -> Result<()> {
        if let Some(parent) = cursor_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
        }
        let bytes = serde_json::to_vec(&self.cursors)?;
        std::fs::write(cursor_path, bytes)
            .with_context(|| format!("writing cursor file {cursor_path:?}"))?;
        Ok(())
    }

    /// Single poll sweep. Returns all new events across all peer inbox files
    /// since the previous sweep. Events are re-verified against the current
    /// trust state — `verified: false` events are still returned (caller
    /// decides whether to notify), but the flag is honest.
    pub fn poll(&mut self) -> Result<Vec<InboxEvent>> {
        let mut out = Vec::new();
        if !self.inbox_dir.exists() {
            return Ok(out);
        }

        let trust = crate::config::read_trust().unwrap_or_else(|_| Value::Null);

        for entry in std::fs::read_dir(&self.inbox_dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let peer = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let cur_len = meta.len();
            let start_at = *self.cursors.get(&peer).unwrap_or(&0);

            if cur_len <= start_at {
                self.cursors.insert(peer.clone(), start_at);
                continue;
            }

            // Read the full file rather than seeking — peer JSONL files are
            // small (one DM channel) and reading is simpler than mid-line
            // recovery on a partial write. Cap at 8 MiB to avoid runaway
            // memory on a misbehaving daemon.
            const READ_CAP: u64 = 8 * 1024 * 1024;
            let bytes = if cur_len <= READ_CAP {
                std::fs::read(&path)?
            } else {
                // Skip what we've seen; only read the tail.
                let mut f = std::fs::File::open(&path)?;
                use std::io::{Read, Seek, SeekFrom};
                f.seek(SeekFrom::Start(start_at))?;
                let mut tail = Vec::new();
                f.take(READ_CAP).read_to_end(&mut tail)?;
                self.cursors
                    .insert(peer.clone(), start_at + tail.len() as u64);
                tail
            };

            // Slice from start_at if we're reading whole file.
            let slice: &[u8] = if cur_len <= READ_CAP {
                &bytes[start_at as usize..]
            } else {
                &bytes[..]
            };

            // Track the last fully-parsed byte offset so a partial trailing
            // line (writer mid-flight) doesn't get prematurely consumed.
            let mut consumed: u64 = start_at;
            let mut cursor_in_slice: usize = 0;
            while let Some(nl) = slice[cursor_in_slice..].iter().position(|&b| b == b'\n') {
                let line = &slice[cursor_in_slice..cursor_in_slice + nl];
                cursor_in_slice += nl + 1;
                consumed += (nl + 1) as u64;
                if line.is_empty() {
                    continue;
                }
                let event: Value = match serde_json::from_slice(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let verified = crate::signing::verify_message_v31(&event, &trust).is_ok();
                out.push(InboxEvent::from_signed(&peer, event, verified));
            }
            self.cursors.insert(peer, consumed);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fresh_home() -> PathBuf {
        let pid = std::process::id();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!("wire-watch-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    // Tests use explicit inbox dirs so they don't race on WIRE_HOME env var
    // (cargo runs unit tests in parallel — env mutation is process-global).
    fn write_event(inbox_dir: &Path, peer: &str, kind: &str, body: &str) {
        std::fs::create_dir_all(inbox_dir).unwrap();
        let path = inbox_dir.join(format!("{peer}.jsonl"));
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let event = serde_json::json!({
            "event_id": format!("test-{}-{}", peer, body.len()),
            "from": format!("did:wire:{peer}"),
            "to": "did:wire:self",
            "type": kind,
            "kind": 1,
            "timestamp": "2026-05-10T00:00:00Z",
            "body": body,
            "sig": "fake",
        });
        writeln!(f, "{}", serde_json::to_string(&event).unwrap()).unwrap();
    }

    #[test]
    fn from_head_starts_at_eof_skips_history() {
        let home = fresh_home();
        let inbox = home.join("inbox");
        write_event(&inbox, "paul", "decision", "old event");
        let mut w = InboxWatcher::from_dir_head(inbox.clone()).unwrap();
        assert!(w.poll().unwrap().is_empty(), "from_head must skip history");
        write_event(&inbox, "paul", "decision", "new event");
        let evs = w.poll().unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].peer, "paul");
        assert_eq!(evs[0].kind, "decision");
        assert!(evs[0].body_preview.contains("new event"));
    }

    #[test]
    fn cursor_file_resumes_across_restarts() {
        let home = fresh_home();
        let inbox = home.join("inbox");
        let cursor = home.join("notify.cursor");

        write_event(&inbox, "paul", "decision", "first");
        let mut w1 = InboxWatcher::from_dir_and_cursor(inbox.clone(), &cursor).unwrap();
        let evs1 = w1.poll().unwrap();
        assert_eq!(evs1.len(), 1);
        w1.save_cursors(&cursor).unwrap();
        drop(w1);

        write_event(&inbox, "paul", "decision", "second");
        let mut w2 = InboxWatcher::from_dir_and_cursor(inbox, &cursor).unwrap();
        let evs2 = w2.poll().unwrap();
        assert_eq!(evs2.len(), 1, "should see only the new event");
        assert!(evs2[0].body_preview.contains("second"));
    }

    #[test]
    fn body_preview_truncated_at_limit() {
        let home = fresh_home();
        let inbox = home.join("inbox");
        let body = "x".repeat(500);
        write_event(&inbox, "paul", "decision", &body);
        let mut w = InboxWatcher::from_dir_and_cursor(inbox, &home.join("notify.cursor")).unwrap();
        let evs = w.poll().unwrap();
        assert_eq!(evs[0].body_preview.chars().count(), BODY_PREVIEW_CHARS);
    }

    #[test]
    fn multi_peer_files_handled_independently() {
        let home = fresh_home();
        let inbox = home.join("inbox");
        write_event(&inbox, "paul", "decision", "p1");
        write_event(&inbox, "willard", "decision", "w1");
        let mut w =
            InboxWatcher::from_dir_and_cursor(inbox.clone(), &home.join("notify.cursor")).unwrap();
        let evs = w.poll().unwrap();
        assert_eq!(evs.len(), 2);
        let peers: std::collections::HashSet<_> = evs.iter().map(|e| e.peer.clone()).collect();
        assert!(peers.contains("paul"));
        assert!(peers.contains("willard"));

        // Add to one peer; only that one shows up
        write_event(&inbox, "paul", "decision", "p2");
        let evs2 = w.poll().unwrap();
        assert_eq!(evs2.len(), 1);
        assert_eq!(evs2[0].peer, "paul");
        assert!(evs2[0].body_preview.contains("p2"));
    }
}
