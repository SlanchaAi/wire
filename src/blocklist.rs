//! RFC-001 Security §T16 — per-peer block-list (rogue / compromised org admin
//! containment).
//!
//! `ORG_VERIFIED` lets an org admin vouch a peer into every org-mate's inbox
//! with no per-receiver gate (and, under Option-A auto-pair, no operator tap).
//! T16's mitigation is a **local** kill switch: `wire block-peer <did>` removes
//! a single peer from this receiver's locally-effective roster *without leaving
//! the org*. A blocked DID can never be org-auto-pinned or surface an
//! org-notify prompt; the inbound pair attempt is dropped silently (no
//! fingerprintable response).
//!
//! Scope of a block is a **DID prefix-free exact match** on whichever DID the
//! operator names:
//!   - block a **session DID** (`did:wire:<handle>-<8hex>`) → mutes that one
//!     session;
//!   - block an **operator DID** (`did:wire:op:<handle>-<32hex>`) → mutes every
//!     session that carries that `op_did` (the T16 intent: cut off the single
//!     adversary the rogue admin injected, across all their sessions).
//!
//! **Fail-safe.** A missing file loads as the empty block-list (nothing
//! blocked — the common case). A *malformed* file also loads empty but logs a
//! warning: a corrupt block-list must not wedge the daemon, and erring toward
//! "not blocked" matches the rest of wire's trust surface (block-list is
//! defense-in-depth on top of the per-org opt-in, never the only gate). The
//! block decision is consulted at the org-easing path only; bilateral SAS
//! (`VERIFIED`) is an explicit operator gesture that is out of scope here — if
//! you SAS-pair a peer you blocked, that deliberate act wins (see
//! `wire block-peer --help`).

use crate::agent_card::{self, AgentCard};
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const FILE: &str = "blocklist.json";

/// One block-list entry: when it was added + an optional operator note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    pub at: String,
    pub note: Option<String>,
}

/// File-backed per-peer block-list. Maps a DID → entry. Absence = not blocked.
#[derive(Debug, Clone, Default)]
pub struct Blocklist {
    blocked: BTreeMap<String, BlockEntry>,
}

impl Blocklist {
    /// Load from `config/wire/blocklist.json`. Missing → empty. Malformed →
    /// empty + a warning (fail-safe: never wedge, never silently lose a real
    /// block without saying so).
    pub fn load() -> Self {
        match crate::config::config_dir() {
            Ok(dir) => Self::load_path(&dir.join(FILE)),
            Err(_) => Self::default(),
        }
    }

    /// Load from an explicit path (testable).
    pub fn load_path(path: &Path) -> Self {
        let Ok(bytes) = std::fs::read(path) else {
            return Self::default();
        };
        let Ok(json) = serde_json::from_slice::<Value>(&bytes) else {
            eprintln!(
                "wire: blocklist at {path:?} is malformed JSON — treating as empty \
                 (no peers blocked). Fix or remove the file to restore your blocks."
            );
            return Self::default();
        };
        let mut blocked = BTreeMap::new();
        if let Some(map) = json.get("blocked").and_then(|v| v.as_object()) {
            for (did, entry) in map {
                let at = entry
                    .get("at")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let note = entry
                    .get("note")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                blocked.insert(did.clone(), BlockEntry { at, note });
            }
        }
        Self { blocked }
    }

    /// Block a DID (idempotent: re-blocking refreshes the note, keeps `at`).
    /// Returns `true` if this is a newly-added block, `false` if already present.
    pub fn block(&mut self, did: &str, note: Option<String>) -> bool {
        match self.blocked.get_mut(did) {
            Some(existing) => {
                if note.is_some() {
                    existing.note = note;
                }
                false
            }
            None => {
                self.blocked.insert(
                    did.to_string(),
                    BlockEntry {
                        at: now_iso(),
                        note,
                    },
                );
                true
            }
        }
    }

    /// Remove a DID from the block-list. Returns `true` if it was present.
    pub fn unblock(&mut self, did: &str) -> bool {
        self.blocked.remove(did).is_some()
    }

    /// Is this exact DID blocked?
    pub fn is_blocked(&self, did: &str) -> bool {
        self.blocked.contains_key(did)
    }

    /// Does this card belong to a blocked peer? Checks both the session DID and
    /// the operator DID (`op_did`) the card carries, so blocking an operator
    /// cuts off all of their sessions. Returns the matched DID for diagnostics.
    pub fn blocks_card<'c>(&self, card: &'c AgentCard) -> Option<&'c str> {
        let session_did = card.get("did").and_then(Value::as_str);
        if let Some(d) = session_did
            && self.is_blocked(d)
        {
            return Some(d);
        }
        if let Some(op_did) = agent_card::card_op_did(card)
            && self.is_blocked(op_did)
        {
            return Some(op_did);
        }
        None
    }

    /// Iterate entries (sorted by DID via the `BTreeMap`), for `wire blocked`.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &BlockEntry)> {
        self.blocked.iter()
    }

    pub fn len(&self) -> usize {
        self.blocked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocked.is_empty()
    }

    /// Persist to `config/wire/blocklist.json`.
    pub fn save(&self) -> Result<()> {
        let dir = crate::config::config_dir()?;
        std::fs::create_dir_all(&dir)?;
        self.save_path(&dir.join(FILE))?;
        Ok(())
    }

    /// Persist to an explicit path (testable).
    pub fn save_path(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_json())
    }

    fn to_json(&self) -> String {
        let blocked: serde_json::Map<String, Value> = self
            .blocked
            .iter()
            .map(|(did, e)| {
                let mut obj = json!({ "at": e.at });
                if let Some(note) = &e.note {
                    obj["note"] = json!(note);
                }
                (did.clone(), obj)
            })
            .collect();
        serde_json::to_string_pretty(&json!({ "version": 1, "blocked": blocked }))
            .unwrap_or_else(|_| "{}".into())
    }
}

fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("wire-blocklist-{}-{name}.json", std::process::id()))
    }

    #[test]
    fn missing_file_blocks_nobody() {
        let p = tmp("missing");
        let _ = std::fs::remove_file(&p);
        let bl = Blocklist::load_path(&p);
        assert!(bl.is_empty());
        assert!(!bl.is_blocked("did:wire:anyone-deadbeef"));
    }

    #[test]
    fn malformed_file_fails_safe_to_empty() {
        let p = tmp("malformed");
        std::fs::write(&p, b"not json {{{").unwrap();
        let bl = Blocklist::load_path(&p);
        assert!(bl.is_empty(), "malformed block-list must load empty");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn block_unblock_roundtrip_persists() {
        let p = tmp("roundtrip");
        let mut bl = Blocklist::default();
        assert!(bl.block("did:wire:rogue-aabbccdd", Some("spammer".into())));
        assert!(
            !bl.block("did:wire:rogue-aabbccdd", None),
            "second block of same DID is not newly-added"
        );
        bl.save_path(&p).unwrap();

        let loaded = Blocklist::load_path(&p);
        assert!(loaded.is_blocked("did:wire:rogue-aabbccdd"));
        let (_, entry) = loaded.entries().next().unwrap();
        assert_eq!(entry.note.as_deref(), Some("spammer"));
        assert!(!entry.at.is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn unblock_reports_presence() {
        let mut bl = Blocklist::default();
        bl.block("did:wire:x-1", None);
        assert!(bl.unblock("did:wire:x-1"));
        assert!(!bl.unblock("did:wire:x-1"), "second unblock is a no-op");
        assert!(!bl.is_blocked("did:wire:x-1"));
    }

    #[test]
    fn blocks_card_matches_session_did() {
        let mut bl = Blocklist::default();
        bl.block("did:wire:peer-12345678", None);
        let card = json!({"did": "did:wire:peer-12345678", "handle": "peer"});
        assert_eq!(bl.blocks_card(&card), Some("did:wire:peer-12345678"));
    }

    #[test]
    fn blocks_card_matches_op_did_across_sessions() {
        // T16 intent: block the operator → mute every session under them.
        // The card's session DID is NOT itself blocked; the `op_did` is.
        let op = "did:wire:op:darby-0123456789abcdef0123456789abcdef";
        let mut bl = Blocklist::default();
        bl.block(op, Some("compromised operator".into()));
        let card = json!({
            "did": "did:wire:fresh-session-99887766",
            "handle": "fresh-session",
            "op_did": op,
        });
        assert_eq!(bl.blocks_card(&card), Some(op));
    }

    #[test]
    fn blocks_card_none_for_unblocked_peer() {
        let mut bl = Blocklist::default();
        bl.block("did:wire:someone-else-aaaa1111", None);
        let card = json!({
            "did": "did:wire:innocent-bbbb2222",
            "handle": "innocent",
            "op_did": "did:wire:op:clean-ffffffffffffffffffffffffffffffff",
        });
        assert_eq!(bl.blocks_card(&card), None);
    }
}
