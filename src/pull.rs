//! Pull-event processing — pure logic shared by `wire pull` and the daemon
//! sync loop.
//!
//! P0.1 (0.5.11): refuse to silently advance cursor past events the running
//! binary cannot process. The cursor only advances to the last event in the
//! contiguous prefix that was either successfully written or rejected for a
//! TERMINAL reason. Events rejected for TRANSIENT reasons (unknown kind,
//! signer not yet pinned) block the cursor — so the next pull re-sees them
//! and a future binary version or freshly-pinned peer can pick up where we
//! left off.
//!
//! Without this rule, an old daemon running against a newer relay silently
//! ate v0.5.x `pair_drop` events (kind=1100) it could neither pin nor verify,
//! advancing the cursor past them. Today's debug session lost ~30 min to it.
//!
//! Adversarial test: `tests/pull_unknown_kind.rs` synthesises a kind=9999
//! event, runs `process_events`, and asserts the cursor stays put + the
//! rejection carries `binary_version=` and `unknown_kind=` so the failure is
//! loud on every retry.
//!
//! Cursor advancement rules:
//!
//! - terminal reject (bad signature, missing field, event_id mismatch,
//!   revoked key) → advance past, retry won't help.
//! - transient reject (unknown kind to THIS binary, signer not in trust) →
//!   DO NOT advance past, future state may unblock.
//! - success → advance past.
//!
//! The first transient reject "blocks" the cursor; subsequent events in the
//! batch are still processed for their inbox-write side effect but cannot
//! advance the cursor beyond the block point. Re-pull observes the same
//! blocking event again → visible failure mode.

use anyhow::Result;
use serde_json::{Value, json};
use std::path::Path;

use crate::{config, pair_invite, signing};

/// Outcome of processing a batch of pulled events.
pub struct PullResult {
    pub written: Vec<Value>,
    pub rejected: Vec<Value>,
    /// New value for `self.last_pulled_event_id`. `None` means the cursor
    /// was not advanced (either no events processable beyond the prior
    /// cursor, or the first event blocked).
    pub advance_cursor_to: Option<String>,
    /// True if at least one event in this batch is blocking cursor advance.
    /// Surfaces to operators in `wire pull` non-JSON output so silent stall
    /// is visible.
    pub blocked: bool,
}

/// Check whether a peer inbox file already contains an event with this
/// `event_id`. Scan-based — O(file_size) — but inbox files are small and
/// only the write path consults this (a few times per pull). Avoids
/// pulling in a separate index file.
///
/// Returns false if the file doesn't exist yet, so the first write to a
/// new peer's inbox is a no-op check.
fn inbox_already_contains(path: &std::path::Path, event_id: &str) -> bool {
    if event_id.is_empty() {
        return false;
    }
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // Quick substring screen first — if event_id isn't anywhere in the
    // file, no point parsing every line. event_id appears once per event
    // as a JSON string value, so the substring is a strong signal.
    let needle = format!("\"event_id\":\"{event_id}\"");
    if !body.contains(&needle) {
        return false;
    }
    // Confirm by line-parse — defensive against an event_id substring
    // appearing inside a body field. JSON parsing rejects that case.
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(trimmed)
            && v.get("event_id").and_then(Value::as_str) == Some(event_id)
        {
            return true;
        }
    }
    false
}

/// Is `kind` known to THIS binary? Used by P0.1 to refuse silent cursor
/// advance past events from a future protocol version.
///
/// The Nostr-compat special cases (kind=1, kind=100) are handled in
/// `signing::kind_class`; this function mirrors them.
pub fn is_known_kind(kind: u32) -> bool {
    if kind == 1 || kind == 100 {
        return true;
    }
    signing::kinds().iter().any(|(k, _)| *k == kind)
}

/// Whether a `VerifyError` is transient (peer pinning may complete later)
/// or terminal (retry won't help).
fn verify_error_is_transient(err: &signing::VerifyError) -> bool {
    matches!(
        err,
        signing::VerifyError::UnknownAgent(_) | signing::VerifyError::UnknownKey(_, _)
    )
}

/// Process a pulled-event batch. Mutates inbox files + relay state (via
/// `pair_invite` side effects) but returns the new cursor target rather
/// than writing it — caller persists.
///
/// `initial_cursor` is the pre-pull value of `self.last_pulled_event_id`.
/// Returned `advance_cursor_to` is what the caller should write back. If
/// the first event blocks the cursor, `advance_cursor_to == initial_cursor`
/// (no change).
pub fn process_events(
    events: &[Value],
    initial_cursor: Option<String>,
    inbox_dir: &Path,
) -> Result<PullResult> {
    let binary_version = env!("CARGO_PKG_VERSION");
    let trust_snapshot = config::read_trust()?;

    let mut written = Vec::new();
    let mut rejected = Vec::new();
    let mut last_advanced = initial_cursor.clone();
    let mut first_block_idx: Option<usize> = None;

    for (idx, event) in events.iter().enumerate() {
        let event_id = event
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let kind = event.get("kind").and_then(Value::as_u64).unwrap_or(0) as u32;

        // P0.1: unknown kind → transient, block cursor, fail loud.
        if !is_known_kind(kind) {
            let reason = format!(
                "unknown_kind={kind} binary_version={binary_version}"
            );
            rejected.push(json!({
                "event_id": event_id,
                "reason": reason,
                "blocks_cursor": true,
                "transient": true,
            }));
            if first_block_idx.is_none() {
                first_block_idx = Some(idx);
            }
            continue;
        }

        // pair_drop / pair_drop_ack — pre-trust side effects that pin sender.
        let drop_paired = match pair_invite::maybe_consume_pair_drop(event) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                // P0.2: a pair_drop that WAS recognised (kind=1100, type=pair_drop)
                // but FAILED during consumption is exactly the silent-fail class —
                // sender expects to be pinned but isn't, and never finds out. Log
                // + structured record for `wire doctor`.
                let peer_handle = event
                    .get("from")
                    .and_then(Value::as_str)
                    .map(|s| crate::agent_card::display_handle_from_did(s).to_string())
                    .unwrap_or_else(|| "<unknown>".to_string());
                eprintln!(
                    "wire pull: pair_drop from {peer_handle} consume FAILED: {e}. \
                     sender will not be pinned; have them re-add or retry."
                );
                pair_invite::record_pair_rejection(
                    &peer_handle,
                    "pair_drop_consume_failed",
                    &e.to_string(),
                );
                false
            }
        };
        if let Err(e) = pair_invite::maybe_consume_pair_drop_ack(event) {
            let peer_handle = event
                .get("from")
                .and_then(Value::as_str)
                .map(|s| crate::agent_card::display_handle_from_did(s).to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            eprintln!(
                "wire pull: pair_drop_ack from {peer_handle} consume FAILED: {e}. \
                 their slot_token NOT recorded; we cannot `wire send` to them \
                 until they retry."
            );
            pair_invite::record_pair_rejection(
                &peer_handle,
                "pair_drop_ack_consume_failed",
                &e.to_string(),
            );
        }
        let active_trust = if drop_paired {
            config::read_trust()?
        } else {
            trust_snapshot.clone()
        };

        match signing::verify_message_v31(event, &active_trust) {
            Ok(()) => {
                let from = event
                    .get("from")
                    .and_then(Value::as_str)
                    .map(|s| crate::agent_card::display_handle_from_did(s).to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let path = inbox_dir.join(format!("{from}.jsonl"));

                // P0.X (0.5.11): dedupe-on-write. Spark reported 3 duplicate
                // pair_drop_ack events landing in their inbox same second,
                // same event_id. Relay double-store or push retry-after-
                // success can re-deliver. Inbox should be content-unique by
                // event_id.
                if inbox_already_contains(&path, &event_id) {
                    rejected.push(json!({
                        "event_id": event_id,
                        "reason": "duplicate event_id already in inbox",
                        "blocks_cursor": false,
                        "transient": false,
                    }));
                    if first_block_idx.is_none() {
                        last_advanced = Some(event_id.clone());
                    }
                    continue;
                }

                use std::io::Write;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
                let mut line = serde_json::to_vec(event)?;
                line.push(b'\n');
                f.write_all(&line)?;
                written.push(json!({"event_id": event_id, "from": from}));
                if first_block_idx.is_none() {
                    last_advanced = Some(event_id.clone());
                }
            }
            Err(e) if verify_error_is_transient(&e) => {
                rejected.push(json!({
                    "event_id": event_id,
                    "reason": e.to_string(),
                    "blocks_cursor": true,
                    "transient": true,
                }));
                if first_block_idx.is_none() {
                    first_block_idx = Some(idx);
                }
            }
            Err(e) => {
                rejected.push(json!({
                    "event_id": event_id,
                    "reason": e.to_string(),
                    "blocks_cursor": false,
                    "transient": false,
                }));
                if first_block_idx.is_none() {
                    last_advanced = Some(event_id.clone());
                }
            }
        }
    }

    Ok(PullResult {
        written,
        rejected,
        advance_cursor_to: last_advanced,
        blocked: first_block_idx.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn known_kinds_recognised() {
        // Special cases.
        assert!(is_known_kind(1));
        assert!(is_known_kind(100));
        // Named v0.1 kinds.
        assert!(is_known_kind(1000));
        assert!(is_known_kind(1100));
        assert!(is_known_kind(1101));
        assert!(is_known_kind(1201));
    }

    #[test]
    fn unknown_kinds_rejected() {
        assert!(!is_known_kind(0));
        assert!(!is_known_kind(9999));
        assert!(!is_known_kind(1099));
        assert!(!is_known_kind(50000));
    }

    #[test]
    fn unknown_kind_rejection_carries_binary_version_and_kind() {
        // Spark's E. rule: the silent failure must be loud. Reject reason
        // must name both the offending kind AND the binary version so an
        // operator running `wire pull --json` sees instantly which side is
        // behind.
        crate::config::test_support::with_temp_home(|| {
            crate::config::ensure_dirs().unwrap();
            let inbox = crate::config::inbox_dir().unwrap();

            let event = json!({
                "event_id": "deadbeef",
                "kind": 9999u32,
                "type": "speculation",
                "from": "did:wire:future-peer",
            });

            let result = process_events(
                &[event],
                Some("prior-cursor".to_string()),
                &inbox,
            )
            .unwrap();

            assert_eq!(result.rejected.len(), 1);
            let reason = result.rejected[0]["reason"].as_str().unwrap();
            assert!(
                reason.contains("unknown_kind=9999"),
                "reason missing kind: {reason}"
            );
            assert!(
                reason.contains("binary_version="),
                "reason missing binary_version: {reason}"
            );
            assert_eq!(result.rejected[0]["blocks_cursor"], true);

            // Cursor MUST NOT advance past unknown event.
            assert_eq!(
                result.advance_cursor_to,
                Some("prior-cursor".to_string()),
                "cursor advanced past unknown kind — silent drop regression"
            );
            assert!(result.blocked);
        });
    }

    #[test]
    fn inbox_dedupe_skips_duplicate_event_id() {
        // P0.X smoke: spark's bug — same event_id arriving twice in the
        // same inbox file produces only ONE inbox line. The pull result
        // surfaces the duplicate as rejected[] with a clear reason so
        // operators see what's happening (vs silently dropping).
        let tmp = std::env::temp_dir().join(format!(
            "wire-dedupe-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let event_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let existing_line = json!({
            "event_id": event_id,
            "from": "did:wire:peer",
            "type": "claim",
            "body": "first occurrence",
        });
        let path = tmp.join("peer.jsonl");
        std::fs::write(&path, format!("{existing_line}\n")).unwrap();
        assert!(inbox_already_contains(&path, event_id));
        assert!(!inbox_already_contains(&path, "different-event-id"));
        assert!(!inbox_already_contains(&path, ""));
    }

    #[test]
    fn inbox_dedupe_substring_in_body_is_not_false_positive() {
        // Adversarial: event_id substring inside a body field shouldn't
        // count as the event already being present.
        let tmp = std::env::temp_dir().join(format!(
            "wire-dedupe-substring-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let target_eid = "deadbeefcafebabe";
        // Existing line has the target eid AS A STRING INSIDE the body,
        // NOT as the event_id field.
        let existing_line = json!({
            "event_id": "different",
            "from": "did:wire:peer",
            "body": format!("the user mentioned event_id deadbeefcafebabe in passing"),
        });
        let path = tmp.join("peer.jsonl");
        std::fs::write(&path, format!("{existing_line}\n")).unwrap();
        // Substring screen sees the eid in the body, but the line-parse
        // confirmation rejects it.
        assert!(!inbox_already_contains(&path, target_eid));
    }

    #[test]
    fn known_kind_after_unknown_does_not_advance_cursor() {
        // Block rule: once first event blocks, NO later event can advance
        // the cursor past it, even if later events would otherwise succeed.
        // Re-pull observes both → visible.
        crate::config::test_support::with_temp_home(|| {
            crate::config::ensure_dirs().unwrap();
            let inbox = crate::config::inbox_dir().unwrap();

            let events = vec![
                json!({
                    "event_id": "evt-unknown",
                    "kind": 9999u32,
                    "type": "speculation",
                    "from": "did:wire:future",
                }),
                json!({
                    "event_id": "evt-known-but-untrusted",
                    "kind": 1000u32,
                    "type": "decision",
                    "from": "did:wire:peer-not-in-trust",
                }),
            ];

            let result = process_events(
                &events,
                Some("prior".to_string()),
                &inbox,
            )
            .unwrap();

            assert_eq!(result.rejected.len(), 2);
            assert_eq!(result.advance_cursor_to, Some("prior".to_string()));
            assert!(result.blocked);
        });
    }
}
