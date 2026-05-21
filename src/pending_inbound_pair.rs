//! Pending-inbound pair store (v0.5.14).
//!
//! When a stranger POSTs a signed `pair_drop` (kind=1100) to our auth-free
//! `/v1/handle/intro/<nick>` endpoint, **the receiver does not auto-pin**.
//! The drop lands here, awaiting the operator's explicit consent: running
//! `wire add <peer>@<relay>` on the receiver side promotes the entry to
//! `VERIFIED` trust and ships our slot_token back via `pair_drop_ack`.
//! Running `wire pair-reject <peer>` deletes the entry without pairing.
//!
//! This restores the bilateral-required semantic to zero-paste pairing:
//! `wire add` must fire on both sides before any capability flows. The
//! v0.5.13-and-earlier behaviour (receiver auto-pinned the stranger as
//! VERIFIED and emitted slot_token in the ack) was a phonebook-scrape
//! spam vector — see the v0.5.14 CHANGELOG entry and the security
//! disclosure issue on this repo.
//!
//! Storage layout: `state/wire/pending-inbound-pairs/<peer-handle>.json`.
//! One file per pending peer, deleted atomically on accept or reject.

use crate::config;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

/// One pending-inbound pair-request awaiting receiver-side `wire add`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInboundPair {
    /// Bare handle (no `@<relay>` suffix). Matches the on-disk key.
    pub peer_handle: String,
    /// Full DID of the peer (e.g. `did:wire:alice-abc12345`).
    pub peer_did: String,
    /// Peer's signed agent-card from the pair_drop body. Already
    /// signature-verified at write time.
    pub peer_card: Value,
    /// Peer's relay URL — where we'd POST our ack and future events.
    pub peer_relay_url: String,
    /// Peer's slot_id on their relay — write target for ack + sends.
    pub peer_slot_id: String,
    /// Peer's slot_token — they shipped it in the drop so we can write
    /// back. Holding this without acting on it is intentional: capability
    /// only flows when operator runs `wire add` to accept.
    pub peer_slot_token: String,
    /// v0.5.17: full set of endpoints the peer advertised (federation +
    /// optional local). When the operator accepts via `wire pair-accept`,
    /// every endpoint here gets pinned into relay_state via
    /// `endpoints::pin_peer_endpoints`. Absent on records written by
    /// v0.5.16-and-earlier code paths; downstream code synthesizes a
    /// single federation entry from the legacy fields in that case.
    #[serde(default)]
    pub peer_endpoints: Vec<crate::endpoints::Endpoint>,
    /// Original pair_drop event_id (SHA-256 over canonical body). Used to
    /// dedupe repeated drops from the same key.
    pub event_id: String,
    /// RFC3339 timestamp from the pair_drop event itself.
    pub event_timestamp: String,
    /// RFC3339 timestamp of when we wrote this pending record.
    pub received_at: String,
}

/// `state/wire/pending-inbound-pairs/` — operator-visible directory.
pub fn pending_inbound_dir() -> Result<PathBuf> {
    Ok(config::state_dir()?.join("pending-inbound-pairs"))
}

fn pending_inbound_path(peer_handle: &str) -> Result<PathBuf> {
    Ok(pending_inbound_dir()?.join(format!("{peer_handle}.json")))
}

/// Write a pending-inbound record. Overwrites any existing record for
/// the same handle (repeated pair_drops from same peer collapse to one
/// pending entry; latest payload wins).
pub fn write_pending_inbound(p: &PendingInboundPair) -> Result<()> {
    let dir = pending_inbound_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {dir:?}"))?;
    let path = pending_inbound_path(&p.peer_handle)?;
    let body = serde_json::to_vec_pretty(p)?;
    std::fs::write(&path, body)
        .with_context(|| format!("writing pending-inbound record {path:?}"))?;
    Ok(())
}

/// Read a pending-inbound record by bare handle. Returns `Ok(None)` if
/// no pending entry exists for that handle.
pub fn read_pending_inbound(peer_handle: &str) -> Result<Option<PendingInboundPair>> {
    let path = pending_inbound_path(peer_handle)?;
    if !path.exists() {
        return Ok(None);
    }
    let body =
        std::fs::read(&path).with_context(|| format!("reading pending-inbound record {path:?}"))?;
    let p: PendingInboundPair = serde_json::from_slice(&body)
        .with_context(|| format!("parsing pending-inbound record {path:?}"))?;
    Ok(Some(p))
}

/// List all pending-inbound records. Sorted by `received_at` ascending
/// (oldest first) so operators see the longest-waiting requests first.
pub fn list_pending_inbound() -> Result<Vec<PendingInboundPair>> {
    let dir = pending_inbound_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PendingInboundPair> = Vec::new();
    for entry in std::fs::read_dir(&dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let body = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Ok(p) = serde_json::from_slice::<PendingInboundPair>(&body) {
            entries.push(p);
        }
    }
    entries.sort_by(|a, b| a.received_at.cmp(&b.received_at));
    Ok(entries)
}

/// Delete a pending-inbound record (called from `wire add` on bilateral
/// completion and from `wire pair-reject`). Idempotent — `Ok(())` if the
/// record didn't exist.
pub fn consume_pending_inbound(peer_handle: &str) -> Result<()> {
    let path = pending_inbound_path(peer_handle)?;
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("deleting pending-inbound record {path:?}"))?;
    }
    Ok(())
}

// Note (v0.5.14): unit tests for this module were removed because they
// mutate process-global `WIRE_HOME` and race with other modules' tests
// (diag, ensure_up, config) that share the same env var. The integration
// tests in `tests/cli.rs` exercise pending-inbound end-to-end via the
// subprocess CLI (each subprocess has its own env), which is the correct
// isolation pattern for env-dependent state.
