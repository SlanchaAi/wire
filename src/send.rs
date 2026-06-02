//! Synchronous event delivery — collapses the legacy
//! `wire send → outbox → daemon push → relay` 3-step into a single
//! direct relay POST.
//!
//! ## Why this exists
//!
//! Paul (2026-06-01): *"Why are we dealing with this whole outbox
//! queued delivered thing it's a headache and always breaks can we
//! streamline and collapse steps."*
//!
//! Pre-fix, every `wire send` (CLI and MCP) wrote to
//! `<outbox_dir>/<peer>.jsonl` and returned `status: "queued"`. The
//! daemon's 5s push loop later POSTed the event to the relay. Three
//! distinct silent-drop classes hide in those steps:
//!
//! 1. **outbox write succeeds, daemon never pushes** — daemon dead,
//!    daemon on wrong WIRE_HOME, TLS broken (the #176 → #183 saga),
//!    operator never ran `wire push`. `queued` looked like success
//!    but no byte ever left the box.
//! 2. **daemon pushed, peer's relay slot stale** — earlier
//!    half-paired state, peer rotated slot, slot_token expired (the
//!    brisk-iris case). Push got 4xx, marked as skipped in the daemon
//!    log, operator never sees it from the `wire send` side.
//! 3. **content-hash dedup blocks retries** — `event_id` is
//!    `sha256(canonical(body))`. Sending the same body twice produces
//!    the same event_id; relay drops the second as `duplicate`. Retry
//!    feels like success but never reaches the peer.
//!
//! ## The new contract
//!
//! - **Default** (`wire send`, `tool_send`): synchronous POST to the
//!   peer's pinned relay slot. Returns `Delivered` / `Duplicate` /
//!   `Failed` inline. No outbox write on the happy path. Operator
//!   sees the actual verdict, not a fake `queued`.
//!
//! - **`--queue` opt-in** (CLI flag; MCP `queue: true` arg):
//!   preserves the legacy outbox-write path for explicit batching /
//!   offline-buffer / pre-pair queue use cases. The daemon's
//!   `run_sync_push` loop continues to drain the outbox so anything
//!   written via this path still delivers.
//!
//! - **Peer not pinned**: the relay coords are unknown — sync POST
//!   is impossible. We error explicitly with a hint to run
//!   `wire dial <peer>` (or pass `--queue` if the operator wants
//!   pre-pair queueing). Pre-fix this case silently wrote to outbox
//!   and the daemon would never push it; now it's loud.
//!
//! - **Stale slot (4xx from relay)**: return `Failed` with the slot
//!   error string. The existing `cli::error_smells_like_slot_4xx`
//!   classifier already detects this shape; the caller surfaces the
//!   re-resolve hint. We do NOT auto-re-pair without the operator's
//!   consent (that's `wire dial`'s job).

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};

/// Result of attempting a synchronous delivery to a peer.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SyncDelivery {
    /// Relay accepted the event. First-time landing on the peer's slot.
    Delivered {
        event_id: String,
        relay_url: String,
        slot_id: String,
    },
    /// Relay said `duplicate` — same `event_id` already on the slot.
    /// Not a failure: the relay HAS the event, the peer can pull it.
    /// Surfaced distinctly so the caller can decide whether to nudge
    /// content uniqueness on the next attempt.
    Duplicate {
        event_id: String,
        relay_url: String,
        slot_id: String,
    },
    /// Peer isn't in `relay_state.peers` — no slot coords to POST to.
    /// This is the explicit "you haven't paired yet" case. The
    /// caller should either suggest `wire dial <peer>` or write
    /// to outbox via the `--queue` opt-in.
    PeerUnknown { event_id: String },
    /// Relay returned a 4xx/410 — slot has rotated, token expired,
    /// peer half-paired and never completed bilateral. The caller
    /// surfaces a hint to `wire dial <peer>`.
    SlotStale {
        event_id: String,
        relay_url: String,
        slot_id: String,
        detail: String,
    },
    /// Transport failure (TLS, DNS, connect timeout, 5xx). The
    /// caller decides whether to fall back to `--queue` or surface
    /// the error.
    TransportError {
        event_id: String,
        relay_url: String,
        slot_id: String,
        detail: String,
    },
}

impl SyncDelivery {
    /// Compact status string for callers that just want the verdict.
    /// Same shape as the JSON `status` field.
    pub fn status_str(&self) -> &'static str {
        match self {
            SyncDelivery::Delivered { .. } => "delivered",
            SyncDelivery::Duplicate { .. } => "duplicate",
            SyncDelivery::PeerUnknown { .. } => "peer_unknown",
            SyncDelivery::SlotStale { .. } => "slot_stale",
            SyncDelivery::TransportError { .. } => "transport_error",
        }
    }

    /// True when the event reached the relay (Delivered or
    /// Duplicate). Both states mean the peer CAN pull it.
    pub fn reached_relay(&self) -> bool {
        matches!(
            self,
            SyncDelivery::Delivered { .. } | SyncDelivery::Duplicate { .. }
        )
    }

    pub fn event_id(&self) -> &str {
        match self {
            SyncDelivery::Delivered { event_id, .. }
            | SyncDelivery::Duplicate { event_id, .. }
            | SyncDelivery::PeerUnknown { event_id }
            | SyncDelivery::SlotStale { event_id, .. }
            | SyncDelivery::TransportError { event_id, .. } => event_id,
        }
    }
}

/// Attempt synchronous delivery of `signed_event` to `peer_handle`.
///
/// Reads the peer's slot coords from `relay_state.peers`, builds a
/// `RelayClient`, POSTs the event. Maps every observable outcome onto
/// a [`SyncDelivery`] variant.
///
/// On success (`Delivered` or `Duplicate`), appends a row to the
/// per-peer pushed log (`<outbox_dir>/<peer>.pushed.jsonl`) so the
/// `pending_push_count` counter in `wire status` stays accurate
/// across both code paths (sync send + legacy daemon push).
pub fn attempt_deliver(peer_handle: &str, signed_event: &Value) -> Result<SyncDelivery> {
    let event_id = signed_event
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // Resolve the peer's slot coords. Missing peer / missing fields →
    // PeerUnknown so the caller can act.
    let state = crate::config::read_relay_state().context("reading relay state")?;
    let peer_obj = match state
        .get("peers")
        .and_then(Value::as_object)
        .and_then(|m| m.get(peer_handle))
    {
        Some(v) => v,
        None => return Ok(SyncDelivery::PeerUnknown { event_id }),
    };
    let relay_url = peer_obj
        .get("relay_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let slot_id = peer_obj
        .get("slot_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let slot_token = peer_obj
        .get("slot_token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if relay_url.is_empty() || slot_id.is_empty() || slot_token.is_empty() {
        return Ok(SyncDelivery::PeerUnknown { event_id });
    }

    // POST.
    let client = crate::relay_client::RelayClient::new(&relay_url);
    match client.post_event(&slot_id, &slot_token, signed_event) {
        Ok(resp) => {
            // Append a row to the per-peer pushed log so
            // `pending_push_count` decrements regardless of whether
            // the event reached the relay via sync send (this path)
            // or via daemon push. Non-fatal on append failure.
            let now = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            if let Err(e) = crate::config::append_pushed_log(peer_handle, &event_id, &now) {
                eprintln!(
                    "wire send: pushed-log append for {peer_handle}/{event_id} failed (non-fatal): {e:#}"
                );
            }
            if resp.status == "duplicate" {
                Ok(SyncDelivery::Duplicate {
                    event_id,
                    relay_url,
                    slot_id,
                })
            } else {
                Ok(SyncDelivery::Delivered {
                    event_id,
                    relay_url,
                    slot_id,
                })
            }
        }
        Err(e) => {
            let detail = crate::relay_client::format_transport_error(&e);
            // Classify 4xx/410 (stale slot) distinctly from transport
            // errors. The existing `cli::error_smells_like_slot_4xx`
            // helper matches the relay's error text shape; reuse it
            // so both code paths share the same classifier.
            if crate::cli::error_smells_like_slot_4xx(&detail) {
                Ok(SyncDelivery::SlotStale {
                    event_id,
                    relay_url,
                    slot_id,
                    detail,
                })
            } else {
                Ok(SyncDelivery::TransportError {
                    event_id,
                    relay_url,
                    slot_id,
                    detail,
                })
            }
        }
    }
}

/// Render a `SyncDelivery` as the JSON value `wire send --json` /
/// `tool_send` return. Fields are flat (no nested struct) so JSON
/// consumers can read `.status` + `.event_id` directly without
/// pattern-matching the variant tag.
pub fn delivery_json(d: &SyncDelivery, peer: &str) -> Value {
    let base = json!({
        "status": d.status_str(),
        "peer": peer,
        "event_id": d.event_id(),
    });
    let mut obj = base.as_object().cloned().unwrap_or_default();
    match d {
        SyncDelivery::Delivered {
            relay_url, slot_id, ..
        }
        | SyncDelivery::Duplicate {
            relay_url, slot_id, ..
        } => {
            obj.insert("relay_url".into(), json!(relay_url));
            obj.insert("slot_id".into(), json!(slot_id));
        }
        SyncDelivery::SlotStale {
            relay_url,
            slot_id,
            detail,
            ..
        }
        | SyncDelivery::TransportError {
            relay_url,
            slot_id,
            detail,
            ..
        } => {
            obj.insert("relay_url".into(), json!(relay_url));
            obj.insert("slot_id".into(), json!(slot_id));
            obj.insert("reason".into(), json!(detail));
        }
        SyncDelivery::PeerUnknown { .. } => {
            obj.insert(
                "reason".into(),
                json!(format!(
                    "peer '{peer}' not pinned — run `wire dial {peer}` to pair, or pass --queue (CLI) / queue:true (MCP) to write to outbox for the daemon to attempt later"
                )),
            );
        }
    }
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_str_matches_variant() {
        let d = SyncDelivery::Delivered {
            event_id: "x".into(),
            relay_url: "https://r".into(),
            slot_id: "s".into(),
        };
        assert_eq!(d.status_str(), "delivered");
        assert!(d.reached_relay());

        let d = SyncDelivery::Duplicate {
            event_id: "x".into(),
            relay_url: "https://r".into(),
            slot_id: "s".into(),
        };
        assert_eq!(d.status_str(), "duplicate");
        assert!(
            d.reached_relay(),
            "duplicate counts as relay-reached: peer can pull it"
        );

        let d = SyncDelivery::PeerUnknown {
            event_id: "x".into(),
        };
        assert_eq!(d.status_str(), "peer_unknown");
        assert!(!d.reached_relay());

        let d = SyncDelivery::SlotStale {
            event_id: "x".into(),
            relay_url: "https://r".into(),
            slot_id: "s".into(),
            detail: "410".into(),
        };
        assert_eq!(d.status_str(), "slot_stale");
        assert!(!d.reached_relay());

        let d = SyncDelivery::TransportError {
            event_id: "x".into(),
            relay_url: "https://r".into(),
            slot_id: "s".into(),
            detail: "tls".into(),
        };
        assert_eq!(d.status_str(), "transport_error");
        assert!(!d.reached_relay());
    }

    #[test]
    fn delivery_json_includes_reason_only_for_failures() {
        let ok = SyncDelivery::Delivered {
            event_id: "abc".into(),
            relay_url: "https://r".into(),
            slot_id: "s".into(),
        };
        let v = delivery_json(&ok, "alice");
        assert_eq!(v["status"], "delivered");
        assert_eq!(v["event_id"], "abc");
        assert_eq!(v["peer"], "alice");
        assert_eq!(v["relay_url"], "https://r");
        assert!(v.get("reason").is_none(), "happy path has no reason field");

        let bad = SyncDelivery::TransportError {
            event_id: "abc".into(),
            relay_url: "https://r".into(),
            slot_id: "s".into(),
            detail: "TLS error: UnknownIssuer".into(),
        };
        let v = delivery_json(&bad, "alice");
        assert_eq!(v["status"], "transport_error");
        assert_eq!(v["reason"], "TLS error: UnknownIssuer");

        let unknown = SyncDelivery::PeerUnknown {
            event_id: "abc".into(),
        };
        let v = delivery_json(&unknown, "alice");
        assert_eq!(v["status"], "peer_unknown");
        assert!(
            v["reason"]
                .as_str()
                .unwrap_or("")
                .contains("wire dial alice")
        );
    }
}
