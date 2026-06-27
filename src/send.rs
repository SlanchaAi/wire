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
    /// Delivered over the peer's **Nostr** transport (RFC-007 D3): no HTTP slot
    /// was reachable, but the peer has a recorded `nostr_transport` and the
    /// relay accepted the published NIP-01 event. `npub` is the peer's x-only
    /// transport key the event was `p`-tagged to. Counts as relay-reached: the
    /// peer can pull it with `wire nostr fetch`.
    DeliveredNostr {
        event_id: String,
        relay_url: String,
        npub: String,
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
            SyncDelivery::DeliveredNostr { .. } => "delivered_nostr",
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
            SyncDelivery::Delivered { .. }
                | SyncDelivery::Duplicate { .. }
                | SyncDelivery::DeliveredNostr { .. }
        )
    }

    pub fn event_id(&self) -> &str {
        match self {
            SyncDelivery::Delivered { event_id, .. }
            | SyncDelivery::Duplicate { event_id, .. }
            | SyncDelivery::DeliveredNostr { event_id, .. }
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

    // RFC-006 Part B: resolve the peer's reachable endpoints from `endpoints[]`
    // — the single peer-routing source — highest-priority first (UDS → local →
    // LAN → federation). No pinned endpoints → PeerUnknown so the caller can
    // act. We try each in order and return on the first that reaches the relay
    // (priority failover — e.g. a sister's local relay first, federation as
    // backup); if all fail, the last failure verdict is returned.
    let state = crate::config::read_relay_state().context("reading relay state")?;
    let endpoints = crate::endpoints::peer_endpoints_in_priority_order(&state, peer_handle);

    let mut last_failure: Option<SyncDelivery> = None;
    for ep in endpoints {
        if ep.relay_url.is_empty() || ep.slot_id.is_empty() || ep.slot_token.is_empty() {
            continue;
        }
        let client = crate::relay_client::RelayClient::new(&ep.relay_url);
        match client.post_event(&ep.slot_id, &ep.slot_token, signed_event) {
            Ok(resp) => {
                // Append a row to the per-peer pushed log so
                // `pending_push_count` decrements regardless of whether the
                // event reached the relay via sync send (this path) or via
                // daemon push. Non-fatal on append failure.
                let now = time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default();
                if let Err(e) = crate::config::append_pushed_log(peer_handle, &event_id, &now) {
                    eprintln!(
                        "wire send: pushed-log append for {peer_handle}/{event_id} failed (non-fatal): {e:#}"
                    );
                }
                return Ok(if resp.status == "duplicate" {
                    SyncDelivery::Duplicate {
                        event_id,
                        relay_url: ep.relay_url,
                        slot_id: ep.slot_id,
                    }
                } else {
                    SyncDelivery::Delivered {
                        event_id,
                        relay_url: ep.relay_url,
                        slot_id: ep.slot_id,
                    }
                });
            }
            Err(e) => {
                let detail = crate::relay_client::format_transport_error(&e);
                // Classify 4xx/410 (stale slot) distinctly from transport
                // errors; reuse the relay's error-text classifier so both
                // paths agree. Keep as last_failure and try the next endpoint.
                last_failure = Some(if crate::cli::error_smells_like_slot_4xx(&detail) {
                    SyncDelivery::SlotStale {
                        event_id: event_id.clone(),
                        relay_url: ep.relay_url,
                        slot_id: ep.slot_id,
                        detail,
                    }
                } else {
                    SyncDelivery::TransportError {
                        event_id: event_id.clone(),
                        relay_url: ep.relay_url,
                        slot_id: ep.slot_id,
                        detail,
                    }
                });
            }
        }
    }

    // No HTTP slot reached the peer (none recorded, or all failed). RFC-007 D3:
    // if the peer has a recorded Nostr transport and this session is enrolled
    // with a secp transport key, route the same signed wire event over Nostr.
    // This is strictly a fallback — when the peer has no `nostr_transport` the
    // HTTP verdict above is returned byte-identical.
    if let Some((peer_npub, nostr_relay)) =
        crate::endpoints::peer_nostr_transport(&state, peer_handle)
        && let Ok(nsk) = crate::config::read_nostr_key()
    {
        match deliver_over_nostr(&peer_npub, &nostr_relay, signed_event, &nsk) {
            Ok(true) => {
                return Ok(SyncDelivery::DeliveredNostr {
                    event_id,
                    relay_url: nostr_relay,
                    npub: peer_npub,
                });
            }
            Ok(false) => {
                last_failure = Some(SyncDelivery::TransportError {
                    event_id: event_id.clone(),
                    relay_url: nostr_relay,
                    slot_id: String::new(),
                    detail: "nostr relay rejected the event (OK=false)".to_string(),
                });
            }
            Err(e) => {
                last_failure = Some(SyncDelivery::TransportError {
                    event_id: event_id.clone(),
                    relay_url: nostr_relay,
                    slot_id: String::new(),
                    detail: format!("nostr publish failed: {e:#}"),
                });
            }
        }
    }

    // Every endpoint failed (or all carried empty coords).
    Ok(last_failure.unwrap_or(SyncDelivery::PeerUnknown { event_id }))
}

/// Encode `signed_event` as a NIP-01 event addressed (`p`-tagged) to the peer's
/// x-only transport key `peer_npub_hex`, sign it with our secp transport key
/// `nsk`, and publish it to `relay_url`. Returns the relay's OK verdict.
///
/// HTTP-slot transport is sync (`reqwest` blocking) but `NostrWs` is async, so
/// we drive the one-shot publish on a fresh runtime (the bridge pattern shared
/// with `cli/relay.rs` + `cli/nostr.rs`). Pure event-building is factored into
/// [`build_addressed_nostr`] so it's unit-testable without a relay.
fn deliver_over_nostr(
    peer_npub_hex: &str,
    relay_url: &str,
    signed_event: &Value,
    nsk: &[u8; 32],
) -> Result<bool> {
    let ev = build_addressed_nostr(signed_event, nsk, peer_npub_hex)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build nostr runtime")?;
    rt.block_on(async {
        let mut ws = crate::nostr_ws::NostrWs::connect(relay_url)
            .await
            .with_context(|| format!("connect {relay_url}"))?;
        ws.publish(&ev).await.context("publish over nostr")
    })
}

/// Build the NIP-01 event for a Nostr-routed send: the full signed wire event
/// rides in `content` (inner Ed25519 sig intact), schnorr-signed by our secp
/// key and `p`-tagged to the peer. Surfaced for unit tests.
fn build_addressed_nostr(
    signed_event: &Value,
    nsk: &[u8; 32],
    peer_npub_hex: &str,
) -> Result<crate::nostr_event::NostrEvent> {
    crate::nostr_event::wire_to_nostr_addressed(signed_event, nsk, peer_npub_hex)
        .map_err(|e| anyhow::anyhow!("encode wire event as nostr: {e}"))
}

/// Build the actionable `peer_unknown` reason string from the three states the
/// old single message conflated (#284.6). `trusted` = a trust pin exists;
/// `has_endpoint` = relay_state has any endpoint for the peer; `has_usable_slot`
/// = at least one endpoint carries a non-empty `slot_token`. Pure → unit-tested.
///
/// The key operator guidance: when a peer is pinned but unsendable, the BARE
/// nickname dial short-circuits to `already_pinned` WITHOUT re-registering the
/// slot, so the fix is the FULL `<peer>@<relay>` dial.
fn peer_unknown_reason(
    peer: &str,
    trusted: bool,
    has_endpoint: bool,
    has_usable_slot: bool,
) -> String {
    if !trusted {
        format!(
            "peer '{peer}' is not pinned — run `wire dial {peer}@<relay>` to pair, or pass --queue (CLI) / queue:true (MCP) to buffer for the daemon to attempt later"
        )
    } else if !has_endpoint {
        format!(
            "peer '{peer}' IS pinned but has no relay endpoint recorded — re-register with a FULL `wire dial {peer}@<relay>` (the bare nickname reports `already_pinned` WITHOUT re-registering the slot)"
        )
    } else if !has_usable_slot {
        format!(
            "peer '{peer}' IS pinned but its relay slot has no token yet — their pair_drop_ack hasn't landed (common right after a daemon/MCP restart). Re-run the FULL `wire dial {peer}@<relay>` (NOT the bare nickname) to re-register, then resend"
        )
    } else {
        format!(
            "peer '{peer}' could not be reached on any recorded endpoint — check `wire status`, then re-dial `{peer}@<relay>`"
        )
    }
}

/// Classify why `peer` is (un)sendable from live trust + relay-state.
/// Returns `None` when the peer has at least one endpoint carrying a
/// non-empty `slot_token` — i.e. a send has a route. Returns
/// `Some(reason)` — the SAME actionable string the send path surfaces on
/// `peer_unknown` — when the peer is not pinned, has no endpoint, or has an
/// endpoint whose `slot_token` is still empty (the `pair_drop_ack` hasn't
/// landed yet). Shared by the send path (`delivery_json`) and the dial path
/// (`cmd_dial`) so the two surfaces can't drift: a bare-nick `wire dial`
/// that resolves an already-pinned-but-unsendable peer can show the operator
/// the exact same cause + next-command that a bouncing `wire send` would.
pub(crate) fn unsendable_reason(peer: &str) -> Option<String> {
    let trust = crate::config::read_trust().unwrap_or_default();
    let state = crate::config::read_relay_state().unwrap_or_default();
    let trusted = trust.get("agents").and_then(|a| a.get(peer)).is_some();
    let eps = crate::endpoints::peer_endpoints_in_priority_order(&state, peer);
    let has_endpoint = !eps.is_empty();
    // Mirror the send loop's usability test EXACTLY (the `continue` skip in
    // `sync_send`): an endpoint routes only when relay_url + slot_id +
    // slot_token are ALL non-empty. A token sitting on an otherwise-malformed
    // endpoint is skipped there, so it must not read as "usable" here either.
    let has_usable_slot = eps
        .iter()
        .any(|e| !e.relay_url.is_empty() && !e.slot_id.is_empty() && !e.slot_token.is_empty());
    // RFC-007 D3: the send path also delivers over Nostr when no HTTP endpoint
    // routes, provided the peer has a recorded `nostr_transport` AND this
    // session holds a secp transport key. A peer reachable only that way IS
    // sendable — don't warn on dial that its HTTP slot has no token.
    let nostr_reachable = crate::endpoints::peer_nostr_transport(&state, peer).is_some()
        && crate::config::read_nostr_key().is_ok();
    if has_usable_slot || nostr_reachable {
        None
    } else {
        Some(peer_unknown_reason(
            peer,
            trusted,
            has_endpoint,
            has_usable_slot,
        ))
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
        SyncDelivery::DeliveredNostr {
            relay_url, npub, ..
        } => {
            obj.insert("relay_url".into(), json!(relay_url));
            obj.insert("transport".into(), json!("nostr"));
            obj.insert("npub".into(), json!(npub));
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
            // #284.6: "peer_unknown" conflated three distinct states — no trust
            // pin, pinned-but-no-endpoint, and pinned-with-an-endpoint-whose-
            // slot_token-is-empty (the ack hasn't landed, common after a
            // daemon/MCP restart). A peer can be VERIFIED in trust yet hit this.
            // Classify against live state so the message names the real cause
            // and the real fix (a FULL `@relay` dial, not the nickname short-
            // circuit which reports already_pinned without re-registering).
            // Via the shared `unsendable_reason` classifier the dial path
            // reuses. `None` here would mean a usable slot exists despite the
            // send reporting PeerUnknown (a route raced away mid-send) — fall
            // back to the generic "could not be reached" guidance.
            let reason = unsendable_reason(peer)
                .unwrap_or_else(|| peer_unknown_reason(peer, true, true, true));
            obj.insert("reason".into(), json!(reason));
        }
    }
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_unknown_reason_classifies_the_three_states() {
        // Not pinned at all.
        let r = peer_unknown_reason("p", false, false, false);
        assert!(r.contains("is not pinned"), "{r}");
        // Pinned but no endpoint → full dial, warn about nickname short-circuit.
        let r = peer_unknown_reason("p", true, false, false);
        assert!(r.contains("IS pinned"), "{r}");
        assert!(r.contains("no relay endpoint"), "{r}");
        assert!(r.contains("@<relay>"), "{r}");
        assert!(r.contains("bare nickname"), "{r}");
        // Pinned, endpoint exists, but slot_token empty (the #284.6 desync).
        let r = peer_unknown_reason("p", true, true, false);
        assert!(r.contains("no token yet"), "{r}");
        assert!(r.contains("daemon/MCP restart"), "{r}");
        assert!(r.contains("NOT the bare nickname"), "{r}");
        // Pinned + usable slot but unreachable (fallback wording).
        let r = peer_unknown_reason("p", true, true, true);
        assert!(r.contains("could not be reached"), "{r}");
    }

    #[test]
    fn unsendable_reason_reads_live_state() {
        use crate::endpoints::{Endpoint, EndpointScope, pin_peer_endpoints};
        crate::config::test_support::with_temp_home(|| {
            // Unknown peer, empty home → the send path's "not pinned" verdict.
            let r = unsendable_reason("ghost").expect("unknown peer is unsendable");
            assert!(r.contains("is not pinned"), "{r}");

            // Peer with a usable federation slot → sendable → None. Guards the
            // common bare-nick dial: no spurious warning when a route exists.
            let mut st = crate::config::read_relay_state().unwrap();
            pin_peer_endpoints(
                &mut st,
                "live",
                &[Endpoint {
                    relay_url: "https://wireup.net".into(),
                    slot_id: "slot-live".into(),
                    slot_token: "tok-abc".into(),
                    scope: EndpointScope::Federation,
                }],
            )
            .unwrap();
            crate::config::write_relay_state(&st).unwrap();
            assert!(
                unsendable_reason("live").is_none(),
                "peer with a non-empty slot_token must read as sendable"
            );

            // Pinned in trust but its endpoint token is still empty (the
            // pair_drop_ack hasn't landed — the #284.6 desync the dial path
            // must now surface instead of a bland `already_pinned`).
            let mut st2 = crate::config::read_relay_state().unwrap();
            pin_peer_endpoints(
                &mut st2,
                "pending",
                &[Endpoint {
                    relay_url: "https://wireup.net".into(),
                    slot_id: "slot-pending".into(),
                    slot_token: String::new(),
                    scope: EndpointScope::Federation,
                }],
            )
            .unwrap();
            crate::config::write_relay_state(&st2).unwrap();
            crate::config::update_trust(|t| {
                t.get_mut("agents")
                    .and_then(Value::as_object_mut)
                    .unwrap()
                    .insert(
                        "pending".into(),
                        json!({"did": "did:wire:pending-0000", "tier": "VERIFIED"}),
                    );
                Ok(())
            })
            .unwrap();
            let r = unsendable_reason("pending").expect("empty-token peer is unsendable");
            assert!(r.contains("no token yet"), "{r}");

            // Reachable only over Nostr: empty HTTP token, but a recorded
            // nostr_transport + a local nostr key → sendable (the RFC-007 D3
            // fallback the send path takes), so NO dial warning.
            let mut st3 = crate::config::read_relay_state().unwrap();
            pin_peer_endpoints(
                &mut st3,
                "nostronly",
                &[Endpoint {
                    relay_url: "https://wireup.net".into(),
                    slot_id: "slot-n".into(),
                    slot_token: String::new(),
                    scope: EndpointScope::Federation,
                }],
            )
            .unwrap();
            st3["peers"]["nostronly"]["nostr_transport"] =
                json!({"npub": "npub1xxx", "relay": "wss://relay.example"});
            crate::config::write_relay_state(&st3).unwrap();
            crate::config::write_nostr_key(&[3u8; 32]).unwrap();
            assert!(
                unsendable_reason("nostronly").is_none(),
                "a Nostr-reachable peer must read as sendable despite an empty HTTP token"
            );

            // Malformed endpoint: a token present but relay_url/slot_id empty is
            // NOT a usable route (the send loop skips it), so still unsendable —
            // matches the send path's `continue` skip exactly.
            let mut st4 = crate::config::read_relay_state().unwrap();
            pin_peer_endpoints(
                &mut st4,
                "malformed",
                &[Endpoint {
                    relay_url: String::new(),
                    slot_id: String::new(),
                    slot_token: "tok-orphan".into(),
                    scope: EndpointScope::Federation,
                }],
            )
            .unwrap();
            crate::config::write_relay_state(&st4).unwrap();
            assert!(
                unsendable_reason("malformed").is_some(),
                "a token on an endpoint with empty relay_url/slot_id is not usable"
            );
        });
    }

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
    fn delivered_nostr_counts_as_reached_and_renders_transport() {
        let d = SyncDelivery::DeliveredNostr {
            event_id: "ev1".into(),
            relay_url: "wss://relay.example".into(),
            npub: "ab".repeat(32),
        };
        assert_eq!(d.status_str(), "delivered_nostr");
        assert!(
            d.reached_relay(),
            "nostr delivery means the peer can pull it"
        );
        assert_eq!(d.event_id(), "ev1");

        let v = delivery_json(&d, "alice");
        assert_eq!(v["status"], "delivered_nostr");
        assert_eq!(v["peer"], "alice");
        assert_eq!(v["event_id"], "ev1");
        assert_eq!(v["relay_url"], "wss://relay.example");
        assert_eq!(v["transport"], "nostr");
        assert_eq!(v["npub"], "ab".repeat(32));
        // No HTTP-slot field on the nostr path.
        assert!(v.get("slot_id").is_none(), "nostr send has no slot_id");
        assert!(v.get("reason").is_none(), "success has no reason");
    }

    #[test]
    fn build_addressed_nostr_is_verifiable_and_addressed() {
        use crate::nostr_key::generate_transport_key;
        use crate::signing::{generate_keypair, sign_message_v31};

        let (sk, pk) = generate_keypair();
        let wire = sign_message_v31(
            &json!({
                "v": "3.1",
                "timestamp": "2026-06-14T12:00:00Z",
                "from": "did:wire:slate-lotus-88232017",
                "to": "did:wire:raven-kettle-1234",
                "kind": 1,
                "body": {"content": "routed over nostr"},
            }),
            &sk,
            &pk,
            "slate-lotus",
        )
        .unwrap();

        let (nsk, _x) = generate_transport_key();
        let (_psk, peer_x) = generate_transport_key();
        let peer_hex = hex::encode(peer_x);

        let ev = build_addressed_nostr(&wire, &nsk, &peer_hex).unwrap();
        // Addressed to the peer (their #p filter selects on this).
        assert!(
            ev.tags
                .iter()
                .any(|t| t.first().map(String::as_str) == Some("p") && t.get(1) == Some(&peer_hex))
        );
        // Transport authenticates and the full signed wire event survives intact.
        assert_eq!(crate::nostr_event::verify_and_decode(&ev).unwrap(), wire);
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
