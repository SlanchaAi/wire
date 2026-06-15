//! RFC-004 Tier-1 — connection health probing.
//!
//! A `wire ping` sends a probe; the peer's **daemon** auto-responds with a
//! probe_ack — no LLM / MCP in the loop (RFC-004 AC-HP2 kill criterion). Both
//! ride the existing `kind=100` heartbeat carrier with a body `t` discriminator
//! (`probe` / `probe_ack`), NOT a new top-level kind — per the event-kind-carrier
//! rule (control signals discriminate on a registered generic kind's body).
//!
//! Probes are **plaintext** (they carry only a correlation nonce, no secret), so
//! the receiving daemon reads `t` directly without decrypting. They are
//! trust-neutral: a probe/ack never mutates a peer's tier or relay state.

use serde_json::{Value, json};

/// The heartbeat carrier kind (registered, special-cased Ephemeral in signing).
pub const HEARTBEAT_KIND: u64 = 100;
/// The event `type` string paired with [`HEARTBEAT_KIND`].
pub const HEARTBEAT_TYPE: &str = "heartbeat";

/// Body of an outbound probe. `nonce` correlates the ack.
pub fn probe_body(nonce: &str) -> Value {
    json!({ "t": "probe", "nonce": nonce })
}

/// Body of a probe_ack answering the probe carrying `nonce`.
pub fn probe_ack_body(nonce: &str) -> Value {
    json!({ "t": "probe_ack", "nonce": nonce })
}

/// If `event` is a kind=100 probe, return its correlation nonce — the signal the
/// daemon uses to decide whether to auto-respond. An event that is heartbeat-kind
/// but carries an unknown/other `t` (or a sealed body) returns `None`: it is
/// simply ignored, cursor advances, no reject (RFC-004 AC-HP4).
pub fn probe_nonce(event: &Value) -> Option<String> {
    if event.get("kind").and_then(Value::as_u64) != Some(HEARTBEAT_KIND) {
        return None;
    }
    let body = event.get("body")?;
    if body.get("t").and_then(Value::as_str) != Some("probe") {
        return None;
    }
    body.get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// True iff `event` is a kind=100 probe_ack carrying `nonce` — the ack a waiting
/// `wire ping` is looking for.
pub fn is_probe_ack_for(event: &Value, nonce: &str) -> bool {
    event.get("kind").and_then(Value::as_u64) == Some(HEARTBEAT_KIND)
        && event
            .get("body")
            .and_then(|b| b.get("t"))
            .and_then(Value::as_str)
            == Some("probe_ack")
        && event
            .get("body")
            .and_then(|b| b.get("nonce"))
            .and_then(Value::as_str)
            == Some(nonce)
}

/// Per-peer ack rate gate (RFC-004 AC-HP3 — a 100-probe flood must yield ≤ a
/// handful of acks, bounded responder CPU). Prunes `times` to the window, then:
/// `>= max` remaining → refuse the ack (`false`); else record `now` and allow
/// (`true`). Same sliding-window shape as the relay's intro gate. Pure →
/// unit-tested. The daemon holds `times` per peer in a process-static map.
pub fn record_ack_within_rate(times: &mut Vec<u64>, now: u64, window: u64, max: usize) -> bool {
    times.retain(|t| now.saturating_sub(*t) < window);
    if times.len() >= max {
        return false;
    }
    times.push(now);
    true
}

// ---------- I/O wrappers (build + sign + deliver). The pure helpers above are
// unit-tested; these do network + key access, exercised by the integration test.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Process-static per-peer ack-rate state. The daemon is long-lived, so the
/// AC-HP3 cap must persist across pull cycles (a one-shot `wire pull` can't flood).
static ACK_RATE: OnceLock<Mutex<HashMap<String, Vec<u64>>>> = OnceLock::new();
const ACK_MAX_PER_WINDOW: usize = 10;
const ACK_WINDOW_SECS: u64 = 10;

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a signed kind=100 heartbeat event carrying `body` to `peer`. Plaintext
/// (probe bodies hold only a nonce — no secret). Mirrors the `cmd_send` shape.
fn build_signed_heartbeat(peer: &str, body: Value) -> anyhow::Result<Value> {
    use crate::config;
    let sk_seed = config::read_private_key()?;
    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let handle = crate::agent_card::display_handle_from_did(&did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;
    let trust = config::read_trust().unwrap_or_else(|_| json!({"agents": {}}));
    let to_did = crate::trust::resolve_peer_did(&trust, peer);
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now,
        "from": did,
        "to": to_did,
        "type": HEARTBEAT_TYPE,
        "kind": HEARTBEAT_KIND,
        "body": body,
    });
    Ok(crate::signing::sign_message_v31(
        &event, &sk_seed, &pk_bytes, &handle,
    )?)
}

/// Send a probe to `peer` (synchronous delivery). The caller then waits for the
/// matching probe_ack to land in the inbox.
pub fn send_probe(peer: &str, nonce: &str) -> anyhow::Result<()> {
    let signed = build_signed_heartbeat(peer, probe_body(nonce))?;
    crate::send::attempt_deliver(peer, &signed)?;
    Ok(())
}

/// Daemon-side auto-respond to verified inbound probes (RFC-004 AC-HP2 — no LLM
/// in the loop). For each `(peer, nonce)`, build+sign a probe_ack and deliver
/// it, rate-limited per peer (AC-HP3). Best-effort: one peer's failure never
/// aborts the rest, and never blocks the pull cycle.
pub fn respond_to_probes(probes: &[(String, String)]) {
    if probes.is_empty() {
        return;
    }
    let now = unix_secs();
    let map = ACK_RATE.get_or_init(|| Mutex::new(HashMap::new()));
    for (peer, nonce) in probes {
        let allowed = {
            let mut g = map.lock().unwrap_or_else(|e| e.into_inner());
            let times = g.entry(peer.clone()).or_default();
            record_ack_within_rate(times, now, ACK_WINDOW_SECS, ACK_MAX_PER_WINDOW)
        };
        if !allowed {
            continue;
        }
        match build_signed_heartbeat(peer, probe_ack_body(nonce)) {
            Ok(signed) => {
                if let Err(e) = crate::send::attempt_deliver(peer, &signed) {
                    eprintln!("wire: probe_ack to {peer} failed (non-fatal): {e:#}");
                }
            }
            Err(e) => eprintln!("wire: building probe_ack for {peer} failed (non-fatal): {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_nonce_extracts_only_real_probes() {
        let p = json!({"kind": 100, "type": "heartbeat", "body": {"t": "probe", "nonce": "abc"}});
        assert_eq!(probe_nonce(&p).as_deref(), Some("abc"));
        // Wrong kind.
        assert!(probe_nonce(&json!({"kind": 1, "body": {"t": "probe", "nonce": "x"}})).is_none());
        // Heartbeat but ack, not probe.
        assert!(
            probe_nonce(&json!({"kind": 100, "body": {"t": "probe_ack", "nonce": "x"}})).is_none()
        );
        // Heartbeat, unknown t (AC-HP4: ignored, not a probe).
        assert!(probe_nonce(&json!({"kind": 100, "body": {"t": "weird"}})).is_none());
        // Sealed body (no plaintext t) → ignored.
        assert!(probe_nonce(&json!({"kind": 100, "body": {"ct": "..."}})).is_none());
    }

    #[test]
    fn is_probe_ack_matches_kind_t_and_nonce() {
        let a = json!({"kind": 100, "body": {"t": "probe_ack", "nonce": "n1"}});
        assert!(is_probe_ack_for(&a, "n1"));
        assert!(!is_probe_ack_for(&a, "n2"), "nonce must match");
        // A probe (not ack) with the same nonce is not the ack.
        let p = json!({"kind": 100, "body": {"t": "probe", "nonce": "n1"}});
        assert!(!is_probe_ack_for(&p, "n1"));
    }

    #[test]
    fn ack_rate_gate_caps_a_flood() {
        // AC-HP3: with max=10 in the window, a 100-probe burst yields exactly 10 acks.
        let mut times: Vec<u64> = Vec::new();
        let now = 1_000u64;
        let mut acked = 0;
        for _ in 0..100 {
            if record_ack_within_rate(&mut times, now, 10, 10) {
                acked += 1;
            }
        }
        assert_eq!(acked, 10, "a 100-probe flood must be capped at 10 acks");
        // After the window, acks flow again.
        assert!(record_ack_within_rate(&mut times, now + 11, 10, 10));
    }
}
