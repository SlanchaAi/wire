//! Multi-endpoint routing for v0.5.17 (dual-slot sessions).
//!
//! Each wire session can hold up to TWO slots:
//!   - **Federation** — on a public relay (default `https://wireup.net`),
//!     listed in the phonebook, reachable across machines.
//!   - **Local** — on a loopback relay (default `http://127.0.0.1:8771`,
//!     started with `wire relay-server --local-only`), invisible from
//!     off-box, sub-millisecond round-trip for same-machine sister-Claude
//!     traffic.
//!
//! Both slots are advertised to paired peers via the `pair_drop` body's
//! `endpoints[]` array (additive — v0.5.16-and-earlier peers see only
//! the federation endpoint at the top-level legacy fields, unchanged).
//!
//! Routing decision lives in `cmd_push`: walk a peer's pinned endpoints
//! in priority order (local first if we also have a local slot), POST
//! the event, fall back to the next endpoint on failure. Pulling: the
//! daemon reads from BOTH slots, dedupes by `event_id`.
//!
//! Storage shape in `relay_state.json` is purely additive:
//!
//! ```jsonc
//! {
//!   "self": {
//!     "relay_url": "https://wireup.net",     // legacy federation pointer
//!     "slot_id":   "abc...",
//!     "slot_token":"...",
//!     "endpoints": [                          // v0.5.17 additive
//!       {"relay_url": "https://wireup.net",     "slot_id": "abc...",  "slot_token": "...", "scope": "federation"},
//!       {"relay_url": "http://127.0.0.1:8771",  "slot_id": "loop...", "slot_token": "...", "scope": "local"}
//!     ]
//!   },
//!   "peers": {
//!     "wire-mesh": {
//!       "relay_url": "https://wireup.net",   // legacy back-compat
//!       "slot_id":   "...",
//!       "slot_token":"...",
//!       "endpoints": [...]                    // v0.5.17 additive
//!     }
//!   }
//! }
//! ```

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Where this endpoint sits in the reachability graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointScope {
    /// Public-facing relay (e.g. `https://wireup.net`). Crosses machines.
    Federation,
    /// Loopback-only relay (e.g. `http://127.0.0.1:8771`). Same-machine only.
    Local,
}

/// One reachable address for a wire identity. Includes the bearer
/// `slot_token` because endpoints flow through the pair_drop body,
/// which is encrypted at protocol level (signed envelope + bilateral
/// pin gate from v0.5.14). Token is the slot's bearer credential; it
/// MUST stay private to the pair and is never published in the agent
/// card or phonebook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub relay_url: String,
    pub slot_id: String,
    pub slot_token: String,
    pub scope: EndpointScope,
}

impl Endpoint {
    pub fn federation(relay_url: String, slot_id: String, slot_token: String) -> Self {
        Self {
            relay_url,
            slot_id,
            slot_token,
            scope: EndpointScope::Federation,
        }
    }

    pub fn local(relay_url: String, slot_id: String, slot_token: String) -> Self {
        Self {
            relay_url,
            slot_id,
            slot_token,
            scope: EndpointScope::Local,
        }
    }
}

/// Read all of a peer's pinned endpoints from `relay_state.json`,
/// sorted in routing priority order:
///
/// 1. Local endpoints first — only when we ALSO have a local slot
///    (i.e. our `self.endpoints` includes a local one with the same
///    relay_url). Otherwise local endpoints are skipped because we
///    can't reach them.
/// 2. Federation endpoints second.
///
/// Back-compat: peers stored by v0.5.16 or earlier have only the
/// top-level `relay_url`/`slot_id`/`slot_token`; this falls back to
/// synthesizing a single federation `Endpoint` from those fields.
pub fn peer_endpoints_in_priority_order(relay_state: &Value, peer_handle: &str) -> Vec<Endpoint> {
    let our_local_relay_url = relay_state
        .get("self")
        .and_then(|s| s.get("endpoints"))
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .find(|e| e.get("scope").and_then(Value::as_str) == Some("local"))
                .and_then(|e| e.get("relay_url"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });

    let peer = match relay_state.get("peers").and_then(|p| p.get(peer_handle)) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let mut all: Vec<Endpoint> = Vec::new();

    if let Some(arr) = peer.get("endpoints").and_then(Value::as_array) {
        for ep in arr {
            if let Ok(parsed) = serde_json::from_value::<Endpoint>(ep.clone()) {
                all.push(parsed);
            }
        }
    }

    // Back-compat: peer was pinned by v0.5.16 or earlier and has no
    // `endpoints` array, just the top-level legacy fields. Synthesize
    // one federation Endpoint from them so routing still finds a path.
    if all.is_empty() {
        let relay_url = peer.get("relay_url").and_then(Value::as_str).unwrap_or("");
        let slot_id = peer.get("slot_id").and_then(Value::as_str).unwrap_or("");
        let slot_token = peer.get("slot_token").and_then(Value::as_str).unwrap_or("");
        if !relay_url.is_empty() && !slot_id.is_empty() && !slot_token.is_empty() {
            all.push(Endpoint::federation(
                relay_url.to_string(),
                slot_id.to_string(),
                slot_token.to_string(),
            ));
        }
    }

    // Sort: local-with-matching-self-local first, then federation,
    // then any local we can't reach (filtered out by predicate).
    let our_local = our_local_relay_url.clone();
    all.sort_by_key(|ep| match (ep.scope, &our_local) {
        (EndpointScope::Local, Some(our)) if &ep.relay_url == our => 0,
        (EndpointScope::Federation, _) => 1,
        _ => 2,
    });
    // Drop unreachable locals (we have no local slot or our local relay
    // doesn't match the peer's local relay_url).
    all.retain(|ep| match (ep.scope, &our_local) {
        (EndpointScope::Local, None) => false,
        (EndpointScope::Local, Some(our)) => &ep.relay_url == our,
        (EndpointScope::Federation, _) => true,
    });
    all
}

/// All of OUR own endpoints from `relay_state.json`. Used by `cmd_push`
/// to find the local slot when routing local-first, and by the daemon's
/// pull loop to iterate every slot we should be reading from.
pub fn self_endpoints(relay_state: &Value) -> Vec<Endpoint> {
    let self_state = match relay_state.get("self") {
        Some(s) if !s.is_null() => s,
        _ => return Vec::new(),
    };
    let mut all: Vec<Endpoint> = Vec::new();
    if let Some(arr) = self_state.get("endpoints").and_then(Value::as_array) {
        for ep in arr {
            if let Ok(parsed) = serde_json::from_value::<Endpoint>(ep.clone()) {
                all.push(parsed);
            }
        }
    }
    if all.is_empty() {
        // Back-compat: synthesize a federation endpoint from legacy
        // top-level fields. Slot_token may be absent in some old
        // states; in that case the synthesized endpoint is partial
        // and downstream code must guard against empty token.
        let relay_url = self_state
            .get("relay_url")
            .and_then(Value::as_str)
            .unwrap_or("");
        let slot_id = self_state
            .get("slot_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let slot_token = self_state
            .get("slot_token")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !relay_url.is_empty() && !slot_id.is_empty() {
            all.push(Endpoint::federation(
                relay_url.to_string(),
                slot_id.to_string(),
                slot_token.to_string(),
            ));
        }
    }
    all
}

/// Pin a peer's full set of endpoints into `relay_state.json` under
/// `peers[handle]`. Preserves the v0.5.16-and-earlier `relay_url` /
/// `slot_id` / `slot_token` top-level fields (pointing at the
/// federation endpoint) so older code paths and back-compat readers
/// don't break. The new `endpoints` array is additive.
pub fn pin_peer_endpoints(
    relay_state: &mut Value,
    peer_handle: &str,
    endpoints: &[Endpoint],
) -> Result<()> {
    // Pick the federation endpoint (if any) to fill the legacy fields.
    let fed = endpoints
        .iter()
        .find(|e| e.scope == EndpointScope::Federation);
    let peers = relay_state
        .as_object_mut()
        .map(|m| {
            m.entry("peers")
                .or_insert_with(|| Value::Object(Default::default()))
        })
        .ok_or_else(|| anyhow::anyhow!("relay_state.json root is not an object"))?
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("relay_state.peers is not an object"))?;
    let mut entry = serde_json::Map::new();
    if let Some(f) = fed {
        entry.insert("relay_url".into(), Value::String(f.relay_url.clone()));
        entry.insert("slot_id".into(), Value::String(f.slot_id.clone()));
        entry.insert("slot_token".into(), Value::String(f.slot_token.clone()));
    } else if let Some(loc) = endpoints.iter().find(|e| e.scope == EndpointScope::Local) {
        // No federation endpoint? Use the local one as the legacy field
        // values. This case is unusual (peer would be unreachable from
        // other machines), but keeps the schema invariant intact.
        entry.insert("relay_url".into(), Value::String(loc.relay_url.clone()));
        entry.insert("slot_id".into(), Value::String(loc.slot_id.clone()));
        entry.insert("slot_token".into(), Value::String(loc.slot_token.clone()));
    }
    entry.insert("endpoints".into(), serde_json::to_value(endpoints)?);
    peers.insert(peer_handle.to_string(), Value::Object(entry));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn peer_endpoints_back_compat_falls_back_to_legacy_fields() {
        let state = json!({
            "peers": {
                "alice": {
                    "relay_url": "https://wireup.net",
                    "slot_id": "abc",
                    "slot_token": "tok"
                }
            }
        });
        let eps = peer_endpoints_in_priority_order(&state, "alice");
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].relay_url, "https://wireup.net");
        assert_eq!(eps[0].scope, EndpointScope::Federation);
    }

    #[test]
    fn peer_endpoints_orders_local_first_when_self_has_matching_local() {
        let state = json!({
            "self": {
                "endpoints": [
                    {"relay_url": "https://wireup.net",    "slot_id": "self-fed",  "slot_token": "t1", "scope": "federation"},
                    {"relay_url": "http://127.0.0.1:8771", "slot_id": "self-loop", "slot_token": "t2", "scope": "local"}
                ]
            },
            "peers": {
                "alice": {
                    "endpoints": [
                        {"relay_url": "https://wireup.net",    "slot_id": "a-fed",  "slot_token": "ta1", "scope": "federation"},
                        {"relay_url": "http://127.0.0.1:8771", "slot_id": "a-loop", "slot_token": "ta2", "scope": "local"}
                    ]
                }
            }
        });
        let eps = peer_endpoints_in_priority_order(&state, "alice");
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].scope, EndpointScope::Local);
        assert_eq!(eps[1].scope, EndpointScope::Federation);
    }

    #[test]
    fn peer_endpoints_drops_local_when_self_has_no_local() {
        let state = json!({
            "self": {
                "endpoints": [
                    {"relay_url": "https://wireup.net", "slot_id": "self-fed", "slot_token": "t1", "scope": "federation"}
                ]
            },
            "peers": {
                "alice": {
                    "endpoints": [
                        {"relay_url": "https://wireup.net",    "slot_id": "a-fed",  "slot_token": "ta1", "scope": "federation"},
                        {"relay_url": "http://127.0.0.1:8771", "slot_id": "a-loop", "slot_token": "ta2", "scope": "local"}
                    ]
                }
            }
        });
        let eps = peer_endpoints_in_priority_order(&state, "alice");
        // Only federation reachable: local was filtered.
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].scope, EndpointScope::Federation);
    }

    #[test]
    fn peer_endpoints_drops_local_when_relay_urls_dont_match() {
        let state = json!({
            "self": {
                "endpoints": [
                    {"relay_url": "http://127.0.0.1:8771", "slot_id": "self-loop", "slot_token": "t2", "scope": "local"}
                ]
            },
            "peers": {
                "alice": {
                    "endpoints": [
                        {"relay_url": "http://127.0.0.1:9999", "slot_id": "a-loop", "slot_token": "ta2", "scope": "local"}
                    ]
                }
            }
        });
        // Our local is :8771, peer's local is :9999 — can't route there.
        let eps = peer_endpoints_in_priority_order(&state, "alice");
        assert_eq!(
            eps.len(),
            0,
            "different local relays cannot reach each other"
        );
    }

    #[test]
    fn pin_peer_endpoints_preserves_legacy_top_level_fields() {
        let mut state = json!({"peers": {}});
        let endpoints = vec![
            Endpoint::federation("https://wireup.net".into(), "abc".into(), "tok".into()),
            Endpoint::local(
                "http://127.0.0.1:8771".into(),
                "loop".into(),
                "loop-tok".into(),
            ),
        ];
        pin_peer_endpoints(&mut state, "alice", &endpoints).unwrap();
        let alice = &state["peers"]["alice"];
        // Legacy fields point at the federation endpoint.
        assert_eq!(alice["relay_url"], "https://wireup.net");
        assert_eq!(alice["slot_id"], "abc");
        assert_eq!(alice["slot_token"], "tok");
        // Endpoints array carries the full set.
        let eps = alice["endpoints"].as_array().unwrap();
        assert_eq!(eps.len(), 2);
    }

    #[test]
    fn self_endpoints_back_compat_falls_back_to_legacy_fields() {
        let state = json!({
            "self": {
                "relay_url": "https://wireup.net",
                "slot_id": "self-fed",
                "slot_token": "t1"
            }
        });
        let eps = self_endpoints(&state);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].scope, EndpointScope::Federation);
        assert_eq!(eps[0].slot_id, "self-fed");
    }

    #[test]
    fn self_endpoints_returns_both_when_dual_slot() {
        let state = json!({
            "self": {
                "endpoints": [
                    {"relay_url": "https://wireup.net",    "slot_id": "self-fed",  "slot_token": "t1", "scope": "federation"},
                    {"relay_url": "http://127.0.0.1:8771", "slot_id": "self-loop", "slot_token": "t2", "scope": "local"}
                ]
            }
        });
        let eps = self_endpoints(&state);
        assert_eq!(eps.len(), 2);
    }
}
