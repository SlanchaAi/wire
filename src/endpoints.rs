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
    /// LAN-bound relay (e.g. `http://192.168.1.50:8771`). Reachable from
    /// other machines on the same network without going through federation.
    /// v0.7.0-alpha.9: third scope for noble-creek-on-paul-mac ↔
    /// running-light-on-spark style across-the-room pairing without
    /// wireup.net hop. Visible to anyone who fetches the agent-card —
    /// opt-in per session (operator passes `--with-lan-relay <url>` at
    /// `wire session new` time).
    Lan,
    /// Unix Domain Socket (e.g. `unix:///path/to/local.sock`). Same-host,
    /// same-uid only. v0.7.0-alpha.16: framed primarily as a SECURITY
    /// boundary — no bound TCP port (no firewall surface), SO_PEERCRED
    /// kernel-attested peer uid (sister-session trust anchor), 0600
    /// socket permissions. Performance win over loopback HTTP is real
    /// but tiny (~1.3µs) and not the headline reason. Opt-in via
    /// `wire session new --with-uds`; Unix-only (Windows falls back to
    /// Local loopback).
    Uds,
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

    /// v0.7.0-alpha.9: construct a LAN-scope endpoint.
    pub fn lan(relay_url: String, slot_id: String, slot_token: String) -> Self {
        Self {
            relay_url,
            slot_id,
            slot_token,
            scope: EndpointScope::Lan,
        }
    }

    /// v0.7.0-alpha.16: construct a UDS-scope endpoint.
    /// `relay_url` is a `unix:///abs/path/to/local.sock` URL (the
    /// `unix://` scheme is wire-internal; readers route to a UDS HTTP
    /// client rather than reqwest).
    pub fn uds(relay_url: String, slot_id: String, slot_token: String) -> Self {
        Self {
            relay_url,
            slot_id,
            slot_token,
            scope: EndpointScope::Uds,
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

    // RFC-006 Part B: `endpoints[]` is the only peer-routing source. The
    // former flat-field synthesis fallback (for pre-v0.5.16 pins with no
    // `endpoints` array) is gone — every pin now carries `endpoints[]`
    // (`pin_peer_endpoints` writes it; invite-accept routes through it too).

    // Sort: UDS (same-host trust anchor) first, then local-loopback-
    // with-matching-self-local, then LAN (cross-machine same-network),
    // then federation. Drop unreachable scopes via the retain pass.
    //
    // v0.7.0-alpha.9: LAN endpoints sit between Local and Federation.
    // Faster than federation; not gated by "our_local matches" because
    // cross-machine peers won't have a matching our-local by definition.
    //
    // v0.7.0-alpha.16: UDS endpoints get rank 0 when peer + self share
    // a UDS socket path (we need to be able to connect to their socket
    // which means it must be readable by our uid). The "same-uid same-
    // host" sister-session trust shape this enforces is the whole
    // point of UDS — see project_wire_transport_substrate_research.
    let our_local = our_local_relay_url.clone();
    all.sort_by_key(|ep| match (ep.scope, &our_local) {
        (EndpointScope::Uds, _) => 0,
        (EndpointScope::Local, Some(our)) if &ep.relay_url == our => 1,
        (EndpointScope::Lan, _) => 2,
        (EndpointScope::Federation, _) => 3,
        _ => 4,
    });
    // Drop unreachable: Local needs matching loopback URL; UDS needs
    // the socket file to exist on our filesystem (the daemon-side
    // connect will surface a clearer error than a routing-time drop
    // would, but we still keep UDS in the routing list — failure
    // falls through to lower-priority scopes).
    all.retain(|ep| match (ep.scope, &our_local) {
        (EndpointScope::Local, None) => false,
        (EndpointScope::Local, Some(our)) => &ep.relay_url == our,
        (EndpointScope::Lan, _) => true,
        (EndpointScope::Uds, _) => true,
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

/// v0.9 canonical single-reader for "my best inbound slot." Returns
/// the first endpoint from `self_endpoints()` — which is already
/// priority-ordered (UDS → Local-with-matching-self → LAN →
/// Federation) AND back-compat-falls-back to legacy top-level fields.
///
/// Replaces ad-hoc `self_state["relay_url"].as_str()` reads scattered
/// through the codebase. Pre-v0.9 those bare reads were the silent-
/// fail root cause: a session with only `self.endpoints[]` (no legacy
/// top-level fields) returned empty strings instead of the available
/// endpoint, and pair_drop_ack / pull / rotate-slot all silently
/// no-op'd. Always use this from new code.
pub fn self_primary_endpoint(relay_state: &Value) -> Option<Endpoint> {
    self_endpoints(relay_state).into_iter().next()
}

/// The single best (highest-priority) endpoint to reach `peer_handle`, or
/// `None` if the peer has no pinned endpoints. RFC-006 Part B: the canonical
/// replacement for reading the old flat `relay_url`/`slot_id`/`slot_token` peer
/// fields — every peer-pin reader resolves through this (or
/// `peer_endpoints_in_priority_order` when it needs failover).
pub fn peer_primary_endpoint(relay_state: &Value, peer_handle: &str) -> Option<Endpoint> {
    peer_endpoints_in_priority_order(relay_state, peer_handle)
        .into_iter()
        .next()
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
    let peers = relay_state
        .as_object_mut()
        .map(|m| {
            m.entry("peers")
                .or_insert_with(|| Value::Object(Default::default()))
        })
        .ok_or_else(|| anyhow::anyhow!("relay_state.json root is not an object"))?
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("relay_state.peers is not an object"))?;
    // v0.14.2 (#162 fix #5): preserve durable peer state across re-pin
    // events. honey-pine observed `wire_peers` tier flapping
    // VERIFIED → PENDING_ACK; root cause is this `peers.insert(.., entry)`
    // wholesale-replacement losing any previously-set field. The fields
    // we explicitly retain here represent monotonic state — once
    // bilateral-pair is complete or the peer's published persona/profile
    // is known, those facts must NOT be wiped just because a fresh
    // pair_drop_ack carrying only endpoint data lands. Other fields
    // (`relay_url`, `slot_id`, `slot_token`, `endpoints`) are always
    // current-state and intentionally re-derived from the input below.
    let preserved: serde_json::Map<String, Value> = peers
        .get(peer_handle)
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter(|(k, _)| {
                    matches!(
                        k.as_str(),
                        "bilateral_completed_at" | "persona" | "profile" | "first_seen_at"
                    )
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    // RFC-006 Part B: `endpoints[]` is the SINGLE peer-routing source. The
    // top-level flat `relay_url`/`slot_id`/`slot_token` fields are no longer
    // written — they were a redundant synthesized copy (the "stale flat beats
    // fresh array" routing hazard). All peer-pin readers now resolve through
    // `peer_endpoints_in_priority_order`. (Self-slot flat is a separate
    // representation, untouched here.)
    let mut entry = preserved;
    entry.insert("endpoints".into(), serde_json::to_value(endpoints)?);
    peers.insert(peer_handle.to_string(), Value::Object(entry));
    Ok(())
}

/// Infer an endpoint scope from a relay URL: `unix://` -> Uds, a loopback
/// host -> Local, otherwise Federation. LAN is never inferred (a private-
/// range IP is indistinguishable from a federation host by URL alone) and
/// must be requested explicitly.
pub fn infer_scope_from_url(url: &str) -> EndpointScope {
    if url.starts_with("unix://") {
        return EndpointScope::Uds;
    }
    let host = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    if host == "127.0.0.1" || host == "localhost" || host == "::1" {
        EndpointScope::Local
    } else {
        EndpointScope::Federation
    }
}

/// Build the `self` block for `relay_state.json` from an endpoint set:
/// the additive `endpoints[]` array plus legacy top-level
/// relay_url/slot_id/slot_token pointing at the federation endpoint (or,
/// absent one, the first endpoint) for v0.5.16-and-earlier back-compat.
fn build_self_value(eps: &[Endpoint]) -> Value {
    let legacy = eps
        .iter()
        .find(|e| e.scope == EndpointScope::Federation)
        .or_else(|| eps.first());
    let mut self_obj = serde_json::Map::new();
    if let Some(l) = legacy {
        self_obj.insert("relay_url".into(), Value::String(l.relay_url.clone()));
        self_obj.insert("slot_id".into(), Value::String(l.slot_id.clone()));
        self_obj.insert("slot_token".into(), Value::String(l.slot_token.clone()));
    }
    self_obj.insert(
        "endpoints".into(),
        serde_json::to_value(eps).unwrap_or(Value::Null),
    );
    Value::Object(self_obj)
}

/// Insert-or-replace one of OUR OWN endpoints in `relay_state["self"]`,
/// keyed by `relay_url` (re-binding the same relay updates it in place).
/// ADDITIVE: every other existing self endpoint is preserved, so an agent
/// can hold a local relay AND a federation relay at once. Rebuilds the
/// legacy top-level fields. Single source of truth for the self-slot write
/// shape — used by `cmd_bind_relay` and `init_self_idempotent`.
pub fn upsert_self_endpoint(relay_state: &mut Value, ep: Endpoint) {
    let mut eps = self_endpoints(relay_state);
    eps.retain(|e| e.relay_url != ep.relay_url);
    eps.push(ep);
    relay_state["self"] = build_self_value(&eps);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn infer_scope_classifies_loopback_unix_and_federation() {
        assert_eq!(
            infer_scope_from_url("http://127.0.0.1:8771"),
            EndpointScope::Local
        );
        assert_eq!(
            infer_scope_from_url("http://localhost:8771"),
            EndpointScope::Local
        );
        assert_eq!(
            infer_scope_from_url("unix:///tmp/wire.sock"),
            EndpointScope::Uds
        );
        assert_eq!(
            infer_scope_from_url("https://wireup.net"),
            EndpointScope::Federation
        );
    }

    #[test]
    fn upsert_self_endpoint_is_additive_then_updates_in_place() {
        let mut state = json!({});
        upsert_self_endpoint(
            &mut state,
            Endpoint::federation("https://wireup.net".into(), "fed1".into(), "ft".into()),
        );
        upsert_self_endpoint(
            &mut state,
            Endpoint::local("http://127.0.0.1:8771".into(), "loc1".into(), "lt".into()),
        );
        // Both kept.
        assert_eq!(self_endpoints(&state).len(), 2);
        // Legacy fields point at federation.
        assert_eq!(state["self"]["relay_url"], "https://wireup.net");
        // Re-binding the same relay replaces that one entry, not appends.
        upsert_self_endpoint(
            &mut state,
            Endpoint::local("http://127.0.0.1:8771".into(), "loc2".into(), "lt2".into()),
        );
        let eps = self_endpoints(&state);
        assert_eq!(eps.len(), 2, "same-relay rebind replaces, not appends");
        let loc = eps
            .iter()
            .find(|e| e.scope == EndpointScope::Local)
            .unwrap();
        assert_eq!(loc.slot_id, "loc2", "local slot updated in place");
    }

    #[test]
    fn peer_endpoints_ignores_flat_only_pin_post_rfc006() {
        // RFC-006 Part B: `endpoints[]` is the single peer-routing source. A
        // peer with ONLY the old flat fields and no `endpoints[]` array yields
        // NO endpoints — the synthesis fallback was removed. (No users to
        // migrate; every real pin now carries `endpoints[]`.)
        let state = json!({
            "peers": {
                "alice": { "relay_url": "https://wireup.net", "slot_id": "abc", "slot_token": "tok" }
            }
        });
        assert!(peer_endpoints_in_priority_order(&state, "alice").is_empty());
    }

    #[test]
    fn peer_endpoints_lan_beats_federation() {
        // v0.7.0-alpha.9: when a peer publishes both Lan and Federation
        // endpoints (and we have a matching local too), priority must be
        // Local(matched) > Lan > Federation. Lan is cross-machine same-
        // network, faster than federation but not as fast as loopback.
        let state = json!({
            "self": {
                "endpoints": [
                    {"relay_url": "http://127.0.0.1:8771", "slot_id": "self-loop", "slot_token": "t1", "scope": "local"},
                    {"relay_url": "https://wireup.net", "slot_id": "self-fed", "slot_token": "t2", "scope": "federation"}
                ]
            },
            "peers": {
                "alice": {
                    "endpoints": [
                        {"relay_url": "https://wireup.net", "slot_id": "a-fed", "slot_token": "ta-f", "scope": "federation"},
                        {"relay_url": "http://192.168.1.50:8771", "slot_id": "a-lan", "slot_token": "ta-l", "scope": "lan"},
                        {"relay_url": "http://127.0.0.1:8771", "slot_id": "a-loop", "slot_token": "ta-loop", "scope": "local"}
                    ]
                }
            }
        });
        let eps = peer_endpoints_in_priority_order(&state, "alice");
        assert_eq!(
            eps.len(),
            3,
            "Local(matched) + Lan + Federation all reachable"
        );
        assert_eq!(
            eps[0].scope,
            EndpointScope::Local,
            "loopback wins (same-machine)"
        );
        assert_eq!(
            eps[1].scope,
            EndpointScope::Lan,
            "Lan second (same-network)"
        );
        assert_eq!(
            eps[2].scope,
            EndpointScope::Federation,
            "Federation last (anywhere)"
        );
    }

    #[test]
    fn peer_endpoints_lan_kept_when_self_has_no_local() {
        // Cross-machine peer scenario: we have no Local, peer has Lan
        // and Federation. Lan must still be kept (we connect TO their
        // LAN address; we don't need a Local of our own to do so).
        let state = json!({
            "self": {
                "endpoints": [
                    {"relay_url": "https://wireup.net", "slot_id": "self-fed", "slot_token": "t1", "scope": "federation"}
                ]
            },
            "peers": {
                "alice": {
                    "endpoints": [
                        {"relay_url": "https://wireup.net", "slot_id": "a-fed", "slot_token": "ta-f", "scope": "federation"},
                        {"relay_url": "http://192.168.1.50:8771", "slot_id": "a-lan", "slot_token": "ta-l", "scope": "lan"}
                    ]
                }
            }
        });
        let eps = peer_endpoints_in_priority_order(&state, "alice");
        assert_eq!(eps.len(), 2);
        assert_eq!(
            eps[0].scope,
            EndpointScope::Lan,
            "Lan preferred over Federation"
        );
        assert_eq!(eps[1].scope, EndpointScope::Federation);
    }

    #[test]
    fn pin_peer_endpoints_writes_no_flat_fields_post_rfc006() {
        // RFC-006 Part B: pin writes `endpoints[]` ONLY — no synthesized
        // top-level relay_url/slot_id/slot_token. Routing reads the array.
        let mut state = json!({});
        let endpoints = vec![
            Endpoint::lan(
                "http://192.168.1.50:8771".to_string(),
                "lan-slot".to_string(),
                "lan-tok".to_string(),
            ),
            Endpoint::local(
                "http://127.0.0.1:8771".to_string(),
                "loop-slot".to_string(),
                "loop-tok".to_string(),
            ),
        ];
        pin_peer_endpoints(&mut state, "alice", &endpoints).unwrap();
        let alice = &state["peers"]["alice"];
        assert!(alice.get("relay_url").is_none(), "no flat relay_url");
        assert!(alice.get("slot_id").is_none(), "no flat slot_id");
        assert!(alice.get("slot_token").is_none(), "no flat slot_token");
        assert_eq!(
            alice["endpoints"].as_array().map(Vec::len),
            Some(2),
            "endpoints[] is the routing source"
        );
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
    fn pin_then_resolve_round_trips_through_endpoints_array() {
        // RFC-006 Part B: pin writes endpoints[]; routing resolves from it
        // (priority order), with NO flat fields involved on either side.
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
        assert!(alice.get("relay_url").is_none(), "no flat fields written");
        assert_eq!(alice["endpoints"].as_array().map(Vec::len), Some(2));
        // Resolve from the array (no flat). Without a matching self-local relay,
        // the peer's loopback endpoint isn't reachable for us, so federation is
        // the primary route.
        // Priority order drops the unreachable loopback (no matching
        // self-local), leaving the federation route.
        let ordered = peer_endpoints_in_priority_order(&state, "alice");
        assert_eq!(ordered.len(), 1, "only the reachable federation route");
        let primary = peer_primary_endpoint(&state, "alice").unwrap();
        assert_eq!(primary.scope, EndpointScope::Federation);
        assert_eq!(primary.slot_id, "abc");
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
