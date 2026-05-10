// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (C) 2026  wire contributors.
//
// This file (and only this file in the wire repository) is licensed under
// the GNU Affero General Public License v3.0 or later. The protocol crate
// (signing, agent_card, trust, canonical, cli, mcp) is Apache-2.0; the CLI
// binary entry point is MIT. See LICENSE.md for the trio explanation.
//
// AGPL on the relay specifically discourages forks that operate `wire-relay`
// as a closed-source SaaS offering — those forks must publish their changes
// under AGPL too. Self-hosting your own relay for your own org or running
// the public-good relay we operate is fully permitted.
//
//! HTTP mailbox relay — minimal, persistent, bearer-authenticated.
//!
//! Design (v0.1):
//!   - One process serves N slots; each slot is a per-peer FIFO of signed events.
//!   - Slot allocation returns `(slot_id, slot_token)`. Holder of the token
//!     can post + read that slot. Tokens never expire in v0.1 (rotate by
//!     allocating a new slot).
//!   - Events are stored verbatim — the relay does NOT verify Ed25519 signatures
//!     itself. Verification happens client-side (`wire tail` + `verify_message_v31`).
//!     The relay is dumb on purpose: it is a content-addressed mailbox, not a
//!     trust authority.
//!   - 256 KiB max body per event.
//!   - Persistence: each slot's events are appended to
//!     `<state_dir>/slots/<slot_id>.jsonl` on every `POST /events`. Tokens
//!     are persisted to `<state_dir>/tokens.json` on allocation.
//!   - On startup, slots + tokens are reloaded from disk.

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
    routing::{get, post},
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

const MAX_EVENT_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct Relay {
    inner: Arc<Mutex<Inner>>,
    state_dir: PathBuf,
}

struct Inner {
    /// slot_id -> ordered list of stored events (parsed JSON Values).
    slots: HashMap<String, Vec<Value>>,
    /// slot_id -> bearer token. Token holder may read + write that slot.
    tokens: HashMap<String, String>,
    /// code_hash -> pair_id (lookup so guests find the host).
    pair_lookup: HashMap<String, String>,
    /// pair_id -> ephemeral pairing state.
    pair_slots: HashMap<String, PairSlot>,
}

#[derive(Clone, Debug, Default)]
struct PairSlot {
    /// SPAKE2 message from the host side.
    host_msg: Option<String>,
    /// SPAKE2 message from the guest side.
    guest_msg: Option<String>,
    /// Sealed bootstrap payload from host (after SAS confirm).
    host_bootstrap: Option<String>,
    /// Sealed bootstrap payload from guest.
    guest_bootstrap: Option<String>,
}

#[derive(Deserialize)]
pub struct AllocateRequest {
    /// Optional handle hint — purely informational, server doesn't enforce.
    #[serde(default)]
    pub handle: Option<String>,
}

#[derive(Deserialize)]
pub struct PostEventRequest {
    pub event: Value,
}

#[derive(Deserialize)]
pub struct ListEventsQuery {
    /// Resume from after this event_id (exclusive). Omit for full slot read.
    pub since: Option<String>,
    /// Max events to return. Default 100, max 1000.
    pub limit: Option<usize>,
}

impl Relay {
    pub async fn new(state_dir: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(state_dir.join("slots")).await?;
        let mut inner = Inner {
            slots: HashMap::new(),
            tokens: HashMap::new(),
            pair_lookup: HashMap::new(),
            pair_slots: HashMap::new(),
        };
        // Reload tokens
        let token_path = state_dir.join("tokens.json");
        if token_path.exists() {
            let body = tokio::fs::read_to_string(&token_path).await?;
            inner.tokens = serde_json::from_str(&body).unwrap_or_default();
        }
        // Reload slots from JSONL
        let mut slots_dir = tokio::fs::read_dir(state_dir.join("slots")).await?;
        while let Some(entry) = slots_dir.next_entry().await? {
            let path = entry.path();
            if path.extension().map(|x| x != "jsonl").unwrap_or(true) {
                continue;
            }
            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let body = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            let mut events = Vec::new();
            for line in body.lines() {
                if let Ok(v) = serde_json::from_str::<Value>(line) {
                    events.push(v);
                }
            }
            inner.slots.insert(stem, events);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            state_dir,
        })
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/healthz", get(healthz))
            .route("/v1/slot/allocate", post(allocate_slot))
            .route("/v1/events/:slot_id", post(post_event).get(list_events))
            .route("/v1/pair", post(pair_open))
            .route("/v1/pair/:pair_id", get(pair_get))
            .route("/v1/pair/:pair_id/bootstrap", post(pair_bootstrap))
            .with_state(self)
    }

    async fn persist_tokens(&self) -> Result<()> {
        let body = {
            let inner = self.inner.lock().await;
            serde_json::to_string_pretty(&inner.tokens)?
        };
        let path = self.state_dir.join("tokens.json");
        tokio::fs::write(path, body).await?;
        Ok(())
    }

    async fn append_event_to_disk(&self, slot_id: &str, event: &Value) -> Result<()> {
        let path = self.state_dir.join("slots").join(format!("{slot_id}.jsonl"));
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        use tokio::io::AsyncWriteExt;
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("opening {path:?}"))?;
        f.write_all(&line).await?;
        f.flush().await?;
        Ok(())
    }
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn allocate_slot(
    State(relay): State<Relay>,
    Json(_req): Json<AllocateRequest>,
) -> impl IntoResponse {
    let slot_id = random_hex(16);
    let slot_token = random_hex(32);
    {
        let mut inner = relay.inner.lock().await;
        inner.slots.insert(slot_id.clone(), Vec::new());
        inner.tokens.insert(slot_id.clone(), slot_token.clone());
    }
    if let Err(e) = relay.persist_tokens().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("persist failed: {e}")})),
        )
            .into_response();
    }
    (
        StatusCode::CREATED,
        Json(json!({"slot_id": slot_id, "slot_token": slot_token})),
    )
        .into_response()
}

async fn post_event(
    State(relay): State<Relay>,
    Path(slot_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<PostEventRequest>,
) -> impl IntoResponse {
    if let Err(resp) = check_token(&relay, &headers, &slot_id).await {
        return resp;
    }
    // Body size cap (rough; serialize and check).
    let body_bytes = match serde_json::to_vec(&req.event) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("event not serializable: {e}")})),
            )
                .into_response();
        }
    };
    if body_bytes.len() > MAX_EVENT_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error": "event exceeds 256 KiB", "max_bytes": MAX_EVENT_BYTES})),
        )
            .into_response();
    }
    let event_id = req
        .event
        .get("event_id")
        .and_then(Value::as_str)
        .map(str::to_string);

    // Dedupe by event_id if present.
    let dup = {
        let inner = relay.inner.lock().await;
        let slot = inner.slots.get(&slot_id);
        if let (Some(eid), Some(slot)) = (&event_id, slot) {
            slot.iter()
                .any(|e| e.get("event_id").and_then(Value::as_str) == Some(eid))
        } else {
            false
        }
    };
    if dup {
        return (
            StatusCode::OK,
            Json(json!({"event_id": event_id, "status": "duplicate"})),
        )
            .into_response();
    }

    {
        let mut inner = relay.inner.lock().await;
        let slot = inner.slots.entry(slot_id.clone()).or_default();
        slot.push(req.event.clone());
    }
    if let Err(e) = relay.append_event_to_disk(&slot_id, &req.event).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("persist failed: {e}")})),
        )
            .into_response();
    }
    (
        StatusCode::CREATED,
        Json(json!({"event_id": event_id, "status": "stored"})),
    )
        .into_response()
}

// ---------- pair-slot handlers ----------

#[derive(Deserialize)]
pub struct PairOpenRequest {
    pub code_hash: String,
    /// SPAKE2 message (base64).
    pub msg: String,
    pub role: String, // "host" or "guest"
}

#[derive(Deserialize)]
pub struct PairBootstrapRequest {
    pub role: String,
    pub sealed: String,
}

async fn pair_open(
    State(relay): State<Relay>,
    Json(req): Json<PairOpenRequest>,
) -> impl IntoResponse {
    if req.role != "host" && req.role != "guest" {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "role must be 'host' or 'guest'"}))).into_response();
    }
    let mut inner = relay.inner.lock().await;
    let pair_id = match inner.pair_lookup.get(&req.code_hash).cloned() {
        Some(id) => id,
        None => {
            let new_id = random_hex(16);
            inner.pair_lookup.insert(req.code_hash.clone(), new_id.clone());
            inner.pair_slots.insert(new_id.clone(), PairSlot::default());
            new_id
        }
    };
    let slot = inner.pair_slots.entry(pair_id.clone()).or_default();
    if req.role == "host" {
        if slot.host_msg.is_some() {
            return (StatusCode::CONFLICT, Json(json!({"error": "host already registered for this code"}))).into_response();
        }
        slot.host_msg = Some(req.msg);
    } else {
        if slot.guest_msg.is_some() {
            return (StatusCode::CONFLICT, Json(json!({"error": "guest already registered for this code"}))).into_response();
        }
        slot.guest_msg = Some(req.msg);
    }
    (StatusCode::CREATED, Json(json!({"pair_id": pair_id}))).into_response()
}

#[derive(Deserialize)]
pub struct PairGetQuery {
    /// "host" or "guest" — caller's role; we return the OTHER side's data.
    pub as_role: String,
}

async fn pair_get(
    State(relay): State<Relay>,
    Path(pair_id): Path<String>,
    Query(q): Query<PairGetQuery>,
) -> impl IntoResponse {
    let inner = relay.inner.lock().await;
    let slot = match inner.pair_slots.get(&pair_id) {
        Some(s) => s.clone(),
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown pair_id"}))).into_response(),
    };
    let (peer_msg, peer_bootstrap) = match q.as_role.as_str() {
        "host" => (slot.guest_msg, slot.guest_bootstrap),
        "guest" => (slot.host_msg, slot.host_bootstrap),
        _ => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "as_role must be 'host' or 'guest'"}))).into_response();
        }
    };
    (
        StatusCode::OK,
        Json(json!({"peer_msg": peer_msg, "peer_bootstrap": peer_bootstrap})),
    )
        .into_response()
}

async fn pair_bootstrap(
    State(relay): State<Relay>,
    Path(pair_id): Path<String>,
    Json(req): Json<PairBootstrapRequest>,
) -> impl IntoResponse {
    let mut inner = relay.inner.lock().await;
    let slot = match inner.pair_slots.get_mut(&pair_id) {
        Some(s) => s,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown pair_id"}))).into_response(),
    };
    match req.role.as_str() {
        "host" => slot.host_bootstrap = Some(req.sealed),
        "guest" => slot.guest_bootstrap = Some(req.sealed),
        _ => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "role must be 'host' or 'guest'"}))).into_response();
        }
    }
    (StatusCode::CREATED, Json(json!({"ok": true}))).into_response()
}

async fn list_events(
    State(relay): State<Relay>,
    Path(slot_id): Path<String>,
    Query(q): Query<ListEventsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = check_token(&relay, &headers, &slot_id).await {
        return resp;
    }
    let limit = q.limit.unwrap_or(100).min(1000);
    let inner = relay.inner.lock().await;
    let events = inner.slots.get(&slot_id).cloned().unwrap_or_default();
    let start = match q.since {
        Some(eid) => events
            .iter()
            .position(|e| e.get("event_id").and_then(Value::as_str) == Some(&eid))
            .map(|i| i + 1)
            .unwrap_or(0),
        None => 0,
    };
    let end = (start + limit).min(events.len());
    let slice = events[start..end].to_vec();
    (StatusCode::OK, Json(slice)).into_response()
}

async fn check_token(
    relay: &Relay,
    headers: &HeaderMap,
    slot_id: &str,
) -> std::result::Result<(), axum::response::Response> {
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_string);
    let presented = match auth {
        Some(t) => t,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing Bearer token"})),
            )
                .into_response());
        }
    };
    let inner = relay.inner.lock().await;
    let expected = match inner.tokens.get(slot_id) {
        Some(t) => t.clone(),
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown slot"})),
            )
                .into_response());
        }
    };
    drop(inner);
    if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "bad token"})),
        )
            .into_response());
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Run the relay until SIGINT/SIGTERM.
pub async fn serve(bind: &str, state_dir: PathBuf) -> Result<()> {
    let relay = Relay::new(state_dir).await?;
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    eprintln!("wire relay-server listening on {bind}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("\nshutting down");
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd")); // length mismatch
    }

    #[test]
    fn random_hex_length() {
        let s = random_hex(16);
        assert_eq!(s.len(), 32); // 16 bytes -> 32 hex chars
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
