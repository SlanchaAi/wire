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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::GlobalKeyExtractor,
};

const MAX_EVENT_BYTES: usize = 256 * 1024;
/// Total bytes a single slot can hold before further POSTs are rejected (413).
/// Defends against an abusive bearer-holder filling relay disk (T11). At 64 MB
/// per slot, an attacker pushing the rate-limit ceiling fills their own slot
/// in ~25 seconds, then gets 413 forever — disk impact bounded.
const MAX_SLOT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct Relay {
    inner: Arc<Mutex<Inner>>,
    state_dir: PathBuf,
    counters: Arc<RelayCounters>,
}

/// Lock-free usage counters served by GET /stats. Counter values are
/// loaded from `<state_dir>/counters.json` on startup and snapshotted back
/// to disk every 30s by `spawn_counter_persister`, so deploys + restarts
/// don't reset them. `boot_unix` is per-process — uptime is process-local.
struct RelayCounters {
    boot_unix: u64,
    handle_claims_total: AtomicU64,
    handle_first_claims_total: AtomicU64,
    slot_allocations_total: AtomicU64,
    pair_opens_total: AtomicU64,
    events_posted_total: AtomicU64,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct CountersSnapshot {
    handle_claims_total: u64,
    handle_first_claims_total: u64,
    slot_allocations_total: u64,
    pair_opens_total: u64,
    events_posted_total: u64,
}

/// One row in `<state_dir>/stats-history.jsonl` — written every 30s by
/// `spawn_counter_persister` so /stats.html can draw sparklines. Live-state
/// fields (`*_active`) are point-in-time; *_total fields are the cumulative
/// counters at that timestamp. Field names mirror the /stats endpoint.
#[derive(serde::Serialize, serde::Deserialize)]
struct HistoryEntry {
    ts: u64,
    handles_active: usize,
    slots_active: usize,
    pair_slots_open: usize,
    streams_active: usize,
    handle_claims_total: u64,
    handle_first_claims_total: u64,
    slot_allocations_total: u64,
    pair_opens_total: u64,
    events_posted_total: u64,
}

#[derive(Deserialize)]
pub struct StatsHistoryQuery {
    /// How many hours of history to return, default 24, max 168 (7 days).
    pub hours: Option<u64>,
}

struct Inner {
    /// slot_id -> ordered list of stored events (parsed JSON Values).
    slots: HashMap<String, Vec<Value>>,
    /// slot_id -> bearer token. Token holder may read + write that slot.
    tokens: HashMap<String, String>,
    /// slot_id -> total bytes stored. Enforced against MAX_SLOT_BYTES.
    slot_bytes: HashMap<String, usize>,
    /// slot_id -> wall-clock unix seconds of the slot owner's last `list_events`
    /// call. Used by `GET /v1/slot/:slot_id/state` so a remote sender can
    /// gauge whether the slot's owner is still polling (i.e., still attentive).
    /// `None` means the slot has never been pulled since the relay restarted.
    last_pull_at_unix: HashMap<String, u64>,
    /// slot_id -> active SSE subscribers (R1 push). Each `UnboundedSender`
    /// belongs to one open `GET /v1/events/:slot_id/stream` connection.
    /// On every successful `post_event` to a slot we walk the slot's list
    /// and broadcast the event; closed channels are pruned lazily on send-
    /// error. Auth: subscribers presented a valid slot_token at stream open.
    streams: HashMap<String, Vec<tokio::sync::mpsc::UnboundedSender<Value>>>,
    /// code_hash -> pair_id (lookup so guests find the host).
    pair_lookup: HashMap<String, String>,
    /// pair_id -> ephemeral pairing state.
    pair_slots: HashMap<String, PairSlot>,
    /// nick -> registered handle directory entry (v0.5).
    handles: HashMap<String, HandleRecord>,
    /// slot_id -> latest operator-published auto-responder health record (R3).
    responder_health: HashMap<String, ResponderHealthRecord>,
    /// token -> short-URL invite record (v0.5.10 — one-curl onboarding).
    /// Token is the path segment in `GET /i/{token}`. Record holds the
    /// underlying `wire://pair?...` URL plus TTL/uses bookkeeping.
    invites: HashMap<String, InviteRecord>,
}

/// One entry in the short-URL invite map. Persisted to
/// `<state_dir>/invites.jsonl` so deploys don't drop active invites.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct InviteRecord {
    token: String,
    invite_url: String,
    expires_unix: u64,
    /// `None` = unlimited until TTL hits. `Some(n)` = decrement each fetch.
    uses_remaining: Option<u32>,
    created_unix: u64,
}

/// One entry in the relay's handle directory (v0.5 — agentic hotline).
/// FCFS on nick: first claimant binds the nick to their DID. Same-DID re-claims
/// are allowed (used for profile updates + slot rotation).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct HandleRecord {
    pub nick: String,
    pub did: String,
    pub card: Value,
    pub slot_id: String,
    pub relay_url: Option<String>,
    pub claimed_at: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ResponderHealthRecord {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    pub set_at: String,
}

#[derive(Clone, Debug)]
struct PairSlot {
    /// SPAKE2 message from the host side.
    host_msg: Option<String>,
    /// SPAKE2 message from the guest side.
    guest_msg: Option<String>,
    /// Sealed bootstrap payload from host (after SAS confirm).
    host_bootstrap: Option<String>,
    /// Sealed bootstrap payload from guest.
    guest_bootstrap: Option<String>,
    /// Last activity time (monotonic) — used for TTL eviction.
    last_touched: std::time::Instant,
}

impl Default for PairSlot {
    fn default() -> Self {
        Self {
            host_msg: None,
            guest_msg: None,
            host_bootstrap: None,
            guest_bootstrap: None,
            last_touched: std::time::Instant::now(),
        }
    }
}

/// Pair-slot idle TTL. After this many seconds without activity, the slot
/// is evicted to free memory + bound brute-force surface (PENTEST.md §code-review #3).
const PAIR_SLOT_TTL_SECS: u64 = 300;

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
        tokio::fs::create_dir_all(state_dir.join("handles")).await?;
        tokio::fs::create_dir_all(state_dir.join("responder-health")).await?;
        let mut inner = Inner {
            slots: HashMap::new(),
            tokens: HashMap::new(),
            slot_bytes: HashMap::new(),
            last_pull_at_unix: HashMap::new(),
            streams: HashMap::new(),
            pair_lookup: HashMap::new(),
            pair_slots: HashMap::new(),
            handles: HashMap::new(),
            responder_health: HashMap::new(),
            invites: HashMap::new(),
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
            // Recompute byte usage for the slot from its persisted events.
            let bytes: usize = events
                .iter()
                .map(|e| serde_json::to_vec(e).map(|v| v.len()).unwrap_or(0))
                .sum();
            inner.slot_bytes.insert(stem.clone(), bytes);
            inner.slots.insert(stem, events);
        }
        // Reload handle directory (v0.5).
        let handles_dir = state_dir.join("handles");
        if handles_dir.exists() {
            let mut rd = tokio::fs::read_dir(&handles_dir).await?;
            while let Some(entry) = rd.next_entry().await? {
                let path = entry.path();
                if path.extension().and_then(|x| x.to_str()) != Some("json") {
                    continue;
                }
                let body = tokio::fs::read_to_string(&path).await.unwrap_or_default();
                if let Ok(rec) = serde_json::from_str::<HandleRecord>(&body) {
                    inner.handles.insert(rec.nick.clone(), rec);
                }
            }
        }
        // Reload responder health records (R3).
        let responder_health_dir = state_dir.join("responder-health");
        if responder_health_dir.exists() {
            let mut rd = tokio::fs::read_dir(&responder_health_dir).await?;
            while let Some(entry) = rd.next_entry().await? {
                let path = entry.path();
                if path.extension().and_then(|x| x.to_str()) != Some("json") {
                    continue;
                }
                let Some(slot_id) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                let body = tokio::fs::read_to_string(&path).await.unwrap_or_default();
                if let Ok(rec) = serde_json::from_str::<ResponderHealthRecord>(&body) {
                    inner.responder_health.insert(slot_id.to_string(), rec);
                }
            }
        }
        // Reload short-URL invites. JSONL append-only; later entries with
        // the same token overwrite earlier (won't happen — tokens are
        // unique by construction — but coded defensively).
        let invites_path = state_dir.join("invites.jsonl");
        if invites_path.exists() {
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let body = tokio::fs::read_to_string(&invites_path)
                .await
                .unwrap_or_default();
            for line in body.lines() {
                if let Ok(rec) = serde_json::from_str::<InviteRecord>(line)
                    && rec.expires_unix > now_unix
                {
                    inner.invites.insert(rec.token.clone(), rec);
                }
            }
        }
        let boot_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Reload counter snapshot. Missing/corrupt file → start at zero.
        let snap: CountersSnapshot =
            match tokio::fs::read_to_string(state_dir.join("counters.json")).await {
                Ok(body) => serde_json::from_str(&body).unwrap_or_default(),
                Err(_) => CountersSnapshot::default(),
            };
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            state_dir,
            counters: Arc::new(RelayCounters {
                boot_unix,
                handle_claims_total: AtomicU64::new(snap.handle_claims_total),
                handle_first_claims_total: AtomicU64::new(snap.handle_first_claims_total),
                slot_allocations_total: AtomicU64::new(snap.slot_allocations_total),
                pair_opens_total: AtomicU64::new(snap.pair_opens_total),
                events_posted_total: AtomicU64::new(snap.events_posted_total),
            }),
        })
    }

    pub fn router(self) -> Router {
        // Rate limit applied to write endpoints that create new state (slots,
        // pair-sessions, bootstraps). 10 req/sec sustained, 50 req burst.
        // v0.1 uses the GLOBAL key extractor (single bucket for all callers) —
        // per-IP needs ConnectInfo middleware which axum 0.7 wires differently.
        // Per-IP keying is a v0.2 hardening; for now Cloudflare WAF + this
        // global cap shoulder DDoS protection in series.
        let governor_conf = std::sync::Arc::new(
            GovernorConfigBuilder::default()
                .per_second(10)
                .burst_size(50)
                .key_extractor(GlobalKeyExtractor)
                .finish()
                .expect("valid governor config"),
        );
        let governor_layer = GovernorLayer {
            config: governor_conf,
        };

        // Hot writes group — rate limited.
        let hot_writes = Router::new()
            .route("/v1/slot/allocate", post(allocate_slot))
            .route("/v1/pair", post(pair_open))
            .route("/v1/pair/:pair_id/bootstrap", post(pair_bootstrap))
            .route("/v1/pair/abandon", post(pair_abandon))
            .layer(governor_layer);

        Router::new()
            .route("/", get(landing_index))
            .route("/favicon.svg", get(landing_favicon))
            .route("/og.png", get(landing_og))
            .route("/demo.cast", get(landing_demo_cast))
            .route("/install", get(landing_install_sh))
            .route("/install.sh", get(landing_install_sh))
            .route("/healthz", get(healthz))
            .route("/stats", get(stats_root))
            .route("/stats.json", get(stats_json))
            .route("/stats.html", get(landing_stats_html))
            .route("/stats.history", get(stats_history))
            .route("/phonebook", get(landing_phonebook_html))
            .route("/phonebook.html", get(landing_phonebook_html))
            .route("/v1/events/:slot_id", post(post_event).get(list_events))
            .route("/v1/slot/:slot_id/state", get(slot_state))
            .route(
                "/v1/slot/:slot_id/responder-health",
                post(responder_health_set),
            )
            .route("/v1/events/:slot_id/stream", get(stream_events))
            .route("/v1/pair/:pair_id", get(pair_get))
            .route("/v1/handle/claim", post(handle_claim))
            .route("/v1/handle/intro/:nick", post(handle_intro))
            .route("/v1/handles", get(handles_directory))
            .route("/v1/invite/register", post(invite_register))
            .route("/i/:token", get(invite_script))
            .route("/.well-known/wire/agent", get(well_known_agent))
            .route(
                "/.well-known/agent-card.json",
                get(well_known_agent_card_a2a),
            )
            .merge(hot_writes)
            .with_state(self)
    }

    /// Evict pair-slots that have been idle past `PAIR_SLOT_TTL_SECS`.
    /// Called inline on every pair-slot mutation; a background sweeper task
    /// (see `Self::start_sweeper`) covers the long-idle case.
    async fn evict_expired_pair_slots(&self) {
        let now = std::time::Instant::now();
        let ttl = std::time::Duration::from_secs(PAIR_SLOT_TTL_SECS);
        let mut inner = self.inner.lock().await;
        let mut to_remove = Vec::new();
        for (id, slot) in inner.pair_slots.iter() {
            if now.duration_since(slot.last_touched) > ttl {
                to_remove.push(id.clone());
            }
        }
        for id in to_remove {
            inner.pair_slots.remove(&id);
            inner.pair_lookup.retain(|_, v| v != &id);
        }
    }

    /// Spawn a background tokio task that runs `evict_expired_pair_slots` every
    /// 60 seconds. Call once after `Relay::new`; the handle is leaked deliberately
    /// — process exit reaps it. Safe to skip in tests where you'd rather test
    /// eviction inline.
    pub fn spawn_pair_sweeper(&self) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                me.evict_expired_pair_slots().await;
            }
        });
    }

    /// Snapshot the in-process counters to `<state_dir>/counters.json`. Called
    /// every 30s by `spawn_counter_persister` and once during graceful
    /// shutdown so a deploy doesn't reset the running totals.
    pub async fn persist_counters(&self) -> Result<()> {
        let snap = CountersSnapshot {
            handle_claims_total: self.counters.handle_claims_total.load(Ordering::Relaxed),
            handle_first_claims_total: self
                .counters
                .handle_first_claims_total
                .load(Ordering::Relaxed),
            slot_allocations_total: self.counters.slot_allocations_total.load(Ordering::Relaxed),
            pair_opens_total: self.counters.pair_opens_total.load(Ordering::Relaxed),
            events_posted_total: self.counters.events_posted_total.load(Ordering::Relaxed),
        };
        let body = serde_json::to_vec_pretty(&snap)?;
        let path = self.state_dir.join("counters.json");
        tokio::fs::write(path, body).await?;
        Ok(())
    }

    /// Append one row to `<state_dir>/stats-history.jsonl` mirroring the
    /// /stats endpoint at this instant. Used by /stats.html for sparklines.
    /// File grows ~250 B per call → ~720 KB/day. A future prune wave can
    /// roll old entries off once the history exceeds 90 days.
    pub async fn append_history(&self) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (handles_active, slots_active, pair_slots_open, streams_active) = {
            let inner = self.inner.lock().await;
            (
                inner.handles.len(),
                inner.slots.len(),
                inner.pair_slots.len(),
                inner.streams.values().map(Vec::len).sum::<usize>(),
            )
        };
        let entry = HistoryEntry {
            ts: now,
            handles_active,
            slots_active,
            pair_slots_open,
            streams_active,
            handle_claims_total: self.counters.handle_claims_total.load(Ordering::Relaxed),
            handle_first_claims_total: self
                .counters
                .handle_first_claims_total
                .load(Ordering::Relaxed),
            slot_allocations_total: self.counters.slot_allocations_total.load(Ordering::Relaxed),
            pair_opens_total: self.counters.pair_opens_total.load(Ordering::Relaxed),
            events_posted_total: self.counters.events_posted_total.load(Ordering::Relaxed),
        };
        let line = serde_json::to_vec(&entry)?;
        let path = self.state_dir.join("stats-history.jsonl");
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        f.write_all(&line).await?;
        f.write_all(b"\n").await?;
        f.flush().await?;
        Ok(())
    }

    /// Spawn a background tokio task that calls `persist_counters` every 30s
    /// + appends a history row on the same tick. Loss bound: counters can
    ///   drift back up to 30s on crash, history can drop one row.
    pub fn spawn_counter_persister(&self) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            // First tick fires immediately; skip it so we don't write the
            // freshly-loaded snapshot back unchanged.
            tick.tick().await;
            loop {
                tick.tick().await;
                if let Err(e) = me.persist_counters().await {
                    eprintln!("counter persist failed: {e}");
                }
                if let Err(e) = me.append_history().await {
                    eprintln!("history append failed: {e}");
                }
            }
        });
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
        // Defense in depth: only allow lowercase hex slot_ids of the exact length
        // we ever produce ourselves (16 random bytes -> 32 hex chars). Blocks
        // any future code path that might let attacker-controlled slot_ids reach
        // disk operations. allocate_slot() always meets this; this assert is
        // belt-and-suspenders against future regressions.
        if !is_valid_slot_id(slot_id) {
            return Err(anyhow::anyhow!("invalid slot_id format: {slot_id:?}"));
        }
        let path = self
            .state_dir
            .join("slots")
            .join(format!("{slot_id}.jsonl"));
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

// Public aggregate-usage snapshot. Counter fields (`*_total`) reset on
// process restart; state fields (`handles_active`, `slots_active`) survive
// on the persistent volume. No DIDs / handles / IPs leaked — counts only.
async fn stats_history(
    State(relay): State<Relay>,
    Query(q): Query<StatsHistoryQuery>,
) -> impl IntoResponse {
    let hours = q.hours.unwrap_or(24).min(168);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cutoff = now.saturating_sub(hours * 3600);
    let path = relay.state_dir.join("stats-history.jsonl");
    let body = tokio::fs::read_to_string(&path).await.unwrap_or_default();
    let entries: Vec<Value> = body
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| {
            v.get("ts")
                .and_then(Value::as_u64)
                .map(|t| t >= cutoff)
                .unwrap_or(false)
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "hours": hours,
            "now_unix": now,
            "count": entries.len(),
            "entries": entries,
        })),
    )
}

async fn landing_stats_html() -> impl IntoResponse {
    static STATS_HTML: &[u8] = include_bytes!("../landing/stats.html");
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=60"),
        ],
        STATS_HTML,
    )
}

async fn landing_phonebook_html() -> impl IntoResponse {
    static PHONEBOOK_HTML: &[u8] = include_bytes!("../landing/phonebook.html");
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=60"),
        ],
        PHONEBOOK_HTML,
    )
}

/// `/stats` dispatch: serve the pretty HTML dashboard to browsers (Accept
/// includes text/html) and JSON to everything else (curl, scripts, scrapers).
/// Keeps the JSON contract intact while letting humans land on the page at
/// the short URL.
async fn stats_root(
    State(relay): State<Relay>,
    headers: HeaderMap,
) -> axum::response::Response {
    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .contains("text/html");
    if wants_html {
        landing_stats_html().await.into_response()
    } else {
        stats_json(State(relay)).await.into_response()
    }
}

async fn stats_json(State(relay): State<Relay>) -> impl IntoResponse {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let inner = relay.inner.lock().await;
    let streams_active: usize = inner.streams.values().map(Vec::len).sum();
    let body = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": now.saturating_sub(relay.counters.boot_unix),
        "handles_active": inner.handles.len(),
        "slots_active": inner.slots.len(),
        "pair_slots_open": inner.pair_slots.len(),
        "streams_active": streams_active,
        "handle_claims_total": relay.counters.handle_claims_total.load(Ordering::Relaxed),
        "handle_first_claims_total": relay.counters.handle_first_claims_total.load(Ordering::Relaxed),
        "slot_allocations_total": relay.counters.slot_allocations_total.load(Ordering::Relaxed),
        "pair_opens_total": relay.counters.pair_opens_total.load(Ordering::Relaxed),
        "events_posted_total": relay.counters.events_posted_total.load(Ordering::Relaxed),
    });
    (StatusCode::OK, Json(body))
}

// Static landing site baked into the binary so apex (wireup.net) can flip
// straight to Fly without a separate static-host. ~37 KB total — negligible
// against the release binary size, and keeps the relay self-contained.
async fn landing_index() -> impl IntoResponse {
    static INDEX_HTML: &[u8] = include_bytes!("../landing/index.html");
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

async fn landing_favicon() -> impl IntoResponse {
    static FAVICON_SVG: &[u8] = include_bytes!("../landing/favicon.svg");
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "image/svg+xml")],
        FAVICON_SVG,
    )
}

async fn landing_og() -> impl IntoResponse {
    static OG_PNG: &[u8] = include_bytes!("../landing/og.png");
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "image/png"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        OG_PNG,
    )
}

async fn landing_demo_cast() -> impl IntoResponse {
    static DEMO_CAST: &[u8] = include_bytes!("../landing/demo.cast");
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/x-asciicast"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        DEMO_CAST,
    )
}

async fn landing_install_sh() -> impl IntoResponse {
    static INSTALL_SH: &[u8] = include_bytes!("../landing/install.sh");
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/x-shellscript; charset=utf-8",
            ),
            (axum::http::header::CACHE_CONTROL, "public, max-age=300"),
        ],
        INSTALL_SH,
    )
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
    relay
        .counters
        .slot_allocations_total
        .fetch_add(1, Ordering::Relaxed);
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
    // Per-slot quota: cap accumulated bytes per slot at MAX_SLOT_BYTES.
    {
        let inner = relay.inner.lock().await;
        let used = inner.slot_bytes.get(&slot_id).copied().unwrap_or(0);
        if used + body_bytes.len() > MAX_SLOT_BYTES {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({
                    "error": "slot quota exceeded",
                    "slot_bytes_used": used,
                    "slot_bytes_max": MAX_SLOT_BYTES,
                    "remediation": "operator should `wire rotate-slot` to drain old slot",
                })),
            )
                .into_response();
        }
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
        let event_size = body_bytes.len();
        let slot = inner.slots.entry(slot_id.clone()).or_default();
        slot.push(req.event.clone());
        *inner.slot_bytes.entry(slot_id.clone()).or_insert(0) += event_size;
    }
    if let Err(e) = relay.append_event_to_disk(&slot_id, &req.event).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("persist failed: {e}")})),
        )
            .into_response();
    }
    relay
        .counters
        .events_posted_total
        .fetch_add(1, Ordering::Relaxed);
    // R1 push: broadcast the new event to every active SSE subscriber on
    // this slot. Dead channels are pruned in-place. The broadcast happens
    // AFTER the disk persist so subscribers and disk readers see the same
    // events; on persist failure we already returned 500 above.
    {
        let mut inner = relay.inner.lock().await;
        if let Some(subs) = inner.streams.get_mut(&slot_id) {
            subs.retain(|tx| tx.send(req.event.clone()).is_ok());
        }
    }
    (
        StatusCode::CREATED,
        Json(json!({"event_id": event_id, "status": "stored"})),
    )
        .into_response()
}

/// R1 — server-sent-events push stream for a slot. Auth'd by slot_token
/// (same as `list_events`). The connection registers an `UnboundedSender`
/// on the slot's subscriber list; every subsequent `post_event` to the slot
/// fans out to all subscribers as `data: <event-json>\n\n` lines. The
/// connection stays open until the client disconnects.
///
/// A 30-second keepalive ping is emitted automatically so reverse proxies
/// (Cloudflare tunnel, nginx) don't time out the upstream.
///
/// Note: the subscriber sees events posted AFTER it subscribed. To catch
/// up on history first, the client should call `GET /v1/events/:slot_id`
/// with `since=` before opening the stream.
async fn stream_events(
    State(relay): State<Relay>,
    Path(slot_id): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
    use futures::stream::StreamExt;

    if let Err(resp) = check_token(&relay, &headers, &slot_id).await {
        return resp;
    }

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    {
        let mut inner = relay.inner.lock().await;
        inner.streams.entry(slot_id.clone()).or_default().push(tx);
    }

    let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx).map(|ev| {
        SseEvent::default()
            .json_data(&ev)
            .map_err(|e| std::io::Error::other(e.to_string()))
    });

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(std::time::Duration::from_secs(30))
                .text("phyllis: still on the line"),
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

#[derive(Deserialize)]
pub struct PairAbandonRequest {
    /// SHA-256 hex digest of the code phrase. Same value the caller posts to
    /// /v1/pair as `code_hash` — knowing the code IS the auth here.
    pub code_hash: String,
}

/// Forget the pair-slot associated with this code_hash. Either side can call;
/// no auth beyond knowledge of the code (which is the shared secret of this
/// handshake anyway). Idempotent: returns 204 whether or not the slot exists.
/// Used by clients to recover after a crash mid-handshake, so the host doesn't
/// stay locked out until the 5-minute TTL.
async fn pair_abandon(
    State(relay): State<Relay>,
    Json(req): Json<PairAbandonRequest>,
) -> impl IntoResponse {
    let mut inner = relay.inner.lock().await;
    if let Some(pair_id) = inner.pair_lookup.remove(&req.code_hash) {
        inner.pair_slots.remove(&pair_id);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn pair_open(
    State(relay): State<Relay>,
    Json(req): Json<PairOpenRequest>,
) -> impl IntoResponse {
    if req.role != "host" && req.role != "guest" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "role must be 'host' or 'guest'"})),
        )
            .into_response();
    }
    relay.evict_expired_pair_slots().await;
    let mut inner = relay.inner.lock().await;
    let pair_id = match inner.pair_lookup.get(&req.code_hash).cloned() {
        Some(id) => id,
        None => {
            let new_id = random_hex(16);
            inner
                .pair_lookup
                .insert(req.code_hash.clone(), new_id.clone());
            inner.pair_slots.insert(new_id.clone(), PairSlot::default());
            relay
                .counters
                .pair_opens_total
                .fetch_add(1, Ordering::Relaxed);
            new_id
        }
    };
    let slot = inner.pair_slots.entry(pair_id.clone()).or_default();
    slot.last_touched = std::time::Instant::now();
    if req.role == "host" {
        if slot.host_msg.is_some() {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "host already registered for this code"})),
            )
                .into_response();
        }
        slot.host_msg = Some(req.msg);
    } else {
        if slot.guest_msg.is_some() {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "guest already registered for this code"})),
            )
                .into_response();
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
    relay.evict_expired_pair_slots().await;
    let mut inner = relay.inner.lock().await;
    let slot = match inner.pair_slots.get_mut(&pair_id) {
        Some(s) => {
            s.last_touched = std::time::Instant::now();
            s.clone()
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown pair_id"})),
            )
                .into_response();
        }
    };
    let (peer_msg, peer_bootstrap) = match q.as_role.as_str() {
        "host" => (slot.guest_msg, slot.guest_bootstrap),
        "guest" => (slot.host_msg, slot.host_bootstrap),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "as_role must be 'host' or 'guest'"})),
            )
                .into_response();
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
    relay.evict_expired_pair_slots().await;
    let mut inner = relay.inner.lock().await;
    let slot = match inner.pair_slots.get_mut(&pair_id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown pair_id"})),
            )
                .into_response();
        }
    };
    slot.last_touched = std::time::Instant::now();
    match req.role.as_str() {
        "host" => slot.host_bootstrap = Some(req.sealed),
        "guest" => slot.guest_bootstrap = Some(req.sealed),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "role must be 'host' or 'guest'"})),
            )
                .into_response();
        }
    }
    (StatusCode::CREATED, Json(json!({"ok": true}))).into_response()
}

// ---------- handle directory (v0.5) ----------

#[derive(Deserialize)]
pub struct HandleClaimRequest {
    /// Nick the claimant wants (case-folded). Domain part is implicit: the
    /// domain the relay's `.well-known` is served from.
    pub nick: String,
    /// Slot id the claimant owns on this relay (proves they allocated here).
    pub slot_id: String,
    /// Optional public-facing relay URL the relay should advertise back in
    /// `.well-known/wire/agent` responses. If omitted, callers will need to
    /// know the relay URL out-of-band.
    pub relay_url: Option<String>,
    /// Claimant's full signed agent-card (includes DID + verify_keys +
    /// optional profile).
    pub card: Value,
}

/// `POST /v1/handle/claim` — claim or update a `nick@<relay-domain>` handle.
///
/// FCFS on nick. Same-DID re-claims allowed (used for profile updates +
/// slot rotation). Different-DID claims on a taken nick return 409.
/// Caller must (a) own the `slot_id` they reference (verified by token
/// being present), and (b) submit a card with a valid self-signature.
async fn handle_claim(
    State(relay): State<Relay>,
    headers: HeaderMap,
    Json(req): Json<HandleClaimRequest>,
) -> impl IntoResponse {
    // Bearer auth: claimant must hold the slot_token for the slot they
    // reference. Prevents nick-squatting from an unauthenticated POSTer.
    if let Err(resp) = check_token(&relay, &headers, &req.slot_id).await {
        return resp;
    }
    // Validate nick (same rules as the client-side parser).
    if !crate::pair_profile::is_valid_nick(&req.nick) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "phyllis: that handle won't fit in the books — nicks need 2-32 chars, lowercase [a-z0-9_-], not on the reserved list",
                "nick": req.nick,
            })),
        )
            .into_response();
    }
    // Verify the card signature using the public verify_agent_card helper.
    if let Err(e) = crate::agent_card::verify_agent_card(&req.card) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("card signature invalid: {e}")})),
        )
            .into_response();
    }
    let did = match req.card.get("did").and_then(Value::as_str) {
        Some(d) => d.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "card missing 'did' field"})),
            )
                .into_response();
        }
    };

    // FCFS check.
    let first_claim = {
        let inner = relay.inner.lock().await;
        match inner.handles.get(&req.nick) {
            Some(existing) if existing.did != did => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "phyllis: this line's already taken by someone else — pick another handle or buzz the rightful owner",
                        "nick": req.nick,
                        "claimed_by": existing.did,
                    })),
                )
                    .into_response();
            }
            Some(_) => false,
            None => true,
        }
    };

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let record = HandleRecord {
        nick: req.nick.clone(),
        did: did.clone(),
        card: req.card.clone(),
        slot_id: req.slot_id.clone(),
        relay_url: req.relay_url.clone(),
        claimed_at: now,
    };

    // Persist to disk first (durable), then update in-memory.
    let path = relay
        .state_dir
        .join("handles")
        .join(format!("{}.json", req.nick));
    let body = match serde_json::to_vec_pretty(&record) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("serialize failed: {e}")})),
            )
                .into_response();
        }
    };
    if let Err(e) = tokio::fs::write(&path, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("persist failed: {e}")})),
        )
            .into_response();
    }
    {
        let mut inner = relay.inner.lock().await;
        inner.handles.insert(req.nick.clone(), record);
    }
    relay
        .counters
        .handle_claims_total
        .fetch_add(1, Ordering::Relaxed);
    if first_claim {
        relay
            .counters
            .handle_first_claims_total
            .fetch_add(1, Ordering::Relaxed);
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "nick": req.nick,
            "did": did,
            "status": if first_claim { "claimed" } else { "re-claimed" },
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct WellKnownAgentQuery {
    pub handle: String,
}

#[derive(Deserialize)]
pub struct HandlesDirectoryQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    pub vibe: Option<String>,
}

// ─── short-URL invites (v0.5.10) ──────────────────────────────────────────
// One-curl onboarding: the invitor registers their `wire://pair?...` URL
// here, gets back a 6-hex token. Anyone who does
//   curl -fsSL https://wireup.net/i/<token> | sh
// gets wire installed (if needed) + the invite accepted, in one shot.
//
// Possession of the short URL = pair authorization (same shape as the
// underlying wire:// invite — it's just a redirector).

#[derive(Deserialize)]
pub struct InviteRegisterRequest {
    /// The wire://pair?... URL produced by `wire invite`. Required.
    pub invite_url: String,
    /// Lifetime in seconds. Default 86400 (24h). Capped at 7 days.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    /// If `Some(n)`, the short URL can be fetched N times before 410s.
    /// `None` = unlimited until TTL hits.
    #[serde(default)]
    pub uses: Option<u32>,
}

impl Relay {
    /// Append one InviteRecord to `<state_dir>/invites.jsonl`.
    async fn persist_invite(&self, rec: &InviteRecord) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut line = serde_json::to_vec(rec)?;
        line.push(b'\n');
        let path = self.state_dir.join("invites.jsonl");
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        f.write_all(&line).await?;
        f.flush().await?;
        Ok(())
    }
}

async fn invite_register(
    State(relay): State<Relay>,
    Json(req): Json<InviteRegisterRequest>,
) -> impl IntoResponse {
    if req.invite_url.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invite_url required"})),
        )
            .into_response();
    }
    // Length cap on the embedded URL to keep persisted records bounded.
    if req.invite_url.len() > 8_192 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error": "invite_url > 8 KiB"})),
        )
            .into_response();
    }
    let ttl = req.ttl_seconds.unwrap_or(86_400).clamp(60, 7 * 86_400);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // 6-hex token → 16.7M space. Collision probability negligible at v0.5
    // scale; if a collision happens (1 in 16M) we 409 and the caller retries.
    let token = random_hex(3);
    let rec = InviteRecord {
        token: token.clone(),
        invite_url: req.invite_url,
        expires_unix: now + ttl,
        uses_remaining: req.uses,
        created_unix: now,
    };
    {
        let mut inner = relay.inner.lock().await;
        if inner.invites.contains_key(&token) {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "token collision, retry"})),
            )
                .into_response();
        }
        inner.invites.insert(token.clone(), rec.clone());
    }
    if let Err(e) = relay.persist_invite(&rec).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("persist failed: {e}")})),
        )
            .into_response();
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "token": token,
            "path": format!("/i/{token}"),
            "expires_unix": rec.expires_unix,
            "uses_remaining": rec.uses_remaining,
        })),
    )
        .into_response()
}

async fn invite_script(
    State(relay): State<Relay>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    // Token shape: 6 lowercase hex. Reject anything else immediately so a
    // path-traversal try never reaches the map lookup.
    if token.len() != 6 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let invite_url = {
        let mut inner = relay.inner.lock().await;
        let Some(rec) = inner.invites.get_mut(&token) else {
            return (StatusCode::NOT_FOUND, "not found\n").into_response();
        };
        if rec.expires_unix <= now {
            return (StatusCode::GONE, "this invite has expired\n").into_response();
        }
        if let Some(n) = rec.uses_remaining {
            if n == 0 {
                return (StatusCode::GONE, "this invite has been used up\n").into_response();
            }
            rec.uses_remaining = Some(n - 1);
        }
        rec.invite_url.clone()
    };
    let escaped = invite_url.replace('\'', "'\\''");
    let script = format!(
        "#!/bin/sh\n\
         # wire — one-curl onboarding (install + pair in one shot)\n\
         # source: https://github.com/SlanchaAi/wire\n\
         set -eu\n\
         INVITE='{escaped}'\n\
         echo \"\u{2192} checking for wire CLI...\"\n\
         if ! command -v wire >/dev/null 2>&1; then\n  \
           echo \"\u{2192} wire not installed; installing first...\"\n  \
           curl -fsSL https://wireup.net/install.sh | sh\n  \
           case \":$PATH:\" in\n    \
             *:\"$HOME/.local/bin\":*) ;;\n    \
             *) export PATH=\"$HOME/.local/bin:$PATH\" ;;\n  \
           esac\n  \
           if ! command -v wire >/dev/null 2>&1; then\n    \
             echo \"\"\n    \
             echo \"wire was installed to ~/.local/bin but it's not on \\$PATH yet.\"\n    \
             echo \"Open a new shell, then run:\"\n    \
             echo \"  wire accept '$INVITE'\"\n    \
             exit 0\n  \
           fi\n\
         fi\n\
         echo \"\u{2192} accepting invite...\"\n\
         wire accept \"$INVITE\"\n"
    );
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/x-shellscript; charset=utf-8",
            ),
            (
                axum::http::header::CACHE_CONTROL,
                "private, no-store, max-age=0",
            ),
        ],
        script,
    )
        .into_response()
}

async fn handles_directory(
    State(relay): State<Relay>,
    Query(q): Query<HandlesDirectoryQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let vibe_filter = q.vibe.as_ref().map(|v| v.to_ascii_lowercase());
    let inner = relay.inner.lock().await;
    let mut records: Vec<HandleRecord> = inner.handles.values().cloned().collect();
    drop(inner);
    records.sort_by(|a, b| a.nick.cmp(&b.nick));

    let cursor = q.cursor.as_deref();
    let mut eligible = Vec::new();
    for rec in records {
        if cursor.is_some_and(|c| rec.nick.as_str() <= c) {
            continue;
        }
        // Hygiene: hide test-shaped nicks from the public directory. Records
        // remain claimed (FCFS protection persists), they just don't surface
        // in the phone book. `demo-` is reserved for asciinema-cast handles,
        // `test-` for integration runs.
        if rec.nick.starts_with("demo-") || rec.nick.starts_with("test-") {
            continue;
        }
        let profile = rec.card.get("profile").cloned().unwrap_or(Value::Null);
        if profile
            .get("listed")
            .and_then(Value::as_bool)
            .is_some_and(|listed| !listed)
        {
            continue;
        }
        if let Some(want) = &vibe_filter {
            let matched = profile
                .get("vibe")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter().any(|v| {
                        v.as_str()
                            .map(|s| s.eq_ignore_ascii_case(want))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            if !matched {
                continue;
            }
        }
        eligible.push((rec, profile));
    }

    let has_more = eligible.len() > limit;
    let page = eligible.into_iter().take(limit).collect::<Vec<_>>();
    let next_cursor = if has_more {
        page.last().map(|(rec, _)| rec.nick.clone())
    } else {
        None
    };
    let handles: Vec<Value> = page
        .into_iter()
        .map(|(rec, profile)| {
            json!({
                "nick": rec.nick,
                "did": rec.did,
                "profile": {
                    "emoji": profile.get("emoji").cloned().unwrap_or(Value::Null),
                    "motto": profile.get("motto").cloned().unwrap_or(Value::Null),
                    "vibe": profile.get("vibe").cloned().unwrap_or(Value::Null),
                    "pronouns": profile.get("pronouns").cloned().unwrap_or(Value::Null),
                    "now": profile.get("now").cloned().unwrap_or(Value::Null),
                },
                "claimed_at": rec.claimed_at,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "handles": handles,
            "next_cursor": next_cursor,
        })),
    )
        .into_response()
}

/// `POST /v1/handle/intro/:nick` — drop a signed pair-introduction event
/// into a known nick's slot WITHOUT needing that slot's bearer token.
///
/// Why this exists: `.well-known/wire/agent` returns a nick's `slot_id` for
/// reachability, but NEVER its `slot_token` (that would leak read+write
/// authority to any handle-resolver). To zero-paste-pair, we need a way for
/// a stranger to deliver their signed agent-card to the nick's owner. This
/// endpoint provides exactly that, and ONLY that: the event must be `kind=1100`
/// (pair_drop / agent_card), self-signed, and the carrying agent-card embedded
/// in the body must verify-OK on its own.
///
/// Rate-limiting is the same governor that gates the other write endpoints.
/// Slot quota still applies — a flood of intros hits the standard 64MB cap.
async fn handle_intro(
    State(relay): State<Relay>,
    Path(nick): Path<String>,
    Json(req): Json<PostEventRequest>,
) -> impl IntoResponse {
    // Look up the nick. Must already be claimed.
    let slot_id = {
        let inner = relay.inner.lock().await;
        match inner.handles.get(&nick) {
            Some(rec) => rec.slot_id.clone(),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": format!("phyllis: that number's been disconnected — {nick:?} isn't claimed on this switchboard")})),
                )
                    .into_response();
            }
        }
    };

    // Only allow kind=1100 pair_drop / agent_card here. Anything else routes
    // to the standard /v1/events/:slot_id with bearer auth.
    let kind = req.event.get("kind").and_then(Value::as_u64).unwrap_or(0);
    let type_str = req.event.get("type").and_then(Value::as_str).unwrap_or("");
    if kind != 1100 && type_str != "pair_drop" && type_str != "agent_card" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "intro endpoint only accepts kind=1100 pair_drop / agent_card events",
                "got_kind": kind,
                "got_type": type_str,
            })),
        )
            .into_response();
    }

    // Body must embed a signed agent-card (so the receiver can pin from it).
    let embedded_card = match req.event.get("body").and_then(|b| b.get("card")) {
        Some(c) => c.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "intro event body must embed 'card' field"})),
            )
                .into_response();
        }
    };
    if let Err(e) = crate::agent_card::verify_agent_card(&embedded_card) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("embedded card signature invalid: {e}")})),
        )
            .into_response();
    }

    // Size + quota checks (same as post_event).
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
            Json(json!({"error": "intro event exceeds 256 KiB", "max_bytes": MAX_EVENT_BYTES})),
        )
            .into_response();
    }
    {
        let inner = relay.inner.lock().await;
        let used = inner.slot_bytes.get(&slot_id).copied().unwrap_or(0);
        if used + body_bytes.len() > MAX_SLOT_BYTES {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({
                    "error": "target slot quota exceeded",
                    "slot_bytes_used": used,
                    "slot_bytes_max": MAX_SLOT_BYTES,
                })),
            )
                .into_response();
        }
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
        let event_size = body_bytes.len();
        let slot = inner.slots.entry(slot_id.clone()).or_default();
        slot.push(req.event.clone());
        *inner.slot_bytes.entry(slot_id.clone()).or_insert(0) += event_size;
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
        Json(json!({"event_id": event_id, "status": "dropped", "to_nick": nick})),
    )
        .into_response()
}

/// `GET /.well-known/wire/agent?handle=<nick>` — WebFinger-style resolver
/// for `nick@<this-relay-domain>` handles. Returns the signed agent-card +
/// slot coords if claimed; 404 if not.
///
/// The `handle` query parameter may be just `<nick>` or `<nick>@<domain>`.
/// Domain part is ignored (the relay only serves nicks it has on file).
/// `GET /.well-known/agent-card.json?handle=<nick>` — A2A v1.0-compatible
/// AgentCard serving wire's handle directory. Same data as `well_known_agent`
/// but in the schema A2A clients (MSFT/AWS/Salesforce/SAP/ServiceNow tooling,
/// agent-card-go, agent-card-python, A2A .NET SDK) already speak.
///
/// Wire-specific fields (DID, slot_id, profile blob, raw signed card) live
/// under the standard A2A `extensions` array using the wire extension URI.
/// A2A-only clients can pair to wire agents knowing only A2A vocabulary;
/// wire-native clients get the full richer card by following the extension.
async fn well_known_agent_card_a2a(
    State(relay): State<Relay>,
    Query(q): Query<WellKnownAgentQuery>,
) -> impl IntoResponse {
    let nick = q.handle.split('@').next().unwrap_or("").to_string();
    if nick.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "handle missing nick"})),
        )
            .into_response();
    }
    let inner = relay.inner.lock().await;
    let rec = match inner.handles.get(&nick) {
        Some(r) => r.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("phyllis: that number's been disconnected — {nick:?} isn't claimed on this switchboard")})),
            )
                .into_response();
        }
    };
    drop(inner);

    let profile = rec.card.get("profile").cloned().unwrap_or(Value::Null);
    let description = profile
        .get("motto")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let display_name = profile
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or(&rec.nick)
        .to_string();
    let relay_url = rec.relay_url.clone().unwrap_or_default();
    // Intro endpoint = where any A2A or wire client posts a signed pair-drop.
    let endpoint = if !relay_url.is_empty() {
        format!(
            "{}/v1/handle/intro/{}",
            relay_url.trim_end_matches('/'),
            rec.nick
        )
    } else {
        format!("/v1/handle/intro/{}", rec.nick)
    };
    let card_sig = rec.card.get("signature").cloned().unwrap_or(Value::Null);

    // Build A2A v1.0 AgentCard shape with wire extension. Fields named to
    // match the A2A spec exactly so downstream tooling (agent-card-go etc.)
    // parses without custom code.
    let a2a_card = json!({
        "id": rec.did,
        "name": display_name,
        "description": description,
        "version": "wire/0.5",
        "endpoint": endpoint,
        "provider": {
            "name": "wire",
            "url": "https://github.com/SlanchaAi/wire"
        },
        "capabilities": {
            "streaming": false,
            "pushNotifications": false,
            "extendedAgentCard": true
        },
        "securitySchemes": {
            "ed25519-event-sig": {
                "type": "signature",
                "alg": "EdDSA",
                "description": "Wire-style signed events (kind=1100 pair_drop for intro; verify against embedded card pubkey)."
            }
        },
        "security": [{"ed25519-event-sig": []}],
        "skills": [],
        "extensions": [{
            // A2A extension URIs are opaque namespace identifiers, not
            // forwardable URLs. Changing this string is a coordinated
            // federation-spec bump because peers match it exactly.
            "uri": "https://slancha.ai/wire/ext/v0.5",
            "description": "Wire-native fields: full signed agent-card, profile blob, DID, slot_id, mailbox relay coords.",
            "required": false,
            "params": {
                "did": rec.did,
                "handle": rec.nick,
                "slot_id": rec.slot_id,
                "relay_url": rec.relay_url,
                "card": rec.card,
                "profile": profile,
                "claimed_at": rec.claimed_at,
            }
        }],
        "signature": card_sig,
    });
    (StatusCode::OK, Json(a2a_card)).into_response()
}

async fn well_known_agent(
    State(relay): State<Relay>,
    Query(q): Query<WellKnownAgentQuery>,
) -> impl IntoResponse {
    let nick = q.handle.split('@').next().unwrap_or("").to_string();
    if nick.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "handle missing nick"})),
        )
            .into_response();
    }
    let inner = relay.inner.lock().await;
    match inner.handles.get(&nick) {
        Some(rec) => (
            StatusCode::OK,
            Json(json!({
                "nick": rec.nick,
                "did": rec.did,
                "card": rec.card,
                "slot_id": rec.slot_id,
                "relay_url": rec.relay_url,
                "claimed_at": rec.claimed_at,
            })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("phyllis: that number's been disconnected — {nick:?} isn't claimed on this switchboard")})),
        )
            .into_response(),
    }
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
    let mut inner = relay.inner.lock().await;
    // R4: record this pull as proof that the slot owner is still polling.
    // Anyone holding the slot_token (i.e., a paired peer) can later read
    // last_pull_at_unix via /v1/slot/:slot_id/state to gauge attentiveness.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    inner.last_pull_at_unix.insert(slot_id.clone(), now_unix);
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

/// R4 — slot-attentiveness probe. Authenticated by slot_token (so only
/// paired peers can ask). Returns `last_pull_at_unix` (the slot owner's most
/// recent `list_events` call, in unix seconds) and `event_count` (total
/// stored). A remote sender uses this before `wire send <peer>` to warn the
/// operator if the peer hasn't polled recently.
async fn slot_state(
    State(relay): State<Relay>,
    Path(slot_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = check_token(&relay, &headers, &slot_id).await {
        return resp;
    }
    let inner = relay.inner.lock().await;
    let event_count = inner.slots.get(&slot_id).map(|v| v.len()).unwrap_or(0);
    let last_pull_at_unix = inner.last_pull_at_unix.get(&slot_id).copied();
    let responder_health = inner.responder_health.get(&slot_id).cloned();
    (
        StatusCode::OK,
        Json(json!({
            "slot_id": slot_id,
            "event_count": event_count,
            "last_pull_at_unix": last_pull_at_unix,
            "responder_health": responder_health,
        })),
    )
        .into_response()
}

async fn responder_health_set(
    State(relay): State<Relay>,
    Path(slot_id): Path<String>,
    headers: HeaderMap,
    Json(record): Json<ResponderHealthRecord>,
) -> impl IntoResponse {
    if let Err(resp) = check_token(&relay, &headers, &slot_id).await {
        return resp;
    }
    let path = relay
        .state_dir
        .join("responder-health")
        .join(format!("{slot_id}.json"));
    let body = match serde_json::to_vec_pretty(&record) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("serialize failed: {e}")})),
            )
                .into_response();
        }
    };
    if let Err(e) = tokio::fs::write(&path, body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("persist failed: {e}")})),
        )
            .into_response();
    }
    {
        let mut inner = relay.inner.lock().await;
        inner
            .responder_health
            .insert(slot_id.clone(), record.clone());
    }
    (StatusCode::OK, Json(record)).into_response()
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
        return Err((StatusCode::FORBIDDEN, Json(json!({"error": "bad token"}))).into_response());
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

fn is_valid_slot_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Run the relay until SIGINT/SIGTERM.
pub async fn serve(bind: &str, state_dir: PathBuf) -> Result<()> {
    let relay = Relay::new(state_dir).await?;
    relay.spawn_pair_sweeper();
    relay.spawn_counter_persister();
    let app = relay.clone().router();
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    eprintln!("wire relay-server listening on {bind}");
    let shutdown_relay = relay.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("\nshutting down — final counter snapshot");
            if let Err(e) = shutdown_relay.persist_counters().await {
                eprintln!("final counter persist failed: {e}");
            }
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pair_slot_evicts_when_idle_past_ttl() {
        let dir = std::env::temp_dir().join(format!("wire-evict-{}", random_hex(8)));
        let _ = std::fs::remove_dir_all(&dir);
        let relay = Relay::new(dir.clone()).await.unwrap();

        // Seed a pair-slot manually with a past last_touched.
        {
            let mut inner = relay.inner.lock().await;
            inner
                .pair_lookup
                .insert("hash-A".to_string(), "id-A".to_string());
            inner.pair_slots.insert(
                "id-A".to_string(),
                PairSlot {
                    last_touched: std::time::Instant::now()
                        - std::time::Duration::from_secs(PAIR_SLOT_TTL_SECS + 60),
                    ..PairSlot::default()
                },
            );

            // And a fresh one — should survive.
            inner
                .pair_lookup
                .insert("hash-B".to_string(), "id-B".to_string());
            inner
                .pair_slots
                .insert("id-B".to_string(), PairSlot::default());

            assert_eq!(inner.pair_slots.len(), 2);
            assert_eq!(inner.pair_lookup.len(), 2);
        }

        relay.evict_expired_pair_slots().await;

        let inner = relay.inner.lock().await;
        assert_eq!(
            inner.pair_slots.len(),
            1,
            "expired slot should have been evicted"
        );
        assert!(inner.pair_slots.contains_key("id-B"));
        assert_eq!(inner.pair_lookup.len(), 1);
        assert!(inner.pair_lookup.contains_key("hash-B"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn slot_id_validator_accepts_only_lowercase_32hex() {
        assert!(is_valid_slot_id("0123456789abcdef0123456789abcdef"));
        assert!(is_valid_slot_id(&random_hex(16)));
        // wrong length
        assert!(!is_valid_slot_id("abc"));
        assert!(!is_valid_slot_id("0123456789abcdef0123456789abcde")); // 31
        assert!(!is_valid_slot_id("0123456789abcdef0123456789abcdef0")); // 33
        // uppercase
        assert!(!is_valid_slot_id("0123456789ABCDEF0123456789abcdef"));
        // path traversal attempts
        assert!(!is_valid_slot_id("../etc/passwd0123456789abcdef0000"));
        assert!(!is_valid_slot_id("..%2Fetc%2Fpasswd00000000000000000"));
        assert!(!is_valid_slot_id("/absolute/path/that/looks/like/key"));
        // null bytes
        assert!(!is_valid_slot_id(
            "0123456789abcdef\0\x31\x32\x33456789abcdef"
        ));
    }
}
