//! Integration tests for `wire::relay_server`.
//!
//! Boots the axum server on `127.0.0.1:0` (kernel-assigned port), then drives
//! it with a plain `reqwest` client. State is persisted to a temp dir so
//! restart-recovery is exercised end-to-end.

use serde_json::{Value, json};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_state_dir() -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-relay-test-{pid}-{n}"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Boot a relay on an ephemeral port. Returns `(base_url, shutdown_handle)`.
async fn spawn_relay(state_dir: std::path::PathBuf) -> String {
    let relay = wire::relay_server::Relay::new(state_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    // Give axum a beat to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

fn signed_card(handle: &str, profile: Value) -> Value {
    let (private_key, public_key) = wire::signing::generate_keypair();
    let mut card = wire::agent_card::build_agent_card(handle, &public_key, None, None, None);
    card["profile"] = profile;
    wire::agent_card::sign_agent_card(&card, &private_key)
}

#[tokio::test]
async fn healthz_returns_200() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap().trim(), "ok");
}

#[tokio::test]
async fn allocate_slot_returns_id_and_token() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({"handle": "paul"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    let slot_id = body["slot_id"].as_str().unwrap();
    let slot_token = body["slot_token"].as_str().unwrap();
    assert_eq!(slot_id.len(), 32, "slot_id should be 16 random bytes hex");
    assert_eq!(
        slot_token.len(),
        64,
        "slot_token should be 32 random bytes hex"
    );
    assert!(slot_id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn post_event_then_get_round_trip() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir.clone()).await;
    let client = reqwest::Client::new();

    // Allocate
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap();
    let slot_token = alloc["slot_token"].as_str().unwrap();

    // Post an event
    let event = json!({"event_id": "abc123", "from": "paul", "body": {"content": "hello"}});
    let resp = client
        .post(format!("{base}/v1/events/{slot_id}"))
        .bearer_auth(slot_token)
        .json(&json!({"event": event}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let post_body: Value = resp.json().await.unwrap();
    assert_eq!(post_body["event_id"], "abc123");
    assert_eq!(post_body["status"], "stored");

    // List
    let resp = client
        .get(format!("{base}/v1/events/{slot_id}"))
        .bearer_auth(slot_token)
        .send()
        .await
        .unwrap();
    let events: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_id"], "abc123");

    // Persisted on disk?
    let jsonl =
        std::fs::read_to_string(dir.join("slots").join(format!("{slot_id}.jsonl"))).unwrap();
    assert!(jsonl.contains("abc123"));
}

#[tokio::test]
async fn post_without_token_is_unauthorized() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/events/{slot_id}"))
        .json(&json!({"event": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn post_with_wrong_token_is_forbidden() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/events/{slot_id}"))
        .bearer_auth("not-the-real-token")
        .json(&json!({"event": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn post_to_unknown_slot_is_404() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/events/deadbeefdeadbeefdeadbeefdeadbeef"))
        .bearer_auth("x")
        .json(&json!({"event": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn duplicate_event_id_is_no_op() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap();
    let slot_token = alloc["slot_token"].as_str().unwrap();

    let event = json!({"event_id": "dedupe-me", "body": {}});
    let post1: Value = client
        .post(format!("{base}/v1/events/{slot_id}"))
        .bearer_auth(slot_token)
        .json(&json!({"event": event}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(post1["status"], "stored");

    let post2: Value = client
        .post(format!("{base}/v1/events/{slot_id}"))
        .bearer_auth(slot_token)
        .json(&json!({"event": event}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(post2["status"], "duplicate");

    // Only one stored event.
    let events: Vec<Value> = client
        .get(format!("{base}/v1/events/{slot_id}"))
        .bearer_auth(slot_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn since_query_returns_only_newer_events() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap();
    let slot_token = alloc["slot_token"].as_str().unwrap();

    for n in 0..5 {
        let event = json!({"event_id": format!("e{n}"), "n": n});
        client
            .post(format!("{base}/v1/events/{slot_id}"))
            .bearer_auth(slot_token)
            .json(&json!({"event": event}))
            .send()
            .await
            .unwrap();
    }

    let events: Vec<Value> = client
        .get(format!("{base}/v1/events/{slot_id}?since=e2"))
        .bearer_auth(slot_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(events.len(), 2); // e3, e4
    assert_eq!(events[0]["event_id"], "e3");
    assert_eq!(events[1]["event_id"], "e4");
}

#[tokio::test]
async fn oversized_body_rejected() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap();
    let slot_token = alloc["slot_token"].as_str().unwrap();

    let big = "x".repeat(300 * 1024); // 300 KiB > 256 KiB cap
    let event = json!({"event_id": "big", "body": big});
    let resp = client
        .post(format!("{base}/v1/events/{slot_id}"))
        .bearer_auth(slot_token)
        .json(&json!({"event": event}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn relay_recovers_state_after_restart() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir.clone()).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap().to_string();
    let slot_token = alloc["slot_token"].as_str().unwrap().to_string();

    client
        .post(format!("{base}/v1/events/{slot_id}"))
        .bearer_auth(&slot_token)
        .json(&json!({"event": {"event_id": "survive", "body": "after restart"}}))
        .send()
        .await
        .unwrap();

    // "Restart" — point a fresh Relay at the same state_dir. The Tokio task
    // for the original Relay is still running but we don't care; it's leaked
    // as test scaffolding. The new instance should load from disk.
    let base2 = spawn_relay(dir).await;
    let events: Vec<Value> = client
        .get(format!("{base2}/v1/events/{slot_id}"))
        .bearer_auth(&slot_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_id"], "survive");
}

#[tokio::test]
async fn slot_state_reports_pull_freshness_after_list_events() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap().to_string();
    let slot_token = alloc["slot_token"].as_str().unwrap().to_string();

    // Before any pull, last_pull_at_unix should be absent.
    let state0: Value = client
        .get(format!("{base}/v1/slot/{slot_id}/state"))
        .bearer_auth(&slot_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state0["event_count"], 0);
    assert!(
        state0["last_pull_at_unix"].is_null(),
        "expected null pre-pull, got: {state0}"
    );

    // Pull the slot — this is the slot owner saying "I'm here, I'm reading".
    let _: Value = client
        .get(format!("{base}/v1/events/{slot_id}"))
        .bearer_auth(&slot_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Now state should show a non-null last_pull_at_unix close to now.
    let state1: Value = client
        .get(format!("{base}/v1/slot/{slot_id}/state"))
        .bearer_auth(&slot_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let last = state1["last_pull_at_unix"].as_u64().expect("populated");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        now.saturating_sub(last) < 5,
        "last_pull_at_unix should be within 5s of now (now={now} last={last})"
    );
}

#[tokio::test]
async fn slot_state_rejects_wrong_token() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap().to_string();

    let resp = client
        .get(format!("{base}/v1/slot/{slot_id}/state"))
        .bearer_auth("wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn responder_health_roundtrip_auth_and_persistence() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir.clone()).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap().to_string();
    let slot_token = alloc["slot_token"].as_str().unwrap().to_string();
    let record = json!({
        "status": "offline",
        "reason": "OAuth expired",
        "last_success_at": "2026-05-15T20:14:00Z",
        "set_at": "2026-05-15T20:15:00Z",
    });

    let wrong = client
        .post(format!("{base}/v1/slot/{slot_id}/responder-health"))
        .bearer_auth("wrong-token")
        .json(&record)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 403);

    let set = client
        .post(format!("{base}/v1/slot/{slot_id}/responder-health"))
        .bearer_auth(&slot_token)
        .json(&record)
        .send()
        .await
        .unwrap();
    assert_eq!(set.status(), 200);

    let state: Value = client
        .get(format!("{base}/v1/slot/{slot_id}/state"))
        .bearer_auth(&slot_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["responder_health"], record);

    let base2 = spawn_relay(dir).await;
    let state2: Value = client
        .get(format!("{base2}/v1/slot/{slot_id}/state"))
        .bearer_auth(&slot_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state2["responder_health"], record);
}

#[tokio::test]
async fn sse_stream_pushes_event_to_subscriber() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap().to_string();
    let slot_token = alloc["slot_token"].as_str().unwrap().to_string();

    // Open SSE subscriber in background.
    let stream_url = format!("{base}/v1/events/{slot_id}/stream");
    let tok_for_stream = slot_token.clone();
    let recv = tokio::spawn(async move {
        use futures::StreamExt;
        let resp = reqwest::Client::new()
            .get(&stream_url)
            .bearer_auth(&tok_for_stream)
            .send()
            .await
            .expect("stream open");
        assert!(
            resp.status().is_success(),
            "stream status: {}",
            resp.status()
        );
        let mut bytes = resp.bytes_stream();
        // Read up to ~2s for the first data: line we expect.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut buf = Vec::new();
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                chunk = bytes.next() => match chunk {
                    Some(Ok(b)) => {
                        buf.extend_from_slice(&b);
                        let s = String::from_utf8_lossy(&buf);
                        if s.contains("nudge-me-now") {
                            return true;
                        }
                    }
                    _ => return false,
                },
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
            }
        }
        false
    });

    // Give the subscriber a moment to register.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // POST an event; subscriber should see it on the stream.
    let resp = client
        .post(format!("{base}/v1/events/{slot_id}"))
        .bearer_auth(&slot_token)
        .json(&json!({"event": {"event_id": "nudge-me-now", "body": "wake up"}}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let saw_it = recv.await.unwrap();
    assert!(saw_it, "SSE subscriber never saw the broadcast event");
}

#[tokio::test]
async fn sse_stream_rejects_wrong_token() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap().to_string();

    let resp = client
        .get(format!("{base}/v1/events/{slot_id}/stream"))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn a2a_agent_card_uses_slancha_extension_uri() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap();
    let slot_token = alloc["slot_token"].as_str().unwrap();
    let (private_key, public_key) = wire::signing::generate_keypair();
    let card = wire::agent_card::sign_agent_card(
        &wire::agent_card::build_agent_card("alice", &public_key, None, None, None),
        &private_key,
    );

    let claim_resp = client
        .post(format!("{base}/v1/handle/claim"))
        .bearer_auth(slot_token)
        .json(&json!({
            "nick": "alice",
            "slot_id": slot_id,
            "relay_url": base,
            "card": card,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(claim_resp.status(), 201);

    let a2a_card: Value = client
        .get(format!("{base}/.well-known/agent-card.json?handle=alice"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        a2a_card["extensions"][0]["uri"],
        "https://slancha.ai/wire/ext/v0.5"
    );
}

#[tokio::test]
async fn stats_split_first_claims_from_reclaims() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let alloc: Value = client
        .post(format!("{base}/v1/slot/allocate"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot_id = alloc["slot_id"].as_str().unwrap();
    let slot_token = alloc["slot_token"].as_str().unwrap();
    let (private_key, public_key) = wire::signing::generate_keypair();
    let card = wire::agent_card::sign_agent_card(
        &wire::agent_card::build_agent_card("alice", &public_key, None, None, None),
        &private_key,
    );

    let first: Value = client
        .post(format!("{base}/v1/handle/claim"))
        .bearer_auth(slot_token)
        .json(&json!({
            "nick": "alice",
            "slot_id": slot_id,
            "relay_url": base,
            "card": card,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first["status"], "claimed");
    let stats1: Value = client
        .get(format!("{base}/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats1["handle_claims_total"], 1);
    assert_eq!(stats1["handle_first_claims_total"], 1);

    let reclaim: Value = client
        .post(format!("{base}/v1/handle/claim"))
        .bearer_auth(slot_token)
        .json(&json!({
            "nick": "alice",
            "slot_id": slot_id,
            "relay_url": base,
            "card": card,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reclaim["status"], "re-claimed");
    let stats2: Value = client
        .get(format!("{base}/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats2["handle_claims_total"], 2);
    assert_eq!(stats2["handle_first_claims_total"], 1);
}

#[tokio::test]
async fn handles_directory_paginates_filters_vibe_and_respects_listed_false() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();

    for (nick, profile) in [
        (
            "alice",
            json!({"emoji": "A", "motto": "alpha", "vibe": ["Nocturnal"], "pronouns": "she/her", "now": {"text": "tuning"}}),
        ),
        (
            "bravo",
            json!({"emoji": "B", "motto": "beta", "vibe": ["solar"], "listed": false}),
        ),
        (
            "carol",
            json!({"emoji": "C", "motto": "gamma", "vibe": ["nocturnal", "ops"]}),
        ),
    ] {
        let alloc: Value = client
            .post(format!("{base}/v1/slot/allocate"))
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let slot_id = alloc["slot_id"].as_str().unwrap();
        let slot_token = alloc["slot_token"].as_str().unwrap();
        let card = signed_card(nick, profile);
        let resp = client
            .post(format!("{base}/v1/handle/claim"))
            .bearer_auth(slot_token)
            .json(&json!({
                "nick": nick,
                "slot_id": slot_id,
                "relay_url": base,
                "card": card,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
    }

    let page1: Value = client
        .get(format!("{base}/v1/handles?limit=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page1["handles"].as_array().unwrap().len(), 1);
    assert_eq!(page1["handles"][0]["nick"], "alice");
    assert_eq!(page1["next_cursor"], "alice");

    let page2: Value = client
        .get(format!("{base}/v1/handles?limit=10&cursor=alice"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page2["handles"].as_array().unwrap().len(), 1);
    assert_eq!(page2["handles"][0]["nick"], "carol");
    assert!(page2["next_cursor"].is_null());

    let nocturnal: Value = client
        .get(format!("{base}/v1/handles?vibe=NOCTURNAL"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nicks: Vec<_> = nocturnal["handles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["nick"].as_str().unwrap())
        .collect();
    assert_eq!(nicks, vec!["alice", "carol"]);
}
