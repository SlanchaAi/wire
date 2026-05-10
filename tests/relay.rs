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
