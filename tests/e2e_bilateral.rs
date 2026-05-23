//! End-to-end bilateral test:
//!   paul (config A) sends a signed event to willard (config B) via a real
//!   relay-server. Willard verifies and reads it from his inbox.
//!
//! v0.1 manual pairing (no SAS yet — that's iter 8): operators exchange
//! agent-card.json files out-of-band (here, by reading the file from the
//! other config dir). Each side runs `wire pin <card-file>` and
//! `wire add-peer-slot ...`.
//!
//! When SPAKE2 + `wire join` ship, this test stays — it documents the
//! "manual fallback" path operators can use behind firewalls or when reading
//! a SAS aloud isn't an option.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-e2e-{prefix}-{pid}-{n}"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn wire_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wire"))
}

fn wire(home: &PathBuf, args: &[&str]) -> std::process::Output {
    let out = Command::new(wire_bin())
        .args(args)
        .env("WIRE_HOME", home)
        .output()
        .expect("spawn wire");
    if !out.status.success() {
        eprintln!(
            "wire {args:?} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paul_sends_to_willard_via_relay_and_willard_verifies() {
    // ---------- 1. boot relay-server ----------
    let relay_dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    // ---------- 2. init paul + willard ----------
    let paul_home = fresh_dir("paul");
    let willard_home = fresh_dir("willard");
    assert!(wire(&paul_home, &["init", "paul", "--offline"]).status.success());
    assert!(wire(&willard_home, &["init", "willard", "--offline"]).status.success());

    // ---------- 3. each binds a slot on the relay ----------
    let paul_bind = wire(&paul_home, &["bind-relay", &relay_url, "--json"]);
    assert!(paul_bind.status.success(), "paul bind-relay failed");
    let paul_bind_json: Value = serde_json::from_slice(&paul_bind.stdout).unwrap();
    assert!(paul_bind_json["slot_id"].as_str().unwrap().len() == 32);

    let willard_bind = wire(&willard_home, &["bind-relay", &relay_url, "--json"]);
    assert!(willard_bind.status.success());

    // ---------- 4. operators exchange (a) agent-cards and (b) slot info ----------
    // Paul reads willard's relay state file (out-of-band copy) and adds his slot.
    let willard_relay: Value = serde_json::from_str(
        &std::fs::read_to_string(willard_home.join("config/wire/relay.json")).unwrap(),
    )
    .unwrap();
    let w_slot_id = willard_relay["self"]["slot_id"].as_str().unwrap();
    let w_slot_token = willard_relay["self"]["slot_token"].as_str().unwrap();
    assert!(
        wire(
            &paul_home,
            &[
                "add-peer-slot",
                "willard",
                &relay_url,
                w_slot_id,
                w_slot_token
            ]
        )
        .status
        .success()
    );

    // Willard does the symmetric thing for paul (so he can post replies).
    let paul_relay: Value = serde_json::from_str(
        &std::fs::read_to_string(paul_home.join("config/wire/relay.json")).unwrap(),
    )
    .unwrap();
    let p_slot_id = paul_relay["self"]["slot_id"].as_str().unwrap();
    let p_slot_token = paul_relay["self"]["slot_token"].as_str().unwrap();
    assert!(
        wire(
            &willard_home,
            &["add-peer-slot", "paul", &relay_url, p_slot_id, p_slot_token]
        )
        .status
        .success()
    );

    // ---------- 5. willard pins paul's signed card (manual out-of-band pairing) ----------
    let paul_card_path = paul_home.join("config/wire/agent-card.json");
    assert!(
        wire(&willard_home, &["pin", paul_card_path.to_str().unwrap()])
            .status
            .success()
    );

    // ---------- 6. paul sends a decision to willard ----------
    let send_out = wire(
        &paul_home,
        &[
            "send",
            "willard",
            "decision",
            "ship the v0.1 demo",
            "--json",
        ],
    );
    assert!(send_out.status.success());
    let send_json: Value = serde_json::from_slice(&send_out.stdout).unwrap();
    let event_id = send_json["event_id"].as_str().unwrap().to_string();
    assert_eq!(event_id.len(), 64);

    // ---------- 7. paul pushes outbox → willard's relay slot ----------
    let push_out = wire(&paul_home, &["push", "--json"]);
    assert!(push_out.status.success(), "push failed");
    let push_json: Value = serde_json::from_slice(&push_out.stdout).unwrap();
    assert_eq!(
        push_json["pushed"].as_array().unwrap().len(),
        1,
        "expected exactly 1 push, got {push_json}"
    );

    // ---------- 8. willard pulls his slot, verifies, writes inbox ----------
    let pull_out = wire(&willard_home, &["pull", "--json"]);
    assert!(pull_out.status.success(), "pull failed");
    let pull_json: Value = serde_json::from_slice(&pull_out.stdout).unwrap();
    assert_eq!(
        pull_json["written"].as_array().unwrap().len(),
        1,
        "expected exactly 1 verified inbox write, got {pull_json}"
    );
    assert_eq!(
        pull_json["rejected"].as_array().unwrap().len(),
        0,
        "got rejections: {pull_json}"
    );

    // ---------- 9. willard tails — sees the verified event ----------
    let tail_out = wire(&willard_home, &["tail", "paul", "--json"]);
    assert!(tail_out.status.success());
    let stdout = String::from_utf8(tail_out.stdout).unwrap();
    let line = stdout.lines().next().expect("tail produced no output");
    let event: Value = serde_json::from_str(line).unwrap();
    assert_eq!(event["event_id"], event_id);
    {
        // v0.5.7+: DID is pubkey-suffixed.
        let from = event["from"].as_str().unwrap();
        assert!(from.starts_with("did:wire:paul-"), "from: {from}");
    }
    // `to` is constructed from typed peer-handle; sender doesn't have peer's
    // pubkey at send-time, so legacy (handle-only) form is preserved.
    assert_eq!(event["to"], "did:wire:willard");
    assert_eq!(event["body"], "ship the v0.1 demo");
    assert_eq!(event["verified"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_rejects_event_with_unknown_signer() {
    // Boot relay
    let relay_dir = fresh_dir("relay-unknown");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    // willard inits + binds, but does NOT pin paul's card.
    let willard_home = fresh_dir("willard-unknown");
    assert!(wire(&willard_home, &["init", "willard", "--offline"]).status.success());
    assert!(
        wire(&willard_home, &["bind-relay", &relay_url])
            .status
            .success()
    );

    // Paul (separate) sends a real signed event into willard's slot via add-peer-slot.
    let paul_home = fresh_dir("paul-unknown");
    assert!(wire(&paul_home, &["init", "paul", "--offline"]).status.success());
    assert!(
        wire(&paul_home, &["bind-relay", &relay_url])
            .status
            .success()
    );
    let willard_relay: Value = serde_json::from_str(
        &std::fs::read_to_string(willard_home.join("config/wire/relay.json")).unwrap(),
    )
    .unwrap();
    let w_slot_id = willard_relay["self"]["slot_id"].as_str().unwrap();
    let w_slot_token = willard_relay["self"]["slot_token"].as_str().unwrap();
    assert!(
        wire(
            &paul_home,
            &[
                "add-peer-slot",
                "willard",
                &relay_url,
                w_slot_id,
                w_slot_token
            ]
        )
        .status
        .success()
    );
    assert!(
        wire(
            &paul_home,
            &["send", "willard", "decision", "from a stranger", "--json"]
        )
        .status
        .success()
    );
    assert!(wire(&paul_home, &["push", "--json"]).status.success());

    // Willard pulls — paul is NOT pinned, so verify_message_v31 returns
    // UnknownAgent and the event lands in `rejected`, not inbox.
    let pull_out = wire(&willard_home, &["pull", "--json"]);
    assert!(pull_out.status.success());
    let pull_json: Value = serde_json::from_slice(&pull_out.stdout).unwrap();
    assert_eq!(pull_json["written"].as_array().unwrap().len(), 0);
    assert_eq!(pull_json["rejected"].as_array().unwrap().len(), 1);
    let reason = pull_json["rejected"][0]["reason"].as_str().unwrap();
    assert!(
        reason.contains("not in trust"),
        "expected 'not in trust' rejection, got: {reason}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responder_health_cli_set_get_roundtrip() {
    let relay_dir = fresh_dir("relay-responder");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    let paul_home = fresh_dir("paul-responder");
    assert!(wire(&paul_home, &["init", "paul", "--offline"]).status.success());
    assert!(
        wire(&paul_home, &["bind-relay", &relay_url])
            .status
            .success()
    );

    let set = wire(
        &paul_home,
        &[
            "responder",
            "set",
            "offline",
            "--reason",
            "OAuth expired",
            "--json",
        ],
    );
    assert!(set.status.success(), "set failed");
    let set_json: Value = serde_json::from_slice(&set.stdout).unwrap();
    assert_eq!(set_json["status"], "offline");
    assert_eq!(set_json["reason"], "OAuth expired");

    let get = wire(&paul_home, &["responder", "get", "--json"]);
    assert!(get.status.success(), "get failed");
    let get_json: Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(get_json["responder_health"]["status"], "offline");
    assert_eq!(get_json["responder_health"]["reason"], "OAuth expired");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_peer_json_reports_three_health_layers() {
    let relay_dir = fresh_dir("relay-status-peer");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    let paul_home = fresh_dir("paul-status-peer");
    let willard_home = fresh_dir("willard-status-peer");
    assert!(wire(&paul_home, &["init", "paul", "--offline"]).status.success());
    assert!(wire(&willard_home, &["init", "willard", "--offline"]).status.success());
    assert!(
        wire(&paul_home, &["bind-relay", &relay_url])
            .status
            .success()
    );
    assert!(
        wire(&willard_home, &["bind-relay", &relay_url])
            .status
            .success()
    );
    let willard_relay: Value = serde_json::from_str(
        &std::fs::read_to_string(willard_home.join("config/wire/relay.json")).unwrap(),
    )
    .unwrap();
    assert!(
        wire(
            &paul_home,
            &[
                "add-peer-slot",
                "willard",
                &relay_url,
                willard_relay["self"]["slot_id"].as_str().unwrap(),
                willard_relay["self"]["slot_token"].as_str().unwrap(),
            ],
        )
        .status
        .success()
    );

    let out = wire(&paul_home, &["status", "--peer", "willard", "--json"]);
    assert!(out.status.success(), "status --peer failed");
    let status: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(status["transport"]["status"], "ok");
    assert_eq!(status["attention"]["status"], "never_pulled");
    assert_eq!(status["responder"]["status"], "not_reported");
}
