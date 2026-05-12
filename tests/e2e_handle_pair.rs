//! End-to-end v0.5 zero-paste pair via handle (`wire add`).
//!
//! Spins a local relay + two wire homes. A claims `coffee-ghost`. B does
//! `wire add coffee-ghost@<relay>` — single command. Asserts:
//!   1. Both sides pinned (trust + relay-state)
//!   2. Bidirectional signed send works
//!   3. pair_drop_ack closes the loop (B's relay-state gains A's slot_token)

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-handle-e2e-{prefix}-{pid}-{n}"));
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

fn wait_until<F: Fn() -> bool>(deadline: Instant, f: F) -> bool {
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_add_zero_paste_e2e() {
    let relay_dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");
    let host_only = addr.ip().to_string(); // for handle's domain part

    // A: init + profile + claim nick.
    let a = fresh_dir("coffee-ghost");
    assert!(
        wire(&a, &["init", "coffee-ghost", "--relay", &relay_url])
            .status
            .success()
    );
    assert!(
        wire(&a, &["profile", "set", "emoji", "👻"])
            .status
            .success()
    );
    assert!(
        wire(
            &a,
            &["profile", "set", "motto", "haunts late-night PR reviews"]
        )
        .status
        .success()
    );
    assert!(
        wire(
            &a,
            &[
                "claim",
                "coffee-ghost",
                "--public-url",
                &relay_url,
                "--json"
            ]
        )
        .status
        .success()
    );

    // B: init only. No prior knowledge of A beyond the handle.
    let b = fresh_dir("night-train");
    assert!(
        wire(&b, &["init", "night-train", "--relay", &relay_url])
            .status
            .success()
    );

    // B: ONE command. wire add coffee-ghost@<host>.
    let handle = format!("coffee-ghost@{host_only}");
    let out = wire(&b, &["add", &handle, "--relay", &relay_url, "--json"]);
    assert!(
        out.status.success(),
        "wire add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let added: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(added["paired_with"].as_str(), Some("did:wire:coffee-ghost"));

    // A pulls → consumes pair_drop → pins B → emits pair_drop_ack.
    let a_pinned_b = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&a, &["pull", "--json"]);
        let p = wire(&a, &["peers", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains("night-train")
    });
    assert!(a_pinned_b, "A never pinned B");

    // B pulls → consumes pair_drop_ack → relay-state gains A's slot_token.
    let b_got_token = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&b, &["pull", "--json"]);
        let relay_json =
            std::fs::read_to_string(b.join("config/wire/relay.json")).unwrap_or_default();
        let v: Value = serde_json::from_str(&relay_json).unwrap_or(Value::Null);
        v["peers"]["coffee-ghost"]["slot_token"]
            .as_str()
            .map(|t| !t.is_empty())
            .unwrap_or(false)
    });
    assert!(
        b_got_token,
        "B never received A's slot_token via pair_drop_ack"
    );

    // B → A signed send.
    assert!(
        wire(
            &b,
            &["send", "coffee-ghost", "decision", "hello via wire add"]
        )
        .status
        .success()
    );
    let _ = wire(&b, &["push", "--json"]);
    let a_got = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&a, &["pull", "--json"]);
        let p = a.join("state/wire/inbox/night-train.jsonl");
        p.exists()
            && std::fs::read_to_string(&p)
                .map(|s| s.contains("hello via wire add"))
                .unwrap_or(false)
    });
    assert!(a_got, "A never received B's message");

    // A → B signed send.
    assert!(
        wire(
            &a,
            &["send", "night-train", "decision", "ack from coffee-ghost"]
        )
        .status
        .success()
    );
    let _ = wire(&a, &["push", "--json"]);
    let b_got = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&b, &["pull", "--json"]);
        let p = b.join("state/wire/inbox/coffee-ghost.jsonl");
        p.exists()
            && std::fs::read_to_string(&p)
                .map(|s| s.contains("ack from coffee-ghost"))
                .unwrap_or(false)
    });
    assert!(b_got, "B never received A's ack");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_409_on_competing_nick() {
    let relay_dir = fresh_dir("relay-conflict");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    let a = fresh_dir("first-claim");
    let b = fresh_dir("squatter");
    assert!(
        wire(&a, &["init", "first-agent", "--relay", &relay_url])
            .status
            .success()
    );
    assert!(
        wire(&b, &["init", "second-agent", "--relay", &relay_url])
            .status
            .success()
    );
    assert!(
        wire(&a, &["claim", "tide-pool", "--public-url", &relay_url])
            .status
            .success()
    );

    let out = wire(&b, &["claim", "tide-pool"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("409") || stderr.contains("already claimed"),
        "stderr: {stderr}"
    );
}

/// Regression: `wire claim` from a fresh WIRE_HOME (no prior `wire init`,
/// no prior `wire bind-relay`) should succeed by auto-initializing identity
/// and auto-allocating the relay slot. This is the "ONE STEP" UX promise —
/// see commit history if reintroducing the bail-on-uninit check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_from_fresh_home_one_step() {
    let relay_dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    // Fresh home: zero prior commands.
    let a = fresh_dir("kuiper");

    let out = wire(
        &a,
        &["claim", "kuiper", "--relay", &relay_url, "--public-url", &relay_url],
    );
    assert!(
        out.status.success(),
        "claim from fresh home failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Identity + slot should now exist.
    assert!(
        a.join("config/wire/agent-card.json").exists(),
        "agent-card.json not created by auto-init"
    );
    let relay_json =
        std::fs::read_to_string(a.join("config/wire/relay.json")).expect("relay.json missing");
    assert!(
        relay_json.contains("slot_id"),
        "relay-state self.slot_id not populated: {relay_json}"
    );
}
