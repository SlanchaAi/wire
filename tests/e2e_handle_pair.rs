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
        .env("WIRE_HOME_FORCE", "1")
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

/// v0.11: read the DID-derived character handle from an
/// initialized session. Required because v0.11 stops using the
/// operator-typed init handle ("paul"/"willard"/etc.) — the actual
/// handle on the agent-card is derived from the keypair.
fn read_handle(home: &PathBuf) -> String {
    let out = wire(home, &["whoami", "--json"]);
    assert!(out.status.success(), "whoami failed: {out:?}");
    let card: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    card["handle"].as_str().unwrap().to_string()
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

    // A: init + profile + claim nick. v0.11: capture the actual card
    // handle (DID-derived character); operator-typed "coffee-ghost" is
    // ignored at init time.
    let a = fresh_dir("coffee-ghost");
    assert!(
        wire(&a, &["init", "coffee-ghost", "--relay", &relay_url])
            .status
            .success()
    );
    let a_h = read_handle(&a);
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
        wire(&a, &["claim", &a_h, "--public-url", &relay_url, "--json"])
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
    let b_h = read_handle(&b);

    // B: ONE command. wire add <a_h>@<host>.
    let handle = format!("{a_h}@{host_only}");
    let out = wire(&b, &["add", &handle, "--relay", &relay_url, "--json"]);
    assert!(
        out.status.success(),
        "wire add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let added: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    {
        // v0.5.7+: DID is pubkey-suffixed. v0.11: handle = character.
        let pw = added["paired_with"].as_str().unwrap();
        assert!(pw.starts_with(&format!("did:wire:{a_h}-")), "got: {pw}");
    }

    // v0.5.14 bilateral gate: A pulls → pair_drop lands in pending-inbound
    // (NO auto-pin, NO ack — operator must explicitly approve). Wait for
    // the pending-inbound record to appear, then accept it.
    let a_has_pending_b = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&a, &["pull", "--json"]);
        let p = wire(&a, &["pending", "--json"]);
        let body = String::from_utf8_lossy(&p.stdout);
        body.contains(b_h.as_str())
    });
    assert!(
        a_has_pending_b,
        "A never received a pending-inbound pair_drop from B ({b_h})"
    );

    // A explicitly accepts — the bilateral gate's consent step. Only after
    // this does A pin B and emit pair_drop_ack with A's endpoints.
    let accept_out = wire(&a, &["accept", &b_h, "--json"]);
    assert!(
        accept_out.status.success(),
        "accept failed: {}",
        String::from_utf8_lossy(&accept_out.stderr)
    );

    // Now A should have pinned B.
    let a_pinned_b = wait_until(Instant::now() + Duration::from_secs(5), || {
        let p = wire(&a, &["peers", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains(b_h.as_str())
    });
    assert!(a_pinned_b, "A never pinned B ({b_h}) post-accept");

    // B pulls → consumes pair_drop_ack → relay-state gains A's slot_token.
    let b_got_token = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&b, &["pull", "--json"]);
        let relay_json =
            std::fs::read_to_string(b.join("config/wire/relay.json")).unwrap_or_default();
        let v: Value = serde_json::from_str(&relay_json).unwrap_or(Value::Null);
        // RFC-006 Part B: slot_token lives in endpoints[], not a flat field.
        v["peers"][a_h.as_str()]["endpoints"]
            .as_array()
            .map(|eps| {
                eps.iter()
                    .any(|e| e["slot_token"].as_str().is_some_and(|t| !t.is_empty()))
            })
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
            &["send", "--queue", &a_h, "decision", "hello via wire add"]
        )
        .status
        .success()
    );
    let _ = wire(&b, &["push", "--json"]);
    let a_got = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&a, &["pull", "--json"]);
        // D1: paired peers' messages are encrypted at rest — read the decrypted
        // view via `tail`, not the raw (ciphertext) inbox JSONL.
        let t = wire(&a, &["tail", &b_h, "--json"]);
        String::from_utf8_lossy(&t.stdout).contains("hello via wire add")
    });
    assert!(a_got, "A never received B's message");

    // A → B signed send.
    assert!(
        wire(
            &a,
            &["send", "--queue", &b_h, "decision", "ack from coffee-ghost"]
        )
        .status
        .success()
    );
    let _ = wire(&a, &["push", "--json"]);
    let b_got = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&b, &["pull", "--json"]);
        // D1: decrypted view via tail (raw inbox is ciphertext for paired peers).
        let t = wire(&b, &["tail", &a_h, "--json"]);
        String::from_utf8_lossy(&t.stdout).contains("ack from coffee-ghost")
    });
    assert!(b_got, "B never received A's ack");
}

/// One-name rule: two agents that both *type* the same nick each end up
/// claiming their OWN distinct DID-derived persona — neither can squat a
/// name and there is no 409, because the typed nick is ignored. Replaces the
/// old `claim_409_on_competing_nick`: the supported surface can no longer
/// produce a competing-nick collision (you cannot choose a name to compete
/// over).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_coerces_to_persona_no_squatting() {
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

    // Both TYPE the same nick `tide-pool`; both succeed because each claim is
    // coerced to that agent's own persona (auto-init + one-name rule).
    let out_a = wire(
        &a,
        &[
            "claim",
            "tide-pool",
            "--relay",
            &relay_url,
            "--public-url",
            &relay_url,
        ],
    );
    assert!(
        out_a.status.success(),
        "A claim failed: {}",
        String::from_utf8_lossy(&out_a.stderr)
    );
    let out_b = wire(
        &b,
        &[
            "claim",
            "tide-pool",
            "--relay",
            &relay_url,
            "--public-url",
            &relay_url,
        ],
    );
    assert!(
        out_b.status.success(),
        "B claim failed (a competing nick should be impossible under one-name): {}",
        String::from_utf8_lossy(&out_b.stderr)
    );

    // Neither agent's on-wire handle is the typed `tide-pool` — each is its
    // own fp-derived persona, and the two are distinct.
    let ha = read_handle(&a);
    let hb = read_handle(&b);
    assert_ne!(ha, "tide-pool", "typed nick was not coerced to persona");
    assert_ne!(hb, "tide-pool", "typed nick was not coerced to persona");
    assert_ne!(ha, hb, "two distinct keypairs must yield distinct personas");
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
        &[
            "claim",
            "kuiper",
            "--relay",
            &relay_url,
            "--public-url",
            &relay_url,
        ],
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
