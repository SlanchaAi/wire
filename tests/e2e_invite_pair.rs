//! End-to-end one-paste invite pair (v0.4.0).
//!
//! Asserts the single-step flow: A mints invite URL, B accepts the URL
//! string, A's daemon-pull consumes the pair_drop event, both sides pinned,
//! bidirectional `wire send` works. No SAS, no code typing, no MCP — just
//! the CLI surface.

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-invite-e2e-{prefix}-{pid}-{n}"));
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

/// v0.11: read the DID-derived character handle from an
/// initialized session. Required because v0.11 stops using the
/// operator-typed init handle (`paul`/`willard`/etc.) — the actual
/// handle on the agent-card is derived from the keypair.
fn read_handle(home: &PathBuf) -> String {
    let out = wire(home, &["whoami", "--json"]);
    assert!(out.status.success(), "whoami failed: {out:?}");
    let card: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    card["handle"].as_str().unwrap().to_string()
}

struct DaemonGuard(Child);
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_daemon(home: &PathBuf) -> DaemonGuard {
    let child = Command::new(wire_bin())
        .args(["daemon", "--interval", "1"])
        .env("WIRE_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn daemon");
    std::thread::sleep(Duration::from_millis(200));
    DaemonGuard(child)
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
async fn invite_url_one_paste_pair_e2e() {
    let relay_dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    let paul = fresh_dir("paul");
    let willard = fresh_dir("willard");

    // Both sides init explicitly. (The zero-config "wire accept" auto-init
    // path is covered by accept_zero_config_auto_init below; same-machine
    // hostname collision makes auto-init undesirable in this test.)
    assert!(
        wire(&paul, &["init", "paul", "--relay", &relay_url])
            .status
            .success()
    );
    let paul_h = read_handle(&paul);
    assert!(
        wire(&willard, &["init", "willard", "--relay", &relay_url])
            .status
            .success()
    );
    let willard_h = read_handle(&willard);

    // paul daemon must run so it pulls pair_drop events from its own slot.
    let _paul_d = spawn_daemon(&paul);

    // 1. paul mints invite URL
    let out = wire(&paul, &["invite", "--relay", &relay_url, "--json"]);
    assert!(out.status.success(), "invite mint failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mint: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("parse invite stdout: {e}\nraw: {stdout}"));
    let invite_url = mint["invite_url"]
        .as_str()
        .expect("invite_url field")
        .to_string();
    assert!(
        invite_url.starts_with("wire://pair?v=1&inv="),
        "url: {invite_url}"
    );

    // 2. willard accepts (zero-config, no prior init). Auto-inits + allocates.
    let out = wire(&willard, &["accept-invite", &invite_url, "--json"]);
    assert!(
        out.status.success(),
        "accept failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let accept: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let pw = accept["paired_with"].as_str().expect("paired_with string");
    assert!(
        pw.starts_with(&format!("did:wire:{paul_h}-")),
        "expected pubkey-suffixed paul DID (handle={paul_h}), got: {pw}"
    );

    // 3. Wait for paul daemon to pull + consume pair_drop → pin willard.
    // Require BOTH trust + relay-state to contain willard so the diagnostic
    // assertions below can't race the daemon's mid-cycle write order (trust
    // first, relay-state second; on CI slow runners the two-phase tick was
    // observable as flakiness).
    let willard_pinned = wait_until(Instant::now() + Duration::from_secs(20), || {
        let peers = wire(&paul, &["peers", "--json"]);
        if !String::from_utf8_lossy(&peers.stdout).contains(&willard_h) {
            return false;
        }
        let relay_str =
            std::fs::read_to_string(paul.join("config/wire/relay.json")).unwrap_or_default();
        relay_str.contains(&willard_h)
    });
    if !willard_pinned {
        eprintln!("--- paul trust.json ---");
        let _ = std::process::Command::new("cat")
            .arg(paul.join("config/wire/trust.json"))
            .status();
        eprintln!("--- paul relay.json ---");
        let _ = std::process::Command::new("cat")
            .arg(paul.join("config/wire/relay.json"))
            .status();
        eprintln!("--- paul inbox dir ---");
        let _ = std::process::Command::new("ls")
            .arg("-la")
            .arg(paul.join("state/wire/inbox"))
            .status();
        eprintln!("--- manual wire pull on paul ---");
        let out = wire(&paul, &["pull", "--json"]);
        eprintln!("stdout: {}", String::from_utf8_lossy(&out.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&out.stderr));
    }
    assert!(willard_pinned, "paul never pinned willard");
    // Diagnostic on success to verify both trust + relay-state were written.
    let trust_str =
        std::fs::read_to_string(paul.join("config/wire/trust.json")).unwrap_or_default();
    let relay_str =
        std::fs::read_to_string(paul.join("config/wire/relay.json")).unwrap_or_default();
    assert!(
        trust_str.contains(&willard_h),
        "paul trust missing willard: {trust_str}"
    );
    assert!(
        relay_str.contains(&willard_h),
        "paul relay.json missing willard: {relay_str}"
    );

    // 4. Bidirectional send: willard → paul (willard already has paul pinned).
    assert!(
        wire(
            &willard,
            &[
                "send",
                "--queue",
                &paul_h,
                "decision",
                "hello from willard via invite"
            ]
        )
        .status
        .success()
    );
    let _ = wire(&willard, &["push", "--json"]);
    let paul_got = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&paul, &["pull", "--json"]);
        // D1: decrypted view via tail (raw inbox is ciphertext for paired peers).
        let t = wire(&paul, &["tail", &willard_h, "--json"]);
        String::from_utf8_lossy(&t.stdout).contains("hello from willard")
    });
    assert!(
        paul_got,
        "paul never received willard's ({willard_h}) message"
    );

    // 5. paul → willard (paul has willard pinned via daemon-consumed drop).
    assert!(
        wire(
            &paul,
            &[
                "send",
                "--queue",
                &willard_h,
                "decision",
                "ack from paul via invite"
            ]
        )
        .status
        .success()
    );
    let _willard_d = spawn_daemon(&willard);
    let _ = wire(&paul, &["push", "--json"]);
    let willard_got = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&willard, &["pull", "--json"]);
        // D1: decrypted view via tail (raw inbox is ciphertext for paired peers).
        let t = wire(&willard, &["tail", &paul_h, "--json"]);
        String::from_utf8_lossy(&t.stdout).contains("ack from paul")
    });
    assert!(willard_got, "willard never received paul's ({paul_h}) ack");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_invite_rejected_on_accept() {
    let relay_dir = fresh_dir("relay-exp");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    let paul = fresh_dir("paul-exp");
    let willard = fresh_dir("willard-exp");
    assert!(
        wire(&paul, &["init", "paul", "--relay", &relay_url])
            .status
            .success()
    );
    let paul_h = read_handle(&paul);
    let _ = &paul_h; // v0.11 unused-var hush

    let out = wire(
        &paul,
        &["invite", "--relay", &relay_url, "--ttl", "1", "--json"],
    );
    let mint: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let invite_url = mint["invite_url"].as_str().unwrap().to_string();

    std::thread::sleep(Duration::from_secs(2));

    let out = wire(&willard, &["accept-invite", &invite_url, "--json"]);
    assert!(
        !out.status.success(),
        "expected accept to fail on expired invite"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("expired"), "stderr: {stderr}");
}

/// Zero-config B side: `wire accept` with no prior `wire init` should auto-
/// init a self identity (handle derived from hostname) and complete the pair.
/// Only asserts A pins a peer (any handle) — we can't predict the auto-handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_zero_config_auto_init() {
    let relay_dir = fresh_dir("relay-zc");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    let paul = fresh_dir("paul-zc");
    let bare = fresh_dir("bare-zc");
    assert!(
        wire(&paul, &["init", "paul", "--relay", &relay_url])
            .status
            .success()
    );
    let paul_h = read_handle(&paul);
    let _ = &paul_h; // v0.11 unused-var hush
    let _paul_d = spawn_daemon(&paul);

    let mint = wire(&paul, &["invite", "--relay", &relay_url, "--json"]);
    let mint_json: Value = serde_json::from_str(&String::from_utf8_lossy(&mint.stdout)).unwrap();
    let url = mint_json["invite_url"].as_str().unwrap().to_string();

    // No prior init on `bare` — accept must bootstrap from nothing.
    let out = wire(&bare, &["accept-invite", &url, "--json"]);
    assert!(
        out.status.success(),
        "zero-config accept failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // paul's trust file should contain exactly one non-self peer within 15s.
    let pinned = wait_until(Instant::now() + Duration::from_secs(15), || {
        let trust_path = paul.join("config/wire/trust.json");
        let Ok(s) = std::fs::read_to_string(&trust_path) else {
            return false;
        };
        let Ok(v) = serde_json::from_str::<Value>(&s) else {
            return false;
        };
        let agents = v["agents"].as_object().cloned().unwrap_or_default();
        // Self is &paul_h + at least one other.
        agents.keys().any(|k| k != &paul_h)
    });
    assert!(pinned, "paul never pinned the bare zero-config peer");
}
