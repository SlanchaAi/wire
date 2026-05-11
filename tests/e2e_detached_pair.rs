//! End-to-end detached pair test with two real `wire daemon` subprocesses.
//!
//! Manual smoke against wire.laulpogan.com confirmed the v0.3.x detached
//! flow works; this test pins it under `cargo test` so regressions surface
//! automatically. Spawns local relay + paul daemon + willard daemon, drives
//! the full detached handshake via CLI, asserts peer pinning + signed
//! send/receive.

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-detach-e2e-{prefix}-{pid}-{n}"));
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

/// Spawn a long-running daemon for the given WIRE_HOME. The returned Child
/// must be killed via DaemonGuard's Drop. Interval is 1s so transitions
/// surface promptly in the test.
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
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    // Tiny wait so cleanup_on_startup PID-file write completes before any
    // CLI command races it.
    std::thread::sleep(Duration::from_millis(200));
    DaemonGuard(child)
}

/// Poll `pair-list --json` until predicate returns Some(T) or deadline.
fn wait_for<F, T>(home: &PathBuf, deadline: Instant, f: F) -> Option<T>
where
    F: Fn(&[Value]) -> Option<T>,
{
    while Instant::now() < deadline {
        let out = wire(home, &["pair-list", "--json"]);
        let body = String::from_utf8_lossy(&out.stdout);
        if let Ok(items) = serde_json::from_str::<Vec<Value>>(&body) {
            if let Some(v) = f(&items) {
                return Some(v);
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detached_pair_full_e2e_with_real_daemons() {
    // Bring up an in-process relay.
    let relay_dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    // Two fresh wire homes; init each.
    let paul = fresh_dir("paul");
    let willard = fresh_dir("willard");
    assert!(wire(&paul, &["init", "paul", "--relay", &relay_url])
        .status
        .success());
    assert!(wire(&willard, &["init", "willard", "--relay", &relay_url])
        .status
        .success());

    // Long-running daemons on both sides. PID files written by
    // cleanup_on_startup; subsequent CLI calls inherit the same WIRE_HOME so
    // pending-pair files are shared with the daemon.
    let _paul_d = spawn_daemon(&paul);
    let _will_d = spawn_daemon(&willard);

    // paul: detached pair-host (auto-spawn daemon is a no-op since we
    // already spawned one with the right PID file). JSON output.
    let host_out = wire(
        &paul,
        &[
            "pair-host",
            "--detach",
            "--json",
            "--relay",
            &relay_url,
        ],
    );
    assert!(host_out.status.success(), "pair-host --detach failed");
    let host_json: Value =
        serde_json::from_slice(&host_out.stdout).expect("pair-host --json valid");
    assert_eq!(host_json["state"], "queued");
    let code = host_json["code_phrase"]
        .as_str()
        .expect("code_phrase")
        .to_string();
    assert!(!code.is_empty());

    // willard: detached pair-join.
    let join_out = wire(
        &willard,
        &[
            "pair-join",
            &code,
            "--detach",
            "--json",
            "--relay",
            &relay_url,
        ],
    );
    assert!(join_out.status.success(), "pair-join --detach failed");
    let join_json: Value = serde_json::from_slice(&join_out.stdout).expect("pair-join --json");
    assert_eq!(join_json["state"], "queued");

    // Wait for both daemons to transition the pair to sas_ready and compute
    // matching digits. Generous deadline since CI may be slow.
    let deadline = Instant::now() + Duration::from_secs(20);
    let paul_sas = wait_for(&paul, deadline, |items| {
        items
            .iter()
            .find(|p| p["code"] == code && p["status"] == "sas_ready")
            .and_then(|p| p["sas"].as_str())
            .map(str::to_string)
    })
    .expect("paul never reached sas_ready");
    let willard_sas = wait_for(&willard, deadline, |items| {
        items
            .iter()
            .find(|p| p["code"] == code && p["status"] == "sas_ready")
            .and_then(|p| p["sas"].as_str())
            .map(str::to_string)
    })
    .expect("willard never reached sas_ready");
    assert_eq!(paul_sas, willard_sas, "SAS digits must match across sides");

    // Confirm on both sides (correct digits). Daemon finalizes on next tick.
    let pa_conf = wire(&paul, &["pair-confirm", &code, &paul_sas, "--json"]);
    assert!(pa_conf.status.success(), "paul confirm failed");
    let wi_conf = wire(&willard, &["pair-confirm", &code, &willard_sas, "--json"]);
    assert!(wi_conf.status.success(), "willard confirm failed");

    // Wait for pair-list to drain (file deleted on finalize).
    let drain_deadline = Instant::now() + Duration::from_secs(15);
    let drained = wait_for(&paul, drain_deadline, |items| {
        if items.is_empty() {
            Some(true)
        } else {
            None
        }
    });
    assert_eq!(
        drained,
        Some(true),
        "paul pair-list must drain after confirm"
    );
    let drained_w = wait_for(&willard, drain_deadline, |items| {
        if items.is_empty() {
            Some(true)
        } else {
            None
        }
    });
    assert_eq!(
        drained_w,
        Some(true),
        "willard pair-list must drain after confirm"
    );

    // peers should now show the counterparty as VERIFIED.
    let paul_peers = wire(&paul, &["peers", "--json"]);
    let willard_peers = wire(&willard, &["peers", "--json"]);
    let pj: Value = serde_json::from_slice(&paul_peers.stdout).unwrap_or_default();
    let wj: Value = serde_json::from_slice(&willard_peers.stdout).unwrap_or_default();
    let has_peer = |v: &Value, target_handle: &str| -> bool {
        if let Some(arr) = v.as_array() {
            arr.iter().any(|p| {
                p.get("handle").and_then(Value::as_str) == Some(target_handle)
                    && p.get("tier").and_then(Value::as_str) == Some("VERIFIED")
            })
        } else {
            false
        }
    };
    assert!(has_peer(&pj, "willard"), "paul missing willard: {pj}");
    assert!(has_peer(&wj, "paul"), "willard missing paul: {wj}");

    // Send + sync + tail round-trip — confirms the pair actually works.
    assert!(wire(
        &paul,
        &["send", "willard", "claim", "hello from detached e2e"]
    )
    .status
    .success());

    // Push outbox + pull inbox via explicit cycles (daemon also does this on
    // its own ticks, but explicit cycles make the test deterministic without
    // waiting on the daemon's 1s interval).
    assert!(wire(&paul, &["push", "--json"]).status.success());
    let pull_out = wire(&willard, &["pull", "--json"]);
    assert!(pull_out.status.success());
    let pull: Value = serde_json::from_slice(&pull_out.stdout).unwrap_or_default();
    let written = pull["written"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or_default();
    assert!(written >= 1, "willard should have pulled at least 1 event");

    // Verify it shows up in tail.
    let tail_out = wire(&willard, &["tail"]);
    let tail_str = String::from_utf8_lossy(&tail_out.stdout);
    assert!(
        tail_str.contains("hello from detached e2e"),
        "willard tail must contain the sent event, got: {tail_str}"
    );
}
