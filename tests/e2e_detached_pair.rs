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

/// v0.11: read the DID-derived character handle from an
/// initialized session. Required because v0.11 stops using the
/// operator-typed init handle (`paul`/`willard`/etc.) — the actual
/// handle on the agent-card is derived from the keypair.
fn read_handle(home: &PathBuf) -> String {
    let out = wire(home, &["whoami", "--json"]);
    assert!(out.status.success(), "whoami failed: {:?}", out);
    let card: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    card["handle"].as_str().unwrap().to_string()
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
        if let Ok(items) = serde_json::from_str::<Vec<Value>>(&body)
            && let Some(v) = f(&items)
        {
            return Some(v);
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

    // Long-running daemons on both sides. PID files written by
    // cleanup_on_startup; subsequent CLI calls inherit the same WIRE_HOME so
    // pending-pair files are shared with the daemon.
    let _paul_d = spawn_daemon(&paul);
    let _will_d = spawn_daemon(&willard);

    // paul: detached pair-host (auto-spawn daemon is a no-op since we
    // already spawned one with the right PID file). JSON output.
    let host_out = wire(
        &paul,
        &["pair-host", "--detach", "--json", "--relay", &relay_url],
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
        if items.is_empty() { Some(true) } else { None }
    });
    assert_eq!(
        drained,
        Some(true),
        "paul pair-list must drain after confirm"
    );
    let drained_w = wait_for(&willard, drain_deadline, |items| {
        if items.is_empty() { Some(true) } else { None }
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
    assert!(has_peer(&pj, &willard_h), "paul missing willard: {pj}");
    assert!(has_peer(&wj, &paul_h), "willard missing paul: {wj}");

    // Send + sync + tail round-trip — confirms the pair actually works.
    assert!(
        wire(
            &paul,
            &["send", &willard_h, "claim", "hello from detached e2e"]
        )
        .status
        .success()
    );

    // Push outbox + pull inbox via explicit cycles. The willard daemon is
    // also running with --interval 1, so it races the CLI pull: when the
    // daemon wins, the explicit `wire pull` finds the event already in
    // willard's inbox and dedupes it as `rejected` with reason
    // "duplicate event_id already in inbox", leaving `written` empty.
    // That's correct behavior (idempotent dedup), so we don't assert on
    // `written.len()` — `wire tail` is the user-visible source of truth
    // and works regardless of which path put the event in the inbox.
    assert!(wire(&paul, &["push", "--json"]).status.success());
    assert!(wire(&willard, &["pull", "--json"]).status.success());

    // Verify it shows up in tail. Allow a couple of retries to absorb the
    // daemon's tick: if the CLI pull deduped against an in-flight daemon
    // write, the inbox file may briefly be open for append.
    let mut tail_str = String::new();
    for _ in 0..10 {
        let tail_out = wire(&willard, &["tail"]);
        tail_str = String::from_utf8_lossy(&tail_out.stdout).into_owned();
        if tail_str.contains("hello from detached e2e") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(
        tail_str.contains("hello from detached e2e"),
        "willard tail must contain the sent event, got: {tail_str}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detached_pair_survives_daemon_restart_mid_handshake() {
    // The v0.3.12 persistent-SPAKE2 promise: a daemon that dies AFTER pair_open
    // (status=polling) but BEFORE sas_ready must recover from the pending file's
    // persisted seed/pair_id/slot info on restart and still complete the
    // handshake instead of bailing aborted_restart.
    let relay_dir = fresh_dir("relay-restart");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    let paul = fresh_dir("paul-restart");
    let willard = fresh_dir("willard-restart");
    assert!(
        wire(&paul, &["init", "paul", "--relay", &relay_url])
            .status
            .success()
    );
    let paul_h = read_handle(&paul);
    let _ = &paul_h; // v0.11 unused-var hush
    assert!(
        wire(&willard, &["init", "willard", "--relay", &relay_url])
            .status
            .success()
    );
    let willard_h = read_handle(&willard);
    let _ = &willard_h; // v0.11 unused-var hush

    let mut paul_d = Some(spawn_daemon(&paul));
    let _will_d = spawn_daemon(&willard);

    let host_out = wire(
        &paul,
        &["pair-host", "--detach", "--json", "--relay", &relay_url],
    );
    let code: String = serde_json::from_slice::<Value>(&host_out.stdout).unwrap()["code_phrase"]
        .as_str()
        .unwrap()
        .to_string();
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
    assert!(join_out.status.success());

    // Wait until paul side reaches polling (i.e. pair_open succeeded, seed
    // persisted to file).
    let _ = wait_for(&paul, Instant::now() + Duration::from_secs(10), |items| {
        items
            .iter()
            .find(|p| p["code"] == code && p["status"] == "polling")
            .map(|_| true)
    })
    .expect("paul never reached polling");

    // Verify the persisted fields are present on disk.
    let pending_dir = paul.join("state/wire/pending-pair");
    let pending_file = pending_dir.join(format!("{code}.json"));
    let body = std::fs::read_to_string(&pending_file).expect("pending file");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "polling");
    assert!(v["pair_id"].is_string(), "pair_id missing: {body}");
    assert!(v["our_slot_id"].is_string(), "our_slot_id missing");
    assert!(v["our_slot_token"].is_string(), "our_slot_token missing");
    assert!(
        v["spake2_seed_b64"].is_string(),
        "spake2_seed_b64 missing: {body}"
    );

    // Kill paul daemon, simulating a crash mid-handshake.
    drop(paul_d.take().unwrap());

    // Restart it. cleanup_on_startup should restore from the persisted seed.
    let _paul_d2 = spawn_daemon(&paul);

    // Both sides should now reach sas_ready.
    let deadline = Instant::now() + Duration::from_secs(25);
    let paul_sas = wait_for(&paul, deadline, |items| {
        items
            .iter()
            .find(|p| p["code"] == code && p["status"] == "sas_ready")
            .and_then(|p| p["sas"].as_str())
            .map(str::to_string)
    })
    .expect("paul never reached sas_ready after restart");
    let will_sas = wait_for(&willard, deadline, |items| {
        items
            .iter()
            .find(|p| p["code"] == code && p["status"] == "sas_ready")
            .and_then(|p| p["sas"].as_str())
            .map(str::to_string)
    })
    .expect("willard never reached sas_ready");
    assert_eq!(
        paul_sas, will_sas,
        "SAS digits must match across restart — proves seed reconstruction reproduced the same SPAKE2 scalar"
    );

    // Confirm + finalize.
    assert!(
        wire(&paul, &["pair-confirm", &code, &paul_sas])
            .status
            .success()
    );
    assert!(
        wire(&willard, &["pair-confirm", &code, &will_sas])
            .status
            .success()
    );

    let drain = wait_for(&paul, Instant::now() + Duration::from_secs(15), |items| {
        if items.is_empty() { Some(true) } else { None }
    });
    assert_eq!(
        drain,
        Some(true),
        "paul pair-list did not drain after restart"
    );

    // Peers VERIFIED on both sides.
    let peers_p: Value =
        serde_json::from_slice(&wire(&paul, &["peers", "--json"]).stdout).unwrap_or_default();
    let peers_w: Value =
        serde_json::from_slice(&wire(&willard, &["peers", "--json"]).stdout).unwrap_or_default();
    let has = |v: &Value, h: &str| -> bool {
        v.as_array()
            .map(|a| {
                a.iter().any(|p| {
                    p.get("handle").and_then(Value::as_str) == Some(h)
                        && p.get("tier").and_then(Value::as_str) == Some("VERIFIED")
                })
            })
            .unwrap_or(false)
    };
    assert!(has(&peers_p, &willard_h), "paul missing willard: {peers_p}");
    assert!(has(&peers_w, &paul_h), "willard missing paul: {peers_w}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detached_pair_two_concurrent_hosts_against_two_guests() {
    // Stress: paul detach-hosts TWO concurrent pairs (codes A + B); two
    // separate guest daemons (alice + bob) each detach-join one. The
    // single paul daemon must drive BOTH pending files independently
    // through the state machine. Verifies the per-code HashMap LIVE_SESSIONS
    // doesn't cross-contaminate state across simultaneous pairs.
    let relay_dir = fresh_dir("relay-multi");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    let paul = fresh_dir("paul-multi");
    let alice = fresh_dir("alice-multi");
    let bob = fresh_dir("bob-multi");
    for (h, dir) in [("paul", &paul), ("alice", &alice), ("bob", &bob)] {
        assert!(
            wire(dir, &["init", h, "--relay", &relay_url])
                .status
                .success()
        );
    }
    // v0.11: capture canonical handles per init. The operator-typed
    // strings ("paul"/"alice"/"bob") are ignored at init time.
    let paul_h = read_handle(&paul);
    let alice_h = read_handle(&alice);
    let bob_h = read_handle(&bob);
    let _ = (&paul_h, &alice_h, &bob_h);

    let _paul_d = spawn_daemon(&paul);
    let _alice_d = spawn_daemon(&alice);
    let _bob_d = spawn_daemon(&bob);

    // paul opens two concurrent detach-hosts.
    let host_a = wire(
        &paul,
        &["pair-host", "--detach", "--json", "--relay", &relay_url],
    );
    let host_b = wire(
        &paul,
        &["pair-host", "--detach", "--json", "--relay", &relay_url],
    );
    assert!(host_a.status.success() && host_b.status.success());
    let code_a: String = serde_json::from_slice::<Value>(&host_a.stdout).unwrap()["code_phrase"]
        .as_str()
        .unwrap()
        .to_string();
    let code_b: String = serde_json::from_slice::<Value>(&host_b.stdout).unwrap()["code_phrase"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        code_a, code_b,
        "concurrent hosts must produce distinct codes"
    );

    // alice joins A, bob joins B.
    assert!(
        wire(
            &alice,
            &[
                "pair-join",
                &code_a,
                "--detach",
                "--json",
                "--relay",
                &relay_url
            ],
        )
        .status
        .success()
    );
    assert!(
        wire(
            &bob,
            &[
                "pair-join",
                &code_b,
                "--detach",
                "--json",
                "--relay",
                &relay_url
            ],
        )
        .status
        .success()
    );

    let deadline = Instant::now() + Duration::from_secs(25);
    // Both paul-side pairs reach sas_ready with their own digits.
    let paul_a_sas = wait_for(&paul, deadline, |items| {
        items
            .iter()
            .find(|p| p["code"] == code_a && p["status"] == "sas_ready")
            .and_then(|p| p["sas"].as_str())
            .map(str::to_string)
    })
    .expect("paul/A never reached sas_ready");
    let paul_b_sas = wait_for(&paul, deadline, |items| {
        items
            .iter()
            .find(|p| p["code"] == code_b && p["status"] == "sas_ready")
            .and_then(|p| p["sas"].as_str())
            .map(str::to_string)
    })
    .expect("paul/B never reached sas_ready");
    assert_ne!(
        paul_a_sas, paul_b_sas,
        "two distinct pairs must produce distinct SAS digits"
    );

    // Guest sides see the same digits as the corresponding host.
    let alice_sas = wait_for(&alice, deadline, |items| {
        items
            .iter()
            .find(|p| p["code"] == code_a && p["status"] == "sas_ready")
            .and_then(|p| p["sas"].as_str())
            .map(str::to_string)
    })
    .expect("alice never reached sas_ready");
    let bob_sas = wait_for(&bob, deadline, |items| {
        items
            .iter()
            .find(|p| p["code"] == code_b && p["status"] == "sas_ready")
            .and_then(|p| p["sas"].as_str())
            .map(str::to_string)
    })
    .expect("bob never reached sas_ready");
    assert_eq!(paul_a_sas, alice_sas, "paul/A and alice must agree on SAS");
    assert_eq!(paul_b_sas, bob_sas, "paul/B and bob must agree on SAS");

    // Confirm everyone.
    assert!(
        wire(&paul, &["pair-confirm", &code_a, &paul_a_sas])
            .status
            .success()
    );
    assert!(
        wire(&paul, &["pair-confirm", &code_b, &paul_b_sas])
            .status
            .success()
    );
    assert!(
        wire(&alice, &["pair-confirm", &code_a, &alice_sas])
            .status
            .success()
    );
    assert!(
        wire(&bob, &["pair-confirm", &code_b, &bob_sas])
            .status
            .success()
    );

    // Both pending lists should drain on paul.
    let drained = wait_for(&paul, Instant::now() + Duration::from_secs(15), |items| {
        if items.is_empty() { Some(true) } else { None }
    });
    assert_eq!(drained, Some(true), "paul pair-list must drain to empty");

    // paul should now have BOTH alice + bob pinned VERIFIED.
    let peers_out = wire(&paul, &["peers", "--json"]);
    let peers: Value = serde_json::from_slice(&peers_out.stdout).unwrap_or_default();
    let handles: Vec<String> = peers
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p.get("handle").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        handles.contains(&alice_h),
        "paul missing alice ({alice_h}): {handles:?}"
    );
    assert!(
        handles.contains(&bob_h),
        "paul missing bob ({bob_h}): {handles:?}"
    );
}
