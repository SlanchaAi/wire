//! End-to-end SAS-pairing test:
//!   paul runs `wire pair-host` (printing a code phrase + waiting for join).
//!   willard runs `wire pair-join <code>` in parallel.
//!   Both finish SPAKE2, exchange AEAD-sealed cards, auto-pin each other.
//!
//! Then the existing send→push→pull→tail flow works without any manual pin
//! or add-peer-slot — the magic-wormhole demo from README.

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-pair-{prefix}-{pid}-{n}"));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_once_drives_full_sync_after_pairing() {
    let relay_dir = fresh_dir("relay-daemon");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    let paul = fresh_dir("paul-daemon");
    let willard = fresh_dir("willard-daemon");
    assert!(wire(&paul, &["init", "paul", "--offline"]).status.success());
    let paul_h = read_handle(&paul);
    assert!(
        wire(&willard, &["init", "willard", "--offline"])
            .status
            .success()
    );
    let willard_h = read_handle(&willard);

    // Pair
    let mut host = std::process::Command::new(wire_bin())
        .args([
            "pair-host",
            "--relay",
            &relay_url,
            "--yes",
            "--timeout",
            "30",
        ])
        .env("WIRE_HOME", &paul)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stderr_pipe = host.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(stderr_pipe);
        let mut found = false;
        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if !found && trimmed.len() == 9 && trimmed.chars().nth(2) == Some('-') {
                tx.send(trimmed.to_string()).ok();
                found = true;
            }
        }
    });
    let code = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let join_handle = std::thread::spawn({
        let willard = willard.clone();
        let relay_url = relay_url.clone();
        move || {
            wire(
                &willard,
                &[
                    "pair-join",
                    &code,
                    "--relay",
                    &relay_url,
                    "--yes",
                    "--timeout",
                    "30",
                ],
            )
        }
    });
    let join_out = join_handle.join().unwrap();
    assert!(join_out.status.success());
    host.wait().unwrap();

    // Send + run daemon --once on each side
    assert!(
        wire(&paul, &["send", &willard_h, "decision", "via daemon"])
            .status
            .success()
    );
    let paul_daemon = wire(&paul, &["daemon", "--once", "--json"]);
    assert!(paul_daemon.status.success());
    let willard_daemon = wire(&willard, &["daemon", "--once", "--json"]);
    assert!(willard_daemon.status.success());

    let pj: serde_json::Value = serde_json::from_slice(&paul_daemon.stdout).unwrap();
    assert_eq!(pj["push"]["pushed"].as_array().unwrap().len(), 1);
    let wj: serde_json::Value = serde_json::from_slice(&willard_daemon.stdout).unwrap();
    assert_eq!(wj["pull"]["written"].as_array().unwrap().len(), 1);
    assert_eq!(wj["pull"]["rejected"].as_array().unwrap().len(), 0);

    // Confirm willard's tail sees the verified event
    let tail = wire(&willard, &["tail", &paul_h, "--json"]);
    let event: serde_json::Value = serde_json::from_str(
        String::from_utf8(tail.stdout)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(event["body"], "via daemon");
    assert_eq!(event["verified"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotate_slot_after_pairing_orphans_old_slot() {
    let relay_dir = fresh_dir("relay-rotate");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    let paul = fresh_dir("paul-rotate");
    let willard = fresh_dir("willard-rotate");
    assert!(wire(&paul, &["init", "paul", "--offline"]).status.success());
    let paul_h = read_handle(&paul);
    let _ = &paul_h; // v0.11 unused-var hush
    assert!(
        wire(&willard, &["init", "willard", "--offline"])
            .status
            .success()
    );
    let willard_h = read_handle(&willard);
    let _ = &willard_h; // v0.11 unused-var hush

    // Pair via existing helper logic (inlined from other tests).
    let mut host = std::process::Command::new(wire_bin())
        .args([
            "pair-host",
            "--relay",
            &relay_url,
            "--yes",
            "--timeout",
            "30",
        ])
        .env("WIRE_HOME", &paul)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stderr_pipe = host.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(stderr_pipe);
        let mut found = false;
        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if !found && trimmed.len() == 9 && trimmed.chars().nth(2) == Some('-') {
                tx.send(trimmed.to_string()).ok();
                found = true;
            }
        }
    });
    let code = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let join_handle = std::thread::spawn({
        let willard = willard.clone();
        let relay_url = relay_url.clone();
        move || {
            wire(
                &willard,
                &[
                    "pair-join",
                    &code,
                    "--relay",
                    &relay_url,
                    "--yes",
                    "--timeout",
                    "30",
                ],
            )
        }
    });
    join_handle.join().unwrap();
    host.wait().unwrap();

    // Capture paul's pre-rotation slot_id.
    let pre: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(paul.join("config/wire/relay.json")).unwrap(),
    )
    .unwrap();
    let old_slot = pre["self"]["slot_id"].as_str().unwrap().to_string();

    // Rotate.
    let rotate_out = wire(&paul, &["rotate-slot", "--json"]);
    assert!(
        rotate_out.status.success(),
        "rotate failed: {:?}",
        rotate_out
    );
    let rj: serde_json::Value = serde_json::from_slice(&rotate_out.stdout).unwrap();
    assert_eq!(rj["rotated"], true);
    assert_eq!(rj["old_slot_id"], old_slot);
    let new_slot = rj["new_slot_id"].as_str().unwrap().to_string();
    assert_ne!(old_slot, new_slot);
    assert_eq!(rj["announced_to"].as_array().unwrap().len(), 1);
    assert_eq!(rj["announced_to"][0].as_str(), Some(willard_h.as_str()));

    // Confirm relay.json now has the new slot.
    let post: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(paul.join("config/wire/relay.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(post["self"]["slot_id"], new_slot);

    // Confirm willard sees the wire_close event when pulling.
    let pull = wire(&willard, &["pull", "--json"]);
    let pj: serde_json::Value = serde_json::from_slice(&pull.stdout).unwrap();
    assert!(!pj["written"].as_array().unwrap().is_empty());
    let tail = wire(&willard, &["tail", &paul_h, "--json"]);
    let tail_str = String::from_utf8(tail.stdout).unwrap();
    let close_event = tail_str
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|e| e["type"] == "wire_close")
        .expect("expected willard's tail to include the wire_close event");
    assert_eq!(close_event["kind"], 1201);
    assert_eq!(close_event["verified"], true);
    assert_eq!(close_event["body"]["new_slot_id"], new_slot);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paul_pair_hosts_willard_joins_then_send_round_trips() {
    // ---- 1. boot relay ----
    let relay_dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    // ---- 2. init both sides ----
    let paul_home = fresh_dir("paul");
    let willard_home = fresh_dir("willard");
    assert!(
        wire(&paul_home, &["init", "paul", "--offline"])
            .status
            .success()
    );
    let paul_h = read_handle(&paul_home);
    let _ = &paul_h; // v0.11 unused-var hush
    assert!(
        wire(&willard_home, &["init", "willard", "--offline"])
            .status
            .success()
    );
    let willard_h = read_handle(&willard_home);
    let _ = &willard_h; // v0.11 unused-var hush

    // ---- 3. start pair-host in background; capture stderr to learn the code ----
    let mut host_proc = Command::new(wire_bin())
        .args([
            "pair-host",
            "--relay",
            &relay_url,
            "--yes",
            "--timeout",
            "30",
        ])
        .env("WIRE_HOME", &paul_home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pair-host");

    // The code phrase is printed on stderr — read line-by-line until we see it.
    let stderr_pipe = host_proc.stderr.take().unwrap();
    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    let stderr_capture = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let stderr_capture_clone = stderr_capture.clone();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(stderr_pipe);
        let mut found = false;
        for line in reader.lines().map_while(Result::ok) {
            stderr_capture_clone.lock().unwrap().push_str(&line);
            stderr_capture_clone.lock().unwrap().push('\n');
            // Code phrase line is indented 4 spaces and matches NN-XXXXXX.
            let trimmed = line.trim();
            if !found && trimmed.len() == 9 && trimmed.chars().nth(2) == Some('-') {
                code_tx.send(trimmed.to_string()).ok();
                found = true;
            }
        }
    });

    // Give pair-host a moment to print the code.
    let code = code_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("never received code from pair-host stderr");
    assert!(
        code.len() == 9 && code.chars().nth(2) == Some('-'),
        "unexpected code shape: {code:?}"
    );

    // ---- 4. willard joins with --yes (skip interactive SAS prompt) ----
    let join_handle = std::thread::spawn({
        let willard_home = willard_home.clone();
        let relay_url = relay_url.clone();
        let code = code.clone();
        move || {
            wire(
                &willard_home,
                &[
                    "pair-join",
                    &code,
                    "--relay",
                    &relay_url,
                    "--yes",
                    "--timeout",
                    "30",
                ],
            )
        }
    });
    let join_out = join_handle.join().expect("join thread panicked");
    assert!(
        join_out.status.success(),
        "pair-join failed: stderr={}",
        String::from_utf8_lossy(&join_out.stderr)
    );

    // ---- 5. host should now exit successfully ----
    let host_out = host_proc.wait_with_output().expect("pair-host wait failed");
    assert!(
        host_out.status.success(),
        "pair-host failed: captured stderr=\n{}",
        stderr_capture.lock().unwrap()
    );

    // Both sides print a final JSON line on stdout.
    let host_stdout = String::from_utf8(host_out.stdout).unwrap();
    let host_final: Value =
        serde_json::from_str(host_stdout.trim().lines().last().unwrap()).unwrap();
    let host_paired = host_final["paired_with"].as_str().unwrap();
    assert!(
        host_paired.starts_with("did:wire:willard-"),
        "got: {host_paired}"
    );

    let join_stdout = String::from_utf8(join_out.stdout).unwrap();
    let join_final: Value =
        serde_json::from_str(join_stdout.trim().lines().last().unwrap()).unwrap();
    let join_paired = join_final["paired_with"].as_str().unwrap();
    assert!(
        join_paired.starts_with("did:wire:paul-"),
        "got: {join_paired}"
    );

    // SAS digits should match across both sides.
    assert_eq!(host_final["sas"], join_final["sas"]);

    // ---- 6. trust + relay state populated on both sides ----
    let paul_trust: Value = serde_json::from_str(
        &std::fs::read_to_string(paul_home.join("config/wire/trust.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(paul_trust["agents"][&willard_h]["tier"], "VERIFIED");
    let willard_trust: Value = serde_json::from_str(
        &std::fs::read_to_string(willard_home.join("config/wire/trust.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(willard_trust["agents"][&paul_h]["tier"], "VERIFIED");

    // ---- 7. send → push → pull → tail without any manual setup ----
    let send_out = wire(
        &paul_home,
        &[
            "send",
            &willard_h,
            "decision",
            "ship the v0.1 demo",
            "--json",
        ],
    );
    assert!(send_out.status.success());
    assert!(wire(&paul_home, &["push", "--json"]).status.success());

    let pull_out = wire(&willard_home, &["pull", "--json"]);
    assert!(pull_out.status.success());
    let pull_json: Value = serde_json::from_slice(&pull_out.stdout).unwrap();
    assert_eq!(
        pull_json["written"].as_array().unwrap().len(),
        1,
        "expected exactly 1 verified inbox write, got {pull_json}"
    );

    let tail_out = wire(&willard_home, &["tail", &paul_h, "--json"]);
    let tail_stdout = String::from_utf8(tail_out.stdout).unwrap();
    let event: Value = serde_json::from_str(tail_stdout.lines().next().unwrap()).unwrap();
    assert_eq!(event["body"], "ship the v0.1 demo");
    assert_eq!(event["verified"], true);
}
