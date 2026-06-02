//! 3-party mesh-of-bilateral end-to-end test.
//!
//! Three agents (paul, willard, carol) each pair with the other two via SAS.
//! That's 3 pair-host/pair-join handshakes total. Each agent ends up with
//! 2 pinned peers in their trust state. Send messages criss-cross; verify
//! each agent receives exactly the events sent to them by their peers.
//!
//! This is the SyncThing model: no native group room, no member-set protocol,
//! no group revocation primitive. Group communication emerges from N(N-1)/2
//! bilateral wires. SyncThing has 73k stars on this pattern alone.

use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::Duration;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-mesh-{prefix}-{pid}-{n}"));
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
            "wire {args:?} failed under {home:?}:\nstdout: {}\nstderr: {}",
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

/// Drive a single SAS pairing between two homes against a relay.
/// `host_home` runs `pair-host`; `guest_home` runs `pair-join` with the
/// captured code phrase. Returns Ok(()) iff both processes exit 0 and
/// emit matching SAS digits.
fn drive_pairing(host_home: &PathBuf, guest_home: &PathBuf, relay_url: &str) {
    let mut host_proc = Command::new(wire_bin())
        .args([
            "pair-host",
            "--relay",
            relay_url,
            "--yes",
            "--timeout",
            "30",
        ])
        .env("WIRE_HOME", host_home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pair-host");

    let stderr_pipe = host_proc.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    let stderr_capture = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let stderr_clone = stderr_capture.clone();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr_pipe);
        let mut found = false;
        for line in reader.lines().map_while(Result::ok) {
            stderr_clone.lock().unwrap().push_str(&line);
            stderr_clone.lock().unwrap().push('\n');
            let trimmed = line.trim();
            if !found && trimmed.len() == 9 && trimmed.chars().nth(2) == Some('-') {
                tx.send(trimmed.to_string()).ok();
                found = true;
            }
        }
    });

    let code = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("never received code from pair-host");

    let guest_handle = std::thread::spawn({
        let guest_home = guest_home.clone();
        let relay_url = relay_url.to_string();
        let code = code.clone();
        move || {
            wire(
                &guest_home,
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
    let guest_out = guest_handle.join().expect("guest panicked");
    assert!(
        guest_out.status.success(),
        "pair-join failed: stderr={}",
        String::from_utf8_lossy(&guest_out.stderr)
    );

    let host_out = host_proc.wait_with_output().expect("host wait failed");
    assert!(
        host_out.status.success(),
        "pair-host failed; captured stderr=\n{}",
        stderr_capture.lock().unwrap()
    );

    // Confirm SAS digits matched.
    let host_stdout = String::from_utf8(host_out.stdout).unwrap();
    let guest_stdout = String::from_utf8(guest_out.stdout).unwrap();
    let host_final: Value =
        serde_json::from_str(host_stdout.trim().lines().last().unwrap()).unwrap();
    let guest_final: Value =
        serde_json::from_str(guest_stdout.trim().lines().last().unwrap()).unwrap();
    assert_eq!(
        host_final["sas"], guest_final["sas"],
        "SAS mismatch between {host_home:?} and {guest_home:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_party_mesh_of_bilateral_round_trips() {
    // ---- 1. boot relay ----
    let relay_dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    // ---- 2. init three agents ----
    let paul = fresh_dir("paul");
    let willard = fresh_dir("willard");
    let carol = fresh_dir("carol");
    assert!(wire(&paul, &["init", "paul", "--offline"]).status.success());
    let paul_h = read_handle(&paul);
    assert!(
        wire(&willard, &["init", "willard", "--offline"])
            .status
            .success()
    );
    let willard_h = read_handle(&willard);
    assert!(
        wire(&carol, &["init", "carol", "--offline"])
            .status
            .success()
    );
    let carol_h = read_handle(&carol);

    // ---- 3. three pairwise pairings (mesh of bilaterals) ----
    drive_pairing(&paul, &willard, &relay_url);
    drive_pairing(&paul, &carol, &relay_url);
    drive_pairing(&willard, &carol, &relay_url);

    // ---- 4. each agent now has the other two pinned ----
    for (home, expected_peers) in [
        (&paul, vec![&willard_h, &carol_h]),
        (&willard, vec![&paul_h, &carol_h]),
        (&carol, vec![&paul_h, &willard_h]),
    ] {
        let trust: Value = serde_json::from_str(
            &std::fs::read_to_string(home.join("config/wire/trust.json")).unwrap(),
        )
        .unwrap();
        for peer in &expected_peers {
            assert_eq!(
                trust["agents"][peer]["tier"], "VERIFIED",
                "{home:?} missing or wrong tier for peer {peer}"
            );
        }
        // Also validate relay state has both peers' slot coords.
        let relay_state: Value = serde_json::from_str(
            &std::fs::read_to_string(home.join("config/wire/relay.json")).unwrap(),
        )
        .unwrap();
        for peer in &expected_peers {
            assert!(
                relay_state["peers"][peer].is_object(),
                "{home:?} missing relay coords for {peer}"
            );
        }
    }

    // ---- 5. criss-cross sends: each agent fires one event to each peer ----
    // paul -> willard, paul -> carol
    assert!(
        wire(&paul, &["send", "--queue", &willard_h, "decision", "P->W"])
            .status
            .success()
    );
    assert!(
        wire(&paul, &["send", "--queue", &carol_h, "decision", "P->C"])
            .status
            .success()
    );
    // willard -> paul, willard -> carol
    assert!(
        wire(&willard, &["send", "--queue", &paul_h, "decision", "W->P"])
            .status
            .success()
    );
    assert!(
        wire(&willard, &["send", "--queue", &carol_h, "decision", "W->C"])
            .status
            .success()
    );
    // carol -> paul, carol -> willard
    assert!(
        wire(&carol, &["send", "--queue", &paul_h, "decision", "C->P"])
            .status
            .success()
    );
    assert!(
        wire(&carol, &["send", "--queue", &willard_h, "decision", "C->W"])
            .status
            .success()
    );

    // ---- 6. all three push ----
    for home in [&paul, &willard, &carol] {
        let push_out = wire(home, &["push", "--json"]);
        assert!(push_out.status.success());
        let pj: Value = serde_json::from_slice(&push_out.stdout).unwrap();
        assert_eq!(
            pj["pushed"].as_array().unwrap().len(),
            2,
            "expected exactly 2 pushed for {home:?}, got {pj}"
        );
    }

    // ---- 7. all three pull, expect 2 verified inbox writes each ----
    for home in [&paul, &willard, &carol] {
        let pull_out = wire(home, &["pull", "--json"]);
        assert!(pull_out.status.success());
        let pj: Value = serde_json::from_slice(&pull_out.stdout).unwrap();
        assert_eq!(
            pj["written"].as_array().unwrap().len(),
            2,
            "expected exactly 2 verified pulls for {home:?}, got {pj}"
        );
        assert_eq!(pj["rejected"].as_array().unwrap().len(), 0);
    }

    // ---- 8. each agent's tail shows the right messages from the right peers ----
    fn tail_bodies(home: &PathBuf, peer: &str) -> Vec<String> {
        let out = wire(home, &["tail", peer, "--json"]);
        assert!(out.status.success());
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .map(|v| v["body"].as_str().unwrap_or("").to_string())
            .collect()
    }

    assert_eq!(tail_bodies(&paul, &willard_h), vec!["W->P".to_string()]);
    assert_eq!(tail_bodies(&paul, &carol_h), vec!["C->P".to_string()]);
    assert_eq!(tail_bodies(&willard, &paul_h), vec!["P->W".to_string()]);
    assert_eq!(tail_bodies(&willard, &carol_h), vec!["C->W".to_string()]);
    assert_eq!(tail_bodies(&carol, &paul_h), vec!["P->C".to_string()]);
    assert_eq!(tail_bodies(&carol, &willard_h), vec!["W->C".to_string()]);

    // ---- 9. cross-confirmation: each agent's tail (no filter) shows exactly 2 events ----
    for home in [&paul, &willard, &carol] {
        let out = wire(home, &["tail", "--json"]);
        let lines = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .count();
        assert_eq!(
            lines, 2,
            "expected exactly 2 events in {home:?} inbox total, got {lines}"
        );
    }
}
