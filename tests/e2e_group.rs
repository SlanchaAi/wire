//! Group-chat end-to-end test (v0.13.3, increment I1).
//!
//! Three agents: a creator (alice) and two members (bob, carol). Alice pairs
//! bilaterally with each member (SAS → VERIFIED), creates a group, adds both
//! verified members, and broadcasts one message. Both members pull and tail
//! the group by id, seeing the creator's message with a verified signature.
//!
//! This is the spec's I1 acceptance path: create → add VERIFIED peer → send →
//! peer tails it. Member-side rosters + member send-back are I2 (join-code).
//! Reuses the relay + SAS-pairing harness shape from `e2e_mesh.rs`.

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
    let path = std::env::temp_dir().join(format!("wire-group-{prefix}-{pid}-{n}"));
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

fn read_handle(home: &PathBuf) -> String {
    let out = wire(home, &["whoami", "--json"]);
    assert!(out.status.success(), "whoami failed: {out:?}");
    let card: Value = serde_json::from_slice(&out.stdout).unwrap();
    card["handle"].as_str().unwrap().to_string()
}

/// Drive a single SAS pairing between two homes against a relay (host runs
/// `pair-host`, guest runs `pair-join` with the captured code). Lifted from
/// `e2e_mesh.rs`.
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
async fn group_creator_broadcast_reaches_both_members() {
    // ---- 1. boot relay ----
    let relay_dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    // ---- 2. init creator + two members ----
    let alice = fresh_dir("alice");
    let bob = fresh_dir("bob");
    let carol = fresh_dir("carol");
    assert!(
        wire(&alice, &["init", "alice", "--offline"])
            .status
            .success()
    );
    assert!(wire(&bob, &["init", "bob", "--offline"]).status.success());
    assert!(
        wire(&carol, &["init", "carol", "--offline"])
            .status
            .success()
    );
    let bob_h = read_handle(&bob);
    let carol_h = read_handle(&carol);

    // ---- 3. alice pairs bilaterally with each member (→ VERIFIED) ----
    drive_pairing(&alice, &bob, &relay_url);
    drive_pairing(&alice, &carol, &relay_url);

    // ---- 4. alice creates a group ----
    assert!(
        wire(&alice, &["group", "create", "release-team"])
            .status
            .success()
    );
    let list: Value =
        serde_json::from_slice(&wire(&alice, &["group", "list", "--json"]).stdout).unwrap();
    let groups = list["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "expected exactly one group, got {list}");
    let gid = groups[0]["id"].as_str().unwrap().to_string();
    assert_eq!(
        groups[0]["members"].as_array().unwrap().len(),
        1,
        "creator-only at create"
    );

    // ---- 5. alice adds both VERIFIED members; epoch bumps per add ----
    assert!(
        wire(&alice, &["group", "add", &gid, &bob_h])
            .status
            .success()
    );
    assert!(
        wire(&alice, &["group", "add", &gid, &carol_h])
            .status
            .success()
    );
    let list2: Value =
        serde_json::from_slice(&wire(&alice, &["group", "list", "--json"]).stdout).unwrap();
    let g = &list2["groups"][0];
    assert_eq!(
        g["members"].as_array().unwrap().len(),
        3,
        "creator + 2 members"
    );
    assert_eq!(
        g["epoch"].as_u64().unwrap(),
        2,
        "two roster mutations → epoch 2"
    );

    // Adding a member who isn't a VERIFIED pinned peer must be refused (T22).
    let bad = wire(&alice, &["group", "add", &gid, "ghost-peer"]);
    assert!(!bad.status.success(), "adding an unpaired peer should fail");

    // ---- 6. alice broadcasts one message to the group ----
    let send = wire(&alice, &["group", "send", &gid, "ship it 🚀"]);
    assert!(send.status.success(), "group send failed: {send:?}");
    let send_json: Value = serde_json::from_slice(
        &wire(&alice, &["group", "send", &gid, "and again", "--json"]).stdout,
    )
    .unwrap();
    assert_eq!(
        send_json["sent"].as_array().unwrap().len(),
        2,
        "fan-out to 2 members"
    );
    assert_eq!(send_json["failed"].as_array().unwrap().len(), 0);

    // ---- 7. alice pushes; both members pull ----
    assert!(wire(&alice, &["push"]).status.success());
    for m in [&bob, &carol] {
        let pull: Value = serde_json::from_slice(&wire(m, &["pull", "--json"]).stdout).unwrap();
        assert_eq!(
            pull["written"].as_array().unwrap().len(),
            2,
            "member should receive both group messages, got {pull}"
        );
        assert_eq!(pull["rejected"].as_array().unwrap().len(), 0);
    }

    // ---- 8. each member tails the group by id and sees the creator's text ----
    for m in [&bob, &carol] {
        let tail: Value =
            serde_json::from_slice(&wire(m, &["group", "tail", &gid, "--json"]).stdout).unwrap();
        let msgs = tail["messages"].as_array().unwrap();
        let texts: Vec<&str> = msgs.iter().filter_map(|x| x["text"].as_str()).collect();
        assert!(
            texts.contains(&"ship it 🚀"),
            "member missing first msg: {tail}"
        );
        assert!(
            texts.contains(&"and again"),
            "member missing second msg: {tail}"
        );
        // Both came from a paired (VERIFIED) creator → signature verifies.
        assert!(
            msgs.iter().all(|x| x["verified"].as_bool() == Some(true)),
            "every group message should verify against the creator's pinned key: {tail}"
        );
    }
}
