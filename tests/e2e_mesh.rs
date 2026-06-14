//! 3-party mesh-of-bilateral end-to-end test.
//!
//! Three agents (paul, willard, carol) each pair with the other two via the
//! canonical zero-paste handle flow (`wire add <handle>@<relay>` + bilateral
//! accept). That's 3 pairings total. Each agent ends up with 2 pinned peers
//! in their trust state. Send messages criss-cross; verify each agent
//! receives exactly the events sent to them by their peers.
//!
//! This is the SyncThing model: no native group room, no member-set protocol,
//! no group revocation primitive. Group communication emerges from N(N-1)/2
//! bilateral wires. SyncThing has 73k stars on this pattern alone.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

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
        .env("WIRE_HOME_FORCE", "1")
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

fn wait_until<F: Fn() -> bool>(deadline: Instant, f: F) -> bool {
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

/// Drive a single canonical (zero-paste, handle-dial) pairing between two
/// homes already bound to `relay_url`. `host_home` is the *target* — it
/// claims its handle, the guest runs `wire add <host_handle>@<relay-domain>`
/// (resolving via the relay's well-known), the target pulls the inbound
/// pair_drop, accepts it (bilateral gate), and the guest pulls the
/// pair_drop_ack. Both ends end up pinned VERIFIED with relay coords.
fn drive_pairing(host_home: &PathBuf, guest_home: &PathBuf, relay_url: &str) {
    let host_handle = read_handle(host_home);
    let guest_handle = read_handle(guest_home);
    // relay_url is "http://127.0.0.1:PORT"; the federation domain is the bare
    // host (no port) — `--relay` carries the actual HTTP endpoint.
    let domain = relay_url
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap()
        .to_string();
    let target = format!("{host_handle}@{domain}");

    // Host publishes its handle so the guest's well-known resolution finds it.
    let claim = wire(
        host_home,
        &["claim", &host_handle, "--public-url", relay_url, "--json"],
    );
    assert!(
        claim.status.success(),
        "host claim {host_handle} failed: stderr={}",
        String::from_utf8_lossy(&claim.stderr)
    );

    // Guest adds the host by handle (zero-paste). Auto-pairs: sends a
    // pair_drop to the host's slot.
    let dial = wire(
        guest_home,
        &["add", &target, "--relay", relay_url, "--json"],
    );
    assert!(
        dial.status.success(),
        "guest add {target} failed: stderr={}",
        String::from_utf8_lossy(&dial.stderr)
    );

    // Host pulls → pair_drop lands in pending-inbound (bilateral gate: no
    // auto-pin). Wait for it, then accept.
    let host_sees_guest = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(host_home, &["pull", "--json"]);
        let p = wire(host_home, &["pending", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains(guest_handle.as_str())
    });
    assert!(
        host_sees_guest,
        "{host_home:?} never received pending-inbound pair from {guest_handle}"
    );
    let accept = wire(host_home, &["accept", &guest_handle, "--json"]);
    assert!(
        accept.status.success(),
        "accept {guest_handle} failed: stderr={}",
        String::from_utf8_lossy(&accept.stderr)
    );

    // Host now pins guest VERIFIED.
    let host_pinned = wait_until(Instant::now() + Duration::from_secs(5), || {
        let p = wire(host_home, &["peers", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains(guest_handle.as_str())
    });
    assert!(host_pinned, "{host_home:?} never pinned {guest_handle}");

    // Guest pulls the pair_drop_ack → gains host's slot_token + pins host.
    let guest_pinned = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(guest_home, &["pull", "--json"]);
        let p = wire(guest_home, &["peers", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains(host_handle.as_str())
    });
    assert!(
        guest_pinned,
        "{guest_home:?} never pinned {host_handle} via pair_drop_ack"
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
    assert!(
        wire(&paul, &["init", "--relay", &relay_url])
            .status
            .success()
    );
    let paul_h = read_handle(&paul);
    assert!(
        wire(&willard, &["init", "--relay", &relay_url])
            .status
            .success()
    );
    let willard_h = read_handle(&willard);
    assert!(
        wire(&carol, &["init", "--relay", &relay_url])
            .status
            .success()
    );
    let carol_h = read_handle(&carol);

    // ---- 3. three pairwise pairings (mesh of bilaterals) ----
    drive_pairing(&paul, &willard, &relay_url);
    drive_pairing(&paul, &carol, &relay_url);
    drive_pairing(&willard, &carol, &relay_url);

    // ---- 3.5. drain pairing artifacts. The canonical pair flow rides
    // pair_drop / pair_drop_ack events on the message slots (the old SAS flow
    // exchanged cards out-of-band, leaving the slots empty). Pull each home to
    // consume any in-flight pairing events, then reset the inbox JSONL so the
    // criss-cross round-trip below counts ONLY the decision messages. ----
    for home in [&paul, &willard, &carol] {
        let _ = wire(home, &["pull", "--json"]);
        let inbox = home.join("state/wire/inbox");
        if inbox.exists() {
            let _ = std::fs::remove_dir_all(&inbox);
        }
    }

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
