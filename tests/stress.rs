//! Stress tests for the wire send/receive pipeline.
//!
//! These exercise the system under load + edge cases that the e2e suite
//! doesn't cover by design. The goal is to find new bugs (not regress
//! known ones). Each test is allowed to be slow (seconds, not ms) — the
//! `--release` build is used and the relay runs in-process.
//!
//! Tests cover:
//!   1. Outbox flood — N messages → 1 peer, all delivered + dedup correct.
//!   2. Concurrent senders — multiple threads queuing into the same peer
//!      outbox, verify no torn JSONL lines and all events received.
//!   3. `wire bind-relay` migration with pinned peers — currently silent
//!      (issue #7 root cause). Test asserts SOME operator-visible signal.
//!   4. Send to a slot_id that doesn't exist on the relay — verify the
//!      sender surfaces a meaningful error, not silent success.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicU32 = AtomicU32::new(0);

// Flood sizes are kept moderate because each `wire send` is a subprocess
// (~180ms per call on the dev box). 100 events ≈ 18s of queueing per test,
// which is the upper bound we tolerate without going async-internal.
const FLOOD_COUNT: usize = 100;
const CONCURRENT_THREADS: usize = 5;
const CONCURRENT_PER_THREAD: usize = 20;

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-stress-{prefix}-{pid}-{n}"));
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

fn wait_until<F: FnMut() -> bool>(deadline: Instant, mut f: F) -> bool {
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

async fn spawn_federation_relay() -> String {
    let dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

/// v0.11: read the DID-derived character handle from a session's
/// agent-card.json. The card handle is the canonical name; the
/// operator-typed `wire init <name>` arg is ignored at init time.
fn read_handle(home: &Path) -> String {
    let path = home.join("config/wire/agent-card.json");
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read agent-card {path:?}: {e}"));
    let v: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("parse agent-card {path:?}: {e}\n{body}"));
    v["handle"]
        .as_str()
        .unwrap_or_else(|| panic!("agent-card missing handle: {body}"))
        .to_string()
}

/// Pair two fresh homes through the bilateral-gate flow (v0.5.14+).
/// Returns (alice_home, alice_handle, bob_home, bob_handle) where each
/// has the other pinned. v0.11: callers must use the returned card
/// handles (DID-derived characters) when sending / inspecting state —
/// the `alice_name`/`bob_name` args here are only used as fresh_dir
/// prefixes; the cards' handles are derived from each home's keypair.
async fn pair_two_homes(
    relay_url: &str,
    alice_name: &str,
    bob_name: &str,
) -> (PathBuf, String, PathBuf, String) {
    // Handle parser wants a dotted-ASCII host without port (so
    // `alice@127.0.0.1`, not `alice@127.0.0.1:56789`). The actual URL
    // is supplied separately via --relay. Mirror the trick used in
    // tests/e2e_handle_pair.rs.
    let host_only = relay_url
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("127.0.0.1");

    let alice = fresh_dir(alice_name);
    assert!(
        wire(&alice, &["init", "--relay", relay_url])
            .status
            .success()
    );
    let alice_h = read_handle(&alice);
    assert!(
        wire(
            &alice,
            &["claim", &alice_h, "--public-url", relay_url, "--json"]
        )
        .status
        .success()
    );

    let bob = fresh_dir(bob_name);
    assert!(wire(&bob, &["init", "--relay", relay_url]).status.success());
    let bob_h = read_handle(&bob);

    // bob → alice: handle-path pair_drop. Lands in alice's pending-inbound.
    let federation = format!("{alice_h}@{host_only}");
    let add_out = wire(&bob, &["add", &federation, "--relay", relay_url, "--json"]);
    assert!(
        add_out.status.success(),
        "bob `wire add` failed: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );

    // alice: wait for pending-inbound, then accept.
    let alice_has_pending = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&alice, &["pull", "--json"]);
        let p = wire(&alice, &["pending", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains(bob_h.as_str())
    });
    assert!(
        alice_has_pending,
        "alice never saw pending-inbound from {bob_h}"
    );
    assert!(wire(&alice, &["accept", &bob_h, "--json"]).status.success());

    // bob: pull pair_drop_ack — pins alice.
    let bob_pinned_alice = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&bob, &["pull", "--json"]);
        let p = wire(&bob, &["peers", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains(alice_h.as_str())
    });
    assert!(
        bob_pinned_alice,
        "bob never pinned alice ({alice_h}) via pair_drop_ack"
    );

    // alice should also have bob pinned post-accept.
    let p = wire(&alice, &["peers", "--json"]);
    let body = String::from_utf8_lossy(&p.stdout);
    assert!(
        body.contains(bob_h.as_str()),
        "alice should have {bob_h} pinned, got: {body}"
    );

    (alice, alice_h, bob, bob_h)
}

fn count_inbox_lines(home: &Path, peer: &str) -> usize {
    let inbox = home
        .join("state")
        .join("wire")
        .join("inbox")
        .join(format!("{peer}.jsonl"));
    let body = std::fs::read_to_string(&inbox).unwrap_or_default();
    body.lines().filter(|l| !l.trim().is_empty()).count()
}

// ---------- TEST 1: outbox flood ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_bind_relay_accumulates_many_slots() {
    // v0.12 additive-bind stress: bind N distinct relays, assert all N
    // self.endpoints persist (no clobber / no JSON corruption); re-binding
    // an existing relay updates in place (count stays N); `--replace`
    // collapses to exactly one slot.
    const N: usize = 5;
    let mut relays = Vec::new();
    for _ in 0..N {
        relays.push(spawn_federation_relay().await);
    }
    let home = fresh_dir("multibind");

    let read_eps = |home: &PathBuf| -> Vec<String> {
        let p = home.join("config").join("wire").join("relay.json");
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v["self"]["endpoints"]
            .as_array()
            .expect("self.endpoints[]")
            .iter()
            .map(|e| e["relay_url"].as_str().unwrap().to_string())
            .collect()
    };

    // init bound to the first relay, then additively bind the rest.
    assert!(
        wire(&home, &["init", "--relay", &relays[0]])
            .status
            .success()
    );
    for r in &relays[1..] {
        let out = wire(&home, &["bind-relay", r, "--scope", "local", "--json"]);
        assert!(
            out.status.success(),
            "additive bind failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let eps = read_eps(&home);
    assert_eq!(eps.len(), N, "all {N} relays must accumulate, got {eps:?}");
    for r in &relays {
        assert!(
            eps.iter().any(|u| u == r.trim_end_matches('/')),
            "relay {r} present: {eps:?}"
        );
    }

    // Re-binding an existing relay updates in place — count unchanged.
    assert!(
        wire(
            &home,
            &["bind-relay", &relays[2], "--scope", "local", "--json"]
        )
        .status
        .success()
    );
    assert_eq!(
        read_eps(&home).len(),
        N,
        "re-binding the same relay must not grow the set"
    );

    // `--replace` collapses to exactly one slot.
    assert!(
        wire(&home, &["bind-relay", &relays[0], "--replace", "--json"])
            .status
            .success()
    );
    let after = read_eps(&home);
    assert_eq!(
        after.len(),
        1,
        "--replace must leave exactly one slot, got {after:?}"
    );
    assert_eq!(after[0], relays[0].trim_end_matches('/'));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_outbox_flood_500_messages_single_peer() {
    let relay_url = spawn_federation_relay().await;
    let (alice, alice_h, bob, bob_h) =
        pair_two_homes(&relay_url, "stress-alice-a", "stress-bob-a").await;

    // Alice sends FLOOD_COUNT messages to bob, sequentially.
    let start = Instant::now();
    for i in 0..FLOOD_COUNT {
        let body = format!("flood msg {i}");
        let out = wire(&alice, &["send", "--queue", &bob_h, "claim", &body]);
        assert!(
            out.status.success(),
            "send {i} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    eprintln!(
        "stress: queued {} sends in {:?}",
        FLOOD_COUNT,
        start.elapsed()
    );

    // Push: the outbox file is append-only history (never truncated by
    // push — it's an audit log). The signal for "successfully delivered"
    // is the JSON output of `wire push --json`: `pushed[]` lists events
    // that hit the relay this call; `skipped[]` (with reason "duplicate")
    // lists events the relay already had. One push should deliver all
    // FLOOD_COUNT events on a healthy relay.
    let push_start = Instant::now();
    let push_out = wire(&alice, &["push", "--json"]);
    assert!(push_out.status.success(), "push failed");
    let push: Value = serde_json::from_slice(&push_out.stdout).unwrap();
    let pushed_count = push["pushed"].as_array().map(|a| a.len()).unwrap_or(0);
    let skipped_count = push["skipped"].as_array().map(|a| a.len()).unwrap_or(0);
    eprintln!(
        "stress: push #1 delivered {pushed_count} pushed + {skipped_count} skipped \
         in {:?}",
        push_start.elapsed()
    );
    assert_eq!(
        pushed_count + skipped_count,
        FLOOD_COUNT,
        "push did not enumerate all {FLOOD_COUNT} events: pushed={pushed_count} \
         skipped={skipped_count} (sum should equal FLOOD_COUNT)"
    );

    // Bob pulls until he has FLOOD_COUNT events in his inbox.
    let pull_start = Instant::now();
    let bob_received = wait_until(Instant::now() + Duration::from_secs(60), || {
        let _ = wire(&bob, &["pull", "--json"]);
        count_inbox_lines(&bob, &alice_h) >= FLOOD_COUNT
    });
    let final_count = count_inbox_lines(&bob, &alice_h);
    eprintln!(
        "stress: bob received {final_count}/{FLOOD_COUNT} events in {:?}",
        pull_start.elapsed()
    );
    assert!(
        bob_received,
        "bob received only {final_count}/{FLOOD_COUNT} events from alice ({alice_h})"
    );

    // Sanity: every line should be valid JSON.
    let inbox = bob
        .join("state")
        .join("wire")
        .join("inbox")
        .join(format!("{alice_h}.jsonl"));
    let body = std::fs::read_to_string(&inbox).unwrap();
    let mut parsed_ok = 0;
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("torn JSONL line in bob's inbox: {e}\nline: {line}"));
        assert!(v.get("event_id").is_some(), "missing event_id: {line}");
        parsed_ok += 1;
    }
    assert_eq!(parsed_ok, final_count);
}

// ---------- TEST 2: concurrent senders ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_concurrent_sends_no_torn_writes() {
    let relay_url = spawn_federation_relay().await;
    let (alice, alice_h, bob, bob_h) =
        pair_two_homes(&relay_url, "stress-alice-b", "stress-bob-b").await;

    // Spawn CONCURRENT_THREADS OS threads, each queues CONCURRENT_PER_THREAD
    // events to bob via subprocess `wire send`. The outbox file is shared
    // across all of them; the per-path mutex in config::append_outbox_record
    // must serialize the writes.
    let total = CONCURRENT_THREADS * CONCURRENT_PER_THREAD;
    let start = Instant::now();
    let handles: Vec<_> = (0..CONCURRENT_THREADS)
        .map(|tid| {
            let alice = alice.clone();
            let bob_h = bob_h.clone();
            std::thread::spawn(move || {
                for i in 0..CONCURRENT_PER_THREAD {
                    let body = format!("thread {tid} msg {i}");
                    let out = wire(&alice, &["send", "--queue", &bob_h, "claim", &body]);
                    assert!(
                        out.status.success(),
                        "thread {tid} send {i} failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("sender thread panicked");
    }
    eprintln!(
        "stress: {CONCURRENT_THREADS} threads × {CONCURRENT_PER_THREAD} sends = {total} in {:?}",
        start.elapsed()
    );

    // Verify outbox file has exactly `total` parseable JSONL lines.
    let outbox = alice
        .join("state")
        .join("wire")
        .join("outbox")
        .join(format!("{bob_h}.jsonl"));
    let body = std::fs::read_to_string(&outbox).expect("outbox missing");
    let mut parsed_ok = 0;
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("torn JSONL in alice's outbox: {e}\nline: {line}"));
        assert!(v.get("event_id").is_some());
        parsed_ok += 1;
    }
    assert_eq!(
        parsed_ok, total,
        "expected {total} parseable lines in outbox, got {parsed_ok}"
    );

    // Push + verify bob receives all of them.
    let push_out = wire(&alice, &["push", "--json"]);
    assert!(push_out.status.success(), "push failed");
    let push: Value = serde_json::from_slice(&push_out.stdout).unwrap();
    let pushed_count = push["pushed"].as_array().map(|a| a.len()).unwrap_or(0);
    let skipped_count = push["skipped"].as_array().map(|a| a.len()).unwrap_or(0);
    assert_eq!(
        pushed_count + skipped_count,
        total,
        "push didn't enumerate all {total} events: pushed={pushed_count} skipped={skipped_count}"
    );
    assert!(
        wait_until(Instant::now() + Duration::from_secs(60), || {
            let _ = wire(&bob, &["pull", "--json"]);
            count_inbox_lines(&bob, &alice_h) >= total
        },),
        "bob never received {total} events"
    );
}

// ---------- TEST 3: bind-relay silent migration (issue #7 detector) ----------

/// Issue #7 root: `wire bind-relay` silently replaces `state.self` with
/// new slot coords without notifying pinned peers. Peers keep pushing to
/// the dead slot, get 200 OK (slot exists, just unread), and messages
/// disappear. This test asserts that the migration produces SOME
/// operator-visible signal when pinned peers exist — either:
///   (a) bind-relay fails / warns when trust.json has pinned peers, OR
///   (b) bind-relay auto-emits wire_close to pinned peers, OR
///   (c) bind-relay refuses without an explicit `--migrate-pinned` flag.
///
/// Today (HEAD): none of the above. This test is EXPECTED TO FAIL until
/// #7 is closed; failure reveals the bug.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_bind_relay_additive_preserves_pinned_peers_issue_7() {
    let relay_url = spawn_federation_relay().await;
    let (alice, _alice_h, _bob, _bob_h) =
        pair_two_homes(&relay_url, "stress-alice-c", "stress-bob-c").await;

    // Spin a SECOND federation relay for alice to add.
    let new_relay_url = spawn_federation_relay().await;

    // v0.12: bind-relay is ADDITIVE by default. Binding a NEW relay while a
    // peer is pinned must NOT black-hole them (issue #7) — the original slot
    // is RETAINED in self.endpoints, so the peer's pushes still land. The
    // danger is now resolved by design, not merely warned about.
    let migrate_out = wire(&alice, &["bind-relay", &new_relay_url, "--json"]);
    assert!(
        migrate_out.status.success(),
        "additive bind-relay should succeed without --migrate-pinned: {}",
        String::from_utf8_lossy(&migrate_out.stderr)
    );
    let state_path = alice.join("config").join("wire").join("relay.json");
    let state: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    let urls: Vec<String> = state["self"]["endpoints"]
        .as_array()
        .expect("self.endpoints[] present")
        .iter()
        .map(|e| e["relay_url"].as_str().unwrap().to_string())
        .collect();
    assert!(
        urls.iter().any(|u| u == relay_url.trim_end_matches('/')),
        "ISSUE #7: additive bind dropped the ORIGINAL relay, black-holing the pinned peer. endpoints={urls:?}"
    );
    assert!(
        urls.iter()
            .any(|u| u == new_relay_url.trim_end_matches('/')),
        "new relay added: {urls:?}"
    );

    // The DESTRUCTIVE path (--replace) must STILL guard: with a pinned peer
    // it refuses (or warns) rather than silently black-holing.
    let replace_out = wire(
        &alice,
        &["bind-relay", &new_relay_url, "--replace", "--json"],
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&replace_out.stderr),
        String::from_utf8_lossy(&replace_out.stdout)
    )
    .to_lowercase();
    let guarded = !replace_out.status.success()
        || combined.contains("pinned")
        || combined.contains("black-hole")
        || combined.contains("rotate-slot");
    assert!(
        guarded,
        "ISSUE #7: --replace silently black-holed a pinned peer. status={:?} out={combined}",
        replace_out.status
    );
}

// ---------- TEST 4: send to dead slot ----------

/// Push to a slot_id that doesn't exist on the relay. The relay should
/// 404; the sender's `wire push` should surface a meaningful error, not
/// silently report success. This is the OTHER half of #7: even if the
/// migration warning lands, an existing-pinned-peer who never re-pinned
/// should see a hard failure when their slot vanishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_send_to_nonexistent_slot_surfaces_error() {
    let relay_url = spawn_federation_relay().await;
    let (alice, _alice_h, _bob, bob_h) =
        pair_two_homes(&relay_url, "stress-alice-d", "stress-bob-d").await;

    // Corrupt alice's pin of bob: replace bob's slot_id with a fake one
    // that does not exist on the relay. This simulates the post-bind-relay
    // state from bob's perspective (alice still thinks bob is at the old
    // slot, but the relay no longer routes to anything alice can reach).
    // v0.11: peers map keyed by bob's CARD HANDLE.
    let relay_state_path = alice.join("config").join("wire").join("relay.json");
    let bytes = std::fs::read(&relay_state_path).expect("relay.json missing");
    let mut state: Value = serde_json::from_slice(&bytes).expect("relay.json malformed");
    let fake_slot_id = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    state["peers"][bob_h.as_str()]["slot_id"] = serde_json::json!(fake_slot_id);
    if let Some(eps) = state["peers"][bob_h.as_str()]["endpoints"].as_array_mut() {
        for ep in eps.iter_mut() {
            ep["slot_id"] = serde_json::json!(fake_slot_id);
        }
    }
    std::fs::write(
        &relay_state_path,
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();

    // Queue a message + push. Capture the push --json output.
    assert!(
        wire(&alice, &["send", "--queue", &bob_h, "claim", "to the void"])
            .status
            .success()
    );
    let push_out = wire(&alice, &["push", "--json"]);
    let stdout = String::from_utf8_lossy(&push_out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&push_out.stderr).into_owned();

    // Acceptable outcomes:
    //   - push exits non-zero, OR
    //   - push --json reports the event in a `failed`/`errors` array with
    //     the fake slot_id or a 404, OR
    //   - push prints a stderr warning containing "slot" + ("not found" or "404")
    let combined = format!("{stdout}\n{stderr}").to_lowercase();
    let surfaced = !push_out.status.success()
        || combined.contains("404")
        || combined.contains("not found")
        || combined.contains("slot not found")
        || combined.contains("\"failed\"")
        || combined.contains("\"errors\"")
        || combined.contains("dead slot");

    assert!(
        surfaced,
        "ISSUE #7 OTHER HALF: push to a nonexistent slot reported success and emitted no \
         operator-visible signal.\n\
         status: {:?}\nstdout: {stdout}\nstderr: {stderr}",
        push_out.status
    );
}
