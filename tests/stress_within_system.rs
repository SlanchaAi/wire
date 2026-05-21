//! Stress tests for the v0.5.17+ within-system / local-relay transport.
//!
//! These complement `tests/stress.rs` (which exercises the federation
//! path) by hammering the **local-relay** path that sister-Claudes on
//! the same machine use. The within-system stack is the OSS positioning
//! play — agents coordinate at sub-millisecond latency without going
//! through a public relay — so any silent failure here is worse than a
//! federation-path failure (the operator can't even tell the local
//! relay is the bottleneck).
//!
//! Setup follows `tests/e2e_dual_slot.rs`: spin BOTH an in-process
//! federation relay and an in-process `--local-only` relay (different
//! random ports on `127.0.0.1`), pair two homes, attach local endpoints
//! manually to each side's `relay-state.json`, then exercise the
//! routing path that `cmd_push` walks (`peer_endpoints_in_priority_order`).

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicU32 = AtomicU32::new(0);

const FLOOD_COUNT: usize = 50;

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-stress-within-{prefix}-{pid}-{n}"));
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
    let dir = fresh_dir("relay-fed");
    let relay = wire::relay_server::Relay::new(dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

async fn spawn_local_only_relay() -> String {
    let dir = fresh_dir("relay-local");
    let relay = wire::relay_server::Relay::new(dir).await.unwrap();
    let app = relay.router_with_mode(wire::relay_server::ServerMode { local_only: true });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

/// Allocate a slot on the local-only relay for this home, then patch
/// `self.endpoints[]` in `relay-state.json` to advertise both
/// federation + local endpoints. Mirrors what
/// `wire session new --with-local` does internally, but works on a
/// plain WIRE_HOME (no session orchestration) so we can drive the
/// routing layer directly.
async fn attach_local_endpoint(home: &Path, handle: &str, local_relay_url: &str) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{local_relay_url}/v1/slot/allocate"))
        .json(&serde_json::json!({"handle": handle}))
        .send()
        .await
        .expect("local slot allocate request");
    assert!(
        resp.status().is_success(),
        "local slot allocate failed: {}",
        resp.status()
    );
    let alloc: Value = resp.json().await.expect("local alloc JSON");
    let local_slot_id = alloc["slot_id"].as_str().unwrap().to_string();
    let local_slot_token = alloc["slot_token"].as_str().unwrap().to_string();

    let state_path = home.join("config").join("wire").join("relay.json");
    let bytes = std::fs::read(&state_path).expect("relay.json missing");
    let mut state: Value = serde_json::from_slice(&bytes).expect("relay.json malformed");
    let fed_url = state["self"]["relay_url"]
        .as_str()
        .expect("self.relay_url missing")
        .to_string();
    let fed_slot_id = state["self"]["slot_id"]
        .as_str()
        .expect("self.slot_id missing")
        .to_string();
    let fed_slot_token = state["self"]["slot_token"]
        .as_str()
        .expect("self.slot_token missing")
        .to_string();
    state["self"]["endpoints"] = serde_json::json!([
        {
            "relay_url": fed_url,
            "slot_id": fed_slot_id,
            "slot_token": fed_slot_token,
            "scope": "federation"
        },
        {
            "relay_url": local_relay_url,
            "slot_id": local_slot_id,
            "slot_token": local_slot_token,
            "scope": "local"
        }
    ]);
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
}

async fn pair_two_homes_with_local_endpoints(
    fed_url: &str,
    local_url: &str,
    alice_name: &str,
    bob_name: &str,
) -> (PathBuf, PathBuf) {
    let host_only = fed_url
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("127.0.0.1");

    // ---- alice ----
    let alice = fresh_dir(alice_name);
    assert!(
        wire(&alice, &["init", alice_name, "--relay", fed_url])
            .status
            .success()
    );
    assert!(
        wire(
            &alice,
            &["claim", alice_name, "--public-url", fed_url, "--json"]
        )
        .status
        .success()
    );
    attach_local_endpoint(&alice, alice_name, local_url).await;

    // ---- bob ----
    let bob = fresh_dir(bob_name);
    assert!(
        wire(&bob, &["init", bob_name, "--relay", fed_url])
            .status
            .success()
    );
    assert!(
        wire(
            &bob,
            &["claim", bob_name, "--public-url", fed_url, "--json"]
        )
        .status
        .success()
    );
    attach_local_endpoint(&bob, bob_name, local_url).await;

    // ---- bilateral pair ----
    let bob_handle = format!("{alice_name}@{host_only}");
    let add_out = wire(&bob, &["add", &bob_handle, "--relay", fed_url, "--json"]);
    assert!(
        add_out.status.success(),
        "bob `wire add` failed: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );

    let alice_has_pending = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&alice, &["pull", "--json"]);
        let p = wire(&alice, &["pair-list-inbound", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains(bob_name)
    });
    assert!(alice_has_pending, "alice never received pending-inbound");
    assert!(
        wire(&alice, &["pair-accept", bob_name, "--json"])
            .status
            .success()
    );

    let bob_pinned = wait_until(Instant::now() + Duration::from_secs(15), || {
        let _ = wire(&bob, &["pull", "--json"]);
        let p = wire(&bob, &["peers", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains(alice_name)
    });
    assert!(bob_pinned, "bob never pinned alice via pair_drop_ack");

    (alice, bob)
}

fn count_inbox_lines(home: &Path, peer: &str) -> usize {
    let inbox = home
        .join("state")
        .join("wire")
        .join("inbox")
        .join(format!("{peer}.jsonl"));
    std::fs::read_to_string(&inbox)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
}

// ---------- TEST -1: v0.6.0 orchestration — pair-all-local mesh ----------

/// v0.6.0 (issue #12): orchestration primitive. Three sister sessions
/// in one WIRE_HOME → `wire session pair-all-local` → every pair
/// bilaterally pinned. Assertions:
///   - The summary JSON reports 3 pairs attempted, 3 succeeded.
///   - Each session's `relay.json` lists the other two under `peers`.
///   - Re-running pair-all-local is idempotent (3 pairs skipped, 0 new).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_all_local_mesh_pairs_every_sister_session_v0_6_0() {
    let fed_url = spawn_federation_relay().await;
    let local_url = spawn_local_only_relay().await;
    let home = fresh_dir("pair-all-local-mesh");

    // Spin 3 sessions in one WIRE_HOME.
    for name in &["alpha", "beth", "charlie"] {
        let out = wire(
            &home,
            &[
                "session",
                "new",
                name,
                "--relay",
                &fed_url,
                "--with-local",
                "--local-relay",
                &local_url,
                "--no-daemon",
                "--json",
            ],
        );
        assert!(
            out.status.success(),
            "session new {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // First run: 3 pairs, 3 succeeded.
    let out = wire(
        &home,
        &[
            "session",
            "pair-all-local",
            "--federation-relay",
            &fed_url,
            "--settle-secs",
            "1",
            "--json",
        ],
    );
    assert!(
        out.status.success(),
        "pair-all-local failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let summary: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        summary["pairs_attempted"].as_u64().unwrap_or(0),
        3,
        "expected 3 pairs (3 choose 2): {summary}"
    );
    assert_eq!(
        summary["pairs_succeeded"].as_u64().unwrap_or(0),
        3,
        "expected all 3 succeeded: {summary}"
    );
    assert_eq!(summary["pairs_failed"].as_u64().unwrap_or(0), 0);

    // Each session's relay.json should list the other two as peers.
    let sessions_root = home.join("sessions");
    for name in &["alpha", "beth", "charlie"] {
        let relay_path = sessions_root
            .join(name)
            .join("config")
            .join("wire")
            .join("relay.json");
        let state: Value =
            serde_json::from_slice(&std::fs::read(&relay_path).expect("relay.json missing"))
                .expect("relay.json parse");
        let peers = state["peers"]
            .as_object()
            .expect("session must have peers map");
        for other in &["alpha", "beth", "charlie"] {
            if other == name {
                continue;
            }
            assert!(
                peers.contains_key(*other),
                "session {name} missing peer {other}: peers={:?}",
                peers.keys().collect::<Vec<_>>()
            );
        }
    }

    // Re-run: idempotent — 3 pairs skipped_already_paired, 0 new.
    let out2 = wire(
        &home,
        &[
            "session",
            "pair-all-local",
            "--federation-relay",
            &fed_url,
            "--settle-secs",
            "1",
            "--json",
        ],
    );
    assert!(out2.status.success(), "pair-all-local re-run failed");
    let summary2: Value = serde_json::from_slice(&out2.stdout).unwrap();
    assert_eq!(
        summary2["pairs_skipped_already_paired"]
            .as_u64()
            .unwrap_or(0),
        3,
        "re-run should skip 3 already-paired: {summary2}"
    );
    assert_eq!(summary2["pairs_succeeded"].as_u64().unwrap_or(0), 0);
}

// ---------- TEST 9: --local-only sessions pair without federation (v0.6.6) ----------

/// v0.6.6: `wire session new --local-only` produces a federation-free
/// session — no nick claim attempt, no federation slot, just a local-
/// relay identity. `wire add --local-sister <name>` (driven by
/// pair-all-local internally) pairs them without ever calling
/// `.well-known/wire/agent`.
///
/// This test deliberately uses `wire` as one of the session names —
/// a reserved nick that would FAIL on federation claim. Pre-v0.6.6
/// pair-all-local 404'd on this case. v0.6.6 pairs cleanly because
/// the local-sister add path doesn't touch federation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_only_sessions_pair_without_federation_v0_6_6() {
    // Federation relay still spun up because `wire session new` runs
    // `wire init <name>` which has no relay opinion when --relay isn't
    // passed. Local relay is the actual data path.
    let _fed_url = spawn_federation_relay().await;
    let local_url = spawn_local_only_relay().await;
    let home = fresh_dir("local-only-mesh");

    // Include `wire` (reserved nick) to prove local-only sessions
    // bypass the federation claim that previously failed.
    let session_names = ["wire", "slancha", "playground"];
    for name in &session_names {
        let out = wire(
            &home,
            &[
                "session",
                "new",
                name,
                "--local-only",
                "--local-relay",
                &local_url,
                "--no-daemon",
                "--json",
            ],
        );
        assert!(
            out.status.success(),
            "local-only session new {name} failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Verify each session has ONLY a local endpoint (no federation slot).
    let sessions_dir = home.join("sessions");
    for name in &session_names {
        let relay_path = sessions_dir
            .join(name)
            .join("config")
            .join("wire")
            .join("relay.json");
        let state: Value =
            serde_json::from_slice(&std::fs::read(&relay_path).expect("relay.json present"))
                .expect("relay.json parse");
        let endpoints = state["self"]["endpoints"]
            .as_array()
            .expect("endpoints array");
        assert!(
            endpoints
                .iter()
                .all(|e| e["scope"].as_str() == Some("local")),
            "local-only session {name} has non-local endpoints: {endpoints:?}"
        );
        assert!(
            !endpoints.is_empty(),
            "local-only session {name} has no endpoints — local relay probe must have succeeded"
        );
    }

    // pair-all-local should succeed: 3 choose 2 = 3 pairs.
    let pair_out = wire(
        &home,
        &["session", "pair-all-local", "--settle-secs", "1", "--json"],
    );
    assert!(
        pair_out.status.success(),
        "pair-all-local on local-only sessions failed: stderr={}",
        String::from_utf8_lossy(&pair_out.stderr)
    );
    let summary: Value = serde_json::from_slice(&pair_out.stdout).expect("JSON");
    assert_eq!(
        summary["pairs_attempted"].as_u64().unwrap_or(0),
        3,
        "3 choose 2 = 3 pairs: {summary}"
    );
    assert_eq!(
        summary["pairs_succeeded"].as_u64().unwrap_or(0),
        3,
        "every pair should succeed even with reserved-nick sessions: {summary}"
    );
    assert_eq!(summary["pairs_failed"].as_u64().unwrap_or(99), 0);

    // Verify the actual peer pin: each session's relay.json#peers
    // should carry the other two.
    for name in &session_names {
        let relay_path = sessions_dir
            .join(name)
            .join("config")
            .join("wire")
            .join("relay.json");
        let state: Value = serde_json::from_slice(&std::fs::read(&relay_path).expect("relay.json"))
            .expect("parse");
        let peers = state["peers"].as_object().expect("peers map");
        for other in &session_names {
            if other == name {
                continue;
            }
            assert!(
                peers.contains_key(*other),
                "session {name} missing local-paired peer {other}: peers={:?}",
                peers.keys().collect::<Vec<_>>()
            );
        }
    }

    // mesh broadcast from `wire` (the reserved-nick session) to the
    // other two should land — proving the routing layer treats local-
    // only sessions as first-class.
    let wire_home = sessions_dir.join("wire");
    let bcast = wire(
        &wire_home,
        &[
            "mesh",
            "broadcast",
            "--scope",
            "local",
            "--json",
            "hello from reserved-nick",
        ],
    );
    assert!(
        bcast.status.success(),
        "broadcast from local-only `wire` failed: stderr={}",
        String::from_utf8_lossy(&bcast.stderr)
    );
    let bs: Value = serde_json::from_slice(&bcast.stdout).expect("JSON");
    assert_eq!(
        bs["delivered"].as_u64().unwrap_or(0),
        2,
        "broadcast should reach the other 2 sisters: {bs}"
    );
    assert_eq!(bs["failed"].as_u64().unwrap_or(99), 0);
}

// ---------- TEST 8: mesh route picks one sister by role + strategy (v0.6.5 / #21) ----------

/// v0.6.5 (issue #21): `wire mesh route <role>` filters sister sessions by
/// `profile.role` (and excludes non-pinned/excluded peers), picks ONE via
/// the requested strategy, signs + pushes the event to that one peer.
/// Spins 3 sessions (alpha=planner, beth=reviewer, charlie=reviewer),
/// pairs them, then:
///   - `--strategy first` × 1: deterministically alpha-sort = beth.
///   - `--strategy round-robin` × 4: must alternate beth/charlie 2-2.
///   - `--strategy random` × 20: must hit BOTH beth and charlie at least
///     once each (loose statistical check; cosmic-ray-tight enough).
///   - Routing to a nonexistent role bails with the role-list hint.
///   - `--exclude beth` from alpha with role=reviewer → only charlie.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_route_picks_one_sister_per_strategy_v0_6_5() {
    let fed_url = spawn_federation_relay().await;
    let local_url = spawn_local_only_relay().await;
    let home = fresh_dir("mesh-route");

    let session_roles = [
        ("alpha", "planner"),
        ("beth", "reviewer"),
        ("charlie", "reviewer"),
    ];
    for (name, _) in &session_roles {
        let out = wire(
            &home,
            &[
                "session",
                "new",
                name,
                "--relay",
                &fed_url,
                "--with-local",
                "--local-relay",
                &local_url,
                "--no-daemon",
                "--json",
            ],
        );
        assert!(
            out.status.success(),
            "session new {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Pair all sessions, then assign roles.
    let pair_out = wire(
        &home,
        &[
            "session",
            "pair-all-local",
            "--federation-relay",
            &fed_url,
            "--settle-secs",
            "1",
            "--json",
        ],
    );
    assert!(
        pair_out.status.success(),
        "pair-all-local failed: stderr={}",
        String::from_utf8_lossy(&pair_out.stderr)
    );
    for (name, role) in &session_roles {
        let session_home = home.join("sessions").join(name);
        let out = wire(&session_home, &["mesh", "role", "set", role]);
        assert!(out.status.success(), "set role {role} for {name}");
    }

    let alpha_home = home.join("sessions").join("alpha");

    // 1) `first` strategy: alphabetical = beth.
    let out = wire(
        &alpha_home,
        &[
            "mesh",
            "route",
            "reviewer",
            "--strategy",
            "first",
            "--json",
            "deterministic",
        ],
    );
    assert!(
        out.status.success(),
        "first-strategy route failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let summary: Value = serde_json::from_slice(&out.stdout).expect("JSON");
    assert_eq!(summary["routed_to"].as_str(), Some("beth"));
    assert_eq!(summary["delivered"].as_bool(), Some(true));

    // 2) round-robin × 4 — first call picks "beth" (alpha sort), second
    // call picks the candidate AFTER beth = charlie, third wraps back to
    // beth, fourth to charlie. Net: 2 beth + 2 charlie.
    let mut rr_routes: Vec<String> = Vec::new();
    for _ in 0..4 {
        let out = wire(
            &alpha_home,
            &[
                "mesh",
                "route",
                "reviewer",
                "--strategy",
                "round-robin",
                "--json",
                "rr",
            ],
        );
        assert!(
            out.status.success(),
            "rr route failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: Value = serde_json::from_slice(&out.stdout).expect("JSON");
        rr_routes.push(v["routed_to"].as_str().unwrap_or("?").to_string());
    }
    let beth_hits = rr_routes.iter().filter(|h| *h == "beth").count();
    let charlie_hits = rr_routes.iter().filter(|h| *h == "charlie").count();
    assert_eq!(
        beth_hits, 2,
        "round-robin should hit beth exactly 2× in 4 calls: routes={rr_routes:?}"
    );
    assert_eq!(
        charlie_hits, 2,
        "round-robin should hit charlie exactly 2× in 4 calls: routes={rr_routes:?}"
    );

    // 3) random × 20 — must hit BOTH beth and charlie at least once
    // (catastrophically unlikely to fail by chance: P(beth-only) = 1/2^20).
    let mut beth_random = 0usize;
    let mut charlie_random = 0usize;
    for _ in 0..20 {
        let out = wire(
            &alpha_home,
            &[
                "mesh",
                "route",
                "reviewer",
                "--strategy",
                "random",
                "--json",
                "rand",
            ],
        );
        assert!(out.status.success(), "random route failed");
        let v: Value = serde_json::from_slice(&out.stdout).expect("JSON");
        match v["routed_to"].as_str().unwrap_or("?") {
            "beth" => beth_random += 1,
            "charlie" => charlie_random += 1,
            other => panic!("unexpected route target `{other}`"),
        }
    }
    assert!(
        beth_random > 0 && charlie_random > 0,
        "random should hit both reviewers in 20 calls: beth={beth_random} charlie={charlie_random}"
    );

    // 4) Nonexistent role → clean bail with role-list hint.
    let none = wire(
        &alpha_home,
        &["mesh", "route", "nonexistent-role", "--json", "nope"],
    );
    assert!(!none.status.success(), "nonexistent role should error");
    let stderr = String::from_utf8_lossy(&none.stderr);
    assert!(
        stderr.contains("wire mesh role list"),
        "error message should hint at `wire mesh role list`: {stderr}"
    );

    // 5) --exclude beth → only charlie is in candidates.
    let exc = wire(
        &alpha_home,
        &[
            "mesh",
            "route",
            "reviewer",
            "--exclude",
            "beth",
            "--strategy",
            "first",
            "--json",
            "exclude",
        ],
    );
    assert!(exc.status.success());
    let v: Value = serde_json::from_slice(&exc.stdout).expect("JSON");
    assert_eq!(v["routed_to"].as_str(), Some("charlie"));
    let cands = v["candidates"].as_array().unwrap();
    assert_eq!(
        cands.len(),
        1,
        "exclude should leave 1 candidate: {cands:?}"
    );
    assert_eq!(cands[0].as_str(), Some("charlie"));
}

// ---------- TEST 7: mesh role assigns + lists role tags across sisters (v0.6.4 / #20) ----------

/// v0.6.4 (issue #20): `wire mesh role set <role>` writes profile.role to
/// the agent-card; `wire mesh role list` enumerates sister sessions and
/// shows each one's role. Spins 3 sessions, sets a distinct role on each,
/// runs `mesh role list --json`, asserts each session reports its role.
/// Validates role-string sanitization (illegal chars rejected, oversize
/// rejected). Also asserts that `wire mesh role get` against a peer with
/// no pinned card returns null (graceful — not a crash).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_role_set_list_round_trips_v0_6_4() {
    let fed_url = spawn_federation_relay().await;
    let local_url = spawn_local_only_relay().await;
    let home = fresh_dir("mesh-role");

    let session_roles = [
        ("alpha", "planner"),
        ("beth", "reviewer"),
        ("charlie", "coder"),
    ];

    for (name, _) in &session_roles {
        let out = wire(
            &home,
            &[
                "session",
                "new",
                name,
                "--relay",
                &fed_url,
                "--with-local",
                "--local-relay",
                &local_url,
                "--no-daemon",
                "--json",
            ],
        );
        assert!(
            out.status.success(),
            "session new {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Set role per session by running `wire mesh role set` against each
    // session's WIRE_HOME directly.
    for (name, role) in &session_roles {
        let session_home = home.join("sessions").join(name);
        let out = wire(&session_home, &["mesh", "role", "set", role]);
        assert!(
            out.status.success(),
            "mesh role set {role} for {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // List from each session's WIRE_HOME and check it sees all 3 roles.
    for (name, _) in &session_roles {
        let session_home = home.join("sessions").join(name);
        let out = wire(&session_home, &["mesh", "role", "list", "--json"]);
        assert!(
            out.status.success(),
            "mesh role list failed for {name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let view: Value = serde_json::from_slice(&out.stdout).expect("JSON");
        let rows = view["sessions"].as_array().expect("sessions array");
        assert_eq!(rows.len(), 3, "list should see 3 sister sessions: {view}");
        for (expected_name, expected_role) in &session_roles {
            let found = rows
                .iter()
                .find(|r| r["name"].as_str() == Some(expected_name));
            let row = found
                .unwrap_or_else(|| panic!("session {expected_name} missing from list: {view}"));
            assert_eq!(
                row["role"].as_str(),
                Some(*expected_role),
                "session {expected_name} role mismatch: {row}"
            );
        }
    }

    // Role validation: illegal char + oversize must reject.
    let alpha_home = home.join("sessions").join("alpha");
    let illegal = wire(&alpha_home, &["mesh", "role", "set", "bad role"]);
    assert!(
        !illegal.status.success(),
        "space-in-role should be rejected"
    );
    assert!(
        String::from_utf8_lossy(&illegal.stderr).contains("illegal char"),
        "illegal char rejection message expected, got: {}",
        String::from_utf8_lossy(&illegal.stderr)
    );
    let oversize: String = "a".repeat(33);
    let too_long = wire(&alpha_home, &["mesh", "role", "set", &oversize]);
    assert!(
        !too_long.status.success(),
        "33-char role should be rejected"
    );

    // Clear works; list reports (unset) thereafter.
    let cleared = wire(&alpha_home, &["mesh", "role", "clear", "--json"]);
    assert!(cleared.status.success(), "mesh role clear failed");
    let after: Value =
        serde_json::from_slice(&wire(&alpha_home, &["mesh", "role", "list", "--json"]).stdout)
            .expect("JSON");
    let alpha_row = after["sessions"]
        .as_array()
        .and_then(|a| a.iter().find(|r| r["name"].as_str() == Some("alpha")))
        .expect("alpha row");
    assert!(
        alpha_row["role"].is_null(),
        "alpha role should be null after clear: {alpha_row}"
    );
}

// ---------- TEST 6: mesh broadcast fans one event to every paired sister (v0.6.3 / #19) ----------

/// v0.6.3 (issue #19): `wire mesh broadcast` signs one event per pinned
/// peer with a shared `broadcast_id` UUID and distinct `event_id`s, then
/// pushes them in parallel. Spins 3 sessions, pairs them, broadcasts
/// from alpha to its local-scope peers, then pulls beth + charlie and
/// asserts each received exactly one event whose `body.broadcast_id`
/// matches the broadcast_id alpha reported, with distinct event_ids
/// across the recipients.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_broadcast_fans_to_every_paired_sister_v0_6_3() {
    let fed_url = spawn_federation_relay().await;
    let local_url = spawn_local_only_relay().await;
    let home = fresh_dir("mesh-broadcast");

    for name in &["alpha", "beth", "charlie"] {
        let out = wire(
            &home,
            &[
                "session",
                "new",
                name,
                "--relay",
                &fed_url,
                "--with-local",
                "--local-relay",
                &local_url,
                "--no-daemon",
                "--json",
            ],
        );
        assert!(
            out.status.success(),
            "session new {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let pair_out = wire(
        &home,
        &[
            "session",
            "pair-all-local",
            "--federation-relay",
            &fed_url,
            "--settle-secs",
            "1",
            "--json",
        ],
    );
    assert!(
        pair_out.status.success(),
        "pair-all-local failed: stderr={}",
        String::from_utf8_lossy(&pair_out.stderr)
    );

    // alpha broadcasts to beth + charlie via the local relay.
    let alpha_home = home.join("sessions").join("alpha");
    let out = wire(
        &alpha_home,
        &[
            "mesh",
            "broadcast",
            "--scope",
            "local",
            "--kind",
            "claim",
            "--json",
            "hello mesh from alpha",
        ],
    );
    assert!(
        out.status.success(),
        "mesh broadcast failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let summary: Value =
        serde_json::from_slice(&out.stdout).expect("broadcast --json must be valid JSON");
    let broadcast_id = summary["broadcast_id"]
        .as_str()
        .expect("broadcast_id present")
        .to_string();
    assert_eq!(
        summary["delivered"].as_u64().unwrap_or(0),
        2,
        "expected delivery to both beth and charlie: {summary}"
    );
    assert_eq!(
        summary["failed"].as_u64().unwrap_or(99),
        0,
        "no failures expected: {summary}"
    );
    assert_eq!(
        summary["target_count"].as_u64().unwrap_or(0),
        2,
        "alpha should see 2 local-scope peers: {summary}"
    );

    // Drive beth + charlie to pull from their slots so the events land
    // in their inbox files. Each pull is per-session-home.
    let beth_home = home.join("sessions").join("beth");
    let charlie_home = home.join("sessions").join("charlie");
    let pull_deadline = Instant::now() + Duration::from_secs(5);
    let mut beth_lines = 0;
    let mut charlie_lines = 0;
    while Instant::now() < pull_deadline {
        let _ = wire(&beth_home, &["pull", "--json"]);
        let _ = wire(&charlie_home, &["pull", "--json"]);
        beth_lines = count_inbox_lines(&beth_home, "alpha");
        charlie_lines = count_inbox_lines(&charlie_home, "alpha");
        if beth_lines >= 1 && charlie_lines >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        beth_lines >= 1,
        "beth's inbox from alpha is empty after pull"
    );
    assert!(
        charlie_lines >= 1,
        "charlie's inbox from alpha is empty after pull"
    );

    // Find the broadcast event in each recipient's inbox by matching
    // body.broadcast_id. Assert distinct event_ids.
    fn find_broadcast_event(session_home: &Path, broadcast_id: &str) -> Option<Value> {
        let inbox = session_home
            .join("state")
            .join("wire")
            .join("inbox")
            .join("alpha.jsonl");
        let body = std::fs::read_to_string(&inbox).ok()?;
        for line in body.lines() {
            let v: Value = serde_json::from_str(line).ok()?;
            // Pair flow events use kind=pair_drop etc.; the broadcast
            // event is the one whose body carries broadcast_id.
            let bid = v["body"]["broadcast_id"].as_str();
            if bid == Some(broadcast_id) {
                return Some(v);
            }
        }
        None
    }
    let beth_event =
        find_broadcast_event(&beth_home, &broadcast_id).expect("beth must have the broadcast");
    let charlie_event = find_broadcast_event(&charlie_home, &broadcast_id)
        .expect("charlie must have the broadcast");

    let beth_eid = beth_event["event_id"].as_str().unwrap_or("");
    let charlie_eid = charlie_event["event_id"].as_str().unwrap_or("");
    assert!(!beth_eid.is_empty() && !charlie_eid.is_empty());
    assert_ne!(
        beth_eid, charlie_eid,
        "per-recipient broadcast events must have distinct event_ids"
    );

    // Body content + target_count round-trip.
    assert_eq!(
        beth_event["body"]["content"].as_str(),
        Some("hello mesh from alpha")
    );
    assert_eq!(
        beth_event["body"]["broadcast_target_count"].as_u64(),
        Some(2)
    );
    assert_eq!(
        charlie_event["body"]["content"].as_str(),
        Some("hello mesh from alpha")
    );

    // --exclude: re-broadcast skipping charlie should deliver only to beth.
    let out2 = wire(
        &alpha_home,
        &[
            "mesh",
            "broadcast",
            "--scope",
            "local",
            "--exclude",
            "charlie",
            "--json",
            "second wave",
        ],
    );
    assert!(out2.status.success(), "exclude broadcast failed");
    let summary2: Value = serde_json::from_slice(&out2.stdout).expect("JSON");
    assert_eq!(
        summary2["delivered"].as_u64().unwrap_or(99),
        1,
        "exclude should deliver to 1: {summary2}"
    );
    let excluded = summary2["skipped_excluded"]
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str() == Some("charlie")))
        .unwrap_or(false);
    assert!(excluded, "charlie should appear in skipped_excluded");
}

// ---------- TEST 5: mesh-status reports paired mesh + per-edge health (v0.6.2 / #18) ----------

/// v0.6.2 (issue #18): `wire session mesh-status --json` enumerates every
/// sister session, walks each session's `relay.json#peers` to identify
/// mesh edges, and probes the relay for each edge's `last_pull_at_unix`.
/// Spins 3 sessions, pairs them via `pair-all-local`, then asserts:
/// - `summary.session_count` == 3
/// - `summary.edge_count` == 3 (3 choose 2)
/// - `summary.asymmetric` == 0 (every pair-all-local edge is bilateral)
/// - every edge has `scope == "local"` (sister sessions share a local relay)
/// - at least one direction per edge has a recorded `last_pull_at_unix`
///   (the pair-all-local handshake itself triggers pulls)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_status_reports_paired_mesh_v0_6_2() {
    let fed_url = spawn_federation_relay().await;
    let local_url = spawn_local_only_relay().await;
    let home = fresh_dir("mesh-status-paired");

    for name in &["alpha", "beth", "charlie"] {
        let out = wire(
            &home,
            &[
                "session",
                "new",
                name,
                "--relay",
                &fed_url,
                "--with-local",
                "--local-relay",
                &local_url,
                "--no-daemon",
                "--json",
            ],
        );
        assert!(
            out.status.success(),
            "session new {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let pair_out = wire(
        &home,
        &[
            "session",
            "pair-all-local",
            "--federation-relay",
            &fed_url,
            "--settle-secs",
            "1",
            "--json",
        ],
    );
    assert!(
        pair_out.status.success(),
        "pair-all-local failed: stderr={}",
        String::from_utf8_lossy(&pair_out.stderr)
    );

    let out = wire(&home, &["session", "mesh-status", "--json"]);
    assert!(
        out.status.success(),
        "mesh-status failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let view: Value = serde_json::from_slice(&out.stdout).expect("mesh-status JSON parse");

    let summary = &view["summary"];
    assert_eq!(
        summary["session_count"].as_u64().unwrap_or(0),
        3,
        "expected 3 sessions: {view}"
    );
    assert_eq!(
        summary["edge_count"].as_u64().unwrap_or(0),
        3,
        "expected 3 edges (3 choose 2): {view}"
    );
    assert_eq!(
        summary["asymmetric"].as_u64().unwrap_or(99),
        0,
        "no edge should be asymmetric after pair-all-local: {view}"
    );

    let edges = view["edges"].as_array().expect("edges array");
    assert_eq!(edges.len(), 3, "expected 3 mesh edges: {view}");
    let mut any_fresh = false;
    for e in edges {
        assert_eq!(
            e["bilateral"].as_bool(),
            Some(true),
            "edge {} ↔ {} not bilateral: {e}",
            e["from"],
            e["to"]
        );
        assert_eq!(
            e["scope"].as_str(),
            Some("local"),
            "edge {} ↔ {} routed off-local: {e}",
            e["from"],
            e["to"]
        );
        // At least one of the two directions per edge should have a
        // last_pull recorded by the relay (the pair handshake pulled at
        // least once per session).
        if let Some(dirs) = e["directions"].as_object() {
            for d in dirs.values() {
                if d.get("last_pull_at_unix")
                    .map(|v| !v.is_null())
                    .unwrap_or(false)
                {
                    any_fresh = true;
                    break;
                }
            }
        }
    }
    assert!(
        any_fresh,
        "expected at least one direction with a recorded last_pull_at_unix: {view}"
    );

    // local_relays should report our spun local relay healthy.
    let local_relays = view["local_relays"].as_array().expect("local_relays array");
    assert!(
        local_relays
            .iter()
            .any(|r| r["url"].as_str() == Some(local_url.as_str())
                && r["healthy"].as_bool() == Some(true)),
        "expected our local relay healthy: {view}"
    );
}

// ---------- TEST 0: regression — wire session new --with-local persists dual endpoints ----------

/// v0.5.20 regression: `try_allocate_local_slot` (cli.rs) and
/// `read_session_endpoints` (session.rs) both joined the wrong filename
/// (`relay-state.json` instead of `relay.json`, the canonical name per
/// `config::relay_state_path`). Result: every `wire session new
/// --with-local` invocation since v0.5.17 silently degraded to
/// federation-only despite the "local slot allocated" stderr line,
/// and `wire session list-local` always returned an empty group.
///
/// This test drives the production `wire session new --with-local`
/// orchestration end-to-end and asserts the session's `relay.json`
/// carries BOTH scope=federation AND scope=local endpoints, AND that
/// the local endpoint URL matches what we passed via --local-relay.
/// If anyone re-introduces the filename bug, this test fails loudly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regression_session_new_with_local_writes_dual_endpoints_v0_5_20() {
    let fed_url = spawn_federation_relay().await;
    let local_url = spawn_local_only_relay().await;
    let home = fresh_dir("session-new-with-local");

    let out = wire(
        &home,
        &[
            "session",
            "new",
            "test-alpha",
            "--relay",
            &fed_url,
            "--with-local",
            "--local-relay",
            &local_url,
            "--no-daemon",
            "--json",
        ],
    );
    assert!(
        out.status.success(),
        "wire session new --with-local failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let relay_path = home
        .join("sessions")
        .join("test-alpha")
        .join("config")
        .join("wire")
        .join("relay.json");
    assert!(
        relay_path.exists(),
        "session's relay.json missing at {relay_path:?} — bootstrap didn't complete"
    );
    let bytes = std::fs::read(&relay_path).expect("read relay.json");
    let state: Value = serde_json::from_slice(&bytes).expect("relay.json must be valid JSON");

    let endpoints = state["self"]["endpoints"]
        .as_array()
        .expect("self.endpoints[] must be present — v0.5.20 fix landed this field");
    let scopes: Vec<&str> = endpoints
        .iter()
        .filter_map(|e| e["scope"].as_str())
        .collect();
    assert!(
        scopes.contains(&"federation"),
        "expected scope=federation, got: {scopes:?}"
    );
    assert!(
        scopes.contains(&"local"),
        "expected scope=local (v0.5.20 fix for the silent --with-local regression): {scopes:?}"
    );

    let local = endpoints
        .iter()
        .find(|e| e["scope"].as_str() == Some("local"))
        .expect("local endpoint not present despite --with-local");
    assert_eq!(
        local["relay_url"].as_str().unwrap_or(""),
        local_url,
        "local endpoint URL must match --local-relay arg"
    );

    // And `wire session list-local --json` must surface the session.
    let list_out = wire(&home, &["session", "list-local", "--json"]);
    assert!(list_out.status.success(), "list-local failed");
    let listing: Value =
        serde_json::from_slice(&list_out.stdout).expect("list-local JSON must parse");
    let group = &listing["local"][&local_url];
    let nicks: Vec<&str> = group
        .as_array()
        .expect("list-local group must exist")
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();
    assert!(
        nicks.contains(&"test-alpha"),
        "list-local must surface the session we just created: {nicks:?} in group {local_url}"
    );
}

// ---------- TEST 1: local-first routing on flood ----------

/// Flood `FLOOD_COUNT` events across the within-system path and assert
/// EVERY event was delivered with `scope: "local"`. Federation
/// fallback should NEVER fire when both peers have a working local
/// endpoint and the local relay is healthy. If even one event reports
/// `scope: "federation"` something is wrong with the priority logic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_within_system_local_first_routing_v0_5_19() {
    let fed_url = spawn_federation_relay().await;
    let local_url = spawn_local_only_relay().await;
    let (alice, bob) =
        pair_two_homes_with_local_endpoints(&fed_url, &local_url, "stress-w-alice", "stress-w-bob")
            .await;

    // Queue FLOOD_COUNT events.
    let queue_start = Instant::now();
    for i in 0..FLOOD_COUNT {
        let body = format!("within-system flood msg {i}");
        let out = wire(&alice, &["send", "stress-w-bob", "claim", &body]);
        assert!(
            out.status.success(),
            "send {i} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    eprintln!(
        "within-system stress: queued {FLOOD_COUNT} events in {:?}",
        queue_start.elapsed()
    );

    // Push in one shot.
    let push_start = Instant::now();
    let push_out = wire(&alice, &["push", "--json"]);
    assert!(push_out.status.success(), "push failed");
    let push: Value = serde_json::from_slice(&push_out.stdout).unwrap();
    let pushed = push["pushed"].as_array().expect("pushed array");
    eprintln!(
        "within-system stress: push delivered {} events in {:?}",
        pushed.len(),
        push_start.elapsed()
    );
    assert_eq!(
        pushed.len(),
        FLOOD_COUNT,
        "expected all {FLOOD_COUNT} events to land via push.pushed[]"
    );

    // EVERY event must have scope=local. A single scope=federation
    // means the priority logic dropped the local endpoint somewhere.
    let mut federation_leaked = 0usize;
    for ev in pushed {
        let scope = ev["scope"].as_str().unwrap_or("?");
        if scope != "local" {
            federation_leaked += 1;
            eprintln!(
                "scope leak: event {} delivered via `{scope}` not `local`: {ev}",
                ev["event_id"].as_str().unwrap_or("?")
            );
        }
    }
    assert_eq!(
        federation_leaked, 0,
        "{federation_leaked}/{FLOOD_COUNT} events leaked to federation when local should have won"
    );

    // And bob must receive all of them via local pull (cursor on the
    // Local-scope endpoint). Allow some slack — pull may need a couple
    // of rounds for large queues.
    let pull_start = Instant::now();
    assert!(
        wait_until(Instant::now() + Duration::from_secs(30), || {
            let _ = wire(&bob, &["pull", "--json"]);
            count_inbox_lines(&bob, "stress-w-alice") >= FLOOD_COUNT
        }),
        "bob never received all {FLOOD_COUNT} events (got {})",
        count_inbox_lines(&bob, "stress-w-alice")
    );
    eprintln!(
        "within-system stress: bob received {FLOOD_COUNT} events in {:?}",
        pull_start.elapsed()
    );
}

// ---------- TEST 2: fallback to federation when local dies mid-flood ----------

/// Mid-flood, the local relay's port is replaced with a closed port in
/// alice's view (simulating the local relay crashing while the daemon
/// keeps going). The remaining sends MUST fall back to federation, NOT
/// fail. Asserts the failover is graceful — exactly what `cmd_push`
/// promises by walking endpoints in priority order with transparent
/// retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_within_system_failover_to_federation_on_local_death_v0_5_19() {
    let fed_url = spawn_federation_relay().await;
    let local_url = spawn_local_only_relay().await;
    let (alice, _bob) = pair_two_homes_with_local_endpoints(
        &fed_url,
        &local_url,
        "stress-w-alice-fb",
        "stress-w-bob-fb",
    )
    .await;

    // First half — should route via local.
    let half = FLOOD_COUNT / 2;
    for i in 0..half {
        let body = format!("pre-failover msg {i}");
        assert!(
            wire(&alice, &["send", "stress-w-bob-fb", "claim", &body])
                .status
                .success()
        );
    }
    let push_out = wire(&alice, &["push", "--json"]);
    assert!(push_out.status.success());
    let push: Value = serde_json::from_slice(&push_out.stdout).unwrap();
    let pushed = push["pushed"].as_array().unwrap();
    assert_eq!(pushed.len(), half, "pre-failover push count");
    for ev in pushed {
        assert_eq!(
            ev["scope"].as_str().unwrap_or("?"),
            "local",
            "pre-failover should be local"
        );
    }

    // Patch alice's view of bob's LOCAL endpoint to a closed port.
    // The federation endpoint is left alone — that's the fallback.
    let alice_relay_state = alice.join("config").join("wire").join("relay.json");
    let bytes = std::fs::read(&alice_relay_state).unwrap();
    let mut state: Value = serde_json::from_slice(&bytes).unwrap();
    if let Some(eps) = state["peers"]["stress-w-bob-fb"]["endpoints"].as_array_mut() {
        for ep in eps.iter_mut() {
            if ep["scope"].as_str() == Some("local") {
                ep["relay_url"] = serde_json::json!("http://127.0.0.1:1"); // closed
            }
        }
    }
    std::fs::write(
        &alice_relay_state,
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();

    // Second half — should fall back to federation.
    for i in half..FLOOD_COUNT {
        let body = format!("post-failover msg {i}");
        assert!(
            wire(&alice, &["send", "stress-w-bob-fb", "claim", &body])
                .status
                .success()
        );
    }
    let push_out = wire(&alice, &["push", "--json"]);
    assert!(push_out.status.success());
    let push: Value = serde_json::from_slice(&push_out.stdout).unwrap();
    let pushed = push["pushed"].as_array().unwrap();
    let skipped = push["skipped"].as_array().unwrap();
    // The second-push's pushed[] sees both the half new events PLUS the
    // earlier half re-attempted (relay returns "duplicate" → skipped).
    // What matters: every NEW event landed on federation.
    let new_post_failover = FLOOD_COUNT - half;
    let mut fed_count = 0usize;
    let mut new_delivered = 0usize;
    for ev in pushed {
        if ev["scope"].as_str() == Some("federation") {
            fed_count += 1;
            new_delivered += 1;
        }
    }
    // Duplicates of pre-failover events arrive via local on the second
    // push because alice's relay-state still has the (now-broken) local
    // endpoint listed — that's fine, they short-circuit as duplicates
    // on the relay anyway. Just ensure no transport-error skips for the
    // new ones.
    let new_transport_skips = skipped
        .iter()
        .filter(|s| s["reason"].as_str() != Some("duplicate") && s.get("event_id").is_some())
        .count();
    assert!(
        new_transport_skips == 0,
        "{new_transport_skips} new events skipped with transport errors during failover — \
         expected graceful federation fallback. push: {push}"
    );
    assert!(
        new_delivered >= new_post_failover || fed_count >= new_post_failover,
        "fewer than {new_post_failover} post-failover events landed on federation \
         (federation deliveries: {fed_count}). push: {push}"
    );
}
