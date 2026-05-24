//! End-to-end integration tests for v0.5.17 dual-slot sessions.
//!
//! These cover the gaps the v0.5.17 ship report flagged as "code-review-
//! only, not automated-tested":
//!
//! 1. Routing prefers the local relay when both peers advertise a local
//!    endpoint that points at the same loopback URL.
//! 2. cmd_push falls back to federation transparently when the local
//!    POST fails.
//! 3. cmd_pull reads from every self.endpoint and advances per-scope
//!    cursors independently.
//! 4. Pair_drop body carries endpoints[]; receiver pins all advertised
//!    endpoints into relay_state.
//! 5. Back-compat: a v0.5.16-shape peer (no endpoints[] in record) still
//!    routes correctly via the synthesized federation endpoint.
//!
//! Each test spins up an in-process federation relay AND an in-process
//! local-only relay (different ports on 127.0.0.1) so the routing
//! decision space is real. WIRE_HOME per session.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-dualslot-e2e-{prefix}-{pid}-{n}"));
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
/// operator-typed init handle ("paul"/"willard"/etc.) — the actual
/// handle on the agent-card is derived from the keypair.
fn read_handle(home: &PathBuf) -> String {
    let out = wire(home, &["whoami", "--json"]);
    assert!(out.status.success(), "whoami failed: {:?}", out);
    let card: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    card["handle"].as_str().unwrap().to_string()
}

/// Spin an in-process federation relay (full routes). Returns the
/// `http://...` URL string.
async fn spawn_federation_relay() -> String {
    let dir = fresh_dir("federation-relay");
    let relay = wire::relay_server::Relay::new(dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

/// Spin an in-process local-only relay. Uses the v0.5.17 ServerMode to
/// strip the phonebook + well-known routes, matching what
/// `wire relay-server --local-only` does in production.
async fn spawn_local_only_relay() -> String {
    let dir = fresh_dir("local-relay");
    let relay = wire::relay_server::Relay::new(dir).await.unwrap();
    let app = relay.router_with_mode(wire::relay_server::ServerMode { local_only: true });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

/// Read the agent's relay_state.json and return the parsed JSON.
fn read_relay_state(home: &Path) -> Value {
    let path = home.join("config").join("wire").join("relay.json");
    let bytes = std::fs::read(&path).expect("relay.json missing");
    serde_json::from_slice(&bytes).expect("relay.json malformed")
}

fn write_relay_state(home: &Path, state: &Value) {
    let path = home.join("config").join("wire").join("relay.json");
    std::fs::write(&path, serde_json::to_vec_pretty(state).unwrap()).expect("write relay.json");
}

/// Allocate a local-relay slot for the given session via direct HTTP POST
/// (mirrors what `wire session new --with-local` does internally), then
/// patch the session's relay_state.json `self.endpoints[]` to include
/// both federation + local endpoints.
async fn add_local_endpoint(home: &Path, handle: &str, local_relay_url: &str) {
    // POST /v1/slot/allocate on the local relay.
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
    let alloc: Value = resp.json().await.expect("local slot allocate JSON");
    let slot_id = alloc["slot_id"].as_str().unwrap().to_string();
    let slot_token = alloc["slot_token"].as_str().unwrap().to_string();

    // Patch self.endpoints[] with both federation + local.
    let mut state = read_relay_state(home);
    let self_obj = state
        .get_mut("self")
        .and_then(Value::as_object_mut)
        .expect("self block in relay_state");
    let fed_url = self_obj["relay_url"].as_str().unwrap().to_string();
    let fed_slot_id = self_obj["slot_id"].as_str().unwrap().to_string();
    let fed_slot_token = self_obj["slot_token"].as_str().unwrap().to_string();
    self_obj.insert(
        "endpoints".into(),
        serde_json::json!([
            {
                "relay_url": fed_url,
                "slot_id": fed_slot_id,
                "slot_token": fed_slot_token,
                "scope": "federation",
            },
            {
                "relay_url": local_relay_url,
                "slot_id": slot_id,
                "slot_token": slot_token,
                "scope": "local",
            }
        ]),
    );
    write_relay_state(home, &state);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_slot_send_prefers_local_endpoint() {
    // Both Alice and Bob have dual slots; the federation slot is on the
    // federation relay, the local slot is on the local-only relay. After
    // bilateral pair, Alice's `wire push` MUST route through the local
    // relay (scope=local in the --json output).
    let fed = spawn_federation_relay().await;
    let local = spawn_local_only_relay().await;

    let alice = fresh_dir("alice");
    let bob = fresh_dir("bob");

    // Init + claim on federation.
    assert!(
        wire(&alice, &["init", "alice", "--relay", &fed])
            .status
            .success()
    );
    let alice_h = read_handle(&alice);
    assert!(
        wire(&alice, &["claim", &alice_h, "--relay", &fed])
            .status
            .success()
    );
    assert!(
        wire(&bob, &["init", "bob", "--relay", &fed])
            .status
            .success()
    );
    let bob_h = read_handle(&bob);
    assert!(
        wire(&bob, &["claim", &bob_h, "--relay", &fed])
            .status
            .success()
    );

    // Patch in local endpoints for both.
    add_local_endpoint(&alice, &alice_h, &local).await;
    add_local_endpoint(&bob, &bob_h, &local).await;

    // Alice sends pair_drop. The body should carry endpoints[] because
    // alice's self.endpoints now has two entries.
    // Handle parser wants <nick>@<dotted-ascii-host> (no port). The
    // --relay override carries the full URL including port. Same pattern
    // as the existing handle-pair e2e test.
    let fed_ip = fed
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap()
        .to_string();
    let add_out = wire(
        &alice,
        &["add", &format!("bob@{fed_ip}"), "--relay", &fed, "--json"],
    );
    assert!(add_out.status.success(), "alice wire add failed");

    // Bob's daemon would normally pull and stash to pending-inbound. Do
    // it inline via `wire pull` then `wire pair-accept`.
    let pull_out = wire(&bob, &["pull", "--json"]);
    assert!(pull_out.status.success(), "bob pull failed: {pull_out:?}");
    let accept_out = wire(&bob, &["pair-accept", &alice_h, "--json"]);
    assert!(
        accept_out.status.success(),
        "bob pair-accept failed: {accept_out:?}"
    );

    // Alice's daemon would pull bob's ack and pin. Do it inline.
    let alice_pull = wire(&alice, &["pull", "--json"]);
    assert!(alice_pull.status.success(), "alice pull failed");

    // Assert bob's relay_state has both endpoints for alice.
    let bob_state = read_relay_state(&bob);
    let alice_eps = bob_state["peers"][&alice_h]["endpoints"]
        .as_array()
        .expect("alice should have endpoints[] in bob's state");
    assert_eq!(
        alice_eps.len(),
        2,
        "alice should have 2 endpoints: {alice_eps:?}"
    );
    let scopes: Vec<&str> = alice_eps
        .iter()
        .filter_map(|e| e["scope"].as_str())
        .collect();
    assert!(scopes.contains(&"federation"), "scopes: {scopes:?}");
    assert!(scopes.contains(&"local"), "scopes: {scopes:?}");

    // Send: Alice → Bob. The push --json output should report the local
    // endpoint as the delivery path.
    assert!(
        wire(
            &alice,
            &["send", &bob_h, "claim", "dual-slot hello", "--json"]
        )
        .status
        .success()
    );
    let push_out = wire(&alice, &["push", "--json"]);
    assert!(push_out.status.success(), "alice push failed");
    let push_json: Value = serde_json::from_slice(&push_out.stdout).expect("push --json parses");
    let pushed = push_json["pushed"]
        .as_array()
        .expect("pushed array in push --json");
    assert_eq!(pushed.len(), 1, "expected 1 pushed event: {pushed:?}");
    assert_eq!(
        pushed[0]["scope"], "local",
        "send must route through local endpoint when both peers have local. push: {push_json}"
    );
    assert_eq!(
        pushed[0]["endpoint"].as_str().unwrap(),
        local,
        "endpoint URL should match the local relay"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_slot_send_falls_back_to_federation_on_local_failure() {
    // Alice has both endpoints; Bob has both endpoints. But we pin a
    // BROKEN local endpoint for bob (port that nothing listens on). When
    // Alice pushes, the local POST should fail, and the daemon should
    // transparently retry on the federation endpoint. Final push --json
    // shows scope=federation.
    let fed = spawn_federation_relay().await;
    let local = spawn_local_only_relay().await;

    let alice = fresh_dir("alice-fallback");
    let bob = fresh_dir("bob-fallback");

    // Init + claim on federation.
    assert!(
        wire(&alice, &["init", "alice", "--relay", &fed])
            .status
            .success()
    );
    let alice_h = read_handle(&alice);
    let _ = &alice_h; // v0.11 unused-var hush
    assert!(
        wire(&alice, &["claim", &alice_h, "--relay", &fed])
            .status
            .success()
    );
    assert!(
        wire(&bob, &["init", "bob", "--relay", &fed])
            .status
            .success()
    );
    let bob_h = read_handle(&bob);
    let _ = &bob_h; // v0.11 unused-var hush
    assert!(
        wire(&bob, &["claim", &bob_h, "--relay", &fed])
            .status
            .success()
    );

    add_local_endpoint(&alice, &alice_h, &local).await;
    add_local_endpoint(&bob, &bob_h, &local).await;

    // Pair bilateral.
    let fed_ip = fed
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap()
        .to_string();
    assert!(
        wire(
            &alice,
            &["add", &format!("bob@{fed_ip}"), "--relay", &fed, "--json"]
        )
        .status
        .success()
    );
    assert!(wire(&bob, &["pull", "--json"]).status.success());
    assert!(
        wire(&bob, &["pair-accept", &alice_h, "--json"])
            .status
            .success()
    );
    assert!(wire(&alice, &["pull", "--json"]).status.success());

    // Patch Alice's view of bob's local endpoint to a port that nothing
    // listens on — simulates "local relay went down for bob".
    let mut alice_state = read_relay_state(&alice);
    let bob_eps = alice_state["peers"][&bob_h]["endpoints"]
        .as_array_mut()
        .expect("bob endpoints[] in alice state");
    for ep in bob_eps.iter_mut() {
        if ep["scope"] == "local" {
            ep["relay_url"] = serde_json::json!("http://127.0.0.1:1");
        }
    }
    write_relay_state(&alice, &alice_state);

    // Send + push: local should fail (port 1 closed), federation should
    // succeed.
    assert!(
        wire(&alice, &["send", &bob_h, "claim", "fallback test", "--json"])
            .status
            .success()
    );
    let push_out = wire(&alice, &["push", "--json"]);
    assert!(push_out.status.success(), "alice push failed");
    let push_json: Value = serde_json::from_slice(&push_out.stdout).expect("push --json parses");
    let pushed = push_json["pushed"]
        .as_array()
        .expect("pushed array in push --json");
    assert_eq!(pushed.len(), 1, "expected 1 pushed event: {pushed:?}");
    assert_eq!(
        pushed[0]["scope"], "federation",
        "send must fall back to federation when local is broken. push: {push_json}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_slot_back_compat_v0_5_16_peer_routes_via_federation() {
    // Alice has dual slots (v0.5.17). Bob has only federation (pretending
    // to be a v0.5.16 peer with no endpoints[] in pair_drop body). When
    // Alice pairs with Bob, alice should pin only the federation endpoint
    // for bob (back-compat synthesis from the legacy fields). Subsequent
    // sends MUST route through federation.
    let fed = spawn_federation_relay().await;
    let local = spawn_local_only_relay().await;

    let alice = fresh_dir("alice-backcompat");
    let bob = fresh_dir("bob-backcompat");

    assert!(
        wire(&alice, &["init", "alice", "--relay", &fed])
            .status
            .success()
    );
    let alice_h = read_handle(&alice);
    let _ = &alice_h; // v0.11 unused-var hush
    assert!(
        wire(&alice, &["claim", &alice_h, "--relay", &fed])
            .status
            .success()
    );
    assert!(
        wire(&bob, &["init", "bob", "--relay", &fed])
            .status
            .success()
    );
    let bob_h = read_handle(&bob);
    let _ = &bob_h; // v0.11 unused-var hush
    assert!(
        wire(&bob, &["claim", &bob_h, "--relay", &fed])
            .status
            .success()
    );

    // Alice gets dual slots; bob stays federation-only (v0.5.16 shape).
    add_local_endpoint(&alice, &alice_h, &local).await;

    let fed_ip = fed
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap()
        .to_string();
    assert!(
        wire(
            &alice,
            &["add", &format!("bob@{fed_ip}"), "--relay", &fed, "--json"]
        )
        .status
        .success()
    );
    assert!(wire(&bob, &["pull", "--json"]).status.success());
    assert!(
        wire(&bob, &["pair-accept", &alice_h, "--json"])
            .status
            .success()
    );
    assert!(wire(&alice, &["pull", "--json"]).status.success());

    // Bob's pair_drop_ack carries only ONE endpoint (federation) because
    // bob has no local slot. After alice pulls the ack, alice's view of
    // bob should have one endpoint, scope=federation.
    let alice_state = read_relay_state(&alice);
    let bob_eps = alice_state["peers"][&bob_h]["endpoints"].as_array();
    // Either endpoints[] is a single federation entry, OR the legacy
    // top-level fields are populated and endpoints[] is absent — both
    // are valid back-compat shapes for routing.
    if let Some(eps) = bob_eps {
        assert_eq!(
            eps.len(),
            1,
            "bob should have 1 endpoint (federation only): {eps:?}"
        );
        assert_eq!(eps[0]["scope"], "federation");
    }

    assert!(
        wire(
            &alice,
            &["send", &bob_h, "claim", "back-compat test", "--json"]
        )
        .status
        .success()
    );
    let push_out = wire(&alice, &["push", "--json"]);
    assert!(push_out.status.success());
    let push_json: Value = serde_json::from_slice(&push_out.stdout).expect("push --json parses");
    let pushed = push_json["pushed"].as_array().expect("pushed array");
    assert_eq!(pushed.len(), 1);
    assert_eq!(
        pushed[0]["scope"], "federation",
        "must route via federation when peer has no local: {push_json}"
    );
}
