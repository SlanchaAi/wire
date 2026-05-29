//! Live two-process e2e — the offline ORG_VERIFIED auto-pair loop (RFC-001).
//!
//! This is the keystone proof that the v0.14 identity layer works end-to-end in
//! the *real* `wire` binary, not just in unit/integration tests:
//!
//!   A enrolls an operator + an org + a self-membership (`wire enroll …`), then
//!   `wire init`s — its agent-card now carries `op_did` / `op_cert` /
//!   `op_pubkey` + the org membership (card-emit wiring, #104). B writes an
//!   `org_policies.json` that auto-trusts A's org, then inits. A dials B. B
//!   pulls → consumes A's pair_drop → verifies the membership **fully offline**
//!   (no resolver, no relay round-trip for trust) and auto-pins A at
//!   `ORG_VERIFIED` (#101) — no manual accept, no SAS.
//!
//! Asserts:
//!   1. A's stored card actually carries the op + org claims (card-emit live).
//!   2. B auto-pins A at `ORG_VERIFIED` purely from the offline membership.
//!   3. A did NOT leak into B's pending-inbound — the policy opt-in genuinely
//!      bypassed the default-deny bilateral gate (the novel behavior).
//!   4. Negative control: a plain (non-member) dialer still lands in pending —
//!      the auto-pin is org-scoped, not a blanket open door.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-orgv-e2e-{prefix}-{pid}-{n}"));
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

/// Run `wire …`, assert success, parse stdout as JSON.
fn wire_json(home: &PathBuf, args: &[&str]) -> Value {
    let out = wire(home, args);
    assert!(
        out.status.success(),
        "wire {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("wire {args:?} stdout not JSON ({e}): {:?}", out.stdout))
}

/// v0.11: the on-wire handle is DID-derived, not the operator-typed init name.
fn read_handle(home: &PathBuf) -> String {
    let card = wire_json(home, &["whoami", "--json"]);
    card["handle"].as_str().unwrap().to_string()
}

// Poll cadence is deliberately gentle (750ms). Each predicate iteration cold-
// starts a `wire` subprocess; a tight loop spawning binaries floods the process
// scheduler and starves the real background daemons that the heavier e2e
// binaries (e.g. detached-pair SAS) run concurrently, tipping their deadlines.
fn wait_until<F: Fn() -> bool>(deadline: Instant, f: F) -> bool {
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(750));
    }
    false
}

/// Does B's `wire peers` list `handle` at the given tier?
fn peer_at_tier(home: &PathBuf, handle: &str, tier: &str) -> bool {
    let out = wire(home, &["peers", "--json"]);
    let peers: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    peers
        .as_array()
        .map(|arr| {
            arr.iter()
                .any(|p| p["handle"].as_str() == Some(handle) && p["tier"].as_str() == Some(tier))
        })
        .unwrap_or(false)
}

async fn spawn_relay() -> (String, String) {
    let relay_dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (format!("http://{addr}"), addr.ip().to_string())
}

// Heavy real-process e2e (spawns a relay + many `wire` subprocesses). Run
// serially out of the default parallel suite — `cargo test --test
// e2e_org_verified -- --ignored --test-threads=1` — so its subprocess churn
// doesn't starve the other real-daemon e2e binaries (notably detached-pair SAS)
// when `cargo test --all-targets` fans every binary out at once.
#[ignore = "heavy live e2e — run via `-- --ignored --test-threads=1`"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn org_member_auto_pins_org_verified_offline() {
    let (relay_url, host_only) = spawn_relay().await;

    // ---- A: enroll operator + org + self-membership, THEN init ----
    // (enroll before init so the card written at init carries the claims —
    //  #104 attaches claims at card-build time; there is no rebuild trigger.)
    let a = fresh_dir("darby");
    let op = wire_json(&a, &["enroll", "op", "--handle", "darby", "--json"]);
    let op_did = op["op_did"].as_str().unwrap().to_string();
    assert!(op_did.starts_with("did:wire:op:"), "bad op_did: {op_did}");

    let org = wire_json(
        &a,
        &["enroll", "org-create", "--handle", "slanchaai", "--json"],
    );
    let org_did = org["org_did"].as_str().unwrap().to_string();

    let m = wire_json(
        &a,
        &[
            "enroll",
            "org-add-member",
            &op_did,
            "--org",
            &org_did,
            "--json",
        ],
    );
    assert_eq!(m["org_did"].as_str(), Some(org_did.as_str()));

    assert!(
        wire(&a, &["init", "darby", "--relay", &relay_url])
            .status
            .success()
    );
    let a_h = read_handle(&a);
    assert!(
        wire(&a, &["claim", &a_h, "--public-url", &relay_url, "--json"])
            .status
            .success()
    );

    // (1) A's stored card actually carries the op + org claims (card-emit live).
    let card_str =
        std::fs::read_to_string(a.join("config/wire/agent-card.json")).expect("A agent-card");
    assert!(
        card_str.contains(&op_did),
        "A's card missing op_did claim — card-emit (#104) not wired into init"
    );
    assert!(
        card_str.contains(&org_did),
        "A's card missing org membership"
    );

    // ---- B: init + claim, then auto-trust A's org ----
    let b = fresh_dir("night-train");
    assert!(
        wire(&b, &["init", "night-train", "--relay", &relay_url])
            .status
            .success()
    );
    let b_h = read_handle(&b);
    assert!(
        wire(&b, &["claim", &b_h, "--public-url", &relay_url, "--json"])
            .status
            .success()
    );
    let policy = serde_json::json!({ "orgs": { org_did.clone(): { "inbound": "auto" } } });
    std::fs::write(
        b.join("config/wire/org_policies.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();

    // ---- A dials B → A's claims-bearing card lands in B's pair_drop ----
    let target = format!("{b_h}@{host_only}");
    let add = wire(&a, &["add", &target, "--relay", &relay_url, "--json"]);
    assert!(
        add.status.success(),
        "A add B failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    // ---- B pulls → (#101) auto-pins A at ORG_VERIFIED, no manual accept ----
    let pinned = wait_until(Instant::now() + Duration::from_secs(20), || {
        let _ = wire(&b, &["pull", "--json"]);
        peer_at_tier(&b, &a_h, "ORG_VERIFIED")
    });
    assert!(
        pinned,
        "B did not auto-pin A ({a_h}) at ORG_VERIFIED from the offline org membership"
    );

    // (3) The opt-in genuinely BYPASSED the default-deny gate: A must NOT also
    //     be sitting in B's pending-inbound.
    let pending = wire(&b, &["pair-list-inbound", "--json"]);
    assert!(
        !String::from_utf8_lossy(&pending.stdout).contains(a_h.as_str()),
        "A leaked into B's pending-inbound despite the org auto-pin"
    );
}

/// Negative control: a plain (non-member) dialer is NOT auto-pinned — it still
/// lands in pending-inbound under the default-deny bilateral gate, even though
/// B has an org policy. Proves the auto-pin is org-scoped, not a blanket door.
#[ignore = "heavy live e2e — run via `-- --ignored --test-threads=1`"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_member_dialer_still_gated_to_pending() {
    let (relay_url, host_only) = spawn_relay().await;

    // A: a plain agent — NO enrollment, NO org claims on its card.
    let a = fresh_dir("plain-dialer");
    assert!(
        wire(&a, &["init", "plain-dialer", "--relay", &relay_url])
            .status
            .success()
    );
    let a_h = read_handle(&a);

    // B: has a (different) org policy, but A is not a member of it.
    let b = fresh_dir("gatekeeper");
    assert!(
        wire(&b, &["init", "gatekeeper", "--relay", &relay_url])
            .status
            .success()
    );
    let b_h = read_handle(&b);
    assert!(
        wire(&b, &["claim", &b_h, "--public-url", &relay_url, "--json"])
            .status
            .success()
    );
    let policy = serde_json::json!({
        "orgs": { "did:wire:org:other-0000000000000000000000000000000000000000000000000000000000000000": { "inbound": "auto" } }
    });
    std::fs::write(
        b.join("config/wire/org_policies.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();

    let target = format!("{b_h}@{host_only}");
    assert!(
        wire(&a, &["add", &target, "--relay", &relay_url, "--json"])
            .status
            .success()
    );

    // B pulls → A should land in pending-inbound, NOT be auto-pinned.
    let in_pending = wait_until(Instant::now() + Duration::from_secs(20), || {
        let _ = wire(&b, &["pull", "--json"]);
        let p = wire(&b, &["pair-list-inbound", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains(a_h.as_str())
    });
    assert!(
        in_pending,
        "non-member A never reached B's pending-inbound (default-deny gate broken?)"
    );
    assert!(
        !peer_at_tier(&b, &a_h, "ORG_VERIFIED"),
        "non-member A was wrongly auto-pinned at ORG_VERIFIED"
    );
}
