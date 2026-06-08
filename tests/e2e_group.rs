//! Group-chat end-to-end test (v0.13.3, increment I2 — bidirectional room).
//!
//! Three agents: a creator (alice) and two members (bob, carol). Alice pairs
//! bilaterally with each member ONLY (canonical handle-dial → VERIFIED; star
//! topology — bob and carol never pair with each other). Alice creates a group
//! (allocating a shared relay-room slot), adds both verified members, and the
//! signed roster (room coords + every member's key) is distributed as
//! group_invite events.
//!
//! Each member posts to the ONE shared room slot; everyone pulls it. The proof
//! is the cross-member read: bob reads carol's message (and vice-versa) with a
//! VERIFIED signature, via the key introduce-pinned from the creator's signed
//! roster — neither ever paired with the other. Reuses the relay + pairing
//! harness shape from `e2e_mesh.rs`.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

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
/// (resolving via the relay's well-known), the host pulls the inbound
/// pair_drop, accepts it (bilateral gate), and the guest pulls the
/// pair_drop_ack. Both ends end up pinned VERIFIED.
fn drive_pairing(host_home: &PathBuf, guest_home: &PathBuf, relay_url: &str) {
    let host_handle = read_handle(host_home);
    let guest_handle = read_handle(guest_home);
    let domain = relay_url
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap()
        .to_string();
    let target = format!("{host_handle}@{domain}");

    let claim = wire(
        host_home,
        &["claim", &host_handle, "--public-url", relay_url, "--json"],
    );
    assert!(
        claim.status.success(),
        "host claim {host_handle} failed: stderr={}",
        String::from_utf8_lossy(&claim.stderr)
    );

    let dial = wire(
        guest_home,
        &["add", &target, "--relay", relay_url, "--json"],
    );
    assert!(
        dial.status.success(),
        "guest add {target} failed: stderr={}",
        String::from_utf8_lossy(&dial.stderr)
    );

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

    let host_pinned = wait_until(Instant::now() + Duration::from_secs(5), || {
        let p = wire(host_home, &["peers", "--json"]);
        String::from_utf8_lossy(&p.stdout).contains(guest_handle.as_str())
    });
    assert!(host_pinned, "{host_home:?} never pinned {guest_handle}");

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

/// Join code: an agent who NEVER paired with anyone joins a group from a code,
/// posts, and an existing member verifies the message — and the joiner verifies
/// the members. Proves `group invite`/`group join` + introduce-pin-on-room-token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn group_join_code_admits_unpaired_member() {
    let relay_dir = fresh_dir("jc-relay");
    let relay = wire::relay_server::Relay::new(relay_dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay_url = format!("http://{addr}");

    // alice (creator) + bob (paired member) + dave (joins by code, never paired).
    let alice = fresh_dir("jc-alice");
    let bob = fresh_dir("jc-bob");
    let dave = fresh_dir("jc-dave");
    // alice + bob bind the relay (the canonical dial flow needs published
    // slots on both pairing ends); dave joins by group code and never pairs,
    // so it stays offline.
    for (h, n) in [(&alice, "alice"), (&bob, "bob")] {
        assert!(
            wire(h, &["init", n, "--relay", &relay_url])
                .status
                .success()
        );
    }
    assert!(wire(&dave, &["init", "dave", "--offline"]).status.success());
    let bob_h = read_handle(&bob);
    let dave_h = read_handle(&dave);

    // alice pairs with bob only; creates a group + adds bob.
    drive_pairing(&alice, &bob, &relay_url);
    assert!(
        wire(&alice, &["group", "create", "open-room"])
            .status
            .success()
    );
    let list: Value =
        serde_json::from_slice(&wire(&alice, &["group", "list", "--json"]).stdout).unwrap();
    let gid = list["groups"][0]["id"].as_str().unwrap().to_string();
    assert!(
        wire(&alice, &["group", "add", &gid, &bob_h])
            .status
            .success()
    );
    assert!(wire(&alice, &["push"]).status.success());
    assert!(wire(&bob, &["pull"]).status.success());

    // alice mints a join code; dave (unpaired) redeems it.
    let inv: Value =
        serde_json::from_slice(&wire(&alice, &["group", "invite", &gid, "--json"]).stdout).unwrap();
    let code = inv["code"].as_str().expect("invite code").to_string();
    assert!(code.starts_with("wire-group:"), "code shape: {code}");
    let join = wire(&dave, &["group", "join", &code]);
    assert!(join.status.success(), "dave join failed: {join:?}");

    // dave is now in the room locally and posts; alice + bob also post.
    assert!(
        wire(
            &dave,
            &["group", "send", &gid, "hi from dave (joined by code)"]
        )
        .status
        .success()
    );
    assert!(
        wire(&bob, &["group", "send", &gid, "welcome dave"])
            .status
            .success()
    );

    // bob tails: must SEE dave's message, VERIFIED — bob never paired with dave,
    // but introduce-pins him from his group_join announcement in the room.
    let bob_tail: Value =
        serde_json::from_slice(&wire(&bob, &["group", "tail", &gid, "--json"]).stdout).unwrap();
    let bob_msgs = bob_tail["messages"].as_array().unwrap();
    let dave_msg = bob_msgs
        .iter()
        .find(|m| m["type"] == "msg" && m["text"] == "hi from dave (joined by code)");
    assert!(dave_msg.is_some(), "bob missing dave's msg: {bob_tail}");
    assert_eq!(
        dave_msg.unwrap()["verified"],
        Value::Bool(true),
        "bob must verify the joined member's message via the room-announced key: {bob_tail}"
    );
    assert!(
        bob_msgs
            .iter()
            .any(|m| m["type"] == "join" && m["from"] == dave_h),
        "bob should see dave's join notice: {bob_tail}"
    );

    // dave tails: sees bob's message verified (dave pinned the roster on join).
    let dave_tail: Value =
        serde_json::from_slice(&wire(&dave, &["group", "tail", &gid, "--json"]).stdout).unwrap();
    let dave_msgs = dave_tail["messages"].as_array().unwrap();
    let welcome = dave_msgs.iter().find(|m| m["text"] == "welcome dave");
    assert!(welcome.is_some(), "dave missing bob's welcome: {dave_tail}");
    assert_eq!(
        welcome.unwrap()["verified"],
        Value::Bool(true),
        "dave must verify a roster member pinned from the join code: {dave_tail}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn group_bidirectional_room_with_introduce_pin() {
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
    // All three bind the relay — alice pairs (dials) bilaterally with each
    // member via the canonical handle-dial flow, which needs published slots.
    assert!(
        wire(&alice, &["init", "alice", "--relay", &relay_url])
            .status
            .success()
    );
    assert!(
        wire(&bob, &["init", "bob", "--relay", &relay_url])
            .status
            .success()
    );
    assert!(
        wire(&carol, &["init", "carol", "--relay", &relay_url])
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

    // ---- 6. alice pushes the group invites; both members pull them ----
    // `group add` queued a signed group_invite (the full roster incl. room
    // slot coords + every member's key) to each member's outbox.
    assert!(wire(&alice, &["push"]).status.success());
    for m in [&bob, &carol] {
        let pull: Value = serde_json::from_slice(&wire(m, &["pull", "--json"]).stdout).unwrap();
        assert!(
            !pull["written"].as_array().unwrap().is_empty(),
            "member should receive at least one group_invite, got {pull}"
        );
        assert_eq!(pull["rejected"].as_array().unwrap().len(), 0);
    }

    // ---- 7. members post to the shared room (ingest materializes the roster
    //         + introduce-pins the other members on the creator's vouch) ----
    assert!(
        wire(&bob, &["group", "send", &gid, "hi from bob"])
            .status
            .success(),
        "bob should post to the room after ingesting the invite"
    );
    assert!(
        wire(&carol, &["group", "send", &gid, "hi from carol"])
            .status
            .success()
    );
    // bob's local roster materialized from the invite (3 members).
    let bob_list: Value =
        serde_json::from_slice(&wire(&bob, &["group", "list", "--json"]).stdout).unwrap();
    assert_eq!(
        bob_list["groups"][0]["members"].as_array().unwrap().len(),
        3,
        "bob materialized the full 3-member roster from the invite"
    );

    // alice also posts (creator into the same room).
    assert!(
        wire(&alice, &["group", "send", &gid, "ship it 🚀"])
            .status
            .success()
    );

    // ---- 8. everyone tails the same room and sees ALL messages, verified ----
    // The cross-member reads are the bidirectional proof: bob reads carol's
    // message (and vice-versa) verified=true via the introduce-pinned key —
    // neither ever paired with the other.
    let tail_texts = |home: &PathBuf| -> (Vec<String>, bool) {
        let tail: Value =
            serde_json::from_slice(&wire(home, &["group", "tail", &gid, "--json"]).stdout).unwrap();
        let msgs = tail["messages"].as_array().unwrap();
        let texts = msgs
            .iter()
            .filter_map(|x| x["text"].as_str().map(str::to_string))
            .collect();
        let all_verified = msgs.iter().all(|x| x["verified"].as_bool() == Some(true));
        (texts, all_verified)
    };

    for home in [&alice, &bob, &carol] {
        let (texts, all_verified) = tail_texts(home);
        assert!(
            texts.iter().any(|t| t == "hi from bob"),
            "{home:?} missing bob's msg: {texts:?}"
        );
        assert!(
            texts.iter().any(|t| t == "hi from carol"),
            "{home:?} missing carol's msg: {texts:?}"
        );
        assert!(
            texts.iter().any(|t| t == "ship it 🚀"),
            "{home:?} missing alice's msg: {texts:?}"
        );
        assert!(
            all_verified,
            "{home:?} saw an UNVERIFIED group message — introduce-pin failed: {texts:?}"
        );
    }
}
