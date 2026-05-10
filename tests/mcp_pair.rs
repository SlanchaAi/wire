//! Integration tests for the MCP-driven pair flow (Goal 1).
//!
//! These tests cover behavior that pure unit tests in `pair_session::tests`
//! cannot — namely, real relay round-trips via the in-process axum relay,
//! and concurrent multi-peer pair sessions sharing one wire mcp process.
//!
//! Test isolation: each test gets a fresh `WIRE_HOME` directory + ephemeral
//! relay listening on `127.0.0.1:0`. No global state is touched.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-mcp-{prefix}-{pid}-{n}"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn wire_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wire"))
}

/// Spawn an MCP server backed by `home`, return handles for stdin/stdout-line-stream.
struct McpProc {
    child: Child,
    stdin: ChildStdin,
    out_rx: mpsc::Receiver<String>,
}

impl McpProc {
    fn spawn(home: &PathBuf) -> Self {
        let mut child = Command::new(wire_bin())
            .arg("mcp")
            .env("WIRE_HOME", home)
            // Prevent wire_pair_confirm from auto-spawning persistent
            // wire daemon / wire notify children that outlive the test.
            .env("WIRE_MCP_SKIP_AUTO_UP", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn wire mcp");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            out_rx: rx,
        }
    }

    /// Send a JSON-RPC request, block up to `timeout` for the matching response.
    fn rpc(&mut self, id: u64, method: &str, params: Value, timeout: Duration) -> Value {
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{}", serde_json::to_string(&req).unwrap()).unwrap();
        self.stdin.flush().ok();
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            let line = self
                .out_rx
                .recv_timeout(remaining)
                .expect("MCP response timed out");
            let v: Value = serde_json::from_str(&line).expect("MCP non-JSON line");
            if v.get("id").and_then(Value::as_u64) == Some(id) {
                return v;
            }
            // notifications / mismatched ids — keep reading
        }
    }

    /// Convenience wrapper for `tools/call` returning the tool's structured payload.
    /// Returns Err(message) if isError=true.
    fn tool_call(
        &mut self,
        id: u64,
        name: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        let resp = self.rpc(
            id,
            "tools/call",
            json!({"name": name, "arguments": args}),
            timeout,
        );
        let result = &resp["result"];
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let is_err = result["isError"].as_bool().unwrap_or(false);
        if is_err {
            return Err(text);
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }
}

impl Drop for McpProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Stand up an ephemeral in-process relay on a random port. Returns base URL.
async fn spawn_relay() -> String {
    let dir = fresh_dir("relay");
    let relay = wire::relay_server::Relay::new(dir).await.unwrap();
    let app = relay.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_init_via_mcp_is_idempotent_for_same_handle() {
    let home = fresh_dir("init-idem");
    let mut mcp = McpProc::spawn(&home);

    // tools/list should advertise wire_init
    let list = mcp.rpc(1, "tools/list", json!({}), Duration::from_secs(5));
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"wire_init"));
    assert!(names.contains(&"wire_pair_initiate"));
    assert!(names.contains(&"wire_pair_join"));
    assert!(names.contains(&"wire_pair_check"));
    assert!(names.contains(&"wire_pair_confirm"));

    // First init
    let r1 = mcp
        .tool_call(
            2,
            "wire_init",
            json!({"handle": "alice"}),
            Duration::from_secs(5),
        )
        .expect("first init succeeds");
    assert_eq!(r1["did"], "did:wire:alice");
    assert_eq!(r1["already_initialized"], false);

    // Second init same handle — no-op, returns existing
    let r2 = mcp
        .tool_call(
            3,
            "wire_init",
            json!({"handle": "alice"}),
            Duration::from_secs(5),
        )
        .expect("second init same handle succeeds");
    assert_eq!(r2["did"], "did:wire:alice");
    assert_eq!(r2["already_initialized"], true);
    assert_eq!(r2["fingerprint"], r1["fingerprint"]); // same key

    // Third init different handle — error
    let err = mcp
        .tool_call(
            4,
            "wire_init",
            json!({"handle": "bob"}),
            Duration::from_secs(5),
        )
        .expect_err("different handle must error");
    assert!(err.contains("already initialized"), "got: {err}");
    assert!(err.contains("bob"), "should mention attempted handle");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_initiate_returns_distinct_session_ids_for_concurrent_calls() {
    let relay_url = spawn_relay().await;
    let home = fresh_dir("multi-init");

    let mut mcp = McpProc::spawn(&home);
    mcp.tool_call(
        1,
        "wire_init",
        json!({"handle": "host", "relay_url": relay_url}),
        Duration::from_secs(10),
    )
    .expect("init");

    // Two host pair sessions in sequence (each MCP call is sequential within
    // a process; the multi-peer property is that BOTH stay alive in the
    // store concurrently, with distinct session_ids).
    let s1 = mcp
        .tool_call(
            2,
            "wire_pair_initiate",
            json!({"max_wait_secs": 0}),
            Duration::from_secs(10),
        )
        .expect("first initiate");
    let s2 = mcp
        .tool_call(
            3,
            "wire_pair_initiate",
            json!({"max_wait_secs": 0}),
            Duration::from_secs(10),
        )
        .expect("second initiate");

    let id1 = s1["session_id"].as_str().unwrap();
    let id2 = s2["session_id"].as_str().unwrap();
    let code1 = s1["code_phrase"].as_str().unwrap();
    let code2 = s2["code_phrase"].as_str().unwrap();
    assert_ne!(id1, id2, "session_ids must be distinct");
    assert_ne!(code1, code2, "code phrases must be distinct");
    assert_eq!(s1["state"], "waiting");
    assert_eq!(s2["state"], "waiting");

    // Both pollable — wire_pair_check on each returns waiting (no peer yet)
    let c1 = mcp
        .tool_call(
            4,
            "wire_pair_check",
            json!({"session_id": id1, "max_wait_secs": 0}),
            Duration::from_secs(5),
        )
        .expect("check 1");
    let c2 = mcp
        .tool_call(
            5,
            "wire_pair_check",
            json!({"session_id": id2, "max_wait_secs": 0}),
            Duration::from_secs(5),
        )
        .expect("check 2");
    assert_eq!(c1["state"], "waiting");
    assert_eq!(c2["state"], "waiting");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_pair_flow_via_mcp_with_correct_sas_finalizes() {
    let relay_url = spawn_relay().await;
    let host_home = fresh_dir("host");
    let guest_home = fresh_dir("guest");

    let mut mcp = McpProc::spawn(&host_home);

    // Init host
    mcp.tool_call(
        1,
        "wire_init",
        json!({"handle": "paul", "relay_url": relay_url}),
        Duration::from_secs(10),
    )
    .expect("init host");

    // Init guest via CLI (simulates separate machine)
    let init_g = Command::new(wire_bin())
        .args(["init", "willard"])
        .env("WIRE_HOME", &guest_home)
        .output()
        .unwrap();
    assert!(init_g.status.success());

    // Host opens pair, returns immediately (max_wait_secs=0)
    let init_resp = mcp
        .tool_call(
            2,
            "wire_pair_initiate",
            json!({"max_wait_secs": 0}),
            Duration::from_secs(10),
        )
        .expect("pair_initiate");
    let session_id = init_resp["session_id"].as_str().unwrap().to_string();
    let code = init_resp["code_phrase"].as_str().unwrap().to_string();

    // Guest joins via CLI in parallel (uses --yes for non-interactive confirm).
    let guest_handle = thread::spawn({
        let guest_home = guest_home.clone();
        let relay_url = relay_url.clone();
        move || {
            let out = Command::new(wire_bin())
                .args([
                    "pair-join",
                    &code,
                    "--relay",
                    &relay_url,
                    "--yes",
                    "--timeout",
                    "30",
                ])
                .env("WIRE_HOME", &guest_home)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "pair-join failed: stderr={}",
                String::from_utf8_lossy(&out.stderr)
            );
            // Parse JSON line on stdout, return SAS
            let s = String::from_utf8(out.stdout).unwrap();
            let v: Value = serde_json::from_str(s.trim().lines().last().unwrap()).unwrap();
            v["sas"].as_str().unwrap().to_string()
        }
    });

    // Host polls wire_pair_check until sas_ready
    let mut host_sas = None;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut req_id = 10u64;
    while Instant::now() < deadline {
        let resp = mcp
            .tool_call(
                req_id,
                "wire_pair_check",
                json!({"session_id": session_id, "max_wait_secs": 2}),
                Duration::from_secs(10),
            )
            .expect("check");
        eprintln!(
            "[test] req {} wire_pair_check -> state={:?} elapsed={:?}",
            req_id,
            resp["state"],
            deadline
                .checked_duration_since(Instant::now())
                .map(|d| Duration::from_secs(20) - d)
        );
        req_id += 1;
        if resp["state"] == "sas_ready" {
            host_sas = Some(resp["sas"].as_str().unwrap().to_string());
            break;
        }
    }
    let host_sas = host_sas.expect("host never reached sas_ready");
    eprintln!("[test] host sas_ready: {host_sas}");

    // User typed the digits back — wire_pair_confirm with correct digits.
    // Must run BEFORE joining the guest thread, because guest is blocking on
    // host's sealed bootstrap which `wire_pair_confirm` is what triggers.
    let typed_digits: String = host_sas.chars().filter(|c| c.is_ascii_digit()).collect();
    let final_resp = mcp
        .tool_call(
            req_id,
            "wire_pair_confirm",
            json!({"session_id": session_id, "user_typed_digits": typed_digits}),
            Duration::from_secs(30),
        )
        .expect("confirm");
    assert_eq!(final_resp["paired_with"], "did:wire:willard");
    assert_eq!(final_resp["peer_handle"], "willard");

    let guest_sas = guest_handle.join().unwrap();
    eprintln!("[test] guest sas: {guest_sas}");
    assert_eq!(host_sas, guest_sas, "SAS must match on both sides");

    // Verify peer pinned by checking wire_peers
    let peers = mcp
        .tool_call(req_id + 1, "wire_peers", json!({}), Duration::from_secs(5))
        .expect("peers");
    let arr = peers.as_array().unwrap();
    assert!(
        arr.iter().any(|p| p["handle"] == "willard"),
        "willard not in peer list: {peers}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_confirm_with_wrong_digits_aborts_session() {
    let relay_url = spawn_relay().await;
    let host_home = fresh_dir("host-bad");
    let guest_home = fresh_dir("guest-bad");

    let mut mcp = McpProc::spawn(&host_home);
    mcp.tool_call(
        1,
        "wire_init",
        json!({"handle": "paul", "relay_url": relay_url}),
        Duration::from_secs(10),
    )
    .unwrap();

    let init_g = Command::new(wire_bin())
        .args(["init", "willard"])
        .env("WIRE_HOME", &guest_home)
        .output()
        .unwrap();
    assert!(init_g.status.success());

    let init_resp = mcp
        .tool_call(
            2,
            "wire_pair_initiate",
            json!({"max_wait_secs": 0}),
            Duration::from_secs(10),
        )
        .unwrap();
    let session_id = init_resp["session_id"].as_str().unwrap().to_string();
    let code = init_resp["code_phrase"].as_str().unwrap().to_string();

    // Guest joins (use --yes to not block on stdin; the bootstrap exchange
    // will time out from guest's side because we're going to ABORT host —
    // so we don't await guest. Instead run it backgrounded and ignore.)
    let _guest = thread::spawn({
        let guest_home = guest_home.clone();
        let relay_url = relay_url.clone();
        move || {
            let _ = Command::new(wire_bin())
                .args([
                    "pair-join",
                    &code,
                    "--relay",
                    &relay_url,
                    "--yes",
                    "--timeout",
                    "5",
                ])
                .env("WIRE_HOME", &guest_home)
                .output();
        }
    });

    // Wait for host SAS-ready
    let mut host_sas = None;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut req_id = 10u64;
    while Instant::now() < deadline {
        let resp = mcp
            .tool_call(
                req_id,
                "wire_pair_check",
                json!({"session_id": session_id, "max_wait_secs": 2}),
                Duration::from_secs(10),
            )
            .expect("check");
        req_id += 1;
        if resp["state"] == "sas_ready" {
            host_sas = Some(resp["sas"].as_str().unwrap().to_string());
            break;
        }
    }
    assert!(host_sas.is_some(), "host never reached sas_ready");

    // User typed WRONG digits → confirm errors, session aborted
    let err = mcp
        .tool_call(
            req_id,
            "wire_pair_confirm",
            json!({"session_id": session_id, "user_typed_digits": "999999"}),
            Duration::from_secs(5),
        )
        .expect_err("wrong digits must abort");
    assert!(err.contains("mismatch"), "got: {err}");

    // Subsequent call to that session_id returns "no such session" (eagerly removed)
    let err2 = mcp
        .tool_call(
            req_id + 1,
            "wire_pair_confirm",
            json!({"session_id": session_id, "user_typed_digits": "000000"}),
            Duration::from_secs(5),
        )
        .expect_err("aborted session was removed");
    assert!(err2.contains("no such session"), "got: {err2}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_resources_list_includes_inbox_per_peer_after_pairing() {
    let relay_url = spawn_relay().await;
    let host_home = fresh_dir("res-host");
    let guest_home = fresh_dir("res-guest");

    let mut mcp = McpProc::spawn(&host_home);
    mcp.tool_call(
        1,
        "wire_init",
        json!({"handle": "paul", "relay_url": relay_url}),
        Duration::from_secs(10),
    )
    .unwrap();

    let init_g = Command::new(wire_bin())
        .args(["init", "willard"])
        .env("WIRE_HOME", &guest_home)
        .output()
        .unwrap();
    assert!(init_g.status.success());

    // Pair host ↔ guest
    let init_resp = mcp
        .tool_call(
            2,
            "wire_pair_initiate",
            json!({"max_wait_secs": 0}),
            Duration::from_secs(10),
        )
        .unwrap();
    let session_id = init_resp["session_id"].as_str().unwrap().to_string();
    let code = init_resp["code_phrase"].as_str().unwrap().to_string();

    let guest_handle = thread::spawn({
        let guest_home = guest_home.clone();
        let relay_url = relay_url.clone();
        move || {
            let out = Command::new(wire_bin())
                .args([
                    "pair-join",
                    &code,
                    "--relay",
                    &relay_url,
                    "--yes",
                    "--timeout",
                    "30",
                ])
                .env("WIRE_HOME", &guest_home)
                .output()
                .unwrap();
            assert!(out.status.success());
        }
    });

    // Drive host to sas_ready + confirm
    let mut req_id = 10u64;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut host_sas = None;
    while Instant::now() < deadline {
        let resp = mcp
            .tool_call(
                req_id,
                "wire_pair_check",
                json!({"session_id": session_id, "max_wait_secs": 2}),
                Duration::from_secs(10),
            )
            .unwrap();
        req_id += 1;
        if resp["state"] == "sas_ready" {
            host_sas = Some(resp["sas"].as_str().unwrap().to_string());
            break;
        }
    }
    let host_sas = host_sas.unwrap();
    let typed: String = host_sas.chars().filter(|c| c.is_ascii_digit()).collect();
    mcp.tool_call(
        req_id,
        "wire_pair_confirm",
        json!({"session_id": session_id, "user_typed_digits": typed}),
        Duration::from_secs(30),
    )
    .unwrap();
    guest_handle.join().unwrap();

    // resources/list should now include wire://inbox/willard + wire://inbox/all
    let list = mcp.rpc(100, "resources/list", json!({}), Duration::from_secs(5));
    let uris: Vec<&str> = list["result"]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["uri"].as_str())
        .collect();
    assert!(uris.contains(&"wire://inbox/all"), "got: {uris:?}");
    assert!(uris.contains(&"wire://inbox/willard"), "got: {uris:?}");

    // resources/read on willard's inbox returns empty (nothing sent yet) but
    // succeeds — it's a JSONL response, not an error.
    let read = mcp.rpc(
        101,
        "resources/read",
        json!({"uri": "wire://inbox/willard"}),
        Duration::from_secs(5),
    );
    assert!(read["result"]["contents"].is_array(), "got: {read}");
    assert_eq!(
        read["result"]["contents"][0]["mimeType"],
        "application/x-ndjson"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_subscribe_emits_updated_notification_on_inbox_grow() {
    // Verifies Goal 2.1: client subscribes to wire://inbox/<peer>, then a
    // fresh JSONL event landing in that peer's inbox triggers a
    // notifications/resources/updated message within ~3 poll cycles.
    let home = fresh_dir("subscribe");
    let inbox = home.join("state/wire/inbox");
    std::fs::create_dir_all(&inbox).unwrap();

    let mut mcp = McpProc::spawn(&home);
    // Init via CLI so the watcher's read_trust succeeds (verified will be
    // false for our synthetic event — that's fine; updated notifications
    // are independent of verification).
    mcp.tool_call(
        1,
        "wire_init",
        json!({"handle": "alice"}),
        Duration::from_secs(5),
    )
    .expect("init");

    // Subscribe to a specific peer URI.
    let sub_resp = mcp.rpc(
        2,
        "resources/subscribe",
        json!({"uri": "wire://inbox/willard"}),
        Duration::from_secs(5),
    );
    assert!(
        sub_resp.get("result").is_some(),
        "subscribe must succeed, got: {sub_resp}"
    );

    // Write a synthetic event to willard's inbox.
    let event = json!({
        "event_id": "evt-001",
        "from": "did:wire:willard",
        "to": "did:wire:alice",
        "type": "decision",
        "kind": 1,
        "timestamp": "2026-05-10T12:00:00Z",
        "body": "subscribe-test event",
        "sig": "fake"
    });
    let path = inbox.join("willard.jsonl");
    let line = serde_json::to_string(&event).unwrap() + "\n";
    std::fs::write(&path, line).unwrap();

    // Watcher poll is 2s; allow up to ~6s for the notification to arrive.
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut got_notification = false;
    while Instant::now() < deadline {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        match mcp.out_rx.recv_timeout(remaining) {
            Ok(line) => {
                let v: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.get("method").and_then(Value::as_str)
                    == Some("notifications/resources/updated")
                    && v["params"]["uri"] == "wire://inbox/willard"
                {
                    got_notification = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    assert!(
        got_notification,
        "expected notifications/resources/updated for wire://inbox/willard within 6s"
    );

    // Unsubscribe; subsequent events should NOT generate notifications.
    let _ = mcp.rpc(
        3,
        "resources/unsubscribe",
        json!({"uri": "wire://inbox/willard"}),
        Duration::from_secs(5),
    );
    // Add a second event.
    let event2 = json!({
        "event_id": "evt-002",
        "from": "did:wire:willard",
        "to": "did:wire:alice",
        "type": "claim",
        "kind": 2,
        "timestamp": "2026-05-10T12:01:00Z",
        "body": "after unsubscribe",
        "sig": "fake"
    });
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    use std::io::Write;
    writeln!(f, "{}", serde_json::to_string(&event2).unwrap()).unwrap();

    // Wait ~5s and verify no further updated notifications.
    let cutoff = Instant::now() + Duration::from_secs(5);
    while Instant::now() < cutoff {
        let remaining = cutoff
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        match mcp.out_rx.recv_timeout(remaining) {
            Ok(line) => {
                let v: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.get("method").and_then(Value::as_str)
                    == Some("notifications/resources/updated")
                {
                    panic!("unexpected notification after unsubscribe: {}", line);
                }
            }
            Err(_) => break,
        }
    }
}

#[test]
fn concurrent_outbox_appends_do_not_corrupt_lines() {
    use wire::config::append_outbox_record;

    // Set isolated WIRE_HOME for this test thread cluster (single process —
    // env var visible to all spawned threads).
    let home = fresh_dir("outbox-concurrent");
    // Safety: only this test sets WIRE_HOME; cargo runs each #[test] in
    // its own thread but std env is process-global. We accept the risk
    // because the other concurrent-flavored tests in this file run inside
    // the tokio runtime with their own sub-processes and DON'T touch
    // wire::config directly.
    unsafe {
        std::env::set_var("WIRE_HOME", &home);
    }

    // First init the identity so outbox dir exists with proper perms
    let init = Command::new(wire_bin())
        .args(["init", "alice"])
        .env("WIRE_HOME", &home)
        .output()
        .unwrap();
    assert!(init.status.success());

    let n_threads = 8usize;
    let n_writes_each = 20usize;
    // Build a payload >4096 bytes to exceed PIPE_BUF, so a non-locking
    // implementation would interleave bytes mid-line.
    let big_body = "x".repeat(8192);
    let line_template = format!(r#"{{"thread":N,"i":I,"body":"{big_body}"}}"#);

    let mut handles = Vec::new();
    for t in 0..n_threads {
        let line_template = line_template.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..n_writes_each {
                let line =
                    line_template
                        .replacen("N", &t.to_string(), 1)
                        .replacen("I", &i.to_string(), 1);
                append_outbox_record("peer1", line.as_bytes()).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let path = home.join("state/wire/outbox/peer1.jsonl");
    let content = std::fs::read_to_string(&path).unwrap();
    let total = (n_threads * n_writes_each) as usize;
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines.len(),
        total,
        "expected {total} lines, got {}",
        lines.len()
    );
    for (idx, line) in lines.iter().enumerate() {
        let parsed: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {idx} did not parse as JSON: {e}\nline: {line}"));
        assert!(parsed["thread"].is_number());
        assert!(parsed["i"].is_number());
    }
}
