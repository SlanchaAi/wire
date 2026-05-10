//! End-to-end tests for the `wire` binary.
//!
//! Each test isolates state by setting `WIRE_HOME` to a temp directory.
//! We invoke the compiled binary via `assert_cmd`-style direct exec — no
//! external crate, just `Command::new(CARGO_BIN)`.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_home() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-cli-test-{pid}-{n}"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn wire_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wire"))
}

fn run(home: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(wire_bin())
        .args(args)
        .env("WIRE_HOME", home)
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to spawn wire")
}

#[test]
fn version_flag_prints_semver() {
    let home = fresh_home();
    let out = run(&home, &["--version"]);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("0.1.0"), "got: {s}");
}

#[test]
fn help_flag_lists_subcommands() {
    let home = fresh_home();
    let out = run(&home, &["--help"]);
    assert!(out.status.success(), "help failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    for cmd in ["init", "join", "whoami", "peers", "send", "tail", "verify", "mcp"] {
        assert!(s.contains(cmd), "missing subcommand {cmd} in help: {s}");
    }
}

#[test]
fn whoami_before_init_errors() {
    let home = fresh_home();
    let out = run(&home, &["whoami"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("not initialized"), "stderr: {stderr}");
}

#[test]
fn init_creates_keypair_and_card() {
    let home = fresh_home();
    let out = run(&home, &["init", "paul", "--json"]);
    assert!(out.status.success(), "init failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["did"], "did:wire:paul");
    assert!(parsed["fingerprint"].as_str().unwrap().len() == 8);

    // Files exist
    assert!(home.join("config/wire/private.key").exists());
    assert!(home.join("config/wire/agent-card.json").exists());
    assert!(home.join("config/wire/trust.json").exists());
}

#[test]
fn init_twice_refuses_to_clobber() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    let out = run(&home, &["init", "paul"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("already initialized"), "stderr: {stderr}");
}

#[test]
fn whoami_after_init_returns_did_and_fingerprint() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    let out = run(&home, &["whoami", "--json"]);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["did"], "did:wire:paul");
    assert_eq!(parsed["handle"], "paul");
    assert!(parsed["capabilities"].is_array());
}

#[test]
fn peers_empty_after_init_is_self_filtered() {
    // After `wire init paul`, trust contains paul (self-attested ATTESTED).
    // `wire peers` filters self out, so we expect an empty list.
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    let out = run(&home, &["peers", "--json"]);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[test]
fn send_writes_to_outbox() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    let out = run(&home, &["send", "willard", "decision", "ship the v0.1 demo", "--json"]);
    assert!(out.status.success(), "send failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["status"], "queued");
    assert_eq!(parsed["peer"], "willard");
    assert!(parsed["event_id"].as_str().unwrap().len() == 64);

    // Outbox file contains exactly one signed JSONL event.
    let outbox = home.join("state/wire/outbox/willard.jsonl");
    assert!(outbox.exists(), "outbox file not created: {outbox:?}");
    let body = std::fs::read_to_string(&outbox).unwrap();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 1);
    let event: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event["from"], "did:wire:paul");
    assert_eq!(event["to"], "did:wire:willard");
    assert!(event.get("signature").is_some());
    assert!(event.get("event_id").is_some());
}

#[test]
fn send_idempotent_under_identical_body() {
    // The same body produces the same event_id (content-addressed).
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    let out1 = run(&home, &["send", "willard", "decision", "fixed-body", "--json"]);
    let out2 = run(&home, &["send", "willard", "decision", "fixed-body", "--json"]);
    let p1: serde_json::Value = serde_json::from_slice(&out1.stdout).unwrap();
    let p2: serde_json::Value = serde_json::from_slice(&out2.stdout).unwrap();
    // Note: timestamps differ, so event_ids differ. The dedupe-on-content
    // property requires the daemon (not yet built). This test pins the
    // current behavior so iter 6's dedupe lands as a deliberate change.
    assert_ne!(p1["event_id"], p2["event_id"], "iter 6 should make these equal");
}

#[test]
fn verify_round_trips_a_send() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    let _ = run(&home, &["send", "paul", "decision", "self-test", "--json"]);
    // Drop the queued event into a temp file and verify it.
    let outbox = home.join("state/wire/outbox/paul.jsonl");
    let line = std::fs::read_to_string(&outbox).unwrap();
    let event_path = home.join("event.json");
    std::fs::write(&event_path, line.trim_end()).unwrap();
    let out = run(&home, &["verify", event_path.to_str().unwrap(), "--json"]);
    assert!(out.status.success(), "verify failed: stderr={}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["verified"], true);
}

#[test]
fn verify_rejects_tampered_event() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    let _ = run(&home, &["send", "paul", "decision", "original", "--json"]);
    let outbox = home.join("state/wire/outbox/paul.jsonl");
    let line = std::fs::read_to_string(&outbox).unwrap();
    let mut event: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    event["body"] = serde_json::json!("tampered");
    let event_path = home.join("event.json");
    std::fs::write(&event_path, serde_json::to_string(&event).unwrap()).unwrap();
    let out = run(&home, &["verify", event_path.to_str().unwrap(), "--json"]);
    assert!(!out.status.success(), "verify should have failed");
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["verified"], false);
}

#[test]
fn join_alias_resolves_to_pair_join() {
    // `wire join` is a clap alias for `wire pair-join`. Without a relay it
    // should fail at the not-initialized check (we haven't run init in this
    // home), but the failure must come from pair-join's logic, not from clap
    // saying "unknown subcommand".
    let home = fresh_home();
    let out = run(&home, &["join", "12-ABCDEF", "--relay", "http://127.0.0.1:1"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // Either "not initialized" (uninited home) or relay healthz failure —
    // both prove the alias dispatched into pair_orchestrate.
    assert!(
        stderr.contains("not initialized") || stderr.contains("healthz"),
        "join alias didn't dispatch to pair-join (stderr: {stderr})"
    );
}

#[test]
fn mcp_initialize_then_tools_list_round_trip() {
    use std::io::Write as _;
    use std::process::Stdio;

    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);

    let mut child = Command::new(wire_bin())
        .arg("mcp")
        .env("WIRE_HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn wire mcp");

    let initialize =
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
    let initialized = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let tools_list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;

    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, "{initialize}").unwrap();
        writeln!(stdin, "{initialized}").unwrap();
        writeln!(stdin, "{tools_list}").unwrap();
    } // drops stdin → server reads EOF → exits

    let out = child.wait_with_output().expect("server didn't exit");
    assert!(out.status.success(), "mcp server crashed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "expected 2 responses (initialize + tools/list), got {}: {stdout}", lines.len());

    let init_resp: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(init_resp["result"]["protocolVersion"], "2025-06-18");

    let list_resp: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    let names: Vec<&str> = list_resp["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"wire_whoami"));
    assert!(names.contains(&"wire_send"));
    assert!(!names.contains(&"wire_init"), "wire_init MUST NOT be exposed via MCP");
    assert!(!names.contains(&"wire_join"), "wire_join MUST NOT be exposed via MCP");
}

#[test]
fn mcp_tools_call_wire_whoami() {
    use std::io::Write as _;
    use std::process::Stdio;

    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);

    let mut child = Command::new(wire_bin())
        .arg("mcp")
        .env("WIRE_HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn wire mcp");

    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize"}}"#).unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"wire_whoami","arguments":{{}}}}}}"#
        )
        .unwrap();
    }

    let out = child.wait_with_output().expect("server didn't exit");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let last_line = stdout.lines().last().unwrap();
    let resp: serde_json::Value = serde_json::from_str(last_line).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["did"], "did:wire:paul");
    assert_eq!(parsed["handle"], "paul");
}

#[test]
fn mcp_tools_call_wire_init_is_refused() {
    // Even if a malicious agent tries to call wire_init via MCP, the server
    // returns isError: true with a security explanation.
    use std::io::Write as _;
    use std::process::Stdio;

    let home = fresh_home();

    let mut child = Command::new(wire_bin())
        .arg("mcp")
        .env("WIRE_HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn wire mcp");

    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize"}}"#).unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"wire_init","arguments":{{"handle":"attacker"}}}}}}"#
        )
        .unwrap();
    }

    let out = child.wait_with_output().expect("server didn't exit");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let last = stdout.lines().last().unwrap();
    let resp: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(resp["result"]["isError"], true);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("not exposed via MCP"), "unexpected refusal: {text}");
    assert!(text.contains("human-in-loop"), "missing security explanation: {text}");

    // Critical: verify no config files were created — the server refused at the
    // protocol layer, so init's side effects must not have happened.
    assert!(!home.join("config/wire/private.key").exists());
    assert!(!home.join("config/wire/agent-card.json").exists());
}

#[test]
fn handle_validation_rejects_special_chars() {
    let home = fresh_home();
    let out = run(&home, &["init", "paul/etc"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("ASCII alphanumeric"), "stderr: {stderr}");
}

#[test]
fn status_before_init_says_not_initialized() {
    let home = fresh_home();
    let out = run(&home, &["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("not initialized"), "stdout: {stdout}");
}

#[test]
fn status_after_init_shows_did_and_zero_peers() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    let out = run(&home, &["status", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["initialized"], true);
    assert_eq!(parsed["did"], "did:wire:paul");
    assert_eq!(parsed["peers"].as_array().unwrap().len(), 0);
    assert_eq!(parsed["self_relay"], serde_json::Value::Null);
    assert_eq!(parsed["outbox"]["events"], 0);
}

#[test]
fn forget_peer_removes_pinned_record() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    // Manually write a peer pin into trust (simulating a prior pair) without
    // running the full SAS flow.
    let trust_path = home.join("config/wire/trust.json");
    let mut trust: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&trust_path).unwrap()).unwrap();
    trust["agents"]["willard"] = serde_json::json!({"tier": "VERIFIED", "did": "did:wire:willard"});
    std::fs::write(&trust_path, serde_json::to_string(&trust).unwrap()).unwrap();

    let out = run(&home, &["forget-peer", "willard", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["removed_from_trust"], true);
    assert_eq!(parsed["handle"], "willard");

    // Confirm trust.json no longer has willard
    let trust_after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&trust_path).unwrap()).unwrap();
    assert!(trust_after["agents"]["willard"].is_null());
}

#[test]
fn forget_peer_unknown_returns_removed_false() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    let out = run(&home, &["forget-peer", "ghost", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["removed"], false);
}

#[test]
fn forget_peer_purge_deletes_jsonl_files() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    // send to peer to materialize outbox file
    let _ = run(&home, &["send", "willard", "decision", "stuff"]);
    let outbox_path = home.join("state/wire/outbox/willard.jsonl");
    assert!(outbox_path.exists());

    // Force willard into trust so forget-peer sees something to remove (test
    // happens to also exercise --purge regardless of trust state).
    let trust_path = home.join("config/wire/trust.json");
    let mut trust: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&trust_path).unwrap()).unwrap();
    trust["agents"]["willard"] = serde_json::json!({"tier": "VERIFIED"});
    std::fs::write(&trust_path, serde_json::to_string(&trust).unwrap()).unwrap();

    let out = run(&home, &["forget-peer", "willard", "--purge", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!parsed["purged_files"].as_array().unwrap().is_empty());
    assert!(!outbox_path.exists(), "outbox file should be deleted with --purge");
}

#[test]
fn status_after_send_shows_outbox_depth() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul"]);
    let _ = run(&home, &["send", "willard", "decision", "hello"]);
    let _ = run(&home, &["send", "willard", "decision", "world"]);
    let out = run(&home, &["status", "--json"]);
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["outbox"]["files"], 1);
    assert_eq!(parsed["outbox"]["events"], 2);
}
