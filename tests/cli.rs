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
fn join_subcommand_is_stub_and_exits_nonzero() {
    let home = fresh_home();
    let out = run(&home, &["join", "paul-7-crossover-clockwork"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("iter 5"), "stub message changed: {stderr}");
}

#[test]
fn mcp_subcommand_is_stub_and_exits_nonzero() {
    let home = fresh_home();
    let out = run(&home, &["mcp"]);
    assert!(!out.status.success());
}

#[test]
fn handle_validation_rejects_special_chars() {
    let home = fresh_home();
    let out = run(&home, &["init", "paul/etc"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("ASCII alphanumeric"), "stderr: {stderr}");
}
