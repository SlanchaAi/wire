//! e2e for RFC-001 §T19/§T20 key rotation through the real `wire` binary.
//!
//! A wire DID commits to its key, so rotating a key mints a NEW DID; the
//! rotation emits a succession cert (old key signs the `old_did → new_did`
//! handoff) and records it. This test drives `wire enroll rotate-op-key` /
//! `rotate-org-key` and asserts: the new DID differs from the old, the handoff
//! is recorded in `succession.jsonl`, and the rotated op key flows into the
//! agent-card on the next `wire init`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "wire-rotate-e2e-{prefix}-{}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn wire_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wire"))
}

fn wire_json(home: &PathBuf, args: &[&str]) -> Value {
    let out = Command::new(wire_bin())
        .args(args)
        .env("WIRE_HOME", home)
        .env("WIRE_HOME_FORCE", "1")
        .output()
        .expect("spawn wire");
    assert!(
        out.status.success(),
        "wire {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("wire {args:?} stdout not JSON ({e}): {:?}", out.stdout))
}

fn succession_lines(home: &Path) -> Vec<Value> {
    let path = home.join("config/wire/succession.jsonl");
    let body = std::fs::read_to_string(path).unwrap_or_default();
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn rotate_op_key_mints_new_did_records_succession_and_flows_to_card() {
    let home = fresh_dir("op");

    let op1 = wire_json(&home, &["enroll", "op", "--handle", "darby", "--json"]);
    let op_did_1 = op1["op_did"].as_str().unwrap().to_string();
    assert!(op_did_1.starts_with("did:wire:op:"));

    // Rotate. New op_did, distinct from the old; JSON reports the handoff.
    let rot = wire_json(&home, &["enroll", "rotate-op-key", "--json"]);
    let op_did_2 = rot["new_op_did"].as_str().unwrap().to_string();
    assert_eq!(rot["old_op_did"].as_str(), Some(op_did_1.as_str()));
    assert!(op_did_2.starts_with("did:wire:op:"));
    assert_ne!(op_did_1, op_did_2, "rotation must mint a new op_did");
    assert!(
        rot["succession_cert"]
            .as_str()
            .is_some_and(|c| !c.is_empty()),
        "rotation must emit a succession cert"
    );

    // The handoff is recorded.
    let recs = succession_lines(&home);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["kind"].as_str(), Some("op"));
    assert_eq!(recs[0]["old_did"].as_str(), Some(op_did_1.as_str()));
    assert_eq!(recs[0]["new_did"].as_str(), Some(op_did_2.as_str()));

    // The rotated key flows into the agent-card on init (card carries the NEW
    // op_did, never the old one).
    assert!(
        Command::new(wire_bin())
            .args(["init", "--offline"])
            .env("WIRE_HOME", &home)
            .env("WIRE_HOME_FORCE", "1")
            .output()
            .unwrap()
            .status
            .success()
    );
    let card = std::fs::read_to_string(home.join("config/wire/agent-card.json")).unwrap();
    assert!(
        card.contains(&op_did_2),
        "card must carry the rotated op_did"
    );
    assert!(
        !card.contains(&op_did_1),
        "card must NOT carry the pre-rotation op_did"
    );

    // A second rotation appends another handoff (old == the previous new).
    let rot2 = wire_json(&home, &["enroll", "rotate-op-key", "--json"]);
    assert_eq!(rot2["old_op_did"].as_str(), Some(op_did_2.as_str()));
    assert_eq!(succession_lines(&home).len(), 2);
}

#[test]
fn rotate_org_key_mints_new_org_did_and_records_succession() {
    let home = fresh_dir("org");
    let org1 = wire_json(
        &home,
        &["enroll", "org-create", "--handle", "slanchaai", "--json"],
    );
    let org_did_1 = org1["org_did"].as_str().unwrap().to_string();
    assert!(org_did_1.starts_with("did:wire:org:"));

    let rot = wire_json(&home, &["enroll", "rotate-org-key", &org_did_1, "--json"]);
    let org_did_2 = rot["new_org_did"].as_str().unwrap().to_string();
    assert_eq!(rot["old_org_did"].as_str(), Some(org_did_1.as_str()));
    assert!(org_did_2.starts_with("did:wire:org:"));
    assert_ne!(org_did_1, org_did_2);

    let recs = succession_lines(&home);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["kind"].as_str(), Some("org"));
    assert_eq!(recs[0]["old_did"].as_str(), Some(org_did_1.as_str()));
    assert_eq!(recs[0]["new_did"].as_str(), Some(org_did_2.as_str()));

    // The new key is stored under the new org_did → it can sign as that org.
    let member = wire_json(
        &home,
        &[
            "enroll",
            "org-add-member",
            "did:wire:op:darby-0123456789abcdef0123456789abcdef",
            "--org",
            &org_did_2,
            "--json",
        ],
    );
    assert_eq!(member["org_did"].as_str(), Some(org_did_2.as_str()));
}
