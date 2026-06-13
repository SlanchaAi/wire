//! Hermetic e2e for RFC-001 §6 project fan-out recipient selection, driven
//! through the real `wire` binary (no relay needed).
//!
//! `wire send-project <tag>` selects recipients = pinned peers at effective
//! tier >= ORG_VERIFIED whose pinned card carries `project == <tag>`, then
//! delivers one signed event to each. This test proves the *selection* end to
//! end: it builds a sender whose trust.json pins four peers — two tagged with
//! the target project at ORG_VERIFIED, one tagged with a different project, one
//! tagged with the target project but UNTRUSTED — and asserts `send-project
//! --json` fans out to exactly the two eligible peers.
//!
//! Delivery itself fails here (the sender has no relay slots for these
//! fabricated peers), but the `--json` output lists the resolved `recipients`
//! before delivery is attempted, which is the routing decision under test. The
//! delivery path itself is the same `send::attempt_deliver` that `wire send`
//! already exercises live.

use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("wire-fanout-e2e-{prefix}-{pid}-{n}"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn wire_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wire"))
}

fn wire(home: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(wire_bin())
        .args(args)
        .env("WIRE_HOME", home)
        .env("WIRE_HOME_FORCE", "1")
        .output()
        .expect("spawn wire")
}

/// Init an offline peer home and return (handle, its signed agent-card JSON).
fn make_peer(prefix: &str, project: &str) -> (String, Value) {
    let home = fresh_dir(prefix);
    assert!(
        wire(&home, &["init", prefix, "--offline"]).status.success(),
        "init {prefix} failed"
    );
    // Tag the card with a project, then read it back.
    assert!(
        wire(&home, &["project", project]).status.success(),
        "set project on {prefix} failed"
    );
    let whoami: Value = serde_json::from_slice(&wire(&home, &["whoami", "--json"]).stdout).unwrap();
    let handle = whoami["handle"].as_str().unwrap().to_string();
    let card: Value =
        serde_json::from_slice(&std::fs::read(home.join("config/wire/agent-card.json")).unwrap())
            .unwrap();
    assert_eq!(
        card.get("project").and_then(Value::as_str),
        Some(project),
        "card for {prefix} should carry project={project}"
    );
    (handle, card)
}

#[test]
fn send_project_fans_out_only_to_eligible_peers() {
    // Sender A.
    let a = fresh_dir("sender");
    assert!(
        wire(&a, &["init", "sender", "--offline"]).status.success(),
        "init sender failed"
    );

    // Four peers with distinct (tier, project) combinations.
    let (b, b_card) = make_peer("bravo", "print-shop"); // ORG_VERIFIED + match  → IN
    let (c, c_card) = make_peer("charlie", "print-shop"); // ORG_VERIFIED + match → IN
    let (d, d_card) = make_peer("delta", "lora-training"); // ORG_VERIFIED, wrong project → OUT
    let (e, e_card) = make_peer("echo", "print-shop"); // UNTRUSTED + match → OUT

    let did = |card: &Value| card["did"].as_str().unwrap().to_string();
    let trust = json!({
        "version": 1,
        "agents": {
            b.clone(): { "tier": "ORG_VERIFIED", "did": did(&b_card), "card": b_card },
            c.clone(): { "tier": "ORG_VERIFIED", "did": did(&c_card), "card": c_card },
            d.clone(): { "tier": "ORG_VERIFIED", "did": did(&d_card), "card": d_card },
            e.clone(): { "tier": "UNTRUSTED",    "did": did(&e_card), "card": e_card },
        }
    });
    std::fs::write(
        a.join("config/wire/trust.json"),
        serde_json::to_vec_pretty(&trust).unwrap(),
    )
    .unwrap();

    // Fan out to print-shop. Delivery fails (no relay slots), but the JSON
    // lists the resolved recipients, which is the routing decision under test.
    let out = wire(&a, &["send-project", "print-shop", "hello team", "--json"]);
    let parsed: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("send-project stdout not JSON ({e}): {:?}", out.stdout));

    let mut recipients: Vec<String> = parsed["recipients"]
        .as_array()
        .expect("recipients array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    recipients.sort();
    let mut expected = vec![b, c];
    expected.sort();
    assert_eq!(
        recipients, expected,
        "fan-out must target exactly the two ORG_VERIFIED print-shop peers; \
         got {recipients:?}, excluded={d} (wrong project) and {e} (UNTRUSTED)"
    );
    assert_eq!(parsed["project"].as_str(), Some("print-shop"));
}

#[test]
fn send_project_no_recipients_is_noop_success() {
    let a = fresh_dir("lonely");
    assert!(
        wire(&a, &["init", "lonely", "--offline"]).status.success(),
        "init failed"
    );
    // No peers pinned at all → empty fan-out, exit 0, recipients = [].
    let out = wire(&a, &["send-project", "anything", "ping", "--json"]);
    assert!(
        out.status.success(),
        "empty fan-out must be a no-op success, got {:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["recipients"].as_array().unwrap().len(), 0);
    assert_eq!(parsed["delivered"].as_u64(), Some(0));
}
