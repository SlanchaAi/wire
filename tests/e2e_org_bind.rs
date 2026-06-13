//! e2e for RFC-001 §2 DNS-TXT org binding through the real `wire` binary,
//! against a fake DNS-over-HTTPS server (so the test is hermetic — no real DNS).
//!
//! Drives `wire org bind <domain>` with `WIRE_DOH_URL` pointed at a local axum
//! server that returns a canned `application/dns-json` TXT answer for
//! `_wire-org.acme.test`, then asserts the resolved `org_did` lands in the
//! receiver's `org_policies.json` and round-trips through `wire org list` /
//! `wire org forget`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use axum::{Json, Router, extract::Query, routing::get};
use serde_json::{Value, json};

static COUNTER: AtomicU32 = AtomicU32::new(0);

// A well-formed org DID (did:wire:org:<handle>-<32 hex>) the fake DoH serves.
const ORG_DID: &str = "did:wire:org:acme-0123456789abcdef0123456789abcdef";

fn fresh_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "wire-orgbind-e2e-{prefix}-{}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn wire_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wire"))
}

fn wire_json(home: &PathBuf, doh_url: &str, args: &[&str]) -> (bool, Value) {
    let out = Command::new(wire_bin())
        .args(args)
        .env("WIRE_HOME", home)
        .env("WIRE_HOME_FORCE", "1")
        .env("WIRE_DOH_URL", doh_url)
        .output()
        .expect("spawn wire");
    let parsed = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.success(), parsed)
}

async fn doh_handler(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
    let name = params.get("name").cloned().unwrap_or_default();
    let qtype = params.get("type").cloned().unwrap_or_default();
    if name == "_wire-org.acme.test" && qtype == "TXT" {
        Json(json!({
            "Status": 0,
            "Answer": [
                { "name": name, "type": 16, "data": format!("\"did={ORG_DID}; v=1\"") }
            ]
        }))
    } else {
        Json(json!({ "Status": 0, "Answer": [] }))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_bind_resolves_doh_and_round_trips_policy() {
    // Fake DoH server.
    let app = Router::new().route("/dns-query", get(doh_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let doh_url = format!("http://{addr}/dns-query");

    let home = fresh_dir("receiver");

    // bind acme.test → org_did, written to org_policies.json at `notify`.
    let (ok, bound) = wire_json(&home, &doh_url, &["org", "bind", "acme.test", "--json"]);
    assert!(ok, "org bind failed: {bound:?}");
    assert_eq!(bound["org_did"].as_str(), Some(ORG_DID));
    assert_eq!(bound["mode"].as_str(), Some("notify"));

    // list shows it.
    let (ok, listed) = wire_json(&home, &doh_url, &["org", "list", "--json"]);
    assert!(ok);
    let orgs = listed["orgs"].as_array().expect("orgs array");
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0]["org_did"].as_str(), Some(ORG_DID));
    assert_eq!(orgs[0]["mode"].as_str(), Some("notify"));

    // forget removes it.
    let (ok, forgotten) = wire_json(&home, &doh_url, &["org", "forget", ORG_DID, "--json"]);
    assert!(ok);
    assert_eq!(forgotten["forgotten"].as_bool(), Some(true));

    let (_ok, after) = wire_json(&home, &doh_url, &["org", "list", "--json"]);
    assert_eq!(after["orgs"].as_array().map(|a| a.len()), Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_bind_errors_when_no_record() {
    let app = Router::new().route("/dns-query", get(doh_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let doh_url = format!("http://{addr}/dns-query");

    let home = fresh_dir("nobind");
    // unknown.test has no _wire-org record → bind fails, policy stays empty.
    let (ok, _v) = wire_json(&home, &doh_url, &["org", "bind", "unknown.test", "--json"]);
    assert!(!ok, "binding a domain with no wire-org record must fail");
    let (_ok, listed) = wire_json(&home, &doh_url, &["org", "list", "--json"]);
    assert_eq!(listed["orgs"].as_array().map(|a| a.len()), Some(0));
}
