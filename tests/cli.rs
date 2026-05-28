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
    // Track Cargo.toml version automatically so the test doesn't need a manual
    // bump on every release.
    let expected = env!("CARGO_PKG_VERSION");
    assert!(
        s.contains(expected),
        "got: {s} (expected to contain {expected})"
    );
}

#[test]
fn help_flag_lists_subcommands() {
    let home = fresh_home();
    let out = run(&home, &["--help"]);
    assert!(out.status.success(), "help failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    for cmd in [
        "init", "join", "whoami", "peers", "send", "tail", "verify", "mcp",
    ] {
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
    let out = run(&home, &["init", "paul", "--offline", "--json"]);
    assert!(out.status.success(), "init failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    {
        // v0.5.7+: DID is pubkey-suffixed (`did:wire:paul-<8hex>`).
        let d = parsed["did"].as_str().unwrap();
        assert!(
            d.starts_with("did:wire:") && d.len() > 17,
            "v0.11: handle = DID-derived character, expected `did:wire:<word-word>-<8hex>`, got: {d}"
        );
    }
    assert!(parsed["fingerprint"].as_str().unwrap().len() == 8);

    // Files exist
    assert!(home.join("config/wire/private.key").exists());
    assert!(home.join("config/wire/agent-card.json").exists());
    assert!(home.join("config/wire/trust.json").exists());
}

#[test]
fn init_twice_refuses_to_clobber() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let out = run(&home, &["init", "paul", "--offline"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("already initialized"), "stderr: {stderr}");
}

#[test]
fn whoami_after_init_returns_did_and_fingerprint() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let out = run(&home, &["whoami", "--json"]);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    {
        // v0.5.7+: DID is pubkey-suffixed (`did:wire:paul-<8hex>`).
        let d = parsed["did"].as_str().unwrap();
        assert!(
            d.starts_with("did:wire:") && d.len() > 17,
            "v0.11: handle = DID-derived character, expected `did:wire:<word-word>-<8hex>`, got: {d}"
        );
    }
    {
        // v0.11: handle = DID-derived character, not operator-typed "paul".
        let h = parsed["handle"].as_str().unwrap();
        let d = parsed["did"].as_str().unwrap();
        assert!(!h.is_empty(), "handle should be non-empty: {h}");
        assert!(
            d.contains(h),
            "did slug must contain handle: did={d} handle={h}"
        );
    }
    assert!(parsed["capabilities"].is_array());
}

#[test]
fn peers_empty_after_init_is_self_filtered() {
    // After `wire init paul`, trust contains paul (self-attested ATTESTED).
    // `wire peers` filters self out, so we expect an empty list.
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let out = run(&home, &["peers", "--json"]);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[test]
fn send_writes_to_outbox() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let out = run(
        &home,
        &[
            "send",
            "willard",
            "decision",
            "ship the v0.1 demo",
            "--json",
        ],
    );
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
    {
        let from = event["from"].as_str().unwrap();
        assert!(from.starts_with("did:wire:"), "from: {from}");
    }
    // `to` is constructed at send time from the peer-handle the operator
    // typed; sender doesn't know the peer's pubkey yet, so the legacy
    // (handle-only) DID form is preserved here.
    assert_eq!(event["to"], "did:wire:willard");
    assert!(event.get("signature").is_some());
    assert!(event.get("event_id").is_some());
}

/// Helper: write a fixture pending-inbound record directly into the
/// temp HOME's pending-inbound dir. Mimics what `maybe_consume_pair_drop`
/// would produce when a stranger's pair_drop lands on the receiver side.
fn write_pending_inbound_fixture(home: &std::path::Path, peer_handle: &str) {
    let dir = home.join("state/wire/pending-inbound-pairs");
    std::fs::create_dir_all(&dir).unwrap();
    let body = serde_json::json!({
        "peer_handle": peer_handle,
        "peer_did": format!("did:wire:{peer_handle}-abcdef12"),
        "peer_card": {"did": format!("did:wire:{peer_handle}-abcdef12")},
        "peer_relay_url": "https://relay.example",
        "peer_slot_id": "slot-xyz",
        "peer_slot_token": "token-xyz",
        "event_id": "evt-1",
        "event_timestamp": "2026-05-17T20:00:00Z",
        "received_at": "2026-05-17T20:00:01Z",
    });
    std::fs::write(
        dir.join(format!("{peer_handle}.json")),
        serde_json::to_vec_pretty(&body).unwrap(),
    )
    .unwrap();
}

#[test]
fn pair_list_inbound_surfaces_pending_v0_5_14() {
    // v0.5.14: zero-paste pair_drops from strangers land in pending-inbound
    // and surface programmatically via `wire pair-list-inbound --json`.
    // Receiver auto-pin was the v0.5.13 spam vector; this test asserts the
    // record is enumerable + the back-compat `pair-list --json` shape is
    // preserved for existing scripts.
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    write_pending_inbound_fixture(&home, "stranger");
    // v0.10: migrated from `wire pair-list-inbound` (removed) to
    // `wire pending`. Same underlying handler; canonical verb.
    let out = run(&home, &["pending", "--json"]);
    assert!(out.status.success(), "pending failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    let arr = parsed.as_array().expect("flat array of pending-inbound");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["peer_handle"], "stranger");
    assert_eq!(arr[0]["peer_slot_token"], "token-xyz");
}

#[test]
fn status_reports_pending_inbound_count_v0_5_14() {
    // `wire status --json` must surface inbound_count separately from
    // SPAKE2 pending_pairs.total so monitoring + dashboards can distinguish
    // "stranger requests awaiting accept" from "active SPAKE2 sessions".
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    write_pending_inbound_fixture(&home, "alice");
    write_pending_inbound_fixture(&home, "bob");
    let out = run(&home, &["status", "--json"]);
    assert!(out.status.success(), "status failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["pending_pairs"]["inbound_count"], 2);
    let mut handles: Vec<&str> = parsed["pending_pairs"]["inbound_handles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    handles.sort();
    assert_eq!(handles, vec!["alice", "bob"]);
}

#[test]
fn pair_reject_deletes_pending_inbound_v0_5_14() {
    // `wire pair-reject <peer>` removes the pending record. After reject,
    // pair-list MUST NOT show the peer and the on-disk file MUST be gone.
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    write_pending_inbound_fixture(&home, "spammer");
    let path = home.join("state/wire/pending-inbound-pairs/spammer.json");
    assert!(path.exists(), "fixture file should exist pre-reject");

    // v0.10: migrated from `wire pair-reject` (removed) to `wire reject`.
    let out = run(&home, &["reject", "spammer", "--json"]);
    assert!(out.status.success(), "reject failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["rejected"], true);
    assert!(
        !path.exists(),
        "pending file should be deleted after reject"
    );

    // pending list is now empty.
    let out2 = run(&home, &["pending", "--json"]);
    let s2 = String::from_utf8(out2.stdout).unwrap();
    let parsed2: serde_json::Value = serde_json::from_str(&s2).unwrap();
    assert!(parsed2.as_array().unwrap().is_empty());
}

// ---------- v0.5.16 session tests ----------
//
// `wire session new` calls `claim` against the relay, so a fully-offline
// test of the bootstrap flow would need to stand up the in-process relay
// (see tests/e2e_*.rs). Here we exercise the OFFLINE surface — list, env,
// current, destroy — by pre-populating a session dir + registry as the
// `new` command would. This keeps the test fast (no network) while
// asserting the operator-facing UX contract.

fn write_session_fixture(
    home: &std::path::Path,
    session_name: &str,
    cwd_key: Option<&str>,
) -> std::path::PathBuf {
    let sessions_root = home.join("sessions");
    let session_home = sessions_root.join(session_name);
    let card_dir = session_home.join("config").join("wire");
    std::fs::create_dir_all(&card_dir).unwrap();
    let card = serde_json::json!({
        "did": format!("did:wire:{session_name}-deadbeef"),
        "handle": session_name,
        "verify_keys": {
            format!("ed25519:{session_name}:deadbeef"): {
                "active": true,
                "alg": "ed25519",
                "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            }
        }
    });
    std::fs::write(
        card_dir.join("agent-card.json"),
        serde_json::to_vec_pretty(&card).unwrap(),
    )
    .unwrap();
    if let Some(cwd) = cwd_key {
        let registry = serde_json::json!({
            "by_cwd": {cwd: session_name}
        });
        std::fs::write(
            sessions_root.join("registry.json"),
            serde_json::to_vec_pretty(&registry).unwrap(),
        )
        .unwrap();
    } else {
        // Ensure sessions root exists even when no registry is requested.
        std::fs::create_dir_all(&sessions_root).unwrap();
    }
    session_home
}

#[test]
fn session_list_empty_reports_no_sessions_v0_5_16() {
    let home = fresh_home();
    let out = run(&home, &["session", "list"]);
    assert!(out.status.success(), "session list failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("no sessions on this machine"),
        "expected empty hint, got: {stdout}"
    );
}

#[test]
fn session_list_enumerates_on_disk_sessions_v0_5_16() {
    let home = fresh_home();
    write_session_fixture(&home, "wire", Some("/Users/paul/Source/wire"));
    write_session_fixture(
        &home,
        "slancha-mesh",
        Some("/Users/paul/Source/slancha-mesh"),
    );

    let out = run(&home, &["session", "list", "--json"]);
    assert!(
        out.status.success(),
        "session list --json failed: {:?}",
        out
    );
    let s = String::from_utf8(out.stdout).unwrap();
    let arr: serde_json::Value = serde_json::from_str(&s).unwrap();
    let items = arr.as_array().expect("flat array");
    assert_eq!(items.len(), 2);
    let names: std::collections::HashSet<&str> =
        items.iter().filter_map(|v| v["name"].as_str()).collect();
    assert!(names.contains("wire"));
    assert!(names.contains("slancha-mesh"));
    // Daemon liveness false for a fixture with no pidfile.
    for item in items {
        assert_eq!(item["daemon_running"], false);
    }
}

#[test]
fn session_env_emits_export_line_for_named_session_v0_5_16() {
    let home = fresh_home();
    write_session_fixture(&home, "wire", None);
    let out = run(&home, &["session", "env", "wire"]);
    assert!(out.status.success(), "session env failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("export WIRE_HOME="), "got: {stdout}");
    assert!(stdout.contains("/sessions/wire"), "got: {stdout}");
}

#[test]
fn session_env_errors_cleanly_for_missing_session_v0_5_16() {
    let home = fresh_home();
    let out = run(&home, &["session", "env", "ghost"]);
    assert!(!out.status.success(), "expected failure: {:?}", out);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("no session named"), "stderr: {stderr}");
    assert!(
        stderr.contains("wire session list") || stderr.contains("wire session new"),
        "should hint: {stderr}"
    );
}

#[test]
fn session_destroy_requires_force_flag_v0_5_16() {
    let home = fresh_home();
    let session_home = write_session_fixture(&home, "wire", None);
    let out = run(&home, &["session", "destroy", "wire"]);
    assert!(
        !out.status.success(),
        "destroy without --force must fail: {:?}",
        out
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("--force"), "stderr: {stderr}");
    // State must still be on disk.
    assert!(session_home.exists(), "session dir should not be deleted");
}

#[test]
fn legacy_pair_verbs_still_callable_but_hidden_v0_10() {
    // v0.10: legacy pair-* verbs stay callable for back-compat (v1.0
    // removes them). They're hidden from --help (v0.9.1) and fire a
    // deprecation banner on use (v0.9.2). This test asserts the
    // back-compat contract: direct invocation still resolves.
    let home = fresh_home();
    for verb in [
        "pair-host",
        "pair-join",
        "pair-accept",
        "pair-reject",
        "pair-list-inbound",
    ] {
        let out = run(&home, &[verb, "--help"]);
        assert!(
            out.status.success(),
            "v0.10 must keep `{verb}` callable for back-compat (v1.0 removes)"
        );
    }
}

#[test]
fn send_no_auto_pair_flag_exists_v0_10() {
    let home = fresh_home();
    let out = run(&home, &["send", "--help"]);
    assert!(out.status.success(), "send --help: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("--no-auto-pair"),
        "send help should mention --no-auto-pair — got: {stdout}"
    );
}

#[test]
fn pair_hidden_from_help_v0_10() {
    let home = fresh_home();
    let out = run(&home, &["--help"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    // `pair` was the megacommand — now hidden.
    assert!(
        !stdout.contains("  pair  ") && !stdout.contains("  pair\n"),
        "v0.10 should hide `pair` from --help — got: {stdout}"
    );
    // Still callable directly.
    let out = run(&home, &["pair", "--help"]);
    assert!(
        out.status.success(),
        "wire pair --help should still work (back-compat): {:?}",
        out
    );
}

#[test]
fn completions_emits_bash_script_v0_9_5() {
    let home = fresh_home();
    let out = run(&home, &["completions", "bash"]);
    assert!(out.status.success(), "completions bash failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("_wire()"),
        "bash completion should start with _wire() — got: {}",
        &stdout[..stdout.len().min(80)]
    );
    // Verb names that the completion grammar must mention.
    for verb in [
        "dial", "send", "pending", "accept", "reject", "whois", "here",
    ] {
        assert!(
            stdout.contains(verb),
            "bash completion missing verb `{verb}`"
        );
    }
}

#[test]
fn completions_emits_zsh_script_v0_9_5() {
    let home = fresh_home();
    let out = run(&home, &["completions", "zsh"]);
    assert!(out.status.success(), "completions zsh failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("#compdef wire"),
        "zsh completion should start with #compdef wire — got: {}",
        &stdout[..stdout.len().min(80)]
    );
}

#[test]
fn completions_supports_fish_and_powershell_v0_9_5() {
    let home = fresh_home();
    for shell in ["fish", "powershell", "elvish"] {
        let out = run(&home, &["completions", shell]);
        assert!(
            out.status.success(),
            "completions {shell} failed: {:?}",
            out
        );
        assert!(
            !out.stdout.is_empty(),
            "completions {shell} produced empty output"
        );
    }
}

#[test]
fn init_interactive_skipped_when_non_tty_v0_9_5() {
    // v0.9.5: when stdin is non-TTY (CI, captured), the interactive
    // prompt MUST be skipped and the v0.9.1 actionable-error wall
    // fires instead. This regression-test the non-interactive path —
    // crucial so CI runs don't hang waiting for stdin.
    let home = fresh_home();
    let out = std::process::Command::new(wire_bin())
        .args(["init", "alice"])
        .env("WIRE_HOME", &home)
        .env("WIRE_NO_AUTO_JSON", "1")
        // Force the smart-default to fail (port that won't resolve) so we
        // hit the no-local-relay branch where interactive prompt MIGHT
        // fire. WIRE_NO_INTERACTIVE forces non-interactive fallback even
        // if stdin happened to be a TTY (defensive).
        .env("WIRE_NO_INTERACTIVE", "1")
        .output()
        .expect("spawn wire");
    // Either the local relay happens to be up (success) or we get the
    // error wall (non-success but actionable). Test just asserts no
    // hang AND no garbled output.
    let stderr = String::from_utf8(out.stderr).unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    if !out.status.success() {
        // Must not be the prompt.
        assert!(
            !stderr.contains("Bind to public federation")
                && !stdout.contains("Bind to public federation"),
            "WIRE_NO_INTERACTIVE should suppress prompt — got stderr={stderr}"
        );
    }
}

#[test]
fn accept_invite_verb_exists_v0_9_4() {
    // v0.9.4: federation invite URL accept gets its own explicit verb.
    let home = fresh_home();
    let out = run(&home, &["accept-invite", "--help"]);
    assert!(out.status.success(), "accept-invite --help: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("federation invite URL"),
        "accept-invite help missing description: {stdout}"
    );
}

#[test]
fn accept_with_url_emits_deprecation_banner_v0_9_4() {
    // v0.9.4: `wire accept wire://pair?...` still works (back-compat
    // with v0.9 smart-dispatch) but emits a deprecation banner
    // pointing operators at the explicit `wire accept-invite` verb.
    let home = fresh_home();
    let out = std::process::Command::new(wire_bin())
        .args(["accept", "wire://pair?v=1&inv=bogus"])
        .env("WIRE_HOME", &home)
        .env("WIRE_NO_AUTO_JSON", "1")
        .output()
        .expect("spawn wire");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("DEPRECATED") && stderr.contains("accept-invite"),
        "accept-with-url should fire deprecation banner — got: {stderr}"
    );
}

#[test]
fn accept_with_name_does_not_emit_deprecation_v0_9_4() {
    // v0.9.4: `wire accept <name>` (canonical path) does NOT fire the
    // deprecation banner — only the URL-input back-compat path does.
    let home = fresh_home();
    let out = std::process::Command::new(wire_bin())
        .args(["accept", "nonexistent-peer"])
        .env("WIRE_HOME", &home)
        .env("WIRE_NO_AUTO_JSON", "1")
        .output()
        .expect("spawn wire");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("DEPRECATED"),
        "accept-with-name should NOT fire banner — got: {stderr}"
    );
}

#[test]
fn here_prints_self_when_no_neighbors_v0_9_3() {
    let home = fresh_home();
    let _ = run(&home, &["init", "alice", "--offline"]);
    // v0.11: handle is DID-derived character, not "alice". Discover it
    // via whoami first so the assertion stays correct.
    let whoami = run(&home, &["whoami", "--json"]);
    let card: serde_json::Value = serde_json::from_slice(&whoami.stdout).unwrap();
    let canonical = card["handle"].as_str().unwrap().to_string();

    let out = std::process::Command::new(wire_bin())
        .args(["here"])
        .env("WIRE_HOME", &home)
        .env("WIRE_NO_AUTO_JSON", "1")
        .env("WIRE_EMOJI", "off") // deterministic in CI
        .output()
        .expect("spawn wire");
    assert!(out.status.success(), "here failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("you are") && stdout.contains(&canonical),
        "here should show self with canonical handle `{canonical}` — got: {stdout}"
    );
    assert!(
        stdout.contains("no neighbors yet"),
        "here should explain empty mesh state — got: {stdout}"
    );
}

#[test]
fn here_json_includes_self_sisters_peers_v0_9_3() {
    let home = fresh_home();
    let _ = run(&home, &["init", "alice", "--offline"]);
    let out = std::process::Command::new(wire_bin())
        .args(["here", "--json"])
        .env("WIRE_HOME", &home)
        .output()
        .expect("spawn wire");
    assert!(out.status.success(), "here --json failed: {:?}", out);
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(parsed.get("self").is_some(), "self field: {parsed}");
    // v0.11: handle = DID-derived character. Assert non-empty + matches
    // DID slug rather than pinning operator-typed name.
    let h = parsed["self"]["handle"].as_str().unwrap();
    let d = parsed["self"]["did"].as_str().unwrap();
    assert!(
        !h.is_empty() && d.contains(h),
        "self handle/did mismatch: {parsed}"
    );
    assert!(
        parsed.get("sister_sessions").is_some(),
        "sister_sessions field"
    );
    assert!(parsed.get("pinned_peers").is_some(), "pinned_peers field");
}

#[test]
fn emoji_fallback_returns_ascii_tag_when_terminal_off_v0_9_3() {
    // v0.9.3: WIRE_EMOJI=off forces emoji_with_fallback to substitute
    // an ASCII tag (e.g. `[bear]`) for the glyph. Test verifies the
    // env var path without depending on terminal detection.
    let home = fresh_home();
    let _ = run(&home, &["init", "alice", "--offline"]);
    let out = std::process::Command::new(wire_bin())
        .args(["here"])
        .env("WIRE_HOME", &home)
        .env("WIRE_NO_AUTO_JSON", "1")
        .env("WIRE_EMOJI", "off")
        .output()
        .expect("spawn wire");
    let stdout = String::from_utf8(out.stdout).unwrap();
    // Any ASCII tag in square brackets at start of "you are" line.
    let you_line = stdout
        .lines()
        .find(|l| l.starts_with("you are "))
        .unwrap_or_else(|| panic!("expected 'you are' line in: {stdout}"));
    assert!(
        you_line.contains('[') && you_line.contains(']'),
        "WIRE_EMOJI=off should render bracketed ASCII tag — got: {you_line}"
    );
}

#[test]
fn whois_typo_returns_did_you_mean_v0_9_2() {
    // v0.9.2 (updated v0.11): nickname typo → suggestion from local
    // pool. v0.11 made handle = DID-derived character, so we discover
    // the actual character from whoami first, then query a typo of it.
    let home = fresh_home();
    let _ = run(&home, &["init", "alice", "--offline"]);
    let whoami = run(&home, &["whoami", "--json"]);
    let card: serde_json::Value = serde_json::from_slice(&whoami.stdout).unwrap();
    let canonical = card["handle"].as_str().unwrap().to_string();
    assert!(
        canonical.contains('-'),
        "expected adj-noun handle: {canonical}"
    );
    // Query a 1-char typo: drop the last char.
    let typo = &canonical[..canonical.len() - 1];

    let out = std::process::Command::new(wire_bin())
        .args(["whois", typo])
        .env("WIRE_HOME", &home)
        .env("WIRE_NO_AUTO_JSON", "1")
        .output()
        .expect("spawn wire");
    let stderr = String::from_utf8(out.stderr).unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Did you mean") && combined.contains(&canonical),
        "whois typo `{typo}` should suggest canonical `{canonical}` — got stdout=`{stdout}` stderr=`{stderr}`"
    );
}

#[test]
fn whois_typo_returns_json_success_with_candidates_v0_9_2() {
    // v0.9.2 (updated v0.11): JSON-mode miss returns exit 0 with
    // {found: false, candidates: [...]} containing the operator's
    // DID-derived character.
    let home = fresh_home();
    let _ = run(&home, &["init", "alice", "--offline"]);
    let whoami = run(&home, &["whoami", "--json"]);
    let card: serde_json::Value = serde_json::from_slice(&whoami.stdout).unwrap();
    let canonical = card["handle"].as_str().unwrap().to_string();
    let typo = &canonical[..canonical.len() - 1];

    let out = std::process::Command::new(wire_bin())
        .args(["whois", typo, "--json"])
        .env("WIRE_HOME", &home)
        .output()
        .expect("spawn wire");
    assert!(
        out.status.success(),
        "whois --json on miss should succeed (exit 0): {:?}",
        out
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["found"], serde_json::Value::Bool(false));
    let candidates = parsed["candidates"].as_array().unwrap();
    assert!(
        candidates
            .iter()
            .any(|c| c.as_str() == Some(canonical.as_str())),
        "candidates should include canonical `{canonical}` for typo `{typo}`: {parsed}"
    );
}

// v0.10: pair-accept verb removed entirely, so the v0.9.2 deprecation-
// banner tests (which exercised pair-accept) are obsolete. The
// deprecation_warn helper is still exercised by the `accept <URL>`
// back-compat path — covered by accept_with_url_emits_deprecation_banner_v0_9_4.

#[test]
fn deprecated_verbs_hidden_from_help_v0_9_1() {
    // v0.9.1: --help should not list the deprecated pair-* + invite
    // verbs as their own subcommand entries (lines starting with two
    // spaces + the verb name + whitespace, which is clap's subcommand-
    // list format). They MAY still appear inside other commands'
    // description text (e.g. `pin` mentions pair-host); the test
    // checks subcommand-listing position, not arbitrary substring.
    let home = fresh_home();
    let out = run(&home, &["--help"]);
    assert!(out.status.success(), "--help failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    for hidden in [
        "pair-host",
        "pair-join",
        "pair-accept",
        "pair-reject",
        "pair-list-inbound",
    ] {
        let leading_pattern = format!("  {hidden} ");
        assert!(
            !stdout.contains(&leading_pattern),
            "--help should hide `{hidden}` from subcommand list (v0.9.1)"
        );
    }
    for visible in ["dial", "send", "pending", "accept", "reject", "whois"] {
        let leading_pattern = format!("  {visible}");
        assert!(
            stdout.contains(&leading_pattern),
            "--help should list canonical `{visible}` as subcommand"
        );
    }
}

// v0.10: pair-accept removed entirely. The v0.9.1 "still callable
// via direct invocation" guarantee is no longer applicable;
// legacy_pair_verbs_removed_from_dispatch_v0_10 asserts the new contract.

#[test]
fn init_offline_creates_keypair_without_slot_v0_9_1() {
    // v0.11: operator-typed `alice` is ignored; DID slug uses the
    // DID-derived character. Assert shape, not the operator's input.
    let home = fresh_home();
    let out = run(&home, &["init", "alice", "--offline", "--json"]);
    assert!(out.status.success(), "init --offline failed: {:?}", out);
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let did = parsed["did"].as_str().unwrap();
    assert!(
        did.starts_with("did:wire:") && did.len() > 17,
        "v0.11: expected `did:wire:<word-word>-<8hex>`, got: {did}"
    );
    assert!(
        parsed.get("relay_url").is_none(),
        "offline init should not have relay_url: {parsed}"
    );
}

#[test]
fn json_emitted_when_stdout_is_piped_v0_9_1() {
    let home = fresh_home();
    let _ = run(&home, &["init", "alice", "--offline"]);
    let out = run(&home, &["whoami"]);
    assert!(out.status.success(), "whoami failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|_| panic!("whoami stdout should be JSON when piped — got: {stdout}"));
    assert!(parsed.get("did").is_some(), "JSON missing did: {parsed}");
}

#[test]
fn json_auto_can_be_opted_out_v0_9_1() {
    let home = fresh_home();
    let _ = run(&home, &["init", "alice", "--offline"]);
    let out = std::process::Command::new(wire_bin())
        .args(["whoami"])
        .env("WIRE_HOME", &home)
        .env("WIRE_NO_AUTO_JSON", "1")
        .output()
        .expect("spawn wire");
    assert!(out.status.success(), "whoami failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    // v0.11: human format prints DID with character handle, not "alice".
    assert!(
        stdout.contains("did:wire:"),
        "WIRE_NO_AUTO_JSON should give human format with `did:` line — got: {stdout}"
    );
    assert!(
        !stdout.trim_start().starts_with('{'),
        "WIRE_NO_AUTO_JSON should NOT emit JSON — got: {stdout}"
    );
}

#[test]
fn auto_detect_chatter_silent_when_non_interactive_v0_9_1() {
    let home = fresh_home();
    let out = run(&home, &["whoami"]);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("auto-detected session"),
        "non-interactive stderr should NOT have auto-detect chatter — got: {stderr}"
    );
}

#[test]
fn session_bind_attaches_existing_session_to_cwd_v0_7_1() {
    // v0.7.1: `wire session bind` adds a cwd → session entry so the
    // walk-up auto-detect resolves to the leaf project rather than an
    // already-registered ancestor.
    let home = fresh_home();
    write_session_fixture(&home, "wire", None);
    let project_cwd = tempfile::tempdir().unwrap();

    let out = Command::new(wire_bin())
        .args(["session", "bind", "wire", "--json"])
        .env("WIRE_HOME", &home)
        .env_remove("RUST_LOG")
        .current_dir(project_cwd.path())
        .output()
        .expect("failed to spawn wire");
    assert!(out.status.success(), "bind failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["session"], "wire");
    assert_eq!(parsed["changed"], true);
    assert!(parsed["previous"].is_null());

    let registry: serde_json::Value = serde_json::from_slice(
        &std::fs::read(home.join("sessions").join("registry.json")).unwrap(),
    )
    .unwrap();
    let by_cwd = registry["by_cwd"].as_object().unwrap();
    let canonical_cwd = std::fs::canonicalize(project_cwd.path())
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let raw_cwd = project_cwd.path().to_string_lossy().into_owned();
    // The CLI records cwd as it sees it from std::env::current_dir(); on
    // macOS the tempdir is symlinked under /private/var, so accept either
    // the canonical or raw form.
    let stored = by_cwd
        .keys()
        .find(|k| **k == canonical_cwd || **k == raw_cwd)
        .unwrap_or_else(|| panic!("registry missing cwd entry: {by_cwd:?}"));
    assert_eq!(by_cwd[stored], "wire");
}

#[test]
fn session_bind_errors_on_unknown_session_v0_7_1() {
    let home = fresh_home();
    let project_cwd = tempfile::tempdir().unwrap();

    let out = Command::new(wire_bin())
        .args(["session", "bind", "ghost"])
        .env("WIRE_HOME", &home)
        .env_remove("RUST_LOG")
        .current_dir(project_cwd.path())
        .output()
        .expect("failed to spawn wire");
    assert!(!out.status.success(), "bind should fail: {:?}", out);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("ghost"),
        "stderr should name session: {stderr}"
    );
    assert!(
        stderr.contains("wire session new") || stderr.contains("does not exist"),
        "stderr should hint: {stderr}"
    );
}

#[test]
fn session_bind_is_idempotent_when_already_bound_v0_7_1() {
    let home = fresh_home();
    write_session_fixture(&home, "wire", None);
    let project_cwd = tempfile::tempdir().unwrap();

    // First bind succeeds + sets changed=true.
    let _ = Command::new(wire_bin())
        .args(["session", "bind", "wire", "--json"])
        .env("WIRE_HOME", &home)
        .current_dir(project_cwd.path())
        .output()
        .expect("first bind");

    // Second bind is a no-op + sets changed=false.
    let out = Command::new(wire_bin())
        .args(["session", "bind", "wire", "--json"])
        .env("WIRE_HOME", &home)
        .current_dir(project_cwd.path())
        .output()
        .expect("second bind");
    assert!(out.status.success(), "second bind: {:?}", out);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid json on second bind");
    assert_eq!(parsed["changed"], false);
}

#[test]
fn session_destroy_with_force_removes_state_and_registry_entry_v0_5_16() {
    let home = fresh_home();
    let session_home = write_session_fixture(&home, "wire", Some("/Users/paul/Source/wire"));
    let registry_path = home.join("sessions").join("registry.json");
    assert!(registry_path.exists());

    let out = run(&home, &["session", "destroy", "wire", "--force", "--json"]);
    assert!(out.status.success(), "destroy failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["destroyed"], true);
    assert!(!session_home.exists(), "session dir should be gone");

    // Registry entry for that cwd should be cleaned up.
    let registry_bytes = std::fs::read(&registry_path).unwrap();
    let registry: serde_json::Value = serde_json::from_slice(&registry_bytes).unwrap();
    let by_cwd = registry["by_cwd"].as_object().unwrap();
    assert!(
        !by_cwd.values().any(|v| v == "wire"),
        "registry must not reference destroyed session"
    );
}

/// Attach a v0.5.17 dual-slot `relay.json` to an existing fixture
/// so `wire session list-local` sees a Local-scope endpoint for it.
fn write_local_endpoint(session_home: &std::path::Path, local_relay: &str, slot_id: &str) {
    let cfg = session_home.join("config").join("wire");
    let body = serde_json::json!({
        "self": {
            "relay_url": "https://wireup.net",
            "slot_id": format!("{slot_id}-fed"),
            "slot_token": "fed-tok",
            "endpoints": [
                {
                    "relay_url": "https://wireup.net",
                    "slot_id": format!("{slot_id}-fed"),
                    "slot_token": "fed-tok",
                    "scope": "federation"
                },
                {
                    "relay_url": local_relay,
                    "slot_id": format!("{slot_id}-loop"),
                    "slot_token": "loop-tok",
                    "scope": "local"
                }
            ]
        }
    });
    std::fs::write(
        cfg.join("relay.json"),
        serde_json::to_vec_pretty(&body).unwrap(),
    )
    .unwrap();
}

#[test]
fn session_list_local_reports_empty_state_v0_5_19() {
    let home = fresh_home();
    let out = run(&home, &["session", "list-local"]);
    assert!(out.status.success(), "list-local failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("no sessions on this machine"),
        "expected empty hint, got: {stdout}"
    );
}

#[test]
fn session_list_local_groups_by_local_relay_url_v0_5_19() {
    let home = fresh_home();
    let alpha = write_session_fixture(&home, "alpha", Some("/Users/paul/Source/alpha"));
    let beta = write_session_fixture(&home, "beta", Some("/Users/paul/Source/beta"));
    let _legacy = write_session_fixture(&home, "legacy", Some("/Users/paul/Source/legacy"));
    write_local_endpoint(&alpha, "http://127.0.0.1:8771", "alpha");
    write_local_endpoint(&beta, "http://127.0.0.1:8771", "beta");
    // legacy intentionally has no relay.json — should land in federation_only.

    let out = run(&home, &["session", "list-local", "--json"]);
    assert!(out.status.success(), "list-local --json failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let local_group = parsed["local"]["http://127.0.0.1:8771"]
        .as_array()
        .expect("expected one local-relay group");
    let names: std::collections::HashSet<&str> = local_group
        .iter()
        .filter_map(|v| v["name"].as_str())
        .collect();
    assert!(names.contains("alpha"), "alpha missing: {stdout}");
    assert!(names.contains("beta"), "beta missing: {stdout}");
    assert!(
        !names.contains("legacy"),
        "legacy must NOT be in local group: {stdout}"
    );

    let fed_only = parsed["federation_only"]
        .as_array()
        .expect("federation_only array");
    let fed_names: std::collections::HashSet<&str> =
        fed_only.iter().filter_map(|v| v["name"].as_str()).collect();
    assert!(
        fed_names.contains("legacy"),
        "legacy should be federation-only: {stdout}"
    );
}

#[test]
fn session_list_local_redacts_slot_token_in_json_v0_5_19() {
    let home = fresh_home();
    let alpha = write_session_fixture(&home, "alpha", None);
    write_local_endpoint(&alpha, "http://127.0.0.1:8771", "alpha");

    let out = run(&home, &["session", "list-local", "--json"]);
    assert!(out.status.success(), "list-local --json failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        !stdout.contains("loop-tok"),
        "slot_token must be redacted from list-local --json: {stdout}"
    );
    assert!(
        !stdout.contains("\"slot_token\""),
        "the slot_token field name must not appear: {stdout}"
    );
}

#[test]
fn accept_errors_cleanly_when_no_pending_request_v0_5_14() {
    // v0.10: migrated from `wire pair-accept` (removed) to `wire accept`.
    // Same loud-fail semantics — must NEVER silently succeed.
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let out = run(&home, &["accept", "ghost"]);
    assert!(!out.status.success(), "expected failure: {:?}", out);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("no pending pair request from ghost"),
        "stderr should explain the missing record: {stderr}"
    );
}

#[test]
fn reject_idempotent_on_missing_peer_v0_5_14() {
    // v0.10: migrated from `wire pair-reject` to `wire reject`. Idempotent.
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let out = run(&home, &["reject", "ghost", "--json"]);
    assert!(out.status.success(), "reject failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["rejected"], false);
}

#[test]
fn send_with_fqdn_peer_normalizes_to_bare_handle_outbox() {
    // Regression for issue #2 Bug B (v0.5.13). Operators and the
    // AGENT_INTEGRATION recipe both showed `wire send <handle>@<relay>`
    // form. Before v0.5.13 that wrote to `<handle>@<relay>.jsonl`,
    // but `wire push` only enumerated bare-handle filenames — events
    // stuck silently for 25 min in the field report. Bare-handle
    // normalization at send time is the on-disk-contract enforcement.
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let out = run(
        &home,
        &[
            "send",
            "willard@wireup.net",
            "claim",
            "fqdn-peer test",
            "--json",
        ],
    );
    assert!(out.status.success(), "send failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["peer"], "willard", "peer field must be bare handle");
    // Bare-handle file MUST exist; FQDN-suffixed file MUST NOT.
    let bare = home.join("state/wire/outbox/willard.jsonl");
    let fqdn = home.join("state/wire/outbox/willard@wireup.net.jsonl");
    assert!(bare.exists(), "bare-handle outbox missing: {bare:?}");
    assert!(
        !fqdn.exists(),
        "fqdn-suffixed outbox MUST NOT be created: {fqdn:?}"
    );
    // Event `to` field uses bare handle in the constructed DID — not the FQDN.
    let body = std::fs::read_to_string(&bare).unwrap();
    let event: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    assert_eq!(event["to"], "did:wire:willard");
}

#[test]
fn send_deadline_writes_signed_time_sensitive_until() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let deadline = "2030-01-02T03:04:05Z";
    let out = run(
        &home,
        &[
            "send",
            "willard",
            "decision",
            "ship before the window closes",
            "--deadline",
            deadline,
            "--json",
        ],
    );
    assert!(out.status.success(), "send failed: {:?}", out);

    let outbox = home.join("state/wire/outbox/willard.jsonl");
    let body = std::fs::read_to_string(&outbox).unwrap();
    let event: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
    assert_eq!(event["time_sensitive_until"], deadline);

    let event_path = home.join("deadline-event.json");
    std::fs::write(&event_path, body.trim_end()).unwrap();
    let verify = run(&home, &["verify", event_path.to_str().unwrap(), "--json"]);
    assert!(
        verify.status.success(),
        "verify failed: stderr={}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn send_idempotent_under_identical_body() {
    // The same body produces the same event_id (content-addressed).
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let out1 = run(
        &home,
        &["send", "willard", "decision", "fixed-body", "--json"],
    );
    let out2 = run(
        &home,
        &["send", "willard", "decision", "fixed-body", "--json"],
    );
    let p1: serde_json::Value = serde_json::from_slice(&out1.stdout).unwrap();
    let p2: serde_json::Value = serde_json::from_slice(&out2.stdout).unwrap();
    // Note: timestamps differ, so event_ids differ. The dedupe-on-content
    // property requires the daemon (not yet built). This test pins the
    // current behavior so iter 6's dedupe lands as a deliberate change.
    assert_ne!(
        p1["event_id"], p2["event_id"],
        "iter 6 should make these equal"
    );
}

#[test]
fn verify_round_trips_a_send() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let _ = run(&home, &["send", "paul", "decision", "self-test", "--json"]);
    // Drop the queued event into a temp file and verify it.
    let outbox = home.join("state/wire/outbox/paul.jsonl");
    let line = std::fs::read_to_string(&outbox).unwrap();
    let event_path = home.join("event.json");
    std::fs::write(&event_path, line.trim_end()).unwrap();
    let out = run(&home, &["verify", event_path.to_str().unwrap(), "--json"]);
    assert!(
        out.status.success(),
        "verify failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["verified"], true);
}

#[test]
fn verify_rejects_tampered_event() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
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
    let out = run(
        &home,
        &["join", "12-ABCDEF", "--relay", "http://127.0.0.1:1"],
    );
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
    let _ = run(&home, &["init", "paul", "--offline"]);

    let mut child = Command::new(wire_bin())
        .arg("mcp")
        .env("WIRE_HOME", &home)
        // v0.13: skip auto-bootstrap (which would hit the real federation
        // relay) — these tests drive identity/tools manually.
        .env("WIRE_MCP_SKIP_AUTO_UP", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn wire mcp");

    let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
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
    assert_eq!(
        lines.len(),
        2,
        "expected 2 responses (initialize + tools/list), got {}: {stdout}",
        lines.len()
    );

    let init_resp: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(init_resp["result"]["protocolVersion"], "2025-06-18");

    let list_resp: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    let names: Vec<&str> = list_resp["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    // Always-safe messaging tools
    assert!(names.contains(&"wire_whoami"));
    assert!(names.contains(&"wire_send"));
    // Goal 1: pairing tools now exposed (with SAS-digit type-back as the gate)
    assert!(names.contains(&"wire_init"));
    assert!(names.contains(&"wire_pair_initiate"));
    assert!(names.contains(&"wire_pair_join"));
    assert!(names.contains(&"wire_pair_check"));
    assert!(names.contains(&"wire_pair_confirm"));
    // Legacy wire_join is not advertised — superseded by wire_pair_join
    assert!(
        !names.contains(&"wire_join"),
        "wire_join is the deprecated alias; surface wire_pair_join instead"
    );
}

#[test]
fn mcp_tools_call_wire_whoami() {
    use std::io::Write as _;
    use std::process::Stdio;

    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);

    let mut child = Command::new(wire_bin())
        .arg("mcp")
        .env("WIRE_HOME", &home)
        // v0.13: skip auto-bootstrap (which would hit the real federation
        // relay) — these tests drive identity/tools manually.
        .env("WIRE_MCP_SKIP_AUTO_UP", "1")
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
    {
        // v0.5.7+: DID is pubkey-suffixed (`did:wire:paul-<8hex>`).
        let d = parsed["did"].as_str().unwrap();
        assert!(
            d.starts_with("did:wire:") && d.len() > 17,
            "v0.11: handle = DID-derived character, expected `did:wire:<word-word>-<8hex>`, got: {d}"
        );
    }
    {
        // v0.11: handle = DID-derived character, not operator-typed "paul".
        let h = parsed["handle"].as_str().unwrap();
        let d = parsed["did"].as_str().unwrap();
        assert!(!h.is_empty(), "handle should be non-empty: {h}");
        assert!(
            d.contains(h),
            "did slug must contain handle: did={d} handle={h}"
        );
    }
}

#[test]
fn mcp_tools_call_wire_init_idempotent_on_repeat() {
    // Goal 1: wire_init is now exposed via MCP, idempotent. First call creates,
    // second call with same handle returns already_initialized=true.
    // (A different-handle second call returns isError — covered in
    // tests/mcp_pair.rs::wire_init_via_mcp_is_idempotent_for_same_handle.)
    use std::io::Write as _;
    use std::process::Stdio;

    let home = fresh_home();

    let mut child = Command::new(wire_bin())
        .arg("mcp")
        .env("WIRE_HOME", &home)
        // v0.13: skip auto-bootstrap (which would hit the real federation
        // relay) — these tests drive identity/tools manually.
        .env("WIRE_MCP_SKIP_AUTO_UP", "1")
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
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"wire_init","arguments":{{"handle":"alice"}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"wire_init","arguments":{{"handle":"alice"}}}}}}"#
        )
        .unwrap();
    }

    let out = child.wait_with_output().expect("server didn't exit");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "expected init + 2 tools/call responses");

    let r1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(r1["result"]["isError"], false);
    let p1: serde_json::Value =
        serde_json::from_str(r1["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    {
        // One-name rule (v0.13.1): the MCP wire_init `handle` arg is a
        // vestigial seed — the DID handle is the keypair-derived persona, not
        // the typed "alice". init_self_idempotent now derives the persona on
        // every init path, closing the leak where the typed handle (or the
        // hostname, on auto-init) became the on-wire name.
        let d = p1["did"].as_str().unwrap();
        assert!(d.starts_with("did:wire:"), "got: {d}");
        assert!(
            !d.starts_with("did:wire:alice-"),
            "one-name rule: typed handle `alice` must be ignored, got: {d}"
        );
    }
    assert_eq!(p1["already_initialized"], false);

    let r2: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(r2["result"]["isError"], false);
    let p2: serde_json::Value =
        serde_json::from_str(r2["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(p2["already_initialized"], true);
    assert_eq!(p2["fingerprint"], p1["fingerprint"]);

    // Config files exist after first init
    assert!(home.join("config/wire/private.key").exists());
    assert!(home.join("config/wire/agent-card.json").exists());
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
    let _ = run(&home, &["init", "paul", "--offline"]);
    let out = run(&home, &["status", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["initialized"], true);
    {
        // v0.5.7+: DID is pubkey-suffixed (`did:wire:paul-<8hex>`).
        let d = parsed["did"].as_str().unwrap();
        assert!(
            d.starts_with("did:wire:") && d.len() > 17,
            "v0.11: handle = DID-derived character, expected `did:wire:<word-word>-<8hex>`, got: {d}"
        );
    }
    assert_eq!(parsed["peers"].as_array().unwrap().len(), 0);
    assert_eq!(parsed["self_relay"], serde_json::Value::Null);
    assert_eq!(parsed["outbox"]["events"], 0);
}

#[test]
fn forget_peer_removes_pinned_record() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
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
    let _ = run(&home, &["init", "paul", "--offline"]);
    let out = run(&home, &["forget-peer", "ghost", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["removed"], false);
}

#[test]
fn forget_peer_purge_deletes_jsonl_files() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
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
    assert!(
        !outbox_path.exists(),
        "outbox file should be deleted with --purge"
    );
}

#[test]
fn status_after_send_shows_outbox_depth() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let _ = run(&home, &["send", "willard", "decision", "hello"]);
    let _ = run(&home, &["send", "willard", "decision", "world"]);
    let out = run(&home, &["status", "--json"]);
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["outbox"]["files"], 1);
    assert_eq!(parsed["outbox"]["events"], 2);
}

// ---------- wire #79: `tail` orientation regression ----------

/// Seed `<home>/state/wire/inbox/<peer>.jsonl` with N synthetic events whose
/// `timestamp` strings sort lexicographically in append order. We bypass the
/// daemon entirely — `cmd_tail` only inspects raw jsonl files + the trust
/// store, so a hand-rolled fixture is enough to exercise its orientation +
/// windowing logic in isolation. Trust is left empty (events will be
/// `verified: false`), but `--json` output still emits one line per event and
/// preserves their original `body` and `timestamp` so the test can identify
/// which window the CLI picked.
fn seed_inbox(home: &std::path::Path, peer: &str, n: usize) {
    let dir = home.join("state/wire/inbox");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{peer}.jsonl"));
    let mut body = String::new();
    for i in 1..=n {
        let ts = format!("2024-01-01T00:00:{i:02}Z");
        body.push_str(&format!(
            r#"{{"timestamp":"{ts}","from":"did:wire:test","kind":2,"type":"decision","body":"evt-{i:02}"}}"#
        ));
        body.push('\n');
    }
    std::fs::write(&path, body).unwrap();
}

fn tail_json_bodies(home: &PathBuf, args: &[&str]) -> Vec<String> {
    let out = run(home, args);
    assert!(out.status.success(), "tail failed: {:?}", out);
    let s = String::from_utf8(out.stdout).unwrap();
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["body"].as_str().unwrap().to_string()
        })
        .collect()
}

/// wire #79 — without `--oldest`, `wire tail --limit N` returns the LAST N
/// events (newest-N) sorted chronologically (oldest-of-window first, newest
/// last), matching `tail -n` orientation. Previously returned the FIRST N.
#[test]
fn tail_default_returns_newest_n() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    seed_inbox(&home, "willard", 10);

    let bodies = tail_json_bodies(&home, &["tail", "willard", "--json", "--limit", "3"]);
    assert_eq!(
        bodies,
        vec!["evt-08", "evt-09", "evt-10"],
        "default tail --limit N must return newest N (chronological order)"
    );
}

/// wire #79 — `--oldest` preserves FIFO behaviour for operators who want to
/// replay an inbox from the start (e.g. forensic walks).
#[test]
fn tail_oldest_flag_returns_first_n() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    seed_inbox(&home, "willard", 10);

    let bodies = tail_json_bodies(
        &home,
        &["tail", "willard", "--json", "--limit", "3", "--oldest"],
    );
    assert_eq!(
        bodies,
        vec!["evt-01", "evt-02", "evt-03"],
        "tail --oldest --limit N must return first N (FIFO)"
    );
}

/// wire #79 — `--limit 0` returns every event in chronological order, in both
/// orientations.
#[test]
fn tail_limit_zero_returns_all_chronological() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    seed_inbox(&home, "willard", 5);

    let default_bodies = tail_json_bodies(&home, &["tail", "willard", "--json", "--limit", "0"]);
    assert_eq!(
        default_bodies,
        vec!["evt-01", "evt-02", "evt-03", "evt-04", "evt-05"]
    );

    let oldest_bodies = tail_json_bodies(
        &home,
        &["tail", "willard", "--json", "--limit", "0", "--oldest"],
    );
    assert_eq!(default_bodies, oldest_bodies);
}

/// wire #79 — without a peer filter, events from multiple peer files are
/// interleaved by timestamp before windowing. Two peers with alternating
/// timestamps; the newest 3 events must come from BOTH files, not just one
/// (which is what the old per-file `break` logic would have produced).
#[test]
fn tail_multi_peer_sorts_by_timestamp() {
    let home = fresh_home();
    let _ = run(&home, &["init", "paul", "--offline"]);
    let dir = home.join("state/wire/inbox");
    std::fs::create_dir_all(&dir).unwrap();
    // alice: events at :01, :03, :05  bob: events at :02, :04, :06
    std::fs::write(
        dir.join("alice.jsonl"),
        concat!(
            r#"{"timestamp":"2024-01-01T00:00:01Z","from":"did:wire:alice","kind":2,"type":"decision","body":"a1"}"#, "\n",
            r#"{"timestamp":"2024-01-01T00:00:03Z","from":"did:wire:alice","kind":2,"type":"decision","body":"a3"}"#, "\n",
            r#"{"timestamp":"2024-01-01T00:00:05Z","from":"did:wire:alice","kind":2,"type":"decision","body":"a5"}"#, "\n",
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("bob.jsonl"),
        concat!(
            r#"{"timestamp":"2024-01-01T00:00:02Z","from":"did:wire:bob","kind":2,"type":"decision","body":"b2"}"#, "\n",
            r#"{"timestamp":"2024-01-01T00:00:04Z","from":"did:wire:bob","kind":2,"type":"decision","body":"b4"}"#, "\n",
            r#"{"timestamp":"2024-01-01T00:00:06Z","from":"did:wire:bob","kind":2,"type":"decision","body":"b6"}"#, "\n",
        ),
    )
    .unwrap();

    let bodies = tail_json_bodies(&home, &["tail", "--json", "--limit", "3"]);
    assert_eq!(
        bodies,
        vec!["b4", "a5", "b6"],
        "expected 3 newest across peers (interleaved by timestamp)"
    );
}
