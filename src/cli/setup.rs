use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::config;

// ---------- up megacommand (full bootstrap) ----------

/// `wire up <nick@relay-host>` — single command from fresh box to ready-to-
/// pair. Composes the steps that today's onboarding walks operators through
/// one by one (init / bind-relay / claim / background daemon / arm monitor
/// recipe). Idempotent: every step checks current state and skips if done.
///
/// Argument parsing accepts:
///   - `<nick>@<relay-host>` — explicit relay
///   - `<nick>`              — defaults to wireup.net (the configured
///     public relay)
pub(crate) fn cmd_up(
    relay_arg: Option<&str>,
    with_local: Option<&str>,
    no_local: bool,
    as_json: bool,
) -> Result<()> {
    // No nick to parse — your handle is your DID-derived persona (one-name
    // rule). The optional arg is only which relay to bind/claim on. Accepts
    // `@host`, bare `host`, or a full URL; defaults to the public relay.
    let relay_url = match relay_arg {
        Some(r) => {
            let r = r.trim_start_matches('@');
            if r.starts_with("http://") || r.starts_with("https://") {
                r.to_string()
            } else {
                format!("https://{r}")
            }
        }
        None => crate::pair_invite::DEFAULT_RELAY.to_string(),
    };

    // Strip any URL userinfo (`<handle>@<host>`) before doing any state-
    // mutating work — otherwise the malformed endpoint gets persisted in
    // `relay_state` AND published in the signed agent-card, where every
    // inbound POST to it 4xxes. Mirrors `cmd_up`'s already-bound branch,
    // which has always ignored the userinfo on the "keeping existing
    // binding" warning path.
    let relay_url = strip_relay_url_userinfo(&relay_url);

    let mut report: Vec<(String, String)> = Vec::new();
    let mut step = |stage: &str, detail: String| {
        report.push((stage.to_string(), detail.clone()));
        if !as_json {
            eprintln!("wire up: {stage} — {detail}");
        }
    };

    // 1. init (or note existing identity). No typed name — cmd_init(None)
    // generates the persona from the freshly-minted keypair (one-name rule).
    if config::is_initialized()? {
        step("init", "already initialized".to_string());
    } else {
        super::cmd_init(Some(&relay_url), false, /* as_json */ false)?;
        step("init", format!("created identity bound to {relay_url}"));
    }

    // Canonical persona handle — the one name we claim and are addressed by.
    let canonical = {
        let card = config::read_agent_card()?;
        let did = card.get("did").and_then(Value::as_str).unwrap_or("");
        crate::agent_card::display_handle_from_did(did).to_string()
    };
    step("identity", format!("persona is `{canonical}`"));

    // 2. Ensure relay binding matches. cmd_init with --relay binds it; if
    // already initialized we may need to bind to the requested relay
    // separately (operator switched relays).
    let relay_state = config::read_relay_state()?;
    let bound_relay = relay_state
        .get("self")
        .and_then(|s| s.get("relay_url"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if bound_relay.is_empty() {
        // Identity exists but never bound to a relay — bind now.
        // Fresh box (no pinned peers yet) — migrate_pinned irrelevant.
        // Pass `false` so the safety check kicks in if state was non-empty.
        super::cmd_bind_relay(
            &relay_url, /* scope */ None, // infer from URL (federation for wireup.net)
            /* replace */ false, /* migrate_pinned */ false, /* as_json */ false,
        )?;
        step("bind-relay", format!("bound to {relay_url}"));
    } else if bound_relay != relay_url {
        step(
            "bind-relay",
            format!(
                "WARNING: identity bound to {bound_relay} but you specified {relay_url}. \
                 Keeping existing binding. Run `wire bind-relay {relay_url}` to switch."
            ),
        );
    } else {
        step("bind-relay", format!("already bound to {bound_relay}"));
    }

    // 3. Claim nick on the relay's handle directory. Idempotent — same-DID
    // re-claims are accepted by the relay.
    match super::cmd_claim(
        &canonical,
        Some(&relay_url),
        None,
        /* hidden */ false,
        /* as_json */ false,
    ) {
        Ok(()) => step(
            "claim",
            format!("{canonical}@{} claimed", strip_proto(&relay_url)),
        ),
        Err(e) => step(
            "claim",
            format!("WARNING: claim failed: {e}. You can retry `wire claim {canonical}`."),
        ),
    }

    // 3b. Opportunistic local dual-slot (additive). Gives same-box sister
    // sessions sub-millisecond loopback routing alongside the federation
    // slot. Local relays carry no handle directory — nothing to claim
    // there; sister discovery is via `wire session list-local`.
    if no_local {
        step("local-slot", "skipped (--no-local)".to_string());
    } else {
        let local_url = with_local
            .unwrap_or("http://127.0.0.1:8771")
            .trim_end_matches('/');
        let already_local = crate::endpoints::self_endpoints(
            &config::read_relay_state().unwrap_or_else(|_| json!({})),
        )
        .iter()
        .any(|e| e.relay_url == local_url);
        if relay_url.trim_end_matches('/') == local_url || already_local {
            step("local-slot", "already covered".to_string());
        } else if crate::relay_client::RelayClient::new(local_url)
            .check_healthz()
            .is_ok()
        {
            match super::cmd_bind_relay(
                local_url,
                Some("local"),
                /* replace */ false,
                /* migrate_pinned */ false,
                /* as_json */ false,
            ) {
                Ok(()) => step(
                    "local-slot",
                    format!("dual-bound local relay {local_url} for sister routing"),
                ),
                Err(e) => step("local-slot", format!("skipped local relay: {e}")),
            }
        } else {
            step(
                "local-slot",
                format!(
                    "no local relay reachable at {local_url} — federation only \
                     (sisters resolve via session-list)"
                ),
            );
        }
    }

    // 4. Background daemon — must be running for pull/push/ack to flow.
    match crate::ensure_up::ensure_daemon_running() {
        Ok(true) => step("daemon", "started fresh background daemon".to_string()),
        Ok(false) => step("daemon", "already running".to_string()),
        Err(e) => step(
            "daemon",
            format!("WARNING: could not start daemon: {e}. Run `wire daemon &` manually."),
        ),
    }

    // 5. Final summary — point operator at the next commands. Covers the
    // first connection (dial), the day-2 retention surfaces (statusline face,
    // reboot survival) and the "which Claude is this?" disambiguator — the
    // three things a fresh `wire up` previously left undiscoverable.
    let summary = "ready. `wire dial <name> \"<msg>\"` to reach a peer, \
         `wire here` to see who's around. \
         Keep it alive across reboots: `wire service install`. \
         See your face in Claude Code: `wire setup --statusline --apply`."
        .to_string();
    step("ready", summary.clone());

    if as_json {
        let steps_json: Vec<_> = report
            .iter()
            .map(|(k, v)| json!({"stage": k, "detail": v}))
            .collect();
        println!(
            "{}",
            serde_json::to_string(&json!({
                "nick": canonical,
                "relay": relay_url,
                "steps": steps_json,
            }))?
        );
    }
    Ok(())
}

/// Strip http:// or https:// prefix for display in `wire up` step output.
pub(crate) fn strip_proto(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string()
}

/// Strip URL userinfo (`https://<userinfo>@<host>...`) from a relay URL,
/// warning to stderr if any was stripped. Returns the cleaned URL.
///
/// Bug 1 this fixes: `wire up <handle>@<relay>` and `wire bind-relay
/// <handle>@<relay>` previously prepended `https://` to the literal arg,
/// recording and publishing the endpoint as `https://<handle>@<relay>` —
/// handle parsed as URL userinfo. Every inbound event POST to that
/// endpoint (pair_drop_ack, messages) gets a 4xx (Cloudflare 400 on
/// wireup.net) because the upstream rejects the userinfo on plain
/// GETs/POSTs. Bilateral pairing can't complete; messages sit
/// undelivered. Also surfaced cosmetically (Bug 3) as a doubled-handle
/// echo at the claim step (`<nick>@<nick>@<host>`) because `strip_proto`
/// left the userinfo in.
///
/// Behavior: strip-and-warn rather than hard-reject. In v0.11+ the handle
/// is DID-derived (one-name rule), so the userinfo isn't *needed* — but
/// `<handle>@<relay>` is literally the wire dial-address format
/// (`wire dial coral-weasel@wireup.net`), so an operator who types
/// `wire up <handle>@<relay>` is making a natural-by-analogy mistake, not
/// a hostile request. Mirrors `cmd_up`'s already-bound branch, which has
/// always ignored the userinfo prefix when keeping an existing clean
/// slot. The hard invariant either way: a userinfo-bearing URL must
/// never reach `self.endpoints[]` or the published agent-card.
/// Self-pair guard (issue #30, explicit "Optional" ask).
///
/// Refuses to proceed when the resolved peer DID matches our own DID. Two
/// ways this fires:
///
///   1. The operator literally dialed their own handle by mistake.
///   2. Two terminals / agents that should be DISTINCT collapsed onto one
///      wire identity — either because v0.13's session-key resolution
///      didn't reach the wire process (env var not propagated; see #29 and
///      the Windows symptoms in #30) or because both terminals share a
///      WIRE_HOME without setting WIRE_SESSION_ID.
///
/// Pre-guard, case (2) silently produced a pair_drop targeting our own
/// slot — bilateral handshake could never complete and the operator could
/// only see "pending forever" with no diagnostic. The guard makes the
/// failure mode debuggable instead of silent by surfacing the exact DID
/// collision and pointing at the `wire whoami` / `WIRE_SESSION_ID`
/// diagnostic that the v0.13.5 session-key adapter introduced.
///
/// Companion to the lightweight nickname-match guard at the top of
/// `cmd_add` (which catches the literal `wire add <our-nick>@<relay>`
/// case before WebFinger). This DID-level guard is the load-bearing one
/// because case (2) — two collapsed terminals with DIFFERENT typed
/// nicknames that BOTH resolve to the shared DID — can't be caught
/// without the post-resolution comparison.
/// Issue #69 follow-up to #15: predicate "does this error smell like a
/// 4xx slot rotation?" — used by `try_reresolve_peer_on_slot_4xx` to
/// decide whether to spend a whois RTT on a re-resolve.
///
/// Original #15 implementation used `last_err.contains("410") ||
/// last_err.contains("404")`, which false-triggers on any unrelated
/// substring with `"410"`/`"404"` in it — e.g. `"slot 4101 expired"`,
/// `"request_id=410abc..."`, `"received 4040 bytes"`. False-trigger cost
/// is a single wasted whois per push call per peer (rate-limited by
/// `already_tried`), but it muddies the doctor diagnostic by inserting
/// spurious "peer slot rotated" log lines.
///
/// This predicate gates on the status code appearing as a *whole token*
/// — preceded by start-of-string / space / colon / tab / newline AND
/// followed by end-of-string / space / colon / tab / newline. That
/// matches both real-world shapes:
///
/// - `reqwest::StatusCode` Display, via `relay_client.rs` line ~339
///   `format!("post_event failed: {status}: {detail}")` →
///   `"post_event failed: 410 Gone: <body>"` (token `"410"` is followed
///   by space).
/// - UDS bare-`u16` Display, via `relay_client.rs` line ~227
///   `format!("post_event (uds {socket_path}) failed: {status}: ...")` →
///   `"post_event (uds /tmp/...sock) failed: 410: <body>"` (token
///   `"410"` is followed by colon).
///
/// And rejects the false-positive shapes documented in
/// `error_smells_like_slot_4xx_tests` below.
pub(crate) fn strip_relay_url_userinfo(url: &str) -> String {
    // Locate the authority segment: everything after `://` (or the whole
    // string if there is no scheme yet), up to the first `/`, `?`, or `#`.
    let authority_start = url.find("://").map(|i| i + 3).unwrap_or(0);
    let rest = &url[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];

    let Some(at_pos) = authority.find('@') else {
        return url.to_string();
    };

    let userinfo = &authority[..at_pos];
    let host = &authority[at_pos + 1..];
    let scheme = &url[..authority_start];
    let tail = &rest[authority_end..];
    let cleaned = format!("{scheme}{host}{tail}");

    eprintln!(
        "wire: ignoring `{userinfo}@` prefix on relay URL `{url}` — \
         in v0.11+ your handle is DID-derived (one-name rule), so the relay URL \
         is just the bare relay. Binding to `{cleaned}` instead."
    );

    cleaned
}

/// Hard assertion that a URL about to be persisted to `relay_state` /
/// published in the signed agent-card carries no userinfo. The
/// `strip_relay_url_userinfo` filter at every public entry point already
/// removes it; this is the belt-and-suspenders check at the actual mutation
/// site — a future code path that bypasses the entry filter must NOT be
/// able to leak a malformed endpoint into a signed card or the persisted
/// relay state.
pub(crate) fn assert_relay_url_clean_for_publish(url: &str) -> Result<()> {
    let authority_start = url.find("://").map(|i| i + 3).unwrap_or(0);
    let rest = &url[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains('@') {
        bail!(
            "internal invariant violated: relay URL `{url}` still carries userinfo at \
             the persist/publish boundary — `strip_relay_url_userinfo` must be called \
             before this point. Refusing to publish a malformed endpoint."
        );
    }
    Ok(())
}

// ---------- setup — one-shot MCP host registration ----------

pub(crate) fn cmd_setup(apply: bool) -> Result<()> {
    use crate::adapters::harness::HARNESS_ADAPTERS;
    use std::path::PathBuf;

    // v0.14.x: no `env` mapping. Per-session identity for Claude Code is
    // resolved by `crate::session::resolve_session_key`, which reads
    // `WIRE_SESSION_ID` then falls back to `CLAUDE_CODE_SESSION_ID`. Current
    // Claude Code (verified 2026-05) propagates `CLAUDE_CODE_SESSION_ID`
    // into every MCP subprocess by default, so the historical mapping was
    // redundant and triggered a misleading MCP Config Diagnostics warning.
    let entry = json!({
        "command": "wire",
        "args": ["mcp"]
    });
    let entry_pretty = serde_json::to_string_pretty(&json!({"wire": &entry}))?;

    // v0.14.2 (#92 category 1): per-host detection + upsert logic lives
    // in `adapters::harness::HARNESS_ADAPTERS`. Adding a new harness is
    // one struct entry there + one test. This loop is the only consumer.
    let mut targets: Vec<(&str, PathBuf)> = Vec::new();
    for adapter in HARNESS_ADAPTERS {
        for path in (adapter.paths_fn)() {
            targets.push((adapter.name, path));
        }
    }

    println!("wire setup\n");
    println!("MCP server snippet (add this to your client's mcpServers):");
    println!();
    println!("{entry_pretty}");
    println!();

    if !apply {
        println!("Probable MCP host config locations on this machine:");
        for (name, path) in &targets {
            let marker = if path.exists() {
                "✓ found"
            } else {
                "  (would create)"
            };
            println!("  {marker:14}  {name}: {}", path.display());
        }
        println!();
        println!("Run `wire setup --apply` to merge wire into each config above.");
        println!(
            "Existing entries with a different command keep yours unchanged unless wire's exact entry is missing."
        );
        return Ok(());
    }

    let mut modified: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for adapter in HARNESS_ADAPTERS {
        for path in (adapter.paths_fn)() {
            match (adapter.upsert_fn)(&path, "wire", &entry) {
                Ok(true) => {
                    modified.push(format!("✓ {} ({})", adapter.name, path.display()));
                }
                Ok(false) => skipped.push(format!(
                    "  {} ({}): already configured",
                    adapter.name,
                    path.display()
                )),
                Err(e) => skipped.push(format!("✗ {} ({}): {e}", adapter.name, path.display())),
            }
        }
    }
    if !modified.is_empty() {
        println!("Modified:");
        for line in &modified {
            println!("  {line}");
        }
        println!();
        println!("Restart the app(s) above to load wire MCP.");
    }
    if !skipped.is_empty() {
        println!();
        println!("Skipped:");
        for line in &skipped {
            println!("  {line}");
        }
    }
    Ok(())
}

// v0.14.2 (#92 cat 1): `fn upsert_mcp_entry` retired. Its three
// shape-dispatching branches (standard / vscode / opencode) moved into
// per-shape `upsert_*` fns in `adapters::harness`. Adding a new shape
// = one new upsert fn + one registry entry, instead of editing this
// switch statement.

// ---------- setup --statusline ----------

/// Bundled Claude Code statusLine renderer (persona emoji + nickname + cwd,
/// pidfile+tasklist liveness). Embedded at compile time; written to the
/// Claude config dir on `wire setup --statusline --apply`.
pub(crate) const STATUSLINE_RENDERER: &str = include_str!("../../assets/wire-statusline.sh");

/// `wire setup --statusline [--apply] [--remove]` — install/remove a Claude
/// Code statusLine that renders this session's wire persona. Honors
/// `$CLAUDE_CONFIG_DIR` (default `~/.claude`). Writes the renderer script and
/// merges a `statusLine` block into settings.json, preserving existing keys
/// and refusing to clobber a settings.json that exists but isn't valid JSON.
pub(crate) fn cmd_setup_statusline(apply: bool, remove: bool) -> Result<()> {
    use std::path::PathBuf;
    let cfg_dir: PathBuf = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".claude")))
        .ok_or_else(|| anyhow!("cannot locate Claude config dir (set $CLAUDE_CONFIG_DIR)"))?;
    let settings_path = cfg_dir.join("settings.json");
    let script_path = cfg_dir.join("wire-statusline.sh");
    // Resolve the shell invocation. On Windows a bare `bash` resolves to
    // System32\bash.exe (WSL) — wrong environment, Windows paths invalid,
    // statusline breaks — so we emit the absolute git-bash path. On Unix a
    // bare `bash <script>` is correct. Script path is quoted for spaces.
    let (command, command_warn) = statusline_command(&script_path);

    println!("wire setup --statusline\n");
    println!("Claude config dir: {}", cfg_dir.display());
    println!("  renderer:  {}", script_path.display());
    println!("  settings:  {}", settings_path.display());
    if let Some(w) = &command_warn {
        println!("  ⚠ {w}");
    }
    println!();

    if remove {
        if !apply {
            println!("Would REMOVE the statusLine key from settings.json and delete the renderer.");
            println!("Run `wire setup --statusline --remove --apply` to do it.");
            return Ok(());
        }
        let dropped = remove_statusline_entry(&settings_path)?;
        let script_gone = if script_path.exists() {
            std::fs::remove_file(&script_path).is_ok()
        } else {
            false
        };
        println!(
            "Removed: statusLine key {} · renderer {}",
            if dropped { "dropped" } else { "absent" },
            if script_gone { "deleted" } else { "absent" }
        );
        return Ok(());
    }

    if !apply {
        println!("Would write the renderer above and merge into settings.json:");
        println!();
        println!("  \"statusLine\": {{ \"type\": \"command\", \"command\": \"{command}\" }}");
        println!();
        println!("Resulting statusline:  ● <emoji> <nickname> · <cwd>");
        println!("Run `wire setup --statusline --apply` to install.");
        println!("(Existing settings.json keys are preserved; an invalid settings.json aborts.)");
        return Ok(());
    }

    if let Some(parent) = script_path.parent() {
        std::fs::create_dir_all(parent).context("creating Claude config dir")?;
    }
    std::fs::write(&script_path, STATUSLINE_RENDERER).context("writing renderer script")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&script_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&script_path, perms);
        }
    }
    let changed = upsert_statusline_entry(&settings_path, &command)?;
    println!("✓ renderer written: {}", script_path.display());
    if changed {
        println!("✓ merged statusLine into: {}", settings_path.display());
    } else {
        println!(
            "  settings.json already configured: {}",
            settings_path.display()
        );
    }
    println!();
    println!("Restart Claude Code (or reopen the session) to see your persona in the statusline.");
    Ok(())
}

/// Merge a `statusLine` command block into a Claude settings.json, preserving
/// all other keys. Returns Ok(true) if changed. Refuses to clobber a file that
/// exists but is not valid JSON.
pub(crate) fn upsert_statusline_entry(path: &std::path::Path, command: &str) -> Result<bool> {
    let mut cfg: Value = if path.exists() {
        let body = std::fs::read_to_string(path).context("reading settings.json")?;
        if body.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&body).context(
                "settings.json exists but is not valid JSON — refusing to clobber; fix or remove it first",
            )?
        }
    } else {
        json!({})
    };
    if !cfg.is_object() {
        bail!("settings.json root is not a JSON object — refusing to clobber");
    }
    let desired = json!({"type": "command", "command": command});
    let root = cfg.as_object_mut().unwrap();
    if root.get("statusLine") == Some(&desired) {
        return Ok(false);
    }
    root.insert("statusLine".to_string(), desired);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).context("creating parent dir")?;
    }
    let out = serde_json::to_string_pretty(&cfg)? + "\n";
    std::fs::write(path, out).context("writing settings.json")?;
    Ok(true)
}

/// Drop the `statusLine` key from settings.json. Ok(true) if a key was removed,
/// Ok(false) if file/key absent. Refuses to edit invalid JSON.
pub(crate) fn remove_statusline_entry(path: &std::path::Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let body = std::fs::read_to_string(path).context("reading settings.json")?;
    if body.trim().is_empty() {
        return Ok(false);
    }
    let mut cfg: Value = serde_json::from_str(&body)
        .context("settings.json is not valid JSON — refusing to edit")?;
    let Some(root) = cfg.as_object_mut() else {
        return Ok(false);
    };
    if root.remove("statusLine").is_none() {
        return Ok(false);
    }
    let out = serde_json::to_string_pretty(&cfg)? + "\n";
    std::fs::write(path, out).context("writing settings.json")?;
    Ok(true)
}

/// Build the `statusLine.command` string for this platform. Returns the
/// command plus an optional warning to surface to the operator.
fn statusline_command(script_path: &std::path::Path) -> (String, Option<String>) {
    #[cfg(windows)]
    {
        match resolve_git_bash() {
            Some(bash) => (format!("\"{}\" \"{}\"", bash, script_path.display()), None),
            None => (
                format!("bash \"{}\"", script_path.display()),
                Some(
                    "could not locate git-bash; using bare `bash`. On Windows that may resolve to \
                     WSL (System32\\bash.exe) and the statusline will be blank — install Git for \
                     Windows or set statusLine.command to your git-bash bash.exe path."
                        .to_string(),
                ),
            ),
        }
    }
    #[cfg(unix)]
    {
        (format!("bash \"{}\"", script_path.display()), None)
    }
}

/// Locate the git-bash `bash.exe` on Windows, avoiding the WSL launcher at
/// `System32\bash.exe`. Claude Code's statusLine command needs the real
/// git-bash so the renderer runs in a POSIX-ish env with valid paths.
#[cfg(windows)]
fn resolve_git_bash() -> Option<String> {
    use std::path::PathBuf;
    // 1. `where.exe bash` — take the first hit that is NOT under System32
    //    (that one is the WSL `bash.exe` launcher).
    if let Ok(out) = std::process::Command::new("where.exe").arg("bash").output()
        && out.status.success()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let p = line.trim();
            if !p.is_empty() && !p.to_lowercase().contains("\\system32\\") {
                return Some(p.to_string());
            }
        }
    }
    // 2. Common Git-for-Windows install locations.
    let candidates = [
        std::env::var("ProgramFiles")
            .ok()
            .map(|p| format!("{p}\\Git\\bin\\bash.exe")),
        std::env::var("ProgramFiles(x86)")
            .ok()
            .map(|p| format!("{p}\\Git\\bin\\bash.exe")),
        std::env::var("LocalAppData")
            .ok()
            .map(|p| format!("{p}\\Programs\\Git\\bin\\bash.exe")),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|c| PathBuf::from(c).exists())
}

#[cfg(test)]
mod statusline_tests {
    use super::*;

    #[test]
    fn statusline_merge_preserves_keys_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"theme":"dark","model":"opus"}"#).unwrap();
        // First merge changes the file but keeps existing keys.
        assert!(upsert_statusline_entry(&path, "bash /x.sh").unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["model"], "opus");
        assert_eq!(v["statusLine"]["type"], "command");
        assert_eq!(v["statusLine"]["command"], "bash /x.sh");
        // Identical re-merge = no change.
        assert!(!upsert_statusline_entry(&path, "bash /x.sh").unwrap());
        // Remove drops ONLY statusLine.
        assert!(remove_statusline_entry(&path).unwrap());
        let v2: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v2["theme"], "dark");
        assert!(v2.get("statusLine").is_none());
        // Remove again = no-op.
        assert!(!remove_statusline_entry(&path).unwrap());
    }

    #[test]
    fn statusline_merge_refuses_to_clobber_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "this is not json {").unwrap();
        let err = upsert_statusline_entry(&path, "bash /x.sh").unwrap_err();
        assert!(
            format!("{err:#}").contains("not valid JSON"),
            "err: {err:#}"
        );
        // File left untouched.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "this is not json {"
        );
    }

    #[test]
    fn statusline_creates_settings_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        assert!(upsert_statusline_entry(&path, "bash /x.sh").unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["statusLine"]["command"], "bash /x.sh");
    }
}

#[cfg(test)]
mod relay_url_tests {
    use super::*;

    #[test]
    fn strip_relay_url_userinfo_strips_handle_and_returns_cleaned() {
        // Bug 1: `wire up <handle>@<relay>` and `wire bind-relay
        // <handle>@<relay>` previously persisted/published the endpoint as
        // `https://<handle>@<relay>` — handle stuck in URL userinfo. Every
        // inbound event POST to that endpoint 4xxed (Cloudflare 400 on
        // wireup.net); bilateral pairing couldn't complete.
        //
        // Strip+warn (not hard-reject): mirrors cmd_up's already-bound
        // branch, which has always ignored the userinfo on the "keeping
        // existing binding" warning path. `<handle>@<relay>` is also
        // literally the wire dial-address format — natural by analogy.

        assert_eq!(
            strip_relay_url_userinfo("https://copilot-agent@wireup.net"),
            "https://wireup.net",
            "https URL with handle userinfo is stripped to the bare host"
        );
        assert_eq!(
            strip_relay_url_userinfo("http://copilot-agent@127.0.0.1:8771"),
            "http://127.0.0.1:8771",
            "http + port + userinfo is stripped, port preserved"
        );
        // user:password@host — both halves of userinfo are dropped.
        assert_eq!(strip_relay_url_userinfo("https://u:p@host"), "https://host");
        // Authority with port + userinfo.
        assert_eq!(
            strip_relay_url_userinfo("https://nick@host:8443"),
            "https://host:8443"
        );
        // Schemeless `<handle>@<host>` — strips correctly. (cmd_up's
        // bare-host normalize prepends https:// before calling, but the
        // function is robust to either input.)
        assert_eq!(strip_relay_url_userinfo("nick@wireup.net"), "wireup.net");
        // Path / query / fragment AFTER the authority are preserved.
        assert_eq!(
            strip_relay_url_userinfo("https://nick@wireup.net/v1/events?x=1#frag"),
            "https://wireup.net/v1/events?x=1#frag"
        );
    }

    #[test]
    fn strip_relay_url_userinfo_passes_clean_urls_through_unchanged() {
        // Bare host (https / http, with and without port, with path / query).
        for ok in [
            "https://wireup.net",
            "http://wireup.net",
            "http://127.0.0.1:8771",
            "https://relay.example.com:9443/v1/wire",
            "https://wireup.net/?env=prod",
            // Path / query containing `@` is fine — it's not in the authority.
            "https://wireup.net/users/me@example.com",
            "https://wireup.net/?to=me@example.com",
            // Fragment with @ — fine.
            "https://wireup.net/#contact@me",
            // IPv6 literal (no @ in authority).
            "http://[::1]:8771",
            // Schemeless bare host — also fine.
            "wireup.net",
            "wireup.net:8443",
        ] {
            assert_eq!(
                strip_relay_url_userinfo(ok),
                ok,
                "clean URL `{ok}` must pass through unchanged"
            );
        }
    }

    #[test]
    fn assert_relay_url_clean_for_publish_blocks_userinfo_at_persist_site() {
        // Belt-and-suspenders: even if a future code path bypasses
        // strip_relay_url_userinfo at the entry, the persist/publish
        // boundary must refuse a userinfo URL. This is the second line
        // of defense that keeps a malformed endpoint out of the SIGNED
        // agent-card and the persisted relay_state.
        assert!(assert_relay_url_clean_for_publish("https://wireup.net").is_ok());
        assert!(assert_relay_url_clean_for_publish("http://127.0.0.1:8771").is_ok());
        assert!(
            assert_relay_url_clean_for_publish("https://wireup.net/?to=me@example.com").is_ok()
        );

        let err = assert_relay_url_clean_for_publish("https://nick@wireup.net")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("invariant violated"),
            "persist-site failure must be flagged as an internal invariant violation, not user error: {err}"
        );
        assert!(
            err.contains("strip_relay_url_userinfo"),
            "error must name the upstream filter so the caller can audit the bypass: {err}"
        );
        // user:password@host is just as bad — userinfo is userinfo.
        assert!(assert_relay_url_clean_for_publish("https://u:p@host").is_err());
        // Authority with port + userinfo.
        assert!(assert_relay_url_clean_for_publish("https://nick@host:8443").is_err());
    }

    #[test]
    fn strip_proto_no_longer_doubles_handle_after_userinfo_fix() {
        // Bug 3 (cosmetic): `wire up <handle>@<relay>` echoed `claimed
        // <nick>@<nick>@<relay>` because strip_proto left the userinfo in.
        // With Bug 1's strip+warn in cmd_up, the claim step receives a
        // bare host — strip_proto returns `<host>` and the echo is
        // `<nick>@<host>` exactly once. Verified end-to-end here:
        let after_strip = strip_relay_url_userinfo("https://nick@wireup.net");
        assert_eq!(after_strip, "https://wireup.net");
        assert_eq!(strip_proto(&after_strip), "wireup.net");
        // And the doubled-echo failure mode that motivated the fix:
        assert!(
            strip_proto("https://nick@wireup.net").contains('@'),
            "strip_proto preserves userinfo by design; the userinfo guard upstream is what prevents the doubled echo"
        );
    }
}
