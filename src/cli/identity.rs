use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::{
    agent_card::{build_agent_card, sign_agent_card},
    config,
    signing::{fingerprint, generate_keypair, make_key_id},
    trust::{add_self_to_trust, empty_trust},
};

// ---------- init ----------

pub(crate) fn cmd_init(relay: Option<&str>, offline: bool, as_json: bool) -> Result<()> {
    // One-name rule: there is no operator-typed name to assign. Your identity
    // — and therefore your name — is minted here, from the freshly-generated
    // keypair: the persona handle is derived from the public-key fingerprint.
    // `init` is the sole naming event; no input names anything.
    if config::is_initialized()? {
        bail!(
            "already initialized — config exists at {:?}. Delete it first if you want a fresh identity.",
            config::config_dir()?
        );
    }
    // v0.9.1 smart-default reachability. If the operator passed neither
    // --relay nor --offline, probe the conventional local relay at
    // http://127.0.0.1:8771 and auto-attach if healthy. Closes the
    // silent-slotless footgun WITHOUT the v0.9 rejection wall, which
    // forced operators through a three-flag decision tree on first
    // invocation. Bare `wire init <handle>` is now ergonomic again
    // whenever a local relay is running (the common dev setup).
    //
    // Probe order:
    //   1. --relay <url>          → use it
    //   2. --offline               → skip slot allocation (rare power-user)
    //   3. local relay reachable  → auto-attach + log to stderr
    //   4. otherwise               → bail with actionable options
    let mut resolved_relay: Option<String> = relay.map(str::to_string);
    if resolved_relay.is_none() && !offline {
        let default_local = "http://127.0.0.1:8771";
        let client = crate::relay_client::RelayClient::new(default_local);
        if client.check_healthz().is_ok() {
            eprintln!(
                "wire init: local relay at {default_local} reachable — auto-attaching. \
                 Use --relay <url> to pick a different relay, --offline to skip."
            );
            resolved_relay = Some(default_local.to_string());
        } else {
            // v0.9.5: interactive prompt for first-time operators
            // when the smart-default can't auto-attach. Detect TTY on
            // stdin AND stderr — only prompt for humans. CI / agents
            // / non-interactive shells fall through to the explicit
            // error wall (unchanged behavior since v0.9.1).
            use std::io::{BufRead, IsTerminal, Write};
            let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
            if interactive && std::env::var("WIRE_NO_INTERACTIVE").is_err() {
                eprintln!("wire init: no local relay reachable at {default_local}.");
                eprint!(
                    "  Bind to public federation relay https://wireup.net instead? \
                     [Y/n/offline/url]: "
                );
                let _ = std::io::stderr().flush();
                let mut input = String::new();
                let _ = std::io::stdin().lock().read_line(&mut input);
                let answer = input.trim();
                match answer {
                    "" | "y" | "Y" | "yes" | "YES" => {
                        eprintln!("wire init: binding to https://wireup.net");
                        resolved_relay = Some("https://wireup.net".to_string());
                    }
                    "n" | "N" | "no" | "NO" => {
                        bail!(
                            "wire init: declined federation default; re-run with --relay <url> or --offline."
                        );
                    }
                    "offline" | "OFFLINE" => {
                        eprintln!(
                            "wire init: proceeding offline. \
                             Run `wire bind-relay <url>` before pairing."
                        );
                        // Fall through with resolved_relay still None;
                        // the `offline` flag is conceptually set but
                        // the caller's local doesn't need updating —
                        // resolved_relay = None + offline behavior
                        // is identical for the rest of cmd_init.
                    }
                    url if url.starts_with("http://") || url.starts_with("https://") => {
                        eprintln!("wire init: binding to {url}");
                        resolved_relay = Some(url.to_string());
                    }
                    other => {
                        bail!(
                            "wire init: unrecognized answer `{other}` — \
                             expected Y/n/offline/<url>. Re-run with --relay or --offline."
                        );
                    }
                }
            } else {
                bail!(
                    "wire init: no relay specified and no local relay reachable at \
                     http://127.0.0.1:8771.\n\
                     Pick one (or just run `wire up`):\n\
                     • `wire service install --local-relay` — start the local relay, then re-run\n\
                     • `wire up @wireup.net` — bind to public federation in one command\n\
                     • `wire init --offline` — generate keypair only \
                     (peers cannot reach you until you `wire bind-relay <url>` later)"
                );
            }
        }
    }
    let relay = resolved_relay.as_deref();

    config::ensure_dirs()?;
    let (sk_seed, pk_bytes) = generate_keypair();
    config::write_private_key(&sk_seed)?;

    // v0.11 ONE-NAME: derive the character nickname from a synthetic DID
    // using the freshly-generated pubkey, then USE THE CHARACTER as the
    // canonical handle. The operator-typed `handle` arg becomes either:
    //   - identical to character (already-canonical input — no-op), OR
    //   - overridden in favor of character (operator-typed name was a
    //     vanity layer that would never have been federation-reachable).
    // Either way, agent-card.handle ends up == character, and every
    // downstream surface (relay phonebook, .well-known, dial/send) keys
    // on the same name an operator sees in their statusline.
    //
    // Per the v0.11 directive: "If you can't call someone via a name,
    // don't let them have it as a name." Operator-typed handles violated
    // that rule because the character was the displayed name but the
    // handle was the addressable one. Now they're the same string.
    // The seed string only fills the (immediately-discarded) handle portion
    // of a synthetic DID; the persona derives from the fp suffix regardless,
    // so the seed is identity-irrelevant — a fixed constant suffices.
    let synth_did = crate::agent_card::did_for_with_key("agent", &pk_bytes);
    let character = crate::character::Character::from_did(&synth_did);
    let canonical_handle: &str = &character.nickname;

    // The card's display `name` is the handle, title-cased — never a
    // free-choice value. There is no operator name input that could diverge.
    let card = build_agent_card(canonical_handle, &pk_bytes, None, None, None);
    // Card-emit (RFC-001 Phase 1b): attach operator/org claims if enrolled
    // (fail-soft no-op otherwise; signed below so the sig covers the claims).
    let card = crate::enroll::with_op_claims_if_enrolled(card)?;
    let signed = sign_agent_card(&card, &sk_seed);
    config::write_agent_card(&signed)?;

    let mut trust = empty_trust();
    add_self_to_trust(&mut trust, canonical_handle, &pk_bytes);
    config::write_trust(&trust)?;

    let fp = fingerprint(&pk_bytes);
    let key_id = make_key_id(canonical_handle, &pk_bytes);
    // Rebind `handle` for the rest of cmd_init so downstream prints,
    // relay-state writes, etc. all reference the canonical name.
    let handle = canonical_handle;

    // If --relay was passed, also bind a slot inline so init+bind happen in one step.
    let mut relay_info: Option<(String, String)> = None;
    if let Some(url) = relay {
        let normalized = url.trim_end_matches('/');
        let client = crate::relay_client::RelayClient::new(normalized);
        client.check_healthz()?;
        let alloc = client.allocate_slot(Some(handle))?;
        let mut state = config::read_relay_state()?;
        state["self"] = json!({
            "relay_url": normalized,
            "slot_id": alloc.slot_id.clone(),
            "slot_token": alloc.slot_token,
        });
        config::write_relay_state(&state)?;
        relay_info = Some((normalized.to_string(), alloc.slot_id));
    }

    let did_str = crate::agent_card::did_for_with_key(handle, &pk_bytes);
    if as_json {
        let mut out = json!({
            "did": did_str.clone(),
            "fingerprint": fp,
            "key_id": key_id,
            "config_dir": config::config_dir()?.to_string_lossy(),
        });
        if let Some((url, slot_id)) = &relay_info {
            out["relay_url"] = json!(url);
            out["slot_id"] = json!(slot_id);
        }
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("generated {did_str} (ed25519:{key_id})");
        println!(
            "config written to {}",
            config::config_dir()?.to_string_lossy()
        );
        if let Some((url, slot_id)) = &relay_info {
            println!("bound to relay {url} (slot {slot_id})");
            println!();
            println!("next step: `wire dial <handle>@{url}` to pair with a peer.");
        } else {
            println!();
            println!("next step: `wire dial <handle>@<relay>` to bind a relay + pair with a peer.");
        }
    }
    Ok(())
}

// ---------- whoami ----------

/// Return the current cwd with the user's home dir abbreviated to `~/`.
/// Used in whoami `--short` / `--colored` output so multi-window operators
/// see *what project* each Claude is working in alongside the character.
fn current_cwd_display() -> String {
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(_) => return String::from("?"),
    };
    if let Some(home) = dirs::home_dir()
        && let Ok(rel) = cwd.strip_prefix(&home)
    {
        // strip_prefix returns "" for cwd == home itself; show "~" then.
        let rel_str = rel.to_string_lossy();
        if rel_str.is_empty() {
            return String::from("~");
        }
        return format!("~/{rel_str}");
    }
    cwd.to_string_lossy().into_owned()
}

/// v0.14: extract the inline op claims from an agent card (or pinned
/// trust row) for surfacing on operator-facing read paths. Returns the
/// subset of fields actually present and non-null — operators read the
/// absence to mean "not enrolled / older peer".
///
/// Surfaced fields: `op_did`, `op_pubkey`, `op_cert`, `org_memberships`,
/// `schema_version`. All RFC-001-defined; all public commits, safe to
/// surface on every read verb. Centralized here so whoami / peers / whois
/// stay in lock-step as the inline set grows (e.g. `sso_attest` in v0.15).
///
/// `pub(crate)` so the MCP surface (`src/mcp.rs`) wires the same helper
/// into `tool_whoami` / `tool_peers` — agents reading MCP responses must
/// see the same op claims that operators see via CLI.
pub(crate) fn op_claims_from_card(card: &Value) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    for key in [
        "op_did",
        "op_pubkey",
        "op_cert",
        "org_memberships",
        "schema_version",
    ] {
        if let Some(v) = card.get(key)
            && !v.is_null()
        {
            out.insert(key.to_string(), v.clone());
        }
    }
    out
}

pub(super) fn cmd_whoami(as_json: bool, short: bool, colored: bool) -> Result<()> {
    if !config::is_initialized()? {
        // v0.14.x: with per-session WIRE_HOME (`sessions/by-key/<hash>`), a
        // freshly-spawned session's home starts EMPTY until `wire up`. The
        // machine-readable consumers that poll whoami every render — statusline
        // scripts, the `.wire-name` cache refreshers — hit that uninitialized
        // state constantly. Bailing (exit 1, no stdout) made them crash on
        // empty stdin or freeze on a stale name. Degrade gracefully here,
        // matching `wire here --json`, so a missing identity is a parseable
        // signal rather than a hard failure. The bare interactive (tty, no
        // JSON) path keeps its actionable hint + exit 1.
        // Precedence mirrors the initialized path below: an explicit --short
        // / --colored beats the piped-stdout JSON default (`json_default`),
        // and bare interactive `wire whoami` still gets the actionable hint.
        if short {
            println!("(uninitialized) · {}", current_cwd_display());
            return Ok(());
        }
        if colored {
            println!(
                "\x1b[2m(uninitialized)\x1b[0m \x1b[2m·\x1b[0m {}",
                current_cwd_display()
            );
            return Ok(());
        }
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "initialized": false,
                    "cwd": current_cwd_display(),
                }))?
            );
            return Ok(());
        }
        bail!("not initialized — run `wire up` first");
    }
    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let handle = card
        .get("handle")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| crate::agent_card::display_handle_from_did(&did).to_string());
    // v0.11: character is purely DID-derived. No overrides — the
    // operator-rename verb is gone and display.json reads are stripped
    // because they introduced a second name that peers couldn't find.
    let character = crate::character::Character::from_did(&did);

    // v0.7.0-alpha.3: append the current cwd (home-abbreviated to `~/`)
    // so operators tab-flipping between multiple Claude windows see both
    // *who* this session is (character) and *what* it's working on (cwd).
    // The cwd is the OPERATOR's cwd, not WIRE_HOME — gives them the
    // anchor they're looking for: "🐅 winter-bay · ~/Source/wire".
    let cwd_display = current_cwd_display();

    // Fast paths used by statuslines, piping, scripts. No agent-card parsing
    // beyond did — these calls are hot (statusline polls ~300ms).
    if short {
        println!("{} · {}", character.short(), cwd_display);
        return Ok(());
    }
    if colored {
        println!("{} \x1b[2m·\x1b[0m {}", character.colored(), cwd_display);
        return Ok(());
    }

    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;
    let fp = fingerprint(&pk_bytes);
    let key_id = make_key_id(&handle, &pk_bytes);
    let capabilities = card
        .get("capabilities")
        .cloned()
        .unwrap_or_else(|| json!(["wire/v3.1"]));

    if as_json {
        // v0.11: character_override is always false now (no rename verb,
        // no display.json reads). Field stays for back-compat with v0.10
        // JSON consumers that key off it.
        let has_override = false;
        let mut payload = serde_json::Map::new();
        // Symmetric with the uninitialized branch above so consumers can
        // branch on a single key instead of probing for `did`.
        payload.insert("initialized".into(), json!(true));
        payload.insert("did".into(), json!(did));
        payload.insert("handle".into(), json!(handle));
        payload.insert("fingerprint".into(), json!(fp));
        payload.insert("key_id".into(), json!(key_id));
        payload.insert("public_key_b64".into(), json!(pk_b64));
        payload.insert("capabilities".into(), capabilities);
        payload.insert(
            "config_dir".into(),
            json!(config::config_dir()?.to_string_lossy()),
        );
        // RFC-008 §A: surface WHICH signal won session/home resolution, so an
        // operator diagnosing a wrong/shared identity sees the cause in one
        // command instead of a forensic deep-dive (cf. #210). Additive,
        // read-only; absent only on pre-RFC-008 binaries.
        payload.insert(
            "session_source".into(),
            json!(crate::session::session_source()),
        );
        payload.insert("persona".into(), serde_json::to_value(&character)?);
        payload.insert("persona_override".into(), json!(has_override));
        // v0.14: surface the RFC-001 op claims (when enrolled) on the
        // canonical operator read verb. Absent ⇒ pre-v0.14 card or not
        // yet enrolled. See `op_claims_from_card` rationale.
        for (k, v) in op_claims_from_card(&card) {
            payload.insert(k, v);
        }
        println!("{}", serde_json::to_string(&payload)?);
    } else {
        println!("{}", character.colored());
        println!("{did} (ed25519:{key_id})");
        println!("fingerprint: {fp}");
        println!("capabilities: {capabilities}");
        // v0.14: when enrolled, surface op_did + membership count so
        // the operator can spot at a glance whether the marquee identity
        // layer is active. Silent when not enrolled (no clutter for
        // pre-v0.14 cards).
        if let Some(op_did) = card.get("op_did").and_then(Value::as_str) {
            let memberships = card
                .get("org_memberships")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            let plural = if memberships == 1 { "" } else { "s" };
            println!("enrolled: {op_did} ({memberships} org membership{plural})");
        }
    }
    Ok(())
}

// ---------- identity (v0.7.0-alpha.3) ----------

pub(super) fn cmd_enroll(cmd: super::EnrollCommand) -> Result<()> {
    match cmd {
        super::EnrollCommand::Op { handle, json } => {
            let (sk, pk) = crate::signing::generate_keypair();
            crate::config::write_op_key(&sk)?;
            crate::config::write_op_handle(&handle)?;
            let op_did = crate::agent_card::did_for_op(&handle, &pk);
            let op_pubkey = crate::signing::b64encode(&pk);
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({"op_did": op_did, "op_pubkey": op_pubkey}))?
                );
            } else {
                println!(
                    "→ operator enrolled\n  op_did:    {op_did}\n  op_pubkey: {op_pubkey}\n  key saved 0600 at {:?}",
                    crate::config::op_key_path()?
                );
            }
            Ok(())
        }
        super::EnrollCommand::OrgCreate { handle, json } => {
            let (sk, pk) = crate::signing::generate_keypair();
            let org_did = crate::agent_card::did_for_org(&handle, &pk);
            crate::config::write_org_key(&org_did, &sk)?;
            let org_pubkey = crate::signing::b64encode(&pk);
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({"org_did": org_did, "org_pubkey": org_pubkey}))?
                );
            } else {
                println!(
                    "→ organization created\n  org_did:    {org_did}\n  org_pubkey: {org_pubkey}\n  key saved 0600 at {:?}",
                    crate::config::org_key_path(&org_did)?
                );
            }
            Ok(())
        }
        super::EnrollCommand::OrgAddMember { op_did, org, json } => {
            if !crate::agent_card::is_op_did(&op_did) {
                bail!("not a valid operator DID (did:wire:op:<handle>-<32hex>): {op_did}");
            }
            let org_sk = crate::config::read_org_key(&org).with_context(|| {
                format!("no stored key for org {org} — run `wire enroll org-create` first")
            })?;
            let org_pk = ed25519_dalek::SigningKey::from_bytes(&org_sk)
                .verifying_key()
                .to_bytes();
            let member_cert = crate::enroll::issue_member_cert(&org_sk, &op_did)?;
            let org_pubkey = crate::signing::b64encode(&org_pk);
            // Store locally so card-emit can attach it (same-machine operator);
            // also printed below for the cross-machine share case.
            crate::config::add_membership(&org, &org_pubkey, &member_cert)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "org_did": org, "org_pubkey": org_pubkey, "member_cert": member_cert
                    }))?
                );
            } else {
                println!(
                    "→ membership issued for {op_did}\n  add to the operator's card org_memberships[]:\n  {{\"org_did\": \"{org}\", \"org_pubkey\": \"{org_pubkey}\", \"member_cert\": \"{member_cert}\"}}"
                );
            }
            Ok(())
        }
        super::EnrollCommand::AddMembership {
            bundle,
            org,
            org_pubkey,
            member_cert,
            json,
        } => cmd_enroll_add_membership(bundle, org, org_pubkey, member_cert, json),
        super::EnrollCommand::Republish { json } => {
            // Rebuild the on-disk card with current enrollment, then republish
            // via the same path `profile set` uses. Closes the enroll-after-init
            // DX gap (see `enroll::rebuild_card_with_current_claims`).
            let card = crate::enroll::rebuild_card_with_current_claims()?;
            let published = republish_card_to_phonebook();
            let op_did = card
                .get("op_did")
                .and_then(Value::as_str)
                .map(str::to_string);
            let n_memberships = card
                .get("org_memberships")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "op_did": op_did,
                        "org_memberships": n_memberships,
                        "published": published,
                    }))?
                );
            } else {
                match op_did {
                    Some(did) => println!(
                        "→ card rebuilt with current enrollment\n  op_did:    {did}\n  memberships: {n_memberships}"
                    ),
                    None => println!(
                        "→ card rebuilt — no operator enrolled (claims stripped if previously present)"
                    ),
                }
                print_profile_publish_result(&published);
            }
            Ok(())
        }
        super::EnrollCommand::RotateOpKey { json } => cmd_enroll_rotate_op_key(json),
        super::EnrollCommand::RotateOrgKey { org_did, json } => {
            cmd_enroll_rotate_org_key(&org_did, json)
        }
        super::EnrollCommand::FleetLink {
            dry_run,
            rotate_machine,
            json,
        } => cmd_enroll_fleet_link(dry_run, rotate_machine, json),
    }
}

/// `wire enroll fleet-link` — RFC-001 amendment #182. Attach an op_sk-signed
/// same-machine attestation to every enrolled sibling session's card so any two
/// of this operator's sessions on this machine auto-pin each other at
/// ORG_VERIFIED. Idempotent: the canonical signed message is deterministic, so a
/// re-run reproduces byte-identical attestations.
fn cmd_enroll_fleet_link(dry_run: bool, rotate_machine: bool, as_json: bool) -> Result<()> {
    // §D precondition: the machine fingerprint must be computable, else there is
    // no same-machine identity to sign.
    crate::same_machine::local_fingerprint().context(
        "could not read this machine's fingerprint (machine-id / OS-user id unreadable) — \
         same-machine attestation unavailable on this platform",
    )?;

    let sessions = crate::session::list_sessions()?;
    let saved_home = std::env::var("WIRE_HOME").ok();

    let mut linked: Vec<String> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();

    for s in &sessions {
        let label = s
            .did
            .clone()
            .unwrap_or_else(|| s.home_dir.display().to_string());
        // Operate in each sibling's own home so config_dir() resolves to that
        // session's card + keys. SAFETY: `wire enroll fleet-link` is a one-shot,
        // single-threaded CLI command — no other thread reads WIRE_HOME
        // concurrently — and we restore it before returning.
        unsafe { std::env::set_var("WIRE_HOME", &s.home_dir) };

        if crate::config::read_op_key().is_err() {
            skipped.push((label, "not enrolled (no op.key)".to_string()));
            continue;
        }
        if dry_run {
            linked.push(label);
            continue;
        }
        // rebuild_card_with_current_claims re-attaches a FRESH same-machine
        // attestation (built against the current machine fingerprint, so this
        // doubles as --rotate-machine) and re-signs locally — no publish.
        match crate::enroll::rebuild_card_with_current_claims() {
            Ok(_) => linked.push(label),
            Err(e) => skipped.push((label, format!("rebuild failed: {e}"))),
        }
    }

    // Restore the caller's WIRE_HOME.
    match saved_home {
        Some(h) => unsafe { std::env::set_var("WIRE_HOME", h) },
        None => unsafe { std::env::remove_var("WIRE_HOME") },
    }

    let verb = if dry_run {
        "would link"
    } else if rotate_machine {
        "re-signed (machine rotation)"
    } else {
        "linked"
    };

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "dry_run": dry_run,
                "rotate_machine": rotate_machine,
                "linked": linked,
                "skipped": skipped.iter().map(|(d, why)| json!({"session": d, "reason": why})).collect::<Vec<_>>(),
            }))?
        );
    } else {
        if linked.is_empty() && !sessions.is_empty() {
            println!("→ no enrolled sibling sessions found to link — run `wire enroll op` first");
        }
        for d in &linked {
            println!("  ✓ {verb}: {d}");
        }
        for (d, why) in &skipped {
            println!("  – skipped {d}: {why}");
        }
        println!(
            "→ {} session(s) {verb}, {} skipped",
            linked.len(),
            skipped.len()
        );
    }
    Ok(())
}

/// `wire enroll rotate-op-key` — RFC-001 §T20 operator key rotation.
fn cmd_enroll_rotate_op_key(as_json: bool) -> Result<()> {
    let old_sk = crate::config::read_op_key()
        .context("no operator key on disk — run `wire enroll op` before rotating")?;
    let old_pk = ed25519_dalek::SigningKey::from_bytes(&old_sk)
        .verifying_key()
        .to_bytes();
    let handle = crate::config::read_op_handle()?.unwrap_or_else(|| "operator".to_string());
    let old_did = crate::agent_card::did_for_op(&handle, &old_pk);

    let (new_sk, new_pk) = crate::signing::generate_keypair();
    let new_did = crate::agent_card::did_for_op(&handle, &new_pk);

    let cert = crate::identity::sign_succession_cert(&old_sk, "op", &old_did, &new_did)?;
    // Defensive self-check: the cert we just produced must verify under the old
    // key for exactly this handoff before we commit the new key to disk.
    crate::identity::verify_succession_cert(&old_pk, &cert, "op", &old_did, &new_did)
        .map_err(|e| anyhow!("internal: succession cert failed self-verify ({e})"))?;

    // Record the handoff BEFORE overwriting the key (so an interruption leaves
    // the old key intact + recoverable, never a new key with no audit trail).
    crate::config::append_succession_record("op", &old_did, &new_did, &cert)?;
    crate::config::write_op_key(&new_sk)?; // commit point

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "kind": "op",
                "old_op_did": old_did,
                "new_op_did": new_did,
                "succession_cert": cert,
            }))?
        );
    } else {
        println!("→ operator key rotated");
        println!("  old op_did: {old_did}");
        println!("  new op_did: {new_did}");
        println!("  succession cert recorded in succession.jsonl.");
        println!("\nNext steps (manual — receiver auto-migration is deferred, T20):");
        println!("  1. Each org you're in re-issues your member_cert against the NEW op_did:");
        println!("       wire enroll org-add-member {new_did} --org <org_did>");
        println!("  2. wire enroll republish   # surface the new op_did on your card");
    }
    Ok(())
}

/// `wire enroll rotate-org-key <org_did>` — RFC-001 §T19 org key rotation.
fn cmd_enroll_rotate_org_key(org_did: &str, as_json: bool) -> Result<()> {
    if !crate::agent_card::is_org_did(org_did) {
        bail!("not a valid org DID (did:wire:org:<handle>-<32hex>): {org_did}");
    }
    let old_sk = crate::config::read_org_key(org_did)
        .with_context(|| format!("no stored key for org {org_did} — nothing to rotate"))?;
    let old_pk = ed25519_dalek::SigningKey::from_bytes(&old_sk)
        .verifying_key()
        .to_bytes();
    // The on-disk key must actually commit to the named org_did (the file is
    // keyed by org_did, but verify the binding before signing a handoff for it).
    let derived = crate::agent_card::did_for_org(org_handle(org_did), &old_pk);
    if derived != org_did {
        bail!(
            "stored key for {org_did} does not commit to it (derived {derived}) — refusing to \
             sign a succession for a mismatched key"
        );
    }

    let (new_sk, new_pk) = crate::signing::generate_keypair();
    let new_did = crate::agent_card::did_for_org(org_handle(org_did), &new_pk);

    let cert = crate::identity::sign_succession_cert(&old_sk, "org", org_did, &new_did)?;
    crate::identity::verify_succession_cert(&old_pk, &cert, "org", org_did, &new_did)
        .map_err(|e| anyhow!("internal: succession cert failed self-verify ({e})"))?;

    crate::config::append_succession_record("org", org_did, &new_did, &cert)?;
    // Store the new key under the NEW org_did; the old key file is left in place.
    crate::config::write_org_key(&new_did, &new_sk)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "kind": "org",
                "old_org_did": org_did,
                "new_org_did": new_did,
                "succession_cert": cert,
            }))?
        );
    } else {
        println!("→ organization key rotated");
        println!("  old org_did: {org_did}");
        println!("  new org_did: {new_did}");
        println!("  new key saved 0600; old key file left in place (delete when ready).");
        println!("\nNext steps:");
        println!("  1. Re-issue every member_cert with the new key:");
        println!("       wire enroll org-add-member <op_did> --org {new_did}");
        println!("  2. Republish the org's DNS-TXT binding to point at {new_did}.");
    }
    Ok(())
}

/// Extract the handle component of an op/org DID (`did:wire:{op,org}:<handle>-<hex>`).
/// Falls back to the whole tail if the shape is unexpected.
fn org_handle(did: &str) -> &str {
    let tail = did
        .strip_prefix("did:wire:org:")
        .or_else(|| did.strip_prefix("did:wire:op:"))
        .unwrap_or(did);
    tail.rsplit_once('-').map(|(h, _)| h).unwrap_or(tail)
}

/// Implementation of `wire enroll add-membership` (closes #127).
///
/// Validates the bundle before storing — a malformed / wrong-key cert
/// would corrupt the next `wire enroll republish` (the bundle is
/// attached verbatim to the agent card; a bad bundle propagates to
/// peers and gets rejected on `evaluate_card_membership`). Verifying
/// up-front means the failure is at ingest time, not at publish time.
fn cmd_enroll_add_membership(
    bundle: Option<String>,
    org: Option<String>,
    org_pubkey: Option<String>,
    member_cert: Option<String>,
    as_json: bool,
) -> Result<()> {
    // Resolve the three fields from either --bundle or the individual flags.
    let (org_did, org_pk_b64, cert_b64) = if let Some(b) = bundle {
        let v: Value = serde_json::from_str(&b).with_context(|| "parsing --bundle as JSON")?;
        let o = v
            .get("org_did")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("--bundle missing 'org_did'"))?
            .to_string();
        let p = v
            .get("org_pubkey")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("--bundle missing 'org_pubkey'"))?
            .to_string();
        let c = v
            .get("member_cert")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("--bundle missing 'member_cert'"))?
            .to_string();
        (o, p, c)
    } else {
        let o = org.ok_or_else(|| anyhow!("--org is required when --bundle is not set"))?;
        let p = org_pubkey
            .ok_or_else(|| anyhow!("--org-pubkey is required when --bundle is not set"))?;
        let c = member_cert
            .ok_or_else(|| anyhow!("--member-cert is required when --bundle is not set"))?;
        (o, p, c)
    };

    // Validate org_did shape — refuse before touching disk.
    if !crate::agent_card::is_org_did(&org_did) {
        bail!("not a valid organization DID (did:wire:org:<handle>-<32hex>): {org_did}");
    }

    // This operator must be enrolled — we need op_did to verify the cert
    // is FOR US, not for a different operator. A cert valid against some
    // other op_did would still verify on the org_pubkey but storing it
    // here would be a misattribution.
    let op_sk = crate::config::read_op_key().with_context(
        || "this operator is not enrolled — run `wire enroll op` first to mint op_did",
    )?;
    let op_handle = crate::config::read_op_handle()
        .ok()
        .flatten()
        .unwrap_or_else(|| "operator".to_string());
    let op_pk = ed25519_dalek::SigningKey::from_bytes(&op_sk)
        .verifying_key()
        .to_bytes();
    let op_did = crate::agent_card::did_for_op(&op_handle, &op_pk);

    // Decode + verify the cert against org_pubkey + this op_did. Failure
    // here is the load-bearing guard against the "stored bundle corrupts
    // republish" footgun.
    let org_pk_bytes =
        crate::signing::b64decode(&org_pk_b64).with_context(|| "decoding --org-pubkey (base64)")?;
    crate::identity::verify_member_cert(&org_pk_bytes, &cert_b64, &op_did)
        .map_err(|e| anyhow!("member_cert verification failed: {e:?} — bundle is not valid for this operator (op_did={op_did})"))?;

    // Idempotent store. add_membership retains-then-pushes so re-running
    // with the same org_did replaces the prior entry; multiple distinct
    // orgs accumulate.
    crate::config::add_membership(&org_did, &org_pk_b64, &cert_b64)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "stored": true,
                "org_did": org_did,
                "op_did": op_did,
                "note": "run `wire enroll republish` to attach the claim to your agent card and republish",
            }))?
        );
    } else {
        println!(
            "→ membership stored\n  org_did:  {org_did}\n  op_did:   {op_did}\n  next: `wire enroll republish` to attach + publish"
        );
    }
    Ok(())
}

pub(super) fn cmd_identity(cmd: super::IdentityCommand) -> Result<()> {
    match cmd {
        // v0.11: IdentityCommand::Rename deleted. The character is the
        // one canonical name (DID-derived); a local-display rename
        // would create a second name peers can't find, violating the
        // "names must be findable" invariant. Aliases (if needed
        // later) become relay-claimed entries that ARE findable —
        // a different architectural shape from rename.
        super::IdentityCommand::Show { json } => cmd_whoami(json, !json, false),
        super::IdentityCommand::List { json } => super::session::cmd_session_list(json),
        super::IdentityCommand::Publish {
            nick,
            relay,
            public_url,
            hidden,
            json,
        } => cmd_claim(&nick, relay.as_deref(), public_url.as_deref(), hidden, json),
        super::IdentityCommand::Destroy { name, force, json } => {
            super::session::cmd_session_destroy(&name, force, json)
        }
        super::IdentityCommand::Create {
            name,
            anonymous,
            local: _,
            json,
        } => cmd_identity_create(name.as_deref(), anonymous, json),
        super::IdentityCommand::Persist {
            name,
            as_name,
            json,
        } => cmd_identity_persist(&name, as_name.as_deref(), json),
        super::IdentityCommand::Demote { name, json } => cmd_identity_demote(&name, json),
    }
}

/// v0.7.0-alpha.20: anonymous identity = sessions root remapped to a
/// per-invocation tmpdir. Operator gets a `WIRE_HOME=...` export they
/// paste into their shell; the identity lives there until reboot
/// clears /tmp. Persist promotes it to the real sessions root.
fn cmd_identity_create(name: Option<&str>, anonymous: bool, as_json: bool) -> Result<()> {
    if anonymous {
        // Generate a unique tmpdir for this anonymous identity.
        let rand_suffix = format!("{:08x}", rand::random::<u32>());
        let anon_name = name
            .map(crate::session::sanitize_name)
            .unwrap_or_else(|| format!("anon-{rand_suffix}"));
        let anon_root = std::env::temp_dir().join(format!("wire-anon-{rand_suffix}"));
        std::fs::create_dir_all(&anon_root)
            .with_context(|| format!("creating anon root {anon_root:?}"))?;
        // Run `wire init <name>` with WIRE_HOME = anon_root/sessions/<name>
        let session_home = anon_root.join("sessions").join(&anon_name);
        std::fs::create_dir_all(&session_home)?;
        let status = super::run_wire_with_home(&session_home, &["init", "--offline"])?;
        if !status.success() {
            bail!("anonymous identity init failed: {status}");
        }
        // Register the anonymous name in a SIDE registry so persist
        // can find it later. Stored at <anon_root>/anon-marker.json.
        let marker = anon_root.join("anon-marker.json");
        std::fs::write(
            &marker,
            serde_json::to_vec_pretty(&serde_json::json!({
                "name": anon_name,
                "session_home": session_home.to_string_lossy(),
                "created_at": time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                "kind": "anonymous",
            }))?,
        )?;
        let card = serde_json::from_slice::<Value>(&std::fs::read(
            session_home
                .join("config")
                .join("wire")
                .join("agent-card.json"),
        )?)?;
        let did = card
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "kind": "anonymous",
                    "name": anon_name,
                    "did": did,
                    "session_home": session_home.to_string_lossy(),
                    "anon_root": anon_root.to_string_lossy(),
                }))?
            );
        } else {
            println!("created anonymous identity `{anon_name}` ({did})");
            println!(
                "  session_home: {} (dies on reboot — /tmp)",
                session_home.display()
            );
            println!();
            println!("activate in this shell:");
            println!("  export WIRE_HOME={}", session_home.display());
            println!();
            println!("promote to persistent later with:");
            println!("  wire identity persist {anon_name}");
        }
        return Ok(());
    }
    // --local (or default): delegate to existing session new flow.
    let name_arg = name.map(|s| s.to_string());
    super::session::cmd_session_new(
        name_arg.as_deref(),
        "https://wireup.net",
        false,
        "http://127.0.0.1:8771",
        false,
        None,
        false,
        None,
        true, // no_daemon: identity create just allocates the identity, no daemon
        true, // local_only: explicit lifecycle
        as_json,
    )
}

/// v0.7.0-alpha.20: promote anonymous → local. Moves session dir from
/// tmpdir to the persistent sessions root + registers in the cwd map.
fn cmd_identity_persist(name: &str, as_name: Option<&str>, as_json: bool) -> Result<()> {
    // Find the anon-marker.json by scanning /tmp/wire-anon-*.
    let temp = std::env::temp_dir();
    let mut found: Option<(std::path::PathBuf, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(&temp)?.flatten() {
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.starts_with("wire-anon-"))
            .unwrap_or(false)
        {
            continue;
        }
        let marker = path.join("anon-marker.json");
        if let Ok(bytes) = std::fs::read(&marker)
            && let Ok(json) = serde_json::from_slice::<Value>(&bytes)
            && json.get("name").and_then(Value::as_str) == Some(name)
        {
            let session_home = json
                .get("session_home")
                .and_then(Value::as_str)
                .map(std::path::PathBuf::from)
                .ok_or_else(|| anyhow!("anon-marker {marker:?} missing session_home"))?;
            found = Some((path, session_home));
            break;
        }
    }
    let (anon_root, anon_session_home) = found.ok_or_else(|| {
        anyhow!(
            "no anonymous identity named `{name}` found in /tmp/wire-anon-* — \
             run `wire identity list` to see available identities"
        )
    })?;

    let new_name = as_name.unwrap_or(name);
    let new_session_home = crate::session::session_dir(new_name)?;
    if new_session_home.exists() {
        bail!(
            "target session `{new_name}` already exists at {new_session_home:?} — \
             pick a different name with --as <new-name>"
        );
    }

    // Move the session dir from tmpdir to persistent root.
    if let Some(parent) = new_session_home.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&anon_session_home, &new_session_home)
        .with_context(|| format!("rename {anon_session_home:?} → {new_session_home:?}"))?;

    // Clean up the (now-empty) anon root + marker.
    let _ = std::fs::remove_dir_all(&anon_root);

    // Register cwd → new_name (operator may have cd'd elsewhere; use the
    // session_home's grandparent as the conceptual "cwd" if no other).
    let cwd = std::env::current_dir().unwrap_or_else(|_| new_session_home.clone());
    let cwd_key = crate::session::normalize_cwd_key(&cwd);
    let new_name_for_reg = new_name.to_string();
    if let Err(e) = crate::session::update_registry(|reg| {
        reg.by_cwd.insert(cwd_key, new_name_for_reg);
        Ok(())
    }) {
        eprintln!("wire identity persist: failed to update registry: {e:#}");
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "kind": "persisted",
                "from_name": name,
                "to_name": new_name,
                "session_home": new_session_home.to_string_lossy(),
            }))?
        );
    } else {
        println!("persisted anonymous identity `{name}` → local session `{new_name}`");
        println!(
            "  session_home: {} (survives reboot)",
            new_session_home.display()
        );
        println!("  registered cwd: {}", cwd.display());
    }
    Ok(())
}

/// v0.7.0-alpha.20: demote federation → local. Removes the federation
/// slot binding from relay.json (and the legacy top-level fields). Keeps
/// the keypair + agent-card so re-publish later just calls `wire identity
/// publish` again. local → anonymous is NOT supported; destroy + recreate
/// is the safer path for that step-down.
fn cmd_identity_demote(name: &str, as_json: bool) -> Result<()> {
    let sessions = crate::session::list_sessions()?;
    let session = sessions
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| anyhow!("no session named `{name}` (run `wire identity list`)"))?;
    let relay_state_path = session
        .home_dir
        .join("config")
        .join("wire")
        .join("relay.json");
    if !relay_state_path.exists() {
        bail!("session `{name}` has no relay state — already demoted?");
    }
    let mut state: Value = serde_json::from_slice(&std::fs::read(&relay_state_path)?)?;
    let self_obj = state.get("self").cloned().unwrap_or(Value::Null);
    let had_fed = self_obj
        .get("relay_url")
        .and_then(Value::as_str)
        .map(|u| {
            u.starts_with("https://") || (u.starts_with("http://") && !u.contains("127.0.0.1"))
        })
        .unwrap_or(false);
    if !had_fed {
        if as_json {
            println!(
                "{}",
                serde_json::to_string(
                    &json!({"name": name, "status": "no-op", "reason": "no federation slot"})
                )?
            );
        } else {
            println!("session `{name}` has no federation slot — nothing to demote");
        }
        return Ok(());
    }
    // Strip federation: remove top-level relay_url/slot_id/slot_token,
    // remove federation-scope entries from endpoints[].
    if let Some(self_mut) = state
        .as_object_mut()
        .and_then(|m| m.get_mut("self"))
        .and_then(|s| s.as_object_mut())
    {
        self_mut.remove("relay_url");
        self_mut.remove("slot_id");
        self_mut.remove("slot_token");
        if let Some(eps) = self_mut.get_mut("endpoints").and_then(|e| e.as_array_mut()) {
            eps.retain(|ep| ep.get("scope").and_then(Value::as_str) != Some("federation"));
        }
    }
    std::fs::write(&relay_state_path, serde_json::to_vec_pretty(&state)?)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(
                &json!({"name": name, "status": "demoted", "from": "federation", "to": "local"})
            )?
        );
    } else {
        println!("demoted `{name}` from federation → local");
        println!("  relay slot binding removed; keypair + agent-card retained");
        println!("  re-publish with `wire identity publish <nick>`");
    }
    Ok(())
}

pub(crate) fn cmd_claim(
    nick: &str,
    relay_override: Option<&str>,
    public_url: Option<&str>,
    hidden: bool,
    as_json: bool,
) -> Result<()> {
    // `wire claim` is the one-step bootstrap: auto-init + auto-allocate slot
    // + claim handle. Operator should never have to run init/bind-relay first.
    let (_did, relay_url, slot_id, slot_token) =
        crate::pair_invite::ensure_self_with_relay(relay_override)?;
    let card = config::read_agent_card()?;

    // v0.13.1 one-name enforcement: the handle you claim in the phonebook
    // MUST equal your DID-derived persona, so the directory entry can never
    // drift from your agent-card handle. A typed nick that differs is ignored
    // (mirrors how `wire init` coerces the typed name). This closes the
    // claim-path reopening of the v0.11 "two names" footgun — before this,
    // `wire claim coffee-ghost` published coffee-ghost@relay -> your DID while
    // your card said e.g. outback-sandpiper. The typed `nick` arg is now
    // vestigial, exactly like the one `wire init` / `wire up` already accept.
    let did = card.get("did").and_then(Value::as_str).unwrap_or_default();
    let canonical = crate::agent_card::display_handle_from_did(did).to_string();
    if !canonical.is_empty() && nick != canonical && !as_json {
        eprintln!(
            "wire claim: typed `{nick}` ignored — one-name rule. Claiming your persona `{canonical}`."
        );
    }
    let nick = if canonical.is_empty() {
        nick
    } else {
        canonical.as_str()
    };
    if !crate::pair_profile::is_valid_nick(nick) {
        bail!(
            "phyllis: {nick:?} won't fit in the books — handles need 2-32 chars, lowercase [a-z0-9_-], not on the reserved list"
        );
    }

    let client = crate::relay_client::RelayClient::new(&relay_url);
    // v0.5.19 (#9.1): forward the `discoverable` flag. None for default
    // (back-compat); Some(false) for `--hidden`. Relays older than
    // v0.5.19 ignore the field, so this is safe to always send.
    let discoverable = if hidden { Some(false) } else { None };
    let resp =
        client.handle_claim_v2(nick, &slot_id, &slot_token, public_url, &card, discoverable)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "nick": nick,
                "relay": relay_url,
                "response": resp,
            }))?
        );
    } else {
        // Best-effort: derive the public domain from the relay URL. If
        // operator passed --public-url that's the canonical address; else
        // the relay URL itself. Falls back to a placeholder if both miss.
        let domain = public_url
            .unwrap_or(&relay_url)
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .split('/')
            .next()
            .unwrap_or("<this-relay-domain>")
            .to_string();
        println!("claimed {nick} on {relay_url} — others can reach you at: {nick}@{domain}");
        println!("verify with: wire whois {nick}@{domain}");
    }
    Ok(())
}

/// `wire unclaim` (#247.1) — release your persona from a relay's handle
/// directory. Owner-gated by your slot token. Frees the nick so it stops
/// resolving and can be re-claimed (a claim is FCFS-permanent otherwise).
pub(crate) fn cmd_unclaim(relay_override: Option<&str>, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — nothing to unclaim (run `wire up` first)");
    }
    // Our self slot on the target relay holds the claim; we present its token.
    let (did, relay_url, _slot_id, slot_token) =
        crate::pair_invite::ensure_self_with_relay(relay_override)?;
    let handle = crate::agent_card::display_handle_from_did(&did).to_string();
    let client = crate::relay_client::RelayClient::new(&relay_url);
    let resp = client.handle_unclaim(&handle, &slot_token)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "nick": handle,
                "relay": relay_url,
                "response": resp,
            }))?
        );
    } else {
        let domain = relay_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        println!("unclaimed {handle} on {relay_url} — {handle}@{domain} no longer resolves");
    }
    Ok(())
}

pub(super) fn cmd_profile(action: super::ProfileAction) -> Result<()> {
    match action {
        super::ProfileAction::Set { field, value, json } => {
            // Try parsing the value as JSON; if that fails, treat it as a
            // bare string. Lets operators pass either `42` or `"hello"` or
            // `["rust","late-night"]` without quoting hell.
            let parsed: Value =
                serde_json::from_str(&value).unwrap_or(Value::String(value.clone()));
            let new_profile = crate::pair_profile::write_profile_field(&field, parsed)?;
            let published = republish_card_to_phonebook();
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "field": field,
                        "profile": new_profile,
                        "published_to": published,
                    }))?
                );
            } else {
                println!("profile.{field} set");
                print_profile_publish_result(&published);
            }
        }
        super::ProfileAction::Get { json } => return super::pairing::cmd_whois(None, json, None),
        super::ProfileAction::Clear { field, json } => {
            let new_profile = crate::pair_profile::write_profile_field(&field, Value::Null)?;
            let published = republish_card_to_phonebook();
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "field": field,
                        "cleared": true,
                        "profile": new_profile,
                        "published_to": published,
                    }))?
                );
            } else {
                println!("profile.{field} cleared");
                print_profile_publish_result(&published);
            }
        }
    }
    Ok(())
}

/// Best-effort: re-publish the (freshly re-signed) agent-card to every relay
/// this identity already holds a federation slot on, so a `wire profile`
/// edit reaches the public phonebook immediately instead of waiting for the
/// next `wire up`. Silent no-op when the identity holds no federation slot
/// (offline / local-only). `discoverable: None` makes the relay PRESERVE the
/// prior setting, so a `--hidden` agent stays hidden across the re-claim.
/// Returns the relay URLs the card was published to.
fn republish_card_to_phonebook() -> Vec<String> {
    let Ok(card) = config::read_agent_card() else {
        return Vec::new();
    };
    let did = card.get("did").and_then(Value::as_str).unwrap_or_default();
    let persona = crate::agent_card::display_handle_from_did(did).to_string();
    if persona.is_empty() {
        return Vec::new();
    }
    let Ok(state) = config::read_relay_state() else {
        return Vec::new();
    };
    let mut published = Vec::new();
    for ep in crate::endpoints::self_endpoints(&state) {
        if ep.scope != crate::endpoints::EndpointScope::Federation
            || ep.slot_id.is_empty()
            || ep.slot_token.is_empty()
        {
            continue;
        }
        let client = crate::relay_client::RelayClient::new(&ep.relay_url);
        if client
            .handle_claim_v2(&persona, &ep.slot_id, &ep.slot_token, None, &card, None)
            .is_ok()
        {
            published.push(ep.relay_url.clone());
        }
    }
    published
}

/// `wire project [<tag>] [--clear]` — show, set, or clear this session's
/// project routing tag (RFC-001 §6).
///
/// The tag is **unsigned** metadata on your agent-card. A peer who pins your
/// card uses it to target `wire send-project <tag>` fan-outs at you. Because
/// peers route off the copy they pinned, set the tag BEFORE pairing (or re-pair
/// after changing it) for the change to reach them — setting it here re-signs
/// the card and best-effort republishes to the phonebook so a re-pull picks it
/// up. The tag never grants trust; the tier floor (>= ORG_VERIFIED) is the gate.
pub(super) fn cmd_project(tag: Option<&str>, clear: bool, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    let mut card = config::read_agent_card()?;

    // Show mode: neither a tag nor --clear given.
    if tag.is_none() && !clear {
        let current = crate::agent_card::card_project(&card);
        if as_json {
            println!("{}", serde_json::to_string(&json!({ "project": current }))?);
        } else {
            match current {
                Some(p) => println!("project = {p}"),
                None => println!("no project tag set. `wire project <tag>` to set one."),
            }
        }
        return Ok(());
    }

    // Mutate: strip the stale self-signature, apply the change, re-sign.
    if let Some(obj) = card.as_object_mut() {
        obj.remove("signature");
        if clear {
            obj.remove("project");
        } else if let Some(t) = tag {
            obj.insert("project".into(), json!(t));
        }
    }
    let sk = config::read_private_key().context("no session key on disk — re-run `wire init`")?;
    let signed = sign_agent_card(&card, &sk);
    config::write_agent_card(&signed)?;
    let published = republish_card_to_phonebook();

    let now = crate::agent_card::card_project(&signed).map(str::to_string);
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "project": now,
                "cleared": clear,
                "published_to": published,
            }))?
        );
    } else {
        match &now {
            Some(p) => println!("→ project set to {p}"),
            None => println!("→ project tag cleared"),
        }
        print_profile_publish_result(&published);
    }
    Ok(())
}

// ---------- org (RFC-001 §2 DNS-TXT trust floor) ----------

/// Dispatch `wire org bind|list|forget`.
pub(crate) fn cmd_org(cmd: super::OrgCommand) -> Result<()> {
    match cmd {
        super::OrgCommand::Bind { domain, mode, json } => cmd_org_bind(&domain, &mode, json),
        super::OrgCommand::List { json } => cmd_org_list(json),
        super::OrgCommand::Forget { org_did, json } => cmd_org_forget(&org_did, json),
    }
}

fn parse_inbound_mode(s: &str) -> Result<crate::pair_decision::InboundMode> {
    use crate::pair_decision::InboundMode;
    match s {
        "auto" => Ok(InboundMode::Auto),
        "notify" => Ok(InboundMode::Notify),
        other => bail!("unknown inbound mode `{other}` — use `notify` (default) or `auto`"),
    }
}

fn mode_label(m: crate::pair_decision::InboundMode) -> &'static str {
    match m {
        crate::pair_decision::InboundMode::Auto => "auto",
        crate::pair_decision::InboundMode::Notify => "notify",
    }
}

fn cmd_org_bind(domain: &str, mode_str: &str, as_json: bool) -> Result<()> {
    let mode = parse_inbound_mode(mode_str)?;
    let resolver = crate::org_bind::DohResolver::new();
    let (org_did, record) = crate::org_bind::bind_org(&resolver, domain, mode)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "domain": domain,
                "org_did": org_did,
                "mode": mode_label(mode),
                "relay": record.relay,
                "sso_iss": record.sso_iss,
            }))?
        );
    } else {
        println!(
            "→ bound {domain} → {org_did} (inbound={})",
            mode_label(mode)
        );
        if let Some(relay) = &record.relay {
            println!("  org relay: {relay}");
        }
        println!(
            "  members presenting a verified member_cert for this org now reach ORG_VERIFIED."
        );
    }
    Ok(())
}

fn cmd_org_list(as_json: bool) -> Result<()> {
    let pol = crate::org_policy::FileOrgPolicy::load();
    let mut rows: Vec<(String, &'static str)> = pol
        .entries()
        .map(|(did, m)| (did.clone(), mode_label(*m)))
        .collect();
    rows.sort();

    if as_json {
        let arr: Vec<Value> = rows
            .iter()
            .map(|(did, m)| json!({ "org_did": did, "mode": m }))
            .collect();
        println!("{}", serde_json::to_string(&json!({ "orgs": arr }))?);
    } else if rows.is_empty() {
        println!("no organizations trusted. `wire org bind <domain>` adds one.");
    } else {
        println!("trusted organizations ({}):", rows.len());
        for (did, m) in &rows {
            println!("  {did}  (inbound={m})");
        }
    }
    Ok(())
}

fn cmd_org_forget(org_did: &str, as_json: bool) -> Result<()> {
    use crate::pair_decision::OrgPolicy;
    let mut pol = crate::org_policy::FileOrgPolicy::load();
    let existed = pol.inbound_mode(org_did).is_some();
    pol.remove(org_did);
    pol.save()?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({ "org_did": org_did, "forgotten": existed }))?
        );
    } else if existed {
        println!("→ forgot {org_did} — its members no longer reach ORG_VERIFIED via org policy.");
    } else {
        println!("{org_did} was not trusted — nothing to forget.");
    }
    Ok(())
}

fn print_profile_publish_result(published: &[String]) {
    if published.is_empty() {
        println!(
            "  (local only — not bound to a federation relay; run `wire up` to publish to the phonebook)"
        );
    } else {
        println!("  published to phonebook: {}", published.join(", "));
    }
}

// v0.14: tests for op-claims surfacing on operator read verbs.
// Pure-over-Value helper; no I/O, no filesystem fixtures needed.
#[cfg(test)]
mod op_claims_surfacing_tests {
    use super::*;

    #[test]
    fn op_claims_extracts_present_non_null_fields() {
        let card = json!({
            "did": "did:wire:foo-deadbeef",
            "handle": "foo",
            "op_did": "did:wire:op:foo-aaaa",
            "op_pubkey": "PKB64==",
            "op_cert": "SIGB64==",
            "org_memberships": [{"org_did": "did:wire:org:slancha-bbbb"}],
            "schema_version": "v3.2",
        });
        let claims = op_claims_from_card(&card);
        assert_eq!(claims.len(), 5);
        assert_eq!(
            claims.get("op_did").and_then(Value::as_str),
            Some("did:wire:op:foo-aaaa")
        );
        assert!(
            claims
                .get("org_memberships")
                .and_then(Value::as_array)
                .is_some()
        );
    }

    #[test]
    fn op_claims_empty_on_pre_v014_card() {
        // A pre-v0.14 card has none of the inline op_* fields. The
        // helper must return an EMPTY map so older peers surface
        // identically on every read verb (no `null`-spam in JSON,
        // no new lines in human output).
        let card = json!({
            "did": "did:wire:bar-cafebabe",
            "handle": "bar",
            "capabilities": ["wire/v3.1"],
        });
        assert!(op_claims_from_card(&card).is_empty());
    }

    #[test]
    fn op_claims_skips_explicit_null_fields() {
        // Defensive: a card where republish has serialized op_did as
        // `null` (e.g., post-unenroll rebuild) must not surface a
        // `null` field — operators read absence to mean "not enrolled".
        let card = json!({
            "did": "did:wire:baz-12341234",
            "op_did": Value::Null,
            "org_memberships": Value::Null,
            "schema_version": "v3.2",
        });
        let claims = op_claims_from_card(&card);
        assert_eq!(claims.len(), 1);
        assert!(claims.get("op_did").is_none());
        assert!(claims.get("org_memberships").is_none());
        assert_eq!(
            claims.get("schema_version").and_then(Value::as_str),
            Some("v3.2")
        );
    }
}

#[cfg(test)]
mod enroll_add_membership_tests {
    use super::*;
    use crate::enroll::issue_member_cert;
    use crate::signing::{b64encode, generate_keypair};

    fn seed_op() -> ([u8; 32], [u8; 32], String) {
        let (sk, pk) = generate_keypair();
        crate::config::write_op_key(&sk).unwrap();
        crate::config::write_op_handle("opfoo").unwrap();
        let op_did = crate::agent_card::did_for_op("opfoo", &pk);
        (sk, pk, op_did)
    }

    #[test]
    fn add_membership_happy_path_stores_and_is_idempotent() {
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let (_op_sk, _op_pk, op_did) = seed_op();
            let (org_sk, org_pk) = generate_keypair();
            let org_did = crate::agent_card::did_for_org("acme", &org_pk);
            let cert = issue_member_cert(&org_sk, &op_did).unwrap();
            let bundle = json!({
                "org_did": org_did,
                "org_pubkey": b64encode(&org_pk),
                "member_cert": cert,
            })
            .to_string();
            cmd_enroll_add_membership(Some(bundle.clone()), None, None, None, true).unwrap();
            let stored = config::read_memberships().unwrap();
            assert_eq!(stored.len(), 1);
            assert_eq!(
                stored[0].get("org_did").and_then(Value::as_str),
                Some(org_did.as_str())
            );
            // Idempotent: re-running with the same org_did replaces, not duplicates.
            cmd_enroll_add_membership(Some(bundle), None, None, None, true).unwrap();
            assert_eq!(config::read_memberships().unwrap().len(), 1);
        });
    }

    #[test]
    fn add_membership_rejects_cert_for_wrong_op_did() {
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let (_op_sk, _op_pk, _op_did) = seed_op();
            let (org_sk, org_pk) = generate_keypair();
            let org_did = crate::agent_card::did_for_org("acme", &org_pk);
            // Cert signed for a DIFFERENT op_did. Verify must refuse.
            let other_did = "did:wire:op:ghost-deadbeefdeadbeefdeadbeefdeadbeef";
            let cert = issue_member_cert(&org_sk, other_did).unwrap();
            let bundle = json!({
                "org_did": org_did,
                "org_pubkey": b64encode(&org_pk),
                "member_cert": cert,
            })
            .to_string();
            let err = cmd_enroll_add_membership(Some(bundle), None, None, None, true).unwrap_err();
            assert!(
                err.to_string().contains("verification failed"),
                "got: {err:#}"
            );
            // And nothing landed on disk.
            assert!(config::read_memberships().unwrap().is_empty());
        });
    }

    #[test]
    fn add_membership_rejects_when_not_enrolled() {
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            // No op key written → we don't know our own op_did → refuse.
            let (org_sk, org_pk) = generate_keypair();
            let org_did = crate::agent_card::did_for_org("acme", &org_pk);
            let cert = issue_member_cert(&org_sk, "did:wire:op:anybody-aaaa").unwrap();
            let bundle = json!({
                "org_did": org_did,
                "org_pubkey": b64encode(&org_pk),
                "member_cert": cert,
            })
            .to_string();
            let err = cmd_enroll_add_membership(Some(bundle), None, None, None, true).unwrap_err();
            assert!(err.to_string().contains("not enrolled"), "got: {err:#}");
        });
    }

    #[test]
    fn add_membership_rejects_malformed_org_did() {
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let _ = seed_op();
            let bundle = json!({
                "org_did": "did:wire:not-an-org",
                "org_pubkey": "AAAA",
                "member_cert": "AAAA",
            })
            .to_string();
            let err = cmd_enroll_add_membership(Some(bundle), None, None, None, true).unwrap_err();
            assert!(
                err.to_string().contains("not a valid organization DID"),
                "got: {err:#}"
            );
        });
    }
}
