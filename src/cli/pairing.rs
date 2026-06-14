use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::config;

// ---------- dial / whois (v0.8 canonical addressing) ----------

/// `wire dial <name> [message]` — the one verb operators reach for.
/// Resolves any name (nickname/handle/session/DID) to a peer and
/// drives the right pair flow + optional first message. See the
/// `Command::Dial` doc for the resolution ladder.
///
/// v0.9: when `name` contains `@<relay>`, route through the federation
/// `wire add <handle>@<relay>` path (`.well-known/wire/agent` resolution
/// plus cross-machine pair_drop). No more bail with "federation isn't
/// implemented yet" — one verb across both orbits.
pub(super) fn cmd_dial(name: &str, message: Option<&str>, as_json: bool) -> Result<()> {
    if name.contains('@') {
        // Federation path. cmd_add already auto-detects (per v0.7.4)
        // when input has `@` and routes through the .well-known
        // resolver + pair_drop deposit. After it returns, the peer
        // is in pending-outbound; bilateral completes when the peer
        // accepts. Optionally send the first message after the add.
        cmd_add(name, None, false, true)
            .map_err(|e| anyhow!("wire dial: federation pair to `{name}` failed: {e:#}"))?;
        if let Some(msg) = message {
            // Peer handle for send = the nick part before the `@`.
            let bare = name.split('@').next().unwrap_or(name);
            super::comms::cmd_send(bare, "claim", msg, None, false, false, as_json)?;
        }
        return Ok(());
    }

    // v0.9.2 helpful-miss: in JSON mode, a resolution miss returns
    // success with `{found: false, candidates: [...]}` instead of
    // erroring. Agents can branch on `found` without wrapping in a
    // try/catch.
    let resolution = match resolve_name_to_target(name) {
        Ok(r) => r,
        Err(e) if as_json => {
            let pool = super::known_local_names();
            let suggestions = super::closest_candidates(name, &pool, 3, 3);
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "name_input": name,
                    "found": false,
                    "candidates": suggestions,
                    "error": format!("{e:#}"),
                }))?
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut steps: Vec<Value> = Vec::new();

    match &resolution {
        DialTarget::PinnedPeer { handle, .. } => {
            steps.push(json!({
                "step": "resolved",
                "kind": "already_pinned",
                "handle": handle,
            }));
        }
        DialTarget::LocalSister { session_name, .. } => {
            steps.push(json!({
                "step": "resolved",
                "kind": "local_sister",
                "session": session_name,
            }));
            // Drive the bilateral pair via the disk-read sister path.
            // cmd_add_local_sister already handles "already paired"
            // gracefully (its internal state.peers check returns the
            // existing pin instead of re-issuing a pair_drop), so
            // re-dialling is idempotent.
            cmd_add_local_sister(session_name, true).map_err(|e| {
                anyhow!("dial: local-sister pair to `{session_name}` failed: {e:#}")
            })?;
            steps.push(json!({
                "step": "paired",
                "via": "local_sister",
            }));
        }
    }

    let send_handle = match &resolution {
        DialTarget::PinnedPeer { handle, .. } => handle.clone(),
        DialTarget::LocalSister { handle, .. } => handle.clone(),
    };

    let send_result = if let Some(msg) = message {
        let r = super::comms::cmd_send(&send_handle, "claim", msg, None, false, false, true);
        match &r {
            Ok(()) => steps.push(json!({"step": "sent", "to": send_handle, "kind": "claim"})),
            Err(e) => steps.push(json!({"step": "send_failed", "error": format!("{e:#}")})),
        }
        Some(r)
    } else {
        None
    };

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "name_input": name,
                "resolved_handle": send_handle,
                "steps": steps,
            }))?
        );
    } else {
        println!("wire dial: resolved `{name}` → handle `{send_handle}`");
        for s in &steps {
            let step = s.get("step").and_then(Value::as_str).unwrap_or("?");
            println!("  - {step}");
        }
        if message.is_some() {
            println!("  (use `wire tail {send_handle}` to read replies)");
        }
    }
    if let Some(Err(e)) = send_result {
        return Err(e);
    }
    Ok(())
}

/// `wire whois <name>` — resolve any local name (nickname/session/
/// handle/DID) to the full identity row. The inspector for the
/// canonical addressing layer. For federation `handle@relay-domain`
/// resolution see `cmd_whois` (line 5536+) — the dispatcher chooses
/// based on whether the input contains `@`.
pub(super) fn cmd_whois_local(name: &str, as_json: bool) -> Result<()> {
    // v0.9.2 helpful-miss: in JSON mode, a resolution miss returns
    // success (exit 0) with `{found: false, candidates: [...]}` so
    // agents don't need try/catch around `wire whois <name>`. In
    // human mode, the bail's did-you-mean line points at the
    // closest candidate.
    let resolution = match resolve_name_to_target(name) {
        Ok(r) => r,
        Err(e) if as_json => {
            let pool = super::known_local_names();
            let suggestions = super::closest_candidates(name, &pool, 3, 3);
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "name_input": name,
                    "found": false,
                    "candidates": suggestions,
                    "error": format!("{e:#}"),
                }))?
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    match resolution {
        DialTarget::PinnedPeer {
            handle,
            did,
            nickname,
            emoji,
            tier,
        } => {
            // v0.14: re-read trust to pull the pinned peer's card for op
            // claims surfacing. Pinned ⇒ card lives in trust.json (no
            // network round-trip). Older peers ⇒ no op_* fields ⇒ empty.
            let op_claims = config::read_trust()
                .ok()
                .and_then(|t| {
                    t.get("agents")
                        .and_then(Value::as_object)
                        .and_then(|m| m.get(&handle))
                        .and_then(|a| a.get("card").cloned())
                })
                .map(|c| super::op_claims_from_card(&c))
                .unwrap_or_default();

            if as_json {
                let mut payload = serde_json::Map::new();
                payload.insert("kind".into(), json!("pinned_peer"));
                payload.insert("handle".into(), json!(handle));
                payload.insert("did".into(), json!(did));
                payload.insert("nickname".into(), json!(nickname));
                payload.insert("emoji".into(), json!(emoji));
                payload.insert("tier".into(), json!(tier));
                for (k, v) in &op_claims {
                    payload.insert(k.clone(), v.clone());
                }
                println!("{}", serde_json::to_string(&payload)?);
            } else {
                let n = nickname.as_deref().unwrap_or("(no character)");
                let e = emoji.as_deref().unwrap_or("?");
                println!("{e} {n}");
                println!("  handle:   {handle}");
                println!("  did:      {did}");
                println!("  tier:     {tier}");
                // v0.14: surface peer's op_did when the pinned card
                // carries one. Silent for pre-v0.14 peers.
                if let Some(op_did) = op_claims.get("op_did").and_then(Value::as_str) {
                    println!("  op_did:   {op_did}");
                }
                println!("  reach:    pinned peer (already in trust ring + slot pinned)");
            }
        }
        DialTarget::LocalSister {
            session_name,
            handle,
            did,
            nickname,
            emoji,
        } => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "kind": "local_sister",
                        "session_name": session_name,
                        "handle": handle,
                        "did": did,
                        "nickname": nickname,
                        "emoji": emoji,
                    }))?
                );
            } else {
                let n = nickname.as_deref().unwrap_or("(no character)");
                let e = emoji.as_deref().unwrap_or("?");
                println!("{e} {n}");
                println!("  session:  {session_name}");
                println!("  handle:   {handle}");
                println!(
                    "  did:      {}",
                    did.as_deref().unwrap_or("(card unreadable)")
                );
                println!("  reach:    local sister on this machine — `wire dial {n}` pairs us");
            }
        }
    }
    Ok(())
}

pub(crate) enum DialTarget {
    PinnedPeer {
        handle: String,
        did: String,
        nickname: Option<String>,
        emoji: Option<String>,
        tier: String,
    },
    LocalSister {
        session_name: String,
        handle: String,
        did: Option<String>,
        nickname: Option<String>,
        emoji: Option<String>,
    },
}

/// Resolution order: pinned peers first (already in our trust ring),
/// then local sister sessions (on-disk discovery). Case-insensitive
/// match against handle, character nickname, session name, or DID.
///
/// `pub(crate)` so the MCP `tool_whois` surface mirrors the CLI's
/// bare-nick resolution (closes the known `missing '@' separator`
/// rejection on bare nicks — agents reading via MCP now resolve
/// pinned peers + local sisters identically to operators reading via
/// CLI).
pub(crate) fn resolve_name_to_target(name: &str) -> Result<DialTarget> {
    let needle = name.trim();
    if needle.is_empty() {
        bail!("empty name");
    }

    // 1. Pinned peers — `wire peers` data. trust.agents is an object
    // keyed by handle (not an array); iterate as a map.
    if config::is_initialized().unwrap_or(false) {
        let trust = config::read_trust().unwrap_or(serde_json::Value::Null);
        if let Some(agents) = trust.get("agents").and_then(Value::as_object) {
            for (handle_key, agent) in agents {
                let did = agent.get("did").and_then(Value::as_str).unwrap_or("");
                if did.is_empty() {
                    continue;
                }
                let handle = handle_key.clone();
                let character = crate::character::Character::from_did(did);
                let tier = agent
                    .get("tier")
                    .and_then(Value::as_str)
                    .unwrap_or("UNKNOWN")
                    .to_string();
                let matches = handle.eq_ignore_ascii_case(needle)
                    || did.eq_ignore_ascii_case(needle)
                    || character.nickname.eq_ignore_ascii_case(needle);
                if matches {
                    return Ok(DialTarget::PinnedPeer {
                        handle,
                        did: did.to_string(),
                        nickname: Some(character.nickname),
                        emoji: Some(character.emoji.to_string()),
                        tier,
                    });
                }
            }
        }
    }

    // 2. Local sister sessions.
    if let Some(session_name) = crate::session::resolve_local_sister(needle) {
        let sessions = crate::session::list_sessions().unwrap_or_default();
        let s = sessions.iter().find(|s| s.name == session_name);
        if let Some(s) = s {
            return Ok(DialTarget::LocalSister {
                session_name: s.name.clone(),
                handle: s.handle.clone().unwrap_or_else(|| s.name.clone()),
                did: s.did.clone(),
                nickname: s.character.as_ref().map(|c| c.nickname.clone()),
                emoji: s.character.as_ref().map(|c| c.emoji.to_string()),
            });
        }
    }

    // v0.9.2: fuzzy did-you-mean suggestion on resolution miss. Walks
    // the union of pinned-peer handles + character nicknames + sister
    // session names + sister character nicknames, returns up to 3 names
    // within Levenshtein distance 3 of the operator's typed name.
    let pool = super::known_local_names();
    let suggestions = super::closest_candidates(name, &pool, 3, 3);
    if suggestions.is_empty() {
        bail!(
            "no peer matched `{name}`.\n\
             Tried: pinned peers (`wire peers`) + local sister sessions \
             (`wire session list-local`).\n\
             For cross-machine federation: `wire dial <handle>@<relay-domain>`."
        );
    }
    bail!(
        "no peer matched `{name}`.\n\
         Did you mean: {}?\n\
         List all: `wire peers`, `wire session list-local`.",
        suggestions
            .iter()
            .map(|s| format!("`{s}`"))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

// ---------- pin (manual out-of-band peer pairing) ----------

pub(super) fn cmd_pin(card_file: &str, as_json: bool) -> Result<()> {
    let body =
        std::fs::read_to_string(card_file).with_context(|| format!("reading {card_file}"))?;
    let card: Value =
        serde_json::from_str(&body).with_context(|| format!("parsing {card_file}"))?;
    crate::agent_card::verify_agent_card(&card)
        .map_err(|e| anyhow!("peer card signature invalid: {e}"))?;

    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &card, Some("VERIFIED"));

    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = crate::agent_card::display_handle_from_did(did).to_string();
    config::write_trust(&trust)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle,
                "did": did,
                "tier": "VERIFIED",
                "pinned": true,
            }))?
        );
    } else {
        println!("pinned {handle} ({did}) at tier VERIFIED");
    }
    Ok(())
}

// ---------- invite / accept — one-paste pair (v0.4.0) ----------

pub(super) fn cmd_invite(
    relay: &str,
    ttl: u64,
    uses: u32,
    share: bool,
    as_json: bool,
) -> Result<()> {
    let url = crate::pair_invite::mint_invite(Some(ttl), uses, Some(relay))?;

    // If --share, register the invite at the relay's short-URL endpoint and
    // build the one-curl onboarding line for the peer to paste.
    let share_payload: Option<Value> = if share {
        let client = reqwest::blocking::Client::new();
        let single_use = if uses == 1 { Some(1u32) } else { None };
        let body = json!({
            "invite_url": url,
            "ttl_seconds": ttl,
            "uses": single_use,
        });
        let endpoint = format!("{}/v1/invite/register", relay.trim_end_matches('/'));
        let resp = client.post(&endpoint).json(&body).send()?;
        if !resp.status().is_success() {
            let code = resp.status();
            let txt = resp.text().unwrap_or_default();
            bail!("relay {code} on /v1/invite/register: {txt}");
        }
        let parsed: Value = resp.json()?;
        let token = parsed
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("relay reply missing token"))?
            .to_string();
        let share_url = format!("{}/i/{}", relay.trim_end_matches('/'), token);
        let curl_line = format!("curl -fsSL {share_url} | sh");
        Some(json!({
            "token": token,
            "share_url": share_url,
            "curl": curl_line,
            "expires_unix": parsed.get("expires_unix"),
        }))
    } else {
        None
    };

    if as_json {
        let mut out = json!({
            "invite_url": url,
            "ttl_secs": ttl,
            "uses": uses,
            "relay": relay,
        });
        if let Some(s) = &share_payload {
            out["share"] = s.clone();
        }
        println!("{}", serde_json::to_string(&out)?);
    } else if let Some(s) = share_payload {
        let curl = s.get("curl").and_then(Value::as_str).unwrap_or("");
        eprintln!("# One-curl onboarding. Share this single line — installs wire if missing,");
        eprintln!("# accepts the invite, pairs both sides. TTL: {ttl}s. Uses: {uses}.");
        println!("{curl}");
    } else {
        eprintln!("# Share this URL with one peer. Pasting it = pair complete on their side.");
        eprintln!("# TTL: {ttl}s. Uses: {uses}.");
        println!("{url}");
    }
    Ok(())
}

pub(super) fn cmd_accept(url: &str, as_json: bool) -> Result<()> {
    // If the user pasted an HTTP(S) short URL (e.g. https://wireup.net/i/AB12),
    // resolve it to the underlying wire://pair?... URL via ?format=url before
    // accepting. Saves them from having to know which URL shape goes where.
    let resolved = if url.starts_with("http://") || url.starts_with("https://") {
        let sep = if url.contains('?') { '&' } else { '?' };
        let resolve_url = format!("{url}{sep}format=url");
        let client = reqwest::blocking::Client::new();
        let resp = client
            .get(&resolve_url)
            .send()
            .with_context(|| format!("GET {resolve_url}"))?;
        if !resp.status().is_success() {
            bail!("could not resolve short URL {url} (HTTP {})", resp.status());
        }
        let body = resp.text().unwrap_or_default().trim().to_string();
        if !body.starts_with("wire://pair?") {
            bail!(
                "short URL {url} did not resolve to a wire:// invite. \
                 (got: {}{})",
                body.chars().take(80).collect::<String>(),
                if body.chars().count() > 80 { "…" } else { "" }
            );
        }
        body
    } else {
        url.to_string()
    };

    let result = crate::pair_invite::accept_invite(&resolved)?;
    if as_json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        let did = result
            .get("paired_with")
            .and_then(Value::as_str)
            .unwrap_or("?");
        println!("paired with {did}");
        println!(
            "you can now: wire send {} <kind> <body>",
            crate::agent_card::display_handle_from_did(did)
        );
    }
    Ok(())
}

// ---------- whois / profile (v0.5) ----------

pub(super) fn cmd_whois(
    handle: Option<&str>,
    as_json: bool,
    relay_override: Option<&str>,
) -> Result<()> {
    if let Some(h) = handle {
        let parsed = crate::pair_profile::parse_handle(h)?;
        // Special-case: if the supplied handle matches our own, skip the
        // network round-trip and print local.
        if config::is_initialized()? {
            let card = config::read_agent_card()?;
            let local_handle = card
                .get("profile")
                .and_then(|p| p.get("handle"))
                .and_then(Value::as_str)
                .map(str::to_string);
            if local_handle.as_deref() == Some(h) {
                return cmd_whois(None, as_json, None);
            }
        }
        // Remote resolution via .well-known/wire/agent on the handle's domain.
        let resolved = crate::pair_profile::resolve_handle(&parsed, relay_override)?;
        if as_json {
            // #247 finding 4: surface the key fingerprint + whether it matches
            // the claimed DID so JSON consumers can gate on poisoned discovery.
            let did = resolved.get("did").and_then(Value::as_str).unwrap_or("");
            let card = resolved.get("card").cloned().unwrap_or(Value::Null);
            let (computed_fp, _did_fp, fp_matches) = resolved_key_fingerprint(&card, did);
            let mut payload = resolved.clone();
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("fingerprint".into(), json!(computed_fp));
                obj.insert("fingerprint_matches_did".into(), json!(fp_matches));
            }
            println!("{}", serde_json::to_string(&payload)?);
        } else {
            print_resolved_profile(&resolved);
        }
        return Ok(());
    }
    let card = config::read_agent_card()?;
    if as_json {
        let profile = card.get("profile").cloned().unwrap_or(Value::Null);
        let mut payload = serde_json::Map::new();
        payload.insert(
            "did".into(),
            card.get("did").cloned().unwrap_or(Value::Null),
        );
        payload.insert("profile".into(), profile);
        // v0.14: surface inline op claims on self-whois too, for parity
        // with `wire whoami --json`. Single mental model across read
        // verbs; absent ⇒ not enrolled.
        for (k, v) in super::op_claims_from_card(&card) {
            payload.insert(k, v);
        }
        println!("{}", serde_json::to_string(&payload)?);
    } else {
        print!("{}", crate::pair_profile::render_self_summary()?);
    }
    Ok(())
}

fn print_resolved_profile(resolved: &Value) {
    let did = resolved.get("did").and_then(Value::as_str).unwrap_or("?");
    let nick = resolved.get("nick").and_then(Value::as_str).unwrap_or("?");
    let relay = resolved
        .get("relay_url")
        .and_then(Value::as_str)
        .unwrap_or("");
    let slot = resolved
        .get("slot_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let profile = resolved
        .get("card")
        .and_then(|c| c.get("profile"))
        .cloned()
        .unwrap_or(Value::Null);
    println!("{did}");
    println!("  nick:         {nick}");
    // #247 finding 4: surface the key fingerprint + flag a card whose key
    // doesn't match its claimed DID, and remind the operator that relay
    // discovery is trusted for ROUTING, not identity — verify out-of-band.
    let card = resolved.get("card").cloned().unwrap_or(Value::Null);
    let (computed_fp, _did_fp, fp_matches) = resolved_key_fingerprint(&card, did);
    if let Some(fp) = &computed_fp {
        if fp_matches {
            println!("  fingerprint:  {fp}  (matches DID)");
        } else {
            println!(
                "  fingerprint:  {fp}  ⚠ DOES NOT MATCH the DID's fingerprint — the relay served a card whose key ≠ its claimed identity. Do NOT pair; verify out-of-band."
            );
        }
    }
    if !relay.is_empty() {
        println!("  relay_url:    {relay}");
    }
    if !slot.is_empty() {
        println!("  slot_id:      {slot}");
    }
    let pick =
        |k: &str| -> Option<String> { profile.get(k).and_then(Value::as_str).map(str::to_string) };
    if let Some(s) = pick("display_name") {
        println!("  display_name: {s}");
    }
    if let Some(s) = pick("emoji") {
        println!("  emoji:        {s}");
    }
    if let Some(s) = pick("motto") {
        println!("  motto:        {s}");
    }
    if let Some(arr) = profile.get("vibe").and_then(Value::as_array) {
        let joined: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        println!("  vibe:         {}", joined.join(", "));
    }
    if let Some(s) = pick("pronouns") {
        println!("  pronouns:     {s}");
    }
    // #247 finding 4: discovery is relay-mediated; the operator should confirm
    // the DID + fingerprint with the peer over a second channel before relying
    // on a first-contact pair.
    println!(
        "  ⓘ resolved via relay discovery (trusted for routing, not identity) — verify this DID + fingerprint out-of-band before relying on the pair."
    );
}

/// Fingerprint check for a resolved peer card (#247 finding 4 — relay-served
/// discovery is trusted-for-routing, not trusted-for-identity).
///
/// Returns `(computed_fp, did_fp, matches)`: `computed_fp` is the fingerprint
/// of the card's advertised ed25519 verify key; `did_fp` is the fingerprint
/// baked into the `did:wire:<handle>-<fp>` the card claims. They MUST be equal —
/// a mismatch means the relay served a card whose key does not match its own
/// DID (a poisoned-discovery red flag). `matches` is false when the card has no
/// usable key or `did_fp` is empty. Pure → unit-tested.
fn resolved_key_fingerprint(card: &Value, did: &str) -> (Option<String>, String, bool) {
    let did_fp = did.rsplit('-').next().unwrap_or("").to_string();
    let computed = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .and_then(|k| crate::signing::b64decode(k).ok())
        .map(|pk| crate::signing::fingerprint(&pk));
    let matches = !did_fp.is_empty() && computed.as_deref() == Some(did_fp.as_str());
    (computed, did_fp, matches)
}

// `wire add <nick@domain>` section header. See cmd_add below.

/// v0.5.19 (#9.4): is this relay domain on the known-good list, or the
/// operator's own relay? Used to suppress the cross-relay phishing
/// warning in `wire add` for the happy path.
fn is_known_relay_domain(peer_domain: &str, our_relay_url: &str) -> bool {
    // Hard-coded known-good list. wireup.net is the default relay.
    const KNOWN_GOOD: &[&str] = &["wireup.net", "wire.laulpogan.com"];
    let peer_domain = peer_domain.trim().to_ascii_lowercase();
    if KNOWN_GOOD.iter().any(|k| *k == peer_domain) {
        return true;
    }
    // Operator's OWN relay is implicitly trusted — they're already
    // bound to it; pairing same-relay peers is the common case.
    let our_host = super::host_of_url(our_relay_url).to_ascii_lowercase();
    if !our_host.is_empty() && our_host == peer_domain {
        return true;
    }
    false
}

/// v0.6.6: pair with a sister session on this machine without federation.
/// Reads the sister's agent-card + endpoints from disk, pins them into our
/// trust + relay_state, builds the same `pair_drop` event the federation
/// path would emit, then POSTs it directly to the sister's local-relay slot.
/// No `.well-known/wire/agent` resolution. Reserved-nick sessions (like
/// the cwd-derived `wire`) are addressable because the local relay never
/// needed a public claim for sister coordination.
/// v0.7.0-alpha.2/3: resolve an input (session name or character nickname)
/// to a local sister session.
///
/// `wire add --local-sister <name-or-nickname>` and adjacent commands take
/// either form. Exact session-name matches always win; nickname matches
/// are a fallback so operators can type "winter-bay" instead of "wire".
/// When a nickname is ambiguous (two sessions share it, e.g. auto-derived
/// for one + override on another), returns `Err(ResolveError::Ambiguous)`
/// with the candidate list so the caller can surface a disambiguation
/// hint instead of silently picking one.
fn resolve_local_session<'a>(
    sessions: &'a [crate::session::SessionInfo],
    input: &str,
) -> Result<&'a crate::session::SessionInfo, ResolveError> {
    // Exact session-name match always wins, even if a nickname elsewhere
    // also matches. Predictable for scripts and operator muscle memory.
    if let Some(s) = sessions.iter().find(|s| s.name == input) {
        return Ok(s);
    }
    let nick_matches: Vec<&crate::session::SessionInfo> = sessions
        .iter()
        .filter(|s| {
            s.character
                .as_ref()
                .map(|c| c.nickname == input)
                .unwrap_or(false)
        })
        .collect();
    match nick_matches.len() {
        0 => Err(ResolveError::NotFound),
        1 => Ok(nick_matches[0]),
        _ => Err(ResolveError::Ambiguous(
            nick_matches.iter().map(|s| s.name.clone()).collect(),
        )),
    }
}

#[derive(Debug)]
pub(crate) enum ResolveError {
    NotFound,
    Ambiguous(Vec<String>),
}

/// v0.7.0-alpha.2/.5: resolve a peer input (handle or character nickname)
/// to a pinned peer's canonical handle.
///
/// `wire send <peer>` accepts either the handle the peer registered with
/// or their character nickname (DID-hash-derived). Exact handle match
/// always wins. When a nickname matches multiple peers (theoretically
/// possible via DID-hash collision in the (adj, noun) space), returns
/// `Ambiguous` so the caller can surface a disambiguation hint instead
/// of silently picking one.
///
/// Only AUTO-DERIVED peer characters are matchable; operator-chosen
/// overrides on the peer's side live in their local `display.json` and
/// aren't yet published via agent-card. (That's the v0.7+ federation
/// lifecycle work — peers publishing overrides so we resolve by what
/// they call themselves, not just what their DID hashes to.)
pub(crate) fn resolve_peer_handle(input: &str) -> Result<Option<String>, ResolveError> {
    let trust = match config::read_trust() {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let agents = match trust.get("agents").and_then(|a| a.as_object()) {
        Some(a) => a,
        None => return Ok(None),
    };
    if agents.contains_key(input) {
        return Ok(Some(input.to_string()));
    }
    let mut nick_matches: Vec<String> = Vec::new();
    for (handle, agent) in agents.iter() {
        // v0.7.0-alpha.6: prefer peer's published display nickname over
        // auto-derived. Allows `wire send <their-chosen-name>` not just
        // `wire send <their-did-hash-derived-name>`.
        let character = match agent.get("card") {
            Some(card) => crate::character::Character::from_card(card),
            None => match agent.get("did").and_then(Value::as_str) {
                Some(did) => crate::character::Character::from_did(did),
                None => continue,
            },
        };
        if character.nickname == input {
            nick_matches.push(handle.clone());
        }
    }
    match nick_matches.len() {
        0 => Ok(None),
        1 => Ok(Some(nick_matches.into_iter().next().unwrap())),
        _ => Err(ResolveError::Ambiguous(nick_matches)),
    }
}

/// Outcome of a local-sister pair_drop — the fields both the CLI renderer and
/// the MCP `wire_dial` surface need.
pub(crate) struct LocalSisterDrop {
    /// Session we actually resolved to (may differ from input if matched by
    /// nickname). The CLI prints a "resolved nickname → session" note when it
    /// differs from the operator's typed name.
    pub resolved_session: String,
    pub paired_with_did: String,
    pub peer_handle: String,
    pub event_id: String,
    pub delivered_via: String,
    pub delivery_relay_url: String,
}

/// Core of the local-sister pair: resolve the sister, pin them VERIFIED,
/// deliver a signed pair_drop to their local slot, and return the outcome.
/// No stdout — `cmd_add_local_sister` renders for the CLI, `tool_dial` returns
/// JSON for MCP (where stdout is the JSON-RPC channel, so a stray println
/// corrupts the protocol). This is what lets an MCP agent dial a bare
/// nickname / local sister instead of hitting the old circular dead-end.
pub(crate) fn add_local_sister_core(sister_name: &str) -> Result<LocalSisterDrop> {
    // 1. Locate sister session by name OR character nickname.
    let sessions = crate::session::list_sessions()?;
    let sister = match resolve_local_session(&sessions, sister_name) {
        Ok(s) => s,
        Err(ResolveError::NotFound) => bail!(
            "no sister session named `{sister_name}` (matched by session name or character nickname). \
             Run `wire session list` to see what's available."
        ),
        Err(ResolveError::Ambiguous(candidates)) => bail!(
            "nickname `{sister_name}` is ambiguous — matches {} sessions: {}. \
             Disambiguate by passing the session name (one of those listed) instead of the nickname.",
            candidates.len(),
            candidates.join(", ")
        ),
    };

    // 2. Refuse self-pair — operator owns both sides, but a self-loop
    // breaks the bilateral state machine.
    let our_card =
        config::read_agent_card().map_err(|_| anyhow!("not initialized — run `wire up` first"))?;
    let our_did = our_card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing did"))?
        .to_string();
    if let Some(sister_did) = sister.did.as_deref()
        && sister_did == our_did
    {
        bail!("refusing to add self (`{sister_name}` is this very session)");
    }

    // 3. Read sister's agent-card + relay state from disk.
    let sister_card_path = sister
        .home_dir
        .join("config")
        .join("wire")
        .join("agent-card.json");
    let sister_card: Value = serde_json::from_slice(
        &std::fs::read(&sister_card_path)
            .with_context(|| format!("reading sister card {sister_card_path:?}"))?,
    )
    .with_context(|| format!("parsing sister card {sister_card_path:?}"))?;
    let sister_relay_state: Value = std::fs::read(
        sister
            .home_dir
            .join("config")
            .join("wire")
            .join("relay.json"),
    )
    .ok()
    .and_then(|b| serde_json::from_slice(&b).ok())
    .unwrap_or_else(|| json!({"self": Value::Null, "peers": {}}));

    let sister_did = sister_card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("sister card missing did"))?
        .to_string();
    let sister_handle = crate::agent_card::display_handle_from_did(&sister_did).to_string();

    // Pull sister's full endpoint set; we want the local one for delivery
    // and we'll pin all of them so OUR pushes prefer local-first per the
    // existing routing logic.
    let sister_endpoints = crate::endpoints::self_endpoints(&sister_relay_state);
    if sister_endpoints.is_empty() {
        bail!(
            "sister `{sister_name}` has no endpoints in its relay.json — recreate with `wire session new --local-only` or `--with-local`"
        );
    }
    let sister_local = sister_endpoints
        .iter()
        .find(|e| e.scope == crate::endpoints::EndpointScope::Local);
    let delivery_endpoint = match sister_local {
        Some(e) => e.clone(),
        None => sister_endpoints[0].clone(),
    };

    // 4. Ensure WE have a slot to advertise back. For local-only sessions
    // this is the local slot; for dual-slot sessions, federation is fine.
    // `ensure_self_with_relay(None)` defaults to wireup.net which is wrong
    // for pure local-only — instead, pick our own existing federation
    // endpoint if present, else fall back to whatever's first.
    let our_relay_state = config::read_relay_state()?;
    let our_endpoints = crate::endpoints::self_endpoints(&our_relay_state);
    if our_endpoints.is_empty() {
        bail!(
            "this session has no endpoints — run `wire session new --local-only` or `wire bind-relay` first"
        );
    }
    let our_advertised = our_endpoints
        .iter()
        .find(|e| e.scope == crate::endpoints::EndpointScope::Federation)
        .cloned()
        .unwrap_or_else(|| our_endpoints[0].clone());

    // 5. Pin sister into our trust (VERIFIED — operator-owned siblings) +
    // relay_state.peers with their full endpoint set. slot_token lands
    // via pair_drop_ack as usual.
    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &sister_card, Some("VERIFIED"));
    config::write_trust(&trust)?;
    let mut relay_state = config::read_relay_state()?;
    crate::endpoints::pin_peer_endpoints(&mut relay_state, &sister_handle, &sister_endpoints)?;
    config::write_relay_state(&relay_state)?;

    // 6. Build the same pair_drop event the federation path emits, with
    // our card + endpoints in the body so the sister can pin us back.
    let sk_seed = config::read_private_key()?;
    let our_handle = crate::agent_card::display_handle_from_did(&our_did).to_string();
    let pk_b64 = our_card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("our card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let mut body = json!({
        "card": our_card,
        "relay_url": our_advertised.relay_url,
        "slot_id": our_advertised.slot_id,
        "slot_token": our_advertised.slot_token,
    });
    body["endpoints"] = serde_json::to_value(&our_endpoints).unwrap_or(json!([]));
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now,
        "from": our_did,
        "to": sister_did,
        "type": "pair_drop",
        "kind": 1100u32,
        "body": body,
    });
    let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &our_handle)?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    // 7. Deliver direct to sister's local slot. Skip /v1/handle/intro
    // (the federation handle indexer) — we already know the slot coords
    // from disk, so post_event is sufficient.
    let client = crate::relay_client::RelayClient::new(&delivery_endpoint.relay_url);
    client
        .post_event(
            &delivery_endpoint.slot_id,
            &delivery_endpoint.slot_token,
            &signed,
        )
        .with_context(|| format!("delivering pair_drop to `{sister_name}`'s local slot"))?;

    let delivered_via = match delivery_endpoint.scope {
        crate::endpoints::EndpointScope::Local => "local",
        crate::endpoints::EndpointScope::Lan => "lan",
        crate::endpoints::EndpointScope::Uds => "uds",
        crate::endpoints::EndpointScope::Federation => "federation",
    }
    .to_string();
    Ok(LocalSisterDrop {
        resolved_session: sister.name.clone(),
        paired_with_did: sister_did,
        peer_handle: sister_handle,
        event_id,
        delivered_via,
        delivery_relay_url: delivery_endpoint.relay_url.clone(),
    })
}

/// CLI renderer over [`add_local_sister_core`]. Output byte-identical to the
/// pre-extraction path (the within-system e2e suite guards it).
pub(crate) fn cmd_add_local_sister(sister_name: &str, as_json: bool) -> Result<()> {
    let drop = add_local_sister_core(sister_name)?;
    // If we matched via nickname (not exact name), surface that so the
    // operator sees what we resolved to. Quiet when names match exactly.
    if drop.resolved_session != sister_name {
        eprintln!(
            "wire add: resolved nickname `{sister_name}` → session `{}`",
            drop.resolved_session
        );
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": sister_name,
                "paired_with": drop.paired_with_did,
                "peer_handle": drop.peer_handle,
                "event_id": drop.event_id,
                "delivered_via": drop.delivered_via,
                "status": "drop_sent",
            }))?
        );
    } else {
        println!(
            "→ found sister `{sister_name}` (did={})\n→ pinned peer locally\n→ pair_drop delivered to {} slot on {}\nawaiting pair_drop_ack from {} to complete bilateral pin.",
            drop.paired_with_did, drop.delivered_via, drop.delivery_relay_url, drop.peer_handle
        );
    }
    Ok(())
}

pub(super) fn cmd_add(
    handle_arg: &str,
    relay_override: Option<&str>,
    local_sister: bool,
    as_json: bool,
) -> Result<()> {
    // v0.7.4: nickname-friendly local-sister resolution. Whether the
    // operator passed `--local-sister` explicitly OR just typed a bare
    // name (no `@<relay>`), try to resolve through the local sessions
    // registry so character nicknames AND session names AND card
    // handles all work as input. Closes the "I only know this peer by
    // its character name" ergonomic gap that forced operators into
    // `wire session list-local | grep <nick> | awk` dances.
    if local_sister {
        let resolved = crate::session::resolve_local_sister(handle_arg)
            .unwrap_or_else(|| handle_arg.to_string());
        return cmd_add_local_sister(&resolved, as_json);
    }
    if !handle_arg.contains('@')
        && let Some(resolved) = crate::session::resolve_local_sister(handle_arg)
    {
        eprintln!(
            "wire add: `{handle_arg}` resolved to local sister session `{resolved}` \
             — routing via --local-sister (disk-read card, no relay lookup)."
        );
        return cmd_add_local_sister(&resolved, as_json);
    }
    if !handle_arg.contains('@') {
        bail!(
            "`{handle_arg}` doesn't match any local sister session and has no \
             @<relay> suffix for federation.\n\
             — Local sisters: `wire session list-local` (operator types name OR \
             character nickname)\n\
             — Federation:    `wire add <handle>@<relay-domain>` (e.g. \
             `wire add alice@wireup.net`)"
        );
    }
    let parsed = crate::pair_profile::parse_handle(handle_arg)?;

    // 1. Auto-init self if needed + ensure a relay slot.
    let (our_did, our_relay, our_slot_id, our_slot_token) =
        crate::pair_invite::ensure_self_with_relay(relay_override)?;
    if our_did == format!("did:wire:{}", parsed.nick) {
        // Lazy guard — actual self-add would also be caught by FCFS later.
        bail!("refusing to add self (handle matches own DID)");
    }

    // v0.5.14 bilateral-completion path: if a pair_drop from this peer is
    // already sitting in pending-inbound, the operator is now accepting it.
    // Pin trust, save relay coords + slot_token from the stored drop, ship
    // our own slot_token back via pair_drop_ack, delete the pending record.
    //
    // This branch is the OTHER half of the v0.5.14 fix to maybe_consume_pair_drop:
    // receiver-side auto-promote was removed there; operator consent flows
    // through here. After this branch returns, both sides are bilaterally
    // pinned and capability flows in both directions.
    if let Some(pending) = crate::pending_inbound_pair::read_pending_inbound(&parsed.nick)? {
        return cmd_add_accept_pending(
            handle_arg,
            &parsed.nick,
            &pending,
            &our_relay,
            &our_slot_id,
            &our_slot_token,
            as_json,
        );
    }

    // v0.5.19 (#9.4): cross-relay phishing guardrail.
    //
    // Threat: operator wants to add `boss@wireup.net` but types
    // `boss@evil-relay.example` (typo, malicious link, look-alike domain).
    // The .well-known resolution returns whoever claimed the nick on the
    // *typo* relay, the bilateral gate still completes (the attacker
    // accepts the pair on their side), and the operator pins the
    // attacker as "boss". v0.5.14 bilateral gate doesn't catch this —
    // there's no asymmetry to detect when the attacker WANTS to be
    // paired.
    //
    // Mitigation: warn loudly when the peer's relay domain is novel
    // (not the operator's own relay, not in a small known-good set).
    // Doesn't block — operators have legitimate reasons to pair across
    // relays. The signal lands in shell history so a phished operator
    // can find it in retrospect.
    if !is_known_relay_domain(&parsed.domain, &our_relay) {
        eprintln!(
            "wire add: WARN unfamiliar relay domain `{}`.",
            parsed.domain
        );
        eprintln!(
            "  This is NOT `wireup.net` (the default), NOT your own relay (`{}`), ",
            super::host_of_url(&our_relay)
        );
        eprintln!(
            "  and not on the known-good list. If you meant `{}@wireup.net`, ",
            parsed.nick
        );
        eprintln!(
            "  run `wire add {}@wireup.net` instead. Otherwise verify with your",
            parsed.nick
        );
        eprintln!("  peer out-of-band that they actually run a relay at this domain");
        eprintln!("  before relying on the pair. (See issue #9.4.)");
    }

    // 2. Resolve peer via .well-known on their relay.
    let resolved = crate::pair_profile::resolve_handle(&parsed, relay_override)?;
    let peer_card = resolved
        .get("card")
        .cloned()
        .ok_or_else(|| anyhow!("resolved missing card"))?;
    let peer_did = resolved
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("resolved missing did"))?
        .to_string();
    let peer_handle = crate::agent_card::display_handle_from_did(&peer_did).to_string();

    // #247 finding 4: this is a relay-mediated first contact. Surface the
    // resolved DID + key fingerprint (so the operator can verify out-of-band),
    // and HARD-REFUSE if the card's key doesn't match its claimed DID — that's
    // a poisoned card, not just an unfamiliar relay.
    let (peer_fp, _did_fp, fp_matches) = resolved_key_fingerprint(&peer_card, &peer_did);
    if peer_fp.is_some() && !fp_matches {
        bail!(
            "wire add: REFUSING to pair `{handle_arg}` — the resolved card's key fingerprint ({}) does not match the fingerprint in its DID `{peer_did}`. The relay served a card whose key ≠ its claimed identity (poisoned discovery). Verify with the peer out-of-band.",
            peer_fp.as_deref().unwrap_or("?")
        );
    }
    if !as_json {
        eprintln!(
            "wire add: resolved {peer_did} (fingerprint {}) via relay discovery — trusted for routing, not identity. Verify out-of-band before relying on this pair.",
            peer_fp.as_deref().unwrap_or("?")
        );
    }

    // Self-pair guard (issue #30, explicit "Optional" ask). Refuses loudly
    // when the resolved peer DID matches our own. See
    // `reject_self_pair_after_resolution` for the full failure-mode and
    // remediation rationale.
    reject_self_pair_after_resolution(&our_did, &peer_did)?;

    let peer_slot_id = resolved
        .get("slot_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("resolved missing slot_id"))?
        .to_string();
    let peer_relay = resolved
        .get("relay_url")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| relay_override.map(str::to_string))
        .unwrap_or_else(|| format!("https://{}", parsed.domain));

    // 3. Pin peer in trust + relay-state. slot_token will arrive via ack.
    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &peer_card, Some("VERIFIED"));
    config::write_trust(&trust)?;
    let mut relay_state = config::read_relay_state()?;
    // Additive re-pin (v0.13.2, E3 token-bleed fix). The old code REPLACED the
    // whole peer entry with a flat federation-only one, seeding the token from
    // the entry's TOP-LEVEL `slot_token`. Two bugs (glossy-magnolia repro):
    //   1. re-dialing a peer that had a local endpoint (from add-peer-slot)
    //      CLOBBERED that local endpoint.
    //   2. after a local add-peer-slot the top-level token was the LOCAL token,
    //      so the federation endpoint inherited a stale LOCAL bearer →
    //      federation delivery would 401.
    // Fix: merge the federation endpoint into the peer's endpoints[] (preserve
    // the local one), and seed its token ONLY from a prior FEDERATION endpoint
    // on the same relay (re-dialing an already-acked peer), never a local one —
    // empty until the pair_drop_ack lands otherwise.
    let mut endpoints: Vec<crate::endpoints::Endpoint> = relay_state
        .get("peers")
        .and_then(|p| p.get(&peer_handle))
        .and_then(|e| e.get("endpoints"))
        .and_then(|a| serde_json::from_value::<Vec<crate::endpoints::Endpoint>>(a.clone()).ok())
        .unwrap_or_default();
    let fed_token = endpoints
        .iter()
        .find(|e| {
            e.relay_url == peer_relay && e.scope == crate::endpoints::EndpointScope::Federation
        })
        .map(|e| e.slot_token.clone())
        .unwrap_or_default();
    let fed_ep = crate::endpoints::Endpoint {
        relay_url: peer_relay.clone(),
        slot_id: peer_slot_id.clone(),
        slot_token: fed_token, // empty until pair_drop_ack lands
        scope: crate::endpoints::EndpointScope::Federation,
    };
    if let Some(existing) = endpoints
        .iter_mut()
        .find(|e| e.relay_url == fed_ep.relay_url)
    {
        *existing = fed_ep;
    } else {
        endpoints.push(fed_ep);
    }
    crate::endpoints::pin_peer_endpoints(&mut relay_state, &peer_handle, &endpoints)?;
    config::write_relay_state(&relay_state)?;

    // 4. Build signed pair_drop with our card + coords (no pair_nonce — this
    // is the v0.5 zero-paste open-mode path).
    let our_card = config::read_agent_card()?;
    let sk_seed = config::read_private_key()?;
    let our_handle = crate::agent_card::display_handle_from_did(&our_did).to_string();
    let pk_b64 = our_card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("our card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    // v0.5.17: advertise all our endpoints (federation + optional local)
    // to the peer in the pair_drop body. Back-compat: top-level
    // relay_url/slot_id/slot_token still point at the federation
    // endpoint so v0.5.16-and-earlier peers ingest unchanged.
    let our_relay_state = config::read_relay_state().unwrap_or_else(|_| json!({}));
    let our_endpoints = crate::endpoints::self_endpoints(&our_relay_state);
    let mut body = json!({
        "card": our_card,
        "relay_url": our_relay,
        "slot_id": our_slot_id,
        "slot_token": our_slot_token,
    });
    if !our_endpoints.is_empty() {
        body["endpoints"] = serde_json::to_value(&our_endpoints).unwrap_or(json!([]));
    }
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now,
        "from": our_did,
        "to": peer_did,
        "type": "pair_drop",
        "kind": 1100u32,
        "body": body,
    });
    let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &our_handle)?;

    // 5. Deliver via /v1/handle/intro/<nick> (auth-free; relay validates kind).
    let client = crate::relay_client::RelayClient::new(&peer_relay);
    let resp = client.handle_intro(&parsed.nick, &signed)?;
    let event_id = signed
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // #278: we just advertised our self endpoints to a FEDERATION peer. If our
    // only self slot is loopback (or UDS), the peer has no routable address to
    // deliver their `pair_drop_ack` to — the pair will sit at PENDING_ACK
    // forever while the operator sees a success-looking `drop_sent`. Warn (and
    // flag it in JSON); don't block — the operator may be about to bind a relay.
    let self_reachable = self_reachable_for_federation(&our_endpoints, &our_relay);
    if !self_reachable {
        eprintln!(
            "wire add: WARN you are not federation-reachable — your only self endpoint is loopback ({our_relay})."
        );
        eprintln!(
            "  {peer_handle} cannot deliver their pair_drop_ack there, so this pair will stay PENDING_ACK."
        );
        eprintln!(
            "  Become reachable, then re-run: `wire bind-relay https://<your-relay>` (or `wire up --relay https://wireup.net`) + `wire claim`."
        );
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle_arg,
                "paired_with": peer_did,
                "peer_handle": peer_handle,
                "event_id": event_id,
                "drop_response": resp,
                "self_reachable": self_reachable,
                "peer_fingerprint": peer_fp,
                "status": "drop_sent",
            }))?
        );
    } else {
        println!(
            "→ resolved {handle_arg} (did={peer_did})\n→ pinned peer locally\n→ intro dropped to {peer_relay}\nawaiting pair_drop_ack from {peer_handle} to complete bilateral pin."
        );
    }
    Ok(())
}

/// True iff our advertised self endpoints give a federation peer a routable
/// address for their `pair_drop_ack`. A purely loopback / UDS self slot is NOT
/// reachable from another host — the peer can never ack, so the pair sticks at
/// PENDING_ACK forever (#278). `endpoints` is `self_endpoints(..)`;
/// `fallback_relay` is the legacy top-level self `relay_url`, consulted only
/// when `endpoints[]` is empty (pre-v0.5.17 state). Pure → unit-tested.
fn self_reachable_for_federation(
    endpoints: &[crate::endpoints::Endpoint],
    fallback_relay: &str,
) -> bool {
    if !endpoints.is_empty() {
        endpoints
            .iter()
            .any(|e| e.scope == crate::endpoints::EndpointScope::Federation)
    } else {
        crate::endpoints::infer_scope_from_url(fallback_relay)
            == crate::endpoints::EndpointScope::Federation
    }
}

/// v0.5.14 bilateral-completion path for `wire add`. Called when the peer's
/// pair_drop is already sitting in `pending-inbound`. Pin trust, write relay
/// coords + slot_token from the stored drop, ship our slot_token back via
/// `pair_drop_ack`, delete the pending record. Symmetric with the SPAKE2
/// invite-URL path (which is already bilateral by virtue of the pre-shared
/// nonce).
fn cmd_add_accept_pending(
    handle_arg: &str,
    peer_nick: &str,
    pending: &crate::pending_inbound_pair::PendingInboundPair,
    _our_relay: &str,
    _our_slot_id: &str,
    _our_slot_token: &str,
    as_json: bool,
) -> Result<()> {
    // 1. Pin peer in trust with VERIFIED — operator gestured consent by running
    //    `wire add` against this handle while a drop was waiting.
    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &pending.peer_card, Some("VERIFIED"));
    config::write_trust(&trust)?;

    // 2. Record peer's relay coords + slot_token (already shipped to us in
    //    the original drop body; held back until now).
    // v0.5.17: pin all advertised endpoints (federation + optional local).
    // Falls back to a single federation entry when the record was written
    // by v0.5.16-era code that didn't carry endpoints[].
    let mut relay_state = config::read_relay_state()?;
    let endpoints_to_pin = if pending.peer_endpoints.is_empty() {
        vec![crate::endpoints::Endpoint::federation(
            pending.peer_relay_url.clone(),
            pending.peer_slot_id.clone(),
            pending.peer_slot_token.clone(),
        )]
    } else {
        pending.peer_endpoints.clone()
    };
    crate::endpoints::pin_peer_endpoints(
        &mut relay_state,
        &pending.peer_handle,
        &endpoints_to_pin,
    )?;
    config::write_relay_state(&relay_state)?;

    // 3. Ship our slot_token to peer via pair_drop_ack — try every advertised
    //    peer endpoint in priority order (Bug 2). `endpoints_to_pin` was
    //    already built from `pending.peer_endpoints` (with legacy-triple
    //    fallback) just above, so we reuse it rather than rebuilding.
    crate::pair_invite::send_pair_drop_ack(&pending.peer_handle, &endpoints_to_pin).with_context(
        || {
            format!(
                "pair_drop_ack send to {} (across {} endpoint(s)) failed",
                pending.peer_handle,
                endpoints_to_pin.len()
            )
        },
    )?;

    // 4. Delete the pending-inbound record now that bilateral is complete.
    crate::pending_inbound_pair::consume_pending_inbound(peer_nick)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle_arg,
                "paired_with": pending.peer_did,
                "peer_handle": pending.peer_handle,
                "status": "bilateral_accepted",
                "via": "pending_inbound",
            }))?
        );
    } else {
        println!(
            "→ accepted pending pair from {peer}\n→ pinned VERIFIED, slot_token recorded\n→ shipped our slot_token back via pair_drop_ack\nbilateral pair complete. Send with `wire send {peer} \"...\"`.",
            peer = pending.peer_handle,
        );
    }
    Ok(())
}

/// `wire accept <peer>` (v0.9+) — bilateral-completion path for a
/// pending-inbound pair request. Pin trust, write relay_state from the stored
/// pair_drop, send `pair_drop_ack` with our slot_token, delete the pending
/// record. Equivalent to running `wire add <peer>@<their-relay>` when a
/// pending-inbound record exists, but without needing to remember the peer's
/// relay domain.
pub(super) fn cmd_pair_accept(peer_nick: &str, as_json: bool) -> Result<()> {
    let nick = crate::agent_card::bare_handle(peer_nick);
    let pending = crate::pending_inbound_pair::read_pending_inbound(nick)?.ok_or_else(|| {
        anyhow!(
            "no pending pair request from {nick}. Run `wire pending` to see who is waiting, \
             or use `wire add <peer>@<relay>` to send a fresh outbound pair request."
        )
    })?;
    let (_our_did, our_relay, our_slot_id, our_slot_token) =
        crate::pair_invite::ensure_self_with_relay(None)?;
    let handle_arg = format!("{}@{}", pending.peer_handle, pending.peer_relay_url);
    cmd_add_accept_pending(
        &handle_arg,
        nick,
        &pending,
        &our_relay,
        &our_slot_id,
        &our_slot_token,
        as_json,
    )
}

/// `wire pending --json` — programmatic access to pending-inbound for scripts.
/// Returns a flat array of records sorted oldest-first.
pub(super) fn cmd_pair_list_inbound(as_json: bool) -> Result<()> {
    let items = crate::pending_inbound_pair::list_pending_inbound()?;
    if as_json {
        println!("{}", serde_json::to_string(&items)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("no pending pair requests — your inbox is clear.");
        return Ok(());
    }
    // v0.9.3: conversational output. Tabular data is for --json. Humans
    // get one short sentence per pending peer, each rendered with the
    // peer's character (DID-derived emoji + nickname) so they can match
    // the speaker against their statusline / mesh-status view at a
    // glance. The "next step" sentence at the bottom names the exact
    // verbs to run.
    let plural = if items.len() == 1 { "" } else { "s" };
    println!("{} pending pair request{plural}:\n", items.len());
    for p in &items {
        let ch = crate::character::Character::from_did(&p.peer_did);
        let glyph = crate::character::emoji_with_fallback(&ch);
        // ASCII-friendly arrow if the operator's terminal can't render
        // emoji (the same routine drives the fallback).
        println!(
            "  {glyph} {nick}  ({handle})  wants to pair with you",
            nick = ch.nickname,
            handle = p.peer_handle,
        );
    }
    println!();
    println!(
        "→ to accept any: `wire accept <name>`  (e.g. `wire accept {first}`)",
        first = items
            .first()
            .map(|p| {
                let ch = crate::character::Character::from_did(&p.peer_did);
                ch.nickname
            })
            .unwrap_or_else(|| "<name>".to_string())
    );
    println!("→ to refuse:    `wire reject <name>`");
    Ok(())
}

/// `wire reject <peer>` (v0.9+) — drop a pending-inbound record without
/// pairing. No event is sent back to the peer; their side stays pending
/// until they time out or the operator-side data ages out.
pub(super) fn cmd_pair_reject(peer_nick: &str, as_json: bool) -> Result<()> {
    let nick = crate::agent_card::bare_handle(peer_nick);
    let existed = crate::pending_inbound_pair::read_pending_inbound(nick)?;
    crate::pending_inbound_pair::consume_pending_inbound(nick)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "peer": nick,
                "rejected": existed.is_some(),
                "had_pending": existed.is_some(),
            }))?
        );
    } else if existed.is_some() {
        println!(
            "→ rejected pending pair from {nick}\n→ pending-inbound record deleted; no ack sent."
        );
    } else {
        println!("no pending pair from {nick} — nothing to reject");
    }
    Ok(())
}

// ---------- block-list (RFC-001 §T16 rogue-admin containment) ----------

/// `wire block-peer <did> [--note ...]` — add a DID to the local block-list so
/// it can never be org-auto-pinned or surface an org-notify prompt.
pub(super) fn cmd_block_peer(did: &str, note: Option<String>, as_json: bool) -> Result<()> {
    if !did.starts_with("did:wire:") {
        bail!(
            "`{did}` is not a wire DID. Pass a session DID (`did:wire:<handle>-<8hex>`) \
             or an operator DID (`did:wire:op:<handle>-<32hex>`). Find a peer's DID with \
             `wire whois <name>` or `wire peers`."
        );
    }
    let mut bl = crate::blocklist::Blocklist::load();
    let newly = bl.block(did, note.clone());
    bl.save()?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "did": did,
                "blocked": true,
                "newly_added": newly,
                "note": note,
            }))?
        );
    } else if newly {
        println!(
            "→ blocked {did}\n→ this peer can no longer be org-auto-paired or notify-prompt you. \
             (A deliberate `wire dial` + SAS pair still overrides the block.)"
        );
    } else {
        println!("{did} was already blocked — note refreshed.");
    }
    Ok(())
}

/// `wire unblock-peer <did>` — remove a DID from the local block-list.
pub(super) fn cmd_unblock_peer(did: &str, as_json: bool) -> Result<()> {
    let mut bl = crate::blocklist::Blocklist::load();
    let existed = bl.unblock(did);
    bl.save()?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({ "did": did, "unblocked": existed }))?
        );
    } else if existed {
        println!("→ unblocked {did} — org-easing paths apply again per your policy.");
    } else {
        println!("{did} was not on the block-list — nothing to do.");
    }
    Ok(())
}

/// `wire blocked` — list the DIDs on the local block-list.
pub(super) fn cmd_blocked(as_json: bool) -> Result<()> {
    let bl = crate::blocklist::Blocklist::load();
    if as_json {
        let entries: Vec<Value> = bl
            .entries()
            .map(|(did, e)| json!({ "did": did, "at": e.at, "note": e.note }))
            .collect();
        println!("{}", serde_json::to_string(&json!({ "blocked": entries }))?);
        return Ok(());
    }
    if bl.is_empty() {
        println!("no peers blocked. `wire block-peer <did>` adds one (RFC-001 §T16).");
        return Ok(());
    }
    println!("blocked peers ({}):", bl.len());
    for (did, e) in bl.entries() {
        match &e.note {
            Some(note) => println!("  {did}  ({}; {note})", e.at),
            None => println!("  {did}  ({})", e.at),
        }
    }
    Ok(())
}

fn reject_self_pair_after_resolution(our_did: &str, peer_did: &str) -> Result<()> {
    if our_did == peer_did {
        bail!(
            "refusing to self-pair: resolved peer DID `{peer_did}` matches your own \
             DID. Two terminals can collapse onto one wire identity when the per-\
             session key isn't reaching the wire process (issue #30 / #29).\n\n\
             Diagnose:\n  \
             • `wire whoami` in each terminal — DIDs MUST differ.\n  \
             • `echo $WIRE_SESSION_ID` (bash) / `echo $env:WIRE_SESSION_ID` \
             (PowerShell) — must be set + distinct per session.\n\n\
             Force distinct identities before relaunching the agent:\n  \
             • bash/zsh:   `export WIRE_SESSION_ID=\"$(uuidgen)\"`\n  \
             • PowerShell: `$env:WIRE_SESSION_ID = [guid]::NewGuid().ToString()`"
        );
    }
    Ok(())
}

// Integration tests for the CLI live in `tests/cli.rs` (cargo's tests/ dir).

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    fn card_with_key(pk: &[u8]) -> Value {
        json!({"verify_keys": {"ed25519:x": {"key": crate::signing::b64encode(pk)}}})
    }

    #[test]
    fn fingerprint_matches_when_card_key_matches_did() {
        let pk = [7u8; 32];
        let fp = crate::signing::fingerprint(&pk);
        let did = format!("did:wire:raven-kettle-{fp}");
        let (computed, did_fp, matches) = resolved_key_fingerprint(&card_with_key(&pk), &did);
        assert_eq!(computed.as_deref(), Some(fp.as_str()));
        assert_eq!(did_fp, fp);
        assert!(matches);
    }

    #[test]
    fn fingerprint_mismatch_when_card_key_differs_from_did() {
        // Poisoned discovery: card advertises a key whose fp ≠ the DID suffix.
        let pk = [7u8; 32];
        let did = "did:wire:raven-kettle-deadbeef"; // wrong suffix
        let (computed, _did_fp, matches) = resolved_key_fingerprint(&card_with_key(&pk), did);
        assert_eq!(
            computed.as_deref(),
            Some(crate::signing::fingerprint(&pk).as_str())
        );
        assert!(!matches, "key-vs-DID mismatch must NOT match");
    }

    #[test]
    fn fingerprint_no_key_is_not_a_match() {
        let (computed, _did_fp, matches) =
            resolved_key_fingerprint(&json!({}), "did:wire:x-12345678");
        assert!(computed.is_none());
        assert!(!matches);
    }
}

#[cfg(test)]
mod reachability_tests {
    use super::*;
    use crate::endpoints::Endpoint;

    #[test]
    fn federation_endpoint_is_reachable() {
        let eps = vec![Endpoint::federation(
            "https://wireup.net".into(),
            "s".into(),
            "t".into(),
        )];
        assert!(self_reachable_for_federation(&eps, "ignored"));
    }

    #[test]
    fn loopback_only_is_not_reachable() {
        // The #278 trap: only a loopback self slot → a federation peer can't ack.
        let eps = vec![Endpoint::local(
            "http://127.0.0.1:18791".into(),
            "s".into(),
            "t".into(),
        )];
        assert!(!self_reachable_for_federation(&eps, "ignored"));
    }

    #[test]
    fn dual_slot_local_plus_federation_is_reachable() {
        let eps = vec![
            Endpoint::local("http://127.0.0.1:8771".into(), "l".into(), "lt".into()),
            Endpoint::federation("https://wireup.net".into(), "f".into(), "ft".into()),
        ];
        assert!(self_reachable_for_federation(&eps, "ignored"));
    }

    #[test]
    fn empty_endpoints_falls_back_to_legacy_relay_scope() {
        // Pre-v0.5.17 state with no endpoints[]: judge by the legacy relay_url.
        assert!(self_reachable_for_federation(&[], "https://wireup.net"));
        assert!(!self_reachable_for_federation(
            &[],
            "http://127.0.0.1:18791"
        ));
    }
}

#[cfg(test)]
mod self_pair_guard_tests {
    use super::*;

    #[test]
    fn reject_self_pair_after_resolution_blocks_matching_dids() {
        // Issue #30 (explicit "Optional" ask): when both terminals collapse
        // onto one wire identity (a v0.13-era WIRE_SESSION_ID propagation
        // gap or a shared WIRE_HOME), the resolved peer DID matches the
        // local DID and pair_drop silently goes nowhere. Guard surfaces
        // it as a refusable error with the diagnostic remediation path.

        let err = reject_self_pair_after_resolution(
            "did:wire:winter-bay-4092b577",
            "did:wire:winter-bay-4092b577",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("refusing to self-pair"),
            "must explicitly refuse, not silently bail: {err}"
        );
        assert!(
            err.contains("did:wire:winter-bay-4092b577"),
            "must include the colliding DID so the operator can grep their `wire whoami` output: {err}"
        );
        assert!(
            err.contains("issue #30") || err.contains("issue #29"),
            "must point at the tracking issue so historical context is one search away: {err}"
        );
        // Remediation must be copy-paste ready — both POSIX and PowerShell
        // (the failure mode is Windows-prevalent per #30).
        assert!(
            err.contains("WIRE_SESSION_ID"),
            "remediation must name the env var operators set: {err}"
        );
        assert!(
            err.contains("uuidgen") || err.contains("NewGuid"),
            "remediation must include a concrete command to mint a unique id: {err}"
        );
    }

    #[test]
    fn reject_self_pair_after_resolution_allows_distinct_dids() {
        // Sanity: the guard must not fire for any normal pair attempt
        // between two distinct identities. Cover the common shapes:
        // adjective-noun personas (post-v0.11), bare keypair hashes, and
        // mixed-case DIDs that happen to share a prefix.
        reject_self_pair_after_resolution(
            "did:wire:winter-bay-4092b577",
            "did:wire:cedar-bayou-0616dc6c",
        )
        .unwrap();
        reject_self_pair_after_resolution("did:wire:ed25519:abc123", "did:wire:ed25519:def456")
            .unwrap();
        // Same persona prefix, different suffix-hash → distinct DIDs (the
        // suffix is the load-bearing identifier). Must NOT trigger the
        // guard.
        reject_self_pair_after_resolution(
            "did:wire:noble-canyon-deadbeef",
            "did:wire:noble-canyon-cafef00d",
        )
        .unwrap();
    }
}
