use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

fn resolve_session_name(name: Option<&str>) -> Result<String> {
    if let Some(n) = name {
        return Ok(crate::session::sanitize_name(n));
    }
    let cwd = std::env::current_dir().with_context(|| "reading cwd")?;
    let registry = crate::session::read_registry().unwrap_or_default();
    Ok(crate::session::derive_name_from_cwd(&cwd, &registry))
}

#[allow(clippy::too_many_arguments)] // 11 transport-mix flags; a config-struct
// refactor is the eventual cleanup. For now we ship the flag-explosion as-is.
pub(super) fn cmd_session_new(
    name_arg: Option<&str>,
    relay: &str,
    with_local: bool,
    local_relay: &str,
    with_lan: bool,
    lan_relay: Option<&str>,
    with_uds: bool,
    uds_socket: Option<&std::path::Path>,
    no_daemon: bool,
    local_only: bool,
    as_json: bool,
) -> Result<()> {
    // v0.6.6: --local-only implies --with-local (a federation-free
    // session with no endpoints at all would be unaddressable).
    let with_local = with_local || local_only;
    // v0.7.0-alpha.9: --with-lan requires --lan-relay <url>.
    if with_lan && lan_relay.is_none() {
        bail!("--with-lan requires --lan-relay <url> (e.g. http://192.168.1.50:8771)");
    }
    // v0.7.0-alpha.18: --with-uds requires --uds-socket <path>.
    if with_uds && uds_socket.is_none() {
        bail!("--with-uds requires --uds-socket <path> (e.g. /tmp/wire.sock)");
    }
    let cwd = std::env::current_dir().with_context(|| "reading cwd")?;
    let mut registry = crate::session::read_registry().unwrap_or_default();
    let name = match name_arg {
        Some(n) => crate::session::sanitize_name(n),
        None => crate::session::derive_name_from_cwd(&cwd, &registry),
    };
    let session_home = crate::session::session_dir(&name)?;

    let already_exists = session_home.exists()
        && session_home
            .join("config")
            .join("wire")
            .join("agent-card.json")
            .exists();
    if already_exists {
        // Idempotent: re-register the cwd (if not already), refresh the
        // daemon if requested, surface the env-var line. Do not re-init
        // identity — that would clobber the keypair.
        registry
            .by_cwd
            .insert(cwd.to_string_lossy().into_owned(), name.clone());
        crate::session::write_registry(&registry)?;
        let info = render_session_info(&name, &session_home, &cwd)?;
        emit_session_new_result(&info, "already_exists", as_json)?;
        if !no_daemon {
            ensure_session_daemon(&session_home)?;
        }
        return Ok(());
    }

    std::fs::create_dir_all(&session_home)
        .with_context(|| format!("creating session dir {session_home:?}"))?;

    // Phase 1: init identity in the new session's WIRE_HOME. For
    // federation-bound sessions we pass `--relay` so init also
    // allocates a federation slot in the same step; for `--local-only`
    // we run init with `--offline` (v0.9 requires explicit reachability
    // acknowledgement at init time) because cmd_session_new allocates
    // the local-relay slot itself via try_allocate_local_slot below.
    // The session is not actually slotless — init is just deferred to
    // the subsequent allocation pass.
    let init_args: Vec<&str> = if local_only {
        vec!["init", "--offline"]
    } else {
        vec!["init", "--relay", relay]
    };
    let init_status = super::run_wire_with_home(&session_home, &init_args)?;
    if !init_status.success() {
        let how = if local_only {
            format!("`wire init {name}` (local-only)")
        } else {
            format!("`wire init {name} --relay {relay}`")
        };
        bail!("{how} failed inside session dir {session_home:?}");
    }

    // Phase 2: claim the handle on the federation relay — SKIPPED when
    // `--local-only`. Local-only sessions have no public address and
    // accept reserved nicks (e.g. cwd-derived `wire`) because nothing
    // tries to publish them.
    let effective_handle = if local_only {
        name.clone()
    } else {
        let mut claim_attempt = 0u32;
        let mut effective = name.clone();
        loop {
            claim_attempt += 1;
            let status =
                super::run_wire_with_home(&session_home, &["claim", &effective, "--relay", relay])?;
            if status.success() {
                break;
            }
            if claim_attempt >= 5 {
                bail!(
                    "5 failed attempts to claim a handle on {relay} for session {name}. \
                     Try `wire session destroy {name} --force` and re-run with a different name, \
                     or use `--local-only` if you don't need a federation address."
                );
            }
            let attempt_path = cwd.join(format!("__attempt_{claim_attempt}"));
            let suffix = crate::session::derive_name_from_cwd(&attempt_path, &registry);
            let token = suffix
                .rsplit('-')
                .next()
                .filter(|t| t.len() == 4)
                .map(str::to_string)
                .unwrap_or_else(|| format!("{claim_attempt}"));
            effective = format!("{name}-{token}");
        }
        effective
    };

    // Persist the cwd → name mapping NOW so subsequent invocations from
    // this directory short-circuit to the "already_exists" branch.
    registry
        .by_cwd
        .insert(cwd.to_string_lossy().into_owned(), name.clone());
    crate::session::write_registry(&registry)?;

    // v0.5.17: --with-local probes the local relay and, if it's
    // reachable, allocates a second slot there. The session's
    // relay_state.json grows a `self.endpoints[]` array carrying both
    // endpoints; routing layer (cmd_push) prefers local for sister-
    // session peers that also have a local slot.
    //
    // v0.6.6 (--local-only): try_allocate_local_slot is the ONLY slot
    // allocation; a failed probe leaves the session with no endpoints,
    // which we surface as a hard error (the operator asked for local-
    // only but the local relay isn't running — fix that first).
    if with_local {
        try_allocate_local_slot(&session_home, &effective_handle, relay, local_relay);
        if local_only {
            // Verify the local slot landed. If the local relay was
            // unreachable, the session would be unreachable from
            // anywhere — surface that loudly instead of leaving an
            // orphaned session dir.
            let relay_state_path = session_home.join("config").join("wire").join("relay.json");
            let state: Value = std::fs::read(&relay_state_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_else(|| json!({"self": Value::Null, "peers": {}}));
            let endpoints = crate::endpoints::self_endpoints(&state);
            let has_local = endpoints
                .iter()
                .any(|e| e.scope == crate::endpoints::EndpointScope::Local);
            if !has_local {
                bail!(
                    "--local-only requested but local-relay probe at {local_relay} failed — \
                     ensure the local relay is running (`wire service install --local-relay`), \
                     then re-run `wire session new {name} --local-only`."
                );
            }
        }
    }

    // v0.7.0-alpha.9: also allocate a LAN-bound slot if requested.
    // Sits AFTER local because cmd_session_new's flow is "add endpoints
    // alongside existing self.endpoints[]" — order independent post-init.
    if with_lan && let Some(lan_url) = lan_relay {
        try_allocate_lan_slot(&session_home, &effective_handle, lan_url);
    }
    // v0.7.0-alpha.18: also allocate a UDS slot if requested.
    if with_uds && let Some(socket_path) = uds_socket {
        try_allocate_uds_slot(&session_home, &effective_handle, socket_path);
    }

    if !no_daemon {
        ensure_session_daemon(&session_home)?;
    }

    let info = render_session_info(&name, &session_home, &cwd)?;
    emit_session_new_result(&info, "created", as_json)
}

/// Coerce a JSON document whose root is valid JSON but not an object
/// (`[]`, `"x"`, `42`, `null`) back to `{}` so callers can mutate it
/// with `as_object_mut()` without panicking. The slot-allocation paths
/// load `relay.json` with a parse-failure fallback to `{}`, but a file
/// holding valid non-object JSON sailed past that fallback and hit the
/// `expect("relay_state root is an object")` below.
fn coerce_object_root(v: &mut serde_json::Value) {
    if !v.is_object() {
        *v = serde_json::json!({});
    }
}

/// v0.7.0-alpha.18: probe + allocate against a UDS-bound relay, then
/// merge the resulting Uds endpoint into `self.endpoints[]` so paired
/// sister sessions can route over the local socket instead of loopback
/// HTTP. Uses the hand-rolled `uds_request` HTTP/1.1 client from
/// alpha.17 — reqwest has no UDS support.
///
/// Non-fatal on probe/alloc failure (mirrors try_allocate_local_slot
/// and try_allocate_lan_slot semantics): session stays at existing
/// endpoint mix, operator can retry once the UDS relay is up.
#[cfg(unix)]
fn try_allocate_uds_slot(
    session_home: &std::path::Path,
    handle: &str,
    uds_socket: &std::path::Path,
) {
    // Probe healthz first so we fail fast with a clear stderr if the
    // socket doesn't exist OR isn't a wire relay.
    let healthz = match crate::relay_client::uds_request(uds_socket, "GET", "/healthz", &[], b"") {
        Ok((200, _)) => true,
        Ok((status, body)) => {
            eprintln!(
                "wire session new: UDS relay probe at {uds_socket:?} returned {status} ({}) — not publishing UDS endpoint",
                String::from_utf8_lossy(&body)
            );
            return;
        }
        Err(e) => {
            eprintln!(
                "wire session new: UDS relay at {uds_socket:?} unreachable ({e:#}) — \
                 not publishing UDS endpoint. Start one with `wire relay-server --uds <path>`."
            );
            return;
        }
    };
    if !healthz {
        return;
    }

    // Allocate a slot via the same hand-rolled HTTP/1.1 client.
    let alloc_body = serde_json::json!({"handle": handle}).to_string();
    let (status, body) = match crate::relay_client::uds_request(
        uds_socket,
        "POST",
        "/v1/slot/allocate",
        &[("Content-Type", "application/json")],
        alloc_body.as_bytes(),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "wire session new: UDS relay slot allocation request failed: {e:#} — not publishing UDS endpoint"
            );
            return;
        }
    };
    if status >= 300 {
        eprintln!(
            "wire session new: UDS relay slot allocation returned {status} ({}) — not publishing UDS endpoint",
            String::from_utf8_lossy(&body)
        );
        return;
    }
    let alloc: crate::relay_client::AllocateResponse = match serde_json::from_slice(&body) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("wire session new: UDS relay returned unparseable allocate response: {e:#}");
            return;
        }
    };

    let state_path = session_home.join("config").join("wire").join("relay.json");
    let mut state: serde_json::Value = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let mut endpoints: Vec<crate::endpoints::Endpoint> = state
        .get("self")
        .and_then(|s| s.get("endpoints"))
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    serde_json::from_value::<crate::endpoints::Endpoint>(v.clone()).ok()
                })
                .collect()
        })
        .unwrap_or_default();
    endpoints.push(crate::endpoints::Endpoint::uds(
        format!("unix://{}", uds_socket.display()),
        alloc.slot_id.clone(),
        alloc.slot_token.clone(),
    ));

    coerce_object_root(&mut state);
    let self_obj = state
        .as_object_mut()
        .expect("relay_state root coerced to object above")
        .entry("self")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !self_obj.is_object() {
        *self_obj = serde_json::Value::Object(serde_json::Map::new());
    }
    if let Some(obj) = self_obj.as_object_mut() {
        obj.insert(
            "endpoints".into(),
            serde_json::to_value(&endpoints).unwrap_or(serde_json::Value::Null),
        );
    }
    if let Err(e) = std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&state).expect("relay_state serializable"),
    ) {
        eprintln!("wire session new: failed to write {state_path:?}: {e}");
        return;
    }
    eprintln!(
        "wire session new: UDS slot allocated on unix://{} (slot_id={}) — sister sessions will see this endpoint in your agent-card",
        uds_socket.display(),
        alloc.slot_id
    );
}

#[cfg(not(unix))]
fn try_allocate_uds_slot(
    _session_home: &std::path::Path,
    _handle: &str,
    _uds_socket: &std::path::Path,
) {
    eprintln!(
        "wire session new: --with-uds is Unix-only (Windows lacks AF_UNIX in tokio/reqwest); ignoring"
    );
}

/// v0.7.0-alpha.9: probe + allocate against a LAN-bound relay, then
/// merge the resulting Lan endpoint into `self.endpoints[]` so peers
/// pulling the agent-card see a third reachable address.
///
/// Mirrors `try_allocate_local_slot` but tags the endpoint
/// `EndpointScope::Lan`. Non-fatal: if probe or alloc fails, the
/// session stays at whatever endpoint mix it already had — operators
/// can retry with `wire session new --with-lan --lan-relay <url>` once
/// the LAN relay is up.
fn try_allocate_lan_slot(session_home: &std::path::Path, handle: &str, lan_relay: &str) {
    let probe = match crate::relay_client::build_blocking_client(Some(
        std::time::Duration::from_millis(500),
    )) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wire session new: cannot build LAN probe client for {lan_relay}: {e:#}");
            return;
        }
    };
    let healthz_url = format!("{}/healthz", lan_relay.trim_end_matches('/'));
    match probe.get(&healthz_url).send() {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            eprintln!(
                "wire session new: LAN relay probe at {healthz_url} returned {} — not publishing LAN endpoint",
                resp.status()
            );
            return;
        }
        Err(e) => {
            eprintln!(
                "wire session new: LAN relay at {lan_relay} unreachable ({}) — not publishing LAN endpoint. \
                 Start one on the LAN-bound interface with `wire relay-server --bind <LAN-IP>:8771 --local-only`.",
                crate::relay_client::format_transport_error(&anyhow::Error::new(e))
            );
            return;
        }
    };

    let lan_client = crate::relay_client::RelayClient::new(lan_relay);
    let alloc = match lan_client.allocate_slot(Some(handle)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "wire session new: LAN relay slot allocation failed: {e:#} — not publishing LAN endpoint"
            );
            return;
        }
    };

    let state_path = session_home.join("config").join("wire").join("relay.json");
    let mut state: serde_json::Value = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    // Read existing endpoints array and add the LAN one. Preserve
    // federation / local entries already there.
    let mut endpoints: Vec<crate::endpoints::Endpoint> = state
        .get("self")
        .and_then(|s| s.get("endpoints"))
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    serde_json::from_value::<crate::endpoints::Endpoint>(v.clone()).ok()
                })
                .collect()
        })
        .unwrap_or_default();
    endpoints.push(crate::endpoints::Endpoint::lan(
        lan_relay.trim_end_matches('/').to_string(),
        alloc.slot_id.clone(),
        alloc.slot_token.clone(),
    ));

    coerce_object_root(&mut state);
    let self_obj = state
        .as_object_mut()
        .expect("relay_state root coerced to object above")
        .entry("self")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !self_obj.is_object() {
        *self_obj = serde_json::Value::Object(serde_json::Map::new());
    }
    if let Some(obj) = self_obj.as_object_mut() {
        obj.insert(
            "endpoints".into(),
            serde_json::to_value(&endpoints).unwrap_or(serde_json::Value::Null),
        );
    }
    if let Err(e) = std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&state).expect("relay_state serializable"),
    ) {
        eprintln!("wire session new: failed to write {state_path:?}: {e}");
        return;
    }
    eprintln!(
        "wire session new: LAN slot allocated on {lan_relay} (slot_id={}) — peers will see this endpoint in your agent-card",
        alloc.slot_id
    );
}

/// v0.5.17: probe the named local relay; if `/healthz` returns ok within
/// a short timeout, allocate a slot there and update the session's
/// `relay_state.json` `self.endpoints[]` to advertise both endpoints.
///
/// Failure to reach the local relay is NOT fatal — the session stays
/// federation-only. Logs to stderr on failure so operators can tell
/// the local relay isn't running, but doesn't abort the bootstrap.
fn try_allocate_local_slot(
    session_home: &std::path::Path,
    handle: &str,
    _federation_relay: &str,
    local_relay: &str,
) {
    // Probe healthz with a tight timeout. Use a fresh client (don't
    // share the daemon-wide one) so the timeout is local to this call.
    let probe = match crate::relay_client::build_blocking_client(Some(
        std::time::Duration::from_millis(500),
    )) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wire session new: cannot build probe client for {local_relay}: {e:#}");
            return;
        }
    };
    let healthz_url = format!("{}/healthz", local_relay.trim_end_matches('/'));
    match probe.get(&healthz_url).send() {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            eprintln!(
                "wire session new: local relay probe at {healthz_url} returned {} — staying federation-only",
                resp.status()
            );
            return;
        }
        Err(e) => {
            eprintln!(
                "wire session new: local relay at {local_relay} unreachable ({}) — staying federation-only. \
                 Start one with `wire relay-server --bind 127.0.0.1:8771 --local-only`.",
                crate::relay_client::format_transport_error(&anyhow::Error::new(e))
            );
            return;
        }
    };

    // Allocate a slot on the local relay.
    let local_client = crate::relay_client::RelayClient::new(local_relay);
    let alloc = match local_client.allocate_slot(Some(handle)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "wire session new: local relay slot allocation failed: {e:#} — staying federation-only"
            );
            return;
        }
    };

    // Merge into the session's relay.json. We invoke wire via
    // run_wire_with_home for federation calls (subprocess isolation),
    // but relay.json is a simple file we can edit directly
    // — and need to, because there's no `wire bind-relay --add-local`
    // command yet (could add later; out of scope for v0.5.17 MVP).
    //
    // v0.5.20 BUG FIX: previously joined `relay-state.json` here, which
    // does not exist (canonical filename is `relay.json` per
    // `config::relay_state_path`). The mis-named file write succeeded
    // but landed in a sibling path nothing else reads. Every
    // `wire session new --with-local` invocation silently degraded to
    // federation-only despite the "local slot allocated" stderr line.
    // Caught by deploying v0.5.19 on the dev laptop and inspecting the
    // session's relay.json — it had only the federation endpoint.
    let state_path = session_home.join("config").join("wire").join("relay.json");
    let mut state: serde_json::Value = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    // Read the existing federation self info (already written by
    // `wire init` + `wire bind-relay` path during session bootstrap).
    let fed_endpoint = state.get("self").and_then(|s| {
        let url = s.get("relay_url").and_then(serde_json::Value::as_str)?;
        let slot_id = s.get("slot_id").and_then(serde_json::Value::as_str)?;
        let slot_token = s.get("slot_token").and_then(serde_json::Value::as_str)?;
        Some(crate::endpoints::Endpoint::federation(
            url.to_string(),
            slot_id.to_string(),
            slot_token.to_string(),
        ))
    });

    let local_endpoint = crate::endpoints::Endpoint::local(
        local_relay.trim_end_matches('/').to_string(),
        alloc.slot_id.clone(),
        alloc.slot_token.clone(),
    );

    let mut endpoints: Vec<crate::endpoints::Endpoint> = Vec::new();
    if let Some(f) = fed_endpoint.clone() {
        endpoints.push(f);
    }
    endpoints.push(local_endpoint);

    // v0.6.6: when there's no federation endpoint (e.g. `--local-only`
    // bootstrap), the legacy top-level `relay_url` / `slot_id` /
    // `slot_token` fields must point at the LOCAL endpoint so callers
    // that read those legacy fields (send_pair_drop_ack, post-v0.6.6
    // ensure_self_with_relay fallback, v0.5.16-era back-compat readers)
    // still find a valid slot. Pre-v0.6.6 this branch wrote
    // `relay_url: federation_relay` with no slot_id, which produced
    // half-populated self state that broke wire-accept on local-only
    // sessions.
    let (legacy_relay, legacy_slot_id, legacy_slot_token) = match fed_endpoint.clone() {
        Some(f) => (f.relay_url, f.slot_id, f.slot_token),
        None => (
            local_relay.trim_end_matches('/').to_string(),
            alloc.slot_id.clone(),
            alloc.slot_token.clone(),
        ),
    };
    coerce_object_root(&mut state);
    let self_obj = state
        .as_object_mut()
        .expect("relay_state root coerced to object above")
        .entry("self")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    // The entry might be Value::Null (left by read_relay_state's default
    // template) — replace with an object before mutating.
    if !self_obj.is_object() {
        *self_obj = serde_json::Value::Object(serde_json::Map::new());
    }
    if let Some(obj) = self_obj.as_object_mut() {
        obj.insert("relay_url".into(), serde_json::Value::String(legacy_relay));
        obj.insert("slot_id".into(), serde_json::Value::String(legacy_slot_id));
        obj.insert(
            "slot_token".into(),
            serde_json::Value::String(legacy_slot_token),
        );
        obj.insert(
            "endpoints".into(),
            serde_json::to_value(&endpoints).unwrap_or(serde_json::Value::Null),
        );
    }

    if let Err(e) = std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&state).unwrap_or_default(),
    ) {
        eprintln!(
            "wire session new: persisting dual-slot relay_state at {state_path:?} failed: {e}"
        );
        return;
    }
    eprintln!(
        "wire session new: local slot allocated on {local_relay} (slot_id={})",
        alloc.slot_id
    );
}

fn render_session_info(
    name: &str,
    session_home: &std::path::Path,
    cwd: &std::path::Path,
) -> Result<serde_json::Value> {
    let card_path = session_home
        .join("config")
        .join("wire")
        .join("agent-card.json");
    let (did, handle) = if card_path.exists() {
        let card: Value = serde_json::from_slice(&std::fs::read(&card_path)?)?;
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
        (did, handle)
    } else {
        (String::new(), String::new())
    };
    Ok(json!({
        "name": name,
        "home_dir": session_home.to_string_lossy(),
        "cwd": cwd.to_string_lossy(),
        "did": did,
        "handle": handle,
        "export": format!("export WIRE_HOME={}", session_home.to_string_lossy()),
    }))
}

fn emit_session_new_result(info: &serde_json::Value, status: &str, as_json: bool) -> Result<()> {
    if as_json {
        let mut obj = info.clone();
        obj["status"] = json!(status);
        println!("{}", serde_json::to_string(&obj)?);
    } else {
        let name = info["name"].as_str().unwrap_or("?");
        let handle = info["handle"].as_str().unwrap_or("?");
        let home = info["home_dir"].as_str().unwrap_or("?");
        let did = info["did"].as_str().unwrap_or("?");
        let export = info["export"].as_str().unwrap_or("?");
        let prefix = if status == "already_exists" {
            "session already exists (re-registered cwd)"
        } else {
            "session created"
        };
        println!(
            "{prefix}\n  name:   {name}\n  handle: {handle}\n  did:    {did}\n  home:   {home}\n\nactivate with:\n  {export}"
        );
    }
    Ok(())
}

/// v0.7.0-alpha.2: idempotent per-cwd session creation.
///
/// When the auto-detect (`maybe_adopt_session_wire_home`) finds no
/// registered session for the current cwd — including via parent-walk —
/// this creates one inline so every Claude tab in a fresh project gets
/// its own wire identity rather than collapsing onto the machine-wide
/// default. Without this, multiple Claudes in unwired cwds all render
/// the same character (the default identity's character), defeating the
/// "every session looks different" promise.
///
/// Opt-out: `WIRE_AUTO_INIT=0` env var (e.g. set in shell profile or
/// `run_wire_with_home` subprocess context).
///
/// Best-effort: any failure (no home dir, name collision pathology,
/// `wire init` subprocess crash) is logged to stderr and we fall back
/// to default identity. Must not block MCP startup.
///
/// MUST be called BEFORE worker thread spawn (env::set_var safety).
pub fn maybe_auto_init_cwd_session(label: &str) {
    if std::env::var("WIRE_HOME").is_ok() {
        return; // explicit override OR auto-detect already won
    }
    if std::env::var("WIRE_AUTO_INIT").as_deref() == Ok("0") {
        return; // operator opt-out
    }
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(_) => return,
    };
    // Defensive: parent-walk re-check (maybe_adopt_session_wire_home
    // already runs but we want to be robust to ordering).
    if crate::session::detect_session_wire_home(&cwd).is_some() {
        return;
    }

    // v0.7.0-alpha.12 (review-fix #135): SINGLE global auto-init lock
    // (was per-name in alpha.3, briefly per-cwd in alpha.12-iter1).
    // Two different cwds with the same basename (e.g. /a/projx +
    // /b/projx) used to race outside the lock: both read empty
    // registry, both derived name="projx", per-name lock didn't help
    // because they queued on DIFFERENT locks (cwd-A and cwd-B).
    //
    // Single lock serializes ALL auto-init across the sessions_root.
    // Inside the lock: re-read registry, derive_name_from_cwd which
    // adds path-hash suffix when basename is occupied by another cwd
    // already committed to the registry. Different cwds get DIFFERENT
    // names guaranteed.
    //
    // Cost: parallel auto-inits in different cwds now serialize
    // (~hundreds of ms each when local relay is up). Acceptable —
    // auto-init runs once per cwd per machine; not a hot path.
    use fs2::FileExt;
    let sessions_root = match crate::session::sessions_root() {
        Ok(r) => r,
        Err(_) => return,
    };
    if let Err(e) = std::fs::create_dir_all(&sessions_root) {
        eprintln!("wire {label}: auto-init: failed to create sessions root {sessions_root:?}: {e}");
        return;
    }
    let lock_path = sessions_root.join(".auto-init.lock");
    let lock_file = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "wire {label}: auto-init: cannot open lockfile {lock_path:?}: {e} — falling back to default identity"
            );
            return;
        }
    };
    if let Err(e) = lock_file.lock_exclusive() {
        eprintln!(
            "wire {label}: auto-init: flock {lock_path:?} failed: {e} — falling back to default identity"
        );
        return;
    }
    // Lock acquired. Read registry + derive name now that all parallel
    // racers serialize through us — derive_name_from_cwd adds a
    // path-hash suffix if the basename is already claimed by another
    // cwd in the (now-stable) registry.
    let registry = crate::session::read_registry().unwrap_or_default();
    let name = crate::session::derive_name_from_cwd(&cwd, &registry);
    let session_home = match crate::session::session_dir(&name) {
        Ok(h) => h,
        Err(_) => {
            let _ = fs2::FileExt::unlock(&lock_file);
            return;
        }
    };
    let agent_card_path = session_home
        .join("config")
        .join("wire")
        .join("agent-card.json");
    let needs_init = !agent_card_path.exists();

    if needs_init {
        if let Err(e) = std::fs::create_dir_all(&session_home) {
            eprintln!(
                "wire {label}: auto-init: failed to create session dir {session_home:?}: {e}"
            );
            let _ = fs2::FileExt::unlock(&lock_file);
            return;
        }
        // v0.9: --offline; the surrounding session-spawn path runs
        // try_allocate_local_slot afterward to attach an inbound slot
        // when a local relay is available. Init itself stays slotless
        // because it's a precursor step, not the final state.
        match super::run_wire_with_home(&session_home, &["init", "--offline"]) {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!(
                    "wire {label}: auto-init: `wire init` for `{name}` exited non-zero ({status}) — falling back to default identity"
                );
                let _ = fs2::FileExt::unlock(&lock_file);
                return;
            }
            Err(e) => {
                eprintln!(
                    "wire {label}: auto-init: failed to spawn `wire init {name}`: {e:#} — falling back to default identity"
                );
                let _ = fs2::FileExt::unlock(&lock_file);
                return;
            }
        }
        // Best-effort: allocate a local-relay slot so this auto-init'd
        // session is addressable by sister sessions. Skipped silently when
        // the local relay isn't running (the function itself reports to
        // stderr). Auto-init'd sessions without endpoints can still
        // surface their character but cannot receive pair_drops until the
        // operator runs `wire bind-relay` or restarts the local relay.
        try_allocate_local_slot(
            &session_home,
            &name,
            "https://wireup.net",
            "http://127.0.0.1:8771",
        );
    } else {
        // Race loser path: peer already created the session. Surface
        // this honestly so the operator can see we adopted rather than
        // double-initialized.
        if std::env::var("WIRE_QUIET_AUTOSESSION").is_err() {
            eprintln!(
                "wire {label}: auto-init: session `{name}` already exists (concurrent mcp peer won the race) — adopting"
            );
        }
    }
    // v0.7.0-alpha.12 (review-fix #135 part 2): register cwd → name
    // BEFORE releasing the auto-init lock. Pre-fix released the lock
    // here and committed the registry update afterward — racers in
    // OTHER cwds with the same basename would acquire the lock,
    // read the registry (still without our entry), and derive the
    // SAME name we just claimed. Live regression test caught it:
    // two cwds /a/projx + /b/projx both got name "projx", both
    // mapped to the same identity. Update the registry WHILE STILL
    // holding the auto-init lock so the next racer sees our claim.
    let cwd_key = crate::session::normalize_cwd_key(&cwd);
    let name_for_reg = name.clone();
    if let Err(e) = crate::session::update_registry(|reg| {
        reg.by_cwd.insert(cwd_key, name_for_reg);
        Ok(())
    }) {
        eprintln!("wire {label}: auto-init: failed to update registry: {e:#}");
        // proceed — env var still gets set below
    }
    // NOW release the lock — racers waiting will see our registry
    // entry on their re-read.
    let _ = fs2::FileExt::unlock(&lock_file);

    if std::env::var("WIRE_QUIET_AUTOSESSION").is_err() {
        eprintln!(
            "wire {label}: auto-init: created session `{name}` for cwd `{}` → WIRE_HOME=`{}`",
            cwd.display(),
            session_home.display()
        );
    }
    // SAFETY: caller contract is "before any thread spawn." MCP::run
    // calls this immediately after `maybe_adopt_session_wire_home`.
    unsafe {
        std::env::set_var("WIRE_HOME", &session_home);
    }
}

fn ensure_session_daemon(session_home: &std::path::Path) -> Result<()> {
    // Check if a daemon is already alive in this session's WIRE_HOME.
    // If so, no-op (let the existing process keep running).
    let pidfile = session_home.join("state").join("wire").join("daemon.pid");
    if pidfile.exists() {
        let bytes = std::fs::read(&pidfile).unwrap_or_default();
        let pid: Option<u32> = if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            v.get("pid").and_then(|p| p.as_u64()).map(|p| p as u32)
        } else {
            String::from_utf8_lossy(&bytes).trim().parse::<u32>().ok()
        };
        if let Some(p) = pid {
            let alive = {
                #[cfg(target_os = "linux")]
                {
                    std::path::Path::new(&format!("/proc/{p}")).exists()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    std::process::Command::new("kill")
                        .args(["-0", &p.to_string()])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                }
            };
            if alive {
                return Ok(());
            }
        }
    }

    // Spawn `wire daemon` detached. The existing `cmd_daemon` writes the
    // versioned pidfile; we just kick it off and return.
    let bin = std::env::current_exe().with_context(|| "locating self exe")?;
    let log_path = session_home.join("state").join("wire").join("daemon.log");
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening daemon log {log_path:?}"))?;
    let log_err = log_file.try_clone()?;
    std::process::Command::new(&bin)
        .env("WIRE_HOME", session_home)
        .env_remove("RUST_LOG")
        .args(["daemon", "--interval", "5"])
        .stdout(log_file)
        .stderr(log_err)
        .stdin(std::process::Stdio::null())
        .spawn()
        .with_context(|| "spawning session-local `wire daemon`")?;
    Ok(())
}

pub(super) fn cmd_session_list(as_json: bool) -> Result<()> {
    let items = crate::session::list_sessions()?;
    if as_json {
        println!("{}", serde_json::to_string(&items)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("no sessions on this machine. `wire session new` to create one.");
        return Ok(());
    }
    println!(
        "{:<22} {:<24} {:<24} {:<10} CWD",
        "PERSONA", "NAME", "HANDLE", "DAEMON"
    );
    for s in items {
        // ANSI-escape-wrapped character takes more visual width than its
        // displayed glyph count; pad based on the plain-text form, then
        // wrap in escapes so the column lines up across rows.
        let plain = s
            .character
            .as_ref()
            .map(|c| c.short())
            .unwrap_or_else(|| "?".to_string());
        let colored = s
            .character
            .as_ref()
            .map(|c| c.colored())
            .unwrap_or_else(|| "?".to_string());
        // Approximate display width: emoji renders as ~2 cells in most
        // terminals; the rest are 1 cell each. We pad to 18 displayed
        // chars (≈22 byte slots when counting emoji).
        let displayed_width = plain.chars().count() + 1; // +1 emoji-wide compensation
        let pad = 22usize.saturating_sub(displayed_width);
        println!(
            "{}{}  {:<24} {:<24} {:<10} {}",
            colored,
            " ".repeat(pad),
            s.name,
            s.handle.as_deref().unwrap_or("?"),
            if s.daemon_running { "running" } else { "down" },
            s.cwd.as_deref().unwrap_or("(no cwd registered)"),
        );
    }
    Ok(())
}

/// v0.5.19: `wire session list-local` — sister-session discovery.
///
/// For each on-disk session, read its `relay-state.json` and surface
/// the ones that have a Local-scope endpoint (allocated via
/// `wire session new --with-local`). Group by the local-relay URL so
/// the operator can see at a glance which sessions are mutually
/// reachable over the same loopback relay.
///
/// Read-only, no daemon contact. Useful as the prelude to teaming /
/// pairing same-box sister claudes (see also `wire session
/// pair-all-local` once implemented).
pub(super) fn cmd_session_list_local(as_json: bool) -> Result<()> {
    let listing = crate::session::list_local_sessions()?;
    if as_json {
        println!("{}", serde_json::to_string(&listing)?);
        return Ok(());
    }

    if listing.local.is_empty() && listing.federation_only.is_empty() {
        println!(
            "no sessions on this machine. `wire session new --with-local` to create one \
             with a local-relay endpoint (start the relay first: \
             `wire relay-server --bind 127.0.0.1:8771 --local-only`)."
        );
        return Ok(());
    }

    if listing.local.is_empty() {
        println!(
            "no sister sessions reachable via a local relay. \
             Re-run `wire session new --with-local` to add a Local endpoint, or \
             start a local relay with `wire relay-server --bind 127.0.0.1:8771 --local-only`."
        );
    } else {
        // Stable iteration order: sort the relay URLs.
        let mut keys: Vec<&String> = listing.local.keys().collect();
        keys.sort();
        for relay_url in keys {
            let group = &listing.local[relay_url];
            println!("LOCAL RELAY: {relay_url}");
            println!("  {:<24} {:<32} {:<10} CWD", "NAME", "HANDLE", "DAEMON");
            for s in group {
                println!(
                    "  {:<24} {:<32} {:<10} {}",
                    s.name,
                    s.handle.as_deref().unwrap_or("?"),
                    if s.daemon_running { "running" } else { "down" },
                    s.cwd.as_deref().unwrap_or("(no cwd registered)"),
                );
            }
            println!();
        }
    }

    if !listing.federation_only.is_empty() {
        println!("federation-only (no local endpoint):");
        for s in &listing.federation_only {
            println!(
                "  {:<24} {:<32} {}",
                s.name,
                s.handle.as_deref().unwrap_or("?"),
                s.cwd.as_deref().unwrap_or("(no cwd registered)"),
            );
        }
    }
    Ok(())
}

/// v0.6.0 (issue #12): orchestrate bilateral pair across every sister
/// session that has a Local-scope endpoint. Skips already-paired
/// pairs; reports a per-pair outcome JSON suitable for scripting.
///
/// Same-uid trust anchor: the caller owns every session enumerated by
/// `list_local_sessions`, so the operator running this command IS the
/// consent for both sides. The bilateral SAS / network-level handshake
/// assumes strangers; same-uid sister sessions are not strangers.
///
/// Per-pair flow (sequential to keep relay-side load + log clarity):
///   1. WIRE_HOME=A wire add <B-handle>@<host>  (writes pending-inbound on B)
///   2. WIRE_HOME=A wire push --json            (sends pair_drop to relay)
///   3. sleep settle_secs                       (pair_drop reaches B)
///   4. WIRE_HOME=B wire pull --json            (B receives pair_drop)
///   5. WIRE_HOME=B wire accept <A-bare>   (B pins A, sends ack)
///   6. WIRE_HOME=B wire push --json            (sends pair_drop_ack)
///   7. sleep settle_secs                       (ack reaches A)
///   8. WIRE_HOME=A wire pull --json            (A pins B)
pub(super) fn cmd_session_pair_all_local(
    settle_secs: u64,
    federation_relay: &str,
    as_json: bool,
) -> Result<()> {
    use std::collections::BTreeSet;
    use std::time::Duration;

    let listing = crate::session::list_local_sessions()?;
    // Flatten + dedup by session NAME (same session can appear under
    // multiple local-relay URLs if it advertises two local endpoints;
    // rare, but pair each pair exactly once).
    let mut by_name: std::collections::BTreeMap<String, crate::session::LocalSessionView> =
        Default::default();
    for group in listing.local.into_values() {
        for s in group {
            by_name.entry(s.name.clone()).or_insert(s);
        }
    }
    let sessions: Vec<crate::session::LocalSessionView> = by_name.into_values().collect();

    if sessions.len() < 2 {
        let msg = format!(
            "{} sister session(s) with a local endpoint — need at least 2 to pair.",
            sessions.len()
        );
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "sessions": sessions.iter().map(|s| &s.name).collect::<Vec<_>>(),
                    "pairs_attempted": 0,
                    "pairs_succeeded": 0,
                    "pairs_skipped_already_paired": 0,
                    "pairs_failed": 0,
                    "note": msg,
                }))?
            );
        } else {
            println!("{msg}");
            if let Some(s) = sessions.first() {
                println!("  - {} ({})", s.name, s.cwd.as_deref().unwrap_or("?"));
            }
            println!("Use `wire session new --with-local` to add more.");
        }
        return Ok(());
    }

    let fed_host = super::host_of_url(federation_relay);
    if fed_host.is_empty() {
        bail!(
            "federation_relay `{federation_relay}` has no parseable host — \
             pass a full URL like `https://wireup.net`."
        );
    }

    // Enumerate unordered pairs deterministically by session name.
    let mut attempted = 0u32;
    let mut succeeded = 0u32;
    let mut skipped_already = 0u32;
    let mut failed = 0u32;
    let mut per_pair: Vec<Value> = Vec::new();

    for i in 0..sessions.len() {
        for j in (i + 1)..sessions.len() {
            let a = &sessions[i];
            let b = &sessions[j];
            attempted += 1;

            // Already-paired check: if A's relay-state has B's CARD
            // HANDLE in peers AND vice versa, skip. v0.11: peer keys
            // are character handles (not session names), so we use
            // each side's handle field (already on the LocalSessionView)
            // for the lookup rather than the session name.
            let a_handle = a.handle.as_deref().unwrap_or(a.name.as_str());
            let b_handle = b.handle.as_deref().unwrap_or(b.name.as_str());
            let a_pinned_b = super::session_has_peer(&a.home_dir, b_handle);
            let b_pinned_a = super::session_has_peer(&b.home_dir, a_handle);
            if a_pinned_b && b_pinned_a {
                skipped_already += 1;
                per_pair.push(json!({
                    "from": a.name,
                    "to": b.name,
                    "status": "already_paired",
                }));
                continue;
            }

            let pair_result = drive_bilateral_pair(
                &a.home_dir,
                &a.name,
                &b.home_dir,
                &b.name,
                &fed_host,
                federation_relay,
                settle_secs,
            );

            match pair_result {
                Ok(()) => {
                    succeeded += 1;
                    per_pair.push(json!({
                        "from": a.name,
                        "to": b.name,
                        "status": "paired",
                    }));
                }
                Err(e) => {
                    failed += 1;
                    let detail = format!("{e:#}");
                    per_pair.push(json!({
                        "from": a.name,
                        "to": b.name,
                        "status": "failed",
                        "error": detail,
                    }));
                }
            }

            // Brief settle between pairs so we don't slam the relay
            // with N(N-1) parallel requests.
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    let _ = BTreeSet::<String>::new(); // silence unused-import lint if any
    let summary = json!({
        "sessions": sessions.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
        "pairs_attempted": attempted,
        "pairs_succeeded": succeeded,
        "pairs_skipped_already_paired": skipped_already,
        "pairs_failed": failed,
        "results": per_pair,
    });
    if as_json {
        println!("{}", serde_json::to_string(&summary)?);
    } else {
        println!(
            "wire session pair-all-local: {} session(s), {} pair(s) attempted",
            sessions.len(),
            attempted
        );
        println!("  paired:                 {succeeded}");
        println!("  skipped (already pinned): {skipped_already}");
        println!("  failed:                 {failed}");
        for entry in summary["results"].as_array().unwrap_or(&vec![]) {
            let from = entry["from"].as_str().unwrap_or("?");
            let to = entry["to"].as_str().unwrap_or("?");
            let status = entry["status"].as_str().unwrap_or("?");
            let err = entry.get("error").and_then(Value::as_str).unwrap_or("");
            if err.is_empty() {
                println!("  {from:<24} ↔ {to:<24} {status}");
            } else {
                println!("  {from:<24} ↔ {to:<24} {status} — {err}");
            }
        }
    }
    Ok(())
}

/// Drive one bilateral pair handshake between two sister sessions
/// using their session home dirs as `WIRE_HOME`. Sequential 8-step
/// flow so failures bubble up at the offending step, not buried in
/// a parallel race. See `cmd_session_pair_all_local` docstring.
///
/// v0.6.6: step 1 (the `wire add`) uses `--local-sister` instead of
/// federation `.well-known/wire/agent` resolution. Reads B's card +
/// endpoints directly off disk under `b_home` and pins them. This
/// makes pair-all-local work for sister sessions whose federation
/// handle is unclaimable (reserved nicks like `wire` / `slancha`) and
/// for sessions created with `wire session new --local-only`
/// (no federation slot at all). The `_federation_relay` / `_fed_host`
/// parameters are retained for callers that want to log them but
/// the handshake itself no longer touches federation.
fn drive_bilateral_pair(
    a_home: &std::path::Path,
    a_name: &str,
    b_home: &std::path::Path,
    b_name: &str,
    _fed_host: &str,
    _federation_relay: &str,
    settle_secs: u64,
) -> Result<()> {
    use std::time::Duration;
    let bin = std::env::current_exe().context("locating self exe")?;

    let run = |home: &std::path::Path, args: &[&str]| -> Result<()> {
        let out = std::process::Command::new(&bin)
            .env("WIRE_HOME", home)
            .env_remove("RUST_LOG")
            .args(args)
            .output()
            .with_context(|| format!("spawning `wire {}`", args.join(" ")))?;
        if !out.status.success() {
            bail!(
                "`wire {}` failed: stderr={}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    };

    // v0.11: each session's agent-card.handle is the DID-derived
    // character, not the session name. wire-accept lookups key on the
    // CARD HANDLE, so we discover each side's canonical handle from
    // its agent-card on disk before driving the pair flow.
    let read_card_handle = |home: &std::path::Path| -> Result<String> {
        let card_path = home.join("config").join("wire").join("agent-card.json");
        let bytes = std::fs::read(&card_path)
            .with_context(|| format!("reading agent-card at {card_path:?}"))?;
        let card: Value = serde_json::from_slice(&bytes)?;
        card.get("handle")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("agent-card at {card_path:?} missing `handle` field"))
    };
    let a_handle = read_card_handle(a_home)
        .with_context(|| format!("session {a_name} (a): read agent-card.handle"))?;
    let b_handle = read_card_handle(b_home)
        .with_context(|| format!("session {b_name} (b): read agent-card.handle"))?;

    // 1. A initiates via --local-sister (uses the session NAME for
    // the registry lookup; cmd_add_local_sister auto-resolves
    // session→handle internally).
    run(a_home, &["add", b_name, "--local-sister", "--json"])
        .with_context(|| format!("step 1/8: {a_name} `wire add {b_name} --local-sister`"))?;

    // 3. settle so pair_drop reaches B's slot
    std::thread::sleep(Duration::from_secs(settle_secs));

    // 4. B pulls pair_drop → 5. B accept (pins A by CARD HANDLE,
    // not by session name — under v0.11 these differ) → 6. B push ack
    run(b_home, &["pull", "--json"]).with_context(|| format!("step 4/8: {b_name} `wire pull`"))?;
    run(b_home, &["accept", &a_handle, "--json"]).with_context(|| {
        format!("step 5/8: {b_name} `wire accept {a_handle}` (a session={a_name})")
    })?;
    run(b_home, &["push", "--json"]).with_context(|| format!("step 6/8: {b_name} `wire push`"))?;

    // 7. settle so ack reaches A's slot
    std::thread::sleep(Duration::from_secs(settle_secs));

    // 8. A pulls ack (pins B by CARD HANDLE)
    run(a_home, &["pull", "--json"]).with_context(|| format!("step 8/8: {a_name} `wire pull`"))?;
    // suppress unused warning when both handles are consumed
    let _ = &b_handle;

    Ok(())
}

pub(super) fn cmd_session_env(name_arg: Option<&str>, as_json: bool) -> Result<()> {
    let name = resolve_session_name(name_arg)?;
    let session_home = crate::session::session_dir(&name)?;
    if !session_home.exists() {
        bail!(
            "no session named {name:?} on this machine. `wire session list` to enumerate, \
             `wire session new {name}` to create."
        );
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "name": name,
                "home_dir": session_home.to_string_lossy(),
                "export": format!("export WIRE_HOME={}", session_home.to_string_lossy()),
            }))?
        );
    } else {
        println!("export WIRE_HOME={}", session_home.to_string_lossy());
    }
    Ok(())
}

pub(super) fn cmd_session_current(as_json: bool) -> Result<()> {
    let cwd = std::env::current_dir().with_context(|| "reading cwd")?;
    let registry = crate::session::read_registry().unwrap_or_default();
    let cwd_key = crate::session::normalize_cwd_key(&cwd);
    // Backward-compat: O(n) normalized scan on read-miss. Mirrors the
    // same pattern in session::derive_name_from_cwd /
    // detect_session_wire_home — handles both consistent-casing and
    // cross-casing upgraders (see session.rs for the full rationale).
    let name = registry
        .by_cwd
        .get(&cwd_key)
        .or_else(|| {
            registry
                .by_cwd
                .iter()
                .find(|(k, _)| {
                    crate::session::normalize_cwd_key(std::path::Path::new(k)) == cwd_key
                })
                .map(|(_, v)| v)
        })
        .cloned();
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "cwd": cwd_key,
                "session": name,
            }))?
        );
    } else if let Some(n) = name {
        println!("{n}");
    } else {
        println!("(no session registered for this cwd)");
    }
    Ok(())
}

pub(super) fn cmd_session_destroy(name_arg: &str, force: bool, as_json: bool) -> Result<()> {
    let name = crate::session::sanitize_name(name_arg);
    let session_home = crate::session::session_dir(&name)?;
    if !session_home.exists() {
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "name": name,
                    "destroyed": false,
                    "reason": "no such session",
                }))?
            );
        } else {
            println!("no session named {name:?} — nothing to destroy.");
        }
        return Ok(());
    }
    if !force {
        bail!(
            "destroying session {name:?} would delete its keypair + state irrecoverably. \
             Pass --force to confirm."
        );
    }

    // Kill the session-local daemon if alive.
    let pidfile = session_home.join("state").join("wire").join("daemon.pid");
    if let Ok(bytes) = std::fs::read(&pidfile) {
        let pid: Option<u32> = if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            v.get("pid").and_then(|p| p.as_u64()).map(|p| p as u32)
        } else {
            String::from_utf8_lossy(&bytes).trim().parse::<u32>().ok()
        };
        if let Some(p) = pid {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &p.to_string()])
                .output();
        }
    }

    std::fs::remove_dir_all(&session_home)
        .with_context(|| format!("removing session dir {session_home:?}"))?;

    // Strip from registry.
    let mut registry = crate::session::read_registry().unwrap_or_default();
    registry.by_cwd.retain(|_, v| v != &name);
    crate::session::write_registry(&registry)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "name": name,
                "destroyed": true,
            }))?
        );
    } else {
        println!("destroyed session {name:?}.");
    }
    Ok(())
}

#[cfg(test)]
mod coerce_object_root_tests {
    use super::coerce_object_root;
    use serde_json::json;

    #[test]
    fn non_object_roots_are_coerced_to_empty_object() {
        for mut corrupt in [
            json!([]),
            json!("corrupt"),
            json!(42),
            serde_json::Value::Null,
        ] {
            coerce_object_root(&mut corrupt);
            assert!(corrupt.is_object(), "root not coerced: {corrupt}");
        }
    }

    #[test]
    fn object_root_is_left_untouched() {
        let mut state = json!({"self": {"endpoints": [1, 2]}});
        coerce_object_root(&mut state);
        assert_eq!(state, json!({"self": {"endpoints": [1, 2]}}));
    }
}
