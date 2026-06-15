//! HTTP client for `wire-relay-server`.
//!
//! Sync wrapper around `reqwest::blocking` so CLI commands stay synchronous —
//! the only async surface in the crate is `relay_server::serve`. Async clients
//! land in v0.2 if a long-running daemon needs them.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Clone)]
pub struct RelayClient {
    base_url: String,
    client: reqwest::blocking::Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AllocateResponse {
    pub slot_id: String,
    pub slot_token: String,
}

#[derive(Debug, Deserialize)]
pub struct PostEventResponse {
    pub event_id: Option<String>,
    pub status: String,
}

/// RFC-003 §2 DNS-TXT binding anchor. `_wire-org.<domain>` records use the
/// same field grammar for org-tier (`did:wire:org:*`) and personal-tier
/// (`did:wire:op:*`) deployments; receivers dispatch on the DID prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireOrgTxtDid {
    Org(String),
    Op(String),
}

impl WireOrgTxtDid {
    pub fn as_str(&self) -> &str {
        match self {
            WireOrgTxtDid::Org(did) | WireOrgTxtDid::Op(did) => did,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireOrgTxtRecord {
    pub did: WireOrgTxtDid,
    pub relay: Option<String>,
    pub sso_iss: Option<String>,
    pub sso_tenant: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireOrgTxtParseError {
    #[error("DNS-TXT record missing required `did=` field")]
    MissingDid,
    #[error("DNS-TXT record missing required `v=` field")]
    MissingVersion,
    #[error("unsupported DNS-TXT record version `{0}`")]
    UnsupportedVersion(String),
    #[error("`did=` must be did:wire:org:* or did:wire:op:* with a long fingerprint suffix")]
    InvalidDid(String),
    #[error("duplicate DNS-TXT field `{0}`")]
    DuplicateField(&'static str),
    #[error("malformed DNS-TXT field `{0}`")]
    MalformedField(String),
}

/// Parse the field grammar used by RFC-003 §2:
///
/// `_wire-org.<domain> TXT "did=<wire-DID>; relay=<url>; sso_iss=<iss>; sso_tenant=<tenant>; v=1"`
///
/// Field-additive evolution rule: at known `v=1`, unknown fields are ignored
/// so future records remain forward-compatible. Unknown `v` values are rejected
/// at parse time because they may change existing-field semantics.
pub fn parse_wire_org_txt_record(record: &str) -> Result<WireOrgTxtRecord, WireOrgTxtParseError> {
    let trimmed = record.trim();
    let body = trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed);

    let mut did: Option<String> = None;
    let mut version: Option<String> = None;
    let mut relay: Option<String> = None;
    let mut sso_iss: Option<String> = None;
    let mut sso_tenant: Option<String> = None;

    fn set_once(
        slot: &mut Option<String>,
        field: &'static str,
        value: &str,
    ) -> Result<(), WireOrgTxtParseError> {
        if slot.is_some() {
            return Err(WireOrgTxtParseError::DuplicateField(field));
        }
        *slot = Some(value.trim().to_string());
        Ok(())
    }

    for raw in body.split(';') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let Some((key, value)) = raw.split_once('=') else {
            return Err(WireOrgTxtParseError::MalformedField(raw.to_string()));
        };
        match key.trim() {
            "did" => set_once(&mut did, "did", value)?,
            "v" => set_once(&mut version, "v", value)?,
            "relay" => set_once(&mut relay, "relay", value)?,
            "sso_iss" => set_once(&mut sso_iss, "sso_iss", value)?,
            "sso_tenant" => set_once(&mut sso_tenant, "sso_tenant", value)?,
            _ => {
                // RFC-003 §2 / RFC-001 §A: field-additive evolution at a
                // known version. Unknown fields are opaque, not fatal.
            }
        }
    }

    let version = version.ok_or(WireOrgTxtParseError::MissingVersion)?;
    if version != "1" {
        return Err(WireOrgTxtParseError::UnsupportedVersion(version));
    }

    let did = did.ok_or(WireOrgTxtParseError::MissingDid)?;
    let did = if crate::agent_card::is_org_did(&did) {
        WireOrgTxtDid::Org(did)
    } else if crate::agent_card::is_op_did(&did) {
        WireOrgTxtDid::Op(did)
    } else {
        return Err(WireOrgTxtParseError::InvalidDid(did));
    };

    Ok(WireOrgTxtRecord {
        did,
        relay,
        sso_iss,
        sso_tenant,
    })
}

/// Env var: when set to a truthy value (`1`, `true`, `yes`), every TLS
/// verification check on every wire HTTPS client is disabled. Intended
/// as an emergency-only operator override for environments behind a
/// TLS-intercepting middlebox (corporate proxy, AV product like Avast
/// re-signing certs with its own root, captive portal). Prints a loud
/// stderr banner on every send when active. **Do not set this in
/// production.** Documented in THREAT_MODEL.md + README.
pub const INSECURE_SKIP_TLS_ENV: &str = "WIRE_INSECURE_SKIP_TLS_VERIFY";

fn insecure_skip_tls_verify() -> bool {
    matches!(
        std::env::var(INSECURE_SKIP_TLS_ENV)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// v0.5.13: emit the loud-fail banner exactly once per process so we
/// don't spam a hundred lines per `wire push`. Per-process `OnceLock`
/// guards the emission. The banner goes to stderr; never stdout (we
/// must not corrupt the `--json` machine-readable contract).
fn maybe_emit_insecure_banner() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if insecure_skip_tls_verify() {
        ONCE.get_or_init(|| {
            eprintln!(
                "\x1b[1;31mwire: WARNING\x1b[0m {INSECURE_SKIP_TLS_ENV}=1 is set; TLS verification is DISABLED for all relay traffic. \
                 MITM attacks against the relay path are undetectable in this mode. Unset to restore default trust validation."
            );
        });
    }
}

/// Centralized builder for blocking HTTPS clients across wire. Uses
/// rustls + Mozilla webpki-roots bundled CA set
/// (`rustls-tls-webpki-roots` reqwest feature). Honors the
/// [`INSECURE_SKIP_TLS_ENV`] escape hatch for the corporate-proxy
/// emergency case.
///
/// v0.14.2: previously this used `rustls-tls-native-roots` (native OS
/// trust store via `rustls-native-certs`) so corp CAs / AV-resign
/// products validated transparently. That broke catastrophically when
/// #170's `--all-sessions` supervisor moved wire daemons into launchd:
/// launchd-spawned processes don't inherit the user's Aqua session
/// keychain context on macOS, so `rustls-native-certs` returned zero
/// roots → every wireup.net request failed with "UnknownIssuer" and
/// the daemon silently no-op'd push/pull (84 events queued, 0 pushed,
/// SSE stream errored on every reconnect). Same binary worked fine
/// from a shell because the operator's Aqua session had keychain
/// access.
///
/// Switching to bundled webpki-roots removes the OS dependency at the
/// cost of corp CA support; operators behind a corporate proxy that
/// resigns certs should set `WIRE_INSECURE_SKIP_TLS_VERIFY=1`. A
/// proper dual-roots verifier (native + webpki via
/// `rustls-platform-verifier`) is filed for follow-up.
pub fn build_blocking_client(
    timeout: Option<std::time::Duration>,
) -> Result<reqwest::blocking::Client> {
    let mut b = reqwest::blocking::Client::builder();
    if let Some(t) = timeout {
        b = b.timeout(t);
    }
    if insecure_skip_tls_verify() {
        maybe_emit_insecure_banner();
        b = b.danger_accept_invalid_certs(true);
    } else {
        // v0.14.2 #177: dual-roots TLS — webpki bundled + OS native
        // when accessible (corp CAs / AV-resign / on-prem). Replaces
        // #176's webpki-only emergency fallback. See `tls.rs` for
        // the why.
        let cfg = crate::tls::shared_client_config();
        b = b.use_preconfigured_tls((*cfg).clone());
    }
    b.build()
        .with_context(|| "constructing reqwest blocking client")
}

/// Flatten an `anyhow::Error` source chain into a single human-readable
/// transport-error line for the `reason` field in `wire push --json` and
/// for stderr surfaces. Classifies the topmost cause (`TLS error`,
/// `DNS error`, `connect timeout`, `read timeout`, `HTTP error`) so a
/// silent failure no longer leaks past the user as a bare URL.
///
/// v0.5.13 rule 1 of the network-resilience doctrine — see issue #6.
pub fn format_transport_error(err: &anyhow::Error) -> String {
    let mut parts: Vec<String> = err.chain().map(|c| c.to_string()).collect();
    // Heuristic classification — search the chain for the lowest-level
    // descriptor and prefix the message so the reader sees the kind
    // even when the topmost context is just the URL.
    let lower = parts
        .iter()
        .map(|p| p.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let class = if lower.iter().any(|p| {
        p.contains("invalid peer certificate")
            || p.contains("certificate verification")
            || p.contains("unknownissuer")
            || p.contains("certificate is not valid")
            || p.contains("tls handshake")
    }) {
        Some("TLS error")
    } else if lower.iter().any(|p| {
        p.contains("dns error")
            || p.contains("nodename nor servname")
            || p.contains("failed to lookup address")
    }) {
        Some("DNS error")
    } else if lower
        .iter()
        .any(|p| p.contains("operation timed out") || p.contains("deadline has elapsed"))
    {
        Some("timeout")
    } else if lower
        .iter()
        .any(|p| p.contains("connection refused") || p.contains("connection reset"))
    {
        Some("connect error")
    } else {
        None
    };
    if let Some(c) = class {
        parts.insert(0, c.to_string());
    }
    parts.join(": ")
}

/// v0.7.0-alpha.17: minimal blocking HTTP/1.1 client over Unix Domain
/// Socket. Used by callers that detect a `unix://` scheme on a relay
/// endpoint URL and route around reqwest (which has no UDS support).
///
/// Connects to `socket_path`, writes a single HTTP/1.1 request, parses
/// status + Content-Length + body. Closes the connection (no keep-
/// alive). Sufficient for wire's request shape: single POST or GET per
/// call, JSON in + JSON out, small payloads.
///
/// Returns `(status_code, body_bytes)`. Caller decodes body per the
/// endpoint's content type.
#[cfg(unix)]
pub fn uds_request(
    socket_path: &std::path::Path,
    method: &str,
    request_target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u16, Vec<u8>)> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let mut stream =
        UnixStream::connect(socket_path).with_context(|| format!("connect UDS {socket_path:?}"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let mut req = String::with_capacity(256 + headers.len() * 32 + body.len());
    req.push_str(method);
    req.push(' ');
    req.push_str(request_target);
    req.push_str(" HTTP/1.1\r\n");
    req.push_str("Host: localhost\r\n");
    req.push_str("Connection: close\r\n");
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    for (k, v) in headers {
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    // Parse HTTP/1.1 response: status line + headers + \r\n\r\n + body.
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("UDS response missing header/body delimiter"))?;
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|e| anyhow!("UDS response head not UTF-8: {e}"))?;
    let body = raw[split + 4..].to_vec();
    let status_line = head.lines().next().unwrap_or("");
    // "HTTP/1.1 200 OK"
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("UDS response missing status code: {status_line:?}"))?;
    Ok((status, body))
}

/// v0.7.0-alpha.19: scheme-aware POST helper that dispatches to either
/// reqwest (for `http(s)://...`) OR the hand-rolled `uds_request` (for
/// `unix:///path/to/sock`). Lets the daemon + cmd_send walk a peer's
/// pinned endpoints uniformly without each call site having to detect
/// scheme + branch.
///
/// Used by the routing layer to send signed events to a peer's slot
/// regardless of which transport scope the peer is reachable on. UDS
/// path uses the alpha.17 client; TCP path uses the existing
/// RelayClient::post_event flow.
pub fn post_event_to_endpoint(
    endpoint: &crate::endpoints::Endpoint,
    event: &Value,
) -> Result<PostEventResponse> {
    #[cfg(unix)]
    if let Some(socket_path) = endpoint.relay_url.strip_prefix("unix://") {
        let body = serde_json::json!({"event": event}).to_string();
        let auth_header = format!("Bearer {}", endpoint.slot_token);
        let (status, body) = uds_request(
            std::path::Path::new(socket_path),
            "POST",
            &format!("/v1/events/{}", endpoint.slot_id),
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &auth_header),
            ],
            body.as_bytes(),
        )?;
        if !(200..300).contains(&status) {
            // Format constraint: `cli::error_smells_like_slot_4xx` parses
            // this error string to gate slot-rotation re-resolves. It
            // matches `<status>` as a whole token bordered by space/colon
            // (see issue #69). The current shape `: {status}: {body}`
            // satisfies that — if you wrap the status differently
            // (commas/brackets, `status=410`, JSON-encode it), update
            // `error_smells_like_slot_4xx` in lockstep and add the new
            // shape to its `slot_reresolve_tests` cases or peer slot
            // rotations will silently stop auto-recovering.
            return Err(anyhow!(
                "post_event (uds {socket_path}) failed: {status}: {}",
                String::from_utf8_lossy(&body)
            ));
        }
        return Ok(serde_json::from_slice(&body)?);
    }
    let client = RelayClient::new(&endpoint.relay_url);
    client.post_event(&endpoint.slot_id, &endpoint.slot_token, event)
}

/// Try posting `event` to each endpoint in priority order; return the first
/// success. Generic over the poster so tests can inject a deterministic mock
/// without spinning up an HTTP server. In production callers pass
/// `post_event_to_endpoint`.
///
/// Bug 2 (P1, federation reachability) this implements: before this helper,
/// the bilateral-pair ack path (`send_pair_drop_ack`) only ever POSTed to the
/// FIRST endpoint in the peer's card. A peer whose first endpoint 4xx'd (e.g.
/// the userinfo-malformed URL surfaced in Bug 1) was unreachable even when
/// they advertised a perfectly good second endpoint. Surfaced when
/// `coral-weasel`'s `wire accept swift-harbor` 400'd on the malformed first
/// endpoint while a clean `https://wireup.net` endpoint sat behind it
/// untouched.
///
/// Failover ordering is the priority order supplied by the caller (typically
/// `peer_endpoints_in_priority_order` / `self_endpoints` — UDS / Local / LAN
/// / Federation, lowest-friction first), so this respects the existing
/// transport-preference contract.
///
/// Returns `Ok((endpoint, response))` on the first success — the caller can
/// log which endpoint actually accepted the event. Returns `Err` if and only
/// if every endpoint failed; the error string includes the per-endpoint
/// reasons so the operator can diagnose without re-tracing.
pub fn try_post_event_with_failover<F>(
    endpoints: &[crate::endpoints::Endpoint],
    event: &Value,
    mut poster: F,
) -> Result<(crate::endpoints::Endpoint, PostEventResponse)>
where
    F: FnMut(&crate::endpoints::Endpoint, &Value) -> Result<PostEventResponse>,
{
    if endpoints.is_empty() {
        bail!(
            "no endpoints to deliver to — peer has no pinned endpoints in relay_state. \
             Re-run the pair flow (or `wire dial <peer>@<relay>`) to re-pin the peer's \
             advertised endpoints."
        );
    }
    let mut errs: Vec<String> = Vec::with_capacity(endpoints.len());
    for ep in endpoints {
        match poster(ep, event) {
            Ok(resp) => return Ok((ep.clone(), resp)),
            Err(e) => errs.push(format!("{} ({:?}): {e}", ep.relay_url, ep.scope)),
        }
    }
    bail!(
        "all {n} endpoint(s) failed:\n  • {reasons}",
        n = endpoints.len(),
        reasons = errs.join("\n  • ")
    )
}

impl RelayClient {
    pub fn new(base_url: &str) -> Self {
        let client = build_blocking_client(Some(std::time::Duration::from_secs(30)))
            .expect("reqwest client construction is infallible with rustls + native roots");
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Allocate a fresh slot. Returns `(slot_id, slot_token)` — caller MUST
    /// persist `slot_token` somewhere safe (mode 0600 file); it grants both
    /// read and write access to the slot.
    pub fn allocate_slot(&self, handle_hint: Option<&str>) -> Result<AllocateResponse> {
        let body = serde_json::json!({"handle": handle_hint});
        let resp = self
            .client
            .post(format!("{}/v1/slot/allocate", self.base_url))
            .json(&body)
            .send()
            .with_context(|| format!("POST {}/v1/slot/allocate", self.base_url))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("allocate failed: {status}: {detail}"));
        }
        Ok(resp.json()?)
    }

    /// POST a signed event to a slot. Caller passes the slot's bearer token
    /// (the relay model in v0.1 is "shared slot token between paired peers" —
    /// see iter 9 SPAKE2 for how this token gets exchanged).
    pub fn post_event(
        &self,
        slot_id: &str,
        slot_token: &str,
        event: &Value,
    ) -> Result<PostEventResponse> {
        let body = serde_json::json!({"event": event});
        let resp = self
            .client
            .post(format!("{}/v1/events/{slot_id}", self.base_url))
            .bearer_auth(slot_token)
            .json(&body)
            .send()
            .with_context(|| format!("POST {}/v1/events/{slot_id}", self.base_url))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            // Format constraint: `cli::error_smells_like_slot_4xx` parses
            // this error string to gate slot-rotation re-resolves. It
            // matches `<status>` as a whole token bordered by space/colon
            // (see issue #69) — `reqwest::StatusCode` Display gives
            // `"410 Gone"` which satisfies that. If you change the
            // wrapping (commas/brackets, `status=410`, JSON-encode it),
            // update `error_smells_like_slot_4xx` in lockstep and add the
            // new shape to its `slot_reresolve_tests` cases or peer slot
            // rotations will silently stop auto-recovering.
            return Err(anyhow!("post_event failed: {status}: {detail}"));
        }
        Ok(resp.json()?)
    }

    /// GET events from a slot. `since` is an event_id cursor (exclusive); pass
    /// `None` for the full slot snapshot. `limit` defaults to 100, max 1000.
    pub fn list_events(
        &self,
        slot_id: &str,
        slot_token: &str,
        since: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<Value>> {
        let mut url = format!("{}/v1/events/{slot_id}", self.base_url);
        let mut sep = '?';
        if let Some(s) = since {
            url.push(sep);
            url.push_str(&format!("since={s}"));
            sep = '&';
        }
        if let Some(n) = limit {
            url.push(sep);
            url.push_str(&format!("limit={n}"));
        }
        let resp = self
            .client
            .get(&url)
            .bearer_auth(slot_token)
            .send()
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("list_events failed: {status}: {detail}"));
        }
        Ok(resp.json()?)
    }

    /// R4 — probe slot attentiveness. Returns `(event_count, last_pull_at_unix)`
    /// — the relay's view of the slot's owner's most recent poll. `None` for
    /// `last_pull_at_unix` means the slot has not been pulled since relay
    /// restart. Best-effort: any HTTP failure returns `Ok((0, None))` so the
    /// caller's pre-flight check degrades to "no signal" rather than abort.
    pub fn slot_state(&self, slot_id: &str, slot_token: &str) -> Result<(usize, Option<u64>)> {
        let url = format!("{}/v1/slot/{slot_id}/state", self.base_url);
        let resp = match self.client.get(&url).bearer_auth(slot_token).send() {
            Ok(r) => r,
            Err(_) => return Ok((0, None)),
        };
        if !resp.status().is_success() {
            return Ok((0, None));
        }
        let v: Value = resp.json().unwrap_or(Value::Null);
        let count = v.get("event_count").and_then(Value::as_u64).unwrap_or(0) as usize;
        let last = v.get("last_pull_at_unix").and_then(Value::as_u64);
        Ok((count, last))
    }

    pub fn responder_health_set(
        &self,
        slot_id: &str,
        slot_token: &str,
        record: &Value,
    ) -> Result<Value> {
        let resp = self
            .client
            .post(format!(
                "{}/v1/slot/{slot_id}/responder-health",
                self.base_url
            ))
            .bearer_auth(slot_token)
            .json(record)
            .send()
            .with_context(|| {
                format!("POST {}/v1/slot/{slot_id}/responder-health", self.base_url)
            })?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("responder_health_set failed: {status}: {detail}"));
        }
        Ok(resp.json()?)
    }

    pub fn responder_health_get(&self, slot_id: &str, slot_token: &str) -> Result<Value> {
        let resp = self
            .client
            .get(format!("{}/v1/slot/{slot_id}/state", self.base_url))
            .bearer_auth(slot_token)
            .send()
            .with_context(|| format!("GET {}/v1/slot/{slot_id}/state", self.base_url))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("responder_health_get failed: {status}: {detail}"));
        }
        let state: Value = resp.json()?;
        Ok(state
            .get("responder_health")
            .cloned()
            .unwrap_or(Value::Null))
    }

    pub fn healthz(&self) -> Result<bool> {
        let resp = self
            .client
            .get(format!("{}/healthz", self.base_url))
            .send()?;
        Ok(resp.status().is_success())
    }

    /// Healthz pre-flight that surfaces the underlying reqwest error in its
    /// own message. Use at every "is the relay reachable before we mutate
    /// state" site. The three possible failure modes (network error, 5xx
    /// from a reachable host, healthy) each get a distinct diagnostic line.
    pub fn check_healthz(&self) -> anyhow::Result<()> {
        match self.healthz() {
            Ok(true) => Ok(()),
            Ok(false) => anyhow::bail!(
                "phyllis: silent line — {}/healthz returned non-200.\n\
                 the host is reachable but the relay isn't returning ok. test:\n  \
                 curl -v {}/healthz",
                self.base_url,
                self.base_url
            ),
            Err(e) => anyhow::bail!(
                "phyllis: silent line — couldn't reach {}/healthz: {e:#}.\n\
                 test reachability from this machine:\n  curl -v {}/healthz\n\
                 if curl also fails, a sandbox / proxy / firewall is the usual cause.\n\
                 (OpenShell sandbox? run `curl -fsSL https://wireup.net/openshell-policy.sh | bash -s <sandbox-name>` on the host first.)",
                self.base_url,
                self.base_url
            ),
        }
    }

    /// Open or join a pair-slot. Returns the relay-assigned `pair_id`.
    /// `role` must be `"host"` or `"guest"`. The host calls first; the guest
    /// uses the same `code_hash` and finds the existing slot.
    pub fn pair_open(&self, code_hash: &str, msg_b64: &str, role: &str) -> Result<String> {
        let body = serde_json::json!({"code_hash": code_hash, "msg": msg_b64, "role": role});
        let resp = self
            .client
            .post(format!("{}/v1/pair", self.base_url))
            .json(&body)
            .send()?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("pair_open failed: {status}: {detail}"));
        }
        let v: Value = resp.json()?;
        v.get("pair_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("pair_open response missing pair_id"))
    }

    /// Forget the pair-slot at this code_hash on the relay. Either side can call;
    /// knowledge of the code is the only auth. Idempotent — succeeds even if the
    /// slot doesn't exist. Use after a client crash mid-handshake so the host
    /// doesn't stay locked out until TTL.
    pub fn pair_abandon(&self, code_hash: &str) -> Result<()> {
        let body = serde_json::json!({"code_hash": code_hash});
        let resp = self
            .client
            .post(format!("{}/v1/pair/abandon", self.base_url))
            .json(&body)
            .send()?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("pair_abandon failed: {status}: {detail}"));
        }
        Ok(())
    }

    /// Read peer's SPAKE2 message + (eventually) sealed bootstrap from a pair-slot.
    pub fn pair_get(
        &self,
        pair_id: &str,
        as_role: &str,
    ) -> Result<(Option<String>, Option<String>)> {
        let resp = self
            .client
            .get(format!(
                "{}/v1/pair/{pair_id}?as_role={as_role}",
                self.base_url
            ))
            .send()?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("pair_get failed: {status}: {detail}"));
        }
        let v: Value = resp.json()?;
        let peer_msg = v
            .get("peer_msg")
            .and_then(Value::as_str)
            .map(str::to_string);
        let peer_bootstrap = v
            .get("peer_bootstrap")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok((peer_msg, peer_bootstrap))
    }

    /// POST a sealed bootstrap payload to the pair-slot.
    pub fn pair_bootstrap(&self, pair_id: &str, role: &str, sealed_b64: &str) -> Result<()> {
        let body = serde_json::json!({"role": role, "sealed": sealed_b64});
        let resp = self
            .client
            .post(format!("{}/v1/pair/{pair_id}/bootstrap", self.base_url))
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            let s = resp.status();
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("pair_bootstrap failed: {s}: {detail}"));
        }
        Ok(())
    }

    /// Claim a `nick@<this-relay-domain>` handle (v0.5). Caller must hold
    /// the bearer token for `slot_id`. FCFS on nick; same-DID re-claims OK.
    ///
    /// Back-compat wrapper around `handle_claim_v2` that omits the
    /// `discoverable` field (relay defaults to discoverable on absence).
    pub fn handle_claim(
        &self,
        nick: &str,
        slot_id: &str,
        slot_token: &str,
        relay_url: Option<&str>,
        card: &Value,
    ) -> Result<Value> {
        self.handle_claim_v2(nick, slot_id, slot_token, relay_url, card, None)
    }

    /// v0.5.19 (#9.1) variant accepting the optional `discoverable`
    /// flag. `None` = relay default (= true, back-compat).
    /// `Some(false)` = opt out of `/v1/handles` bulk listing while
    /// keeping direct `.well-known/wire/agent` resolution working.
    /// Relays older than v0.5.19 ignore the field — safe to always send.
    pub fn handle_claim_v2(
        &self,
        nick: &str,
        slot_id: &str,
        slot_token: &str,
        relay_url: Option<&str>,
        card: &Value,
        discoverable: Option<bool>,
    ) -> Result<Value> {
        let mut body = serde_json::json!({
            "nick": nick,
            "slot_id": slot_id,
            "relay_url": relay_url,
            "card": card,
        });
        if let Some(d) = discoverable {
            body["discoverable"] = serde_json::json!(d);
        }
        let resp = self
            .client
            .post(format!("{}/v1/handle/claim", self.base_url))
            .bearer_auth(slot_token)
            .json(&body)
            .send()
            .with_context(|| format!("POST {}/v1/handle/claim", self.base_url))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("handle_claim failed: {status}: {detail}"));
        }
        Ok(resp.json()?)
    }

    /// `DELETE /v1/handle/claim/:nick` — release a claimed handle (#247.1).
    /// Owner-gated by the slot's bearer token.
    pub fn handle_unclaim(&self, nick: &str, slot_token: &str) -> Result<Value> {
        let resp = self
            .client
            .delete(format!("{}/v1/handle/claim/{nick}", self.base_url))
            .bearer_auth(slot_token)
            .send()
            .with_context(|| format!("DELETE {}/v1/handle/claim/{nick}", self.base_url))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("handle_unclaim failed: {status}: {detail}"));
        }
        Ok(resp.json()?)
    }

    /// POST an intro (zero-paste pair-drop) event to a known nick's slot
    /// without holding that slot's bearer token. Relay validates the event
    /// is kind=1100 with an embedded signed agent-card; otherwise refuses.
    pub fn handle_intro(&self, nick: &str, event: &Value) -> Result<Value> {
        let body = serde_json::json!({"event": event});
        let resp = self
            .client
            .post(format!("{}/v1/handle/intro/{nick}", self.base_url))
            .json(&body)
            .send()
            .with_context(|| format!("POST {}/v1/handle/intro/{nick}", self.base_url))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("handle_intro failed: {status}: {detail}"));
        }
        Ok(resp.json()?)
    }

    /// Resolve a handle on this relay via A2A v1.0 `.well-known/agent-card.json?handle=<nick>`.
    /// Returns the parsed AgentCard JSON. Wire-served relays embed wire-native
    /// fields (DID, slot_id, profile, raw card) under `extensions[0].params`.
    /// Foreign A2A agents return their A2A card without wire ext — useful for
    /// `wire whois` even when full mailbox pairing isn't possible.
    pub fn well_known_agent_card_a2a(&self, handle: &str) -> Result<Value> {
        let resp = self
            .client
            .get(format!("{}/.well-known/agent-card.json", self.base_url))
            .query(&[("handle", handle)])
            .send()
            .with_context(|| {
                format!(
                    "GET {}/.well-known/agent-card.json?handle={handle}",
                    self.base_url
                )
            })?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!(
                "well_known_agent_card_a2a failed: {status}: {detail}"
            ));
        }
        Ok(resp.json()?)
    }

    /// Resolve a handle on this relay via `.well-known/wire/agent?handle=<nick>`.
    /// Caller passes either the full `nick@domain` or just `<nick>` — the
    /// server only uses the local part.
    pub fn well_known_agent(&self, handle: &str) -> Result<Value> {
        let resp = self
            .client
            .get(format!("{}/.well-known/wire/agent", self.base_url))
            .query(&[("handle", handle)])
            .send()
            .with_context(|| {
                format!(
                    "GET {}/.well-known/wire/agent?handle={handle}",
                    self.base_url
                )
            })?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().unwrap_or_default();
            return Err(anyhow!("well_known_agent failed: {status}: {detail}"));
        }
        Ok(resp.json()?)
    }
}

#[cfg(all(test, unix))]
mod uds_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// Spawn a one-shot UDS HTTP/1.1 server that returns a canned
    /// response. Returns the socket path; cleanup is via drop of the
    /// tempdir the caller manages.
    fn spawn_canned_uds_server(socket_path: std::path::PathBuf, status: u16, body: &'static str) {
        let listener = UnixListener::bind(&socket_path).expect("bind canned UDS");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept canned UDS");
            // Read the FULL request (headers + Content-Length body), not a
            // single read(). `uds_request` writes headers and body in two
            // syscalls; a single read can wake between them, after which
            // responding + dropping the stream resets the client mid-write —
            // the `uds_request_round_trips_200_with_body` flake (4 hits).
            let mut req: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                req.extend_from_slice(&chunk[..n]);
                if let Some(split) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&req[..split]);
                    let content_length: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if req.len() >= split + 4 + content_length {
                        break;
                    }
                }
            }
            let body_bytes = body.as_bytes();
            let status_text = match status {
                200 => "OK",
                201 => "Created",
                400 => "Bad Request",
                _ => "Status",
            };
            let resp = format!(
                "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body_bytes.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        });
    }

    #[test]
    fn uds_request_round_trips_200_with_body() {
        let tmpdir = std::env::temp_dir().join(format!("wire-uds-test-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmpdir).unwrap();
        let sock = tmpdir.join("rt.sock");
        let _ = std::fs::remove_file(&sock);
        spawn_canned_uds_server(sock.clone(), 200, r#"{"ok":true}"#);
        // Give the server a moment to bind.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let (status, body) = uds_request(
            &sock,
            "POST",
            "/v1/test",
            &[("Content-Type", "application/json")],
            b"{}",
        )
        .expect("uds_request succeeds");
        assert_eq!(status, 200);
        assert_eq!(body, br#"{"ok":true}"#);
    }

    #[test]
    fn uds_request_surfaces_non_2xx_status() {
        let tmpdir = std::env::temp_dir().join(format!("wire-uds-test-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmpdir).unwrap();
        let sock = tmpdir.join("err.sock");
        let _ = std::fs::remove_file(&sock);
        spawn_canned_uds_server(sock.clone(), 400, r#"{"error":"bad"}"#);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let (status, body) = uds_request(&sock, "GET", "/v1/test", &[], b"")
            .expect("uds_request succeeds even on 4xx");
        assert_eq!(status, 400);
        assert_eq!(body, br#"{"error":"bad"}"#);
    }

    #[test]
    fn uds_request_fails_on_nonexistent_socket() {
        let nope = std::path::Path::new("/tmp/wire-uds-nonexistent-socket-aaa.sock");
        let _ = std::fs::remove_file(nope);
        let err = uds_request(nope, "GET", "/", &[], b"").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("connect UDS"),
            "expected connect error, got: {msg}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn url_normalization_trims_trailing_slash() {
        let c = RelayClient::new("http://example.com/");
        assert_eq!(c.base_url, "http://example.com");
        let c = RelayClient::new("http://example.com");
        assert_eq!(c.base_url, "http://example.com");
    }

    #[test]
    fn format_transport_error_classifies_tls() {
        // Simulate the Avast/corp-proxy class from issue #6: reqwest wraps
        // a rustls UnknownIssuer inside a hyper error inside a context URL.
        let inner = anyhow!("invalid peer certificate: UnknownIssuer");
        let middle: anyhow::Error = inner.context("hyper send");
        let top = middle.context("POST https://relay.example/v1/events/abc");
        let formatted = format_transport_error(&top);
        assert!(
            formatted.starts_with("TLS error:"),
            "expected TLS class prefix, got: {formatted}"
        );
        assert!(
            formatted.contains("UnknownIssuer"),
            "lost root cause: {formatted}"
        );
        assert!(
            formatted.contains("POST https://relay.example"),
            "lost context URL: {formatted}"
        );
    }

    #[test]
    fn format_transport_error_classifies_timeout() {
        let inner = anyhow!("operation timed out");
        let top = inner.context("POST https://relay.example/v1/events/abc");
        let formatted = format_transport_error(&top);
        assert!(formatted.starts_with("timeout:"), "got: {formatted}");
    }

    #[test]
    fn format_transport_error_classifies_dns() {
        let inner = anyhow!("dns error: failed to lookup address");
        let top = inner.context("POST https://relay.example/v1/events/abc");
        let formatted = format_transport_error(&top);
        assert!(formatted.starts_with("DNS error:"), "got: {formatted}");
    }

    #[test]
    fn format_transport_error_falls_back_to_chain_join() {
        // Unknown class → no prefix, just the joined chain. Behavior MUST
        // still surface every cause (this is the loud-fail invariant).
        let inner = anyhow!("Refused to connect for non-standard reason xyz");
        let top = inner.context("POST https://relay.example/v1/events/abc");
        let formatted = format_transport_error(&top);
        assert!(formatted.contains("Refused to connect"));
        assert!(formatted.contains("POST https://relay.example"));
    }

    #[test]
    fn insecure_env_recognizes_truthy_values_and_default_off() {
        // Process-global env var → must be one test, not two (otherwise
        // parallel cargo-test threads race). Single test owns the var's
        // lifecycle from "unset" through truthy values back to "unset".
        use std::sync::{Mutex, OnceLock};
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        let _lock = GUARD.get_or_init(|| Mutex::new(())).lock().unwrap();

        // SAFETY: env mutation here is serialized by the GUARD mutex;
        // other tests in this module do not touch INSECURE_SKIP_TLS_ENV.
        unsafe {
            std::env::remove_var(INSECURE_SKIP_TLS_ENV);
        }
        assert!(!insecure_skip_tls_verify(), "default must be secure");

        for v in ["1", "true", "yes", "on", "TRUE", "Yes"] {
            unsafe {
                std::env::set_var(INSECURE_SKIP_TLS_ENV, v);
            }
            assert!(insecure_skip_tls_verify(), "value {v:?} should be truthy");
        }
        // Falsy / unset round-trip back to secure.
        for v in ["0", "false", "no", "off", ""] {
            unsafe {
                std::env::set_var(INSECURE_SKIP_TLS_ENV, v);
            }
            assert!(
                !insecure_skip_tls_verify(),
                "value {v:?} must not enable insecure mode"
            );
        }
        unsafe {
            std::env::remove_var(INSECURE_SKIP_TLS_ENV);
        }
    }

    fn org_did() -> &'static str {
        "did:wire:org:example-0123456789abcdef0123456789abcdef"
    }

    fn op_did() -> &'static str {
        "did:wire:op:operator-abcdef0123456789abcdef0123456789"
    }

    #[test]
    fn parse_wire_org_txt_record_dispatches_org_and_op_dids() {
        let org = parse_wire_org_txt_record(&format!(
            "did={}; relay=https://relay.example; sso_iss=https://issuer.example; sso_tenant=tenant; v=1",
            org_did()
        ))
        .unwrap();
        assert_eq!(org.did, WireOrgTxtDid::Org(org_did().to_string()));
        assert_eq!(org.relay.as_deref(), Some("https://relay.example"));
        assert_eq!(org.sso_iss.as_deref(), Some("https://issuer.example"));
        assert_eq!(org.sso_tenant.as_deref(), Some("tenant"));

        let op = parse_wire_org_txt_record(&format!("did={}; v=1", op_did())).unwrap();
        assert_eq!(op.did, WireOrgTxtDid::Op(op_did().to_string()));
        assert_eq!(op.relay, None);
    }

    #[test]
    fn parse_wire_org_txt_record_rejects_unknown_version_and_session_did() {
        let unknown_v = parse_wire_org_txt_record(&format!("did={}; v=2", org_did())).unwrap_err();
        assert_eq!(
            unknown_v,
            WireOrgTxtParseError::UnsupportedVersion("2".into())
        );

        let session_did =
            parse_wire_org_txt_record("did=did:wire:session-01234567; v=1").unwrap_err();
        assert!(matches!(session_did, WireOrgTxtParseError::InvalidDid(_)));
    }

    #[test]
    fn parse_wire_org_txt_record_rejects_duplicate_known_fields() {
        let err = parse_wire_org_txt_record(&format!("did={}; v=1; v=1", org_did())).unwrap_err();
        assert_eq!(err, WireOrgTxtParseError::DuplicateField("v"));
    }

    proptest! {
        #[test]
        fn parse_wire_org_txt_record_ignores_unknown_fields_at_v1(
            unknown_fields in prop::collection::vec(
                (
                    "[a-z_][a-z0-9_]{0,16}",
                    "[A-Za-z0-9._:/-]{0,64}"
                ),
                0..32
            )
        ) {
            let mut record = format!("did={}; v=1", org_did());
            for (key, value) in unknown_fields {
                prop_assume!(!matches!(
                    key.as_str(),
                    "did" | "v" | "relay" | "sso_iss" | "sso_tenant"
                ));
                record.push_str("; ");
                record.push_str(&key);
                record.push('=');
                record.push_str(&value);
            }

            let parsed = parse_wire_org_txt_record(&record).unwrap();
            prop_assert_eq!(parsed.did, WireOrgTxtDid::Org(org_did().to_string()));
        }

        #[test]
        fn parse_wire_org_txt_record_rejects_every_unknown_version(
            version in "[A-Za-z0-9._-]{1,16}"
        ) {
            prop_assume!(version != "1");
            let record = format!("did={}; v={version}; future=opaque", org_did());
            let err = parse_wire_org_txt_record(&record).unwrap_err();
            prop_assert_eq!(err, WireOrgTxtParseError::UnsupportedVersion(version));
        }
    }
}

#[cfg(test)]
mod failover_tests {
    use super::*;
    use crate::endpoints::{Endpoint, EndpointScope};
    use std::sync::Mutex;

    fn fed_ep(url: &str, slot: &str, token: &str) -> Endpoint {
        Endpoint::federation(url.to_string(), slot.to_string(), token.to_string())
    }

    fn local_ep(url: &str, slot: &str, token: &str) -> Endpoint {
        Endpoint {
            relay_url: url.to_string(),
            slot_id: slot.to_string(),
            slot_token: token.to_string(),
            scope: EndpointScope::Local,
        }
    }

    fn ok_resp() -> PostEventResponse {
        PostEventResponse {
            event_id: Some("evt-1".to_string()),
            status: "queued".to_string(),
        }
    }

    #[test]
    fn first_endpoint_succeeds_no_further_attempts() {
        // Happy path: first endpoint accepts; subsequent endpoints are
        // never tried. Pins that failover doesn't churn unnecessary RTTs
        // when the primary works.
        let endpoints = vec![
            fed_ep("https://good.example", "slot1", "tok1"),
            fed_ep("https://other.example", "slot2", "tok2"),
        ];
        let attempts: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let result = try_post_event_with_failover(&endpoints, &serde_json::json!({}), |ep, _| {
            attempts.lock().unwrap().push(ep.relay_url.clone());
            Ok(ok_resp())
        })
        .unwrap();
        assert_eq!(result.0.relay_url, "https://good.example");
        assert_eq!(
            *attempts.lock().unwrap(),
            vec!["https://good.example".to_string()],
            "must NOT try the second endpoint after the first succeeds"
        );
    }

    #[test]
    fn skips_dead_endpoint_and_succeeds_on_next() {
        // The Bug 2 regression case: a peer advertises [bad, good]. Pre-fix,
        // send_pair_drop_ack would 4xx on `bad` and give up — bilateral pair
        // unreachable. Now the failover helper tries `bad`, records the
        // error, tries `good`, succeeds. Mirrors the swift-harbor ↔
        // coral-weasel incident exactly.
        let endpoints = vec![
            // Bad first endpoint (modeling the userinfo-malformed URL from
            // Bug 1 / the federation 400 coral-weasel hit on accept).
            fed_ep("https://copilot-agent@wireup.net", "slot-bad", "tok-bad"),
            // Clean second endpoint that actually works.
            fed_ep("https://wireup.net", "slot-good", "tok-good"),
        ];
        let attempts: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let (delivered_ep, _resp) =
            try_post_event_with_failover(&endpoints, &serde_json::json!({}), |ep, _| {
                attempts.lock().unwrap().push(ep.relay_url.clone());
                if ep.relay_url.contains('@') {
                    Err(anyhow!("400 Bad Request (userinfo embedded)"))
                } else {
                    Ok(ok_resp())
                }
            })
            .unwrap();
        assert_eq!(
            delivered_ep.relay_url, "https://wireup.net",
            "the successful endpoint must be the one returned to the caller"
        );
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![
                "https://copilot-agent@wireup.net".to_string(),
                "https://wireup.net".to_string()
            ],
            "must try `bad` first, then fall over to `good`"
        );
    }

    #[test]
    fn respects_priority_order_caller_supplies() {
        // We don't re-sort; we honor the caller's order. Typical input is
        // `peer_endpoints_in_priority_order` (UDS / Local / LAN / Federation),
        // so the "first tried" semantics encode the existing transport-
        // preference contract. Test: Local before Federation in input →
        // Local tried first.
        let endpoints = vec![
            local_ep("http://127.0.0.1:8771", "loc1", "loctok"),
            fed_ep("https://wireup.net", "fed1", "fedtok"),
        ];
        let attempts: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let _ = try_post_event_with_failover(&endpoints, &serde_json::json!({}), |ep, _| {
            attempts.lock().unwrap().push(ep.relay_url.clone());
            Ok(ok_resp())
        })
        .unwrap();
        assert_eq!(
            attempts.lock().unwrap()[0],
            "http://127.0.0.1:8771",
            "Local-scope endpoint must be tried first (per the caller's priority order)"
        );
    }

    #[test]
    fn all_failures_returns_combined_error() {
        // All endpoints fail: the helper must combine the per-endpoint
        // reasons into a single error so the operator can diagnose without
        // re-tracing — same shape as cmd_push's failure logging.
        let endpoints = vec![
            fed_ep("https://a.example", "s", "t"),
            fed_ep("https://b.example", "s", "t"),
            fed_ep("https://c.example", "s", "t"),
        ];
        let err = try_post_event_with_failover(&endpoints, &serde_json::json!({}), |ep, _| {
            Err(anyhow!("simulated 500 from {}", ep.relay_url))
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("all 3 endpoint(s) failed"),
            "error must surface the total count: {err}"
        );
        // Every endpoint URL appears in the combined error so each
        // failure is attributable.
        for u in [
            "https://a.example",
            "https://b.example",
            "https://c.example",
        ] {
            assert!(
                err.contains(u),
                "combined error must include each failing endpoint URL ({u}): {err}"
            );
        }
    }

    #[test]
    fn empty_endpoints_returns_actionable_error() {
        // A peer with no pinned endpoints is unreachable by definition. The
        // helper must say so explicitly (not silently return Ok) and point
        // at the re-pair remediation.
        let endpoints: Vec<Endpoint> = Vec::new();
        let err = try_post_event_with_failover(&endpoints, &serde_json::json!({}), |_, _| {
            unreachable!("poster must not be called when endpoint list is empty")
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("no endpoints to deliver to"),
            "empty-list error must be explicit: {err}"
        );
        assert!(
            err.contains("re-pin") || err.contains("dial") || err.contains("pair"),
            "empty-list error must point at the remediation path: {err}"
        );
    }
}
