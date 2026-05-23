//! HTTP client for `wire-relay-server`.
//!
//! Sync wrapper around `reqwest::blocking` so CLI commands stay synchronous —
//! the only async surface in the crate is `relay_server::serve`. Async clients
//! land in v0.2 if a long-running daemon needs them.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

/// Centralized builder for blocking HTTPS clients across wire. Loads
/// the OS native trust store (rustls-tls-native-roots) so corporate
/// proxies, AV cert-resign products, and on-prem CAs validate. Honors
/// the [`INSECURE_SKIP_TLS_ENV`] escape hatch for the corporate-proxy
/// emergency case.
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
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connect UDS {socket_path:?}"))?;
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
            let mut req_buf = [0u8; 4096];
            let _ = stream.read(&mut req_buf);
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
        let tmpdir = std::env::temp_dir().join(format!(
            "wire-uds-test-{}",
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&tmpdir).unwrap();
        let sock = tmpdir.join("rt.sock");
        let _ = std::fs::remove_file(&sock);
        spawn_canned_uds_server(sock.clone(), 200, r#"{"ok":true}"#);
        // Give the server a moment to bind.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let (status, body) = uds_request(&sock, "POST", "/v1/test", &[("Content-Type", "application/json")], b"{}")
            .expect("uds_request succeeds");
        assert_eq!(status, 200);
        assert_eq!(body, br#"{"ok":true}"#);
    }

    #[test]
    fn uds_request_surfaces_non_2xx_status() {
        let tmpdir = std::env::temp_dir().join(format!(
            "wire-uds-test-{}",
            rand::random::<u32>()
        ));
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
        assert!(msg.contains("connect UDS"), "expected connect error, got: {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
