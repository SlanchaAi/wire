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

impl RelayClient {
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client construction is infallible with default config");
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
    pub fn handle_claim(
        &self,
        nick: &str,
        slot_id: &str,
        slot_token: &str,
        relay_url: Option<&str>,
        card: &Value,
    ) -> Result<Value> {
        let body = serde_json::json!({
            "nick": nick,
            "slot_id": slot_id,
            "relay_url": relay_url,
            "card": card,
        });
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
}
