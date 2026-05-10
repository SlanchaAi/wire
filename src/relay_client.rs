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

    pub fn healthz(&self) -> Result<bool> {
        let resp = self.client.get(format!("{}/healthz", self.base_url)).send()?;
        Ok(resp.status().is_success())
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
