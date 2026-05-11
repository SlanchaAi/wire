//! Agent profile + handle parsing (v0.5 — agentic hotline).
//!
//! Three-layer identity:
//!   1. DID (`did:wire:<hash>`) — immutable cryptographic anchor (unchanged).
//!   2. Handle (`nick@domain`) — mutable, human-readable, DNS-anchored.
//!   3. Profile — freeform personality (emoji, motto, vibe, pronouns, `now`).
//!
//! Profile fields live inside the existing signed agent-card under a `profile`
//! key. Editing any field re-signs the card. Card signature thus covers DID,
//! handle, AND personality atomically — peers verifying the card get both
//! identity and vibe in one signed blob.
//!
//! See `SPEC_v0_5.md` for the full design.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use crate::config;

pub const PROFILE_SCHEMA_VERSION: &str = "v0.5";

/// Reserved nick set — refuse to mint any of these as the local part of a
/// handle. Length-1 nicks also reserved (impose `nick.len() >= 2`).
pub const RESERVED_NICKS: &[&str] = &[
    "wire", "system", "admin", "root", "null", "everyone", "here", "me", "you", "self", "all",
    "none",
];

/// Parsed handle: `nick@domain`. `domain` is lowercased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    pub nick: String,
    pub domain: String,
}

impl Handle {
    pub fn as_string(&self) -> String {
        format!("{}@{}", self.nick, self.domain)
    }
}

impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.nick, self.domain)
    }
}

/// Parse `nick@domain`. Returns `Err` on malformed inputs or reserved nicks.
///
/// Nick rules: 2-32 chars, `[a-z0-9_-]`. Domain rules: DNS-label-shaped,
/// dot-separated, lowercase ASCII. We don't fully validate domain syntax
/// here — DNS resolution will fail later if the operator typo'd it.
pub fn parse_handle(s: &str) -> Result<Handle> {
    let (nick, domain) = s
        .split_once('@')
        .ok_or_else(|| anyhow!("handle missing '@' separator: {s:?}"))?;
    if nick.is_empty() || domain.is_empty() {
        bail!("handle has empty nick or domain: {s:?}");
    }
    if !is_valid_nick(nick) {
        bail!("nick {nick:?} invalid — must be 2..=32 chars, [a-z0-9_-], not reserved");
    }
    if !is_valid_domain(domain) {
        bail!("domain {domain:?} invalid — must be lowercase ASCII, dot-separated");
    }
    Ok(Handle {
        nick: nick.to_string(),
        domain: domain.to_string(),
    })
}

/// True iff `s` is a syntactically valid nick (handle local-part). Does NOT
/// check reservation — that is enforced by `parse_handle` AND by relay
/// directory at claim time.
pub fn is_valid_nick(s: &str) -> bool {
    let len = s.len();
    if !(2..=32).contains(&len) {
        return false;
    }
    if RESERVED_NICKS.contains(&s) {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn is_valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    // Lowercase ASCII, dot-separated labels of 1..=63 chars each.
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Editable profile fields. All optional; unset fields stay `null` in the
/// signed card.
pub const PROFILE_FIELDS: &[&str] = &[
    "display_name",
    "emoji",
    "motto",
    "vibe",
    "pronouns",
    "avatar_url",
    "handle",
    "now",
];

/// Read this agent's profile blob from the agent-card. Returns `Value::Null`
/// if no profile fields have ever been set (back-compat with v0.4 cards).
pub fn read_profile() -> Result<Value> {
    let card = config::read_agent_card()?;
    Ok(card.get("profile").cloned().unwrap_or(Value::Null))
}

/// Set a single profile field and re-sign the agent-card. `value` must be a
/// JSON value the caller has already parsed/validated (string for most fields;
/// array for `vibe`; object for `now`).
pub fn write_profile_field(field: &str, value: Value) -> Result<Value> {
    if !PROFILE_FIELDS.contains(&field) {
        bail!(
            "unknown profile field {field:?}; allowed: {}",
            PROFILE_FIELDS.join(", ")
        );
    }
    // Handle gets extra validation.
    if field == "handle" {
        let s = value
            .as_str()
            .ok_or_else(|| anyhow!("handle must be a string"))?;
        parse_handle(s)?;
    }
    if field == "vibe" && !value.is_array() {
        bail!("vibe must be a JSON array of strings");
    }
    if field == "now" && !(value.is_null() || value.is_object()) {
        bail!("now must be a JSON object with text/since/ttl_secs or null");
    }

    let mut card = config::read_agent_card()?;
    let card_obj = card
        .as_object_mut()
        .ok_or_else(|| anyhow!("agent-card is not a JSON object"))?;

    // Get or create the profile sub-object.
    let profile = card_obj
        .entry("profile".to_string())
        .or_insert_with(|| json!({"schema_version": PROFILE_SCHEMA_VERSION}));
    let profile_obj = profile
        .as_object_mut()
        .ok_or_else(|| anyhow!("profile field is not an object"))?;

    if value.is_null() {
        profile_obj.remove(field);
    } else {
        profile_obj.insert(field.to_string(), value);
    }
    profile_obj.insert("schema_version".to_string(), json!(PROFILE_SCHEMA_VERSION));

    // Re-sign the whole card (signature covers profile via card_canonical).
    let sk_seed = config::read_private_key()?;
    // Strip prior signature before re-signing.
    card_obj.remove("signature");
    let resigned = crate::agent_card::sign_agent_card(&card, &sk_seed);
    config::write_agent_card(&resigned)?;

    Ok(resigned.get("profile").cloned().unwrap_or(Value::Null))
}

/// Resolve a `nick@domain` handle via the remote relay's
/// `.well-known/wire/agent` endpoint. Returns the parsed JSON payload
/// `{nick, did, card, slot_id, relay_url, claimed_at}` on success. Verifies
/// the card signature; on tamper, returns `Err`.
///
/// The relay-URL hint helps: if `relay_url` is `Some`, that base is used.
/// Otherwise we assume `https://<domain>` (matches operator's DNS-anchored
/// setup, e.g. `wire.laulpogan.com`).
pub fn resolve_handle(handle: &Handle, relay_url: Option<&str>) -> anyhow::Result<Value> {
    let base = relay_url
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", handle.domain));
    let client = crate::relay_client::RelayClient::new(&base);
    let resolved = client.well_known_agent(&handle.nick)?;
    let card = resolved
        .get("card")
        .ok_or_else(|| anyhow!("resolved payload missing 'card' field"))?;
    crate::agent_card::verify_agent_card(card)
        .map_err(|e| anyhow!("resolved card signature invalid: {e}"))?;
    let did_in_resp = resolved
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("resolved payload missing 'did'"))?;
    let did_in_card = card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("resolved card missing 'did'"))?;
    if did_in_resp != did_in_card {
        bail!("resolved DID mismatch: payload={did_in_resp} card={did_in_card}");
    }
    Ok(resolved)
}

/// Render the local agent's profile as a friendly multi-line string for
/// `wire whois` with no argument (i.e., show self).
pub fn render_self_summary() -> Result<String> {
    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .unwrap_or("did:wire:?")
        .to_string();
    let local_handle = did.strip_prefix("did:wire:").unwrap_or(&did).to_string();
    let profile = card.get("profile").cloned().unwrap_or(Value::Null);

    let mut out = String::new();
    let line = |out: &mut String, k: &str, v: &str| {
        if !v.is_empty() {
            out.push_str(&format!("  {k:14}{v}\n"));
        }
    };

    out.push_str(&format!("{}\n", did));

    if let Some(handle) = profile.get("handle").and_then(Value::as_str) {
        line(&mut out, "handle:", handle);
    } else {
        line(&mut out, "handle:", &format!("{local_handle}@(unset)"));
    }
    if let Some(name) = profile.get("display_name").and_then(Value::as_str) {
        line(&mut out, "display_name:", name);
    }
    if let Some(emoji) = profile.get("emoji").and_then(Value::as_str) {
        line(&mut out, "emoji:", emoji);
    }
    if let Some(motto) = profile.get("motto").and_then(Value::as_str) {
        line(&mut out, "motto:", motto);
    }
    if let Some(vibe) = profile.get("vibe").and_then(Value::as_array) {
        let joined: Vec<String> = vibe
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        line(&mut out, "vibe:", &joined.join(", "));
    }
    if let Some(pronouns) = profile.get("pronouns").and_then(Value::as_str) {
        line(&mut out, "pronouns:", pronouns);
    }
    if let Some(now) = profile.get("now")
        && let Some(text) = now.get("text").and_then(Value::as_str)
    {
        line(&mut out, "now:", text);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handle_round_trip() {
        let h = parse_handle("coffee-ghost@anthropic.dev").unwrap();
        assert_eq!(h.nick, "coffee-ghost");
        assert_eq!(h.domain, "anthropic.dev");
        assert_eq!(h.as_string(), "coffee-ghost@anthropic.dev");
    }

    #[test]
    fn parse_handle_accepts_underscore_and_digits() {
        assert!(parse_handle("dragonfly_42@home.arpa").is_ok());
        assert!(parse_handle("v2@wire.laulpogan.com").is_ok());
    }

    #[test]
    fn parse_handle_rejects_no_at() {
        assert!(parse_handle("paul").is_err());
        assert!(parse_handle("paul.example.com").is_err());
    }

    #[test]
    fn parse_handle_rejects_empty_parts() {
        assert!(parse_handle("@example.com").is_err());
        assert!(parse_handle("paul@").is_err());
    }

    #[test]
    fn parse_handle_rejects_reserved_nicks() {
        for r in RESERVED_NICKS {
            let s = format!("{r}@example.com");
            assert!(
                parse_handle(&s).is_err(),
                "expected reserved nick {r:?} to be rejected"
            );
        }
    }

    #[test]
    fn parse_handle_rejects_single_char_nick() {
        assert!(parse_handle("a@example.com").is_err());
    }

    #[test]
    fn parse_handle_rejects_uppercase_or_emoji_in_nick() {
        assert!(parse_handle("Paul@example.com").is_err());
        assert!(parse_handle("p👻@example.com").is_err());
    }

    #[test]
    fn parse_handle_rejects_overlong_nick() {
        let long = "a".repeat(33);
        let s = format!("{long}@example.com");
        assert!(parse_handle(&s).is_err());
    }

    #[test]
    fn parse_handle_rejects_bad_domain() {
        assert!(parse_handle("paul@-bad.example.com").is_err());
        assert!(parse_handle("paul@bad-.example.com").is_err());
        assert!(parse_handle("paul@.bad.com").is_err());
    }

    #[test]
    fn is_valid_nick_lower_bound() {
        assert!(!is_valid_nick("a"));
        assert!(is_valid_nick("ab"));
    }
}
