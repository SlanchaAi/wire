//! Staged pair session for MCP.
//!
//! Splits the magic-wormhole pair flow (`cli::pair_orchestrate`) into discrete
//! stages so an MCP server can drive it across multiple JSON-RPC tool calls.
//!
//! State machine:
//!
//! ```text
//!     pair_session_open
//!            │
//!            ▼
//!    ┌─Opened ─────────┐
//!    │  (peer not in)  │  pair_session_try_sas (idempotent poll)
//!    └─────────────────┘
//!            │ peer's SPAKE2 msg arrives
//!            ▼
//!     SasReady (sas + aead_key cached)
//!            │ user types digits → pair_session_confirm_sas
//!            ▼
//!     Confirmed
//!            │ pair_session_finalize
//!            ▼
//!     Finalized (peer pinned, relay coords saved)
//!
//!  Aborted = SAS mismatch / TTL expired / peer aborted (terminal, removed from store)
//! ```
//!
//! Concurrency: each session is keyed by its relay `pair_id` (unique per
//! pairing). Sessions are independent — pairing with N peers concurrently
//! creates N sessions in the store, each with its own pair_id at the relay
//! and its own `Mutex<PairSessionState>`. No cross-session locking.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::sas::{
    PakeSide, compute_sas_pake, derive_aead_key, generate_code_phrase, open_bootstrap,
    parse_code_phrase, seal_bootstrap,
};

/// Session evicted after this much wall time. 10min covers human-pace OOB
/// code-phrase sharing (voice/text) plus AEAD bootstrap exchange comfortably,
/// matches the relay pair-slot TTL ceiling, and forces a fresh `pair_initiate`
/// if a session has been abandoned.
pub const SESSION_TTL: Duration = Duration::from_secs(600);

/// One in-flight pair session held in the MCP server process.
///
/// Public fields are read-only contracts; mutate only via the staged
/// `pair_session_*` functions below so invariants stay coherent.
pub struct PairSessionState {
    pub role: String, // "host" or "guest"
    pub relay_url: String,
    pub pair_id: String,   // == public session_id
    pub code: String,      // human-readable code phrase
    pub code_hash: String, // hex of SHA-256(b"wire/v1 code-phrase" || code)
    pub pake: PakeSide,    // SPAKE2 side; .finish() consumes inner state
    pub our_slot_id: String,
    pub our_slot_token: String,
    pub spake_key: Option<[u8; 32]>,
    pub aead_key: Option<[u8; 32]>,
    /// Raw 6-digit SAS, no dash. Display as "{first 3}-{last 3}".
    pub sas: Option<String>,
    pub sas_confirmed: bool,
    pub bootstrap_sealed_sent: bool,
    pub finalized: bool,
    pub aborted: Option<String>,
    pub created_at: Instant,
}

impl PairSessionState {
    pub fn session_id(&self) -> &str {
        &self.pair_id
    }
    pub fn formatted_sas(&self) -> Option<String> {
        self.sas
            .as_ref()
            .map(|d| format!("{}-{}", &d[..3], &d[3..]))
    }
}

// ---------- module-private store ----------

type Store = Mutex<HashMap<String, Arc<Mutex<PairSessionState>>>>;
static STORE: OnceLock<Store> = OnceLock::new();

fn store() -> &'static Store {
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Insert a fresh session, returning the public session_id.
pub fn store_insert(s: PairSessionState) -> String {
    let id = s.pair_id.clone();
    let arc = Arc::new(Mutex::new(s));
    store().lock().unwrap().insert(id.clone(), arc);
    id
}

/// Look up a session by id. Returns None if missing or evicted.
pub fn store_get(session_id: &str) -> Option<Arc<Mutex<PairSessionState>>> {
    store().lock().unwrap().get(session_id).cloned()
}

/// Remove a session. Used after finalize, abort, or TTL eviction.
pub fn store_remove(session_id: &str) {
    store().lock().unwrap().remove(session_id);
}

/// Sweep expired sessions. Called opportunistically before each public op.
pub fn store_sweep_expired() {
    let mut g = store().lock().unwrap();
    g.retain(|_, arc| {
        // Try lock; if a session is mid-op, leave it. Eviction will retry next sweep.
        match arc.try_lock() {
            Ok(s) => s.created_at.elapsed() < SESSION_TTL,
            Err(_) => true,
        }
    });
}

#[cfg(test)]
pub fn store_clear_for_test() {
    store().lock().unwrap().clear();
}

// ---------- staged operations ----------

/// **Stage 1.** Open a pair session at the relay.
///
/// Side effects:
///   - Allocates a relay slot for self if not already bound (matches
///     existing `cli::cmd_pair_*` first-run behavior).
///   - Generates code phrase (host) or accepts the typed one (guest).
///   - Posts our SPAKE2 message to `/v1/pair`.
///
/// Returns a `PairSessionState` you should feed to `store_insert` and then
/// drive forward via `pair_session_try_sas` and `pair_session_finalize`.
pub fn pair_session_open(
    role: &str,
    relay_url: &str,
    code_in: Option<&str>,
) -> Result<PairSessionState> {
    if !crate::config::is_initialized()? {
        bail!("not initialized — operator must run `wire init <handle>` first");
    }
    if role != "host" && role != "guest" {
        bail!("role must be 'host' or 'guest' (got {role:?})");
    }

    // Auto-bind relay slot if we don't have one for this URL.
    let mut relay_state = crate::config::read_relay_state()?;
    let need_alloc = relay_state["self"].is_null()
        || relay_state["self"]["relay_url"].as_str() != Some(relay_url);

    let card = crate::config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let handle = did.strip_prefix("did:wire:").unwrap_or(&did).to_string();

    if need_alloc {
        let client = crate::relay_client::RelayClient::new(relay_url);
        if !client.healthz().unwrap_or(false) {
            bail!("relay healthz failed at {relay_url}");
        }
        let alloc = client.allocate_slot(Some(&handle))?;
        relay_state["self"] = json!({
            "relay_url": relay_url,
            "slot_id": alloc.slot_id,
            "slot_token": alloc.slot_token,
        });
        crate::config::write_relay_state(&relay_state)?;
    }
    let our_slot_id = relay_state["self"]["slot_id"]
        .as_str()
        .ok_or_else(|| anyhow!("relay-state self.slot_id missing"))?
        .to_string();
    let our_slot_token = relay_state["self"]["slot_token"]
        .as_str()
        .ok_or_else(|| anyhow!("relay-state self.slot_token missing"))?
        .to_string();

    let code = match code_in {
        Some(c) => parse_code_phrase(c)?.to_string(),
        None => generate_code_phrase(),
    };

    let code_hash = {
        let mut h = Sha256::new();
        h.update(b"wire/v1 code-phrase");
        h.update(code.as_bytes());
        hex::encode(h.finalize())
    };

    let pake = PakeSide::new(&code, code_hash.as_bytes());
    let our_msg_b64 = crate::signing::b64encode(&pake.msg_out);

    let client = crate::relay_client::RelayClient::new(relay_url);
    let pair_id = client.pair_open(&code_hash, &our_msg_b64, role)?;

    Ok(PairSessionState {
        role: role.to_string(),
        relay_url: relay_url.to_string(),
        pair_id,
        code,
        code_hash,
        pake,
        our_slot_id,
        our_slot_token,
        spake_key: None,
        aead_key: None,
        sas: None,
        sas_confirmed: false,
        bootstrap_sealed_sent: false,
        finalized: false,
        aborted: None,
        created_at: Instant::now(),
    })
}

/// **Stage 2.** Try to advance a session to SAS-ready. Single non-blocking
/// poll of the relay. Idempotent: re-calling after SAS is cached returns the
/// same digits without further network I/O.
///
/// Returns:
///   - `Ok(Some(formatted))` — `"ABC-DEF"` six-digit SAS, ready to display
///   - `Ok(None)` — peer's SPAKE2 message hasn't landed yet; try again later
///   - `Err(...)` — relay error, or peer sent malformed message
pub fn pair_session_try_sas(s: &mut PairSessionState) -> Result<Option<String>> {
    if let Some(formatted) = s.formatted_sas() {
        return Ok(Some(formatted));
    }
    if s.aborted.is_some() {
        bail!(
            "session aborted: {}",
            s.aborted.as_deref().unwrap_or("unknown")
        );
    }
    let client = crate::relay_client::RelayClient::new(&s.relay_url);
    let (peer_msg, _) = client.pair_get(&s.pair_id, &s.role)?;
    let peer_msg_b64 = match peer_msg {
        Some(m) => m,
        None => return Ok(None),
    };
    let peer_msg_bytes = crate::signing::b64decode(&peer_msg_b64)?;
    let spake_key = s.pake.finish(&peer_msg_bytes)?;
    let sas = compute_sas_pake(&spake_key, &spake_key[..16], &spake_key[16..]);
    let aead_key = derive_aead_key(&spake_key, s.code_hash.as_bytes());
    s.spake_key = Some(spake_key);
    s.aead_key = Some(aead_key);
    s.sas = Some(sas);
    Ok(s.formatted_sas())
}

/// **Stage 2 helper.** Bounded loop wrapping `try_sas`. Used both by CLI
/// (long timeout, blocking) and MCP (short timeout, fall through to async poll).
pub fn pair_session_wait_for_sas(
    s: &mut PairSessionState,
    max_wait_secs: u64,
    poll_interval: Duration,
) -> Result<Option<String>> {
    let deadline = Instant::now() + Duration::from_secs(max_wait_secs);
    loop {
        if let Some(sas) = pair_session_try_sas(s)? {
            return Ok(Some(sas));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(poll_interval);
    }
}

/// **Stage 3.** Validate the user-typed digits against the cached SAS.
///
/// `typed` may be `"384217"`, `"384-217"`, or `"384 217"` — non-digits are
/// stripped before compare. Mismatch sets `s.aborted` and the session must
/// be discarded; no retries (forces fresh `pair_initiate`).
pub fn pair_session_confirm_sas(s: &mut PairSessionState, typed: &str) -> Result<()> {
    let cached = s
        .sas
        .as_ref()
        .ok_or_else(|| anyhow!("session not in sas_ready state"))?
        .clone();
    if s.sas_confirmed {
        bail!("SAS already confirmed for this session");
    }
    if s.aborted.is_some() {
        bail!(
            "session aborted: {}",
            s.aborted.as_deref().unwrap_or("unknown")
        );
    }
    let normalized: String = typed.chars().filter(|c| c.is_ascii_digit()).collect();
    if normalized.len() != 6 {
        s.aborted = Some(format!(
            "user typed {} digits, expected 6",
            normalized.len()
        ));
        bail!("expected 6 digits (got {})", normalized.len());
    }
    if normalized != cached {
        // Constant-ish compare — both strings are short and known length, but
        // we still want to NOT leak via early-return divergence.
        let mut diff = 0u8;
        for (a, b) in normalized.bytes().zip(cached.bytes()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            s.aborted = Some("SAS mismatch — user-typed digits did not match".into());
            bail!("SAS digit mismatch — pairing aborted (start a fresh pair-initiate)");
        }
    }
    s.sas_confirmed = true;
    Ok(())
}

/// **Stage 4.** Seal+exchange bootstrap, AEAD-open peer's, pin peer.
///
/// Caller must have called `pair_session_confirm_sas` first (or, for CLI
/// where the y/n prompt serves the same role, must set `s.sas_confirmed`
/// before calling this).
///
/// Returns a JSON summary suitable for printing or returning as MCP result.
pub fn pair_session_finalize(s: &mut PairSessionState, timeout_secs: u64) -> Result<Value> {
    if !s.sas_confirmed {
        bail!("SAS not confirmed — call pair_session_confirm_sas first");
    }
    if s.aborted.is_some() {
        bail!(
            "session aborted: {}",
            s.aborted.as_deref().unwrap_or("unknown")
        );
    }
    let aead_key = s
        .aead_key
        .ok_or_else(|| anyhow!("session not ready: no aead_key cached"))?;
    let card = crate::config::read_agent_card()?;

    if !s.bootstrap_sealed_sent {
        let bootstrap_payload = json!({
            "card": card.clone(),
            "relay_url": s.relay_url,
            "slot_id": s.our_slot_id,
            "slot_token": s.our_slot_token,
        });
        let plaintext = serde_json::to_vec(&bootstrap_payload)?;
        let sealed = seal_bootstrap(&aead_key, &plaintext)?;
        let client = crate::relay_client::RelayClient::new(&s.relay_url);
        client.pair_bootstrap(&s.pair_id, &s.role, &crate::signing::b64encode(&sealed))?;
        s.bootstrap_sealed_sent = true;
    }

    let client = crate::relay_client::RelayClient::new(&s.relay_url);
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let peer_bootstrap_b64 = loop {
        let (_, peer_bootstrap) = client.pair_get(&s.pair_id, &s.role)?;
        if let Some(b) = peer_bootstrap {
            break b;
        }
        if Instant::now() >= deadline {
            bail!("timeout after {timeout_secs}s waiting for peer's sealed bootstrap");
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    let peer_sealed = crate::signing::b64decode(&peer_bootstrap_b64)?;
    let peer_plain = open_bootstrap(&aead_key, &peer_sealed)
        .map_err(|e| anyhow!("AEAD open failed — wrong code, MITM, or peer aborted: {e}"))?;
    let peer_payload: Value = serde_json::from_slice(&peer_plain)?;
    let peer_card = peer_payload
        .get("card")
        .cloned()
        .ok_or_else(|| anyhow!("peer bootstrap missing card"))?;
    crate::agent_card::verify_agent_card(&peer_card)
        .map_err(|e| anyhow!("peer card signature invalid: {e}"))?;

    let mut trust = crate::config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &peer_card, Some("VERIFIED"));
    crate::config::write_trust(&trust)?;

    let peer_did = peer_card
        .get("did")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let peer_handle = peer_did
        .strip_prefix("did:wire:")
        .unwrap_or(&peer_did)
        .to_string();
    let peer_relay_url = peer_payload
        .get("relay_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let peer_slot_id = peer_payload
        .get("slot_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let peer_slot_token = peer_payload
        .get("slot_token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let mut relay_state = crate::config::read_relay_state()?;
    relay_state["peers"][&peer_handle] = json!({
        "relay_url": peer_relay_url,
        "slot_id": peer_slot_id,
        "slot_token": peer_slot_token,
    });
    crate::config::write_relay_state(&relay_state)?;

    s.finalized = true;
    let formatted_sas = s.formatted_sas().unwrap_or_default();

    Ok(json!({
        "paired_with": peer_did,
        "peer_handle": peer_handle,
        "peer_relay_url": peer_relay_url,
        "peer_slot_id": peer_slot_id,
        "sas": formatted_sas,
    }))
}

// ---------- idempotent init ----------

/// MCP-callable init: idempotent if already inited under the same handle,
/// errors on different-handle conflict, accepts optional --relay binding.
///
/// This is the only writeable identity-creation entry point safe to expose
/// to agents — it can't change the operator's existing identity.
pub fn init_self_idempotent(
    handle: &str,
    name: Option<&str>,
    relay: Option<&str>,
) -> Result<Value> {
    use crate::agent_card::{build_agent_card, sign_agent_card};
    use crate::signing::{fingerprint, generate_keypair, make_key_id};
    use crate::trust::{add_self_to_trust, empty_trust};

    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("handle must be ASCII alphanumeric / '-' / '_' (got {handle:?})");
    }

    if crate::config::is_initialized()? {
        let card = crate::config::read_agent_card()?;
        let existing_did = card
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let existing_handle = existing_did
            .strip_prefix("did:wire:")
            .unwrap_or(&existing_did)
            .to_string();
        if existing_handle != handle {
            bail!(
                "already initialized as did:wire:{existing_handle}; refusing to re-init with different handle {handle:?}. \
                 Operator must explicitly delete config to re-init."
            );
        }
        let pk_b64 = card
            .get("verify_keys")
            .and_then(Value::as_object)
            .and_then(|m| m.values().next())
            .and_then(|v| v.get("key"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
        let pk_bytes = crate::signing::b64decode(pk_b64)?;
        let mut out = json!({
            "did": existing_did,
            "handle": handle,
            "fingerprint": fingerprint(&pk_bytes),
            "key_id": make_key_id(handle, &pk_bytes),
            "config_dir": crate::config::config_dir()?.to_string_lossy(),
            "already_initialized": true,
        });
        let relay_state = crate::config::read_relay_state()?;
        if let Some(url) = relay {
            if relay_state["self"].is_null() {
                let client = crate::relay_client::RelayClient::new(url);
                if !client.healthz().unwrap_or(false) {
                    bail!("relay healthz failed at {url}");
                }
                let alloc = client.allocate_slot(Some(handle))?;
                let mut rs = relay_state;
                rs["self"] = json!({
                    "relay_url": url,
                    "slot_id": alloc.slot_id.clone(),
                    "slot_token": alloc.slot_token,
                });
                crate::config::write_relay_state(&rs)?;
                out["relay_url"] = json!(url);
                out["slot_id"] = json!(alloc.slot_id);
            } else if let Some(existing_url) = relay_state["self"]["relay_url"].as_str() {
                out["relay_url"] = json!(existing_url);
                out["slot_id"] = relay_state["self"]["slot_id"].clone();
            }
        }
        return Ok(out);
    }

    crate::config::ensure_dirs()?;
    let (sk_seed, pk_bytes) = generate_keypair();
    crate::config::write_private_key(&sk_seed)?;
    let card = build_agent_card(handle, &pk_bytes, name, None, None);
    let signed = sign_agent_card(&card, &sk_seed);
    crate::config::write_agent_card(&signed)?;
    let mut trust = empty_trust();
    add_self_to_trust(&mut trust, handle, &pk_bytes);
    crate::config::write_trust(&trust)?;

    let mut out = json!({
        "did": format!("did:wire:{handle}"),
        "handle": handle,
        "fingerprint": fingerprint(&pk_bytes),
        "key_id": make_key_id(handle, &pk_bytes),
        "config_dir": crate::config::config_dir()?.to_string_lossy(),
        "already_initialized": false,
    });

    if let Some(url) = relay {
        let client = crate::relay_client::RelayClient::new(url);
        if !client.healthz().unwrap_or(false) {
            bail!("relay healthz failed at {url}");
        }
        let alloc = client.allocate_slot(Some(handle))?;
        let mut rs = crate::config::read_relay_state()?;
        rs["self"] = json!({
            "relay_url": url,
            "slot_id": alloc.slot_id.clone(),
            "slot_token": alloc.slot_token,
        });
        crate::config::write_relay_state(&rs)?;
        out["relay_url"] = json!(url);
        out["slot_id"] = json!(alloc.slot_id);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_sas_strips_dash_and_spaces() {
        let mut s = mk_sas_ready_state("384217");
        pair_session_confirm_sas(&mut s, "384-217").unwrap();
        assert!(s.sas_confirmed);
    }

    #[test]
    fn confirm_sas_mismatch_aborts_session() {
        let mut s = mk_sas_ready_state("384217");
        let err = pair_session_confirm_sas(&mut s, "999999").unwrap_err();
        assert!(err.to_string().contains("mismatch"));
        assert!(s.aborted.is_some());
        assert!(!s.sas_confirmed);
    }

    #[test]
    fn confirm_sas_wrong_length_aborts() {
        let mut s = mk_sas_ready_state("384217");
        let err = pair_session_confirm_sas(&mut s, "12345").unwrap_err();
        assert!(err.to_string().contains("6 digits"));
        assert!(s.aborted.is_some());
    }

    #[test]
    fn confirm_sas_double_confirm_rejected() {
        let mut s = mk_sas_ready_state("384217");
        pair_session_confirm_sas(&mut s, "384217").unwrap();
        let err = pair_session_confirm_sas(&mut s, "384217").unwrap_err();
        assert!(err.to_string().contains("already confirmed"));
    }

    #[test]
    fn store_holds_independent_sessions() {
        store_clear_for_test();
        let s1 = mk_sas_ready_state("111111");
        let s2 = mk_sas_ready_state("222222");
        let id1 = store_insert(s1);
        let id2 = store_insert(s2);
        assert_ne!(id1, id2);
        assert!(store_get(&id1).is_some());
        assert!(store_get(&id2).is_some());
        store_remove(&id1);
        assert!(store_get(&id1).is_none());
        assert!(store_get(&id2).is_some());
        store_clear_for_test();
    }

    fn mk_sas_ready_state(sas: &str) -> PairSessionState {
        // Build a synthetic session bypassing the relay — only the post-SAS
        // helpers (confirm/abort) are exercised in unit tests; integration
        // tests cover the full wire including relay I/O.
        let pair_id = format!(
            "test-{}-{:?}",
            sas,
            std::time::Instant::now().elapsed().as_nanos()
        );
        PairSessionState {
            role: "host".into(),
            relay_url: "http://invalid".into(),
            pair_id,
            // Code phrase format is "NN-XXXXXX" (2 digits, dash, 6 base32 chars).
            code: "12-ABCDEF".into(),
            code_hash: "deadbeef".into(),
            pake: PakeSide::new("12-ABCDEF", b"test"),
            our_slot_id: "slot-self".into(),
            our_slot_token: "tok-self".into(),
            spake_key: Some([0u8; 32]),
            aead_key: Some([0u8; 32]),
            sas: Some(sas.into()),
            sas_confirmed: false,
            bootstrap_sealed_sent: false,
            finalized: false,
            aborted: None,
            created_at: Instant::now(),
        }
    }
}
