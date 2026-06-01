//! wire — magic-wormhole for AI agents.
//!
//! v0.1 surface (this crate):
//!   - [`canonical`] — sorted-key, no-whitespace JSON; the wire-byte form.
//!   - [`signing`] — Ed25519 sign-over-event_id (Nostr NIP-01 style).
//!   - [`agent_card`] — DID-anchored agent identity + bilateral SAS.
//!   - [`trust`] — per-peer tier state machine (UNTRUSTED → VERIFIED).
//!
//! v0.2+ (NOT in this crate yet, see `BACKLOG.md`):
//!   - relay client/server, SPAKE2 handshake, CLI, file_share/file_revoke kinds.

pub mod agent_card;
pub mod canonical;
pub mod character;
pub mod cli;
pub mod config;
pub mod daemon_stream;
pub mod daemon_supervisor;
pub mod diag;
pub mod endpoints;
pub mod enroll;
pub mod ensure_up;
pub mod group;
pub mod identity;
pub mod inbox_watch;
pub mod macaroon;
pub mod mcp;
pub mod org_membership;
pub mod org_policy;
pub mod os_notify;
pub mod pair_decision;
pub mod pair_invite;
pub mod pair_profile;
pub mod pair_session;
pub mod pending_inbound_pair;
pub mod pending_pair;
pub mod platform;
pub mod pull;
pub mod relay_client;
pub mod relay_server;
pub mod sas;
pub mod service;
pub mod session;
pub mod signing;
pub mod sso_provider;
pub mod trust;

// Curated re-exports for ergonomic call sites.
pub use signing::{
    KIND_RANGES, KindClass, SignError, VerifyError, b64decode, b64encode, compute_event_id,
    fingerprint, generate_keypair, kind_class, kinds, make_key_id, sign_message_v31,
    verify_message_v31,
};

pub use agent_card::{
    AgentCard, CARD_SCHEMA_VERSION, CardError, DID_METHOD, build_agent_card, card_canonical,
    compute_sas, did_for, sign_agent_card, verify_agent_card,
};

pub use trust::{
    Tier, Trust, add_agent_card_pin, add_self_to_trust, empty_trust, get_tier, promote_to_verified,
};
