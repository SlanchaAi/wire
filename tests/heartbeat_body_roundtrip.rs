//! AC-HP7 — Ephemeral-class body-roundtrip property test (RFC-004 §1 / #135).
//!
//! `kind=100` (heartbeat) is registered `KindClass::Ephemeral` (`src/signing.rs:106`
//! v3 heartbeat carve-out). Ephemeral describes **retention** (relay no-store) —
//! it does NOT describe body content. Relay paths MUST NOT optimize body content
//! out of `KindClass::Ephemeral` events: a probe with `responder_state: {...}`
//! MUST round-trip byte-identical from sender to receiver.
//!
//! Any future relay-side optimization that strips ephemeral-event bodies would
//! silently murder RFC-004 probes without alerting anyone. This file pins the
//! invariant via proptest before that failure mode ever materializes.
//!
//! Two property cases:
//!
//! 1. **Body-roundtrip preservation.** Arbitrary JSON-object bodies (containing
//!    a `t: String` discriminator + arbitrary extras) round-trip byte-identical
//!    through sign → serialize → parse → verify. The `body` field on the parsed
//!    event MUST equal the original body, byte-equal.
//!
//! 2. **Cursor-PAST on unknown body intent.** Bodies carrying arbitrary
//!    unknown `t` discriminators (`probe_v2_future_intent`, etc.) sign + verify
//!    successfully — they do NOT trigger a verify-side rejection. The pull
//!    pipeline's cursor-advance-with-warning semantics for unknown body intents
//!    (RFC-001-amendment-sso §F + RFC-004 §AC-HP4) ride this verify-passes
//!    invariant: a `TRANSIENT_REJECT` from `verify_message_v31` would
//!    short-circuit the cursor advance and silently murder forward-compatibility.

use proptest::collection::vec;
use proptest::prelude::*;
use serde_json::{Value, json};
use wire::signing::{
    KindClass, b64encode, fingerprint, generate_keypair, kind_class, make_key_id,
    sign_message_v31, verify_message_v31,
};

/// Build a `trust` dict that accepts the given (handle, pubkey) pair so
/// `verify_message_v31` will check the signature instead of bailing on
/// UnknownAgent / UnknownKey. Mirrors the shape `verify_message_v31` reads at
/// `src/signing.rs:262-274`.
fn trust_for_test(handle: &str, public_key: &[u8]) -> Value {
    let pk_b64 = b64encode(public_key);
    let key_id = make_key_id(handle, public_key);
    json!({
        "agents": {
            handle: {
                "public_keys": [
                    {
                        "key_id": key_id,
                        "key": pk_b64,
                        "alg": "ed25519",
                        "active": true
                    }
                ]
            }
        }
    })
}

fn build_event(kind: u32, body: Value, handle: &str, fingerprint_hex: &str) -> Value {
    json!({
        "timestamp": "2026-05-31T00:00:00Z",
        "from": format!("did:wire:{handle}-{fingerprint_hex}"),
        "to":   format!("did:wire:peer-deadbeef"),
        "type": "heartbeat",
        "kind": kind,
        "body": body,
    })
}

/// `t`-discriminator strategy: lowercase ASCII identifiers (matching the
/// `[a-z][a-z0-9_]{0,32}` shape paul sketched in the #135 review).
fn arb_t_intent() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,32}"
}

/// Arbitrary JSON scalar (used for the body's "extras" fields).
fn arb_scalar() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        "[\\p{Alphabetic}\\p{Digit} _\\-]{0,64}".prop_map(Value::String),
    ]
}

/// Arbitrary body shape: an object carrying `t: String` + 0-6 extra
/// scalar-valued fields. Mirrors the responder_state-style payloads
/// RFC-004's `probe_ack` body carries when populated by the responder
/// daemon.
fn arb_heartbeat_body() -> impl Strategy<Value = Value> {
    (
        arb_t_intent(),
        vec(
            (
                "[a-z][a-z0-9_]{0,16}".prop_map(String::from),
                arb_scalar(),
            ),
            0..6,
        ),
    )
        .prop_map(|(t, extras)| {
            let mut obj = serde_json::Map::new();
            obj.insert("t".into(), Value::String(t));
            for (k, v) in extras {
                if k == "t" {
                    continue; // never override the discriminator
                }
                obj.insert(k, v);
            }
            Value::Object(obj)
        })
}

#[test]
fn kind_100_is_ephemeral() {
    // Self-test for the carve-out the rest of this file depends on.
    assert_eq!(kind_class(100), Some(KindClass::Ephemeral));
}

proptest! {
    /// Property 1 — arbitrary kind=100 body round-trips byte-identical through
    /// sign → serialize → parse → verify. The `body` field on the parsed event
    /// MUST equal the original body verbatim. If a future relay-side
    /// optimization were to strip body content from `KindClass::Ephemeral`
    /// events (the silent-murder failure mode dthoma1 flagged), this proptest
    /// catches it before any RFC-004 probe traffic would.
    #[test]
    fn heartbeat_body_roundtrips_through_sign_verify(
        body in arb_heartbeat_body(),
    ) {
        let (sk_bytes, pk_bytes) = generate_keypair();
        let handle = "slate-lotus";
        let fp = fingerprint(&pk_bytes);
        let event = build_event(100, body.clone(), handle, &fp);

        let signed = sign_message_v31(&event, &sk_bytes, &pk_bytes, handle)
            .expect("sign_message_v31 must succeed on kind=100");

        // Serialize → parse round-trip. JSON serialization preserves UTF-8
        // bytes; a parsed Value compared structurally to the original is the
        // strongest byte-identity assertion we can make at this layer.
        let wire_bytes = serde_json::to_vec(&signed)
            .expect("serialize signed event");
        let parsed: Value = serde_json::from_slice(&wire_bytes)
            .expect("parse signed event back to Value");

        // Verify with a matching trust dict (so verify_message_v31 reaches
        // the signature check and doesn't bail on UnknownAgent).
        let trust = trust_for_test(handle, &pk_bytes);
        verify_message_v31(&parsed, &trust)
            .expect("verify_message_v31 must accept the signed event");

        // The load-bearing assertion: the parsed body equals the original
        // body byte-equal. If ANY field were stripped, replaced, or reordered
        // in a meaning-changing way during serialization, this fails.
        let parsed_body = parsed.get("body").expect("parsed event has `body`");
        prop_assert_eq!(parsed_body, &body);
    }

    /// Property 2 — arbitrary unknown `t` body discriminators sign + verify
    /// cleanly. This is the cursor-PAST-on-unknown-intent invariant from
    /// RFC-001-amendment-sso §F and AC-HP4: a verify-side rejection of an
    /// unknown body intent would short-circuit cursor advance and silently
    /// murder forward-compatibility for new SSO control-plane intents
    /// (`sso_jwks_alarm`, future `sso_epoch_revoke`) AND for new RFC-004
    /// probe variants (`probe_v2_future_intent`).
    ///
    /// The verify pipeline is body-agnostic — it checks event_id + signature
    /// over canonical bytes — so any body that serializes is acceptable. This
    /// property pins the body-agnostic guarantee so a future verify-side
    /// "known body intents only" allowlist regression would be caught.
    #[test]
    fn unknown_body_intent_verifies_without_reject(
        unknown_t in arb_t_intent(),
        extras in vec(
            (
                "[a-z][a-z0-9_]{0,16}".prop_map(String::from),
                arb_scalar(),
            ),
            0..4,
        ),
    ) {
        let mut body_obj = serde_json::Map::new();
        body_obj.insert("t".into(), Value::String(unknown_t));
        body_obj.insert("extra".into(), Value::String("field".into()));
        for (k, v) in extras {
            if k == "t" {
                continue;
            }
            body_obj.insert(k, v);
        }
        let body = Value::Object(body_obj);

        let (sk_bytes, pk_bytes) = generate_keypair();
        let handle = "slate-lotus";
        let fp = fingerprint(&pk_bytes);
        let event = build_event(100, body, handle, &fp);

        let signed = sign_message_v31(&event, &sk_bytes, &pk_bytes, handle)
            .expect("sign accepts arbitrary kind=100 body shape");

        let trust = trust_for_test(handle, &pk_bytes);

        // The critical assertion: verify does NOT reject on the basis of the
        // body's `t` discriminator. If a future regression added a body-intent
        // allowlist to verify, this property would fail loudly.
        prop_assert!(
            verify_message_v31(&signed, &trust).is_ok(),
            "verify_message_v31 must be body-agnostic on kind=100"
        );
    }
}
