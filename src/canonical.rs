//! Canonical wire-byte form for events + cards.
//!
//! Rules (v0.1):
//!   1. Object keys serialize in lexicographic byte order.
//!   2. No whitespace anywhere (`,` and `:` separators only).
//!   3. UTF-8 throughout — non-ASCII is NOT \uXXXX-escaped.
//!   4. The top-level fields `signature` and `public_key_id` are stripped
//!      before serialization (they are computed *over* the canonical bytes,
//!      so they cannot be inside them).
//!   5. The top-level field `event_id` is stripped iff `strict = true` —
//!      `compute_event_id` uses strict-mode bytes; `verify_message_v31`
//!      uses non-strict because the wire copy carries `event_id` already.
//!
//! Implementation note — `serde_json::Map` uses `BTreeMap` internally when
//! the `preserve_order` cargo feature is OFF (which is the default). This
//! gives us free lexicographic key ordering at every nesting level. If a
//! downstream crate ever enables `preserve_order` we'll need to walk and
//! re-sort manually; for now the default is sufficient.

use serde_json::Value;

/// Strip metadata fields from a top-level object before canonicalization.
///
/// Always removes `signature` and `public_key_id`. Removes `event_id` iff
/// `strict` is true.
fn strip_meta(value: &Value, strict: bool) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if k == "signature" || k == "public_key_id" {
                    continue;
                }
                if strict && k == "event_id" {
                    continue;
                }
                out.insert(k.clone(), v.clone());
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Canonical bytes for a JSON value.
///
/// `strict = true` excludes `event_id` (use when *computing* event_id).
/// `strict = false` keeps `event_id` (use for transport/storage).
pub fn canonical(value: &Value, strict: bool) -> Vec<u8> {
    let stripped = strip_meta(value, strict);
    serde_json::to_vec(&stripped).expect("canonical serialization is infallible for Value")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn excludes_signature_and_public_key_id() {
        let v = json!({"a": 1, "signature": "sig", "public_key_id": "id"});
        let out = canonical(&v, false);
        assert!(!std::str::from_utf8(&out).unwrap().contains("signature"));
        assert!(!std::str::from_utf8(&out).unwrap().contains("public_key_id"));
    }

    #[test]
    fn strict_excludes_event_id() {
        let v = json!({"a": 1, "event_id": "deadbeef"});
        assert!(!std::str::from_utf8(&canonical(&v, true)).unwrap().contains("event_id"));
        assert!(std::str::from_utf8(&canonical(&v, false)).unwrap().contains("event_id"));
    }

    #[test]
    fn keys_are_sorted_lexicographically() {
        let a = json!({"b": 1, "a": 2, "c": 3});
        let b = json!({"c": 3, "a": 2, "b": 1});
        assert_eq!(canonical(&a, false), canonical(&b, false));
        let s = String::from_utf8(canonical(&a, false)).unwrap();
        assert_eq!(s, r#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn no_whitespace_in_output() {
        let v = json!({"x": [1, 2, 3], "y": {"z": "w"}});
        let s = String::from_utf8(canonical(&v, false)).unwrap();
        assert!(!s.contains(' '));
        assert!(!s.contains('\n'));
    }

    #[test]
    fn nested_objects_also_sorted() {
        let v = json!({"outer": {"b": 1, "a": 2}});
        let s = String::from_utf8(canonical(&v, false)).unwrap();
        assert_eq!(s, r#"{"outer":{"a":2,"b":1}}"#);
    }

    #[test]
    fn non_ascii_passes_through_unescaped() {
        let v = json!({"name": "Pål"});
        let s = String::from_utf8(canonical(&v, false)).unwrap();
        assert!(s.contains("Pål"), "got {s}");
    }
}
