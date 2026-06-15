//! RFC-007 D3.2b-i: the NIP-01 relay protocol — the JSON-array messages a Nostr
//! relay speaks. Pure serialize (client→relay) + parse (relay→client); the
//! WebSocket that actually carries them (`NostrWs`) is the D3.2b-ii slice.
//!
//! NIP-01 messages are JSON arrays whose first element is a type tag:
//!
//! - client→relay: `["EVENT", <event>]`, `["REQ", <sub_id>, <filter>…]`,
//!   `["CLOSE", <sub_id>]`
//! - relay→client: `["EVENT", <sub_id>, <event>]`, `["OK", <id>, <bool>, <msg>]`,
//!   `["EOSE", <sub_id>]`, `["CLOSED", <sub_id>, <msg>]`, `["NOTICE", <msg>]`
//!
//! Wire uses this to publish a [`NostrEvent`] (`EVENT`) and to pull events
//! addressed to its npub (`REQ` with a `#p` filter, read `EVENT`/`EOSE`).

use serde_json::{Value, json};

use crate::nostr_event::NostrEvent;

/// A NIP-01 subscription filter. Only the fields wire uses; every field is
/// optional and omitted from the JSON when empty/`None` (NIP-01 treats an
/// absent field as "no constraint").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// Match these event ids (hex).
    pub ids: Vec<String>,
    /// Match these author pubkeys (hex x-only).
    pub authors: Vec<String>,
    /// Match these kinds.
    pub kinds: Vec<u32>,
    /// `#p` tag — match events that p-tag these pubkeys (i.e. addressed to me).
    pub p_tags: Vec<String>,
    /// Only events at/after this unix time.
    pub since: Option<i64>,
    /// Only events at/before this unix time.
    pub until: Option<i64>,
    /// Cap the number of stored events the relay returns.
    pub limit: Option<usize>,
}

impl Filter {
    /// The NIP-01 JSON object for this filter (empty fields omitted).
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        if !self.ids.is_empty() {
            m.insert("ids".into(), json!(self.ids));
        }
        if !self.authors.is_empty() {
            m.insert("authors".into(), json!(self.authors));
        }
        if !self.kinds.is_empty() {
            m.insert("kinds".into(), json!(self.kinds));
        }
        if !self.p_tags.is_empty() {
            m.insert("#p".into(), json!(self.p_tags));
        }
        if let Some(s) = self.since {
            m.insert("since".into(), json!(s));
        }
        if let Some(u) = self.until {
            m.insert("until".into(), json!(u));
        }
        if let Some(l) = self.limit {
            m.insert("limit".into(), json!(l));
        }
        Value::Object(m)
    }
}

/// A client→relay message.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientMessage {
    /// Publish an event.
    Event(NostrEvent),
    /// Open a subscription `sub_id` matching any of `filters`.
    Req {
        sub_id: String,
        filters: Vec<Filter>,
    },
    /// Close a subscription.
    Close(String),
}

impl ClientMessage {
    /// Serialize to the NIP-01 wire string the relay expects.
    pub fn to_json_string(&self) -> String {
        let v = match self {
            ClientMessage::Event(e) => json!(["EVENT", e]),
            ClientMessage::Req { sub_id, filters } => {
                let mut arr = vec![json!("REQ"), json!(sub_id)];
                arr.extend(filters.iter().map(Filter::to_json));
                Value::Array(arr)
            }
            ClientMessage::Close(sub) => json!(["CLOSE", sub]),
        };
        serde_json::to_string(&v).expect("client message always serializes")
    }
}

/// A relay→client message.
#[derive(Debug, Clone, PartialEq)]
pub enum RelayMessage {
    /// A stored/live event matching subscription `sub_id`.
    Event { sub_id: String, event: NostrEvent },
    /// Result of a publish: `accepted` + a human message.
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    /// End of stored events for `sub_id` (live events follow).
    Eose(String),
    /// The relay closed subscription `sub_id` with a reason.
    Closed { sub_id: String, message: String },
    /// A human-readable relay notice.
    Notice(String),
    /// A message type this client doesn't model (forward-compat — never an error
    /// so a relay extension can't wedge the read loop).
    Unknown(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelayParseError {
    /// Not valid JSON.
    NotJson,
    /// Not a JSON array, or empty.
    NotArray,
    /// First element isn't a string type-tag.
    NoType,
    /// The message had the right tag but the wrong arity/field types.
    BadShape,
    /// An `EVENT` message's event payload didn't parse as a `NostrEvent`.
    BadEvent,
}

impl std::fmt::Display for RelayParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RelayParseError::NotJson => "relay message is not JSON",
            RelayParseError::NotArray => "relay message is not a JSON array",
            RelayParseError::NoType => "relay message has no string type tag",
            RelayParseError::BadShape => "relay message has the wrong shape for its type",
            RelayParseError::BadEvent => "relay EVENT carried a malformed event",
        };
        write!(f, "{s}")
    }
}

impl RelayMessage {
    /// Parse a relay→client message string. Unknown type tags are returned as
    /// [`RelayMessage::Unknown`] rather than erroring.
    pub fn parse(s: &str) -> Result<RelayMessage, RelayParseError> {
        let v: Value = serde_json::from_str(s).map_err(|_| RelayParseError::NotJson)?;
        let arr = v.as_array().filter(|a| !a.is_empty());
        let arr = arr.ok_or(RelayParseError::NotArray)?;
        let tag = arr
            .first()
            .and_then(Value::as_str)
            .ok_or(RelayParseError::NoType)?;
        match tag {
            "EVENT" => {
                let sub_id = str_at(arr, 1)?;
                let event_val = arr.get(2).ok_or(RelayParseError::BadShape)?.clone();
                let event: NostrEvent =
                    serde_json::from_value(event_val).map_err(|_| RelayParseError::BadEvent)?;
                Ok(RelayMessage::Event { sub_id, event })
            }
            "OK" => {
                let event_id = str_at(arr, 1)?;
                let accepted = arr
                    .get(2)
                    .and_then(Value::as_bool)
                    .ok_or(RelayParseError::BadShape)?;
                // Per NIP-01 the message is REQUIRED but commonly empty; tolerate
                // its absence.
                let message = arr.get(3).and_then(Value::as_str).unwrap_or("").to_string();
                Ok(RelayMessage::Ok {
                    event_id,
                    accepted,
                    message,
                })
            }
            "EOSE" => Ok(RelayMessage::Eose(str_at(arr, 1)?)),
            "CLOSED" => Ok(RelayMessage::Closed {
                sub_id: str_at(arr, 1)?,
                message: arr.get(2).and_then(Value::as_str).unwrap_or("").to_string(),
            }),
            "NOTICE" => Ok(RelayMessage::Notice(
                arr.get(1).and_then(Value::as_str).unwrap_or("").to_string(),
            )),
            other => Ok(RelayMessage::Unknown(other.to_string())),
        }
    }
}

/// The string at array index `i`, or `BadShape`.
fn str_at(arr: &[Value], i: usize) -> Result<String, RelayParseError> {
    arr.get(i)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or(RelayParseError::BadShape)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr_event::wire_to_nostr;
    use crate::nostr_key::generate_transport_key;
    use crate::signing::{generate_keypair, sign_message_v31};

    fn an_event() -> NostrEvent {
        let (sk, pk) = generate_keypair();
        let msg = json!({
            "timestamp": "2026-06-14T12:00:00Z",
            "from": "did:wire:slate-lotus-1",
            "kind": 1,
            "body": {"content": "hi"},
        });
        let wire = sign_message_v31(&msg, &sk, &pk, "slate-lotus").unwrap();
        let (nsk, _x) = generate_transport_key();
        wire_to_nostr(&wire, &nsk).unwrap()
    }

    #[test]
    fn filter_omits_empty_fields() {
        let f = Filter {
            p_tags: vec!["abcd".into()],
            kinds: vec![1, 4],
            since: Some(1700000000),
            ..Default::default()
        };
        let v = f.to_json();
        assert_eq!(v["#p"], json!(["abcd"]));
        assert_eq!(v["kinds"], json!([1, 4]));
        assert_eq!(v["since"], json!(1700000000));
        // Empty / None fields are absent (no constraint).
        assert!(v.get("ids").is_none());
        assert!(v.get("authors").is_none());
        assert!(v.get("until").is_none());
        assert!(v.get("limit").is_none());
    }

    #[test]
    fn client_event_serializes_to_nip01() {
        let ev = an_event();
        let s = ClientMessage::Event(ev.clone()).to_json_string();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v[0], "EVENT");
        assert_eq!(v[1]["id"], ev.id);
        assert_eq!(v[1]["sig"], ev.sig);
    }

    #[test]
    fn client_req_serializes_tag_subid_and_filters() {
        let req = ClientMessage::Req {
            sub_id: "wire-sub-1".into(),
            filters: vec![Filter {
                p_tags: vec!["mypub".into()],
                kinds: vec![1],
                ..Default::default()
            }],
        };
        let v: Value = serde_json::from_str(&req.to_json_string()).unwrap();
        assert_eq!(v[0], "REQ");
        assert_eq!(v[1], "wire-sub-1");
        assert_eq!(v[2]["#p"], json!(["mypub"]));
    }

    #[test]
    fn client_close_serializes() {
        let v: Value =
            serde_json::from_str(&ClientMessage::Close("s1".into()).to_json_string()).unwrap();
        assert_eq!(v, json!(["CLOSE", "s1"]));
    }

    #[test]
    fn parse_relay_event() {
        let ev = an_event();
        // A relay echoes the event under a subscription id.
        let s = serde_json::to_string(&json!(["EVENT", "sub-1", ev])).unwrap();
        match RelayMessage::parse(&s).unwrap() {
            RelayMessage::Event { sub_id, event } => {
                assert_eq!(sub_id, "sub-1");
                assert_eq!(event, ev);
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn parse_ok_eose_closed_notice() {
        assert_eq!(
            RelayMessage::parse(r#"["OK","abc123",true,"saved"]"#).unwrap(),
            RelayMessage::Ok {
                event_id: "abc123".into(),
                accepted: true,
                message: "saved".into()
            }
        );
        // OK with missing message tolerated.
        assert_eq!(
            RelayMessage::parse(r#"["OK","abc123",false]"#).unwrap(),
            RelayMessage::Ok {
                event_id: "abc123".into(),
                accepted: false,
                message: String::new()
            }
        );
        assert_eq!(
            RelayMessage::parse(r#"["EOSE","sub-1"]"#).unwrap(),
            RelayMessage::Eose("sub-1".into())
        );
        assert_eq!(
            RelayMessage::parse(r#"["CLOSED","sub-1","rate-limited"]"#).unwrap(),
            RelayMessage::Closed {
                sub_id: "sub-1".into(),
                message: "rate-limited".into()
            }
        );
        assert_eq!(
            RelayMessage::parse(r#"["NOTICE","hello"]"#).unwrap(),
            RelayMessage::Notice("hello".into())
        );
    }

    #[test]
    fn parse_unknown_type_is_not_an_error() {
        // Forward-compat: a relay extension type must not wedge the read loop.
        assert_eq!(
            RelayMessage::parse(r#"["AUTH","challenge"]"#).unwrap(),
            RelayMessage::Unknown("AUTH".into())
        );
    }

    #[test]
    fn parse_rejects_malformed() {
        assert_eq!(
            RelayMessage::parse("not json"),
            Err(RelayParseError::NotJson)
        );
        assert_eq!(RelayMessage::parse("{}"), Err(RelayParseError::NotArray));
        assert_eq!(RelayMessage::parse("[]"), Err(RelayParseError::NotArray));
        assert_eq!(RelayMessage::parse("[123]"), Err(RelayParseError::NoType));
        // EVENT with a non-event payload.
        assert_eq!(
            RelayMessage::parse(r#"["EVENT","sub",{"not":"an event"}]"#),
            Err(RelayParseError::BadEvent)
        );
        // EOSE without a sub id.
        assert_eq!(
            RelayMessage::parse(r#"["EOSE"]"#),
            Err(RelayParseError::BadShape)
        );
    }

    #[test]
    fn client_event_then_relay_event_roundtrip() {
        // Publish shape and the relay-echo shape both carry the same event bytes.
        let ev = an_event();
        let published = ClientMessage::Event(ev.clone()).to_json_string();
        let pv: Value = serde_json::from_str(&published).unwrap();
        // Relay re-emits it with a sub id prepended.
        let echoed = serde_json::to_string(&json!(["EVENT", "s", pv[1]])).unwrap();
        match RelayMessage::parse(&echoed).unwrap() {
            RelayMessage::Event { event, .. } => assert_eq!(event, ev),
            other => panic!("expected Event, got {other:?}"),
        }
    }
}
