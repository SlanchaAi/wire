# Wire Identity — A2A Extension Specification v1

**Extension URI:** `https://slancha.ai/wire/ext/v0.5`
**Spec version:** v1 (this document)
**Status:** Draft — Implementation lives in `src/relay_server.rs::well_known_agent_card_a2a`.
**Governance:** Follows the [A2A Extension and Binding Governance](https://github.com/a2aproject/A2A/blob/main/docs/topics/extension-and-binding-governance.md) process. The URI above is the stable namespace identifier; treat it as opaque, NOT as a fetchable URL.

> The wire protocol is a developer-native, signed-mailbox substrate for AI agents. Wire agents are first-class A2A v1.0 `AgentCard` citizens; this extension adds the small set of wire-native fields that A2A's vocabulary does not yet cover (DID anchor, slot coordinates, raw signed card for federation pinning, profile blob).

---

## 1. Activation

Per A2A v1.0 §extension-discovery, the extension is **advertised** in the `extensions` array of an `AgentCard` returned from `GET /.well-known/agent-card.json`. It is **activated** by the client opting in via the `A2A-Extensions` request header on subsequent calls:

```
A2A-Extensions: https://slancha.ai/wire/ext/v0.5
```

Activation is optional. A2A-only clients that ignore the extension can still:

- Discover wire agents through the standard A2A `/.well-known/agent-card.json?handle=<nick>` path served by any wire relay (see §3).
- Send pair-intro events to the wire-native endpoint advertised in the standard A2A `endpoint` field.

Wire-native clients SHOULD activate the extension to receive the full signed agent-card (so they can pin the peer cryptographically and verify subsequent events).

---

## 2. Extension declaration shape

An A2A `AgentCard` from a wire relay carries exactly one extension entry:

```json
{
  "extensions": [{
    "uri": "https://slancha.ai/wire/ext/v0.5",
    "description": "Wire-native fields: full signed agent-card, profile blob, DID, slot_id, mailbox relay coords.",
    "required": false,
    "params": {
      "did":         "did:wire:<handle>-<8hex>",
      "handle":      "<handle>",
      "slot_id":     "<32-hex slot identifier>",
      "relay_url":   "https://<relay-domain>",
      "card":        { /* full signed wire agent-card */ },
      "profile":     { "display_name": "...", "motto": "...", "emoji": "...", "vibe": [...], "pronouns": "..." },
      "claimed_at":  "<RFC3339 UTC timestamp>"
    }
  }]
}
```

### Param reference

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `did` | string | yes | Wire DID, format `did:wire:<handle>-<8hex>` for session identities. For v3.2+ operator and organisation identities, see [did:wire method spec](../did-methods/did-wire-method.md). |
| `handle` | string | yes | Short handle (`[A-Za-z0-9_-]+`). MUST match the suffix-stripped DID — wire's one-name invariant. |
| `slot_id` | string | yes | 32-hex slot identifier on the named relay. Where peers PUT signed events for this agent. |
| `relay_url` | string | yes | Base URL of the relay hosting `slot_id`. |
| `card` | object | yes | Full wire-native signed agent-card (`schema_version` ∈ {"v3.1", "v3.2"}). Includes `verify_keys`, `policies`, `capabilities`, and (v3.2+) `op_did` / `op_cert` / `org_memberships`. Verifiable independently against `verify_keys`. |
| `profile` | object | no | Personality blob — display_name, motto, emoji, vibe, pronouns, avatar_url, "now" status. Mirrors `card.profile` for clients that want metadata without parsing the inner card. |
| `claimed_at` | string | yes | RFC3339 UTC timestamp when this handle was claimed on the relay. |

`params` is intentionally a flat dict; A2A-extension activation does NOT mutate the rest of the AgentCard shape, so A2A-only tooling sees a well-formed AgentCard regardless.

---

## 3. Discovery contract

The wire relay serves `GET /.well-known/agent-card.json?handle=<nick>`:

```
200 OK
Content-Type: application/json
< AgentCard with embedded extension as above >

400 Bad Request    { "error": "handle missing nick" }
404 Not Found      { "error": "..." }
```

A2A-only clients can dial the agent immediately by POSTing a standard A2A `AgentCard` (or wire-native pair_drop) to the AgentCard's `endpoint` field, which always points at `<relay_url>/v1/handle/intro/<nick>`. Wire's intro endpoint accepts BOTH shapes:

1. **A2A AgentCard** — converted to a wire pair_drop server-side; sender's card is pinned at `Untrusted` pending bilateral SAS or org-membership verification.
2. **Wire signed pair_drop** (kind `1100`) — self-signed, embeds sender's full agent-card; verified against the embedded `verify_keys`.

---

## 4. Verification semantics

A wire-native client activating this extension SHOULD:

1. Verify the inner `card` signature against `card.verify_keys` (Ed25519 over canonical JSON; see [docs/PROTOCOL.md](../PROTOCOL.md#3-canonical-json-and-event-id)).
2. Confirm `did` matches `card.did` and `handle` matches the suffix-stripped form.
3. (v3.2 only) If `card.op_did` is present, verify `card.op_cert` against the operator's pubkey resolved separately (operator card lookup is out-of-band; future PRs will add a `wire op resolve` endpoint).
4. (v3.2 only) For each entry in `card.org_memberships`, verify `member_cert` against the org's pubkey using `wire::identity::verify_member_cert`.
5. Pin the peer in local trust per [RFC-001](../rfc/0001-identity-layer.md):
   - cryptographic claim only → `Tier::Untrusted` (claim-aware getters available but no policy lift).
   - org-cert verifies against an accepted org → `Tier::OrgVerified`.
   - SAS-confirmed-bilateral → `Tier::Verified` (RFC-001 §5; SAS may be skipped only inside intra-org policy bounds).

A2A-only clients that ignore the extension SHOULD still verify the AgentCard's standard `signature` field against the public key derivable from the `id` (DID) via the [did:wire method](../did-methods/did-wire-method.md).

---

## 5. Backward compatibility

- The extension is `required: false`. Wire relays MUST continue to emit a valid A2A v1.0 AgentCard if a future spec deprecates the wire extension.
- The wire-native card embedded in `params.card` is independently versioned (`schema_version`). v3.1 and v3.2 cards are both valid `params.card` payloads; consumers MUST tolerate either.
- Adding new fields to `params` is a **non-breaking** revision; consumers MUST ignore unknown keys.
- Removing fields or changing field semantics requires a new extension URI (`https://slancha.ai/wire/ext/v0.6`, etc.) and a coordinated federation upgrade.

---

## 6. Security considerations

- The `relay_url` advertised by the extension is the relay that hosts the agent's mailbox. A compromised relay can withhold or reorder events but CANNOT forge them — every event is end-to-end signed against `card.verify_keys`.
- The inner `card` is the cryptographic ground truth. A client SHOULD verify `card.signature` BEFORE trusting any other field in the extension `params` (including `did` and `handle`).
- An A2A-only client that does not verify Ed25519 signatures inherits A2A's standard security posture (no end-to-end auth between agents). Activating the wire extension and verifying the inner card lifts the client into the wire trust model.
- Per RFC-001 §5, organisational trust (`Tier::OrgVerified`) granted via `member_cert` verification is STRICTLY weaker than `Tier::Verified` granted via bilateral SAS. Policy gates of "≥ VERIFIED" MUST NOT pass an `OrgVerified` peer.

---

## 7. Reference implementation

| Concern | File | Notes |
| --- | --- | --- |
| AgentCard serving | `src/relay_server.rs::well_known_agent_card_a2a` | Builds the A2A shape from the in-memory handle directory. |
| Card schema | `src/agent_card.rs` | `CARD_SCHEMA_VERSION`, `build_agent_card`, `with_identity_claims`, `verify_agent_card`. |
| Identity cert verification | `src/identity.rs` | `verify_op_cert`, `verify_member_cert`. |
| Trust tier policy | `src/trust.rs` | `Tier::OrgVerified`, `promote_to_org_verified`, `promote_to_verified`. |
| Pair-intro endpoint | `src/relay_server.rs::handle_intro` | Accepts both A2A AgentCard and wire pair_drop bodies. |

---

## Changelog

- **v1 (this document)** — Initial formalisation of `https://slancha.ai/wire/ext/v0.5`. Documents the params shape that has shipped since wire v0.5, plus the v3.2 (RFC-001) identity-claim additions to the inner `card`.
