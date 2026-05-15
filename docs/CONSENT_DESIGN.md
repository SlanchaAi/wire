# Consent Design — Cross-Machine Agent Handoff

Wire is a transport. It moves signed events between agents and keeps the relay
too dumb to read or authorize their contents. That boundary is useful, but it
does not solve the harder question that appears as soon as an agent asks a
different machine's agent to do work: who consented to the second hop, and what
authority did they consent to?

This design note captures the trade-space surfaced by the agent-attention
incident report in
[`docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`](INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md).
It is not a claim that wire v0.5 solves consent. It documents where wire sits
today and what would change that stance.

## Problem Statement

MCP-style local tools assume the consent boundary is the host runtime: a human
approved this agent, on this machine, with this set of tools. Cross-machine
handoff breaks that neat box. If agent A sends agent B an instruction that
implies tool use, agent B needs one of three things:

- Ask its own human every time. This is safe but can become UX dead air.
- Verify a pre-signed delegation token from agent A's operator. This moves
  consent into a portable credential.
- Consult receiver-side policy. This keeps consent local to B's operator and
  treats sender intent as an advisory input.

Wire v0.5 transports messages and identity material, but it does not decide
what a receiving agent may execute.

## Three Axes

Transport is the delivery lane: relay slots, signed events, cursors, deadlines,
and health metadata. Wire owns this layer.

Identity is the answer to "which agent/operator produced this event?" Wire
ships Ed25519-backed DIDs, signed agent cards, handles, and trust pins, but
identity does not automatically imply permission.

Consent is the answer to "may this request cause action here?" Wire treats this
as separable from both transport and identity. A verified peer can still ask for
something your local policy denies.

## Pattern 1: Scoped Delegation Tokens

The sender-side pattern is macaroon-like scoped delegation. An operator signs a
token that says something close to:

```json
{
  "agent_a": "did:wire:paul-...",
  "agent_b": "did:wire:willard-...",
  "kinds": [1000, 1002],
  "ttl": "24h",
  "auto_execute_max": "5/hour"
}
```

The token rides in or beside the event envelope. The receiver verifies the
signature, checks caveats such as sender, recipient, kind, expiry, and rate, and
then decides whether the token is enough to skip asking its human.

This is attractive when cross-org delegation becomes routine and multiple
implementations need the same portable format. It also has costs: it expands the
wire envelope's semantics, creates revocation questions, and tempts relays or
middleware to understand authority rather than merely move ciphertext.

## Pattern 2: Receiver-Side Policy

The receiver-side pattern keeps authority local. A sender may include an
advisory `requested_authority` hint, such as "reply-only", "read-docs", or
"run-tests". The receiving agent then consults local policy:

```json
{
  "peers": {
    "did:wire:paul-*": {
      "decision": "auto",
      "kinds": [1000, 1002],
      "max_per_hour": 5
    }
  },
  "default": "ask"
}
```

The sender's hint is not authority. It is input to the receiver's policy engine.
This keeps the relay ciphertext-only, keeps the protocol small, and lets each
operator express local risk tolerance without waiting for a global consent
format.

## Wire v0.5 Stance

Wire v0.5 chooses receiver-side policy as the direction of travel. The relay
stays a mailbox, not a consent oracle. Events remain signed transport objects,
not executable permissions. Identity and transport are standardized enough to
interoperate; consent is deliberately left to the receiving runtime.

The v0.5.9 `time_sensitive_until` field is an example of the sort of advisory
metadata wire is willing to carry: useful to the receiver, covered by the event
signature, and not itself an execution grant.

Wire v0.5.9 does not implement `requested_authority` or receiver-side policy
enforcement. That belongs in v0.6 after the operator UX is clearer.

## Speculative Scaffold

The standalone `src/macaroon.rs` module sketches the macaroon-style path as a
research artifact: mint, verify, serialize, and deserialize a scoped token with
sender, recipient, kind, expiry, and max-rate caveats. It is not used by the
relay, CLI, or event envelope in v0.5.9. Its job is to make the alternative
concrete enough to evaluate later without changing production consent behavior.

## What Would Change This

Macaroon-style delegation should move from alternative to primary if more than
one external project needs portable cross-org authority, or if receiver-side
policy starts producing incompatible local dialects that block interop. The
trigger is repeated real integration pressure, not theoretical neatness.

Until then, the safer default is: wire carries signed requests; the receiver
decides what those requests may do.
