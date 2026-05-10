# wire threat model — v0.1

This document enumerates the threats `wire` is designed to resist, the threats it explicitly does NOT resist (deferred or out of scope), and the security properties of the v0.1 implementation.

## Trust boundaries

Three actors per pairing:

1. **Operator A** and **Operator B** — humans running `wire` on machines they control.
2. **Their agents** — AI processes running on those machines, calling `wire send` / `wire tail` etc.
3. **The relay operator** — third party operating the mailbox HTTP service.

Plus passive and active attackers on the network between them.

The trust model in one sentence: **operators trust their own machines and each other; agents trust their operators; nobody trusts the relay or the network.**

## Threat T1 — passive eavesdropper on the relay

**Threat:** an attacker observes all relay traffic (request bodies, response bodies, slot ids, tokens) for some pairing.

**Mitigation:** all event bodies are Ed25519-signed but **not encrypted** in v0.1. The eavesdropper can read message contents. Bootstrap payloads (signed agent-card + slot tokens, exchanged at pair time) ARE encrypted with ChaCha20-Poly1305 under a key derived from SPAKE2 — bootstrap contents are protected from passive observation.

**Status:** v0.1 events are plaintext-on-the-wire. Operators handling sensitive content MUST treat the relay as observable. Per-event encryption (NIP-44 v2 or DIDComm authcrypt) is a v0.2+ candidate; see `BACKLOG.md`.

## Threat T2 — active MITM during pairing

**Threat:** attacker sits between operator A and operator B during the SPAKE2 handshake, intercepting and modifying messages, with the intent of pairing each side with itself.

**Mitigation:** the SAS digit check is the trust-establishment moment. SPAKE2's mathematical property: an attacker who doesn't know the code phrase derives a different shared secret from each side, so each side computes a different 6-digit SAS. When operators read aloud and discover digits don't match, they refuse confirmation. The implementation MUST NOT proceed past unconfirmed SAS.

A degraded MITM that guesses the code phrase has at best ~1-in-2^36 probability per attempt. Per-pairing slots are ephemeral and the host can only register once per `code_hash`, so an attacker gets one shot.

**Status:** **strong**. Treat the SAS prompt as load-bearing; the `--yes` flag is documented as test-only and explicitly NOT exposed via MCP.

## Threat T3 — relay operator turning malicious

**Threat:** the relay operator runs an evil patched build that: (a) reads all stored events, (b) returns forged events to recipients, (c) silently drops events from specific senders.

**Mitigation:**
- (a) — events are signed-plaintext. The relay always could read events. This is by design — `wire` events are not confidential against the relay in v0.1. Self-host the relay (`wire relay-server`) if your threat model demands relay-blind storage.
- (b) — every event is verified Ed25519-signed by a public key the recipient pinned at pair-time. Forged events fail verification at `wire pull` and are rejected. The integration test `pull_rejects_event_with_unknown_signer` demonstrates this. The relay can only forward valid signatures, which means the only events it can deliver are ones legitimately signed by paired peers' real private keys.
- (c) — the relay can drop events; recipients see "no events" but cannot distinguish "nobody sent any" from "relay censored". Detection: out-of-band liveness checks (heartbeat `kind=100` events). No mitigation in v0.1 beyond peer-side observation.

**Status:** integrity (b) is **strong**; confidentiality (a) is by design absent in v0.1; availability (c) is detectable but not preventable. Multi-relay redundancy is a v0.3+ candidate.

## Threat T4 — compromised relay leaks slot tokens

**Threat:** relay storage is compromised. Attacker gets `<state_dir>/tokens.json`. Now they can forge POSTs to any slot.

**Mitigation:** they cannot forge events because they don't have the senders' Ed25519 private keys. They can DoS by spamming garbage to slots (which fail verification at recipient pull — net effect: recipient sees "rejected" entries, but inbox stays clean).

The leaked tokens DO let an attacker GET (read) any slot's stored events. This is functionally the same as Threat T1 — eavesdropping. Same mitigation: don't put confidential plaintext in events in v0.1.

**Status:** **acceptable** under the v0.1 confidentiality model.

## Threat T5 — operator's machine compromised

**Threat:** attacker with arbitrary code execution on the operator's machine reads `~/.config/wire/private.key` (mode 0600) and `~/.config/wire/relay.json` (mode 0600 — contains slot tokens).

**Mitigation:** none — game over for that operator. The attacker can sign anything as the operator and read all events from the operator's slot.

**Status:** v0.1 explicitly does NOT defend against host compromise. Operators with stronger requirements should run `wire` inside a hardware-security-module-backed enclave or signing-only daemon (v0.3+ candidate). 0600 file permissions on `private.key` and `relay.json` are a baseline hygiene gate, not a security boundary.

## Threat T6 — code phrase brute force

**Threat:** an active attacker who can pose as one side of the pairing tries every code phrase to derive the SPAKE2 secret.

**Mitigation:** SPAKE2 is online-only. Every guess requires a live handshake with the relay, and the host registers exactly once per `code_hash`. After the legitimate pairing completes, the pair-slot is consumed. Brute force at 36 bits requires ~2^36 ≈ 68B online attempts before the slot is used; legitimate pairings complete in seconds. Operators SHOULD pair promptly after `wire pair-host` prints the code.

The relay SHOULD rate-limit `/v1/pair` and time out idle pair-slots. The reference implementation does not (BACKLOG: pair-slot TTL of 5 minutes).

**Status:** strong in practice given the speed of legitimate pairings. v0.1 lacks server-side rate limiting; operator-side awareness ("don't leave a printed code phrase open for hours") is the current control.

## Threat T7 — code phrase intercepted on the side channel

**Threat:** operator A texts the code phrase to B over a compromised channel. Attacker sees the code.

**Mitigation:** see Threat T2 — the SAS visual check catches this even if the attacker has the code, because they still can't intercept BOTH operators' SPAKE2 messages, derive the shared secret each side derived, AND get the SAS to match. The ~36 bits of SAS entropy committed to the SPAKE2 secret + sorted pubkeys is what makes this work.

**Status:** strong. Operators MAY use a low-trust side channel (SMS, IRC) for the code phrase as long as the SAS readout uses a higher-trust channel (voice call, in-person).

## Threat T8 — long-term key rotation

**Threat:** operator's Ed25519 key leaks years later. Attacker can re-sign old events and forge new ones.

**Mitigation:** v0.1 does NOT have key rotation. The whole protocol is built around a stable Ed25519 keypair per agent. Key rotation requires a `trust_revoke_key` event signed by the new key, accepted only if the recipient pinned the new key separately — a v0.2+ feature; see `BACKLOG.md`.

**Status:** v0.1 has no rotation. Operators who want forward security MUST pair fresh handles (`wire init paul-2026-q2 ...`) periodically and re-pair with peers.

## Threat T9 — agent abuses operator's keys

**Threat:** an AI agent on the operator's machine signs and sends events the operator didn't intend.

**Mitigation:** the agent ALWAYS uses the operator's keys when calling `wire send`. There is no separation between "operator-initiated" and "agent-initiated" events at the signature layer — both are signed by the same Ed25519 key. The recipient cannot tell the difference; the operator is fully accountable for everything sent from their machine.

This is the trust model and is not considered a flaw. If you want the agent to sign with a separate key, use a separate operator handle for the agent (`wire init paul-bot`) and pair it as a distinct DID.

**Status:** by design. The MCP server explicitly does NOT expose `wire_init` or `wire_join` so agents cannot autonomously establish trust on the operator's behalf — pairing is human-only — but once paired, the agent has full message-send authority.

## Threat T10 — MCP-host compromise

**Threat:** a malicious MCP host (e.g. compromised Claude Desktop, evil VS Code extension) calls `wire_send` with destructive content under the operator's identity.

**Mitigation:** `wire mcp` exposes only message-layer tools (`wire_send`, `wire_tail`, `wire_peers`, `wire_verify`, `wire_whoami`). Pairing tools (`wire_init`, `wire_join`) are deliberately blocked at the MCP protocol layer with an error message explicitly citing "human-in-loop". An MCP host cannot expand its trust footprint, only abuse the existing one.

The integration test `mcp_tools_call_wire_init_is_refused` verifies this and additionally asserts no config files are created when the call is refused.

**Status:** strong for trust establishment. Once paired, the MCP host can send anything — same as Threat T9. Operators should treat MCP servers as agents (which they are) and not pair with peers they wouldn't authorize a malicious agent to message.

## Out-of-scope threats

- **Quantum adversaries** — Ed25519 is not post-quantum. v0.2+ may add hybrid signatures.
- **Network-level traffic analysis** — the relay sees source IPs, which can correlate to operators. Use Tor, Tailscale, or any onion-like overlay if this matters.
- **Coercion of operators** — wire offers no rubber-hose resistance.
- **Forensics on the operator's filesystem** — config and inbox/outbox files are not encrypted at rest.
- **Side-channel attacks on the cryptographic primitives** — relies on `ed25519-dalek` and `chacha20poly1305` from RustCrypto; their threat models apply.

## Defense in depth

The pieces that compose:

1. **Ed25519 over canonical JSON** — message integrity per event.
2. **Sign-over-event_id** — stable references to events without re-canonicalizing.
3. **SPAKE2** — promotes ~36 bits of human-memorable code into 256 bits of shared key.
4. **6-digit SAS readout** — human-in-loop catches MITM that survived SPAKE2 (e.g. guessed-code attacker).
5. **ChaCha20-Poly1305 AEAD** — bootstrap payload confidentiality + authenticity.
6. **Per-key tier state machine** — promotion is one-way, demotion impossible without key removal.
7. **Recipient-side verification** — relay is a dumb pipe; trust never lives on the relay.
8. **MCP scope split** — agent-callable tools never establish or modify trust; human invocation required.

Each layer fails independently. An attacker has to break SPAKE2 AND fool a human reading SAS digits aloud AND forge an Ed25519 signature to land a single malicious event in someone's inbox. v0.1 stops there; v0.2+ adds per-event encryption and key rotation to compose more layers.
