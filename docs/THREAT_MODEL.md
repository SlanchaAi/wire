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

**Status:** **strong**. Treat the SAS prompt as load-bearing. The CLI `--yes` flag is documented as test-only. The MCP equivalent (`wire_pair_confirm`) requires the user to type the 6 SAS digits back into chat — accepting only a `y/n` would defeat the gate. See Threats T10 and T14 for the MCP-host trust model.

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

## Threat T11 — abusive paired peer floods recipient's slot

**Threat:** paul and willard pair via SAS. willard's machine is later compromised (or willard goes hostile) and the slot_token + URL paul shared during pairing now belongs to the attacker. Attacker scripts `curl -X POST` posting 256 KiB events to paul's slot at the rate-limit ceiling (10 req/sec global cap on paul's relay). 2.5 MB/sec → 9 GB/hour → ~220 GB/day. Relay disk fills; every other peer-pair on that relay loses service.

**Mitigations available today:**
- **`wire forget-peer willard`** removes willard from paul's trust + drops paul's local copy of willard's slot. **Does NOT revoke the bearer-token paul gave willard during pairing — that's still valid against paul's slot.** This was the v0.1 design gap.
- **`wire rotate-slot`** (new, iter 21) — paul allocates a fresh slot on the same relay, abandons the old one, and emits a signed `kind=1201 wire_close` event over the OLD slot announcing the new mailbox. Old slot → orphaned → attacker's 256 KiB flood goes to a slot nobody reads. Recovery procedure:
  1. `wire forget-peer willard` — drop willard from trust
  2. `wire rotate-slot` — orphan the leaky bearer
  3. Other paired peers see the wire_close and learn the new slot_id (from peer's `wire pull`); they `wire add-peer-slot paul <relay> <new-slot-id> <new-token>` once paul re-issues the token
  4. (v0.2 daemon will auto-update peer's relay.json from the wire_close event; v0.1 needs manual re-issue)

**Underlying design issue:** v0.1 slot tokens are **bilateral-shared** — paul's token is what paul uses to read AND what willard uses to post. If willard is compromised, paul's slot token is in the attacker's hands. v0.2+ should split into:
- Owner-token (paul reads paul's slot)
- Per-peer sender-tokens (willard gets paul-issued, individually revocable, never doubles as paul's read-token)

That's a significant redesign — BACKLOG'd.

**Operator monitoring:** `du -sh ~/.local/state/wire-relay/` periodically; relay disk-cap alerting via systemd or external monitoring. Cloudflare WAF can also rate-limit at the edge if a specific source IP becomes abusive.

**Status:** **partially mitigated as of iter 21** (rotate-slot subcommand). Per-peer revocation via separate sender-tokens deferred to v0.2. v0.1 attack surface bound by: per-peer trust (you SAS-paired with them, you accepted the cost of compromise), 256 KiB body cap (per-event), 10 req/sec global rate limit (per-relay), disk monitoring (operator-side).

## Threat T12 — slot-token rotation gap

**Threat:** even without an abusive peer, a paired peer can become compromised silently (host owned, SSH key stolen) and the operator may want to rotate slot tokens periodically as hygiene.

**Mitigation:** `wire rotate-slot` ships in iter 21. Currently a manual operator action; v0.2 may add scheduled rotation (via systemd timer or cron) for operators who want periodic slot churn.

**Status:** rotation primitive ships v0.1; auto-rotation is v0.2 candidate.

## Threat T10 — MCP-host compromise (revised v0.2 of this threat, Goal 1)

**Threat:** a malicious MCP host (compromised Claude Desktop, evil VS Code
extension, prompt-injected agent runtime) calls wire tools to either (a) send
destructive content under the operator's identity, or (b) silently establish
trust with a peer the operator didn't intend.

**Mitigation v0.1 (initial):** the original v0.1 strategy was to refuse all
pairing tools (`wire_init`, `wire_join`) over MCP entirely — the operator had
to run those from a terminal. This kept (b) airtight at the cost of every
pairing requiring a context switch out of the agent's chat.

**Mitigation v0.2 (Goal 1, current):** pairing tools ARE exposed via MCP, but
the SAS confirmation gate is preserved by requiring the user to type the
**6 SAS digits back into chat** as the only way to finalize:

| Tool | Trust step performed | Human required? |
|---|---|---|
| `wire_init(handle)` | Generates self-keypair, writes self-card. Idempotent. | No — local-only, no peer trust |
| `wire_pair_initiate(relay_url)` | Opens host pair-slot, returns code phrase + session_id | No |
| `wire_pair_join(code_phrase)` | Guest SPAKE2 against code phrase, returns SAS + session_id | No |
| `wire_pair_check(session_id)` | Polls for SAS-ready | No |
| `wire_pair_confirm(session_id, user_typed_digits)` | Validates typed digits vs cached SAS, then finalizes (AEAD bootstrap + pin) | **YES — user types the 6 SAS digits into chat** |

**Why the digit-typeback is the load-bearing step.** Today's `--yes` in CLI
just consumes a `y` keystroke. An MCP host that auto-confirmed via a `y`
boolean would defeat the gate entirely. By requiring the user to type the
**actual SAS digits the user reads from their peer over a side channel**:

1. The agent has no access to the side-channel SAS — only the user does.
2. A malicious agent that shows fabricated digits in chat fails because the
   user's peer's agent shows different (real) digits over voice/text.
3. `wire_pair_confirm` validates digit equality server-side, mismatch aborts
   the session permanently (no retry — forces fresh `pair_initiate`).

**Status:** comparable to CLI `--yes` security for messaging (Threat T9
unchanged); pairing trust is gated on the user typing the correct out-of-band
SAS, which a compromised MCP host cannot fabricate without breaking the
SPAKE2 + AEAD primitives. See Threat T14 for the residual risk.

The integration tests under `tests/mcp_pair.rs` verify each leg:
`wire_init_via_mcp_is_idempotent_for_same_handle`,
`pair_initiate_returns_distinct_session_ids_for_concurrent_calls`,
`full_pair_flow_via_mcp_with_correct_sas_finalizes`,
`pair_confirm_with_wrong_digits_aborts_session`.

## Threat T14 — prompt-injected agent auto-fills SAS digits

**Threat:** an MCP host implementation auto-types the 6 SAS digits to
`wire_pair_confirm` WITHOUT routing the request through the human, defeating
the typeback gate. Concretely:

- A prompt-injected agent in Claude Desktop reads the SAS from `wire_pair_check`'s
  tool result, then calls `wire_pair_confirm` itself with those same digits,
  never showing them to the user.
- A poorly-implemented agent UI auto-fills the digit field from the previous
  tool's output.
- A test harness or "headless" agent flag bypasses user confirmation.

**Wire's enforcement boundary stops at the MCP server.** Wire CANNOT inspect
the user's terminal/UI to verify a human actually typed the digits — by the
time `wire_pair_confirm(session_id, "384217")` arrives over JSON-RPC, the
digits are a string, period.

**Mitigations available to host implementations (NOT to wire):**

1. **Treat `wire_pair_confirm`'s `user_typed_digits` field as user-input-only.**
   The MCP host (Claude Desktop / VS Code MCP / custom agent runtime) should
   require the SAS to come from the user's input field, not from a previous
   tool's output. Today no MCP host has a primitive that enforces this.

2. **Display SAS via a `display_to_user_verbatim` channel.** Future MCP
   capability: a structured output field hosts MUST render to user before
   the agent can call the next tool. v0.2 wire MCP could surface this once
   the spec includes it.

3. **Two-step confirm in chat.** v0.2 candidate: split confirm into
   `wire_pair_request_user_input` (returns a token; agent posts message to
   user) + `wire_pair_submit_user_input(token, digits)`. The host's chat
   transport guarantees the token's lifecycle — agent cannot replay its own
   tool output.

**Wire-side hardening today:**
- The tool description for `wire_pair_confirm` instructs the host that
  digits MUST come from the user typing in chat, not auto-fill.
- Mismatch on first call aborts the session permanently (no brute-force
  window). Tools `wire_pair_check`/`_initiate`/`_join` return prose `next:`
  fields telling the agent to ask the user out loud.
- Goal-2 OS notifications (when shipped) will fire a native toast on
  every `wire_pair_initiate`/`_join` so the user notices unexpected
  pair attempts even if the chat-UI was silent.

**Status:** un-mitigated at the wire layer. Documented as host
responsibility. Operators choosing an MCP host should prefer one with
explicit user-confirmation primitives.

## Threat T13 — relay process compromise leaks to other host workloads

**Threat:** the wire relay process (or any wire process) is exploited via a memory-safety bug in a Rust dependency, an axum/hyper HTTP CVE, or a malicious crate in the supply chain. Attacker now has code execution as the user that owns the wire process. On a shared host running wire alongside other workloads (a Spark box running forge / slancha-api / training pipelines / SSH keys / Anthropic API keys / etc.), this is a *lateral movement* problem distinct from the wire protocol's threat model.

**Memory-safety baseline:**
- wire is pure Rust. ed25519-dalek, chacha20poly1305, spake2, sha2, hkdf, axum, tokio, hyper, reqwest are all RustCrypto-grade or production-grade with active audit history. **No C in the critical path.**
- `cargo audit` is part of the build pipeline (CI YAML + recommended pre-release check). v0.1.0 audited clean as of 2026-05-10 after patching `time` 0.3.45 → 0.3.47 (RUSTSEC-2026-0009 stack-exhaustion DoS).
- Worst-realistic case: a panic in axum or tokio request handling crashes the relay process. systemd `Restart=on-failure` brings it back. A panic does NOT escalate to RCE in safe Rust.

**Lateral-movement mitigations available today:**
- **systemd `NoNewPrivileges=true` + `PrivateTmp=true`** — applied to `wire-public-relay.service` and `wire-public-landing.service` on the test deployment. Process cannot acquire new privileges via setuid binaries; tmp files are isolated.
- **Resource caps:** `MemoryMax=1G`, `CPUQuota=50%`, `TasksMax=200` — bound damage from runaway / DoS / abusive bearer flooding (T11). A wire process can't OOM-kill the host or starve forge.
- **Listen-on-loopback:** relay binds `127.0.0.1:8770`; only Cloudflare Tunnel reaches it from outside. No direct internet exposure of the Rust process.
- **Operator runs as non-root user:** wire uses user-mode systemd. Process does not have CAP_SYS_ADMIN, cannot mount filesystems, cannot reboot the host.

**Mitigations available but not applied to user-mode systemd on Spark:**
The example unit at `examples/systemd/wire-relay-server.service` includes `ProtectSystem=strict`, `ProtectHome=read-only`, `ProtectKernelTunables=true`, `LockPersonality=true`, `RestrictNamespaces=true`, `SystemCallFilter=@system-service`, etc. These directives require root-mode systemd to apply capability-bounding sets and fail with status `218/CAPABILITIES` in user mode. **Operators running wire as a system-mode unit (`/etc/systemd/system/`) get the full hardening set; user-mode deployments get the minimal subset.** The example file documents both.

**What an attacker WOULD have, even with full host compromise:**
- Read access to `~/.config/wire/private.key` (Ed25519 seed) → can sign as the operator's DID → game over for that DID, but recoverable by `wire init` with a new handle and re-pairing
- Read access to `~/.config/wire/relay.json` (slot tokens) → can read operator's mailbox + forge events as that operator → mitigated by `wire rotate-slot` (T11)
- Read access to anything else under `~/.config/` and `~/.local/state/` that's owned by the same user — INCLUDING other workloads' state if they share the user account
  - Recommendation: run wire as a dedicated service user, not as the operator's daily-driver account. v0.2 release notes will document this; for v0.1 test deployment on Spark we accept the shared-`admin` posture.

**What an attacker WOULD NOT have:**
- Root on the host (no `sudo` access; `NoNewPrivileges` blocks setuid escalation)
- Access to other users' homes (`ProtectHome=read-only` would block, but not currently applied in user mode — operator's other workloads under `/home/admin/` are technically reachable; see "shared user account" caveat above)
- Direct kernel tampering (would need CAP_SYS_ADMIN; wire never has this)
- Permanence beyond process lifetime (no persistence beyond what the operator's user can already write — restart from clean source recovers)

**Supply chain:**
- 294 transitive Rust dependencies (per `cargo audit` output)
- All locked via `Cargo.lock` checked into the repo — reproducible builds
- `--locked` flag should be passed to `cargo build` / `cargo install` in CI to enforce
- Future hardening: sigstore-rooted release artifact attestation (BACKLOG)

**Operational hygiene:**
- `cargo audit` should run on every CI build (`.github/workflows/ci.yml` covers this implicitly via Swatinem cache; explicit `cargo audit` step is a v0.2 ask)
- Subscribe to RustSec advisories for the dep tree
- Keep deps updated; `cargo update` regularly + retest

**Status:** **principled mitigations in place; full system-mode hardening available but unused on Spark's user-mode test deployment.** Operators with stronger isolation needs (multi-tenant, regulated, etc.) should: (1) run wire as a dedicated service user, (2) use system-mode systemd with the full hardening directive set, (3) optionally run wire inside a container or VM for additional isolation.

## Out-of-scope threats

- **Quantum adversaries** — Ed25519 is not post-quantum. v0.2+ may add hybrid signatures.
- **Network-level traffic analysis** — the relay sees source IPs, which can correlate to operators. Use Tor, Tailscale, or any onion-like overlay if this matters.
- **Coercion of operators** — wire offers no rubber-hose resistance.
- **Forensics on the operator's filesystem** — config and inbox/outbox files are not encrypted at rest.
- **Side-channel attacks on the cryptographic primitives** — relies on `ed25519-dalek` and `chacha20poly1305` from RustCrypto; their threat models apply.

## Network-resilience doctrine (v0.5.13)

Wire's HTTPS surface (relay POST/GET, `/stream` long-poll, well-known fetches) consults Mozilla webpki roots + the OS native trust store via `rustls-tls-native-roots`. Three rules cover the "corporate AV/proxy is MITM-ing every TLS connection" failure class surfaced in issue #6:

1. **Loud transport error class.** Every transport failure surfaces the full `anyhow::Error` source chain with a leading class label (`TLS error:`, `DNS error:`, `timeout:`, `connect error:`). `wire push --json` returns the formatted reason in the `reason` field. No silent `"skipped: 23, reason: POST https://…"` — the real cause (`invalid peer certificate: UnknownIssuer`, `failed to lookup address`) is always visible.

2. **OS native trust store.** macOS Keychain, Linux `/etc/ssl/certs`, Windows certificate store are all consulted. Corporate / on-prem CAs work without code-side configuration. `SSL_CERT_FILE` is honored by rustls when set.

3. **`WIRE_INSECURE_SKIP_TLS_VERIFY` escape hatch.** Setting the env var to a truthy value (`1`, `true`, `yes`, `on`) disables TLS verification for every wire HTTPS client AND prints a loud red stderr banner on the first send each process. Intended for the corporate-network "AV product re-signs every cert, no other choice" case. **MITM attacks against the relay path are undetectable in this mode** — only the wire envelope (Ed25519 over canonical JSON) keeps protecting message integrity; the relay can fully see and tamper with metadata. Never default-on; loud-failed if used.

### Operator workflow when `wire push` fails with a TLS error

1. Inspect: `wire push --json | jq '.skipped[].reason'` shows the full TLS chain.
2. If your environment trusts a corporate CA: install it in the OS trust store; wire picks it up next run.
3. If you cannot install the CA (managed device, etc.): `WIRE_INSECURE_SKIP_TLS_VERIFY=1 wire push` once to confirm. Then escalate to your IT to install the CA properly; do not leave the env var set as a permanent workaround.

## Defense in depth

The pieces that compose:

1. **Ed25519 over canonical JSON** — message integrity per event.
2. **Sign-over-event_id** — stable references to events without re-canonicalizing.
3. **SPAKE2** — promotes ~36 bits of human-memorable code into 256 bits of shared key.
4. **6-digit SAS readout** — human-in-loop catches MITM that survived SPAKE2 (e.g. guessed-code attacker).
5. **ChaCha20-Poly1305 AEAD** — bootstrap payload confidentiality + authenticity.
6. **Per-key tier state machine** — promotion is one-way, demotion impossible without key removal.
7. **Recipient-side verification** — relay is a dumb pipe; trust never lives on the relay.
8. **MCP human-in-loop gate** — pairing tools are agent-callable, but trust finalization requires the user to type the 6-digit SAS back into chat (`wire_pair_confirm`). The user-typed digits are compared server-side against the SPAKE2-derived SAS; mismatch aborts permanently (T10). Host-level enforcement of "digits came from human, not from prior tool output" remains the host's responsibility (T14).

Each layer fails independently. An attacker has to break SPAKE2 AND fool a human reading SAS digits aloud AND forge an Ed25519 signature to land a single malicious event in someone's inbox. v0.1 stops there; v0.2+ adds per-event encryption and key rotation to compose more layers.
