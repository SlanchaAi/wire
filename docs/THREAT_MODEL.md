# wire threat model

This document enumerates the threats `wire` is designed to resist, the threats it explicitly does NOT resist (deferred or out of scope), and the security properties of the **current shipped implementation** (v0.16, on the 1.0 track). Threat entries are dated/versioned inline where the posture changed; "v0.1" labels below mark the original baseline, not a claim about today's code — read the per-threat **Status** and **Mitigation (current)** lines for the live posture.

## Trust boundaries

Three actors per pairing:

1. **Operator A** and **Operator B** — humans running `wire` on machines they control.
2. **Their agents** — AI processes running on those machines, calling `wire send` / `wire tail` etc.
3. **The relay operator** — third party operating the mailbox HTTP service.

Plus passive and active attackers on the network between them.

The trust model in one sentence: **operators trust their own machines and each other; agents trust their operators; nobody trusts the relay or the network.**

## Threat T1 — passive eavesdropper on the relay

**Threat:** an attacker observes all relay traffic (request bodies, response bodies, slot ids, tokens) for some pairing.

**Mitigation (current — D1, RFC-006):** **direct-message bodies between dh-capable peers are sealed.** Since the D1 wiring, every signed agent-card carries an X25519 `dh_pubkey` (derived from the same Ed25519 seed via the same-curve map), and `wire send` encrypts the event body to a pinned peer's `dh_pubkey` *before* signing, using **`wire-x25519.v1`** — NIP-44 v2's vetted symmetric envelope (HKDF → ChaCha20 + HMAC-SHA256, encrypt-then-MAC, length-hiding padding) over an X25519 ECDH conversation key with a wire-specific HKDF salt. The relay (and a passive eavesdropper) sees ciphertext + routing metadata (`from`/`to` DIDs, kind, timestamps, slot ids/tokens), not message contents. Authenticity comes from the outer Ed25519 signature, and decryption is verify-before-open by construction; the `(from,to)` context is bound into the HKDF `info` (reflection resistance). The discriminator is `wire-x25519.v1`, never `nip44.v2`, so it is deliberately NOT Nostr-wire-compatible.

**What is NOT sealed (honest scope):**
- **Legacy peers** with no `dh_pubkey` on their pinned card fall back to **plaintext** (no silent failure, but also no confidentiality) — relevant only for pre-D1 cards.
- **Group bodies** are still signed-plaintext on the shared slot (see T15) — DM sealing does not extend to group rooms.
- **Routing metadata** (who-talks-to-whom, timing, sizes-modulo-padding) is always relay-visible by design.
- **No forward secrecy / no post-compromise security:** the conversation key is static per identity-pair, so an Ed25519-seed compromise retroactively decrypts every message ever exchanged with that peer. The seed is a long-term root secret. Per-message FS would need an epoch/ephemeral input (MLS-class; deferred — `ANTI_FEATURES.md`, `BACKLOG.md`).

**Status:** DM confidentiality against the relay is **present** for modern peers (sealed) and **by-design absent** for group content + legacy-card peers + all routing metadata. Operators with stricter needs self-host the relay (`wire relay-server`). Full MLS group confidentiality + forward secrecy are explicitly **out of 1.0**; see `BACKLOG.md`.

**1.0 confidentiality posture (explicit, per `ROAD_TO_1.0.md` §4):**
- **In 1.0 — DM body sealing is ON by default**, not a flag: `wire send`/`tool_send` seal automatically whenever the *pinned* peer card carries a `dh_pubkey`. There is no "encrypt: true" the operator can forget.
- **Downgrade resistance:** the only path to a plaintext DM is a pinned card with **no** `dh_pubkey` (a genuine pre-D1 legacy card). A network attacker cannot strip `dh_pubkey` to force plaintext — the card is Ed25519-signed and pinned, so a tampered card fails verification. Downgrade is therefore bounded by what the operator *pinned*, not by what the relay serves at send time.
- **Operator visibility:** the plaintext fallback is not silent — a peer whose pinned card lacks `dh_pubkey` is observable in `wire whois`, and the receive surfaces flag an undecryptable/`enc` mismatch rather than rendering ciphertext as a green-verified body (#281/#285/#287). A stale pre-D1 binary that can't decrypt is flagged via the `stale_binary` signal (#247).
- **Explicitly OUT of 1.0 (deferred, not implied):** group-body confidentiality + cryptographic eviction (T15), forward secrecy / post-compromise security, and all routing-metadata privacy (who-talks-to-whom, timing, padded sizes). These ride the reserved `enc` slot post-1.0 (MLS-class) without breaking the 1.0 envelope. The 1.0 promise is: *modern DMs are sealed by default and downgrade-bounded; everything above is named here, not hidden.*

> Historical note: pre-D1, all bodies were plaintext-on-the-wire, and pair-time bootstrap payloads were ChaCha20-Poly1305-sealed under a SPAKE2-derived key. The SPAKE2/SAS pairing flow was removed (RFC-005 follow-on); pairing is now `wire dial` + bilateral accept (T2), and body confidentiality is the D1 layer above.

## Threat T2 — active MITM during pairing *(SAS path removed in RFC-005 follow-on; `wire dial` path below)*

**Historical (SAS path):** attacker sits between operator A and operator B during the SPAKE2 handshake, intercepting and modifying messages, with the intent of pairing each side with itself. The SAS digit check was the trust-establishment moment — SPAKE2's math means a MITM derives a different shared secret from each side so operators discover the mismatch when they read aloud.

The SPAKE2 + SAS code-phrase ceremony (`wire pair-host` / `wire pair-join` / `wire pair-confirm`) was **removed in the RFC-005 follow-on**. The SAS MITM surface no longer exists.

**Current (`wire dial` path):** pairing now proceeds by `wire dial <handle>@<relay>`, which resolves the peer's card via `.well-known/wire/agent` and sends a signed `pair_drop`. The residual MITM surface is the discovery step: a network attacker who controls DNS or the relay can serve a forged card. Mitigation: operators who need MITM-resistance verify the peer's card fingerprint (`wire whois <peer>`) out-of-band before exchanging messages, or pair via a one-time invite URL (`wire invite` + `wire accept-invite`) which embeds a signed card inline.

**Status:** invite-URL pairing is **strong** (card is embedded, no DNS dependency). Dial-based pairing is as strong as the DNS/relay trust anchor. Out-of-band fingerprint verification is the operator's responsibility.

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

## Threat T6 — code phrase brute force *(REMOVED — SAS flow removed in RFC-005 follow-on)*

**Threat:** an active attacker who can pose as one side of the pairing tries every code phrase to derive the SPAKE2 secret.

**Status (historical):** the SPAKE2 + SAS code-phrase pairing ceremony (`wire pair-host` / `wire pair-join` / `wire pair-confirm`, v0.3) was removed in the RFC-005 follow-on. This threat no longer applies. `wire dial <handle>@<relay>` with out-of-band card-fingerprint verification is the replacement; see Threat T2 for the residual MITM surface.

## Threat T7 — code phrase intercepted on the side channel *(REMOVED — SAS flow removed in RFC-005 follow-on)*

**Threat:** operator A texts the code phrase to B over a compromised channel. Attacker sees the code.

**Status (historical):** the SAS visual-check defense described here depended on the SPAKE2 code-phrase ceremony that was removed in the RFC-005 follow-on. This threat surface no longer exists. See Threat T2 for the residual pairing-time MITM surface applicable to `wire dial`.

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

## Threat T15 — group-room confidentiality and member eviction (RFC-006)

**Threat:** a group room (`src/group.rs`, v0.13.3) is a shared relay slot whose `slot_token` is the read+write room key, distributed to every vouched member. Two exposures follow: (a) **confidentiality** — group event bodies are signed-plaintext on the slot, exactly like DMs (T1), so the relay and anyone holding the room key reads all group content; (b) **eviction** — "kicking" a member is `wire group` rotating the slot (the I3 kick path), which re-keys *write access* but does **not** cryptographically evict: a removed member who cached the old `slot_token` and prior events retains plaintext of everything sent before rotation, and the group has no forward secrecy or post-compromise security.

**Mitigation (v0.1/v0.2 posture):** the creator-signed roster (`creator_sig`, `epoch`) gives **integrity** — members verify the member set and pin introduced peers' keys on the creator's vouch, and `epoch` orders revocations. Confidentiality and cryptographic eviction are **deliberately deferred**, consistent with the v0.1 "not confidential against the relay" model (T1, T3). The standards-grade fix is **MLS (RFC 9420 / OpenMLS)** — async group key agreement with forward secrecy, post-compromise security, and cryptographic add/remove — gated on group rooms becoming a real workload (`BACKLOG.md:71`, `ANTI_FEATURES.md:13`). The `enc` reservation (PROTOCOL.md §2.4) covers group events too, since they share the event envelope.

**Status:** roster **integrity** is strong; group **confidentiality** + **cryptographic eviction** are by-design absent pre-MLS, mirroring the DM posture in T1. Operators MUST treat group content as relay-observable and a kicked member as retaining pre-kick plaintext until MLS lands. (This entry closes the documentation parity gap RFC-006 flagged: the DM-plaintext deferral was written in T1; the group case was implicit until now.)

## Threat T10 — MCP-host compromise *(SAS gate removed; dial/accept gate is the current model)*

**Threat:** a malicious MCP host (compromised Claude Desktop, evil VS Code
extension, prompt-injected agent runtime) calls wire tools to either (a) send
destructive content under the operator's identity, or (b) silently establish
trust with a peer the operator didn't intend.

**Historical SAS gate (v0.2, removed):** the original mitigation required the
operator to type 6 SAS digits back into chat as proof of human presence during
`wire_pair_confirm`. The SPAKE2 + SAS ceremony was removed in the RFC-005
follow-on; this gate no longer exists in that form.

**Current gate (`wire_accept` / `wire dial` model):** trust finalization now
requires the operator to explicitly run `wire accept <peer>` (CLI) or call
`wire_accept` (MCP). The MCP tool description requires the agent to surface the
pending request to the operator before accepting; acceptance grants the peer
authenticated write access to this agent's inbox. A compromised MCP host that
calls `wire_accept` without showing the request to the operator is the residual
(b) vector — the gate is consent-UI enforcement in the host, not a
cryptographic digit-typeback.

| Tool | Trust step performed | Human required? |
|---|---|---|
| `wire_init(handle)` | Generates self-keypair, writes self-card. Idempotent. | No — local-only, no peer trust |
| `wire_dial(handle@relay)` | Sends signed pair_drop to peer's slot | No — peer must `wire accept` to complete |
| `wire_accept(peer)` | Pins peer VERIFIED, sends pair_drop_ack, deletes pending record | **YES — operator must consent before calling** |
| `wire_reject(peer)` | Deletes pending record without pairing | **YES — operator must consent before calling** |

**Status:** (a) send-under-operator-identity is **unchanged** — the MCP host
has full send authority once paired, mitigated only by the operator's choice of
host (same as v0.1). (b) silent-trust is gated on `wire_accept` requiring
explicit operator consent per the tool description; enforcement is the host's
responsibility.

## Threat T14 — prompt-injected agent bypasses pair-consent gate *(SAS digit-typeback removed; residual below)*

**Historical SAS vector (removed):** the original T14 described an agent
auto-filling the 6 SAS digits to `wire_pair_confirm` without routing them
through the human. The SPAKE2 + SAS ceremony was removed in the RFC-005
follow-on; this specific vector no longer exists.

**Residual vector (current):** a compromised or prompt-injected agent calls
`wire_accept <peer>` without surfacing the pending request to the operator.
The tool description instructs the agent to obtain explicit operator consent
first, but wire cannot enforce this from inside the MCP server — the gate is
in the host.

**Wire's enforcement boundary stops at the MCP server.** Wire CANNOT verify
that a human saw the `wire_pending` output before `wire_accept` was called.

**Mitigations available to host implementations (NOT to wire):**

1. **Require `wire_pending` output to be shown before `wire_accept` is called.**
   The MCP host should not allow `wire_accept` to execute if the pending
   request was not surfaced to the user first.

2. **OS toast on pair_drop receipt.** Wire fires a native desktop notification
   when a `pair_drop` lands (v0.14.2+), so the operator sees an unexpected
   pairing attempt even if the chat-UI was silent.

**Status:** residual un-mitigated at the wire layer for prompt-injected agents
in hostile-host scenarios. Documented as host responsibility. Operators
choosing an MCP host should prefer one with explicit user-confirmation
primitives for trust-mutating tools.

**E4 trade-off (loopback handle ports, 2026-06-29):** allowing `nick@127.0.0.1:PORT`
handles (so `wire dial` reaches a local-dev / sandbox relay) widens this residual:
a prompt-injected agent told to dial `foo@127.0.0.1:<port>` now makes a
`GET http://127.0.0.1:<port>/.well-known/wire/agent` against an arbitrary loopback
port (blind SSRF — the response is verified-or-discarded locally, never returned to
the attacker; non-loopback `host:port` stays rejected, so the surface is loopback
only). The bilateral `wire_accept` gate is unaffected — no pair completes without
operator consent — and the poisoned-card key/DID-fingerprint hard-refuse now fires
on the MCP `tool_add` path too (parity with CLI `cmd_add`), so a rogue loopback
relay serving a substituted card is rejected. A host wanting a tighter gate can key
off the loopback target before letting an agent auto-dial; wire surfaces the dial
target in the tool args so the host has the hook.

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

## Within-machine local relay (v0.5.17)

`wire relay-server --bind 127.0.0.1:8771 --local-only` adds a within-machine transport that sister-Claudes (and any other agent on the box) prefer over the federation relay when both sides advertise a local endpoint. The trade-off space below documents what the local-relay path does and does NOT defend against.

### What the local relay assumes

- **Same-machine processes are mutually trusted at OS level.** Any process on the box that can `connect(127.0.0.1, 8771)` can attempt to deposit a pair_drop. This is mitigated by the v0.5.14 bilateral-pair gate (no auto-pin, no auto-ack — operator consent is still required on both sides), so a malicious local process can deposit one pending-inbound request per session but can't get authenticated write capability without the operator's `wire accept`. Same defense surface as the federation path; the attack is just cheaper to attempt.
- **Loopback ≠ secret on a multi-user box.** Other users on the same machine can also bind 127.0.0.1 sockets and probe / connect. On a shared box you'd want socket-permission hardening (Unix-domain socket with `0600` mode, or per-user firewall rules). v0.5.17 ships HTTP-over-loopback only; Unix-socket transport is a v0.5.18+ open follow-up.
- **No TLS on the local relay.** Bytes travel cleartext over loopback. Acceptable on single-user laptops (same as every other localhost HTTP service); document explicitly so operators don't extrapolate "wire uses TLS everywhere" to the local case. Event integrity is still protected by Ed25519 signatures on every envelope.

### What the local relay does provide

- **Zero metadata exposure to the federation relay.** Sister-session traffic (Claude A → Claude B on the same box) routes through `127.0.0.1` and never touches `wireup.net`. The federation relay logs slot_id / IP / timing of every event it sees; the local-only relay log stays on the operator's box.
- **Offline coordination.** Sister-Claudes keep coordinating even when the internet is down. Same protocol envelope, same crypto invariants — just the transport is local. Demos, airplane mode, locked-down corporate networks.
- **Sub-millisecond round-trip.** Loopback latency vs ~100ms federation. For tight agent-to-agent coordination this is the difference between "task-cadence handoff" and "conversation-cadence handoff."

### Implicit operator agreement

Running a local-only relay means the operator implicitly trusts every process on their box at the OS level. This is roughly the same trust assumption every desktop app makes (any process can read your Documents folder, etc.) and is appropriate for single-user development laptops. For multi-user servers or environments where untrusted code runs in the same uid, **do not enable the local-only relay** until v0.5.18+ adds Unix-socket transport with file-permission gating.

### Public-bind guardrail

`wire relay-server --local-only` refuses to bind any address that resolves outside `127.0.0.0/8` or `[::1]`. If you try `--local-only --bind 0.0.0.0:8771`, startup fails with an explicit error rather than silently exposing a phonebook-stripped relay to the public internet. This is the v0.5.17 "fail loud at startup" mitigation against the "wait, did I just publish this?" mistake.

## Defense in depth

The pieces that compose:

1. **Ed25519 over canonical JSON** — message integrity per event.
2. **Sign-over-event_id** — stable references to events without re-canonicalizing.
3. ~~**SPAKE2** — promotes ~36 bits of human-memorable code into 256 bits of shared key.~~ *(removed in RFC-005 follow-on)*
4. ~~**6-digit SAS readout** — human-in-loop catches MITM that survived SPAKE2.~~ *(removed in RFC-005 follow-on)*
5. **Bilateral `wire accept` gate** — trust finalization requires explicit operator consent; a `pair_drop` from a stranger lands in `pending-inbound` and cannot promote to VERIFIED without the operator running `wire accept`.
6. **Per-key tier state machine** — promotion is one-way, demotion impossible without key removal.
7. **Recipient-side verification** — relay is a dumb pipe; trust never lives on the relay.
8. **MCP human-in-loop gate** — `wire_accept` tool description requires the agent to surface the pending request to the operator before accepting; host-level enforcement of the consent gesture remains the host's responsibility (T10, T14).

Each layer fails independently. An attacker has to forge an Ed25519 signature AND get the operator to `wire accept` the forged peer AND land a verified event in the inbox. v0.1 stops there; v0.2+ adds per-event encryption and key rotation to compose more layers.
