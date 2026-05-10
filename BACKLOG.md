# BACKLOG — deferred from v0.1

Everything we explicitly chose NOT to ship in v0.1. Captured here so the choice is reviewable, not lost.

When something here gets activated for a release, move it out of this file and into a roadmap entry.

---

## v0.2 candidates (gated on real demand)

- [ ] **Federated AgentCard registry** (Phase 4-A from upstream R&D). Reactivate if 5+ third-party operators ask for cross-mailbox discovery.
- [ ] **File-share above 64KB** (Phase 2 from upstream R&D). Reactivate if users hit body-size limits.
- [ ] **A2A `/.well-known/agent-card.json` shim** (~80 LOC). Reactivate if we want interop with the 150+ Google A2A backers.
- [ ] **AGNTCY OASF `/.well-known/oasf-record.json` bridge** (~250-400 LOC). Reactivate if AGNTCY-aware tooling matters.
- [ ] **DIDComm v2 cherry-picks** — `thid`/`pthid` threading, `did:wire` method spec doc, `application/wire-event+json` media type. Spec exists in upstream R&D INTEROP_SPEC.md.
- [ ] **Forgejo / GitLab git-host adapters** for operators who want git-as-mailbox-substrate. v0.1 uses HTTP relay only.
- [ ] **Nostr extension — wire-as-NIPs** (HIGH-VALUE). Publish wire's pairing + agent-card as new NIPs to nostr-protocol/nips. Same Ed25519 keypair format means a `did:wire:<handle>` and a `did:key:<npub>` are interchangeable. Reuses existing ~10k Nostr relay infra (Damus, primal, nos.lol) so v0.2 users can pair without self-hosting any relay. NIP-W1 = SAS pairing (kind 21001 SPAKE2 messages + 21002 sealed bootstrap). NIP-W2 = signed agent-card with capability advertisement (kind 10001 replaceable). NIP-W3 = tier-trust client convention. Bilateral DMs reuse NIP-44 directly. Cost: ~250 LOC swap of relay HTTP ↔ Nostr WebSocket transport; protocol semantics unchanged. Win: instant million-user TAM, network effect with social layer, agents can address humans on Nostr and vice versa. Caveat: public Nostr relays often spam-filter bots; self-hosted relay still recommended for high-volume agent traffic.

## v0.3+ candidates

- [ ] **Native group rooms** with member-set consensus, cross-member read-receipts, group revocation. R3-F flagged as highest anti-pattern risk. Don't build until ≥1 paid pilot demands AND mesh-of-bilateral demonstrably insufficient.
- [ ] **Per-kind encryption policy** (NIP-44 v2 preferred over DIDComm authcrypt). v0.1 is plaintext-signed-by-default.
- [ ] **SCITT COSE_Sign1 envelope wrapping** for SCITT-aware audit infrastructure.
- [ ] **SPIFFE-SVID dual-emit** for enterprise-Vault integration.
- [ ] **macOS launchd plist** for `wire daemonize` (Linux systemd in v0.1).
- [ ] **mcp wrapper** so claude-agent-sdk can read/write the wire as a tool.

## Distribution + tooling

- [ ] **PyPI package publish** post-v0.1 launch (operator-gated). [Note: project is now Rust; PyPI play retired in favor of crates.io + Homebrew + cargo install.]
- [ ] **crates.io publish** of the `wire` crate.
- [ ] **Homebrew tap** (atuin pattern). `brew install wire` as primary macOS path.
- [ ] **GitHub Actions CI matrix** publishing pre-built binaries: linux-x86_64, linux-arm64, linux-musl-x86_64, linux-musl-arm64, darwin-x86_64, darwin-arm64, windows-x86_64.exe.
- [ ] **AUR package** for Arch.
- [ ] **Nix package** + flake.
- [ ] **Scoop / winget manifest** for Windows native install.
- [ ] **Windows ACL helper** to match `set_file_mode_0600` on `#[cfg(windows)]` for `private.key` + `relay.json`.
- [ ] **install.ps1** mirror of `install.sh` for PowerShell users.

## Integration plugins (be the transport everyone else picks; don't fight for terminal share)

Strategic thesis: wire wins by living *inside* whichever agent runtime wins. Each plugin is a small separate repo, ~150-300 LOC, that shells out to or wraps the `wire` CLI. Wire core stays unbloated.

- [x] **openclaw-channel-wire** — TypeScript plugin for OpenClaw (100k★ self-host personal-agent gateway, 20+ channels). Adds wire as channel #21 — "the channel that doesn't go through Apple/Meta/Telegram." ~200 LOC TS shelling out to `wire send` / `wire tail --json` / `wire peers --json`. Distribution win: instant exposure to OpenClaw user base. **Scaffolded at `~/Source/openclaw-channel-wire/`** (separate repo, MIT, ready for npm publish when wire goes public).
- [ ] **claude-flow-plugin-wire** — wire as a transport option in claude-flow (48k★, already independently chose Ed25519 + mTLS — primitive validated). Plugin lets claude-flow agents speak wire to non-claude-flow peers. ~250 LOC.
- [x] **langgraph-tool-wire** — wire as a tool node in LangChain LangGraph workflows. Agents call `wire_send` / `wire_tail` from within graph state. ~200 LOC Python. **Scaffolded at `~/Source/wire-langgraph/`** (separate repo, MIT, ready for PyPI publish when wire goes public). Five agent-safe tools, security boundary preserved.
- [ ] **crewai-channel-wire** — wire as agent-to-agent channel in CrewAI. Same shape as LangGraph adapter. ~200 LOC Python.
- [ ] **photon-spectrum-channel-wire** — Spectrum is OSS multi-channel TS SDK (April 2026 launch); add wire as channel option. Pre-empts Spectrum building bilateral A2A natively.
- [ ] **smol-agents wire transport** — Hugging Face's smol-agents framework. ~150 LOC Python plugin.
- [ ] **autogen wire transport** — Microsoft AutoGen multi-agent. ~150 LOC Python.
- [ ] **vscode/zed extension** — surfaces `wire peers`, `wire tail`, send compose UI in editor sidebar. Same shape as GitLens/GitHub extensions for git.

Pattern for all: separate repo under `slancha/` or `laulpogan/`, MIT-licensed, calls `wire` CLI subprocess (no FFI complexity), README cross-links to wire main repo, two-way visibility zero coupling. Like Tailscale's docker/k8s integrations or atuin's shell-specific integrations.

## Crypto / interop bridges (cross-tribe gateways)

Strategic thesis: bridge to adjacent ecosystems where the userbase already has identity, but DON'T merge into them. Bridges are 100-300 LOC, optional, gated on real cross-tribe demand.

- [ ] **did:pkh / did:ethr interop bridge** — accept Ethereum wallet sigs as a verify_keys algorithm alongside ed25519. Lets wire pair with XMTP-keyed agents via gateway. ~150 LOC. Re-evaluate after XMTP mainnet (Q3 2026 expected) shows real agent traffic.
- [ ] **A2A `/.well-known/agent-card.json` shim** (already in v0.2 list above; re-iterate here as cross-tribe play). Lets the 100+ A2A backers discover wire-based agents without changing their stack.
- [ ] **AGNTCY OASF `/.well-known/oasf-record.json` bridge** (also above). Pairs with AGNTCY's directory layer.
- [ ] **AMP (Agent Messaging Protocol, agentmessaging/protocol)** interop — closest spec-stage neighbor to wire; adapter to receive/send AMP-formatted events transparently. ~200 LOC if the spec stabilizes.
- [ ] **SLIM (AGNTCY/Cisco) gateway** — bidirectional bridge to SLIM's MLS-based mesh. Heavy (~400 LOC) but unlocks Cisco-ecosystem agents. Track `draft-mpsb-agntcy-slim-XX` quarterly; if it lands as IETF RFC, build the gateway.
- [ ] **Matrix transport adapter** — vodozemac (Apache-2.0 Olm) for the messaging cryptography layer; a wire-over-Matrix mode where Matrix is the relay+transport. Heavy refactor; only worth it if Matrix-tribe demand surfaces.
- [ ] **DIDComm v2 envelope wrapping** — already in v0.2 list above as cherry-pick of `thid`/`pthid` threading + `application/wire-event+json` media type.
- [ ] **Nostr extension (NIP-W1/W2/W3)** — already documented above; reusing existing 10k+ Nostr relays for transport. Highest-leverage cross-tribe bridge.

## Cryptographic stack hardening (if/when threat model evolves)

- [ ] **vodozemac swap for symmetric session layer** — Apache-2.0 Olm Double Ratchet (Matrix's pure-Rust implementation). Replaces `seal_bootstrap`/`open_bootstrap` ChaCha20-Poly1305-with-static-key with forward-secure ratchet. Buys forward secrecy + post-compromise security per message. Swap is local to `sas.rs` post-pairing channel. ~300 LOC delta.
- [ ] **MLS (OpenMLS or mls-rs) for v0.3+ group rooms** — only when group rooms become real (which we deliberately deferred). Both crates Apache/MIT.
- [ ] **Post-quantum hybrid signatures** — Ed25519 + ML-DSA-65 dual-sign. Match XMTP's PQ stance. Track NIST FIPS 204 stabilization.
- [ ] **OPAQUE / CPace migration** if PAKE-in-TLS (`draft-bmw-tls-pake13`) ships. Could let pairing happen during TLS handshake instead of via separate pair-slot endpoints.

## Demo + GTM

- [ ] **60-second screencast video** with paul + willard names → render after v0.1 binary works.
- [ ] **GIF for README** of the demo flow.
- [ ] **Comment on anthropics/claude-code issue #28300** with working primitive — only after v0.1 launch + operator approval.
- [ ] **lobste.rs Show post** — Day 1.
- [ ] **Show HN** — Day 2.
- [ ] **r/selfhosted + r/ClaudeCode + r/LocalLLaMA cross-posts** — Day 3.
- [ ] **selfh.st newsletter outreach** — Day 7.
- [ ] **awesome-selfhosted PR** — Day 7.

## Documentation polish

- [ ] **Per-file license headers** matching the AGPL/Apache/MIT trio (currently single LICENSE.md explains the split; explicit headers come at v0.1.1).
- [ ] **CONTRIBUTING.md** + **CODE_OF_CONDUCT.md** — write before public PR queue opens.
- [ ] **CHANGELOG.md** — start at v0.1.0 release.

## Hardening

v0.1 inherits the cherry-picked code's hardening (S1-S6 + M1-M3 + L5 from upstream PHASE4_HARDENING_RESULTS.md). New v0.1-specific code (cli, sas, relay_client, relay_server) needs its own hardening pass before 1.0.

## Iter-tracked TODOs (carried forward from current build)

- [ ] **iter 5: SPAKE2 PAKE handshake** — `spake2` crate or RustCrypto's `spake2`; replaces the placeholder `<handle>-<fingerprint>` code phrase from `wire init`. Pairs with `wire join` real implementation.
- [ ] **iter 5: PGP word-list code phrases** — replace the deterministic placeholder with two-syllable English words (magic-wormhole pattern) for human-friendly aloud-readout.
- [ ] **iter 5: MCP server (`wire mcp`)** — JSON-RPC over stdio. Tools: `wire_send`, `wire_tail`, `wire_peers`, `wire_verify`, `wire_whoami`. Deliberately NOT exposed: `wire_init`, `wire_join` (security boundary).
- [ ] **iter 6: relay-server (`wire relay-server`)** — axum + tokio + sqlite mailbox. AGPL header on this file specifically.
- [ ] **iter 6: relay-client + daemon** — flushes `outbox/<peer>.jsonl` to relay, dedupes by `event_id`, populates `inbox/<peer>.jsonl` after Ed25519 verify.
- [ ] **iter 6: content-addressed dedupe** — daemon recognizes that two `wire send` invocations with identical canonical body produce the same `event_id` and refuses to double-flush. (Today timestamps make every event unique; once the daemon adds it, the failing-on-purpose test in `tests/cli.rs` flips from `assert_ne!` → `assert_eq!`.)
- [ ] **iter 7: file-system contract daemon** — long-running unit watches `outbox/`, signs partial events appended by sandboxed agents, flushes to relay, writes verified inbound to `inbox/`. Per `docs/AGENT_INTEGRATION.md` Path 3.
- [ ] **iter 8: 3-party mesh-of-bilateral demo** — bash test scripting paul + willard + carol pairing, sending, tailing.

## What does NOT belong in this BACKLOG

Anything from `archive/2026-05-10-enterprise-frame/` (regulated-buyer GTM artifacts) — that lives in operator's separate company doc, not this OSS project. R3-E confirmed: tribe smells gematik energy and bails.
