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

## v0.3+ candidates

- [ ] **Native group rooms** with member-set consensus, cross-member read-receipts, group revocation. R3-F flagged as highest anti-pattern risk. Don't build until ≥1 paid pilot demands AND mesh-of-bilateral demonstrably insufficient.
- [ ] **Per-kind encryption policy** (NIP-44 v2 preferred over DIDComm authcrypt). v0.1 is plaintext-signed-by-default.
- [ ] **SCITT COSE_Sign1 envelope wrapping** for SCITT-aware audit infrastructure.
- [ ] **SPIFFE-SVID dual-emit** for enterprise-Vault integration.
- [ ] **macOS launchd plist** for `wire daemonize` (Linux systemd in v0.1).
- [ ] **mcp wrapper** so claude-agent-sdk can read/write the wire as a tool.

## Distribution + tooling

- [ ] **PyPI package publish** post-v0.1 launch (operator-gated).
- [ ] **Homebrew tap** (atuin pattern).
- [ ] **macOS / Windows PyInstaller binaries** (v0.1 ships Linux x86_64 + ARM64 first).
- [ ] **AUR package** for Arch.
- [ ] **Nix package**.

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

## What does NOT belong in this BACKLOG

Anything from `archive/2026-05-10-enterprise-frame/` (regulated-buyer GTM artifacts) — that lives in operator's separate company doc, not this OSS project. R3-E confirmed: tribe smells gematik energy and bails.
