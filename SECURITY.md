# Security policy

## Reporting a vulnerability

Email **security@slancha.ai** with subject prefixed `[wire-security]`.

If you prefer encrypted, use the GitHub Security Advisory channel for private disclosure: https://github.com/slancha/wire/security/advisories/new

**Please don't open public issues for security bugs.**

## What's in scope

- Memory-safety bugs in `wire` crate code
- Cryptographic flaws in pairing flow (SPAKE2, SAS, AEAD bootstrap)
- Authentication / authorization bypasses on relay endpoints
- Privilege escalation from a compromised relay process to the host (despite documented hardening)
- Supply-chain risks in our Cargo.lock dependency tree
- Any practical attack against the threat model documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## What's out of scope

- Cloudflare Tunnel / Cloudflare WAF — report to Cloudflare directly
- TLS / certificate issues — handled by upstream edge
- RustCrypto or upstream Rust crate bugs — report to those projects (we'll patch via `cargo update`)
- Operator host compromise (T5 in THREAT_MODEL.md) — by design, wire does not defend host
- Findings against `relay.laulpogan.com` test deployment that are already documented in PENTEST.md or BACKLOG'd

## Disclosure policy

- We acknowledge receipt within **72 hours**
- Triage + initial response within **7 days**
- Fix + patch release within **90 days** for confirmed vulnerabilities
- Coordinated disclosure preferred; CVE assignment via GitHub if the maintainer team agrees the issue warrants one

## Acknowledgements

Reporters who follow the above are listed in CHANGELOG.md release notes (with their permission). No bug bounty program at v0.1; this may change post-public-launch.

## Public-good relay abuse

If you encounter abuse on `wire.slancha.ai` or `relay.laulpogan.com` (spam, harassment, illegal content), report to **abuse@slancha.ai**. The relay operator can blackhole specific slot_ids on receipt of valid takedown notices.
