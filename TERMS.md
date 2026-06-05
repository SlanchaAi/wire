# Terms of Service — public-good wire relay

**Effective:** 2026-05-10. Applies to the public-good relay operated at `wire.slancha.ai` (and the test deployment at `wire.laulpogan.com`). Self-hosted relays are out of scope — operators of those instances set their own terms.

## 1. The service

Slancha (the "operator") provides a free public-good wire relay — an HTTP mailbox endpoint at `https://wire.slancha.ai/v1/*`. Anyone may use it to coordinate with peers via the wire protocol (see [docs/PROTOCOL.md](docs/PROTOCOL.md)).

The service is provided **as-is, without warranty**. We may take it offline, change behavior, or delete data at any time without notice.

## 2. Acceptable use

You may not use this relay to:
- Send spam, unsolicited advertising, or unwanted automated messages
- Distribute malware, phishing payloads, or content prohibited by law in the operator's jurisdiction
- Harass, threaten, or coordinate harassment of any person
- Circumvent rate limits, quotas, or other technical controls
- Attempt to compromise the relay process or other users' slots
- Use the service for content that infringes copyright, trademark, or other IP rights

Violations result in slot blackholing without notice. Repeat offenders may be blocked at the IP level via Cloudflare WAF.

## 3. Quotas + limits

- Per-event body cap: 256 KiB
- Per-slot total cap: 64 MiB (older content is NOT auto-evicted in v0.1; rotate slots periodically)
- Allocate / pair / bootstrap rate: 10 req/sec sustained, 50 req burst (global, across all callers)
- No SLA. The operator is not on call. Best-effort uptime.

If you need higher quotas or guaranteed availability, **self-host**. The relay is open-source ([AGPL](LICENSES/AGPL-3.0-or-later.txt)) and ~7 MB to deploy ([docs/CONTAINERS.md](docs/CONTAINERS.md)).

## 4. No accounts, minimal logging

The relay does not require accounts, registration, or KYC. It logs:
- Source IP per request (Cloudflare access logs; retained per Cloudflare's policy)
- Request method + path + response code + body size (operator-side, retained 30 days)
- Slot allocation events (slot_id and timestamp; retained until slot expires or operator wipes)

It does NOT log:
- Event body contents (relay is a dumb pipe; bodies are signed, not always encrypted, but not inspected)
- Pair-slot SPAKE2 messages or AEAD bootstrap blobs (handled in-memory only)
- Any operator identity beyond the source IP CF gives us

See [PRIVACY.md](PRIVACY.md) for the full privacy posture.

## 5. Content liability

Wire events are signed by their senders' Ed25519 keys. The operator does not author, edit, or endorse any content stored on the relay. Senders are solely responsible for what they sign.

The operator may, in its sole discretion, remove specific slots in response to:
- Valid DMCA takedown notices (US copyright holders only — send to `abuse@slancha.ai`)
- Court orders from a jurisdiction the operator recognizes
- Reports of abuse violating §2 above

## 6. Termination

The operator may terminate or suspend access for any user, slot, or IP at any time, with or without cause, with or without notice, with or without refund (there's nothing to refund — service is free).

You may stop using the service at any time. To wipe your local state: `rm -rf ~/.config/wire ~/.local/state/wire` plus revoke any slot tokens via `wire rotate-slot`.

## 7. Disclaimer of warranties

THE RELAY IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. THE OPERATOR DISCLAIMS ALL WARRANTIES INCLUDING BUT NOT LIMITED TO MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

The operator's total liability for any claim related to the service is capped at the amount you paid for the service, which is $0.

## 8. Governing law

These terms are governed by the laws of the operator's primary jurisdiction. Disputes that cannot be resolved by good-faith negotiation will be resolved by arbitration in that jurisdiction.

## 9. Changes

The operator may revise these terms at any time. Continued use after a change constitutes acceptance. Material changes will be announced on the project's website + GitHub release notes.

## 10. Contact

- General: `hello@slancha.ai`
- Security: `security@slancha.ai`
- Abuse / takedown: `abuse@slancha.ai`
- DMCA: `abuse@slancha.ai` with subject `[DMCA]`

---

*If you self-host wire, these terms do not apply to your relay. Set your own.*
