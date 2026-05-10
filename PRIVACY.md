# Privacy Policy — public-good wire relay

**Effective:** 2026-05-10. Applies to `wire.slancha.ai` and the test deployment at `wire.laulpogan.com`. Self-hosted relays are operated by their respective operators; this policy does NOT govern those.

## 1. What we see

The wire relay sees these things, by protocol design:

- **Source IP** — provided by Cloudflare on every request
- **Bearer slot token** — authenticates writes/reads to a specific slot
- **Event ciphertext bodies** — signed by sender, sometimes (in v0.1, often) plaintext within the signed envelope
- **Pair-slot ephemeral state** — SPAKE2 messages + AEAD bootstrap blobs, both held in memory only and evicted after 5 minutes idle

We do NOT see:
- Code phrases (only their SHA-256, by which we route pair-slots)
- AEAD-key material or SPAKE2 secrets (the math is on the client)
- Operator identities beyond what an IP address reveals
- Real names, emails, phone numbers — we don't collect any

## 2. What we log

| Data | Where | Retention |
|---|---|---|
| Source IP + request method + path + response code + body size | Cloudflare access logs + relay journal | 30 days |
| Slot allocation events (`slot_id`, timestamp) | relay JSONL persistence | until operator manual wipe or slot rotation |
| Stored events per slot (full ciphertext + signatures) | relay disk | until slot deletion or operator manual wipe |
| Error logs | systemd journal on relay host | 30 days |

We do NOT log:
- Event body contents (we don't inspect what we store; we just store it)
- Pair-slot SPAKE2 / AEAD payloads (memory only)
- Anything you send to `wire init`, `wire pair-host`, or `wire pair-join` on YOUR machine — those run client-side; we never see them

## 3. Subprocessors

- **Cloudflare** — provides the tunnel + WAF + edge TLS termination. Cloudflare sees source IPs, request paths, request/response bodies. See [Cloudflare's privacy policy](https://www.cloudflare.com/privacypolicy/).
- **GitHub** (when applicable) — when binaries are downloaded from GitHub Releases, GitHub sees the IP making the download. See [GitHub's privacy policy](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement).

We do not share data with anyone else.

## 4. Your rights

Depending on your jurisdiction:

- **GDPR (EU)** — IP addresses are personal data. You have the right to access, rectify, erase, and port. Email `privacy@slancha.ai` to exercise these. We respond within 30 days. We have no DPO at v0.1; the operator handles requests directly.
- **CCPA (California)** — same as above; you may also opt out of any "sale" of personal data, though we don't sell anything.
- **Other jurisdictions** — write to `privacy@slancha.ai`; we'll do what's reasonable.

To erase your data:
1. Run `wire rotate-slot` (orphans your old slot)
2. Email `privacy@slancha.ai` with the old `slot_id` requesting deletion of the orphaned slot's stored events
3. We delete within 7 days

## 5. Data location

Relay state lives on the relay's host. The host is operated by the operator (Slancha) on infrastructure they choose. Current host: TBD (test deployment is on Spark in [paul's location]; production deployment will be specified at launch).

## 6. Third-party tools (none required)

You may use wire entirely without depending on this relay — `wire relay-server` lets you run your own. In that case, this policy does not apply.

## 7. Children's privacy

The relay is not directed at children under 13. We do not knowingly collect data from children. If you believe we have, contact `privacy@slancha.ai`.

## 8. Changes

We may update this policy. Changes will be announced via the project website and GitHub. Continued use after a change constitutes acceptance.

## 9. Contact

- Privacy requests: `privacy@slancha.ai`
- Security: `security@slancha.ai`
- General: `hello@slancha.ai`

---

*Self-hosted operators: this policy is a template. Adapt it for your deployment, especially §3 subprocessors and §5 data location.*
