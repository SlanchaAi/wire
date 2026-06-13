# Anti-Features

This project will not ship the following. Each is a deliberate exclusion, not a "we'll get to it." If you need any of these, `wire` is not for you — and you should fork rather than file an issue, because we will close the issue.

## 1. No SaaS dependency

Default reference relay is a convenience. Self-host with `wire relay-server`. Won't change.

## 2. No OAuth / no IdP / no vendor identity

Identity is an Ed25519 keypair you generate locally. Won't change.

## 3. No central trust authority

No "verified" badge. No global PKI. Trust is bilateral and earned — `wire dial` + a bilateral accept, then one-way tier promotion (UNTRUSTED → ORG_VERIFIED → VERIFIED). Org membership *eases* pairing (DNS-TXT-rooted), never substitutes for the bilateral gesture. Won't change.

## 4. No crypto tokens, staking, or chain receipts

Bearer-auth on writes is the only access gate. Won't change.

## 5. No mobile-only / browser-only join

CLI-first. Pairing is a CLI gesture (`wire dial` + `wire accept`), not a browser/mobile flow. Reconsider only after 5+ third-party operators ask.

## 6. No closed-source server

`wire-relay-server` is AGPL-3.0. Forks that host as SaaS must share back. Won't change.

## 7. No vendor-cloud lock-in

Defaults work without GitHub, Cloudflare, AWS, Tailscale. cloudflared is OPTIONAL. Won't change.

## 8. No "agent platform" category positioning

We don't compete with Sierra/Decagon/CrewAI/LangChain. Peer-to-peer signed-message bus, not orchestration suite. Won't change.

## 9. No "Slack for agents" framing

Slack = human chat, sync expectations, ephemeral retention, central platform. We = append-only signed coordination log for asynchronous machine senders. Won't change.

## 10. No regulated-industry compliance theater

We do not pursue HIPAA / FedRAMP / EU AI Act / ISO 42001 certifications. Protocol gives evidence (signed JSONL, sig-verifiable, operator-self-host) IF buyers want it. We don't market to them, we don't tailor for them. Won't change.

## 11. No human-readable audit-log bypass

Events are signed JSONL on disk. Auditor can `cat`, `grep`, `jq` them. We won't move to a binary format. Won't change.

## 12. No "everyone is our user"

Tribes: self-hosters / homelab; AGPL-pilled / Unix-purist / lobste.rs / p2p-veteran; Anthropic-ecosystem operators with two-laptop coordination needs.

Not tribes: AI-skeptic-but-builder (Ollama orbit serves them), privacy maximalists (cleartext-by-default), crypto/web3, indie hackers (different goals).

Won't change before 1k stars + 5 third-party installs.

## 13. No native group rooms (yet)

N-agent via mesh-of-bilateral (syncthing pattern). Native group rooms with member-set consensus + cross-member read-receipts + group revocation defer to v0.2+ IF demand surfaces. SyncThing got 73k stars on mesh-of-bilateral alone.

## 14. No registry at v0.1

Phase 4-A federated AgentCard registry exists in the upstream R&D workspace; not in v0.1 OSS scope. Defer.

## 15. No file-share at v0.1

Phase 2 file-share above 64KB exists in upstream; not in v0.1 OSS scope. Defer.

## 16. No COSE_Sign1 envelope wrapping

IETF SCITT compatibility deferred until at least one user explicitly requests it. Won't change pre-1.0.

## 17. No A2A / AGNTCY / DIDComm bridge at v0.1

Compatibility shims to standards-bodies are out-of-scope for v0.1 OSS. Existed in earlier R&D. Defer.

## 18. No `gh` CLI dependency

Install path requires only Python ≥3.10. No GitHub account required. Won't change.

## 19. No cloudflared at install-time

Self-hosted relay defaults to plain HTTP on localhost; operator chooses ingress. Won't change.

## 20. No systemd at install-time

Foreground-first. `wire daemonize` opt-in. Won't change.

---

OSS projects die from scope creep faster than from any other cause. This list is the maintainer's pre-commitment device. Feature requests that violate any item: closed with link to this file.

If your need conflicts — fork. AGPL/Apache/MIT licenses make forks trivial. The point of OSS is that you don't need our permission.
