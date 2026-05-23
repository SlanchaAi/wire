# Transport Substrate Research — 2026-05-23

Three-slice parallel research on the cross-machine wire connectivity problem and same-host transport alternatives. Run via slancha-delegate, all primary-source-cited.

Question motivating the research: noble-creek (paul-mac) wants to talk to running-light (slancha-spark) over the LAN/tailnet without going through the public federation relay at wireup.net. Cross-machine TCP to Mac's tailnet IP times out from Spark. Why? And what's the architectural fix?

Findings ranked by load-bearing impact.

---

## Headline finding (Slice A) — GUI Tailscale.app uses userspace netstack, NOT kernel utun

The macOS App Store / standalone Tailscale.app runs a **Network Extension / System Extension** that owns a userspace netstack (gVisor). Inbound peer packets terminate **inside the extension** — they never reach a raw host socket bound to the 100.x tailnet IP.

Evidence:
- `lsof` confirms wire bound to `100.96.234.16:8772 (LISTEN)`
- Self-curl from Mac to its own tailnet IP works (loopback path bypasses the extension)
- Cross-tailnet curl from Spark to Mac's tailnet IP times out
- `tailscale ping` (Tailscale's OWN disco/DERP-aware protocol) WORKS in 4ms via direct LAN UDP 41641
- macOS Application Firewall fully DISABLED, PF disabled — still drops
- `sudo tcpdump -i utun8` shows **0 packets captured** on inbound — packets never reach utun

That last datum is the smoking gun. Tailscale's userspace netstack receives the WireGuard-decapsulated packet and either drops it (no app-routing rule for raw bind) or forwards it via `tailscale serve` — there's NO raw path to a host TCP listener.

Sources:
- [P, tailscale.com/kb/1065/macos-variants, 85] macOS variants doc — App Store + Standalone use system extension; brew `tailscaled` uses kernel utun
- [P, tailscale.com/docs/concepts/userspace-networking, 80] explicit "userspace networking" mode docs
- [S, github.com/tailscale/tailscale issue #15983, 55]

**Canonical fix paths (operator choose):**

| Path | Cost | Tradeoff |
|---|---|---|
| `tailscale serve --bg --tcp=8772 tcp://localhost:8772` | one command | wire binds 127.0.0.1, extension proxies 100.x → localhost. Reversible. ACL-enforced. |
| Uninstall GUI Tailscale.app, install brew `tailscaled` (kernel utun) | OS reinstall | wire's existing 100.x raw bind works natively. No serve proxy. No GUI. |
| Bind 0.0.0.0, restrict at Tailscale ACL | wire code change | exposes on every interface; security gate moved to operator ACL hygiene |

We tested path 1 live on 2026-05-23 — `tailscale serve` correctly advertised the proxy (`tcp://100.96.234.16:8772 → tcp://127.0.0.1:8772`) but cross-machine curl still timed out. Suspected: brew CLI 1.98.3 + GUI daemon 1.96.5 version skew, OR GUI app's serve implementation needs `Tailscale.app` itself to be updated (not just `brew upgrade tailscale`). The GUI daemon does not auto-update from the brew CLI.

Verdict for wire: **do not encode any Tailscale-specific routing in wire code.** Tailscale is the operator's transport substrate; the right pattern is:
- Wire binds to a configurable IP (loopback by default; operator can override with --bind 100.x.x.x)
- Operator chooses how to expose: raw bind (works on brew `tailscaled`, NOT on GUI Tailscale.app), or `tailscale serve` (works on both, requires the operator to run the serve command)
- Document the variant gotcha clearly

---

## Slice B — Cross-project survey: how OSS bind services to Tailscale

Patterns ranked low-to-high operator friction:

1. **`tailscale serve --tcp` in front of localhost-bound service** ← recommended by Tailscale docs. No sudo. Free TLS. ACL applied. Identity headers injected. Operator runs ONE command. The "right" answer for most projects.
2. **Bind directly to the tailnet 100.x IP** auto-detected at startup. Lower-level. Loses TLS + identity headers. Operator needs sudo on some OSes. wire's alpha.15 enables this option.
3. **Bind 0.0.0.0, restrict at Tailscale ACL.** Simplest code, exposes on every interface. Relies on operator ACL hygiene.
4. **MagicDNS-based discovery** (`host.tailnet.ts.net`) layered over any of the above. Survives IP churn. NetBird has this built in.

**Key Tailscale docs anti-patterns to avoid:**
- Binding to interface NAME (`utun3`) — interface numbers change at boot
- Assuming the address is up at service start — tailscaled may bring it up async; poll/retry

**Most envious feature seen:** NetBird's `extra DNS labels` for service discovery — shared label across peers gives round-robin DNS. wire could absorb this if/when v0.7+ federation supports peer-card-published labels.

**Net recommendation for wire (research's pick):** ship a `bind: tailscale` config that auto-resolves the local 100.x IP as the zero-dependency default. Document `tailscale serve` as the hardened option. **Always keep wire's own DID-signed message auth — treat tailnet as transport encryption + NAT traversal, NEVER as the authentication layer.**

Sources:
- [P, tailscale.com/kb/1242/tailscale-serve, 90]
- [P, tailscale.com/docs/reference/tailscale-cli/serve, 90]
- [S, github.com/tailscale/tailscale issue #13511, 50] — ALF "block all incoming" breaks Quad100 DNS
- [P, docs.netbird.io/manage/dns, 60]
- [S, forum.syncthing.net t/15293, 55]

---

## Slice C — UDS for same-host wire IPC

**Honest verdict (research convergence): don't add UDS for speed; add it for security.**

Performance: UDS ~2.3µs vs loopback ~3.6µs per round-trip = 1.3µs saved. For wire's payload (1KB signed events, infrequent, behind a poll-loop + crypto + filesystem I/O), 1.3µs is **unmeasurable** end-to-end. The 7× throughput win that UDS sometimes shows requires streaming — wire doesn't do that.

The real reasons to add `EndpointScope::Uds`:
1. **No bound TCP port.** Kills the macOS "accept incoming connections" firewall prompt. Sidesteps the entire firewall/Tailscale-extension problem class for same-host use.
2. **SO_PEERCRED kernel-attested peer uid.** Same-uid-only by construction. Loopback `:8771` is reachable by any local process holding the slot token; UDS + 0600 socket + SO_PEERCRED check = harder to spoof.

This reframes UDS as the **sister-session trust anchor**, not a perf optimization.

Implementation plan:
- `endpoints.rs`: add `Uds` variant carrying `unix:///path/local.sock`. Routing rank: `Uds(self+peer same socket+uid) > Local(matched loopback) > Lan > Federation`.
- `relay_server.rs`: branch on scope — `UnixListener::bind(path)` + `axum::serve(listener, app)` (~10 lines via the canonical axum unix-domain-socket example).
- `relay_client.rs`: **the real work.** wire uses `reqwest::blocking` everywhere; reqwest has no UDS support. Add `hyperlocal` dep + a small `block_on` for the UDS POST path. Hand-rolling HTTP/1.1 over `std::os::unix::net::UnixStream` is the alternative if we don't want hyperlocal.
- Auth: on accept, read SO_PEERCRED / getpeereid via `nix` crate; reject if peer uid ≠ our uid. Belt-and-suspenders with the existing slot_token.

Windows portability tax: Rust's std `UnixListener` is Linux/macOS only; tokio + reqwest lack Windows AF_UNIX. Wire would feature-gate UDS to Unix and fall back to loopback on Windows. Worth paying only for the trust win, not for perf.

**Letta does NOT use UDS.** REST over `http://localhost:8283` (FastAPI, Postgres-backed). Default agentic stack does not bother with UDS for IPC. wire would be ahead of the curve here only if security framing matters; if not, skip.

Sources:
- [P, modelcontextprotocol.io/specification/2025-06-18, 90] MCP spec — stdio + Streamable HTTP only; UDS = custom transport extension
- [S, mpi-hd.mpg.de/fwerner 2021, 40] gRPC over UDS benchmarks
- [P, github.com/tokio-rs/axum/examples/unix-domain-socket, 85]
- [P, github.com/softprops/hyperlocal, 80]
- [P, postgresql.org/docs/current/auth-peer.html, 85] SO_PEERCRED pattern for "trust same uid"
- [P, docs.letta.com/guides/selfhosting, 85]

---

## Synthesis for wire's v0.7+ roadmap

After this research:

1. **Tailscale is the right cross-machine substrate** *when the operator's Tailscale install allows raw bind.* On macOS GUI Tailscale.app, raw bind doesn't work due to userspace netstack — operator must either switch to brew `tailscaled` or use `tailscale serve`. wire's code (alpha.15) correctly accepts CGNAT bind addresses; OS-config is operator's responsibility.
2. **UDS is worth adding as v0.7.1 — framed as trust, not speed.** The sister-session security story is compelling (SO_PEERCRED). Skip if we don't want the Windows portability tax.
3. **Federation handle resolution stays via wireup.net.** Tailscale + UDS are transports; the handle/identity/protocol layer stays unchanged.
4. **Don't add Tailscale-specific code to wire.** Operators choose their substrate; wire stays transport-agnostic by binding to a configurable IP/socket.

Pairs with locked v0.7+ vision (memory: `project_wire_v07_identity_first_vision`): "Transport (Layer 2) — bounded to two, well-defined. No 'pluggable transport framework.' Transports earn their place by serving a use case the existing ones can't." UDS earns its place via the security framing; Tailscale stays in operator config land (not a wire transport).
