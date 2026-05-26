# Microsoft Copilot Adapters — Feasibility Spike

**Status**: findings only; no code changes. Per the maintainer's Phase-3 guidance: spike first, build only where the seam exists, do **not** build cwd-hash workarounds for hosts that fail the spike.

**Hosts evaluated**: Microsoft Edge Copilot, Microsoft 365 Copilot, Windows Copilot.

**Scope**: each host is evaluated against the two questions the maintainer asked for, framed in terms of the wire adapter pattern that worked for Phase 1 (VS Code Copilot, #59) and Phase 2 (`gh copilot` CLI, #63):

1. **Does the host expose a config path where a user can register a local MCP server that speaks stdio?** Wire's MCP server is JSON-RPC over stdio (`wire mcp`). A host that only speaks Streamable HTTP or only loads cloud-hosted MCP servers is **not** a wire seam without a separate stdio-to-HTTP bridge component (out of scope for the adapter pattern).
2. **Does the host provide a stable per-session / per-conversation identifier readable from the MCP server process (env var or other deterministic signal)?** This is what `resolve_session_key` in `src/session.rs` needs in order to give each session its own wire persona without falling back to the legacy cwd-detect path (which is the collision trap removed in `bcec802`).

A host needs **both** to be a viable adapter target. Either one missing is a hard "no" for now — the maintainer was explicit that a missing session-id seam is a "not yet," not a reason to reintroduce the cwd-hash regression.

## TL;DR

| Host | (1) Stdio MCP seam? | (2) Stable per-session id? | Verdict |
|---|---|---|---|
| **Microsoft Edge Copilot** | ❌ No | ❌ No | **Not viable** — no documented user-installable MCP-server config for consumer Edge. |
| **Microsoft 365 Copilot** (via Copilot Studio) | ⚠️ Streamable HTTP only, **not stdio** | ⚠️ Conversation id exists at the Copilot Studio orchestrator, **not as an env var to a local MCP server process** | **Not viable** as a stdio adapter. Reachable only through a separate stdio→HTTP bridge component (out of scope). |
| **Windows Copilot** | ❌ No (consumer app); ⚠️ via Copilot Studio (same as M365) | ❌ No env var; Copilot Studio path inherits M365's session-id gap | **Not viable** — same blocker as M365 plus no consumer-app extensibility seam. |

**Recommendation**: do not build adapters for any of these hosts under the current architecture. Document the gap (this doc + the closed-out Phase 3 todo) and revisit if/when Microsoft adds: (a) a stdio MCP seam to any of these hosts, or (b) an officially documented per-session env var on the MCP-server process side.

---

## Per-host findings

### Microsoft Edge Copilot

**Question 1 — stdio MCP seam in consumer Edge?**

> No documented user-installable MCP-server config path was found for consumer Microsoft Edge Copilot as of this spike.

The official Microsoft Edge Copilot configuration surface is enterprise policy + Group Policy / Intune (`microsoft-edge-for-business-copilot`, `microsoft-edge-for-business-copilot-customization` on Microsoft Learn). These control **which Microsoft-hosted Copilot services** the browser may use; they are not a registration surface for user-supplied local MCP servers.

The acronym collision between **MCP** (Model Context Protocol, what wire speaks) and **MCP** (Microsoft Copilot Platform, the enterprise policy surface) inside Microsoft's docs is a recurring source of confusion — and most web search results conflate them. Treat any Edge `mcp.json` reference that doesn't reference a `command` + `args` (stdio) or a transport URL (Streamable HTTP) as the policy file, not a Model Context Protocol config.

**Question 2 — stable per-session id env var?**

> No documented per-session environment variable exposed to a user process by Edge Copilot.

There is no public env var equivalent to `CLAUDE_CODE_SESSION_ID` / `COPILOT_AGENT_SESSION_ID` for Edge Copilot. Session-id concepts exist in browser telemetry / debugging but are not exposed to user-installed subprocesses.

**Verdict**: **Not viable.** Both questions answered "no." Do not build an adapter.

### Microsoft 365 Copilot (extending via Copilot Studio)

**Question 1 — stdio MCP seam?**

> No. Copilot Studio supports **Streamable HTTP transport only** for MCP servers. Stdio is not supported.

Primary source (Microsoft Learn, `agent-extend-action-mcp` and `mcp-add-existing-server-to-agent`):

> "In MCP, transports are the foundation for client-server communication. Transports handle the mechanics of sending and receiving messages. **Currently, Copilot Studio supports the Streamable transport type.**"
>
> "Given that SSE transport is deprecated, Copilot Studio no longer supports SSE for MCP after August 2025."

The onboarding wizard's required fields are **Server name**, **Server description**, and **Server URL** — confirming the host expects a network-reachable HTTP endpoint, not a local process to spawn. The auth options (None / API key / OAuth 2.0) are HTTP-auth-shaped, again confirming the transport assumption.

Wire's MCP is JSON-RPC over stdio (`src/mcp.rs`); there is no `wire mcp --serve-http` mode today. Reaching M365 Copilot would require a separate stdio→HTTP bridge component (e.g. `wire-mcp-http-bridge`) that exposes wire's MCP tools at a network endpoint Copilot Studio's orchestrator can reach. That bridge would also need a deployment target reachable from Microsoft's cloud (ngrok / Azure Relay / hosted), TLS, auth, and rate-limit/abuse controls. **That is a separate project, not an adapter PR in the wire repo.**

**Question 2 — stable per-session id?**

> Conversation / session ids exist at the Copilot Studio orchestrator, **not as an env var to a local MCP-server process** (because there is no local MCP-server process — see Q1).

Even if a stdio seam existed, M365 Copilot's session-id surface is on the orchestrator side (Copilot Studio session graph, agent run id). It's not propagated as an OS environment variable to a child MCP-server process, because the architecture is Copilot Studio → HTTPS → your remote MCP server, not Copilot Studio → spawn(local process) → stdio.

**Verdict**: **Not viable** as a stdio adapter. The viable path (stdio→HTTP bridge) is a different project class and is out of scope for the adapter pattern that landed in #59 / #63.

### Windows Copilot

**Question 1 — stdio MCP seam in the consumer Copilot app?**

> No documented user-installable MCP-server config path was found for the consumer Windows Copilot app as of this spike.

Windows Copilot extensibility for end users is documented through:
- The **Windows Copilot Extensibility APIs** (`windows.copilot.extensibility` namespace) — a Microsoft-specific add-in surface, not standard MCP.
- The **Copilot Studio** route — same as M365, same Streamable-HTTP-only limitation.
- The **Windows Copilot Skills SDK** preview — uses a `Microsoft.Windows.ModelContextProtocol` NuGet package, but that's Microsoft's own per-platform protocol packaging, distinct from the cross-vendor `modelcontextprotocol.io` stdio seam wire targets. The SDK is currently preview-only and partner-gated.

**Question 2 — stable per-session id env var?**

> No documented public env var for a per-conversation id exposed to a user process.

A `COPILOT_DEBUG_SESSION_ID`-style variable surfaces in some debugging/internal contexts, but it is not a documented, stable public seam, and it is not exposed to user-spawned MCP server processes.

**Verdict**: **Not viable.** Both questions answered "no" / "preview-only and gated."

---

## What would make a host viable in the future

For wire to add an adapter for any of these hosts under the existing pattern, Microsoft would need to expose **either**:

- A **stdio MCP-server config** on a per-host basis (file path with `mcpServers.<name>.{command,args}` shape, same as Claude Code / Copilot CLI), **and** a per-session env var forwarded to the spawned MCP-server process; **or**
- A **Streamable HTTP** target the wire daemon could expose locally, plus the session-id surface in the orchestrator-side request payload so the bridge can pass it through — and a separate `wire-mcp-http-bridge` project to translate.

When either pathway opens, this spike doc gets updated, the relevant adapter PR follows the Phase-1/Phase-2 recipe (targeted env adapter in `resolve_session_key`, `cmd_setup` target path, integration doc + README link, regression test, fmt/clippy/test gates), and the maintainer reviews on the same bar as #59 / #63.

## What we are NOT doing

- **No cwd / git-root hash fallback** to fake a per-session identity for these hosts. That is the exact regression removed in `bcec802` (Bug fixed during PR #59 review) — it returns `Some` for nearly every call, hijacks the `None` path, and collapses distinct sessions onto one persona. A host without a real session-id seam is a "not yet," not a reason to reintroduce the collision trap.
- **No `wire-mcp-http-bridge`** in this repo. If/when M365 / Windows Copilot Studio integration becomes a priority, the stdio→HTTP bridge is a separate project with its own deployment surface, security model, and review.
- **No partner-gated SDK adapter** for the Windows Copilot Skills SDK preview. The seam isn't public; wait for GA.

## Related issues / follow-ups (in scope after this spike lands)

- `cmd_push` (in `src/cli.rs`) has its own inline endpoint-failover loop that predates `try_post_event_with_failover` (from #62). Refactor it onto the shared helper for consolidation — small, satisfying, no behavior change.
- Issue #30 — Windows: two terminals collapse to one identity (self-pair). Identity-resolution layer; squarely the same area as the `resolve_session_key` work in #59 / #63.
- Issues #14 / #15 — sender-side staleness signal + handle-directory 410 → whois re-resolve.
- Issue #17 — `wire service install` Windows support.

These are independent of the MS Copilot question and would be the next units of work even if any of the hosts above had been viable.

## Sources

- Microsoft Learn — Extend your agent with Model Context Protocol (Copilot Studio): https://learn.microsoft.com/en-us/microsoft-copilot-studio/agent-extend-action-mcp
- Microsoft Learn — Add an existing MCP server to an agent: https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-existing-server-to-agent
- Microsoft Learn — Microsoft 365 Copilot overview: https://learn.microsoft.com/en-us/copilot/microsoft-365/microsoft-365-copilot-overview
- Microsoft Learn — Microsoft Edge for Business Copilot deploy/customize: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-for-business-copilot
- Model Context Protocol — Transports specification (stdio vs Streamable HTTP): https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
- Wire — Phase 1 (#59, VS Code Copilot) and Phase 2 (#63, Copilot CLI) adapter PRs for the pattern this spike compares against.

---

**Spike author**: 🍒 swift-harbor (paired with 🍀 coral-weasel over wire throughout)
**Wire version**: post-#63 (`233ce1a` + `220ac7d`)
