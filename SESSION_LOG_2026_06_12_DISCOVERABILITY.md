# Session log — 2026-06-12 — post-launch discoverability follow-ups

After A–F merged (D #250 → E #251 → F #253), continued the mission ("Go").
Two follow-up PRs that complete the value of what shipped:

## PR #254 `docs/lead-with-wire-demo` — make `wire demo` the front door
`wire demo` (F) existed but nothing pointed at it. README's 60-second demo
still opened with 6 manual commands; install.sh next-steps didn't mention it.
- README local-demo section now leads with `curl … | sh` → `wire demo`; the
  by-hand two-terminal walkthrough stays below.
- install.sh prints `wire demo` as the first next-step.
Docs/shell only. docs-lint + `bash -n` clean.

## PR #255 `docs/sync-mcp-tool-docs` — stop the agent docs lying + guard
The agent-facing MCP docs advertised ghost tools and missed real ones (and
#250's new wire_here widened the gap).
- PLUGIN.md: removed `wire_up`/`wire_pair_*` (don't exist), listed the full
  27-tool catalog grouped by purpose.
- AGENT_INTEGRATION.md: fixed call-breakers (`wire_tail since=event_id` param
  that doesn't exist, `wire_accept(target=)` → `peer`, `wire tail --since`
  flag that doesn't exist); added wire_here/wire_status/wire_pull rows.
- **Anti-drift guard**: test `agent_docs_match_advertised_tools` reads both
  docs, asserts every `tool_defs()` name is in PLUGIN.md + no ghost tool in
  either. CI fails if tools change without doc updates. Container-gate green.

## Mechanics note
Accidentally started #255's edits on #254's branch (forgot to switch after
PR'ing #254); split them out via `git stash push <paths>` → new branch off
main → pop. Both PRs independent. Pinned-rustfmt reflow on the new test
folded via --amend (caught by the gate; the `| tail` pipe-exit trap avoided
this time by `> log; echo $?`).

## Status
- #254, #255 open, container-gate-green, unmerged (human gate).
- All A–F themes already on main (8f0b66a).
