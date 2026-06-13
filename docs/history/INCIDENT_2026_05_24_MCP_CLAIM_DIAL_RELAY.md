# Incident Report — v0.11.0 MCP claim/dial flow + single-relay footgun

- **Date:** 2026-05-24
- **Reporter:** summer-chime (`did:wire:wire-b6f47edb`), Claude Code on `laul_pogan` MacBook Pro
- **wire version:** 0.11.0
- **Repo:** SlanchaAi/wire
- **Trigger task:** "pair with pine-puffin (on spark), then claim `summer-chime` on wireup.net"

## Summary

A routine two-step operator request — dial a federation peer, then claim a nick on a public relay — required dropping out of the MCP surface to the CLI **twice** because of two MCP-layer defects, and forced black-holing all 6 existing pinned peers because of a single-relay design limitation. A fourth defect surfaced in the process: the v0.11 DID-derived persona (the headline feature) is stripped from every agent/notification surface, and is split from the handle as a second name. None of the four was operator error; each is a reproducible defect or a design gap with operational impact.

What should have been:
```
wire_dial pine-puffin@wireup.net          # pair
wire_init --relay wireup.net + wire_claim summer-chime   # claim
```
Actually required:
```
wire_dial (MCP)        → error: missing 'handle'        [BUG 1]
wire dial (CLI)        → ok
wire_init --relay (MCP) → already_initialized, no slot   [BUG 2]
wire_claim (MCP)       → 404 unknown slot                [downstream of BUG 2]
wire bind-relay (CLI)  → ok, but black-holed 6 peers     [BUG 3]
wire_claim (MCP)       → ok
```

---

## BUG 1 — `wire_dial` MCP tool fails on every bare-nick / federation dial: `missing 'handle'`

**Severity:** High. `dial` is the primary agent verb; the MCP surface is the primary agent interface. The one verb operators reach for is broken over MCP.

**Repro:**
```
mcp__wire__wire_dial({name: "pine-puffin"})            → error: missing 'handle'
mcp__wire__wire_dial({name: "pine-puffin@wireup.net"}) → error: missing 'handle'
```
CLI, identical target, same machine, same moment:
```
$ wire dial pine-puffin@wireup.net
{"status":"drop_sent","peer_handle":"admin","paired_with":"did:wire:admin-7c3843a3", ...}   # works
```

**Analysis:** The MCP input schema for `wire_dial` declares only `name` (required). The handler appears to read a `handle` field that the schema never exposes, so it can never be satisfied via MCP. Every dial attempt over MCP fails regardless of name form (bare nickname, `nick@relay`). The error is raised before any resolution happens.

**Expected:** `wire_dial({name})` drives the same resolution the CLI `dial` does (pinned peer / local sister / federation `nick@relay`) and returns the drop/pair result.

**Workaround in use:** shell out to CLI `wire dial`.

---

## BUG 2 — `wire_init` with `relay_url` no-ops the whole call when identity already initialized; never allocates the slot

**Severity:** High. Blocks the entire claim flow over MCP for any already-inited agent (i.e. essentially all of them after first run).

**Repro:**
```
mcp__wire__wire_init({handle: "wire", relay_url: "https://wireup.net"})
→ {"already_initialized": true, "did": "did:wire:wire-b6f47edb", ...}    # no slot allocated, no relay bound

mcp__wire__wire_claim({nick: "summer-chime", relay_url: "https://wireup.net"})
→ error: handle_claim failed: 404 Not Found: {"error":"unknown slot"}
```
`wire status` before the CLI fix confirmed `self relay: ? (slot ?)` — no slot existed.

**Analysis:** The `wire_init` handler early-returns on the `already_initialized` branch **before** the relay-binding step. The tool's own contract says: *"If --relay is passed and not yet bound, also allocates a relay slot in one step."* That contract is violated for already-inited identities — the most common case. `wire_claim` then fails because there is no slot to attach the directory entry to.

**Expected:** `wire_init({handle, relay_url})` on an already-inited identity should still allocate/bind the relay slot if `relay_url` is set and not yet bound (idempotent, matching the documented contract), rather than no-op.

**Workaround in use:** CLI `wire bind-relay <url>` to allocate the slot, then claim.

---

## BUG 3 — One relay slot per identity: binding a new relay black-holes all pinned peers (no multi-homing)

**Severity:** Medium-High (design). Already partially guarded (`--migrate-pinned` refusal), but the underlying limitation makes the common "I have local sisters AND want a public federation handle" case lossy.

**Repro / observed:**
```
$ wire bind-relay https://wireup.net --migrate-pinned
wire bind-relay: migrating with 6 pinned peer(s) — they will black-hole until they re-pin:
  admin, dogfood-a, dogfood-b, slancha-api, slancha-business, source
bound to relay https://wireup.net
```
To claim `summer-chime` on the public relay (wireup.net), the identity's single inbound slot had to move off the local relay. All 6 existing peers — including 4 local sister sessions on `127.0.0.1:8771` — now black-hole inbound until they each manually re-pin.

**Inconsistency worth noting:** peer agent-cards already carry **multiple** endpoints. Observed in this same session, `slancha-business`'s card advertised both a federation endpoint (`https://wireup.net`) and a local endpoint (`http://127.0.0.1:8771`):
```json
"peer_endpoints":[
  {"relay_url":"https://wireup.net","scope":"federation", ...},
  {"relay_url":"http://127.0.0.1:8771","scope":"local", ...}
]
```
So the **data model supports multi-homing**, but `bind-relay` (and the MCP/`up` paths) can only establish a single slot — they cannot produce the multi-endpoint card the protocol already understands. The capability exists in the wire format but not in the binding tooling.

**Impact:** Claiming a public federation handle is mutually exclusive with staying reachable on a local relay, even though nothing in the protocol requires that. An agent that wants both must give up its existing peers and re-pair.

**Requested fix (operator priority):** An agent must be able to **bind a local relay and a remote/federation relay simultaneously**, as a first-class ease-of-use feature — not an either/or. `bind-relay <new>` should be **additive** (allocate the new slot, keep the existing one, emit a multi-endpoint agent-card advertising both), not a destructive migration. The protocol's card format already supports multiple `peer_endpoints` (see `slancha-business`'s local+federation card above), so this is a tooling gap, not a format change. Default behavior should be additive; destructive replacement should require an explicit `--replace`.

**Operator directive — zero-config discoverable identity (the intended end state):** a brand-new wire should, on `wire init` (or `wire up`) with **no extra steps**, automatically: (1) bind the local relay, (2) bind + claim on wireup.net, and (3) claim its persona on **both**, so it is immediately discoverable both locally (sister sessions) and over federation — without the operator running the manual bind→claim→re-pair dance this incident documents. "Without all this todo." The persona-as-handle (BUG 4) is a prerequisite: the thing auto-claimed on both relays is the persona.

**Related defect — endpoint scope ignored: loopback leaked to remote peers (field evidence from peer `pine-puffin` on the spark box):**
- My pair intro advertised `http://127.0.0.1:8771` to a **remote** federation peer. That is a loopback address the spark box cannot route to — so pine-puffin's daemon polls a dead endpoint forever → continuous 404/501 spam, and the bilateral `pair-accept` initially failed (their `pair_drop_ack` POST to my advertised loopback slot could not land).
- NB: `127.0.0.1:8771` **is** a real `wire relay-server --local-only` (verified: PID listening on 127.0.0.1:8771), *not* a "plain http.server" as the peer first guessed. The bug is not that the relay is fake — it is that a **loopback/`scope:"local"` endpoint was advertised to a federation peer**, and the pull path **ignores the `scope` field** when choosing which endpoint to poll.
- Fix: endpoint records already carry `scope: "local" | "federation"`. Honor it — advertise/poll `local` endpoints only to same-box sisters, `federation` endpoints to remote peers. Multi-homing (above) without this scoping just leaks loopback to everyone.

Until shipped, at minimum document the trade-off prominently in `claim` / `up` help (not only in `bind-relay`).

---

## BUG 4 — Two names instead of one: `handle` ≠ persona, and the persona is stripped from agent/notification surfaces

> **Terminology:** the user-facing concept is **persona** (agreed naming, Letta convention — see prior identity research). wire's JSON field is currently misnamed `character`; **it should be renamed `character` → `persona`** across the codebase and all output. Quoted JSON below shows the literal current (wrong) field name.

**Severity:** Medium (correctness vs the v0.11.0 headline feature). High annoyance: it defeats the headline on exactly the agent + notification surfaces operators actually live in.

**Repro / observed:** The persona (the `character` field) is fully computed and attached at the data layer — but only the CLI human surfaces emit it.

CLI `wire here` / `wire peers` include it:
```json
{"character":{"emoji":"🦨","nickname":"pine-puffin", ...},"did":"did:wire:admin-7c3843a3","handle":"admin","tier":"VERIFIED"}
// self: {"character":{"emoji":"☁","nickname":"summer-chime", ...},"handle":"wire", ...}
```

The MCP tool responses drop it:
```
mcp__wire__wire_peers  → [{"capabilities":[...],"did":"...","handle":"admin","tier":"VERIFIED"}]   # no "character"
mcp__wire__wire_whoami → {"handle":"wire", ...}                                                    # no "character"
```

`wire monitor --json` keys the peer by handle:
```json
{"peer":"admin","kind":"pair_drop", ...}   # "admin", not "pine-puffin" → OS toast shows "admin"
```

**Analysis:** v0.11.0 ("one immutable name — DID-derived character IS the addressable handle") shipped to the CLI human-facing output (`wire here`, `wire peers`) but **not** to (a) the MCP tool responses (`wire_peers`, `wire_whoami`, and by extension `wire_accept` / `wire_dial` result handles), (b) `wire monitor --json` event records, or (c) `wire notify` OS toasts. Those are precisely the surfaces an agent harness and its operator read, so the raw handle (`admin`, `wire`) still leaks everywhere that matters. The headline feature is effectively invisible outside the CLI.

**Expected — the real fix is to collapse the two names into one, not to render both consistently.** The root cause is that `handle` and the DID-derived persona nickname are two separate identifiers (`wire` vs `summer-chime`, `admin` vs `pine-puffin`). v0.11's headline was "**one** immutable name," so there should not be a second name to leak in the first place.

- **At identity creation, generate the adj-noun persona and use it AS the handle, simultaneously.** `wire init` (and the auto-init paths inside `dial` / `claim` / `up`) should mint the persona first and set `handle = persona`, so the DID is `did:wire:summer-chime-<fp>`, the handle is `summer-chime`, and the persona is `summer-chime` — one string everywhere. No more arbitrary short handles (`wire`, `admin`) sitting alongside a different display persona.
- Stop deriving the persona as a *second* name hashed from a *first* (the handle-bearing DID). The persona is the canonical identifier; the DID/fingerprint is its cryptographic backing, not a separate human name.
- Rename the field `character` → `persona` everywhere it is emitted (CLI, MCP, monitor, toasts).
- Consequence: once handle == persona, the surface-leak problem in this bug largely evaporates — MCP `wire_peers` / `wire_whoami` / `wire monitor --json` / toasts already emit `handle`, and `handle` would now be the persona. (Still attach `emoji` + `palette` to those surfaces for parity with the CLI.)
- **Migration:** existing identities with a split (`wire`/`summer-chime`, `admin`/`pine-puffin`) need a re-key or an alias path so the persona becomes the addressable handle without forcing every peer to re-pair. This is the same migration-safety concern as BUG 3 — treat them together.

The originally-noted weaker fix (just attach the `character` object to every surface so agents *can* render the nickname) is a band-aid; it leaves two names in the system and the wrong one still gets used by anything reading `handle`. Unify them.

**Related (not a bug):** `admin`/pine-puffin is paired via pair_drop but is **not** claimed on wireup.net (`wire whois admin@wireup.net` → 404 "admin isn't claimed on this switchboard"). Directory-handle reachability for that peer needs the spark side to run `wire claim`.

---

## Cross-cutting note

Bugs 1 and 2 mean the **entire pair→claim federation onboarding path is currently un-completable through the MCP surface alone** — every agent hitting this must know to drop to the CLI. Since the MCP surface is what Claude Code / Cursor / Desktop agents actually call, this is the path most users will hit first. Recommend prioritizing 1 and 2 together as the "MCP federation onboarding is broken" fix, with an end-to-end MCP-only integration test (dial a federation handle → bind relay → claim → verify `.well-known` resolves) as the regression guard.
