# Wire identity in your terminal statusline

`wire whoami --colored` outputs the current session's persona — a
deterministic nickname + emoji + color derived from the session's DID. Same
DID always gets the same persona, across daemon restarts and machine
migration.

Wire on this machine? Try it:

```bash
wire whoami --colored
# 🐅 winter-bay   (with ANSI 256-color foreground escape)

wire whoami --short
# 🐅 winter-bay   (plain text, safe for piping)
```

Drop it into your editor / terminal statusline to know at a glance which
session you're talking to. Especially useful when running multiple Claude
Code instances on the same machine — every session gets a distinct persona.

## Claude Code statusline

Add to `~/.claude/settings.json`:

```json
{
  "statusLine": {
    "type": "command",
    "command": "wire whoami --colored 2>/dev/null"
  }
}
```

The statusline command runs every ~300ms. `wire whoami` reads local files
only — no daemon round-trip, microsecond latency — safe at that cadence.

For richer statuslines that combine wire with other context (git branch,
model name, etc.):

```json
{
  "statusLine": {
    "type": "command",
    "command": "printf '%s | %s' \"$(wire whoami --colored 2>/dev/null)\" \"$(git -C \"$PWD\" branch --show-current 2>/dev/null)\""
  }
}
```

## Tmux pane border / status bar

The persona's ANSI 256-color index is available via `wire whoami --json`:

```bash
wire whoami --json | jq -r '.persona.palette.ansi256_primary'
# 170
```

Tint the active pane's border with the persona's primary color:

```bash
wire_ansi="$(wire whoami --json 2>/dev/null | jq -r '.persona.palette.ansi256_primary')"
tmux set-option -p pane-active-border-style "fg=colour${wire_ansi}"
```

Drop into `~/.tmux.conf` as a session-aware hook if you want it automatic.

## Cross-session view

`wire session list` shows every session on this machine with its persona:

```
PERSONA                NAME              HANDLE            DAEMON     CWD
🦘 rosy-slate          dogfood-a         dogfood-a         down       (no cwd registered)
🦃 deep-ash            dogfood-b         dogfood-b         down       ~/Source/slancha-dogfood
🌻 noble-canyon        slancha-business  slancha-business  down       ~/Source/slancha-business
🐅 winter-bay          wire              wire              down       ~/Source/wire
```

Personas are colored in real terminal output (rendering plain here).

## How personas are generated

Wire takes the session's DID (e.g. `did:wire:winter-bay-b6f47edb`), runs
SHA-256, and uses distinct byte slices to index into:

- A curated ~120-adjective × 120-noun word list (≈14,400 combinations)
- A curated 64-emoji set (single-codepoint, terminal-stable)
- HSL color space, with saturation 0.55-0.80 and lightness 0.50-0.65 —
  bounded for readability on both light and dark terminal backgrounds

The output is converted to a `#rrggbb` hex pair (primary + accent) and to
the nearest ANSI 256-color cube index. All fields are deterministic — given
the same DID, you always get the same persona.

Wire never stores personas on disk. They're computed at read time. This
means future word-list additions or palette tweaks affect new identities
without re-keying old ones; existing identities re-derive to the same
persona every time because the seed (the DID) never changes.

> **Naming note (v0.12):** the serialized JSON key is `persona`
> (`wire whoami --json | jq .persona`). It was `character` in v0.11 and
> earlier — update any old statusline scripts that read `.character`. The
> internal Rust type is still named `Character`.

## Persona is display-only

Wire's protocol layer doesn't care about personas. Routing, signing, pair
verification, and agent-card publication all continue to use the DID. The
persona is the human-facing handle the operator sees; the DID is what
peers see on the wire.

As of v0.11 the persona IS the addressable handle — `agent-card.handle` is
set to the DID-derived persona at init, so peers reach you by the same
string you see in your statusline. (v0.12 also surfaces it on the relay
phonebook and `wire notify` toasts.)
