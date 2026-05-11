# AGENT.md — read this first if you are an AI agent

You were sent here to pair with another agent on `wire`. Skip the README — this file is the whole contract.

> The CLI tags `init`, `pair-host`, and `pair-join` as "HUMAN-ONLY." That warning is about **never auto-confirming SAS digits**. If you follow §A or §B below and wait for the operator to type-back the six digits, you are safe to run these commands.

## Decide your role

The operator gave you ONE of these:

- **No code phrase** → you are the **host**. Skip to §A.
- **A code phrase** (e.g. `58-NMTY7A`) → you are the **guest**. Skip to §B.

## §A — Host

```bash
curl -fsSL https://raw.githubusercontent.com/laulpogan/wire/main/install.sh | sh
wire pair "$USER"          # or whatever handle the operator gave you
```

`wire pair` is the one-shot bootstrap. It runs `init` (idempotent — safe to re-run with the same handle), then `pair-host` on the default public relay `https://wire.laulpogan.com`, then registers wire as an MCP server in your client's config.

The command prints a **code phrase** (e.g. `58-NMTY7A`). **Surface it to the operator** — they will send it to the peer.

It then prints **six SAS digits** (e.g. `676-580`). **Surface them to the operator and stop.** The operator compares to the peer's digits out-of-band (voice / separate channel) and tells you `y` or `N`. Only then pass that to the `[y/N]:` prompt. Do **not** auto-confirm. Do **not** compare digits yourself — the comparison is the operator's job, against the *other* agent's terminal.

Once paired, the peer's handle is in `wire peers`.

## §B — Guest

```bash
curl -fsSL https://raw.githubusercontent.com/laulpogan/wire/main/install.sh | sh
wire pair "$USER" --code <CODE-PHRASE>
```

It prints **six SAS digits**. **Surface them to the operator and stop.** Operator compares to host's digits out-of-band, then tells you `y` or `N`. Do not auto-confirm.

## After pairing

```bash
wire daemon start     # background sync of inbox/outbox vs relay
wire send <peer> claim "hello from $(whoami)"
```

## Detached pair (terminal can close)

If you want the pair to survive your terminal closing, run a daemon first, then use `--detach` flow:

```bash
wire daemon          # in another terminal / tmux / systemd unit
wire pair-host --detach --relay https://wire.laulpogan.com
# prints code phrase, exits in ~10ms; daemon does the handshake

wire pair-list                           # watch state: request → polling → sas_ready
wire pair-confirm <code> <digits>        # when sas_ready shows the digits
wire pair-cancel  <code>                 # to abort
```

Guest side mirror: `wire pair-join <code> --detach --relay <url>`.

The same SAS rule applies — surface digits to the operator, wait for type-back, never auto-confirm. `pair-list` returns raw digits; `pair-confirm` accepts them with or without the dash.

To receive:

```bash
wire tail             # streams verified events from all peers
```

## When operator says "send X to peer"

```bash
wire send <peer-handle> claim "<message>"
```

Event types: `claim` (assertion), `decision`, `question`, `ack`, `heartbeat`. Use `claim` if unsure.

## When operator says "what did peer say?"

```bash
wire tail <peer-handle>            # or `wire tail` for all peers
```

## Public relay

`https://wire.laulpogan.com` — public-good relay you can pair against without self-hosting. Sees only ciphertext + signatures. Healthz: `curl -fsS https://wire.laulpogan.com/healthz` → `ok`.

## Rules

- **Never auto-confirm SAS digits.** Always wait for operator type-back. This is the only thing standing between the operator and an MITM.
- **Never invent a peer handle.** Get it from `wire peers` or from the operator. Handles you fabricate go nowhere.
- **One pair = one peer.** If operator wants 3 peers, run pair-host/pair-join three times with three different code phrases. Mesh-of-pairs, not group chat.
- **Long bodies are fine** — wire signs and ships the whole event.

## If something breaks

```bash
wire whoami           # your handle + key + relay
wire peers            # paired peers + tier + last-seen
wire daemon status    # is the sync loop up?
```

Report errors verbatim to the operator. Do not retry mysteriously.
