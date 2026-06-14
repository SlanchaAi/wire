# wire integration tests (`tests/it/`)

**Real** end-to-end tests, not unit tests. Each script boots actual relay
processes and drives the shipped `wire` binary exactly as a user or script
would, then asserts on observable behaviour — pinned peers, delivered + verified
messages, trust tier, group membership. They cover the seams `cargo test`'s
library-level tests can't: the real CLI surface, arg parsing, process
lifecycle, and on-machine multi-agent connections.

## Run

```sh
cargo build --release --bin wire
WIRE=./target/release/wire tests/it/run-all.sh      # whole suite
WIRE=./target/release/wire tests/it/10-handle-pair.sh   # one test
```

Requires `jq` and `curl`. Each test is self-contained: it allocates its own
temp homes, boots its own loopback relay(s) on a dedicated port, and cleans up
on exit. Runs in CI as the `integration-tests` job and in the local
`test-env/run.sh` gate.

## The suite

| Test | Flow exercised |
|------|----------------|
| `10-handle-pair` | Two agents pair zero-paste over a loopback relay; bidirectional signed messages; bilateral accept gate; VERIFIED tier. |
| `20-local-mesh`  | Three `session new` sisters on one box; `pair-all-local` forms the mesh; sister→sister signed send over loopback. |
| `30-onboarding`  | `wire up <relay>` full bootstrap (init+bind+claim) and `wire up --offline` keygen; one-name persona; offline binds nothing. |
| `40-nuke-recovery` | `nuke --dry-run` changes nothing, `--force` wipes, re-`up` rebuilds. |
| `50-group-chat`  | Join-by-code: a member who never pairs anyone is read VERIFIED by others via the creator's signed roster (introduce-on-vouch). |

## Adding a test

Name it `NN-<slug>.sh` (the runner globs `[0-9]*-*.sh` in order), `source`
`lib.sh`, call `it_init`, and use `boot_relay` / `w` / `wait_until` / `assert` /
`pair_handle`. Exit nonzero on failure (the `assert` helper does this for you).
