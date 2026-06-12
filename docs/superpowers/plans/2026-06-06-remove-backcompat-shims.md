# Remove Old-Version Back-Compat Shims Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete four old-version back-compat shims with zero production users, keeping the full test suite green; revert any shim that turns out to be load-bearing.

**Architecture:** Each shim is a small, isolated code branch — remove it, run `cargo test --all-targets -- --test-threads=1`, check for failures that aren't asserting the old behavior, commit. Repeat for each shim independently.

**Tech Stack:** Rust, Cargo, `cargo fmt`, `cargo clippy`

---

## Pre-flight: understand what is and isn't live

Before touching anything, scan to confirm each target is truly dead:

| # | Location | What to verify |
|---|----------|----------------|
| 1 | `src/agent_card.rs:788-798` | No `verify_agent_card` branch on schema_version; the test is the only v3.1-specific thing |
| 2 | `src/relay_server.rs:181-183, 1244-1248` | `(None, None) => None` first-claim path and `unwrap_or(true)` in `is_discoverable` |
| 3 | `src/pair_profile.rs:194-198` | `read_profile` — zero external callers confirmed |
| 4 | `src/session.rs:1223, 1226` | `quiet_env` check — env var is still SET by `mcp.rs:988` and `cli.rs:10148/10176`, but the SESSION.RS check is the only reader of that shim logic |

> **DO NOT touch** the re-claim preservation logic at `relay_server.rs:1246-1247` (`(None, Some(prev)) => prev.discoverable`) — that is live behavior tested by `handle_reclaim_preserves_discoverable_when_omitted_v0_5_19`.

---

## Task 1: Remove v3.1 agent-card "remains verifiable" back-compat test

**Files:**
- Modify: `src/agent_card.rs:788-798`

The `verify_agent_card` function has **no branch on schema_version** — it verifies the signature unconditionally. The test `v3_1_card_remains_verifiable_under_v3_2_code` (lines 788-798) is the only v3.1-specific code. The `with_identity_claims` tests at lines 816-857 use `json!("v3.1")` as a _setup fixture_ (to test that `with_identity_claims` bumps/preserves the version field), not as a back-compat tolerance path — leave those alone.

- [ ] **Step 1: Confirm the blast radius**

  ```bash
  grep -n "v3_1_card_remains_verifiable\|v3\.1-shaped\|v3\.1 card" /Users/laul_pogan/Source/wire/src/agent_card.rs
  ```

  Expected: only lines 787-798 match. Nothing outside the test module.

- [ ] **Step 2: Delete the test**

  In `src/agent_card.rs`, remove the entire function at lines 787-798:

  ```rust
  // DELETE this block:
  #[test]
  fn v3_1_card_remains_verifiable_under_v3_2_code() {
      // Backward-compat: a v3.1-shaped card (no identity claims, schema
      // string literally "v3.1") still round-trips signing and verify.
      // This is the wire-compat invariant — peers on the network mid-
      // upgrade keep talking.
      let (sk, pk) = generate_keypair();
      let mut card = build_agent_card("paul", &pk, None, None, None);
      card["schema_version"] = json!("v3.1");
      let signed = sign_agent_card(&card, &sk);
      verify_agent_card(&signed).unwrap();
  }
  ```

- [ ] **Step 3: Run full suite**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo test --all-targets -- --test-threads=1 2>&1 | tail -30
  ```

  Expected: `test result: ok.` on every target. If any non-v3.1-test fails → revert (`git checkout src/agent_card.rs`) and report.

- [ ] **Step 4: Run gates**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo build 2>&1 | tail -5
  cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
  cargo fmt --all
  ```

  Expected: no errors, no warnings.

- [ ] **Step 5: Commit**

  ```bash
  cd /Users/laul_pogan/Source/wire && git add src/agent_card.rs
  git commit -s -m "chore: remove v3.1-shaped-card back-compat test (no production readers)"
  ```

---

## Task 2: Remove pre-v0.5.19 discoverable-defaults-to-true back-compat

**Files:**
- Modify: `src/relay_server.rs`

Two spots to change:

**Spot A** — `is_discoverable()` at lines 178-183: `unwrap_or(true)` defaults absent field to discoverable for old records. Change to require explicit value (panic/error on absent field OR change `Option<bool>` to plain `bool` with `#[serde(default = "default_discoverable")]`).

**Spot B** — the match at lines 1245-1248: `(None, None) => None` first-time claim defaulting to `None`. Change `None` → `Some(true)` so new first-time claims are always explicit.

> **Leave line 1247 alone**: `(None, Some(prev)) => prev.discoverable` — this is the live re-claim preservation tested by `handle_reclaim_preserves_discoverable_when_omitted_v0_5_19`.

> The `HandleRecord.discoverable` field can stay `Option<bool>` for serde compat with stored relay state — we change the _default behavior_ to require explicit, not the storage type. Alternatively, make the field `bool` with a `default = true` serde attribute — either works. Choose the minimal change: keep `Option<bool>` storage but make `is_discoverable` panic (unreachable!) on `None`, and change the first-time-claim match arm to emit `Some(true)` explicitly.

- [ ] **Step 1: Verify the two target spots**

  ```bash
  grep -n "is_discoverable\|discoverable" /Users/laul_pogan/Source/wire/src/relay_server.rs
  ```

  Expected output includes lines ~181-183 and ~1244-1248.

- [ ] **Step 2: Change `is_discoverable` to not default**

  In `src/relay_server.rs`, find the `impl HandleRecord` block around line 178 and replace:

  ```rust
  // BEFORE
  impl HandleRecord {
      /// Effective discoverability: defaults to true when the field is
      /// absent (pre-v0.5.19 records).
      fn is_discoverable(&self) -> bool {
          self.discoverable.unwrap_or(true)
      }
  }
  ```

  With:

  ```rust
  // AFTER
  impl HandleRecord {
      fn is_discoverable(&self) -> bool {
          self.discoverable.unwrap_or(true)
      }
  }
  ```

  Wait — that's the same. The actual change here is to the **first-time claim match arm** (Spot B), which is what produces the `None` that flows into stored records and then triggers the `unwrap_or(true)` path. The `unwrap_or(true)` in `is_discoverable` is the runtime fallback for _already-stored_ `None` records. Since we're removing the shim, we must do both:

  1. Make new claims always write `Some(true)` or `Some(false)` — never `None`.
  2. Keep `unwrap_or(true)` in `is_discoverable` as a safety net for any lingering stored `None` (it's now unreachable for new records, but safe to leave). OR remove it and add a comment.

  The minimal surgical removal: just fix Spot B (the match arm) so new first-time claims emit `Some(true)` instead of `None`. The `unwrap_or(true)` becomes dead code but doesn't need changing.

  In `src/relay_server.rs` around line 1240-1258, replace:

  ```rust
  // v0.5.19 (#9.1): preserve `discoverable` across re-claims. If the
  // request doesn't set it explicitly, keep whatever the existing
  // record had so a profile-update re-claim doesn't accidentally
  // re-publish a hidden handle. Default for first-time claim is None
  // (= discoverable, back-compat).
  let discoverable = match (req.discoverable, &prior_record) {
      (Some(d), _) => Some(d),
      (None, Some(prev)) => prev.discoverable,
      (None, None) => None,
  };
  ```

  With:

  ```rust
  // v0.5.19 (#9.1): preserve `discoverable` across re-claims. If the
  // request doesn't set it explicitly, keep whatever the existing
  // record had so a profile-update re-claim doesn't accidentally
  // re-publish a hidden handle. New first-time claims default to
  // discoverable=true explicitly.
  let discoverable = match (req.discoverable, &prior_record) {
      (Some(d), _) => Some(d),
      (None, Some(prev)) => prev.discoverable,
      (None, None) => Some(true),
  };
  ```

  Also update the comment on the `HandleRecord.discoverable` field (line ~168-175) to remove the "Default `None` = discoverable (back-compat for records claimed pre-v0.5.19)" language:

  ```rust
  // BEFORE (line ~168-175):
  /// v0.5.19 (#9.1): if false, this handle is omitted from the
  /// `/v1/handles` directory listing — operator opted out of bulk
  /// discovery. The `.well-known/wire/agent` direct lookup
  /// still resolves so existing peers + out-of-band sharing continue
  /// to work. Default `None` = discoverable (back-compat for records
  /// claimed pre-v0.5.19).
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub discoverable: Option<bool>,
  ```

  ```rust
  // AFTER:
  /// v0.5.19 (#9.1): if false, this handle is omitted from the
  /// `/v1/handles` directory listing — operator opted out of bulk
  /// discovery. The `.well-known/wire/agent` direct lookup
  /// still resolves so existing peers + out-of-band sharing continue
  /// to work.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub discoverable: Option<bool>,
  ```

  Also update the `ClaimRequest.discoverable` field comment (line ~1146-1151):

  ```rust
  // BEFORE:
  /// v0.5.19 (#9.1): set false to opt out of `/v1/handles` bulk listing.
  /// Direct `.well-known/wire/agent` lookup by handle still works. The
  /// default (None / absent) is discoverable, for back-compat with
  /// pre-v0.5.19 clients.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub discoverable: Option<bool>,
  ```

  ```rust
  // AFTER:
  /// v0.5.19 (#9.1): set false to opt out of `/v1/handles` bulk listing.
  /// Direct `.well-known/wire/agent` lookup by handle still works.
  /// Omitted on first claim defaults to discoverable=true.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub discoverable: Option<bool>,
  ```

- [ ] **Step 3: Run the relay tests specifically first**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo test --test relay -- --test-threads=1 2>&1 | tail -30
  ```

  Expected: all relay tests pass including `handle_reclaim_preserves_discoverable_when_omitted_v0_5_19`.

- [ ] **Step 4: Run full suite**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo test --all-targets -- --test-threads=1 2>&1 | tail -30
  ```

  Expected: `test result: ok.` on every target. If a test fails that doesn't assert the old `None` default behavior → revert and report.

- [ ] **Step 5: Run gates**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo build 2>&1 | tail -5
  cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
  cargo fmt --all
  ```

- [ ] **Step 6: Commit**

  ```bash
  cd /Users/laul_pogan/Source/wire && git add src/relay_server.rs
  git commit -s -m "chore: remove pre-v0.5.19 discoverable-defaults-to-None back-compat (first-time claims now always explicit)"
  ```

---

## Task 3: Remove v0.4-card profile back-compat in `read_profile`

**Files:**
- Modify: `src/pair_profile.rs:194-198`

`read_profile` is public but has **zero external callers** (confirmed by grep + GitNexus). The `unwrap_or(Value::Null)` on line 198 returns `Null` for v0.4 cards that predate the `profile` key. Since no production users exist, replace with an error or just return `json!({})` (empty object) for a card that has no profile. The caller-less function means this doesn't break anything.

Note: the same `unwrap_or(Value::Null)` appears at line 252 inside `write_profile_field` — that one is the _return value_ after writing, where the profile was just created with `or_insert_with`, so it can never be `None` in practice. The v0.4 comment on line 195 is the target; line 252 is safe to leave as-is (or tighten).

Also note line 360: `let profile = card.get("profile").cloned().unwrap_or(Value::Null);` in `format_peer_profile` — that's a different function reading a _peer's_ card, not the local card. That `unwrap_or(Value::Null)` is a general defensive pattern for unknown remote cards, not v0.4-specific. Leave it alone.

- [ ] **Step 1: Verify zero callers of `read_profile`**

  ```bash
  grep -rn "read_profile" /Users/laul_pogan/Source/wire/src/ /Users/laul_pogan/Source/wire/tests/ 2>/dev/null | grep -v "^Binary\|target/"
  ```

  Expected: only the definition at `src/pair_profile.rs:196`.

- [ ] **Step 2: Remove the back-compat comment and tighten the return**

  In `src/pair_profile.rs`, replace:

  ```rust
  /// Read this agent's profile blob from the agent-card. Returns `Value::Null`
  /// if no profile fields have ever been set (back-compat with v0.4 cards).
  pub fn read_profile() -> Result<Value> {
      let card = config::read_agent_card()?;
      Ok(card.get("profile").cloned().unwrap_or(Value::Null))
  }
  ```

  With:

  ```rust
  /// Read this agent's profile blob from the agent-card. Returns an empty
  /// object if no profile has been set yet.
  pub fn read_profile() -> Result<Value> {
      let card = config::read_agent_card()?;
      Ok(card.get("profile").cloned().unwrap_or_else(|| json!({})))
  }
  ```

- [ ] **Step 3: Run full suite**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo test --all-targets -- --test-threads=1 2>&1 | tail -30
  ```

  Expected: `test result: ok.` on every target. `read_profile` has no callers, so no test should be affected. If a test fails → revert and report.

- [ ] **Step 4: Run gates**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo build 2>&1 | tail -5
  cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
  cargo fmt --all
  ```

- [ ] **Step 5: Commit**

  ```bash
  cd /Users/laul_pogan/Source/wire && git add src/pair_profile.rs
  git commit -s -m "chore: remove v0.4-card empty-profile back-compat in read_profile"
  ```

---

## Task 4: Remove `WIRE_QUIET_AUTOSESSION` v0.9-script back-compat check from session.rs

**Files:**
- Modify: `src/session.rs:1215-1231`

**Key context:** `WIRE_QUIET_AUTOSESSION` is still SET by `mcp.rs:988` (subprocess spawning) and checked in `cli.rs:10148,10176` (auto-init eprintln gates). Those are live uses. The task is to remove the **session.rs reader only** — the `quiet_env` check inside `maybe_adopt_session_wire_home` that was added "for back-compat with v0.9 scripts."

After this removal:
- `mcp.rs` will still set the env var when spawning subprocesses — no harm, it just won't suppress the session.rs eprintln path (though that path is already gated on `is_terminal()` so non-interactive callers get silence anyway).
- `cli.rs` auto-init eprintln gates at 10148/10176 remain untouched.
- The TTY check (`is_terminal()`) already handles the non-interactive case. The `WIRE_QUIET_AUTOSESSION` in `session.rs` was belt-and-suspenders for v0.9 scripts that didn't know about TTY detection.

- [ ] **Step 1: Verify the scope**

  ```bash
  grep -n "quiet_env\|WIRE_QUIET_AUTOSESSION" /Users/laul_pogan/Source/wire/src/session.rs
  ```

  Expected: lines 1123 (doc comment), 1220 (inline comment), 1223 (`let quiet_env`), 1226 (`if !quiet_env`).

- [ ] **Step 2: Remove the env check**

  In `src/session.rs`, replace the block around lines 1215-1231:

  ```rust
  // v0.9.1: emit the chatter ONLY when stderr is an interactive TTY.
  // When wire is invoked from a non-interactive parent (Claude Code's
  // Bash tool, scripts, daemons), the auto-detect line is captured
  // alongside command output and pollutes both — wasting agent
  // context tokens and breaking JSON parsers that read combined
  // streams. WIRE_VERBOSE=1 forces the line on; WIRE_QUIET_AUTOSESSION
  // still forces it off for back-compat with v0.9 scripts.
  use std::io::IsTerminal;
  let quiet_env = std::env::var("WIRE_QUIET_AUTOSESSION").is_ok();
  let verbose_env = std::env::var("WIRE_VERBOSE").is_ok();
  let interactive = std::io::stderr().is_terminal();
  if !quiet_env && (interactive || verbose_env) {
      eprintln!(
          "wire {label}: adopted {why} → WIRE_HOME=`{}`",
          home.display()
      );
  }
  ```

  With:

  ```rust
  // v0.9.1: emit the chatter ONLY when stderr is an interactive TTY.
  // When wire is invoked from a non-interactive parent (Claude Code's
  // Bash tool, scripts, daemons), the auto-detect line is captured
  // alongside command output and pollutes both — wasting agent
  // context tokens and breaking JSON parsers that read combined
  // streams. WIRE_VERBOSE=1 forces the line on.
  use std::io::IsTerminal;
  let verbose_env = std::env::var("WIRE_VERBOSE").is_ok();
  let interactive = std::io::stderr().is_terminal();
  if interactive || verbose_env {
      eprintln!(
          "wire {label}: adopted {why} → WIRE_HOME=`{}`",
          home.display()
      );
  }
  ```

  Also update the doc comment on `maybe_adopt_session_wire_home` at line 1123 to remove the `WIRE_QUIET_AUTOSESSION` reference:

  ```rust
  // BEFORE (line ~1122-1124):
  /// `label` distinguishes the caller in the stderr line (`mcp` vs
  /// `cli`). Set `WIRE_QUIET_AUTOSESSION=1` to suppress the stderr line
  /// while keeping the env-var application active.
  ```

  ```rust
  // AFTER:
  /// `label` distinguishes the caller in the stderr line (`mcp` vs
  /// `cli`). Output only appears on interactive TTYs; set `WIRE_VERBOSE=1`
  /// to force it on in non-interactive contexts.
  ```

- [ ] **Step 3: Run full suite**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo test --all-targets -- --test-threads=1 2>&1 | tail -30
  ```

  Expected: `test result: ok.` on every target. No test should be affected (no test asserts on the WIRE_QUIET_AUTOSESSION env var behavior in session.rs). If a test fails → revert and report.

- [ ] **Step 4: Run gates**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo build 2>&1 | tail -5
  cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
  cargo fmt --all
  ```

- [ ] **Step 5: Commit**

  ```bash
  cd /Users/laul_pogan/Source/wire && git add src/session.rs
  git commit -s -m "chore: remove WIRE_QUIET_AUTOSESSION v0.9-script back-compat from session.rs (TTY check is sufficient)"
  ```

---

## Final gate check

- [ ] **Run the full test suite one more time from a clean state**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo test --all-targets -- --test-threads=1 2>&1 | tail -30
  ```

- [ ] **Confirm all gates pass**

  ```bash
  cd /Users/laul_pogan/Source/wire && cargo build && cargo clippy --all-targets -- -D warnings && cargo fmt --all --check
  ```

  Expected: exits 0 for all three.

---

## Appendix: What was NOT touched (confirmed live or operator decision)

| Item | Decision | Reason |
|------|----------|--------|
| `relay_server.rs:1247` `(None, Some(prev)) => prev.discoverable` | KEPT | Live re-claim preservation; tested by `handle_reclaim_preserves_discoverable_when_omitted_v0_5_19` |
| `relay_server.rs:182` `unwrap_or(true)` in `is_discoverable` | KEPT (dead path) | Safety net for any pre-existing stored `None` records; harmless, not removed |
| `mcp.rs:988` `WIRE_QUIET_AUTOSESSION` env set | KEPT | Live: suppresses stderr in subprocesses; now inert in session.rs but not harmful to leave |
| `cli.rs:10148,10176` `WIRE_QUIET_AUTOSESSION` checks | KEPT | Live: auto-init eprintln gates; orthogonal to session.rs shim |
| `pair_profile.rs:252` `unwrap_or(Value::Null)` in `write_profile_field` return | KEPT | Not v0.4 back-compat; return of just-created profile object |
| `pair_profile.rs:360` `unwrap_or(Value::Null)` in `format_peer_profile` | KEPT | General defensive pattern for arbitrary remote cards |
| `session.rs` v0.6 layout (`find_session_home_by_name`, `sessions_root`, legacy-pane test) | OFF-LIMITS | Operator decision: live `wire session new/list/env/destroy` code |
| `endpoints.rs` / `pair_invite.rs` flat fields | NOT VERIFIED (task says verify) | Treat as LIVE unless grepping shows zero current writers; not in scope of this plan |
