//! Cross-platform process-management primitives.
//!
//! Wire historically called `pgrep` + `kill` directly, which gave us
//! "unsupported platform" rot on Windows. v0.7.3 funnels every
//! liveness check / command-line search / SIGTERM through this module
//! so the Windows daemon + relay paths get the same teardown +
//! respawn behavior the Linux + macOS paths have always had.
//!
//! ## Helpers
//!
//! - [`process_alive`] — "is pid <N> still around?"
//! - [`find_processes_by_cmdline`] — `pgrep -f <pattern>` equivalent
//! - [`kill_process`] — SIGTERM / SIGKILL equivalent (taskkill /T on
//!   Windows so the tree dies, not just the parent)
//!
//! Each helper returns conservative defaults on tool failure (empty
//! Vec, `false`) so callers can chain them without aborting an upgrade
//! mid-flight when one query hiccups.

use std::process::Command;

/// True iff pid is alive.
///
/// - Linux: `/proc/<pid>` exists (no fork, no shell-out).
/// - macOS / BSD: `kill -0 <pid>` (signal 0 = check only).
/// - Windows: `tasklist /FI "PID eq <pid>" /FO CSV /NH`. A miss prints
///   `INFO: No tasks are running...` to stdout AND exits 0, so we
///   detect by content rather than exit code.
pub fn process_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        let out = Command::new("tasklist.exe")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout);
                let trimmed = s.trim();
                !trimmed.is_empty() && !trimmed.starts_with("INFO:")
            }
            _ => false,
        }
    }
}

/// The role/subcommand of a `wire <role> ...` process pattern —
/// `cmdline_role("wire daemon") == "daemon"`, `cmdline_role("wire
/// relay-server") == "relay-server"`. A pattern without the `wire ` prefix
/// passes through unchanged.
///
/// The Windows process scan matches this role (not the full `wire daemon`
/// string) against the command line, because the image is `wire.exe` and the
/// contiguous `wire daemon` never matches the real `wire.exe daemon` cmdline.
/// Hoisted out of the `cfg(windows)` block + unit-tested so the `.exe`-match
/// regression (which caused `wire upgrade` to accumulate daemons) is locked on
/// EVERY platform's CI, not only on a Windows runner.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn cmdline_role(pattern: &str) -> &str {
    pattern.strip_prefix("wire ").unwrap_or(pattern)
}

/// `pgrep -f <pattern>` equivalent: every pid whose command line
/// contains `pattern`. Empty Vec on tool error or zero matches.
///
/// - Unix: `pgrep -f <pattern>` (one fork, parses pid-per-line stdout).
/// - Windows: PowerShell + CIM (`Get-CimInstance Win32_Process` with
///   `CommandLine` filter). `wmic` was the old path but is deprecated
///   in Windows 11 24H2; CIM is the supported replacement and works
///   back to Windows 10. Pattern is single-quoted into the PowerShell
///   `-like` operator so most metacharacters pass through verbatim;
///   callers that need literal `'` or `[`/`]` should escape per
///   PowerShell rules.
pub fn find_processes_by_cmdline(pattern: &str) -> Vec<u32> {
    #[cfg(unix)]
    {
        Command::new("pgrep")
            .args(["-f", pattern])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .filter_map(|s| s.parse::<u32>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
    #[cfg(windows)]
    {
        // Single-quote the pattern in the PowerShell string. Inside
        // single-quoted PS strings, the only escape is `''` for a
        // literal single quote; we replace pre-emptively.
        // The Windows process image is `wire.exe`, so a Unix-style full
        // pattern like "wire daemon" does NOT match the actual command line
        // "wire.exe daemon" (the ".exe " breaks the contiguous match). Match
        // the wire image by Name and the ROLE/subcommand (the pattern minus a
        // leading "wire ") in the command line. Without this, find returned
        // nothing for the real daemon on Windows, so `wire upgrade` killed no
        // daemons and they ACCUMULATED (glossy-magnolia: 2->3->4->5 over three
        // upgrade cycles — the exact multi-daemon cursor race doctor warns of).
        //
        // Two further guards (glossy-magnolia repro):
        //   - `$_.Name -like 'wire*'` — only wire processes count. Without it
        //     the query SELF-MATCHED: this PowerShell process's own command
        //     line contains the pattern literal, so it showed up as a phantom
        //     "orphan daemon" with a new pid every call (doctor FAILed on
        //     every healthy box).
        //   - `$_.ProcessId -ne $PID` — belt-and-suspenders self-exclusion.
        let role = cmdline_role(pattern);
        let escaped = role.replace('\'', "''");
        let ps = format!(
            "Get-CimInstance Win32_Process | \
             Where-Object {{ $_.Name -like 'wire*' -and $_.ProcessId -ne $PID -and $_.CommandLine -like '*{escaped}*' }} | \
             Select-Object -ExpandProperty ProcessId"
        );
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .filter_map(|s| s.parse::<u32>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pattern;
        Vec::new()
    }
}

/// Return the command line of a specific pid, or `None` if the pid
/// is missing / unreadable / exited between query and answer.
///
/// v0.14.2 (#162 diagnostic, post-supervisor #170): when `wire status`
/// surfaces orphan pids, the operator wants to know "which session
/// is that daemon serving?" without grepping `ps` themselves —
/// closes the launchd-vs-session-isolation diagnostic gap honey-pine
/// burned multiple sessions on.
///
/// - Linux: read `/proc/<pid>/cmdline` (NUL-separated, replace with spaces).
/// - macOS / BSD: `ps -p <pid> -o command=` (no header, single column).
/// - Windows: PowerShell CIM `Get-CimInstance Win32_Process | Where
///   {$_.ProcessId -eq <pid>} | Select CommandLine`.
///
/// Conservative on failure: returns `None` rather than synthesizing a
/// placeholder. Callers should treat None as "annotation unavailable",
/// not "process is dead" — `process_alive` is the liveness oracle.
pub fn pid_cmdline(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/{pid}/cmdline");
        let bytes = std::fs::read(&path).ok()?;
        // `/proc/<pid>/cmdline` is NUL-separated argv. Convert NULs to
        // spaces for human-readable output; trim trailing NUL.
        let s: String = bytes
            .into_iter()
            .map(|b| if b == 0 { b' ' } else { b })
            .map(|b| b as char)
            .collect();
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let out = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }
    #[cfg(windows)]
    {
        let ps = format!(
            "Get-CimInstance Win32_Process | \
             Where-Object {{ $_.ProcessId -eq {pid} }} | \
             Select-Object -ExpandProperty CommandLine"
        );
        let out = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        None
    }
}

/// Parse `--session <name>` from a wire daemon command line. Returns
/// `None` if not present. v0.14.2 (#170 supervisor pairs a `--session
/// <name>` arg with the WIRE_HOME the daemon serves; this extracts it
/// for orphan-pid diagnostic display).
pub fn parse_session_arg(cmdline: &str) -> Option<&str> {
    let parts: Vec<&str> = cmdline.split_whitespace().collect();
    let i = parts.iter().position(|p| *p == "--session")?;
    parts.get(i + 1).copied()
}

/// Signal a pid to exit. Returns true on successful dispatch (NOT on
/// confirmed exit — poll [`process_alive`] for that). `force=true` is
/// SIGKILL / `taskkill /F`; `force=false` is SIGTERM / `taskkill`
/// (graceful).
///
/// Windows note: we pass `/T` so the whole process tree dies, not just
/// the root. The daemon's `wire daemon` invocation is single-process
/// today but the relay-server spawns hyper worker threads; `/T` is
/// the safe default.
pub fn kill_process(pid: u32, force: bool) -> bool {
    #[cfg(unix)]
    {
        let sig = if force { "-9" } else { "-15" };
        Command::new("kill")
            .args([sig, &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        let pid_str = pid.to_string();
        let mut args: Vec<&str> = vec!["/PID", &pid_str, "/T"];
        if force {
            args.push("/F");
        }
        Command::new("taskkill.exe")
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, force);
        false
    }
}

/// Resolve the path of the currently-running executable, robust to the Linux
/// kernel's `(deleted)` marker.
///
/// When a running binary is replaced *in place* — e.g. `cargo install
/// slancha-wire` unlinks and recreates `~/.cargo/bin/wire` while `wire upgrade`
/// is still running — the kernel appends a literal ` (deleted)` suffix to
/// `/proc/self/exe`. That suffix marks the unlinked inode; it is NOT part of
/// the path. [`std::env::current_exe`] surfaces it verbatim, and writing it
/// into a systemd `ExecStart=` / launchd program path corrupts the unit
/// (`error: unrecognized subcommand '(deleted)'`, the unit then flaps forever).
///
/// This strips a trailing ` (deleted)` so callers get the real install path,
/// which the in-place replacement has already recreated on disk. Issues #274,
/// #276.
pub fn current_exe_resolved() -> std::io::Result<std::path::PathBuf> {
    Ok(strip_deleted_suffix(&std::env::current_exe()?))
}

/// Pure inner of [`current_exe_resolved`]: strip a trailing ` (deleted)` kernel
/// marker from an exe path. Only the exact trailing ` (deleted)` token (leading
/// space included) is removed — a path that merely contains the text, or a real
/// filename ending in `(deleted)` without the kernel's leading space, is left
/// untouched. Testable without an actually-unlinked binary.
pub fn strip_deleted_suffix(p: &std::path::Path) -> std::path::PathBuf {
    match p.to_string_lossy().strip_suffix(" (deleted)") {
        Some(stripped) => std::path::PathBuf::from(stripped),
        None => p.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_deleted_suffix_removes_kernel_marker() {
        use std::path::Path;
        // The repro from #274: cargo in-place replace → /proc/self/exe carries
        // the marker → it must NOT reach the unit's ExecStart.
        assert_eq!(
            strip_deleted_suffix(Path::new("/home/admin/.cargo/bin/wire (deleted)")),
            Path::new("/home/admin/.cargo/bin/wire")
        );
    }

    #[test]
    fn strip_deleted_suffix_leaves_clean_path_untouched() {
        use std::path::Path;
        assert_eq!(
            strip_deleted_suffix(Path::new("/usr/local/bin/wire")),
            Path::new("/usr/local/bin/wire")
        );
    }

    #[test]
    fn strip_deleted_suffix_only_strips_exact_trailing_token() {
        use std::path::Path;
        // No leading space → not the kernel marker shape → leave alone.
        assert_eq!(
            strip_deleted_suffix(Path::new("/opt/wire(deleted)")),
            Path::new("/opt/wire(deleted)")
        );
    }

    #[test]
    fn cmdline_role_strips_wire_prefix() {
        // Locks the Windows .exe-match logic on every platform's CI: the role
        // is what we match against `wire.exe daemon`, not the full pattern.
        assert_eq!(cmdline_role("wire daemon"), "daemon");
        assert_eq!(cmdline_role("wire relay-server"), "relay-server");
        // No `wire ` prefix → unchanged (custom patterns pass through).
        assert_eq!(cmdline_role("daemon"), "daemon");
        assert_eq!(cmdline_role("relay-server"), "relay-server");
    }

    #[test]
    fn process_alive_returns_true_for_self() {
        // Our own pid is alive by definition.
        let me = std::process::id();
        assert!(
            process_alive(me),
            "process_alive should return true for self pid {me}"
        );
    }

    #[test]
    fn process_alive_returns_false_for_clearly_dead_pid() {
        // pid 0 is reserved on every Unix; on Windows it's the
        // "System Idle Process" pseudo-pid and tasklist won't list
        // it under a numeric filter. Either way: should report dead.
        // Use a high pid that's astronomically unlikely to be alive
        // to dodge the pid=0 edge case ambiguity on Windows.
        let dead = 4_000_000_001;
        assert!(
            !process_alive(dead),
            "process_alive should return false for synthetic dead pid {dead}"
        );
    }

    #[test]
    fn parse_session_arg_extracts_following_value() {
        assert_eq!(
            parse_session_arg("wire daemon --session slancha-mesh --interval 5"),
            Some("slancha-mesh")
        );
        assert_eq!(
            parse_session_arg("wire daemon --interval 5 --session wire-dev"),
            Some("wire-dev")
        );
        // Mid-cmdline + extra whitespace is fine — split_whitespace handles it.
        assert_eq!(
            parse_session_arg("/path/to/wire   daemon   --session   foo"),
            Some("foo")
        );
    }

    #[test]
    fn parse_session_arg_returns_none_without_flag() {
        assert_eq!(parse_session_arg("wire daemon --interval 5"), None);
        // Bare `wire daemon --all-sessions` is the supervisor itself —
        // it doesn't carry a single `--session`. Operators reading the
        // supervisor's cmdline should see no annotation, not a
        // misleading session attribution.
        assert_eq!(
            parse_session_arg("wire daemon --all-sessions --interval 5"),
            None
        );
        // Empty input is safe.
        assert_eq!(parse_session_arg(""), None);
    }

    #[test]
    fn parse_session_arg_returns_none_when_flag_is_last_token() {
        // `--session` at end with no value following → None, not a panic.
        assert_eq!(parse_session_arg("wire daemon --session"), None);
    }

    #[test]
    fn pid_cmdline_returns_something_for_self() {
        // Cross-platform sanity: our own process must have a cmdline.
        // We can't assert exact content (test runner cmdlines vary) —
        // just that it returns Some and is non-empty.
        let me = std::process::id();
        let cmd = pid_cmdline(me);
        assert!(
            cmd.is_some() && !cmd.as_ref().unwrap().is_empty(),
            "pid_cmdline(self) should return a non-empty cmdline, got {cmd:?}"
        );
    }

    #[test]
    fn pid_cmdline_returns_none_for_dead_pid() {
        // Use the same astronomically-unlikely pid pattern as
        // process_alive_returns_false_for_clearly_dead_pid above.
        let dead = 4_000_000_003;
        assert_eq!(
            pid_cmdline(dead),
            None,
            "pid_cmdline should return None for synthetic dead pid"
        );
    }

    #[test]
    fn kill_process_on_nonexistent_pid_returns_false_or_noop() {
        // Asserting on the return value is brittle because `kill -15`
        // against a missing pid returns 1 on linux but 0 on some
        // BSDs. The contract is "does not panic" — that alone is
        // worth a test, given the cfg-gated dispatch.
        let dead = 4_000_000_002;
        let _ = kill_process(dead, false);
    }
}
