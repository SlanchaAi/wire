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
        let role = pattern.strip_prefix("wire ").unwrap_or(pattern);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn kill_process_on_nonexistent_pid_returns_false_or_noop() {
        // Asserting on the return value is brittle because `kill -15`
        // against a missing pid returns 1 on linux but 0 on some
        // BSDs. The contract is "does not panic" — that alone is
        // worth a test, given the cfg-gated dispatch.
        let dead = 4_000_000_002;
        let _ = kill_process(dead, false);
    }
}
