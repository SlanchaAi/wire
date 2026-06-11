use anyhow::{Context, Result, anyhow};
use serde_json::json;

use crate::config;

use super::QuietAction;

// ---------- quiet (v0.14.x toast kill switch) ----------

/// Path to the file that, when present, silences every wire desktop
/// toast. Created by `wire quiet on`, removed by `wire quiet off`. Read
/// per-toast-call by `crate::os_notify::toasts_disabled` — no daemon
/// restart needed for the toggle to take effect, just for binary swap.
fn quiet_flag_path() -> Result<std::path::PathBuf> {
    Ok(config::config_dir()?.join("quiet"))
}

pub(crate) fn cmd_quiet(action: QuietAction) -> Result<()> {
    match action {
        QuietAction::On => {
            let path = quiet_flag_path()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("creating config dir for quiet flag: {}", parent.display())
                })?;
            }
            // Idempotent: open with create-if-missing, write nothing.
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .with_context(|| format!("writing {}", path.display()))?;
            println!(
                "wire quiet: ON (toasts silenced — file at {})",
                path.display()
            );
            Ok(())
        }
        QuietAction::Off => {
            let path = quiet_flag_path()?;
            match std::fs::remove_file(&path) {
                Ok(()) => println!("wire quiet: OFF (toasts re-enabled)"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    println!("wire quiet: OFF (was already off)")
                }
                Err(e) => return Err(anyhow!("removing {}: {e}", path.display())),
            }
            // Re-check env: a user can override file-off with WIRE_NO_TOASTS=1.
            if std::env::var("WIRE_NO_TOASTS").is_ok_and(|v| !v.is_empty() && v != "0") {
                println!(
                    "  note: WIRE_NO_TOASTS={} is still set in env — toasts stay silenced for this process / daemon until `launchctl unsetenv WIRE_NO_TOASTS` (or unset in your shell).",
                    std::env::var("WIRE_NO_TOASTS").unwrap_or_default()
                );
            }
            Ok(())
        }
        QuietAction::Status { json } => {
            let env_set = std::env::var("WIRE_NO_TOASTS").is_ok_and(|v| !v.is_empty() && v != "0");
            let file_present = quiet_flag_path()?.exists();
            let (state, via) = match (env_set, file_present) {
                (true, _) => ("on", "env"),
                (false, true) => ("on", "file"),
                (false, false) => ("off", "none"),
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "state": state,
                        "via": via,
                        "file": quiet_flag_path()?.display().to_string(),
                        "env_WIRE_NO_TOASTS": std::env::var("WIRE_NO_TOASTS").ok(),
                    }))?
                );
            } else {
                match (env_set, file_present) {
                    (true, _) => println!(
                        "wire quiet: ON (via WIRE_NO_TOASTS={} in env)",
                        std::env::var("WIRE_NO_TOASTS").unwrap_or_default()
                    ),
                    (false, true) => println!(
                        "wire quiet: ON (via file at {})",
                        quiet_flag_path()?.display()
                    ),
                    (false, false) => println!("wire quiet: OFF"),
                }
            }
            Ok(())
        }
    }
}

// ---------- nuke ----------

pub(crate) fn cmd_nuke(
    force: bool,
    purge: bool,
    dry_run: bool,
    really_this_machine: bool,
    as_json: bool,
) -> Result<()> {
    use std::io::{IsTerminal, Write};
    let plan = crate::nuke::NukePlan::compute(purge)?;

    // Render what will/would be removed.
    if as_json && dry_run {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }
    if !as_json {
        eprintln!("wire nuke will remove:");
        for p in &plan.paths {
            eprintln!("  dir   {}", p.display());
        }
        for m in &plan.mcp_files {
            eprintln!("  mcp   {} (de-register `wire`)", m.display());
        }
        eprintln!("  units launchd/systemd/schtasks (daemon + local-relay)");
        eprintln!("  procs any running wire daemon / supervisor / relay-server");
        if purge {
            eprintln!("  PURGE the `wire` binary + shell PATH/env lines");
        }
    }
    if dry_run {
        return Ok(());
    }

    // Host guard: a registry-bound DEFAULT home (WIRE_HOME ignored)
    // means a live operator install — refuse the machine-global
    // teardown without --really-this-machine. Applies even with
    // --force: --force answers "skip the typed confirmation", not
    // "yes, this operator machine".
    let bound = crate::nuke::default_registry_bindings();
    if let Some(msg) = crate::nuke::host_guard_refusal(&bound, really_this_machine) {
        anyhow::bail!(msg);
    }

    // Gate.
    if !crate::nuke::should_proceed(force, std::io::stdin().is_terminal(), || {
        eprint!("\nType `nuke` to confirm: ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        line
    }) {
        if !as_json {
            eprintln!("aborted — nothing removed. (Use --force for automation.)");
        }
        anyhow::bail!("nuke not confirmed");
    }

    // Kill survivors not covered by unit teardown (best-effort).
    let killed = kill_wire_processes();

    // Execute.
    let mut report = plan.execute()?;
    report.killed_pids = killed;

    // --purge: remove binary + shell lines.
    if purge {
        report.binary_removed = purge_binary_and_shell(&mut report.warnings);
    }

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        eprintln!(
            "nuked: {} dir(s), {} mcp entr(ies), {} unit(s), {} proc(s){}",
            report.removed_paths.len(),
            report.removed_mcp_entries.len(),
            report.removed_units.len(),
            report.killed_pids.len(),
            if report.binary_removed {
                ", binary+shell"
            } else {
                ""
            },
        );
        for w in &report.warnings {
            eprintln!("  warn: {w}");
        }
    }
    Ok(())
}

/// Best-effort kill of any wire daemon / supervisor / relay-server
/// process. Returns the pids we asked the OS to terminate.
fn kill_wire_processes() -> Vec<u32> {
    let mut killed = Vec::new();
    #[cfg(unix)]
    for pat in ["wire daemon", "relay-server"] {
        if let Ok(out) = std::process::Command::new("pkill")
            .arg("-f")
            .arg(pat)
            .output()
        {
            // pkill exit 0 = killed something; record nothing granular (best-effort).
            let _ = out;
        }
    }
    #[cfg(windows)]
    {
        // Kill wire.exe by PID, EXCLUDING our own process — a broad
        // `taskkill /IM wire.exe` would terminate this very `wire nuke`
        // run mid-execution. Enumerate via `tasklist` CSV and skip self.
        let self_pid = std::process::id();
        if let Ok(out) = std::process::Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq wire.exe", "/FO", "CSV", "/NH"])
            .output()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                // CSV row: "wire.exe","1234","Console","1","12,345 K"
                if let Some(pid) = line
                    .split(',')
                    .nth(1)
                    .and_then(|s| s.trim().trim_matches('"').parse::<u32>().ok())
                {
                    if pid != self_pid {
                        let _ = std::process::Command::new("taskkill")
                            .args(["/F", "/PID", &pid.to_string()])
                            .output();
                        killed.push(pid);
                    }
                }
            }
        }
    }
    // unix records nothing granular (pkill is coarse, best-effort); the
    // vec stays empty there, which keeps the report shape stable.
    let _ = &mut killed;
    killed
}

/// --purge: remove the wire binary + scrub shell PATH/env lines.
/// Returns true if the binary was removed (false on the Windows
/// self-delete case, where we print the manual command instead).
fn purge_binary_and_shell(warnings: &mut Vec<String>) -> bool {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            warnings.push(format!("resolve exe: {e:#}"));
            return false;
        }
    };
    #[cfg(windows)]
    {
        eprintln!("purge: a running .exe can't delete itself. Remove it manually:");
        eprintln!("  del \"{}\"", exe.display());
        warnings.push("binary self-delete skipped on Windows (manual del printed)".into());
        return false;
    }
    #[cfg(unix)]
    {
        match std::fs::remove_file(&exe) {
            Ok(()) => {
                // Best-effort shell-line scrub: well-known rc files.
                scrub_shell_lines(warnings);
                true
            }
            Err(e) => {
                warnings.push(format!("rm binary {}: {e:#}", exe.display()));
                false
            }
        }
    }
}

#[cfg(unix)]
fn scrub_shell_lines(warnings: &mut Vec<String>) {
    let Some(home) = dirs::home_dir() else {
        return;
    };
    for rc in [".bashrc", ".zshrc", ".profile", ".config/fish/config.fish"] {
        let path = home.join(rc);
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let filtered: String = content
            .lines()
            .filter(|l| !(l.contains("wire") && (l.contains("PATH") || l.contains("WIRE_"))))
            .collect::<Vec<_>>()
            .join("\n");
        if filtered != content
            && let Err(e) = std::fs::write(&path, filtered + "\n")
        {
            warnings.push(format!("scrub {}: {e:#}", path.display()));
        }
    }
}
