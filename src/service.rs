//! Install + manage OS service units that run wire components
//! automatically across reboots.
//!
//! Today's onboarding tells operators "run `wire daemon &` in a tmux
//! pane or write a launchd plist yourself" — friction that gets skipped,
//! leading to the "daemon dies on reboot, peer sends evaporate" silent
//! class. Bake the unit install into `wire service install` so it's one
//! command, idempotent, cross-platform.
//!
//! ## Service kinds (v0.5.22)
//!
//! - **Daemon** (`wire service install`) — runs `wire daemon --interval 5`.
//!   Pulls/pushes the operator's own inbox/outbox. ONE per identity.
//!   Label: `sh.slancha.wire.daemon`.
//!
//! - **LocalRelay** (`wire service install --local-relay`) — runs
//!   `wire relay-server --bind 127.0.0.1:8771 --local-only`. The
//!   loopback transport for sister-agents on the same box (v0.5.17
//!   dual-slot). ONE per machine. Label: `sh.slancha.wire.local-relay`.
//!
//! ## Unit paths
//!
//! - macOS: `~/Library/LaunchAgents/<label>.plist`
//! - linux: `~/.config/systemd/user/wire-<kind>.service`
//!
//! Units auto-start on login + restart on crash. Pair with
//! `wire upgrade` (P0.5) for atomic version swaps without unit churn.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};

/// Which wire service is being managed. Each kind has its own launchd
/// label / systemd unit name / log path so the two kinds can coexist
/// on the same machine without colliding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    /// `wire daemon --interval 5`. One per identity. The default.
    Daemon,
    /// `wire relay-server --bind 127.0.0.1:8771 --local-only`. One
    /// per machine — provides the loopback transport that sister
    /// agents' sessions route through (v0.5.17 dual-slot).
    LocalRelay,
}

impl ServiceKind {
    /// launchd Label / systemd unit base name (without `.service`).
    fn label(self) -> &'static str {
        match self {
            ServiceKind::Daemon => "sh.slancha.wire.daemon",
            ServiceKind::LocalRelay => "sh.slancha.wire.local-relay",
        }
    }

    /// systemd unit filename (`wire-daemon.service` etc.).
    fn systemd_unit_name(self) -> &'static str {
        match self {
            ServiceKind::Daemon => "wire-daemon.service",
            ServiceKind::LocalRelay => "wire-local-relay.service",
        }
    }

    /// Human-readable name for `Description=` / log messages.
    fn description(self) -> &'static str {
        match self {
            ServiceKind::Daemon => "wire — daemon (push/pull sync)",
            ServiceKind::LocalRelay => "wire — local-only relay (127.0.0.1:8771)",
        }
    }

    /// Arguments to pass to the `wire` binary in the ProgramArguments
    /// / ExecStart line. The first element of the wider arg vector is
    /// the binary itself, supplied separately by callers.
    fn binary_args(self) -> &'static [&'static str] {
        match self {
            ServiceKind::Daemon => &["daemon", "--interval", "5"],
            ServiceKind::LocalRelay => {
                &["relay-server", "--bind", "127.0.0.1:8771", "--local-only"]
            }
        }
    }

    /// Per-kind log file basename. macOS-only — launchd's
    /// `StandardOutPath` directive redirects daemon stdout/stderr to a
    /// real file under `~/Library/Logs/`. On Linux the systemd unit
    /// has no equivalent file redirect (it logs to journald instead,
    /// which is the idiomatic Linux pattern; `journalctl --user -u
    /// <unit>` reads it). v0.5.23: stopped reporting a log-file path
    /// to Linux operators since no file was ever written there —
    /// previously the install detail message named a phantom location
    /// in `~/.cache/wire/` that confused anyone who went looking for
    /// the actual log.
    fn log_basename(self) -> &'static str {
        match self {
            ServiceKind::Daemon => "wire-daemon.log",
            ServiceKind::LocalRelay => "wire-local-relay.log",
        }
    }
}

/// Outcome of `wire service install` etc., suitable for both human + JSON
/// rendering.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceReport {
    pub action: String,
    pub platform: String,
    pub unit_path: String,
    pub status: String,
    pub detail: String,
    /// v0.5.22: which service kind this report is about ("daemon" or
    /// "local-relay"). Lets JSON consumers distinguish multiple reports.
    #[serde(default)]
    pub kind: String,
}

/// Back-compat shim — `wire service install` with no flags installs
/// the daemon, matching pre-v0.5.22 behavior.
pub fn install() -> Result<ServiceReport> {
    install_kind(ServiceKind::Daemon)
}
pub fn uninstall() -> Result<ServiceReport> {
    uninstall_kind(ServiceKind::Daemon)
}
pub fn status() -> Result<ServiceReport> {
    status_kind(ServiceKind::Daemon)
}

/// Install a user-scope service unit for the given kind.
pub fn install_kind(kind: ServiceKind) -> Result<ServiceReport> {
    let exe = std::env::current_exe()?;
    let exe_str = exe.to_string_lossy().to_string();

    // v0.5.23: log path is macOS-only — launchd's StandardOutPath
    // directive redirects to a file; systemd defaults to journald
    // and we don't add an explicit file-redirect directive (let
    // operators use `journalctl --user -u <unit>` which is the
    // idiomatic Linux read path).
    let log_str = if cfg!(target_os = "macos") {
        ensure_macos_log_path(kind)?.to_string_lossy().to_string()
    } else {
        String::new()
    };

    if cfg!(target_os = "macos") {
        let plist_path = launchd_plist_path(kind)?;
        if let Some(parent) = plist_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
        }
        let plist = launchd_plist_xml(kind, &exe_str, &log_str);
        std::fs::write(&plist_path, plist).with_context(|| format!("writing {plist_path:?}"))?;

        // launchctl bootstrap is idempotent if we bootout first.
        let _ = Command::new("launchctl")
            .args(["bootout", &launchctl_target_for(kind)])
            .status();
        let load = Command::new("launchctl")
            .args([
                "bootstrap",
                &launchctl_user_target(),
                plist_path.to_str().unwrap_or(""),
            ])
            .status();
        let loaded = load.map(|s| s.success()).unwrap_or(false);

        return Ok(ServiceReport {
            action: "install".into(),
            platform: "macos-launchd".into(),
            unit_path: plist_path.to_string_lossy().to_string(),
            status: if loaded {
                "loaded".into()
            } else {
                "written".into()
            },
            detail: if loaded {
                format!("plist written + bootstrapped; logs at {log_str}")
            } else {
                format!(
                    "plist written; `launchctl bootstrap` failed — try `launchctl bootstrap {} {}` manually",
                    launchctl_user_target(),
                    plist_path.display()
                )
            },
            kind: kind_label(kind).into(),
        });
    }
    if cfg!(target_os = "linux") {
        let unit_path = systemd_unit_path(kind)?;
        if let Some(parent) = unit_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
        }
        let unit = systemd_unit_text(kind, &exe_str);
        std::fs::write(&unit_path, unit).with_context(|| format!("writing {unit_path:?}"))?;

        // Reload + enable + start. Each is idempotent on linux.
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let enabled = Command::new("systemctl")
            .args(["--user", "enable", "--now", kind.systemd_unit_name()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        // v0.5.23: surface the "user-scope unit only starts after first
        // login" footgun. systemd user units require `loginctl enable-
        // linger <user>` to start at boot without a console login
        // session. Operators logging in via SSH frequently miss this
        // and discover the service is "down at boot" only later.
        // Check the current state and only nag if linger is OFF.
        let linger_note = if enabled && !linger_enabled() {
            let user = std::env::var("USER").unwrap_or_else(|_| "$USER".into());
            format!(
                " NOTE: linger is OFF — service starts at *first login*, \
                 not at boot. For boot-time start (e.g. headless SSH boxes), \
                 run `sudo loginctl enable-linger {user}` once."
            )
        } else {
            String::new()
        };

        return Ok(ServiceReport {
            action: "install".into(),
            platform: "linux-systemd-user".into(),
            unit_path: unit_path.to_string_lossy().to_string(),
            status: if enabled {
                "enabled".into()
            } else {
                "written".into()
            },
            detail: if enabled {
                format!(
                    "unit written + enable --now succeeded; logs via \
                     `journalctl --user -u {}`{linger_note}",
                    kind.systemd_unit_name()
                )
            } else {
                format!(
                    "unit written; `systemctl --user enable --now {}` failed — try manually",
                    kind.systemd_unit_name()
                )
            },
            kind: kind_label(kind).into(),
        });
    }
    bail!("wire service install: unsupported platform")
}

pub fn uninstall_kind(kind: ServiceKind) -> Result<ServiceReport> {
    if cfg!(target_os = "macos") {
        let plist_path = launchd_plist_path(kind)?;
        let _ = Command::new("launchctl")
            .args(["bootout", &launchctl_target_for(kind)])
            .status();
        let removed = if plist_path.exists() {
            std::fs::remove_file(&plist_path).ok();
            true
        } else {
            false
        };
        return Ok(ServiceReport {
            action: "uninstall".into(),
            platform: "macos-launchd".into(),
            unit_path: plist_path.to_string_lossy().to_string(),
            status: if removed {
                "removed".into()
            } else {
                "absent".into()
            },
            detail: "launchctl bootout + plist file removed".into(),
            kind: kind_label(kind).into(),
        });
    }
    if cfg!(target_os = "linux") {
        let unit_path = systemd_unit_path(kind)?;
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", kind.systemd_unit_name()])
            .status();
        let removed = if unit_path.exists() {
            std::fs::remove_file(&unit_path).ok();
            true
        } else {
            false
        };
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        return Ok(ServiceReport {
            action: "uninstall".into(),
            platform: "linux-systemd-user".into(),
            unit_path: unit_path.to_string_lossy().to_string(),
            status: if removed {
                "removed".into()
            } else {
                "absent".into()
            },
            detail: "systemctl disable --now + unit file removed".into(),
            kind: kind_label(kind).into(),
        });
    }
    bail!("wire service uninstall: unsupported platform")
}

pub fn status_kind(kind: ServiceKind) -> Result<ServiceReport> {
    if cfg!(target_os = "macos") {
        let plist_path = launchd_plist_path(kind)?;
        let exists = plist_path.exists();
        let listed = Command::new("launchctl")
            .args(["list", kind.label()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        return Ok(ServiceReport {
            action: "status".into(),
            platform: "macos-launchd".into(),
            unit_path: plist_path.to_string_lossy().to_string(),
            status: if listed {
                "loaded".into()
            } else if exists {
                "installed (not loaded)".into()
            } else {
                "absent".into()
            },
            detail: format!("plist exists={exists}, launchctl-list-success={listed}"),
            kind: kind_label(kind).into(),
        });
    }
    if cfg!(target_os = "linux") {
        let unit_path = systemd_unit_path(kind)?;
        let exists = unit_path.exists();
        let active = Command::new("systemctl")
            .args(["--user", "is-active", kind.systemd_unit_name()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);
        return Ok(ServiceReport {
            action: "status".into(),
            platform: "linux-systemd-user".into(),
            unit_path: unit_path.to_string_lossy().to_string(),
            status: if active {
                "active".into()
            } else if exists {
                "installed (inactive)".into()
            } else {
                "absent".into()
            },
            detail: format!("unit exists={exists}, is-active={active}"),
            kind: kind_label(kind).into(),
        });
    }
    bail!("wire service status: unsupported platform")
}

/// v0.5.23 (linux only): true iff `loginctl show-user --property=Linger`
/// returns `Linger=yes`. Used to suppress the install-time linger nag
/// when the operator has already enabled it. Best-effort: returns false
/// on any error (missing `loginctl`, $USER unset, command failure) so
/// the nag fires by default rather than silently going missing.
#[cfg(target_os = "linux")]
fn linger_enabled() -> bool {
    let user = match std::env::var("USER") {
        Ok(u) if !u.is_empty() => u,
        _ => return false,
    };
    Command::new("loginctl")
        .args(["show-user", &user, "--property=Linger"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).into_owned())
            } else {
                None
            }
        })
        .map(|s| s.trim().eq_ignore_ascii_case("Linger=yes"))
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn linger_enabled() -> bool {
    // Non-linux platforms don't have systemd's linger concept.
    // Compiled but never called from the macOS / Windows / BSD
    // branches; provided so cross-target unit tests compile.
    false
}

fn kind_label(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Daemon => "daemon",
        ServiceKind::LocalRelay => "local-relay",
    }
}

fn launchd_plist_path(kind: ServiceKind) -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME env var unset"))?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", kind.label())))
}

fn launchctl_user_target() -> String {
    let uid = Command::new("id")
        .args(["-u"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "0".to_string());
    format!("gui/{uid}")
}

fn launchctl_target_for(kind: ServiceKind) -> String {
    format!("{}/{}", launchctl_user_target(), kind.label())
}

/// Resolve the macOS log destination for a service kind and ensure
/// the parent directory exists. Returns the absolute path that
/// launchd's `StandardOutPath` will redirect the service's stdout/
/// stderr to (`~/Library/Logs/wire-<kind>.log`).
///
/// v0.5.23: macOS-only. The previous version had a Linux branch that
/// computed a path nothing would ever write to, because the Linux
/// systemd unit logs to journald rather than a file. Caused a
/// confusing "logs at ~/.cache/wire/..." message on `wire service
/// install` when no such file ever appeared.
#[cfg(target_os = "macos")]
fn ensure_macos_log_path(kind: ServiceKind) -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME env var unset"))?;
    let dir = PathBuf::from(&home).join("Library").join("Logs");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating log dir {dir:?}"))?;
    Ok(dir.join(kind.log_basename()))
}

/// Stub for non-macOS targets so the macOS branch in `install_kind`
/// type-checks under cross-platform builds. Never called in practice
/// because the corresponding `cfg!(target_os = "macos")` guard skips
/// it. Returns an empty path; if you ever see this in a non-macOS
/// log message, it's a bug.
#[cfg(not(target_os = "macos"))]
fn ensure_macos_log_path(_kind: ServiceKind) -> Result<PathBuf> {
    Ok(PathBuf::new())
}

fn launchd_plist_xml(kind: ServiceKind, exe: &str, log_path: &str) -> String {
    let args_xml = kind
        .binary_args()
        .iter()
        .map(|a| format!("        <string>{a}</string>"))
        .collect::<Vec<_>>()
        .join("\n");
    let label = kind.label();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{log_path}</string>
    <key>StandardErrorPath</key>
    <string>{log_path}</string>
</dict>
</plist>
"#
    )
}

fn systemd_unit_path(kind: ServiceKind) -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME env var unset"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user")
        .join(kind.systemd_unit_name()))
}

fn systemd_unit_text(kind: ServiceKind, exe: &str) -> String {
    let args = kind.binary_args().join(" ");
    let desc = kind.description();
    format!(
        r#"[Unit]
Description={desc}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} {args}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchd_plist_xml_for_daemon_contains_required_keys() {
        let xml = launchd_plist_xml(
            ServiceKind::Daemon,
            "/usr/local/bin/wire",
            "/tmp/wire-daemon.log",
        );
        assert!(xml.contains("<key>Label</key>"));
        assert!(xml.contains(ServiceKind::Daemon.label()));
        assert!(xml.contains("/usr/local/bin/wire"));
        assert!(xml.contains("<string>daemon</string>"));
        assert!(xml.contains("<string>--interval</string>"));
        assert!(xml.contains("<key>KeepAlive</key>"));
        assert!(xml.contains("<key>RunAtLoad</key>"));
        assert!(xml.contains("<true/>"));
        // v0.5.22: log path is honored, not /dev/null.
        assert!(xml.contains("/tmp/wire-daemon.log"));
        assert!(!xml.contains("/dev/null"));
    }

    #[test]
    fn launchd_plist_xml_for_local_relay_uses_correct_args() {
        let xml = launchd_plist_xml(
            ServiceKind::LocalRelay,
            "/usr/local/bin/wire",
            "/tmp/wire-local-relay.log",
        );
        assert!(xml.contains(ServiceKind::LocalRelay.label()));
        assert!(xml.contains("<string>relay-server</string>"));
        assert!(xml.contains("<string>--bind</string>"));
        assert!(xml.contains("<string>127.0.0.1:8771</string>"));
        assert!(xml.contains("<string>--local-only</string>"));
        // Must NOT include daemon args.
        assert!(!xml.contains("<string>daemon</string>"));
    }

    #[test]
    fn systemd_unit_text_for_daemon_contains_required_directives() {
        let unit = systemd_unit_text(ServiceKind::Daemon, "/usr/local/bin/wire");
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("/usr/local/bin/wire daemon --interval 5"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn systemd_unit_text_for_local_relay_uses_correct_exec() {
        let unit = systemd_unit_text(ServiceKind::LocalRelay, "/usr/local/bin/wire");
        assert!(
            unit.contains("/usr/local/bin/wire relay-server --bind 127.0.0.1:8771 --local-only")
        );
        assert!(!unit.contains("daemon --interval"));
    }

    #[test]
    fn label_and_unit_name_distinct_per_kind() {
        // Both kinds MUST have distinct identifiers so they can coexist
        // on the same machine.
        assert_ne!(ServiceKind::Daemon.label(), ServiceKind::LocalRelay.label());
        assert_ne!(
            ServiceKind::Daemon.systemd_unit_name(),
            ServiceKind::LocalRelay.systemd_unit_name()
        );
        assert_ne!(
            ServiceKind::Daemon.log_basename(),
            ServiceKind::LocalRelay.log_basename()
        );
    }
}
