//! P1.9 (0.5.11): install + manage an OS service unit that runs
//! `wire daemon` automatically.
//!
//! Today's onboarding tells operators "run `wire daemon &` in a tmux
//! pane or write a launchd plist yourself" — friction that gets skipped,
//! leading to the "daemon dies on reboot, peer sends evaporate" silent
//! class. Bake the unit install into `wire service install` so it's one
//! command, idempotent, cross-platform.
//!
//! macOS: `~/Library/LaunchAgents/sh.slancha.wire.daemon.plist`
//! linux: `~/.config/systemd/user/wire-daemon.service`
//!
//! The unit auto-starts on login + restarts on crash. Pair with
//! `wire upgrade` (P0.5) for atomic version swaps without unit churn.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};

const LAUNCHD_LABEL: &str = "sh.slancha.wire.daemon";
const SYSTEMD_UNIT_NAME: &str = "wire-daemon.service";

/// Outcome of `wire service install` etc., suitable for both human + JSON
/// rendering.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceReport {
    pub action: String,
    pub platform: String,
    pub unit_path: String,
    pub status: String,
    pub detail: String,
}

/// Install a user-scope service unit that runs `wire daemon` and writes
/// a [P0.4 versioned pidfile](crate::ensure_up::DaemonPid).
pub fn install() -> Result<ServiceReport> {
    let exe = std::env::current_exe()?;
    let exe_str = exe.to_string_lossy().to_string();

    if cfg!(target_os = "macos") {
        let plist_path = launchd_plist_path()?;
        if let Some(parent) = plist_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {parent:?}"))?;
        }
        let plist = launchd_plist_xml(&exe_str);
        std::fs::write(&plist_path, plist)
            .with_context(|| format!("writing {plist_path:?}"))?;

        // launchctl load is idempotent — bootout first to avoid the
        // "service already loaded" error on re-install.
        let _ = Command::new("launchctl")
            .args(["bootout", &launchctl_user_target()])
            .status();
        let load = Command::new("launchctl")
            .args(["bootstrap", &launchctl_user_target(), plist_path.to_str().unwrap_or("")])
            .status();
        let loaded = load.map(|s| s.success()).unwrap_or(false);

        return Ok(ServiceReport {
            action: "install".into(),
            platform: "macos-launchd".into(),
            unit_path: plist_path.to_string_lossy().to_string(),
            status: if loaded { "loaded".into() } else { "written".into() },
            detail: if loaded {
                "plist written and bootstrapped via launchctl".into()
            } else {
                "plist written; `launchctl bootstrap` failed — try manually".into()
            },
        });
    }
    if cfg!(target_os = "linux") {
        let unit_path = systemd_unit_path()?;
        if let Some(parent) = unit_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {parent:?}"))?;
        }
        let unit = systemd_unit_text(&exe_str);
        std::fs::write(&unit_path, unit)
            .with_context(|| format!("writing {unit_path:?}"))?;

        // Reload + enable + start. Each is idempotent on linux.
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let enabled = Command::new("systemctl")
            .args(["--user", "enable", "--now", SYSTEMD_UNIT_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        return Ok(ServiceReport {
            action: "install".into(),
            platform: "linux-systemd-user".into(),
            unit_path: unit_path.to_string_lossy().to_string(),
            status: if enabled { "enabled".into() } else { "written".into() },
            detail: if enabled {
                "service unit written, daemon-reload + enable --now succeeded".into()
            } else {
                "unit written; `systemctl --user enable --now` failed — try manually".into()
            },
        });
    }
    bail!("wire service install: unsupported platform")
}

pub fn uninstall() -> Result<ServiceReport> {
    if cfg!(target_os = "macos") {
        let plist_path = launchd_plist_path()?;
        let _ = Command::new("launchctl")
            .args(["bootout", &launchctl_user_target()])
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
            status: if removed { "removed".into() } else { "absent".into() },
            detail: "launchctl bootout + plist file removed".into(),
        });
    }
    if cfg!(target_os = "linux") {
        let unit_path = systemd_unit_path()?;
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", SYSTEMD_UNIT_NAME])
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
            status: if removed { "removed".into() } else { "absent".into() },
            detail: "systemctl disable --now + unit file removed".into(),
        });
    }
    bail!("wire service uninstall: unsupported platform")
}

pub fn status() -> Result<ServiceReport> {
    if cfg!(target_os = "macos") {
        let plist_path = launchd_plist_path()?;
        let exists = plist_path.exists();
        // launchctl print on a user target succeeds if the service is
        // loaded; failure = not loaded.
        let listed = Command::new("launchctl")
            .args(["list", LAUNCHD_LABEL])
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
        });
    }
    if cfg!(target_os = "linux") {
        let unit_path = systemd_unit_path()?;
        let exists = unit_path.exists();
        let active = Command::new("systemctl")
            .args(["--user", "is-active", SYSTEMD_UNIT_NAME])
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
        });
    }
    bail!("wire service status: unsupported platform")
}

fn launchd_plist_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME env var unset"))?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist")))
}

fn launchctl_user_target() -> String {
    // `gui/<uid>` is the modern domain for user-scope LaunchAgents. Use
    // `id -u` rather than pulling in libc just for getuid().
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

fn launchd_plist_xml(exe: &str) -> String {
    // Minimal launchd plist. KeepAlive=true keeps the daemon up across
    // any crash; RunAtLoad=true starts it on launchctl bootstrap +
    // every login.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>daemon</string>
        <string>--interval</string>
        <string>5</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
"#
    )
}

fn systemd_unit_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME env var unset"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user")
        .join(SYSTEMD_UNIT_NAME))
}

fn systemd_unit_text(exe: &str) -> String {
    // User-scope unit. Restart=on-failure + RestartSec=5 keep daemon
    // alive through transient crashes; Install.WantedBy=default.target
    // makes it survive logout/login.
    format!(
        r#"[Unit]
Description=wire — magic-wormhole for AI agents (daemon)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} daemon --interval 5
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
    fn launchd_plist_xml_contains_required_keys() {
        // P1.9: catch the "minimal plist forgot KeepAlive and the daemon
        // died silently when terminal closed" class.
        let xml = launchd_plist_xml("/usr/local/bin/wire");
        assert!(xml.contains("<key>Label</key>"));
        assert!(xml.contains(LAUNCHD_LABEL));
        assert!(xml.contains("/usr/local/bin/wire"));
        assert!(xml.contains("<key>KeepAlive</key>"));
        assert!(xml.contains("<key>RunAtLoad</key>"));
        // <true/> form, not <bool>true</bool>, is the only one launchd
        // accepts for plist booleans.
        assert!(xml.contains("<true/>"));
    }

    #[test]
    fn systemd_unit_text_contains_required_directives() {
        let unit = systemd_unit_text("/usr/local/bin/wire");
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("/usr/local/bin/wire daemon"));
        assert!(unit.contains("Restart=on-failure"));
        // WantedBy must be default.target for user-scope units (not
        // multi-user.target which is system-scope and unprivileged users
        // can't enable).
        assert!(unit.contains("WantedBy=default.target"));
    }
}
