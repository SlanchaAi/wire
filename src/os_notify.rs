//! Cross-platform best-effort desktop notifications.
//!
//! Each backend shells out to the native binary (notify-send / osascript /
//! powershell). Failures are swallowed — we'd rather lose a toast than crash
//! the caller. Used by both `wire notify` (inbox events) and the daemon's
//! pending-pair tick (SAS-ready, pair-confirmed).

#[cfg(target_os = "linux")]
pub fn toast(title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .arg("--app-name=wire")
        .arg("--icon=mail-message-new")
        .arg(title)
        .arg(body)
        .output();
}

#[cfg(target_os = "macos")]
pub fn toast(title: &str, body: &str) {
    let safe = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "display notification \"{}\" with title \"{}\"",
        safe(body),
        safe(title),
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output();
}

#[cfg(target_os = "windows")]
pub fn toast(title: &str, body: &str) {
    eprintln!("[wire notify] {title}\n  {body}");
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn toast(title: &str, body: &str) {
    eprintln!("[wire notify] {title}\n  {body}");
}
