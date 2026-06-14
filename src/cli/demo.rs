//! `wire demo` — a self-contained, ephemeral two-agent round-trip.
//!
//! One command boots a throwaway local relay, mints two temporary
//! identities, pairs them, and sends a signed message end-to-end — then
//! tears it all down. No install of a relay, no second terminal, no
//! copy-pasting a persona name. The fastest way to SEE wire work before
//! setting it up for real.
//!
//! It drives the same flow the CI-green `demo-invite.sh` exercises, but as a
//! shipped verb: it self-execs the running `wire` binary as subprocesses,
//! each under an isolated `WIRE_HOME`, so the orchestration matches exactly
//! what an operator would type by hand.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

/// RAII cleanup: kill the relay child and remove the temp tree on every exit
/// path (success, error, or panic). The demo must never leak a relay process
/// or a temp directory.
struct DemoGuard {
    relay: Option<Child>,
    work: PathBuf,
}

impl Drop for DemoGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.relay.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

/// Grab a free localhost port by binding :0 and reading back the assigned
/// port. The listener is dropped immediately; the relay re-binds it. (Small
/// TOCTOU window, fine for a local demo.)
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("reserving a local port")?;
    Ok(listener.local_addr()?.port())
}

/// Run a `wire` subcommand under an isolated home; return captured stdout.
/// Errors carry the subprocess stderr so a demo failure is diagnosable.
fn wire(bin: &Path, home: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new(bin)
        .env("WIRE_HOME", home)
        .env("WIRE_HOME_FORCE", "1")
        .env("WIRE_NO_TOASTS", "1")
        .env("WIRE_NO_INTERACTIVE", "1")
        .env_remove("WIRE_SESSION_ID")
        .args(args)
        .output()
        .with_context(|| format!("spawning `wire {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`wire {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Poll the relay's `/healthz` until it answers 200 (or time out).
fn wait_for_relay(port: u16) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(mut sock) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = sock.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n");
            let mut buf = [0u8; 128];
            if let Ok(n) = sock.read(&mut buf)
                && String::from_utf8_lossy(&buf[..n]).contains(" 200 ")
            {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("local relay did not come up on 127.0.0.1:{port}")
}

/// This home's DID-derived persona handle (`whoami --json .handle`).
fn handle_of(bin: &Path, home: &Path) -> Result<String> {
    let j: Value = serde_json::from_str(&wire(bin, home, &["whoami", "--json"])?)
        .context("parsing whoami --json")?;
    j.get("handle")
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("whoami --json missing a handle"))
}

pub(super) fn cmd_demo(as_json: bool) -> Result<()> {
    let bin = std::env::current_exe().context("locating the running wire binary")?;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let work = std::env::temp_dir().join(format!("wire-demo-{}-{nanos}", std::process::id()));
    let relay_home = work.join("relay");
    let a_home = work.join("agent-a");
    let b_home = work.join("agent-b");
    for d in [&relay_home, &a_home, &b_home] {
        std::fs::create_dir_all(d).with_context(|| format!("creating demo dir {}", d.display()))?;
    }

    let port = free_port()?;
    let relay_url = format!("http://127.0.0.1:{port}");

    let say = |s: &str| {
        if !as_json {
            println!("{s}");
        }
    };

    say(&format!("▶ booting a throwaway local relay on {relay_url}"));
    let relay = Command::new(&bin)
        .env("WIRE_HOME", &relay_home)
        .env("WIRE_NO_TOASTS", "1")
        .args(["relay-server", "--bind", &format!("127.0.0.1:{port}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning the local relay-server")?;
    // From here on, _guard tears everything down on any return/panic.
    let _guard = DemoGuard {
        relay: Some(relay),
        work: work.clone(),
    };
    wait_for_relay(port)?;

    say("▶ minting two throwaway identities on it…");
    wire(&bin, &a_home, &["init", "--relay", &relay_url])?;
    wire(&bin, &b_home, &["init", "--relay", &relay_url])?;
    let a = handle_of(&bin, &a_home)?;
    let b = handle_of(&bin, &b_home)?;
    say(&format!("    agent A → {a}\n    agent B → {b}"));

    say("▶ pairing them (A invites, B accepts — one paste in real life)…");
    let invite: Value = serde_json::from_str(&wire(
        &bin,
        &a_home,
        &["invite", "--relay", &relay_url, "--json"],
    )?)
    .context("parsing invite --json")?;
    let url = invite
        .get("invite_url")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("invite --json missing invite_url"))?;
    wire(&bin, &b_home, &["accept-invite", url, "--json"])?;
    // A pulls to consume B's pair_drop and pin B back (bilateral).
    wire(&bin, &a_home, &["pull", "--json"])?;

    let message = "hello from agent A 👋";
    say(&format!("▶ {a} sends {b}: \"{message}\""));
    wire(&bin, &a_home, &["send", &b, "decision", message])?;
    wire(&bin, &a_home, &["push", "--json"])?;
    wire(&bin, &b_home, &["pull", "--json"])?;

    let tail = wire(&bin, &b_home, &["tail", &a, "--json"])?;
    let landed: Value = tail
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|e| {
            e.get("body")
                .and_then(Value::as_str)
                .map(|s| s.contains("hello from agent A"))
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow!("round-trip failed: message never landed in B's inbox"))?;
    let verified = landed
        .get("verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !verified {
        bail!("round-trip failed: B received the message but its signature did not verify");
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "ok": true,
                "agent_a": a,
                "agent_b": b,
                "message": message,
                "verified": true,
                "relay_url": relay_url,
            }))?
        );
    } else {
        println!(
            "    {b} received it — signature verified ✓\n\
             \n\
             ✓ two agents just talked over a relay you owned: signed, verified, end-to-end.\n\
             \x20 (all ephemeral — torn down now.)\n\
             \n\
             Do it for real:\n\
             \x20 wire up                          come online (one command)\n\
             \x20 wire dial <friend>@wireup.net    reach someone on another machine\n\
             \x20 wire here                        who am I, who's around?"
        );
    }
    Ok(())
}
