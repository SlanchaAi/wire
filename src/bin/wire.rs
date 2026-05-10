//! `wire` binary entry point.
//!
//! All logic lives in `wire::cli` so it can be unit-tested. This file is
//! only argument parsing + error printing.

use std::process::ExitCode;

fn main() -> ExitCode {
    if let Err(e) = wire::cli::run() {
        eprintln!("error: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
