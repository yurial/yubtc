//! `yubtc` — native CLI for the yubtc Bitcoin wallet.
//!
//! The binary is a thin wrapper around the clap-derived command tree
//! in [`cli`]; all command implementations live in [`cmd`]. Errors
//! funnel through [`error::CliError`] to a stderr message + exit code
//! via [`error::report`].
//!
//! See `specs/spec.md` «CLI — команды» for the original design and `cli.rs`
//! for the flag surface (mirrors `yubtc-python/src/yubtc/cli.py` 1:1).

pub mod cli;
pub mod cmd;
pub mod error;
pub mod prompt;

use std::process::ExitCode;

use clap::Parser;

mod logging;

fn main() -> ExitCode {
    // Logging policy (C7): silent in release unless YUBTC_LOG is set.
    logging::init();

    let parsed = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // clap's own error reporting writes to stderr/clap-stderr
            // and returns the appropriate exit code (1 for usage,
            // 2 for parse).
            e.exit()
        }
    };

    tracing::debug!(command = ?parsed.command, "dispatching");

    // Async dispatch on a per-call tokio runtime. The wallet core is
    // async because it talks to reqwest; the CLI exposes only sync
    // methods to its callers, so a one-shot runtime here is correct.
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("yubtc-cli")
        .build()
        .expect("yubtc: failed to build tokio runtime")
        .block_on(cmd::run(parsed.command));

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => error::report(&e),
    }
}
