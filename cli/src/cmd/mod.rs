//! yubtc CLI — command implementations and dispatch.
//!
//! The clap-derived command tree lives in [`crate::cli`]; the
//! implementations live here. Each command returns
//! `Result<(), CliError>` and is unit-tested in-module.
//!
//! Commands:
//!
//! - [`newseed`] — generate a fresh seed and print the resulting address.
//! - [`address`] — show the P2PKH address for `(seed, nonce)`.
//! - [`dumpprivkey`] — show the WIF for `(seed, nonce)`.
//! - [`balance`] — show the wallet's per-address balance.
//! - [`send`] — build, sign, optionally broadcast a transaction
//!   (with optional Coin Control TUI).
//! - [`psbt`] — BIP-174 subcommand group: `create` / `sign` /
//!   `combine` / `finalize` / `extract` / `decode` (Phase 14);
//!   stdin→stdout filters around [`yubtc_core::psbt`].
//! - [`pushtx`] — broadcast a raw tx read from stdin.
//!
//! Dispatch lives in [`run`], called from `main.rs`. Unknown / mistyped
//! commands are caught by clap before reaching `run` (clap exits with
//! code 2 on arg parse errors).

pub mod address;
pub mod balance;
pub mod dumpprivkey;
pub mod ms;
pub mod newseed;
pub mod psbt;
pub mod pushtx;
pub mod send;

pub mod select;
pub mod tui;

use crate::cli::Command;
use crate::error::CliError;

/// The Phase-13 typed refusal of a P2WSH recipient (`bc1q…` with a
/// 32-byte program) on the personal-send surfaces (`send`,
/// `psbt create`). v0.3 unlocked P2WSH lock scripts in the wallet
/// core for the multi-sig quorum surface (cashback address), but the
/// documented recipient policy of the personal flows is unchanged —
/// this guard reproduces the pre-v0.3 error message byte-for-byte
/// (`SegWitAddrError::UnsupportedProgram` as it surfaced through
/// `WalletError::AddressDecode` before the core unlock).
pub fn reject_p2wsh_recipient(address: &yubtc_core::misc::TAddress) -> Result<(), CliError> {
    if yubtc_core::address::decode_p2wsh_address(address.as_str()).is_ok() {
        return Err(CliError::Wallet(format!(
            "address could not be decoded: {}",
            yubtc_core::address::SegWitAddrError::UnsupportedProgram
        )));
    }
    Ok(())
}

/// Dispatch a parsed clap command to the corresponding implementation.
///
/// All command implementations are `async` because they call into the
/// async wallet core (`reqwest`-backed `NetworkBackend`); we run them
/// on a per-call tokio runtime via [`block_on`].
///
/// Returning `Err(CliError::Cancelled)` (q / Esc in the TUI) is
/// translated by `main` into exit code 130.
pub async fn run(cmd: Command) -> Result<(), CliError> {
    match cmd {
        Command::Newseed(args) => newseed::run(args).await,
        Command::Address(args) => address::run(args).await,
        Command::Balance(args) => balance::run(args).await,
        Command::Send(args) => send::run(args).await,
        Command::Psbt(args) => psbt::run(args.command).await,
        Command::Ms(args) => ms::run(args.command).await,
        Command::Dumpprivkey(args) => dumpprivkey::run(args).await,
        Command::Pushtx(args) => pushtx::run(args).await,
    }
}
