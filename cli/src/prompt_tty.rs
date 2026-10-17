//! Terminal dispatch for seed / passphrase entry.
//!
//! COVERAGE-EXCLUDED FILE: this module touches `rpassword` and real
//! TTY detection, neither of which can be exercised without an
//! interactive terminal. CI excludes it from llvm-cov measurement via
//! `--ignore-filename-regex '(^|/)(prompt_tty|tui_term)\.rs$'`; every
//! testable primitive (line reading, trimming, prompt order, the
//! hidden-input selection) lives in [`super`] (`prompt.rs`) and is
//! unit-tested there. Do not move logic back into this file.
//!
//! CI / piped stdin: `rpassword` defaults to `/dev/tty` for both
//! input and output, which doesn't exist in headless test runners.
//! When stdin is a TTY we keep the original `rpassword` behaviour
//! (no echo, `/dev/tty` dance); when stdin is a pipe the passphrase
//! is the first stdin line. The passphrase is prompted BEFORE the
//! seed, and an empty passphrase hides the seed read as well (no
//! echo, like a password read, so a bystander cannot see the seed
//! being typed); a non-empty one keeps the plain echoed line read.

use std::io::{self, IsTerminal};

use yubtc_core::misc::{TPassphrase, TSeed};

use crate::error::CliError;

/// Read the passphrase (no echo) and then the seed from stdin.
///
/// Returns `(seed, passphrase)`. The passphrase is read first: on a
/// TTY with `rpassword` (no echo, raw bytes), on a pipe it is the
/// first stdin line with only the trailing newline stripped. The
/// seed comes second — read with no echo as well when the passphrase
/// is empty, as the plain echoed line otherwise; it is
/// whitespace-trimmed. Both are canonicalised by the newtype
/// constructors in `yubtc-core::misc`.
pub fn read_seed_and_passphrase() -> Result<(TSeed, TPassphrase), CliError> {
    read_seed_and_passphrase_on(&mut super::prompt_seed)
}

/// [`read_seed_and_passphrase`] for the stdin→stdout filter commands
/// (`psbt`, `ms`): the `Seed: ` label goes to stderr so stdout stays
/// machine-readable.
pub fn read_seed_and_passphrase_stderr() -> Result<(TSeed, TPassphrase), CliError> {
    read_seed_and_passphrase_on(&mut super::prompt_seed_stderr)
}

/// Shared plumbing: lock stdin once and route the no-echo reads
/// through `rpassword`, delegating the prompt order and the
/// hidden-input selection to the testable orchestration in
/// [`super`].
fn read_seed_and_passphrase_on(
    print_seed_label: &mut dyn FnMut() -> Result<(), CliError>,
) -> Result<(TSeed, TPassphrase), CliError> {
    let stdin = io::stdin();
    let is_tty = stdin.is_terminal();
    let mut handle = stdin.lock();

    // rpassword opens /dev/tty directly — there's no FD-0 contention
    // with the stdin lock we are holding.
    let mut read_hidden = |label: &str| rpassword::prompt_password(label);

    super::read_seed_and_passphrase_from(&mut handle, is_tty, &mut read_hidden, print_seed_label)
}
