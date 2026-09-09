//! Terminal dispatch for seed / passphrase entry.
//!
//! COVERAGE-EXCLUDED FILE: this module touches `rpassword` and real
//! TTY detection, neither of which can be exercised without an
//! interactive terminal. CI excludes it from llvm-cov measurement via
//! `--ignore-filename-regex '(^|/)(prompt_tty|tui_term)\.rs$'`; every
//! testable primitive (line reading, trimming) lives in
//! [`super`] (`prompt.rs`) and is unit-tested there. Do not move
//! logic back into this file.
//!
//! CI / piped stdin: `rpassword` defaults to `/dev/tty` for both
//! input and output, which doesn't exist in headless test runners.
//! When stdin is a TTY we keep the original `rpassword` behaviour (no
//! echo, `/dev/tty` dance); when stdin is a pipe the passphrase is
//! the second stdin line (the Python CLI convention).

use std::io::{self, IsTerminal};

use yubtc_core::misc::{TPassphrase, TSeed};

use super::{read_passphrase_line, read_seed_from, stdin_err};
use crate::error::CliError;

/// Read the seed (one line) and the passphrase (no echo) from stdin.
///
/// Returns `(seed, passphrase)`. The seed is whitespace-trimmed; on a
/// TTY the passphrase is read with `rpassword` (no echo, raw bytes),
/// on a pipe it is the second stdin line with only the trailing
/// newline stripped. Both are canonicalised by the newtype
/// constructors in `yubtc-core::misc`.
pub fn read_seed_and_passphrase() -> Result<(TSeed, TPassphrase), CliError> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    let seed = read_seed_from(&mut handle)?;

    // Passphrase read: TTY → rpassword handles the /dev/tty dance
    // and no-echo input. Pipe → second line on stdin.
    let passphrase_str = if stdin.is_terminal() {
        // We're holding the lock, but rpassword opens /dev/tty
        // directly — there's no FD-0 contention. Drop the lock first
        // to avoid the rare case where rpassword's internal lock
        // ordering disagrees with ours.
        drop(handle);
        rpassword::prompt_password("Passphrase: ").map_err(stdin_err)?
    } else {
        read_passphrase_line(&mut handle)?
    };
    let passphrase = TPassphrase::new(passphrase_str);

    Ok((seed, passphrase))
}
