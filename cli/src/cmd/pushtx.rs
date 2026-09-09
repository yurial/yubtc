//! `yubtc pushtx` — broadcast a raw tx read from stdin.
//!
//! Mirrors `yubtc-python/src/yubtc/cli.py:pushtx`:
//!
//! - Reads one line of hex from stdin (the raw tx).
//! - Computes the txid as the double-SHA256 of the raw bytes in
//!   reversed byte order.
//! - Prints `id:`, `txsize=`, `rawtx:`.
//! - Prompts unless `-y` is set.

use std::io::{self, BufRead, Write};

use crate::cli::PushtxArgs;
use crate::error::CliError;
use sha2::{Digest, Sha256};
use yubtc_core::net;

pub async fn run(args: PushtxArgs) -> Result<(), CliError> {
    // Backend injection: resolve once, thread explicitly.
    let backend =
        net::get_backend_with_retries(args.provider.provider.as_str(), args.provider.retries)?;

    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut rawtx_hex = String::new();
    handle
        .read_line(&mut rawtx_hex)
        .map_err(|e| CliError::Stdin(e.to_string()))?;
    let rawtx_hex = rawtx_hex.trim();
    if rawtx_hex.is_empty() {
        return Err(CliError::Usage("no transaction on stdin".to_string()));
    }
    let rawtx = hex::decode(rawtx_hex)
        .map_err(|e| CliError::Usage(format!("invalid hex on stdin: {e}")))?;

    // txid = reversed double-SHA256 of the raw bytes. Bitcoin convention.
    let h1 = Sha256::digest(&rawtx);
    let mut txid = Sha256::digest(h1);
    txid.reverse();
    let txid_hex = hex::encode(txid);

    println!("id: {txid_hex}");
    println!("txsize={}", rawtx.len());
    println!("rawtx: {rawtx_hex}");

    if !args.yes {
        let mut answer = String::new();
        print!("broadcast? ");
        // The `println!`s above already flushed line-buffered stdout,
        // so this flush (for the not-yet-flushed prompt) cannot fail
        // unless the earlier println!s would have panicked first.
        io::stdout()
            .flush()
            .expect("invariant: stdout healthy after println! flushes");
        // Reuse the `handle` lock taken above: `io::stdin().read_line`
        // would take a second lock on the same thread and deadlock
        // (std's Stdin mutex is not reentrant).
        handle
            .read_line(&mut answer)
            .map_err(|e| CliError::Stdin(e.to_string()))?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Err(CliError::BroadcastDeclined);
        }
    }

    net::broadcast(backend.as_ref(), &rawtx).await?;
    Ok(())
}
