//! `yubtc balance` — show the wallet balance.
//!
//! Mirrors `yubtc-python/src/yubtc/cli.py:balance`:
//!
//! - Reads seed + passphrase from stdin.
//! - Iterates the wallet's scanned addresses, fetching unspent outputs
//!   via the current backend.
//! - Prints `{nonce}# {address}: {amount} BTC` per address, then
//!   `Total: {amount} BTC`. `-v` adds per-UTXO lines.
//! - `-e` includes used-but-currently-empty addresses (otherwise they
//!   are skipped to avoid noise).

use crate::cli::BalanceArgs;
use crate::error::CliError;
use crate::prompt::{prompt_seed, read_seed_and_passphrase, validate_entered_seed};
use yubtc_core::misc::{satoshi2btc, TNonce, TSatoshi};
use yubtc_core::net;

use super::address::resolve_kdf;

pub async fn run(args: BalanceArgs) -> Result<(), CliError> {
    prompt_seed()?;
    let (seed, passphrase) = read_seed_and_passphrase()?;
    // Reception-time seed policy (permissive default / opt-in
    // strict BIP-39 + the non-blocking entropy warning), before any
    // KDF work (specs/spec.md «Seed policy», R-1…R-6).
    validate_entered_seed(&seed, args.seed_policy.strict_bip39)?;
    let kdf = resolve_kdf(args.kdf.kdf, &passphrase);
    let addr_type = args.addr_type.addr_type.to_core();

    // Backend injection: resolve once, thread explicitly.
    let backend =
        net::get_backend_with_retries(args.provider.provider.as_str(), args.provider.retries)?;

    let nonce = TNonce::new(args.nonce);
    let mut wallet = yubtc_core::wallet::Wallet::new(
        seed.clone(),
        nonce,
        args.new,
        passphrase.clone(),
        kdf,
        addr_type,
        backend.clone(),
    )
    .await?;

    let backend = wallet.backend().clone();
    let mut total: u64 = 0;
    for privkey in wallet.privkeys.iter_mut() {
        let address = privkey.get_address();
        let unspent = privkey
            .get_unspent(backend.as_ref(), args.confirmations)
            .await?;
        let in_amount: u64 = unspent.iter().map(|u| u.amount).sum();
        let is_unused = privkey.is_unused(backend.as_ref()).await?;
        if !args.empty && in_amount == 0 && !is_unused {
            continue;
        }
        if is_unused {
            println!("{}# {}: unused", privkey.nonce, address);
            continue;
        }
        let amount_btc = satoshi2btc(TSatoshi::new(in_amount));
        total = total.saturating_add(in_amount);
        println!("{}# {}: {amount_btc} BTC", privkey.nonce, address);
        if args.verbose {
            for tx in unspent {
                let tx_amount_btc = satoshi2btc(TSatoshi::new(tx.amount));
                println!(
                    "    ({}:{}): {tx_amount_btc}",
                    hex::encode(tx.txid),
                    tx.vout
                );
            }
        }
    }
    println!("Total: {}", satoshi2btc(TSatoshi::new(total)));
    Ok(())
}
