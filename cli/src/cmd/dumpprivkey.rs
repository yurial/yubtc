//! `yubtc dumpprivkey` — show the WIF for `(seed, nonce)`.
//!
//! Mirrors `yubtc-python/src/yubtc/cli.py:dumpprivkey`:
//!
//! - Reads the seed from stdin (one line).
//! - Reads the passphrase via `rpassword` (no echo).
//! - Prints the address then the WIF (two lines).

use crate::cli::DumpprivkeyArgs;
use crate::error::CliError;
use crate::prompt::{prompt_seed, read_seed_and_passphrase, validate_entered_seed};
use yubtc_core::misc::TNonce;
use yubtc_core::net;

use super::address::resolve_kdf;

pub async fn run(args: DumpprivkeyArgs) -> Result<(), CliError> {
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
    let wallet = yubtc_core::wallet::Wallet::new(
        seed.clone(),
        nonce,
        1,
        passphrase.clone(),
        kdf,
        addr_type,
        backend,
    )
    .await?;
    let privkey = wallet
        .privkeys
        .first()
        .expect("invariant: Wallet::new(new=1) yields at least one key");
    // The address in the selected form (the WIF is the key of that
    // form: for `pbkdf2` each addr_type is its own BIP-32 leaf, for
    // вариант-A KDFs the WIF is identical across types).
    let address = privkey.get_address();
    let wif = privkey.get_privwif();
    println!("Address: {address}");
    println!("{wif}");
    Ok(())
}
