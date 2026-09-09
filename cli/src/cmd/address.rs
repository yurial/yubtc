//! `yubtc address` — show the receive address for `(seed, nonce)`.
//!
//! Mirrors `yubtc-python/src/yubtc/cli.py:address` (extended by the
//! Phase 13 `--addr-type` axis):
//!
//! - Reads the seed from stdin (one line).
//! - Reads the passphrase via `rpassword` (no echo).
//! - Resolves `--provider` via `yubtc_core::net::get_backend`.
//! - Resolves `--kdf` (`auto` → yubtc/pbkdf2 per legacy heuristic) and
//!   `--addr-type` (`native` default → P2WPKH `bc1q…`).
//! - Prints the first privkey's address in the selected form.

use crate::cli::{AddressArgs, KdfName};
use crate::error::CliError;
use crate::prompt::{prompt_seed, read_seed_and_passphrase, validate_entered_seed};
use yubtc_core::kdf::KdfAlgo;
use yubtc_core::misc::{TNonce, TPassphrase, TSeed};
use yubtc_core::net;
use yubtc_core::wallet::Wallet;

pub async fn run(args: AddressArgs) -> Result<(), CliError> {
    prompt_seed()?;
    let (seed, passphrase) = read_seed_and_passphrase()?;
    // Reception-time seed policy (permissive default / opt-in
    // strict BIP-39 + the non-blocking entropy warning), before any
    // KDF work (specs/spec.md «Seed policy», R-1…R-6).
    validate_entered_seed(&seed, args.seed_policy.strict_bip39)?;
    let kdf = resolve_kdf(args.kdf.kdf, &passphrase);
    let addr_type = args.addr_type.addr_type.to_core();

    // Backend injection: resolve once, thread explicitly (specs/spec.md
    // «Явная передача бэкенда»).
    let backend =
        net::get_backend_with_retries(args.provider.provider.as_str(), args.provider.retries)?;

    let nonce = TNonce::new(args.nonce);
    let wallet = Wallet::new(
        seed.clone(),
        nonce,
        args.new,
        passphrase.clone(),
        kdf,
        addr_type,
        backend,
    )
    .await?;
    let address = wallet
        .privkeys
        .first()
        .ok_or_else(|| CliError::Wallet("new wallet has no addresses".to_string()))?
        .get_address();
    println!("{address}");
    Ok(())
}

/// `auto` → yubtc cascade (empty passphrase) or pbkdf2 (non-empty).
/// Anything else passes through as the matching `KdfAlgo`.
pub fn resolve_kdf(flag: KdfName, passphrase: &TPassphrase) -> KdfAlgo {
    match flag {
        KdfName::Auto => {
            if passphrase.is_empty() {
                KdfAlgo::Yubtc
            } else {
                KdfAlgo::Pbkdf2
            }
        }
        KdfName::Yubtc => KdfAlgo::Yubtc,
        KdfName::Pbkdf2 => KdfAlgo::Pbkdf2,
        KdfName::Argon2id => KdfAlgo::Argon2id,
        KdfName::Scrypt => KdfAlgo::Scrypt,
    }
}

/// Helper kept for parity with `address`/`dumpprivkey`/`balance`/`send`
/// — each of those commands constructs the wallet from `(seed,
/// nonce, new, passphrase, kdf, addr_type)`; centralising the
/// construction avoids drift between them.
#[allow(dead_code)]
pub async fn open_wallet(
    seed: TSeed,
    nonce: TNonce,
    new: usize,
    passphrase: TPassphrase,
    kdf: KdfAlgo,
    addr_type: yubtc_core::wallet::AddrType,
    backend: std::sync::Arc<dyn yubtc_core::net::NetworkBackend>,
) -> Result<Wallet, CliError> {
    Ok(Wallet::new(seed, nonce, new, passphrase, kdf, addr_type, backend).await?)
}

#[cfg(test)]
mod tests {
    //! Tests for the `resolve_kdf` helper.
    //!
    //! Mirrors the Python `_resolve_kdf`: `auto` infers yubtc/pbkdf2
    //! from passphrase emptiness; everything else passes through.

    use super::*;
    use yubtc_core::misc::TPassphrase;

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn auto_with_empty_passphrase_picks_yubtc() {
        assert_eq!(
            resolve_kdf(KdfName::Auto, &TPassphrase::EMPTY),
            KdfAlgo::Yubtc
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn auto_with_non_empty_passphrase_picks_pbkdf2() {
        assert_eq!(
            resolve_kdf(KdfName::Auto, &TPassphrase::new("hunter2")),
            KdfAlgo::Pbkdf2
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn named_kdfs_pass_through_unchanged() {
        assert_eq!(
            resolve_kdf(KdfName::Yubtc, &TPassphrase::EMPTY),
            KdfAlgo::Yubtc
        );
        assert_eq!(
            resolve_kdf(KdfName::Pbkdf2, &TPassphrase::new("x")),
            KdfAlgo::Pbkdf2
        );
        assert_eq!(
            resolve_kdf(KdfName::Argon2id, &TPassphrase::new("x")),
            KdfAlgo::Argon2id
        );
        assert_eq!(
            resolve_kdf(KdfName::Scrypt, &TPassphrase::new("x")),
            KdfAlgo::Scrypt
        );
    }

    /// In-process tests for the `open_wallet` helper (kept for parity
    /// with the other commands; dead code in the binary). The wallet
    /// scan talks to the injected backend, so these tests mutate the
    /// process-global backend and are `#[serial]`. They never read
    /// stdin.
    ///
    /// `serde_json::json!` expands to `unwrap()` internally, which
    /// trips the repo-wide disallowed-methods lint — same allowance
    /// as the core test modules.
    #[allow(clippy::disallowed_methods)]
    mod open_wallet_tests {
        use super::super::open_wallet;
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use yubtc_core::kdf::KdfAlgo;
        use yubtc_core::misc::{TNonce, TPassphrase, TSeed};
        use yubtc_core::net::BlockchainInfoBackend;

        // BIP-39 test vector #2 — 9 distinct words of 12 passes the
        // C6 entropy floor (vector #1 abandon×11+about no longer
        // does).
        const SEED: &str =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";

        /// One-shot runtime for the sync test fns below. `enable_all`
        /// is required: wiremock's mock server uses timers.
        fn block_on<F: std::future::Future>(fut: F) -> F::Output {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime builds")
                .block_on(fut)
        }

        fn fixture_key(nonce: u32) -> yubtc_core::wallet::TPrivKey {
            yubtc_core::wallet::TPrivKey::new(
                &TSeed::new(SEED),
                TNonce::new(nonce),
                &TPassphrase::new("x"),
                KdfAlgo::Pbkdf2,
            )
            .expect("fixture derivation is deterministic")
        }

        /// Zero-balance chain: every address unused → the scan stops
        /// at nonce 0 and `new` appends it. The gap walk checks all
        /// three address forms per nonce, so the mock body must carry
        /// each form's address (P2PKH + P2WPKH + P2TR of the fixture
        /// keys).
        async fn zero_chain() -> MockServer {
            use yubtc_core::wallet::AddrType;
            let server = MockServer::start().await;
            let mut obj = serde_json::Map::new();
            for nonce in 0..8u32 {
                for addr_type in AddrType::ALL {
                    let key = yubtc_core::wallet::TPrivKey::with_addr_type(
                        &TSeed::new(SEED),
                        TNonce::new(nonce),
                        &TPassphrase::new("x"),
                        KdfAlgo::Pbkdf2,
                        addr_type,
                    )
                    .expect("fixture derivation is deterministic");
                    obj.insert(
                        key.get_address().as_str().to_string(),
                        serde_json::json!({ "total_received": 0, "final_balance": 0, "n_tx": 0 }),
                    );
                }
            }
            Mock::given(method("GET"))
                .and(path("/balance"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::Value::Object(obj)),
                )
                .mount(&server)
                .await;
            server
        }

        #[ntest_timeout::timeout(5000)]
        #[test]
        fn open_wallet_scans_to_gap_limit() {
            let result = block_on(async {
                let server = zero_chain().await;
                let backend = Arc::new(BlockchainInfoBackend::new(server.uri()));
                open_wallet(
                    TSeed::new(SEED),
                    TNonce::new(0),
                    1,
                    TPassphrase::new("x"),
                    KdfAlgo::Pbkdf2,
                    yubtc_core::wallet::AddrType::Legacy,
                    backend,
                )
                .await
            });
            let wallet = result.expect("wallet opens against the mock chain");
            assert_eq!(wallet.privkeys.len(), 1);
            assert_eq!(
                wallet.privkeys[0].get_p2pkh_address().as_str(),
                fixture_key(0).get_p2pkh_address().as_str()
            );
        }

        #[ntest_timeout::timeout(5000)]
        #[test]
        fn open_wallet_rejects_empty_seed() {
            let result = block_on(async {
                let backend = Arc::new(BlockchainInfoBackend::new("http://127.0.0.1:1"));
                open_wallet(
                    TSeed::new(""),
                    TNonce::new(0),
                    1,
                    TPassphrase::new("x"),
                    KdfAlgo::Pbkdf2,
                    yubtc_core::wallet::AddrType::Legacy,
                    backend,
                )
                .await
            });
            // `Wallet::new` validates the seed before any I/O, so an
            // Ok here is impossible — invariant expect, not a branch.
            let err = result
                .err()
                .expect("invariant: Wallet::new rejects an empty seed before any I/O");
            assert!(err.to_string().contains("seed cannot be empty"));
        }
    }
}
