//! `yubtc send` — build, sign, optionally broadcast a transaction.
//!
//! Mirrors `yubtc-python/src/yubtc/cli.py:send`:
//!
//! - Reads seed + passphrase from stdin.
//! - Resolves `--provider` / `--kdf`.
//! - If `-i` is set, opens the Coin Control TUI to pick inputs.
//! - Otherwise performs a lazy scan to gap-limit (or until the
//!   target is met), picks UTXOs from every contributing address,
//!   and builds the tx with the gap-limit unused address (or the
//!   last sourced address on target-met) as cashback. This matches
//!   Python's `_scan_inputs` semantics.
//! - `--scan` prints the per-address report after the lazy scan.
//! - Builds, signs, and either broadcasts or prints the raw tx.

use crate::cli::SendArgs;
use crate::error::CliError;
use crate::prompt::{prompt_seed, read_seed_and_passphrase, validate_entered_seed};
use yubtc_core::misc::{TAddress, TNonce, TSatoshi};
use yubtc_core::net;

use super::address::resolve_kdf;
use super::tui;

pub async fn run(args: SendArgs) -> Result<(), CliError> {
    // The documented Phase-13 recipient policy (v0.3: P2WSH lock
    // scripts are unlocked in the core for the multisig quorum
    // surface only — personal sends keep the typed refusal).
    // Checked first: the address is a pure argument, no I/O needed.
    super::reject_p2wsh_recipient(&TAddress::new(args.address.clone()))?;
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

    println!(
        "Address: {}",
        wallet
            .privkeys
            .first()
            .expect(
                "invariant: Wallet::new(new=1,
                yubtc_core::wallet::AddrType::Native,
            ) yields at least one key"
            )
            .get_address()
    );

    let dst = TAddress::new(args.address.clone());

    // `ALL` = drain; otherwise parse a decimal BTC amount.
    let amount_sat = if args.amount.eq_ignore_ascii_case("ALL") {
        None
    } else {
        let amount_sat = yubtc_core::misc::btc2satoshi(&args.amount)
            .map_err(|e| CliError::Usage(format!("amount: {e}")))?;
        if amount_sat.get() == 0 {
            return Err(CliError::Usage(
                "amount must be > 0 (use ALL to drain)".to_string(),
            ));
        }
        Some(amount_sat)
    };

    let fee_sat = if args.fee == 0.0 {
        TSatoshi::ZERO
    } else {
        let fee_btc = format!("{:.8}", args.fee);
        yubtc_core::misc::btc2satoshi(&fee_btc).map_err(|e| CliError::Usage(format!("fee: {e}")))?
    };
    let feekb_sat = TSatoshi::new(args.feekb);

    // `--scan`: print per-address info (nonce, address, balance)
    // for every scanned address. The wallet already walked to the
    // gap limit during construction; we just print the snapshot.
    if args.scan {
        print_scan_report(&wallet, args.confirmations).await?;
    }

    if args.interactive {
        return run_interactive(
            wallet,
            dst,
            amount_sat,
            fee_sat,
            feekb_sat,
            args.confirmations,
            args.broadcast || args.yes,
            args.yes,
            &tui::run_selection,
        )
        .await;
    }

    // Non-interactive path: lazy scan to gap-limit (or until the
    // target is met). Python parity: scan walks addresses, picks
    // UTXOs from every contributing address, cashback goes to the
    // gap-limit unused address (or last sourced on target-met).
    let target_sat = match (amount_sat, fee_sat.get()) {
        (Some(amt), fee) => Some(TSatoshi::new(amt.get() + fee)),
        // Drain mode: target = u64::MAX so we never early-terminate
        // on target-met, only on gap-limit.
        (None, _) => Some(TSatoshi::new(u64::MAX)),
    };
    let (sources, cashback_addr) = yubtc_core::wallet::scan_inputs_until(
        &seed,
        &passphrase,
        kdf,
        addr_type,
        wallet.backend().as_ref(),
        target_sat,
        args.confirmations,
    )
    .await?;
    if sources.is_empty() {
        return Err(CliError::Usage(
            "insufficient funds: no UTXOs in wallet".to_string(),
        ));
    }
    let tx = wallet
        .make_transaction(
            &dst,
            amount_sat,
            feekb_sat,
            fee_sat,
            args.confirmations,
            Some(sources),
            Some(cashback_addr),
        )
        .await?;

    // The broadcast payload is the WIRE serialization (BIP-144): for
    // a witness transaction the stripped layout is not a valid
    // network payload. Witness-free txs serialise byte-identically
    // to v0.1.
    finish(wallet.backend().as_ref(), &tx.tx, args.broadcast, args.yes).await
}

/// Print one line per scanned address: `{nonce}# {address}: {btc} BTC`.
///
/// Mirrors the Python `on_address` callback used by `--scan`. UTXOs
/// are filtered by `confirmations` so the report matches what the
/// fee loop will see.
async fn print_scan_report(
    wallet: &yubtc_core::wallet::Wallet,
    confirmations: u32,
) -> Result<(), CliError> {
    for mut privkey in wallet.privkeys.iter().cloned() {
        let unspent = privkey
            .get_unspent(wallet.backend().as_ref(), confirmations)
            .await?;
        let in_amount: u64 = unspent.iter().map(|u| u.amount).sum();
        let address = privkey.get_address();
        let amount_btc = yubtc_core::misc::satoshi2btc(yubtc_core::misc::TSatoshi::new(in_amount));
        println!("{}# {}: {amount_btc} BTC", privkey.nonce, address);
    }
    Ok(())
}

/// Selection-step signature injected into the interactive flows:
/// receives the full `Vec<Source>` (scan order), the target amount
/// (`None` = drain), the hard-set fee, the fee rate and the cashback
/// address; returns the per-UTXO selection mask (`Ok(None)` = user
/// cancelled, `Err` = terminal I/O failure). Shared by `send` and
/// `psbt create -i`.
pub(crate) type SelectFn<'a> = &'a dyn Fn(
    Vec<yubtc_core::wallet::Source>,
    Option<TSatoshi>,
    TSatoshi,
    TSatoshi,
    Option<TAddress>,
) -> std::io::Result<Option<Vec<bool>>>;

/// Outcome of the shared Coin Control selection + build step.
pub(crate) enum BuiltTx {
    /// Every scanned address is empty — nothing to spend.
    NoFunds,
    /// The user cancelled the selection (q / Esc).
    Cancelled,
    /// A signed transaction built from the selected inputs, together
    /// with the sources that funded it (in `vin` order — one entry
    /// per input, needed by the `psbt create` Creator).
    Built {
        tx: yubtc_core::transaction::Transaction,
        sources: Vec<yubtc_core::wallet::Source>,
    },
}

/// Interactive selection core shared by `send -i` and
/// `psbt create -i`: scan to the gap limit, run the Coin Control
/// selection step, regroup the selection, and build + sign the
/// transaction. Terminal I/O failures and build errors are `Err`;
/// the `BuiltTx::NoFunds` / `BuiltTx::Cancelled` outcomes are the
/// caller's to present.
///
/// `select` is the selection step, injected for testability: the
/// production caller passes [`tui::run_selection`]; tests pass a stub
/// so the post-selection flow is drivable headlessly. Taken as `&dyn
/// Fn` (not a generic) deliberately: a single instantiation keeps the
/// coverage counters shared between the real binary and the tests.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn select_and_build(
    wallet: &yubtc_core::wallet::Wallet,
    dst: TAddress,
    amount_sat: Option<TSatoshi>,
    fee_sat: TSatoshi,
    feekb_sat: TSatoshi,
    confirmations: u32,
    select: SelectFn<'_>,
) -> Result<BuiltTx, CliError> {
    // Scan to gap so the user sees every available UTXO. Reuse the
    // wallet's existing scan by walking addresses in order.
    let sources = collect_sources(wallet, confirmations).await?;
    if sources.is_empty() {
        return Ok(BuiltTx::NoFunds);
    }

    let cashback_addr = wallet.privkeys.first().map(|pk| pk.get_address());

    // If the target can't be reached, bail out before the UI.
    if let Some(target) = amount_sat {
        let total: u64 = sources
            .iter()
            .flat_map(|s| s.unspent.iter())
            .map(|u| u.amount)
            .sum();
        if target.get() > total {
            return Err(CliError::Usage(format!(
                "insufficient funds: target {} sat, available {total} sat",
                target.get()
            )));
        }
    }

    let mask = select(
        sources.clone(),
        amount_sat,
        fee_sat,
        feekb_sat,
        cashback_addr.clone(),
    )
    .map_err(|e| CliError::Stdin(e.to_string()))?;
    let Some(mask) = mask else {
        return Ok(BuiltTx::Cancelled);
    };

    let selected = tui::to_selected(sources.clone(), mask);
    if selected.is_empty() {
        return Err(CliError::Usage("no inputs selected".to_string()));
    }

    // Build sources Vec<Source> from the selected flat list.
    let grouped = group_sources(selected);

    let tx = wallet
        .make_transaction(
            &dst,
            amount_sat,
            feekb_sat,
            fee_sat,
            confirmations,
            Some(grouped.clone()),
            cashback_addr,
        )
        .await?;
    Ok(BuiltTx::Built {
        tx: tx.tx,
        sources: grouped,
    })
}

/// Interactive (`-i`) send flow: collect every funded address, run the
/// Coin Control selection step, then build/sign/optionally broadcast
/// from the selected inputs only.
///
/// Thin wrapper over [`select_and_build`] (shared with
/// `psbt create -i`) that presents the `NoFunds` / `Cancelled`
/// outcomes and finishes with the signed-tx announcement +
/// optional broadcast.
#[allow(clippy::too_many_arguments)]
async fn run_interactive(
    wallet: yubtc_core::wallet::Wallet,
    dst: TAddress,
    amount_sat: Option<TSatoshi>,
    fee_sat: TSatoshi,
    feekb_sat: TSatoshi,
    confirmations: u32,
    broadcast: bool,
    yes: bool,
    select: SelectFn<'_>,
) -> Result<(), CliError> {
    let backend = wallet.backend().clone();
    match select_and_build(
        &wallet,
        dst,
        amount_sat,
        fee_sat,
        feekb_sat,
        confirmations,
        select,
    )
    .await?
    {
        BuiltTx::NoFunds => {
            println!("No funds available");
            Ok(())
        }
        BuiltTx::Cancelled => {
            println!("Cancelled");
            Ok(())
        }
        BuiltTx::Built { tx, .. } => finish(backend.as_ref(), &tx, broadcast, yes).await,
    }
}

/// Walk the wallet's scanned privkeys and gather a `Vec<Source>` of
/// `(privkey, unspent)` pairs, filtered by `confirmations`.
pub(crate) async fn collect_sources(
    wallet: &yubtc_core::wallet::Wallet,
    confirmations: u32,
) -> Result<Vec<yubtc_core::wallet::Source>, CliError> {
    let mut sources = Vec::new();
    for mut privkey in wallet.privkeys.iter().cloned() {
        let unspent = privkey
            .get_unspent(wallet.backend().as_ref(), confirmations)
            .await
            .map_err(CliError::from)?;
        if unspent.is_empty() {
            continue;
        }
        sources.push(yubtc_core::wallet::Source { privkey, unspent });
    }
    Ok(sources)
}

/// Group the flat `(TPrivKey, Utxo)` selection back into
/// [`Vec<Source>`] keyed by the privkey's nonce.
///
/// Contract:
/// - Keying is by `TPrivKey::nonce` — stable and unique within a
///   wallet (the gap scan derives sequential nonces) — NOT by
///   pointer identity: the incoming `TPrivKey`s are loop-owned
///   clones whose addresses may repeat across iterations, so a
///   pointer key could merge distinct keys or split one key's UTXOs.
/// - Output is ordered by ascending nonce (the wallet scan produces
///   nonce-ascending sources, so this matches the TUI's row order).
/// - Within a group, UTXOs keep their arrival order.
/// - Every input UTXO appears in the output exactly once; groups are
///   never empty.
fn group_sources(
    flat: Vec<(yubtc_core::wallet::TPrivKey, yubtc_core::wallet::Utxo)>,
) -> Vec<yubtc_core::wallet::Source> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<yubtc_core::misc::TNonce, yubtc_core::wallet::Source> = BTreeMap::new();
    for (pk, u) in flat {
        match map.get_mut(&pk.nonce) {
            Some(src) => src.unspent.push(u),
            None => {
                let nonce = pk.nonce;
                map.insert(
                    nonce,
                    yubtc_core::wallet::Source {
                        privkey: pk,
                        unspent: vec![u],
                    },
                );
            }
        }
    }
    map.into_values().collect()
}

/// Print the signed-tx announcement (Python `_announce_tx` parity,
/// extended by the Phase 13 vsize line) and optionally broadcast.
///
/// The printed/broadcast payload is the **wire** serialization
/// (BIP-144) — a witness transaction is only a valid network payload
/// in that layout. `txsize` is the wire byte count; `vsize` is the
/// BIP-141 virtual size the fee loop bills at (witness bytes weigh
/// 1/4). `id` is the real txid (witness data excluded, BIP-141).
async fn finish(
    backend: &dyn yubtc_core::net::NetworkBackend,
    tx: &yubtc_core::transaction::Transaction,
    broadcast: bool,
    yes: bool,
) -> Result<(), CliError> {
    let wire = tx.serialize_wire();
    let raw_tx_hex = hex::encode(&wire);
    println!("id: {}", hex::encode(tx.id()));
    println!("txsize={}", wire.len());
    println!("vsize={}", tx.vsize());
    println!("rawtx: {raw_tx_hex}");
    if broadcast {
        if !yes {
            print!("broadcast? ");
            use std::io::Write;
            // The `println!`s above already flushed line-buffered
            // stdout, so this flush (for the not-yet-flushed prompt)
            // cannot fail unless the earlier println!s would have
            // panicked first.
            std::io::stdout()
                .flush()
                .expect("invariant: stdout healthy after println! flushes");
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .map_err(|e| CliError::Stdin(e.to_string()))?;
            if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                return Err(CliError::BroadcastDeclined);
            }
        }
        net::broadcast(backend, &wire).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit tests for the pure `group_sources` helper (the TUI-side
    //! flat `(TPrivKey, Utxo)` selection → `Vec<Source>` regrouping).
    //! `group_sources` touches no global state, so these tests run
    //! without `#[serial]`.
    //!
    //! The `run_interactive` tests below drive the post-selection flow
    //! (mask → regroup → make_transaction → finish) headlessly by
    //! injecting a stub selector; they mutate the process-global
    //! network backend and are therefore `#[serial]`, following the
    //! pattern of the `newseed` in-process tests.

    use super::group_sources;
    use yubtc_core::kdf::KdfAlgo;
    use yubtc_core::misc::{TNonce, TPassphrase, TSeed};
    use yubtc_core::wallet::{TPrivKey, Utxo};

    // BIP-39 test vector #2 — 9 distinct words of 12 passes the C6
    // entropy floor (vector #1 abandon×11+about no longer does).
    const SEED: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    fn pk(nonce: u32) -> TPrivKey {
        TPrivKey::new(
            &TSeed::new(SEED),
            TNonce::new(nonce),
            &TPassphrase::new("x"),
            KdfAlgo::Pbkdf2,
        )
        .expect("fixture derivation is deterministic")
    }

    fn utxo(amount: u64, vout: u32) -> Utxo {
        Utxo {
            txid: [vout as u8; 32],
            vout,
            amount,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0x88, 0xac],
            confirmations: 6,
        }
    }

    /// Empty input → empty output.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn group_sources_empty_is_empty() {
        assert!(group_sources(Vec::new()).is_empty());
    }

    /// Multi-entry input driving both map arms (fresh-key insert +
    /// existing-key append), interleaved so a broken keying cannot
    /// pass by accident: three nonces, UTXOs interleaved across
    /// them. The grouping semantics ARE asserted (keyed by the
    /// privkey's nonce — stable and unique per wallet; the old
    /// pointer-based key collapsed distinct keys via stack-slot
    /// reuse) and the output must be ordered by nonce.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn group_sources_groups_by_nonce_and_orders_by_it() {
        let flat = vec![
            (pk(2), utxo(300, 2)),
            (pk(0), utxo(100, 0)),
            (pk(2), utxo(350, 3)),
            (pk(1), utxo(200, 1)),
            (pk(0), utxo(150, 5)),
        ];
        let grouped = group_sources(flat);

        assert_eq!(grouped.len(), 3, "three distinct nonces → three sources");
        let nonces: Vec<u32> = grouped.iter().map(|s| s.privkey.nonce.get()).collect();
        assert_eq!(nonces, vec![0, 1, 2], "output ordered by nonce");

        assert_eq!(
            grouped[0]
                .unspent
                .iter()
                .map(|u| u.amount)
                .collect::<Vec<_>>(),
            vec![100, 150],
            "nonce-0 keeps its two UTXOs in arrival order"
        );
        assert_eq!(
            grouped[1]
                .unspent
                .iter()
                .map(|u| u.amount)
                .collect::<Vec<_>>(),
            vec![200]
        );
        assert_eq!(
            grouped[2]
                .unspent
                .iter()
                .map(|u| u.amount)
                .collect::<Vec<_>>(),
            vec![300, 350]
        );
    }

    /// Same key appearing again after other keys' entries must land
    /// in the SAME group (append arm across interleaving). This is
    /// the exact shape that used to collapse into wrong groups when
    /// keyed by a loop-local pointer.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn group_sources_same_nonce_never_splits_or_merges() {
        let flat = vec![
            (pk(5), utxo(10, 0)),
            (pk(9), utxo(20, 0)),
            (pk(5), utxo(11, 1)),
            (pk(7), utxo(30, 0)),
            (pk(5), utxo(12, 2)),
        ];
        let grouped = group_sources(flat);

        assert_eq!(grouped.len(), 3);
        assert_eq!(
            grouped
                .iter()
                .map(|s| s.privkey.nonce.get())
                .collect::<Vec<_>>(),
            vec![5, 7, 9]
        );
        let five = &grouped[0];
        assert_eq!(
            five.unspent.iter().map(|u| u.amount).collect::<Vec<_>>(),
            vec![10, 11, 12],
            "all three nonce-5 UTXOs land in one group, arrival order"
        );

        // No-data-loss invariant over the whole output.
        let total: u64 = grouped
            .iter()
            .flat_map(|s| s.unspent.iter())
            .map(|u| u.amount)
            .sum();
        assert_eq!(total, 10 + 20 + 11 + 30 + 12);
    }

    /// A single key with one UTXO (the `None` insert arm alone).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn group_sources_single_entry() {
        let k = pk(7);
        let grouped = group_sources(vec![(k, utxo(42, 3))]);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].unspent.len(), 1);
        assert_eq!(grouped[0].unspent[0].amount, 42);
        assert_eq!(grouped[0].unspent[0].vout, 3);
    }

    // --- run_interactive (in-process, stub selector) -------------------

    use super::run_interactive;
    use async_trait::async_trait;
    use yubtc_core::misc::{TAddress, TSatoshi};
    use yubtc_core::net::{NetError, NetworkBackend};
    use yubtc_core::wallet::AddressInfo;

    const PASSPHRASE: &str = "x";

    /// Backend fixture: the nonce-0 fixture address is used and holds
    /// exactly one deeply-confirmed 100_000-sat UTXO; every other
    /// address is unused and empty. The wallet scan then stops after
    /// nonce 1 and `collect_sources` sees a single source with a
    /// single UTXO. With `unspent_fails` set, `get_unspent` errors
    /// for every address — the wallet scan (which only uses
    /// `get_info`) still succeeds, so downstream `get_unspent`
    /// callers surface their error arms.
    struct SendFixtureBackend {
        funded: Option<(String, Vec<u8>)>,
        unspent_fails: bool,
    }

    impl SendFixtureBackend {
        fn funded(script: Vec<u8>) -> Self {
            Self {
                funded: Some((pk(0).get_p2pkh_address().as_str().to_string(), script)),
                unspent_fails: false,
            }
        }

        /// Every address unused and empty.
        fn unfunded() -> Self {
            Self {
                funded: None,
                unspent_fails: false,
            }
        }
    }

    #[async_trait]
    impl NetworkBackend for SendFixtureBackend {
        async fn get_unspent(&self, address: &TAddress) -> Result<Vec<Utxo>, NetError> {
            if self.unspent_fails {
                return Err(NetError::Http("mock: unspent down".to_string()));
            }
            match &self.funded {
                Some((funded, script)) if address.as_str() == funded => Ok(vec![Utxo {
                    txid: [0x11; 32],
                    vout: 0,
                    amount: 100_000,
                    script_pubkey: script.clone(),
                    confirmations: 100,
                }]),
                _ => Ok(vec![]),
            }
        }

        async fn get_info(&self, address: &TAddress) -> Result<AddressInfo, NetError> {
            let used = self
                .funded
                .as_ref()
                .is_some_and(|(funded, _)| funded == address.as_str());
            Ok(AddressInfo {
                total_received: u64::from(used) * 100_000,
                final_balance: u64::from(used) * 100_000,
                n_tx: u64::from(used),
            })
        }

        async fn broadcast(&self, _raw_tx: &[u8]) -> Result<(), NetError> {
            Ok(())
        }

        async fn raw_transaction(&self, _txid: &str) -> Result<String, NetError> {
            // The send flow never fetches raw transactions; a canned
            // minimal-valid answer keeps the trait total for tests.
            Ok("00".repeat(100))
        }

        fn name(&self) -> &'static str {
            "send-test-backend"
        }
    }

    /// The 25-byte P2PKH lock script of the fixture key at `nonce`
    /// (required: `build_vin` validates the UTXO script against the
    /// spender's pubkey hash).
    fn p2pkh_script(nonce: u32) -> Vec<u8> {
        use yubtc_core::address::hash160_pubkey;
        use yubtc_core::privkey::privkey_to_pubkey;
        use yubtc_core::script::make_p2pkh_lock_script;
        let pubkey = privkey_to_pubkey(&pk(nonce).privkey);
        make_p2pkh_lock_script(&hash160_pubkey(&pubkey)).to_vec()
    }

    /// Install the fixture backend, build the wallet the same way
    /// `run` does (scan + one extra address), and hand both to the
    /// caller. The caller must `reset_backend()` when done.
    /// `unspent_fails` flips `get_unspent` to a hard error (see
    /// [`SendFixtureBackend`]).
    async fn fixture_wallet_with(unspent_fails: bool) -> yubtc_core::wallet::Wallet {
        let backend = SendFixtureBackend {
            funded: Some((
                pk(0).get_p2pkh_address().as_str().to_string(),
                p2pkh_script(0),
            )),
            unspent_fails,
        };
        yubtc_core::wallet::Wallet::new(
            TSeed::new(SEED),
            TNonce::new(0),
            1,
            TPassphrase::new(PASSPHRASE),
            KdfAlgo::Pbkdf2,
            yubtc_core::wallet::AddrType::Legacy,
            std::sync::Arc::new(backend),
        )
        .await
        .expect("fixture wallet builds against the stub backend")
    }

    /// Default fixture: healthy backend.
    async fn fixture_wallet() -> yubtc_core::wallet::Wallet {
        fixture_wallet_with(false).await
    }

    /// Common `run_interactive` arguments: send 50_000 sat (of the
    /// 100_000 available) to a fixture address outside the wallet,
    /// fee via feekb, no broadcast (so `finish` never touches stdin
    /// or the network).
    fn interactive_dst_and_amount() -> (TAddress, Option<TSatoshi>) {
        (wallet_privkey_free_dst(), Some(TSatoshi::new(50_000)))
    }

    /// A destination that is not part of the fixture wallet (nonce 5),
    /// so the cashback/output split is exercised.
    fn wallet_privkey_free_dst() -> TAddress {
        pk(5).get_p2pkh_address()
    }

    /// Mask of `true`/`false` matching the flat UTXO count of `sources`.
    fn mask_for(sources: &[yubtc_core::wallet::Source], on: bool) -> Vec<bool> {
        let n: usize = sources.iter().map(|s| s.unspent.len()).sum();
        vec![on; n]
    }

    /// Selector stub that confirms every offered UTXO. Shared by the
    /// success test and the backend-failure test (where it is never
    /// reached) so its body stays covered.
    fn select_all(
        sources: Vec<yubtc_core::wallet::Source>,
        _t: Option<TSatoshi>,
        _f: TSatoshi,
        _fk: TSatoshi,
        _c: Option<TAddress>,
    ) -> std::io::Result<Option<Vec<bool>>> {
        Ok(Some(mask_for(&sources, true)))
    }

    /// Full selection: `Ok(Some(all-true mask))` → tx built, signed,
    /// printed, not broadcast → `Ok(())`.
    #[ntest_timeout::timeout(15000)]
    #[test]
    fn run_interactive_builds_tx_from_selection() {
        block_on(async {
            let wallet = fixture_wallet().await;
            let (dst, amount) = interactive_dst_and_amount();
            let result = run_interactive(
                wallet,
                dst,
                amount,
                TSatoshi::ZERO,
                TSatoshi::new(1000),
                1,
                false,
                false,
                &select_all,
            )
            .await;
            result.expect("selection → build → print succeeds");
        });
    }

    /// `Ok(None)` from the selector → the "Cancelled" early return.
    #[ntest_timeout::timeout(15000)]
    #[test]
    fn run_interactive_cancelled_is_ok() {
        block_on(async {
            let wallet = fixture_wallet().await;
            let (dst, amount) = interactive_dst_and_amount();
            let result = run_interactive(
                wallet,
                dst,
                amount,
                TSatoshi::ZERO,
                TSatoshi::new(1000),
                1,
                false,
                false,
                &|_s, _t, _f, _fk, _c| Ok(None),
            )
            .await;
            result.expect("cancelled selection is not an error");
        });
    }

    /// All-false mask → empty selection → `CliError::Usage("no inputs
    /// selected")`.
    #[ntest_timeout::timeout(15000)]
    #[test]
    fn run_interactive_empty_selection_is_usage_error() {
        block_on(async {
            let wallet = fixture_wallet().await;
            let (dst, amount) = interactive_dst_and_amount();
            let err = run_interactive(
                wallet,
                dst,
                amount,
                TSatoshi::ZERO,
                TSatoshi::new(1000),
                1,
                false,
                false,
                &|sources, _t, _f, _fk, _c| Ok(Some(mask_for(&sources, false))),
            )
            .await
            .expect_err("empty selection must be rejected");
            // Display-based variant + payload pin — a `matches!` guard
            // leaves an always-unexecuted branch edge.
            assert_eq!(err.to_string(), "no inputs selected");
        });
    }

    /// A hard-set fee larger than the selected input: the pre-UI
    /// check passes (it only compares the target against the total),
    /// but `make_transaction`'s `make_vout` rejects the combination
    /// (`InputDoesNotCoverFee`) → the `make_transaction` error arm of
    /// `run_interactive` → `CliError::Wallet`.
    #[ntest_timeout::timeout(15000)]
    #[test]
    fn run_interactive_fee_exceeds_input_is_wallet_error() {
        block_on(async {
            let wallet = fixture_wallet().await;
            let (dst, _amount) = interactive_dst_and_amount();
            let err = run_interactive(
                wallet,
                dst,
                Some(TSatoshi::new(1)),
                TSatoshi::new(200_000),
                TSatoshi::new(1000),
                1,
                false,
                false,
                &select_all,
            )
            .await
            .expect_err("fee above the selected input must fail");
            assert!(
                err.to_string().contains("input does not cover fee"),
                "got: {err}"
            );
        });
    }

    /// Selector I/O failure → `CliError::Stdin`.
    #[ntest_timeout::timeout(15000)]
    #[test]
    fn run_interactive_selector_error_is_stdin_error() {
        block_on(async {
            let wallet = fixture_wallet().await;
            let (dst, amount) = interactive_dst_and_amount();
            let err = run_interactive(
                wallet,
                dst,
                amount,
                TSatoshi::ZERO,
                TSatoshi::new(1000),
                1,
                false,
                false,
                &|_s, _t, _f, _fk, _c| Err(std::io::Error::other("tty gone")),
            )
            .await
            .expect_err("selector failure must propagate");
            // Display-based variant pin — see the note above.
            assert_eq!(err.to_string(), "stdin: tty gone");
        });
    }

    /// One-shot runtime for the sync test fns above.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime builds")
            .block_on(fut)
    }

    /// Drive the fixture backend's remaining trait surface
    /// (`broadcast`, `name`, and the unfunded `get_unspent` arm) so
    /// the test helper itself stays fully covered — the
    /// `run_interactive` flow only ever calls `get_info` and the
    /// funded `get_unspent` arm.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn send_fixture_backend_implements_full_trait_surface() {
        use yubtc_core::net::NetworkBackend as _;

        let backend = SendFixtureBackend::funded(p2pkh_script(0));
        block_on(async {
            backend
                .broadcast(b"tx")
                .await
                .expect("fixture broadcast succeeds");
            let unspent = backend
                .get_unspent(&TAddress::new("not-a-funded-address"))
                .await
                .expect("unfunded get_unspent succeeds");
            assert!(unspent.is_empty());
            let raw = backend
                .raw_transaction(&"ab".repeat(32))
                .await
                .expect("fixture raw_transaction succeeds");
            assert_eq!(raw.len(), 200);
        });
        assert_eq!(backend.name(), "send-test-backend");
    }

    /// `get_unspent` failing during `collect_sources` (inside
    /// `run_interactive`) → `CliError::Network`; the selector is
    /// never reached.
    #[ntest_timeout::timeout(15000)]
    #[test]
    fn run_interactive_unspent_failure_is_network_error() {
        block_on(async {
            let wallet = fixture_wallet_with(true).await;
            let (dst, amount) = interactive_dst_and_amount();
            let err = run_interactive(
                wallet,
                dst,
                amount,
                TSatoshi::ZERO,
                TSatoshi::new(1000),
                1,
                false,
                false,
                &select_all,
            )
            .await
            .expect_err("unspent failure must propagate");
            assert!(err.to_string().contains("mock: unspent down"), "got: {err}");
        });
    }

    /// `get_unspent` failing inside `print_scan_report` (the
    /// `--scan` path of `run`) → `CliError::Network`.
    #[ntest_timeout::timeout(15000)]
    #[test]
    fn print_scan_report_unspent_failure_is_network_error() {
        block_on(async {
            let wallet = fixture_wallet_with(true).await;
            let err = super::print_scan_report(&wallet, 1)
                .await
                .expect_err("scan report must fail when the backend is down");
            assert!(err.to_string().contains("mock: unspent down"), "got: {err}");
        });
    }

    /// No funded addresses → `collect_sources` yields nothing → the
    /// "No funds available" early return (`Ok(())`).
    #[ntest_timeout::timeout(15000)]
    #[test]
    fn run_interactive_no_funds_is_ok() {
        block_on(async {
            let wallet = yubtc_core::wallet::Wallet::new(
                TSeed::new(SEED),
                TNonce::new(0),
                1,
                TPassphrase::new(PASSPHRASE),
                KdfAlgo::Pbkdf2,
                yubtc_core::wallet::AddrType::Legacy,
                std::sync::Arc::new(SendFixtureBackend::unfunded()),
            )
            .await
            .expect("unfunded wallet still constructs");
            let (dst, amount) = interactive_dst_and_amount();
            let result = run_interactive(
                wallet,
                dst,
                amount,
                TSatoshi::ZERO,
                TSatoshi::new(1000),
                1,
                false,
                false,
                &select_all,
            )
            .await;
            result.expect("no funds is not an error");
        });
    }

    /// Target above the available total → the pre-UI usage error
    /// (`insufficient funds: target … sat, available … sat`).
    #[ntest_timeout::timeout(15000)]
    #[test]
    fn run_interactive_insufficient_target_is_usage_error() {
        block_on(async {
            let wallet = fixture_wallet().await;
            let (dst, _amount) = interactive_dst_and_amount();
            let err = run_interactive(
                wallet,
                dst,
                Some(TSatoshi::new(150_000)),
                TSatoshi::ZERO,
                TSatoshi::new(1000),
                1,
                false,
                false,
                &select_all,
            )
            .await
            .expect_err("target above total must be rejected");
            assert!(
                err.to_string()
                    .contains("insufficient funds: target 150000 sat, available 100000 sat"),
                "got: {err}"
            );
        });
    }

    /// Drain mode (`amount_sat = None`) skips the target check (the
    /// `if let Some(target)` false edge) and proceeds to selection.
    #[ntest_timeout::timeout(15000)]
    #[test]
    fn run_interactive_drain_skips_target_check() {
        block_on(async {
            let wallet = fixture_wallet().await;
            let (dst, _amount) = interactive_dst_and_amount();
            let result = run_interactive(
                wallet,
                dst,
                None,
                TSatoshi::ZERO,
                TSatoshi::new(1000),
                1,
                false,
                false,
                &|_s, _t, _f, _fk, _c| Ok(None),
            )
            .await;
            result.expect("drain with cancelled selection is Ok");
        });
    }
}
