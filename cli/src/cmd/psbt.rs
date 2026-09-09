//! `yubtc psbt` — BIP-174 subcommand group (Phase 14, spec ОВ-6).
//!
//! Six stdin→stdout filters around [`yubtc_core::psbt`]:
//!
//! - `create ADDR AMOUNT` — Creator (+Updater): the `send` build path
//!   (scan → selector → fee loop, including the `-i` Coin Control TUI)
//!   without the signing step; the built transaction is stripped back
//!   to its unsigned form and every input gains its UTXO field
//!   (`WITNESS_UTXO` for witness forms, `NON_WITNESS_UTXO` fetched via
//!   `NetworkBackend::raw_transaction` for legacy P2PKH). The only
//!   online subcommand.
//! - `sign` — Signer: fully offline; prompts seed + passphrase
//!   (stdin lines 1–2, PSBT on line 3), walks nonces
//!   `0..PSBT_SIGN_MAX_NONCE` × 3 address forms (ОВ-9) and adds
//!   `PARTIAL_SIG`s for own inputs (BIP-174 MUST: everything else is
//!   carried through untouched; unsigned inputs are reported on
//!   stderr, never fatal).
//! - `combine` — Combiner: merges one base64 PSBT per stdin line
//!   left-to-right; conflicting values fail deterministically.
//! - `finalize` — Finalizer: converts complete `PARTIAL_SIG`s into
//!   final scriptSig / witness fields, per input.
//! - `extract` — Extractor: the signed wire-format tx as hex —
//!   pipeable into `yubtc pushtx`.
//! - `decode` — human-readable JSON dump (yubtc extension, not a
//!   BIP-174 role) incl. the fee when UTXO data is complete.
//!
//! Stdout carries exactly one payload line per command (base64 /
//! hex / JSON); diagnostics (unsigned-input list, fee sanity) go to
//! stderr so shell pipes stay byte-clean.

use std::io::{self, BufRead, Read};

use crate::cli::{KdfName, PsbtCommand, PsbtCreateArgs, PsbtSignArgs};
use crate::error::CliError;
use crate::prompt::{
    prompt_seed_stderr, read_seed_and_passphrase, stdin_err, validate_entered_seed,
};
use yubtc_core::misc::{TAddress, TNonce, TSatoshi};
use yubtc_core::net;
use yubtc_core::psbt::{CreateInput, PartiallySignedTransaction};
use yubtc_core::transaction::{Transaction, TxIn};
use yubtc_core::wallet::{self, Source};
use yubtc_core::PSBT_SIGN_MAX_NONCE;

use super::address::resolve_kdf;
use super::send::{self, BuiltTx};
use super::tui;

/// Dispatch a parsed `psbt` subcommand.
pub async fn run(cmd: PsbtCommand) -> Result<(), CliError> {
    match cmd {
        PsbtCommand::Create(args) => create(args).await,
        PsbtCommand::Sign(args) => sign(args),
        PsbtCommand::Combine => combine(),
        PsbtCommand::Finalize => finalize(),
        PsbtCommand::Extract => extract(),
        PsbtCommand::Decode => decode(),
    }
}

// --- create ----------------------------------------------------------

/// `psbt create` — Creator (+Updater). Mirrors the `send` flow up to
/// and including `make_transaction`, then strips the signatures and
/// wraps the unsigned transaction (with UTXO fields) in a PSBT. Both
/// flows call the same scan, the same selector and the same fee loop
/// with the same arguments, so
/// `psbt create | psbt sign | psbt finalize | psbt extract` reproduces
/// `send`'s raw tx byte-for-byte (pinned by the CLI integration test).
async fn create(args: PsbtCreateArgs) -> Result<(), CliError> {
    // The documented Phase-13 recipient policy (v0.3: P2WSH lock
    // scripts are unlocked in the core for the multisig quorum
    // surface only — personal psbt creates keep the typed refusal).
    // Checked first: the address is a pure argument, no I/O needed.
    super::reject_p2wsh_recipient(&TAddress::new(args.address.clone()))?;
    // The seed prompt goes to stderr: stdout carries exactly one
    // payload line (the base64 PSBT) per the filter contract.
    prompt_seed_stderr()?;
    let (seed, passphrase) = read_seed_and_passphrase()?;
    // Reception-time seed policy (permissive default / opt-in strict
    // BIP-39 + the non-blocking entropy warning), before any KDF work
    // (specs/spec.md «Seed policy», R-1…R-6).
    validate_entered_seed(&seed, args.seed_policy.strict_bip39)?;
    // No `--kdf` on the psbt surface (spec ОВ-6 grammar): the legacy
    // `auto` heuristic picks the algorithm.
    let kdf = resolve_kdf(KdfName::Auto, &passphrase);
    let addr_type = args.addr_type.addr_type.to_core();

    // Backend injection: resolve once, thread explicitly.
    let backend =
        net::get_backend_with_retries(args.provider.provider.as_str(), args.provider.retries)?;

    let wallet = yubtc_core::wallet::Wallet::new(
        seed.clone(),
        TNonce::new(args.nonce),
        1,
        passphrase.clone(),
        kdf,
        addr_type,
        backend,
    )
    .await?;

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

    // Coin Control: pick UTXOs in the TUI, then stop at the unsigned
    // PSBT («Экспорт unsigned PSBT после Coin Control», spec).
    if args.interactive {
        let backend = wallet.backend().clone();
        let built = send::select_and_build(
            &wallet,
            dst,
            amount_sat,
            fee_sat,
            feekb_sat,
            args.confirmations,
            &tui::run_selection,
        )
        .await?;
        return present_built(backend.as_ref(), built).await;
    }

    // Non-interactive path: lazy scan to gap-limit (or until the
    // target is met) — identical to `send`'s non-interactive flow.
    let target_sat = match (amount_sat, fee_sat.get()) {
        (Some(amt), fee) => Some(TSatoshi::new(amt.get() + fee)),
        // Drain mode: target = u64::MAX so we never early-terminate
        // on target-met, only on gap-limit.
        (None, _) => Some(TSatoshi::new(u64::MAX)),
    };
    let (sources, cashback_addr) = wallet::scan_inputs_until(
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
            Some(sources.clone()),
            Some(cashback_addr),
        )
        .await?;

    let unsigned = create_psbt_from_built(wallet.backend().as_ref(), &tx.tx, &sources).await?;
    println!("{}", unsigned.to_base64());
    Ok(())
}

/// Creator core: from the built-and-signed transaction and the sources
/// that funded it, produce the unsigned PSBT.
///
/// The signed transaction is stripped back to its unsigned form (empty
/// `scriptSig` and witness stacks — BIP-174's `UNSIGNED_TX` mandate),
/// and one UTXO field per input is written: `WITNESS_UTXO` from the
/// scan metadata for witness-form inputs, `NON_WITNESS_UTXO` from
/// `NetworkBackend::raw_transaction` for legacy (P2PKH) inputs. The
/// vin↔UTXO pairing relies on `make_transaction` → `build_vin`
/// emitting exactly one `vin` entry per funding UTXO, in the same
/// (source, unspent) order as the flattened `sources`.
async fn create_psbt_from_built(
    backend: &dyn net::NetworkBackend,
    signed: &Transaction,
    sources: &[Source],
) -> Result<PartiallySignedTransaction, CliError> {
    let utxos: Vec<&wallet::Utxo> = sources.iter().flat_map(|s| s.unspent.iter()).collect();
    if utxos.len() != signed.vin.len() {
        return Err(CliError::Wallet(format!(
            "internal: {} vin entries but {} funding UTXOs",
            signed.vin.len(),
            utxos.len()
        )));
    }
    let unsigned = Transaction {
        version: signed.version,
        vin: signed
            .vin
            .iter()
            .map(|vin| TxIn {
                script: Vec::new(),
                witness: Vec::new(),
                ..vin.clone()
            })
            .collect(),
        vout: signed.vout.clone(),
        locktime: signed.locktime,
    };
    let mut inputs = Vec::with_capacity(utxos.len());
    for (vin, u) in signed.vin.iter().zip(utxos) {
        // The Creator writes exactly one UTXO field per form: the full
        // prev-tx for legacy inputs, the spent output for witness forms.
        let prev_tx = if yubtc_core::script::extract_p2pkh_hash(&u.script_pubkey).is_ok() {
            let txid_hex = hex::encode(vin.txhash);
            let raw_hex = backend.raw_transaction(&txid_hex).await?;
            let raw = hex::decode(raw_hex.trim())
                .map_err(|e| CliError::Network(format!("raw tx {txid_hex}: bad hex: {e}")))?;
            Some(
                yubtc_core::psbt::parse_wire_tx(&raw)
                    .map_err(|e| CliError::Network(format!("raw tx {txid_hex}: {e}")))?,
            )
        } else {
            None
        };
        inputs.push(CreateInput {
            amount: u.amount,
            script_pubkey: u.script_pubkey.clone(),
            prev_tx,
            redeem_script: None,
            witness_script: None,
            tap_leaf_script: None,
        });
    }
    Ok(PartiallySignedTransaction::create(unsigned, inputs)?)
}

/// Present the outcome of the shared interactive selection:
/// `NoFunds` / `Cancelled` print the same friendly lines as `send -i`
/// (exit 0 — nothing went wrong); `Built` stops at the unsigned PSBT
/// (the `-i` exit point is one step before `send`'s, spec ОВ-6).
///
/// Split out of [`create`] so the arms stay coverage-measurable —
/// the production TUI cannot run headless, but this helper takes the
/// same [`BuiltTx`] values directly (unit tests below).
async fn present_built(backend: &dyn net::NetworkBackend, built: BuiltTx) -> Result<(), CliError> {
    match built {
        BuiltTx::NoFunds => {
            println!("No funds available");
            Ok(())
        }
        BuiltTx::Cancelled => {
            println!("Cancelled");
            Ok(())
        }
        BuiltTx::Built { tx, sources } => {
            let unsigned = create_psbt_from_built(backend, &tx, &sources).await?;
            println!("{}", unsigned.to_base64());
            Ok(())
        }
    }
}

// --- sign ------------------------------------------------------------

/// `psbt sign` — offline Signer. stdin: seed, passphrase, PSBT
/// (three lines; the passphrase follows the Python CLI pipe
/// convention, the PSBT is read after the prompt helpers release the
/// stdin lock). On a TTY the passphrase is read with `rpassword`.
fn sign(args: PsbtSignArgs) -> Result<(), CliError> {
    // The seed prompt goes to stderr: stdout carries exactly one
    // payload line (the base64 PSBT) per the filter contract.
    prompt_seed_stderr()?;
    let (seed, passphrase) = read_seed_and_passphrase()?;
    validate_entered_seed(&seed, args.seed_policy.strict_bip39)?;
    // No `--kdf` on the psbt surface (spec ОВ-6 grammar): `auto`.
    let kdf = resolve_kdf(KdfName::Auto, &passphrase);

    let line = read_psbt_line()?;
    let mut unsigned_psbt = parse_psbt_line(&line)?;

    // Bounded offline walk (ОВ-9): inputs keyed beyond the nonce bound
    // (or foreign inputs) stay unsigned — reported, not fatal.
    let unsigned_inputs = wallet::sign_psbt_with(&seed, &passphrase, kdf, &mut unsigned_psbt)?;
    for i in &unsigned_inputs {
        eprintln!(
            "warning: input {i} not signed (foreign input, no UTXO data, or nonce beyond the {PSBT_SIGN_MAX_NONCE}-nonce walk bound)"
        );
    }
    report_fee(&unsigned_psbt);
    println!("{}", unsigned_psbt.to_base64());
    Ok(())
}

/// The fee-sanity line (spec: `psbt sign` displays the fee when every
/// input carries UTXO data; missing data is a warning, not an error —
/// the Signer must work on PSBT data alone).
pub(crate) fn fee_line(fee_sat: Option<u64>) -> String {
    match fee_sat {
        Some(fee) => format!("fee: {fee} sat"),
        None => "warning: fee unavailable (some inputs lack UTXO data)".to_string(),
    }
}

/// Print [`fee_line`] to stderr (stdout stays machine-readable).
fn report_fee(psbt: &PartiallySignedTransaction) {
    eprintln!("{}", fee_line(psbt.summary().fee_sat));
}

// --- combine / finalize / extract / decode ---------------------------

/// `psbt combine` — Combiner. Reads one base64 PSBT per stdin line
/// (blank lines ignored; at least two required) and merges
/// left-to-right. Conflicts fail deterministically
/// ([`PsbtError::ConflictingField`]) per the spec — no arbitrary pick.
fn combine() -> Result<(), CliError> {
    let mut buffer = String::new();
    io::stdin()
        .lock()
        .read_to_string(&mut buffer)
        .map_err(stdin_err)?;
    let mut acc: Option<PartiallySignedTransaction> = None;
    let mut count = 0usize;
    for line in buffer.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed = parse_psbt_line(line)?;
        acc = Some(match acc {
            None => parsed,
            Some(prev) => prev.combine(&parsed)?,
        });
        count += 1;
    }
    if count < 2 {
        return Err(CliError::Usage(
            "psbt combine needs at least two PSBTs on stdin (one per line)".to_string(),
        ));
    }
    println!(
        "{}",
        acc.expect("count >= 2 implies at least one parsed PSBT")
            .to_base64()
    );
    Ok(())
}

/// `psbt finalize` — Finalizer: per-input conversion of complete
/// `PARTIAL_SIG`s into the final fields; incomplete inputs stay
/// untouched (extraction enforces completeness).
fn finalize() -> Result<(), CliError> {
    let mut psbt = parse_psbt_line(&read_psbt_line()?)?;
    psbt.finalize();
    println!("{}", psbt.to_base64());
    Ok(())
}

/// `psbt extract` — Extractor: the completed transaction in wire
/// format (BIP-144), hex on stdout — the exact payload `yubtc pushtx`
/// consumes on stdin.
fn extract() -> Result<(), CliError> {
    let psbt = parse_psbt_line(&read_psbt_line()?)?;
    let tx = psbt.extract_transaction()?;
    println!("{}", hex::encode(tx.serialize_wire()));
    Ok(())
}

/// `psbt decode` — human-readable dump as pretty-printed JSON (the
/// [`yubtc_core::psbt::PsbtSummary`] shape; not a BIP-174 role).
/// `fee_sat` is `null` when some input lacks UTXO data (spec: a
/// warning situation, not an error).
fn decode() -> Result<(), CliError> {
    let psbt = parse_psbt_line(&read_psbt_line()?)?;
    let summary = psbt.summary();
    // A summary carries strings/integers/booleans/Option only — no
    // non-string map keys — so serialization is infallible by
    // construction.
    println!(
        "{}",
        serde_json::to_string_pretty(&summary)
            .expect("invariant: PsbtSummary always serializes to JSON")
    );
    Ok(())
}

// --- stdin plumbing --------------------------------------------------

/// Read one base64 PSBT line from stdin. Empty input (EOF, blank
/// line) is the usage error — every filter expects exactly one PSBT.
fn read_psbt_line() -> Result<String, CliError> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut line = String::new();
    handle.read_line(&mut line).map_err(stdin_err)?;
    let line = line.trim().to_string();
    if line.is_empty() {
        return Err(CliError::Usage("no PSBT on stdin".to_string()));
    }
    Ok(line)
}

/// Decode one base64 PSBT line. Transport-level base64 breakage gets
/// the friendlier usage message; structural PSBT errors keep the
/// typed `PsbtError` rendering (exit code 1 either way).
fn parse_psbt_line(line: &str) -> Result<PartiallySignedTransaction, CliError> {
    let bytes = yubtc_core::psbt::decode_base64(line)
        .map_err(|_| CliError::Usage("invalid base64 PSBT on stdin".to_string()))?;
    PartiallySignedTransaction::parse(&bytes).map_err(CliError::Psbt)
}

#[cfg(test)]
mod tests {
    //! Unit tests for the Creator core ([`create_psbt_from_built`])
    //! and the fee-sanity line. The Creator tests drive an in-memory
    //! backend (no network, no global state), so they run fully
    //! parallel; the stdin-level behaviour is covered by the
    //! `cmd_psbt` subprocess tests.

    use super::send::BuiltTx;
    use super::{create_psbt_from_built, fee_line, present_built};
    use crate::error::CliError;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use yubtc_core::kdf::KdfAlgo;
    use yubtc_core::misc::{TAddress, TNonce, TPassphrase, TSeed};
    use yubtc_core::net::{NetError, NetworkBackend};
    use yubtc_core::psbt::PartiallySignedTransaction;
    use yubtc_core::transaction::{Transaction, TxIn, TxOut};
    use yubtc_core::wallet::{AddrType, Source, TPrivKey, Utxo};

    // BIP-39 test vector #2 — 9 distinct words of 12 passes the C6
    // entropy floor.
    const SEED: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const PASSPHRASE: &str = "x";

    fn pk(nonce: u32, form: AddrType) -> TPrivKey {
        TPrivKey::with_addr_type(
            &TSeed::new(SEED),
            TNonce::new(nonce),
            &TPassphrase::new(PASSPHRASE),
            KdfAlgo::Pbkdf2,
            form,
        )
        .expect("fixture derivation is deterministic")
    }

    /// Lock script of `key` in its own form.
    fn lock_script(key: &TPrivKey, form: AddrType) -> Vec<u8> {
        use yubtc_core::privkey::privkey_to_pubkey;
        let pubkey = privkey_to_pubkey(&key.privkey);
        match form {
            AddrType::Legacy => yubtc_core::script::make_p2pkh_lock_script(
                &yubtc_core::address::hash160_pubkey(&pubkey),
            ),
            AddrType::Native => yubtc_core::script::make_p2wpkh_lock_script(
                &yubtc_core::address::hash160_pubkey(&pubkey),
            )
            .to_vec(),
            AddrType::Taproot => {
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&pubkey[1..33]);
                let output = yubtc_core::address::taproot_output_key(&xonly)
                    .expect("fixture key is a valid curve point");
                yubtc_core::script::make_p2tr_lock_script(&output).to_vec()
            }
        }
    }

    /// A synthetic previous transaction paying `amount` to `script`
    /// from the all-`0xaa` prevout — enough for the Creator's
    /// `NON_WITNESS_UTXO` (its txid must match the spending vin).
    fn prev_tx(amount: u64, script: Vec<u8>) -> Transaction {
        Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0xaa; 32],
                n: 0,
                script: Vec::new(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut { amount, script }],
            locktime: 0,
        }
    }

    /// A "signed" transaction spending `prev` (legacy) and a
    /// witness-form output: the Creator's input. The script/witness
    /// fields carry marker bytes so the test can verify the Creator
    /// strips them.
    fn signed_tx(prev: &Transaction, witness_script: Vec<u8>) -> Transaction {
        let mut vin = vec![TxIn {
            txhash: prev.id(),
            n: 0,
            script: vec![0x47; 71], // fake scriptSig
            sequence: 0xffff_fffe,
            witness: Vec::new(),
        }];
        vin.push(TxIn {
            txhash: [0xbb; 32],
            n: 1,
            script: Vec::new(),
            sequence: 0xffff_fffe,
            witness: vec![vec![0x30; 71], vec![0x21; 33]],
        });
        Transaction {
            version: 2,
            vin,
            vout: vec![TxOut {
                amount: 50_000,
                script: witness_script,
            }],
            locktime: 0,
        }
    }

    /// A single-input "signed" transaction spending only `prev`
    /// (legacy form) — the one-vin fixture for the raw-tx failure
    /// tests (1 vin entry ↔ 1 funding UTXO).
    fn signed_tx_1(prev: &Transaction, out_script: Vec<u8>) -> Transaction {
        Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: prev.id(),
                n: 0,
                script: vec![0x47; 71], // fake scriptSig
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 50_000,
                script: out_script,
            }],
            locktime: 0,
        }
    }

    /// In-memory backend serving canned `raw_transaction` payloads.
    struct RawTxBackend {
        raw_transactions: Mutex<std::collections::HashMap<String, String>>,
    }

    impl RawTxBackend {
        fn with(prev: &Transaction) -> Self {
            let mut map = std::collections::HashMap::new();
            map.insert(hex::encode(prev.id()), hex::encode(prev.serialize_wire()));
            Self {
                raw_transactions: Mutex::new(map),
            }
        }
    }

    #[async_trait]
    impl NetworkBackend for RawTxBackend {
        async fn get_unspent(&self, _address: &TAddress) -> Result<Vec<Utxo>, NetError> {
            Err(NetError::Http("mock: not used here".to_string()))
        }

        async fn get_info(
            &self,
            _address: &TAddress,
        ) -> Result<yubtc_core::wallet::AddressInfo, NetError> {
            Err(NetError::Http("mock: not used here".to_string()))
        }

        async fn broadcast(&self, _raw_tx: &[u8]) -> Result<(), NetError> {
            Err(NetError::Http("mock: not used here".to_string()))
        }

        async fn raw_transaction(&self, txid: &str) -> Result<String, NetError> {
            self.raw_transactions
                .lock()
                .expect("raw map lock")
                .get(txid)
                .cloned()
                .ok_or_else(|| NetError::BadResponse(format!("no raw tx for {txid}")))
        }

        fn name(&self) -> &'static str {
            "psbt-test-backend"
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_strips_signatures_and_fills_utxo_fields() {
        let legacy_key = pk(0, AddrType::Legacy);
        let native_key = pk(0, AddrType::Native);
        let prev = prev_tx(60_000, lock_script(&legacy_key, AddrType::Legacy));
        let signed = signed_tx(&prev, lock_script(&native_key, AddrType::Native));
        let backend = RawTxBackend::with(&prev);

        let sources = vec![
            Source {
                privkey: legacy_key,
                unspent: vec![Utxo {
                    txid: prev.id(),
                    vout: 0,
                    amount: 60_000,
                    script_pubkey: lock_script(&pk(0, AddrType::Legacy), AddrType::Legacy),
                    confirmations: 100,
                }],
            },
            Source {
                privkey: native_key,
                unspent: vec![Utxo {
                    txid: [0xbb; 32],
                    vout: 1,
                    amount: 80_000,
                    script_pubkey: lock_script(&pk(0, AddrType::Native), AddrType::Native),
                    confirmations: 100,
                }],
            },
        ];

        let psbt = block_on(create_psbt_from_built(&backend, &signed, &sources))
            .expect("Creator succeeds against the canned backend");

        // Signatures stripped: unsigned tx is truly unsigned.
        assert!(psbt.unsigned_tx.vin.iter().all(|i| i.script.is_empty()));
        assert!(psbt.unsigned_tx.vin.iter().all(|i| i.witness.is_empty()));
        assert_eq!(psbt.unsigned_tx.vout.len(), 1);
        assert_eq!(psbt.unsigned_tx.vout[0].amount, 50_000);

        // Legacy input carries NON_WITNESS_UTXO; witness input carries
        // WITNESS_UTXO with the scanned amount.
        assert!(psbt.inputs[0].non_witness_utxo.is_some());
        assert!(psbt.inputs[0].witness_utxo.is_none());
        let witness_utxo = psbt.inputs[1].witness_utxo.as_ref().expect("witness field");
        assert_eq!(witness_utxo.amount, 80_000);
        assert!(psbt.inputs[1].non_witness_utxo.is_none());

        // The wire round trip is stable: serialize → parse →
        // serialize is the canonical form, and the base64 transport
        // decodes back to the same PSBT.
        let canonical = psbt.serialize();
        let reparsed = PartiallySignedTransaction::parse(&canonical).expect("canonical parse");
        assert_eq!(reparsed.serialize(), canonical);
        assert_eq!(
            PartiallySignedTransaction::from_base64(&psbt.to_base64()).expect("base64 round trip"),
            psbt
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_rejects_vin_utxo_count_mismatch() {
        let legacy_key = pk(1, AddrType::Legacy);
        let prev = prev_tx(60_000, lock_script(&legacy_key, AddrType::Legacy));
        let signed = signed_tx(&prev, vec![0x51]);
        // One vin entry, but no funding UTXOs at all.
        let err = block_on(create_psbt_from_built(
            &RawTxBackend::with(&prev),
            &signed,
            &[],
        ))
        .expect_err("mismatched sources must be rejected");
        assert!(
            err.to_string()
                .contains("2 vin entries but 0 funding UTXOs"),
            "got: {err}"
        );
        assert!(matches!(err, CliError::Wallet(_)));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_surfaces_raw_tx_fetch_failure() {
        let legacy_key = pk(2, AddrType::Legacy);
        let prev = prev_tx(60_000, lock_script(&legacy_key, AddrType::Legacy));
        let signed = signed_tx_1(&prev, vec![0x51]);
        // The backend has no canned raw tx → BadResponse → Network.
        let empty = RawTxBackend {
            raw_transactions: Mutex::new(std::collections::HashMap::new()),
        };
        let sources = vec![Source {
            privkey: legacy_key,
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 60_000,
                script_pubkey: lock_script(&pk(2, AddrType::Legacy), AddrType::Legacy),
                confirmations: 100,
            }],
        }];
        let err = block_on(create_psbt_from_built(&empty, &signed, &sources))
            .expect_err("missing raw tx must surface");
        assert!(matches!(err, CliError::Network(_)), "got: {err}");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_surfaces_raw_tx_decode_failure() {
        // A raw-tx payload that is valid hex but not a valid
        // transaction must surface as a Network error naming the txid.
        let legacy_key = pk(3, AddrType::Legacy);
        let prev = prev_tx(60_000, lock_script(&legacy_key, AddrType::Legacy));
        let signed = signed_tx_1(&prev, vec![0x51]);
        let backend = RawTxBackend {
            raw_transactions: Mutex::new(std::collections::HashMap::from([(
                hex::encode(prev.id()),
                "deadbeef".to_string(),
            )])),
        };
        let sources = vec![Source {
            privkey: legacy_key,
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 60_000,
                script_pubkey: lock_script(&pk(3, AddrType::Legacy), AddrType::Legacy),
                confirmations: 100,
            }],
        }];
        let err = block_on(create_psbt_from_built(&backend, &signed, &sources))
            .expect_err("garbage raw tx must surface");
        assert!(matches!(err, CliError::Network(_)), "got: {err}");
        assert!(err.to_string().contains("raw tx"), "got: {err}");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn lock_script_covers_all_three_forms() {
        // The legacy and native arms are pinned via the Creator tests;
        // the taproot arm produces the 34-byte P2TR witness program
        // `51 20 <32-byte output key>`.
        let script = lock_script(&pk(5, AddrType::Taproot), AddrType::Taproot);
        assert_eq!(script.len(), 34);
        assert_eq!(&script[..2], &[0x51, 0x20]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn raw_tx_backend_unused_trait_methods_error_and_name_pins() {
        // The in-memory Creator backend only serves `raw_transaction`;
        // its other trait methods are total error stubs (never hit by
        // the Creator). Drive them so the stub bodies stay measured,
        // and pin `name`.
        let backend = RawTxBackend {
            raw_transactions: Mutex::new(std::collections::HashMap::new()),
        };
        block_on(async {
            let addr = TAddress::new("bc1qexample");
            let err = backend.get_unspent(&addr).await.expect_err("stub errors");
            assert!(matches!(err, NetError::Http(_)));
            let err = backend.get_info(&addr).await.expect_err("stub errors");
            assert!(matches!(err, NetError::Http(_)));
            let err = backend.broadcast(&[0x01]).await.expect_err("stub errors");
            assert!(matches!(err, NetError::Http(_)));
        });
        assert_eq!(NetworkBackend::name(&backend), "psbt-test-backend");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn fee_line_pins_both_arms() {
        assert_eq!(fee_line(Some(1234)), "fee: 1234 sat");
        assert_eq!(
            fee_line(None),
            "warning: fee unavailable (some inputs lack UTXO data)"
        );
    }

    // --- present_built (interactive outcome presentation) ------------
    //
    // The production TUI cannot run headless, so the match arms are
    // driven through the helper with the same BuiltTx values the
    // selector produces.

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn present_built_nofunds_and_cancelled_are_ok() {
        let backend = RawTxBackend {
            raw_transactions: Mutex::new(std::collections::HashMap::new()),
        };
        block_on(present_built(&backend, BuiltTx::NoFunds)).expect("NoFunds is Ok(())");
        block_on(present_built(&backend, BuiltTx::Cancelled)).expect("Cancelled is Ok(())");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn present_built_emits_psbt_for_built_tx() {
        let legacy_key = pk(4, AddrType::Legacy);
        let prev = prev_tx(60_000, lock_script(&legacy_key, AddrType::Legacy));
        let signed = signed_tx_1(&prev, vec![0x51]);
        let backend = RawTxBackend::with(&prev);
        let sources = vec![Source {
            privkey: legacy_key,
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 60_000,
                script_pubkey: lock_script(&pk(4, AddrType::Legacy), AddrType::Legacy),
                confirmations: 100,
            }],
        }];
        block_on(present_built(
            &backend,
            BuiltTx::Built {
                tx: signed,
                sources,
            },
        ))
        .expect("Built outcome produces the unsigned PSBT");
        // present_built returns Ok — the base64 went to stdout. The
        // Creator core is pinned in detail by the
        // creator_strips_signatures_and_fills_utxo_fields test above.
    }

    /// One-shot runtime for the sync test fns above.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime builds")
            .block_on(fut)
    }
}
