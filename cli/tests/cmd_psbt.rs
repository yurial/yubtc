//! `yubtc psbt` — subprocess tests (Phase 14, spec ОВ-6).
//!
//! The six stdin→stdout filters around `yubtc_core::psbt`:
//!
//! - **create** (the only online command) runs against the same
//!   wiremock chain fixtures as `send`: funded native (P2WPKH) chain,
//!   legacy (P2PKH) chain with a real prev-tx served by
//!   `GET /rawtx/{txid}`, unfunded chain, interactive headless.
//!   The flagship test pins the spec invariant
//!   `create | sign | finalize | extract` == `send`'s raw tx
//!   byte-for-byte (same scan, same selector, same fee loop,
//!   deterministic signatures).
//! - **sign / combine / finalize / extract / decode** are fully
//!   offline: the PSBT fixtures are built in-process via
//!   `yubtc_core::psbt` around the shared `(SEED, PASSPHRASE,
//!   pbkdf2)` fixture keys, fed to the binary on stdin, and the
//!   base64/hex/JSON outputs are parsed back and inspected.
//!
//! Known-seed vectors: the exact signed PSBT, finalized PSBT and
//! extracted wire hex of the single-input fixture are pinned as
//! literals (the full 16-tuple KAT file is stage 3; these pins guard
//! the CLI surface against drift until then).

mod common;

use assert_cmd::Command;
use common::{
    balance_map, mount_balance, mount_rawtx, mount_unspent, stdin_seed_pass, LOW_ENTROPY_SEED, SEED,
};
use predicates::str::contains;
use wiremock::MockServer;

use yubtc_core::misc::{TNonce, TPassphrase, TSeed};
use yubtc_core::psbt::{CreateInput, PartiallySignedTransaction, UnknownKv};
use yubtc_core::transaction::{Transaction, TxIn, TxOut};
use yubtc_core::wallet::AddrType;

const PASSPHRASE: &str = common::PASSPHRASE;

fn yubtc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_yubtc"))
}

// --- argv / stdin builders -------------------------------------------

/// `psbt create` argv: mock provider, extra flags, then the two
/// positionals. No `--kdf`: the psbt surface is `auto`-only (ОВ-6),
/// which the non-empty fixture passphrase routes to pbkdf2 — the same
/// derivation the `common` helpers use.
fn create_argv(address: &str, amount: &str, extra: &[&str]) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "psbt".into(),
        "create".into(),
        "--provider".into(),
        "mock".into(),
    ];
    argv.extend(extra.iter().map(|s| s.to_string()));
    argv.push(address.to_string());
    argv.push(amount.to_string());
    argv
}

/// stdin for the offline filters that prompt a seed: seed, passphrase,
/// PSBT (the `psbt sign` three-line contract).
///
/// The offline fixtures are built around the legacy `yubtc` cascade
/// KDF (empty passphrase — three hashes per derivation, so the ОВ-9
/// walk `0..1000 × 3` forms stays in the millisecond range even when
/// it runs to the bound on foreign inputs). The CLI resolves `auto` +
/// empty passphrase to exactly that KDF.
fn sign_stdin(psbt_b64: &str) -> String {
    sign_stdin_for(SEED, "", psbt_b64)
}

/// stdin for signing PSBTs created *by the CLI* (`psbt create` /
/// legacy fixture chain): those wallets use the `common` pbkdf2
/// fixture `(SEED, "x")`.
fn sign_stdin_pbkdf2(psbt_b64: &str) -> String {
    sign_stdin_for(SEED, PASSPHRASE, psbt_b64)
}

/// [`sign_stdin`] for an arbitrary (seed, passphrase) pair.
fn sign_stdin_for(seed: &str, passphrase: &str, psbt_b64: &str) -> String {
    format!("{seed}\n{passphrase}\n{psbt_b64}\n")
}

/// stdin for the seedless filters (combine / finalize / extract /
/// decode): just the PSBT line(s).
fn psbt_stdin(lines: &[&str]) -> String {
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

/// Run one offline filter, assert success, return its trimmed stdout
/// (exactly one payload line per the module contract).
fn run_filter(args: &[&str], stdin_data: &str) -> String {
    let out = yubtc()
        .args(args)
        .write_stdin(stdin_data)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(out)
        .expect("stdout is utf-8")
        .trim()
        .to_string()
}

// --- mock chain fixtures ---------------------------------------------

/// Funded native chain (the `send` fixture): nonce 0 carries one
/// 100000-sat P2WPKH UTXO, nonce 1 is the empty gap address.
async fn funded_chain() -> MockServer {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map(&[100_000])).await;
    mount_unspent(&server, 0, &[common::utxo(0, 100_000)]).await;
    mount_unspent(&server, 1, &[]).await;
    server
}

/// Unfunded chain: every scanned address unused.
async fn unfunded_chain() -> MockServer {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map(&[])).await;
    mount_unspent(&server, 0, &[]).await;
    server
}

/// A synthetic previous transaction paying `amount` sat to `script`.
fn prev_tx_paying(amount: u64, script: Vec<u8>) -> Transaction {
    Transaction {
        version: 2,
        vin: vec![TxIn {
            txhash: [0xaa; 32],
            n: 0,
            script: Vec::new(),
            sequence: yubtc_core::SEQUENCE_RBF_SIGNALED,
            witness: Vec::new(),
        }],
        vout: vec![TxOut { amount, script }],
        locktime: 0,
    }
}

/// Funded legacy chain: nonce 0 carries one 100000-sat P2PKH UTXO
/// whose txid is the *real* txid of the returned prev-tx (the Creator
/// fetches it via `GET /rawtx/{txid}`, and the Signer later verifies
/// `dsha256(prev) == prevout.txid` — both need the honest txid).
async fn funded_legacy_chain() -> (MockServer, Transaction) {
    let prev = prev_tx_paying(
        100_000,
        hex::decode(common::p2pkh_script_hex(0)).expect("script hex"),
    );
    let server = MockServer::start().await;
    let mut received = balance_map(&[]);
    common::balance_map_with_legacy_used(&mut received, SEED, 0, 100_000);
    mount_balance(&server, &received).await;
    mount_unspent(
        &server,
        0,
        &[common::MockUtxo {
            txid_hex: hex::encode(prev.id()),
            vout: 0,
            value: 100_000,
            confirmations: 100,
            legacy: true,
        }],
    )
    .await;
    mount_unspent(&server, 1, &[]).await;
    mount_rawtx(
        &server,
        &hex::encode(prev.id()),
        hex::encode(prev.serialize_wire()),
    )
    .await;
    (server, prev)
}

// --- in-process PSBT fixtures (offline filters) -----------------------

/// Native-form fixture key at `nonce` for an arbitrary seed under the
/// `yubtc` cascade KDF (empty passphrase). The cascade is three hashes
/// per derivation, which keeps the ОВ-9 walk fast in the subprocess
/// tests even when it runs to the 1000-nonce bound on foreign inputs.
fn cascade_key(seed: &str, nonce: u32) -> yubtc_core::wallet::TPrivKey {
    use yubtc_core::kdf::KdfAlgo;
    yubtc_core::wallet::TPrivKey::with_addr_type(
        &TSeed::new(seed),
        TNonce::new(nonce),
        &TPassphrase::EMPTY,
        KdfAlgo::Yubtc,
        AddrType::Native,
    )
    .expect("derivation is deterministic")
}

/// P2WPKH lock script of `seed`'s cascade key at `nonce`.
fn cascade_p2wpkh_script(seed: &str, nonce: u32) -> Vec<u8> {
    use yubtc_core::address::hash160_pubkey;
    use yubtc_core::privkey::privkey_to_pubkey;
    use yubtc_core::script::make_p2wpkh_lock_script;
    let pubkey = privkey_to_pubkey(&cascade_key(seed, nonce).privkey);
    make_p2wpkh_lock_script(&hash160_pubkey(&pubkey)).to_vec()
}

/// Compressed pubkey of the fixture seed's cascade key at `nonce`.
fn fixture_pubkey(nonce: u32) -> Vec<u8> {
    use yubtc_core::privkey::privkey_to_pubkey;
    privkey_to_pubkey(&cascade_key(SEED, nonce).privkey).to_vec()
}

/// The canonical single-input fixture: 100 000 sat at the fixture
/// key's P2WPKH script spent to 40 000 sat at the fixture key 9's
/// script (60 000 sat fee). UTXO field: `WITNESS_UTXO` (native form).
fn psbt_fixture() -> PartiallySignedTransaction {
    let unsigned = Transaction {
        version: 2,
        vin: vec![TxIn {
            txhash: [0x42; 32],
            n: 0,
            script: Vec::new(),
            sequence: yubtc_core::SEQUENCE_RBF_SIGNALED,
            witness: Vec::new(),
        }],
        vout: vec![TxOut {
            amount: 40_000,
            script: cascade_p2wpkh_script(SEED, 9),
        }],
        locktime: 0,
    };
    PartiallySignedTransaction::create(
        unsigned,
        vec![CreateInput {
            amount: 100_000,
            script_pubkey: cascade_p2wpkh_script(SEED, 0),
            prev_tx: None,
            redeem_script: None,
            witness_script: None,
            tap_leaf_script: None,
        }],
    )
    .expect("fixture PSBT builds")
}

/// Two-input fixture for the Combiner tests: input 0 belongs to the
/// fixture seed, input 1 to a second wallet (`ARBITRARY_PHRASE`,
/// accepted permissively like any phrase) — two disjoint signers of
/// one transaction.
fn two_signer_psbt_fixture() -> PartiallySignedTransaction {
    let unsigned = Transaction {
        version: 2,
        vin: vec![
            TxIn {
                txhash: [0x42; 32],
                n: 0,
                script: Vec::new(),
                sequence: yubtc_core::SEQUENCE_RBF_SIGNALED,
                witness: Vec::new(),
            },
            TxIn {
                txhash: [0x43; 32],
                n: 0,
                script: Vec::new(),
                sequence: yubtc_core::SEQUENCE_RBF_SIGNALED,
                witness: Vec::new(),
            },
        ],
        vout: vec![TxOut {
            amount: 40_000,
            script: cascade_p2wpkh_script(SEED, 9),
        }],
        locktime: 0,
    };
    PartiallySignedTransaction::create(
        unsigned,
        vec![
            CreateInput {
                amount: 100_000,
                script_pubkey: cascade_p2wpkh_script(SEED, 0),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
            CreateInput {
                amount: 80_000,
                script_pubkey: cascade_p2wpkh_script(common::ARBITRARY_PHRASE, 0),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
        ],
    )
    .expect("two-input fixture PSBT builds")
}

// --- Known-seed vectors ------------------------------------------------
//
// Exact outputs of the fixture pipeline
// (`psbt sign` → `psbt finalize` → `psbt extract`) for
// `psbt_fixture()` under `(SEED, PASSPHRASE, pbkdf2)`. Generated once
// from this exact code path; the literals pin the CLI surface (the
// full 16-tuple KAT arrives with stage 3).

/// Signed PSBT (one `PARTIAL_SIG` added, everything else carried).
const PINNED_SIGNED_B64: &str = "cHNidP8BAFICAAAAAUJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCAAAAAAD+////AUCcAAAAAAAAFgAU7MyhA3p9dZUBN3C7mAScmWtUBz4AAAAAAAEBH6CGAQAAAAAAFgAUFrHzMI1m0b03sHKcehzqXxYQULYiAgPo2ZYUtOzGbPQRLqSeJT1aclxj5izj0LMKpSMGav5ezEgwRQIhAI1K1Gn5OV+/Faxs2nKdUaDdFbviQ9cwyhGxDvYzQJ0GAiAphvpqUmwOWXW/PJwFb3JzIStiNjO2ybYZpBzxSAgGWwEAAA==";

/// Finalized PSBT (final witness stack replaces the partial sig).
const PINNED_FINALIZED_B64: &str = "cHNidP8BAFICAAAAAUJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCAAAAAAD+////AUCcAAAAAAAAFgAU7MyhA3p9dZUBN3C7mAScmWtUBz4AAAAAAAEBH6CGAQAAAAAAFgAUFrHzMI1m0b03sHKcehzqXxYQULYBCGwCSDBFAiEAjUrUafk5X78VrGzacp1RoN0Vu+JD1zDKEbEO9jNAnQYCICmG+mpSbA5Zdb88nAVvcnMhK2I2M7bJthmkHPFICAZbASED6NmWFLTsxmz0ES6kniU9WnJcY+Ys49CzCqUjBmr+XswAAA==";

/// Extracted wire-format transaction (BIP-144), hex.
const PINNED_EXTRACTED_HEX: &str = "0200000000010142424242424242424242424242424242424242424242424242424242424242420000000000feffffff01409c000000000000160014eccca1037a7d7595013770bb98049c996b54073e024830450221008d4ad469f9395fbf15ac6cda729d51a0dd15bbe243d730ca11b10ef633409d0602202986fa6a526c0e5975bf3c9c056f7273212b623633b6c9b619a41cf14808065b012103e8d99614b4ecc66cf4112ea49e253d5a725c63e62ce3d0b30aa523066afe5ecc00000000";

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_sign_known_seed_vector_pins_signed_output() {
    let fixture = psbt_fixture();

    let signed_b64 = run_filter(&["psbt", "sign"], &sign_stdin(&fixture.to_base64()));
    assert_eq!(
        signed_b64, PINNED_SIGNED_B64,
        "known-seed sign vector drifted"
    );

    // Structural properties behind the pin.
    let signed = PartiallySignedTransaction::from_base64(&signed_b64).expect("signed reparses");
    assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
    assert_eq!(
        signed.inputs[0].partial_sigs[0].0 .0,
        fixture_pubkey(0),
        "the signature key is the fixture key"
    );
    // BIP-174: the Signer only *adds* — the unsigned tx and UTXO data
    // are carried through untouched.
    assert_eq!(signed.unsigned_tx, fixture.unsigned_tx);
    assert_eq!(
        signed.inputs[0].witness_utxo,
        fixture.inputs[0].witness_utxo
    );
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_sign_reports_fee_on_stderr() {
    let stderr = yubtc()
        .args(["psbt", "sign"])
        .write_stdin(sign_stdin(&psbt_fixture().to_base64()))
        .assert()
        .success()
        .get_output()
        .stderr
        .clone();
    let text = String::from_utf8(stderr).expect("utf-8");
    assert!(text.contains("fee: 60000 sat"), "got: {text}");
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_sign_is_idempotent_on_an_already_signed_input() {
    let once = run_filter(&["psbt", "sign"], &sign_stdin(&psbt_fixture().to_base64()));
    // Re-signing must not add a second signature: byte-identical out.
    let twice = run_filter(&["psbt", "sign"], &sign_stdin(&once));
    assert_eq!(once, twice, "re-signing adds no second signature");
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_sign_skips_foreign_inputs_with_warning() {
    // Input 0 belongs to the fixture seed, input 1 to another wallet:
    // only input 0 gains a signature, input 1 is reported (BIP-174
    // MUST: a signer signs only what it can).
    let psbt = two_signer_psbt_fixture();
    let assert = yubtc()
        .args(["psbt", "sign"])
        .write_stdin(sign_stdin(&psbt.to_base64()))
        .assert()
        .success();
    let out = assert.get_output().clone();
    let text_out = String::from_utf8(out.stdout).expect("utf-8");
    let text_err = String::from_utf8(out.stderr).expect("utf-8");
    assert!(
        text_err.contains("warning: input 1 not signed"),
        "got: {text_err}"
    );
    assert!(!text_err.contains("input 0 not signed"), "got: {text_err}");

    let signed = PartiallySignedTransaction::from_base64(text_out.trim()).expect("reparses");
    assert_eq!(signed.inputs[0].partial_sigs.len(), 1, "own input signed");
    assert!(
        signed.inputs[1].partial_sigs.is_empty(),
        "foreign input untouched"
    );
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_sign_low_entropy_seed_permissive_ok_strict_rejected() {
    let psbt = psbt_fixture().to_base64();
    // Permissive default: accepted (its keys just match nothing —
    // every input is foreign, the walk runs to the nonce bound).
    let out = run_filter(
        &["psbt", "sign"],
        &sign_stdin_for(LOW_ENTROPY_SEED, "", &psbt),
    );
    assert!(
        PartiallySignedTransaction::from_base64(&out)
            .expect("permissive run produces a PSBT")
            .inputs[0]
            .partial_sigs
            .is_empty(),
        "foreign seed signs nothing"
    );
    // --strict-bip39: the same seed is rejected at reception, before
    // any PSBT work.
    yubtc()
        .args(["psbt", "sign", "--strict-bip39"])
        .write_stdin(sign_stdin_for(LOW_ENTROPY_SEED, "", &psbt))
        .assert()
        .failure()
        .stderr(contains("strict"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_sign_invalid_base64_is_usage_error() {
    yubtc()
        .args(["psbt", "sign"])
        .write_stdin(sign_stdin("!!! definitely not base64 !!!"))
        .assert()
        .failure()
        .stderr(contains("invalid base64"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_sign_structural_psbt_error_is_typed() {
    use yubtc_core::psbt::encode_base64;
    // Valid base64, not a PSBT (a raw tx / arbitrary bytes): the
    // typed PsbtError rendering, not the transport message.
    yubtc()
        .args(["psbt", "sign"])
        .write_stdin(sign_stdin(&encode_base64(b"hello, world")))
        .assert()
        .failure()
        .stderr(contains("psbt: not a PSBT: bad magic bytes"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_sign_without_psbt_line_is_usage_error() {
    // Seed + passphrase but no third line (EOF): every filter needs
    // exactly one PSBT on stdin.
    yubtc()
        .args(["psbt", "sign"])
        .write_stdin(format!("{SEED}\n{PASSPHRASE}\n"))
        .assert()
        .failure()
        .stderr(contains("no PSBT on stdin"));
}

// --- combine -----------------------------------------------------------

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_combine_merges_disjoint_signers() {
    let psbt = two_signer_psbt_fixture();
    let b64 = psbt.to_base64();
    // Signer A (fixture seed) signs input 0 only; signer B
    // (ARBITRARY_PHRASE) signs input 1 only.
    let signed_a = run_filter(&["psbt", "sign"], &sign_stdin(&b64));
    let signed_b = run_filter(
        &["psbt", "sign"],
        &sign_stdin_for(common::ARBITRARY_PHRASE, "", &b64),
    );

    let combined_b64 = run_filter(&["psbt", "combine"], &psbt_stdin(&[&signed_a, &signed_b]));
    let combined = PartiallySignedTransaction::from_base64(&combined_b64).expect("reparses");
    assert_eq!(combined.inputs[0].partial_sigs.len(), 1, "A's sig kept");
    assert_eq!(combined.inputs[1].partial_sigs.len(), 1, "B's sig added");

    // The combined PSBT finalizes and extracts into a complete
    // two-witness-input transaction — the Phase 15 multi-sig pipeline
    // rehearsal.
    let finalized = run_filter(&["psbt", "finalize"], &psbt_stdin(&[&combined_b64]));
    let tx = PartiallySignedTransaction::from_base64(&finalized)
        .expect("finalized reparses")
        .extract_transaction()
        .expect("both inputs finalized");
    assert_eq!(tx.vin.len(), 2);
    assert_eq!(tx.vin[0].witness.len(), 2);
    assert_eq!(tx.vin[1].witness.len(), 2);
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_combine_is_idempotent() {
    // combine(p, p) == p — the same signed PSBT merged with itself.
    // Blank lines around/between the payloads are ignored.
    let signed = run_filter(&["psbt", "sign"], &sign_stdin(&psbt_fixture().to_base64()));
    let combined = run_filter(&["psbt", "combine"], &format!("\n{signed}\n\n{signed}\n\n"));
    assert_eq!(combined, signed, "combine is idempotent");
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_combine_single_line_is_usage_error() {
    let b64 = psbt_fixture().to_base64();
    yubtc()
        .args(["psbt", "combine"])
        .write_stdin(psbt_stdin(&[&b64]))
        .assert()
        .failure()
        .stderr(contains("at least two PSBTs"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_combine_conflicting_values_fail_deterministically() {
    // Same key (a proprietary unknown pair) with different values in
    // the two PSBTs: the Combiner refuses instead of picking (spec:
    // deterministic failure, not BIP-174's arbitrary choice).
    let mut a = psbt_fixture();
    a.unknown_global.push(UnknownKv {
        key: vec![0xFC, 0xAB],
        value: vec![0x01],
    });
    let mut b = psbt_fixture();
    b.unknown_global.push(UnknownKv {
        key: vec![0xFC, 0xAB],
        value: vec![0x02],
    });
    yubtc()
        .args(["psbt", "combine"])
        .write_stdin(psbt_stdin(&[&a.to_base64(), &b.to_base64()]))
        .assert()
        .failure()
        .stderr(contains("combine conflict: same key with different values"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_combine_equal_unknown_pairs_merge_and_survive() {
    // Byte-identical unknown pairs are kept exactly once and carried
    // through the pipeline untouched (unknown-passthrough at the CLI
    // level).
    let mut psbt = psbt_fixture();
    psbt.unknown_global.push(UnknownKv {
        key: vec![0xFC, 0xCD],
        value: vec![0xDE, 0xAD, 0xBE, 0xEF],
    });
    let combined = run_filter(
        &["psbt", "combine"],
        &psbt_stdin(&[&psbt.to_base64(), &psbt.to_base64()]),
    );
    let merged = PartiallySignedTransaction::from_base64(&combined).expect("reparses");
    assert_eq!(merged.unknown_global.len(), 1);
    assert_eq!(merged.unknown_global[0].value, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_combine_foreign_transactions_fail() {
    // Two PSBTs of different unsigned transactions: not combinable.
    let other = {
        let mut psbt = psbt_fixture();
        psbt.unsigned_tx.vin[0].txhash = [0x44; 32];
        psbt
    };
    yubtc()
        .args(["psbt", "combine"])
        .write_stdin(psbt_stdin(&[
            &psbt_fixture().to_base64(),
            &other.to_base64(),
        ]))
        .assert()
        .failure()
        .stderr(contains("combine refused: UNSIGNED_TX values differ"));
}

// --- finalize / extract -------------------------------------------------

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_finalize_pins_finalized_output() {
    let signed = run_filter(&["psbt", "sign"], &sign_stdin(&psbt_fixture().to_base64()));
    let finalized_b64 = run_filter(&["psbt", "finalize"], &psbt_stdin(&[&signed]));
    assert_eq!(
        finalized_b64, PINNED_FINALIZED_B64,
        "known-seed finalize vector drifted"
    );
    let finalized = PartiallySignedTransaction::from_base64(&finalized_b64).expect("reparses");
    // The partial sig is consumed: final witness in, partial list out.
    assert!(finalized.inputs[0].partial_sigs.is_empty());
    let witness = finalized.inputs[0]
        .final_scriptwitness
        .as_ref()
        .expect("final witness stack");
    // The stack serialization: compact size 2 (sig ‖ pubkey), then
    // the items — the P2WPKH completion for this form.
    assert_eq!(witness[0], 2, "two stack items");
    assert!(witness.len() > 72 + 33, "stack carries sig and pubkey");
    assert!(finalized.inputs[0].final_scriptsig.is_none());
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_finalize_on_unsigned_input_is_a_noop_success() {
    // Finalizer works per input; an input without a complete form is
    // left untouched — no error, no final fields.
    let out = run_filter(
        &["psbt", "finalize"],
        &psbt_stdin(&[&psbt_fixture().to_base64()]),
    );
    let finalized = PartiallySignedTransaction::from_base64(&out).expect("reparses");
    assert!(finalized.inputs[0].final_scriptwitness.is_none());
    assert!(finalized.inputs[0].final_scriptsig.is_none());
    assert!(finalized.inputs[0].partial_sigs.is_empty());
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_extract_pins_wire_hex() {
    let signed = run_filter(&["psbt", "sign"], &sign_stdin(&psbt_fixture().to_base64()));
    let finalized = run_filter(&["psbt", "finalize"], &psbt_stdin(&[&signed]));
    let hex_tx = run_filter(&["psbt", "extract"], &psbt_stdin(&[&finalized]));
    assert_eq!(
        hex_tx, PINNED_EXTRACTED_HEX,
        "known-seed extract vector drifted"
    );
    // BIP-144 witness form (marker/flag present after the version).
    let bytes = hex::decode(&hex_tx).expect("hex");
    assert_eq!((bytes[4], bytes[5]), (0x00, 0x01), "marker ‖ flag");
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_extract_before_finalize_fails() {
    yubtc()
        .args(["psbt", "extract"])
        .write_stdin(psbt_stdin(&[&psbt_fixture().to_base64()]))
        .assert()
        .failure()
        .stderr(contains(
            "psbt: not all inputs are finalized; extraction refused",
        ));
}

/// `psbt finalize && psbt extract | yubtc pushtx` — the spec's
/// end-to-end shell pipeline: the extracted hex is exactly the
/// broadcast payload.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_extract_pipes_into_pushtx() {
    let server = funded_chain().await;
    let created = run_psbt_create(&server, "0.0004", &[]);
    // The created PSBT belongs to the pbkdf2 CLI wallet (fixture
    // seed + "x"); it signs at nonce 0, so the walk exits early.
    let signed = run_filter(&["psbt", "sign"], &sign_stdin_pbkdf2(&created));
    let finalized = run_filter(&["psbt", "finalize"], &psbt_stdin(&[&signed]));
    let hex_tx = run_filter(&["psbt", "extract"], &psbt_stdin(&[&finalized]));

    let push_server = MockServer::start().await;
    common::mount_pushtx_ok(&push_server).await;
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", push_server.uri())
        .args(["pushtx", "-y", "--provider", "mock"])
        .write_stdin(format!("{hex_tx}\n"))
        .assert()
        .success();

    let requests = push_server.received_requests().await.expect("server alive");
    assert_eq!(requests.len(), 1, "exactly one broadcast");
    assert_eq!(
        String::from_utf8_lossy(&requests[0].body),
        format!("tx={hex_tx}"),
        "the pipe payload is the broadcast payload"
    );
}

// --- decode -------------------------------------------------------------

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_decode_dumps_json_with_fee() {
    let dump = run_filter(
        &["psbt", "decode"],
        &psbt_stdin(&[&psbt_fixture().to_base64()]),
    );
    let v: serde_json::Value = serde_json::from_str(&dump).expect("valid JSON");
    let fixture = psbt_fixture();
    assert_eq!(
        v["txid_hex"].as_str().expect("txid"),
        hex::encode(fixture.unsigned_tx.id())
    );
    assert_eq!(v["version"].as_u64(), Some(0));
    let input = &v["inputs"].as_array().expect("inputs array")[0];
    assert_eq!(input["has_utxo"].as_bool(), Some(true));
    assert_eq!(input["n_partial_sigs"].as_u64(), Some(0));
    assert_eq!(input["sighash_type"], serde_json::Value::Null);
    assert_eq!(input["finalized"].as_bool(), Some(false));
    let output = &v["outputs"].as_array().expect("outputs array")[0];
    assert_eq!(output["amount_sat"].as_u64(), Some(40_000));
    assert_eq!(
        output["script_pubkey_hex"].as_str(),
        Some(hex::encode(cascade_p2wpkh_script(SEED, 9))).as_deref()
    );
    // 100 000 in − 40 000 out.
    assert_eq!(v["fee_sat"].as_u64(), Some(60_000));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_decode_counts_partial_sigs() {
    let signed = run_filter(&["psbt", "sign"], &sign_stdin(&psbt_fixture().to_base64()));
    let dump = run_filter(&["psbt", "decode"], &psbt_stdin(&[&signed]));
    let v: serde_json::Value = serde_json::from_str(&dump).expect("valid JSON");
    assert_eq!(v["inputs"][0]["n_partial_sigs"].as_u64(), Some(1));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_decode_fee_is_null_without_utxo_data() {
    // An input with no UTXO field: fee degrades to null (a warning
    // situation per spec — the decoder works on PSBT data alone).
    let mut psbt = psbt_fixture();
    psbt.inputs[0].witness_utxo = None;
    let dump = run_filter(&["psbt", "decode"], &psbt_stdin(&[&psbt.to_base64()]));
    let v: serde_json::Value = serde_json::from_str(&dump).expect("valid JSON");
    assert_eq!(v["fee_sat"], serde_json::Value::Null);
    assert_eq!(v["inputs"][0]["has_utxo"].as_bool(), Some(false));
}

// --- create (online) ----------------------------------------------------

/// Run `psbt create` against `server`, return the base64 PSBT line.
fn run_psbt_create(server: &MockServer, amount: &str, extra: &[&str]) -> String {
    let out = yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(create_argv(&common::address(9), amount, extra))
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(out).expect("utf-8").trim().to_string()
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_emits_unsigned_psbt() {
    let server = funded_chain().await;

    let b64 = run_psbt_create(&server, "0.0005", &["--fee", "0.0001"]);
    let psbt = PartiallySignedTransaction::from_base64(&b64).expect("create emits a PSBT");

    // The unsigned tx pays the 40 000 sat cashback to the wallet's
    // gap address (cashback first — `make_vout` order) and 50 000 sat
    // (0.0005 BTC) to the destination; the signature fields are empty
    // (BIP-174 UNSIGNED_TX mandate).
    assert!(psbt.unsigned_tx.vin.iter().all(|i| i.script.is_empty()));
    assert!(psbt.unsigned_tx.vin.iter().all(|i| i.witness.is_empty()));
    assert_eq!(psbt.unsigned_tx.vout.len(), 2);
    assert_eq!(psbt.unsigned_tx.vout[0].amount, 40_000);
    assert_eq!(
        psbt.unsigned_tx.vout[0].script,
        hex::decode(common::p2wpkh_script_hex(0)).expect("script hex")
    );
    assert_eq!(psbt.unsigned_tx.vout[1].amount, 50_000);
    assert_eq!(
        psbt.unsigned_tx.vout[1].script,
        hex::decode(common::p2wpkh_script_hex(9)).expect("script hex")
    );

    // The Creator filled the UTXO field of its one input from the
    // scan metadata.
    let utxo = psbt.inputs[0].witness_utxo.as_ref().expect("witness utxo");
    assert_eq!(utxo.amount, 100_000);
    assert_eq!(
        utxo.script,
        hex::decode(common::p2wpkh_script_hex(0)).expect("script hex")
    );
    assert!(psbt.inputs[0].non_witness_utxo.is_none());
    assert!(psbt.inputs[0].partial_sigs.is_empty(), "unsigned");

    // One output map per output, both empty (preserve-only).
    assert_eq!(psbt.outputs.len(), 2);
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_all_drains_to_single_output() {
    let server = funded_chain().await;

    let b64 = run_psbt_create(&server, "ALL", &["--fee", "0.0001"]);
    let psbt = PartiallySignedTransaction::from_base64(&b64).expect("PSBT");
    // Drain: input − fee to the destination, no cashback output.
    assert_eq!(psbt.unsigned_tx.vout.len(), 1);
    assert_eq!(psbt.unsigned_tx.vout[0].amount, 90_000);
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_legacy_input_fetches_non_witness_utxo() {
    let (server, prev) = funded_legacy_chain().await;

    let dst = common::taproot_address_for(SEED, 9);
    let argv = create_argv(
        &dst,
        "0.0004",
        &["--addr-type", "legacy", "--fee", "0.0001"],
    );
    let out = yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(argv)
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let b64 = String::from_utf8(out).expect("utf-8").trim().to_string();
    let psbt = PartiallySignedTransaction::from_base64(&b64).expect("PSBT");

    // The legacy input carries the full prev-tx fetched from the
    // /rawtx endpoint; its txid is the spent outpoint.
    let fetched = psbt.inputs[0].non_witness_utxo.as_ref().expect("prev tx");
    assert_eq!(fetched.id(), prev.id());
    assert_eq!(fetched.id(), psbt.unsigned_tx.vin[0].txhash);
    assert!(psbt.inputs[0].witness_utxo.is_none());

    // …and the pipeline completes offline from there: the final wire
    // tx spends the legacy input with a scriptSig (no witness).
    let signed = run_filter(&["psbt", "sign"], &sign_stdin_pbkdf2(&b64));
    let finalized = run_filter(&["psbt", "finalize"], &psbt_stdin(&[&signed]));
    let finalized_psbt = PartiallySignedTransaction::from_base64(&finalized).expect("reparses");
    assert!(
        finalized_psbt.inputs[0]
            .final_scriptsig
            .as_ref()
            .expect("legacy final scriptSig")
            .len()
            > 70
    );
    assert!(finalized_psbt.inputs[0].final_scriptwitness.is_none());
    let hex_tx = run_filter(&["psbt", "extract"], &psbt_stdin(&[&finalized]));
    let bytes = hex::decode(&hex_tx).expect("hex");
    // No witness input data → no marker/flag: byte 4 is the vin count.
    assert_eq!(bytes[4], 0x01);
}

/// `--fee NaN` parses as f64::NaN, skips the `== 0.0` fee-loop fast
/// path and fails the sat conversion ("NaN" is not a decimal amount).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_rejects_unparseable_fee() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(create_argv(
            &common::address(9),
            "0.0005",
            &["--fee", "NaN"],
        ))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("fee:"));
}

/// A backend answering `/rawtx/{txid}` with a non-hex body must
/// surface as a typed network error (not panic, not a silent skip).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_legacy_input_rejects_non_hex_rawtx_body() {
    let prev = prev_tx_paying(
        100_000,
        hex::decode(common::p2pkh_script_hex(0)).expect("script hex"),
    );
    let server = MockServer::start().await;
    let mut received = balance_map(&[]);
    common::balance_map_with_legacy_used(&mut received, SEED, 0, 100_000);
    mount_balance(&server, &received).await;
    mount_unspent(
        &server,
        0,
        &[common::MockUtxo {
            txid_hex: hex::encode(prev.id()),
            vout: 0,
            value: 100_000,
            confirmations: 100,
            legacy: true,
        }],
    )
    .await;
    mount_unspent(&server, 1, &[]).await;
    mount_rawtx(&server, &hex::encode(prev.id()), "not-hex-at-all".into()).await;

    let dst = common::taproot_address_for(SEED, 9);
    let argv = create_argv(
        &dst,
        "0.0004",
        &["--addr-type", "legacy", "--fee", "0.0001"],
    );
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(argv)
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("bad hex"));
}

/// The spec invariant: `psbt create | psbt sign | psbt finalize |
/// psbt extract` reproduces `send`'s raw tx byte-for-byte (same scan,
/// selector, fee loop; deterministic signatures).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_pipeline_matches_send_rawtx_byte_for_byte() {
    let server = funded_chain().await;

    let send_out = yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args([
            "send",
            "--provider",
            "mock",
            "--kdf",
            "pbkdf2",
            "--fee",
            "0.0001",
            &common::address(9),
            "0.0005",
        ])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let send_text = String::from_utf8(send_out).expect("utf-8");
    let send_hex = send_text
        .lines()
        .find(|l| l.starts_with("rawtx: "))
        .expect("rawtx line")
        .trim_start_matches("rawtx: ");

    let created = run_psbt_create(&server, "0.0005", &["--fee", "0.0001"]);
    let signed = run_filter(&["psbt", "sign"], &sign_stdin_pbkdf2(&created));
    let finalized = run_filter(&["psbt", "finalize"], &psbt_stdin(&[&signed]));
    let hex_tx = run_filter(&["psbt", "extract"], &psbt_stdin(&[&finalized]));

    assert_eq!(
        hex_tx, send_hex,
        "the PSBT pipeline must reproduce send's transaction exactly"
    );
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_wallet_scan_failure_is_wallet_error() {
    // `/balance` failing from the start: `Wallet::new`'s gap walk
    // fails, its `?` in `create` propagates (exit 1).
    let server = MockServer::start().await;
    common::mount_balance_error(&server, 500).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(create_argv(&common::address(9), "0.0005", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("status 500"));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_lazy_scan_failure_is_network_error() {
    // `/balance` healthy (nonce 0 used), `/unspent` failing: the
    // failure comes from the lazy `scan_inputs_until` after wallet
    // construction — its `?` arm in `create`.
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map(&[100_000])).await;
    common::mount_unspent_error(&server, 500).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(create_argv(&common::address(9), "0.0005", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("status 500"));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_unfunded_wallet_is_usage_error() {
    let server = unfunded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(create_argv(&common::address(9), "0.0005", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("insufficient funds: no UTXOs in wallet"));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_zero_amount_is_usage_error() {
    let server = unfunded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(create_argv(&common::address(9), "0", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("amount must be > 0 (use ALL to drain)"));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_garbage_amount_is_usage_error() {
    let server = unfunded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(create_argv(&common::address(9), "lots", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("amount:"));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_amount_plus_fee_exceeds_input() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(create_argv(
            &common::address(9),
            "0.005",
            &["--fee", "0.0001"],
        ))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("amount + fee exceeds input"));
}

// Unix-only: the headless Coin Control TUI contract relies on
// terminal init failing fast; on Windows crossterm succeeds without
// a console and the event read blocks (see cli/src/cmd/tui.rs).
#[cfg(unix)]
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_interactive_headless_is_stdin_error() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(create_argv(
            &common::address(9),
            "0.0005",
            &["--interactive"],
        ))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn psbt_create_interactive_no_funds_is_ok() {
    let server = unfunded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(create_argv(
            &common::address(9),
            "0.0005",
            &["--interactive"],
        ))
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains("No funds available"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_create_rejects_a_p2wsh_recipient_with_the_typed_error() {
    // v0.3 unlocked P2WSH lock scripts in the core for the multisig
    // quorum surface; the personal `psbt create` recipient policy is
    // unchanged (the same typed message as `send`).
    let p2wsh = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", "http://127.0.0.1:1")
        .args(create_argv(p2wsh, "0.0005", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains(
            "address could not be decoded: P2WSH addresses (witness v0, 32-byte program) \
             are out of scope",
        ));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_create_unknown_provider_is_network_error() {
    // `--provider` is a clap ValueEnum: an unknown name is rejected
    // by the parser itself (exit 2) before `get_backend` is reached.
    // argv built inline: the default `--provider mock` in
    // `create_argv` would collide with the bad provider flag.
    yubtc()
        .env_remove("YUBTC_MOCK_BACKEND_URL")
        .args([
            "psbt",
            "create",
            "--provider",
            "nonsense",
            &common::address(9),
            "0.0005",
        ])
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("invalid value 'nonsense' for '--provider"));
}

// --- --help surface ------------------------------------------------------

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_help_pins_group_surface() {
    let out = yubtc()
        .args(["psbt", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf-8");
    for subcommand in ["create", "sign", "combine", "finalize", "extract", "decode"] {
        assert!(text.contains(subcommand), "missing `{subcommand}` in help");
    }
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_create_help_pins_flags() {
    let out = yubtc()
        .args(["psbt", "create", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf-8");
    for flag in [
        "-n, --nonce",
        "-c, --confirmations",
        "-f, --fee",
        "-k, --feekb",
        "-i, --interactive",
        "--provider",
        "--addr-type",
        "--strict-bip39",
    ] {
        assert!(text.contains(flag), "missing `{flag}` in create help");
    }
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn psbt_sign_help_has_strict_flag_but_no_nonce() {
    let out = yubtc()
        .args(["psbt", "sign", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf-8");
    assert!(text.contains("--strict-bip39"), "missing --strict-bip39");
    assert!(
        !text.contains("--nonce"),
        "sign must not take -n (ОВ-9 walk)"
    );
}
