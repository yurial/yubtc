//! `yubtc ms` — subprocess tests (specs/spec.md «Multi-sig»).
//!
//! - **R-MS-1 pins:** `ms create 2` / `ms send ADDR AMOUNT` (missing
//!   N or M) are usage errors with clap's exit code 2 — the values
//!   are never defaulted, prompted, or substituted.
//! - **create** is exercised offline for every documented arm:
//!   watch-only (no stdin at all), `-n` participation, the WIF
//!   sugar, `ForeignWif` rejection, and each quorum validation
//!   error. Known-seed vectors: the address/redeem pair of the
//!   fixture tuple is pinned as a literal (the full KAT axis is
//!   stage 4; this pin guards the CLI surface against drift).
//! - **send** runs end-to-end against the wiremock chain (UTXO
//!   fixture on the quorum address + honest prev-tx): the emitted
//!   PSBT is inspected, piped through `psbt decode`, and driven
//!   through the full Phase 14 chain
//!   (`psbt sign` → `finalize` → `extract`) to a spendable
//!   multisig transaction.

// `serde_json::json!` expands to `unwrap()` internally — same
// allowance as the shared `common` fixtures module.
#![allow(clippy::disallowed_methods)]

use assert_cmd::Command;
use predicates::str::contains;
use wiremock::MockServer;

use yubtc_core::kdf::KdfAlgo;
use yubtc_core::misc::{TAddress, TNonce, TPassphrase, TSeed};
use yubtc_core::psbt::PartiallySignedTransaction;
use yubtc_core::transaction::{Transaction, TxIn, TxOut};
use yubtc_core::wallet::{ms_create_address, ms_own_pubkey, MsForm};

/// Fixture seed for the ms surfaces: the `yubtc` cascade KDF (empty
/// passphrase — the `auto` heuristic routes empty passphrases there),
/// three hashes per derivation, so every derivation (and the ОВ-9
/// walk of the `psbt sign` chain step) stays fast. The Signer walk
/// marks an input signed at the FIRST matching own key, so the two
/// signers of the e2e chain are two distinct seeds (the spec's 2-of-3
/// e2e shape: two participants).
const MS_SEED: &str = "phase15ms";
const MS_SEED_B: &str = "phase15msB";

fn yubtc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_yubtc"))
}

/// stdin for the `-n` flows: seed line, empty-passphrase line (the
/// cascade route).
fn ms_stdin() -> String {
    format!("{MS_SEED}\n\n")
}

/// Cascade fixture pubkey of `seed` at `nonce` — the own key is
/// seed A nonce 0, the co-signing cosigner is seed B nonce 0 (the
/// second e2e signer).
fn fixture_pubkey(seed: &str, nonce: u32) -> [u8; 33] {
    ms_own_pubkey(
        &TSeed::new(seed),
        TNonce::new(nonce),
        &TPassphrase::EMPTY,
        KdfAlgo::Yubtc,
    )
    .expect("fixture derivation is deterministic")
}

/// A static foreign cosigner key: arbitrary compressed-pubkey-shaped
/// bytes (the quorum address only hashes them; this key never signs —
/// M = 2 is reached by the own key and the nonce-1 cosigner).
fn foreign_pubkey() -> [u8; 33] {
    let mut k = [0x02u8; 33];
    k[1..].fill(0x5a);
    k
}

/// The fixture 2-of-3 quorum: own key (nonce 0) + cosigner (nonce 1)
/// + the static foreign key. `(address, redeem)`.
fn fixture_quorum() -> (TAddress, Vec<u8>) {
    ms_create_address(
        3,
        2,
        &[
            fixture_pubkey(MS_SEED, 0),
            fixture_pubkey(MS_SEED_B, 0),
            foreign_pubkey(),
        ],
        yubtc_core::wallet::MsForm::P2sh,
    )
    .expect("fixture quorum is valid")
}

/// Native (bech32) destination for the send fixtures — cascade key 9.
fn fixture_dst() -> String {
    yubtc_core::wallet::TPrivKey::with_addr_type(
        &TSeed::new(MS_SEED),
        TNonce::new(9),
        &TPassphrase::EMPTY,
        KdfAlgo::Yubtc,
        yubtc_core::wallet::AddrType::Native,
    )
    .expect("derives")
    .get_address()
    .as_str()
    .to_string()
}

// --- R-MS-1: no defaults for N or M -----------------------------------

#[test]
fn r_ms_1_ms_create_without_m_is_a_usage_error() {
    // `yubtc ms create 2` — N present, M missing: clap must refuse
    // with its usage error before any command code runs. The value
    // is never defaulted (the spec's pin: «Пропущенный N или M —
    // ошибка, никогда не значение»).
    yubtc()
        .args(["ms", "create", "2"])
        .assert()
        .failure()
        .code(2)
        .stderr(contains("required arguments were not provided"))
        .stderr(contains("<M>"));
}

#[test]
fn r_ms_1_ms_create_without_any_positional_is_a_usage_error() {
    yubtc()
        .args(["ms", "create"])
        .assert()
        .failure()
        .code(2)
        .stderr(contains("required arguments were not provided"));
}

#[test]
fn r_ms_1_ms_send_without_n_and_m_is_a_usage_error() {
    // `ms send ADDR AMOUNT` — both quorum positionals missing.
    yubtc()
        .args(["ms", "send", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "0.001"])
        .assert()
        .failure()
        .code(2)
        .stderr(contains("required arguments were not provided"));
}

#[test]
fn r_ms_1_ms_send_with_only_n_is_a_usage_error() {
    yubtc()
        .args([
            "ms",
            "send",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "0.001",
            "3",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(contains("required arguments were not provided"))
        .stderr(contains("<M>"));
}

// --- create: offline surface ------------------------------------------

#[test]
fn ms_send_rejects_zero_amount_before_any_network_work() {
    // `0` parses to 0 sat and must be refused before the backend is
    // even resolved (no scan, no prompt beyond the seed).
    yubtc()
        .args([
            "ms",
            "send",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "0",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "-n",
            "0",
        ])
        .write_stdin(ms_stdin())
        .assert()
        .failure()
        .stderr(contains("amount must be > 0"));
}

#[test]
fn ms_send_rejects_unparseable_amount() {
    // A non-decimal amount fails the BTC→sat conversion before any
    // network work (the typed usage error names the argument).
    yubtc()
        .args([
            "ms",
            "send",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "not-a-amount",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "-n",
            "0",
        ])
        .write_stdin(ms_stdin())
        .assert()
        .failure()
        .stderr(contains("amount:"));
}

#[test]
fn ms_send_treats_66_char_non_hex_key_as_wif_sugar() {
    // 66 chars that are not hex fall through `parse_key_arg` to the
    // WIF route; the garbage WIF then fails the R-MS-6 own-key match.
    let not_hex = "z".repeat(66);
    yubtc()
        .args([
            "ms",
            "send",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "0.001",
            "3",
            "2",
            "--key",
            &not_hex,
            "-n",
            "0",
        ])
        .write_stdin(ms_stdin())
        .assert()
        .failure()
        .stderr(contains("WIF does not match the key derived at this nonce"));
}

#[test]
fn ms_create_help_lists_the_surface() {
    yubtc()
        .args(["ms", "create", "--help"])
        .assert()
        .success()
        .stdout(contains("--key"))
        .stdout(contains("--nonce"))
        .stdout(contains("N"))
        .stdout(contains("M"));
}

#[test]
fn ms_create_watch_only_builds_the_quorum_without_stdin() {
    let (addr, redeem) = fixture_quorum();
    // No seed is requested: watch-only create runs with NO stdin.
    let out = yubtc()
        .args([
            "ms",
            "create",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED, 0)),
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "--key",
            &hex::encode(foreign_pubkey()),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).expect("utf-8");
    assert_eq!(
        stdout,
        format!(
            "m-of-n: 2-of-3\naddress: {}\nredeem: {}\n",
            addr.as_str(),
            hex::encode(&redeem)
        )
    );
}

#[test]
fn ms_create_is_invariant_under_key_order_r_ms_4() {
    // The same key set in reversed argument order: identical address
    // and redeem lines (BIP-67 sort, R-MS-4).
    let (addr, redeem) = fixture_quorum();
    for order in [vec![0, 1, 2], vec![2, 1, 0], vec![1, 2, 0]] {
        let keys = [
            fixture_pubkey(MS_SEED, 0),
            fixture_pubkey(MS_SEED_B, 0),
            foreign_pubkey(),
        ];
        let mut cmd = yubtc();
        cmd.args(["ms", "create", "3", "2"]);
        for i in order {
            cmd.arg("--key").arg(hex::encode(keys[i as usize]));
        }
        let out = cmd.assert().success().get_output().stdout.clone();
        let stdout = String::from_utf8(out).expect("utf-8");
        assert!(
            stdout.contains(addr.as_str()) && stdout.contains(&hex::encode(&redeem)),
            "permuted invocation must reproduce the fixed address: {stdout}"
        );
    }
}

/// Known-seed pinned vector (KAT-style): the fixture tuple's output
/// is pinned as literals to guard the CLI surface against drift.
/// (Computed once from the fixture derivation; the in-process
/// expectations above assert the same values structurally.)
#[test]
fn ms_create_watch_only_matches_the_pinned_known_seed_vector() {
    let (addr, redeem) = fixture_quorum();
    // The literals below were produced by this exact derivation —
    // any change to sorting, hashing, or the P2SH encoding breaks
    // this pin loudly.
    assert_eq!(
        addr.as_str(),
        "3KGeCaKyugCMNQ9f5LSMzPpMAovk5tLCwA",
        "pinned 2-of-3 fixture address"
    );
    let expected_redeem = hex::encode(&redeem);
    assert_eq!(
        expected_redeem,
        "5221025a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a2102717d3024f6e018cd556986c8e88ae30e21876d2352112c8410bad019644c1a712103a5a97da6a5981e2dd27039218e5a204a79a90d7bac6a707cae6f88bbd20b563953ae",
        "pinned canonical redeem (BIP-67-sorted 2-of-3)"
    );
}

#[test]
fn ms_create_with_nonce_derives_the_own_key() {
    // `-n 0` + one cosigner: the own key (nonce 0) is appended by the
    // CLI — the quorum equals the full fixture tuple.
    let (addr, redeem) = fixture_quorum();
    let out = yubtc()
        .args([
            "ms",
            "create",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "--key",
            &hex::encode(foreign_pubkey()),
            "-n",
            "0",
        ])
        .write_stdin(ms_stdin())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).expect("utf-8");
    assert!(stdout.contains(addr.as_str()), "got: {stdout}");
    assert!(stdout.contains(&hex::encode(&redeem)), "got: {stdout}");
}

#[test]
fn ms_create_with_own_wif_sugar_matches_the_derived_key() {
    // `--key <WIF>` instead of the derivation: the WIF matches the
    // nonce-0 key, so the same quorum address results.
    let (addr, redeem) = fixture_quorum();
    let wif = yubtc_core::wallet::TPrivKey::new(
        &TSeed::new(MS_SEED),
        TNonce::new(0),
        &TPassphrase::EMPTY,
        KdfAlgo::Yubtc,
    )
    .expect("derives")
    .get_privwif();
    let out = yubtc()
        .args([
            "ms",
            "create",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "--key",
            &hex::encode(foreign_pubkey()),
            "--key",
            &wif,
            "-n",
            "0",
        ])
        .write_stdin(ms_stdin())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).expect("utf-8");
    assert!(stdout.contains(addr.as_str()), "got: {stdout}");
    assert!(stdout.contains(&hex::encode(&redeem)), "got: {stdout}");
}

#[test]
fn ms_create_rejects_a_foreign_wif() {
    // A valid WIF of a DIFFERENT key (nonce 9 of the fixture seed)
    // is refused — R-MS-6/ОВ-11: only the own derived key passes.
    let foreign_wif = yubtc_core::wallet::TPrivKey::new(
        &TSeed::new(MS_SEED),
        TNonce::new(9),
        &TPassphrase::EMPTY,
        KdfAlgo::Yubtc,
    )
    .expect("derives")
    .get_privwif();
    yubtc()
        .args([
            "ms",
            "create",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "--key",
            &hex::encode(foreign_pubkey()),
            "--key",
            &foreign_wif,
            "-n",
            "0",
        ])
        .write_stdin(ms_stdin())
        .assert()
        .failure()
        .code(1)
        .stderr(contains("WIF does not match the key derived at this nonce"));
}

#[test]
fn ms_create_wif_without_nonce_is_a_usage_error() {
    let wif = yubtc_core::wallet::TPrivKey::new(
        &TSeed::new(MS_SEED),
        TNonce::new(0),
        &TPassphrase::EMPTY,
        KdfAlgo::Yubtc,
    )
    .expect("derives")
    .get_privwif();
    yubtc()
        .args(["ms", "create", "3", "2", "--key", &wif])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("requires -n"));
}

#[test]
fn ms_create_validates_the_quorum() {
    let k0 = hex::encode(fixture_pubkey(MS_SEED, 0));
    let k1 = hex::encode(fixture_pubkey(MS_SEED_B, 0));

    // Key count ≠ N.
    yubtc()
        .args(["ms", "create", "2", "1", "--key", &k0])
        .assert()
        .failure()
        .code(1)
        .stderr(contains(
            "key count mismatch: expected exactly 2 keys, got 1",
        ));

    // M > N (QuorumBounds).
    yubtc()
        .args(["ms", "create", "2", "3", "--key", &k0, "--key", &k1])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("quorum out of bounds: need 1 ≤ M ≤ N ≤ 15"));

    // N = 16 exceeds the spendable bound (R-MS-2).
    let sixteen: Vec<String> = (0..16)
        .map(|i| {
            let mut k = [0x02u8; 33];
            k[32] = i as u8 + 1;
            hex::encode(k)
        })
        .collect();
    let mut cmd = yubtc();
    cmd.args(["ms", "create", "16", "16"]);
    for k in &sixteen {
        cmd.arg("--key").arg(k);
    }
    cmd.assert()
        .failure()
        .code(1)
        .stderr(contains("quorum out of bounds"));

    // Duplicate key (R-MS-3).
    yubtc()
        .args(["ms", "create", "2", "1", "--key", &k0, "--key", &k0])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("duplicate key in the quorum"));

    // Uncompressed prefix in a 66-char hex value.
    let mut uncompressed = [0x04u8; 33];
    uncompressed[32] = 0x11;
    yubtc()
        .args([
            "ms",
            "create",
            "2",
            "1",
            "--key",
            &hex::encode(uncompressed),
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("compressed pubkey"));
}

// --- send: mock-chain fixtures ----------------------------------------

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

/// Bitcoin txid convention: reversed double-SHA256 of the raw bytes.
fn txid_of(raw: &[u8]) -> String {
    let h1 = Sha256::digest(raw);
    let mut h2 = Sha256::digest(h1);
    h2.reverse();
    hex::encode(h2)
}

/// A synthetic previous transaction paying `amount` to the quorum
/// script (the honest txid is required: the Signer verifies
/// `dsha256(prev) == prevout.txid`).
fn prev_tx_paying(amount: u64, script: &[u8]) -> Transaction {
    Transaction {
        version: 2,
        vin: vec![TxIn {
            txhash: [0xaa; 32],
            n: 0,
            script: Vec::new(),
            sequence: yubtc_core::SEQUENCE_RBF_SIGNALED,
            witness: Vec::new(),
        }],
        vout: vec![TxOut {
            amount,
            script: script.to_vec(),
        }],
        locktime: 0,
    }
}

/// Stand up the mock chain: one 60 000-sat confirmed UTXO at the
/// quorum address plus the honest raw prev-tx endpoint.
async fn funded_quorum_chain(quorum_script: &[u8]) -> (MockServer, Transaction) {
    let (addr, _) = fixture_quorum();
    let prev = prev_tx_paying(60_000, quorum_script);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/unspent"))
        .and(query_param("active", addr.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "unspent_outputs": [{
                "tx_hash": txid_of(&prev.serialize_wire()),
                "tx_output_n": 0,
                "value": 60_000,
                "script": hex::encode(quorum_script),
                "confirmations": 10,
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/rawtx/{}", txid_of(&prev.serialize_wire()))))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(hex::encode(prev.serialize_wire())),
        )
        .mount(&server)
        .await;
    (server, prev)
}

/// `ms send` argv: the fixture quorum spend of 0.0005 BTC at the
/// fixture quorum (own = nonce 0, cosigners = nonce 1 + foreign),
/// mock provider, fee loop at 1000 sat/kB.
fn send_argv(dst: &str) -> Vec<String> {
    vec![
        "ms".into(),
        "send".into(),
        dst.to_string(),
        "0.0005".into(),
        "3".into(),
        "2".into(),
        "--key".into(),
        hex::encode(fixture_pubkey(MS_SEED_B, 0)),
        "--key".into(),
        hex::encode(foreign_pubkey()),
        "-n".into(),
        "0".into(),
        "-c".into(),
        "6".into(),
        "-k".into(),
        "1000".into(),
        "--provider".into(),
        "mock".into(),
    ]
}

/// Run `ms send` against `server`, return (stdout base64 line, full
/// stderr).
fn run_send(server: &MockServer, dst: &str) -> (String, String) {
    let out = yubtc()
        .args(send_argv(dst))
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .write_stdin(ms_stdin())
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let stderr = String::from_utf8(out.stderr).expect("utf-8 stderr");
    (stdout.trim().to_string(), stderr)
}

#[tokio::test]
async fn ms_send_e2e_full_pipeline_to_a_spendable_multisig_tx() {
    let (_, redeem) = fixture_quorum();
    let quorum_script =
        yubtc_core::script::make_p2sh_lock_script(&yubtc_core::address::hash160_script(&redeem));
    let (server, _prev) = funded_quorum_chain(&quorum_script).await;
    let dst = fixture_dst();

    // 1. `ms send` — Creator + Signer in one step.
    let (psbt_b64, stderr) = run_send(&server, &dst);
    assert!(stderr.contains("fee:"), "fee line on stderr: {stderr}");
    let psbt = PartiallySignedTransaction::from_base64(&psbt_b64).expect("base64 PSBT");
    assert_eq!(psbt.inputs.len(), 1);
    assert_eq!(
        psbt.inputs[0].redeem_script.as_deref(),
        Some(redeem.as_slice())
    );
    // Exactly the own key has signed so far.
    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    assert_eq!(
        psbt.inputs[0].partial_sigs[0].0 .0,
        fixture_pubkey(MS_SEED, 0).to_vec()
    );
    // Cashback went back to the QUORUM address (vout[0], make_vout
    // layout), the destination is vout[1].
    assert_eq!(psbt.unsigned_tx.vout[0].script, quorum_script);
    assert_eq!(psbt.unsigned_tx.vout.len(), 2);

    // 2. `ms send | psbt decode` — the pipe contract works.
    let decode_out = yubtc()
        .args(["psbt", "decode"])
        .write_stdin(format!("{psbt_b64}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let summary: serde_json::Value =
        serde_json::from_slice(&decode_out).expect("decode emits JSON");
    assert_eq!(summary["inputs"][0]["n_partial_sigs"], 1);
    assert_eq!(summary["outputs"].as_array().expect("outputs").len(), 2);
    assert!(summary["fee_sat"].as_u64().expect("fee present") > 0);

    // 3. The cosigner (seed B) signs via the standard `psbt sign`
    // (ОВ-12 — no `ms sign` exists; the walk of seed B finds its
    // nonce-0 key among the redeem members).
    let signed_b64 = yubtc()
        .args(["psbt", "sign"])
        .write_stdin(format!("{MS_SEED_B}\n\n{psbt_b64}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let signed = PartiallySignedTransaction::from_base64(
        String::from_utf8(signed_b64).expect("utf-8").trim(),
    )
    .expect("signed PSBT parses");
    // Own + nonce-1 cosigner = the M = 2 quorum (the foreign key
    // never signs — its secret is not known to this wallet).
    assert_eq!(signed.inputs[0].partial_sigs.len(), 2);

    // 4. finalize → extract: a complete scriptSig (OP_0 dummy, M
    // signature pushes, the pushed redeem), no witness.
    let finalized_b64 = yubtc()
        .args(["psbt", "finalize"])
        .write_stdin(format!("{}\n", signed.to_base64()))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let wire_hex = yubtc()
        .args(["psbt", "extract"])
        .write_stdin(finalized_b64)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let wire =
        hex::decode(String::from_utf8(wire_hex).expect("utf-8").trim()).expect("wire hex decodes");
    let tx = yubtc_core::psbt::parse_wire_tx(&wire).expect("wire tx parses");
    // scriptSig bytes are part of the legacy txid preimage — the
    // completed txid differs from the unsigned one; the outputs are
    // pinned instead.
    assert_eq!(tx.vout, psbt.unsigned_tx.vout);
    let script_sig = &tx.vin[0].script;
    assert_eq!(script_sig[0], 0x00, "R-MS-5: the dummy element is OP_0");
    assert!(
        script_sig
            .windows(redeem.len())
            .any(|w| w == redeem.as_slice()),
        "the redeem script is pushed last"
    );
    assert!(tx.vin[0].witness.is_empty(), "P2SH-multisig is legacy");
}

#[tokio::test]
async fn ms_send_refuses_a_quorum_the_wallet_does_not_join() {
    let (_, redeem) = fixture_quorum();
    let quorum_script =
        yubtc_core::script::make_p2sh_lock_script(&yubtc_core::address::hash160_script(&redeem));
    let (server, _) = funded_quorum_chain(&quorum_script).await;
    let dst = fixture_dst();

    // No `-n` → NotAParticipant, without touching the seed prompt
    // (empty stdin is enough).
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args([
            "ms",
            "send",
            &dst,
            "0.0005",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "--key",
            &hex::encode(foreign_pubkey()),
            "--provider",
            "mock",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("own key is not a participant of this quorum"));
}

#[test]
fn ms_send_wif_without_nonce_is_a_usage_error() {
    // The send-side twin of the create guard: a WIF without `-n` has
    // nothing to be verified against.
    let wif = yubtc_core::wallet::TPrivKey::new(
        &TSeed::new(MS_SEED),
        TNonce::new(0),
        &TPassphrase::EMPTY,
        KdfAlgo::Yubtc,
    )
    .expect("derives")
    .get_privwif();
    yubtc()
        .args([
            "ms",
            "send",
            &fixture_dst(),
            "0.0005",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "--key",
            &wif,
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("requires -n"));
}

#[test]
fn ms_send_rejects_a_negative_explicit_fee() {
    // `-f` is routed through the same safe BTC parser: a negative
    // fee is a usage error before any network activity.
    yubtc()
        .args([
            "ms",
            "send",
            &fixture_dst(),
            "0.0005",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "-n",
            "0",
            "--fee=-0.5",
        ])
        .write_stdin(ms_stdin())
        .assert()
        .failure()
        .code(1)
        .stderr(contains("fee:"));
}

#[tokio::test]
async fn ms_send_surfaces_quorum_and_network_failures() {
    let (_, redeem) = fixture_quorum();
    let quorum_script =
        yubtc_core::script::make_p2sh_lock_script(&yubtc_core::address::hash160_script(&redeem));
    let dst = fixture_dst();

    // Quorum bounds (n = 16) — refused before any network call.
    let server = MockServer::start().await;
    let mut cmd = yubtc();
    cmd.args(["ms", "send", &dst, "0.0005", "16", "16"])
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .write_stdin(ms_stdin());
    let keys: Vec<String> = (0..15)
        .map(|i| {
            let mut k = [0x02u8; 33];
            k[32] = i as u8 + 1;
            hex::encode(k)
        })
        .collect();
    for k in &keys {
        cmd.arg("--key").arg(k);
    }
    cmd.arg("-n").arg("0").arg("--provider").arg("mock");
    cmd.assert()
        .failure()
        .code(1)
        .stderr(contains("quorum out of bounds"));

    // Funded chain, but the UTXO is too shallow for -c 50 (the argv
    // is spelled out here because the default `-c 6` would clash).
    let (server, _) = funded_quorum_chain(&quorum_script).await;
    let mut deep = yubtc();
    deep.args([
        "ms",
        "send",
        &dst,
        "0.0005",
        "3",
        "2",
        "--key",
        &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
        "--key",
        &hex::encode(foreign_pubkey()),
        "-n",
        "0",
        "-c",
        "50",
        "-k",
        "1000",
        "--provider",
        "mock",
    ])
    .env("YUBTC_MOCK_BACKEND_URL", server.uri())
    .write_stdin(ms_stdin())
    .assert()
    .failure()
    .code(1)
    .stderr(contains("amount + fee exceeds input"));

    // Backend failure (UTXO fetch 500) → network error.
    let server2 = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/unspent"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server2)
        .await;
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server2.uri())
        .args(send_argv(&dst))
        .write_stdin(ms_stdin())
        .assert()
        .failure()
        .code(1)
        .stderr(contains("network"));
}

#[tokio::test]
async fn ms_send_rejects_bad_amount_and_destination() {
    // Amount 0 is refused before any network activity…
    yubtc()
        .args([
            "ms",
            "send",
            &fixture_dst(),
            "0",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "-n",
            "0",
        ])
        .write_stdin(ms_stdin())
        .assert()
        .failure()
        .code(1)
        .stderr(contains("amount must be > 0"));

    // …and a malformed destination decodes only inside the Creator
    // (after the UTXO fetch), so this runs against the funded chain.
    let (_, redeem) = fixture_quorum();
    let quorum_script =
        yubtc_core::script::make_p2sh_lock_script(&yubtc_core::address::hash160_script(&redeem));
    let (server, _) = funded_quorum_chain(&quorum_script).await;
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args([
            "ms",
            "send",
            "not-an-address",
            "0.0005",
            "3",
            "2",
            "--key",
            &hex::encode(fixture_pubkey(MS_SEED_B, 0)),
            "--key",
            &hex::encode(foreign_pubkey()),
            "-n",
            "0",
            "--provider",
            "mock",
        ])
        .write_stdin(ms_stdin())
        .assert()
        .failure()
        .code(1)
        .stderr(contains("address could not be decoded"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn ms_create_p2wsh_form_prints_the_witness_address() {
    // v0.3: `--form p2wsh` addresses the SAME redeem script tuple as
    // `bc1q…` (bech32 v0, SHA256(redeem)); the three-line output
    // block is unchanged and the address matches the wallet-level
    // derivation for the witness form.
    let k1 = hex::encode(fixture_pubkey(MS_SEED, 1));
    let k2 = hex::encode(fixture_pubkey(MS_SEED, 2));
    let stdin = format!("{MS_SEED}\n\n");
    let argv = [
        "ms", "create", "3", "2", "--form", "p2wsh", "--key", &k1, "--key", &k2, "-n", "0",
    ];
    let out = yubtc()
        .args(argv)
        .write_stdin(stdin)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf-8");
    let lines: Vec<&str> = text.trim().lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "m-of-n: 2-of-3");
    let address = lines[1].strip_prefix("address: ").expect("address line");
    let redeem_hex = lines[2].strip_prefix("redeem: ").expect("redeem line");
    assert!(address.starts_with("bc1q"), "witness address: {address}");
    let mut quorum = vec![fixture_pubkey(MS_SEED, 1), fixture_pubkey(MS_SEED, 2)];
    quorum.push(fixture_pubkey(MS_SEED, 0));
    let (_p2sh_addr, redeem) =
        ms_create_address(3, 2, &quorum, MsForm::P2sh).expect("fixture quorum is valid");
    assert_eq!(redeem_hex, hex::encode(&redeem));
    // Cross-form parity: the P2SH address differs, the redeem does not.
    let program = yubtc_core::address::decode_p2wsh_address(address)
        .expect("the CLI address decodes as P2WSH");
    assert_eq!(program, yubtc_core::address::sha256_script(&redeem));
}

// --- p2tr form (v0.3 Tapscript, spec «Поверхность» / ОВ-19) -----------

/// The x-only hex of a compressed fixture key (the p2tr `--key`
/// grammar, R-MS-10: 64 hex chars).
fn xonly_hex(key: &[u8; 33]) -> String {
    hex::encode(&key[1..33])
}

#[test]
fn ms_create_help_pins_the_form_flag_and_the_key_encodings() {
    // The `--form` flag with its three values is the shell wire
    // contract; the R-MS-10 encodings are spelled out in the help
    // (x-only 64-char hex for p2tr vs compressed 66-char hex).
    for cmd in [["ms", "create", "--help"], ["ms", "send", "--help"]] {
        yubtc()
            .args(cmd)
            .assert()
            .success()
            .stdout(contains("--form"))
            .stdout(contains("p2tr"))
            .stdout(contains("x-only"))
            .stdout(contains("66"));
    }
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn ms_create_p2tr_form_prints_the_tapscript_address_and_witness_material() {
    // v0.3 Tapscript: `--form p2tr` prints FIVE lines — m-of-n,
    // address (bc1p…), redeem (the CHECKSIGADD tapscript, different
    // bytes than the p2sh redeem), internal (the NUMS key) and
    // control (the 33-byte BIP-341 control block, 66 hex chars).
    let k1 = xonly_hex(&fixture_pubkey(MS_SEED, 1));
    let k2 = xonly_hex(&fixture_pubkey(MS_SEED, 2));
    let stdin = format!("{MS_SEED}\n\n");
    let argv = [
        "ms", "create", "3", "2", "--form", "p2tr", "--key", &k1, "--key", &k2, "-n", "0",
    ];
    let out = yubtc()
        .args(argv)
        .write_stdin(stdin)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf-8");
    let lines: Vec<&str> = text.trim().lines().collect();
    assert_eq!(lines.len(), 5, "p2tr prints the witness material: {text}");
    assert_eq!(lines[0], "m-of-n: 2-of-3");
    let address = lines[1].strip_prefix("address: ").expect("address line");
    let redeem_hex = lines[2].strip_prefix("redeem: ").expect("redeem line");
    let internal = lines[3].strip_prefix("internal: ").expect("internal line");
    let control = lines[4].strip_prefix("control: ").expect("control line");

    assert!(address.starts_with("bc1p"), "taproot address: {address}");
    let program = yubtc_core::address::decode_taproot_address(address)
        .expect("the CLI address decodes as P2TR");

    // The quorum the CLI assembled: own key (nonce 0) + the two
    // cosigners, as x-only projections inside the tapscript.
    let mut quorum = vec![fixture_pubkey(MS_SEED, 1), fixture_pubkey(MS_SEED, 2)];
    quorum.push(fixture_pubkey(MS_SEED, 0));
    let (expected, script) =
        ms_create_address(3, 2, &quorum, MsForm::P2tr).expect("fixture quorum is valid");
    assert_eq!(address, expected.as_str());
    assert_eq!(redeem_hex, hex::encode(&script));
    // The redeem is NOT the p2sh/p2wsh redeem — different bytes for
    // the same key set (spec: «один кворум — три адреса»).
    let (p2sh_addr, p2sh_redeem) =
        ms_create_address(3, 2, &quorum, MsForm::P2sh).expect("p2sh twin");
    assert_ne!(redeem_hex, hex::encode(&p2sh_redeem));
    assert_ne!(address, p2sh_addr.as_str());

    // internal: the NUMS point (R-MS-8), the same constant the core
    // tweak derives from.
    assert_eq!(
        internal,
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    );
    // control: 33 bytes (66 hex) — c[0] ‖ H at depth 0 (BIP-341).
    assert_eq!(control.len(), 66, "33-byte control block: {control}");
    assert!(control.ends_with(internal), "c[1..33] == H");
    let control_bytes = hex::decode(control).expect("hex control block");
    let leaf_hash = yubtc_core::script::tapscript_leaf_hash(&script);
    let expected_control = yubtc_core::address::tapscript_control_block(
        &yubtc_core::fwd::MS_TAPSCRIPT_INTERNAL_KEY,
        &leaf_hash,
    )
    .expect("NUMS tweak is total");
    assert_eq!(control_bytes, expected_control);
    // The address commits to the tweaked output key of this material.
    let output_key = yubtc_core::address::tapscript_output_key(
        &yubtc_core::fwd::MS_TAPSCRIPT_INTERNAL_KEY,
        &leaf_hash,
    )
    .expect("NUMS tweak is total");
    assert_eq!(program, output_key);
}

#[test]
fn ms_create_p2tr_rejects_a_compressed_key_with_the_typed_encoding_error() {
    // R-MS-10: a 66-char compressed key under `--form p2tr` is a
    // wrong *encoding* — refused with the typed MsError::
    // InvalidKeyEncoding before any seed is touched (watch-only:
    // no stdin at all).
    let compressed = hex::encode(fixture_pubkey(MS_SEED, 1));
    let xonly = xonly_hex(&fixture_pubkey(MS_SEED, 2));
    yubtc()
        .args([
            "ms",
            "create",
            "2",
            "1",
            "--form",
            "p2tr",
            "--key",
            &compressed,
            "--key",
            &xonly,
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains(
            "key encoding does not match the form: p2sh/p2wsh need 66-hex compressed \
             keys, p2tr needs 64-hex x-only keys",
        ));
}

#[test]
fn ms_create_p2tr_falls_through_non_hex_values_to_the_wif_guard() {
    // 64 chars that are not hex are not a p2tr pubkey — they take
    // the WIF route and die on the R-MS-6 own-key match (ForeignWif
    // stays the verdict for WIF-shaped garbage in every form).
    let z64 = "z".repeat(64);
    yubtc()
        .args([
            "ms", "create", "2", "1", "--form", "p2tr", "--key", &z64, "-n", "0",
        ])
        .write_stdin(ms_stdin())
        .assert()
        .failure()
        .code(1)
        .stderr(contains("WIF does not match the key derived at this nonce"));
}

/// Stand up the mock chain for a p2tr quorum spend: one 60 000-sat
/// confirmed UTXO at the p2tr quorum address and **no /rawtx
/// endpoint at all** — the Creator must not fetch prev-txs (the
/// WITNESS_UTXO commits the amount, symmetric with P2WSH).
async fn funded_p2tr_chain(quorum_script: &[u8]) -> (MockServer, TAddress) {
    let (addr, _) = p2tr_quorum();
    let script_hex = hex::encode(quorum_script);
    let prev_txid = "cd".repeat(32);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/unspent"))
        .and(query_param("active", addr.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "unspent_outputs": [{
                "tx_hash": prev_txid,
                "tx_output_n": 0,
                "value": 60_000,
                "script": script_hex,
                "confirmations": 10,
            }]
        })))
        .mount(&server)
        .await;
    (server, addr)
}

/// The fixture 2-of-3 quorum in the p2tr form: the same three keys
/// as [`fixture_quorum`], addressed through the NUMS tapscript.
fn p2tr_quorum() -> (TAddress, Vec<u8>) {
    ms_create_address(
        3,
        2,
        &[
            fixture_pubkey(MS_SEED, 0),
            fixture_pubkey(MS_SEED_B, 0),
            foreign_pubkey(),
        ],
        MsForm::P2tr,
    )
    .expect("fixture quorum is valid")
}

/// `ms send --form p2tr` argv: the fixture quorum spend with the
/// x-only `--key` grammar (R-MS-10), mock provider, fee loop.
fn send_p2tr_argv(dst: &str) -> Vec<String> {
    vec![
        "ms".into(),
        "send".into(),
        dst.to_string(),
        "0.0005".into(),
        "3".into(),
        "2".into(),
        "--form".into(),
        "p2tr".into(),
        "--key".into(),
        xonly_hex(&fixture_pubkey(MS_SEED_B, 0)),
        "--key".into(),
        xonly_hex(&foreign_pubkey()),
        "-n".into(),
        "0".into(),
        "-c".into(),
        "6".into(),
        "-k".into(),
        "1000".into(),
        "--provider".into(),
        "mock".into(),
    ]
}

#[tokio::test]
async fn ms_send_p2tr_e2e_full_pipeline_to_a_spendable_tapscript_tx() {
    // The v0.3 Tapscript send chain, fully offline on the mock:
    // build (Creator+Signer) → psbt sign (cosigner) → combine →
    // finalize → extract → an independent structural check of the
    // R-MS-11 witness.
    let (_, script) = p2tr_quorum();
    let quorum_script = yubtc_core::wallet::ms_quorum_lock_script(&script, MsForm::P2tr);
    let (server, _) = funded_p2tr_chain(&quorum_script).await;
    let dst = fixture_dst();

    // 1. `ms send --form p2tr` — Creator + Signer in one step.
    let out = yubtc()
        .args(send_p2tr_argv(&dst))
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .write_stdin(ms_stdin())
        .assert()
        .success()
        .get_output()
        .clone();
    let stderr = String::from_utf8(out.stderr).expect("utf-8 stderr");
    assert!(stderr.contains("fee:"), "fee line on stderr: {stderr}");
    let psbt_b64 = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let psbt_b64 = psbt_b64.trim().to_string();
    let psbt = PartiallySignedTransaction::from_base64(&psbt_b64).expect("base64 PSBT");
    assert_eq!(psbt.inputs.len(), 1);
    // Script-path Creator fields: WITNESS_UTXO (no prev-tx fetch —
    // the mock has no /rawtx route, so a fetch would have failed
    // the run), TAP_LEAF_SCRIPT (script ‖ 0xc0) and the NUMS
    // TAP_INTERNAL_KEY; no REDEEM/WITNESS_SCRIPT.
    let input = &psbt.inputs[0];
    assert!(input.non_witness_utxo.is_none());
    assert!(input.witness_utxo.is_some());
    assert!(input.redeem_script.is_none() && input.witness_script.is_none());
    let leaf_hash = yubtc_core::script::tapscript_leaf_hash(&script);
    assert_eq!(input.tap_leaf_scripts.len(), 1);
    let leaf = &input.tap_leaf_scripts[0];
    assert_eq!(leaf.script_with_version, [&script[..], &[0xc0u8]].concat());
    assert_eq!(
        leaf.control_block,
        yubtc_core::address::tapscript_control_block(
            &yubtc_core::fwd::MS_TAPSCRIPT_INTERNAL_KEY,
            &leaf_hash
        )
        .expect("NUMS tweak is total")
        .to_vec()
    );
    assert_eq!(
        input.tap_internal_key,
        Some(yubtc_core::fwd::MS_TAPSCRIPT_INTERNAL_KEY)
    );
    // The own key signed the script path: one TAP_SCRIPT_SIG keyed
    // by the x-only projection ‖ leaf_hash, 64 bytes (ОВ-17).
    assert_eq!(input.tap_script_sigs.len(), 1);
    assert_eq!(
        input.tap_script_sigs[0].x_only,
        &fixture_pubkey(MS_SEED, 0)[1..33]
    );
    assert_eq!(input.tap_script_sigs[0].leaf_hash, leaf_hash);
    assert_eq!(input.tap_script_sigs[0].sig.len(), 64);
    // Cashback to the bc1p quorum address (vout[0]), destination vout[1].
    assert_eq!(psbt.unsigned_tx.vout.len(), 2);
    assert_eq!(psbt.unsigned_tx.vout[0].script, quorum_script);

    // 2. `ms send | psbt decode` — the pipe contract works for p2tr
    // (the JSON summary counts ECDSA PARTIAL_SIGs; the script-path
    // signatures live in TAP_SCRIPT_SIG, so the count is 0 here —
    // the UTXO-committed fee is what matters for the pipe).
    let decode_out = yubtc()
        .args(["psbt", "decode"])
        .write_stdin(format!("{psbt_b64}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let summary: serde_json::Value =
        serde_json::from_slice(&decode_out).expect("decode emits JSON");
    assert_eq!(summary["inputs"][0]["n_partial_sigs"], 0);
    assert!(summary["inputs"][0]["has_utxo"]
        .as_bool()
        .expect("utxo flag"));
    assert!(summary["fee_sat"].as_u64().expect("fee present") > 0);

    // 3. The cosigner (seed B) signs via the standard `psbt sign`:
    // the script-path walk finds its nonce-0 x-only key among the
    // tapscript members.
    let signed_b64 = String::from_utf8(
        yubtc()
            .args(["psbt", "sign"])
            .write_stdin(format!("{MS_SEED_B}\n\n{psbt_b64}\n"))
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .expect("utf-8");
    let signed =
        PartiallySignedTransaction::from_base64(signed_b64.trim()).expect("signed PSBT parses");
    assert_eq!(signed.inputs[0].tap_script_sigs.len(), 2, "own + cosigner");

    // 4. combine → finalize → extract.
    let combined_b64 = yubtc()
        .args(["psbt", "combine"])
        .write_stdin(format!("{psbt_b64}\n{signed_b64}"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let finalized_b64 = yubtc()
        .args(["psbt", "finalize"])
        .write_stdin(combined_b64)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let wire_hex = yubtc()
        .args(["psbt", "extract"])
        .write_stdin(finalized_b64)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let wire =
        hex::decode(String::from_utf8(wire_hex).expect("utf-8").trim()).expect("wire hex decodes");
    let tx = yubtc_core::psbt::parse_wire_tx(&wire).expect("wire tx parses");

    // 5. Independent structural check of the finalized spend:
    // empty scriptSig, the R-MS-11 witness stack
    // `[w_N … w_1] ‖ tapscript ‖ control block` (5 elements for
    // N = 3), exactly the M = 2 signer slots non-empty (64 bytes
    // each) at the reversed key positions, and the outputs pinned.
    assert_eq!(tx.vout, psbt.unsigned_tx.vout);
    assert_eq!(tx.vin[0].script, Vec::<u8>::new());
    let witness = &tx.vin[0].witness;
    assert_eq!(witness.len(), 3 + 2, "N slots + script + control block");
    assert_eq!(witness[3].as_slice(), script.as_slice());
    let control = yubtc_core::address::tapscript_control_block(
        &yubtc_core::fwd::MS_TAPSCRIPT_INTERNAL_KEY,
        &leaf_hash,
    )
    .expect("NUMS tweak is total");
    assert_eq!(witness[4].as_slice(), control.as_slice());
    // The slots are the script keys in REVERSE order; the foreign
    // key never signs (its secret is not known to either wallet).
    let (_, keys) = yubtc_core::script::extract_multisig_tapscript(&script)
        .expect("the quorum script is the canonical tapscript");
    let own_xonly = &fixture_pubkey(MS_SEED, 0)[1..33];
    let seed_b_xonly = &fixture_pubkey(MS_SEED_B, 0)[1..33];
    let foreign_xonly = &foreign_pubkey()[1..33];
    for (slot, key) in witness[..3].iter().zip(keys.iter().rev()) {
        if key.as_slice() == foreign_xonly {
            assert!(slot.is_empty(), "the non-signer slot is empty");
        } else {
            assert!(
                key.as_slice() == own_xonly || key.as_slice() == seed_b_xonly,
                "slot key is a quorum member"
            );
            assert_eq!(slot.len(), 64, "SIGHASH_DEFAULT Schnorr signature");
        }
    }
}
