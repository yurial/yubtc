//! `yubtc dumpprivkey` — subprocess tests.
//!
//! Happy path prints `Address: <p2pkh>` + the mainnet WIF (verified
//! round-trip through `wif_to_privkey`). Error paths mirror
//! `address`: mock provider without the env var, empty stdin,
//! non-UTF-8 stdin.

mod common;

use assert_cmd::Command;
use common::{
    address, address_for, balance_map, balance_map_for, mount_balance, stdin_low_entropy_seed_pass,
    stdin_seed_pass, stdin_seed_pass_for,
};
use predicates::str::contains;
use wiremock::MockServer;

const UNREACHABLE: &str = "http://127.0.0.1:1";

fn yubtc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_yubtc"))
}

async fn zero_chain() -> MockServer {
    let server = MockServer::start().await;
    let received = balance_map(&[]);
    mount_balance(&server, &received).await;
    server
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn dumpprivkey_prints_address_and_wif() {
    let server = zero_chain().await;

    let output = yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["dumpprivkey", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).expect("stdout is utf-8");
    // `prompt_seed` writes `Seed: ` without newline, so the first
    // line is `Seed: Address: <addr>`; the WIF is the next line.
    let mut lines = text.lines();
    let address_line = lines.next().expect("address line");
    let wif_line = lines.next().expect("wif line");
    assert_eq!(address_line, format!("Seed: Address: {}", address(0)));

    // Round-trip: the WIF must decode back to the fixture key and
    // re-derive the same address (the default form is native, so the
    // re-derivation goes through the P2WPKH encoding).
    let key = yubtc_core::address::wif_to_privkey(wif_line).expect("valid WIF");
    let rederived = yubtc_core::address::pubkey_to_segwit_address(
        &yubtc_core::privkey::privkey_to_pubkey(&key),
    );
    assert_eq!(rederived.as_str(), address(0));
}

/// `--nonce 3` dumps the key for nonce 3.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn dumpprivkey_nonce_flag_selects_key() {
    let server = zero_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args([
            "dumpprivkey",
            "--provider",
            "mock",
            "--kdf",
            "pbkdf2",
            "--nonce",
            "3",
        ])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains(format!("Address: {}", address(3))));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn dumpprivkey_mock_provider_without_env_var_is_network_error() {
    yubtc()
        .env_remove("YUBTC_MOCK_BACKEND_URL")
        .args(["dumpprivkey", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("YUBTC_MOCK_BACKEND_URL is not set"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn dumpprivkey_empty_stdin_is_seed_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["dumpprivkey", "--provider", "mock"])
        .assert()
        .failure()
        .stderr(contains("seed phrase is empty"));
}

/// Permissive default (R-1): an arbitrary non-BIP-39 phrase dumps
/// its WIF like any other seed, with the non-blocking R-6 warning
/// (~90 bits) on stderr.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn dumpprivkey_permissive_accepts_arbitrary_phrase_with_warning() {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map_for(common::ARBITRARY_PHRASE, &[])).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["dumpprivkey", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass_for(common::ARBITRARY_PHRASE))
        .assert()
        .success()
        .stderr(contains("warning: low entropy"))
        .stdout(contains(format!(
            "Address: {}",
            address_for(common::ARBITRARY_PHRASE, 0)
        )));
}

/// Checksum-valid but low-entropy seed (abandon ×11 + about) is
/// rejected at reception by the strict C6 entropy floor — before the
/// backend registry is even consulted (no mock env var set here).
#[test]
#[ntest_timeout::timeout(30_000)]
fn dumpprivkey_low_entropy_seed_rejected_at_reception() {
    yubtc()
        .env_remove("YUBTC_MOCK_BACKEND_URL")
        .args(["dumpprivkey", "--provider", "mock", "--strict-bip39"])
        .write_stdin(stdin_low_entropy_seed_pass())
        .assert()
        .failure()
        .stderr(contains("entropy too low"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn dumpprivkey_non_utf8_stdin_is_stdin_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["dumpprivkey", "--provider", "mock"])
        .write_stdin([0xff, 0x0a])
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}
