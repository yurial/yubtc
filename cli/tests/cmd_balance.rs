//! `yubtc balance` — subprocess tests.
//!
//! Chain fixture: nonce 0 funded (100000 sat), nonce 1 used but
//! currently empty, nonce 2 unused (gap stop), `--new 1` re-appends
//! nonce 2. The matrix covers:
//!
//! - funded line + `Total:` (plain and `-v` per-UTXO breakdown);
//! - used-but-empty skipped silently by default, shown with `-e`
//!   (as `0.00000000 BTC`), per-UTXO loop empty under `-e -v`;
//! - unused line (`N# addr: unused`);
//! - `/unspent` and `/balance` HTTP failures → network error;
//! - provider registry error, empty seed, non-UTF-8 stdin.

mod common;

use assert_cmd::Command;
use common::{
    address, address_for, balance_map, balance_map_for, mount_balance, mount_balance_error,
    mount_unspent, mount_unspent_error, mount_unspent_for, stdin_low_entropy_seed_pass,
    stdin_seed_pass, stdin_seed_pass_for, utxo,
};
use predicates::boolean::PredicateBooleanExt;
use predicates::str::contains;
use wiremock::MockServer;

const UNREACHABLE: &str = "http://127.0.0.1:1";

fn yubtc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_yubtc"))
}

/// nonce 0: 100000 sat; nonce 1: used, empty; nonce 2+: unused.
async fn mixed_chain() -> MockServer {
    let server = MockServer::start().await;
    let received = balance_map(&[100_000, 500]);
    mount_balance(&server, &received).await;
    mount_unspent(&server, 0, &[utxo(0, 100_000)]).await;
    mount_unspent(&server, 1, &[]).await;
    mount_unspent(&server, 2, &[]).await;
    server
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn balance_funded_address_shows_amount_and_total() {
    let server = mixed_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["balance", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains(format!("0# {}: 0.00100000 BTC", address(0))))
        .stdout(contains(format!("2# {}: unused", address(2))))
        .stdout(contains("Total: 0.00100000\n"));
}

/// `-v` adds the per-UTXO breakdown line under the funded address.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn balance_verbose_lists_utxos() {
    let server = mixed_chain().await;
    let txid_hex = format!("{:0>64}", "0");

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["balance", "--provider", "mock", "--kdf", "pbkdf2", "-v"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains(format!("    ({txid_hex}:0): 0.00100000")))
        .stdout(contains("Total: 0.00100000\n"));
}

/// Default: the used-but-empty nonce 1 is skipped silently.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn balance_used_but_empty_skipped_by_default() {
    let server = mixed_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["balance", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains(format!("1# {}", address(1))).not());
}

/// `-e` shows the used-but-empty address with a zero balance (and
/// `-e -v` runs the per-UTXO loop over an empty list for it).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn balance_empty_flag_shows_used_but_empty_address() {
    let server = mixed_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args([
            "balance",
            "--provider",
            "mock",
            "--kdf",
            "pbkdf2",
            "-e",
            "-v",
        ])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains(format!("1# {}: 0.00000000 BTC", address(1))))
        .stdout(contains("Total: 0.00100000\n"));
}

/// Unfunded wallet: the single unused address is listed, total 0.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn balance_unfunded_wallet_shows_unused_and_zero_total() {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map(&[])).await;
    mount_unspent(&server, 0, &[]).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["balance", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains(format!("0# {}: unused", address(0))))
        .stdout(contains("Total: 0.00000000\n"));
}

/// UTXOs below the confirmations threshold are filtered out → the
/// address counts as zero-funded and (being used) is skipped.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn balance_confirmations_filter_excludes_shallow_utxo() {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map(&[100_000])).await;
    let shallow = common::MockUtxo {
        txid_hex: format!("{:0>64}", "7"),
        vout: 0,
        value: 100_000,
        confirmations: 2,
        legacy: false,
    };
    mount_unspent(&server, 0, &[shallow]).await;
    mount_unspent(&server, 1, &[]).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args([
            "balance",
            "--provider",
            "mock",
            "--kdf",
            "pbkdf2",
            "--confirmations",
            "6",
        ])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains(format!("0# {}", address(0))).not())
        .stdout(contains("Total: 0.00000000\n"));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn balance_unspent_http_error_is_network_error() {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map(&[100_000])).await;
    mount_unspent_error(&server, 500).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["balance", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("bad response: status 500"));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn balance_backend_http_error_is_network_error() {
    let server = MockServer::start().await;
    mount_balance_error(&server, 500).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["balance", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("bad response: status 500"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn balance_mock_provider_without_env_var_is_network_error() {
    yubtc()
        .env_remove("YUBTC_MOCK_BACKEND_URL")
        .args(["balance", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("YUBTC_MOCK_BACKEND_URL is not set"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn balance_empty_stdin_is_seed_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["balance", "--provider", "mock"])
        .assert()
        .failure()
        .stderr(contains("seed phrase is empty"));
}

/// Permissive default (R-1): an arbitrary non-BIP-39 phrase is
/// accepted and scanned like any other seed, with the non-blocking
/// R-6 warning (~90 bits) on stderr.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn balance_permissive_accepts_arbitrary_phrase_with_warning() {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map_for(common::ARBITRARY_PHRASE, &[])).await;
    mount_unspent_for(&server, common::ARBITRARY_PHRASE, 0, &[]).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["balance", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass_for(common::ARBITRARY_PHRASE))
        .assert()
        .success()
        .stderr(contains("warning: low entropy"))
        .stdout(contains(format!(
            "0# {}: unused",
            address_for(common::ARBITRARY_PHRASE, 0)
        )))
        .stdout(contains("Total: 0.00000000\n"));
}

/// Checksum-valid but low-entropy seed (abandon ×11 + about) is
/// rejected at reception by the strict C6 entropy floor — before the
/// backend registry is even consulted (no mock env var set here).
#[test]
#[ntest_timeout::timeout(30_000)]
fn balance_low_entropy_seed_rejected_at_reception() {
    yubtc()
        .env_remove("YUBTC_MOCK_BACKEND_URL")
        .args(["balance", "--provider", "mock", "--strict-bip39"])
        .write_stdin(stdin_low_entropy_seed_pass())
        .assert()
        .failure()
        .stderr(contains("entropy too low"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn balance_non_utf8_stdin_is_stdin_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["balance", "--provider", "mock"])
        .write_stdin([0xff, 0x0a])
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}
