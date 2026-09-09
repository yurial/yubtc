//! `yubtc address` — subprocess tests.
//!
//! Happy path (seed + passphrase piped, pbkdf2, mock backend with a
//! zero-balance gap scan) prints exactly the deterministic fixture
//! address. Error paths: `--new 0` (empty-privkeys guard), mock
//! provider without the env var (registry error), empty stdin
//! (reception error in both modes), low-entropy seed under
//! `--strict-bip39` (blocking strict rejection, before backend
//! resolution), non-UTF-8 stdin (read failure), and the
//! yubtc-KDF-with-passphrase incompatibility. Permissive-reception
//! tests (C8): an arbitrary non-BIP-39 phrase and the low-entropy
//! BIP-39 vector are both accepted without the flag.

mod common;

use assert_cmd::Command;
use common::{
    address, address_for, balance_map, balance_map_for, mount_balance, stdin_low_entropy_seed_pass,
    stdin_seed_pass, stdin_seed_pass_for, SEED,
};
use predicates::boolean::PredicateBooleanExt;
use predicates::str::contains;
use wiremock::MockServer;

const UNREACHABLE: &str = "http://127.0.0.1:1";

fn yubtc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_yubtc"))
}

/// Zero-balance mock: every scanned address unused → the wallet scan
/// stops at nonce 0 and `--new 1` appends it.
async fn zero_chain() -> MockServer {
    let server = MockServer::start().await;
    let received = balance_map(&[]);
    mount_balance(&server, &received).await;
    server
}

/// Asserts the full stdout: the `Seed: ` prompt followed by the
/// address line.
fn assert_address_stdout(cmd_out: &[u8], expected: &str) {
    assert_eq!(
        String::from_utf8_lossy(cmd_out),
        format!("Seed: {expected}\n")
    );
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn address_prints_deterministic_fixture_address() {
    let server = zero_chain().await;

    let out = yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["address", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_address_stdout(&out, &address(0));
}

/// `--nonce 5` shifts the scan; the printed address is nonce 5.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn address_nonce_flag_selects_address() {
    let server = zero_chain().await;

    let out = yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args([
            "address",
            "--provider",
            "mock",
            "--kdf",
            "pbkdf2",
            "--nonce",
            "5",
        ])
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_address_stdout(&out, &address(5));
}

/// `--addr-type` selects the receive-address encoding (Phase 13).
/// The zero-balance mock covers every form of nonces 0..8, so all
/// three types scan cleanly against it.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn address_addr_type_flag_selects_encoding() {
    let server = zero_chain().await;

    for (flag, expected) in [
        ("native", common::address(0)),
        ("taproot", common::taproot_address_for(common::SEED, 0)),
        ("legacy", common::legacy_address_for(common::SEED, 0)),
    ] {
        let out = yubtc()
            .env("YUBTC_MOCK_BACKEND_URL", server.uri())
            .args([
                "address",
                "--provider",
                "mock",
                "--kdf",
                "pbkdf2",
                "--addr-type",
                flag,
            ])
            .write_stdin(stdin_seed_pass())
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        assert_address_stdout(&out, &expected);
    }
}

/// `--new 0` leaves the wallet with no addresses after the gap stop →
/// `CliError::Wallet("new wallet has no addresses")` (exit 1).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn address_new_zero_hits_empty_privkeys_guard() {
    let server = zero_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args([
            "address",
            "--provider",
            "mock",
            "--kdf",
            "pbkdf2",
            "--new",
            "0",
        ])
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("new wallet has no addresses"));
}

/// `--provider mock` without the env var → network error (exit 1)
/// before anything else happens.
#[test]
#[ntest_timeout::timeout(30_000)]
fn address_mock_provider_without_env_var_is_network_error() {
    yubtc()
        .env_remove("YUBTC_MOCK_BACKEND_URL")
        .args(["address", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("YUBTC_MOCK_BACKEND_URL is not set"));
}

/// Empty stdin → empty seed → rejected at reception in both modes
/// (R-2), before backend resolution (exit 1). This exercises the
/// permissive default; `--strict-bip39` adds nothing for the empty
/// phrase.
#[test]
#[ntest_timeout::timeout(30_000)]
fn address_empty_stdin_is_seed_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["address", "--provider", "mock"])
        .assert()
        .failure()
        .stderr(contains("seed phrase is empty"));
}

/// Permissive default (R-1): an arbitrary non-BIP-39 phrase is
/// accepted and derived like any other seed. Its short text
/// estimates ~90 bits, so the non-blocking R-6 warning accompanies
/// the success on stderr.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn address_permissive_accepts_arbitrary_phrase_with_warning() {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map_for(common::ARBITRARY_PHRASE, &[])).await;

    let out = yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["address", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_seed_pass_for(common::ARBITRARY_PHRASE))
        .assert()
        .success()
        .stderr(contains("warning: low entropy"))
        .get_output()
        .stdout
        .clone();
    assert_address_stdout(&out, &address_for(common::ARBITRARY_PHRASE, 0));
}

/// Permissive default (R-1): the checksum-valid but entropy-floor
/// failing BIP-39 vector (abandon ×11 + about) is accepted WITHOUT
/// the warning — its long lowercase text estimates ~442 bits, far
/// above the R-6 threshold. The same input under `--strict-bip39`
/// is rejected below.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn address_permissive_accepts_low_entropy_bip39_vector_silently() {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map_for(common::LOW_ENTROPY_SEED, &[])).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["address", "--provider", "mock", "--kdf", "pbkdf2"])
        .write_stdin(stdin_low_entropy_seed_pass())
        .assert()
        .success()
        .stderr(contains("warning").not())
        .stdout(contains(address_for(common::LOW_ENTROPY_SEED, 0)));
}

/// Checksum-valid but low-entropy seed (abandon ×11 + about) is
/// rejected at reception by the strict C6 entropy floor — before the
/// backend registry is even consulted (no mock env var set here).
#[test]
#[ntest_timeout::timeout(30_000)]
fn address_low_entropy_seed_rejected_at_reception() {
    yubtc()
        .env_remove("YUBTC_MOCK_BACKEND_URL")
        .args(["address", "--provider", "mock", "--strict-bip39"])
        .write_stdin(stdin_low_entropy_seed_pass())
        .assert()
        .failure()
        .stderr(contains("entropy too low"));
}

/// Non-UTF-8 seed line → stdin read failure (exit 1).
#[test]
#[ntest_timeout::timeout(30_000)]
fn address_non_utf8_stdin_is_stdin_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["address", "--provider", "mock"])
        .write_stdin([0xff, 0x0a])
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}

/// Explicit `--kdf yubtc` with a non-empty passphrase is rejected by
/// the KDF layer (passphrase-free cascade) → wallet error (exit 1).
#[test]
#[ntest_timeout::timeout(30_000)]
fn address_yubtc_kdf_with_passphrase_is_wallet_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["address", "--provider", "mock", "--kdf", "yubtc"])
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("passphrase"));
}

/// Auto KDF with an empty passphrase line picks the yubtc cascade
/// and still succeeds (second line blank).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn address_auto_kdf_empty_passphrase_uses_yubtc() {
    // Yubtc-cascade addresses differ from the pbkdf2 fixture, so the
    // balance map is rebuilt from the yubtc keys.
    use std::collections::BTreeMap;
    use yubtc_core::kdf::KdfAlgo;
    use yubtc_core::misc::{TNonce, TPassphrase, TSeed};

    // Variant A (spec ОВ-2): the cascade key is the SAME for every
    // address form — only the encoding differs. The multi-form scan
    // queries all three, so the map must carry every form.
    let key_at = |nonce: u32| {
        yubtc_core::wallet::TPrivKey::new(
            &TSeed::new(SEED),
            TNonce::new(nonce),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
        )
        .expect("fixture derivation is deterministic")
    };
    // The CLI default is `--addr-type native`: expect the segwit
    // encoding of the same cascade key.
    let expected = key_at(0)
        .address_of(yubtc_core::wallet::AddrType::Native)
        .expect("variant-A keys encode in every form");

    let server = MockServer::start().await;
    let mut received = BTreeMap::new();
    for nonce in 0..10u32 {
        for form in yubtc_core::wallet::AddrType::ALL {
            let addr = key_at(nonce)
                .address_of(form)
                .expect("variant-A keys encode in every form");
            received.insert(addr.as_str().to_string(), 0);
        }
    }
    mount_balance(&server, &received).await;

    let out = yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["address", "--provider", "mock"])
        .write_stdin(format!("{SEED}\n\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_address_stdout(&out, expected.as_str());
}
