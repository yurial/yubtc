//! `yubtc pushtx` — subprocess tests against a wiremock backend.
//!
//! Covers the full `run()` matrix: happy broadcast (`-y`), the
//! confirmation prompt (y / yes / no arms), the "no transaction on
//! stdin" and "invalid hex on stdin" usage errors, the invalid-UTF-8
//! stdin read error, the missing `YUBTC_MOCK_BACKEND_URL` provider
//! error, and a failing broadcast endpoint. Also pins the printed
//! `id:` (reversed double-SHA256) / `txsize=` / `rawtx:` values.
//!
//! Tests that fail before any HTTP request use an unreachable mock
//! URL: `get_backend("mock")` only requires the env var to be set —
//! connectivity is checked lazily at broadcast time.

mod common;

use assert_cmd::Command;
use common::{mount_pushtx_error, mount_pushtx_ok, txid_of};
use predicates::str::{contains, is_match};
use wiremock::MockServer;

/// URL that always refuses TCP connections (provider resolution
/// succeeds; any actual request would fail fast).
const UNREACHABLE: &str = "http://127.0.0.1:1";

fn yubtc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_yubtc"))
}

/// `pushtx -y` with a happy `/pushtx`: exit 0, txid/txsize/rawtx
/// printed, and the form body `tx=<hex>` actually reaches the server.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn pushtx_yes_flag_broadcasts_and_prints_txid() {
    let server = MockServer::start().await;
    mount_pushtx_ok(&server).await;
    let raw_hex = "0102030405";
    let raw = hex::decode(raw_hex).expect("valid hex fixture");

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["pushtx", "-y", "--provider", "mock"])
        .write_stdin(format!("{raw_hex}\n"))
        .assert()
        .success()
        .stdout(contains(format!("id: {}", txid_of(&raw))))
        .stdout(contains("txsize=5\n"))
        .stdout(contains(format!("rawtx: {raw_hex}")));

    let requests = server.received_requests().await.expect("server alive");
    assert_eq!(requests.len(), 1, "exactly one broadcast");
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_eq!(requests[0].url.path(), "/pushtx");
    assert_eq!(
        String::from_utf8_lossy(&requests[0].body),
        format!("tx={raw_hex}")
    );
}

/// Prompt path answering `y`: broadcast goes through.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn pushtx_prompt_yes_broadcasts() {
    let server = MockServer::start().await;
    mount_pushtx_ok(&server).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["pushtx", "--provider", "mock"])
        .write_stdin("0102\ny\n")
        .assert()
        .success()
        .stdout(contains("broadcast? "));

    assert_eq!(
        server
            .received_requests()
            .await
            .expect("server alive")
            .len(),
        1,
        "broadcast after y"
    );
}

/// Prompt path answering `YES` (case-insensitive `yes` arm).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn pushtx_prompt_yes_word_case_insensitive_broadcasts() {
    let server = MockServer::start().await;
    mount_pushtx_ok(&server).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["pushtx", "--provider", "mock"])
        .write_stdin("0102\nYES\n")
        .assert()
        .success();

    assert_eq!(
        server
            .received_requests()
            .await
            .expect("server alive")
            .len(),
        1,
        "broadcast after YES"
    );
}

/// Prompt path answering `n`: `BroadcastDeclined` — exit code 0 with
/// the decline message on stderr, nothing broadcast.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn pushtx_prompt_no_declines_with_exit_zero() {
    let server = MockServer::start().await;
    mount_pushtx_ok(&server).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["pushtx", "--provider", "mock"])
        .write_stdin("0102\nn\n")
        .assert()
        .code(0)
        .stderr(contains("broadcast declined"));

    assert!(
        server
            .received_requests()
            .await
            .expect("server alive")
            .is_empty(),
        "no broadcast after n"
    );
}

/// Invalid hex on stdin → usage error (exit 1).
#[test]
#[ntest_timeout::timeout(30_000)]
fn pushtx_invalid_hex_is_usage_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["pushtx", "-y", "--provider", "mock"])
        .write_stdin("zzzz\n")
        .assert()
        .failure()
        .stderr(contains("invalid hex on stdin"));
}

/// Whitespace-only line trims to "no transaction on stdin" (exit 1).
#[test]
#[ntest_timeout::timeout(30_000)]
fn pushtx_whitespace_only_stdin_is_no_transaction() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["pushtx", "-y", "--provider", "mock"])
        .write_stdin("   \n")
        .assert()
        .failure()
        .stderr(contains("no transaction on stdin"));
}

/// EOF (empty stdin) → "no transaction on stdin" (exit 1).
#[test]
#[ntest_timeout::timeout(30_000)]
fn pushtx_empty_stdin_is_no_transaction() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["pushtx", "-y", "--provider", "mock"])
        .assert()
        .failure()
        .stderr(contains("no transaction on stdin"));
}

/// Non-UTF-8 first line makes `read_line` fail → stdin error (exit 1).
#[test]
#[ntest_timeout::timeout(30_000)]
fn pushtx_non_utf8_tx_line_is_stdin_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(["pushtx", "-y", "--provider", "mock"])
        .write_stdin([0xff, 0x0a])
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}

/// Non-UTF-8 answer line fails the second `read_line` → stdin error.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn pushtx_non_utf8_answer_line_is_stdin_error() {
    let server = MockServer::start().await;
    mount_pushtx_ok(&server).await;
    let mut stdin = b"0102\n".to_vec();
    stdin.extend_from_slice(&[0xff, 0x0a]);

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["pushtx", "--provider", "mock"])
        .write_stdin(stdin)
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}

/// `--provider mock` without `YUBTC_MOCK_BACKEND_URL` → provider
/// registry error surfaces as a network error (exit 1).
#[test]
#[ntest_timeout::timeout(30_000)]
fn pushtx_mock_provider_without_env_var_is_network_error() {
    yubtc()
        .env_remove("YUBTC_MOCK_BACKEND_URL")
        .args(["pushtx", "-y", "--provider", "mock"])
        .write_stdin("0102\n")
        .assert()
        .failure()
        .stderr(contains("YUBTC_MOCK_BACKEND_URL is not set"));
}

/// Broadcast endpoint returns 500 → `NetError::Broadcast` → exit 1
/// with the status and body in the message.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn pushtx_broadcast_rejected_by_server_is_network_error() {
    let server = MockServer::start().await;
    mount_pushtx_error(&server, 500).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["pushtx", "-y", "--provider", "mock"])
        .write_stdin("0102\n")
        .assert()
        .failure()
        .stderr(is_match(r"network: broadcast failed: status=500").expect("regex is valid"));
}
