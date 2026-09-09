//! `--retries` end-to-end (v0.3 resilience, specs/spec.md
//! «Network backends» → «Failover и retry»): the CLI flag must reach the backend's HTTP layer.
//!
//! Driven through `pushtx --provider mock`: the mock provider
//! (`YUBTC_MOCK_BACKEND_URL`) points at a wiremock server whose
//! `/pushtx` endpoint fails once (500) before succeeding, which pins
//! both the retry loop (a transient 5xx is survived) and the
//! `--retries 0` passthrough (a single attempt, v0.1 behaviour).
//!
//! `--provider auto` has no hermetic end-to-end here — it resolves to
//! the three production providers (the mock is excluded by design) —
//! so its acceptance is pinned at parse level (`cli.rs`) and its
//! behaviour exhaustively in `core/src/net/mod.rs` with fakes.

mod common;

use assert_cmd::Command;
use common::{mount_pushtx_ok, txid_of};
use predicates::str::contains;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn yubtc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_yubtc"))
}

const RAW_HEX: &str = "0102030405";

/// Mount a one-shot 500 in front of the happy `/pushtx` endpoint.
async fn mount_transient_500_then_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/pushtx"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(server)
        .await;
    mount_pushtx_ok(server).await;
}

/// A transient 500 on the first attempt is retried: the broadcast
/// lands on the second attempt and the command succeeds.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn pushtx_retries_a_transient_500_until_success() {
    let server = MockServer::start().await;
    mount_transient_500_then_ok(&server).await;
    let raw = hex::decode(RAW_HEX).expect("valid hex fixture");

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["pushtx", "-y", "--provider", "mock", "--retries", "1"])
        .write_stdin(format!("{RAW_HEX}\n"))
        .assert()
        .success()
        .stdout(contains(format!("id: {}", txid_of(&raw))));

    let requests = server.received_requests().await.expect("server alive");
    assert_eq!(requests.len(), 2, "one retry after the transient 500");
}

/// `--retries 0` is the v0.1 behaviour: exactly one attempt, the
/// transient 500 is NOT survived and the command fails with the
/// broadcast error mapping.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn pushtx_retries_zero_is_a_single_attempt() {
    let server = MockServer::start().await;
    mount_transient_500_then_ok(&server).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(["pushtx", "-y", "--provider", "mock", "--retries", "0"])
        .write_stdin(format!("{RAW_HEX}\n"))
        .assert()
        .failure()
        .code(1)
        .stderr(contains("broadcast failed: status=500"));

    let requests = server.received_requests().await.expect("server alive");
    assert_eq!(requests.len(), 1, "no retry with --retries 0");
}
