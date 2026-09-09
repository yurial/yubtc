//! `yubtc send` — subprocess tests.
//!
//! Chain fixtures:
//! - **funded**: nonce 0 has one 100000-sat UTXO, nonce 1+ unused →
//!   wallet `[pk0, pk1]`, `scan_inputs_until` sources `[pk0]`.
//! - **unfunded**: every nonce unused → wallet `[pk0]`, no sources.
//!
//! Covered matrix: numeric amount / `ALL` (both cases) / zero /
//! garbage amounts; unset vs explicit vs overflow fee; `--scan`;
//! empty-source usage error; amount-exceeds-input wallet error;
//! `--broadcast` with `-y` / prompt `y` / `yes` / `n`; broadcast
//! server failure; `--interactive` headless (TUI raw-mode failure →
//! stdin error, "No funds available", insufficient target); provider
//! registry error; empty / non-UTF-8 stdin.
//!
//! The empty-privkeys guard in `run` is unreachable from the CLI:
//! `Wallet::new` is called with `new_addresses = 1`, so the wallet
//! always has at least one key after the gap stop.

mod common;

use assert_cmd::Command;
use common::{
    address, address_for, balance_map, balance_map_for, legacy_utxo, mount_balance,
    mount_pushtx_error, mount_pushtx_ok, mount_unspent, mount_unspent_error, mount_unspent_for,
    stdin_low_entropy_seed_pass, stdin_seed_pass, stdin_seed_pass_for, utxo,
};
use predicates::str::contains;
use wiremock::MockServer;

const UNREACHABLE: &str = "http://127.0.0.1:1";

fn yubtc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_yubtc"))
}

/// Destination outside the scanned wallet range.
fn dst() -> String {
    address(9)
}

/// `send` argv: mock provider, pbkdf2, extra flags, then the two
/// positionals (destination, amount).
fn send_cmd(amount: &str, extra: &[&str]) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "send".into(),
        "--provider".into(),
        "mock".into(),
        "--kdf".into(),
        "pbkdf2".into(),
    ];
    argv.extend(extra.iter().map(|s| s.to_string()));
    argv.push(dst());
    argv.push(amount.to_string());
    argv
}

async fn funded_chain() -> MockServer {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map(&[100_000])).await;
    mount_unspent(&server, 0, &[utxo(0, 100_000)]).await;
    // The wallet also carries the unused gap address (nonce 1);
    // `--scan` / `--interactive` fetch its (empty) unspent list too.
    mount_unspent(&server, 1, &[]).await;
    server
}

async fn unfunded_chain() -> MockServer {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map(&[])).await;
    // `--scan` / `--interactive` fetch the unspent list even for the
    // unused gap address.
    mount_unspent(&server, 0, &[]).await;
    server
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_numeric_amount_prints_signed_tx() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains(format!("Address: {}", address(0))))
        .stdout(contains("id: "))
        // Phase 13 announce: wire byte count + vsize lines.
        .stdout(contains("txsize="))
        .stdout(contains("vsize="))
        .stdout(contains("rawtx: "));

    // No --broadcast: the pushtx endpoint must stay untouched.
    for req in server.received_requests().await.expect("server alive") {
        assert_ne!(
            req.url.path(),
            "/pushtx",
            "no broadcast without --broadcast"
        );
    }
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_all_drains_wallet() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("ALL", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains("rawtx: "));
}

/// `all` (lowercase) hits the same `eq_ignore_ascii_case` arm.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_lowercase_all_drains_wallet() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("all", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains("rawtx: "));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_explicit_fee_is_accepted() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--fee", "0.0001"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains("rawtx: "));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_amount_zero_is_usage_error() {
    let server = unfunded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("amount must be > 0 (use ALL to drain)"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn send_rejects_a_p2wsh_recipient_with_the_typed_error() {
    // v0.3 unlocked P2WSH lock scripts in the core for the multisig
    // quorum surface, but the documented Phase-13 recipient policy of
    // the personal `send` is unchanged: a `bc1q…` address with a
    // 32-byte program refuses with the pre-v0.3 typed message
    // (`SegWitAddrError::UnsupportedProgram` through AddressDecode).
    // BIP-173 P2WSH test vector address.
    let p2wsh = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    let mut argv = vec![
        "send".to_string(),
        "--provider".to_string(),
        "mock".to_string(),
    ];
    argv.push(p2wsh.to_string());
    argv.push("0.0005".to_string());
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(&argv)
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains(
            "address could not be decoded: P2WSH addresses (witness v0, 32-byte program) \
             are out of scope",
        ));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_amount_garbage_is_usage_error() {
    let server = unfunded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("abc", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("amount:"));
}

/// A fee whose 8-decimal formatting overflows u64 satoshi → usage
/// error from the `fee:` mapping.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_fee_overflow_is_usage_error() {
    let server = unfunded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--fee", "1e60"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("fee:"));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_scan_prints_per_address_report() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--scan"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains(format!("0# {}: 0.00100000 BTC", address(0))))
        .stdout(contains(format!("1# {}: 0.00000000 BTC", address(1))))
        .stdout(contains("rawtx: "));
}

/// Scan report on an unfunded wallet (all-zero lines), then the
/// empty-sources usage error terminates the send.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_scan_unfunded_then_no_utxos_error() {
    let server = unfunded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--scan"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("insufficient funds: no UTXOs in wallet"))
        .stdout(contains(format!("0# {}: 0.00000000 BTC", address(0))));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_unfunded_wallet_is_no_utxos_usage_error() {
    let server = unfunded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("ALL", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("insufficient funds: no UTXOs in wallet"));
}

/// Funded wallet but target above total: the gap scan returns sources
/// and `make_vout` rejects with AmountExceedsInput (wallet error).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_amount_exceeds_input_is_wallet_error() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.005", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("amount + fee exceeds input"));
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_broadcast_with_yes_flag_posts_signed_tx() {
    let server = funded_chain().await;
    mount_pushtx_ok(&server).await;

    let output = yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--broadcast", "-y"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // The broadcast form body must carry exactly the printed raw tx.
    let text = String::from_utf8(output).expect("stdout is utf-8");
    let rawtx = text
        .lines()
        .find(|l| l.starts_with("rawtx: "))
        .expect("rawtx line")
        .trim_start_matches("rawtx: ");
    hex::decode(rawtx).expect("rawtx is valid hex");
    let requests = server.received_requests().await.expect("server alive");
    let push: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path() == "/pushtx")
        .collect();
    assert_eq!(push.len(), 1, "one broadcast");
    assert_eq!(
        String::from_utf8_lossy(&push[0].body),
        format!("tx={rawtx}")
    );
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_broadcast_prompt_yes_posts_tx() {
    let server = funded_chain().await;
    mount_pushtx_ok(&server).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--broadcast"]))
        .write_stdin(format!("{}y\n", stdin_seed_pass()))
        .assert()
        .success()
        .stdout(contains("broadcast? "));

    let requests = server.received_requests().await.expect("server alive");
    assert!(
        requests.iter().any(|r| r.url.path() == "/pushtx"),
        "broadcast after y"
    );
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_broadcast_prompt_yes_word_posts_tx() {
    let server = funded_chain().await;
    mount_pushtx_ok(&server).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--broadcast"]))
        .write_stdin(format!("{}yes\n", stdin_seed_pass()))
        .assert()
        .success();

    let requests = server.received_requests().await.expect("server alive");
    assert!(
        requests.iter().any(|r| r.url.path() == "/pushtx"),
        "broadcast after yes"
    );
}

/// Declining keeps exit code 0; the tx is printed before the prompt.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_broadcast_prompt_no_declines_but_prints_tx() {
    let server = funded_chain().await;
    mount_pushtx_ok(&server).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--broadcast"]))
        .write_stdin(format!("{}n\n", stdin_seed_pass()))
        .assert()
        .code(0)
        .stdout(contains("rawtx: "))
        .stderr(contains("broadcast declined"));

    let requests = server.received_requests().await.expect("server alive");
    assert!(
        !requests.iter().any(|r| r.url.path() == "/pushtx"),
        "no broadcast after n"
    );
}

#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_broadcast_server_error_is_network_error() {
    let server = funded_chain().await;
    mount_pushtx_error(&server, 500).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--broadcast", "-y"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("broadcast failed: status=500"));
}

/// `--interactive` with funds reaches the Coin Control TUI, which
/// cannot start without a terminal → mapped to a stdin error (1).
// Unix-only: the headless Coin Control TUI contract relies on
// terminal init failing fast; on Windows crossterm succeeds without
// a console and the event read blocks (see cli/src/cmd/tui.rs).
#[cfg(unix)]
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_interactive_headless_is_stdin_error() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--interactive"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}

/// Drain + `--interactive`: `amount_sat` is `None`, so the target
/// check is skipped entirely before the same headless TUI failure.
// Unix-only: the headless Coin Control TUI contract relies on
// terminal init failing fast; on Windows crossterm succeeds without
// a console and the event read blocks (see cli/src/cmd/tui.rs).
#[cfg(unix)]
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_interactive_all_headless_is_stdin_error() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("ALL", &["--interactive"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}

/// `--interactive -y`: `broadcast || yes` sees `yes = true` with
/// `--broadcast` unset (the RHS-true arm) before the TUI failure.
// Unix-only: the headless Coin Control TUI contract relies on
// terminal init failing fast; on Windows crossterm succeeds without
// a console and the event read blocks (see cli/src/cmd/tui.rs).
#[cfg(unix)]
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_interactive_yes_flag_headless_is_stdin_error() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--interactive", "-y"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}

/// `--interactive --broadcast`: `broadcast || yes` short-circuits on
/// the LHS before the TUI failure.
// Unix-only: the headless Coin Control TUI contract relies on
// terminal init failing fast; on Windows crossterm succeeds without
// a console and the event read blocks (see cli/src/cmd/tui.rs).
#[cfg(unix)]
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_interactive_broadcast_flag_headless_is_stdin_error() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--interactive", "--broadcast"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}

/// `--interactive --scan`: report first, then the same TUI failure.
// Unix-only: the headless Coin Control TUI contract relies on
// terminal init failing fast; on Windows crossterm succeeds without
// a console and the event read blocks (see cli/src/cmd/tui.rs).
#[cfg(unix)]
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_interactive_with_scan_prints_report_then_fails() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--scan", "--interactive"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stdout(contains(format!("0# {}: 0.00100000 BTC", address(0))))
        .stderr(contains("stdin:"));
}

/// `--interactive` with an unfunded wallet exits 0 with the message.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_interactive_no_funds_is_ok() {
    let server = unfunded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--interactive"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .stdout(contains("No funds available"));
}

/// `--interactive` with target above the available total bails out
/// before the UI with a usage error (exit 1).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_interactive_insufficient_target_is_usage_error() {
    let server = funded_chain().await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.005", &["--interactive"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains(
            "insufficient funds: target 500000 sat, available 100000 sat",
        ));
}

/// Legacy-form UTXO spent to a `bc1p…` (P2TR) recipient: the scan
/// finds the P2PKH UTXO via its form, `build_vin` signs it with the
/// legacy scheme, and the recipient lock script is the 34-byte P2TR
/// witness program. Witness-free tx → the wire payload equals the
/// stripped layout (v0.1 byte-for-byte).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_legacy_utxo_to_taproot_dst() {
    let server = MockServer::start().await;
    let mut received = balance_map(&[]);
    common::balance_map_with_legacy_used(&mut received, common::SEED, 0, 100_000);
    mount_balance(&server, &received).await;
    mount_unspent(&server, 0, &[legacy_utxo(0, 100_000)]).await;

    let mut argv: Vec<String> = vec![
        "send".into(),
        "--provider".into(),
        "mock".into(),
        "--kdf".into(),
        "pbkdf2".into(),
        "--addr-type".into(),
        "legacy".into(),
    ];
    argv.push(common::taproot_address_for(common::SEED, 9));
    argv.push("ALL".into());

    let output = yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(&argv)
        .write_stdin(stdin_seed_pass())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).expect("stdout is utf-8");
    let rawtx = text
        .lines()
        .find(|l| l.starts_with("rawtx: "))
        .expect("rawtx line")
        .trim_start_matches("rawtx: ");
    let bytes = hex::decode(rawtx).expect("rawtx is valid hex");
    // No witness → no marker/flag: byte 4 is the vin count (0x01),
    // not the BIP-144 marker (0x00).
    assert_eq!(bytes[4], 0x01);
    // The single output pays to a P2TR script (51 20 …). Layout:
    // … vout = amount(8) + script-len(1) + script(34), then
    // locktime(4) → the script occupies the last 38 bytes.
    let n = bytes.len();
    assert_eq!(&bytes[n - 38..n - 36], &[0x51, 0x20]);
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn send_mock_provider_without_env_var_is_network_error() {
    yubtc()
        .env_remove("YUBTC_MOCK_BACKEND_URL")
        .args(send_cmd("0.0005", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stderr(contains("YUBTC_MOCK_BACKEND_URL is not set"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn send_empty_stdin_is_seed_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(send_cmd("0.0005", &[]))
        .assert()
        .failure()
        .stderr(contains("seed phrase is empty"));
}

/// Permissive default (R-1): an arbitrary non-BIP-39 phrase builds
/// and signs like any other seed, with the non-blocking R-6 warning
/// (~90 bits) on stderr. The destination and the funded UTXO follow
/// the arbitrary seed via the `_for` fixtures.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_permissive_accepts_arbitrary_phrase_with_warning() {
    let arb = common::ARBITRARY_PHRASE;
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map_for(arb, &[100_000])).await;
    mount_unspent_for(&server, arb, 0, &[utxo(0, 100_000)]).await;
    mount_unspent_for(&server, arb, 1, &[]).await;

    let mut argv: Vec<String> = vec![
        "send".into(),
        "--provider".into(),
        "mock".into(),
        "--kdf".into(),
        "pbkdf2".into(),
    ];
    argv.push(address_for(arb, 9));
    argv.push("ALL".into());

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(&argv)
        .write_stdin(stdin_seed_pass_for(arb))
        .assert()
        .success()
        .stderr(contains("warning: low entropy"))
        .stdout(contains(format!("Address: {}", address_for(arb, 0))))
        .stdout(contains("rawtx: "));
}

/// Checksum-valid but low-entropy seed (abandon ×11 + about) is
/// rejected at reception by the strict C6 entropy floor — before the
/// backend registry is even consulted (no mock env var set here).
#[test]
#[ntest_timeout::timeout(30_000)]
fn send_low_entropy_seed_rejected_at_reception() {
    yubtc()
        .env_remove("YUBTC_MOCK_BACKEND_URL")
        .args(send_cmd("0.0005", &["--strict-bip39"]))
        .write_stdin(stdin_low_entropy_seed_pass())
        .assert()
        .failure()
        .stderr(contains("entropy too low"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn send_non_utf8_stdin_is_stdin_error() {
    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", UNREACHABLE)
        .args(send_cmd("0.0005", &[]))
        .write_stdin([0xff, 0x0a])
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}

/// Non-UTF-8 broadcast answer fails `finish`'s `read_line`.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_broadcast_non_utf8_answer_is_stdin_error() {
    let server = funded_chain().await;
    mount_pushtx_ok(&server).await;
    let mut stdin = stdin_seed_pass().into_bytes();
    stdin.extend_from_slice(&[0xff, 0x0a]);

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--broadcast"]))
        .write_stdin(stdin)
        .assert()
        .failure()
        .stderr(contains("stdin:"));
}

/// `prompt_seed` is the first statement of `run` and writes the seed
/// prompt to stdout. Redirecting stdout to `/dev/full` makes every
/// write fail with `ENOSPC`, so the `prompt_seed()?` error arm fires
/// before anything else runs.
///
/// `/dev/full` is a Linux device (macOS and Windows don't have it),
/// so the trick — and the test — is Linux-only. The ubuntu CI leg
/// keeps the behaviour pinned; the coverage pipeline also runs there.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_unwritable_stdout_is_stdin_error() {
    let server = funded_chain().await;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_yubtc"))
        .args(send_cmd("0.0005", &[]))
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .stdout(std::process::Stdio::from(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full exists on Linux"),
        ))
        .output()
        .expect("binary spawns");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("stdin:"), "stderr: {stderr}");
}

/// `scan_inputs_until` re-queries `/balance` after `Wallet::new`'s
/// own scan. Serve the balance endpoint twice (enough for the
/// construction scan: nonce 0 used, nonce 1 unused), then fail with
/// 500 — the lazy scan inside `run` errors through its `?` arm.
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_balance_dying_mid_scan_is_network_error() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = MockServer::start().await;
    // First five balance requests succeed (the Wallet::new walk is
    // multi-form since Phase 13: nonce 0's legacy form is unused but
    // its native form used — 2 requests — then nonce 1's three forms
    // are all unused — 3 requests), the rest fail — wiremock falls
    // through to the later-mounted mock once `up_to_n_times` is
    // exhausted, so the lazy re-scan inside `run` is the first to see
    // the 500.
    let mut obj = serde_json::Map::new();
    for (addr, tr) in balance_map(&[100_000]) {
        let mut entry = serde_json::Map::new();
        entry.insert("total_received".to_string(), tr.into());
        entry.insert("final_balance".to_string(), tr.into());
        entry.insert("n_tx".to_string(), u64::from(tr > 0).into());
        obj.insert(addr, serde_json::Value::Object(entry));
    }
    Mock::given(method("GET"))
        .and(path("/balance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::Value::Object(obj)))
        .up_to_n_times(5)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/balance"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &[]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        // `Address:` proves Wallet::new completed; the failure comes
        // from the lazy scan that follows it.
        .stdout(contains("Address: "))
        .stderr(contains("wallet: network error: bad response: status 500"));
}

/// `--scan` after a successful wallet construction, with `/unspent`
/// failing: `print_scan_report`'s error propagates through its `?`
/// arm in `run` (exit 1, wallet error).
#[tokio::test]
#[ntest_timeout::timeout(30_000)]
async fn send_scan_unspent_failure_is_wallet_error() {
    let server = MockServer::start().await;
    mount_balance(&server, &balance_map(&[100_000])).await;
    mount_unspent_error(&server, 500).await;

    yubtc()
        .env("YUBTC_MOCK_BACKEND_URL", server.uri())
        .args(send_cmd("0.0005", &["--scan"]))
        .write_stdin(stdin_seed_pass())
        .assert()
        .failure()
        .stdout(contains("Address: "))
        .stderr(contains("wallet: network error: bad response: status 500"));
}
