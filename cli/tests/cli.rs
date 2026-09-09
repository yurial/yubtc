//! End-to-end checks on the `yubtc` binary itself.
//!
//! Phase 5 turned the binary from a "loud no-op" placeholder into a
//! real clap-driven CLI. These tests pin the parts that should never
//! regress:
//!
//! - bare invocation (`yubtc`) exits with clap's usage-error code (2)
//!   because no subcommand was supplied;
//! - `--help` succeeds and prints the help text;
//! - unknown subcommands are rejected by clap (exit code 2, "error:
//!   unrecognized subcommand 'foo'") — a typo never silently no-ops;
//! - `--version` succeeds and prints the package version.

use assert_cmd::Command;
use predicates::str::contains;

fn yubtc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_yubtc"))
}

#[test]
fn bare_invocation_fails_with_usage_code() {
    // clap exits with code 2 when a required argument is missing
    // (no subcommand → no `command` argument). It writes the usage
    // help to stderr before exiting.
    yubtc()
        .assert()
        .failure()
        .code(2)
        .stderr(contains("Usage:"));
}

#[test]
fn unknown_subcommand_is_rejected() {
    yubtc()
        .arg("frobnicate")
        .assert()
        .failure()
        .stderr(contains("unrecognized subcommand"));
}

#[test]
fn help_prints_command_list() {
    yubtc()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("newseed"))
        .stdout(contains("address"))
        .stdout(contains("balance"))
        .stdout(contains("send"))
        .stdout(contains("dumpprivkey"))
        .stdout(contains("pushtx"));
}

#[test]
fn version_prints_package_version() {
    yubtc()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_for_send_lists_flags() {
    yubtc()
        .arg("send")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("--provider"))
        .stdout(contains("--broadcast"))
        .stdout(contains("--interactive"))
        .stdout(contains("--scan"));
}

// --- v0.3 resilience flags (--retries, --provider auto) -------------

#[test]
fn help_lists_retries_and_auto_provider() {
    // Every network command carries the shared provider group; pin
    // the new v0.3 surface on one of them.
    yubtc()
        .arg("balance")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("--retries"))
        .stdout(contains("auto"));
}

#[test]
fn provider_auto_and_retries_zero_are_accepted() {
    // Parse-level acceptance: `balance` prompts for the seed BEFORE
    // resolving the backend, so an empty stdin fails cleanly at the
    // seed prompt (exit 1) — proving clap accepted `auto` and
    // `--retries 0` without touching any network.
    yubtc()
        .args(["balance", "--provider", "auto", "--retries", "0"])
        .write_stdin("")
        .assert()
        .failure()
        .code(1)
        .stderr(contains("seed phrase is empty"));
}

#[test]
fn retries_rejects_non_numeric_value() {
    yubtc()
        .args(["balance", "--retries", "not-a-number"])
        .assert()
        .failure()
        .code(2)
        .stderr(contains("invalid value"));
}

#[test]
fn retries_rejects_negative_value() {
    // `--retries` is a count; clap rejects a negative before the
    // value parser is ever consulted.
    yubtc()
        .args(["balance", "--retries", "-1"])
        .assert()
        .failure()
        .code(2)
        .stderr(contains("unexpected argument '-1'"));
}

/// Logging policy (C7): `YUBTC_LOG=debug` turns on the subscriber —
/// the `dispatching` event from `main` reaches stderr. Private
/// material never appears (no event carries seed/passphrase/WIF
/// fields; the command event only names the subcommand enum).
#[test]
#[ntest_timeout::timeout(30_000)]
fn yubtc_log_debug_emits_events_to_stderr() {
    yubtc()
        .env("YUBTC_LOG", "debug")
        .arg("newseed")
        .assert()
        .success()
        .stderr(contains("dispatching"))
        .stderr(contains("yubtc"));
}

/// Without `YUBTC_LOG` a debug binary (what the tests run) installs
/// the `debug`-level default — pinned so the policy's debug-build
/// default can't silently rot. (The release profile compiles the
/// default out entirely.)
#[test]
#[ntest_timeout::timeout(30_000)]
fn debug_build_logs_at_debug_by_default() {
    yubtc()
        .arg("newseed")
        .assert()
        .success()
        .stderr(contains("dispatching"))
        .stderr(contains("yubtc"));
}

/// An invalid `YUBTC_LOG` value falls back to the debug default
/// instead of aborting — a typo in a debug knob must not take the
/// wallet down.
#[test]
#[ntest_timeout::timeout(30_000)]
fn yubtc_log_invalid_value_falls_back_to_default() {
    yubtc()
        .env("YUBTC_LOG", "not-a-level")
        .arg("newseed")
        .assert()
        .success()
        .stderr(contains("dispatching"))
        .stderr(contains("yubtc"));
}
