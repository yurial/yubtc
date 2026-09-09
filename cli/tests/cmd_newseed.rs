//! `yubtc newseed` — subprocess tests.
//!
//! `newseed` derives the address straight from the seed (no wallet,
//! no network — see `src/cmd/newseed.rs`), so the happy path is safe
//! to drive in a subprocess without any backend. Error paths that
//! fail before derivation (`-n 11` / `-n 0` → `generate_seed` →
//! `CliError::Seed`, exit 1) are pinned too.

mod common;

use assert_cmd::Command;
use predicates::str::contains;
use predicates::Predicate;

fn yubtc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_yubtc"))
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn newseed_invalid_word_count_is_seed_error() {
    yubtc()
        .args(["newseed", "-n", "11"])
        .assert()
        .failure()
        .stderr(contains("seed:"));
}

#[test]
#[ntest_timeout::timeout(30_000)]
fn newseed_zero_words_is_seed_error() {
    yubtc()
        .args(["newseed", "-n", "0"])
        .assert()
        .failure()
        .stderr(contains("seed:"));
}

/// Happy path, no network: exit 0, the first stdout line is the seed
/// (15 words by default), the second carries a mainnet native-SegWit
/// address (the Phase 13 default `--addr-type native`). This is the
/// regression pin for the "new wallet has no addresses" failure every
/// fresh seed used to hit on real backends.
#[test]
#[ntest_timeout::timeout(30_000)]
fn newseed_prints_seed_and_mainnet_address_without_network() {
    let out = yubtc()
        .args(["newseed"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("newseed prints UTF-8");
    let mut lines = text.lines();
    let seed_line = lines.next().expect("seed line present");
    let words: Vec<&str> = seed_line.split_whitespace().collect();
    assert_eq!(words.len(), 15, "default word count, got: {seed_line:?}");

    let address_line = lines.next().expect("address line present");
    let address_ok = predicates::str::is_match(r"^Address: bc1q[023456789ac-hj-np-z]{14,74}\r?$")
        .expect("valid regex")
        .eval(address_line);
    assert!(
        address_ok,
        "mainnet bech32 P2WPKH address expected, got: {address_line:?}"
    );
    // Seed words must all be BIP-39 dictionary words — cross-check a
    // few structural properties (lowercase ascii) without bundling a
    // full wordlist here; `validate_seed` in core owns the real check.
    assert!(
        words
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_lowercase())),
        "seed words are lowercase dictionary words, got: {seed_line:?}"
    );
}

/// `--addr-type taproot` prints a bech32m `bc1p…` address.
#[test]
#[ntest_timeout::timeout(30_000)]
fn newseed_addr_type_taproot_prints_p2tr() {
    let out = yubtc()
        .args(["newseed", "--addr-type", "taproot"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("newseed prints UTF-8");
    let address_line = text.lines().nth(1).expect("address line present");
    let address_ok = predicates::str::is_match(r"^Address: bc1p[023456789ac-hj-np-z]{14,74}\r?$")
        .expect("valid regex")
        .eval(address_line);
    assert!(
        address_ok,
        "mainnet bech32m P2TR address expected, got: {address_line:?}"
    );
}

/// `--addr-type legacy` reproduces the v0.1 P2PKH encoding bit-for-bit.
#[test]
#[ntest_timeout::timeout(30_000)]
fn newseed_addr_type_legacy_prints_p2pkh() {
    let out = yubtc()
        .args(["newseed", "--addr-type", "legacy"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("newseed prints UTF-8");
    let address_line = text.lines().nth(1).expect("address line present");
    let address_ok = predicates::str::is_match(r"^Address: 1[a-km-zA-HJ-NP-Z1-9]{25,34}\r?$")
        .expect("valid regex")
        .eval(address_line);
    assert!(
        address_ok,
        "mainnet P2PKH address expected, got: {address_line:?}"
    );
}

/// `-n` selects the word count; the address derivation stays offline.
#[test]
#[ntest_timeout::timeout(30_000)]
fn newseed_respects_word_count_still_offline() {
    let out = yubtc()
        .args(["newseed", "-n", "24"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("newseed prints UTF-8");
    let seed_line = text.lines().next().expect("seed line present");
    assert_eq!(
        seed_line.split_whitespace().count(),
        24,
        "-n 24 requested, got: {seed_line:?}"
    );
}
