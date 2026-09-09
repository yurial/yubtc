#![no_main]

//! BIP-39 mnemonic validation fuzz target.
//!
//! Drives `seed::validate_seed` with arbitrary bytes interpreted as
//! UTF-8 strings. The harness is the only place we feed truly
//! untrusted text into the wallet's mnemonic parser; everywhere
//! else, the input comes from the user typing a phrase they (should
//! have) written down.
//!
//! `validate_seed` is pure and never panics — it returns
//! `Result<(), SeedError>` for every malformed input. We use the
//! `Arbitrary` `String` rather than raw `&[u8]` because the
//! `bip39` crate's parser expects UTF-8 whitespace-separated words;
//! fuzzing raw bytes would just exercise the UTF-8 validation
//! before the BIP-39 logic kicks in.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Cap the input size so a runaway corpus can't drag the harness
    // down — BIP-39 phrases are 12-24 words, well under 1 KiB.
    if data.len() > 4096 {
        return;
    }
    // Non-UTF-8 inputs are rejected by `String::from_utf8` before
    // the validator runs, so we just skip them.
    let Ok(phrase) = std::str::from_utf8(data) else {
        return;
    };
    // The validator must NEVER panic — `Result` covers every failure.
    let _ = yubtc_core::seed::validate_seed(&yubtc_core::misc::TSeed(phrase.to_string()));
});
