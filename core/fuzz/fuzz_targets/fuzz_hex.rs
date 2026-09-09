#![no_main]

//! Hex decoding fuzz target.
//!
//! Drives `hex::decode` with arbitrary byte strings. The hex
//! decoder is reached on every API response (UTXO txid, raw tx hex
//! from `pushtx`, address-info fields) — a panic here is a
//! crash-on-network-input bug.
//!
//! `hex::decode` is total: every input returns
//! `Result<Vec<u8>, hex::FromHexError>`. The harness asserts that
//! property holds across the entire fuzzed input space.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Cap input — even a 1 KiB hex string is already 512 bytes of
    // decoded payload, which is plenty for a tx.
    if data.len() > 8192 {
        return;
    }
    // Convert bytes to a string view; non-UTF-8 inputs are still
    // valid hex strings as long as every byte is ASCII hex. We
    // round-trip through `String::from_utf8_lossy` to feed the
    // decoder the same shape the network layer does.
    let s = String::from_utf8_lossy(data);
    let _ = hex::decode(s.as_ref());
});
