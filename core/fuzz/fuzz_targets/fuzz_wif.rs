#![no_main]

//! base58check WIF parsing fuzz target.
//!
//! Drives `address::wif_to_secret` with arbitrary base58check
//! strings. WIF is the wallet's only key-import path
//! (`yubtc dumpprivkey` / `wif_to_privkey`), so a panic here is a
//! crash-on-import bug — anyone feeding garbage must get a typed
//! `WifError`, not a process kill.
//!
//! The validator is total: every input returns
//! `Result<[u8; 32], WifError>`. The harness covers both the
//! base58check layer (decode + checksum) and the secp256k1 layer
//! (`SigningKey::from_bytes` rejects out-of-range scalars).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 {
        return;
    }
    // base58check strings are ASCII; we feed the parser what the
    // network / file-import would feed it.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = yubtc_core::address::wif_to_secret(s);
});
