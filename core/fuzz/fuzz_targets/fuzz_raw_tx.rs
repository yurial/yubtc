#![no_main]

//! Raw Bitcoin transaction deserialization fuzz target.
//!
//! Drives `bitcoin::Transaction::consensus_decode` with arbitrary
//! bytes. `bitcoin` is the crate yubtc-core uses for the WIF and
//! base58check paths; fuzzing its transaction parser catches
//! panics in any future code that ends up validating a tx shape
//! (e.g. an Electrum server response carrying a tx hex, an
//! imported PSBT, or a sign-and-verify round trip).
//!
//! The decoder is total: every input returns
//! `Result<Transaction, _>`. The harness just confirms it never
//! panics on adversarial bytes.
//!
//! `consensus_decode` lives on the `bitcoin::consensus::Decodable`
//! trait, not as a method on `Transaction` directly — see the
//! rustdoc for [`bitcoin::Transaction`] in the bitcoin 0.31 crate.

use libfuzzer_sys::fuzz_target;

use bitcoin::consensus::Decodable;

fuzz_target!(|data: &[u8]| {
    if data.len() > 100_000 {
        return;
    }
    // `consensus_decode` wants a `&mut Read`. Wrap the slice in a
    // `Cursor` so the decoder can pull bytes off.
    let mut cursor = std::io::Cursor::new(data);
    let _ = bitcoin::Transaction::consensus_decode(&mut cursor);
});
