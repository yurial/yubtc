#![no_main]

//! PSBT (BIP-174) parser fuzz target (Phase 14).
//!
//! Drives `yubtc_core::psbt::PartiallySignedTransaction::parse` with
//! arbitrary bytes. The parser is the wallet's entry point for
//! coordinator-supplied PSBTs (`psbt sign` / `combine` / `finalize` /
//! `extract` / `decode` all parse attacker-controlled input fully
//! offline), so the property under test is: **no panic, no overflow,
//! no oversized allocation** for the entire input space — including
//! allocation-bomb compact sizes, which the `PSBT_MAX_SIZE` guard
//! rejects before any allocation.
//!
//! Beyond the no-panic property, every accepted input must satisfy
//! the canonical re-encode stability invariants (specs/spec.md
//! «Сериализация»):
//!
//! 1. `parse(serialize(p)) == p` — one canonization pass is lossless;
//! 2. `serialize(parse(serialize(p))) == serialize(p)` — canonization
//!    is a fixed point (a second pass changes nothing).
//!
//! A violation of either would break bit-for-bit parity with the
//! Python mirror and the KAT pipeline.

use libfuzzer_sys::fuzz_target;

use yubtc_core::psbt::PartiallySignedTransaction;

fuzz_target!(|data: &[u8]| {
    if data.len() > yubtc_core::PSBT_MAX_SIZE {
        // Above the parse guard: reject without running (the parser
        // itself would answer TooLarge, but skipping keeps the
        // harness fast on huge inputs).
        return;
    }
    if let Ok(psbt) = PartiallySignedTransaction::parse(data) {
        let canonical = psbt.serialize();
        let reparsed =
            PartiallySignedTransaction::parse(&canonical).expect("canonical form must re-parse");
        assert_eq!(reparsed, psbt, "parse(serialize(p)) == p");
        assert_eq!(
            reparsed.serialize(),
            canonical,
            "canonization is a fixed point"
        );
    }
});
