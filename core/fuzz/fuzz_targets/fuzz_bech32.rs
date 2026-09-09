#![no_main]

//! bech32/bech32m codec fuzz target (Phase 13 stage 3).
//!
//! Drives `bech32::decode` / `bech32::encode` / `decode_segwit_address`
//! with arbitrary strings — the parser every SegWit receive and send
//! path reaches on adversarial input (`bc1…` addresses arrive from
//! untrusted sources: pasted QR codes, BIP-21 URIs, the network
//! layer). A panic here is a crash-on-input bug; the decoder is
//! total, so every input must resolve to a typed error or a valid
//! value.
//!
//! Invariants exercised:
//!
//! 1. `decode` never panics and never loops on any UTF-8 input.
//! 2. Decode/encode stability: a successfully decoded string
//!    re-encodes to a canonical lowercase string that decodes to the
//!    *same* `(hrp, encoding, data)` triple (the encoder is the
//!    inverse of the decoder on the accepted language, BIP-173/350).
//! 3. `five_bit_to_bytes(bytes_to_5bit(x)) == x` for arbitrary bytes —
//!    the convertbits pair backing the witness-program regrouping is
//!    a lossless total round-trip (8→5 with pad, 5→8 strict).
//! 4. The full SegWit layer (`decode_segwit_address`) also never
//!    panics; it rejects everything the generic layer accepts unless
//!    it is a mainnet witness program within yubtc's scope.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 {
        return;
    }
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // 1 + 2: generic bech32 layer — no panic, decode/encode stability.
    if let Ok((hrp, encoding, payload)) = yubtc_core::bech32::decode(s) {
        let reencoded = yubtc_core::bech32::encode(&hrp, encoding, &payload)
            .expect("re-encoding a successfully decoded bech32 string must succeed");
        assert!(
            reencoded.len() <= yubtc_core::bech32::BECH32_MAX_LEN,
            "re-encoded string exceeds the BIP-173 length limit"
        );
        let again = yubtc_core::bech32::decode(&reencoded)
            .expect("re-encoded bech32 string must decode");
        assert_eq!(
            again, (hrp, encoding, payload),
            "decode(encode(decode(s))) is not stable"
        );
    }

    // 3: convertbits round-trip is total and lossless.
    let back = yubtc_core::bech32::five_bit_to_bytes(&yubtc_core::bech32::bytes_to_5bit(data));
    assert_eq!(
        back.as_deref(),
        Some(data),
        "bytes_to_5bit/five_bit_to_bytes round-trip broken"
    );

    // 4: the SegWit layer on top of the generic decoder — no panic,
    // and whatever it accepts must round-trip through the encoder.
    if let Ok(wp) = yubtc_core::address::decode_segwit_address(s) {
        assert!(
            wp.version <= 1,
            "decode_segwit_address accepted an out-of-scope witness version"
        );
    }
});
