//! Bech32 / Bech32m encoding (BIP-173 / BIP-350).
//!
//! Hand-rolled, panic-free codec in the same style as the inline
//! base58 decoder in [`crate::address`] (which replaced the
//! panic-prone `base58-0.2.0` decoder). Every malformed input is
//! rejected with a typed [`Bech32Error`]; no `unwrap`/`panic!` in
//! production paths.
//!
//! The codec is the generic BIP-173/350 string format (arbitrary
//! HRP + 5-bit data values). The SegWit-address layer on top of it —
//! witness version/program validation, `bc` HRP, bech32-vs-bech32m
//! selection — lives in [`crate::address::decode_segwit_address`].
//!
//! Checksum constants: `1` for bech32 (BIP-173) and `0x2bc830a3` for
//! bech32m (BIP-350). Encoders always emit lowercase; decoders accept
//! all-lowercase and all-uppercase input and reject mixed case.
//!
//! Mirrors the reference algorithms in the BIPs (polymod + hrp_expand)
//! bit-for-bit; pinned by the official BIP-173/350 test vectors in the
//! tests below.

/// The BIP-173 character set (GF(2⁵) alphabet, in encoding order).
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Bech32m checksum constant (BIP-350). Bech32 uses `1`.
pub const BECH32M_CONST: u32 = 0x2bc830a3;

/// Maximum total length of a bech32 string (BIP-173).
pub const BECH32_MAX_LEN: usize = 90;

/// Which checksum specification a string satisfies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// BIP-173 bech32 — checksum constant `1`. Used by witness v0.
    Bech32,

    /// BIP-350 bech32m — checksum constant `0x2bc830a3`. Used by
    /// witness v1+.
    Bech32m,
}

impl Encoding {
    /// The checksum constant this encoding xors into the polymod.
    pub const fn checksum_const(self) -> u32 {
        match self {
            Encoding::Bech32 => 1,
            Encoding::Bech32m => BECH32M_CONST,
        }
    }
}

/// Errors returned by the generic bech32 codec.
///
/// The SegWit-address layer maps these onto
/// [`crate::address::SegWitAddrError`]; this enum is the raw
/// string-level surface.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Bech32Error {
    /// The string exceeded 90 characters (BIP-173 overall max length).
    #[error("bech32 string longer than {BECH32_MAX_LEN} characters")]
    TooLong,

    /// A character outside the US-ASCII printable range [33, 126] or
    /// outside the data-part charset was encountered.
    #[error("invalid bech32 character {0:?}")]
    InvalidCharacter(char),

    /// Some characters are lowercase and some are uppercase (BIP-173
    /// decoders MUST reject mixed case).
    #[error("mixed-case bech32 string")]
    MixedCase,

    /// The string is structurally malformed: no `1` separator, empty
    /// HRP, or a data part shorter than the 6-character checksum.
    #[error("malformed bech32 structure")]
    InvalidStructure,

    /// Neither the bech32 (`1`) nor the bech32m (`0x2bc830a3`)
    /// checksum matches.
    #[error("bech32 checksum mismatch")]
    InvalidChecksum,

    /// An encoder-side data value is not a 5-bit number (>= 32).
    #[error("bech32 data value {0} out of 5-bit range")]
    InvalidDataValue(u8),
}

/// BCH checksum generator from BIP-173 (generator polynomial
/// `0x3b6a57b2`, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3).
fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// HRP expansion from BIP-173: high bits of each character, a zero
/// separator, then the low 5 bits of each character.
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.as_bytes() {
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.as_bytes() {
        out.push(b & 31);
    }
    out
}

/// Encode `data` (5-bit values, checksum excluded) with `hrp` under
/// the given [`Encoding`].
///
/// Contract:
/// - `hrp` must be non-empty and contain only US-ASCII characters in
///   [33, 126] — the encoder does not re-validate and produces
///   garbage (not panics) for out-of-range HRPs. All production
///   callers pass the constant `"bc"`.
/// - every value in `data` must be < 32; otherwise
///   [`Bech32Error::InvalidDataValue`].
/// - returns [`Bech32Error::TooLong`] when the result would exceed
///   90 characters (BIP-173).
/// - the output is always lowercase (BIP-173 encoder MUST).
pub fn encode(hrp: &str, encoding: Encoding, data: &[u8]) -> Result<String, Bech32Error> {
    for &v in data {
        if v > 31 {
            return Err(Bech32Error::InvalidDataValue(v));
        }
    }
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; 6]);
    let polymod = polymod(&values) ^ encoding.checksum_const();

    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for &v in data {
        // `v < 32` is checked above, so the charset index is in range.
        out.push(CHARSET[v as usize] as char);
    }
    for i in (0..6).rev() {
        let v = ((polymod >> (5 * i)) & 31) as usize;
        out.push(CHARSET[v] as char);
    }
    if out.len() > BECH32_MAX_LEN {
        return Err(Bech32Error::TooLong);
    }
    Ok(out)
}

/// Decode a bech32/bech32m string into `(hrp, encoding, data)`.
///
/// Contract:
/// - mixed-case input is rejected with [`Bech32Error::MixedCase`]
///   (BIP-173 MUST); all-lowercase and all-uppercase are accepted and
///   the returned `hrp` is always lowercase.
/// - the returned `data` excludes the 6-character checksum; it MAY be
///   empty (a pure-checksum payload is valid generic bech32).
/// - the returned [`Encoding`] tells which checksum constant the
///   string satisfies; the SegWit layer enforces the
///   v0→bech32 / v1+→bech32m correspondence (BIP-350 rule 2).
pub fn decode(s: &str) -> Result<(String, Encoding, Vec<u8>), Bech32Error> {
    if s.len() > BECH32_MAX_LEN {
        return Err(Bech32Error::TooLong);
    }
    // Every character must be US-ASCII printable [33, 126] (BIP-173
    // HRP and data-part validity). Checked on the raw string before
    // case handling so the byte-level slicing below is char-boundary
    // safe.
    for c in s.chars() {
        let v = c as u32;
        if !(33..=126).contains(&v) {
            return Err(Bech32Error::InvalidCharacter(c));
        }
    }
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }
    let s = s.to_ascii_lowercase();

    // The LAST '1' is the separator (BIP-173 allows '1' inside the
    // HRP; the final one delimits the data part).
    let pos = s.rfind('1').ok_or(Bech32Error::InvalidStructure)?;
    // `pos == 0` → empty HRP; `pos + 7 > len` → data part shorter
    // than the 6-character checksum.
    if pos == 0 || pos + 7 > s.len() {
        return Err(Bech32Error::InvalidStructure);
    }
    let hrp = &s[..pos];
    let data_part = &s[pos + 1..];

    let mut data = Vec::with_capacity(data_part.len());
    for c in data_part.chars() {
        match CHARSET.iter().position(|&x| x == c as u8) {
            Some(v) => data.push(v as u8),
            None => return Err(Bech32Error::InvalidCharacter(c)),
        }
    }

    // The checksum characters are still part of `data` here — the
    // polymod runs over the HRP expansion plus the full data part and
    // must land on one of the two checksum constants.
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    let chk = polymod(&values);
    let encoding = match chk {
        1 => Encoding::Bech32,
        BECH32M_CONST => Encoding::Bech32m,
        _ => return Err(Bech32Error::InvalidChecksum),
    };
    let payload_len = data.len() - 6; // guaranteed >= 0 by the length check
    data.truncate(payload_len);
    Ok((hrp.to_string(), encoding, data))
}

/// Re-group arbitrary bytes into 5-bit values, zero-padding the final
/// group (the 8→5 direction of BIP-173 convertbits with `pad=true`).
///
/// Infallible: 20 or 32 input bytes always produce a whole number of
/// groups plus at most one padded group; the accumulator is masked to
/// 12 bits (4 kept + 8 fresh), so no arithmetic can overflow.
pub fn bytes_to_5bit(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = ((acc << 8) | u32::from(b)) & 0xfff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// Re-group 5-bit values back into bytes (the 5→8 direction of
/// BIP-173 convertbits with `pad=false`).
///
/// Strict per BIP-173: any value >= 32, more than 4 bits of trailing
/// padding, or non-zero padding bits yield `None` (the SegWit layer
/// maps that to `SegWitAddrError::InvalidStructure`).
pub fn five_bit_to_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &v in data {
        if v > 31 {
            return None;
        }
        acc = ((acc << 5) | u32::from(v)) & 0xfff;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // An incomplete trailing group must be at most 4 bits AND zero.
    if bits >= 5 {
        return None;
    }
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    // --- BIP-173 valid generic bech32 strings --------------------------

    const BIP173_VALID_BECH32: &[&str] = &[
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl",
    ];

    // --- BIP-350 valid generic bech32m strings ------------------------

    const BIP350_VALID_BECH32M: &[&str] = &[
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    ];

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip173_valid_strings_decode_as_bech32() {
        for s in BIP173_VALID_BECH32 {
            let (hrp, encoding, _data) = decode(s).expect(s);
            assert_eq!(encoding, Encoding::Bech32, "{s}");
            // The decoded HRP is always lowercase.
            assert_eq!(hrp, hrp.to_ascii_lowercase(), "{s}");
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip350_valid_strings_decode_as_bech32m() {
        for s in BIP350_VALID_BECH32M {
            let (hrp, encoding, _data) = decode(s).expect(s);
            assert_eq!(encoding, Encoding::Bech32m, "{s}");
            assert_eq!(hrp, hrp.to_ascii_lowercase(), "{s}");
        }
    }

    // --- encode: reconstruct the official strings ---------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn encode_reproduces_bip173_generic_strings() {
        // "A12UEL5L" / "a12uel5l" are hrp "a" with an empty payload;
        // "?1ezyfcl" is hrp "?" with an empty payload.
        let cases: &[(&str, &str)] = &[
            ("a", "a12uel5l"),
            ("?", "?1ezyfcl"),
            (
                "split",
                "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            ),
        ];
        for (hrp, expected) in cases {
            let (decoded_hrp, encoding, data) = decode(expected).unwrap();
            assert_eq!(decoded_hrp, *hrp);
            assert_eq!(encoding, Encoding::Bech32);
            assert_eq!(encode(hrp, Encoding::Bech32, &data).unwrap(), *expected);
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn encode_reproduces_bip350_generic_strings() {
        let cases: &[(&str, &str)] = &[
            ("a", "a1lqfn3a"),
            ("?", "?1v759aa"),
            ("abcdef", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx"),
        ];
        for (hrp, expected) in cases {
            let (decoded_hrp, encoding, data) = decode(expected).unwrap();
            assert_eq!(decoded_hrp, *hrp);
            assert_eq!(encoding, Encoding::Bech32m);
            assert_eq!(encode(hrp, Encoding::Bech32m, &data).unwrap(), *expected);
        }
    }

    // --- BIP-173 invalid generic strings ------------------------------
    //
    // The 0x20/0x7F/0x80-prefixed vectors are encoded with the
    // printable stand-ins ' ' (0x20), DEL is unreachable in a &str
    // literal for 0x7F — ' ' and 'ÿ' (U+00FF > 126) cover the
    // out-of-range paths.

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip173_invalid_strings_are_rejected() {
        // HRP character out of range (space = 0x20).
        assert_eq!(decode(" 1nwldj5"), Err(Bech32Error::InvalidCharacter(' ')));
        // HRP character out of range (U+00FF > 126).
        assert!(matches!(
            decode("ÿ1axkwrx"),
            Err(Bech32Error::InvalidCharacter('ÿ'))
        ));
        // Overall max length exceeded (91 chars).
        let too_long = format!("{}1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqq", "a".repeat(85));
        assert!(too_long.len() > BECH32_MAX_LEN);
        assert_eq!(decode(&too_long), Err(Bech32Error::TooLong));
        // No separator character.
        assert_eq!(decode("pzry9x0s0muk"), Err(Bech32Error::InvalidStructure));
        // Empty HRP.
        assert_eq!(decode("1pzry9x0s0muk"), Err(Bech32Error::InvalidStructure));
        // Invalid data character ('b' is excluded from the charset).
        assert_eq!(decode("x1b4n0q5v"), Err(Bech32Error::InvalidCharacter('b')));
        // Too short checksum (data part < 6 chars).
        assert_eq!(decode("li1dgmt3"), Err(Bech32Error::InvalidStructure));
        // Checksum calculated with the uppercase form of the HRP:
        // passes the case check (all uppercase), then fails bech32
        // checksum after lowercasing.
        assert_eq!(decode("A1G7SGD8"), Err(Bech32Error::InvalidChecksum));
        // Empty HRP (separator at position 0).
        assert_eq!(decode("10a06t8"), Err(Bech32Error::InvalidStructure));
        assert_eq!(decode("1qzzfhee"), Err(Bech32Error::InvalidStructure));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip350_invalid_strings_are_rejected() {
        // Invalid data character.
        assert_eq!(decode("y1b0jsk6g"), Err(Bech32Error::InvalidCharacter('b')));
        assert_eq!(
            decode("lt1igcx5c0"),
            Err(Bech32Error::InvalidCharacter('i'))
        );
        // Too short checksum.
        assert_eq!(decode("in1muywd"), Err(Bech32Error::InvalidStructure));
        // Invalid character in checksum.
        assert_eq!(decode("mm1crxm3i"), Err(Bech32Error::InvalidCharacter('i')));
        assert_eq!(decode("au1s5cgom"), Err(Bech32Error::InvalidCharacter('o')));
        // Checksum calculated with the uppercase form of the HRP.
        assert_eq!(decode("M1VUXWEZ"), Err(Bech32Error::InvalidChecksum));
        // Empty HRP.
        assert_eq!(decode("16plkw9"), Err(Bech32Error::InvalidStructure));
        assert_eq!(decode("1p2gdwpf"), Err(Bech32Error::InvalidStructure));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn mixed_case_is_rejected() {
        // From the BIP-173 segwit list: mixed case MUST be rejected
        // at the codec level, before any address semantics.
        assert_eq!(
            decode("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7"),
            Err(Bech32Error::MixedCase)
        );
        // Minimal mixed-case probe on a generic string.
        assert_eq!(decode("a12Uel5L"), Err(Bech32Error::MixedCase));
    }

    // --- checksum constant selection ---------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn encoding_checksum_consts_match_bips() {
        assert_eq!(Encoding::Bech32.checksum_const(), 1);
        assert_eq!(Encoding::Bech32m.checksum_const(), BECH32M_CONST);
        assert_eq!(BECH32M_CONST, 0x2bc830a3);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn encode_rejects_out_of_range_data_values() {
        assert_eq!(
            encode("bc", Encoding::Bech32, &[32]),
            Err(Bech32Error::InvalidDataValue(32))
        );
        assert_eq!(
            encode("bc", Encoding::Bech32m, &[255]),
            Err(Bech32Error::InvalidDataValue(255))
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn encode_rejects_result_longer_than_90() {
        // 83-char HRP is the BIP-173 HRP max; with the separator and
        // 6 checksum chars any non-empty payload breaches 90.
        let hrp = "a".repeat(83);
        let err = encode(&hrp, Encoding::Bech32, &[0]).unwrap_err();
        assert_eq!(err, Bech32Error::TooLong);
    }

    // --- 5-bit regrouping ---------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bytes_to_5bit_official_example() {
        // The canonical P2WPKH program 751e76e8...bd6 from BIP-173
        // encodes to the data part of bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        // (version 0 + payload). Decode the official address to get
        // the expected 5-bit values.
        let (_, _, data) = decode("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap();
        let program = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        assert_eq!(bytes_to_5bit(&program), data[1..]);
        assert_eq!(data[0], 0); // witness version 0
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn five_bit_to_bytes_round_trips_bytes_to_5bit() {
        let payload: Vec<u8> = (0..=255u8).collect();
        let grouped = bytes_to_5bit(&payload);
        assert_eq!(five_bit_to_bytes(&grouped).unwrap(), payload);
        // Empty payload round-trips to empty.
        assert_eq!(
            five_bit_to_bytes(&bytes_to_5bit(&[])).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn five_bit_to_bytes_rejects_bad_padding() {
        // More than 4 bits of padding: 6 values = 30 bits → 3 bytes
        // + 6 leftover bits (31,31,31,31,31 = 25 ones; +0 pads to 30).
        assert_eq!(five_bit_to_bytes(&[31, 31, 31, 31, 31, 0]), None);
        // Exactly 5 leftover bits is still "more than 4".
        assert_eq!(five_bit_to_bytes(&[7]), None);
        // Non-zero padding: [25, 25] = 11001 11001 → byte 206 with
        // 2 leftover bits "01" ≠ 0.
        assert_eq!(five_bit_to_bytes(&[25, 25]), None);
        // Same prefix with zero padding decodes fine.
        assert_eq!(five_bit_to_bytes(&[24, 24]).unwrap(), vec![198u8]);
        // ...and 25 one-bits + one zero value = 3 bytes + 1 zero bit.
        assert_eq!(
            five_bit_to_bytes(&[31, 31, 31, 31, 0]).unwrap(),
            vec![255u8, 255, 240]
        );
        // Value out of 5-bit range.
        assert_eq!(five_bit_to_bytes(&[32]), None);
    }

    // --- proptests -----------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(1000))]

        #[ntest_timeout::timeout(30000)]
        #[test]
        fn round_trip_v0_v1_programs(encoding_idx in 0u8..2, program in proptest::collection::vec(any::<u8>(), 2..=40)) {
            // Generic codec round-trip: any 2..=40-byte payload encodes,
            // decodes, and (after the segwit layer's version prefix)
            // reproduces the original bytes. Both checksum encodings.
            let encoding = if encoding_idx == 0 { Encoding::Bech32 } else { Encoding::Bech32m };
            let data = bytes_to_5bit(&program);
            let s = encode("bc", encoding, &data).unwrap();
            let (hrp, dec_encoding, decoded) = decode(&s).unwrap();
            prop_assert_eq!(hrp, "bc");
            prop_assert_eq!(dec_encoding, encoding);
            prop_assert_eq!(decoded.clone(), data);
            prop_assert_eq!(five_bit_to_bytes(&decoded).unwrap(), program);
            // Uppercase input decodes to the same values (and the
            // encoded form stays lowercase).
            let (hrp2, enc2, data2) = decode(&s.to_ascii_uppercase()).unwrap();
            prop_assert_eq!(hrp2, "bc");
            prop_assert_eq!(enc2, encoding);
            prop_assert_eq!(data2, decoded);
            prop_assert!(s.chars().all(|c| !c.is_ascii_uppercase()));
        }
    }
}
