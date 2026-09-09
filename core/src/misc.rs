//! Miscellaneous utilities: newtype wrappers for magic types, the
//! `not_none!` macro for required kwargs, and `btc2satoshi` /
//! `satoshi2btc` conversions.
//!
//! Newtypes prevent passing a raw `u64` where satoshi are expected, or a
//! raw `String` where an address is expected — catching a class of bugs
//! at compile time that would otherwise be runtime unit mismatches.

// --- Newtype wrappers -------------------------------------------------

macro_rules! impl_display_via_inner {
    ($($t:ty),+) => {
        $(impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        })+
    };
}

/// A count of satoshi — the lowest-resolution Bitcoin unit. 1 BTC =
/// 100 000 000 sat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TSatoshi(pub u64);

impl TSatoshi {
    pub const ZERO: Self = Self(0);

    pub const fn new(sat: u64) -> Self {
        Self(sat)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl_display_via_inner!(TSatoshi);

impl std::ops::Add for TSatoshi {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for TSatoshi {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

/// A user-facing Bitcoin amount. Stored as satoshi (same resolution as
/// [`TSatoshi`]) but semantically distinct: the value the user typed in
/// `yubtc send 1.5 …`. Conversions via `btc2satoshi` / `satoshi2btc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TBTC(pub u64);

impl TBTC {
    pub const ZERO: Self = Self(0);

    pub const fn from_satoshi(sat: u64) -> Self {
        Self(sat)
    }

    pub const fn to_satoshi(self) -> TSatoshi {
        TSatoshi(self.0)
    }
}

impl_display_via_inner!(TBTC);

/// A mainnet P2PKH or P2SH address, base58check-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TAddress(pub String);

impl TAddress {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl_display_via_inner!(TAddress);

/// BIP-44 address index. yubtc walks `chain=0` only, so this is the
/// final step in `m/44'/0'/0'/0/<nonce>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TNonce(pub u32);

impl TNonce {
    pub const ZERO: Self = Self(0);

    pub const fn new(n: u32) -> Self {
        Self(n)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl_display_via_inner!(TNonce);

/// A BIP-39 mnemonic phrase. Stored as a single whitespace-joined
/// string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TSeed(pub String);

impl TSeed {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Split the phrase into individual words. NFKD normalisation and
    /// validation happen in [`crate::seed`].
    pub fn words(&self) -> Vec<&str> {
        self.0.split_whitespace().collect()
    }
}

impl_display_via_inner!(TSeed);

/// BIP-39 passphrase. Empty string = no passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TPassphrase(pub String);

impl TPassphrase {
    pub const EMPTY: Self = Self(String::new());

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl_display_via_inner!(TPassphrase);

// --- Errors ----------------------------------------------------------

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MiscError {
    /// The BTC string did not parse. Mirrors the Python `Decimal`
    /// `InvalidOperation` message.
    #[error("invalid BTC amount '{0}': {1}")]
    InvalidBtc(String, String),

    /// The amount has more than 8 decimal places (BTC's satoshi
    /// resolution). Mirrors the Python guard.
    #[error("BTC amount '{0}' has more than 8 decimal places")]
    TooManyDecimals(String),

    /// BTC amount underflow: more satoshi required than fits in `u64`.
    #[error("BTC amount overflows u64 satoshi")]
    Overflow,
}

// --- btc2satoshi / satoshi2btc --------------------------------------

/// Number of satoshi in one BTC. Same constant as `yubtc-python`.
pub const SATOSHI_PER_BTC: u64 = 100_000_000;

/// Parse a user-typed BTC amount into a [`TSatoshi`].
///
/// Format: `<int>.<frac>` where `<frac>` is 0–8 digits. Matches
/// `yubtc-python`'s `Decimal(repr(btc)) * SATOSHI_PER_BTC` behaviour:
/// rejects negative values, amounts with more than 8 fractional
/// digits, and unparsable strings.
pub fn btc2satoshi(btc: &str) -> Result<TSatoshi, MiscError> {
    if let Some(rest) = btc.strip_prefix('-') {
        // Mirror Python: `Decimal('-1.5')` parses but `btc2satoshi`
        // would return a negative int. yubtc's CLI rejects negative
        // sends upstream; the lib still has to fail safely.
        return Err(MiscError::InvalidBtc(
            btc.to_string(),
            format!("negative amount '{rest}'"),
        ));
    }

    let (int_part, frac_part) = match btc.split_once('.') {
        Some((i, f)) => (i, f),
        None => (btc, ""),
    };

    if int_part.is_empty() && frac_part.is_empty() {
        return Err(MiscError::InvalidBtc(btc.to_string(), "empty".to_string()));
    }

    if frac_part.len() > 8 {
        return Err(MiscError::TooManyDecimals(btc.to_string()));
    }

    let int_sat: u64 = int_part.parse().map_err(|e: std::num::ParseIntError| {
        MiscError::InvalidBtc(btc.to_string(), e.to_string())
    })?;

    let frac_sat: u64 = if frac_part.is_empty() {
        0
    } else {
        // Right-pad with zeros so "1.5" → "50000000".
        let padded = format!("{frac_part:0<8}");
        padded.parse().map_err(|e: std::num::ParseIntError| {
            MiscError::InvalidBtc(btc.to_string(), e.to_string())
        })?
    };

    let total = int_sat
        .checked_mul(SATOSHI_PER_BTC)
        .and_then(|x| x.checked_add(frac_sat))
        .ok_or(MiscError::Overflow)?;

    Ok(TSatoshi(total))
}

/// Format a [`TSatoshi`] as a BTC string.
///
/// Always emits exactly 8 fractional digits (matching the Python
/// `Decimal` default precision) so the output is stable for tests and
/// logs.
pub fn satoshi2btc(sat: TSatoshi) -> String {
    format!("{}.{:08}", sat.0 / SATOSHI_PER_BTC, sat.0 % SATOSHI_PER_BTC)
}

// --- not_none! macro -------------------------------------------------

/// Unwrap an `Option<T>` as a required kwarg, with a fixed message that
/// mirrors `yubtc-python`'s `'X not set'`.
///
/// Python style: `seed = not_none!(opts.seed)`. In Rust this is just
/// `expect`, but the macro enforces the message format that the
/// Python convention expects from `yubtc-python`.
#[macro_export]
macro_rules! not_none {
    ($val:expr) => {
        $val.expect("required argument not set")
    };
}

// --- tagged hash / TapTweak -------------------------------------------

/// BIP-340/341 tagged hash: `sha256(sha256(tag) ‖ sha256(tag) ‖ msg)`.
///
/// Shared by the Taproot address derivation (`"TapTweak"`) and the
/// BIP-341 signature digest (`"TapSighash"`). Infallible and
/// allocation-free in output; `msg` is hashed streaming, so callers
/// can pass pre-assembled byte slices.
pub(crate) fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// BIP-341 tweak scalar for a key-path spend (empty Merkle root):
/// `t = int(tagged_hash("TapTweak", x(P)))` reduced modulo the
/// secp256k1 group order.
///
/// `internal_xonly` is the 32-byte x-only internal key. The output
/// key is `Q = lift_x(x(P)) + t·G` (see
/// [`crate::address::taproot_output_key`]); the tweaked signing
/// scalar is the internal scalar plus or minus `t` depending on the
/// parity of `Q` (see `transaction::sign_segwit`).
pub(crate) fn taproot_tweak_scalar(internal_xonly: &[u8; 32]) -> k256::Scalar {
    use k256::elliptic_curve::bigint::U256;
    use k256::elliptic_curve::ops::Reduce;

    <k256::Scalar as Reduce<U256>>::reduce_bytes(&tagged_hash(b"TapTweak", internal_xonly).into())
}

/// BIP-341 tweak scalar for a **script-path** spend (specs/spec.md
/// «Multi-sig» → «Адрес и leaf-хеш»): `t =
/// int(tagged_hash("TapTweak", internal_key ‖ leaf_hash))` where
/// `leaf_hash = tagged_hash("TapLeaf", 0xc0 ‖ compact_size ‖ script)`
/// (a single-leaf tree: the Merkle root equals the leaf hash).
///
/// Unlike [`taproot_tweak_scalar`] (BIP-86/BIP-341 key-path — the
/// reduce is total because the probability of `t ≥ n` is ignored per
/// BIP-86), the script-path rule **fails** on `t ≥ n` with
/// [`crate::address::AddressError::TapTweak`] (probability ~2⁻¹²⁸;
/// reported as a typed error, never wrapped modulo the order).
pub(crate) fn taproot_tweak_script_scalar(
    internal_xonly: &[u8; 32],
    leaf_hash: &[u8; 32],
) -> Result<k256::Scalar, crate::address::AddressError> {
    let mut msg = [0u8; 64];
    msg[..32].copy_from_slice(internal_xonly);
    msg[32..].copy_from_slice(leaf_hash);
    tweak_script_scalar_from_digest(tagged_hash(b"TapTweak", &msg))
}

/// Core of [`taproot_tweak_script_scalar`]: the canonical-scalar check
/// over a ready digest. Split out so the `t ≥ n` failure arm stays
/// testable with a crafted digest (a hash above the order cannot be
/// produced on demand for real inputs — probability ~2⁻¹²⁸), mirroring
/// the `tweak_output_key` split in [`crate::address`].
fn tweak_script_scalar_from_digest(
    t_bytes: [u8; 32],
) -> Result<k256::Scalar, crate::address::AddressError> {
    // BIP-341: «If t ≥ n, the wallet MUST fail» — from_repr succeeds
    // exactly for canonical (below the order) scalars.
    use k256::elliptic_curve::PrimeField;
    <k256::Scalar as PrimeField>::from_repr(t_bytes.into())
        .into_option()
        .ok_or_else(|| {
            crate::address::AddressError::TapTweak(
                "script-path tweak scalar ≥ curve order (p ≈ 2^-128)".to_string(),
            )
        })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    // --- newtype sanity -----------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tsatoshi_arithmetic() {
        assert_eq!(TSatoshi::new(100) + TSatoshi::new(50), TSatoshi::new(150));
        assert_eq!(TSatoshi::new(100) - TSatoshi::new(30), TSatoshi::new(70));
        assert_eq!(TSatoshi::ZERO.get(), 0);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tbtc_round_trip_via_satoshi() {
        let btc = TBTC::from_satoshi(150_000_000);
        assert_eq!(btc.to_satoshi().get(), 150_000_000);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taddress_wraps_string() {
        let a = TAddress::new("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(a.as_str(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(a.to_string(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tnonce_helpers() {
        assert_eq!(TNonce::new(7).get(), 7);
        assert_eq!(TNonce::ZERO.get(), 0);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tseed_words_splits_on_whitespace() {
        let s = TSeed::new("alpha  bravo   charlie");
        assert_eq!(s.words(), vec!["alpha", "bravo", "charlie"]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tpassphrase_empty_is_default() {
        assert!(TPassphrase::EMPTY.is_empty());
        assert!(TPassphrase::default().is_empty());
        assert!(!TPassphrase::new("hunter2").is_empty());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tpassphrase_as_str_returns_inner() {
        assert_eq!(TPassphrase::EMPTY.as_str(), "");
        assert_eq!(TPassphrase::new("hunter2").as_str(), "hunter2");
    }

    // --- btc2satoshi / satoshi2btc -----------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn btc2satoshi_integer() {
        assert_eq!(btc2satoshi("1").unwrap().get(), 100_000_000);
        assert_eq!(btc2satoshi("0").unwrap().get(), 0);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn btc2satoshi_fractional() {
        assert_eq!(btc2satoshi("0.5").unwrap().get(), 50_000_000);
        assert_eq!(btc2satoshi("1.5").unwrap().get(), 150_000_000);
        assert_eq!(btc2satoshi("0.00000001").unwrap().get(), 1);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn btc2satoshi_pads_short_frac() {
        // "1.5" → "1.50000000" → 150_000_000 sat.
        assert_eq!(btc2satoshi("1.5").unwrap().get(), 150_000_000);
        // "1.05" → "1.05000000" → 105_000_000 sat.
        assert_eq!(btc2satoshi("1.05").unwrap().get(), 105_000_000);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn btc2satoshi_rejects_negative() {
        assert!(matches!(
            btc2satoshi("-1"),
            Err(MiscError::InvalidBtc(_, _))
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn btc2satoshi_rejects_too_many_decimals() {
        assert!(matches!(
            btc2satoshi("0.000000001"),
            Err(MiscError::TooManyDecimals(_))
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn btc2satoshi_rejects_garbage() {
        assert!(matches!(
            btc2satoshi("abc"),
            Err(MiscError::InvalidBtc(_, _))
        ));
        assert!(matches!(
            btc2satoshi("1.2.3"),
            Err(MiscError::InvalidBtc(_, _))
        ));
        assert!(matches!(btc2satoshi(""), Err(MiscError::InvalidBtc(_, _))));
        assert!(matches!(btc2satoshi("."), Err(MiscError::InvalidBtc(_, _))));
        // Empty integer part with a non-empty fraction: the
        // int/fraction split succeeds, so the error comes from the
        // int-part parse ("cannot parse integer from empty string"),
        // not from the both-empty guard above.
        assert!(matches!(
            btc2satoshi(".5"),
            Err(MiscError::InvalidBtc(_, _))
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn btc2satoshi_rejects_overflow() {
        // u64::MAX / SATOSHI_PER_BTC = 184_467_440_737.09551615 BTC.
        // Any value ≥ 184_467_440_738 BTC overflows.
        assert!(matches!(
            btc2satoshi("184467440737.09551616"),
            Err(MiscError::Overflow)
        ));
        // Same with no fractional part.
        assert!(matches!(
            btc2satoshi("184467440738"),
            Err(MiscError::Overflow)
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn satoshi2btc_format_is_stable() {
        assert_eq!(satoshi2btc(TSatoshi::new(0)), "0.00000000");
        assert_eq!(satoshi2btc(TSatoshi::new(1)), "0.00000001");
        assert_eq!(satoshi2btc(TSatoshi::new(150_000_000)), "1.50000000");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn btc2satoshi_then_satoshi2btc_round_trip() {
        // satoshi2btc always emits exactly 8 fractional digits, so
        // each input must too — otherwise the assertion on the
        // formatted output fails on the formatter, not on the
        // parser.
        for raw in [
            "0.00000000",
            "0.00000001",
            "1.00000000",
            "1.50000000",
            "21.00000001",
        ] {
            let sat = btc2satoshi(raw).unwrap();
            assert_eq!(satoshi2btc(sat), raw, "round-trip failed for {raw}");
        }
    }

    // --- not_none! macro ----------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn not_none_unwraps_some() {
        let x: Option<u32> = Some(42);
        assert_eq!(not_none!(x), 42);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    #[should_panic(expected = "required argument not set")]
    fn not_none_panics_on_none() {
        let x: Option<u32> = None;
        let _ = not_none!(x);
    }

    // --- tagged_hash / TapTweak ---------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tagged_hash_expands_tag_twice() {
        // Structural pin: tagged_hash(t, m) must equal
        // sha256(sha256(t) ‖ sha256(t) ‖ m) — computed manually here
        // so any drift from the BIP-340 definition is caught even if
        // every official vector were removed.
        let t = b"TapSighash";
        let m = b"yubtc";
        let th = Sha256::digest(t);
        let mut concat = Vec::new();
        concat.extend_from_slice(&th);
        concat.extend_from_slice(&th);
        concat.extend_from_slice(m);
        let expected = Sha256::digest(&concat);
        assert_eq!(tagged_hash(t, m).as_slice(), expected.as_slice());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_tweak_scalar_matches_bip341_vector() {
        // Official BIP-341 wallet test vector (scriptPubKey section,
        // entry 0 — empty script tree): the tweak for internal key
        // d6889cb0...961d is tagged_hash("TapTweak", x(P)).
        let internal =
            hex::decode("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d")
                .unwrap();
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&internal);
        let t = taproot_tweak_scalar(&xonly);
        assert_eq!(
            hex::encode(t.to_bytes()),
            "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_tweak_scalar_is_deterministic() {
        let xonly = [7u8; 32];
        assert_eq!(
            taproot_tweak_scalar(&xonly).to_bytes(),
            taproot_tweak_scalar(&xonly).to_bytes()
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_tweak_script_scalar_binds_internal_and_leaf() {
        // Structural pin: t = int(tagged_hash("TapTweak", p ‖ h)) and
        // the output key is lift_x(p) + t·G — verified against an
        // independent k256 point computation for the NUMS internal key
        // and a fixed leaf hash.
        use k256::elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::{bigint::U256, point::AffineCoordinates as _};
        use k256::ProjectivePoint;

        let internal = crate::fwd::MS_TAPSCRIPT_INTERNAL_KEY;
        let leaf: [u8; 32] =
            hex::decode("640fca23685170704e436970f8ca462899442be7b8a4010bcb31eb579c65c004")
                .unwrap()
                .try_into()
                .unwrap();
        let t = taproot_tweak_script_scalar(&internal, &leaf).expect("t < n");
        let expected_t = tagged_hash(
            b"TapTweak",
            &[internal.as_slice(), leaf.as_slice()].concat(),
        );
        assert_eq!(
            t.to_bytes().as_slice(),
            <k256::Scalar as Reduce<U256>>::reduce_bytes(&expected_t.into())
                .to_bytes()
                .as_slice()
        );
        // Q = lift_x(H) + t·G — the x coordinate must match the pinned
        // output key of the 2-of-3 fixture leaf (independent Python
        // derivation, spec vectors; the fixture Q has odd parity).
        let mut sec1 = [0u8; 33];
        sec1[0] = 0x02;
        sec1[1..].copy_from_slice(&internal);
        let h = k256::PublicKey::from_sec1_bytes(&sec1).expect("NUMS is a curve point");
        let q = ProjectivePoint::from(h.as_affine()) + (ProjectivePoint::GENERATOR * t);
        let mut qx = [0u8; 32];
        qx.copy_from_slice(&q.to_affine().x());
        assert_eq!(
            hex::encode(qx),
            "8df67ad4ec3bfb01b66fb6fbdfec811f90b3fa0e9842ea523f6e09d387280688"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_tweak_script_scalar_rejects_t_above_order() {
        // The BIP-341 failure arm (t ≥ n, p ≈ 2^-128) driven with a
        // crafted digest through the split core: an all-0xff…f digest
        // is ≥ n with certainty, so the canonical-scalar check must
        // refuse it as the typed TapTweak error.
        let err = tweak_script_scalar_from_digest([0xffu8; 32]).unwrap_err();
        assert!(matches!(err, crate::address::AddressError::TapTweak(_)));
        assert!(err.to_string().contains("curve order"));
    }
}
