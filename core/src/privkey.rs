//! Private key operations.
//!
//! - [`bin2privkey`] — X25519-style clamping of a 32-byte secret
//!   (preserved for bit-for-bit compat with `yubtc-python`, even though
//!   secp256k1 doesn't need it).
//! - [`seed2privkey`] — combined `seed2bin + bin2privkey` into a
//!   `k256::ecdsa::SigningKey` ready for signing or address derivation.
//! - [`sign_hash`] — ECDSA over an arbitrary 32-byte digest.
//! - [`sign_data`] — double-SHA256 + ECDSA, the Bitcoin transaction
//!   signing convention.
//! - [`privkey_to_pubkey`] — 33-byte compressed public key.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use k256::EncodedPoint;
use sha2::{Digest, Sha256};

use crate::kdf::{seed2bin_with_purpose, KdfAlgo, PURPOSE_LEGACY};
use crate::misc::{TNonce, TPassphrase, TSeed};

#[derive(Debug, thiserror::Error)]
pub enum PrivKeyError {
    #[error("KDF failed: {0}")]
    Kdf(#[from] crate::kdf::KdfError),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("derived scalar is zero or >= secp256k1 order: {0}")]
    InvalidScalar(String),
}

/// X25519-style clamp of a 32-byte secret.
///
/// `privkey[0] &= 248; privkey[31] &= 127; privkey[31] |= 64;`
///
/// secp256k1 does not require this — it's a no-op for the curve's
/// subgroup structure — but the legacy `yubtc` cascade KDF has
/// clamped its output since the original yubtc-python, and the Rust
/// port keeps it there for bit-for-bit compatibility with
/// pre-passphrase wallets (decision C1: clamp is scoped to the
/// `yubtc_cascade` branch ONLY; see [`seed2privkey_with_kdf`]).
pub fn bin2privkey(data: &[u8; 32]) -> [u8; 32] {
    let mut out = *data;
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

/// Turn raw KDF output into a `SigningKey` WITHOUT clamping.
///
/// Used by the BIP-39-compatible branches (`pbkdf2`/`argon2id`/
/// `scrypt`): their 32-byte BIP-44 leaf must go into secp256k1
/// verbatim, or addresses stop matching what Trezor/Ledger/Electrum
/// show for the same `(mnemonic, passphrase)` (decision C1).
///
/// Returns [`PrivKeyError::InvalidScalar`] when the bytes are zero or
/// `>= n` (the curve order). For uniformly random 32-byte KDF output
/// this has probability ~2^-128, but it is a real, reported error —
/// not an `expect` — because unlike the clamped branch there is no
/// proof it cannot happen.
pub fn bytes_to_signing_key(raw: &[u8; 32]) -> Result<SigningKey, PrivKeyError> {
    SigningKey::from_bytes(raw.into()).map_err(|e| {
        PrivKeyError::InvalidScalar(format!("raw 32-byte secret rejected by secp256k1: {e}"))
    })
}

/// Combined `seed2bin` + key materialisation into a `k256`
/// `SigningKey`.
///
/// Default KDF: matches `yubtc-python`'s `seed2bin` routing (empty
/// passphrase → legacy cascade; non-empty → BIP-39/32/44).
pub fn seed2privkey(
    seed: &TSeed,
    nonce: TNonce,
    passphrase: &TPassphrase,
) -> Result<SigningKey, PrivKeyError> {
    seed2privkey_with_kdf(seed, nonce, passphrase, KdfAlgo::default_for(passphrase))
}

/// As [`seed2privkey`] but lets the caller pick the KDF algorithm.
///
/// Clamp policy (decision C1): `KdfAlgo::Yubtc` (the legacy cascade)
/// clamps its output via [`bin2privkey`] for bit-for-bit compatibility
/// with pre-passphrase yubtc wallets; every BIP-39-compatible branch
/// (`Pbkdf2`/`Argon2id`/`Scrypt`) feeds the raw 32-byte BIP-44 leaf
/// to secp256k1 directly via [`bytes_to_signing_key`] so addresses
/// match external BIP-44 wallets.
pub fn seed2privkey_with_kdf(
    seed: &TSeed,
    nonce: TNonce,
    passphrase: &TPassphrase,
    kdf: KdfAlgo,
) -> Result<SigningKey, PrivKeyError> {
    seed2privkey_with_purpose(seed, nonce, passphrase, kdf, PURPOSE_LEGACY)
}

/// [`seed2privkey_with_kdf`] at a parameterised BIP-32 purpose (Phase
/// 13): only the BIP-39-standard `pbkdf2` branch honours `purpose`
/// (`m/84'…` for native P2WPKH, `m/86'…` for P2TR — BIP-84/86); the
/// other KDFs ignore it (вариант A, spec ОВ-2 — same key, other
/// encoding). The clamp policy is identical to
/// [`seed2privkey_with_kdf`].
pub fn seed2privkey_with_purpose(
    seed: &TSeed,
    nonce: TNonce,
    passphrase: &TPassphrase,
    kdf: KdfAlgo,
    purpose: u32,
) -> Result<SigningKey, PrivKeyError> {
    let raw = seed2bin_with_purpose(seed, nonce, passphrase, kdf, purpose)?;
    match kdf {
        KdfAlgo::Yubtc => {
            let clamped = bin2privkey(&raw);
            // Clamping guarantees the result is in `[0, n)` where `n`
            // is the secp256k1 curve order (max_clamped = 0xf8..7f <
            // n = 0xff..41), so `from_bytes` cannot fail. Use
            // `expect` rather than `?` to avoid an unreachable error
            // branch in the coverage report.
            Ok(SigningKey::from_bytes((&clamped).into())
                .expect("clamped scalar out of secp256k1 range: bug in bin2privkey"))
        }
        KdfAlgo::Pbkdf2 | KdfAlgo::Argon2id | KdfAlgo::Scrypt => bytes_to_signing_key(&raw),
    }
}

/// Sign a 32-byte digest directly (low-S signatures, normalised by
/// `k256`).
///
/// The digest IS the signed prehash: on-chain `OP_CHECKSIG` treats the
/// transaction sighash as the raw ECDSA `z`, so the signature must
/// commit to the digest itself. k256's `Signer::sign` trait method is
/// NOT that — it applies a SHA-256 prehash to its argument (signing
/// `SHA256(msg)` instead); the `signature::hazmat::PrehashSigner`
/// API used here treats its argument as the prehash (deterministic
/// RFC6979 nonce, no extra data) and is byte-identical to
/// `yubtc-python`'s `sign_hash`
/// (`coincurve.PrivateKey.sign(…, hasher=None)`).
///
/// Infallible by construction: for secp256k1 a 32-byte prehash is
/// exactly the `bits2field` width (the API's only systematic failure
/// mode), and RFC6979 never derives a zero nonce or `s` — the same
/// documented-invariants `expect` precedent as [`bin2privkey`] and
/// `transaction.rs::taproot_sign_sighash`.
pub fn sign_hash(privkey: &SigningKey, hash: &[u8; 32]) -> Signature {
    privkey
        .sign_prehash(hash)
        .expect("32-byte prehash is a valid secp256k1 z; RFC6979 k/s cannot be zero")
}

/// Bitcoin transaction signing: `double-SHA256(data) → ECDSA`.
pub fn sign_data(privkey: &SigningKey, data: &[u8]) -> Result<Signature, PrivKeyError> {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&second);
    Ok(sign_hash(privkey, &hash))
}

/// 33-byte compressed public key (the `0x02 || X` / `0x03 || X` form).
pub fn privkey_to_pubkey(privkey: &SigningKey) -> [u8; 33] {
    let encoded = EncodedPoint::from(privkey.verifying_key());
    let bytes = encoded.to_bytes();
    let mut out = [0u8; 33];
    // Defensive: the encoded form is always 33 bytes for secp256k1
    // compressed.
    out.copy_from_slice(&bytes[..33]);
    out
}

/// Uncompressed public key (65 bytes) — used for some WIF encoding
/// paths in other wallets; yubtc does not use it directly but exposes
/// it for completeness.
pub fn privkey_to_pubkey_uncompressed(privkey: &SigningKey) -> [u8; 65] {
    let enc = privkey.verifying_key().to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(enc.as_bytes());
    out
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    // --- bin2privkey (clamp) -----------------------------------------

    /// Decision C1: the legacy `yubtc` cascade keeps its clamp, so a
    /// given (seed, nonce) derives exactly the key it always did —
    /// pre-passphrase wallets still open bit-for-bit.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn yubtc_kdf_still_clamps_its_output() {
        let seed = TSeed::new("clamp parity seed");
        let key = seed2privkey_with_kdf(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc)
            .expect("yubtc cascade derives");
        let raw = crate::kdf::seed2bin(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc)
            .expect("seed2bin derives");
        let clamped = bin2privkey(&raw);
        assert_eq!(key.to_bytes().as_slice(), &clamped[..]);
    }

    /// Decision C1: the BIP-39-compatible branches (`pbkdf2`,
    /// `argon2id`, `scrypt`) feed the raw 32-byte BIP-44 leaf to
    /// secp256k1 WITHOUT the clamp — clamping there would break
    /// address parity with Trezor/Ledger/Electrum for the same
    /// (mnemonic, passphrase).
    #[ntest_timeout::timeout(180_000)]
    #[test]
    fn bip39_kdfs_skip_the_clamp() {
        let seed = TSeed::new(
            "abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon about",
        );
        for kdf in [KdfAlgo::Pbkdf2, KdfAlgo::Argon2id, KdfAlgo::Scrypt] {
            let passphrase = TPassphrase::new("x");
            let key = seed2privkey_with_kdf(&seed, TNonce::new(0), &passphrase, kdf)
                .expect("supported KDF derives");
            let raw =
                crate::kdf::seed2bin(&seed, TNonce::new(0), &passphrase, kdf).expect("seed2bin");
            assert_eq!(
                key.to_bytes().as_slice(),
                &raw[..],
                "{kdf:?}: key must be the UNclamped KDF output"
            );
        }
    }

    /// The unclamped path reports a typed error (not an `expect`) for
    /// out-of-range scalars: unlike the clamped branch there is no
    /// proof the KDF output is `< n`, so the branch is reachable by
    /// contract even though random output hits it with p ~ 2^-128.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bytes_to_signing_key_rejects_out_of_range_scalar() {
        // 0xffff..ff > secp256k1 order 0xffff..fe..41.
        let too_big = [0xffu8; 32];
        // `.err().expect()` instead of `expect_err`: the latter
        // spawns a closure wrapper that llvm-cov counts as a
        // zero-hit missed function (the error arm never runs the
        // Ok-side formatting closure).
        #[allow(clippy::err_expect)]
        let err = bytes_to_signing_key(&too_big)
            .err()
            .expect("all-ones is above the curve order");
        assert!(matches!(err, PrivKeyError::InvalidScalar(_)), "got {err:?}");
        assert!(err.to_string().contains("secp256k1"), "got {err:?}");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bytes_to_signing_key_rejects_zero_scalar() {
        #[allow(clippy::err_expect)]
        let err = bytes_to_signing_key(&[0u8; 32])
            .err()
            .expect("zero is not a valid scalar");
        assert!(matches!(err, PrivKeyError::InvalidScalar(_)), "got {err:?}");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bytes_to_signing_key_accepts_in_range_scalar() {
        // 1 is a valid scalar (generator multiple).
        let mut one = [0u8; 32];
        one[31] = 1;
        let key = bytes_to_signing_key(&one).expect("scalar 1 is valid");
        assert_eq!(key.to_bytes().as_slice(), &one[..]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn clamp_clears_low_three_bits_of_first_byte() {
        let data = [0xffu8; 32];
        let out = bin2privkey(&data);
        // First byte: 0xff & 0xf8 == 0xf8.
        assert_eq!(out[0], 0xf8);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn clamp_clears_high_bit_and_sets_bit_6_of_last_byte() {
        let data = [0u8; 32];
        let out = bin2privkey(&data);
        // 0 & 127 == 0, 0 | 64 == 64.
        assert_eq!(out[31], 0x40);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn clamp_combined() {
        let mut data = [0u8; 32];
        data[0] = 0xff;
        data[31] = 0xff;
        let out = bin2privkey(&data);
        assert_eq!(out[0], 0xf8);
        assert_eq!(out[31], 0x7f | 0x40);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn clamp_is_deterministic() {
        let data = [42u8; 32];
        assert_eq!(bin2privkey(&data), bin2privkey(&data));
    }

    // --- seed2privkey ------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed2privkey_default_for_empty_passphrase_uses_yubtc_cascade() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let bytes: [u8; 32] = pk.to_bytes().into();
        // Sanity: not all zeros.
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed2privkey_default_for_passphrase_uses_pbkdf2() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::new("test")).unwrap();
        let bytes: [u8; 32] = pk.to_bytes().into();
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed2privkey_differs_per_nonce() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let p0 = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let p1 = seed2privkey(&seed, TNonce::new(1), &TPassphrase::EMPTY).unwrap();
        let b0: [u8; 32] = p0.to_bytes().into();
        let b1: [u8; 32] = p1.to_bytes().into();
        assert_ne!(b0, b1);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed2privkey_with_yubtc_kdf_rejects_passphrase() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let r = seed2privkey_with_kdf(
            &seed,
            TNonce::new(0),
            &TPassphrase::new("x"),
            KdfAlgo::Yubtc,
        );
        assert!(matches!(r, Err(PrivKeyError::Kdf(_))));
    }

    // --- sign_hash / sign_data ---------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_hash_produces_64_bytes() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let hash = [1u8; 32];
        let sig = sign_hash(&pk, &hash);
        assert_eq!(sig.to_bytes().len(), 64);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_hash_is_deterministic() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let hash = [7u8; 32];
        let s1 = sign_hash(&pk, &hash);
        let s2 = sign_hash(&pk, &hash);
        assert_eq!(s1, s2);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_data_double_sha256_matches_sign_hash() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let data = b"hello world";
        let sig_data = sign_data(&pk, data).unwrap();
        // Manual double-SHA256.
        let first = Sha256::digest(data);
        let second = Sha256::digest(first);
        let mut h = [0u8; 32];
        h.copy_from_slice(&second);
        let sig_hash = sign_hash(&pk, &h);
        assert_eq!(sig_data, sig_hash);
    }

    /// Regression (crypto audit, CLAIM 1): `sign_hash` must commit to
    /// the digest ITSELF — on-chain `OP_CHECKSIG` verifies the
    /// signature against the sighash as the raw ECDSA `z`. k256's
    /// `Signer::sign` would instead commit to `SHA256(sighash)` and
    /// produce signatures no node accepts; the digest-level
    /// `verify_prehash` is the semantics check, and the prehashing
    /// `verify` MUST disagree (otherwise the two APIs would be
    /// indistinguishable and this test vacuous).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_hash_commits_to_the_digest_itself() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::signature::Verifier;

        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let vk = pk.verifying_key();
        let sighash = [7u8; 32];
        let sig = sign_hash(&pk, &sighash);
        vk.verify_prehash(&sighash, &sig)
            .expect("signature must verify over the digest itself");
        assert!(
            vk.verify(&sighash, &sig).is_err(),
            "signature must NOT verify over SHA256(sighash) — that would \
             mean sign_hash applies a prehash (the CLAIM 1 bug)"
        );
    }

    /// Same semantics check for `sign_data`: the signature commits to
    /// the double-SHA256 of the data, not to its triple hash.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_data_commits_to_the_double_sha256_digest() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let vk = pk.verifying_key();
        let data = b"yubtc";
        let sig = sign_data(&pk, data).unwrap();
        let first = Sha256::digest(data);
        let second = Sha256::digest(first);
        let mut h = [0u8; 32];
        h.copy_from_slice(&second);
        vk.verify_prehash(&h, &sig)
            .expect("signature must verify over the double-SHA256 digest");
        let wrong_digest = Sha256::digest(h);
        assert!(vk.verify_prehash(&wrong_digest, &sig).is_err());
    }

    // --- privkey_to_pubkey -------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn privkey_to_pubkey_is_compressed_33_bytes() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let pub_bytes = privkey_to_pubkey(&pk);
        assert_eq!(pub_bytes.len(), 33);
        // Compressed prefix is 0x02 (y even) or 0x03 (y odd). Branch
        // free: masking the low bit collapses both accepted values to
        // a single comparison (a `||` here would leave one arm
        // permanently uncovered for branch coverage).
        assert_eq!(pub_bytes[0] & 0xFE, 0x02);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn privkey_to_pubkey_uncompressed_is_65_bytes() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let pub_bytes = privkey_to_pubkey_uncompressed(&pk);
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn pubkey_starts_with_uncompressed_then_compressed_prefix_match() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let comp = privkey_to_pubkey(&pk);
        let uncomp = privkey_to_pubkey_uncompressed(&pk);
        // The X coordinate is identical between compressed and
        // uncompressed (it's the 32 bytes after the prefix in both).
        assert_eq!(&comp[1..], &uncomp[1..33]);
    }

    // --- proptest ----------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]
        fn clamp_never_changes_byte_31_high_bit_to_zero_when_it_was_one(
            high in 0x80u8..=0xff,
        ) {
            // The high bit of byte[31] is cleared regardless of input;
            // | 64 sets bit 6 — so the final byte always has bits 6 and
            // possibly 5..0 set, but not bit 7.
            let mut data = [0u8; 32];
            data[31] = high;
            let out = bin2privkey(&data);
            prop_assert_eq!(out[31] & 0x80, 0);
            prop_assert_eq!(out[31] & 0x40, 0x40);
        }
    }
}
