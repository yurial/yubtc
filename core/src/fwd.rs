//! Default constants for the yubtc wallet.
//!
//! Single source of truth for the whole workspace — CLI and Android UI
//! read from here, never inline literals. Bit-for-bit compatibility
//! with `yubtc-python/src/yubtc/fwd.py` is required: existing wallets
//! must keep working without a recompile of their data.
//!
//! See [`yubtc/specs/spec.md`](../specs/spec.md#defaults--единый-источник-правды)
//! for the rationale behind each value.

// --- Wallet defaults --------------------------------------------------

/// Default nonce for `address`, `balance`, `dumpprivkey`, `send`
/// (when `-n` is omitted).
pub const DEFAULT_NONCE: u32 = 0;

/// Number of words in a freshly generated seed (`newseed -n`).
pub const DEFAULT_SEED_WORDS: usize = 15;

/// How many new addresses to generate for `--new`.
pub const DEFAULT_NEW_ADDRESSES: usize = 1;

/// Confirmation depth used to filter UTXOs (`balance -c`, `send -c`).
pub const DEFAULT_CONFIRMATIONS: u32 = 6;

/// HTTP request timeout (seconds) for all network backends.
///
/// Decision C4: 5, mirroring `yubtc-python/src/yubtc/fwd.py`. Backends
/// are expected to answer in seconds; a 180-second fallback masks a
/// hung API and freezes the wallet (specs/spec.md Defaults table).
pub const DEFAULT_TIMEOUT_HTTP: u64 = 5;

// --- Network resilience (v0.3 «Failover») -----------------------------

/// Retries per HTTP request before the backend is declared dead
/// (`--retries` default; CLI and Android read this, never inline
/// literals). `0` reproduces the v0.1 behaviour: exactly one attempt,
/// no backoff, no failover machinery in between.
pub const DEFAULT_HTTP_RETRIES: u32 = 3;

/// Base delay of the exponential backoff between retry attempts:
/// 500 ms before retry 1, doubled per subsequent retry.
pub const HTTP_RETRY_BASE_DELAY_MS: u64 = 500;

/// Cap of the exponential backoff: a retry never waits longer than
/// this regardless of the attempt number (500 ms → 1 s → 2 s → 2 s…).
pub const HTTP_RETRY_MAX_DELAY_MS: u64 = 2_000;

/// A `Retry-After` header on a 429 response is honoured only when it
/// is an integer number of seconds within this sane window; anything
/// else (missing, non-numeric, negative, larger) falls back to the
/// exponential backoff so a hostile/misbehaving server cannot stall
/// the wallet for minutes.
pub const HTTP_RETRY_AFTER_MAX_SECS: u64 = 30;

/// Default fee (`send -f`) in satoshi.
pub const DEFAULT_FEE: u64 = 0;

/// Default passphrase (empty = no passphrase).
pub const DEFAULT_PASSPHRASE: &str = "";

/// BIP-39 wordlist validation: are duplicates allowed?
pub const DEFAULT_ALLOW_DUPS: bool = true;

// --- Transaction defaults --------------------------------------------

/// Default `nLockTime` for every outgoing tx.
pub const DEFAULT_LOCKTIME: u32 = 0;

/// BIP-125 RBF signal: every outgoing tx advertises replaceability.
pub const SEQUENCE_RBF_SIGNALED: u32 = 0xfffffffe;

/// Empty script (default for `CScript`-shaped fields).
pub const EMPTY_SCRIPT: &[u8] = b"";

/// Default feerate (sat/kB). Equivalent to 1 sat/vB — adequate for
/// normal mempool load, tx usually lands in the next block.
///
/// Note: differs from `yubtc-python`, where the CLI `--fee` default
/// is the flat `MINIMAL_FEE`. `yubtc` defaults to a usable rate. The
/// relay floor itself is NOT defined here — it comes from
/// `bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE` (decision C2).
pub const DEFAULT_FEEKB: u64 = 1000;

// --- Dust thresholds -------------------------------------------------

/// Minimum size of a valid P2PKH output (Bitcoin Core dust limit).
pub const DUST_THRESHOLD_P2PKH: u64 = 546;

/// Minimum size of a valid P2SH output (Bitcoin Core dust limit).
pub const DUST_THRESHOLD_P2SH: u64 = 540;

/// Minimum size of a valid P2WPKH output. Bitcoin Core
/// `GetDustThreshold`: ⌊3 · (22 + 67) / 1000⌋-shaped formula — the
/// 22-byte output plus the ~67 vB cost of spending it with a
/// witness-discounted P2WPKH input.
pub const DUST_THRESHOLD_P2WPKH: u64 = 294;

/// Minimum size of a valid P2TR output: the 34-byte output plus the
/// ~67.5 vB (rounded to 68) cost of a key-path Schnorr spend →
/// ⌊3 · (34 + 68) / 1000⌋ = 330 (specs/spec.md «Fee / witness accounting»).
pub const DUST_THRESHOLD_P2TR: u64 = 330;

/// Minimum size of a valid P2WSH output (specs/spec.md «Multi-sig»,
/// форма P2WSH): the 34-byte output (`00 20 ‖ <32>`)
/// plus the ~67 vB cost of spending it with a witness-discounted
/// input — the same Bitcoin Core `GetDustThreshold` formula as the
/// other witness forms: ⌊3 · (43 + 67) / 1000⌋ = 330. The value
/// coincides with [`DUST_THRESHOLD_P2TR`] because both outputs
/// serialize to 34-byte scripts, but the forms stay distinct
/// constants (a dust-policy change for one form must not silently
/// move the other).
pub const DUST_THRESHOLD_P2WSH: u64 = 330;

/// Default receive-address type after Phase 13: native P2WPKH (spec
/// ОВ-1 — P2TR stays opt-in until the Schnorr path has been audited).
/// The type itself lives in [`crate::wallet::AddrType`]; this constant
/// is the single default the CLI / Android read.
pub const DEFAULT_ADDR_TYPE: crate::wallet::AddrType = crate::wallet::AddrType::Native;

// --- PSBT (BIP-174) defaults -----------------------------------------

/// Hard cap on the encoded size of a PSBT (bytes). A parse attempt on
/// anything larger fails with `PsbtError::TooLarge` before any
/// allocation — the fuzz/OOM guard against allocation bombs built from
/// oversized 64-bit compact sizes (specs/spec.md «PSBT — BIP-174» → «Сериализация»).
pub const PSBT_MAX_SIZE: usize = 4 * 1024 * 1024;

/// Upper bound for the Signer's offline nonce walk (ОВ-9). A stateless
/// wallet cannot map a UTXO back to its key, so `psbt sign` walks
/// nonces `0..PSBT_SIGN_MAX_NONCE`, deriving all three address forms
/// per nonce and matching the derived `scriptPubKey` against the
/// UTXO field. Inputs whose key lives at a nonce past the bound are
/// left unsigned (and reported by the caller). 1000 × 3 forms ≈ 3000
/// derivations — milliseconds.
pub const PSBT_SIGN_MAX_NONCE: u32 = 1000;

/// Pinned sighash type for legacy (P2PKH) and P2WPKH partial
/// signatures: `SIGHASH_ALL` (ОВ-8). The only flag the wallet ever
/// produces or accepts for these forms; a PSBT whose `SIGHASH_TYPE`
/// field disagrees means the input is not signed.
pub const PSBT_SIGHASH_ALL: u32 = 0x0000_0001;

/// Pinned sighash type for P2TR key-path partial signatures:
/// `SIGHASH_DEFAULT` (ОВ-8) — semantically SIGHASH_ALL, and the
/// Schnorr signature carries no sighash suffix byte.
pub const PSBT_SIGHASH_DEFAULT: u32 = 0x0000_0000;

// --- Multi-sig (P2SH, Phase 15) --------------------------------------

/// Upper bound for the multisig quorum size: `1 ≤ M ≤ N ≤ 15`
/// (R-MS-2). The bound is 15, not the consensus
/// `MAX_PUBKEYS_PER_MULTISIG = 20`: at N = 16 the redeem script
/// occupies 34·16 + 4 = 548 bytes — above the 520-byte
/// `MAX_SCRIPT_ELEMENT_SIZE` consensus limit on a single push — so the
/// P2SH output would be fundamentally unspendable (the redeem script
/// could not even be pushed into a `scriptSig`). The 20-key consensus
/// cap is never reached before the 520-byte one.
pub const MS_MAX_PUBKEYS: u32 = 15;

/// The internal key of every Tapscript quorum tree (R-MS-8, specs/spec.md
/// «Multi-sig»): the NUMS point
/// `H = lift_x(0x5092…ac0)` quoted verbatim in the BIP-341 text
/// (X = SHA-256 of the uncompressed SEC1 encoding of the generator G;
/// «nothing up my sleeve», ОВ-15). The tree is exactly one leaf, so
/// the key path physically does not exist: even a hypothetical
/// key-path spend of `Q = H + t·G` would require dlog(H), which is
/// unknown by construction. yubtc never produces signatures under `Q`.
pub const MS_TAPSCRIPT_INTERNAL_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Worst-case wire size of one Tapscript signature slot in the final
/// witness (spec «Размерная модель fee loop»): CompactSize(64) + the
/// 64-byte Schnorr signature + 1 sighash byte = 66. The canonical
/// yubtc final is 65 (SIGHASH_DEFAULT carries no sighash byte —
/// ОВ-17), but the fee loop must never underpay, so the estimate is
/// the worst case.
pub const MS_SIG_SIZE_ESTIMATE_TAP: usize = 66;

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    // Asserting constants is the entire point of a frozen snapshot:
    // the test exists so that editing a `const` breaks the build.
    #[allow(clippy::assertions_on_constants)]
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn defaults_match_yubtc_python() {
        // Snapshot of the values in yubtc-python/src/yubtc/fwd.py at
        // the time Phase 1 was planned. A change here is a
        // balance-breaking event for existing wallets.
        assert_eq!(DEFAULT_NONCE, 0);
        assert_eq!(DEFAULT_SEED_WORDS, 15);
        assert_eq!(DEFAULT_NEW_ADDRESSES, 1);
        assert_eq!(DEFAULT_CONFIRMATIONS, 6);
        // Decision C4: 180 → 5 — the claim that this mirrors
        // yubtc-python is now literally true (its fwd.py uses 5).
        assert_eq!(DEFAULT_TIMEOUT_HTTP, 5);
        assert_eq!(DEFAULT_FEE, 0);
        assert_eq!(DEFAULT_PASSPHRASE, "");
        assert!(DEFAULT_ALLOW_DUPS);
        assert_eq!(DEFAULT_LOCKTIME, 0);
        assert_eq!(SEQUENCE_RBF_SIGNALED, 0xfffffffe);
        assert_eq!(EMPTY_SCRIPT, b"");
        assert_eq!(DEFAULT_FEEKB, 1000);
        assert_eq!(DUST_THRESHOLD_P2PKH, 546);
        assert_eq!(DUST_THRESHOLD_P2SH, 540);
    }

    #[allow(clippy::assertions_on_constants)]
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn phase_v03_resilience_defaults_match_spec() {
        // Frozen snapshot of the resilience spec values (specs/spec.md
        // «Network backends» → «Failover и retry»). The retry
        // constants are NOT part of the bit-for-bit legacy
        // contract — they shape latency, not data.
        assert_eq!(DEFAULT_HTTP_RETRIES, 3);
        assert_eq!(HTTP_RETRY_BASE_DELAY_MS, 500);
        assert_eq!(HTTP_RETRY_MAX_DELAY_MS, 2_000);
        assert_eq!(HTTP_RETRY_AFTER_MAX_SECS, 30);
    }

    #[allow(clippy::assertions_on_constants)]
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn phase14_psbt_defaults_match_spec() {
        // Frozen snapshot of the PSBT spec values (specs/spec.md
        // «PSBT — BIP-174» + ОВ-8/ОВ-9 decisions).
        assert_eq!(PSBT_MAX_SIZE, 4_194_304);
        assert_eq!(PSBT_SIGN_MAX_NONCE, 1000);
        assert_eq!(PSBT_SIGHASH_ALL, 1);
        assert_eq!(PSBT_SIGHASH_DEFAULT, 0);
    }

    #[allow(clippy::assertions_on_constants)]
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn phase13_defaults_match_spec() {
        // Frozen snapshot of the address-form spec values (specs/spec.md
        // «Fee / witness accounting (vbytes)» and «Адресная политика»).
        assert_eq!(DUST_THRESHOLD_P2WPKH, 294);
        assert_eq!(DUST_THRESHOLD_P2TR, 330);
        assert!(matches!(DEFAULT_ADDR_TYPE, crate::wallet::AddrType::Native));
    }

    #[allow(clippy::assertions_on_constants)]
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn v0_3_p2wsh_dust_matches_spec() {
        // Frozen snapshot of the multisig spec value (specs/spec.md
        // «Multi-sig», размерная модель): ⌊3 · (43 + 67)
        // / 1000⌋ = 330 — same formula as P2TR (both 34-byte
        // outputs), kept a distinct constant.
        assert_eq!(DUST_THRESHOLD_P2WSH, 330);
    }

    #[allow(clippy::assertions_on_constants)]
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn phase15_ms_defaults_match_spec() {
        // Frozen snapshot of the multisig spec values (specs/spec.md
        // «Multi-sig», R-MS-2). The 15 bound
        // keeps the redeem script pushable: 34·16 + 4 = 548 > 520
        // (MAX_SCRIPT_ELEMENT_SIZE) would make N = 16 unspendable.
        assert_eq!(MS_MAX_PUBKEYS, 15);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn v0_3_tapscript_defaults_match_spec() {
        // Frozen snapshot of the Tapscript spec values (specs/spec.md
        // «Multi-sig», R-MS-8 + размерная
        // модель): the NUMS internal key quoted verbatim in BIP-341
        // and the worst-case witness-slot estimate.
        assert_eq!(
            hex::encode(MS_TAPSCRIPT_INTERNAL_KEY),
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        );
        assert_eq!(MS_SIG_SIZE_ESTIMATE_TAP, 66);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn nums_point_is_sha256_of_the_uncompressed_generator() {
        // ОВ-15 self-reproduction: the NUMS x coordinate equals
        // SHA-256 of the uncompressed SEC1 encoding of G — the
        // derivation BIP-341 gives in its text. This is what makes the
        // point "nothing up my sleeve": anyone can recompute it.
        use k256::elliptic_curve::sec1::ToEncodedPoint as _;
        use k256::ProjectivePoint;
        use sha2::{Digest, Sha256};
        // SHA-256 of the uncompressed SEC1 encoding of G (04 ‖ x ‖ y).
        let uncompressed = ProjectivePoint::GENERATOR
            .to_affine()
            .to_encoded_point(false);
        let x = Sha256::digest(uncompressed.as_bytes());
        assert_eq!(x.as_slice(), MS_TAPSCRIPT_INTERNAL_KEY);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn r_ms_9_tapscript_520_byte_boundary_arithmetic() {
        // R-MS-9 const-guard: the unified 15-key bound is exactly the
        // BIP-342 MAX_SCRIPT_ELEMENT_SIZE limit for the CHECKSIGADD
        // idiom — |s| = 34N + 2; N = 15 → 512 ≤ 520 (spendable);
        // N = 16 → 546 > 520 (a leaf element that size is
        // consensus-invalid, so 16 is the physical ceiling).
        let size_of = |n: usize| 34 * n + 2;
        assert_eq!(size_of(MS_MAX_PUBKEYS as usize), 512);
        assert!(size_of(MS_MAX_PUBKEYS as usize) <= 520);
        assert!(size_of(MS_MAX_PUBKEYS as usize + 1) > 520);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn r_ms_1_no_default_n_or_m_symbols_exist() {
        // R-MS-1 pin («символа дефолта N/M в fwd.rs не существует»):
        // the defaults module defines MS_MAX_PUBKEYS and nothing
        // else for the multisig surface — a missing N or M is an
        // error at every boundary, never a substituted value. The
        // banned names are assembled at run time so this test's own
        // source never contains them.
        let src = include_str!("fwd.rs");
        for word in ["MS", "QUORUM", "MULTISIG"] {
            let banned = format!("DEFAULT_{word}");
            assert!(
                !src.contains(&banned),
                "R-MS-1: fwd.rs must not define a default N/M constant ({banned})"
            );
        }
        // The inverse sanity check: the one symbol that IS allowed.
        assert!(src.contains("MS_MAX_PUBKEYS"));
    }
}
