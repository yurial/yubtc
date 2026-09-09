//! yubtc-core: Rust core for the yubtc Bitcoin wallet.
//!
//! Bit-for-bit compatible with [`yubtc-python`](../../yubtc-python/) —
//! the same seed (without passphrase) yields the same address at the same
//! `nonce`.
//!
//! # Modules
//!
//! - [`fwd`]: default constants (single source of truth for the whole
//!   workspace; CLI/Android read from here, never inline literals).
//! - [`misc`]: newtype wrappers for magic types
//!   ([`TSatoshi`](misc::TSatoshi), [`TBTC`](misc::TBTC),
//!   [`TAddress`](misc::TAddress), [`TNonce`](misc::TNonce),
//!   [`TSeed`](misc::TSeed), [`TPassphrase`](misc::TPassphrase)),
//!   the [`not_none!`](misc::not_none) macro for required kwargs, and
//!   `btc2satoshi` / `satoshi2btc` conversions.
//! - [`seed`]: BIP-39 wrapper around the [`bip39`] crate.
//! - [`kdf`]: four KDF algorithms — `yubtc`, `pbkdf2` (BIP-39/32/44),
//!   `argon2id`, `scrypt`.
//! - [`privkey`]: `bin2privkey` clamp, `seed2privkey`, ECDSA signing
//!   via `k256`.
//! - [`address`]: P2PKH/P2SH base58check decoding, P2WPKH (bech32) and
//!   P2TR (bech32m, BIP-86 TapTweak) address derivation, strict SegWit
//!   address decoding, and mainnet WIF encoding/decoding.
//! - [`bech32`]: panic-free bech32/bech32m codec (BIP-173/BIP-350) —
//!   charset, polymod checksums (const `1` / `0x2bc830a3`), 5-bit
//!   regrouping; pinned by the official BIP test vectors.
//! - [`script`]: P2PKH / P2SH / P2WPKH / P2TR `scriptPubKey` builders
//!   + strict extractors.
//! - [`transaction`]: `TxIn` (with witness stack), `TxOut`,
//!   `Transaction` with stripped/wire serialization, txid/wtxid,
//!   weight/vsize, BIP-143 / BIP-341 sighashes, BIP-340 Schnorr and
//!   legacy SIGHASH_ALL signing.
//! - [`psbt`]: PSBT / BIP-174 (Phase 14) — parser/serializer with
//!   canonical key ordering, the Creator/Signer/Combiner/Finalizer/
//!   Extractor roles, hand-rolled base64 transport, and the official
//!   BIP-174 vectors as fixtures.
//! - [`wallet`]: `TPrivKey`, `Wallet`, UTXO model, fee loop, transaction
//!   assembly.
//! - [`net`]: pluggable `NetworkBackend` trait + blockchain.info /
//!   blockstream / mempool.space implementations.
//!
//! # Re-exports
//!
//! [`fwd::*`] and [`misc::*`] are re-exported at the crate root for
//! convenience (callers reach `yubtc_core::DEFAULT_FEEKB` directly).
//! Other modules are addressed by full path (`yubtc_core::kdf::seed2bin`)
//! to keep the public surface small and explicit.
//!
//! # KAT strategy
//!
//! Phase 1 ships **round-trip tests** only (Rust `seed2bin` →
//! `privkey2addr` must match what `yubtc-python` produces for the same
//! `(seed, nonce, passphrase)`). Fixed hex KAT vectors are deferred to a
//! later phase.

//! - [`net`]: pluggable `NetworkBackend` trait + blockchain.info /
//!   blockstream / mempool.space implementations.
//! - [`uniffi_api`]: foreign-function bindings (UniFFI). Sync facade
//!   over the async wallet core; consumed by the Android app and any
//!   other non-Rust language that needs to talk to yubtc.

pub mod address;
pub mod bech32;
pub mod fwd;
pub mod kdf;
pub mod misc;
pub mod net;
pub mod privkey;
pub mod psbt;
pub mod script;
pub mod seed;
pub mod transaction;
pub mod uniffi_api;
pub mod wallet;

pub use crate::fwd::*;
pub use crate::misc::*;

uniffi::setup_scaffolding!();
