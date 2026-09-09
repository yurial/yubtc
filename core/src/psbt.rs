//! PSBT — Partially Signed Bitcoin Transaction (BIP-174, Phase 14 v0.2).
//!
//! Purpose: a transport container for exchanging partial signatures
//! between a stateless yubtc wallet and external coordinators. Everything
//! that eventually goes on-chain is byte-for-byte identical to the
//! Phase 13 flows ([`crate::transaction`]); this module adds only the
//! container, the canonical (de)serialization, and the five BIP-174
//! roles (Creator, Signer, Combiner, Finalizer, Extractor) plus a
//! human-readable `decode` summary.
//!
//! # Wire format (BIP-174)
//!
//! ```text
//! <psbt>    := 0x70 0x73 0x62 0x74 0xFF <global-map> <input-map>* <output-map>*
//! <map>     := <keypair>* 0x00
//! <keypair> := <keylen><keytype><keydata><valuelen><valuedata>
//! ```
//!
//! Contract highlights (all tested, specs/spec.md «Сериализация»):
//!
//! - **Canonical ordering** — the serializer emits each map's pairs in
//!   ascending full-key-byte order (type, then keydata, lexicographic),
//!   giving bit-for-bit determinism against the Python mirror. The
//!   parser accepts any order.
//! - **Duplicates** — a repeated full key inside one map is
//!   [`PsbtError::DuplicateKey`] (a PSBT with duplicates is invalid
//!   per BIP-174).
//! - **Minimal key types** — the `<keytype>` prefix must be a
//!   minimally-encoded compact size (`0xFD 0x00 0x02` for type 2 is
//!   [`PsbtError::NonMinimalCompactSize`]).
//! - **Exact keydata lengths** — "No key data" field types require
//!   `keylen == 1`; `PARTIAL_SIG` and BIP-32-derivation keys require a
//!   33-byte compressed or 65-byte uncompressed pubkey (other lengths →
//!   [`PsbtError::InvalidKeyLength`]).
//! - **Size guard** — inputs above [`crate::PSBT_MAX_SIZE`] fail with
//!   [`PsbtError::TooLarge`] before any allocation (fuzz/OOM guard).
//! - **Unknown-field passthrough** — fields outside the in-scope set
//!   (xpubs, BIP-32 derivations, preimage fields, BIP-371 taproot
//!   fields, proprietary `0xFC`, anything unassigned) are kept as
//!   opaque `(key, value)` byte pairs and carried through the whole
//!   pipeline byte-for-byte; the extracted transaction never sees them.
//! - **Map counts** — the number of input/output maps must equal the
//!   unsigned tx's input/output counts ([`PsbtError::MapCountMismatch`]).
//!
//! # Scope (Phase 14)
//!
//! In-scope typed fields: global `UNSIGNED_TX` (0x00) and `VERSION`
//! (0xFB, read-only, v0 only); per-input `NON_WITNESS_UTXO` (0x00),
//! `WITNESS_UTXO` (0x01), `PARTIAL_SIG` (0x02), `SIGHASH_TYPE` (0x03),
//! `REDEEM_SCRIPT` (0x04), `WITNESS_SCRIPT` (0x05), `FINAL_SCRIPTSIG`
//! (0x07), `FINAL_SCRIPTWITNESS` (0x08). Per-output fields are
//! preserve-only. Signatures: legacy/BIP-143 ECDSA with the pinned
//! `SIGHASH_ALL` suffix (ОВ-8) and BIP-341 key-path Schnorr
//! (64 bytes, no suffix, `SIGHASH_DEFAULT`). Signing is restricted to
//! P2PKH / P2WPKH / P2TR key-path / P2SH-multisig (Phase 15 — via
//! canonical `REDEEM_SCRIPT` membership) / P2WSH-multisig (v0.3 — via
//! canonical `WITNESS_SCRIPT` membership, BIP-143 with
//! `scriptCode = redeem`); P2WSH without a witness script and
//! redeem-less P2SH inputs answer
//! [`PsbtError::UnsupportedInputScript`].

use k256::ecdsa::{Signature, SigningKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::fwd::{
    MS_TAPSCRIPT_INTERNAL_KEY, PSBT_MAX_SIZE, PSBT_SIGHASH_ALL, PSBT_SIGHASH_DEFAULT,
};
use crate::privkey::{privkey_to_pubkey, sign_hash};
use crate::script::push_data;
use crate::transaction::{
    bip143_sighash, taproot_keypath_sighash, taproot_scriptpath_sighash, taproot_sign_sighash,
    taproot_sign_sighash_untweaked, SpendContext, SpendInput, Transaction, TxIn, TxOut,
};

// --- Errors ----------------------------------------------------------

/// Everything that can go wrong in a PSBT's life. Every variant is a
/// tested branch (specs/spec.md «Rust API surface», errors table).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PsbtError {
    /// The bytes do not start with the `psbt` magic `0x70 0x73 0x62 0x74
    /// 0xFF` — e.g. a raw network transaction was passed instead of a
    /// PSBT (official BIP-174 invalid vector).
    #[error("not a PSBT: bad magic bytes")]
    InvalidMagic,

    /// The byte stream ended in the middle of a keypair, a value, or
    /// before an expected map terminator; also a second map terminator
    /// (a stray `0x00`) and key-type prefixes shorter than their
    /// declared width.
    #[error("PSBT data truncated or structurally malformed")]
    Truncated,

    /// The field-type prefix of a key was not minimally encoded as a
    /// compact size (e.g. `0xFD 0x00 0x02` for type 2).
    #[error("key type compact size is not minimally encoded")]
    NonMinimalCompactSize,

    /// The key data length does not match the field type: a "no key
    /// data" field carried keydata, or a pubkey-keyed field
    /// (`PARTIAL_SIG`, BIP-32 derivation) carried a key that is neither
    /// 33 nor 65 bytes. Carries the offending field type byte.
    #[error("invalid key data length for field type {0}")]
    InvalidKeyLength(u8),

    /// The same full key appeared twice in one map. BIP-174: a PSBT
    /// with duplicate keys is invalid.
    #[error("duplicate key in a PSBT map")]
    DuplicateKey,

    /// The global `VERSION` field carried a value other than 0. PSBTv2
    /// (BIP-370) is an explicit non-goal for Phase 14.
    #[error("unsupported PSBT version {0} (only v0 is supported)")]
    UnsupportedVersion(u32),

    /// The global map has no `UNSIGNED_TX` field (v0 mandate).
    #[error("global map lacks the UNSIGNED_TX field")]
    MissingUnsignedTx,

    /// The `UNSIGNED_TX` value did not parse as a valid unsigned
    /// transaction: malformed wire bytes, zero outputs, a non-empty
    /// `scriptSig`, or witness serialization format.
    #[error("UNSIGNED_TX is not a valid unsigned transaction")]
    InvalidUnsignedTx,

    /// The number of input or output maps differs from the unsigned
    /// transaction's input or output count (including maps missing at
    /// end-of-data or extra maps after the expected ones).
    #[error("input/output map count does not match the unsigned transaction")]
    MapCountMismatch,

    /// A typed field's value was malformed: wrong length (VERSION,
    /// SIGHASH_TYPE), trailing bytes after a UTXO structure, or an
    /// invalid base64 transport encoding.
    #[error("field value malformed")]
    InvalidFieldValue,

    /// The input's UTXO `scriptPubKey` requires redeem/witness script
    /// support yubtc does not implement: a P2WSH script without a
    /// canonical multisig `WITNESS_SCRIPT`, or a P2SH whose redeem
    /// script is absent/non-canonical (a foreign multisig
    /// form — yubtc does not sign or finalize it; R-MS-3). The fields
    /// themselves are preserved.
    #[error("input script requires redeem/witness script support (P2SH/P2WSH)")]
    UnsupportedInputScript,

    /// The `NON_WITNESS_UTXO` of an input being signed does not hash
    /// (`dsha256` of the stripped layout) to the referenced prevout
    /// txid. No signature is produced (BIP-174 "Data Signers Check
    /// For").
    #[error("NON_WITNESS_UTXO does not hash to the referenced prevout txid")]
    UtxoMismatch,

    /// The input carries a `SIGHASH_TYPE` that differs from the sighash
    /// pinned for its form (`SIGHASH_ALL` for P2PKH/P2WPKH,
    /// `SIGHASH_DEFAULT` for P2TR key-path — ОВ-8). The wallet-level
    /// Signer walk treats this as "leave unsigned"; the library
    /// primitive reports it.
    #[error("SIGHASH_TYPE {0} does not match the sighash pinned for this input form")]
    UnsupportedSighashType(u32),

    /// `combine` found the same key with different values. yubtc fails
    /// deterministically instead of picking arbitrarily (spec: KAT
    /// reproducibility; commutativity on disjoint signers is preserved).
    #[error("combine conflict: same key with different values")]
    ConflictingField,

    /// `combine` was called on PSBTs whose global `UNSIGNED_TX` values
    /// differ (byte comparison) — they are not the same transaction.
    #[error("combine refused: UNSIGNED_TX values differ")]
    ForeignTransaction,

    /// An input lacks the data the requested per-input operation needs:
    /// no UTXO field to finalize against, no matching partial
    /// signature, a blocked sighash byte, or an unknown script form.
    /// Carries the input index.
    #[error("input {0} is incomplete for the requested operation")]
    IncompleteInput(usize),

    /// `extract_transaction` refused: at least one input has no
    /// completed final fields (or a form that cannot be validated).
    /// The PSBT is not modified (BIP-174 Extractor MUST).
    #[error("not all inputs are finalized; extraction refused")]
    NotFinalized,

    /// The encoded PSBT exceeds [`crate::PSBT_MAX_SIZE`] (4 MiB) —
    /// rejected before any allocation.
    #[error("PSBT exceeds the {PSBT_MAX_SIZE}-byte size cap")]
    TooLarge,
}

// --- Field type constants (BIP-174 registry) -------------------------

/// Global `UNSIGNED_TX`; per-input `NON_WITNESS_UTXO`; per-output
/// `REDEEM_SCRIPT`.
const T_ZERO: u8 = 0x00;
/// Global `XPUB` (preserve-only, shape-checked).
const T_GLOBAL_XPUB: u8 = 0x01;
/// Per-input `WITNESS_UTXO`; per-output `WITNESS_SCRIPT`.
const T_IN_WITNESS_UTXO: u8 = 0x01;
/// Per-input `PARTIAL_SIG`; per-output `BIP32_DERIVATION`.
const T_PARTIAL_SIG: u8 = 0x02;
/// Per-input `SIGHASH_TYPE` (read-only, pinned-sighash gate).
const T_SIGHASH_TYPE: u8 = 0x03;
/// Per-input `REDEEM_SCRIPT` (preserve: P2SH is out of scope).
const T_REDEEM_SCRIPT: u8 = 0x04;
/// Per-input `WITNESS_SCRIPT` (preserve: P2WSH is out of scope).
const T_WITNESS_SCRIPT: u8 = 0x05;
/// Per-input `BIP32_DERIVATION` (preserve-only, shape-checked).
const T_IN_BIP32_DERIVATION: u8 = 0x06;
/// Per-input `FINAL_SCRIPTSIG`.
const T_FINAL_SCRIPTSIG: u8 = 0x07;
/// Per-input `FINAL_SCRIPTWITNESS`.
const T_FINAL_SCRIPTWITNESS: u8 = 0x08;
/// Per-input `TAP_SCRIPT_SIG` (BIP-371; W/R on the p2tr-multisig
/// path): key = x-only pubkey (32) ‖ leaf_hash (32), value = the
/// 64-byte Schnorr signature (ОВ-17 — no sighash suffix).
const T_IN_TAP_SCRIPT_SIG: u8 = 0x14;
/// Per-input `TAP_LEAF_SCRIPT` (BIP-371; W/R on the p2tr-multisig
/// path): key = control block, value = tapscript ‖ leaf_version.
const T_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
// `TAP_BIP32_DERIVATION` (0x16) is deliberately absent from the typed
// registry: per ОВ-18 it is preserve-only and the Signer ignores the
// field entirely — it flows through the opaque passthrough untouched
// (pinned by the round-trip test below).
/// Per-input `TAP_INTERNAL_KEY` (BIP-371; W/R on the p2tr-multisig
/// path): value = the NUMS internal key (32 bytes).
const T_IN_TAP_INTERNAL_KEY: u8 = 0x17;
/// Per-input `TAP_MERKLE_ROOT` (BIP-371; read-only): never written
/// (the root equals the leaf hash, computable from `0x15`); a present
/// value is verified against the computed leaf hash.
const T_IN_TAP_MERKLE_ROOT: u8 = 0x18;
/// Global `VERSION` (read-only; v0 only; never written).
const T_VERSION: u8 = 0xFB;

/// Valid keydata lengths for pubkey-keyed fields: compressed and
/// uncompressed SEC pubkeys.
const PUBKEY_KEY_LENGTHS: [usize; 2] = [33, 65];

// --- Data types ------------------------------------------------------

/// A SEC public key as carried in PSBT keys: 33-byte compressed
/// (yubtc's own convention) or 65-byte uncompressed (accepted for
/// foreign partial signatures).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKey(pub Vec<u8>);

/// An opaque key/value pair preserved byte-for-byte through the whole
/// pipeline. `key` includes the field-type prefix exactly as it
/// appeared on the wire.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnknownKv {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// One `TAP_SCRIPT_SIG` (0x14) entry: the 64-byte Schnorr signature
/// (`sig`) by the x-only key `x_only` over the leaf `leaf_hash`
/// (BIP-371 key = `x_only ‖ leaf_hash`; ОВ-17 — the signature carries
/// no sighash suffix).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TapScriptSig {
    /// The signer's 32-byte x-only public key (a script key).
    pub x_only: [u8; 32],

    /// `hashTapLeaf` of the leaf the signature commits to.
    pub leaf_hash: [u8; 32],

    /// The 64-byte BIP-340 signature.
    pub sig: Vec<u8>,
}

/// One `TAP_LEAF_SCRIPT` (0x15) entry: a tapscript with its leaf
/// version (`script ‖ 0xc0`) keyed by the control block that reveals
/// it (BIP-371).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TapLeafScript {
    /// The control block (`c[0] ‖ internal key ‖ path`).
    pub control_block: Vec<u8>,

    /// The tapscript with the trailing leaf-version byte.
    pub script_with_version: Vec<u8>,
}

/// Per-input PSBT map (the in-scope typed fields + opaque passthrough).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PsbtInput {
    /// Full previous transaction (`NON_WITNESS_UTXO`, 0x00) — required
    /// by the Creator for legacy (P2PKH) inputs.
    pub non_witness_utxo: Option<Transaction>,

    /// Spent output (`WITNESS_UTXO`, 0x01) — required by the Creator
    /// for witness-form inputs; commits the amount for BIP-143/341.
    pub witness_utxo: Option<TxOut>,

    /// Partial signatures (`PARTIAL_SIG`, 0x02): pubkey → DER sig with
    /// the `SIGHASH_ALL` suffix, or a bare 64-byte Schnorr signature
    /// for P2TR key-path (no suffix, `SIGHASH_DEFAULT`).
    pub partial_sigs: Vec<(PubKey, Vec<u8>)>,

    /// `SIGHASH_TYPE` (0x03). Read-only: accepted only when it matches
    /// the sighash pinned for the input's form (ОВ-8).
    pub sighash_type: Option<u32>,

    /// `REDEEM_SCRIPT` (0x04) — preserve-only.
    pub redeem_script: Option<Vec<u8>>,

    /// `WITNESS_SCRIPT` (0x05) — preserve-only.
    pub witness_script: Option<Vec<u8>>,

    /// Completed input script (`FINAL_SCRIPTSIG`, 0x07). Written by the
    /// Finalizer for legacy (P2PKH) inputs.
    pub final_scriptsig: Option<Vec<u8>>,

    /// Completed witness stack (`FINAL_SCRIPTWITNESS`, 0x08) — the
    /// serialized stack (`compact_size` count + items). Written by the
    /// Finalizer for witness-form inputs.
    pub final_scriptwitness: Option<Vec<u8>>,

    /// `TAP_SCRIPT_SIG` (0x14) — script-path partial signatures
    /// (p2tr-multisig W/R; preserve-typed on other forms).
    pub tap_script_sigs: Vec<TapScriptSig>,

    /// `TAP_LEAF_SCRIPT` (0x15) — revealed tapscripts (p2tr-multisig
    /// W/R; preserve-typed on other forms). yubtc builds exactly one
    /// (single-leaf trees, R-MS-8); the Signer/Finalizer take the
    /// first entry deterministically.
    pub tap_leaf_scripts: Vec<TapLeafScript>,

    /// `TAP_INTERNAL_KEY` (0x17) — the NUMS internal key the Creator
    /// writes for a p2tr-multisig input.
    pub tap_internal_key: Option<[u8; 32]>,

    /// `TAP_MERKLE_ROOT` (0x18) — never written by yubtc; a present
    /// value is verified against the computed leaf hash (read-only).
    pub tap_merkle_root: Option<[u8; 32]>,

    /// Opaque pairs (unknown / preserve-only fields).
    pub unknown: Vec<UnknownKv>,
}

/// Per-output PSBT map. yubtc writes no defined BIP-174 output fields —
/// everything is preserved as opaque pairs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PsbtOutput {
    pub unknown: Vec<UnknownKv>,
}

/// Human-readable per-input line of [`PsbtSummary`] (`psbt decode`).
///
/// `Serialize` (serde) drives the CLI's `psbt decode` JSON dump; the
/// payload is strings/integers/booleans only, so the shape is
/// FFI-friendly and stable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PsbtInputSummary {
    /// UTXO data (either field) is present.
    pub has_utxo: bool,
    /// Number of `PARTIAL_SIG` entries.
    pub n_partial_sigs: usize,
    /// Raw `SIGHASH_TYPE` field, if any.
    pub sighash_type: Option<u32>,
    /// A final field (`FINAL_SCRIPTSIG` or `FINAL_SCRIPTWITNESS`)
    /// is present.
    pub finalized: bool,
}

/// Human-readable per-output line of [`PsbtSummary`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PsbtOutputSummary {
    pub amount_sat: u64,
    pub script_pubkey_hex: String,
}

/// Human-readable PSBT digest (`psbt decode`; not a BIP-174 role).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PsbtSummary {
    /// txid (display order hex) of the unsigned transaction.
    pub txid_hex: String,
    /// PSBT version (always 0 in yubtc).
    pub version: u32,
    pub inputs: Vec<PsbtInputSummary>,
    pub outputs: Vec<PsbtOutputSummary>,
    /// `Σ inputs − Σ outputs` when every input carries UTXO data,
    /// otherwise `None` (the Signer/decoder must work on PSBT data
    /// alone — a warning, not an error, per spec).
    pub fee_sat: Option<u64>,
}

// --- Signing-form dispatch -------------------------------------------

/// The three input forms yubtc can finalize, derived strictly from the
/// UTXO `scriptPubKey` shape. The parsed key commitment (hash160 or
/// the x-only output key) is carried along so consumers never
/// re-extract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// Canonical 25-byte P2PKH, with its 20-byte key hash.
    Legacy([u8; 20]),
    /// Canonical 22-byte P2WPKH (`00 14 <20>`), with its key hash.
    P2wpkh([u8; 20]),
    /// Canonical 34-byte P2TR key-path (`51 20 <32>`), with the
    /// committed x-only output key.
    P2tr([u8; 32]),
}

impl Form {
    /// The sighash pinned for the form (ОВ-8): `SIGHASH_ALL` for the
    /// ECDSA forms, `SIGHASH_DEFAULT` for the P2TR key-path.
    fn pinned_sighash(self) -> u32 {
        match self {
            Form::Legacy(_) | Form::P2wpkh(_) => PSBT_SIGHASH_ALL,
            Form::P2tr(_) => PSBT_SIGHASH_DEFAULT,
        }
    }
}

/// Strict form classification by `scriptPubKey` shape. P2SH, P2WSH and
/// anything non-canonical → `None` (unsupported for
/// finalizing/extracting; the Signer answers
/// [`PsbtError::UnsupportedInputScript`] separately).
fn form_of_script(script_pubkey: &[u8]) -> Option<Form> {
    if let Ok(hash) = crate::script::extract_p2pkh_hash(script_pubkey) {
        return Some(Form::Legacy(hash));
    }
    if let Ok(hash) = crate::script::extract_p2wpkh_hash(script_pubkey) {
        return Some(Form::P2wpkh(hash));
    }
    if let Ok(key) = crate::script::extract_p2tr_output_key(script_pubkey) {
        return Some(Form::P2tr(key));
    }
    None
}

/// True when the script is a canonical P2SH (`a9 14 <20> 87`).
fn is_p2sh_script(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == crate::script::OP_HASH160
        && script[1] == 0x14
        && script[22] == crate::script::OP_EQUAL
}

/// True when the script is a canonical P2WSH (`00 20 <32>`).
fn is_p2wsh_script(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == crate::script::OP_0 && script[1] == 0x20
}

/// True when the script is a canonical P2TR (`51 20 <32>`).
fn is_p2tr_script(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == crate::script::OP_1 && script[1] == 0x20
}

#[cfg(test)]
mod shape_helper_tests {
    //! The 34-byte SegWit-program shape helpers distinguish their
    //! form from the *other* 34-byte program (P2WSH vs P2TR), not
    //! just from arbitrary bytes — pinned here directly.

    #[test]
    fn p2tr_and_p2wsh_shape_helpers_reject_each_other() {
        use super::{is_p2tr_script, is_p2wsh_script};
        let mut wsh = vec![0x00, 0x20];
        wsh.extend_from_slice(&[0x11; 32]);
        let mut tr = vec![crate::script::OP_1, 0x20];
        tr.extend_from_slice(&[0x22; 32]);
        assert!(is_p2wsh_script(&wsh));
        assert!(!is_p2wsh_script(&tr));
        assert!(is_p2tr_script(&tr));
        assert!(!is_p2tr_script(&wsh));
        // Not a 34-byte program at all.
        assert!(!is_p2tr_script(&[0x51; 33]));
        assert!(!is_p2wsh_script(&[0x00; 33]));
    }
}

// --- Wire primitives -------------------------------------------------

/// One key/value pair of a PSBT map: full key bytes (including the
/// field-type prefix) and the raw value.
type KvPair = (Vec<u8>, Vec<u8>);

/// Sequential reader over a PSBT byte slice. All reads are
/// bounds-checked; any over-read is [`PsbtError::Truncated`] — there
/// are no panics and no oversized allocations (values are slices into
/// the input, never copied up-front).
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Byte at `pos + offset` without consuming.
    fn peek(&self, offset: usize) -> Option<u8> {
        self.data.get(self.pos + offset).copied()
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], PsbtError> {
        if n > self.remaining() as u64 {
            return Err(PsbtError::Truncated);
        }
        let n = n as usize;
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], PsbtError> {
        let bytes = self.take(N as u64)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Bitcoin CompactSize. Encoding-strictness is deliberately relaxed
    /// here (only the *key type* prefix must be minimal per spec); the
    /// 4 MiB cap plus slice-based reads make oversized lengths a plain
    /// truncation, not an allocation bomb.
    fn read_compact_size(&mut self) -> Result<u64, PsbtError> {
        let prefix = self.read_array::<1>()?[0];
        match prefix {
            0x00..=0xfc => Ok(u64::from(prefix)),
            0xfd => Ok(u64::from(u16::from_le_bytes(self.read_array::<2>()?))),
            0xfe => Ok(u64::from(u32::from_le_bytes(self.read_array::<4>()?))),
            _ => Ok(u64::from_le_bytes(self.read_array::<8>()?)),
        }
    }
}

/// Append the CompactSize encoding of `n` to `out`.
fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Split a PSBT key into `(field type, keydata)`. The type prefix must
/// be a minimally-encoded CompactSize ([`PsbtError::
/// NonMinimalCompactSize`] otherwise); a truncated prefix is
/// [`PsbtError::Truncated`].
fn split_key(key: &[u8]) -> Result<(u64, &[u8]), PsbtError> {
    let prefix = *key.first().ok_or(PsbtError::Truncated)?;
    let (ty, header_len) = match prefix {
        0x00..=0xfc => (u64::from(prefix), 1),
        0xfd => {
            if key.len() < 3 {
                return Err(PsbtError::Truncated);
            }
            let v = u64::from(u16::from_le_bytes([key[1], key[2]]));
            if v < 0xfd {
                return Err(PsbtError::NonMinimalCompactSize);
            }
            (v, 3)
        }
        0xfe => {
            if key.len() < 5 {
                return Err(PsbtError::Truncated);
            }
            let v = u64::from(u32::from_le_bytes([key[1], key[2], key[3], key[4]]));
            if v <= 0xffff {
                return Err(PsbtError::NonMinimalCompactSize);
            }
            (v, 5)
        }
        _ => {
            if key.len() < 9 {
                return Err(PsbtError::Truncated);
            }
            let v = u64::from_le_bytes([
                key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8],
            ]);
            if v <= 0xffff_ffff {
                return Err(PsbtError::NonMinimalCompactSize);
            }
            (v, 9)
        }
    };
    Ok((ty, &key[header_len..]))
}

/// Keydata length check for pubkey-keyed fields (`PARTIAL_SIG`,
/// BIP-32 derivation): exactly 33 or 65 bytes.
fn pubkey_keydata_len(keydata: &[u8]) -> bool {
    PUBKEY_KEY_LENGTHS.contains(&keydata.len())
}

// --- Transaction parsing (values of UNSIGNED_TX / NON_WITNESS_UTXO) --

/// Parse a raw transaction in wire format (BIP-144; witness stacks
/// allowed), e.g. the hex payload
/// [`crate::net::NetworkBackend::raw_transaction`] returns for a
/// legacy input's `NON_WITNESS_UTXO` (the Creator's prev-tx source,
/// Phase 14 stage 2). Any structural defect — truncation, trailing
/// bytes, non-minimal counts — surfaces as the corresponding
/// [`PsbtError`]; there are no panics.
pub fn parse_wire_tx(data: &[u8]) -> Result<Transaction, PsbtError> {
    parse_tx(data, true)
}

/// Parse a transaction from `data`. When `segwit_allowed` the BIP-144
/// marker/flag layout is accepted (used for `NON_WITNESS_UTXO`, which
/// may carry witness data); otherwise the stripped layout only (used
/// for `UNSIGNED_TX`, which must never carry a witness). Counts and
/// lengths use minimally-bounded CompactSize reads; any over-read or
/// trailing bytes are [`PsbtError::Truncated`].
fn parse_tx(data: &[u8], segwit_allowed: bool) -> Result<Transaction, PsbtError> {
    let mut r = Reader::new(data);
    let version = i32::from_le_bytes(r.read_array::<4>()?);
    // BIP-144 detection: a stripped tx with ≥ 1 input cannot start its
    // vin count with 0x00, so `00 01` after the version is an
    // unambiguous marker/flag pair. (Same heuristic as Bitcoin Core.)
    let segwit =
        segwit_allowed && r.remaining() >= 2 && r.peek(0) == Some(0x00) && r.peek(1) == Some(0x01);
    if segwit {
        r.take(2)?;
    }
    let n_vin = r.read_compact_size()?;
    // Each input occupies ≥ 41 bytes, so a count above the remaining
    // length is truncated data; this also bounds the loop below.
    if n_vin > r.remaining() as u64 {
        return Err(PsbtError::Truncated);
    }
    let mut vin = Vec::new();
    for _ in 0..n_vin {
        let txhash = r.read_array::<32>()?;
        let n = u32::from_le_bytes(r.read_array::<4>()?);
        let script_len = r.read_compact_size()?;
        let script = r.take(script_len)?.to_vec();
        let sequence = u32::from_le_bytes(r.read_array::<4>()?);
        vin.push(TxIn {
            txhash,
            n,
            script,
            sequence,
            witness: Vec::new(),
        });
    }
    let n_vout = r.read_compact_size()?;
    // Each output occupies ≥ 9 bytes — same bound as the inputs.
    if n_vout > r.remaining() as u64 {
        return Err(PsbtError::Truncated);
    }
    let mut vout = Vec::new();
    for _ in 0..n_vout {
        let amount = u64::from_le_bytes(r.read_array::<8>()?);
        let script_len = r.read_compact_size()?;
        let script = r.take(script_len)?.to_vec();
        vout.push(TxOut { amount, script });
    }
    if segwit {
        for vin_item in vin.iter_mut() {
            let n_items = r.read_compact_size()?;
            if n_items > r.remaining() as u64 {
                return Err(PsbtError::Truncated);
            }
            let mut stack = Vec::new();
            for _ in 0..n_items {
                let item_len = r.read_compact_size()?;
                stack.push(r.take(item_len)?.to_vec());
            }
            vin_item.witness = stack;
        }
    }
    let locktime = u32::from_le_bytes(r.read_array::<4>()?);
    if !r.at_end() {
        return Err(PsbtError::Truncated);
    }
    Ok(Transaction {
        version,
        vin,
        vout,
        locktime,
    })
}

/// Parse a `WITNESS_UTXO` value: `amount (u64 LE) ‖ compact_size ‖
/// scriptPubKey`. Trailing bytes → [`PsbtError::InvalidFieldValue`].
fn parse_witness_utxo(data: &[u8]) -> Result<TxOut, PsbtError> {
    let mut r = Reader::new(data);
    let amount = u64::from_le_bytes(r.read_array::<8>()?);
    let script_len = r.read_compact_size()?;
    let script = r.take(script_len)?.to_vec();
    if !r.at_end() {
        return Err(PsbtError::InvalidFieldValue);
    }
    Ok(TxOut { amount, script })
}

/// Serialize a witness stack (`FINAL_SCRIPTWITNESS` value): the
/// `compact_size` element count followed by length-prefixed items.
fn encode_witness_stack(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    write_compact_size(&mut out, items.len() as u64);
    for item in items {
        write_compact_size(&mut out, item.len() as u64);
        out.extend_from_slice(item);
    }
    out
}

/// Decode a serialized witness stack. `Err(())` on any malformed input
/// (mapped by callers to a typed [`PsbtError`]).
fn decode_witness_stack(data: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    let mut r = Reader::new(data);
    let n_items = r.read_compact_size().map_err(|_| ())?;
    if n_items > r.remaining() as u64 {
        return Err(());
    }
    let mut stack = Vec::new();
    for _ in 0..n_items {
        let item_len = r.read_compact_size().map_err(|_| ())?;
        stack.push(r.take(item_len).map_err(|_| ())?.to_vec());
    }
    if !r.at_end() {
        return Err(());
    }
    Ok(stack)
}

/// Double SHA-256 in internal (non-reversed) byte order.
fn dsha256(data: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&Sha256::digest(Sha256::digest(data)));
    arr
}

// --- The PSBT type ----------------------------------------------------

/// A parsed PSBT: the unsigned transaction plus one map per input and
/// per output and the opaque global leftovers. Construct via
/// [`PartiallySignedTransaction::parse`],
/// [`PartiallySignedTransaction::create`] or [`PartiallySignedTransaction::from_base64`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartiallySignedTransaction {
    /// PSBT version. Always 0: the parser rejects anything else
    /// ([`PsbtError::UnsupportedVersion`]) and the serializer never
    /// writes the `VERSION` field (absence encodes v0).
    pub version: u32,

    /// The global `UNSIGNED_TX` (stripped serialization; all `scriptSig`
    /// and witness data empty).
    pub unsigned_tx: Transaction,

    /// One map per `vin` entry, in `vin` order.
    pub inputs: Vec<PsbtInput>,

    /// One map per `vout` entry, in `vout` order.
    pub outputs: Vec<PsbtOutput>,

    /// Opaque global pairs (xpubs, proprietary fields, anything
    /// unassigned) — carried byte-for-byte.
    pub unknown_global: Vec<UnknownKv>,
}

/// Creator input descriptor: the UTXO metadata of one `vin` entry.
#[derive(Debug, Clone)]
pub struct CreateInput {
    /// Spent amount in satoshi (committed by BIP-143/341 digests).
    pub amount: u64,

    /// `scriptPubKey` of the spent output.
    pub script_pubkey: Vec<u8>,

    /// Full previous transaction — **required** for legacy (P2PKH)
    /// inputs and for P2SH-multisig inputs (Phase 15): it becomes the
    /// `NON_WITNESS_UTXO` field. Fetched via
    /// [`crate::net::NetworkBackend::raw_transaction`]. Ignored for
    /// other inputs (the Creator writes exactly one UTXO field per
    /// form, per spec).
    pub prev_tx: Option<Transaction>,

    /// The redeem script of a P2SH input (Phase 15). When present for a
    /// canonical P2SH `scriptPubKey`, the Creator takes the
    /// P2SH-multisig branch: the input gets `NON_WITNESS_UTXO` +
    /// `REDEEM_SCRIPT (0x04)` (the field becomes W/R on that path;
    /// preserve-only otherwise). Absent — the pre-Phase-15 behaviour
    /// (a bare P2SH input is a foreign form backed by a
    /// `WITNESS_UTXO`).
    pub redeem_script: Option<Vec<u8>>,

    /// The witness script of a P2WSH input (v0.3, spec «P2WSH
    /// (v0.3)»). When present for a canonical P2WSH `scriptPubKey`,
    /// the Creator takes the P2WSH-multisig branch: the input gets
    /// `WITNESS_UTXO` + `WITNESS_SCRIPT (0x05)` (the field becomes
    /// W/R on that path; preserve-only otherwise) — no
    /// `NON_WITNESS_UTXO`, no prev-tx fetch (BIP-143 commits the
    /// amount). Absent — the pre-v0.3 behaviour (a bare P2WSH input
    /// is a foreign form backed by a `WITNESS_UTXO`).
    pub witness_script: Option<Vec<u8>>,

    /// The tapscript leaf of a P2TR input (v0.3, spec «Tapscript
    /// (P2TR script-path) (v0.3)»): the `TAP_LEAF_SCRIPT` **value**
    /// `script ‖ 0xc0`. When present for a canonical P2TR
    /// `scriptPubKey`, the Creator takes the Tapscript-multisig
    /// branch: the input gets `WITNESS_UTXO` + `TAP_LEAF_SCRIPT
    /// (0x15)` (the control-block key the Creator builds itself from
    /// the NUMS internal key and the leaf hash) +
    /// `TAP_INTERNAL_KEY (0x17)` — no `NON_WITNESS_UTXO`, no prev-tx
    /// fetch (BIP-341 commits the amount via the `WITNESS_UTXO`).
    /// Absent — the Phase 13 behaviour (a bare P2TR input is a
    /// key-path output backed by a `WITNESS_UTXO`).
    pub tap_leaf_script: Option<Vec<u8>>,
}

impl PartiallySignedTransaction {
    /// Parse a PSBT from its wire encoding.
    ///
    /// Applies the full validation ladder (specs/spec.md «Валидация»): size
    /// cap, magic, map structure and terminators, key/value rules,
    /// duplicates, `UNSIGNED_TX` presence and semantics (parses as a
    /// stripped transaction, ≥ 1 output, no scriptSig data), version 0,
    /// and map counts matching the transaction.
    pub fn parse(data: &[u8]) -> Result<Self, PsbtError> {
        if data.len() > PSBT_MAX_SIZE {
            return Err(PsbtError::TooLarge);
        }
        const MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];
        if data.len() < MAGIC.len() || data[..MAGIC.len()] != MAGIC {
            return Err(PsbtError::InvalidMagic);
        }
        let mut r = Reader::new(&data[MAGIC.len()..]);

        let global_pairs = read_map(&mut r)?;
        let mut version: u32 = 0;
        let mut unsigned_tx: Option<Transaction> = None;
        let mut unknown_global: Vec<UnknownKv> = Vec::new();
        for (key, value) in global_pairs {
            let (ty, keydata) = split_key(&key)?;
            if ty > u64::from(u8::MAX) {
                // Field types beyond the BIP-174 registry — opaque.
                unknown_global.push(UnknownKv { key, value });
                continue;
            }
            let ty = ty as u8;
            match ty {
                T_ZERO => {
                    // `UNSIGNED_TX` — "no key data" type.
                    if !keydata.is_empty() {
                        return Err(PsbtError::InvalidKeyLength(T_ZERO));
                    }
                    let tx = parse_tx(&value, false).map_err(|_| PsbtError::InvalidUnsignedTx)?;
                    if tx.vout.is_empty() || tx.vin.iter().any(|i| !i.script.is_empty()) {
                        return Err(PsbtError::InvalidUnsignedTx);
                    }
                    unsigned_tx = Some(tx);
                }
                T_VERSION => {
                    if !keydata.is_empty() {
                        return Err(PsbtError::InvalidKeyLength(T_VERSION));
                    }
                    if value.len() != 4 {
                        return Err(PsbtError::InvalidFieldValue);
                    }
                    version = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                    if version != 0 {
                        return Err(PsbtError::UnsupportedVersion(version));
                    }
                }
                T_GLOBAL_XPUB => {
                    // Preserve-only, but the BIP-defined key shape is
                    // still validated: 78-byte serialized xpub. The
                    // value (master fingerprint + derivation path) is
                    // carried opaque — the path is not interpreted.
                    if keydata.len() != 78 {
                        return Err(PsbtError::InvalidKeyLength(T_GLOBAL_XPUB));
                    }
                    unknown_global.push(UnknownKv { key, value });
                }
                _ => {
                    unknown_global.push(UnknownKv { key, value });
                }
            }
        }
        let unsigned_tx = unsigned_tx.ok_or(PsbtError::MissingUnsignedTx)?;

        let mut inputs = Vec::with_capacity(unsigned_tx.vin.len());
        for _ in 0..unsigned_tx.vin.len() {
            if r.at_end() {
                return Err(PsbtError::MapCountMismatch);
            }
            let pairs = read_map(&mut r)?;
            inputs.push(parse_input_map(pairs)?);
        }
        let mut outputs = Vec::with_capacity(unsigned_tx.vout.len());
        for _ in 0..unsigned_tx.vout.len() {
            if r.at_end() {
                return Err(PsbtError::MapCountMismatch);
            }
            let pairs = read_map(&mut r)?;
            outputs.push(parse_output_map(pairs)?);
        }
        if !r.at_end() {
            // Leftover bytes: an all-zero tail is a stray second map
            // terminator (spec: «второй терминатор — Truncated»);
            // anything else is one map too many.
            if r.data[r.pos..].iter().all(|&b| b == 0) {
                return Err(PsbtError::Truncated);
            }
            return Err(PsbtError::MapCountMismatch);
        }
        Ok(Self {
            version,
            unsigned_tx,
            inputs,
            outputs,
            unknown_global,
        })
    }

    /// Serialize in canonical form: pairs of every map sorted by full
    /// key bytes (type, then keydata, lexicographic), maps in fixed
    /// order (global, inputs, outputs). `serialize(parse(x)) == x`
    /// holds for any canonically-ordered `x`; one canonization pass is
    /// stable (`serialize(parse(serialize(parse(x)))) ==
    /// serialize(parse(x))`).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x70, 0x73, 0x62, 0x74, 0xff]);
        let mut global: Vec<KvPair> = vec![(vec![T_ZERO], self.unsigned_tx.serialize_stripped())];
        for kv in &self.unknown_global {
            global.push((kv.key.clone(), kv.value.clone()));
        }
        write_map(&mut out, global);
        for input in &self.inputs {
            write_map(&mut out, self.input_pairs(input));
        }
        for output in &self.outputs {
            let pairs: Vec<KvPair> = output
                .unknown
                .iter()
                .map(|kv| (kv.key.clone(), kv.value.clone()))
                .collect();
            write_map(&mut out, pairs);
        }
        out
    }

    /// The typed + opaque pairs of one input map, pre-sorting.
    fn input_pairs(&self, input: &PsbtInput) -> Vec<KvPair> {
        let mut pairs = Vec::new();
        if let Some(prev) = &input.non_witness_utxo {
            pairs.push((vec![T_ZERO], prev.serialize_wire()));
        }
        if let Some(utxo) = &input.witness_utxo {
            let mut value = Vec::new();
            value.extend_from_slice(&utxo.amount.to_le_bytes());
            write_compact_size(&mut value, utxo.script.len() as u64);
            value.extend_from_slice(&utxo.script);
            pairs.push((vec![T_IN_WITNESS_UTXO], value));
        }
        for (pubkey, sig) in &input.partial_sigs {
            let mut key = vec![T_PARTIAL_SIG];
            key.extend_from_slice(&pubkey.0);
            pairs.push((key, sig.clone()));
        }
        if let Some(t) = input.sighash_type {
            pairs.push((vec![T_SIGHASH_TYPE], t.to_le_bytes().to_vec()));
        }
        if let Some(script) = &input.redeem_script {
            pairs.push((vec![T_REDEEM_SCRIPT], script.clone()));
        }
        if let Some(script) = &input.witness_script {
            pairs.push((vec![T_WITNESS_SCRIPT], script.clone()));
        }
        // BIP-371 taproot fields: W/R on the p2tr-multisig path,
        // preserve-typed elsewhere. `TAP_BIP32_DERIVATION` (0x16)
        // stays in the opaque passthrough entirely (ОВ-18).
        for s in &input.tap_script_sigs {
            let mut key = vec![T_IN_TAP_SCRIPT_SIG];
            key.extend_from_slice(&s.x_only);
            key.extend_from_slice(&s.leaf_hash);
            pairs.push((key, s.sig.clone()));
        }
        for leaf in &input.tap_leaf_scripts {
            let mut key = vec![T_IN_TAP_LEAF_SCRIPT];
            key.extend_from_slice(&leaf.control_block);
            pairs.push((key, leaf.script_with_version.clone()));
        }
        if let Some(internal) = &input.tap_internal_key {
            pairs.push((vec![T_IN_TAP_INTERNAL_KEY], internal.to_vec()));
        }
        if let Some(root) = &input.tap_merkle_root {
            pairs.push((vec![T_IN_TAP_MERKLE_ROOT], root.to_vec()));
        }
        // BIP-174: an empty final scriptSig is serialized as "unset",
        // never as an empty value.
        if let Some(script) = &input.final_scriptsig {
            if !script.is_empty() {
                pairs.push((vec![T_FINAL_SCRIPTSIG], script.clone()));
            }
        }
        if let Some(stack) = &input.final_scriptwitness {
            if !stack.is_empty() {
                pairs.push((vec![T_FINAL_SCRIPTWITNESS], stack.clone()));
            }
        }
        for kv in &input.unknown {
            pairs.push((kv.key.clone(), kv.value.clone()));
        }
        pairs
    }

    /// UTXO metadata of input `index`: `(scriptPubKey, amount)` taken
    /// from `WITNESS_UTXO` when present, else from the `vout` entry the
    /// input spends inside `NON_WITNESS_UTXO`. `None` when the input
    /// carries no usable UTXO data (the Signer silently skips such
    /// inputs — BIP-174 MUST).
    pub fn input_utxo_data(&self, index: usize) -> Option<(Vec<u8>, u64)> {
        let input = self.inputs.get(index)?;
        if let Some(utxo) = &input.witness_utxo {
            return Some((utxo.script.clone(), utxo.amount));
        }
        let prev = input.non_witness_utxo.as_ref()?;
        let n = self.unsigned_tx.vin.get(index)?.n as usize;
        let out = prev.vout.get(n)?;
        Some((out.script.clone(), out.amount))
    }

    /// Per-input BIP-341 digest context: `SpendInput` for every input
    /// of the transaction, from [`Self::input_utxo_data`]. `None` when
    /// any input lacks UTXO data (a key-path P2TR digest commits to all
    /// inputs, so the input becomes unsignable rather than the whole
    /// signing pass failing).
    fn spend_context(&self) -> Option<SpendContext> {
        let mut inputs = Vec::with_capacity(self.unsigned_tx.vin.len());
        for i in 0..self.unsigned_tx.vin.len() {
            let (script_pubkey, amount) = self.input_utxo_data(i)?;
            inputs.push(SpendInput {
                amount,
                script_pubkey,
            });
        }
        Some(SpendContext { inputs })
    }
}

/// Read one key/value map; the zero-length key terminates it.
/// Duplicate full keys are [`PsbtError::DuplicateKey`] (BIP-174:
/// "Handling Duplicated Keys" — a PSBT with duplicates is invalid).
fn read_map(r: &mut Reader) -> Result<Vec<KvPair>, PsbtError> {
    let mut out: Vec<KvPair> = Vec::new();
    let mut seen: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    loop {
        if r.at_end() {
            return Err(PsbtError::Truncated);
        }
        let keylen = r.read_compact_size()?;
        if keylen == 0 {
            return Ok(out);
        }
        let key = r.take(keylen)?.to_vec();
        if !seen.insert(key.clone()) {
            return Err(PsbtError::DuplicateKey);
        }
        let valuelen = r.read_compact_size()?;
        let value = r.take(valuelen)?.to_vec();
        out.push((key, value));
    }
}

/// Emit one map: pairs sorted by full key bytes, then the terminator.
fn write_map(out: &mut Vec<u8>, mut pairs: Vec<KvPair>) {
    // Keys are unique within a map (parse rejects duplicates; the
    // creators below build unique keys), so the order is total and the
    // canonical form deterministic.
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, value) in pairs {
        write_compact_size(out, key.len() as u64);
        out.extend_from_slice(&key);
        write_compact_size(out, value.len() as u64);
        out.extend_from_slice(&value);
    }
    out.push(0);
}

/// Interpret one input map's entries into a [`PsbtInput`].
fn parse_input_map(pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<PsbtInput, PsbtError> {
    let mut input = PsbtInput::default();
    for (key, value) in pairs {
        let (ty, keydata) = split_key(&key)?;
        if ty > u64::from(u8::MAX) {
            input.unknown.push(UnknownKv { key, value });
            continue;
        }
        let ty = ty as u8;
        match ty {
            T_ZERO => {
                // `NON_WITNESS_UTXO`: full previous tx, wire format
                // (witness allowed); must consume the value exactly.
                if !keydata.is_empty() {
                    return Err(PsbtError::InvalidKeyLength(T_ZERO));
                }
                let tx = parse_tx(&value, true).map_err(|_| PsbtError::InvalidFieldValue)?;
                input.non_witness_utxo = Some(tx);
            }
            T_IN_WITNESS_UTXO => {
                if !keydata.is_empty() {
                    return Err(PsbtError::InvalidKeyLength(T_IN_WITNESS_UTXO));
                }
                input.witness_utxo = Some(parse_witness_utxo(&value)?);
            }
            T_PARTIAL_SIG => {
                if !pubkey_keydata_len(keydata) {
                    return Err(PsbtError::InvalidKeyLength(T_PARTIAL_SIG));
                }
                input.partial_sigs.push((PubKey(keydata.to_vec()), value));
            }
            T_SIGHASH_TYPE => {
                if !keydata.is_empty() {
                    return Err(PsbtError::InvalidKeyLength(T_SIGHASH_TYPE));
                }
                if value.len() != 4 {
                    return Err(PsbtError::InvalidFieldValue);
                }
                input.sighash_type =
                    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]));
            }
            T_REDEEM_SCRIPT => {
                if !keydata.is_empty() {
                    return Err(PsbtError::InvalidKeyLength(T_REDEEM_SCRIPT));
                }
                input.redeem_script = Some(value);
            }
            T_WITNESS_SCRIPT => {
                if !keydata.is_empty() {
                    return Err(PsbtError::InvalidKeyLength(T_WITNESS_SCRIPT));
                }
                input.witness_script = Some(value);
            }
            T_IN_BIP32_DERIVATION => {
                // Preserve-only; the pubkey key shape is still validated
                // (official BIP-174 invalid vector: 32-byte "pubkey").
                if !pubkey_keydata_len(keydata) {
                    return Err(PsbtError::InvalidKeyLength(T_IN_BIP32_DERIVATION));
                }
                input.unknown.push(UnknownKv { key, value });
            }
            T_FINAL_SCRIPTSIG => {
                if !keydata.is_empty() {
                    return Err(PsbtError::InvalidKeyLength(T_FINAL_SCRIPTSIG));
                }
                input.final_scriptsig = Some(value);
            }
            T_FINAL_SCRIPTWITNESS => {
                if !keydata.is_empty() {
                    return Err(PsbtError::InvalidKeyLength(T_FINAL_SCRIPTWITNESS));
                }
                input.final_scriptwitness = Some(value);
            }
            T_IN_TAP_SCRIPT_SIG => {
                // BIP-371 key: x-only pubkey (32) ‖ leaf_hash (32).
                if keydata.len() != 64 {
                    return Err(PsbtError::InvalidKeyLength(T_IN_TAP_SCRIPT_SIG));
                }
                let mut x_only = [0u8; 32];
                x_only.copy_from_slice(&keydata[..32]);
                let mut leaf_hash = [0u8; 32];
                leaf_hash.copy_from_slice(&keydata[32..]);
                input.tap_script_sigs.push(TapScriptSig {
                    x_only,
                    leaf_hash,
                    sig: value,
                });
            }
            T_IN_TAP_LEAF_SCRIPT => {
                // BIP-371 key: the control block — 33 bytes for a
                // single-leaf tree (`33 + 32·depth`, depth = 0).
                if keydata.len() != 33 {
                    return Err(PsbtError::InvalidKeyLength(T_IN_TAP_LEAF_SCRIPT));
                }
                if value.is_empty() {
                    return Err(PsbtError::InvalidFieldValue);
                }
                input.tap_leaf_scripts.push(TapLeafScript {
                    control_block: keydata.to_vec(),
                    script_with_version: value,
                });
            }
            T_IN_TAP_INTERNAL_KEY => {
                if !keydata.is_empty() {
                    return Err(PsbtError::InvalidKeyLength(T_IN_TAP_INTERNAL_KEY));
                }
                if value.len() != 32 {
                    return Err(PsbtError::InvalidFieldValue);
                }
                input.tap_internal_key =
                    Some(value.try_into().expect("32-byte value checked above"));
            }
            T_IN_TAP_MERKLE_ROOT => {
                if !keydata.is_empty() {
                    return Err(PsbtError::InvalidKeyLength(T_IN_TAP_MERKLE_ROOT));
                }
                if value.len() != 32 {
                    return Err(PsbtError::InvalidFieldValue);
                }
                input.tap_merkle_root =
                    Some(value.try_into().expect("32-byte value checked above"));
            }
            _ => input.unknown.push(UnknownKv { key, value }),
        }
    }
    Ok(input)
}

/// Interpret one output map's entries. yubtc writes no defined output
/// fields, but the BIP-174 output key shapes are validated
/// (`REDEEM_SCRIPT` 0x00 / `WITNESS_SCRIPT` 0x01 — no keydata;
/// `BIP32_DERIVATION` 0x02 — pubkey keydata) before the pair is
/// preserved.
fn parse_output_map(pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<PsbtOutput, PsbtError> {
    let mut output = PsbtOutput::default();
    for (key, value) in pairs {
        let (ty, keydata) = split_key(&key)?;
        if ty > u64::from(u8::MAX) {
            output.unknown.push(UnknownKv { key, value });
            continue;
        }
        let ty = ty as u8;
        match ty {
            T_ZERO | T_IN_WITNESS_UTXO => {
                // Per-output REDEEM_SCRIPT (0x00) / WITNESS_SCRIPT (0x01).
                if !keydata.is_empty() {
                    return Err(PsbtError::InvalidKeyLength(ty));
                }
                output.unknown.push(UnknownKv { key, value });
            }
            T_PARTIAL_SIG => {
                // Per-output BIP32_DERIVATION (0x02).
                if !pubkey_keydata_len(keydata) {
                    return Err(PsbtError::InvalidKeyLength(T_PARTIAL_SIG));
                }
                output.unknown.push(UnknownKv { key, value });
            }
            _ => output.unknown.push(UnknownKv { key, value }),
        }
    }
    Ok(output)
}

// --- Roles -----------------------------------------------------------

impl PartiallySignedTransaction {
    /// Creator (+Updater, spec «Роли»): wrap an unsigned transaction
    /// and its UTXO metadata into a fresh PSBT.
    ///
    /// `unsigned_tx` must be truly unsigned — empty `scriptSig` and
    /// empty witness stacks (the official BIP-174 vector with a filled
    /// scriptSig is exactly this refusal) — with at least one output,
    /// and `inputs` must parallel `vin`. For every legacy (P2PKH)
    /// input a `prev_tx` whose txid matches the outpoint is required;
    /// witness-form inputs get a `WITNESS_UTXO` from `(amount,
    /// script_pubkey)`. Known derivation data the wallet does not have
    /// (xpubs, BIP-32 paths) is deliberately not written (ОВ-9).
    pub fn create(unsigned_tx: Transaction, inputs: Vec<CreateInput>) -> Result<Self, PsbtError> {
        if unsigned_tx.vout.is_empty() {
            return Err(PsbtError::InvalidUnsignedTx);
        }
        if unsigned_tx.vin.len() != inputs.len() {
            return Err(PsbtError::MapCountMismatch);
        }
        if unsigned_tx
            .vin
            .iter()
            .any(|v| !v.script.is_empty() || !v.witness.is_empty())
        {
            return Err(PsbtError::InvalidUnsignedTx);
        }
        let mut psbt_inputs = Vec::with_capacity(inputs.len());
        for (i, (vin, create)) in unsigned_tx.vin.iter().zip(inputs).enumerate() {
            if matches!(form_of_script(&create.script_pubkey), Some(Form::Legacy(_))) {
                let prev = create.prev_tx.ok_or(PsbtError::IncompleteInput(i))?;
                if prev.id() != vin.txhash {
                    return Err(PsbtError::UtxoMismatch);
                }
                psbt_inputs.push(PsbtInput {
                    non_witness_utxo: Some(prev),
                    witness_utxo: None,
                    ..PsbtInput::default()
                });
            } else if is_p2sh_script(&create.script_pubkey) && create.redeem_script.is_some() {
                // Phase 15 Creator branch (spec «PSBT: Creator, Signer и
                // Finalizer»): the input spends the P2SH of a known
                // redeem script — an explicit-address multisig UTXO.
                // The redeem script must be canonical (R-MS-3) and hash
                // to the `scriptPubKey` commitment; the full prev tx is
                // mandatory (a P2SH input is legacy — no witness
                // discount, no BIP-143 amount commitment).
                let redeem = create
                    .redeem_script
                    .expect("checked Some in the branch condition above");
                crate::script::extract_multisig_quorum(&redeem)
                    .map_err(|_| PsbtError::UnsupportedInputScript)?;
                let committed: [u8; 20] = create.script_pubkey[2..22]
                    .try_into()
                    .expect("canonical P2SH carries a 20-byte hash at bytes 2..22");
                if crate::address::hash160_script(&redeem) != committed {
                    return Err(PsbtError::UtxoMismatch);
                }
                let prev = create.prev_tx.ok_or(PsbtError::IncompleteInput(i))?;
                if prev.id() != vin.txhash {
                    return Err(PsbtError::UtxoMismatch);
                }
                psbt_inputs.push(PsbtInput {
                    non_witness_utxo: Some(prev),
                    witness_utxo: None,
                    redeem_script: Some(redeem),
                    witness_script: None,
                    ..PsbtInput::default()
                });
            } else if let Some(redeem) = create.witness_script {
                if !is_p2wsh_script(&create.script_pubkey) {
                    // A witness script on a non-P2WSH input is not a
                    // Creator surface yubtc builds — fall through to
                    // the default `WITNESS_UTXO` arm below (the
                    // witness-script field is dropped: preserve-only
                    // semantics for foreign forms).
                    psbt_inputs.push(PsbtInput {
                        non_witness_utxo: None,
                        witness_utxo: Some(TxOut {
                            amount: create.amount,
                            script: create.script_pubkey,
                        }),
                        ..PsbtInput::default()
                    });
                } else {
                    // Creator branch, P2WSH-multisig (spec «Multi-sig»): the
                    // input spends the P2WSH of a known witness script
                    // — the witness form of the multisig quorum. The
                    // witness script must be canonical (R-MS-3) and
                    // SHA-256-commit to the `scriptPubKey` program;
                    // the UTXO rides as `WITNESS_UTXO` (BIP-143
                    // commits the amount — no `NON_WITNESS_UTXO`, no
                    // prev-tx fetch), and `WITNESS_SCRIPT (0x05)`
                    // becomes W/R on this path.
                    crate::script::extract_multisig_quorum(&redeem)
                        .map_err(|_| PsbtError::UnsupportedInputScript)?;
                    let committed: [u8; 32] = create.script_pubkey[2..34]
                        .try_into()
                        .expect("canonical P2WSH carries a 32-byte program at bytes 2..34");
                    if crate::address::sha256_script(&redeem) != committed {
                        return Err(PsbtError::UtxoMismatch);
                    }
                    psbt_inputs.push(PsbtInput {
                        non_witness_utxo: None,
                        witness_utxo: Some(TxOut {
                            amount: create.amount,
                            script: create.script_pubkey,
                        }),
                        witness_script: Some(redeem),
                        ..PsbtInput::default()
                    });
                }
            } else if let Some(leaf_value) = create.tap_leaf_script {
                if !is_p2tr_script(&create.script_pubkey) {
                    // A tap leaf on a non-P2TR input is not a Creator
                    // surface yubtc builds — fall through to the
                    // default `WITNESS_UTXO` arm below (the field is
                    // dropped: preserve-only semantics for foreign
                    // forms).
                    psbt_inputs.push(PsbtInput {
                        non_witness_utxo: None,
                        witness_utxo: Some(TxOut {
                            amount: create.amount,
                            script: create.script_pubkey,
                        }),
                        ..PsbtInput::default()
                    });
                } else {
                    // v0.3 Creator branch (spec «Tapscript (P2TR
                    // script-path) (v0.3)»): the input spends the P2TR
                    // output of a known tapscript leaf — the script
                    // path of the multisig quorum. The leaf value must
                    // carry the canonical leaf version byte over a
                    // canonical R-MS-7 script, and the tweaked NUMS
                    // output key must commit to the `scriptPubKey`
                    // program; the UTXO rides as `WITNESS_UTXO`
                    // (BIP-341 commits the amount — no prev-tx fetch),
                    // `TAP_LEAF_SCRIPT (0x15)` is keyed by the control
                    // block the Creator derives offline, and
                    // `TAP_INTERNAL_KEY (0x17)` pins the NUMS key.
                    if leaf_value.last() != Some(&crate::script::TAPSCRIPT_LEAF_VERSION) {
                        return Err(PsbtError::UnsupportedInputScript);
                    }
                    let script = &leaf_value[..leaf_value.len() - 1];
                    crate::script::extract_multisig_tapscript(script)
                        .map_err(|_| PsbtError::UnsupportedInputScript)?;
                    let leaf_hash = crate::script::tapscript_leaf_hash(script);
                    let committed: [u8; 32] = create.script_pubkey[2..34]
                        .try_into()
                        .expect("canonical P2TR carries a 32-byte program at bytes 2..34");
                    let output_key = crate::address::tapscript_output_key(
                        &MS_TAPSCRIPT_INTERNAL_KEY,
                        &leaf_hash,
                    )
                    .expect("NUMS lift and tweak are total for the canonical internal key");
                    if output_key != committed {
                        return Err(PsbtError::UtxoMismatch);
                    }
                    let control_block = crate::address::tapscript_control_block(
                        &MS_TAPSCRIPT_INTERNAL_KEY,
                        &leaf_hash,
                    )
                    .expect("NUMS lift and tweak are total for the canonical internal key");
                    psbt_inputs.push(PsbtInput {
                        non_witness_utxo: None,
                        witness_utxo: Some(TxOut {
                            amount: create.amount,
                            script: create.script_pubkey,
                        }),
                        tap_leaf_scripts: vec![TapLeafScript {
                            control_block: control_block.to_vec(),
                            script_with_version: leaf_value,
                        }],
                        tap_internal_key: Some(MS_TAPSCRIPT_INTERNAL_KEY),
                        ..PsbtInput::default()
                    });
                }
            } else {
                psbt_inputs.push(PsbtInput {
                    non_witness_utxo: None,
                    witness_utxo: Some(TxOut {
                        amount: create.amount,
                        script: create.script_pubkey,
                    }),
                    ..PsbtInput::default()
                });
            }
        }
        let outputs = unsigned_tx
            .vout
            .iter()
            .map(|_| PsbtOutput::default())
            .collect();
        Ok(Self {
            version: 0,
            unsigned_tx,
            inputs: psbt_inputs,
            outputs,
            unknown_global: Vec::new(),
        })
    }

    /// Signer, single input: add our `PARTIAL_SIG` to input `index` if
    /// `privkey` is the key of the UTXO backing it.
    ///
    /// Returns `Ok(true)` when a signature was added (or was already
    /// present — the operation is idempotent), `Ok(false)` when the
    /// input cannot be signed with this key (no UTXO data, foreign
    /// script or key, or an incomplete BIP-341 digest context). Errors:
    /// [`PsbtError::UnsupportedInputScript`] for P2WSH-shaped UTXOs
    /// whose `WITNESS_SCRIPT` is absent or not a canonical bare
    /// CHECKMULTISIG script (v0.3 lifts the blanket Phase-14 refusal
    /// for the witness form of the multisig quorum) and for P2SH
    /// inputs whose `REDEEM_SCRIPT` is absent or not a canonical bare
    /// CHECKMULTISIG script (R-MS-3 — yubtc does not sign or finalize
    /// such scripts), [`PsbtError::UnsupportedSighashType`]
    /// when the input pins a sighash other than the form's
    /// (ОВ-8 — the wallet walk turns this into a silent skip),
    /// [`PsbtError::UtxoMismatch`] when a present `NON_WITNESS_UTXO`
    /// fails the txid check or a redeem/witness script fails its
    /// hash160/SHA-256 commitment (BIP-174 "Data Signers Check For").
    ///
    /// Digests reuse the Phase 13 machinery: legacy SIGHASH_ALL over
    /// the blanked serialization with the signed input's scriptCode —
    /// the UTXO `scriptPubKey` for P2PKH (byte-identical to
    /// [`crate::wallet::build_vin`]-based signing) and the redeem
    /// script for P2SH-multisig (Phase 15; the same algorithm,
    /// parameterized scriptCode). BIP-143 for P2WPKH
    /// and BIP-341 key-path for P2TR (`aux_rand = 0x00 × 32`), so
    /// signatures match the direct path byte-for-byte (RFC6979 /
    /// BIP-340 determinism). The v0.3 P2WSH-multisig branch signs the
    /// BIP-143 digest with `scriptCode = redeem` (spec «P2WSH
    /// (v0.3)»).
    ///
    /// P2SH-multisig identification is **membership, not script
    /// ownership** (R-MS-4): the P2SH `scriptPubKey` is never "ours" by
    /// shape, so the input is signed iff the key's compressed pubkey is
    /// one of the redeem script's N keys. The P2WSH branch applies the
    /// same membership rule against the witness script's keys.
    pub fn sign_input(&mut self, index: usize, privkey: &SigningKey) -> Result<bool, PsbtError> {
        let (script_pubkey, amount) = match self.input_utxo_data(index) {
            Some(data) => data,
            None => return Ok(false),
        };
        if is_p2wsh_script(&script_pubkey) {
            return self.sign_input_p2wsh_multisig(index, privkey, amount);
        }
        if is_p2sh_script(&script_pubkey) {
            return self.sign_input_p2sh_multisig(index, privkey);
        }
        if is_p2tr_script(&script_pubkey) && !self.inputs[index].tap_leaf_scripts.is_empty() {
            // v0.3: a P2TR input is no longer exhausted by the key
            // path — a present `TAP_LEAF_SCRIPT` selects the
            // Tapscript-multisig script-path branch (spec «PSBT:
            // ветки Tapscript-multisig»).
            return self.sign_input_p2tr_scriptpath(index, privkey);
        }
        let pubkey = privkey_to_pubkey(privkey);
        let form = match own_form(&script_pubkey, &pubkey) {
            Some(form) => form,
            None => return Ok(false),
        };
        let pinned = form.pinned_sighash();
        if let Some(t) = self.inputs[index].sighash_type {
            if t != pinned {
                return Err(PsbtError::UnsupportedSighashType(t));
            }
        }
        check_prev_tx(
            self.inputs[index].non_witness_utxo.as_ref(),
            &self.unsigned_tx,
            index,
        )?;
        if self.inputs[index]
            .partial_sigs
            .iter()
            .any(|(k, _)| k.0.as_slice() == pubkey)
        {
            return Ok(true);
        }
        let sighash_byte = pinned as u8;
        let sig: Vec<u8> = match form {
            Form::Legacy(_) => {
                let mut bytes = blanked_serialization(&self.unsigned_tx, index, &script_pubkey);
                bytes.extend_from_slice(&pinned.to_le_bytes());
                // Sign the digest itself (on-chain semantics): the
                // double-SHA256 legacy sighash is the ECDSA prehash,
                // not a message to be hashed again (see `sign_hash`).
                let sig: Signature = sign_hash(privkey, &dsha256(&bytes));
                let mut der = sig.to_der().as_bytes().to_vec();
                der.push(sighash_byte);
                der
            }
            Form::P2wpkh(_) => {
                // The 26-byte BIP-143 scriptCode rebuilt from the
                // witness program: `0x19 0x76 0xa9 0x14 <20> 0x88 0xac`.
                let mut script_code = Vec::with_capacity(26);
                script_code.extend_from_slice(&[0x19, 0x76, 0xa9, 0x14]);
                script_code.extend_from_slice(&script_pubkey[2..]);
                script_code.extend_from_slice(&[0x88, 0xac]);
                let sighash = bip143_sighash(&self.unsigned_tx, index, &script_code, amount)
                    .expect("input index is below vin.len() by the dispatch contract");
                // Sign the digest itself (on-chain semantics): the
                // BIP-143 sighash is the ECDSA prehash, not a message
                // to be hashed again (see `sign_hash`).
                let sig: Signature = sign_hash(privkey, &sighash);
                let mut der = sig.to_der().as_bytes().to_vec();
                der.push(sighash_byte);
                der
            }
            Form::P2tr(_) => {
                let spend = match self.spend_context() {
                    Some(ctx) => ctx,
                    // BIP-341 commits to all inputs; without complete
                    // UTXO data the digest is not computable — skip.
                    None => return Ok(false),
                };
                let sighash = taproot_keypath_sighash(&self.unsigned_tx, index, &spend)
                    .expect("context complete and index in range by the dispatch contract");
                taproot_sign_sighash(privkey, &sighash).to_vec()
            }
        };
        insert_partial_sig(&mut self.inputs[index], PubKey(pubkey.to_vec()), sig);
        Ok(true)
    }

    /// Signer, P2SH-multisig branch (Phase 15, spec «PSBT: Creator,
    /// Signer и Finalizer»): sign the legacy SIGHASH_ALL digest with
    /// `scriptCode = redeem` when the key's compressed pubkey is a
    /// member of the redeem script's quorum. See [`Self::sign_input`]
    /// for the full contract; `index` must reference a
    /// canonical-P2SH input.
    fn sign_input_p2sh_multisig(
        &mut self,
        index: usize,
        privkey: &SigningKey,
    ) -> Result<bool, PsbtError> {
        let pubkey = privkey_to_pubkey(privkey);
        // Clone (≤ 513 bytes) so the field borrow ends before the
        // mutable `insert_partial_sig` below.
        let redeem = match &self.inputs[index].redeem_script {
            Some(redeem) => redeem.clone(),
            // P2SH without a redeem script: pre-Phase-15 refusal
            // (yubtc cannot know what the hash commits to).
            None => return Err(PsbtError::UnsupportedInputScript),
        };
        // R-MS-3: only canonical bare CHECKMULTISIG redeem scripts are
        // signed; anything else (including duplicate keys) is refused.
        let (_m, keys) = crate::script::extract_multisig_quorum(&redeem)
            .map_err(|_| PsbtError::UnsupportedInputScript)?;
        // BIP-174 "Data Signers Check For": the redeem script must
        // hash to the commitment in the UTXO's P2SH scriptPubKey.
        let script_pubkey = self
            .input_utxo_data(index)
            .expect("UTXO data presence verified by the caller before dispatch")
            .0;
        let committed: [u8; 20] = script_pubkey[2..22]
            .try_into()
            .expect("canonical P2SH carries a 20-byte hash at bytes 2..22");
        if crate::address::hash160_script(&redeem) != committed {
            return Err(PsbtError::UtxoMismatch);
        }
        // Membership, not scriptPubKey shape (R-MS-4).
        if !keys.iter().any(|k| k == &pubkey) {
            return Ok(false);
        }
        // ОВ-8: the pinned sighash for the legacy ECDSA forms.
        if let Some(t) = self.inputs[index].sighash_type {
            if t != PSBT_SIGHASH_ALL {
                return Err(PsbtError::UnsupportedSighashType(t));
            }
        }
        // BIP-174 "Data Signers Check For": the prev tx must hash to
        // the outpoint being spent.
        check_prev_tx(
            self.inputs[index].non_witness_utxo.as_ref(),
            &self.unsigned_tx,
            index,
        )?;
        // Idempotent: our signature is already in place.
        if self.inputs[index]
            .partial_sigs
            .iter()
            .any(|(k, _)| k.0.as_slice() == pubkey)
        {
            return Ok(true);
        }
        // Legacy digest with scriptCode = redeem: the blanked
        // serialization restores the redeem script into the signed
        // input's `scriptSig` slot, then the SIGHASH_ALL suffix.
        let mut bytes = blanked_serialization(&self.unsigned_tx, index, &redeem);
        bytes.extend_from_slice(&PSBT_SIGHASH_ALL.to_le_bytes());
        // Sign the digest itself (on-chain semantics): the double-SHA256
        // legacy sighash is the ECDSA prehash, not a message to be
        // hashed again (see `sign_hash`).
        let sig: Signature = sign_hash(privkey, &dsha256(&bytes));
        let mut der = sig.to_der().as_bytes().to_vec();
        der.push(PSBT_SIGHASH_ALL as u8);
        insert_partial_sig(&mut self.inputs[index], PubKey(pubkey.to_vec()), der);
        Ok(true)
    }

    /// Signer, P2WSH-multisig branch (spec «Multi-sig»): sign
    /// the BIP-143 SIGHASH_ALL digest with `scriptCode = redeem` when
    /// the key's compressed pubkey is a member of the witness script's
    /// quorum. See [`Self::sign_input`] for the full contract;
    /// `index` must reference a canonical-P2WSH input and `amount` is
    /// the `WITNESS_UTXO` value the BIP-143 digest commits to.
    fn sign_input_p2wsh_multisig(
        &mut self,
        index: usize,
        privkey: &SigningKey,
        amount: u64,
    ) -> Result<bool, PsbtError> {
        let pubkey = privkey_to_pubkey(privkey);
        // Clone (≤ 513 bytes) so the field borrow ends before the
        // mutable `insert_partial_sig` below.
        let redeem = match &self.inputs[index].witness_script {
            Some(redeem) => redeem.clone(),
            // P2WSH without a witness script: pre-v0.3 refusal (yubtc
            // cannot know what the SHA-256 commitment is).
            None => return Err(PsbtError::UnsupportedInputScript),
        };
        // R-MS-3: only canonical bare CHECKMULTISIG witness scripts
        // are signed; anything else (including duplicate keys) is
        // refused.
        let (_m, keys) = crate::script::extract_multisig_quorum(&redeem)
            .map_err(|_| PsbtError::UnsupportedInputScript)?;
        // BIP-174 "Data Signers Check For": the witness script must
        // SHA-256-commit to the program in the UTXO's P2WSH
        // scriptPubKey.
        let script_pubkey = self
            .input_utxo_data(index)
            .expect("UTXO data presence verified by the caller before dispatch")
            .0;
        let committed: [u8; 32] = script_pubkey[2..34]
            .try_into()
            .expect("canonical P2WSH carries a 32-byte program at bytes 2..34");
        if crate::address::sha256_script(&redeem) != committed {
            return Err(PsbtError::UtxoMismatch);
        }
        // Membership, not scriptPubKey shape (R-MS-4).
        if !keys.iter().any(|k| k == &pubkey) {
            return Ok(false);
        }
        // ОВ-8: the pinned sighash for the BIP-143 ECDSA forms.
        if let Some(t) = self.inputs[index].sighash_type {
            if t != PSBT_SIGHASH_ALL {
                return Err(PsbtError::UnsupportedSighashType(t));
            }
        }
        // BIP-174 "Data Signers Check For": a *present*
        // NON_WITNESS_UTXO must still hash to the outpoint being
        // spent (the field is optional for witness forms).
        check_prev_tx(
            self.inputs[index].non_witness_utxo.as_ref(),
            &self.unsigned_tx,
            index,
        )?;
        // Idempotent: our signature is already in place.
        if self.inputs[index]
            .partial_sigs
            .iter()
            .any(|(k, _)| k.0.as_slice() == pubkey)
        {
            return Ok(true);
        }
        // BIP-143 digest with scriptCode = the serialized witness
        // script (`CompactSize(|redeem|) ‖ redeem` — the BIP-143
        // scriptCode serialization, not an OP_PUSHDATA push), the
        // amount committed from the WITNESS_UTXO.
        let mut script_code = crate::transaction::compact_size(redeem.len() as u64);
        script_code.extend_from_slice(&redeem);
        let sighash = bip143_sighash(&self.unsigned_tx, index, &script_code, amount)
            .expect("input index is below vin.len() by the dispatch contract");
        // Sign the digest itself (on-chain semantics): the BIP-143
        // sighash is the ECDSA prehash, not a message to be hashed
        // again (see `sign_hash`).
        let sig: Signature = sign_hash(privkey, &sighash);
        let mut der = sig.to_der().as_bytes().to_vec();
        der.push(PSBT_SIGHASH_ALL as u8);
        insert_partial_sig(&mut self.inputs[index], PubKey(pubkey.to_vec()), der);
        Ok(true)
    }

    /// Signer, P2TR **script-path** branch (v0.3, spec «Tapscript
    /// (P2TR script-path) (v0.3)»): sign the BIP-341 script-path
    /// digest (SigMsg with `spend_type = 0x02`, extended by the leaf
    /// hash, key version 0 and no `OP_CODESEPARATOR`) with untweaked
    /// BIP-340 Schnorr (R-MS-10/ОВ-10) when the key's x-only pubkey is
    /// a member of the `TAP_LEAF_SCRIPT` tapscript. See
    /// [`Self::sign_input`] for the full contract; `index` must
    /// reference a canonical-P2TR input with a `TAP_LEAF_SCRIPT`.
    fn sign_input_p2tr_scriptpath(
        &mut self,
        index: usize,
        privkey: &SigningKey,
    ) -> Result<bool, PsbtError> {
        let pubkey = privkey_to_pubkey(privkey);
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&pubkey[1..33]);
        // Clone (≤ 513 + 33 bytes) so the field borrow ends before the
        // mutable `insert` below.
        let (control_block, leaf_value) = {
            let leaf = self.inputs[index]
                .tap_leaf_scripts
                .first()
                .expect("dispatch guarantees a non-empty tap_leaf_scripts");
            (leaf.control_block.clone(), leaf.script_with_version.clone())
        };
        // Control block: 33 bytes (`33 + 32·depth`, depth = 0), the
        // canonical 0xc0 leaf version in `c[0] & 0xfe`, and the NUMS
        // internal key (R-MS-8 — yubtc signs only its own single-leaf
        // NUMS trees).
        if control_block.len() != 33
            || control_block[0] & 0xfe != crate::script::TAPSCRIPT_LEAF_VERSION
            || control_block[1..33] != MS_TAPSCRIPT_INTERNAL_KEY
        {
            return Err(PsbtError::UnsupportedInputScript);
        }
        // Leaf value: tapscript ‖ leaf_version with the version byte
        // exactly 0xc0 (leaf versions ≠ 0xc0 are out of scope).
        if leaf_value.last() != Some(&crate::script::TAPSCRIPT_LEAF_VERSION) {
            return Err(PsbtError::UnsupportedInputScript);
        }
        let script = &leaf_value[..leaf_value.len() - 1];
        // R-MS-7: only the canonical CHECKSIGADD idiom is signed.
        let (_m, keys) = crate::script::extract_multisig_tapscript(script)
            .map_err(|_| PsbtError::UnsupportedInputScript)?;
        let leaf_hash = crate::script::tapscript_leaf_hash(script);
        // BIP-174 "Data Signers Check For": the tweaked NUMS output
        // key must commit to the program in the UTXO's P2TR
        // scriptPubKey…
        let script_pubkey = self
            .input_utxo_data(index)
            .expect("UTXO data presence verified by the caller before dispatch")
            .0;
        let committed: [u8; 32] = script_pubkey[2..34]
            .try_into()
            .expect("canonical P2TR carries a 32-byte program at bytes 2..34");
        let output_key =
            crate::address::tapscript_output_key(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)
                .expect("NUMS lift and tweak are total for the canonical internal key");
        if output_key != committed {
            return Err(PsbtError::UtxoMismatch);
        }
        // …and any present `TAP_MERKLE_ROOT` must equal the computed
        // leaf hash (the tree is exactly one leaf — the root IS the
        // leaf hash).
        if let Some(root) = self.inputs[index].tap_merkle_root {
            if root != leaf_hash {
                return Err(PsbtError::UtxoMismatch);
            }
        }
        // Membership, not scriptPubKey shape (R-MS-4): the x-only key
        // must be one of the tapscript's keys.
        if !keys.iter().any(|k| k == &x_only) {
            return Ok(false);
        }
        // ОВ-17: SIGHASH_DEFAULT is pinned; absent or explicit 0x00.
        if let Some(t) = self.inputs[index].sighash_type {
            if t != PSBT_SIGHASH_DEFAULT {
                return Err(PsbtError::UnsupportedSighashType(t));
            }
        }
        // BIP-174 "Data Signers Check For": a *present*
        // NON_WITNESS_UTXO must still hash to the outpoint being
        // spent (the field is optional for witness forms).
        check_prev_tx(
            self.inputs[index].non_witness_utxo.as_ref(),
            &self.unsigned_tx,
            index,
        )?;
        // Idempotent: our signature for this leaf is already in place.
        if self.inputs[index]
            .tap_script_sigs
            .iter()
            .any(|s| s.x_only == x_only && s.leaf_hash == leaf_hash)
        {
            return Ok(true);
        }
        // BIP-341 script-path digest commits to all inputs; without
        // complete UTXO data the digest is not computable — skip.
        let spend = match self.spend_context() {
            Some(ctx) => ctx,
            None => return Ok(false),
        };
        let sighash = taproot_scriptpath_sighash(&self.unsigned_tx, index, &spend, &leaf_hash)
            .expect("context complete and index in range by the dispatch contract");
        let sig = taproot_sign_sighash_untweaked(privkey, &sighash).to_vec();
        let input = &mut self.inputs[index];
        let pos = input
            .tap_script_sigs
            .partition_point(|s| (s.x_only, s.leaf_hash) <= (x_only, leaf_hash));
        input.tap_script_sigs.insert(
            pos,
            TapScriptSig {
                x_only,
                leaf_hash,
                sig,
            },
        );
        Ok(true)
    }

    /// Combiner: merge `other` into a copy of `self`.
    ///
    /// PSBTs are identified by their global `UNSIGNED_TX` (byte
    /// equality) — anything else is [`PsbtError::ForeignTransaction`].
    /// Equal keys with equal values collapse to one pair; equal keys
    /// with different values are a deterministic
    /// [`PsbtError::ConflictingField`] refusal (spec decision — no
    /// arbitrary pick); different keys of the same type are all kept.
    /// The merge is commutative for disjoint signers and idempotent.
    pub fn combine(&self, other: &Self) -> Result<Self, PsbtError> {
        if self.unsigned_tx.serialize_stripped() != other.unsigned_tx.serialize_stripped() {
            return Err(PsbtError::ForeignTransaction);
        }
        let unknown_global = merge_unknown(&self.unknown_global, &other.unknown_global)?;
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for (a, b) in self.inputs.iter().zip(&other.inputs) {
            inputs.push(merge_input(a, b)?);
        }
        let mut outputs = Vec::with_capacity(self.outputs.len());
        for (a, b) in self.outputs.iter().zip(&other.outputs) {
            outputs.push(PsbtOutput {
                unknown: merge_unknown(&a.unknown, &b.unknown)?,
            });
        }
        Ok(Self {
            version: self.version,
            unsigned_tx: self.unsigned_tx.clone(),
            inputs,
            outputs,
            unknown_global,
        })
    }

    /// Finalizer: finalize every input that is complete, leave the rest
    /// untouched (per-input operation; completeness of the whole
    /// transaction is the Extractor's rule). Already-finalized inputs
    /// are left as they are, so `finalize` is idempotent.
    pub fn finalize(&mut self) {
        for i in 0..self.inputs.len() {
            let _ = self.finalize_input(i);
        }
    }

    /// Finalize a single input (spec «Finalizer»): when the input's
    /// form is complete, convert its `PARTIAL_SIG` into the final
    /// fields —
    ///
    /// - P2PKH: `FINAL_SCRIPTSIG` = `push(sig ‖ 0x01) ‖ push(pubkey)`,
    ///   the pushed on-chain layout (spec, yubtc-python direct-path
    ///   `CScript`), byte-identical to the direct-path `scriptSig`;
    /// - P2WPKH: `FINAL_SCRIPTWITNESS` = `[sig ‖ 0x01, pubkey]`;
    /// - P2TR key-path: `FINAL_SCRIPTWITNESS` = `[sig64]`.
    ///
    /// The finalizing signer is identified by key commitment: hash160
    /// match for P2PKH/P2WPKH, BIP-86 TapTweak match for P2TR. A
    /// signature whose sighash byte disagrees with the input's
    /// `SIGHASH_TYPE` (when present) or the form's pin blocks the input
    /// (BIP-174 MUST) — reported as [`PsbtError::IncompleteInput`].
    /// On success the intermediate fields (`PARTIAL_SIG`,
    /// `SIGHASH_TYPE`, `REDEEM/WITNESS_SCRIPT`) are removed; UTXO and
    /// unknown fields are preserved (BIP-174 mandate: the Extractor
    /// checks the final tx against the UTXOs).
    ///
    /// Phase 15 adds the P2SH-multisig path: a canonical-P2SH input
    /// with a `REDEEM_SCRIPT` is finalized when `hash160(redeem)`
    /// matches the `scriptPubKey` commitment and `PARTIAL_SIG` holds
    /// exactly one valid-sighash signature for **every** one of the
    /// script's M-of-N keys. The final `scriptSig` is assembled in
    /// *script* key order (R-MS-4), never in `PARTIAL_SIG` arrival
    /// order: `OP_0 ‖ push(sig ‖ 0x01)×M ‖ push(redeem)` (R-MS-5).
    /// A non-canonical redeem script is
    /// [`PsbtError::UnsupportedInputScript`] (yubtc does not finalize
    /// foreign multisig forms).
    pub fn finalize_input(&mut self, index: usize) -> Result<(), PsbtError> {
        if self
            .inputs
            .get(index)
            .ok_or(PsbtError::IncompleteInput(index))?
            .final_scriptsig
            .is_some()
            || self.inputs[index].final_scriptwitness.is_some()
        {
            return Ok(());
        }
        let (script_pubkey, _) = self
            .input_utxo_data(index)
            .ok_or(PsbtError::IncompleteInput(index))?;
        if is_p2sh_script(&script_pubkey) {
            return self.finalize_input_p2sh_multisig(index, &script_pubkey);
        }
        if is_p2wsh_script(&script_pubkey) {
            return self.finalize_input_p2wsh_multisig(index, &script_pubkey);
        }
        if is_p2tr_script(&script_pubkey) && !self.inputs[index].tap_leaf_scripts.is_empty() {
            // v0.3: a P2TR input with a revealed tapscript finalizes
            // through the script-path branch (the R-MS-11 witness),
            // never the key path.
            return self.finalize_input_p2tr_scriptpath(index);
        }
        let input = &mut self.inputs[index];
        let form = form_of_script(&script_pubkey).ok_or(PsbtError::IncompleteInput(index))?;
        let pinned = form.pinned_sighash();
        if let Some(t) = input.sighash_type {
            if t != pinned {
                return Err(PsbtError::IncompleteInput(index));
            }
        }
        match form {
            Form::Legacy(hash) => {
                let (pubkey, sig) =
                    partial_sig_by_hash(input, &hash).ok_or(PsbtError::IncompleteInput(index))?;
                if sig.last() != Some(&(pinned as u8)) {
                    return Err(PsbtError::IncompleteInput(index));
                }
                // Clone before mutating `input`: the immutable borrow
                // from the lookup ends here (NLL). `sig` already ends
                // with the sighash byte, so the pushed layout is
                // `push(sig ‖ 0x01) ‖ push(pubkey)` — a raw
                // concatenation would be interpreted as opcodes by
                // the script interpreter and never validate.
                let mut script = push_data(sig);
                script.extend_from_slice(&push_data(&pubkey.0));
                input.final_scriptsig = Some(script);
            }
            Form::P2wpkh(hash) => {
                let (pubkey, sig) =
                    partial_sig_by_hash(input, &hash).ok_or(PsbtError::IncompleteInput(index))?;
                if sig.last() != Some(&(pinned as u8)) {
                    return Err(PsbtError::IncompleteInput(index));
                }
                input.final_scriptwitness =
                    Some(encode_witness_stack(&[sig.clone(), pubkey.0.clone()]));
            }
            Form::P2tr(output_key) => {
                let sig = input
                    .partial_sigs
                    .iter()
                    .find_map(|(pubkey, sig)| {
                        if sig.len() != 64 || pubkey.0.len() != 33 {
                            return None;
                        }
                        let tweaked =
                            crate::address::taproot_output_key(&xonly_arr(&pubkey.0)).ok()?;
                        (tweaked == output_key).then(|| sig.clone())
                    })
                    .ok_or(PsbtError::IncompleteInput(index))?;
                input.final_scriptwitness = Some(encode_witness_stack(&[sig]));
            }
        }
        // Intermediates out, UTXOs and unknowns stay.
        input.partial_sigs.clear();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        Ok(())
    }

    /// Finalizer, P2SH-multisig branch (Phase 15). See
    /// [`Self::finalize_input`] for the full contract; `index` must
    /// reference a canonical-P2SH input.
    fn finalize_input_p2sh_multisig(
        &mut self,
        index: usize,
        script_pubkey: &[u8],
    ) -> Result<(), PsbtError> {
        // A P2SH input is finalizable only with a known redeem script.
        let redeem = match &self.inputs[index].redeem_script {
            Some(redeem) => redeem.clone(),
            None => return Err(PsbtError::IncompleteInput(index)),
        };
        // R-MS-3: foreign (non-canonical) redeem scripts are refused,
        // not merely left incomplete.
        let (m, keys) = crate::script::extract_multisig_quorum(&redeem)
            .map_err(|_| PsbtError::UnsupportedInputScript)?;
        // The redeem script must hash to the scriptPubKey commitment.
        let committed: [u8; 20] = script_pubkey[2..22]
            .try_into()
            .expect("canonical P2SH carries a 20-byte hash at bytes 2..22");
        if crate::address::hash160_script(&redeem) != committed {
            return Err(PsbtError::UtxoMismatch);
        }
        // ОВ-8: SIGHASH_ALL is pinned; anything else blocks the input.
        if let Some(t) = self.inputs[index].sighash_type {
            if t != PSBT_SIGHASH_ALL {
                return Err(PsbtError::IncompleteInput(index));
            }
        }
        // One valid-sighash signature per participating script key.
        // CHECKMULTISIG matching is greedy, so *any* M distinct member
        // keys can carry the spend: collect the signatures that are
        // present, in script-key order, and require at least M of them
        // (R-MS-4 — the layout below follows script order; extra
        // members beyond the threshold are deterministically dropped
        // from the tail).
        let mut member_sigs: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
        for key in &keys {
            if let Some(sig) = self.inputs[index]
                .partial_sigs
                .iter()
                .find_map(|(pubkey, sig)| (pubkey.0.as_slice() == key).then(|| sig.clone()))
            {
                if sig.last() != Some(&(PSBT_SIGHASH_ALL as u8)) {
                    return Err(PsbtError::IncompleteInput(index));
                }
                member_sigs.push(sig);
            }
        }
        if member_sigs.len() < m {
            return Err(PsbtError::IncompleteInput(index));
        }
        member_sigs.truncate(m);
        let sig_refs: Vec<&[u8]> = member_sigs.iter().map(|s| s.as_slice()).collect();
        let script_sig = crate::script::make_multisig_script_sig(&redeem, &sig_refs);
        let input = &mut self.inputs[index];
        input.final_scriptsig = Some(script_sig);
        // Intermediates out, UTXOs and unknowns stay.
        input.partial_sigs.clear();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        Ok(())
    }

    /// Finalizer, P2WSH-multisig branch (spec «Multi-sig»).
    /// See [`Self::finalize_input`] for the full contract; `index`
    /// must reference a canonical-P2WSH input. The final
    /// `FINAL_SCRIPTWITNESS` is the BIP-141 stack — empty-string
    /// dummy, the M signatures in script-key order, the witness
    /// script — never a `scriptSig`.
    fn finalize_input_p2wsh_multisig(
        &mut self,
        index: usize,
        script_pubkey: &[u8],
    ) -> Result<(), PsbtError> {
        // A P2WSH input is finalizable only with a known witness
        // script.
        let redeem = match &self.inputs[index].witness_script {
            Some(redeem) => redeem.clone(),
            None => return Err(PsbtError::IncompleteInput(index)),
        };
        // R-MS-3: foreign (non-canonical) witness scripts are
        // refused, not merely left incomplete.
        let (m, keys) = crate::script::extract_multisig_quorum(&redeem)
            .map_err(|_| PsbtError::UnsupportedInputScript)?;
        // The witness script must commit to the scriptPubKey program.
        let committed: [u8; 32] = script_pubkey[2..34]
            .try_into()
            .expect("canonical P2WSH carries a 32-byte program at bytes 2..34");
        if crate::address::sha256_script(&redeem) != committed {
            return Err(PsbtError::UtxoMismatch);
        }
        // ОВ-8: SIGHASH_ALL is pinned; anything else blocks the input.
        if let Some(t) = self.inputs[index].sighash_type {
            if t != PSBT_SIGHASH_ALL {
                return Err(PsbtError::IncompleteInput(index));
            }
        }
        // One valid-sighash signature per participating script key
        // (greedy CHECKMULTISIG semantics — any M distinct members can
        // carry the spend; collected in script-key order, extras
        // truncated from the tail — the Phase 15 rule, carried over).
        let mut member_sigs: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
        for key in &keys {
            if let Some(sig) = self.inputs[index]
                .partial_sigs
                .iter()
                .find_map(|(pubkey, sig)| (pubkey.0.as_slice() == key).then(|| sig.clone()))
            {
                if sig.last() != Some(&(PSBT_SIGHASH_ALL as u8)) {
                    return Err(PsbtError::IncompleteInput(index));
                }
                member_sigs.push(sig);
            }
        }
        if member_sigs.len() < m {
            return Err(PsbtError::IncompleteInput(index));
        }
        member_sigs.truncate(m);
        let sig_refs: Vec<&[u8]> = member_sigs.iter().map(|s| s.as_slice()).collect();
        let witness = crate::script::make_multisig_witness(&redeem, &sig_refs);
        let input = &mut self.inputs[index];
        input.final_scriptwitness = Some(encode_witness_stack(&witness));
        // Intermediates out, UTXOs and unknowns stay.
        input.partial_sigs.clear();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        Ok(())
    }

    /// Finalizer, P2TR script-path branch (v0.3, spec «Tapscript
    /// (P2TR script-path) (v0.3)» + R-MS-11). See
    /// [`Self::finalize_input`] for the full contract; `index` must
    /// reference a canonical-P2TR input with a `TAP_LEAF_SCRIPT`.
    ///
    /// The input finalizes when the leaf/commitment checks pass and
    /// `TAP_SCRIPT_SIG` holds exactly one 64-byte signature for **at
    /// least M** of the tapscript's member keys (pubkeys outside the
    /// script are ignored; a malformed signature length blocks the
    /// input). The final `FINAL_SCRIPTWITNESS` is the R-MS-11 stack —
    /// the per-key slots in **reverse** script-key order (empty
    /// vectors for non-signers, no dummy — `OP_CHECKSIGADD` has no
    /// off-by-one), the tapscript, the control block — never a
    /// `scriptSig`. After finalization the intermediate fields
    /// (`TAP_SCRIPT_SIG`, `TAP_LEAF_SCRIPT`, `TAP_INTERNAL_KEY`,
    /// `TAP_MERKLE_ROOT`, `SIGHASH_TYPE`) are removed (BIP-371
    /// mandate); UTXO and unknown fields are preserved.
    fn finalize_input_p2tr_scriptpath(&mut self, index: usize) -> Result<(), PsbtError> {
        let (control_block, leaf_value) = {
            let leaf = self.inputs[index]
                .tap_leaf_scripts
                .first()
                .expect("dispatch guarantees a non-empty tap_leaf_scripts");
            (leaf.control_block.clone(), leaf.script_with_version.clone())
        };
        // The same structural/commitment ladder the Signer runs: a
        // foreign control block or leaf is refused, not merely left
        // incomplete.
        if control_block.len() != 33
            || control_block[0] & 0xfe != crate::script::TAPSCRIPT_LEAF_VERSION
            || control_block[1..33] != MS_TAPSCRIPT_INTERNAL_KEY
        {
            return Err(PsbtError::UnsupportedInputScript);
        }
        if leaf_value.last() != Some(&crate::script::TAPSCRIPT_LEAF_VERSION) {
            return Err(PsbtError::UnsupportedInputScript);
        }
        let script = leaf_value[..leaf_value.len() - 1].to_vec();
        let (m, keys) = crate::script::extract_multisig_tapscript(&script)
            .map_err(|_| PsbtError::UnsupportedInputScript)?;
        let leaf_hash = crate::script::tapscript_leaf_hash(&script);
        let script_pubkey = self
            .input_utxo_data(index)
            .expect("UTXO data presence verified by the caller before dispatch")
            .0;
        let committed: [u8; 32] = script_pubkey[2..34]
            .try_into()
            .expect("canonical P2TR carries a 32-byte program at bytes 2..34");
        let output_key =
            crate::address::tapscript_output_key(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)
                .expect("NUMS lift and tweak are total for the canonical internal key");
        if output_key != committed {
            return Err(PsbtError::UtxoMismatch);
        }
        if let Some(root) = self.inputs[index].tap_merkle_root {
            if root != leaf_hash {
                return Err(PsbtError::UtxoMismatch);
            }
        }
        // ОВ-17: SIGHASH_DEFAULT is pinned; anything else blocks the
        // input.
        if let Some(t) = self.inputs[index].sighash_type {
            if t != PSBT_SIGHASH_DEFAULT {
                return Err(PsbtError::IncompleteInput(index));
            }
        }
        // Per-key slots in script order: exactly one 64-byte signature
        // per participating member key; member keys beyond the
        // threshold are deterministically dropped from the tail (the
        // Phase 15 greedy rule — CHECKSIGADD would otherwise count
        // them and invalidate the spend); keys outside the script are
        // ignored.
        let mut sig_slots: Vec<Option<Vec<u8>>> = Vec::with_capacity(keys.len());
        let mut taken = 0usize;
        for key in &keys {
            let sig = self.inputs[index].tap_script_sigs.iter().find_map(|s| {
                (s.x_only == *key && s.leaf_hash == leaf_hash).then(|| s.sig.clone())
            });
            match sig {
                Some(sig) if taken < m => {
                    if sig.len() != 64 {
                        return Err(PsbtError::IncompleteInput(index));
                    }
                    sig_slots.push(Some(sig));
                    taken += 1;
                }
                // A member key beyond the threshold keeps its slot —
                // empty (the R-MS-11 stack is exactly N slots long;
                // CHECKSIGADD would count an extra non-empty slot and
                // invalidate the spend).
                Some(_) => sig_slots.push(None),
                None => sig_slots.push(None),
            }
        }
        if taken < m {
            return Err(PsbtError::IncompleteInput(index));
        }
        let slots: Vec<Option<&[u8]>> = sig_slots.iter().map(|s| s.as_deref()).collect();
        let witness =
            crate::script::make_multisig_tapscript_witness(&script, &control_block, &slots);
        let input = &mut self.inputs[index];
        input.final_scriptwitness = Some(encode_witness_stack(&witness));
        // Intermediates out (BIP-371: the finalizer removes the
        // taproot fields after FINAL_SCRIPTWITNESS), UTXOs and
        // unknowns stay.
        input.partial_sigs.clear();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.tap_script_sigs.clear();
        input.tap_leaf_scripts.clear();
        input.tap_internal_key = None;
        input.tap_merkle_root = None;
        Ok(())
    }

    /// Extractor: require every input to be finalized, then build the
    /// wire-format transaction (`serialize_wire`; the marker/flag
    /// section appears exactly when some input carries a witness
    /// stack). The PSBT itself is not modified.
    ///
    /// Phase 15: a canonical-P2SH input (with a `REDEEM_SCRIPT`) is
    /// extracted via its `FINAL_SCRIPTSIG` — like legacy — and must
    /// not carry a witness stack ([`PsbtError::IncompleteInput`]). A
    /// P2SH input without a redeem script stays a foreign form yubtc
    /// cannot validate ([`PsbtError::NotFinalized`]).
    pub fn extract_transaction(&self) -> Result<Transaction, PsbtError> {
        let mut tx = self.unsigned_tx.clone();
        for (i, input) in self.inputs.iter().enumerate() {
            let script_pubkey = self.input_utxo_data(i).map(|(spk, _)| spk);
            let is_p2sh = script_pubkey
                .as_deref()
                .map(is_p2sh_script)
                .unwrap_or(false);
            let form = script_pubkey.as_deref().and_then(form_of_script);
            match form {
                Some(Form::Legacy(_)) => {
                    let script = input
                        .final_scriptsig
                        .as_ref()
                        .ok_or(PsbtError::NotFinalized)?;
                    tx.vin[i].script = script.clone();
                }
                Some(Form::P2wpkh(_)) | Some(Form::P2tr(_)) => {
                    // v0.3: a P2TR input carrying a `TAP_LEAF_SCRIPT`
                    // is a script-path spend — `FINAL_SCRIPTSIG` on it
                    // is the symmetrical refusal of the P2WSH arm (a
                    // witness form never finalizes through a
                    // `scriptSig`).
                    if input.final_scriptsig.is_some() && !input.tap_leaf_scripts.is_empty() {
                        return Err(PsbtError::IncompleteInput(i));
                    }
                    let stack = input
                        .final_scriptwitness
                        .as_ref()
                        .ok_or(PsbtError::NotFinalized)?;
                    let stack =
                        decode_witness_stack(stack).map_err(|_| PsbtError::IncompleteInput(i))?;
                    tx.vin[i].witness = stack;
                    tx.vin[i].script = Vec::new();
                }
                None if is_p2sh => {
                    // P2SH-multisig: legacy spend, no witness stack
                    // (BIP-141 — a witness would make it a nested
                    // SegWit spend, explicitly rejected in Phase 13).
                    if input.final_scriptwitness.is_some() {
                        return Err(PsbtError::IncompleteInput(i));
                    }
                    // Requires FINAL_SCRIPTSIG, like legacy. (The
                    // Finalizer strips the intermediate REDEEM_SCRIPT
                    // field, so presence-based completeness is the
                    // check that survives finalization.)
                    let script = input
                        .final_scriptsig
                        .as_ref()
                        .ok_or(PsbtError::NotFinalized)?;
                    tx.vin[i].script = script.clone();
                }
                None if script_pubkey
                    .as_deref()
                    .map(is_p2wsh_script)
                    .unwrap_or(false) =>
                {
                    // P2WSH-multisig (v0.3): witness spend, no
                    // scriptSig (a pushed scriptSig on a witness v0
                    // output is not a form yubtc builds — the
                    // symmetrical refusal of the P2SH arm's witness
                    // check). The guard matched a present scriptPubKey,
                    // so the expect below cannot fire.
                    if input.final_scriptsig.is_some() {
                        return Err(PsbtError::IncompleteInput(i));
                    }
                    let stack = input
                        .final_scriptwitness
                        .as_ref()
                        .ok_or(PsbtError::NotFinalized)?;
                    let stack =
                        decode_witness_stack(stack).map_err(|_| PsbtError::IncompleteInput(i))?;
                    tx.vin[i].witness = stack;
                    tx.vin[i].script = Vec::new();
                }
                None => {
                    // Without a recognizable UTXO form the Extractor
                    // cannot validate completeness — refuse (BIP-174
                    // Extractor MUST check).
                    return Err(PsbtError::NotFinalized);
                }
            }
        }
        Ok(tx)
    }

    /// Human-readable digest (`psbt decode`; a yubtc extension, not a
    /// BIP-174 role).
    pub fn summary(&self) -> PsbtSummary {
        let mut credit_sat: u128 = 0;
        let mut all_inputs_known = true;
        for i in 0..self.inputs.len() {
            match self.input_utxo_data(i) {
                Some((_, amount)) => credit_sat += u128::from(amount),
                None => all_inputs_known = false,
            }
        }
        let spend_sat: u128 = self
            .unsigned_tx
            .vout
            .iter()
            .map(|o| u128::from(o.amount))
            .sum();
        let fee_sat = if all_inputs_known {
            credit_sat
                .checked_sub(spend_sat)
                .and_then(|fee| u64::try_from(fee).ok())
        } else {
            None
        };
        PsbtSummary {
            txid_hex: hex::encode(self.unsigned_tx.id()),
            version: self.version,
            inputs: self
                .inputs
                .iter()
                .map(|input| PsbtInputSummary {
                    has_utxo: input.witness_utxo.is_some() || input.non_witness_utxo.is_some(),
                    n_partial_sigs: input.partial_sigs.len(),
                    sighash_type: input.sighash_type,
                    finalized: input.final_scriptsig.is_some()
                        || input.final_scriptwitness.is_some(),
                })
                .collect(),
            outputs: self
                .outputs
                .iter()
                .zip(&self.unsigned_tx.vout)
                .map(|(_, out)| PsbtOutputSummary {
                    amount_sat: out.amount,
                    script_pubkey_hex: hex::encode(&out.script),
                })
                .collect(),
            fee_sat,
        }
    }
}

/// The script form this key commits to, `None` for foreign keys:
/// hash160 commitment for P2PKH/P2WPKH, BIP-86 TapTweak commitment for
/// P2TR key-path.
fn own_form(script_pubkey: &[u8], pubkey: &[u8; 33]) -> Option<Form> {
    let hash160 = crate::address::hash160_pubkey(pubkey);
    match form_of_script(script_pubkey) {
        Some(Form::Legacy(hash)) if hash == hash160 => Some(Form::Legacy(hash)),
        Some(Form::P2wpkh(hash)) if hash == hash160 => Some(Form::P2wpkh(hash)),
        Some(Form::P2tr(committed)) => {
            let tweaked = crate::address::taproot_output_key(&xonly_arr(pubkey)).ok()?;
            (tweaked == committed).then_some(Form::P2tr(committed))
        }
        _ => None,
    }
}

/// Legacy sighash preimage helper: the blanked stripped serialization
/// with the signed input's `scriptSig` set to the UTXO `scriptPubKey`
/// (the `build_vin` convention), ready for the sighash-type suffix.
fn blanked_serialization(tx: &Transaction, index: usize, script_pubkey: &[u8]) -> Vec<u8> {
    let mut preimage = Transaction {
        version: tx.version,
        vin: tx
            .vin
            .iter()
            .map(|vin| TxIn {
                script: Vec::new(),
                ..vin.clone()
            })
            .collect(),
        vout: tx.vout.clone(),
        locktime: tx.locktime,
    };
    preimage.vin[index].script = script_pubkey.to_vec();
    preimage.serialize_stripped()
}

/// The BIP-174 "Data Signers Check For" prev-tx rule shared by every
/// Signer branch: a *present* `NON_WITNESS_UTXO` must hash (stripped,
/// double-SHA256) to the outpoint being spent. Absent — vacuously
/// satisfied (the field is optional for witness forms; legacy/Creator
/// paths make it mandatory upstream).
fn check_prev_tx(
    prev: Option<&Transaction>,
    unsigned_tx: &Transaction,
    index: usize,
) -> Result<(), PsbtError> {
    if let Some(prev) = prev {
        if prev.id() != unsigned_tx.vin[index].txhash {
            return Err(PsbtError::UtxoMismatch);
        }
    }
    Ok(())
}

/// Insert a partial signature keeping `partial_sigs` sorted by pubkey
/// (deterministic serialization and KAT reproducibility).
fn insert_partial_sig(input: &mut PsbtInput, pubkey: PubKey, sig: Vec<u8>) {
    let pos = input.partial_sigs.partition_point(|(k, _)| k.0 <= pubkey.0);
    input.partial_sigs.insert(pos, (pubkey, sig));
}

/// The partial signature whose pubkey commits to `hash` (P2PKH /
/// P2WPKH finalization dispatch).
fn partial_sig_by_hash<'a>(
    input: &'a PsbtInput,
    hash: &[u8; 20],
) -> Option<(&'a PubKey, &'a Vec<u8>)> {
    input.partial_sigs.iter().find_map(|(pubkey, sig)| {
        if pubkey.0.len() != 33 {
            return None;
        }
        let mut compressed = [0u8; 33];
        compressed.copy_from_slice(&pubkey.0);
        (crate::address::hash160_pubkey(&compressed) == *hash).then_some((pubkey, sig))
    })
}

fn xonly_arr(pubkey: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&pubkey[1..33]);
    out
}

/// Merge opaque pair lists: identical keys must carry identical values
/// ([`PsbtError::ConflictingField`] otherwise), new keys are appended.
fn merge_unknown(a: &[UnknownKv], b: &[UnknownKv]) -> Result<Vec<UnknownKv>, PsbtError> {
    let mut out = a.to_vec();
    for kv in b {
        match out.iter().find(|existing| existing.key == kv.key) {
            Some(existing) if existing.value != kv.value => {
                return Err(PsbtError::ConflictingField);
            }
            Some(_) => {}
            None => out.push(kv.clone()),
        }
    }
    Ok(out)
}

/// Merge one optional typed field: absent sides are filled from the
/// other, both-present must be equal.
fn merge_field<T: Clone + PartialEq>(a: Option<T>, b: Option<T>) -> Result<Option<T>, PsbtError> {
    match (a, b) {
        (None, y) => Ok(y),
        (x, None) => Ok(x),
        (Some(x), Some(y)) => {
            if x == y {
                Ok(Some(x))
            } else {
                Err(PsbtError::ConflictingField)
            }
        }
    }
}

/// Merge a typed key-carrying list (`TAP_SCRIPT_SIG` /
/// `TAP_LEAF_SCRIPT`): identical keys must carry identical values
/// ([`PsbtError::ConflictingField`] otherwise), new keys are appended;
/// the result is kept sorted for deterministic serialization.
fn merge_typed_list<T: Clone + PartialEq + Ord>(
    a: &[T],
    b: &[T],
    key_of: impl Fn(&T) -> Vec<u8>,
) -> Result<Vec<T>, PsbtError> {
    let mut out = a.to_vec();
    for item in b {
        let key = key_of(item);
        match out.iter().find(|existing| key_of(existing) == key) {
            Some(existing) if existing != item => {
                return Err(PsbtError::ConflictingField);
            }
            Some(_) => {}
            None => out.push(item.clone()),
        }
    }
    out.sort();
    Ok(out)
}

/// Merge two input maps (see [`PartiallySignedTransaction::combine`]).
fn merge_input(a: &PsbtInput, b: &PsbtInput) -> Result<PsbtInput, PsbtError> {
    let non_witness_utxo = merge_field(a.non_witness_utxo.clone(), b.non_witness_utxo.clone())?;
    let witness_utxo = merge_field(a.witness_utxo.clone(), b.witness_utxo.clone())?;
    let mut partial_sigs = a.partial_sigs.clone();
    for (pubkey, sig) in &b.partial_sigs {
        match partial_sigs.iter().find(|(k, _)| k == pubkey) {
            Some((_, existing)) if existing != sig => {
                return Err(PsbtError::ConflictingField);
            }
            Some(_) => {}
            None => partial_sigs.push((pubkey.clone(), sig.clone())),
        }
    }
    partial_sigs.sort_by(|x, y| x.0.cmp(&y.0));
    let tap_script_sigs = merge_typed_list(&a.tap_script_sigs, &b.tap_script_sigs, |s| {
        [s.x_only.as_slice(), s.leaf_hash.as_slice()].concat()
    })?;
    let tap_leaf_scripts = merge_typed_list(&a.tap_leaf_scripts, &b.tap_leaf_scripts, |l| {
        l.control_block.clone()
    })?;
    Ok(PsbtInput {
        non_witness_utxo,
        witness_utxo,
        partial_sigs,
        sighash_type: merge_field(a.sighash_type, b.sighash_type)?,
        redeem_script: merge_field(a.redeem_script.clone(), b.redeem_script.clone())?,
        witness_script: merge_field(a.witness_script.clone(), b.witness_script.clone())?,
        final_scriptsig: merge_field(a.final_scriptsig.clone(), b.final_scriptsig.clone())?,
        final_scriptwitness: merge_field(
            a.final_scriptwitness.clone(),
            b.final_scriptwitness.clone(),
        )?,
        tap_script_sigs,
        tap_leaf_scripts,
        tap_internal_key: merge_field(a.tap_internal_key, b.tap_internal_key)?,
        tap_merkle_root: merge_field(a.tap_merkle_root, b.tap_merkle_root)?,
        unknown: merge_unknown(&a.unknown, &b.unknown)?,
    })
}

// --- base64 transport (RFC 4648 §4, hand-rolled, panic-free) ---------

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64-encode `data` with standard alphabet and `=` padding
/// (BIP-174's transport encoding; no new dependencies, same policy as
/// the hand-rolled bech32 codec).
pub fn encode_base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Base64-decode `s` (standard alphabet, `=` padding). Leading and
/// trailing ASCII whitespace is ignored; any other deviation — length
/// not a multiple of 4, unknown characters, padding in the wrong
/// place — is [`PsbtError::InvalidFieldValue`] (the transport-level
/// encoding error maps onto the shared "malformed value" variant).
pub fn decode_base64(s: &str) -> Result<Vec<u8>, PsbtError> {
    fn value_of(c: u8) -> Result<u32, PsbtError> {
        match c {
            b'A'..=b'Z' => Ok(u32::from(c - b'A')),
            b'a'..=b'z' => Ok(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Ok(u32::from(c - b'0') + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(PsbtError::InvalidFieldValue),
        }
    }
    let trimmed = s.trim_matches(|c: char| c.is_ascii_whitespace());
    let bytes = trimmed.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(PsbtError::InvalidFieldValue);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for quad in bytes.chunks(4) {
        let mut vals = [0u32; 4];
        let mut n_data = 4usize;
        for (i, &c) in quad.iter().enumerate() {
            if c == b'=' {
                // Padding may only shorten the final group from the
                // third character on.
                n_data = n_data.min(i);
            } else {
                if i >= n_data {
                    return Err(PsbtError::InvalidFieldValue);
                }
                vals[i] = value_of(c)?;
            }
        }
        if n_data < 2 {
            return Err(PsbtError::InvalidFieldValue);
        }
        let packed = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push((packed >> 16) as u8);
        if n_data >= 3 {
            out.push((packed >> 8) as u8);
        }
        if n_data >= 4 {
            out.push(packed as u8);
        }
    }
    Ok(out)
}

impl PartiallySignedTransaction {
    /// Parse from the base64 transport encoding (one line, BIP-174's
    /// `psbt` string). See [`decode_base64`] for the accepted grammar.
    pub fn from_base64(s: &str) -> Result<Self, PsbtError> {
        Self::parse(&decode_base64(s)?)
    }

    /// Render in canonical wire form and base64-encode — the string
    /// form every role outputs.
    pub fn to_base64(&self) -> String {
        encode_base64(&self.serialize())
    }
}
// Official BIP-174 test vectors (bitcoin/bips bip-0174.mediawiki),
// transcribed verbatim from the "Bytes in Hex" fields of the test
// vector section. Generated from the BIP source; do not hand-edit.
#[cfg(test)]
pub(crate) mod bip {
    // --- invalid vectors -------------------------------------------------

    /// BIP-174 case: Network transaction, not PSBT format
    pub(crate) const INV_NOT_A_PSBT: &str = "0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300";
    /// BIP-174 case: PSBT missing outputs
    pub(crate) const INV_MISSING_OUTPUTS: &str = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000";
    /// BIP-174 case: PSBT where one input has a filled scriptSig in the unsigned tx
    pub(crate) const INV_FILLED_SCRIPTSIG: &str = "70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000";
    /// BIP-174 case: PSBT where inputs and outputs are provided but without an unsigned tx
    pub(crate) const INV_NO_UNSIGNED_TX: &str = "70736274ff000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000";
    /// BIP-174 case: PSBT with duplicate keys in an input
    pub(crate) const INV_DUPLICATE_KEYS: &str = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000000";
    /// BIP-174 case: PSBT with invalid global transaction typed key
    pub(crate) const INV_KEY_GLOBAL_TX_KEYDATA: &str = "70736274ff020001550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000";
    /// BIP-174 case: PSBT with invalid input witness utxo typed key
    pub(crate) const INV_KEY_WITNESS_UTXO_KEYDATA: &str = "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac000000000002010020955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000";
    /// BIP-174 case: PSBT with invalid pubkey length for input partial signature typed key
    pub(crate) const INV_KEY_PARTIAL_SIG_PUBKEY_LEN: &str = "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87210203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000";
    /// BIP-174 case: PSBT with invalid redeemscript typed key
    pub(crate) const INV_KEY_REDEEM_SCRIPT_KEYDATA: &str = "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a01020400220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000";
    /// BIP-174 case: PSBT with invalid witnessscript typed key
    pub(crate) const INV_KEY_WITNESS_SCRIPT_KEYDATA: &str = "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d568102050047522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000";
    /// BIP-174 case: PSBT with invalid pubkey in input BIP 32 derivation paths typed key
    pub(crate) const INV_KEY_IN_BIP32_PUBKEY_LEN: &str = "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae210603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd10b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000";
    /// BIP-174 case: PSBT with invalid non-witness utxo typed key
    pub(crate) const INV_KEY_NON_WITNESS_UTXO_KEYDATA: &str = "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f0000000000020000bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000";
    /// BIP-174 case: PSBT with invalid final scriptsig typed key
    pub(crate) const INV_KEY_FINAL_SCRIPTSIG_KEYDATA: &str = "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000020700da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000";
    /// BIP-174 case: PSBT with invalid final script witness typed key
    pub(crate) const INV_KEY_FINAL_SCRIPTWITNESS_KEYDATA: &str = "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903020800da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000";
    /// BIP-174 case: PSBT with invalid pubkey in output BIP 32 derivation paths typed key
    pub(crate) const INV_KEY_OUT_BIP32_PUBKEY_LEN: &str = "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00210203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58710d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000";
    /// BIP-174 case: PSBT with invalid input sighash type typed key
    pub(crate) const INV_KEY_SIGHASH_TYPE_KEYDATA: &str = "70736274ff0100730200000001301ae986e516a1ec8ac5b4bc6573d32f83b465e23ad76167d68b38e730b4dbdb0000000000ffffffff02747b01000000000017a91403aa17ae882b5d0d54b25d63104e4ffece7b9ea2876043993b0000000017a914b921b1ba6f722e4bfa83b6557a3139986a42ec8387000000000001011f00ca9a3b00000000160014d2d94b64ae08587eefc8eeb187c601e939f9037c0203000100000000010016001462e9e982fff34dd8239610316b090cd2a3b747cb000100220020876bad832f1d168015ed41232a9ea65a1815d9ef13c0ef8759f64b5b2b278a65010125512103b7ce23a01c5b4bf00a642537cdfabb315b668332867478ef51309d2bd57f8a8751ae00";
    /// BIP-174 case: PSBT with invalid output redeemScript typed key
    pub(crate) const INV_KEY_OUT_REDEEM_SCRIPT_KEYDATA: &str = "70736274ff0100730200000001301ae986e516a1ec8ac5b4bc6573d32f83b465e23ad76167d68b38e730b4dbdb0000000000ffffffff02747b01000000000017a91403aa17ae882b5d0d54b25d63104e4ffece7b9ea2876043993b0000000017a914b921b1ba6f722e4bfa83b6557a3139986a42ec8387000000000001011f00ca9a3b00000000160014d2d94b64ae08587eefc8eeb187c601e939f9037c0002000016001462e9e982fff34dd8239610316b090cd2a3b747cb000100220020876bad832f1d168015ed41232a9ea65a1815d9ef13c0ef8759f64b5b2b278a65010125512103b7ce23a01c5b4bf00a642537cdfabb315b668332867478ef51309d2bd57f8a8751ae00";
    /// BIP-174 case: PSBT with invalid output witnessScript typed key
    pub(crate) const INV_KEY_OUT_WITNESS_SCRIPT_KEYDATA: &str = "70736274ff0100730200000001301ae986e516a1ec8ac5b4bc6573d32f83b465e23ad76167d68b38e730b4dbdb0000000000ffffffff02747b01000000000017a91403aa17ae882b5d0d54b25d63104e4ffece7b9ea2876043993b0000000017a914b921b1ba6f722e4bfa83b6557a3139986a42ec8387000000000001011f00ca9a3b00000000160014d2d94b64ae08587eefc8eeb187c601e939f9037c00010016001462e9e982fff34dd8239610316b090cd2a3b747cb000100220020876bad832f1d168015ed41232a9ea65a1815d9ef13c0ef8759f64b5b2b278a6521010025512103b7ce23a01c5b4bf00a642537cdfabb315b668332867478ef51309d06d57f8a8751ae00";
    /// BIP-174 case: PSBT with unsigned tx serialized with witness serialization format
    pub(crate) const INV_UNSIGNED_TX_WIRE_FORMAT: &str = "70736274ff01007802000000000101268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc78700b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000";
    /// BIP-174 case: PSBT with an invalid value data due to its size being not the stated size
    pub(crate) const INV_VALUE_SIZE_MISMATCH: &str = "70736274ff0100337401ff0700010000000100ff01000a73317428ff0000000001ff010301000001000000000000000076010000004100090000000000";
    /// BIP-174 case: PSBT with one P2PKH input. Outputs are empty
    pub(crate) const VAL_ONE_P2PKH_INPUT: &str = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000";
    /// BIP-174 case: PSBT with one P2PKH input and one P2SH-P2WPKH input. First input is signed and finalized. Outputs are empty
    pub(crate) const VAL_P2PKH_P2SH_P2WPKH_FINALIZED: &str = "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000";
    /// BIP-174 case: PSBT with one P2PKH input which has a non-final scriptSig and has a sighash type specified. Outputs are empty
    pub(crate) const VAL_SIGHASH_TYPE_SPECIFIED: &str = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001030401000000000000";
    /// BIP-174 case: PSBT with one P2PKH input and one P2SH-P2WPKH input both with non-final scriptSigs. P2SH-P2WPKH input's redeemScript is available. Outputs filled
    pub(crate) const VAL_NON_FINAL_SCRIPTSIGS_FILLED: &str = "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000100df0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e13000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb8230800220202ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e9910b4a6ba670000008000000080020000800022020394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d0510b4a6ba6700000080010000800200008000";
    /// BIP-174 case: PSBT with one P2SH-P2WSH input of a 2-of-2 multisig, redeemScript, witnessScript, and keypaths are available. Contains one signature
    pub(crate) const VAL_P2SH_P2WSH_MULTISIG_ONE_SIG: &str = "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000";
    /// BIP-174 case: PSBT with one P2WSH input of a 2-of-2 multisig. witnessScript, keypaths, and global xpubs are available. Contains no signatures. Outputs filled
    pub(crate) const VAL_P2WSH_MULTISIG_XPUBS: &str = "70736274ff01005202000000019dfc6628c26c5899fe1bd3dc338665bfd55d7ada10f6220973df2d386dec12760100000000ffffffff01f03dcd1d000000001600147b3a00bfdc14d27795c2b74901d09da6ef133579000000004f01043587cf02da3fd0088000000097048b1ad0445b1ec8275517727c87b4e4ebc18a203ffa0f94c01566bd38e9000351b743887ee1d40dc32a6043724f2d6459b3b5a4d73daec8fbae0472f3bc43e20cd90c6a4fae000080000000804f01043587cf02da3fd00880000001b90452427139cd78c2cff2444be353cd58605e3e513285e528b407fae3f6173503d30a5e97c8adbc557dac2ad9a7e39c1722ebac69e668b6f2667cc1d671c83cab0cd90c6a4fae000080010000800001012b0065cd1d000000002200202c5486126c4978079a814e13715d65f36459e4d6ccaded266d0508645bafa6320105475221029da12cdb5b235692b91536afefe5c91c3ab9473d8e43b533836ab456299c88712103372b34234ed7cf9c1fea5d05d441557927be9542b162eb02e1ab2ce80224c00b52ae2206029da12cdb5b235692b91536afefe5c91c3ab9473d8e43b533836ab456299c887110d90c6a4fae0000800000008000000000220603372b34234ed7cf9c1fea5d05d441557927be9542b162eb02e1ab2ce80224c00b10d90c6a4fae0000800100008000000000002202039eff1f547a1d5f92dfa2ba7af6ac971a4bd03ba4a734b03156a256b8ad3a1ef910ede45cc500000080000000800100008000";
    /// BIP-174 case: PSBT with unknown types in the inputs
    pub(crate) const VAL_UNKNOWN_INPUT_TYPES: &str = "70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000af00102030405060708090f0102030405060708090a0b0c0d0e0f0000";
    /// BIP-174 case: PSBT with `PSBT_GLOBAL_XPUB`
    pub(crate) const VAL_GLOBAL_XPUB: &str = "70736274ff01009d0100000002710ea76ab45c5cb6438e607e59cc037626981805ae9e0dfd9089012abb0be5350100000000ffffffff190994d6a8b3c8c82ccbcfb2fba4106aa06639b872a8d447465c0d42588d6d670000000000ffffffff0200e1f505000000001976a914b6bc2c0ee5655a843d79afedd0ccc3f7dd64340988ac605af405000000001600141188ef8e4ce0449eaac8fb141cbf5a1176e6a088000000004f010488b21e039e530cac800000003dbc8a5c9769f031b17e77fea1518603221a18fd18f2b9a54c6c8c1ac75cbc3502f230584b155d1c7f1cd45120a653c48d650b431b67c5b2c13f27d7142037c1691027569c503100008000000080000000800001011f00e1f5050000000016001433b982f91b28f160c920b4ab95e58ce50dda3a4a220203309680f33c7de38ea6a47cd4ecd66f1f5a49747c6ffb8808ed09039243e3ad5c47304402202d704ced830c56a909344bd742b6852dccd103e963bae92d38e75254d2bb424502202d86c437195df46c0ceda084f2a291c3da2d64070f76bf9b90b195e7ef28f77201220603309680f33c7de38ea6a47cd4ecd66f1f5a49747c6ffb8808ed09039243e3ad5c1827569c5031000080000000800000008000000000010000000001011f00e1f50500000000160014388fb944307eb77ef45197d0b0b245e079f011de220202c777161f73d0b7c72b9ee7bde650293d13f095bc7656ad1f525da5fd2e10b11047304402204cb1fb5f869c942e0e26100576125439179ae88dca8a9dc3ba08f7953988faa60220521f49ca791c27d70e273c9b14616985909361e25be274ea200d7e08827e514d01220602c777161f73d0b7c72b9ee7bde650293d13f095bc7656ad1f525da5fd2e10b1101827569c5031000080000000800000008000000000000000000000220202d20ca502ee289686d21815bd43a80637b0698e1fbcdbe4caed445f6c1a0a90ef1827569c50310000800000008000000080000000000400000000";
    /// BIP-174 case: PSBT with global unsigned tx that has 0 inputs and 0 outputs
    pub(crate) const VAL_TX_0_IN_0_OUT: &str = "70736274ff01000a0000000000000000000000";
    /// BIP-174 case: PSBT with 0 inputs
    pub(crate) const VAL_ZERO_INPUTS: &str = "70736274ff01004c020000000002d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000000";
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::fwd::{PSBT_MAX_SIZE, PSBT_SIGN_MAX_NONCE};
    use crate::kdf::KdfAlgo;
    use crate::misc::{TAddress, TNonce, TPassphrase, TSatoshi, TSeed};
    use crate::net::{NetError, NetworkBackend};
    use crate::privkey::seed2privkey_with_kdf;
    use crate::wallet::{
        build_vin, derive_script, make_vout, sign_psbt_with, AddrType, Source, TPrivKey, Wallet,
    };
    // Synthetic surrogate signatures in the combine/commutativity
    // property tests still go through the `Signer` trait (they are
    // container-level fixtures, not on-chain signatures).
    use k256::ecdsa::signature::Signer as _;
    use proptest::prelude::*;
    use std::sync::Mutex;

    /// Fixture seed shared by all role tests (yubtc cascade KDF —
    /// offline derivation, deterministic).
    const SEED: &str = "phase14psbt";

    fn fixture_key(nonce: u32) -> SigningKey {
        seed2privkey_with_kdf(
            &TSeed::new(SEED),
            TNonce::new(nonce),
            &TPassphrase::EMPTY,
            kdf(),
        )
        .expect("fixture derives")
    }

    fn fixture_kdf() -> KdfAlgo {
        KdfAlgo::Yubtc
    }

    fn kdf() -> KdfAlgo {
        fixture_kdf()
    }

    /// `scriptPubKey` of the fixture key at `(nonce, form)`.
    fn fixture_spk(nonce: u32, form: AddrType) -> Vec<u8> {
        derive_script(
            &TSeed::new(SEED),
            TNonce::new(nonce),
            &TPassphrase::EMPTY,
            kdf(),
            form,
        )
        .expect("fixture derives")
    }

    /// Build one raw PSBT keypair (`keylen ‖ key ‖ valuelen ‖ value`).
    fn kv(key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_compact_size(&mut out, key.len() as u64);
        out.extend_from_slice(key);
        write_compact_size(&mut out, value.len() as u64);
        out.extend_from_slice(value);
        out
    }

    /// Assemble a raw PSBT from raw pair bytes and raw sub-maps.
    fn assemble(
        global_pairs: &[Vec<u8>],
        input_maps: &[Vec<u8>],
        output_maps: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x70, 0x73, 0x62, 0x74, 0xff]);
        for pair in global_pairs {
            out.extend_from_slice(pair);
        }
        out.push(0);
        for m in input_maps.iter().chain(output_maps) {
            out.extend_from_slice(m);
            out.push(0);
        }
        out
    }

    /// A minimal but valid unsigned tx (one input, one P2PKH-ish
    /// output) for hand-assembled parse tests.
    fn stub_tx_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&2i32.to_le_bytes());
        out.push(1); // one vin
        out.extend_from_slice(&[0x11u8; 32]);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.push(0); // empty scriptSig
        out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        out.push(1); // one vout
        out.extend_from_slice(&1000u64.to_le_bytes());
        out.push(1);
        out.push(0x51);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    /// A valid unsigned tx spending one legacy and two witness-form
    /// outputs of the fixture prev tx — the self-parity KAT skeleton.
    fn kat_prev_tx() -> Transaction {
        Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x11; 32],
                n: 3,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![
                TxOut {
                    amount: 60_000,
                    script: fixture_spk(0, AddrType::Legacy),
                },
                TxOut {
                    amount: 30_000,
                    script: fixture_spk(0, AddrType::Native),
                },
                TxOut {
                    amount: 20_000,
                    script: fixture_spk(0, AddrType::Taproot),
                },
            ],
            locktime: 0,
        }
    }

    // --- NetworkBackend impl for the walk tests ----------------------
    //
    // The Signer walk itself is offline; the backend is only part of
    // the Wallet struct. Every method is driven in
    // `walk_test_backend_methods_exercised` so coverage stays honest.

    #[derive(Debug, Default)]
    struct WalkTestBackend {
        raw_calls: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl NetworkBackend for WalkTestBackend {
        async fn get_unspent(
            &self,
            _address: &TAddress,
        ) -> Result<Vec<crate::wallet::Utxo>, NetError> {
            Ok(Vec::new())
        }
        async fn get_info(
            &self,
            _address: &TAddress,
        ) -> Result<crate::wallet::AddressInfo, NetError> {
            Ok(crate::wallet::AddressInfo::default())
        }
        async fn broadcast(&self, _raw_tx: &[u8]) -> Result<(), NetError> {
            Ok(())
        }
        async fn raw_transaction(&self, txid: &str) -> Result<String, NetError> {
            self.raw_calls.lock().unwrap().push(txid.to_string());
            Ok("00".repeat(100))
        }
        fn name(&self) -> &'static str {
            "walk-test"
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn walk_test_backend_methods_exercised() {
        let backend = WalkTestBackend::default();
        assert_eq!(backend.name(), "walk-test");
    }

    #[tokio::test]
    async fn walk_test_backend_async_methods_exercised() {
        let backend = WalkTestBackend::default();
        let addr = TAddress::new("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        assert!(backend.get_unspent(&addr).await.unwrap().is_empty());
        assert_eq!(backend.get_info(&addr).await.unwrap().n_tx, 0);
        backend.broadcast(b"deadbeef").await.unwrap();
        let hex_tx = backend.raw_transaction(&"ab".repeat(32)).await.unwrap();
        assert_eq!(hex_tx.len(), 200);
        let expected_calls = vec!["ab".repeat(32)];
        assert_eq!(
            backend.raw_calls.lock().unwrap().as_slice(),
            expected_calls.as_slice()
        );
    }

    // --- base64 codec -------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn base64_matches_rfc4648_test_vectors() {
        // The RFC 4648 §5... §4 test vectors.
        for (raw, encoded) in [
            (&b""[..], ""),
            (b"f".as_slice(), "Zg=="),
            (b"fo".as_slice(), "Zm8="),
            (b"foo".as_slice(), "Zm9v"),
            (b"foob".as_slice(), "Zm9vYg=="),
            (b"fooba".as_slice(), "Zm9vYmE="),
            (b"foobar".as_slice(), "Zm9vYmFy"),
        ] {
            assert_eq!(encode_base64(raw), encoded, "encode {raw:?}");
            assert_eq!(decode_base64(encoded).unwrap(), raw, "decode {encoded}");
        }
    }

    /// The BIP-174 transport string of the first valid vector decodes
    /// to its hex twin — cross-checks the codec against the BIP text.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn base64_decodes_bip174_vector() {
        let bytes = decode_base64(BIP_ONE_P2PKH_B64).unwrap();
        assert_eq!(bytes, hex::decode(bip::VAL_ONE_P2PKH_INPUT).unwrap());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn base64_ignores_surrounding_whitespace() {
        assert_eq!(decode_base64("  Zm9v\n").unwrap(), b"foo".as_slice());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn base64_rejects_malformed_input() {
        assert_eq!(decode_base64("A"), Err(PsbtError::InvalidFieldValue));
        assert_eq!(decode_base64("ABC"), Err(PsbtError::InvalidFieldValue));
        assert_eq!(decode_base64("ABCD*"), Err(PsbtError::InvalidFieldValue));
        assert_eq!(decode_base64("AB#D"), Err(PsbtError::InvalidFieldValue));
        // Padding in the middle of a group.
        assert_eq!(decode_base64("A=CD"), Err(PsbtError::InvalidFieldValue));
        // Data after padding.
        assert_eq!(decode_base64("Zg=A"), Err(PsbtError::InvalidFieldValue));
        // A lone padding group.
        assert_eq!(decode_base64("===="), Err(PsbtError::InvalidFieldValue));
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(1000))]

        #[test]
        fn prop_base64_round_trip(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let encoded = encode_base64(&data);
            assert_eq!(decode_base64(&encoded).unwrap(), data);
        }
    }

    // --- compact size / key split --------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn compact_size_known_encodings() {
        for (value, expected) in [
            (0u64, vec![0u8]),
            (0xfc, vec![0xfc]),
            (0xfd, vec![0xfd, 0xfd, 0x00]),
            (0x1_0000, vec![0xfe, 0x00, 0x00, 0x01, 0x00]),
            (0x1_0000_0000, vec![0xff, 0, 0, 0, 0, 1, 0, 0, 0]),
        ] {
            let mut out = Vec::new();
            write_compact_size(&mut out, value);
            assert_eq!(out, expected);
            let mut r = Reader::new(&out);
            assert_eq!(r.read_compact_size().unwrap(), value);
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn split_key_enforces_minimal_type_encoding() {
        // Single-byte type.
        assert_eq!(
            split_key(&[0x02, 0xaa, 0xbb]).unwrap(),
            (2, &[0xaa, 0xbb][..])
        );
        // Non-minimal: `fd 02 00` encodes type 2 (the spec's
        // «0xFD 0x00 0x02» example, byte order notwithstanding).
        assert_eq!(
            split_key(&[0xfd, 0x02, 0x00]),
            Err(PsbtError::NonMinimalCompactSize)
        );
        // `fd 00 02` is type 512 — minimal, fine.
        assert_eq!(split_key(&[0xfd, 0x00, 0x02]).unwrap().0, 512);
        // Minimal 3-byte type (300 > 0xfc).
        assert_eq!(split_key(&[0xfd, 0x2c, 0x01]).unwrap(), (300, &[][..]));
        // Non-minimal 5-byte type (0x0100 ≤ 0xffff).
        assert_eq!(
            split_key(&[0xfe, 0x00, 0x01, 0x00, 0x00]),
            Err(PsbtError::NonMinimalCompactSize)
        );
        // Minimal 5-byte type (0x10000 > 0xffff).
        assert_eq!(
            split_key(&[0xfe, 0x00, 0x00, 0x01, 0x00]).unwrap().0,
            0x1_0000
        );
        // Non-minimal 9-byte type (0x0100_0000 ≤ 0xffff_ffff).
        assert_eq!(
            split_key(&[0xff, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0]),
            Err(PsbtError::NonMinimalCompactSize)
        );
        // Minimal 9-byte type.
        assert_eq!(
            split_key(&[0xff, 0, 0, 0, 0, 1, 0, 0, 0]).unwrap().0,
            0x1_0000_0000
        );
        // Truncated type prefixes.
        assert_eq!(split_key(&[0xfd]), Err(PsbtError::Truncated));
        assert_eq!(split_key(&[0xfd, 0x01]), Err(PsbtError::Truncated));
        assert_eq!(split_key(&[0xfe, 0x01]), Err(PsbtError::Truncated));
        assert_eq!(split_key(&[0xff, 0x01]), Err(PsbtError::Truncated));
        assert_eq!(split_key(&[]), Err(PsbtError::Truncated));
    }

    // --- parser: structure errors ---------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_bad_and_short_magic() {
        assert_eq!(
            PartiallySignedTransaction::parse(b""),
            Err(PsbtError::InvalidMagic)
        );
        // Shorter than the magic can only be "not a PSBT".
        assert_eq!(
            PartiallySignedTransaction::parse(b"psbt"),
            Err(PsbtError::InvalidMagic)
        );
        assert_eq!(
            PartiallySignedTransaction::parse(b"xxxx\xffwhatever"),
            Err(PsbtError::InvalidMagic)
        );
        // Official vector: a raw network transaction.
        assert_eq!(
            PartiallySignedTransaction::parse(&hex::decode(bip::INV_NOT_A_PSBT).unwrap()),
            Err(PsbtError::InvalidMagic)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_oversized_input() {
        let mut data = vec![0u8; PSBT_MAX_SIZE + 1];
        data[..5].copy_from_slice(&[0x70, 0x73, 0x62, 0x74, 0xff]);
        assert_eq!(
            PartiallySignedTransaction::parse(&data),
            Err(PsbtError::TooLarge)
        );
        // Exactly at the cap passes the guard (then fails on the
        // missing UNSIGNED_TX, not on size).
        data.pop();
        assert_eq!(
            PartiallySignedTransaction::parse(&data),
            Err(PsbtError::MissingUnsignedTx)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_truncation_mid_keypair() {
        // Deep cut: lands inside the input map's 421-byte value.
        let mut bytes = hex::decode(bip::VAL_ONE_P2PKH_INPUT).unwrap();
        bytes.truncate(bytes.len() - 30);
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::Truncated)
        );
        // Cutting the two output-map terminators off leaves the
        // expected output maps missing entirely.
        let mut bytes = hex::decode(bip::VAL_ONE_P2PKH_INPUT).unwrap();
        bytes.truncate(bytes.len() - 2);
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::MapCountMismatch)
        );
        // The official "value size not as stated" vector: a declared
        // length that overruns the buffer. The corruption surfaces at
        // the UNSIGNED_TX layer (the mangled stream is caught while
        // parsing the global transaction field).
        assert_eq!(
            PartiallySignedTransaction::parse(&hex::decode(bip::INV_VALUE_SIZE_MISMATCH).unwrap()),
            Err(PsbtError::InvalidUnsignedTx)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_second_terminator_and_extra_maps() {
        // Stray 0x00 after the final map — the "second terminator".
        let mut bytes = hex::decode(bip::VAL_ONE_P2PKH_INPUT).unwrap();
        bytes.push(0);
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::Truncated)
        );
        // A trailing non-zero byte = an extra (non-empty) map.
        let mut bytes = hex::decode(bip::VAL_ONE_P2PKH_INPUT).unwrap();
        bytes.push(0x01);
        bytes.push(0x02);
        bytes.push(0x03);
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::MapCountMismatch)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_missing_maps_and_missing_unsigned_tx() {
        // Official vector: 2 outputs declared, no output maps.
        assert_eq!(
            PartiallySignedTransaction::parse(&hex::decode(bip::INV_MISSING_OUTPUTS).unwrap()),
            Err(PsbtError::MapCountMismatch)
        );
        // Official vector: maps present, UNSIGNED_TX absent.
        assert_eq!(
            PartiallySignedTransaction::parse(&hex::decode(bip::INV_NO_UNSIGNED_TX).unwrap()),
            Err(PsbtError::MissingUnsignedTx)
        );
        // Empty global map alone → no UNSIGNED_TX either.
        let bytes = assemble(&[], &[], &[]);
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::MissingUnsignedTx)
        );
    }

    /// The transport string of BIP-174's first valid vector ("PSBT with
    /// one P2PKH input. Outputs are empty"), used to cross-check the
    /// hand-rolled base64 codec against the BIP text.
    const BIP_ONE_P2PKH_B64: &str = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA";

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_non_minimal_key_type() {
        // The spec's non-minimal example («0xFD 0x00 0x02» for type 2)
        // in wire (little-endian) byte order: key type `fd 02 00`.
        let tx = stub_tx_bytes();
        let bad_pair = kv(&[0xfd, 0x02, 0x00, 0xaa], &[0x01]);
        let bytes = assemble(
            &[kv(&[T_ZERO], &tx), bad_pair],
            &[Vec::new()],
            &[Vec::new()],
        );
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::NonMinimalCompactSize)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_duplicate_keys_across_known_and_unknown() {
        // Same unknown key twice in the global map.
        let tx = stub_tx_bytes();
        let pair = kv(&[0x51, 0xaa], &[0x01]);
        let bytes = assemble(&[kv(&[T_ZERO], &tx), pair.clone(), pair], &[], &[]);
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::DuplicateKey)
        );
    }

    /// Table of the official invalid vectors that fail on key shapes.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip_invalid_vectors_map_to_typed_errors() {
        let cases: &[(&str, &str, PsbtError)] = &[
            (
                "duplicate keys in an input",
                bip::INV_DUPLICATE_KEYS,
                PsbtError::DuplicateKey,
            ),
            (
                "global transaction typed key with keydata",
                bip::INV_KEY_GLOBAL_TX_KEYDATA,
                PsbtError::InvalidKeyLength(T_ZERO),
            ),
            (
                "input witness utxo typed key with keydata",
                bip::INV_KEY_WITNESS_UTXO_KEYDATA,
                PsbtError::InvalidKeyLength(T_IN_WITNESS_UTXO),
            ),
            (
                "32-byte pubkey in PARTIAL_SIG key",
                bip::INV_KEY_PARTIAL_SIG_PUBKEY_LEN,
                PsbtError::InvalidKeyLength(T_PARTIAL_SIG),
            ),
            (
                "redeem script typed key with keydata",
                bip::INV_KEY_REDEEM_SCRIPT_KEYDATA,
                PsbtError::InvalidKeyLength(T_REDEEM_SCRIPT),
            ),
            (
                "witness script typed key with keydata",
                bip::INV_KEY_WITNESS_SCRIPT_KEYDATA,
                PsbtError::InvalidKeyLength(T_WITNESS_SCRIPT),
            ),
            (
                "32-byte pubkey in input BIP32 derivation key",
                bip::INV_KEY_IN_BIP32_PUBKEY_LEN,
                PsbtError::InvalidKeyLength(T_IN_BIP32_DERIVATION),
            ),
            (
                "non-witness utxo typed key with keydata",
                bip::INV_KEY_NON_WITNESS_UTXO_KEYDATA,
                PsbtError::InvalidKeyLength(T_ZERO),
            ),
            (
                "final scriptsig typed key with keydata",
                bip::INV_KEY_FINAL_SCRIPTSIG_KEYDATA,
                PsbtError::InvalidKeyLength(T_FINAL_SCRIPTSIG),
            ),
            (
                "final scriptwitness typed key with keydata",
                bip::INV_KEY_FINAL_SCRIPTWITNESS_KEYDATA,
                PsbtError::InvalidKeyLength(T_FINAL_SCRIPTWITNESS),
            ),
            (
                "32-byte pubkey in output BIP32 derivation key",
                bip::INV_KEY_OUT_BIP32_PUBKEY_LEN,
                PsbtError::InvalidKeyLength(T_PARTIAL_SIG),
            ),
            (
                "sighash type typed key with keydata",
                bip::INV_KEY_SIGHASH_TYPE_KEYDATA,
                PsbtError::InvalidKeyLength(T_SIGHASH_TYPE),
            ),
            (
                "output redeem script typed key with keydata",
                bip::INV_KEY_OUT_REDEEM_SCRIPT_KEYDATA,
                PsbtError::InvalidKeyLength(T_ZERO),
            ),
            (
                "output witness script typed key with keydata",
                bip::INV_KEY_OUT_WITNESS_SCRIPT_KEYDATA,
                PsbtError::InvalidKeyLength(T_IN_WITNESS_UTXO),
            ),
            (
                "unsigned tx in witness serialization format",
                bip::INV_UNSIGNED_TX_WIRE_FORMAT,
                PsbtError::InvalidUnsignedTx,
            ),
            (
                "filled scriptSig in the unsigned tx",
                bip::INV_FILLED_SCRIPTSIG,
                PsbtError::InvalidUnsignedTx,
            ),
        ];
        for (name, hex_str, expected) in cases {
            let bytes = hex::decode(hex_str).unwrap();
            let actual = PartiallySignedTransaction::parse(&bytes);
            assert_eq!(actual.as_ref(), Err(expected), "case: {name}");
            // No panics on Display either.
            assert!(!actual.unwrap_err().to_string().is_empty());
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_bad_field_values() {
        let tx = stub_tx_bytes();
        // VERSION with a non-4-byte value.
        let bytes = assemble(
            &[kv(&[T_ZERO], &tx), kv(&[T_VERSION], &[1, 2, 3])],
            &[Vec::new()],
            &[Vec::new()],
        );
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::InvalidFieldValue)
        );
        // SIGHASH_TYPE with a 3-byte value (the input carries a
        // well-formed WITNESS_UTXO so parsing reaches the bad pair).
        let input_pair = {
            let mut v = Vec::new();
            v.extend_from_slice(&0u64.to_le_bytes());
            write_compact_size(&mut v, 22);
            v.extend_from_slice(&[0u8; 22]);
            kv(&[T_IN_WITNESS_UTXO], &v)
        };
        let sighash_pair = kv(&[T_SIGHASH_TYPE], &[1, 0, 0]);
        let mut input_map = input_pair;
        input_map.extend_from_slice(&sighash_pair);
        let bytes = assemble(&[kv(&[T_ZERO], &tx)], &[input_map], &[Vec::new()]);
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::InvalidFieldValue)
        );
        // WITNESS_UTXO with trailing bytes.
        let mut value = Vec::new();
        value.extend_from_slice(&0u64.to_le_bytes());
        write_compact_size(&mut value, 1);
        value.push(0x51);
        value.push(0xff); // trailing
        let bytes = assemble(
            &[kv(&[T_ZERO], &tx)],
            &[kv(&[T_IN_WITNESS_UTXO], &value)],
            &[Vec::new()],
        );
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::InvalidFieldValue)
        );
        // NON_WITNESS_UTXO with trailing bytes.
        let mut value = tx.clone();
        value.push(0);
        let bytes = assemble(
            &[kv(&[T_ZERO], &tx)],
            &[kv(&[T_ZERO], &value)],
            &[Vec::new(), Vec::new()],
        );
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::InvalidFieldValue)
        );
        // Global xpub with a wrong keydata length.
        let mut key = vec![T_GLOBAL_XPUB];
        key.extend_from_slice(&[0u8; 77]);
        let bytes = assemble(
            &[kv(&[T_ZERO], &tx), kv(&key, &[])],
            &[Vec::new()],
            &[Vec::new()],
        );
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::InvalidKeyLength(T_GLOBAL_XPUB))
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_nonzero_version() {
        let tx = stub_tx_bytes();
        let bytes = assemble(
            &[kv(&[T_ZERO], &tx), kv(&[T_VERSION], &1u32.to_le_bytes())],
            &[],
            &[],
        );
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::UnsupportedVersion(1))
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_accepts_version_zero_field_and_strips_it() {
        let tx = stub_tx_bytes();
        let bytes = assemble(
            &[kv(&[T_ZERO], &tx), kv(&[T_VERSION], &0u32.to_le_bytes())],
            &[Vec::new()],
            &[Vec::new()],
        );
        let psbt = PartiallySignedTransaction::parse(&bytes).unwrap();
        assert_eq!(psbt.version, 0);
        // v0 is encoded by ABSENCE — the field is not written back.
        assert_eq!(psbt.serialize(), {
            let mut expected = Vec::new();
            expected.extend_from_slice(&[0x70, 0x73, 0x62, 0x74, 0xff]);
            expected.extend_from_slice(&kv(&[T_ZERO], &tx));
            expected.push(0); // global terminator
            expected.push(0); // empty input map
            expected.push(0); // empty output map
            expected
        });
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_unsigned_tx_without_outputs() {
        // Official vector "0 inputs and 0 outputs": the yubtc validator
        // requires ≥ 1 output (same rule the "missing outputs" vector
        // encodes); the current BIP text lists this case as valid, the
        // deviation is deliberate and documented.
        let bytes = hex::decode(bip::VAL_TX_0_IN_0_OUT).unwrap();
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::InvalidUnsignedTx)
        );
        // Garbage that is not a transaction at all.
        let bytes = assemble(&[kv(&[T_ZERO], &[1, 2, 3])], &[], &[]);
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::InvalidUnsignedTx)
        );
    }

    /// All official valid vectors: parse → serialize → parse must be
    /// stable, and (the vectors being canonically ordered)
    /// `serialize(parse(x)) == x` byte-for-byte.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip_valid_vectors_round_trip() {
        let vectors = [
            bip::VAL_ONE_P2PKH_INPUT,
            bip::VAL_P2PKH_P2SH_P2WPKH_FINALIZED,
            bip::VAL_SIGHASH_TYPE_SPECIFIED,
            bip::VAL_NON_FINAL_SCRIPTSIGS_FILLED,
            bip::VAL_P2SH_P2WSH_MULTISIG_ONE_SIG,
            bip::VAL_P2WSH_MULTISIG_XPUBS,
            bip::VAL_UNKNOWN_INPUT_TYPES,
            bip::VAL_GLOBAL_XPUB,
            bip::VAL_ZERO_INPUTS,
        ];
        for hex_str in vectors {
            let bytes = hex::decode(hex_str).unwrap();
            let first = PartiallySignedTransaction::parse(&bytes).expect("valid vector must parse");
            let re = first.serialize();
            assert_eq!(re, bytes, "canonical round-trip");
            let second = PartiallySignedTransaction::parse(&re).unwrap();
            assert_eq!(first, second, "structural stability");
            assert_eq!(second.serialize(), re, "serialization stability");
            // The base64 transport agrees with the wire form.
            assert_eq!(decode_base64(&first.to_base64()).unwrap(), re);
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_canonicalizes_unsorted_maps() {
        // Take the first valid vector and swap its input-map pairs so
        // the key order is non-canonical; parse must accept it and the
        // serializer must restore the canonical order.
        let bytes = hex::decode(bip::VAL_NON_FINAL_SCRIPTSIGS_FILLED).unwrap();
        // Its second input map has the (sorted) pairs `00`, `01`;
        // rebuild the same PSBT with those two pairs swapped by
        // injecting a fresh map ordering through the raw assembler is
        // brittle — instead inject unknown pairs out of order.
        let mut psbt = PartiallySignedTransaction::parse(&bytes).unwrap();
        psbt.inputs[1].unknown = vec![
            UnknownKv {
                key: vec![0x51, 0x02],
                value: vec![1],
            },
            UnknownKv {
                key: vec![0x51, 0x01],
                value: vec![2],
            },
        ];
        let serialized = psbt.serialize();
        let reparsed = PartiallySignedTransaction::parse(&serialized).unwrap();
        // Equality is on the canonical form (parse stores the pairs in
        // wire order; serialize re-sorts deterministically).
        assert_eq!(reparsed.serialize(), serialized);
        // Sorted output: 0x51 0x01 before 0x51 0x02.
        let needle_a = kv(&[0x51, 0x01], &[2]);
        let needle_b = kv(&[0x51, 0x02], &[1]);
        let pos_a = serialized
            .windows(needle_a.len())
            .position(|w| w == needle_a.as_slice())
            .unwrap();
        let pos_b = serialized
            .windows(needle_b.len())
            .position(|w| w == needle_b.as_slice())
            .unwrap();
        assert!(pos_a < pos_b);
    }

    // --- create -------------------------------------------------------

    fn kat_utxos() -> (Transaction, Vec<CreateInput>) {
        let prev = kat_prev_tx();
        let create_inputs = vec![
            CreateInput {
                amount: 60_000,
                script_pubkey: fixture_spk(0, AddrType::Legacy),
                prev_tx: Some(prev.clone()),
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
            CreateInput {
                amount: 30_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
            CreateInput {
                amount: 20_000,
                script_pubkey: fixture_spk(0, AddrType::Taproot),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
        ];
        (prev, create_inputs)
    }

    /// An unsigned tx spending the three fixture UTXOs (the PSBT
    /// `vin`/signer shape mirrors `build_vin`, with empty scripts).
    fn kat_unsigned_tx() -> Transaction {
        Transaction {
            version: 2,
            vin: vec![
                TxIn {
                    txhash: kat_prev_tx().id(),
                    n: 0,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                },
                TxIn {
                    txhash: [0x22; 32],
                    n: 1,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                },
                TxIn {
                    txhash: [0x33; 32],
                    n: 0,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                },
            ],
            vout: vec![TxOut {
                amount: 10_000,
                script: fixture_spk(5, AddrType::Native),
            }],
            locktime: 0,
        }
    }

    /// BIP-125 RBF sequence, same constant `build_vin` uses.
    const SEQUENCE_RBF: u32 = crate::fwd::SEQUENCE_RBF_SIGNALED;

    /// A minimal single-input/single-output unsigned tx spending a
    /// P2WPKH-shaped output of `[txid] n=0` — the skeleton for the
    /// per-role error-path tests.
    fn one_input_tx(txid: [u8; 32]) -> Transaction {
        Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: txid,
                n: 0,
                script: vec![],
                sequence: SEQUENCE_RBF,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 10_000,
                script: fixture_spk(5, AddrType::Native),
            }],
            locktime: 0,
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn create_builds_per_form_utxo_fields() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let psbt = PartiallySignedTransaction::create(unsigned.clone(), create_inputs).unwrap();
        assert_eq!(psbt.version, 0);
        assert_eq!(psbt.unsigned_tx, unsigned);
        assert_eq!(psbt.outputs.len(), unsigned.vout.len());
        assert!(psbt.outputs.iter().all(|o| o.unknown.is_empty()));
        assert!(psbt.inputs[0].non_witness_utxo.is_some());
        assert!(psbt.inputs[0].witness_utxo.is_none());
        assert_eq!(psbt.inputs[1].witness_utxo.as_ref().unwrap().amount, 30_000);
        assert!(psbt.inputs[1].non_witness_utxo.is_none());
        assert_eq!(
            psbt.inputs[2].witness_utxo.as_ref().unwrap().script,
            fixture_spk(0, AddrType::Taproot)
        );
        // Creator output is canonical and re-parses.
        assert_eq!(
            PartiallySignedTransaction::parse(&psbt.serialize()).unwrap(),
            psbt
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn create_rejects_inconsistent_requests() {
        let unsigned = kat_unsigned_tx();
        let (_, mut create_inputs) = kat_utxos();
        // Input count mismatch.
        create_inputs.pop();
        assert_eq!(
            PartiallySignedTransaction::create(unsigned.clone(), create_inputs),
            Err(PsbtError::MapCountMismatch)
        );
        // Unsigned tx with a filled scriptSig.
        let (_, create_inputs) = kat_utxos();
        let mut with_script = kat_unsigned_tx();
        with_script.vin[0].script = vec![0x51];
        assert_eq!(
            PartiallySignedTransaction::create(with_script, create_inputs.clone()),
            Err(PsbtError::InvalidUnsignedTx)
        );
        // Unsigned tx with witness data.
        let mut with_witness = kat_unsigned_tx();
        with_witness.vin[1].witness = vec![vec![1]];
        assert_eq!(
            PartiallySignedTransaction::create(with_witness, create_inputs.clone()),
            Err(PsbtError::InvalidUnsignedTx)
        );
        // No outputs.
        let mut no_vout = kat_unsigned_tx();
        no_vout.vout.clear();
        assert_eq!(
            PartiallySignedTransaction::create(no_vout, create_inputs),
            Err(PsbtError::InvalidUnsignedTx)
        );
        // Legacy input without prev_tx (single-input tx).
        let unsigned = one_input_tx([1; 32]);
        let inputs = vec![CreateInput {
            amount: 60_000,
            script_pubkey: fixture_spk(0, AddrType::Legacy),
            prev_tx: None,
            redeem_script: None,
            witness_script: None,
            tap_leaf_script: None,
        }];
        assert_eq!(
            PartiallySignedTransaction::create(unsigned, inputs),
            Err(PsbtError::IncompleteInput(0))
        );
        // prev_tx whose txid does not match the outpoint.
        let unsigned = one_input_tx([1; 32]);
        let mut prev = kat_prev_tx();
        prev.vout[0].amount = 1;
        let inputs = vec![CreateInput {
            amount: 60_000,
            script_pubkey: fixture_spk(0, AddrType::Legacy),
            prev_tx: Some(prev),
            redeem_script: None,
            witness_script: None,
            tap_leaf_script: None,
        }];
        assert_eq!(
            PartiallySignedTransaction::create(unsigned, inputs),
            Err(PsbtError::UtxoMismatch)
        );
    }

    // --- sign_input -----------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_input_skips_foreign_and_dataless_inputs() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        // Foreign key (nonce 9 never matches).
        let foreign = fixture_key(9);
        assert!(!psbt.sign_input(1, &foreign).unwrap());
        assert!(psbt.inputs[1].partial_sigs.is_empty());
        // Input without UTXO data.
        let ours = fixture_key(0);
        let mut bare = PartiallySignedTransaction::create(
            one_input_tx([0x22; 32]),
            vec![CreateInput {
                amount: 30_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        bare.inputs[0].witness_utxo = None;
        assert!(!bare.sign_input(0, &ours).unwrap());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_input_rejects_script_forms_needing_redeem_or_witness_scripts() {
        // P2SH-shaped UTXO.
        let key = fixture_key(0);
        let p2sh = crate::script::make_p2sh_lock_script(&[0xab; 20]);
        let mut psbt = PartiallySignedTransaction::create(
            Transaction {
                version: 2,
                vin: vec![TxIn {
                    txhash: [1; 32],
                    n: 0,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                }],
                vout: vec![TxOut {
                    amount: 1000,
                    script: vec![0x51],
                }],
                locktime: 0,
            },
            vec![CreateInput {
                amount: 1000,
                script_pubkey: p2sh,
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert_eq!(
            psbt.sign_input(0, &key),
            Err(PsbtError::UnsupportedInputScript)
        );
        // P2WSH-shaped UTXO.
        let p2wsh_spk = {
            let mut s = vec![0x00, 0x20];
            s.extend_from_slice(&[0xcd; 32]);
            s
        };
        let mut psbt = PartiallySignedTransaction::create(
            Transaction {
                version: 2,
                vin: vec![TxIn {
                    txhash: [1; 32],
                    n: 0,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                }],
                vout: vec![TxOut {
                    amount: 1000,
                    script: vec![0x51],
                }],
                locktime: 0,
            },
            vec![CreateInput {
                amount: 1000,
                script_pubkey: p2wsh_spk,
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert_eq!(
            psbt.sign_input(0, &key),
            Err(PsbtError::UnsupportedInputScript)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_input_rejects_mismatched_and_accepts_pinned_sighash() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        // A foreign SIGHASH_TYPE on the P2WPKH input (pinned: 0x01).
        psbt.inputs[1].sighash_type = Some(0x0000_0080 | 1);
        let key = fixture_key(0);
        assert_eq!(
            psbt.sign_input(1, &key),
            Err(PsbtError::UnsupportedSighashType(0x0000_0081))
        );
        // The pinned value is accepted and the signature carries the
        // SIGHASH_ALL suffix.
        psbt.inputs[1].sighash_type = Some(PSBT_SIGHASH_ALL);
        assert!(psbt.sign_input(1, &key).unwrap());
        let sig = &psbt.inputs[1].partial_sigs[0].1;
        assert_eq!(*sig.last().unwrap(), 0x01);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_input_is_idempotent_and_sorted() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        let key = fixture_key(0);
        assert!(psbt.sign_input(1, &key).unwrap());
        let before = psbt.inputs[1].partial_sigs.clone();
        // Second attempt: Ok(true), no duplicate entry.
        assert!(psbt.sign_input(1, &key).unwrap());
        assert_eq!(psbt.inputs[1].partial_sigs, before);
        // Sign a second, pubkey-larger key into the same input... the
        // input only commits to one key; use a multisig-shaped pair set
        // to exercise sorted insertion instead: add a synthetic smaller
        // pubkey entry and re-sign — order must stay pubkey-sorted.
        psbt.inputs[1].partial_sigs.clear();
        insert_partial_sig(&mut psbt.inputs[1], PubKey(vec![0x03; 33]), vec![9]);
        insert_partial_sig(&mut psbt.inputs[1], PubKey(vec![0x02; 33]), vec![8]);
        assert_eq!(
            psbt.inputs[1]
                .partial_sigs
                .iter()
                .map(|(k, _)| k.0[0])
                .collect::<Vec<_>>(),
            vec![0x02, 0x03]
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_input_checks_non_witness_utxo_txid() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        // Tamper with the stored NON_WITNESS_UTXO after creation (the
        // coordinator's prev tx does not hash to the outpoint's txid):
        // the signer must refuse.
        psbt.inputs[0].non_witness_utxo.as_mut().unwrap().locktime = 999;
        let key = fixture_key(0);
        assert_eq!(psbt.sign_input(0, &key), Err(PsbtError::UtxoMismatch));
        // The check also runs when the input additionally carries a
        // witness_utxo (the prev tx is verified either way).
        psbt.inputs[0].non_witness_utxo.as_mut().unwrap().locktime = 0;
        assert!(psbt.sign_input(0, &key).unwrap());
        psbt.inputs[0].non_witness_utxo.as_mut().unwrap().locktime = 999;
        assert_eq!(psbt.sign_input(0, &key), Err(PsbtError::UtxoMismatch));
    }

    // --- finalize + extract ----------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_finalize_extract_full_pipeline_all_forms() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        let key = fixture_key(0); // variant A: same key everywhere
        for i in 0..psbt.inputs.len() {
            assert!(psbt.sign_input(i, &key).unwrap(), "input {i} must sign");
        }
        psbt.finalize();
        // Intermediates are gone; finals exist; UTXOs and unknowns stay.
        for input in &psbt.inputs {
            assert!(input.partial_sigs.is_empty());
            assert!(input.sighash_type.is_none());
            assert!(input.redeem_script.is_none());
            assert!(input.witness_script.is_none());
            // Exactly one final field per form is asserted per-input
            // below; the loop only pins the intermediates-away rule.
        }
        assert!(psbt.inputs[0].non_witness_utxo.is_some());
        assert!(psbt.inputs[1].witness_utxo.is_some());

        let tx = psbt.extract_transaction().unwrap();
        // Legacy: scriptSig = push(sig ‖ 0x01) ‖ push(pubkey) — the
        // pushed on-chain layout (spec «Finalizer», yubtc-python
        // direct-path `CScript`). The first byte is the signature
        // item's push prefix, NOT the DER SEQUENCE tag (0x30): a raw
        // concatenation would be read as opcodes and never validate.
        let pubkey = privkey_to_pubkey(&key);
        let script = &tx.vin[0].script;
        let sig_item_len = script[0] as usize;
        assert!(
            (71..=73).contains(&sig_item_len),
            "push prefix must announce a 71-73 byte DER sig ‖ sighash, got {sig_item_len}"
        );
        assert_eq!(script[1], 0x30); // DER SEQUENCE inside the push
        assert_eq!(*script[1 + sig_item_len - 1..].first().unwrap(), 0x01);
        assert_eq!(script[1 + sig_item_len], 33, "pubkey push prefix");
        assert_eq!(&script[2 + sig_item_len..], &pubkey[..]);
        assert_eq!(script.len(), 1 + sig_item_len + 1 + 33);
        assert!(tx.vin[0].witness.is_empty());
        assert_eq!(tx.vin[1].witness.len(), 2);
        assert_eq!(tx.vin[1].witness[1].len(), 33);
        assert!(tx.vin[1].script.is_empty());
        assert_eq!(tx.vin[2].witness.len(), 1);
        assert_eq!(tx.vin[2].witness[0].len(), 64);
        assert!(tx.has_witness());
        // finalize is idempotent; extraction is stable.
        psbt.finalize();
        assert_eq!(psbt.extract_transaction().unwrap(), tx);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_before_finalize_is_refused_without_changes() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        let before = psbt.serialize();
        assert_eq!(psbt.extract_transaction(), Err(PsbtError::NotFinalized));
        assert_eq!(psbt.serialize(), before);
        // A P2PKH input finalized only with a witness stack also
        // refuses (the form dictates which final field is required).
        // Hand-built (create() would demand a prev tx for a legacy
        // input; the extractor rule is independent of that).
        let psbt = PartiallySignedTransaction {
            version: 0,
            unsigned_tx: one_input_tx([1; 32]),
            inputs: vec![PsbtInput {
                witness_utxo: Some(TxOut {
                    amount: 1000,
                    script: fixture_spk(0, AddrType::Legacy),
                }),
                final_scriptwitness: Some(encode_witness_stack(&[vec![1]])),
                ..PsbtInput::default()
            }],
            outputs: vec![PsbtOutput::default()],
            unknown_global: Vec::new(),
        };
        assert_eq!(psbt.extract_transaction(), Err(PsbtError::NotFinalized));
        // Malformed final witness stack → IncompleteInput.
        let mut psbt = PartiallySignedTransaction::create(
            one_input_tx([1; 32]),
            vec![CreateInput {
                amount: 1000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        psbt.inputs[0].final_scriptwitness = Some(vec![0xff, 0xff]);
        assert_eq!(
            psbt.extract_transaction(),
            Err(PsbtError::IncompleteInput(0))
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalize_input_reports_incomplete_inputs() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        // Out-of-range index.
        assert_eq!(psbt.finalize_input(99), Err(PsbtError::IncompleteInput(99)));
        // No partial signature yet.
        assert_eq!(psbt.finalize_input(1), Err(PsbtError::IncompleteInput(1)));
        // P2TR input without a matching 64-byte signature.
        let key = fixture_key(0);
        assert!(psbt.sign_input(2, &key).unwrap());
        psbt.inputs[2].partial_sigs[0].1 = vec![1; 32]; // not 64 bytes
        assert_eq!(psbt.finalize_input(2), Err(PsbtError::IncompleteInput(2)));
        // A signature with a foreign sighash byte blocks the input.
        let mut psbt2 = PartiallySignedTransaction::create(
            Transaction {
                version: 2,
                vin: vec![TxIn {
                    txhash: [1; 32],
                    n: 0,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                }],
                vout: vec![TxOut {
                    amount: 1000,
                    script: vec![0x51],
                }],
                locktime: 0,
            },
            vec![CreateInput {
                amount: 1000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert!(psbt2.sign_input(0, &key).unwrap());
        let last = psbt2.inputs[0].partial_sigs[0].1.len() - 1;
        psbt2.inputs[0].partial_sigs[0].1[last] = 0x02;
        assert_eq!(psbt2.finalize_input(0), Err(PsbtError::IncompleteInput(0)));
        // Unknown script form (P2SH) is incomplete by definition.
        let p2sh = crate::script::make_p2sh_lock_script(&[0xab; 20]);
        let mut psbt3 = PartiallySignedTransaction::create(
            Transaction {
                version: 2,
                vin: vec![TxIn {
                    txhash: [1; 32],
                    n: 0,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                }],
                vout: vec![TxOut {
                    amount: 1000,
                    script: vec![0x51],
                }],
                locktime: 0,
            },
            vec![CreateInput {
                amount: 1000,
                script_pubkey: p2sh,
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert_eq!(psbt3.finalize_input(0), Err(PsbtError::IncompleteInput(0)));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalize_skips_incomplete_inputs_silently() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        // Only input 1 is signed; finalize() finalizes it and leaves
        // the others untouched without erroring.
        let key = fixture_key(0);
        assert!(psbt.sign_input(1, &key).unwrap());
        psbt.finalize();
        assert!(psbt.inputs[1].final_scriptwitness.is_some());
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[0].final_scriptsig.is_none());
    }

    // --- Signer walk (ОВ-9) ----------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn walk_signs_inputs_at_several_nonces_and_reports_rest() {
        let mut unsigned = kat_unsigned_tx();
        // Move the taproot input to a UTXO keyed at nonce 7.
        unsigned.vin[2].txhash = [0x44; 32];
        let create_inputs = vec![
            CreateInput {
                amount: 60_000,
                script_pubkey: fixture_spk(0, AddrType::Legacy),
                prev_tx: Some(kat_prev_tx()),
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
            CreateInput {
                amount: 30_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
            CreateInput {
                amount: 20_000,
                script_pubkey: fixture_spk(7, AddrType::Taproot),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
        ];
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        let unsigned_list =
            sign_psbt_with(&TSeed::new(SEED), &TPassphrase::EMPTY, kdf(), &mut psbt).unwrap();
        assert!(unsigned_list.is_empty(), "all three inputs must sign");
        assert_eq!(psbt.inputs[2].partial_sigs[0].1.len(), 64);
    }

    #[ntest_timeout::timeout(120_000)]
    #[test]
    fn walk_leaves_foreign_and_over_bound_inputs_unsigned() {
        // An input keyed at a nonce beyond the walk bound: derive its
        // script at nonce PSBT_SIGN_MAX_NONCE and confirm the walk
        // leaves it unsigned.
        let over_bound = derive_script(
            &TSeed::new(SEED),
            TNonce::new(PSBT_SIGN_MAX_NONCE),
            &TPassphrase::EMPTY,
            kdf(),
            AddrType::Native,
        )
        .unwrap();
        let unsigned = Transaction {
            version: 2,
            vin: vec![
                TxIn {
                    txhash: [0x22; 32],
                    n: 1,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                },
                TxIn {
                    txhash: [0x55; 32],
                    n: 0,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                },
            ],
            vout: vec![TxOut {
                amount: 10_000,
                script: fixture_spk(5, AddrType::Native),
            }],
            locktime: 0,
        };
        let create_inputs = vec![
            CreateInput {
                amount: 30_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
            CreateInput {
                amount: 20_000,
                script_pubkey: over_bound,
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
        ];
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        let unsigned_list =
            sign_psbt_with(&TSeed::new(SEED), &TPassphrase::EMPTY, kdf(), &mut psbt).unwrap();
        assert_eq!(unsigned_list, vec![1]);
        assert!(!psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[1].partial_sigs.is_empty());
    }

    #[ntest_timeout::timeout(120_000)]
    #[test]
    fn walk_swallows_sighash_skips_but_propagates_utxo_mismatch() {
        // Sighash mismatch → input left unsigned, no error (ОВ-8).
        let unsigned = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x22; 32],
                n: 1,
                script: vec![],
                sequence: SEQUENCE_RBF,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 10_000,
                script: fixture_spk(5, AddrType::Native),
            }],
            locktime: 0,
        };
        let mut psbt = PartiallySignedTransaction::create(
            unsigned,
            vec![CreateInput {
                amount: 30_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        psbt.inputs[0].sighash_type = Some(2);
        let unsigned_list =
            sign_psbt_with(&TSeed::new(SEED), &TPassphrase::EMPTY, kdf(), &mut psbt).unwrap();
        assert_eq!(unsigned_list, vec![0]);

        // UtxoMismatch → the walk aborts with the error.
        let unsigned = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: kat_prev_tx().id(),
                n: 0,
                script: vec![],
                sequence: SEQUENCE_RBF,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 10_000,
                script: fixture_spk(5, AddrType::Native),
            }],
            locktime: 0,
        };
        let mut psbt = PartiallySignedTransaction::create(
            unsigned,
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: fixture_spk(0, AddrType::Legacy),
                prev_tx: Some(kat_prev_tx()),
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        // Tamper the stored prev tx post-create (coordinator-supplied
        // data that does not hash to the outpoint).
        psbt.inputs[0].non_witness_utxo.as_mut().unwrap().locktime = 7;
        assert_eq!(
            sign_psbt_with(&TSeed::new(SEED), &TPassphrase::EMPTY, kdf(), &mut psbt),
            Err(PsbtError::UtxoMismatch)
        );
    }

    /// THE self-parity KAT: create → sign → finalize → extract produces
    /// the byte-identical wire transaction of the direct path
    /// (`build_vin` + `make_vout` + `sign_segwit`) for the same inputs.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn pipeline_wire_equals_direct_path_wire() {
        let seed = TSeed::new(SEED);
        let pass = TPassphrase::EMPTY;
        let key_legacy =
            TPrivKey::with_addr_type(&seed, TNonce::new(0), &pass, kdf(), AddrType::Legacy)
                .unwrap();
        let key_native =
            TPrivKey::with_addr_type(&seed, TNonce::new(0), &pass, kdf(), AddrType::Native)
                .unwrap();
        let key_taproot =
            TPrivKey::with_addr_type(&seed, TNonce::new(0), &pass, kdf(), AddrType::Taproot)
                .unwrap();
        let prev = kat_prev_tx();

        let sources = vec![
            Source {
                privkey: key_legacy.clone(),
                unspent: vec![crate::wallet::Utxo {
                    txid: prev.id(),
                    vout: 0,
                    amount: 60_000,
                    script_pubkey: fixture_spk(0, AddrType::Legacy),
                    confirmations: 6,
                }],
            },
            Source {
                privkey: key_native.clone(),
                unspent: vec![crate::wallet::Utxo {
                    txid: [0x22; 32],
                    vout: 1,
                    amount: 30_000,
                    script_pubkey: fixture_spk(0, AddrType::Native),
                    confirmations: 6,
                }],
            },
            Source {
                privkey: key_taproot.clone(),
                unspent: vec![crate::wallet::Utxo {
                    txid: [0x33; 32],
                    vout: 0,
                    amount: 20_000,
                    script_pubkey: fixture_spk(0, AddrType::Taproot),
                    confirmations: 6,
                }],
            },
        ];

        // --- direct path (the `send` flow minus the fee loop) ---------
        let (vin, in_amount, signers, spend) = build_vin(&sources).unwrap();
        let dst = key_native.get_address();
        let cashback = key_legacy.get_address();
        let vout = make_vout(
            &cashback,
            &dst,
            TSatoshi::new(in_amount),
            Some(TSatoshi::new(10_000)),
            TSatoshi::new(500),
        )
        .unwrap()
        .vout;
        let unsigned = Transaction {
            version: 2,
            vin,
            vout,
            locktime: 0,
        };
        let direct = unsigned
            .sign_segwit(&signers, Some(&spend))
            .expect("direct path signs");

        // --- PSBT path -------------------------------------------------
        let mut blanked = direct.clone();
        for v in blanked.vin.iter_mut() {
            v.script = Vec::new();
            v.witness = Vec::new();
        }
        let create_inputs = vec![
            CreateInput {
                amount: 60_000,
                script_pubkey: fixture_spk(0, AddrType::Legacy),
                prev_tx: Some(prev),
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
            CreateInput {
                amount: 30_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
            CreateInput {
                amount: 20_000,
                script_pubkey: fixture_spk(0, AddrType::Taproot),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            },
        ];
        let mut psbt = PartiallySignedTransaction::create(blanked, create_inputs).unwrap();
        let unsigned_inputs =
            sign_psbt_with(&seed, &pass, kdf(), &mut psbt).expect("psbt path signs");
        assert!(unsigned_inputs.is_empty());
        psbt.finalize();
        let extracted = psbt.extract_transaction().unwrap();

        // The whole point: bit-for-bit parity with the direct path.
        assert_eq!(extracted.serialize_wire(), direct.serialize_wire());
        assert_eq!(extracted.id(), direct.id());
        assert_eq!(extracted.wtxid(), direct.wtxid());
    }

    #[tokio::test]
    async fn wallet_sign_psbt_delegates_to_the_walk() {
        let seed = TSeed::new(SEED);
        let wallet = Wallet::from_privkeys(
            seed.clone(),
            TPassphrase::EMPTY,
            kdf(),
            AddrType::Native,
            std::sync::Arc::new(WalkTestBackend::default()),
            vec![],
        );
        let unsigned = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x22; 32],
                n: 1,
                script: vec![],
                sequence: SEQUENCE_RBF,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 10_000,
                script: fixture_spk(5, AddrType::Native),
            }],
            locktime: 0,
        };
        let mut psbt = PartiallySignedTransaction::create(
            unsigned,
            vec![CreateInput {
                amount: 30_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        let unsigned_list = wallet.sign_psbt(&mut psbt).unwrap();
        assert!(unsigned_list.is_empty());
        assert!(!psbt.inputs[0].partial_sigs.is_empty());
    }

    // --- combine ---------------------------------------------------------

    fn signed_pair_of_psbt() -> (PartiallySignedTransaction, SigningKey, SigningKey) {
        // A single P2WPKH input; signer A is the real owner, signer B a
        // synthetic second key (disjoint signers for commutativity).
        let unsigned = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x22; 32],
                n: 1,
                script: vec![],
                sequence: SEQUENCE_RBF,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 10_000,
                script: fixture_spk(5, AddrType::Native),
            }],
            locktime: 0,
        };
        let psbt = PartiallySignedTransaction::create(
            unsigned,
            vec![CreateInput {
                amount: 30_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        let b = SigningKey::from_bytes((&[0x42u8; 32]).into()).expect("valid scalar");
        (psbt, fixture_key(0), b)
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn combine_is_idempotent() {
        let (psbt, key, _) = signed_pair_of_psbt();
        let mut signed = psbt.clone();
        assert!(signed.sign_input(0, &key).unwrap());
        let combined = signed.combine(&signed).unwrap();
        assert_eq!(combined.serialize(), signed.serialize());
        assert_eq!(combined, signed);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn combine_refuses_foreign_transactions_and_conflicts() {
        let (psbt, key, _) = signed_pair_of_psbt();
        // Different unsigned tx.
        let mut other_unsigned = kat_unsigned_tx();
        other_unsigned.vout[0].amount = 999;
        let other = PartiallySignedTransaction::create(
            other_unsigned,
            vec![
                CreateInput {
                    amount: 60_000,
                    script_pubkey: fixture_spk(0, AddrType::Legacy),
                    prev_tx: Some(kat_prev_tx()),
                    redeem_script: None,
                    witness_script: None,
                    tap_leaf_script: None,
                },
                CreateInput {
                    amount: 30_000,
                    script_pubkey: fixture_spk(0, AddrType::Native),
                    prev_tx: None,
                    redeem_script: None,
                    witness_script: None,
                    tap_leaf_script: None,
                },
                CreateInput {
                    amount: 20_000,
                    script_pubkey: fixture_spk(0, AddrType::Taproot),
                    prev_tx: None,
                    redeem_script: None,
                    witness_script: None,
                    tap_leaf_script: None,
                },
            ],
        )
        .unwrap();
        assert_eq!(psbt.combine(&other), Err(PsbtError::ForeignTransaction));
        // Same key, different signature value.
        let mut a = psbt.clone();
        let mut b = psbt.clone();
        assert!(a.sign_input(0, &key).unwrap());
        assert!(b.sign_input(0, &key).unwrap());
        b.inputs[0].partial_sigs[0].1[10] ^= 0xff;
        assert_eq!(a.combine(&b), Err(PsbtError::ConflictingField));
        // Same for an unknown global pair.
        let mut c = psbt.clone();
        let mut d = psbt.clone();
        c.unknown_global.push(UnknownKv {
            key: vec![0x51, 1],
            value: vec![1],
        });
        d.unknown_global.push(UnknownKv {
            key: vec![0x51, 1],
            value: vec![2],
        });
        assert_eq!(c.combine(&d), Err(PsbtError::ConflictingField));
        // And a typed per-input field.
        let mut e = psbt.clone();
        let mut f = psbt.clone();
        e.inputs[0].redeem_script = Some(vec![1]);
        f.inputs[0].redeem_script = Some(vec![2]);
        assert_eq!(e.combine(&f), Err(PsbtError::ConflictingField));
        // And the witness_utxo.
        let mut g = psbt.clone();
        g.inputs[0].witness_utxo.as_mut().unwrap().amount = 1;
        assert_eq!(a.combine(&g), Err(PsbtError::ConflictingField));
        // And a final field.
        let mut h = psbt.clone();
        let mut k = psbt.clone();
        h.inputs[0].final_scriptsig = Some(vec![1]);
        k.inputs[0].final_scriptsig = Some(vec![2]);
        assert_eq!(h.combine(&k), Err(PsbtError::ConflictingField));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn combine_merges_disjoint_signers_and_unknowns() {
        let (psbt, key_a, _key_b) = signed_pair_of_psbt();
        let mut a = psbt.clone();
        let mut b = psbt.clone();
        assert!(a.sign_input(0, &key_a).unwrap());
        // Signer B cannot sign (foreign key) — emulate a disjoint
        // signer by injecting its synthetic partial sig directly.
        b.inputs[0]
            .partial_sigs
            .push((PubKey(vec![0x02; 33]), vec![0xBB; 64]));
        b.unknown_global.push(UnknownKv {
            key: vec![0x51, 7],
            value: vec![9],
        });
        let ab = a.combine(&b).unwrap();
        let ba = b.combine(&a).unwrap();
        assert_eq!(ab.serialize(), ba.serialize(), "commutativity");
        // Owner sig + synthetic sig + unknown pair, all present once.
        assert_eq!(ab.inputs[0].partial_sigs.len(), 2);
        assert_eq!(ab.unknown_global.len(), 1);
        // combine(p, combine(p, p)) stays stable.
        let aba = a.combine(&ab).unwrap();
        assert_eq!(aba.serialize(), ab.serialize());
    }

    // --- unknown-field passthrough ---------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn unknown_pairs_survive_the_full_pipeline_byte_for_byte() {
        let unknown_global = UnknownKv {
            key: vec![0x51, 0xaa, 0xbb],
            value: vec![1, 2, 3],
        };
        let unknown_in = UnknownKv {
            key: vec![0x52, 0xcc],
            value: vec![4, 5],
        };
        let unknown_out = UnknownKv {
            key: vec![0x53, 0xdd, 0xee],
            value: vec![6],
        };

        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        psbt.unknown_global.push(unknown_global.clone());
        psbt.inputs[1].unknown.push(unknown_in.clone());
        psbt.outputs[0].unknown.push(unknown_out.clone());

        let key = fixture_key(0);
        for i in 0..psbt.inputs.len() {
            assert!(psbt.sign_input(i, &key).unwrap());
        }
        let combined = psbt.combine(&psbt).unwrap();
        let mut combined = combined;
        combined.finalize();
        let tx = combined.extract_transaction().unwrap();

        assert_eq!(combined.unknown_global, vec![unknown_global]);
        assert_eq!(combined.inputs[1].unknown, vec![unknown_in]);
        assert_eq!(combined.outputs[0].unknown, vec![unknown_out]);
        // The wire transaction is exactly the clean pipeline's wire:
        // opaque pairs never leak on-chain.
        let clean_unsigned = kat_unsigned_tx();
        let (_, clean_inputs) = kat_utxos();
        let mut clean = PartiallySignedTransaction::create(clean_unsigned, clean_inputs).unwrap();
        for i in 0..clean.inputs.len() {
            assert!(clean.sign_input(i, &key).unwrap());
        }
        clean.finalize();
        assert_eq!(
            tx.serialize_wire(),
            clean.extract_transaction().unwrap().serialize_wire()
        );
        // And the round-trip keeps everything byte-identical.
        let re = PartiallySignedTransaction::parse(&combined.serialize()).unwrap();
        assert_eq!(re, combined);
    }

    // --- summary (decode) -------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn summary_reports_counts_fees_and_states() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        let key = fixture_key(0);
        assert!(psbt.sign_input(1, &key).unwrap());

        let s = psbt.summary();
        assert_eq!(s.version, 0);
        assert_eq!(s.txid_hex, hex::encode(psbt.unsigned_tx.id()));
        assert_eq!(s.inputs.len(), 3);
        assert!(s.inputs.iter().all(|i| i.has_utxo));
        assert_eq!(s.inputs[1].n_partial_sigs, 1);
        assert_eq!(s.inputs[0].n_partial_sigs, 0);
        assert!(!s.inputs[1].finalized);
        assert_eq!(s.fee_sat, Some(110_000 - 10_000));
        assert_eq!(s.outputs.len(), 1);
        assert_eq!(s.outputs[0].amount_sat, 10_000);
        assert_eq!(
            s.outputs[0].script_pubkey_hex,
            hex::encode(fixture_spk(5, AddrType::Native))
        );

        // Missing UTXO data → fee unknown.
        psbt.inputs[2].witness_utxo = None;
        assert_eq!(psbt.summary().fee_sat, None);
        // After finalize the finalized flag flips.
        psbt.finalize();
        let s = psbt.summary();
        assert!(s.inputs[1].finalized);
        assert!(!s.inputs[0].finalized);
        // Outputs under inputs is a nonsense fee → None.
        let mut psbt2 = PartiallySignedTransaction::create(kat_unsigned_tx(), {
            let (_, create_inputs) = kat_utxos();
            create_inputs
        })
        .unwrap();
        psbt2.unsigned_tx.vout[0].amount = u64::MAX;
        assert_eq!(psbt2.summary().fee_sat, None);
    }

    // --- misc API surface ---------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn from_base64_round_trips_the_transport_form() {
        let unsigned = kat_unsigned_tx();
        let (_, create_inputs) = kat_utxos();
        let psbt = PartiallySignedTransaction::create(unsigned, create_inputs).unwrap();
        let b64 = psbt.to_base64();
        let back = PartiallySignedTransaction::from_base64(&b64).unwrap();
        assert_eq!(back, psbt);
        // Transport errors surface as InvalidFieldValue.
        assert_eq!(
            PartiallySignedTransaction::from_base64("not-base64!"),
            Err(PsbtError::InvalidFieldValue)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn every_error_variant_carries_a_message() {
        let variants = vec![
            PsbtError::InvalidMagic,
            PsbtError::Truncated,
            PsbtError::NonMinimalCompactSize,
            PsbtError::InvalidKeyLength(0x02),
            PsbtError::DuplicateKey,
            PsbtError::UnsupportedVersion(2),
            PsbtError::MissingUnsignedTx,
            PsbtError::InvalidUnsignedTx,
            PsbtError::MapCountMismatch,
            PsbtError::InvalidFieldValue,
            PsbtError::UnsupportedInputScript,
            PsbtError::UtxoMismatch,
            PsbtError::UnsupportedSighashType(0x81),
            PsbtError::ConflictingField,
            PsbtError::ForeignTransaction,
            PsbtError::IncompleteInput(3),
            PsbtError::NotFinalized,
            PsbtError::TooLarge,
        ];
        for e in variants {
            assert!(!e.to_string().is_empty());
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sighash_pins_match_the_phase13_constants() {
        assert_eq!(PSBT_SIGHASH_ALL, 1);
        assert_eq!(PSBT_SIGHASH_DEFAULT, 0);
        assert_eq!(Form::Legacy([0; 20]).pinned_sighash(), PSBT_SIGHASH_ALL);
        assert_eq!(Form::P2wpkh([0; 20]).pinned_sighash(), PSBT_SIGHASH_ALL);
        assert_eq!(Form::P2tr([0; 32]).pinned_sighash(), PSBT_SIGHASH_DEFAULT);
    }

    // --- property-based invariants (≥ 1000 cases per invariant) ---------

    /// Deterministic synthetic signing key from a u64 seed.
    ///
    /// The seed is hashed so distinct seeds map to distinct scalars;
    /// the hash output lands above the secp256k1 order with
    /// probability ~2⁻¹²⁸ — the same documented-invariant `expect`
    /// precedent as the TapTweak paths (kdf.rs precedent).
    #[inline(never)]
    fn synth_key(seed: u64) -> SigningKey {
        let bytes = Sha256::digest(seed.to_le_bytes());
        SigningKey::from_bytes(&bytes)
            .expect("hashed scalar is a valid secp256k1 scalar (p ≈ 2⁻¹²⁸)")
    }

    /// An opaque-pair strategy: unique keys (the index byte is
    /// deduplicated, so two pairs never share a full key), arbitrary
    /// values.
    fn unknown_pairs() -> impl Strategy<Value = Vec<UnknownKv>> {
        proptest::collection::vec(
            (0u8..8, proptest::collection::vec(any::<u8>(), 0..24)),
            0..4,
        )
        .prop_map(|entries| {
            let mut seen = std::collections::BTreeSet::new();
            entries
                .into_iter()
                .filter(|(idx, _)| seen.insert(*idx))
                .map(|(idx, value)| UnknownKv {
                    key: vec![0x51, idx],
                    value,
                })
                .collect()
        })
    }

    fn unsigned_fixture() -> Transaction {
        Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x22; 32],
                n: 1,
                script: vec![],
                sequence: SEQUENCE_RBF,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 10_000,
                script: fixture_spk(5, AddrType::Native),
            }],
            locktime: 0,
        }
    }

    fn fixture_create_inputs() -> Vec<CreateInput> {
        vec![CreateInput {
            amount: 30_000,
            script_pubkey: fixture_spk(0, AddrType::Native),
            prev_tx: None,
            redeem_script: None,
            witness_script: None,
            tap_leaf_script: None,
        }]
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(1000))]

        /// Unknown-field passthrough: arbitrary opaque pairs injected
        /// into all three maps survive create → sign → combine →
        /// finalize → extract byte-for-byte, and the wire transaction
        /// is untouched by them.
        #[test]
        fn prop_unknown_passthrough_byte_for_byte(
            g in unknown_pairs(),
            i in unknown_pairs(),
            o in unknown_pairs(),
        ) {
            let mut psbt = PartiallySignedTransaction::create(
                unsigned_fixture(),
                fixture_create_inputs(),
            )
            .unwrap();
            psbt.unknown_global = g.clone();
            psbt.inputs[0].unknown = i.clone();
            psbt.outputs[0].unknown = o.clone();

            let key = fixture_key(0);
            prop_assert!(psbt.sign_input(0, &key).unwrap());
            let combined = psbt.combine(&psbt).unwrap();
            let mut finalized = combined;
            finalized.finalize();
            let tx = finalized.extract_transaction().unwrap();

            prop_assert_eq!(finalized.unknown_global, g);
            prop_assert_eq!(&finalized.inputs[0].unknown, &i);
            prop_assert_eq!(&finalized.outputs[0].unknown, &o);

            let mut clean = PartiallySignedTransaction::create(
                unsigned_fixture(),
                fixture_create_inputs(),
            )
            .unwrap();
            prop_assert!(clean.sign_input(0, &key).unwrap());
            clean.finalize();
            prop_assert_eq!(
                tx.serialize_wire(),
                clean.extract_transaction().unwrap().serialize_wire()
            );
        }

        /// `combine(p, p) == p` — idempotence on arbitrary injected
        /// states.
        #[test]
        fn prop_combine_idempotent(
            g in unknown_pairs(),
            i in unknown_pairs(),
            o in unknown_pairs(),
            sighash in proptest::option::of(0u32..),
        ) {
            let mut psbt = PartiallySignedTransaction::create(
                unsigned_fixture(),
                fixture_create_inputs(),
            )
            .unwrap();
            psbt.unknown_global = g;
            psbt.inputs[0].unknown = i;
            psbt.outputs[0].unknown = o;
            psbt.inputs[0].sighash_type = sighash;
            let combined = psbt.combine(&psbt).unwrap();
            prop_assert_eq!(combined.serialize(), psbt.serialize());
        }

        /// `combine(sign_A(p), sign_B(p)) == combine(sign_B(p),
        /// sign_A(p))` for disjoint synthetic signers (library-level,
        /// no wallet — the Phase 15 multi-sig groundwork). The synthetic
        /// partial signatures are injected directly: `sign_input` only
        /// signs script-committed keys, while `combine` merges without
        /// interpreting signature values, exactly as BIP-174 requires.
        #[test]
        fn prop_combine_commutative(seed_a in any::<u64>(), seed_b in any::<u64>()) {
            prop_assume!(seed_a != seed_b);
            let signed_by = |seed: u64| {
                let mut psbt = PartiallySignedTransaction::create(
                    unsigned_fixture(),
                    fixture_create_inputs(),
                )
                .unwrap();
                let key = synth_key(seed);
                let pubkey = privkey_to_pubkey(&key);
                // Deterministic per-key surrogate signature (DER +
                // SIGHASH_ALL suffix, the ECDSA convention).
                let sig: k256::ecdsa::Signature = key.sign(&[7u8; 32]);
                let mut sig = sig.to_der().as_bytes().to_vec();
                sig.push(0x01);
                psbt.inputs[0]
                    .partial_sigs
                    .push((PubKey(pubkey.to_vec()), sig));
                psbt
            };
            let a = signed_by(seed_a);
            let b = signed_by(seed_b);
            let ab = a.combine(&b).unwrap();
            let ba = b.combine(&a).unwrap();
            prop_assert_eq!(ab.serialize(), ba.serialize());
        }

        /// `serialize(parse(x))` is stable: a second canonization pass
        /// changes nothing.
        #[test]
        fn prop_canonicalization_stable(
            g in unknown_pairs(),
            i in unknown_pairs(),
            o in unknown_pairs(),
        ) {
            let mut psbt = PartiallySignedTransaction::create(
                unsigned_fixture(),
                fixture_create_inputs(),
            )
            .unwrap();
            psbt.unknown_global = g;
            psbt.inputs[0].unknown = i;
            psbt.outputs[0].unknown = o;
            let first = psbt.serialize();
            let reparsed = PartiallySignedTransaction::parse(&first).unwrap();
            prop_assert_eq!(reparsed.serialize(), first);
        }

        /// Parsing arbitrary bytes never panics.
        #[test]
        fn prop_parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = PartiallySignedTransaction::parse(&data);
            let _ = PartiallySignedTransaction::parse(&data[..data.len() / 2]);
        }
    }

    // --- coverage of the remaining parse/sign/finalize/combine arms -----

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_tx_rejects_oversized_counts_and_witness_items() {
        let tx = stub_tx_bytes();
        // vin count far beyond the remaining bytes (0xfd-prefixed).
        let mut bad = Vec::new();
        bad.extend_from_slice(&2i32.to_le_bytes());
        bad.extend_from_slice(&[0xfd, 0xff, 0xff]);
        assert_eq!(
            PartiallySignedTransaction::parse(&assemble(
                &[kv(&[T_ZERO], &bad)],
                &[Vec::new()],
                &[Vec::new()]
            )),
            Err(PsbtError::InvalidUnsignedTx)
        );
        // vout count beyond the remaining bytes.
        let mut bad = Vec::new();
        bad.extend_from_slice(&2i32.to_le_bytes());
        bad.push(1); // one vin
        bad.extend_from_slice(&[0x11u8; 32]);
        bad.extend_from_slice(&1u32.to_le_bytes());
        bad.push(0); // empty scriptSig
        bad.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        bad.extend_from_slice(&[0xfd, 0xff, 0xff]); // vout count 65535
        assert_eq!(
            PartiallySignedTransaction::parse(&assemble(
                &[kv(&[T_ZERO], &bad)],
                &[Vec::new()],
                &[Vec::new()]
            )),
            Err(PsbtError::InvalidUnsignedTx)
        );
        // Witness item count beyond the remaining bytes (a wire-format
        // prev tx in NON_WITNESS_UTXO).
        let mut wire = Vec::new();
        wire.extend_from_slice(&2i32.to_le_bytes());
        wire.push(0x00); // marker
        wire.push(0x01); // flag
        wire.push(1); // one vin
        wire.extend_from_slice(&[0x11u8; 32]);
        wire.extend_from_slice(&1u32.to_le_bytes());
        wire.push(0); // empty scriptSig
        wire.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        wire.push(1); // one vout
        wire.extend_from_slice(&1000u64.to_le_bytes());
        wire.push(0); // empty script
                      // witness section comes before the locktime (BIP-144): a huge
                      // item count truncates before the locktime ever parses.
        wire.extend_from_slice(&[0xfd, 0xff, 0xff]);
        wire.extend_from_slice(&0u32.to_le_bytes()); // locktime
        assert_eq!(
            PartiallySignedTransaction::parse(&assemble(
                &[kv(&[T_ZERO], &tx)],
                &[kv(&[T_ZERO], &wire)],
                &[Vec::new()]
            )),
            Err(PsbtError::InvalidFieldValue)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_read_map_reports_truncation_without_terminator() {
        // A map whose bytes simply end (no terminator): the loop's
        // EOF guard fires.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x70, 0x73, 0x62, 0x74, 0xff]);
        bytes.extend_from_slice(&kv(&[T_ZERO], &stub_tx_bytes()));
        // no terminator — straight to EOF.
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::Truncated)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_accepts_wide_field_type_prefixes_as_opaque() {
        // Field type 300 (`fd 2c 01`, minimally encoded) is outside
        // the BIP-174 registry — carried as an opaque pair in every
        // map.
        let wide_key = [0xfd_u8, 0x2c, 0x01].to_vec();
        let tx = stub_tx_bytes();
        let bytes = assemble(
            &[kv(&[T_ZERO], &tx), kv(&wide_key, &[9, 9])],
            &[kv(&wide_key, &[7])],
            &[kv(&wide_key, &[8])],
        );
        let psbt = PartiallySignedTransaction::parse(&bytes).unwrap();
        assert_eq!(psbt.unknown_global.len(), 1);
        assert_eq!(psbt.unknown_global[0].key, wide_key);
        assert_eq!(psbt.inputs[0].unknown.len(), 1);
        assert_eq!(psbt.outputs[0].unknown.len(), 1);
        // Canonical round trip keeps the wide keys.
        assert_eq!(psbt.serialize(), bytes);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_rejects_version_typed_key_with_keydata() {
        let bytes = assemble(
            &[
                kv(&[T_ZERO], &stub_tx_bytes()),
                kv(&[T_VERSION, 0xaa], &0u32.to_le_bytes()),
            ],
            &[Vec::new()],
            &[Vec::new()],
        );
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::InvalidKeyLength(T_VERSION))
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_reports_missing_input_map() {
        // Two inputs declared, one input map present: the input-map
        // loop's EOF guard fires (distinct from the output-map guard).
        let mut tx = Vec::new();
        tx.extend_from_slice(&2i32.to_le_bytes());
        tx.push(2); // two vins
        for _ in 0..2 {
            tx.extend_from_slice(&[0x11u8; 32]);
            tx.extend_from_slice(&1u32.to_le_bytes());
            tx.push(0);
            tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        }
        tx.push(1); // one vout
        tx.extend_from_slice(&1000u64.to_le_bytes());
        tx.push(1);
        tx.push(0x51);
        tx.extend_from_slice(&0u32.to_le_bytes());
        // One input map, one output map — the second input map is gone.
        let bytes = assemble(&[kv(&[T_ZERO], &tx)], &[Vec::new()], &[Vec::new()]);
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::MapCountMismatch)
        );
        // No bytes at all after the first input map: the input-map
        // loop's own EOF guard fires (not the output-map one).
        let bytes = assemble(&[kv(&[T_ZERO], &tx)], &[Vec::new()], &[]);
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::MapCountMismatch)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_witness_stack_rejects_oversized_count_and_trailing_bytes() {
        let mut psbt = PartiallySignedTransaction::create(
            one_input_tx([1; 32]),
            vec![CreateInput {
                amount: 1000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        // Oversized element count: the truncated-body shape trips the
        // reader first (count prefix 0xff needs 8 more bytes).
        psbt.inputs[0].final_scriptwitness = Some(vec![0xff, 0x01, 0x02]);
        assert_eq!(
            psbt.extract_transaction(),
            Err(PsbtError::IncompleteInput(0))
        );
        // A well-formed count prefix carrying a count above the
        // remaining bytes hits the guard itself.
        psbt.inputs[0].final_scriptwitness = Some(vec![0xfe, 0xff, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            psbt.extract_transaction(),
            Err(PsbtError::IncompleteInput(0))
        );
        // A well-formed stack followed by trailing bytes.
        let mut stack = encode_witness_stack(&[vec![1]]);
        stack.push(0x00); // trailing junk
        psbt.inputs[0].final_scriptwitness = Some(stack);
        assert_eq!(
            psbt.extract_transaction(),
            Err(PsbtError::IncompleteInput(0))
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_input_skips_taproot_input_without_complete_context() {
        // Two inputs, both P2TR; the second carries no UTXO data — the
        // BIP-341 digest for the first cannot be computed → Ok(false).
        let mut psbt = PartiallySignedTransaction::create(
            Transaction {
                version: 2,
                vin: vec![
                    TxIn {
                        txhash: [1; 32],
                        n: 0,
                        script: vec![],
                        sequence: SEQUENCE_RBF,
                        witness: Vec::new(),
                    },
                    TxIn {
                        txhash: [2; 32],
                        n: 0,
                        script: vec![],
                        sequence: SEQUENCE_RBF,
                        witness: Vec::new(),
                    },
                ],
                vout: vec![TxOut {
                    amount: 10_000,
                    script: fixture_spk(5, AddrType::Native),
                }],
                locktime: 0,
            },
            vec![
                CreateInput {
                    amount: 20_000,
                    script_pubkey: fixture_spk(0, AddrType::Taproot),
                    prev_tx: None,
                    redeem_script: None,
                    witness_script: None,
                    tap_leaf_script: None,
                },
                CreateInput {
                    amount: 20_000,
                    script_pubkey: fixture_spk(0, AddrType::Taproot),
                    prev_tx: None,
                    redeem_script: None,
                    witness_script: None,
                    tap_leaf_script: None,
                },
            ],
        )
        .unwrap();
        psbt.inputs[1].witness_utxo = None;
        let key = fixture_key(0);
        assert!(!psbt.sign_input(0, &key).unwrap());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_input_skips_taproot_input_committed_to_a_foreign_key() {
        // The script is canonical P2TR but tweaked from a different
        // internal key: the taproot branch of the ownership check.
        let key = fixture_key(0);
        let pubkey = privkey_to_pubkey(&key);
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&pubkey[1..33]);
        // Foreign internal key 0x01… (never the fixture key's).
        let foreign_internal = {
            let mut b = [0x01u8; 32];
            b[31] = 0x02;
            b
        };
        let foreign_output = crate::address::taproot_output_key(&foreign_internal)
            .expect("tweaks for a valid curve point");
        let spk = crate::script::make_p2tr_lock_script(&foreign_output).to_vec();
        let _ = xonly;
        let mut psbt = PartiallySignedTransaction::create(
            one_input_tx([1; 32]),
            vec![CreateInput {
                amount: 20_000,
                script_pubkey: spk,
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert!(!psbt.sign_input(0, &key).unwrap());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalize_input_respects_the_sighash_type_field() {
        let mut psbt = PartiallySignedTransaction::create(
            one_input_tx([1; 32]),
            vec![CreateInput {
                amount: 1000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        let key = fixture_key(0);
        assert!(psbt.sign_input(0, &key).unwrap());
        // The signature's sighash byte is the pinned 0x01, but the
        // input's SIGHASH_TYPE field says 2 — the gate blocks the input.
        psbt.inputs[0].sighash_type = Some(2);
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::IncompleteInput(0)));
        // The matching pinned value finalizes fine.
        psbt.inputs[0].sighash_type = Some(PSBT_SIGHASH_ALL);
        assert!(psbt.finalize_input(0).is_ok());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalize_input_legacy_gates_and_non_compressed_keys() {
        let prev = kat_prev_tx();
        let mut unsigned = one_input_tx(prev.id());
        unsigned.vout[0].amount = 10_000;
        let mut psbt = PartiallySignedTransaction::create(
            unsigned,
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: fixture_spk(0, AddrType::Legacy),
                prev_tx: Some(prev),
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        // A non-compressed (65-byte) pubkey partial signature is not a
        // finalizing candidate for the P2PKH form: IncompleteInput.
        psbt.inputs[0]
            .partial_sigs
            .push((PubKey(vec![0x04; 65]), vec![1, 0x01]));
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::IncompleteInput(0)));
        // A compressed-key signature with a foreign sighash byte is
        // blocked by the legacy gate.
        let key = fixture_key(0);
        assert!(psbt.sign_input(0, &key).unwrap());
        let last = psbt.inputs[0].partial_sigs[0].1.len() - 1;
        psbt.inputs[0].partial_sigs[0].1[last] = 0x03;
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::IncompleteInput(0)));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_refuses_inputs_without_a_recognizable_form() {
        // The input has UTXO data and even a final field, but the
        // scriptPubKey shape is a **bare** P2WSH (no witness script):
        // v0.3 moved the P2WSH-multisig form to the supported set, so
        // a FINAL_SCRIPTSIG on a witness input is now the specific
        // IncompleteInput refusal (symmetry with the P2SH arm), and
        // without any final field the input stays NotFinalized.
        let p2wsh = {
            let mut s = vec![0x00, 0x20];
            s.extend_from_slice(&[0xab; 32]);
            s
        };
        let mut psbt = PartiallySignedTransaction::create(
            one_input_tx([1; 32]),
            vec![CreateInput {
                amount: 1000,
                script_pubkey: p2wsh,
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        psbt.inputs[0].final_scriptsig = Some(vec![0x51]);
        assert_eq!(
            psbt.extract_transaction(),
            Err(PsbtError::IncompleteInput(0))
        );
        psbt.inputs[0].final_scriptsig = None;
        assert_eq!(psbt.extract_transaction(), Err(PsbtError::NotFinalized));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalize_and_extract_refuse_fully_unrecognizable_forms() {
        // A UTXO script shape the wallet can never own (neither
        // P2PKH/P2SH/P2WPKH/P2TR nor a P2SH/P2WSH form with known
        // scripts): the Finalizer refuses with IncompleteInput and
        // the Extractor with NotFinalized (BIP-174 Extractor MUST
        // check) — the generic arms behind the per-form dispatches.
        let blob = vec![0x6a, 0x09, 0xab, 0xcd];
        let mut psbt = PartiallySignedTransaction::create(
            one_input_tx([1; 32]),
            vec![CreateInput {
                amount: 1000,
                script_pubkey: blob,
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::IncompleteInput(0)));
        assert_eq!(psbt.extract_transaction(), Err(PsbtError::NotFinalized));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extractor_p2wsh_refuses_a_malformed_final_stack() {
        // A finalized P2WSH input whose FINAL_SCRIPTWITNESS does not
        // parse is IncompleteInput, not a crash.
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.finalize_input(0).expect("complete quorum");
        psbt.inputs[0].final_scriptwitness = Some(b"\xff garbage".to_vec());
        let err = psbt.extract_transaction().unwrap_err();
        assert_eq!(err, PsbtError::IncompleteInput(0));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn combine_fills_one_sided_fields_and_detects_witness_conflicts() {
        let (psbt, key, _) = signed_pair_of_psbt();
        let mut a = psbt.clone();
        let mut b = psbt.clone();
        // a finalizes its input (final_scriptwitness present), b does
        // not: the (Some, None) arms of every merge_field run.
        assert!(a.sign_input(0, &key).unwrap());
        a.finalize_input(0).unwrap();
        // A conflicting final_scriptwitness triggers that call's
        // ConflictingField arm.
        b.inputs[0].final_scriptwitness = Some(encode_witness_stack(&[vec![1]]));
        assert_eq!(a.combine(&b), Err(PsbtError::ConflictingField));
        // Without the conflict the one-sided merge succeeds and keeps
        // the finalized side.
        b.inputs[0].final_scriptwitness = None;
        let merged = a.combine(&b).unwrap();
        assert!(merged.inputs[0].final_scriptwitness.is_some());
        // Non-witness UTXO and sighash_type conflicts (same arm shape).
        let mut c = psbt.clone();
        let mut d = psbt.clone();
        c.inputs[0].sighash_type = Some(1);
        d.inputs[0].sighash_type = Some(3);
        assert_eq!(c.combine(&d), Err(PsbtError::ConflictingField));
        let mut e = psbt.clone();
        let mut f = psbt.clone();
        e.inputs[0].witness_script = Some(vec![1]);
        f.inputs[0].witness_script = Some(vec![2]);
        assert_eq!(e.combine(&f), Err(PsbtError::ConflictingField));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_input_treats_non_p2sh_23_byte_scripts_as_foreign() {
        // A 23-byte script that fails the P2SH opcode chain mid-way:
        // every `&&` arm of the P2SH shape check gets exercised.
        let key = fixture_key(0);
        let mut spk = vec![0x99; 23]; // wrong leading opcode
        spk[1] = 0x14;
        let mut psbt = PartiallySignedTransaction::create(
            one_input_tx([1; 32]),
            vec![CreateInput {
                amount: 1000,
                script_pubkey: spk,
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert!(!psbt.sign_input(0, &key).unwrap());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_accepts_zero_input_zero_output_prev_tx() {
        // A NON_WITNESS_UTXO whose byte after the version is 0x00 but
        // not followed by 0x01: the SegWit marker/flag heuristic's
        // false arm. The prev tx simply has no inputs/outputs.
        let mut wire = Vec::new();
        wire.extend_from_slice(&2i32.to_le_bytes());
        wire.push(0); // zero vins
        wire.push(0); // zero vouts
        wire.extend_from_slice(&0u32.to_le_bytes());
        let unsigned = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x22; 32],
                n: 1,
                script: vec![],
                sequence: SEQUENCE_RBF,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 10_000,
                script: fixture_spk(5, AddrType::Native),
            }],
            locktime: 0,
        };
        let psbt = PartiallySignedTransaction::create(
            unsigned,
            vec![CreateInput {
                amount: 30_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        // Inject via serialize→parse round trip: hand-crafted global.
        let mut with_prev = psbt.clone();
        with_prev.inputs[0].non_witness_utxo =
            Some(parse_tx(&wire, true).expect("the empty prev tx parses"));
        let reparsed = PartiallySignedTransaction::parse(&with_prev.serialize()).unwrap();
        assert!(reparsed.inputs[0].non_witness_utxo.is_some());
        assert!(reparsed.inputs[0]
            .non_witness_utxo
            .as_ref()
            .unwrap()
            .vout
            .is_empty());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn serialize_omits_empty_final_fields() {
        // BIP-174: an empty final scriptSig/witness is "unset", never
        // an empty value — the serializer's skip arms.
        let psbt = PartiallySignedTransaction {
            version: 0,
            unsigned_tx: one_input_tx([1; 32]),
            inputs: vec![PsbtInput {
                witness_utxo: Some(TxOut {
                    amount: 1000,
                    script: fixture_spk(0, AddrType::Native),
                }),
                final_scriptsig: Some(Vec::new()),
                final_scriptwitness: Some(Vec::new()),
                ..PsbtInput::default()
            }],
            outputs: vec![PsbtOutput::default()],
            unknown_global: Vec::new(),
        };
        let bytes = psbt.serialize();
        assert!(!windows_contain(&bytes, &[T_FINAL_SCRIPTSIG]));
        assert!(!windows_contain(&bytes, &[T_FINAL_SCRIPTWITNESS]));
        // Canonicalization: the empty finals read back as unset.
        let reparsed = PartiallySignedTransaction::parse(&bytes).unwrap();
        assert_eq!(reparsed.inputs[0].final_scriptsig, None);
        assert_eq!(reparsed.inputs[0].final_scriptwitness, None);
    }

    /// True when `needle` appears anywhere in `haystack`.
    fn windows_contain(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn combine_covers_equal_and_conflicting_transaction_fields() {
        // Identical prev tx, sighash type and redeem script on both
        // sides: every merge_field instantiation takes the equal arm.
        let prev = kat_prev_tx();
        let unsigned = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: prev.id(),
                n: 0,
                script: vec![],
                sequence: SEQUENCE_RBF,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 10_000,
                script: fixture_spk(5, AddrType::Native),
            }],
            locktime: 0,
        };
        let build = |redeem: Option<Vec<u8>>, sighash: Option<u32>| {
            let mut psbt = PartiallySignedTransaction::create(
                unsigned.clone(),
                vec![CreateInput {
                    amount: 60_000,
                    script_pubkey: fixture_spk(0, AddrType::Legacy),
                    prev_tx: Some(prev.clone()),
                    redeem_script: None,
                    witness_script: None,
                    tap_leaf_script: None,
                }],
            )
            .unwrap();
            psbt.inputs[0].redeem_script = redeem;
            psbt.inputs[0].sighash_type = sighash;
            psbt
        };
        let a = build(Some(vec![1]), Some(1));
        let b = build(Some(vec![1]), Some(1));
        let merged = a.combine(&b).unwrap();
        assert_eq!(merged.inputs[0].redeem_script.as_deref(), Some(&[1][..]));
        assert_eq!(merged.inputs[0].sighash_type, Some(1));
        assert!(merged.inputs[0].non_witness_utxo.is_some());

        // The Transaction-typed merge_field's conflict arm.
        let mut c = build(Some(vec![1]), Some(1));
        let mut d = build(Some(vec![1]), Some(1));
        c.inputs[0].non_witness_utxo.as_mut().unwrap().locktime = 5;
        d.inputs[0].non_witness_utxo.as_mut().unwrap().locktime = 6;
        assert_eq!(c.combine(&d), Err(PsbtError::ConflictingField));

        // The u32-typed merge_field's equal arm (sighash equal, no
        // conflict) is covered by `merged` above.
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn summary_finalized_flag_reflects_scriptsig_finals() {
        // The summary's `finalized` predicate over a legacy-finalized
        // input (FINAL_SCRIPTSIG present, witness absent).
        let prev = kat_prev_tx();
        let unsigned = one_input_tx(prev.id());
        let mut psbt = PartiallySignedTransaction::create(
            unsigned,
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: fixture_spk(0, AddrType::Legacy),
                prev_tx: Some(prev),
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        let key = fixture_key(0);
        assert!(psbt.sign_input(0, &key).unwrap());
        psbt.finalize_input(0).unwrap();
        assert!(psbt.summary().inputs[0].finalized);
        assert!(psbt.inputs[0].final_scriptsig.is_some());
        assert!(psbt.inputs[0].final_scriptwitness.is_none());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2sh_shape_check_rejects_wrong_second_byte() {
        // 23 bytes, OP_HASH160 first, but the push width byte is not
        // 0x14: the second condition of the P2SH shape chain.
        let key = fixture_key(0);
        let mut spk = vec![0xa9u8, 0x15];
        spk.extend_from_slice(&[0x77; 20]);
        spk.push(0x87);
        assert_eq!(spk.len(), 23);
        let mut psbt = PartiallySignedTransaction::create(
            one_input_tx([1; 32]),
            vec![CreateInput {
                amount: 1000,
                script_pubkey: spk,
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert!(!psbt.sign_input(0, &key).unwrap());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_tx_wire_detection_needs_the_flag_byte() {
        // NON_WITNESS_UTXO of 5 bytes: after the version only one byte
        // remains, so the SegWit marker/flag window cannot even be
        // inspected (`remaining >= 2` fails) and the stripped parse
        // then truncates.
        let unsigned = one_input_tx([1; 32]);
        let mut psbt = PartiallySignedTransaction::create(
            unsigned,
            vec![CreateInput {
                amount: 1000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        psbt.inputs[0].non_witness_utxo = Some(Transaction {
            vin: Vec::new(),
            vout: Vec::new(),
            ..Default::default()
        });
        psbt.inputs[0].non_witness_utxo = None;
        // Hand-write the 5-byte value: version 2 + a zero byte.
        let mut value = Vec::new();
        value.extend_from_slice(&2i32.to_le_bytes());
        value.push(0x00);
        let bytes = assemble(
            &[kv(&[T_ZERO], &stub_tx_bytes())],
            &[kv(&[T_ZERO], &value)],
            &[Vec::new()],
        );
        assert_eq!(
            PartiallySignedTransaction::parse(&bytes),
            Err(PsbtError::InvalidFieldValue)
        );
        let _ = psbt;
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalize_p2tr_skips_non_compressed_key_signatures() {
        // A 65-byte-key partial signature with a well-formed 64-byte
        // value: the P2TR dispatch must skip the pubkey shape before
        // tweaking, then find the real (compressed) signature.
        let unsigned = one_input_tx([1; 32]);
        let mut psbt = PartiallySignedTransaction::create(
            unsigned,
            vec![CreateInput {
                amount: 20_000,
                script_pubkey: fixture_spk(0, AddrType::Taproot),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        let key = fixture_key(0);
        assert!(psbt.sign_input(0, &key).unwrap());
        // Uncompressed-key entry sorts before the compressed one.
        psbt.inputs[0]
            .partial_sigs
            .insert(0, (PubKey(vec![0x04; 65]), vec![1u8; 64]));
        assert!(psbt.finalize_input(0).is_ok());
        let stack = decode_witness_stack(&psbt.inputs[0].final_scriptwitness.clone().unwrap())
            .expect("finalize wrote a canonical stack");
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 64);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_input_skips_foreign_p2pkh_input() {
        // The Legacy guard arm of the ownership dispatch: canonical
        // P2PKH output committed to a different hash160.
        let foreign = fixture_key(9);
        let prev = kat_prev_tx();
        let mut psbt = PartiallySignedTransaction::create(
            one_input_tx(prev.id()),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: fixture_spk(0, AddrType::Legacy),
                prev_tx: Some(prev),
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert!(!psbt.sign_input(0, &foreign).unwrap());
        assert!(psbt.inputs[0].partial_sigs.is_empty());
    }

    // --- parse_wire_tx (Creator prev-tx source, stage 2) ---------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_wire_tx_round_trips_wire_and_stripped() {
        // Witness-form payload: the BIP-144 marker/flag layout must be
        // accepted (NON_WITNESS_UTXO may carry witness data).
        let prev = kat_prev_tx();
        let bytes = prev.serialize_wire();
        let parsed = parse_wire_tx(&bytes).expect("wire bytes parse");
        assert_eq!(parsed.id(), prev.id());

        // Stripped payloads are equally valid (witness-free prev txs).
        let stripped = prev.serialize_stripped();
        let parsed = parse_wire_tx(&stripped).expect("stripped bytes parse");
        assert_eq!(parsed.id(), prev.id());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_wire_tx_rejects_garbage() {
        // Empty input, a lone magic byte, and a structurally broken tx
        // (vin count far beyond the data) must all be typed errors —
        // never a panic.
        assert_eq!(parse_wire_tx(&[]), Err(PsbtError::Truncated));
        assert_eq!(parse_wire_tx(&[0x02]), Err(PsbtError::Truncated));
        assert_eq!(parse_wire_tx(&[0xff; 8]), Err(PsbtError::Truncated));
    }

    // --- Phase 15: P2SH-multisig (Creator / Signer / Finalizer /
    //     Extractor) ---------------------------------------------------

    /// Fixture seed for the multisig tests (distinct from the Phase 14
    /// `SEED` so the two fixture families never share keys).
    const MS_SEED: &str = "phase15multisig";

    /// Quorum key `nonce`: legacy-form derivation from [`MS_SEED`].
    fn ms_key(nonce: u32) -> SigningKey {
        seed2privkey_with_kdf(
            &TSeed::new(MS_SEED),
            TNonce::new(nonce),
            &TPassphrase::EMPTY,
            kdf(),
        )
        .expect("fixture derives")
    }

    fn ms_pubkey(nonce: u32) -> [u8; 33] {
        crate::privkey::privkey_to_pubkey(&ms_key(nonce))
    }

    /// 2-of-3 redeem over the fixture keys (BIP-67-sorted by the
    /// builder).
    fn ms_redeem() -> Vec<u8> {
        crate::script::make_multisig_redeem_script(2, &[ms_pubkey(0), ms_pubkey(1), ms_pubkey(2)])
            .expect("fixture quorum is valid")
    }

    /// The fixture redeem's keys in script (sorted) order.
    fn ms_redeem_keys() -> Vec<[u8; 33]> {
        crate::script::extract_multisig_quorum(&ms_redeem())
            .expect("fixture redeem is canonical")
            .1
    }

    /// P2SH `scriptPubKey` committing to the fixture redeem script.
    fn ms_p2sh_spk() -> Vec<u8> {
        crate::script::make_p2sh_lock_script(&crate::address::hash160_script(&ms_redeem()))
    }

    /// Prev tx paying 60_000 sat to the fixture P2SH address.
    fn ms_prev_tx() -> Transaction {
        Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x22; 32],
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 60_000,
                script: ms_p2sh_spk(),
            }],
            locktime: 0,
        }
    }

    /// Unsigned tx spending the fixture multisig output to a foreign
    /// native-P2WPKH destination.
    fn ms_unsigned_tx(txhash: [u8; 32]) -> Transaction {
        Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash,
                n: 0,
                script: vec![],
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 50_000,
                script: fixture_spk(9, AddrType::Native),
            }],
            locktime: 0,
        }
    }

    /// Creator output for the happy-path fixture: one P2SH-multisig
    /// input with its redeem script.
    fn ms_create_psbt() -> PartiallySignedTransaction {
        let prev = ms_prev_tx();
        PartiallySignedTransaction::create(
            ms_unsigned_tx(prev.id()),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2sh_spk(),
                prev_tx: Some(prev),
                redeem_script: Some(ms_redeem()),
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .expect("fixture PSBT builds")
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_p2sh_branch_writes_non_witness_utxo_and_redeem_script() {
        let psbt = ms_create_psbt();
        let input = &psbt.inputs[0];
        assert!(input.non_witness_utxo.is_some());
        assert!(input.witness_utxo.is_none());
        assert_eq!(input.redeem_script.as_deref(), Some(ms_redeem().as_slice()));
        // The typed field survives the wire round trip byte-for-byte
        // (REDEEM_SCRIPT 0x04 is W/R on the P2SH-multisig path).
        let parsed =
            PartiallySignedTransaction::parse(&psbt.serialize()).expect("canonical wire parses");
        assert_eq!(parsed, psbt);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_p2sh_branch_rejections() {
        let prev = ms_prev_tx();
        // Non-canonical redeem script (R-MS-3) → UnsupportedInputScript.
        let err = PartiallySignedTransaction::create(
            ms_unsigned_tx(prev.id()),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2sh_spk(),
                prev_tx: Some(prev.clone()),
                redeem_script: Some(vec![0x51]),
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // Redeem that hashes elsewhere → UtxoMismatch.
        let other_redeem =
            crate::script::make_multisig_redeem_script(1, &[ms_pubkey(7)]).expect("valid quorum");
        let err = PartiallySignedTransaction::create(
            ms_unsigned_tx(prev.id()),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2sh_spk(),
                prev_tx: Some(prev.clone()),
                redeem_script: Some(other_redeem),
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap_err();
        assert_eq!(err, PsbtError::UtxoMismatch);
        // Missing prev tx → IncompleteInput (P2SH is a legacy input).
        let err = PartiallySignedTransaction::create(
            ms_unsigned_tx(prev.id()),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2sh_spk(),
                prev_tx: None,
                redeem_script: Some(ms_redeem()),
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap_err();
        assert_eq!(err, PsbtError::IncompleteInput(0));
        // Prev tx that does not match the outpoint → UtxoMismatch.
        let err = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x33; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2sh_spk(),
                prev_tx: Some(prev),
                redeem_script: Some(ms_redeem()),
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap_err();
        assert_eq!(err, PsbtError::UtxoMismatch);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn signer_p2sh_signs_members_skips_foreign_keys() {
        let mut psbt = ms_create_psbt();
        // A quorum member signs; the signature is legacy DER ‖ 0x01.
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        let sigs = &psbt.inputs[0].partial_sigs;
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].0 .0, ms_pubkey(0).to_vec());
        assert_eq!(*sigs[0].1.last().expect("non-empty"), 0x01);
        // Idempotent re-sign.
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        // The second member signs alongside the first.
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 2);
        // A third member's key is foreign for a 2-of-3 threshold
        // (membership holds for every listed key — the third key of a
        // 2-of-3 IS a member; the threshold only matters at finalize).
        assert!(psbt.sign_input(0, &ms_key(2)).unwrap());
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 3);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn signer_p2sh_rejections_and_foreign_membership() {
        // P2SH without a redeem script keeps the Phase 14 refusal.
        let mut psbt = PartiallySignedTransaction::create(
            ms_unsigned_tx(ms_prev_tx().id()),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2sh_spk(),
                prev_tx: Some(ms_prev_tx()),
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert_eq!(
            psbt.sign_input(0, &ms_key(0)),
            Err(PsbtError::UnsupportedInputScript)
        );

        // Non-canonical redeem script → UnsupportedInputScript.
        let mut psbt = ms_create_psbt();
        psbt.inputs[0].redeem_script = Some(vec![0x51]);
        assert_eq!(
            psbt.sign_input(0, &ms_key(0)),
            Err(PsbtError::UnsupportedInputScript)
        );

        // Redeem that hashes elsewhere → UtxoMismatch.
        let mut psbt = ms_create_psbt();
        psbt.inputs[0].redeem_script =
            Some(crate::script::make_multisig_redeem_script(1, &[ms_pubkey(7)]).expect("valid"));
        assert_eq!(psbt.sign_input(0, &ms_key(0)), Err(PsbtError::UtxoMismatch));

        // Non-member key → Ok(false), no signature.
        let foreign = seed2privkey_with_kdf(
            &TSeed::new("totally foreign seed"),
            TNonce::new(0),
            &TPassphrase::EMPTY,
            kdf(),
        )
        .expect("fixture derives");
        let mut psbt = ms_create_psbt();
        assert!(!psbt.sign_input(0, &foreign).unwrap());
        assert!(psbt.inputs[0].partial_sigs.is_empty());

        // SIGHASH_TYPE disagreement → UnsupportedSighashType (ОВ-8).
        let mut psbt = ms_create_psbt();
        psbt.inputs[0].sighash_type = Some(0x02);
        assert_eq!(
            psbt.sign_input(0, &ms_key(0)),
            Err(PsbtError::UnsupportedSighashType(0x02))
        );

        // NON_WITNESS_UTXO that does not hash to the outpoint →
        // UtxoMismatch (BIP-174 Data Signers Check For). The fake prev
        // tx keeps the P2SH vout so the input still dispatches to the
        // multisig branch; only its id changes.
        let mut psbt = ms_create_psbt();
        let mut wrong_prev = ms_prev_tx();
        wrong_prev.vin[0].n = 1; // any content change shifts the txid
        psbt.inputs[0].non_witness_utxo = Some(wrong_prev);
        assert_eq!(psbt.sign_input(0, &ms_key(0)), Err(PsbtError::UtxoMismatch));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalizer_p2sh_builds_scriptsig_in_script_order() {
        // Sign the LATER script key first: the assembled scriptSig must
        // still lay signatures out in redeem-script key order (R-MS-4).
        let mut psbt = ms_create_psbt();
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        let sigs: Vec<(PubKey, Vec<u8>)> = psbt.inputs[0].partial_sigs.clone();
        assert_eq!(sigs.len(), 2);
        // insert_partial_sig keeps PARTIAL_SIG sorted by pubkey, so the
        // script-order layout comes from the Finalizer, not storage.
        let sig_of = |k: &[u8; 33]| -> Vec<u8> {
            sigs.iter()
                .find(|(pk, _)| pk.0.as_slice() == k)
                .expect("member sig present")
                .1
                .clone()
        };

        psbt.finalize_input(0).expect("2-of-3 quorum is complete");
        let script_sig = psbt.inputs[0].final_scriptsig.as_ref().expect("finalized");
        // The two signers are the keys at nonces 0 and 1; their order
        // INSIDE the scriptSig follows the script (BIP-67 sorted),
        // regardless of signing order.
        let mut signers = [ms_pubkey(0), ms_pubkey(1)];
        signers.sort();
        let (a, b) = (&signers[0], &signers[1]);
        // OP_0 dummy ‖ push(sig‖0x01)×2 in script order ‖ push(redeem).
        assert_eq!(script_sig[0], 0x00);
        assert_eq!(script_sig[1], sig_of(a).len() as u8);
        assert_eq!(&script_sig[2..2 + sig_of(a).len()], &sig_of(a)[..]);
        let off = 2 + sig_of(a).len();
        assert_eq!(script_sig[off], sig_of(b).len() as u8);
        assert_eq!(
            &script_sig[off + 1..off + 1 + sig_of(b).len()],
            &sig_of(b)[..]
        );
        let off = off + 1 + sig_of(b).len();
        // 105-byte redeem > 75 → OP_PUSHDATA1 push.
        assert_eq!(script_sig[off], crate::script::OP_PUSHDATA1);
        assert_eq!(script_sig[off + 1], ms_redeem().len() as u8);
        assert_eq!(&script_sig[off + 2..], &ms_redeem()[..]);
        // Intermediates stripped, UTXO data preserved.
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[0].redeem_script.is_none());
        assert!(psbt.inputs[0].non_witness_utxo.is_some());
        // Idempotent.
        assert!(psbt.finalize_input(0).is_ok());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalizer_p2sh_incomplete_and_foreign() {
        // One signature short of the threshold → IncompleteInput, the
        // input stays untouched (per-input Finalizer).
        let mut psbt = ms_create_psbt();
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::IncompleteInput(0)));
        assert!(psbt.inputs[0].final_scriptsig.is_none());

        // A signature with a foreign sighash byte blocks the input.
        let mut psbt = ms_create_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        let last = psbt.inputs[0].partial_sigs[0].1.len() - 1;
        psbt.inputs[0].partial_sigs[0].1[last] = 0x03;
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::IncompleteInput(0)));

        // SIGHASH_TYPE ≠ 0x01 → IncompleteInput (ОВ-8, Finalizer arm).
        let mut psbt = ms_create_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].sighash_type = Some(0x02);
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::IncompleteInput(0)));

        // Non-canonical redeem → UnsupportedInputScript (R-MS-3: yubtc
        // does not finalize foreign multisig forms).
        let mut psbt = ms_create_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].redeem_script = Some(vec![0x51]);
        assert_eq!(
            psbt.finalize_input(0),
            Err(PsbtError::UnsupportedInputScript)
        );

        // Redeem hash mismatch → UtxoMismatch.
        let mut psbt = ms_create_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].redeem_script =
            Some(crate::script::make_multisig_redeem_script(1, &[ms_pubkey(7)]).expect("valid"));
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::UtxoMismatch));

        // P2SH without a redeem script → IncompleteInput.
        let mut psbt = PartiallySignedTransaction::create(
            ms_unsigned_tx(ms_prev_tx().id()),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2sh_spk(),
                prev_tx: Some(ms_prev_tx()),
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::IncompleteInput(0)));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extractor_p2sh_uses_final_scriptsig_and_refuses_witness() {
        // Complete quorum → extraction moves the scriptSig into the
        // wire input.
        let mut psbt = ms_create_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.finalize_input(0).expect("complete");
        let expected = psbt.inputs[0].final_scriptsig.clone().expect("final");
        let tx = psbt.extract_transaction().expect("extracts");
        assert_eq!(tx.vin[0].script, expected);
        assert!(tx.vin[0].witness.is_empty());

        // An unfinalized P2SH input → NotFinalized.
        let psbt = ms_create_psbt();
        assert_eq!(psbt.extract_transaction(), Err(PsbtError::NotFinalized));

        // A witness stack on a P2SH input → IncompleteInput (nested
        // SegWit spends are explicitly out of scope).
        let mut psbt = ms_create_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.finalize_input(0).expect("complete");
        psbt.inputs[0].final_scriptwitness = Some(vec![0x01]);
        assert_eq!(
            psbt.extract_transaction(),
            Err(PsbtError::IncompleteInput(0))
        );
    }

    // --- Independent OP_CHECKMULTISIG verification (e2e evidence) ----
    //
    // The verifier deliberately shares no code with yubtc: the wire tx
    // is parsed by the `bitcoin` crate, the legacy sighash preimage is
    // re-encoded field-by-field with a local varint writer, and the
    // CHECKMULTISIG stack semantics (empty dummy → greedy
    // signature-to-key matching in script-key order) are implemented
    // locally; every signature is ECDSA-verified with k256 over the
    // recomputed digest.

    /// Recompute the legacy SIGHASH_ALL digest of input 0 with
    /// `scriptCode = redeem`, independently of yubtc (over an
    /// already-parsed wire transaction).
    fn independent_ms_digest_tx(tx: &bitcoin::Transaction, redeem: &[u8]) -> [u8; 32] {
        use bitcoin::hashes::Hash as _;
        use sha2::{Digest as _, Sha256};

        fn varint(out: &mut Vec<u8>, n: usize) {
            if n < 0xfd {
                out.push(n as u8);
            } else {
                out.push(0xfd);
                out.extend_from_slice(&(n as u16).to_le_bytes());
            }
        }

        let txin = &tx.input[0];
        let mut pre = Vec::new();
        pre.extend_from_slice(&tx.version.0.to_le_bytes());
        varint(&mut pre, tx.input.len());
        pre.extend_from_slice(txin.previous_output.txid.as_raw_hash().as_byte_array());
        pre.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
        varint(&mut pre, redeem.len());
        pre.extend_from_slice(redeem);
        pre.extend_from_slice(&txin.sequence.to_consensus_u32().to_le_bytes());
        varint(&mut pre, tx.output.len());
        for out in &tx.output {
            pre.extend_from_slice(&out.value.to_sat().to_le_bytes());
            varint(&mut pre, out.script_pubkey.len());
            pre.extend_from_slice(out.script_pubkey.as_bytes());
        }
        pre.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());
        pre.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL
        Sha256::digest(Sha256::digest(&pre)).into()
    }

    /// [`independent_ms_digest_tx`] over raw wire bytes: the wire must
    /// parse as a transaction and carry exactly one input.
    fn independent_ms_digest(wire: &[u8], redeem: &[u8]) -> Result<[u8; 32], String> {
        use bitcoin::consensus::deserialize;

        let tx: bitcoin::Transaction = deserialize(wire).map_err(|e| format!("wire parse: {e}"))?;
        if tx.input.len() != 1 {
            return Err("fixture expects a single input".into());
        }
        Ok(independent_ms_digest_tx(&tx, redeem))
    }

    /// Evaluate a completed P2SH-multisig spend the way the consensus
    /// interpreter would: parse the scriptSig pushes, check the empty
    /// dummy (R-MS-5 / BIP-147), parse the redeem script, and greedily
    /// match each signature against the script's keys in order
    /// (R-MS-4 placement), verifying ECDSA over the legacy digest.
    fn independent_checkmultisig_verify(
        wire: &[u8],
        expected_keys: &[[u8; 33]],
    ) -> Result<(), String> {
        use bitcoin::blockdata::script::Instruction;
        use bitcoin::consensus::deserialize;
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let tx: bitcoin::Transaction = deserialize(wire).map_err(|e| format!("wire parse: {e}"))?;
        // bitcoin's consensus deserializer enforces a non-empty vin,
        // so indexing is sound for anything that parsed.
        let txin = &tx.input[0];

        // --- scriptSig decomposition ---------------------------------
        let mut pushes: Vec<Vec<u8>> = Vec::new();
        let mut bare_ops: Vec<u8> = Vec::new();
        for ins in txin.script_sig.instructions() {
            match ins.map_err(|e| format!("script parse: {e}"))? {
                Instruction::PushBytes(b) => pushes.push(b.as_bytes().to_vec()),
                Instruction::Op(op) => bare_ops.push(op.to_u8()),
            }
        }
        // The OP_0 dummy pushes an EMPTY byte string, so in the
        // canonical form there are no bare opcodes at all, the first
        // push is empty (the dummy — a non-empty first push is a
        // NULLDUMMY violation / a missing dummy), then M signatures,
        // then the redeem script push.
        if !bare_ops.is_empty() {
            return Err(format!(
                "unexpected bare opcodes {bare_ops:?} in the scriptSig"
            ));
        }
        if pushes.len() < 3 {
            return Err("scriptSig needs a dummy, at least one signature, and the redeem".into());
        }
        if !pushes[0].is_empty() {
            return Err(format!(
                "the dummy element must be empty (BIP-147), got {} bytes",
                pushes[0].len()
            ));
        }
        let redeem = pushes.last().expect("checked above").clone();
        let sigs = &pushes[1..pushes.len() - 1];

        // --- redeem script: OP_m ‖ (0x21‖key)×N ‖ OP_n ‖ 0xae --------
        if redeem.len() < 3 + 34 || redeem[redeem.len() - 1] != 0xae {
            return Err("redeem is not a CHECKMULTISIG script".into());
        }
        if redeem[0] < 0x51 || redeem[redeem.len() - 2] < 0x51 {
            return Err("quorum counters must be OP_1..=OP_16".into());
        }
        let m = (redeem[0] - 0x50) as usize;
        let n = (redeem[redeem.len() - 2] - 0x50) as usize;
        if m > n {
            return Err("m must not exceed n".into());
        }
        if redeem.len() != 3 + 34 * n {
            return Err("redeem body does not match N pushes".into());
        }
        let mut keys: Vec<&[u8]> = Vec::with_capacity(n);
        for i in 0..n {
            let s = 1 + i * 34;
            if redeem[s] != 0x21 {
                return Err("non-canonical key push".into());
            }
            keys.push(&redeem[s + 1..s + 34]);
        }
        if keys.len() != expected_keys.len()
            || keys
                .iter()
                .zip(expected_keys)
                .any(|(a, b)| *a != b.as_slice())
        {
            return Err("redeem keys do not match the expected quorum".into());
        }
        if sigs.len() != m {
            return Err(format!("expected {m} signatures, got {}", sigs.len()));
        }

        // --- digest + greedy CHECKMULTISIG matching -------------------
        let digest = independent_ms_digest_tx(&tx, &redeem);
        let mut key_idx = 0usize;
        for (j, sig) in sigs.iter().enumerate() {
            if sig.last() != Some(&0x01) {
                return Err(format!("signature {j} lacks the SIGHASH_ALL suffix"));
            }
            let der = &sig[..sig.len() - 1];
            let signature = k256::ecdsa::Signature::from_der(der)
                .map_err(|e| format!("signature {j}: bad DER: {e}"))?;
            let mut matched = false;
            while key_idx < keys.len() {
                let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(keys[key_idx])
                    .map_err(|e| format!("key {key_idx}: {e}"))?;
                let verified = vk.verify_prehash(&digest, &signature).is_ok();
                key_idx += 1;
                if verified {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err(format!("signature {j} matches no remaining script key"));
            }
        }
        Ok(())
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_e2e_two_signers_combine_finalize_extract_independent_verify() {
        // 1. Creator: ms_create_psbt equivalent (the wallet-level
        //    orchestration is exercised in wallet.rs tests).
        let mut psbt_a = ms_create_psbt();
        // 2. Signer A — the seed-based walk finds its key by *membership*
        //    (ОВ-9 walk + R-MS-6 legacy nonce derivation).
        let unsigned = sign_psbt_with(
            &TSeed::new(MS_SEED),
            &TPassphrase::EMPTY,
            kdf(),
            &mut psbt_a,
        )
        .expect("walk completes");
        assert!(unsigned.is_empty(), "the walk must sign the member input");
        assert_eq!(psbt_a.inputs[0].partial_sigs.len(), 1);
        // 3. Signer B — direct primitive on the second quorum key.
        let mut psbt_b = ms_create_psbt();
        assert!(psbt_b.sign_input(0, &ms_key(1)).unwrap());
        // 4. Combiner: A ∪ B.
        let mut combined = psbt_a.combine(&psbt_b).expect("disjoint signers");
        assert_eq!(combined.inputs[0].partial_sigs.len(), 2);
        // 5. Finalizer: 2-of-3 quorum complete.
        combined.finalize();
        assert!(combined.inputs[0].final_scriptsig.is_some());
        // 6. Extractor: the wire transaction.
        let tx = combined.extract_transaction().expect("complete quorum");
        let wire = tx.serialize_wire();

        // 7. Independent consensus-equivalent verification.
        independent_checkmultisig_verify(&wire, &ms_redeem_keys())
            .expect("the extracted spend must verify independently");

        // Bit-for-bit pin: the same pipeline in a different signer
        // order produces the identical wire.
        let mut flip = ms_create_psbt();
        assert!(flip.sign_input(0, &ms_key(1)).unwrap());
        assert!(flip.sign_input(0, &ms_key(0)).unwrap());
        flip.finalize();
        let tx_flip = flip.extract_transaction().expect("complete quorum");
        assert_eq!(tx_flip.serialize_wire(), wire);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_scriptsig_mutations_fail_independent_verification() {
        // A complete spend, decomposed for mutation.
        let mut psbt = ms_create_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        let sigs: Vec<Vec<u8>> = psbt.inputs[0]
            .partial_sigs
            .iter()
            .map(|(_, s)| s.clone())
            .collect();
        let redeem = ms_redeem();
        let keys = ms_redeem_keys();
        psbt.finalize_input(0).expect("2-of-3 quorum is complete");
        let base_tx = psbt.extract_transaction().expect("complete quorum");
        let finalize_to_wire = |script_sig: Vec<u8>| -> Vec<u8> {
            let mut tx = base_tx.clone();
            tx.vin[0].script = script_sig;
            tx.serialize_wire()
        };

        // Mutation 1: non-empty dummy (BIP-147 NULLDUMMY violation).
        let mut bad_dummy = vec![0x01, 0x00];
        bad_dummy.extend_from_slice(&crate::script::push_data(&sigs[0]));
        bad_dummy.extend_from_slice(&crate::script::push_data(&sigs[1]));
        bad_dummy.extend_from_slice(&crate::script::push_data(&redeem));
        let wire = finalize_to_wire(bad_dummy);
        let err = independent_checkmultisig_verify(&wire, &keys).unwrap_err();
        assert!(err.contains("dummy"), "got: {err}");

        // Mutation 2: signatures in the wrong (non-script) order.
        let script_sig = crate::script::make_multisig_script_sig(&redeem, &[&sigs[1], &sigs[0]]);
        let wire = finalize_to_wire(script_sig);
        let err = independent_checkmultisig_verify(&wire, &keys).unwrap_err();
        assert!(
            err.contains("matches no remaining script key"),
            "got: {err}"
        );

        // Mutation 3: a signature by a foreign key over the same
        // digest — the greedy match runs out of keys.
        let digest = independent_ms_digest(
            &finalize_to_wire(crate::script::make_multisig_script_sig(
                &redeem,
                &[&sigs[0], &sigs[1]],
            )),
            &redeem,
        )
        .expect("digest");
        let foreign_sig = {
            let sig = crate::privkey::sign_hash(&ms_key(7), &digest);
            let mut der = sig.to_der().as_bytes().to_vec();
            der.push(0x01);
            der
        };
        let script_sig =
            crate::script::make_multisig_script_sig(&redeem, &[&sigs[0], &foreign_sig]);
        let wire = finalize_to_wire(script_sig);
        let err = independent_checkmultisig_verify(&wire, &keys).unwrap_err();
        assert!(
            err.contains("matches no remaining script key"),
            "got: {err}"
        );

        // Mutation 4: the dummy dropped entirely (no OP_0 op).
        let mut no_dummy = crate::script::push_data(&sigs[0]);
        no_dummy.extend_from_slice(&crate::script::push_data(&sigs[1]));
        no_dummy.extend_from_slice(&crate::script::push_data(&redeem));
        let wire = finalize_to_wire(no_dummy);
        let err = independent_checkmultisig_verify(&wire, &keys).unwrap_err();
        assert!(err.contains("dummy"), "got: {err}");
    }

    #[ntest_timeout::timeout(120_000)]
    #[test]
    fn wallet_walk_leaves_foreign_quorums_unsigned() {
        // A P2SH-multisig input whose redeem script contains none of
        // our keys: the walk must skip it (reported), not error.
        let foreign_keys: Vec<[u8; 33]> = (0..3)
            .map(|i| {
                crate::privkey::privkey_to_pubkey(
                    &seed2privkey_with_kdf(
                        &TSeed::new(format!("foreign quorum {i}")),
                        TNonce::new(0),
                        &TPassphrase::EMPTY,
                        kdf(),
                    )
                    .expect("fixture derives"),
                )
            })
            .collect();
        let redeem =
            crate::script::make_multisig_redeem_script(2, &foreign_keys).expect("valid quorum");
        let spk = crate::script::make_p2sh_lock_script(&crate::address::hash160_script(&redeem));
        let prev = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x55; 32],
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 60_000,
                script: spk,
            }],
            locktime: 0,
        };
        let mut psbt = PartiallySignedTransaction::create(
            ms_unsigned_tx(prev.id()),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: prev.vout[0].script.clone(),
                prev_tx: Some(prev),
                redeem_script: Some(redeem),
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .expect("fixture PSBT builds");
        let unsigned = sign_psbt_with(&TSeed::new(MS_SEED), &TPassphrase::EMPTY, kdf(), &mut psbt)
            .expect("walk completes");
        assert_eq!(unsigned, vec![0]);
        assert!(psbt.inputs[0].partial_sigs.is_empty());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_input_prev_tx_mismatch_is_utxo_mismatch_for_every_form() {
        // The shared BIP-174 "Data Signers Check For" arm behind the
        // per-form dispatch: a *present* NON_WITNESS_UTXO that does
        // not hash to the outpoint refuses with UtxoMismatch — for
        // the key forms (the multisig branches carry their own copies
        // of the check, covered by their branch tests).
        for form in [AddrType::Legacy, AddrType::Native, AddrType::Taproot] {
            // The injected NON_WITNESS_UTXO carries the right script
            // but an id that differs from the outpoint: build it from
            // a distinct outpoint marker per form.
            let wrong_prev = Transaction {
                version: 2,
                vin: vec![TxIn {
                    txhash: [0x77; 32],
                    n: 0,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                }],
                vout: vec![TxOut {
                    amount: 1000,
                    script: fixture_spk(0, form),
                }],
                locktime: 0,
            };

            let script_pubkey = fixture_spk(0, form);
            // A legacy Creator input requires a *matching* prev tx;
            // the mismatching UTXO field is injected afterwards,
            // exactly like a parsed PSBT could carry it. The witness
            // forms skip the field at creation.
            let matching_prev = Transaction {
                version: 2,
                vin: vec![TxIn {
                    txhash: [0x11; 32],
                    n: 0,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                }],
                vout: vec![TxOut {
                    amount: 1000,
                    script: fixture_spk(0, form),
                }],
                locktime: 0,
            };
            let prev_tx = (form == AddrType::Legacy).then(|| matching_prev.clone());
            let unsigned = Transaction {
                version: 2,
                vin: vec![TxIn {
                    txhash: if form == AddrType::Legacy {
                        matching_prev.id()
                    } else {
                        [0x11; 32]
                    },
                    n: 0,
                    script: vec![],
                    sequence: SEQUENCE_RBF,
                    witness: Vec::new(),
                }],
                vout: vec![TxOut {
                    amount: 500,
                    script: fixture_spk(9, AddrType::Native),
                }],
                locktime: 0,
            };
            let mut psbt = PartiallySignedTransaction::create(
                unsigned,
                vec![CreateInput {
                    amount: 1000,
                    script_pubkey,
                    prev_tx,
                    redeem_script: None,
                    witness_script: None,
                    tap_leaf_script: None,
                }],
            )
            .unwrap();
            psbt.inputs[0].non_witness_utxo = Some(wrong_prev);
            let err = psbt.sign_input(0, &fixture_key(0)).unwrap_err();
            assert_eq!(err, PsbtError::UtxoMismatch, "form {form:?}");
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn signer_p2sh_accepts_explicit_pinned_sighash_and_witness_utxo() {
        // SIGHASH_TYPE present and equal to the pin: the check
        // falls through and the input signs (the `Some(1)` arm).
        let mut psbt = ms_create_psbt();
        psbt.inputs[0].sighash_type = Some(PSBT_SIGHASH_ALL);
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());

        // A P2SH input backed by WITNESS_UTXO only (no
        // NON_WITNESS_UTXO): the prev-tx check is vacuous (its `None`
        // arm) and the UTXO data comes from the witness field — the
        // legacy digest does not commit amounts, so signing works.
        let mut psbt = ms_create_psbt();
        let prev = psbt.inputs[0].non_witness_utxo.take();
        psbt.inputs[0].witness_utxo = Some(crate::transaction::TxOut {
            amount: 60_000,
            script: ms_p2sh_spk(),
        });
        assert!(prev.is_some());
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalizer_p2sh_accepts_explicit_pinned_sighash() {
        // SIGHASH_TYPE present and equal to the pin: the Finalizer's
        // `Some(1)` arm falls through and the input finalizes.
        let mut psbt = ms_create_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].sighash_type = Some(PSBT_SIGHASH_ALL);
        assert!(psbt.finalize_input(0).is_ok());
    }

    // --- v0.3: P2WSH-multisig (Creator / Signer / Finalizer /
    //     Extractor) ---------------------------------------------------

    /// The fixture redeem's P2WSH `scriptPubKey`: `00 20 ‖
    /// SHA256(redeem)`.
    fn ms_p2wsh_spk() -> Vec<u8> {
        crate::script::make_p2wsh_lock_script(&crate::address::sha256_script(&ms_redeem())).to_vec()
    }

    /// Creator output for the P2WSH happy-path fixture: one
    /// P2WSH-multisig input with its witness script (no prev tx —
    /// BIP-143 commits the amount via WITNESS_UTXO).
    fn ms_create_p2wsh_psbt() -> PartiallySignedTransaction {
        PartiallySignedTransaction::create(
            ms_unsigned_tx([0x44; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2wsh_spk(),
                prev_tx: None,
                redeem_script: None,
                witness_script: Some(ms_redeem()),
                tap_leaf_script: None,
            }],
        )
        .expect("fixture PSBT builds")
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_p2wsh_branch_writes_witness_utxo_and_witness_script() {
        let psbt = ms_create_p2wsh_psbt();
        let input = &psbt.inputs[0];
        // Witness form: WITNESS_UTXO carries (amount, scriptPubKey);
        // no NON_WITNESS_UTXO, no prev-tx fetch.
        assert!(input.witness_utxo.is_some());
        assert!(input.non_witness_utxo.is_none());
        assert_eq!(input.witness_utxo.as_ref().unwrap().amount, 60_000);
        assert_eq!(input.witness_utxo.as_ref().unwrap().script, ms_p2wsh_spk());
        // WITNESS_SCRIPT (0x05) is W/R on the P2WSH-multisig path.
        assert_eq!(
            input.witness_script.as_deref(),
            Some(ms_redeem().as_slice())
        );
        // The typed fields survive the wire round trip byte-for-byte.
        let parsed =
            PartiallySignedTransaction::parse(&psbt.serialize()).expect("canonical wire parses");
        assert_eq!(parsed, psbt);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_p2wsh_branch_rejections() {
        // Non-canonical witness script (R-MS-3) → UnsupportedInputScript.
        let err = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x44; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2wsh_spk(),
                prev_tx: None,
                redeem_script: None,
                witness_script: Some(vec![0x51]),
                tap_leaf_script: None,
            }],
        )
        .unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // Witness script that commits elsewhere → UtxoMismatch.
        let other_redeem = crate::script::make_multisig_redeem_script(
            2,
            &[ms_pubkey(3), ms_pubkey(4), ms_pubkey(5)],
        )
        .unwrap();
        let err = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x44; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2wsh_spk(),
                prev_tx: None,
                redeem_script: None,
                witness_script: Some(other_redeem),
                tap_leaf_script: None,
            }],
        )
        .unwrap_err();
        assert_eq!(err, PsbtError::UtxoMismatch);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn signer_p2wsh_signs_by_membership_and_rejects_foreign() {
        // The walk-independent primitive: fixture keys 0 and 1 are
        // members, key 7 is foreign.
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        // Idempotent: signing twice is Ok(true) without a second sig.
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        // The second member signs a fresh copy; the foreign key is
        // silently skipped (Ok(false)).
        let mut psbt2 = ms_create_p2wsh_psbt();
        assert!(psbt2.sign_input(0, &ms_key(1)).unwrap());
        let mut psbt3 = ms_create_p2wsh_psbt();
        assert!(!psbt3.sign_input(0, &ms_key(7)).unwrap());
        assert!(psbt3.inputs[0].partial_sigs.is_empty());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn signer_p2wsh_rejections() {
        // Absent WITNESS_SCRIPT → UnsupportedInputScript (the pre-v0.3
        // refusal, preserved for redeem-less P2WSH inputs).
        let mut psbt = ms_create_p2wsh_psbt();
        psbt.inputs[0].witness_script = None;
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // Non-canonical witness script → UnsupportedInputScript.
        let mut psbt = ms_create_p2wsh_psbt();
        psbt.inputs[0].witness_script = Some(vec![0x51]);
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // SHA-256 commitment mismatch → UtxoMismatch.
        let mut psbt = ms_create_p2wsh_psbt();
        let other = crate::script::make_multisig_redeem_script(
            2,
            &[ms_pubkey(3), ms_pubkey(4), ms_pubkey(5)],
        )
        .unwrap();
        psbt.inputs[0].witness_script = Some(other);
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UtxoMismatch);
        // A pinned sighash other than SIGHASH_ALL → UnsupportedSighashType.
        let mut psbt = ms_create_p2wsh_psbt();
        psbt.inputs[0].sighash_type = Some(0x02);
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedSighashType(0x02));
        // A *present* NON_WITNESS_UTXO must still hash to the outpoint
        // (BIP-174 Data Signers Check, optional field).
        let mut psbt = ms_create_p2wsh_psbt();
        psbt.inputs[0].non_witness_utxo = Some(ms_prev_tx());
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UtxoMismatch);
        // Explicit pinned SIGHASH_ALL falls through and signs.
        let mut psbt = ms_create_p2wsh_psbt();
        psbt.inputs[0].sighash_type = Some(PSBT_SIGHASH_ALL);
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalizer_p2wsh_builds_the_bip141_witness_stack() {
        // Only one of two signatures: IncompleteInput, input untouched.
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        let err = psbt.finalize_input(0).unwrap_err();
        assert_eq!(err, PsbtError::IncompleteInput(0));
        assert!(psbt.inputs[0].final_scriptwitness.is_none());
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        // Signatures arrive in reverse script-key order on purpose:
        // the Finalizer re-orders by the script's key order (R-MS-4),
        // never by `PARTIAL_SIG` arrival (the fixture keys sort as
        // nonces 0 < 1 < 2, so reverse nonce order is reverse script
        // order).
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(2)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        // A third member's signature beyond the M=2 threshold is
        // deterministically dropped.
        assert!(psbt.sign_input(0, &ms_key(2)).unwrap());
        psbt.finalize_input(0).expect("M signatures complete");
        let stack_bytes = psbt.inputs[0]
            .final_scriptwitness
            .as_ref()
            .expect("finalized input carries the witness stack");
        let stack = decode_witness_stack(stack_bytes).expect("canonical stack encoding");
        // M + 2 items: empty dummy, M sigs (script-key order —
        // verified against the independent digest in the e2e below),
        // redeem.
        assert_eq!(stack.len(), 4);
        assert!(stack[0].is_empty(), "BIP-141 dummy is the empty item");
        assert_eq!(stack[1].last(), Some(&0x01));
        assert_eq!(stack[2].last(), Some(&0x01));
        assert_eq!(stack[3], ms_redeem());
        // Intermediates stripped, UTXO fields preserved.
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[0].witness_script.is_none());
        assert!(psbt.inputs[0].witness_utxo.is_some());
        // Wrong sighash byte on a member signature blocks the input.
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].partial_sigs[0].1.pop();
        psbt.inputs[0].partial_sigs[0].1.push(0x02);
        let err = psbt.finalize_input(0).unwrap_err();
        assert_eq!(err, PsbtError::IncompleteInput(0));
        // A pinned sighash other than SIGHASH_ALL blocks the input
        // (the `Some(t) != pin` arm of the Finalizer's ОВ-8 check).
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].sighash_type = Some(0x02);
        let err = psbt.finalize_input(0).unwrap_err();
        assert_eq!(err, PsbtError::IncompleteInput(0));
        // The pin matching exactly falls through and finalizes.
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].sighash_type = Some(PSBT_SIGHASH_ALL);
        psbt.finalize_input(0).expect("the matching pin finalizes");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalizer_p2wsh_structural_rejections() {
        // A bare P2WSH input (no witness script) is Incomplete.
        let mut psbt = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x44; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2wsh_spk(),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::IncompleteInput(0)));
        // A non-canonical witness script is UnsupportedInputScript.
        let mut psbt = ms_create_p2wsh_psbt();
        psbt.inputs[0].witness_script = Some(vec![0x51]);
        assert_eq!(
            psbt.finalize_input(0),
            Err(PsbtError::UnsupportedInputScript)
        );
        // A SHA-256 commitment mismatch is UtxoMismatch.
        let mut psbt = ms_create_p2wsh_psbt();
        psbt.inputs[0].witness_script = Some(
            crate::script::make_multisig_redeem_script(
                2,
                &[ms_pubkey(3), ms_pubkey(4), ms_pubkey(5)],
            )
            .unwrap(),
        );
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::UtxoMismatch));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_p2wsh_witness_script_on_a_foreign_input_falls_through() {
        // A `witness_script` on a non-P2WSH input is not a Creator
        // surface yubtc builds: the input falls through to the
        // default `WITNESS_UTXO` arm (the field is dropped —
        // preserve-only semantics for foreign forms).
        let psbt = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x44; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: Some(ms_redeem()),
                tap_leaf_script: None,
            }],
        )
        .expect("the fall-through builds a plain witness input");
        assert!(psbt.inputs[0].witness_utxo.is_some());
        assert!(psbt.inputs[0].witness_script.is_none());
        assert!(psbt.inputs[0].non_witness_utxo.is_none());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extractor_p2wsh_requires_the_witness_stack() {
        // Not finalized → NotFinalized.
        let psbt = ms_create_p2wsh_psbt();
        assert_eq!(psbt.extract_transaction(), Err(PsbtError::NotFinalized));
        // FINAL_SCRIPTSIG on a P2WSH input → IncompleteInput (the
        // symmetrical refusal of the P2SH arm's witness check).
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].final_scriptsig = Some(vec![0x51]);
        let err = psbt.extract_transaction().unwrap_err();
        assert_eq!(err, PsbtError::IncompleteInput(0));
        // Finalized → the wire tx carries the witness stack, an empty
        // scriptSig, and the txid ignores the witness (BIP-141).
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.finalize_input(0).expect("complete quorum");
        let tx = psbt.extract_transaction().expect("complete quorum");
        assert!(tx.vin[0].script.is_empty());
        assert_eq!(tx.vin[0].witness.len(), 4);
        assert!(tx.vin[0].witness[0].is_empty());
        assert!(tx.has_witness());
        assert_eq!(tx.serialize_wire(), tx.serialize_wire());
        // wtxid differs from txid (the witness is in the wire only).
        assert_ne!(tx.wtxid(), tx.id());
    }

    // --- Independent BIP-143 / CHECKMULTISIG-over-witness
    //     verification (e2e evidence, v0.3) ----------------------------

    /// Recompute the BIP-143 SIGHASH_ALL digest of input 0 with
    /// `scriptCode = witness script` via the `bitcoin` crate's
    /// reference implementation — deliberately independent of yubtc's
    /// hand-rolled `bip143_sighash`.
    fn independent_p2wsh_digest(
        wire: &[u8],
        redeem: &[u8],
        amount: u64,
    ) -> Result<[u8; 32], String> {
        use bitcoin::consensus::deserialize;
        use bitcoin::hashes::Hash as _;
        use bitcoin::sighash::{EcdsaSighashType, SighashCache};
        use bitcoin::Amount;
        use bitcoin::ScriptBuf;

        let tx: bitcoin::Transaction = deserialize(wire).map_err(|e| format!("wire parse: {e}"))?;
        if tx.input.len() != 1 {
            return Err("fixture expects a single input".into());
        }
        let script = ScriptBuf::from(redeem.to_vec());
        let digest = SighashCache::new(&tx)
            .p2wsh_signature_hash(0, &script, Amount::from_sat(amount), EcdsaSighashType::All)
            .map_err(|e| format!("bip143: {e}"))?;
        Ok(digest.to_byte_array())
    }

    /// Evaluate a completed P2WSH-multisig spend the way the consensus
    /// interpreter would: read the witness stack, check the empty
    /// dummy (BIP-141), parse the witness script, and greedily match
    /// each signature against the script's keys in order (R-MS-4),
    /// verifying ECDSA over the *independently recomputed* BIP-143
    /// digest.
    fn independent_p2wsh_verify(
        wire: &[u8],
        amount: u64,
        expected_keys: &[[u8; 33]],
    ) -> Result<(), String> {
        use bitcoin::consensus::deserialize;
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let tx: bitcoin::Transaction = deserialize(wire).map_err(|e| format!("wire parse: {e}"))?;
        let txin = &tx.input[0];
        // The BIP-141 wire must carry the marker/flag section.
        if txin.witness.is_empty() {
            return Err("the witness stack is empty on the wire".into());
        }
        let stack: Vec<Vec<u8>> = txin.witness.iter().map(|w| w.to_vec()).collect();
        if stack.len() < 3 {
            return Err("witness needs a dummy, at least one signature, and the script".into());
        }
        if !stack[0].is_empty() {
            return Err(format!(
                "the dummy item must be empty (BIP-141), got {} bytes",
                stack[0].len()
            ));
        }
        let redeem = stack.last().expect("checked above").clone();
        let sigs = &stack[1..stack.len() - 1];

        // Witness script: OP_m ‖ (0x21‖key)×N ‖ OP_n ‖ 0xae.
        if redeem.len() < 3 + 34 || redeem[redeem.len() - 1] != 0xae {
            return Err("witness script is not a CHECKMULTISIG script".into());
        }
        let m = (redeem[0] - 0x50) as usize;
        let n = (redeem[redeem.len() - 2] - 0x50) as usize;
        if m > n || redeem.len() != 3 + 34 * n {
            return Err("witness script is not a canonical quorum".into());
        }
        let mut keys: Vec<&[u8]> = Vec::with_capacity(n);
        for i in 0..n {
            let s = 1 + i * 34;
            if redeem[s] != 0x21 {
                return Err("non-canonical key push".into());
            }
            keys.push(&redeem[s + 1..s + 34]);
        }
        if keys.len() != expected_keys.len()
            || keys
                .iter()
                .zip(expected_keys)
                .any(|(a, b)| *a != b.as_slice())
        {
            return Err("witness-script keys do not match the expected quorum".into());
        }
        if sigs.len() != m {
            return Err(format!("expected {m} signatures, got {}", sigs.len()));
        }

        // Digest + greedy CHECKMULTISIG matching: the BIP-143 digest
        // is recomputed by the reference implementation.
        let digest = independent_p2wsh_digest(wire, &redeem, amount)?;
        let mut key_idx = 0usize;
        for (j, sig) in sigs.iter().enumerate() {
            if sig.last() != Some(&0x01) {
                return Err(format!("signature {j} lacks the SIGHASH_ALL suffix"));
            }
            let der = &sig[..sig.len() - 1];
            let signature = k256::ecdsa::Signature::from_der(der)
                .map_err(|e| format!("signature {j}: bad DER: {e}"))?;
            let mut matched = false;
            while key_idx < keys.len() {
                let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(keys[key_idx])
                    .map_err(|e| format!("key {key_idx}: {e}"))?;
                let verified = vk.verify_prehash(&digest, &signature).is_ok();
                key_idx += 1;
                if verified {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err(format!("signature {j} matches no remaining script key"));
            }
        }
        Ok(())
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2wsh_e2e_two_signers_combine_finalize_extract_independent_verify() {
        // 1. Creator.
        let mut psbt_a = ms_create_p2wsh_psbt();
        // 2. Signer A — membership via the wallet walk (ОВ-9 + R-MS-4).
        let unsigned = sign_psbt_with(
            &TSeed::new(MS_SEED),
            &TPassphrase::EMPTY,
            kdf(),
            &mut psbt_a,
        )
        .expect("walk completes");
        assert!(unsigned.is_empty(), "the walk must sign the member input");
        assert_eq!(psbt_a.inputs[0].partial_sigs.len(), 1);
        // 3. Signer B — direct primitive on the second quorum key.
        let mut psbt_b = ms_create_p2wsh_psbt();
        assert!(psbt_b.sign_input(0, &ms_key(1)).unwrap());
        // 4. Combiner.
        let mut combined = psbt_a.combine(&psbt_b).expect("disjoint signers");
        assert_eq!(combined.inputs[0].partial_sigs.len(), 2);
        // 5. Finalizer.
        combined.finalize();
        assert!(combined.inputs[0].final_scriptwitness.is_some());
        assert!(combined.inputs[0].final_scriptsig.is_none());
        // 6. Extractor.
        let tx = combined.extract_transaction().expect("complete quorum");
        let wire = tx.serialize_wire();
        // 7. Independent consensus-equivalent verification: bitcoin
        //    crate's BIP-143 + local greedy CHECKMULTISIG over the
        //    witness stack.
        independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys())
            .expect("the extracted spend must verify independently");
        // Bit-for-bit pin: the signer order does not change the wire
        // (R-MS-4).
        let mut flip = ms_create_p2wsh_psbt();
        assert!(flip.sign_input(0, &ms_key(1)).unwrap());
        assert!(flip.sign_input(0, &ms_key(0)).unwrap());
        flip.finalize();
        let tx_flip = flip.extract_transaction().expect("complete quorum");
        assert_eq!(tx_flip.serialize_wire(), wire);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2wsh_independent_verifier_rejection_table() {
        // The verifier itself must be exercised on every defensive
        // arm, so a green e2e cannot hide a vacuous checker (the
        // `p2wsh_e2e` test's mutation table plus this table cover the
        // remaining arms).
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.finalize_input(0).expect("2-of-3 quorum is complete");
        let base_tx = psbt.extract_transaction().expect("complete quorum");
        let good_stack = base_tx.vin[0].witness.clone();

        // Digest helper: a multi-input wire is outside the fixture
        // contract (and the reference digest refuses it).
        let two_input = Transaction {
            version: 2,
            vin: base_tx
                .vin
                .clone()
                .into_iter()
                .chain(base_tx.vin.clone())
                .collect(),
            vout: base_tx.vout.clone(),
            locktime: 0,
        };
        let err = independent_p2wsh_digest(&two_input.serialize_wire(), &ms_redeem(), 60_000)
            .unwrap_err();
        assert!(err.contains("single input"), "got: {err}");

        // Wire without a witness section.
        let err =
            independent_p2wsh_verify(&base_tx.serialize_stripped(), 60_000, &ms_redeem_keys())
                .unwrap_err();
        assert!(err.contains("empty on the wire"), "got: {err}");

        // Stack too short to be a quorum spend.
        let wire = {
            let mut tx = base_tx.clone();
            tx.vin[0].witness = vec![Vec::new()];
            tx.serialize_wire()
        };
        let err = independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys()).unwrap_err();
        assert!(err.contains("needs a dummy"), "got: {err}");

        // A quorum whose counters are m > n.
        let bad_script = {
            let mut s = vec![0x53u8, 0x21];
            s.extend_from_slice(&ms_pubkey(0));
            s.push(0x52);
            s.push(0xae);
            s
        };
        let digest_of_bad = {
            // The digest itself does not parse the script: any wire
            // with one input works.
            let mut tx = base_tx.clone();
            tx.vin[0].witness = vec![Vec::new(), vec![0x01], bad_script.clone()];
            tx.serialize_wire()
        };
        let err = independent_p2wsh_verify(&digest_of_bad, 60_000, &ms_redeem_keys()).unwrap_err();
        // m > n is caught before the length check, so the message is
        // deterministic — no tolerant `||` chain here: its never-taken
        // operand would read as a permanent branch gap.
        assert!(err.contains("canonical quorum"), "got: {err}");

        // A witness script too short to carry even one push: the length
        // arm of the CHECKMULTISIG shape check (len < 3 + 34).
        let short_script = vec![0x51u8, 0xae];
        let wire = {
            let mut tx = base_tx.clone();
            tx.vin[0].witness = vec![Vec::new(), vec![0x01], short_script];
            tx.serialize_wire()
        };
        let err = independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys()).unwrap_err();
        assert!(err.contains("not a CHECKMULTISIG"), "got: {err}");

        // Canonical 2-of-2 layout with a corrupted total length: a stray
        // «OP_2 OP_CHECKMULTISIG» tail keeps the terminator (0xae) and
        // the counters sane, so the length arm of the quorum check
        // (len != 3 + 34 * n) is what rejects it.
        let wrong_len = {
            let mut s = vec![0x52u8, 0x21];
            s.extend_from_slice(&ms_pubkey(0));
            s.extend_from_slice(&ms_pubkey(1));
            s.push(0x52);
            s.push(0xae);
            s.extend_from_slice(&[0x52, 0xae]);
            s
        };
        let wire = {
            let mut tx = base_tx.clone();
            tx.vin[0].witness = vec![Vec::new(), vec![0x01], wrong_len];
            tx.serialize_wire()
        };
        let err = independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys()).unwrap_err();
        assert!(err.contains("canonical quorum"), "got: {err}");

        // A non-canonical key push inside the witness script: same
        // total length, the second slot's prefix flipped to 0x20.
        let bad_push = {
            let mut s = ms_redeem();
            s[1 + 34] = 0x20;
            s
        };
        let wire = {
            let mut tx = base_tx.clone();
            tx.vin[0].witness = vec![Vec::new(), vec![0x01], bad_push];
            tx.serialize_wire()
        };
        let err = independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys()).unwrap_err();
        assert!(err.contains("non-canonical key push"), "got: {err}");

        // Witness-script keys that do not match the expected quorum.
        // First by count (the length arm of the comparison), then by
        // content with the arity kept (the pairwise `.any()` arm).
        let other_keys = vec![ms_pubkey(5), ms_pubkey(6)];
        let err =
            independent_p2wsh_verify(&base_tx.serialize_wire(), 60_000, &other_keys).unwrap_err();
        assert!(
            err.contains("do not match the expected quorum"),
            "got: {err}"
        );
        let foreign_keys = vec![ms_pubkey(5), ms_pubkey(6), ms_pubkey(7)];
        let err =
            independent_p2wsh_verify(&base_tx.serialize_wire(), 60_000, &foreign_keys).unwrap_err();
        assert!(
            err.contains("do not match the expected quorum"),
            "got: {err}"
        );

        // Fewer signatures than the threshold.
        let short = vec![
            good_stack[0].clone(),
            good_stack[1].clone(),
            good_stack[3].clone(),
        ];
        let wire = {
            let mut tx = base_tx.clone();
            tx.vin[0].witness = short;
            tx.serialize_wire()
        };
        let err = independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys()).unwrap_err();
        assert!(err.contains("expected 2 signatures, got 1"), "got: {err}");

        // A signature without the SIGHASH_ALL suffix.
        let no_suffix = vec![
            good_stack[0].clone(),
            good_stack[1][..good_stack[1].len() - 1].to_vec(),
            good_stack[2].clone(),
            good_stack[3].clone(),
        ];
        let wire = {
            let mut tx = base_tx.clone();
            tx.vin[0].witness = no_suffix;
            tx.serialize_wire()
        };
        let err = independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys()).unwrap_err();
        assert!(err.contains("lacks the SIGHASH_ALL suffix"), "got: {err}");

        // The digest helper accepts the good wire (used by mutation 3
        // of the mutation test) — the sanity side of the contract.
        assert!(independent_p2wsh_digest(&base_tx.serialize_wire(), &ms_redeem(), 60_000).is_ok());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2wsh_witness_mutations_fail_independent_verification() {
        // A complete spend, decomposed for mutation.
        let mut psbt = ms_create_p2wsh_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.finalize_input(0).expect("2-of-3 quorum is complete");
        let base_tx = psbt.extract_transaction().expect("complete quorum");
        let good_stack = base_tx.vin[0].witness.clone();
        let finalize_to_wire = |stack: Vec<Vec<u8>>| -> Vec<u8> {
            let mut tx = base_tx.clone();
            tx.vin[0].witness = stack;
            tx.serialize_wire()
        };

        // Mutation 1: non-empty dummy item (BIP-141 NULLDUMMY).
        let mut bad = good_stack.clone();
        bad[0] = vec![0x00];
        let wire = finalize_to_wire(bad);
        let err = independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys()).unwrap_err();
        assert!(err.contains("dummy"), "got: {err}");

        // Mutation 2: signatures swapped — the greedy match runs out
        // of script keys.
        let mut bad = good_stack.clone();
        bad.swap(1, 2);
        let wire = finalize_to_wire(bad);
        let err = independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys()).unwrap_err();
        assert!(
            err.contains("matches no remaining script key"),
            "got: {err}"
        );

        // Mutation 3: a signature by a foreign key over the same
        // digest.
        let digest =
            independent_p2wsh_digest(&finalize_to_wire(good_stack.clone()), &ms_redeem(), 60_000)
                .expect("digest");
        let foreign_sig = {
            let sig = crate::privkey::sign_hash(&ms_key(7), &digest);
            let mut der = sig.to_der().as_bytes().to_vec();
            der.push(0x01);
            der
        };
        let mut bad = good_stack.clone();
        bad[2] = foreign_sig;
        let wire = finalize_to_wire(bad);
        let err = independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys()).unwrap_err();
        assert!(
            err.contains("matches no remaining script key"),
            "got: {err}"
        );

        // Mutation 4: the redeem script swapped out — the stack
        // commits to a different quorum than the output. The appended
        // zero byte breaks the 0xae terminator, so the rejection
        // message is deterministic (the tolerant `||` chain here would
        // leave its second operand permanently untaken).
        let mut bad = good_stack.clone();
        bad[3].push(0x00);
        let wire = finalize_to_wire(bad);
        let err = independent_p2wsh_verify(&wire, 60_000, &ms_redeem_keys()).unwrap_err();
        assert!(err.contains("not a CHECKMULTISIG"), "got: {err}");
    }

    #[ntest_timeout::timeout(120_000)]
    #[test]
    fn wallet_walk_leaves_foreign_p2wsh_quorums_unsigned() {
        // A P2WSH-multisig input whose witness script contains none of
        // our keys: the walk must skip it (reported), not error.
        let foreign_keys: Vec<[u8; 33]> = (0..3)
            .map(|i| {
                crate::privkey::privkey_to_pubkey(
                    &seed2privkey_with_kdf(
                        &TSeed::new(format!("foreign p2wsh {i}")),
                        TNonce::new(0),
                        &TPassphrase::EMPTY,
                        kdf(),
                    )
                    .expect("fixture derives"),
                )
            })
            .collect();
        let redeem =
            crate::script::make_multisig_redeem_script(2, &foreign_keys).expect("valid quorum");
        let spk = crate::script::make_p2wsh_lock_script(&crate::address::sha256_script(&redeem));
        let mut psbt = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x55; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: spk.to_vec(),
                prev_tx: None,
                redeem_script: None,
                witness_script: Some(redeem),
                tap_leaf_script: None,
            }],
        )
        .expect("fixture PSBT builds");
        let unsigned = sign_psbt_with(&TSeed::new(MS_SEED), &TPassphrase::EMPTY, kdf(), &mut psbt)
            .expect("walk completes");
        assert_eq!(unsigned, vec![0]);
        assert!(psbt.inputs[0].partial_sigs.is_empty());
    }

    // --- v0.3: P2TR script-path multisig (Creator / Signer /
    //     Finalizer / Extractor) --------------------------------------

    /// The fixture quorum's canonical tapscript (R-MS-7) over the
    /// x-only projections of the fixture keys (BIP-67 sort by the
    /// x-only bytes, R-MS-10).
    fn ms_tapscript() -> Vec<u8> {
        let xonly: Vec<[u8; 32]> = (0..3)
            .map(|i| {
                let pk = ms_pubkey(i);
                pk[1..33].try_into().expect("33-byte key by type")
            })
            .collect();
        crate::script::make_multisig_tapscript(2, &xonly).expect("fixture quorum is valid")
    }

    /// For each fixture nonce, its position in the tapscript's
    /// x-only-sorted key order (R-MS-10 — not necessarily the nonce
    /// order).
    fn ms_script_position(nonce: u32) -> usize {
        let xonly: [u8; 32] = ms_pubkey(nonce)[1..33].try_into().expect("33-byte key");
        ms_tapscript_keys()
            .iter()
            .position(|k| *k == xonly)
            .expect("fixture key is in the script")
    }

    /// The fixture tapscript's keys in script (sorted) order.
    fn ms_tapscript_keys() -> Vec<[u8; 32]> {
        crate::script::extract_multisig_tapscript(&ms_tapscript())
            .expect("fixture tapscript is canonical")
            .1
    }

    /// The fixture leaf's `TAP_LEAF_SCRIPT` value: `script ‖ 0xc0`.
    fn ms_tap_leaf_value() -> Vec<u8> {
        let mut v = ms_tapscript();
        v.push(crate::script::TAPSCRIPT_LEAF_VERSION);
        v
    }

    /// The fixture leaf's control block (`c[0] ‖ NUMS H`).
    fn ms_tap_control_block() -> Vec<u8> {
        crate::address::tapscript_control_block(
            &MS_TAPSCRIPT_INTERNAL_KEY,
            &crate::script::tapscript_leaf_hash(&ms_tapscript()),
        )
        .expect("NUMS lift and tweak are total")
        .to_vec()
    }

    /// The fixture quorum's P2TR `scriptPubKey`: `51 20 ‖ x(Q)`.
    fn ms_p2tr_spk() -> Vec<u8> {
        ms_p2tr_spk_for(&ms_tapscript())
    }

    /// The P2TR `scriptPubKey` committing to the tweaked NUMS output
    /// key of the given tapscript's single leaf.
    fn ms_p2tr_spk_for(script: &[u8]) -> Vec<u8> {
        let leaf_hash = crate::script::tapscript_leaf_hash(script);
        let output = crate::address::tapscript_output_key(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)
            .expect("NUMS lift and tweak are total");
        crate::script::make_p2tr_lock_script(&output).to_vec()
    }

    /// Creator output for the P2TR script-path happy-path fixture.
    fn ms_create_p2tr_psbt() -> PartiallySignedTransaction {
        PartiallySignedTransaction::create(
            ms_unsigned_tx([0x77; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2tr_spk(),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: Some(ms_tap_leaf_value()),
            }],
        )
        .expect("fixture PSBT builds")
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_p2tr_branch_writes_tap_fields_and_witness_utxo() {
        let psbt = ms_create_p2tr_psbt();
        let input = &psbt.inputs[0];
        // Witness form: WITNESS_UTXO carries (amount, scriptPubKey);
        // no NON_WITNESS_UTXO, no prev-tx fetch.
        assert!(input.witness_utxo.is_some());
        assert!(input.non_witness_utxo.is_none());
        assert_eq!(input.witness_utxo.as_ref().unwrap().amount, 60_000);
        assert_eq!(input.witness_utxo.as_ref().unwrap().script, ms_p2tr_spk());
        // TAP_LEAF_SCRIPT (0x15): control-block keydata, script ‖ 0xc0
        // value.
        assert_eq!(input.tap_leaf_scripts.len(), 1);
        assert_eq!(
            input.tap_leaf_scripts[0].control_block,
            ms_tap_control_block()
        );
        assert_eq!(
            input.tap_leaf_scripts[0].script_with_version,
            ms_tap_leaf_value()
        );
        // TAP_INTERNAL_KEY (0x17): the NUMS key. TAP_MERKLE_ROOT is
        // never written (the root is computable from 0x15).
        assert_eq!(input.tap_internal_key, Some(MS_TAPSCRIPT_INTERNAL_KEY));
        assert!(input.tap_merkle_root.is_none());
        // The typed fields survive the wire round trip byte-for-byte.
        let parsed =
            PartiallySignedTransaction::parse(&psbt.serialize()).expect("canonical wire parses");
        assert_eq!(parsed, psbt);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn creator_p2tr_branch_rejections_and_fall_through() {
        // Non-canonical leaf version byte (not exactly 0xc0) →
        // UnsupportedInputScript.
        let mut bad_leaf = ms_tap_leaf_value();
        *bad_leaf.last_mut().unwrap() = 0xc1;
        let err = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x77; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2tr_spk(),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: Some(bad_leaf),
            }],
        )
        .unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // Non-canonical script inside the leaf value (CHECKMULTISIG
        // byte instead of NUMEQUAL terminus) → UnsupportedInputScript.
        let mut bad_script = ms_tap_leaf_value();
        let n = bad_script.len();
        bad_script[n - 2] = crate::script::OP_CHECKMULTISIG;
        let err = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x77; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2tr_spk(),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: Some(bad_script),
            }],
        )
        .unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // A leaf committing to a different output key → UtxoMismatch.
        let other = {
            let xonly: Vec<[u8; 32]> = (4..7)
                .map(|i| {
                    let pk = ms_pubkey(i);
                    pk[1..33].try_into().expect("33-byte key by type")
                })
                .collect();
            let mut v = crate::script::make_multisig_tapscript(2, &xonly).expect("valid quorum");
            v.push(crate::script::TAPSCRIPT_LEAF_VERSION);
            v
        };
        let err = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x77; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2tr_spk(),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: Some(other),
            }],
        )
        .unwrap_err();
        assert_eq!(err, PsbtError::UtxoMismatch);
        // A tap leaf on a foreign (non-P2TR) input falls through to
        // the plain WITNESS_UTXO arm; the field is dropped.
        let psbt = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x77; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: fixture_spk(0, AddrType::Native),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: Some(ms_tap_leaf_value()),
            }],
        )
        .expect("the fall-through builds a plain witness input");
        assert!(psbt.inputs[0].witness_utxo.is_some());
        assert!(psbt.inputs[0].tap_leaf_scripts.is_empty());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn signer_p2tr_scriptpath_signs_members_skips_foreign() {
        // The walk-independent primitive: fixture keys 0 and 1 are
        // members, key 7 is foreign.
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
        // The signature is keyed by (x-only ‖ leaf_hash) and is
        // exactly 64 bytes (ОВ-17 — no sighash suffix).
        let entry = &psbt.inputs[0].tap_script_sigs[0];
        assert_eq!(
            entry.x_only,
            ms_tapscript_keys()
                .iter()
                .find(|k| **k == ms_pubkey(0)[1..33])
                .copied()
                .expect("member key is in the script")
        );
        assert_eq!(
            entry.leaf_hash,
            crate::script::tapscript_leaf_hash(&ms_tapscript())
        );
        assert_eq!(entry.sig.len(), 64);
        // Idempotent: signing twice is Ok(true) without a second sig.
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
        // The second member signs a fresh copy; the foreign key is
        // silently skipped (Ok(false)).
        let mut psbt2 = ms_create_p2tr_psbt();
        assert!(psbt2.sign_input(0, &ms_key(1)).unwrap());
        let mut psbt3 = ms_create_p2tr_psbt();
        assert!(!psbt3.sign_input(0, &ms_key(7)).unwrap());
        assert!(psbt3.inputs[0].tap_script_sigs.is_empty());
        // Without TAP_LEAF_SCRIPT the input is a key-path P2TR: the
        // member key does not tweak to the NUMS output key → skipped.
        let mut psbt4 = ms_create_p2tr_psbt();
        psbt4.inputs[0].tap_leaf_scripts.clear();
        assert!(!psbt4.sign_input(0, &ms_key(0)).unwrap());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn signer_p2tr_scriptpath_rejections() {
        // Corrupted control block (internal key flipped) →
        // UnsupportedInputScript.
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].tap_leaf_scripts[0].control_block[5] ^= 0xff;
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // A control block of the wrong LENGTH (a foreign multi-leaf
        // depth-1 block is 65 bytes; any non-33 is refused) →
        // UnsupportedInputScript.
        let mut psbt = ms_create_p2tr_psbt();
        let mut long_cb = ms_tap_control_block();
        long_cb.extend_from_slice(&[0x11; 32]);
        psbt.inputs[0].tap_leaf_scripts[0].control_block = long_cb;
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // Without COMPLETE UTXO data the BIP-341 digest (it commits
        // to all inputs) is not computable — the input is skipped
        // (Ok(false)), not an error. The input under signing keeps
        // its UTXO (the dispatch needs it); a second input loses
        // its field, which starves `spend_context`.
        let two = PartiallySignedTransaction::create(
            Transaction {
                version: 2,
                vin: vec![
                    TxIn {
                        txhash: [0x81; 32],
                        n: 0,
                        script: vec![],
                        sequence: 0xffff_fffe,
                        witness: Vec::new(),
                    },
                    TxIn {
                        txhash: [0x82; 32],
                        n: 0,
                        script: vec![],
                        sequence: 0xffff_fffe,
                        witness: Vec::new(),
                    },
                ],
                vout: vec![TxOut {
                    amount: 1_000,
                    script: fixture_spk(9, AddrType::Native),
                }],
                locktime: 0,
            },
            vec![
                CreateInput {
                    amount: 60_000,
                    script_pubkey: ms_p2tr_spk(),
                    prev_tx: None,
                    redeem_script: None,
                    witness_script: None,
                    tap_leaf_script: Some(ms_tap_leaf_value()),
                },
                CreateInput {
                    amount: 10_000,
                    script_pubkey: fixture_spk(0, AddrType::Native),
                    prev_tx: None,
                    redeem_script: None,
                    witness_script: None,
                    tap_leaf_script: None,
                },
            ],
        )
        .expect("two-input fixture builds");
        let mut two = two;
        two.inputs[1].witness_utxo = None;
        assert!(!two.sign_input(0, &ms_key(0)).unwrap());
        assert!(two.inputs[0].tap_script_sigs.is_empty());
        // Wrong leaf version in c[0] (0x80 & 0xfe ≠ 0xc0) →
        // UnsupportedInputScript.
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].tap_leaf_scripts[0].control_block[0] = 0x80;
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // Wrong leaf version byte in the value → UnsupportedInputScript.
        let mut psbt = ms_create_p2tr_psbt();
        let n = psbt.inputs[0].tap_leaf_scripts[0].script_with_version.len();
        psbt.inputs[0].tap_leaf_scripts[0].script_with_version[n - 1] = 0xbe;
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // Non-canonical tapscript → UnsupportedInputScript.
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].tap_leaf_scripts[0].script_with_version = vec![0x51, 0xc0];
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedInputScript);
        // Tweak commitment mismatch (leaf ↔ UTXO program) →
        // UtxoMismatch.
        let mut psbt = ms_create_p2tr_psbt();
        let other_keys: Vec<[u8; 32]> = (4..7)
            .map(|i| {
                let pk = ms_pubkey(i);
                pk[1..33].try_into().expect("33-byte key by type")
            })
            .collect();
        let mut other = crate::script::make_multisig_tapscript(2, &other_keys).unwrap();
        other.push(crate::script::TAPSCRIPT_LEAF_VERSION);
        psbt.inputs[0].tap_leaf_scripts[0].script_with_version = other;
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UtxoMismatch);
        // A present TAP_MERKLE_ROOT that disagrees with the computed
        // leaf hash → UtxoMismatch.
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].tap_merkle_root = Some([0x11; 32]);
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UtxoMismatch);
        // The exact leaf hash as the root is accepted (the single-leaf
        // tree root IS the leaf hash).
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].tap_merkle_root = Some(crate::script::tapscript_leaf_hash(&ms_tapscript()));
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        // A pinned sighash other than SIGHASH_DEFAULT (ОВ-17) →
        // UnsupportedSighashType.
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].sighash_type = Some(0x01);
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UnsupportedSighashType(0x01));
        // Explicit SIGHASH_DEFAULT falls through and signs.
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].sighash_type = Some(PSBT_SIGHASH_DEFAULT);
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        // A *present* NON_WITNESS_UTXO must still hash to the outpoint
        // (BIP-174 Data Signers Check, optional field).
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].non_witness_utxo = Some(ms_prev_tx());
        let err = psbt.sign_input(0, &ms_key(0)).unwrap_err();
        assert_eq!(err, PsbtError::UtxoMismatch);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalizer_p2tr_builds_the_reverse_slot_witness() {
        // Only one of two signatures: IncompleteInput, input untouched.
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        let err = psbt.finalize_input(0).unwrap_err();
        assert_eq!(err, PsbtError::IncompleteInput(0));
        assert!(psbt.inputs[0].final_scriptwitness.is_none());
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
        // Signatures arrive in reverse script-key order on purpose:
        // the Finalizer maps them to per-key slots (R-MS-11), never by
        // arrival order. The fixture keys sort as nonces 0 < 1 < 2, so
        // reverse nonce order is reverse script order.
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        psbt.finalize_input(0).expect("M signatures complete");
        let stack_bytes = psbt.inputs[0]
            .final_scriptwitness
            .as_ref()
            .expect("finalized input carries the witness stack");
        let stack = decode_witness_stack(stack_bytes).expect("canonical stack encoding");
        // N + 2 items: the N reverse-order slots (exactly M
        // non-empty), the tapscript, the control block. No dummy
        // element. Slot i of the stack carries the signature of the
        // (N−1−i)-th script key — the R-MS-11 reversal.
        assert_eq!(stack.len(), 5);
        let p0 = ms_script_position(0);
        let p1 = ms_script_position(1);
        for (pos, sig) in [(p0, 0usize), (p1, 1usize)] {
            let stack_idx = 2 - pos; // reverse: stack[i] ↔ script key N−1−i
            assert_eq!(
                stack[stack_idx].len(),
                64,
                "script position {pos} carries signer {sig}'s 64-byte signature"
            );
        }
        // Exactly M non-empty slots (the count covers the slots only;
        // the script and the control block close the stack).
        assert_eq!(stack[..3].iter().filter(|s| !s.is_empty()).count(), 2);
        assert_eq!(stack[3], ms_tapscript());
        assert_eq!(stack[4], ms_tap_control_block());
        // Intermediates stripped (BIP-371 mandate), UTXO preserved.
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        assert!(psbt.inputs[0].tap_leaf_scripts.is_empty());
        assert!(psbt.inputs[0].tap_internal_key.is_none());
        assert!(psbt.inputs[0].sighash_type.is_none());
        assert!(psbt.inputs[0].witness_utxo.is_some());
        // A wrong-length signature on a member key blocks the input
        // (the validation table: «подпись 0x14 ≠ 64 байта»).
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].tap_script_sigs[0].sig.pop();
        let err = psbt.finalize_input(0).unwrap_err();
        assert_eq!(err, PsbtError::IncompleteInput(0));
        // A pinned sighash other than SIGHASH_DEFAULT blocks the input.
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].sighash_type = Some(0x02);
        let err = psbt.finalize_input(0).unwrap_err();
        assert_eq!(err, PsbtError::IncompleteInput(0));
        // The matching pin falls through and finalizes.
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].sighash_type = Some(PSBT_SIGHASH_DEFAULT);
        psbt.finalize_input(0).expect("the matching pin finalizes");
        // «Over-signing»: all three members signed — the Finalizer
        // deterministically drops the tail beyond M (CHECKSIGADD would
        // count 3 ≠ 2 and invalidate the spend); the third key's slot
        // stays empty.
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(2)).unwrap());
        psbt.finalize_input(0)
            .expect("extras dropped, quorum complete");
        let stack =
            decode_witness_stack(psbt.inputs[0].final_scriptwitness.as_ref().unwrap()).unwrap();
        assert_eq!(stack.len(), 5);
        assert_eq!(
            stack[..3].iter().filter(|s| !s.is_empty()).count(),
            2,
            "exactly M non-empty slots"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn finalizer_p2tr_structural_rejections() {
        // A bare P2TR input (no tap leaf) is Incomplete (the key-path
        // arm finds no matching signature).
        let mut psbt = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x77; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: ms_p2tr_spk(),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .unwrap();
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::IncompleteInput(0)));
        // A corrupted control block is UnsupportedInputScript.
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].tap_leaf_scripts[0].control_block[1] ^= 0xff;
        assert_eq!(
            psbt.finalize_input(0),
            Err(PsbtError::UnsupportedInputScript)
        );
        // A control block of the wrong length is UnsupportedInputScript.
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].tap_leaf_scripts[0]
            .control_block
            .truncate(32);
        assert_eq!(
            psbt.finalize_input(0),
            Err(PsbtError::UnsupportedInputScript)
        );
        // A wrong leaf version in c[0] is UnsupportedInputScript.
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].tap_leaf_scripts[0].control_block[0] = 0x80;
        assert_eq!(
            psbt.finalize_input(0),
            Err(PsbtError::UnsupportedInputScript)
        );
        // A wrong leaf-version byte in the value is
        // UnsupportedInputScript.
        let mut psbt = ms_create_p2tr_psbt();
        let n = psbt.inputs[0].tap_leaf_scripts[0].script_with_version.len();
        psbt.inputs[0].tap_leaf_scripts[0].script_with_version[n - 1] = 0xbe;
        assert_eq!(
            psbt.finalize_input(0),
            Err(PsbtError::UnsupportedInputScript)
        );
        // A present TAP_MERKLE_ROOT that disagrees with the computed
        // leaf hash is UtxoMismatch…
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].tap_merkle_root = Some([0x33; 32]);
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::UtxoMismatch));
        // …while the exact leaf hash (the single-leaf tree root)
        // finalizes normally.
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].tap_merkle_root = Some(crate::script::tapscript_leaf_hash(&ms_tapscript()));
        psbt.finalize_input(0).expect("the exact root finalizes");
        // A non-canonical leaf (the tiny «script» 0x51 does not parse
        // as the R-MS-7 idiom) is UnsupportedInputScript.
        let mut psbt = ms_create_p2tr_psbt();
        psbt.inputs[0].tap_leaf_scripts[0].script_with_version = vec![0x51u8, 0xc0];
        assert_eq!(
            psbt.finalize_input(0),
            Err(PsbtError::UnsupportedInputScript)
        );
        // A canonical leaf committing elsewhere is UtxoMismatch.
        let mut psbt = ms_create_p2tr_psbt();
        let other_keys: Vec<[u8; 32]> = (4..7)
            .map(|i| {
                let pk = ms_pubkey(i);
                pk[1..33].try_into().expect("33-byte key by type")
            })
            .collect();
        let mut other = crate::script::make_multisig_tapscript(2, &other_keys).unwrap();
        other.push(crate::script::TAPSCRIPT_LEAF_VERSION);
        psbt.inputs[0].tap_leaf_scripts[0].script_with_version = other;
        assert_eq!(psbt.finalize_input(0), Err(PsbtError::UtxoMismatch));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extractor_p2tr_scriptpath_requires_the_witness_stack() {
        // Not finalized → NotFinalized.
        let psbt = ms_create_p2tr_psbt();
        assert_eq!(psbt.extract_transaction(), Err(PsbtError::NotFinalized));
        // FINAL_SCRIPTSIG on a P2TR script-path input → IncompleteInput
        // (the symmetrical refusal of the P2WSH arm).
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.inputs[0].final_scriptsig = Some(vec![0x51]);
        let err = psbt.extract_transaction().unwrap_err();
        assert_eq!(err, PsbtError::IncompleteInput(0));
        // Finalized → the wire tx carries the witness stack, an empty
        // scriptSig, and the txid ignores the witness (BIP-141).
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.finalize_input(0).expect("complete quorum");
        let tx = psbt.extract_transaction().expect("complete quorum");
        assert!(tx.vin[0].script.is_empty());
        assert_eq!(tx.vin[0].witness.len(), 5);
        assert!(tx.has_witness());
        assert_ne!(tx.wtxid(), tx.id());

        // A KEY-PATH P2TR input (no TAP_LEAF_SCRIPT — a personal
        // BIP-86 spend) is NOT subject to the scriptSig refusal: a
        // finalized key-path witness extracts even with an injected
        // (nonsensical) FINAL_SCRIPTSIG, because no tap leaf exists
        // to conflict with.
        let internal = ms_key(0);
        let xonly: [u8; 32] = crate::privkey::privkey_to_pubkey(&internal)[1..33]
            .try_into()
            .expect("33-byte key");
        let output = crate::address::taproot_output_key(&xonly).expect("BIP-86 tweak is total");
        let spk = crate::script::make_p2tr_lock_script(&output).to_vec();
        let mut keypath = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x77; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: spk,
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: None,
            }],
        )
        .expect("key-path fixture builds");
        assert!(keypath.sign_input(0, &internal).unwrap());
        keypath.finalize_input(0).expect("key-path finalizes");
        keypath.inputs[0].final_scriptsig = Some(vec![0x51, 0x52]);
        let tx = keypath
            .extract_transaction()
            .expect("key-path spend extracts");
        assert_eq!(tx.vin[0].witness.len(), 1);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_psbt_fields_parse_reject_wrong_shapes() {
        // 0x14 keydata must be exactly 64 bytes (x-only ‖ leaf_hash).
        let short_key = {
            let mut k = vec![0x14u8];
            k.extend_from_slice(&[0xaa; 63]);
            k
        };
        let hand = assemble(
            &[kv(&[T_ZERO], &stub_tx_bytes())],
            &[kv(&short_key, &[0xff; 64])],
            &[],
        );
        assert_eq!(
            PartiallySignedTransaction::parse(&hand).unwrap_err(),
            PsbtError::InvalidKeyLength(0x14)
        );
        // 0x15 keydata must be exactly 33 bytes (the single-leaf
        // control block, `33 + 32·depth` at depth 0).
        let bad_cb = {
            let mut k = vec![0x15u8];
            k.extend_from_slice(&[0xaa; 34]);
            k
        };
        let hand = assemble(
            &[kv(&[T_ZERO], &stub_tx_bytes())],
            &[kv(&bad_cb, &[0x51, 0xc0])],
            &[],
        );
        assert_eq!(
            PartiallySignedTransaction::parse(&hand).unwrap_err(),
            PsbtError::InvalidKeyLength(0x15)
        );
        // 0x17 and 0x18 values must be 32 bytes ("no key data" fields
        // with fixed-width values).
        for (ty, value_len) in [(0x17u8, 31usize), (0x18, 31)] {
            let mut pair = vec![1u8, ty];
            pair.push(value_len as u8);
            pair.extend(std::iter::repeat(0xaau8).take(value_len));
            let hand = assemble(&[kv(&[T_ZERO], &stub_tx_bytes())], &[pair], &[]);
            assert_eq!(
                PartiallySignedTransaction::parse(&hand).unwrap_err(),
                PsbtError::InvalidFieldValue
            );
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_typed_field_parse_shapes_close_the_table() {
        // 0x15 with a valid 33-byte control-block keydata but an
        // empty value (the script ‖ leaf-version is mandatory).
        let cb_key = {
            let mut k = vec![0x15u8];
            k.extend_from_slice(&[0xaa; 33]);
            k
        };
        let hand = assemble(&[kv(&[T_ZERO], &stub_tx_bytes())], &[kv(&cb_key, &[])], &[]);
        assert_eq!(
            PartiallySignedTransaction::parse(&hand).unwrap_err(),
            PsbtError::InvalidFieldValue
        );

        // 0x17 and 0x18 are "no key data" fields: any keydata is an
        // InvalidKeyLength refusal.
        for ty in [0x17u8, 0x18] {
            let mut key = vec![ty];
            key.extend_from_slice(&[0xaa; 4]); // 4 bytes of keydata
            let hand = assemble(&[kv(&[T_ZERO], &stub_tx_bytes())], &[kv(&key, &[])], &[]);
            assert_eq!(
                PartiallySignedTransaction::parse(&hand).unwrap_err(),
                PsbtError::InvalidKeyLength(ty)
            );
        }

        // A valid 0x18 (32-byte root) parses into the typed field —
        // yubtc's Creator never writes it, but a foreign container
        // carrying one must round trip (the Signer verifies it).
        // The stub tx has one output too, so an empty output map
        // closes the container.
        let hand = assemble(
            &[kv(&[T_ZERO], &stub_tx_bytes())],
            &[kv(&[0x18], &[0x22; 32])],
            &[Vec::new()],
        );
        let parsed = PartiallySignedTransaction::parse(&hand).expect("valid 0x18 parses");
        assert_eq!(parsed.inputs[0].tap_merkle_root, Some([0x22; 32]));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_merkle_root_serializes_when_present() {
        // The serializer supports 0x18 for foreign/preserve data even
        // though yubtc's own Creator leaves the root unset (it is
        // computable from TAP_LEAF_SCRIPT): setting the field and
        // round-tripping the container keeps it byte-faithful.
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.inputs[0].tap_merkle_root.is_none());
        psbt.inputs[0].tap_merkle_root = Some([0x22; 32]);
        let parsed = PartiallySignedTransaction::parse(&psbt.serialize())
            .expect("a container with 0x18 parses");
        assert_eq!(parsed, psbt);
        assert_eq!(parsed.inputs[0].tap_merkle_root, Some([0x22; 32]));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tap_bip32_derivation_0x16_is_preserved_verbatim() {
        // ОВ-18: TAP_BIP32_DERIVATION (0x16) is preserve-only — the
        // Signer ignores it entirely and the field flows through the
        // whole pipeline byte-for-byte (in `unknown`).
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        let mut key = vec![0x16u8];
        key.extend_from_slice(&[0x33; 32]); // x-only pubkey keydata
        let value: Vec<u8> = [0x01u8]
            .into_iter()
            .chain([0u8; 4])
            .chain([0u8; 4])
            .chain([0x22; 32]) // a leaf hash the Signer must not read
            .collect();
        psbt.inputs[0].unknown.push(UnknownKv {
            key: key.clone(),
            value: value.clone(),
        });
        let mut parsed = PartiallySignedTransaction::parse(&psbt.serialize())
            .expect("preserve-only field parses");
        assert_eq!(parsed, psbt);
        assert_eq!(parsed.inputs[0].unknown.len(), 1);
        assert_eq!(parsed.inputs[0].unknown[0].key, key);
        assert_eq!(parsed.inputs[0].unknown[0].value, value);
        // …and it is untouched by signing and finalization.
        assert!(parsed.sign_input(0, &ms_key(1)).unwrap());
        let mut finalized = parsed;
        finalized.finalize_input(0).expect("quorum complete");
        assert_eq!(finalized.inputs[0].unknown.len(), 1);
        assert_eq!(finalized.inputs[0].unknown[0].key, key);
        assert_eq!(finalized.inputs[0].unknown[0].value, value);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn combine_p2tr_tap_script_sigs_is_order_independent() {
        // Spec property: arbitrary TAP_SCRIPT_SIG insertion order —
        // the same final witness (deterministic serialization).
        let mut a = ms_create_p2tr_psbt();
        assert!(a.sign_input(0, &ms_key(0)).unwrap());
        let mut b = ms_create_p2tr_psbt();
        assert!(b.sign_input(0, &ms_key(1)).unwrap());
        let ab = a.combine(&b).expect("disjoint signers");
        let ba = b.combine(&a).expect("disjoint signers");
        // The merged maps are equal regardless of combine order (the
        // typed list is sorted).
        assert_eq!(ab, ba);
        let mut ab = ab;
        ab.finalize();
        let mut ba = ba;
        ba.finalize();
        assert_eq!(ab.serialize(), ba.serialize());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn combine_typed_list_merge_is_idempotent_and_detects_conflicts() {
        // Two containers carrying the SAME TAP_SCRIPT_SIG (deterministic
        // signing makes the re-signed twin byte-identical): the typed
        // list merge keeps one entry — identical keys with identical
        // values are a no-op, not a conflict.
        let mut a = ms_create_p2tr_psbt();
        assert!(a.sign_input(0, &ms_key(0)).unwrap());
        let mut b = ms_create_p2tr_psbt();
        assert!(b.sign_input(0, &ms_key(0)).unwrap());
        assert_eq!(a.inputs[0].tap_script_sigs, b.inputs[0].tap_script_sigs);
        let combined = a.combine(&b).expect("identical entries merge");
        assert_eq!(combined.inputs[0].tap_script_sigs.len(), 1);

        // The same key with a DIFFERENT value is a ConflictingField —
        // for both typed lists (TAP_SCRIPT_SIG and TAP_LEAF_SCRIPT).
        let mut flipped = ms_create_p2tr_psbt();
        assert!(flipped.sign_input(0, &ms_key(0)).unwrap());
        flipped.inputs[0].tap_script_sigs[0].sig[0] ^= 0x01;
        assert_eq!(
            a.combine(&flipped).unwrap_err(),
            PsbtError::ConflictingField
        );

        let mut other_leaf = ms_create_p2tr_psbt();
        other_leaf.inputs[0].tap_leaf_scripts[0].script_with_version[0] ^= 0x01;
        assert_eq!(
            a.combine(&other_leaf).unwrap_err(),
            PsbtError::ConflictingField
        );
    }

    #[ntest_timeout::timeout(30_000)]
    #[test]
    fn p2tr_e2e_n8_exercises_the_extended_leaf_size_in_the_verifier() {
        // N = 8 makes the leaf 34·8 + 2 = 274 ≥ 253 bytes: the
        // verifier's independent leaf-hash construction must take the
        // two-byte (0xFD) CompactSize branch for the script length.
        // The 8-of-8 quorum is spendable (R-MS-9: ≤ 15) and every
        // member signs.
        let xonly: Vec<[u8; 32]> = (0..8)
            .map(|i| {
                let pk = ms_pubkey(i);
                pk[1..33].try_into().expect("33-byte key by type")
            })
            .collect();
        let script = crate::script::make_multisig_tapscript(8, &xonly)
            .expect("8-of-8 is within the quorum bound");
        assert!(script.len() >= 0xfd, "the leaf must need 0xFD encoding");
        // The verifier pairs slots with the keys in SCRIPT (sorted)
        // order (R-MS-10 BIP-67), not the construction order.
        let (m, script_keys) = crate::script::extract_multisig_tapscript(&script)
            .expect("fixture tapscript is canonical");
        assert_eq!((m, script_keys.len()), (8, 8));
        let mut leaf_value = script.clone();
        leaf_value.push(crate::script::TAPSCRIPT_LEAF_VERSION);
        let spk = ms_p2tr_spk_for(&script);

        let mut psbt = PartiallySignedTransaction::create(
            ms_unsigned_tx([0x77; 32]),
            vec![CreateInput {
                amount: 60_000,
                script_pubkey: spk.clone(),
                prev_tx: None,
                redeem_script: None,
                witness_script: None,
                tap_leaf_script: Some(leaf_value),
            }],
        )
        .expect("fixture PSBT builds");
        for i in 0..8 {
            assert!(psbt.sign_input(0, &ms_key(i)).unwrap(), "member {i} signs");
        }
        psbt.finalize();
        let tx = psbt.extract_transaction().expect("complete 8-of-8");
        let wire = tx.serialize_wire();
        assert_eq!(tx.vin[0].witness.len(), 8 + 2);
        independent_tapscript_verify(&wire, &spk, 60_000, &script_keys, &script)
            .expect("the N = 8 spend verifies independently");
    }

    /// A finalized (M = 2 signatures) 2-of-3 script-path spend wire —
    /// the base fixture of the verifier mutation tests.
    fn ms_finalized_p2tr_tx() -> crate::transaction::Transaction {
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.finalize_input(0).expect("2-of-3 quorum is complete");
        psbt.extract_transaction().expect("complete quorum")
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2tr_verifier_rejects_a_non_canonical_leaf_idiom() {
        // The verifier re-checks canonicality (R-MS-7) beyond the
        // expected-script equality: a leaf ending in NUMEQUALVERIFY
        // (0x9c) — with its OWN consistent control block and output
        // commitment, so every earlier check passes — is refused as
        // not the canonical quorum idiom.
        let mut noncanonical = ms_tapscript();
        *noncanonical.last_mut().unwrap() = 0x9c;
        let leaf_hash = crate::script::tapscript_leaf_hash(&noncanonical);
        let control =
            crate::address::tapscript_control_block(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)
                .expect("NUMS tweak is total");
        let output = crate::address::tapscript_output_key(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)
            .expect("NUMS tweak is total");
        let spk = crate::script::make_p2tr_lock_script(&output).to_vec();

        // The finalized 2-of-3 e2e spend, its leaf swapped for the
        // non-canonical twin (slots kept: the layout check runs
        // before the idiom check).
        let mut tx = ms_finalized_p2tr_tx();
        let n = tx.vin[0].witness.len();
        tx.vin[0].witness[n - 2] = noncanonical.clone();
        tx.vin[0].witness[n - 1] = control.to_vec();

        let err = independent_tapscript_verify(
            &tx.serialize_wire(),
            &spk,
            60_000,
            &ms_tapscript_keys(),
            &noncanonical,
        )
        .unwrap_err();
        assert!(err.contains("not the canonical quorum idiom"), "got: {err}");

        // An over-threshold M byte on a same-length leaf (M = 4 on a
        // 3-key script) — CHECKSIGADD would count at most 3, so the
        // quorum could never be met — is refused the same way.
        let mut overm = ms_tapscript();
        let om = overm.len();
        overm[om - 2] = 0x54; // OP_4 threshold over N = 3 keys
        let om_leaf = crate::script::tapscript_leaf_hash(&overm);
        let om_control =
            crate::address::tapscript_control_block(&MS_TAPSCRIPT_INTERNAL_KEY, &om_leaf)
                .expect("NUMS tweak is total");
        let om_output = crate::address::tapscript_output_key(&MS_TAPSCRIPT_INTERNAL_KEY, &om_leaf)
            .expect("NUMS tweak is total");
        let om_spk = crate::script::make_p2tr_lock_script(&om_output).to_vec();
        let mut tx = ms_finalized_p2tr_tx();
        let n = tx.vin[0].witness.len();
        tx.vin[0].witness[n - 2] = overm.clone();
        tx.vin[0].witness[n - 1] = om_control.to_vec();
        let err = independent_tapscript_verify(
            &tx.serialize_wire(),
            &om_spk,
            60_000,
            &ms_tapscript_keys(),
            &overm,
        )
        .unwrap_err();
        assert!(err.contains("not the canonical quorum idiom"), "got: {err}");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2tr_verifier_rejects_a_leaf_size_mismatch() {
        // A 2-of-2 leaf revealed against N = 3 expected keys: the
        // stack layout matches (N + 2 items), the leaf is self-
        // consistent (own control block and output commitment), but
        // its size is not 34·N + 2 — the idiom check catches the
        // disagreement between the revealed script and the quorum.
        let keys = ms_tapscript_keys();
        let short_script = crate::script::make_multisig_tapscript(2, &keys[..2])
            .expect("2-of-2 is within the quorum bound");
        assert_ne!(
            short_script.len(),
            34 * keys.len() + 2,
            "the fixture must disagree with N = 3"
        );
        let leaf_hash = crate::script::tapscript_leaf_hash(&short_script);
        let control =
            crate::address::tapscript_control_block(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)
                .expect("NUMS tweak is total");
        let output = crate::address::tapscript_output_key(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)
            .expect("NUMS tweak is total");
        let spk = crate::script::make_p2tr_lock_script(&output).to_vec();

        let mut tx = ms_finalized_p2tr_tx();
        let n = tx.vin[0].witness.len();
        tx.vin[0].witness[n - 2] = short_script.clone();
        tx.vin[0].witness[n - 1] = control.to_vec();

        let err =
            independent_tapscript_verify(&tx.serialize_wire(), &spk, 60_000, &keys, &short_script)
                .unwrap_err();
        assert!(err.contains("not the canonical quorum idiom"), "got: {err}");
    }

    #[ntest_timeout::timeout(120_000)]
    #[test]
    fn wallet_walk_signs_p2tr_scriptpath_member() {
        // The wallet Signer walk (ОВ-9 pattern) covers the script-path
        // branch: the own key at nonce 0 of MS_SEED is a member.
        let mut psbt = ms_create_p2tr_psbt();
        let unsigned = sign_psbt_with(&TSeed::new(MS_SEED), &TPassphrase::EMPTY, kdf(), &mut psbt)
            .expect("walk completes");
        assert!(unsigned.is_empty(), "the walk must sign the member input");
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
    }

    // --- Independent BIP-341/BIP-342 verification (e2e evidence,
    //     v0.3) ---------------------------------------------------------

    /// Recompute the BIP-341 script-path digest via the `bitcoin`
    /// crate's reference implementation — deliberately independent of
    /// the hand-rolled SigMsg/ext assembly.
    fn independent_tapscript_digest(
        wire: &[u8],
        utxo_spk: &[u8],
        amount: u64,
        script: &[u8],
    ) -> Result<[u8; 32], String> {
        use bitcoin::consensus::deserialize;
        use bitcoin::hashes::Hash as _;
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::{Amount, ScriptBuf, TxOut};

        let tx: bitcoin::Transaction = deserialize(wire).map_err(|e| format!("wire parse: {e}"))?;
        if tx.input.len() != 1 {
            return Err("fixture expects a single input".into());
        }
        let utxos = [TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::from_bytes(utxo_spk.to_vec()),
        }];
        // The reference crate derives hashTapLeaf itself (the leaf
        // version is part of its LeafVersion::TapScript).
        let leaf = bitcoin::taproot::TapLeafHash::from_script(
            &ScriptBuf::from_bytes(script.to_vec()),
            bitcoin::taproot::LeafVersion::TapScript,
        );
        let digest = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&utxos),
                leaf,
                TapSighashType::Default,
            )
            .map_err(|e| format!("bip341: {e}"))?;
        Ok(*digest.as_byte_array())
    }

    /// Evaluate a completed P2TR script-path spend the way BIP-341/
    /// BIP-342 consensus would: derive the tweaked output key from the
    /// control block (NUMS internal key, parity check, commitment to
    /// the UTXO program), then run the CHECKSIG/CHECKSIGADD/NUMEQUAL
    /// stack machine over the witness slots with BIP-340 verification
    /// of each non-empty signature against the *independently
    /// recomputed* script-path digest.
    ///
    /// `expected_keys` is the script's key set in script order; the
    /// witness stack layout (`[w_N … w_1] ‖ script ‖ control`), the
    /// BIP-341 control-block validation (leaf version, parity of y(Q),
    /// output-key commitment to the UTXO program) and the BIP-342
    /// fail-on-invalid-signature semantics are enforced here.
    fn independent_tapscript_verify(
        wire: &[u8],
        utxo_spk: &[u8],
        amount: u64,
        expected_keys: &[[u8; 32]],
        expected_script: &[u8],
    ) -> Result<(), String> {
        use bitcoin::consensus::deserialize;
        use k256::elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::{bigint::U256, point::AffineCoordinates as _};
        use k256::schnorr::{Signature as SchnorrSig, VerifyingKey};
        use k256::{ProjectivePoint, Scalar};
        use sha2::{Digest as _, Sha256};

        let tx: bitcoin::Transaction = deserialize(wire).map_err(|e| format!("wire parse: {e}"))?;
        let txin = &tx.input[0];
        if txin.witness.is_empty() {
            return Err("the witness stack is empty on the wire".into());
        }
        let stack: Vec<Vec<u8>> = txin.witness.iter().map(|w| w.to_vec()).collect();
        // Layout: [w_N … w_1] ‖ script ‖ control — N + 2 items.
        if stack.len() != expected_keys.len() + 2 {
            return Err(format!(
                "witness must carry N + 2 items (N = {}), got {}",
                expected_keys.len(),
                stack.len()
            ));
        }
        let script = &stack[stack.len() - 2];
        let control = &stack[stack.len() - 1];
        if script != expected_script {
            return Err("the revealed tapscript does not match the expected leaf".into());
        }

        // Control block: c[0] = 0xc0 | parity(y(Q)); the internal key
        // it carries must tweak to the UTXO program.
        if control.len() != 33 || control[0] & 0xfe != 0xc0 {
            return Err("control block must be 33 bytes with the 0xc0 leaf version".into());
        }
        let internal: [u8; 32] = control[1..33].try_into().expect("33-byte control block");
        let tagged = |tag: &[u8], msg: &[u8]| {
            let th = Sha256::digest(tag);
            Sha256::digest([th.as_slice(), th.as_slice(), msg].concat())
        };
        let mut leaf_msg = Vec::new();
        leaf_msg.push(0xc0);
        // minimal CompactSize of |script|
        if script.len() < 0xfd {
            leaf_msg.push(script.len() as u8);
        } else {
            leaf_msg.push(0xfd);
            leaf_msg.extend_from_slice(&(script.len() as u16).to_le_bytes());
        }
        leaf_msg.extend_from_slice(script);
        let leaf_hash = tagged(b"TapLeaf", &leaf_msg);
        let tweak = tagged(
            b"TapTweak",
            &[internal.as_slice(), leaf_hash.as_slice()].concat(),
        );
        let t = <Scalar as Reduce<U256>>::reduce_bytes(&tweak);
        let mut sec1 = [0u8; 33];
        sec1[0] = 0x02;
        sec1[1..].copy_from_slice(&internal);
        let p = k256::PublicKey::from_sec1_bytes(&sec1)
            .map_err(|e| format!("internal key lift: {e}"))?;
        let q =
            (ProjectivePoint::from(p.as_affine()) + (ProjectivePoint::GENERATOR * t)).to_affine();
        if bool::from(q.y_is_odd()) != (control[0] & 1 == 1) {
            return Err("control-block parity bit disagrees with y(Q)".into());
        }
        let program = utxo_spk;
        if program.len() != 34
            || program[0] != 0x51
            || program[1] != 0x20
            || program[2..] != q.x().to_vec()
        {
            return Err("the tweaked output key does not commit to the UTXO program".into());
        }

        // The script itself: canonical R-MS-7 shape with the expected
        // keys in order and a threshold M ≤ N (the slot layout check
        // above already pinned N).
        if script.len() != 34 * expected_keys.len() + 2
            || script[script.len() - 1] != 0x9d
            || script[script.len() - 2] - 0x50 > expected_keys.len() as u8
        {
            return Err("the revealed script is not the canonical quorum idiom".into());
        }

        // The BIP-341 script-path digest, recomputed independently.
        let digest = independent_tapscript_digest(wire, utxo_spk, amount, script)?;

        // The BIP-342 stack machine: walk the script, maintain the
        // numeric accumulator; empty signature = skip (0), a non-empty
        // invalid signature FAILS the script (not a 0 push).
        let slots = &stack[..stack.len() - 2]; // w_N … w_1
        let mut acc: u64 = 0;
        // The first script key closes with OP_CHECKSIG (its boolean
        // result seeds the counter); the rest with OP_CHECKSIGADD.
        // Split out of the loop so no constant-true `i == 0` branch
        // exists for the coverage accounting to fold.
        {
            let key = &expected_keys[0];
            let sig: &[u8] = &slots[slots.len() - 1];
            let vk = VerifyingKey::from_bytes(key)
                .map_err(|e| format!("key 0 is not a valid x-only point: {e}"))?;
            if !sig.is_empty() {
                let s = SchnorrSig::try_from(sig)
                    .map_err(|e| format!("signature 0 is not 64 bytes: {e}"))?;
                vk.verify_raw(&digest, &s)
                    .map_err(|_| "signature 0 failed BIP-340 verification".to_string())?;
                acc += 1;
            }
        }
        for (i, key) in expected_keys[1..].iter().enumerate() {
            // The (i+1)-th script key pairs with slot w_{i+2}: from
            // the top of the stack that is slots[len - 2 - i].
            let sig: &[u8] = &slots[slots.len() - 2 - i];
            let vk = VerifyingKey::from_bytes(key)
                .map_err(|e| format!("key {} is not a valid x-only point: {e}", i + 1))?;
            // OP_CHECKSIGADD: pop sig, add 1 when it verifies;
            // empty → adds 0; invalid non-empty → fail.
            if !sig.is_empty() {
                let s = SchnorrSig::try_from(sig)
                    .map_err(|e| format!("signature {} is not 64 bytes: {e}", i + 1))?;
                vk.verify_raw(&digest, &s)
                    .map_err(|_| format!("signature {} failed BIP-340 verification", i + 1))?;
                acc += 1;
            }
        }
        // OP_M pushes M; OP_NUMEQUAL compares — success iff acc == M.
        let m = script[script.len() - 2] - 0x50;
        if acc != m as u64 {
            return Err(format!(
                "CHECKSIGADD counter {acc} does not equal the threshold {m}"
            ));
        }
        Ok(())
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2tr_e2e_two_signers_combine_finalize_extract_independent_verify() {
        // 1. Creator.
        let mut psbt_a = ms_create_p2tr_psbt();
        // 2. Signer A — membership via the wallet walk (ОВ-9 + R-MS-4).
        let unsigned = sign_psbt_with(
            &TSeed::new(MS_SEED),
            &TPassphrase::EMPTY,
            kdf(),
            &mut psbt_a,
        )
        .expect("walk completes");
        assert!(unsigned.is_empty(), "the walk must sign the member input");
        assert_eq!(psbt_a.inputs[0].tap_script_sigs.len(), 1);
        // 3. Signer B — direct primitive on the second quorum key.
        let mut psbt_b = ms_create_p2tr_psbt();
        assert!(psbt_b.sign_input(0, &ms_key(1)).unwrap());
        // 4. Combiner.
        let mut combined = psbt_a.combine(&psbt_b).expect("disjoint signers");
        assert_eq!(combined.inputs[0].tap_script_sigs.len(), 2);
        // 5. Finalizer.
        combined.finalize();
        assert!(combined.inputs[0].final_scriptwitness.is_some());
        assert!(combined.inputs[0].final_scriptsig.is_none());
        // 6. Extractor.
        let tx = combined.extract_transaction().expect("complete quorum");
        let wire = tx.serialize_wire();
        // 7. Independent consensus-equivalent verification: the
        //    bitcoin crate's BIP-341 script-path digest + the BIP-342
        //    stack machine with BIP-340 verification.
        independent_tapscript_verify(
            &wire,
            &ms_p2tr_spk(),
            60_000,
            &ms_tapscript_keys(),
            &ms_tapscript(),
        )
        .expect("the extracted spend must verify independently");
        // The control block on the wire is the pinned single-leaf
        // NUMS tree (c[0] ‖ H).
        assert_eq!(tx.vin[0].witness.last().unwrap(), &ms_tap_control_block());
        // Bit-for-bit pin: the signer order does not change the wire
        // (R-MS-4).
        let mut flip = ms_create_p2tr_psbt();
        assert!(flip.sign_input(0, &ms_key(1)).unwrap());
        assert!(flip.sign_input(0, &ms_key(0)).unwrap());
        flip.finalize();
        let tx_flip = flip.extract_transaction().expect("complete quorum");
        assert_eq!(tx_flip.serialize_wire(), wire);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2tr_independent_verifier_rejection_table() {
        // The verifier itself must be exercised on every defensive
        // arm, so a green e2e cannot hide a vacuous checker.
        let mut psbt = ms_create_p2tr_psbt();
        assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
        assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
        psbt.finalize_input(0).expect("2-of-3 quorum is complete");
        let base_tx = psbt.extract_transaction().expect("complete quorum");
        let wire = base_tx.serialize_wire();
        let keys = ms_tapscript_keys();
        let spk = ms_p2tr_spk();

        // Garbage wire.
        let err = independent_tapscript_verify(&[0x01; 16], &spk, 60_000, &keys, &ms_tapscript())
            .unwrap_err();
        assert!(err.contains("wire parse"), "got: {err}");

        // A two-input tx is outside the single-input fixture contract.
        let two_input = Transaction {
            version: 2,
            vin: base_tx
                .vin
                .clone()
                .into_iter()
                .chain(base_tx.vin.clone())
                .collect(),
            vout: base_tx.vout.clone(),
            locktime: 0,
        };
        let err = independent_tapscript_digest(
            &two_input.serialize_wire(),
            &spk,
            60_000,
            &ms_tapscript(),
        )
        .unwrap_err();
        assert!(err.contains("single input"), "got: {err}");

        // Wrong item count (N + 2 expected).
        let short_stack = {
            let mut tx = base_tx.clone();
            tx.vin[0].witness.pop();
            tx.serialize_wire()
        };
        let err = independent_tapscript_verify(&short_stack, &spk, 60_000, &keys, &ms_tapscript())
            .unwrap_err();
        assert!(err.contains("N + 2 items"), "got: {err}");

        // Empty witness section.
        let err = independent_tapscript_verify(
            &base_tx.serialize_stripped(),
            &spk,
            60_000,
            &keys,
            &ms_tapscript(),
        )
        .unwrap_err();
        assert!(err.contains("empty on the wire"), "got: {err}");

        // The revealed script swapped out.
        let mut other_script = ms_tapscript();
        other_script[0] ^= 0x01;
        let err =
            independent_tapscript_verify(&wire, &spk, 60_000, &keys, &other_script).unwrap_err();
        assert!(
            err.contains("does not match the expected leaf"),
            "got: {err}"
        );

        // Control block with the wrong leaf version nibble.
        let bad_version_control = {
            let mut tx = base_tx.clone();
            let n = tx.vin[0].witness.len();
            tx.vin[0].witness[n - 1][0] = 0x80;
            tx.serialize_wire()
        };
        let err = independent_tapscript_verify(
            &bad_version_control,
            &spk,
            60_000,
            &keys,
            &ms_tapscript(),
        )
        .unwrap_err();
        assert!(err.contains("leaf version"), "got: {err}");

        // Control block parity bit flipped (c[0] & 1 ≠ y(Q) mod 2 —
        // the NUMS tweak of the fixture has odd parity, so flipping
        // the bit claims even).
        let bad_parity_control = {
            let mut tx = base_tx.clone();
            let n = tx.vin[0].witness.len();
            tx.vin[0].witness[n - 1][0] ^= 0x01;
            tx.serialize_wire()
        };
        let err =
            independent_tapscript_verify(&bad_parity_control, &spk, 60_000, &keys, &ms_tapscript())
                .unwrap_err();
        assert!(err.contains("parity bit disagrees"), "got: {err}");

        // A control block whose internal key is not a valid curve
        // point (all-ones x is ≥ the field order) → the lift itself
        // fails before any commitment check.
        let bad_lift_control = {
            let mut tx = base_tx.clone();
            let n = tx.vin[0].witness.len();
            tx.vin[0].witness[n - 1][1..33].fill(0xff);
            tx.serialize_wire()
        };
        let err =
            independent_tapscript_verify(&bad_lift_control, &spk, 60_000, &keys, &ms_tapscript())
                .unwrap_err();
        assert!(err.contains("internal key lift"), "got: {err}");

        // A control block carrying a valid but FOREIGN internal key →
        // the tweaked Q does not commit to the UTXO program. The
        // parity byte is recomputed for the foreign key, so the
        // refusal is genuinely the commitment check, not parity.
        let foreign_internal: [u8; 32] =
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .expect("fixed generator x")
                .try_into()
                .expect("32-byte x");
        let foreign_control = {
            let leaf_hash = crate::script::tapscript_leaf_hash(&ms_tapscript());
            let cb = crate::address::tapscript_control_block(&foreign_internal, &leaf_hash)
                .expect("the generator lifts");
            let mut tx = base_tx.clone();
            let n = tx.vin[0].witness.len();
            tx.vin[0].witness[n - 1] = cb.to_vec();
            tx.serialize_wire()
        };
        let err =
            independent_tapscript_verify(&foreign_control, &spk, 60_000, &keys, &ms_tapscript())
                .unwrap_err();
        assert!(
            err.contains("does not commit to the UTXO program"),
            "got: {err}"
        );

        // A control block of the wrong LENGTH (a depth-1 foreign
        // block is 65 bytes) → refused before the point arithmetic.
        let long_control = {
            let mut tx = base_tx.clone();
            let n = tx.vin[0].witness.len();
            let mut cb = tx.vin[0].witness[n - 1].clone();
            cb.extend_from_slice(&[0x11; 32]);
            tx.vin[0].witness[n - 1] = cb;
            tx.serialize_wire()
        };
        let err = independent_tapscript_verify(&long_control, &spk, 60_000, &keys, &ms_tapscript())
            .unwrap_err();
        assert!(err.contains("must be 33 bytes"), "got: {err}");

        // Wrong UTXO program (a different P2TR output).
        let other_spk = crate::script::make_p2tr_lock_script(&[0x99u8; 32]).to_vec();
        let err = independent_tapscript_verify(&wire, &other_spk, 60_000, &keys, &ms_tapscript())
            .unwrap_err();
        assert!(
            err.contains("does not commit to the UTXO program"),
            "got: {err}"
        );

        // Malformed UTXO programs: wrong length, wrong witness
        // version, wrong program length byte — every shape arm of the
        // commitment check fires on its own.
        let mut wrong_version = spk.clone();
        wrong_version[0] = 0x50;
        let mut wrong_length_byte = spk.clone();
        wrong_length_byte[1] = 0x21;
        for (name, bad_spk) in [
            ("truncated program", spk[..33].to_vec()),
            ("wrong version", wrong_version),
            ("wrong program length byte", wrong_length_byte),
        ] {
            let err = independent_tapscript_verify(&wire, &bad_spk, 60_000, &keys, &ms_tapscript())
                .unwrap_err();
            assert!(
                err.contains("does not commit to the UTXO program"),
                "{name}: {err}"
            );
        }

        // Threshold counter mismatch: only one of two signatures —
        // counter 1 ≠ M 2.
        let one_sig = {
            let mut tx = base_tx.clone();
            let n = tx.vin[0].witness.len();
            tx.vin[0].witness[n - 4] = Vec::new(); // w_2's slot emptied
            tx.serialize_wire()
        };
        let err = independent_tapscript_verify(&one_sig, &spk, 60_000, &keys, &ms_tapscript())
            .unwrap_err();
        assert!(err.contains("does not equal the threshold"), "got: {err}");

        // BIP-342 fail-on-invalid: a non-empty slot signed by a key
        // that did not sign (foreign signature in w_1's slot) —
        // BIP-340 verification fails the script.
        let digest =
            independent_tapscript_digest(&wire, &spk, 60_000, &ms_tapscript()).expect("digest");
        let foreign_sig = taproot_sign_sighash_untweaked(&ms_key(7), &digest).to_vec();
        let wrong_signer = {
            let mut tx = base_tx.clone();
            let n = tx.vin[0].witness.len();
            tx.vin[0].witness[n - 3] = foreign_sig; // w_1's slot
            tx.serialize_wire()
        };
        let err = independent_tapscript_verify(&wrong_signer, &spk, 60_000, &keys, &ms_tapscript())
            .unwrap_err();
        assert!(err.contains("failed BIP-340 verification"), "got: {err}");

        // A slot swapped between two real signers — each signature
        // fails under the other's key.
        let swapped = {
            let mut tx = base_tx.clone();
            let n = tx.vin[0].witness.len();
            tx.vin[0].witness.swap(n - 3, n - 4);
            tx.serialize_wire()
        };
        let err = independent_tapscript_verify(&swapped, &spk, 60_000, &keys, &ms_tapscript())
            .unwrap_err();
        assert!(err.contains("failed BIP-340 verification"), "got: {err}");

        // All three slots non-empty (over-signing): the third
        // signature is valid but the counter 3 ≠ M 2.
        let oversigned = {
            let mut psbt = ms_create_p2tr_psbt();
            assert!(psbt.sign_input(0, &ms_key(0)).unwrap());
            assert!(psbt.sign_input(0, &ms_key(1)).unwrap());
            assert!(psbt.sign_input(0, &ms_key(2)).unwrap());
            psbt.finalize_input(0)
                .expect("the finalizer drops the tail");
            // Restore the dropped third signature into the empty slot
            // by hand (BIP-342 semantics: it would be counted).
            let mut tx = psbt.extract_transaction().expect("extracts");
            // The finalizer drops the LAST script key's signature —
            // restore it AT ITS OWN slot (the last script key's stack
            // index is 0) so the mutation is a pure over-signature,
            // not a misplaced one.
            let last_nonce = (0..3)
                .find(|&n| ms_script_position(n) == 2)
                .expect("the fixture covers every script position");
            assert!(tx.vin[0].witness[0].is_empty());
            tx.vin[0].witness[0] =
                taproot_sign_sighash_untweaked(&ms_key(last_nonce), &digest).to_vec();
            tx.serialize_wire()
        };
        let err = independent_tapscript_verify(&oversigned, &spk, 60_000, &keys, &ms_tapscript())
            .unwrap_err();
        assert!(err.contains("does not equal the threshold"), "got: {err}");
    }

    // --- Independent-verifier rejection table --------------------------
    //
    // The verifier itself must be exercised on every defensive arm, so
    // a green e2e cannot hide a vacuous checker.

    /// Wire tx with a single input carrying `script` as its scriptSig.
    fn wire_with_scriptsig(script: Vec<u8>) -> Vec<u8> {
        Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x66; 32],
                n: 0,
                script,
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 1_000,
                script: vec![0x51; 23],
            }],
            locktime: 0,
        }
        .serialize_wire()
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn independent_digest_rejects_unusable_wire() {
        use sha2::{Digest as _, Sha256};
        // A long output script forces the varint helper's `0xfd`
        // escalation branch inside the preimage.
        let long_out = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x66; 32],
                n: 0,
                script: vec![],
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 1,
                script: vec![0x51; 300],
            }],
            locktime: 0,
        }
        .serialize_wire();
        let redeem = [0x51u8; 3];
        let digest = independent_ms_digest(&long_out, &redeem).expect("digest");
        // The digest must differ from the same tx with a short output
        // (the long script is part of the commitment).
        let short = wire_with_scriptsig(vec![]);
        assert_ne!(digest, independent_ms_digest(&short, &redeem).unwrap());

        // Garbage is a typed "wire parse" error, never a panic.
        let err = independent_ms_digest(&[0x00, 0x01, 0x02], &redeem).unwrap_err();
        assert!(err.contains("wire parse"), "got: {err}");
        // A two-input tx is outside the helper's single-input fixture
        // contract.
        let two_in = Transaction {
            version: 2,
            vin: vec![
                TxIn {
                    txhash: [0x66; 32],
                    n: 0,
                    script: vec![],
                    sequence: 0xffff_fffe,
                    witness: Vec::new(),
                },
                TxIn {
                    txhash: [0x67; 32],
                    n: 0,
                    script: vec![],
                    sequence: 0xffff_fffe,
                    witness: Vec::new(),
                },
            ],
            vout: vec![TxOut {
                amount: 1,
                script: vec![0x51],
            }],
            locktime: 0,
        }
        .serialize_wire();
        let err = independent_ms_digest(&two_in, &redeem).unwrap_err();
        assert!(err.contains("single input"), "got: {err}");
        // Silence the unused-import lint if sha2 binding is only used
        // via the helper above.
        let _ = Sha256::digest(&[0u8][..]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn independent_verifier_rejects_malformed_inputs() {
        let keys = ms_redeem_keys();
        let redeem = ms_redeem();
        let full_scriptsig =
            crate::script::make_multisig_script_sig(&redeem, &[&[0x30u8; 72], &[0x30u8; 72]]);
        // (hand-built sigs: the wrong-signature mutations only need to
        // reach the structural checks below; the e2e test covers the
        // real-crypto path)
        // A syntactically-well-formed signature blob: 0x30 tag, 72
        // bytes, SIGHASH_ALL suffix — good enough for the structural
        // mutations below (DER validity is only needed where tested).
        let ok_sig = {
            let mut s = vec![0x30u8; 72];
            s.push(0x01);
            s
        };

        // Garbage wire.
        let err = independent_checkmultisig_verify(&[0x01; 16], &keys).unwrap_err();
        assert!(err.contains("wire parse"), "got: {err}");

        // Bare (non-push) opcode in the scriptSig.
        let mut bad_ops = vec![0x00u8, 0x61]; // OP_0, OP_NOP
        bad_ops.extend_from_slice(&full_scriptsig[1..]);
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(bad_ops), &keys).unwrap_err();
        assert!(err.contains("bare opcodes"), "got: {err}");

        // Dummy + one item only: no signature/redeem structure.
        let mut too_few = vec![0x00u8];
        too_few.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(too_few), &keys).unwrap_err();
        assert!(err.contains("needs a dummy"), "got: {err}");

        // The last push is not a CHECKMULTISIG script.
        let mut not_redeem = vec![0x00u8];
        not_redeem.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        not_redeem.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        not_redeem.extend_from_slice(&crate::script::push_data(&[0x51, 0x51, 0x51]));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(not_redeem), &keys).unwrap_err();
        assert!(err.contains("not a CHECKMULTISIG"), "got: {err}");

        // Quorum counter below OP_1.
        let mut bad_counter = vec![0x00u8];
        bad_counter.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        bad_counter.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        let mut bad_redeem = vec![0x00u8, 0x21];
        bad_redeem.extend_from_slice(&keys[0]);
        bad_redeem.extend_from_slice(&[0x51, 0xae]);
        bad_counter.extend_from_slice(&crate::script::push_data(&bad_redeem));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(bad_counter), &keys).unwrap_err();
        assert!(err.contains("quorum counters"), "got: {err}");

        // m > n.
        let mut m_over_n = vec![0x00u8];
        m_over_n.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        m_over_n.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        let mut bad_redeem = vec![0x52, 0x21];
        bad_redeem.extend_from_slice(&keys[0]);
        bad_redeem.extend_from_slice(&[0x51, 0xae]);
        m_over_n.extend_from_slice(&crate::script::push_data(&bad_redeem));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(m_over_n), &keys).unwrap_err();
        assert!(err.contains("m must not exceed"), "got: {err}");

        // Body length does not match N.
        let mut short_body = vec![0x00u8];
        short_body.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        short_body.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        let mut body_redeem = vec![0x51, 0x21];
        body_redeem.extend_from_slice(&keys[0]);
        body_redeem.extend_from_slice(&[0x52, 0xae]);
        short_body.extend_from_slice(&crate::script::push_data(&body_redeem));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(short_body), &keys).unwrap_err();
        assert!(err.contains("body does not match"), "got: {err}");

        // Non-0x21 push inside the body (0x20 header, still n·34 long).
        let mut bad_push = vec![0x00u8];
        bad_push.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        bad_push.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        let mut weird_redeem = vec![0x52, 0x20];
        weird_redeem.extend_from_slice(&keys[0]);
        weird_redeem.push(0x21);
        weird_redeem.extend_from_slice(&keys[1]);
        weird_redeem.extend_from_slice(&[0x52, 0xae]);
        assert_eq!(weird_redeem.len(), 3 + 2 * 34);
        bad_push.extend_from_slice(&crate::script::push_data(&weird_redeem));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(bad_push), &keys).unwrap_err();
        assert!(err.contains("non-canonical key push"), "got: {err}");

        // Canonical redeem, but the expected keys do not match it.
        let err = independent_checkmultisig_verify(
            &wire_with_scriptsig(full_scriptsig.clone()),
            &[ms_pubkey(7), ms_pubkey(8), ms_pubkey(9)],
        )
        .unwrap_err();
        assert!(
            err.contains("do not match the expected quorum"),
            "got: {err}"
        );

        // Signature count below the threshold.
        let mut one_sig = vec![0x00u8];
        one_sig.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        one_sig.extend_from_slice(&crate::script::push_data(&redeem));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(one_sig), &keys).unwrap_err();
        assert!(err.contains("expected 2 signatures"), "got: {err}");

        // A long final push that is not a CHECKMULTISIG script: the
        // length arm passes, the terminal-opcode arm fires (and vice
        // versa in the shorter "not a CHECKMULTISIG" case above).
        let mut long_not_ms = vec![0x00u8];
        long_not_ms.extend_from_slice(&crate::script::push_data(&ok_sig));
        long_not_ms.extend_from_slice(&crate::script::push_data(&ok_sig));
        long_not_ms.extend_from_slice(&crate::script::push_data(&[0x51u8; 40]));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(long_not_ms), &keys).unwrap_err();
        assert!(err.contains("not a CHECKMULTISIG"), "got: {err}");

        // Valid length and terminal opcode, but the n-counter is not a
        // small-integer push.
        let mut bad_ncounter = vec![0x00u8];
        bad_ncounter.extend_from_slice(&crate::script::push_data(&ok_sig));
        bad_ncounter.extend_from_slice(&crate::script::push_data(&ok_sig));
        let mut n_redeem = vec![0x52];
        n_redeem.push(0x21);
        n_redeem.extend_from_slice(&keys[0]);
        n_redeem.push(0x21);
        n_redeem.extend_from_slice(&keys[1]);
        n_redeem.extend_from_slice(&[0x00, 0xae]);
        assert_eq!(n_redeem.len(), 3 + 2 * 34);
        bad_ncounter.extend_from_slice(&crate::script::push_data(&n_redeem));
        let err = independent_checkmultisig_verify(&wire_with_scriptsig(bad_ncounter), &keys)
            .unwrap_err();
        assert!(err.contains("quorum counters"), "got: {err}");

        // Canonical redeem, but the expected key COUNT differs.
        let err = independent_checkmultisig_verify(
            &wire_with_scriptsig(full_scriptsig.clone()),
            &keys[..2],
        )
        .unwrap_err();
        assert!(
            err.contains("do not match the expected quorum"),
            "got: {err}"
        );

        // A truncated OP_PUSHDATA1 push makes the instruction
        // iterator fail mid-script.
        let mut truncated = vec![0x00u8, 0x4c];
        truncated.extend_from_slice(&crate::script::push_data(&redeem));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(truncated), &keys).unwrap_err();
        assert!(err.contains("script parse"), "got: {err}");

        // A DER blob that does not parse (wrong sequence tag, valid
        // SIGHASH_ALL suffix).
        let mut der_blob = vec![0x31u8; 71];
        der_blob.push(0x01);
        let mut bad_der = vec![0x00u8];
        bad_der.extend_from_slice(&crate::script::push_data(&der_blob));
        bad_der.extend_from_slice(&crate::script::push_data(&ok_sig));
        bad_der.extend_from_slice(&crate::script::push_data(&redeem));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(bad_der), &keys).unwrap_err();
        assert!(err.contains("bad DER"), "got: {err}");

        // Keys that are canonical 33-byte pushes but not valid SEC
        // points (0x04 prefix): the ECDSA layer refuses to load them.
        let mut bad_keys_redeem = vec![0x52];
        for k in 0..2 {
            bad_keys_redeem.push(0x21);
            bad_keys_redeem.push(0x04);
            bad_keys_redeem.extend_from_slice(&[k as u8 + 1; 32]);
        }
        bad_keys_redeem.extend_from_slice(&[0x52, 0xae]);
        assert_eq!(bad_keys_redeem.len(), 3 + 2 * 34);
        let mut expected_bad = [[0x04u8; 33]; 2];
        expected_bad[0][1..33].copy_from_slice(&[1; 32]);
        expected_bad[1][1..33].copy_from_slice(&[2; 32]);
        // Well-formed DER signatures (the mutation targets key
        // LOADING, not DER parsing).
        let valid_sig = {
            let sig = crate::privkey::sign_hash(&ms_key(0), &[7u8; 32]);
            let mut der = sig.to_der().as_bytes().to_vec();
            der.push(0x01);
            der
        };
        let mut bad_keys_script = vec![0x00u8];
        bad_keys_script.extend_from_slice(&crate::script::push_data(&valid_sig));
        bad_keys_script.extend_from_slice(&crate::script::push_data(&valid_sig));
        bad_keys_script.extend_from_slice(&crate::script::push_data(&bad_keys_redeem));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(bad_keys_script), &expected_bad)
                .unwrap_err();
        assert!(err.contains("key 0"), "got: {err}");

        // A signature without the SIGHASH_ALL suffix.
        let mut no_suffix = vec![0x00u8];
        no_suffix.extend_from_slice(&crate::script::push_data(&[0x30u8; 72]));
        let mut suffixed = vec![0x30u8; 72];
        suffixed.push(0x01);
        no_suffix.extend_from_slice(&crate::script::push_data(&suffixed));
        no_suffix.extend_from_slice(&crate::script::push_data(&redeem));
        let err =
            independent_checkmultisig_verify(&wire_with_scriptsig(no_suffix), &keys).unwrap_err();
        assert!(err.contains("SIGHASH_ALL suffix"), "got: {err}");
    }
}
