//! Bitcoin transaction model and signing — the wire format the wallet
//! emits to the network.
//!
//! yubtc ships its own (deliberately minimal) transaction model rather
//! than using `bitcoin::Transaction` directly:
//!
//! - The **wire format** must match `yubtc-python` byte-for-byte; the
//!   Python implementation hand-rolls a `CIn`/`COut`/`CTransaction`
//!   with `struct.pack("<L", ...)`, so anything that goes over the
//!   network has to be reproducible.
//! - The **signing conventions** are pinned by official vectors:
//!   legacy SIGHASH_ALL over the blanked serialization, BIP-143 for
//!   P2WPKH witnesses, BIP-341 (key-path, SIGHASH_DEFAULT) plus
//!   BIP-340 Schnorr (`aux_rand = 0x00 × 32`, spec ОВ-3) for P2TR.
//!   Off-by-one here would send valid signatures over the wrong
//!   digest and the network would silently reject the tx.
//! - The **`Transaction`** type is owned (no Cow), because the wallet
//!   only ever mutates copies via `sign()` and doesn't reuse `TxIn`.
//!
//! Segregation of txid and wtxid (BIP-141): [`Transaction::id`] and
//! [`Transaction::wtxid`] hash the stripped and wire layouts
//! respectively; [`Transaction::weight`]/[`Transaction::vsize`]
//! implement the SegWit fee accounting. The legacy paths are frozen
//! byte-for-byte — guarded by the v0.1 tests and KATs.
//!
//! Structure mirrors `yubtc-python/src/yubtc/transaction.py`. Tests
//! pin the byte layout, the IDs, and the signing conventions via
//! known-answer vectors computed against the BIP references.

use k256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::privkey::sign_hash;
use crate::script::push_data;

// --- Errors ----------------------------------------------------------

/// Errors emitted by transaction construction.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransactionError {
    /// `signers` length did not match `vin` length. Each input is signed
    /// by exactly one key.
    #[error("signers length must match vin length (got {0} signers, {1} vin)")]
    SignersLengthMismatch(usize, usize),

    /// BIP-143/BIP-341 signing requires per-input UTXO metadata
    /// ([`SpendContext`]) and either none was supplied or it does not
    /// cover every input of the transaction.
    #[error("spend context missing or incomplete (BIP-143/BIP-341 signing needs amounts and scriptPubKeys of all inputs)")]
    MissingSpendContext,

    /// A sighash was requested for an input index outside the
    /// transaction's input list.
    #[error("input index {0} out of range ({1} inputs)")]
    InputIndexOutOfRange(usize, usize),
}

/// How an input is signed, derived from the shape of the UTXO's
/// `scriptPubKey` (see [`SigScheme::from_script_pubkey`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigScheme {
    /// Pre-SegWit: legacy SIGHASH_ALL digest over the blanked
    /// serialization, signature in `scriptSig`.
    Legacy,

    /// Native P2WPKH (witness v0): BIP-143 digest, SIGHASH_ALL,
    /// `[DER sig ‖ 0x01, compressed pubkey]` witness.
    Bip143P2wpkh,

    /// P2TR key-path (witness v1): BIP-341 digest, SIGHASH_DEFAULT
    /// (0x00), bare 64-byte Schnorr signature witness.
    Bip341KeyPath,
}

impl SigScheme {
    /// Dispatch a `scriptPubKey` to its signing scheme by strict
    /// shape: `00 14 <20>` → P2WPKH, `51 20 <32>` → P2TR key-path,
    /// everything else (including P2PKH, P2SH and malformed
    /// look-alikes) → legacy.
    pub fn from_script_pubkey(script_pubkey: &[u8]) -> Self {
        if script_pubkey.len() == 22 && script_pubkey[0] == 0x00 && script_pubkey[1] == 0x14 {
            return SigScheme::Bip143P2wpkh;
        }
        if script_pubkey.len() == 34 && script_pubkey[0] == 0x51 && script_pubkey[1] == 0x20 {
            return SigScheme::Bip341KeyPath;
        }
        SigScheme::Legacy
    }
}

/// UTXO metadata for one input, threaded through
/// [`Transaction::sign_segwit`] as [`SpendContext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendInput {
    /// Value of the spent output in satoshi (committed by both
    /// BIP-143 and BIP-341 digests).
    pub amount: u64,

    /// `scriptPubKey` of the spent output. For BIP-341 digests the
    /// context's copy is authoritative.
    pub script_pubkey: Vec<u8>,
}

/// Per-input UTXO metadata required by the SegWit digest algorithms.
///
/// BIP-143 commits to the signed input's amount; BIP-341 commits to
/// the amounts **and scriptPubKeys of every input**. `inputs` must be
/// parallel to `Transaction::vin`; otherwise signing fails with
/// [`TransactionError::MissingSpendContext`]. Legacy-only
/// transactions never consult the context.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpendContext {
    /// One entry per transaction input, in `vin` order.
    pub inputs: Vec<SpendInput>,
}

/// Bitcoin transaction input — references a previous output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    /// 32-byte hash of the referenced transaction (in Bitcoin's
    /// reversed-double-SHA256 display order).
    pub txhash: [u8; 32],

    /// Index of the referenced output inside that transaction. `u32`
    /// because the consensus rule limits it to `0xffff_ffff`.
    pub n: u32,

    /// Signature script (`scriptSig`). Empty for unsigned inputs; set
    /// to `<signature> <pubkey>` after signing.
    pub script: Vec<u8>,

    /// Sequence number. BIP-125 RBF uses `0xfffffffe` (signalled
    /// replaceable); `0xffffffff` (or `0` for nLockTime use) for
    /// final inputs.
    pub sequence: u32,

    /// Witness stack (BIP-141). Empty for legacy inputs and for
    /// unsigned SegWit inputs; after [`Transaction::sign_segwit`] a
    /// P2WPKH input carries `[DER sig ‖ 0x01, compressed pubkey]` and
    /// a P2TR key-path input a bare 64-byte Schnorr signature. The
    /// stack is excluded from the stripped serialization and `txid`,
    /// but included in the wire serialization and `wtxid`.
    pub witness: Vec<Vec<u8>>,
}

impl TxIn {
    /// Serialise an input per the Bitcoin protocol:
    ///
    /// ```text
    /// 32 bytes  txhash
    ///  4 bytes  n          (LE)
    ///  1+ bytes varint(len(script))
    ///  N bytes  script
    ///  4 bytes  sequence   (LE)
    /// ```
    ///
    /// The witness stack is *not* part of the input serialization;
    /// SegWit wire format places all witness stacks after the outputs
    /// (see [`Transaction::serialize_wire`]).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + self.script.len() + 1 + 4);
        out.extend_from_slice(&self.txhash);
        out.extend_from_slice(&self.n.to_le_bytes());
        out.extend_from_slice(&compact_size(self.script.len() as u64));
        out.extend_from_slice(&self.script);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out
    }
}

/// Bitcoin transaction output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// Value in satoshi (`u64` covers the full `int64_t` consensus
    /// range — Bitcoin Core pins it to `0x7fffffff` for dust reasons
    /// but the wire format allows the whole `u64`).
    pub amount: u64,

    /// Lock script (`scriptPubKey`). Empty for provably-unspendable
    /// outputs (rare; typically `OP_RETURN` payloads in non-yubtc
    /// wallets).
    pub script: Vec<u8>,
}

impl TxOut {
    /// Serialise an output per the Bitcoin protocol:
    ///
    /// ```text
    /// 8 bytes  amount   (LE)
    /// 1+ bytes varint(len(script))
    /// N bytes  script
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 1 + self.script.len());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&compact_size(self.script.len() as u64));
        out.extend_from_slice(&self.script);
        out
    }
}

/// A full transaction: a list of inputs, a list of outputs, plus
/// version/locktime framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Wire format version. `yubtc` always uses `2` (post-BIP-68,
    /// pre-SegWit). The field stays public so wallet code can construct
    /// unusual versions in tests if needed; production code should
    /// leave it at the default.
    pub version: i32,

    /// Inputs being spent. Empty for the "no-input" sentinel used by
    /// some test helpers.
    pub vin: Vec<TxIn>,

    /// Outputs being created. Empty for burn-only txs.
    pub vout: Vec<TxOut>,

    /// `nLockTime`. `0` for immediately-spendable.
    pub locktime: u32,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            version: 2,
            vin: Vec::new(),
            vout: Vec::new(),
            locktime: 0,
        }
    }
}

impl Transaction {
    /// Serialise the **stripped** (pre-SegWit) layout:
    ///
    /// ```text
    ///  4 bytes version     (LE)
    ///  1+ bytes varint(vin count)
    ///  sum   of TxIn::serialize()
    ///  1+ bytes varint(vout count)
    ///  sum   of TxOut::serialize()
    ///  4 bytes locktime    (LE)
    /// ```
    ///
    /// Witness stacks are ignored. `txid` is the double-SHA256 of
    /// exactly these bytes (BIP-141).
    pub fn serialize_stripped(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 1 + 4);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&compact_size(self.vin.len() as u64));
        for vin in &self.vin {
            out.extend_from_slice(&vin.serialize());
        }
        out.extend_from_slice(&compact_size(self.vout.len() as u64));
        for vout in &self.vout {
            out.extend_from_slice(&vout.serialize());
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    /// Serialise the full transaction in the stripped layout.
    ///
    /// Kept as the v0.1 entry point so existing callers (fee loop
    /// sizing, broadcast hex) stay byte-for-byte; SegWit-aware
    /// serialization is [`Transaction::serialize_wire`].
    pub fn serialize(&self) -> Vec<u8> {
        self.serialize_stripped()
    }

    /// Serialise the **wire** layout (BIP-144):
    ///
    /// ```text
    ///  4 bytes version     (LE)
    ///  0x00 marker, 0x01 flag        (only when witnessed)
    ///  … vin / vout as in the stripped layout
    ///  per input: varint(item count) + varint(len) + item bytes
    ///  4 bytes locktime    (LE)
    /// ```
    ///
    /// When no input carries a witness the marker/flag section is
    /// omitted and the output is byte-identical to
    /// [`Transaction::serialize_stripped`] — every v0.1 transaction
    /// serialises exactly as before. All counts and lengths use
    /// Bitcoin's CompactSize (see [`compact_size`] for the Phase 15
    /// LEB128 correction).
    pub fn serialize_wire(&self) -> Vec<u8> {
        if !self.has_witness() {
            return self.serialize_stripped();
        }
        let mut out = Vec::with_capacity(self.serialize_stripped().len() + 2);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(0x00); // marker
        out.push(0x01); // flag
        out.extend_from_slice(&compact_size(self.vin.len() as u64));
        for vin in &self.vin {
            out.extend_from_slice(&vin.serialize());
        }
        out.extend_from_slice(&compact_size(self.vout.len() as u64));
        for vout in &self.vout {
            out.extend_from_slice(&vout.serialize());
        }
        for vin in &self.vin {
            out.extend_from_slice(&compact_size(vin.witness.len() as u64));
            for item in &vin.witness {
                out.extend_from_slice(&compact_size(item.len() as u64));
                out.extend_from_slice(item);
            }
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    /// True when at least one input carries a non-empty witness stack.
    pub fn has_witness(&self) -> bool {
        self.vin.iter().any(|vin| !vin.witness.is_empty())
    }

    /// Transaction weight (BIP-141): `base_size·3 + total_size`,
    /// where base is the stripped and total the wire size.
    pub fn weight(&self) -> usize {
        self.serialize_stripped().len() * 3 + self.serialize_wire().len()
    }

    /// Virtual size (BIP-141): `ceil(weight / 4)`. Equals the stripped
    /// size for transactions without witness, so v0.1 fee math is
    /// unchanged.
    pub fn vsize(&self) -> usize {
        self.weight().div_ceil(4)
    }

    /// Compute the Bitcoin transaction id: the double-SHA256 of the
    /// **stripped** serialization, displayed in the reversed (LE)
    /// order expected by block explorers. Witness data does not
    /// affect the txid (BIP-141); for legacy transactions this is the
    /// same value v0.1 produced.
    pub fn id(&self) -> [u8; 32] {
        let bytes = self.serialize_stripped();
        let first = Sha256::digest(bytes);
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out.reverse();
        out
    }

    /// Compute the witness transaction id (BIP-141): double-SHA256 of
    /// the **wire** serialization, in the same reversed display order
    /// as [`Transaction::id`]. For transactions without witness this
    /// equals the txid (the wire layout is the stripped one).
    pub fn wtxid(&self) -> [u8; 32] {
        let bytes = self.serialize_wire();
        let first = Sha256::digest(bytes);
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out.reverse();
        out
    }

    /// Produce a signed copy of the transaction (legacy path).
    ///
    /// `signers` is a `&[(SigningKey, [u8; 33])]` parallel to `vin`:
    /// one `(privkey, compressed_pubkey)` per input. Each input's
    /// signature script ends up `push(<der_signature> ‖ <0x01
    /// sighash_byte>) ‖ push(<33-byte pubkey>)`, matching
    /// `yubtc-python`'s `CScript` convention.
    ///
    /// Every input is signed with the pre-SegWit SIGHASH_ALL algorithm,
    /// unchanged from v0.1. Transactions containing SegWit inputs must
    /// use [`Transaction::sign_segwit`], which dispatches per-input
    /// schemes.
    ///
    /// `sign()` does not mutate `self`; it `clone()`s, signs the
    /// clone, and returns the signed copy.
    pub fn sign(
        &self,
        signers: &[(SigningKey, [u8; 33])],
    ) -> Result<Transaction, TransactionError> {
        if signers.len() != self.vin.len() {
            return Err(TransactionError::SignersLengthMismatch(
                signers.len(),
                self.vin.len(),
            ));
        }
        let mut tx = self.clone();
        // Pre-compute every signature first, then attach all at
        // once. The standard SIGHASH_ALL algorithm signs each input
        // with the *other* inputs' scripts blanked, so we can't
        // iteratively edit `tx.vin[i].script` in place without
        // recompiling the previous signature every iteration.
        let mut scripts = Vec::with_capacity(self.vin.len());
        for (i, (privkey, pubkey)) in signers.iter().enumerate() {
            scripts.push(legacy_script_sig(self, i, privkey, pubkey));
        }
        for (i, script) in scripts.into_iter().enumerate() {
            tx.vin[i].script = script;
        }
        Ok(tx)
    }

    /// Produce a signed copy of the transaction, choosing each input's
    /// scheme from its UTXO `scriptPubKey` shape
    /// ([`SigScheme::from_script_pubkey`]).
    ///
    /// - Legacy inputs get the pre-SegWit SIGHASH_ALL `scriptSig`
    ///   (byte-for-byte the [`Transaction::sign`] output).
    /// - P2WPKH inputs get a BIP-143 SIGHASH_ALL signature as the
    ///   witness `[DER sig ‖ 0x01, compressed pubkey]`; `scriptSig` is
    ///   left empty.
    /// - P2TR key-path inputs get a BIP-341 SIGHASH_DEFAULT digest
    ///   signed with BIP-340 Schnorr (`aux_rand = 0x00 × 32`, per
    ///   spec ОВ-3) as a bare 64-byte witness item.
    ///
    /// Mixed transactions (legacy + witness inputs) are allowed: each
    /// input's digest is computed independently.
    ///
    /// Errors: [`TransactionError::SignersLengthMismatch`] when
    /// `signers` does not parallel `vin`;
    /// [`TransactionError::MissingSpendContext`] when a SegWit input
    /// needs UTXO metadata that `spend` does not provide (BIP-143:
    /// the signed input's amount; BIP-341: amounts and scriptPubKeys
    /// of *all* inputs).
    pub fn sign_segwit(
        &self,
        signers: &[(SigningKey, [u8; 33])],
        spend: Option<&SpendContext>,
    ) -> Result<Transaction, TransactionError> {
        if signers.len() != self.vin.len() {
            return Err(TransactionError::SignersLengthMismatch(
                signers.len(),
                self.vin.len(),
            ));
        }
        let mut tx = self.clone();
        for (i, (privkey, pubkey)) in signers.iter().enumerate() {
            match SigScheme::from_script_pubkey(&self.vin[i].script) {
                SigScheme::Legacy => {
                    tx.vin[i].script = legacy_script_sig(self, i, privkey, pubkey);
                }
                SigScheme::Bip143P2wpkh => {
                    let ctx = spend.ok_or(TransactionError::MissingSpendContext)?;
                    let meta = ctx
                        .inputs
                        .get(i)
                        .ok_or(TransactionError::MissingSpendContext)?;
                    let script_code = p2wpkh_script_code(&self.vin[i].script);
                    // `i < vin.len()` holds by the signing loop, so
                    // the validated wrapper is not needed here.
                    let sighash = bip143_sighash_in_range(self, i, &script_code, meta.amount);
                    // Sign the digest itself (on-chain semantics): the
                    // BIP-143 sighash is the ECDSA prehash, not a
                    // message to be hashed again (see `sign_hash`).
                    let sig: Signature = sign_hash(privkey, &sighash);
                    let mut witness_sig = sig.to_der().as_bytes().to_vec();
                    witness_sig.push(SIGHASH_ALL);
                    tx.vin[i].script = Vec::new();
                    tx.vin[i].witness = vec![witness_sig, pubkey.to_vec()];
                }
                SigScheme::Bip341KeyPath => {
                    let ctx = spend.ok_or(TransactionError::MissingSpendContext)?;
                    if ctx.inputs.len() != self.vin.len() {
                        return Err(TransactionError::MissingSpendContext);
                    }
                    let sighash = taproot_keypath_sighash_in_range(self, i, ctx);
                    let sig = taproot_sign_sighash(privkey, &sighash);
                    tx.vin[i].script = Vec::new();
                    tx.vin[i].witness = vec![sig.to_vec()];
                }
            }
        }
        Ok(tx)
    }
}

/// SIGHASH_ALL byte (legacy and BIP-143 signature suffix).
const SIGHASH_ALL: u8 = 0x01;

/// `SIGHASH_ALL` as the 4-byte little-endian sighash-type field.
const SIGHASH_ALL_LE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// `SIGHASH_DEFAULT` hash-type byte for BIP-341 SigMsg (semantically
/// equal to SIGHASH_ALL; the signature carries no sighash suffix).
const SIGHASH_DEFAULT: u8 = 0x00;

/// Double SHA-256, in internal (non-reversed) byte order.
fn dsha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Bitcoin CompactSize wire encoding (`0xfd`/`0xfe`/`0xff` prefixes).
///
/// Used for witness item counts and lengths; the legacy vin/vout
/// layout keeps `to_varint` (the two encodings coincide below 0xfd,
/// which covers every value the wallet serialises — counts and
/// script/witness lengths alike). Also the BIP-143 `scriptCode`
/// serialization prefix of a P2WSH witness script (v0.3):
/// `CompactSize(|script|) ‖ script` — the crate-visible form
/// `psbt.rs` builds the digest preimage from.
pub(crate) fn compact_size(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut out = vec![0xfd];
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out
    } else if n <= 0xffff_ffff {
        let mut out = vec![0xfe];
        out.extend_from_slice(&(n as u32).to_le_bytes());
        out
    } else {
        let mut out = vec![0xff];
        out.extend_from_slice(&n.to_le_bytes());
        out
    }
}

/// Legacy pre-SegWit SIGHASH_ALL signature script for input `i`.
///
/// Shared by [`Transaction::sign`] and [`Transaction::sign_segwit`]:
/// builds the blanked preimage (every `scriptSig` emptied except the
/// signed input, which carries its UTXO `scriptPubKey` per the
/// `build_vin` convention), appends the sighash type, and returns
/// `push(DER sig ‖ 0x01) ‖ push(pubkey)` — the pushed on-chain
/// layout per the spec and yubtc-python's `CScript` behaviour (a raw
/// concatenation would be interpreted as opcodes by the script
/// interpreter and never validate). The signature commits to the
/// sighash digest itself (`sign_hash`).
fn legacy_script_sig(
    tx: &Transaction,
    i: usize,
    privkey: &SigningKey,
    pubkey: &[u8; 33],
) -> Vec<u8> {
    let mut preimage = Transaction {
        version: tx.version,
        vin: tx
            .vin
            .iter()
            .map(|vin| TxIn {
                script: vec![],
                ..vin.clone()
            })
            .collect(),
        vout: tx.vout.clone(),
        locktime: tx.locktime,
    };
    // Restore the i-th input from the original (preserves its real
    // script — empty for unsigned inputs).
    preimage.vin[i] = tx.vin[i].clone();
    let mut bytes = preimage.serialize();
    bytes.extend_from_slice(&SIGHASH_ALL_LE); // 0x01 little-endian
    let sighash = dsha256(&bytes);
    let sig = sign_hash(privkey, &sighash);
    let mut sig_with_sighash = sig.to_der().as_bytes().to_vec();
    sig_with_sighash.push(SIGHASH_ALL);
    let mut script = push_data(&sig_with_sighash);
    script.extend_from_slice(&push_data(pubkey));
    script
}

/// P2WPKH `scriptCode` for BIP-143: `0x19 0x76 0xa9 0x14 <20-byte
/// hash> 0x88 0xac` (26 bytes: the CompactSize length prefix plus the
/// equivalent P2PKH script), rebuilt from the 22-byte `00 14 <hash>`
/// witness program.
///
/// Contract: `script_pubkey` must be the 22-byte P2WPKH shape
/// (guaranteed by [`SigScheme::from_script_pubkey`] dispatch).
fn p2wpkh_script_code(script_pubkey: &[u8]) -> [u8; 26] {
    debug_assert_eq!(script_pubkey.len(), 22, "P2WPKH program shape");
    debug_assert_eq!(script_pubkey[0], 0x00);
    debug_assert_eq!(script_pubkey[1], 0x14);
    let mut out = [0u8; 26];
    out[0] = 0x19;
    out[1] = 0x76; // OP_DUP
    out[2] = 0xa9; // OP_HASH160
    out[3] = 0x14;
    out[4..24].copy_from_slice(&script_pubkey[2..22]);
    out[24] = 0x88; // OP_EQUALVERIFY
    out[25] = 0xac; // OP_CHECKSIG
    out
}

/// BIP-143 signature digest (SIGHASH_ALL) for a P2WPKH input.
///
/// `script_code` is the 26-byte `0x1976a914{hash}88ac` blob
/// ([`p2wpkh_script_code`]); `amount` the spent output's value. All
/// other committed data comes from `tx` (version, outpoints,
/// sequences, outputs, locktime).
///
/// Errors: [`TransactionError::InputIndexOutOfRange`] when
/// `input_index` is not a valid input of `tx`.
pub fn bip143_sighash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    amount: u64,
) -> Result<[u8; 32], TransactionError> {
    if input_index >= tx.vin.len() {
        return Err(TransactionError::InputIndexOutOfRange(
            input_index,
            tx.vin.len(),
        ));
    }
    Ok(bip143_sighash_in_range(
        tx,
        input_index,
        script_code,
        amount,
    ))
}

/// Core of [`bip143_sighash`] without the index validation.
///
/// Contract: `input_index < tx.vin.len()` — checked by the public
/// wrapper and guaranteed inside [`Transaction::sign_segwit`] by the
/// signing loop.
fn bip143_sighash_in_range(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    amount: u64,
) -> [u8; 32] {
    let vin = &tx.vin[input_index];

    let mut buf = Vec::new();
    for input in &tx.vin {
        buf.extend_from_slice(&input.txhash);
        buf.extend_from_slice(&input.n.to_le_bytes());
    }
    let hash_prevouts = dsha256(&buf);

    buf.clear();
    for input in &tx.vin {
        buf.extend_from_slice(&input.sequence.to_le_bytes());
    }
    let hash_sequence = dsha256(&buf);

    buf.clear();
    for output in &tx.vout {
        buf.extend_from_slice(&output.serialize());
    }
    let hash_outputs = dsha256(&buf);

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&vin.txhash);
    preimage.extend_from_slice(&vin.n.to_le_bytes());
    preimage.extend_from_slice(script_code);
    preimage.extend_from_slice(&amount.to_le_bytes());
    preimage.extend_from_slice(&vin.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());
    preimage.extend_from_slice(&SIGHASH_ALL_LE);
    dsha256(&preimage)
}

/// BIP-341 signature digest for a P2TR **key-path** spend with
/// `SIGHASH_DEFAULT` (0x00) and no annex.
///
/// `spend` must carry one [`SpendInput`] per transaction input —
/// BIP-341 commits to the amounts and scriptPubKeys of *all* inputs;
/// the context's `script_pubkey` values are authoritative for the
/// digest.
///
/// Errors: [`TransactionError::MissingSpendContext`] when the context
/// does not cover every input; [`TransactionError::InputIndexOutOfRange`]
/// when `input_index` is invalid.
pub fn taproot_keypath_sighash(
    tx: &Transaction,
    input_index: usize,
    spend: &SpendContext,
) -> Result<[u8; 32], TransactionError> {
    if spend.inputs.len() != tx.vin.len() {
        return Err(TransactionError::MissingSpendContext);
    }
    if input_index >= tx.vin.len() {
        return Err(TransactionError::InputIndexOutOfRange(
            input_index,
            tx.vin.len(),
        ));
    }
    Ok(taproot_keypath_sighash_in_range(tx, input_index, spend))
}

/// Core of [`taproot_keypath_sighash`] without the context/index
/// validation.
///
/// Contract: `spend.inputs.len() == tx.vin.len()` and
/// `input_index < tx.vin.len()` — both checked by the public wrapper
/// and guaranteed inside [`Transaction::sign_segwit`].
fn taproot_keypath_sighash_in_range(
    tx: &Transaction,
    input_index: usize,
    spend: &SpendContext,
) -> [u8; 32] {
    let sig_msg = taproot_sig_msg(tx, input_index, spend, 0x00);
    // sighash = tagged_hash("TapSighash", 0x00 (epoch) ‖ SigMsg).
    let mut msg = Vec::with_capacity(sig_msg.len() + 1);
    msg.push(0x00);
    msg.extend_from_slice(&sig_msg);
    crate::misc::tagged_hash(b"TapSighash", &msg)
}

/// The five BIP-341 `sha_*` midstate fields shared by every Taproot
/// digest: `sha_prevouts`, `sha_amounts`, `sha_scriptpubkeys`,
/// `sha_sequences`, `sha_outputs` (single SHA-256 of the concatenated
/// per-input data — the context's `script_pubkey` values are
/// authoritative).
fn taproot_sha_fields(tx: &Transaction, spend: &SpendContext) -> [Vec<u8>; 5] {
    let mut buf = Vec::new();
    for input in &tx.vin {
        buf.extend_from_slice(&input.txhash);
        buf.extend_from_slice(&input.n.to_le_bytes());
    }
    let sha_prevouts = Sha256::digest(&buf);

    buf.clear();
    for meta in &spend.inputs {
        buf.extend_from_slice(&meta.amount.to_le_bytes());
    }
    let sha_amounts = Sha256::digest(&buf);

    buf.clear();
    for meta in &spend.inputs {
        buf.extend_from_slice(&compact_size(meta.script_pubkey.len() as u64));
        buf.extend_from_slice(&meta.script_pubkey);
    }
    let sha_scriptpubkeys = Sha256::digest(&buf);

    buf.clear();
    for input in &tx.vin {
        buf.extend_from_slice(&input.sequence.to_le_bytes());
    }
    let sha_sequences = Sha256::digest(&buf);

    buf.clear();
    for output in &tx.vout {
        buf.extend_from_slice(&output.serialize());
    }
    let sha_outputs = Sha256::digest(&buf);

    [
        sha_prevouts.to_vec(),
        sha_amounts.to_vec(),
        sha_scriptpubkeys.to_vec(),
        sha_sequences.to_vec(),
        sha_outputs.to_vec(),
    ]
}

/// The BIP-341 `SigMsg` (175 bytes) with `SIGHASH_DEFAULT` and no
/// annex: `0x00 ‖ nVersion ‖ nLockTime ‖ sha_prevouts ‖ sha_amounts
/// ‖ sha_scriptpubkeys ‖ sha_sequences ‖ sha_outputs ‖ spend_type ‖
/// input_index`. `spend_type` carries `ext_flag` in its low bit
/// (0x00 key path, 0x02 script path with the BIP-342 extension) and
/// annex-absence in bit 1.
fn taproot_sig_msg(
    tx: &Transaction,
    input_index: usize,
    spend: &SpendContext,
    spend_type: u8,
) -> Vec<u8> {
    let [sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences, sha_outputs] =
        taproot_sha_fields(tx, spend);
    let mut sig_msg = Vec::with_capacity(175);
    sig_msg.push(SIGHASH_DEFAULT);
    sig_msg.extend_from_slice(&tx.version.to_le_bytes());
    sig_msg.extend_from_slice(&tx.locktime.to_le_bytes());
    sig_msg.extend_from_slice(&sha_prevouts);
    sig_msg.extend_from_slice(&sha_amounts);
    sig_msg.extend_from_slice(&sha_scriptpubkeys);
    sig_msg.extend_from_slice(&sha_sequences);
    sig_msg.extend_from_slice(&sha_outputs);
    sig_msg.push(spend_type);
    sig_msg.extend_from_slice(&(input_index as u32).to_le_bytes());
    sig_msg
}

/// BIP-341 **script-path** signature digest for a P2TR spend of a
/// Tapscript leaf with `SIGHASH_DEFAULT` (0x00) and no annex
/// (specs/spec.md «Дайджест — BIP-341 script-path + расширение
/// BIP-342»):
///
/// ```text
/// SigMsg = 0x00 ‖ … (as the key path, spend_type = 0x02) …
/// ext    = leaf_hash (32) ‖ 0x00 (key_version) ‖ 0xFFFFFFFF
///          (codesep_pos, 4 LE)
/// sighash = tagged_hash("TapSighash", 0x00 (epoch) ‖ SigMsg ‖ ext)
/// ```
///
/// `spend` must carry one [`SpendInput`] per transaction input (the
/// script-path digest commits to all inputs exactly like the key-path
/// one); `leaf_hash` is the spent leaf's `hashTapLeaf`. Errors mirror
/// [`taproot_keypath_sighash`].
pub fn taproot_scriptpath_sighash(
    tx: &Transaction,
    input_index: usize,
    spend: &SpendContext,
    leaf_hash: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    if spend.inputs.len() != tx.vin.len() {
        return Err(TransactionError::MissingSpendContext);
    }
    if input_index >= tx.vin.len() {
        return Err(TransactionError::InputIndexOutOfRange(
            input_index,
            tx.vin.len(),
        ));
    }
    let mut sig_msg = taproot_sig_msg(tx, input_index, spend, 0x02);
    sig_msg.extend_from_slice(leaf_hash);
    sig_msg.push(0x00); // key_version: 0 (the only defined value)
    sig_msg.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // codesep_pos
    let mut msg = Vec::with_capacity(sig_msg.len() + 1);
    msg.push(0x00); // epoch
    msg.extend_from_slice(&sig_msg);
    Ok(crate::misc::tagged_hash(b"TapSighash", &msg))
}

/// Compute the BIP-86/BIP-341 tweaked signing scalar for a key-path
/// spend with an empty Merkle root: `d' + t` where `d'` is the
/// internal scalar normalized to the even-Y representation and
/// `t = tagged_hash("TapTweak", x(P))`.
///
/// **Parity audit (stage 3).** BIP-341 «Construction» defines the
/// tweak over the *x-only* internal key: `t =
/// int(tagged_hash("TapTweak", x(P)))`, `Q = lift_x(x(P)) + t·G`, and
/// its key-path spending rule gives the tweaked secret as `d + t
/// (mod n)` — where `d` is the secret of the *lifted* (even-Y) point,
/// because `x(P)` alone denotes `P` with even y (BIP-340 § 2
/// «Public Key Generation»: negate `d` when `d·G` has odd y). So the
/// `n − d` flip, when the wallet's raw key has odd y, happens on the
/// **internal** key before the tweak is added — this is exactly the
/// explicit `n − d` the Python mirror performs in
/// `yubtc-python transaction.taproot_tweaked_scalar`.
///
/// In Rust the flip is delegated to k256: `schnorr::SigningKey::
/// from_bytes` routes through `From<NonZeroScalar>`, which does
/// `secret_key.conditional_assign(&-secret_key, is_odd(dG))` — the
/// BIP-340 even-Y normalization verbatim (k256 0.13). Hence
/// `norm.to_bytes()` below *is* the normalized `d'` for both input
/// parities, and `d_norm + t` is modular (`k256::Scalar` arithmetic
/// is `(mod n)`), so the `d' + t < 2n` intermediate cannot "overflow"
/// the group order — the wrap mirrors the Python `% SECP256K1_N`.
/// This library-level dependency is pinned by
/// `taproot_tweaked_scalar_normalizes_internal_parity` (parity
/// independence) and `taproot_tweaked_scalar_always_matches_output_key`
/// (signing key = address commitment); a k256 upgrade that dropped
/// the implicit flip would fail both loudly.
///
/// There is deliberately **no** ±t parity flip on the **output** key
/// Q: BIP-341 defines the tweaked secret as `d' + t` and lets the
/// BIP-340 signing algorithm (which normalizes to the even-Y point
/// internally, BIP-340 § 2 «Signing») handle Q's parity — the x-only
/// output key `x(Q)` is parity-independent.
fn taproot_tweaked_scalar(internal_privkey: &SigningKey) -> k256::Scalar {
    use k256::elliptic_curve::bigint::U256;
    use k256::elliptic_curve::ops::Reduce;

    // Normalize to the even-Y representation first: BIP-341 defines
    // the tweak over the x-only internal key. A valid ECDSA scalar is
    // always a valid BIP-340 scalar (nonzero, < n), so this cannot
    // fail — documented invariant, `expect` over an unreachable error
    // branch. `to_bytes()` returns the normalized scalar (see the
    // parity audit above).
    let norm = k256::schnorr::SigningKey::from_bytes(&internal_privkey.to_bytes())
        .expect("internal ecdsa scalar is a valid BIP-340 scalar (nonzero, < n)");
    let xonly: [u8; 32] = norm.verifying_key().to_bytes().into();
    let t = crate::misc::taproot_tweak_scalar(&xonly);
    let d_norm = <k256::Scalar as Reduce<U256>>::reduce_bytes(&norm.to_bytes());
    d_norm + t
}

/// Sign a BIP-341 key-path sighash with BIP-340 Schnorr.
///
/// The digest is signed under the **tweaked** key (see
/// [`taproot_tweaked_scalar`]). `aux_rand` is the deterministic
/// `0x00 × 32` (spec ОВ-3), so signatures are reproducible bit-for-bit
/// across runs and against the Python mirror.
///
/// Infallible by construction: the tweaked scalar is nonzero and
/// below the curve order (k256's `(mod n)` arithmetic applies), and
/// BIP-340 signing fails only for a zero nonce or `s` — probability
/// ~2⁻¹²⁸ for a fixed aux, not reachable with real keys. Both
/// conditions are `expect`s over documented invariants (kdf.rs
/// precedent) rather than statically unreachable error branches.
pub fn taproot_sign_sighash(internal_privkey: &SigningKey, sighash: &[u8; 32]) -> [u8; 64] {
    let tweaked = taproot_tweaked_scalar(internal_privkey);
    let key = k256::schnorr::SigningKey::from_bytes(&tweaked.to_bytes())
        .expect("tweaked scalar is a valid BIP-340 scalar (nonzero, < n)");
    key.sign_raw(&sighash[..], &[0u8; 32])
        .expect("BIP-340 signing cannot fail: zero nonce/s has probability ~2^-128")
        .to_bytes()
}

/// Sign a sighash with **untweaked** BIP-340 Schnorr — the Tapscript
/// script-path rule (v0.3, R-MS-10/ОВ-10): the signature commits under
/// the key lying in the script itself, and the key-path tweak scalar
/// is *not* applied (the tweak is key-path mechanics only — a script
/// path never signs under `Q`).
///
/// The BIP-340 even-Y normalization applies: the signing scalar is the
/// internal scalar normalized to the even-Y representative, so the
/// signature verifies under the x-only key `x(d·G)` — exactly the 32
/// bytes the tapscript push carries (bytes `1..33` of the compressed
/// encoding, parity-free). `aux_rand = 0x00 × 32` (ОВ-3), like every
/// yubtc Schnorr signature.
///
/// Infallible by construction: the internal scalar is a valid BIP-340
/// scalar (nonzero, < n), and signing cannot fail for a fixed aux
/// (zero nonce/s has probability ~2⁻¹²⁸) — documented invariants,
/// `expect` over unreachable error branches (kdf.rs precedent).
pub fn taproot_sign_sighash_untweaked(privkey: &SigningKey, sighash: &[u8; 32]) -> [u8; 64] {
    let key = k256::schnorr::SigningKey::from_bytes(&privkey.to_bytes())
        .expect("internal ecdsa scalar is a valid BIP-340 scalar (nonzero, < n)");
    key.sign_raw(&sighash[..], &[0u8; 32])
        .expect("BIP-340 signing cannot fail: zero nonce/s has probability ~2^-128")
        .to_bytes()
}

// --- Varint ----------------------------------------------------------

/// LEB128-style varint with continuation bit. Note: this is the
/// `yubtc-python` `toVarInt`, **not** Bitcoin's `CompactSize`
/// (`misc::varint` in the Python codebase is the same shape, and the
/// two are coincidentally identical — but the names diverge; we pick
/// the Bitcoin protocol's name for the same byte layout).
///
/// 7-bit groups, LSB first; the high bit of each byte marks "more
/// bytes follow".
///
/// Panics if `value` doesn't fit in `u64`. (`u64::MAX` takes 10 bytes;
/// Bitcoin never asks for that many.)
///
/// Legacy LEB128 helper, kept for yubtc-python `toVarInt` parity and
/// its pinned tests. NOT used by the wire encoders any more — every
/// transaction length/count is a Bitcoin [`compact_size`] (the two
/// encodings agree byte-for-byte below 128, which covers every
/// pre-Phase-15 flow; see the Phase 15 wire correction there).
pub fn to_varint(mut value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    loop {
        let to_write = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(to_write);
            return buf;
        }
        buf.push(to_write | 0x80);
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::misc::{TNonce, TPassphrase, TSeed};
    use crate::privkey::{privkey_to_pubkey, seed2privkey};
    use crate::script::{OP_DUP, OP_HASH160};
    use sha2::{Digest, Sha256};

    /// 32-byte hash used as the referenced tx for any test tx. Matches
    /// `yubtc-python/tests/test_transaction.py::TXHASH`.
    const TXHASH: [u8; 32] = [0xab; 32];

    // --- to_varint ----------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn to_varint_known_values() {
        // Pins the LEB128-with-continuation-bit encoding. The exact
        // bytes are not Bitcoin's CompactSize by accident; both shapes
        // happen to agree on small values, but the names diverge in
        // yubtc-python (`to_varint` for LEB128 vs. `misc.varint` for
        // CompactSize). This is the one used by the tx wire format.
        assert_eq!(to_varint(0), b"\x00");
        assert_eq!(to_varint(1), b"\x01");
        assert_eq!(to_varint(0x7f), b"\x7f");
        assert_eq!(to_varint(0x80), b"\x80\x01");
        assert_eq!(to_varint(0xff), b"\xff\x01");
        assert_eq!(to_varint(0x100), b"\x80\x02");
        assert_eq!(to_varint(0x3fff), b"\xff\x7f");
        assert_eq!(to_varint(0x4000), b"\x80\x80\x01");
        assert_eq!(to_varint(0xffff), b"\xff\xff\x03");
        assert_eq!(to_varint(0xffffff), b"\xff\xff\xff\x07");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn to_varint_picks_one_byte_when_possible() {
        // Everything < 128 must serialise as a single byte (no
        // continuation bit). Covers the loop's "first iteration only"
        // path.
        assert_eq!(to_varint(0).len(), 1);
        assert_eq!(to_varint(127).len(), 1);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn to_varint_round_trip_for_random_values() {
        // Property: decode(encode(v)) == v. Cover all values up to
        // 3 bytes (24 bit); anything above is well past Bitcoin's
        // observable range and serves only as a tiebreaker.
        for v in [
            0u64, 1, 0x7f, 0x80, 0xff, 0x100, 0x3fff, 0x4000, 0xffff, 0xffffff, 1_000_000,
        ] {
            let bytes = to_varint(v);
            // Manual decode to verify round-trip without depending on
            // a decoder (we have none yet).
            let mut acc: u64 = 0;
            let mut shift = 0;
            for &b in &bytes {
                acc |= u64::from(b & 0x7f) << shift;
                shift += 7;
                if b & 0x80 == 0 {
                    break;
                }
            }
            assert_eq!(acc, v, "round-trip failed for {v}");
        }
    }

    // --- Phase 15 wire correction: CompactSize lengths -----------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tx_in_uses_compact_size_for_large_script_lengths() {
        // A 253-byte script (the multisig scriptSig class) must encode
        // its length as the 3-byte CompactSize `fd fd 00` — a LEB128
        // encoder would emit `fd 01`, which a Bitcoin node parses as a
        // non-minimal varint and rejects.
        let script = vec![0xabu8; 253];
        let txin = TxIn {
            txhash: [0x11; 32],
            n: 0,
            script: script.clone(),
            sequence: 0xffff_fffe,
            witness: Vec::new(),
        };
        let bytes = txin.serialize();
        assert_eq!(bytes.len(), 32 + 4 + 3 + 253 + 4);
        assert_eq!(&bytes[36..39], &[0xfd, 0xfd, 0x00]);
        assert_eq!(&bytes[39..39 + 253], &script[..]);

        // Scripts below 128 keep the single-byte length: v0.1 bytes
        // are unchanged (LEB128 and CompactSize agree there).
        let small = TxIn {
            script: vec![0x22u8; 107],
            ..txin.clone()
        };
        let bytes = small.serialize();
        assert_eq!(bytes[36], 107);
        assert_eq!(bytes.len(), 32 + 4 + 1 + 107 + 4);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_sized_tx_round_trips_through_bitcoin_parse() {
        // The completed P2SH-multisig input size class: a tx whose
        // scriptSig is 253 bytes must round-trip through an
        // independent (bitcoin-crate) consensus deserializer.
        use bitcoin::consensus::Decodable as _;
        let mut script = vec![0x00u8]; // OP_0 dummy
        script.extend_from_slice(&[0x30u8; 146]); // two pushed sigs
        script.extend_from_slice(&[0x51u8; 106]); // pushed redeem-ish
        assert_eq!(script.len(), 253);
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x33; 32],
                n: 0,
                script: script.clone(),
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 1_000,
                script: vec![0x51; 23],
            }],
            locktime: 0,
        };
        let wire = tx.serialize_wire();
        let parsed = bitcoin::Transaction::consensus_decode(&mut &wire[..])
            .expect("bitcoin consensus parse");
        assert_eq!(parsed.input[0].script_sig.as_bytes(), &script[..]);
        assert_eq!(parsed.output[0].value.to_sat(), 1_000);
    }

    // --- TxIn ---------------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tx_in_serialize_known_answer() {
        // 32 txhash + 4 n (LE) + varint(len) + script + 4 sequence (LE).
        let inp = TxIn {
            txhash: TXHASH,
            n: 0,
            script: vec![OP_DUP, OP_HASH160],
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&TXHASH);
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.push(0x02); // varint(2)
        expected.extend_from_slice(&[OP_DUP, OP_HASH160]);
        expected.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert_eq!(inp.serialize(), expected);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tx_in_serialize_with_sequence_and_empty_script() {
        // Empty script means varint(0) → single zero byte.
        let inp = TxIn {
            txhash: TXHASH,
            n: 1,
            script: vec![],
            sequence: 0x1234_5678,
            witness: Vec::new(),
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&TXHASH);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.push(0x00); // varint(0)
        expected.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        assert_eq!(inp.serialize(), expected);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tx_in_serialize_n_at_u32_max() {
        // n=0xffffffff must round-trip bit-for-bit (tests that we
        // don't mask to u16 by accident).
        let inp = TxIn {
            txhash: TXHASH,
            n: 0xffff_ffff,
            script: vec![],
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        };
        let bytes = inp.serialize();
        // 32 (txhash) + 4 (n) + 1 (varint 0) + 4 (sequence) = 41.
        assert_eq!(bytes.len(), 41);
        assert_eq!(&bytes[32..36], &0xffff_ffffu32.to_le_bytes());
    }

    // --- TxOut --------------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tx_out_serialize_known_answer() {
        // 8 amount (LE) + varint(len) + script.
        let out = TxOut {
            amount: 100_000,
            script: vec![OP_DUP, OP_HASH160],
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&100_000u64.to_le_bytes());
        expected.push(0x02); // varint(2)
        expected.extend_from_slice(&[OP_DUP, OP_HASH160]);
        assert_eq!(out.serialize(), expected);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tx_out_serialize_zero_amount() {
        // Zero-amount outputs (provably-unspendable / OP_RETURN
        // data carriers in non-yubtc wallets) must still serialise
        // correctly.
        let out = TxOut {
            amount: 0,
            script: vec![],
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&0u64.to_le_bytes());
        expected.push(0x00); // varint(0)
        assert_eq!(out.serialize(), expected);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tx_out_serialize_max_amount() {
        // u64::MAX — confirms the field is full-width (no surprise
        // downcast to int64).
        let out = TxOut {
            amount: u64::MAX,
            script: vec![0xac],
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&u64::MAX.to_le_bytes());
        expected.push(0x01); // varint(1)
        expected.push(0xac);
        assert_eq!(out.serialize(), expected);
    }

    // --- Transaction --------------------------------------------------

    fn example_tx() -> Transaction {
        Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: TXHASH,
                n: 0,
                script: vec![OP_DUP, OP_HASH160],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 100_000,
                script: vec![OP_DUP, OP_HASH160],
            }],
            locktime: 0,
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn transaction_default_is_version_2() {
        let tx: Transaction = Default::default();
        assert_eq!(tx.version, 2);
        assert_eq!(tx.locktime, 0);
        assert!(tx.vin.is_empty());
        assert!(tx.vout.is_empty());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn transaction_serialize_known_answer() {
        // Pin the exact byte layout: 4 version + varint(vin count)
        // + sum(in serialize) + varint(vout count) + sum(out
        // serialize) + 4 locktime.
        let tx = example_tx();
        let s = tx.serialize();
        let mut expected = Vec::new();
        expected.extend_from_slice(&2i32.to_le_bytes());
        expected.push(0x01); // varint(1) vin
        expected.extend_from_slice(&TXHASH);
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.push(0x02); // varint(2)
        expected.extend_from_slice(&[OP_DUP, OP_HASH160]);
        expected.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        expected.push(0x01); // varint(1) vout
        expected.extend_from_slice(&100_000u64.to_le_bytes());
        expected.push(0x02); // varint(2)
        expected.extend_from_slice(&[OP_DUP, OP_HASH160]);
        expected.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(s, expected);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn transaction_serialize_multiple_in_out() {
        let tx = Transaction {
            version: 2,
            vin: vec![
                TxIn {
                    txhash: TXHASH,
                    n: 0,
                    script: vec![],
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                },
                TxIn {
                    txhash: TXHASH,
                    n: 1,
                    script: vec![0xab],
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                },
            ],
            vout: vec![
                TxOut {
                    amount: 1,
                    script: vec![],
                },
                TxOut {
                    amount: 2,
                    script: vec![0x76],
                },
            ],
            locktime: 0,
        };
        let s = tx.serialize();
        let expected_len =
            // version + counts
            4 + 1 + 1
            // vin
            + (32 + 4 + 1 + 4) + (32 + 4 + 1 + 1 + 4)
            // vout
            + (8 + 1) + (8 + 1 + 1)
            // locktime
            + 4;
        assert_eq!(s.len(), expected_len);
        assert_eq!(&s[..4], &2i32.to_le_bytes());
        assert_eq!(&s[s.len() - 4..], &0u32.to_le_bytes());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn transaction_id_is_double_sha256_reversed() {
        let tx = example_tx();
        let first = Sha256::digest(tx.serialize());
        let second = Sha256::digest(first);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&second);
        expected.reverse();
        assert_eq!(tx.id(), expected);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn transaction_id_known_answer() {
        // Pin exact bytes -- a movement here is balance-breaking:
        // every consumer (block explorers, wallet watchers) indexes
        // on txid in this exact form.
        let tx = example_tx();
        assert_eq!(
            hex::encode(tx.id()),
            "5f74d3c48b7f6f76be52629ea1ea3399131883b5e96e039ba949ff71621fd1b8"
        );
    }

    // --- Transaction::sign -------------------------------------------

    fn seed_privkey() -> SigningKey {
        let seed = TSeed::new("qwe");
        seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap()
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_populates_each_input_script() {
        let pk = seed_privkey();
        let pubkey = privkey_to_pubkey(&pk);
        let tx = Transaction {
            version: 2,
            vin: vec![
                TxIn {
                    txhash: TXHASH,
                    n: 0,
                    script: vec![],
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                },
                TxIn {
                    txhash: TXHASH,
                    n: 1,
                    script: vec![],
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                },
            ],
            vout: vec![TxOut {
                amount: 1000,
                script: vec![OP_DUP, OP_HASH160],
            }],
            locktime: 0,
        };
        let signers = vec![(pk.clone(), pubkey), (pk, pubkey)];
        let signed = tx.sign(&signers).unwrap();
        for (i, vin) in signed.vin.iter().enumerate() {
            assert!(!vin.script.is_empty(), "input {i} has empty script");
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_script_ends_with_pubkey() {
        // `push(<der_signature> ‖ <0x01 sighash>) ‖ push(<33-byte
        // pubkey>)` is the convention. Anything else means the script
        // is misshapen and the network would reject the tx at relay.
        let pk = seed_privkey();
        let pubkey = privkey_to_pubkey(&pk);
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: TXHASH,
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 1000,
                script: vec![OP_DUP, OP_HASH160],
            }],
            locktime: 0,
        };
        let signers = vec![(pk, pubkey)];
        let signed = tx.sign(&signers).unwrap();
        let script = &signed.vin[0].script;
        let len = script.len();
        assert!(len >= 33, "script too short to contain pubkey");
        assert_eq!(&script[len - 33..], &pubkey[..]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_appends_sighash_all_byte() {
        // SIGHASH_ALL = 0x01 sits at the END of the pushed signature
        // item (`push(sig ‖ 0x01)`), i.e. right before the pubkey's
        // one-byte push prefix. A different value (SIGHASH_NONE |
        // SIGHASH_ANYONECANPAY, say) would change the tx semantics --
        // the network would still parse it but a sender expecting
        // SIGHASH_ALL would have signed over the wrong digest.
        let pk = seed_privkey();
        let pubkey = privkey_to_pubkey(&pk);
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: TXHASH,
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 1000,
                script: vec![OP_DUP, OP_HASH160],
            }],
            locktime: 0,
        };
        let signers = vec![(pk, pubkey)];
        let signed = tx.sign(&signers).unwrap();
        let script = &signed.vin[0].script;
        let sighash_byte = script[script.len() - 35];
        assert_eq!(sighash_byte, 0x01);
        // ...and the pubkey item is a proper 33-byte push.
        assert_eq!(script[script.len() - 34], 33);
    }

    /// Regression (crypto audit, CLAIM 2): the legacy scriptSig is the
    /// PUSHED layout `push(sig ‖ 0x01) ‖ push(pubkey)`, and the
    /// signature commits to the legacy sighash digest ITSELF (CLAIM
    /// 1). The digest is rebuilt here independently of the signing
    /// code (blanked serialization + `0x01000000`, double-SHA256) —
    /// the same construction as yubtc-python's `CTransaction.sign`.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_legacy_scriptsig_is_pushed_and_sig_commits_to_sighash() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::VerifyingKey;

        let pk = seed_privkey();
        let pubkey = privkey_to_pubkey(&pk);
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: TXHASH,
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 1000,
                script: vec![OP_DUP, OP_HASH160],
            }],
            locktime: 0,
        };
        let signed = tx.sign(&[(pk, pubkey)]).unwrap();
        let script = &signed.vin[0].script;

        // Pushed layout: [sig_len] [sig ‖ 0x01] [0x21] [pubkey].
        let sig_item_len = script[0] as usize;
        assert_eq!(
            script.len(),
            1 + sig_item_len + 1 + 33,
            "script must be exactly push(sig‖0x01) ‖ push(pubkey)"
        );
        let sig_item = &script[1..1 + sig_item_len];
        assert_eq!(
            *sig_item.last().unwrap(),
            0x01,
            "sighash byte inside the push"
        );
        assert_eq!(script[1 + sig_item_len], 33, "pubkey push prefix");
        assert_eq!(&script[2 + sig_item_len..], &pubkey[..]);

        // Independent legacy sighash rebuild (blanked preimage).
        let mut preimage = Transaction {
            version: tx.version,
            vin: vec![tx.vin[0].clone()],
            vout: tx.vout.clone(),
            locktime: tx.locktime,
        };
        preimage.vin[0].script = tx.vin[0].script.clone();
        preimage.vin[0].witness = Vec::new();
        let mut bytes = preimage.serialize();
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let sighash = dsha256(&bytes);

        let sig = Signature::from_der(&sig_item[..sig_item_len - 1]).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
        vk.verify_prehash(&sighash, &sig)
            .expect("legacy signature must verify over the sighash digest itself");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_changes_id() {
        // The id moves after signing because the signature scripts
        // are now non-empty. If id() ever returns the same bytes,
        // either serialisation is broken or the signature scripts
        // are empty.
        let pk = seed_privkey();
        let pubkey = privkey_to_pubkey(&pk);
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: TXHASH,
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 1000,
                script: vec![OP_DUP, OP_HASH160],
            }],
            locktime: 0,
        };
        let signers = vec![(pk, pubkey)];
        let signed = tx.sign(&signers).unwrap();
        assert_ne!(signed.id(), tx.id());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_does_not_mutate_original() {
        // `sign` clones first -- the input tx's signature scripts
        // must stay empty after the call.
        let pk = seed_privkey();
        let pubkey = privkey_to_pubkey(&pk);
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: TXHASH,
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 1000,
                script: vec![OP_DUP, OP_HASH160],
            }],
            locktime: 0,
        };
        let serialized_before = tx.serialize();
        let signers = vec![(pk, pubkey)];
        let _ = tx.sign(&signers).unwrap();
        assert!(tx.vin[0].script.is_empty());
        assert_eq!(tx.serialize(), serialized_before);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_rejects_signers_length_mismatch() {
        // Each input is signed by exactly one key. We refuse to
        // silently pick one -- picking would be a denial-of-service
        // (the unsigned inputs give a malformed tx).
        let pk = seed_privkey();
        let pubkey = privkey_to_pubkey(&pk);
        let tx = Transaction {
            version: 2,
            vin: vec![
                TxIn {
                    txhash: TXHASH,
                    n: 0,
                    script: vec![],
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                },
                TxIn {
                    txhash: TXHASH,
                    n: 1,
                    script: vec![],
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                },
            ],
            vout: vec![TxOut {
                amount: 1000,
                script: vec![OP_DUP, OP_HASH160],
            }],
            locktime: 0,
        };
        let signers = vec![(pk, pubkey)];
        let err = tx.sign(&signers).unwrap_err();
        assert_eq!(err, TransactionError::SignersLengthMismatch(1, 2));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_rejects_oversized_signers_list() {
        // The opposite mismatch direction: more signers than inputs.
        let pk = seed_privkey();
        let pubkey = privkey_to_pubkey(&pk);
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: TXHASH,
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 1000,
                script: vec![OP_DUP, OP_HASH160],
            }],
            locktime: 0,
        };
        let signers = vec![(pk.clone(), pubkey), (pk, pubkey)];
        let err = tx.sign(&signers).unwrap_err();
        assert_eq!(err, TransactionError::SignersLengthMismatch(2, 1));
    }

    // --- SegWit model: serialization -----------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn serialize_stripped_equals_legacy_serialize() {
        // The stripped layout IS the v0.1 layout — pinned by the
        // known-answer above; assert the split entry points agree.
        let tx = example_tx();
        assert_eq!(tx.serialize(), tx.serialize_stripped());
        assert_eq!(tx.serialize(), tx.serialize_stripped());
        assert!(!tx.has_witness());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn witness_never_enters_stripped_or_txid() {
        let mut tx = example_tx();
        let without = tx.serialize_stripped();
        let txid_without = tx.id();
        tx.vin[0].witness = vec![vec![0xaa; 64]];
        assert_eq!(tx.serialize_stripped(), without);
        assert_eq!(tx.id(), txid_without);
        assert!(tx.has_witness());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wire_without_witness_is_stripped() {
        // Explicitly empty witness stacks must not trigger the
        // marker/flag section.
        let mut tx = example_tx();
        tx.vin[0].witness = Vec::new();
        assert_eq!(tx.serialize_wire(), tx.serialize_stripped());
        assert_eq!(tx.wtxid(), tx.id());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wire_with_witness_has_marker_flag_and_stacks() {
        let mut tx = example_tx();
        tx.vin[0].witness = vec![vec![0x01, 0x02], vec![0x03]];
        let wire = tx.serialize_wire();
        let stripped = tx.serialize_stripped();
        // Same version prefix, then marker 0x00 + flag 0x01.
        assert_eq!(&wire[..4], &stripped[..4]);
        assert_eq!(&wire[4..6], &[0x00, 0x01]);
        // The wire body after marker/flag is the stripped body minus
        // version, plus the witness section before locktime.
        let body = &wire[6..wire.len() - 4];
        let stripped_body = &stripped[4..stripped.len() - 4];
        // vin/vout section identical…
        let vin_vout_len = stripped_body.len();
        assert_eq!(&body[..vin_vout_len], stripped_body);
        // …witness section for the single input: varint(2 items),
        // varint(2) ‖ [0x01, 0x02], varint(1) ‖ [0x03].
        assert_eq!(&body[vin_vout_len..], &[0x02, 0x02, 0x01, 0x02, 0x01, 0x03]);
        assert!(wire.len() > stripped.len());
        assert_ne!(tx.wtxid(), tx.id());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn weight_and_vsize_follow_bip141() {
        let mut tx = example_tx();
        let base = tx.serialize_stripped().len();
        // No witness: weight = 4·base, vsize = base (v0.1 behaviour).
        assert_eq!(tx.weight(), base * 4);
        assert_eq!(tx.vsize(), base);
        tx.vin[0].witness = vec![vec![0xab; 64]];
        let total = tx.serialize_wire().len();
        assert_eq!(tx.weight(), base * 3 + total);
        assert_eq!(tx.vsize(), (base * 3 + total).div_ceil(4));
        assert!(tx.vsize() >= base);
    }

    // --- compact_size ---------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn compact_size_ranges() {
        assert_eq!(compact_size(0), vec![0x00]);
        assert_eq!(compact_size(0xfc), vec![0xfc]);
        assert_eq!(compact_size(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(compact_size(0x10000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(
            compact_size(0x1_0000_0000),
            vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
    }

    // --- BIP-143 official vector ----------------------------------------

    /// Unsigned transaction of the official BIP-143 native P2WPKH
    /// example: two inputs (P2PK + P2WPKH), two P2PKH outputs,
    /// nLockTime 17, nVersion 1.
    fn bip143_example_tx() -> Transaction {
        let h0: [u8; 32] =
            hex::decode("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f")
                .unwrap()
                .try_into()
                .unwrap();
        let h1: [u8; 32] =
            hex::decode("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a")
                .unwrap()
                .try_into()
                .unwrap();
        Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    txhash: h0,
                    n: 0,
                    // The spent P2PK scriptPubKey (build_vin
                    // convention: `script` holds the UTXO's
                    // scriptPubKey until signing).
                    script: hex::decode(
                        "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac",
                    )
                    .unwrap(),
                    sequence: 0xffff_ffee,
                    witness: Vec::new(),
                },
                TxIn {
                    txhash: h1,
                    n: 1,
                    // P2WPKH witness program 00141d0f…71a1.
                    script: hex::decode("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                },
            ],
            vout: vec![
                TxOut {
                    amount: 0x06b2_2c20,
                    script: hex::decode("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")
                        .unwrap(),
                },
                TxOut {
                    amount: 0x0d51_9390,
                    script: hex::decode("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac")
                        .unwrap(),
                },
            ],
            locktime: 17,
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip143_sighash_matches_official_vector() {
        // Official digest for the second input (P2WPKH, 6 BTC).
        let tx = bip143_example_tx();
        let script_code = p2wpkh_script_code(
            &hex::decode("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap(),
        );
        assert_eq!(
            hex::encode(script_code),
            "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
        );
        let sighash = bip143_sighash(&tx, 1, &script_code, 600_000_000).unwrap();
        assert_eq!(
            hex::encode(sighash),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip143_sighash_rejects_out_of_range_index() {
        let tx = bip143_example_tx();
        let err = bip143_sighash(&tx, 2, &[0u8; 26], 0).unwrap_err();
        assert_eq!(err, TransactionError::InputIndexOutOfRange(2, 2));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_segwit_p2wpkh_produces_verifiable_witness() {
        // Sign the official example transaction: the produced witness
        // signature must verify against the (official) BIP-143 digest
        // and the signer pubkey. The private keys of the BIP example
        // are redacted in the BIP text, so the exact signature bytes
        // are not reproducible — validity over the official digest is
        // the checkable property.
        use k256::ecdsa::{Signature, VerifyingKey};

        let tx = bip143_example_tx();
        let key = seed_privkey();
        let pubkey = privkey_to_pubkey(&key);
        let spend = SpendContext {
            inputs: vec![
                SpendInput {
                    amount: 625_000_000,
                    script_pubkey: tx.vin[0].script.clone(),
                },
                SpendInput {
                    amount: 600_000_000,
                    script_pubkey: tx.vin[1].script.clone(),
                },
            ],
        };
        let signed = tx
            .sign_segwit(&[(key.clone(), pubkey), (key, pubkey)], Some(&spend))
            .unwrap();
        // Legacy input: scriptSig populated, no witness.
        assert!(!signed.vin[0].script.is_empty());
        assert!(signed.vin[0].witness.is_empty());
        // P2WPKH input: empty scriptSig, two witness items.
        assert!(signed.vin[1].script.is_empty());
        assert_eq!(signed.vin[1].witness.len(), 2);
        assert_eq!(signed.vin[1].witness[1], pubkey.to_vec());
        let wit_sig = &signed.vin[1].witness[0];
        assert_eq!(*wit_sig.last().unwrap(), 0x01, "sighash type suffix");
        // Verify over the official digest. `verify_prehash` is the
        // on-chain semantics: the BIP-143 sighash IS the ECDSA `z` —
        // the prehashing `Verifier::verify` would check the signature
        // against SHA256(sighash) and (before the CLAIM 1 fix) passed
        // vacuously against the buggy signer.
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let der = &wit_sig[..wit_sig.len() - 1];
        let sig = Signature::from_der(der).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
        let official_sighash: [u8; 32] =
            hex::decode("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
                .unwrap()
                .try_into()
                .unwrap();
        vk.verify_prehash(&official_sighash, &sig).unwrap();
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wire_format_matches_official_bip143_signed_tx() {
        // The official signed serialization of the BIP-143 example:
        // marker/flag, per-input witness stacks (input 0 empty,
        // input 1 sig+pubkey), stripped body unchanged. The
        // transaction is assembled from the BIP's published bytes —
        // only the P2WPKH witness is ours.
        let official = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
        let mut tx = bip143_example_tx();
        tx.vin[0].script = hex::decode(
            "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01",
        )
        .unwrap();
        // Post-signing state: the witness input's scriptSig is empty.
        tx.vin[1].script = Vec::new();
        tx.vin[1].witness = vec![
            hex::decode(
                "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01",
            )
            .unwrap(),
            hex::decode(
                "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357",
            )
            .unwrap(),
        ];
        assert_eq!(hex::encode(tx.serialize_wire()), official);
        // txid excludes the witness: hash the stripped layout.
        assert_eq!(tx.id(), {
            let first = Sha256::digest(tx.serialize_stripped());
            let second = Sha256::digest(first);
            let mut out = [0u8; 32];
            out.copy_from_slice(&second);
            out.reverse();
            out
        });
    }

    // --- BIP-341 official vectors ----------------------------------------

    /// Minimal wire parser for the BIP-341 wallet test vector's
    /// unsigned transaction (single-byte varints, empty scriptSigs).
    fn parse_unsigned_tx(hex_str: &str) -> Transaction {
        let b = hex::decode(hex_str).unwrap();
        let mut i = 0usize;
        let u8_at = |i: &mut usize| {
            let v = b[*i];
            *i += 1;
            v
        };
        let take = |i: &mut usize, n: usize| -> Vec<u8> {
            let v = b[*i..*i + n].to_vec();
            *i += n;
            v
        };
        let version = i32::from_le_bytes(take(&mut i, 4).try_into().unwrap());
        let n_in = u8_at(&mut i) as usize;
        let mut vin = Vec::new();
        for _ in 0..n_in {
            let txhash = take(&mut i, 32).try_into().unwrap();
            let n = u32::from_le_bytes(take(&mut i, 4).try_into().unwrap());
            let script_len = u8_at(&mut i) as usize;
            let script = take(&mut i, script_len);
            let sequence = u32::from_le_bytes(take(&mut i, 4).try_into().unwrap());
            vin.push(TxIn {
                txhash,
                n,
                script,
                sequence,
                witness: Vec::new(),
            });
        }
        let n_out = u8_at(&mut i) as usize;
        let mut vout = Vec::new();
        for _ in 0..n_out {
            let amount = u64::from_le_bytes(take(&mut i, 8).try_into().unwrap());
            let script_len = u8_at(&mut i) as usize;
            let script = take(&mut i, script_len);
            vout.push(TxOut { amount, script });
        }
        let locktime = u32::from_le_bytes(take(&mut i, 4).try_into().unwrap());
        assert_eq!(i, b.len(), "trailing bytes in vector tx");
        Transaction {
            version,
            vin,
            vout,
            locktime,
        }
    }

    const BIP341_UNSIGNED_TX: &str = "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d";

    /// `(scriptPubKey, amountSats)` of the nine UTXOs spent by the
    /// BIP-341 wallet test vector transaction.
    fn bip341_spend_context() -> SpendContext {
        let spks = [
            "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
            "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
            "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
            "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
            "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc",
            "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
            "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
            "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
        ];
        let amounts = [
            420_000_000u64,
            462_000_000,
            294_000_000,
            504_000_000,
            630_000_000,
            378_000_000,
            672_000_000,
            546_000_000,
            588_000_000,
        ];
        SpendContext {
            inputs: spks
                .iter()
                .zip(amounts)
                .map(|(spk, amount)| SpendInput {
                    amount,
                    script_pubkey: hex::decode(spk).unwrap(),
                })
                .collect(),
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip341_sighash_matches_official_vector() {
        // Input 4 of the BIP-341 wallet test vector is signed with
        // SIGHASH_DEFAULT (hashType 0) — the exact scheme yubtc uses.
        let tx = parse_unsigned_tx(BIP341_UNSIGNED_TX);
        let spend = bip341_spend_context();
        let sighash = taproot_keypath_sighash(&tx, 4, &spend).unwrap();
        assert_eq!(
            hex::encode(sighash),
            "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip341_schnorr_signature_matches_official_vector() {
        // The BIP-341 vectors publish unredacted tweaked private
        // keys: signing the official input-4 digest with the vector's
        // tweakedPrivkey and aux = 0x00×32 must reproduce the
        // published witness byte-for-byte. This pins the BIP-340
        // signing primitive (incl. aux handling) that
        // `taproot_sign_sighash` delegates to.
        let sighash: [u8; 32] =
            hex::decode("4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef")
                .unwrap()
                .try_into()
                .unwrap();
        let tweaked: [u8; 32] =
            hex::decode("a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7f14b549400b4d501")
                .unwrap()
                .try_into()
                .unwrap();
        let key = k256::schnorr::SigningKey::from_bytes(&tweaked).unwrap();
        let sig = key.sign_raw(&sighash, &[0u8; 32]).unwrap();
        assert_eq!(
            hex::encode(sig.to_bytes()),
            "b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_tweaked_scalar_matches_bip341_vector() {
        // Vector input 0 (key-path, empty Merkle root): the tweaked
        // private key derived from the internal key must equal the
        // published tweakedPrivkey.
        let internal_bytes: [u8; 32] =
            hex::decode("6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa")
                .unwrap()
                .try_into()
                .unwrap();
        let internal = SigningKey::from_bytes((&internal_bytes).into()).unwrap();
        let tweaked = taproot_tweaked_scalar(&internal);
        assert_eq!(
            hex::encode(tweaked.to_bytes()),
            "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_tweaked_scalar_always_matches_output_key() {
        // For every key (both internal-key parities and both tweaked
        // point parities occur across this range) the tweaked scalar
        // must sign under the x-only tweaked output key: the BIP-340
        // signer normalizes parity internally, so `x((d+t)·G)` — the
        // only thing an address commits to — matches in both cases.
        use crate::address::taproot_output_key;
        use k256::schnorr::SigningKey as SchnorrKey;

        for i in 1u8..=8 {
            let mut scalar = [0u8; 32];
            scalar[31] = i;
            let internal = SigningKey::from_bytes((&scalar).into()).unwrap();
            let tweaked = taproot_tweaked_scalar(&internal);
            let xonly: [u8; 32] = {
                let norm = SchnorrKey::from_bytes(&internal.to_bytes()).unwrap();
                norm.verifying_key().to_bytes().into()
            };
            let q_even = taproot_output_key(&xonly).unwrap();
            let tweaked_key = SchnorrKey::from_bytes(&tweaked.to_bytes()).unwrap();
            assert_eq!(
                tweaked_key.verifying_key().to_bytes().as_slice(),
                q_even,
                "scalar {i}"
            );
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_tweaked_scalar_normalizes_internal_parity() {
        // Explicit-parity audit (stage 3; see the parity-audit doc on
        // `taproot_tweaked_scalar`): BIP-341 «Construction» computes
        // the tweak over the x-only internal key, so a raw scalar `d`
        // and its negation `n − d` (opposite SEC1 parity byte,
        // identical x) must yield the *same* tweaked scalar — both
        // normalize to the even-Y representative before `t` is added
        // (BIP-340 § 2 «Public Key Generation»). Rust delegates the
        // flip to k256's `From<NonZeroScalar>`; if a k256 upgrade
        // ever dropped it, the parity pairs would diverge here (and
        // `taproot_tweaked_scalar_always_matches_output_key` would
        // fail for odd-Y keys) instead of silently deriving keys that
        // disagree with their own address. The hardcoded values come
        // from the Python mirror (`transaction.taproot_tweaked_scalar`
        // in yubtc-python), which performs the `n − d` flip
        // explicitly.
        use k256::elliptic_curve::bigint::U256;
        use k256::elliptic_curve::ops::Reduce;

        // (scalar d, Python-mirror tweaked scalar for d / n − d).
        let cases: &[(u64, &str)] = &[
            (
                1,
                "3cf5216d476a5e637bf0da674e50ddf55c403270dd36494dfcca438132fa30e8",
            ),
            (
                0x2a,
                "0b3bbf46d8cda9544f711b6cfb89d730ff17d38b95680cff668a157ef518b042",
            ),
        ];

        for &(d_val, py_tweaked_hex) in cases {
            let mut bytes = [0u8; 32];
            bytes[24..].copy_from_slice(&d_val.to_be_bytes());
            let d = <k256::Scalar as Reduce<U256>>::reduce_bytes((&bytes).into());
            let d_neg = -d;

            let key = SigningKey::from_bytes(&d.to_bytes()).unwrap();
            let key_neg = SigningKey::from_bytes(&d_neg.to_bytes()).unwrap();

            // The pair spans both parities of the raw key (0x02/0x03)
            // while committing to the same x-only internal key.
            let pk = privkey_to_pubkey(&key);
            let pk_neg = privkey_to_pubkey(&key_neg);
            assert_ne!(pk[0], pk_neg[0], "n − d must flip the pubkey parity");
            assert_eq!(&pk[1..], &pk_neg[1..], "n − d keeps the x coordinate");

            // Parity independence: both members normalize to the
            // even-Y scalar before the tweak, so the tweaked scalar
            // must coincide.
            let t1 = taproot_tweaked_scalar(&key);
            let t2 = taproot_tweaked_scalar(&key_neg);
            assert_eq!(
                t1, t2,
                "tweaked scalar must not depend on the internal-key parity (d={d_val:#x})"
            );

            // Bit-for-bit agreement with the explicit `n − d` flip in
            // the Python mirror.
            assert_eq!(
                hex::encode(t1.to_bytes()),
                py_tweaked_hex,
                "tweaked scalar diverges from the Python mirror (d={d_val:#x})"
            );

            // End-to-end: the tweaked key is exactly the BIP-86
            // output key the taproot address commits to.
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&pk[1..]);
            let out = crate::address::taproot_output_key(&xonly).unwrap();
            let tweaked_key = k256::schnorr::SigningKey::from_bytes(&t1.to_bytes()).unwrap();
            assert_eq!(
                tweaked_key.verifying_key().to_bytes().as_slice(),
                out,
                "tweaked key must equal the tweaked output key (d={d_val:#x})"
            );
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_sign_sighash_is_deterministic_and_verifies() {
        // Deterministic aux (ОВ-3): signing twice yields identical
        // bytes, and the signature verifies under the tweaked output
        // key.
        use k256::ecdsa::SigningKey as EcdsaKey;
        use k256::schnorr::{Signature as SchnorrSig, VerifyingKey};

        let mut scalar = [0u8; 32];
        scalar[31] = 0x2a;
        let internal = EcdsaKey::from_bytes((&scalar).into()).unwrap();
        let sighash = [7u8; 32];
        let sig1 = taproot_sign_sighash(&internal, &sighash);
        let sig2 = taproot_sign_sighash(&internal, &sighash);
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 64);

        // Verify against the BIP-86 tweaked output key.
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&privkey_to_pubkey(&internal)[1..]);
        let output_key = crate::address::taproot_output_key(&xonly).unwrap();
        let vk = VerifyingKey::from_bytes(&output_key).unwrap();
        vk.verify_raw(&sighash, &SchnorrSig::try_from(&sig1[..]).unwrap())
            .unwrap();
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_scriptpath_sighash_matches_the_reference_implementation() {
        // The script-path digest must equal the `bitcoin` crate's
        // reference `taproot_script_spend_signature_hash` for the same
        // transaction / context / leaf (deliberately independent of
        // the hand-rolled SigMsg assembly above), with SIGHASH_DEFAULT
        // and no annex.
        use bitcoin::consensus::deserialize;
        use bitcoin::hashes::Hash as _;
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::{Amount, Transaction as BtcTx, TxOut as BtcTxOut};

        let tx = Transaction {
            version: 2,
            vin: vec![
                TxIn {
                    txhash: TXHASH,
                    n: 0,
                    script: vec![],
                    sequence: 0xffff_fffe,
                    witness: Vec::new(),
                },
                TxIn {
                    txhash: [0x5au8; 32],
                    n: 1,
                    script: vec![],
                    sequence: 0xffff_fffe,
                    witness: Vec::new(),
                },
            ],
            vout: vec![TxOut {
                amount: 40_000,
                script: vec![0x51, 0x20],
            }],
            locktime: 7,
        };
        let spend = SpendContext {
            inputs: vec![
                SpendInput {
                    amount: 50_000,
                    script_pubkey: make_p2tr_fixture_spk(),
                },
                SpendInput {
                    amount: 60_000,
                    script_pubkey: vec![0x51, 0x20],
                },
            ],
        };
        let leaf: [u8; 32] =
            hex::decode("640fca23685170704e436970f8ca462899442be7b8a4010bcb31eb579c65c004")
                .unwrap()
                .try_into()
                .unwrap();

        // The reference types are built from the wire bytes — the
        // same consensus parse an independent verifier performs.
        let ref_tx: BtcTx = deserialize(&tx.serialize_stripped()).expect("reference wire parse");
        let utxos = [
            BtcTxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(
                    spend.inputs[0].script_pubkey.clone(),
                ),
            },
            BtcTxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(
                    spend.inputs[1].script_pubkey.clone(),
                ),
            },
        ];
        let leaf_hash = bitcoin::taproot::TapLeafHash::from_byte_array(leaf);
        let expected = SighashCache::new(&ref_tx)
            .taproot_script_spend_signature_hash(
                1,
                &Prevouts::All(&utxos),
                leaf_hash,
                TapSighashType::Default,
            )
            .expect("reference digest");
        assert_eq!(
            hex::encode(expected.to_byte_array()),
            hex::encode(taproot_scriptpath_sighash(&tx, 1, &spend, &leaf).unwrap())
        );
        // Sanity: the same leaf under the key-path digest must
        // produce a different value (spend_type 0x00, no ext).
        let keypath = taproot_keypath_sighash(&tx, 1, &spend).unwrap();
        assert_ne!(
            keypath,
            taproot_scriptpath_sighash(&tx, 1, &spend, &leaf).unwrap()
        );
        // A different leaf changes the digest (the ext section is
        // part of the commitment).
        let other_leaf = [0x11u8; 32];
        assert_ne!(
            taproot_scriptpath_sighash(&tx, 1, &spend, &leaf).unwrap(),
            taproot_scriptpath_sighash(&tx, 1, &spend, &other_leaf).unwrap()
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_scriptpath_sighash_validates_context_and_index() {
        let tx = example_tx();
        let leaf = [0u8; 32];
        let empty = SpendContext { inputs: vec![] };
        assert_eq!(
            taproot_scriptpath_sighash(&tx, 0, &empty, &leaf),
            Err(TransactionError::MissingSpendContext)
        );
        let one = SpendContext {
            inputs: vec![SpendInput {
                amount: 1,
                script_pubkey: vec![0xac],
            }],
        };
        assert_eq!(
            taproot_scriptpath_sighash(&tx, 5, &one, &leaf),
            Err(TransactionError::InputIndexOutOfRange(5, 1))
        );
    }

    /// scriptPubKey fixture for the script-path digest test: the
    /// 34-byte P2TR output of the reference 2-of-3 leaf.
    fn make_p2tr_fixture_spk() -> Vec<u8> {
        use k256::elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::{bigint::U256, point::AffineCoordinates as _};
        use k256::ProjectivePoint;

        let internal = crate::fwd::MS_TAPSCRIPT_INTERNAL_KEY;
        let leaf: [u8; 32] =
            hex::decode("640fca23685170704e436970f8ca462899442be7b8a4010bcb31eb579c65c004")
                .unwrap()
                .try_into()
                .unwrap();
        let mut sec1 = [0u8; 33];
        sec1[0] = 0x02;
        sec1[1..].copy_from_slice(&internal);
        let h = k256::PublicKey::from_sec1_bytes(&sec1).unwrap();
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&internal);
        msg[32..].copy_from_slice(&leaf);
        let t = <k256::Scalar as Reduce<U256>>::reduce_bytes(
            &crate::misc::tagged_hash(b"TapTweak", &msg).into(),
        );
        let q =
            (ProjectivePoint::from(h.as_affine()) + (ProjectivePoint::GENERATOR * t)).to_affine();
        let mut out = vec![0x51, 0x20];
        out.extend_from_slice(&q.x());
        out
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_sign_sighash_untweaked_verifies_under_the_script_key() {
        // R-MS-10/ОВ-10: the script-path signature is BIP-340 under
        // the UNTWEAKED key — it verifies against the x-only key the
        // tapscript push carries, and does NOT verify under the
        // BIP-86-style tweaked output key (the tweak is key-path
        // mechanics only).
        use k256::schnorr::{Signature as SchnorrSig, VerifyingKey};

        let mut scalar = [0u8; 32];
        scalar[31] = 0x2a;
        let internal = SigningKey::from_bytes((&scalar).into()).unwrap();
        let sighash = [0x42u8; 32];
        let sig = taproot_sign_sighash_untweaked(&internal, &sighash);
        assert_eq!(sig.len(), 64);
        // Deterministic (aux = 0x00 × 32, ОВ-3).
        assert_eq!(sig, taproot_sign_sighash_untweaked(&internal, &sighash));

        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&privkey_to_pubkey(&internal)[1..]);
        let vk = VerifyingKey::from_bytes(&xonly).unwrap();
        vk.verify_raw(&sighash, &SchnorrSig::try_from(&sig[..]).unwrap())
            .expect("verifies under the untweaked x-only script key");
        // The key-path (BIP-86) tweak of the same key must NOT
        // verify this signature.
        let tweaked = crate::address::taproot_output_key(&xonly).unwrap();
        let tweaked_vk = VerifyingKey::from_bytes(&tweaked).unwrap();
        assert!(tweaked_vk
            .verify_raw(&sighash, &SchnorrSig::try_from(&sig[..]).unwrap())
            .is_err());
        // Parity independence: n − d (odd-Y representative of the
        // same x-only key) produces the identical signature — the
        // BIP-340 normalization of R-MS-10.
        use k256::elliptic_curve::bigint::U256;
        use k256::elliptic_curve::ops::Reduce;
        let d = <k256::Scalar as Reduce<U256>>::reduce_bytes((&scalar).into());
        let neg = SigningKey::from_bytes(&(-d).to_bytes()).unwrap();
        assert_ne!(privkey_to_pubkey(&neg)[0], privkey_to_pubkey(&internal)[0]);
        assert_eq!(
            taproot_sign_sighash_untweaked(&neg, &sighash),
            sig,
            "n − d normalizes to the same even-Y scalar (same x-only key)"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_segwit_p2tr_full_flow() {
        // End-to-end: derive an internal key, build a P2TR input
        // whose scriptPubKey is the tweaked output key, sign via
        // sign_segwit, then verify the bare 64-byte witness against
        // the BIP-341 digest and the tweaked key.
        use crate::script::make_p2tr_lock_script;
        use k256::schnorr::{Signature as SchnorrSig, VerifyingKey};

        let internal = seed_privkey();
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&privkey_to_pubkey(&internal)[1..]);
        let output_key = crate::address::taproot_output_key(&xonly).unwrap();

        let tx = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: TXHASH,
                n: 3,
                script: make_p2tr_lock_script(&output_key).to_vec(),
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 1_000,
                script: vec![0x51, 0x20],
            }],
            locktime: 0,
        };
        let spend = SpendContext {
            inputs: vec![SpendInput {
                amount: 50_000,
                script_pubkey: tx.vin[0].script.clone(),
            }],
        };
        let signed = tx
            .sign_segwit(
                &[(internal.clone(), privkey_to_pubkey(&internal))],
                Some(&spend),
            )
            .unwrap();
        assert!(signed.vin[0].script.is_empty());
        assert_eq!(signed.vin[0].witness.len(), 1);
        let sig = &signed.vin[0].witness[0];
        assert_eq!(sig.len(), 64, "SIGHASH_DEFAULT: no sighash suffix");

        let sighash = taproot_keypath_sighash(&tx, 0, &spend).unwrap();
        let vk = VerifyingKey::from_bytes(&output_key).unwrap();
        vk.verify_raw(&sighash, &SchnorrSig::try_from(&sig[..]).unwrap())
            .unwrap();

        // Wire serialization carries the witness; txid does not.
        assert!(signed.has_witness());
        assert_ne!(signed.wtxid(), signed.id());
    }

    // --- sign_segwit error paths -----------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_segwit_rejects_signer_mismatch() {
        let pk = seed_privkey();
        let pubkey = privkey_to_pubkey(&pk);
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: TXHASH,
                n: 0,
                script: vec![],
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            vout: vec![],
            locktime: 0,
        };
        let err = tx.sign_segwit(&[], None).unwrap_err();
        assert_eq!(err, TransactionError::SignersLengthMismatch(0, 1));
        let err = tx
            .sign_segwit(&[(pk.clone(), pubkey), (pk, pubkey)], None)
            .unwrap_err();
        assert_eq!(err, TransactionError::SignersLengthMismatch(2, 1));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_segwit_requires_spend_context_for_p2wpkh() {
        let pk = seed_privkey();
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: TXHASH,
                n: 0,
                // Full P2WPKH shape 00 14 <20×0> so the scheme
                // dispatch selects Bip143P2wpkh.
                script: {
                    let mut s = vec![0x00, 0x14];
                    s.extend_from_slice(&[0u8; 20]);
                    s
                },
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            vout: vec![],
            locktime: 0,
        };
        let signers = [(pk, [0u8; 33])];
        let err = tx.sign_segwit(&signers, None).unwrap_err();
        assert_eq!(err, TransactionError::MissingSpendContext);
        // Context present but shorter than vin → same error.
        let spend = SpendContext { inputs: vec![] };
        let err = tx.sign_segwit(&signers, Some(&spend)).unwrap_err();
        assert_eq!(err, TransactionError::MissingSpendContext);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sign_segwit_requires_full_context_for_p2tr() {
        let pk = seed_privkey();
        let pubkey = privkey_to_pubkey(&pk);
        // Full P2TR shape 51 20 <32×0> so the dispatch selects
        // Bip341KeyPath; second input stays legacy-shaped (empty).
        let mut p2tr_spk = vec![0x51, 0x20];
        p2tr_spk.extend_from_slice(&[0u8; 32]);
        let tx = Transaction {
            version: 2,
            vin: vec![
                TxIn {
                    txhash: TXHASH,
                    n: 0,
                    script: p2tr_spk,
                    sequence: 0xffff_fffe,
                    witness: Vec::new(),
                },
                TxIn {
                    txhash: TXHASH,
                    n: 1,
                    script: vec![],
                    sequence: 0xffff_fffe,
                    witness: Vec::new(),
                },
            ],
            vout: vec![],
            locktime: 0,
        };
        let signers = [(pk.clone(), pubkey), (pk, pubkey)];
        // None at all.
        let err = tx.sign_segwit(&signers, None).unwrap_err();
        assert_eq!(err, TransactionError::MissingSpendContext);
        // Non-empty but not covering both inputs.
        let spend = SpendContext {
            inputs: vec![SpendInput {
                amount: 1,
                script_pubkey: vec![0x51, 0x20],
            }],
        };
        let err = tx.sign_segwit(&signers, Some(&spend)).unwrap_err();
        assert_eq!(err, TransactionError::MissingSpendContext);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_keypath_sighash_rejects_short_context_and_bad_index() {
        let tx = example_tx(); // one input
        let spend = SpendContext { inputs: vec![] };
        let err = taproot_keypath_sighash(&tx, 0, &spend).unwrap_err();
        assert_eq!(err, TransactionError::MissingSpendContext);
        // Context covering exactly the inputs, but index out of
        // range.
        let one = SpendContext {
            inputs: vec![SpendInput {
                amount: 1,
                script_pubkey: vec![0xac],
            }],
        };
        let err = taproot_keypath_sighash(&tx, 5, &one).unwrap_err();
        assert_eq!(err, TransactionError::InputIndexOutOfRange(5, 1));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn sig_scheme_dispatch() {
        // P2WPKH shape 00 14 <20>.
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(&[0u8; 20]);
        assert_eq!(
            SigScheme::from_script_pubkey(&p2wpkh),
            SigScheme::Bip143P2wpkh
        );
        // P2TR shape 51 20 <32>.
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            SigScheme::from_script_pubkey(&p2tr),
            SigScheme::Bip341KeyPath
        );
        // Legacy shapes and malformed look-alikes.
        assert_eq!(SigScheme::from_script_pubkey(&[0u8; 25]), SigScheme::Legacy);
        assert_eq!(SigScheme::from_script_pubkey(&[0u8; 23]), SigScheme::Legacy);
        assert_eq!(SigScheme::from_script_pubkey(&[]), SigScheme::Legacy);
        let mut bad22 = vec![0x01, 0x14]; // wrong version opcode
        bad22.extend_from_slice(&[0u8; 20]);
        assert_eq!(SigScheme::from_script_pubkey(&bad22), SigScheme::Legacy);
        let mut bad34 = vec![0x51, 0x21]; // wrong push size
        bad34.extend_from_slice(&[0u8; 32]);
        assert_eq!(SigScheme::from_script_pubkey(&bad34), SigScheme::Legacy);
        // Right version opcode, wrong push size: the second `&&` arm
        // of the P2WPKH check short-circuits into `Legacy`.
        let mut bad22_push = vec![0x00, 0x15]; // 0x15 ≠ 0x14
        bad22_push.extend_from_slice(&[0u8; 20]);
        assert_eq!(
            SigScheme::from_script_pubkey(&bad22_push),
            SigScheme::Legacy
        );
        // Wrong version opcode at the right length: the second `&&`
        // arm of the P2TR check short-circuits into `Legacy`.
        let mut bad34_version = vec![0x00, 0x20]; // 0x00 ≠ 0x51
        bad34_version.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            SigScheme::from_script_pubkey(&bad34_version),
            SigScheme::Legacy
        );
    }

    // --- proptests ------------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(1000))]

        #[ntest_timeout::timeout(30000)]
        #[test]
        fn serialization_invariants_hold(
            version in 0i32..=2,
            n_in in 0usize..=3,
            n_out in 0usize..=3,
            witness in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..=70), 0..=3),
        ) {
            let vin: Vec<TxIn> = (0..n_in).map(|i| TxIn {
                txhash: [i as u8; 32],
                n: i as u32,
                script: vec![0xac; i],
                sequence: 0xffff_fffe,
                witness: if i < witness.len() { vec![witness[i].clone()] } else { Vec::new() },
            }).collect();
            let vout: Vec<TxOut> = (0..n_out).map(|i| TxOut {
                amount: 1_000 + i as u64,
                script: vec![0x76; i],
            }).collect();
            let tx = Transaction { version, vin, vout, locktime: 0 };

            let base = tx.serialize_stripped().len();
            let total = tx.serialize_wire().len();
            // BIP-141 weight formula and the fee invariants.
            prop_assert_eq!(tx.weight(), base * 3 + total);
            prop_assert_eq!(tx.vsize(), tx.weight().div_ceil(4));
            prop_assert!(total >= base);
            prop_assert!(tx.vsize() >= base);
            if !tx.has_witness() {
                prop_assert_eq!(total, base);
                prop_assert_eq!(tx.vsize(), base);
                prop_assert_eq!(tx.wtxid(), tx.id());
                // No witness ⇒ the wire layout *is* the stripped one,
                // byte for byte.
                prop_assert_eq!(tx.serialize_wire(), tx.serialize_stripped());
            } else {
                // Converse direction: marker/flag plus witness data
                // push the wire strictly past the stripped size, so
                // weight ≥ 4·base + 3 and the witness discount can
                // never bill a witnessed tx at the bare size — vsize
                // is *strictly* above the stripped length.
                prop_assert!(total > base);
                prop_assert!(tx.vsize() > base);
                prop_assert_ne!(tx.wtxid(), tx.id());
            }
        }

        // vsize monotonicity in witness length (BIP-141): growing a
        // witness stack never decreases the vsize, and the
        // empty → non-empty step strictly increases it — a bare tx
        // weighs exactly 4·base, so the marker/flag bytes (which enter
        // the wire layout on top of the first item) always cross at
        // least one vsize unit.
        #[ntest_timeout::timeout(30000)]
        #[test]
        fn vsize_monotone_in_witness_length(
            n_in in 1usize..=3,
            n_out in 0usize..=3,
            items in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..=80),
                0..=5,
            ),
        ) {
            let build = |witness: Vec<Vec<u8>>| {
                let mut tx = Transaction {
                    version: 2,
                    vin: (0..n_in)
                        .map(|i| TxIn {
                            txhash: [i as u8; 32],
                            n: i as u32,
                            script: vec![0xac; i],
                            sequence: 0xffff_fffe,
                            witness: Vec::new(),
                        })
                        .collect(),
                    vout: (0..n_out)
                        .map(|i| TxOut {
                            amount: 1_000 + i as u64,
                            script: vec![0x76; i],
                        })
                        .collect(),
                    locktime: 0,
                };
                tx.vin[0].witness = witness;
                tx
            };
            for prefix in 0..=items.len() {
                let tx = build(items[..prefix].to_vec());
                let vsize = tx.vsize();
                let wire = tx.serialize_wire().len();
                if prefix < items.len() {
                    let grown = build(items[..prefix + 1].to_vec());
                    prop_assert!(grown.vsize() >= vsize);
                    prop_assert!(grown.serialize_wire().len() >= wire);
                    if prefix == 0 {
                        prop_assert!(grown.vsize() > vsize);
                    }
                }
            }
        }
    }
}
