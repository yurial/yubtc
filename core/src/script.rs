//! Bitcoin script construction and minimal decoding utilities for yubtc.
//!
//! The full Bitcoin script interpreter is out of scope — yubtc only needs
//! to **build** the canonical P2PKH and P2SH lock scripts that Bitcoin
//! Core expects on `scriptPubKey`, and to **extract** the 20-byte hash
//! out of a P2PKH script it already built. Decoding non-canonical
//! scripts is the network's job (verification), not the wallet's.
//!
//! The opcode constants are kept as plain `u8` because the wallet only
//! references five opcodes (`OP_DUP`, `OP_HASH160`, `OP_EQUAL`,
//! `OP_EQUALVERIFY`, `OP_CHECKSIG`). A full enum would be dead surface
//! for a 100%-coverage rule and a frequent cause of `non-exhaustive`
//! friction in tests.
//!
//! Mirrors `yubtc-python/src/yubtc/script.py` (lock-script side) and the
//! `script2pkh` helper in
//! `yubtc-python/src/yubtc/transaction.py`. Serialisation matches the
//! Python implementation byte-for-byte.
//!
//! The M-of-N multisig surface (specs/spec.md «Multi-sig»):
//! [`make_multisig_redeem_script`] builds the canonical bare
//! `OP_m ‖ (0x21 ‖ pubkey)×N ‖ OP_n ‖ OP_CHECKMULTISIG` redeem script
//! (BIP-67-sorted keys), [`extract_multisig_quorum`] is the strict
//! shape-check counterpart, and [`make_multisig_script_sig`] assembles
//! the final `scriptSig` layout the PSBT Finalizer emits.

use thiserror::Error;

use crate::fwd::MS_MAX_PUBKEYS;

/// `OP_0` (0x00). Pushes an empty byte string; on the wire it encodes
/// witness version 0 in SegWit lock scripts.
pub const OP_0: u8 = 0x00;

/// `OP_1` (0x51). Pushes 1; on the wire it encodes witness version 1
/// in SegWit lock scripts.
pub const OP_1: u8 = 0x51;

/// `OP_PUSHBYTES_20` (0x14). Pushes the next 20 bytes.
pub const OP_PUSHBYTES_20: u8 = 0x14;

/// `OP_PUSHBYTES_32` (0x20). Pushes the next 32 bytes.
pub const OP_PUSHBYTES_32: u8 = 0x20;

/// `OP_DUP` (0x76). Duplicates the top stack item.
pub const OP_DUP: u8 = 0x76;

/// `OP_HASH160` (0xa9). `SHA-256 → RIPEMD-160` of the top stack item.
pub const OP_HASH160: u8 = 0xa9;

/// `OP_EQUAL` (0x87). Pops two items, pushes 1 if equal else 0.
pub const OP_EQUAL: u8 = 0x87;

/// `OP_EQUALVERIFY` (0x88). Like `OP_EQUAL` but fails the script if not
/// equal.
pub const OP_EQUALVERIFY: u8 = 0x88;

/// `OP_CHECKSIG` (0xac). Verifies a signature against the public key on
/// the top of the stack.
pub const OP_CHECKSIG: u8 = 0xac;

/// `OP_CHECKMULTISIG` (0xae). Pops the empty dummy element, then M
/// signatures and the M-of-N pubkey list, and verifies. The terminal
/// opcode of a canonical multisig redeem script (Phase 15, R-MS-3).
pub const OP_CHECKMULTISIG: u8 = 0xae;

/// `OP_CHECKSIGADD` (0xba, BIP-342). Pops a signature and a pubkey,
/// verifies against the script-path sighash, and adds the boolean
/// result (1/0) to the numeric accumulator below — the CHECKMULTISIG
/// replacement of the tapscript idiom (R-MS-7). CHECKMULTISIG itself
/// is a disabled opcode under tapscript consensus (fails like
/// `OP_RETURN`), so the two forms cannot be confused.
pub const OP_CHECKSIGADD: u8 = 0xba;

/// `OP_NUMEQUAL` (0x9d). Pops two numeric items, pushes 1 when their
/// numeric values are equal. The terminal opcode of the canonical
/// tapscript idiom — the plain (non-VERIFY) mirror of
/// [`OP_CHECKMULTISIG`]'s semantics (R-MS-7).
pub const OP_NUMEQUAL: u8 = 0x9d;

/// Leaf version byte of the canonical Tapscript quorum leaf
/// (BIP-342): 0xc0 = leaf version 192, the only defined tapscript
/// version. Enters the leaf hash (`0xc0 ‖ compact_size ‖ script`) and
/// the control block's first byte (`c[0] = 0xc0 | parity(y(Q))`).
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// `OP_PUSHDATA1` (0x4c). Pushes the next byte-many bytes — the
/// first length escalation for items above the single-opcode
/// 0x4b-byte limit (a > 75-byte multisig redeem script is pushed this
/// way in a `scriptSig`).
pub const OP_PUSHDATA1: u8 = 0x4c;

/// `OP_PUSHDATA2` (0x4d). Pushes the next two byte-many bytes — the
/// second length escalation (a redeem script with more than 7 keys
/// exceeds 255 bytes: 34·8 + 4 = 276).
pub const OP_PUSHDATA2: u8 = 0x4d;

/// Errors that `script` can return to the wallet.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScriptError {
    /// The lock script did not pass the canonical P2PKH/P2SH shape
    /// check. Either wrong length or wrong opcode at a fixed position.
    #[error("invalid script: expected P2PKH layout, got {0} bytes")]
    InvalidScript(usize),

    /// A redeem script (or key set) did not pass the canonical bare
    /// CHECKMULTISIG shape check (Phase 15, R-MS-2/R-MS-3): quorum
    /// bounds violated, non-canonical pubkey push, duplicate key, or
    /// any byte layout other than
    /// `OP_m ‖ (0x21 ‖ 33B compressed key)×N ‖ OP_n ‖ OP_CHECKMULTISIG`.
    #[error("invalid multisig redeem script")]
    InvalidMultisigRedeem,

    /// A leaf script (or key set) did not pass the canonical tapscript
    /// CHECKSIGADD shape check (v0.3, R-MS-7): quorum bounds violated,
    /// non-x-only or duplicate key, `OP_CHECKMULTISIG` /
    /// `NUMEQUALVERIFY` / any byte layout other than
    /// `0x20‖pk_1 OP_CHECKSIG … 0x20‖pk_N OP_CHECKSIGADD OP_M
    /// OP_NUMEQUAL`.
    #[error("invalid multisig tapscript")]
    InvalidMultisigTapscript,
}

/// Build the canonical P2PKH lock script for a 20-byte hash160.
///
/// Layout: `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG` —
/// exactly 25 bytes. This is the script that goes into a transaction
/// output (`scriptPubKey`) when paying to a P2PKH address.
///
/// Panics if `hash160.len() != 20`; the type signature makes the only
/// legal call site pass a 20-byte slice, so the runtime check is a
/// belt-and-braces guard against future refactors losing the type.
pub fn make_p2pkh_lock_script(hash160: &[u8]) -> Vec<u8> {
    assert_eq!(
        hash160.len(),
        20,
        "hash160 must be 20 bytes, got {}",
        hash160.len()
    );
    let mut out = Vec::with_capacity(25);
    out.push(OP_DUP);
    out.push(OP_HASH160);
    out.push(0x14);
    out.extend_from_slice(hash160);
    out.push(OP_EQUALVERIFY);
    out.push(OP_CHECKSIG);
    out
}

/// Build the canonical P2SH lock script for a 20-byte hash160.
///
/// Layout: `OP_HASH160 <20 bytes> OP_EQUAL` — exactly 23 bytes. This is
/// the script that goes into a transaction output when paying to a
/// P2SH address. The hash is the `hash160` of the redeem script, not
/// the address itself.
pub fn make_p2sh_lock_script(hash160: &[u8]) -> Vec<u8> {
    assert_eq!(
        hash160.len(),
        20,
        "hash160 must be 20 bytes, got {}",
        hash160.len()
    );
    let mut out = Vec::with_capacity(23);
    out.push(OP_HASH160);
    out.push(0x14);
    out.extend_from_slice(hash160);
    out.push(OP_EQUAL);
    out
}

/// Single-item data push: a length prefix followed by the item.
///
/// Items up to `0x4b` bytes use the one-opcode form
/// (`OP_PUSHBYTES_N`); 76–255 bytes escalate to [`OP_PUSHDATA1`] with
/// an explicit one-byte length; 256–65535 bytes escalate to
/// [`OP_PUSHDATA2`] with a little-endian two-byte length. The wallet's
/// largest item is a 15-key redeem script (34·15 + 4 = 514 bytes),
/// so [`OP_PUSHDATA2`] is the deepest encoding it ever needs.
///
/// This is the on-chain-valid scriptSig element encoding used by the
/// legacy signing path: `push(sig ‖ 0x01) ‖ push(pubkey)`, matching
/// `yubtc-python`'s `CScript([signature, pubkey])` and the spec's
/// Finalizer layout (`FINAL_SCRIPTSIG = push(sig‖0x01) ‖ push(pubkey)`).
/// A raw `sig ‖ pubkey` concatenation is NOT a script: the interpreter
/// would read the DER bytes as opcodes and the input would never
/// validate.
///
/// Panics if `data.len() > 0xffff`: the wallet pushes 33-byte
/// compressed pubkeys, 71–73-byte `DER ‖ sighash` ECDSA signatures,
/// and redeem scripts capped at 513 bytes ([`MS_MAX_PUBKEYS`] keeps
/// the redeem script inside the 520-byte `MAX_SCRIPT_ELEMENT_SIZE`
/// consensus push limit). Longer items would need the 5/9-byte
/// `OP_PUSHDATA4` encoding — dead surface, so the guard turns a
/// future longer item into a loud failure instead of a silently
/// malformed script.
pub fn push_data(data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() <= 0xffff,
        "item too long for a single/OP_PUSHDATA1/OP_PUSHDATA2 push: {} bytes",
        data.len()
    );
    let mut out = Vec::with_capacity(data.len() + 3);
    if data.len() <= 0x4b {
        out.push(data.len() as u8);
    } else if data.len() <= 0xff {
        out.push(OP_PUSHDATA1);
        out.push(data.len() as u8);
    } else {
        out.push(OP_PUSHDATA2);
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

/// The on-wire length of [`push_data`] for an item of `len` bytes:
/// 1 for the single-opcode form, 2 for `OP_PUSHDATA1`, 3 for
/// `OP_PUSHDATA2` (the spec's `pushlen(|redeem|)` in the multisig
/// `scriptSig` size model).
pub fn push_data_len(len: usize) -> usize {
    if len <= 0x4b {
        1
    } else if len <= 0xff {
        2
    } else {
        3
    }
}

/// Extract the 20-byte hash160 from a canonical P2PKH script.
///
/// Returns `InvalidScript` if the script doesn't match the 25-byte
/// P2PKH template exactly. This is used by the wallet to recover the
/// destination address from a UTXO's `script_pubkey` and is **not** a
/// general-purpose script decoder — non-canonical scripts (P2SH,
/// non-standard, witness) are rejected, by design.
///
/// The wallet only ever feeds P2PKH scripts in (anything else is an
/// `InvalidUtxo` upstream of this call), so we reject non-P2PKH without
/// bothering with a full opcode parser.
pub fn extract_p2pkh_hash(script: &[u8]) -> Result<[u8; 20], ScriptError> {
    // Length guard first -- cheap and catches the common case
    // (P2SH scripts are 23 bytes, well below the 25-byte P2PKH
    // shape). Then opcode layout: every fixed-position byte must
    // match exactly. The point of the strict shape check (rather
    // than a generic opcode parser) is to refuse P2SH and other
    // non-P2PKH scripts that happen to have a 20-byte push in the
    // middle: the wallet only ever feeds P2PKH in, anything else
    // is an `InvalidUtxo` upstream.
    if script.len() != 25 {
        return Err(ScriptError::InvalidScript(script.len()));
    }
    if script[0] != OP_DUP
        || script[1] != OP_HASH160
        || script[2] != 0x14
        || script[23] != OP_EQUALVERIFY
        || script[24] != OP_CHECKSIG
    {
        return Err(ScriptError::InvalidScript(script.len()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&script[3..23]);
    Ok(out)
}

/// Build the canonical P2WPKH witness lock script for a 20-byte
/// hash160 (native SegWit, witness version 0).
///
/// Layout: `OP_0 OP_PUSHBYTES_20 <20 bytes>` — exactly 22 bytes
/// (`00 14 <hash>`). This is the `scriptPubKey` corresponding to a
/// `bc1q…` address. Infallible: the fixed-size types rule out every
/// length error by construction.
pub fn make_p2wpkh_lock_script(hash160: &[u8; 20]) -> [u8; 22] {
    let mut out = [0u8; 22];
    out[0] = OP_0;
    out[1] = OP_PUSHBYTES_20;
    out[2..].copy_from_slice(hash160);
    out
}

/// Build the canonical P2TR witness lock script for a 32-byte x-only
/// output key (witness version 1, BIP-341/Taproot).
///
/// Layout: `OP_1 OP_PUSHBYTES_32 <32 bytes>` — exactly 34 bytes
/// (`51 20 <key>`). This is the `scriptPubKey` corresponding to a
/// `bc1p…` address. Infallible: fixed-size types rule out every
/// length error by construction.
pub fn make_p2tr_lock_script(output_key: &[u8; 32]) -> [u8; 34] {
    let mut out = [0u8; 34];
    out[0] = OP_1;
    out[1] = OP_PUSHBYTES_32;
    out[2..].copy_from_slice(output_key);
    out
}

/// Extract the 20-byte hash160 from a canonical P2WPKH witness
/// script.
///
/// Strict shape check (like [`extract_p2pkh_hash`], not a general
/// script decoder): the script must be exactly `00 14 <20 bytes>` —
/// 22 bytes. Anything else (other lengths, other witness versions,
/// P2PKH/P2SH) is rejected with [`ScriptError::InvalidScript`].
pub fn extract_p2wpkh_hash(script: &[u8]) -> Result<[u8; 20], ScriptError> {
    if script.len() != 22 || script[0] != OP_0 || script[1] != OP_PUSHBYTES_20 {
        return Err(ScriptError::InvalidScript(script.len()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&script[2..]);
    Ok(out)
}

/// Extract the 32-byte x-only output key from a canonical P2TR
/// witness script.
///
/// Strict shape check (like [`extract_p2pkh_hash`], not a general
/// script decoder): the script must be exactly `51 20 <32 bytes>` —
/// 34 bytes. Anything else is rejected with
/// [`ScriptError::InvalidScript`].
pub fn extract_p2tr_output_key(script: &[u8]) -> Result<[u8; 32], ScriptError> {
    if script.len() != 34 || script[0] != OP_1 || script[1] != OP_PUSHBYTES_32 {
        return Err(ScriptError::InvalidScript(script.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&script[2..]);
    Ok(out)
}

/// Build the canonical P2WSH witness lock script for a 32-byte
/// SHA-256 commitment (native SegWit, witness version 0).
///
/// Layout: `OP_0 OP_PUSHBYTES_32 <32 bytes>` — exactly 34 bytes
/// (`00 20 <hash>`). This is the `scriptPubKey` of a `bc1q…` v0
/// address carrying a 32-byte program; for the v0.3 multisig surface
/// the commitment is `SHA256(redeem)` of the quorum's canonical
/// redeem script. Infallible: the fixed-size type rules out every
/// length error by construction.
pub fn make_p2wsh_lock_script(sha256: &[u8; 32]) -> [u8; 34] {
    let mut out = [0u8; 34];
    out[0] = OP_0;
    out[1] = OP_PUSHBYTES_32;
    out[2..].copy_from_slice(sha256);
    out
}

/// Extract the 32-byte SHA-256 commitment from a canonical P2WSH
/// witness script.
///
/// Strict shape check (like [`extract_p2pkh_hash`], not a general
/// script decoder): the script must be exactly `00 20 <32 bytes>` —
/// 34 bytes. Anything else (other lengths, other witness versions,
/// the 34-byte P2TR script `51 20 <32>`) is rejected with
/// [`ScriptError::InvalidScript`].
pub fn extract_p2wsh_program(script: &[u8]) -> Result<[u8; 32], ScriptError> {
    if script.len() != 34 || script[0] != OP_0 || script[1] != OP_PUSHBYTES_32 {
        return Err(ScriptError::InvalidScript(script.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&script[2..]);
    Ok(out)
}

// --- Multisig (Phase 15, P2SH) ---------------------------------------

/// `OP_N` for N in `1..=16`: `0x50 + N` (single-byte `OP_1`…`OP_16`
/// small-integer opcodes). The quorum bounds keep both multisig
/// counters inside this range.
fn op_n(n: usize) -> u8 {
    debug_assert!((1..=16).contains(&n));
    0x50 + n as u8
}

/// The canonical compressed-pubkey shape accepted in a multisig
/// redeem script: SEC prefix `02` (even Y) or `03` (odd Y). The 33-byte
/// length is enforced by the caller's push-window type (`[u8; 33]`).
/// Bitwise `|` (not `||`) so both prefix arms stay measurable.
fn is_canonical_compressed_pubkey(key: &[u8; 33]) -> bool {
    (key[0] == 0x02) | (key[0] == 0x03)
}

/// Build the canonical bare M-of-N CHECKMULTISIG redeem script
/// (Phase 15, specs/spec.md «Правила» R-MS-2/3/4).
///
/// Layout: `OP_m ‖ (0x21 ‖ <33-byte compressed pubkey>)×N ‖ OP_n ‖
/// OP_CHECKMULTISIG` — nothing else is ever built or accepted.
///
/// Validation:
/// - **R-MS-2 (quorum bounds)**: `1 ≤ m ≤ keys.len() ≤` [`MS_MAX_PUBKEYS`]
///   (= 15 — above it the redeem script no longer fits the 520-byte
///   `MAX_SCRIPT_ELEMENT_SIZE` consensus limit on a single push, so
///   such a P2SH output is fundamentally unspendable);
/// - **R-MS-3 (duplicates)**: two equal keys make the quorum
///   degenerate (one key would have to supply two signatures) and are
///   rejected.
///
/// **R-MS-4 (BIP-67)**: the keys are sorted lexicographically by
/// their 33 compressed bytes before assembly, so the same key *set*
/// always yields the same redeem script — and therefore the same
/// P2SH address — regardless of argument order. Signers place
/// signatures by the *script's* key order ([`extract_multisig_quorum`]
/// returns it), not by argument order.
///
/// Errors: [`ScriptError::InvalidMultisigRedeem`] for every violation
/// above (the wallet maps bounds/duplicates onto the typed
/// `MsError` variants at its own boundary).
pub fn make_multisig_redeem_script(m: usize, keys: &[[u8; 33]]) -> Result<Vec<u8>, ScriptError> {
    let n = keys.len();
    if n == 0 || m == 0 || m > n || n > MS_MAX_PUBKEYS as usize {
        return Err(ScriptError::InvalidMultisigRedeem);
    }
    let mut sorted = keys.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(ScriptError::InvalidMultisigRedeem);
    }
    // Exact capacity: 1 (OP_m) + 34·N + 1 (OP_n) + 1 (OP_CHECKMULTISIG)
    // = 34·N + 3 ≤ 513 bytes for the maximal quorum (15 keys) — inside
    // the 520-byte MAX_SCRIPT_ELEMENT_SIZE push limit.
    let mut out = Vec::with_capacity(34 * n + 3);
    out.push(op_n(m));
    for key in &sorted {
        out.push(0x21);
        out.extend_from_slice(key);
    }
    out.push(op_n(n));
    out.push(OP_CHECKMULTISIG);
    Ok(out)
}

/// Extract the quorum `(m, keys)` from a canonical bare CHECKMULTISIG
/// redeem script — keys in **script order** (the order signatures must
/// take in the final `scriptSig`, R-MS-4).
///
/// Strict shape check, symmetric with [`extract_p2pkh_hash`] — not a
/// general script decoder: the script must be exactly
/// `OP_m ‖ (0x21 ‖ 33-byte compressed pubkey)×N ‖ OP_n ‖
/// OP_CHECKMULTISIG` with `1 ≤ m ≤ n ≤` [`MS_MAX_PUBKEYS`], no
/// `OP_PUSHDATA` wrappers, no trailing bytes, and no duplicate keys
/// (R-MS-3 — yubtc does not sign or finalize such scripts). Anything
/// else is [`ScriptError::InvalidMultisigRedeem`].
pub fn extract_multisig_quorum(script: &[u8]) -> Result<(usize, Vec<[u8; 33]>), ScriptError> {
    // OP_m + one key push + OP_n + OP_CHECKMULTISIG is the minimum.
    if script.len() < 3 + 34 {
        return Err(ScriptError::InvalidMultisigRedeem);
    }
    let m_op = script[0];
    let n_op = script[script.len() - 2];
    if script[script.len() - 1] != OP_CHECKMULTISIG {
        return Err(ScriptError::InvalidMultisigRedeem);
    }
    // Small-integer opcodes only, with the R-MS-2 bound (OP_16 would
    // be a 548-byte script — unspendable).
    let op_bound = 0x50 + MS_MAX_PUBKEYS as u8;
    if !(0x51..=op_bound).contains(&m_op) || !(0x51..=op_bound).contains(&n_op) {
        return Err(ScriptError::InvalidMultisigRedeem);
    }
    let m = (m_op - 0x50) as usize;
    let n = (n_op - 0x50) as usize;
    if m > n {
        return Err(ScriptError::InvalidMultisigRedeem);
    }
    // The middle must be exactly N single-opcode 33-byte pushes.
    let body = script.len() - 3;
    if body != n * 34 {
        return Err(ScriptError::InvalidMultisigRedeem);
    }
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let start = 1 + i * 34;
        if script[start] != 0x21 {
            return Err(ScriptError::InvalidMultisigRedeem);
        }
        let key: [u8; 33] = script[start + 1..start + 34]
            .try_into()
            .expect("window bounds-checked above yields exactly 33 key bytes");
        if !is_canonical_compressed_pubkey(&key) {
            return Err(ScriptError::InvalidMultisigRedeem);
        }
        keys.push(key);
    }
    // R-MS-3: duplicates make the quorum degenerate — rejected.
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(ScriptError::InvalidMultisigRedeem);
    }
    Ok((m, keys))
}

/// Assemble the finalized P2SH-multisig `scriptSig` (R-MS-4/R-MS-5):
///
/// ```text
/// OP_0 ‖ push(sig_i ‖ 0x01)×M (in redeem-script key order) ‖ push(redeem)
/// ```
///
/// The leading `OP_0` is the empty-push dummy compensating the
/// off-by-one stack error of `OP_CHECKMULTISIG` (R-MS-5 — BIP-147
/// NULLDUMMY makes a non-empty dummy consensus-invalid). `sigs` must
/// already be ordered by the redeem script's key order — the Finalizer
/// derives that order from [`extract_multisig_quorum`], never from
/// `PARTIAL_SIG` arrival order — and each element must be the complete
/// `DER ‖ sighash` signature. The redeem script is pushed with
/// [`push_data`] (its length can escalate to `OP_PUSHDATA1/2`).
pub fn make_multisig_script_sig(redeem: &[u8], sigs: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(OP_0);
    for sig in sigs {
        out.extend_from_slice(&push_data(sig));
    }
    out.extend_from_slice(&push_data(redeem));
    out
}

/// Assemble the finalized **P2WSH**-multisig witness stack
/// (specs/spec.md «Multi-sig», форма P2WSH; BIP-141):
///
/// ```text
/// [ ‖ ‖ (empty string — CHECKMULTISIG dummy), push(sig_i ‖ 0x01)×M, ‖redeem‖ ]
/// ```
///
/// `M + 2` items, signatures in the redeem script's key order. Unlike
/// the P2SH `scriptSig` ([`make_multisig_script_sig`]) there is **no**
/// separate `OP_0` byte: the BIP-141 dummy is a witness item of length
/// zero, which serializes as a bare CompactSize `0x00` and *is* the
/// empty push compensating the `OP_CHECKMULTISIG` off-by-one stack
/// error (R-MS-5 semantics; BIP-147 NULLDUMMY satisfied — the dummy is
/// empty). The redeem script rides as the last witness item, never
/// pushed through a `scriptSig`.
pub fn make_multisig_witness(redeem: &[u8], sigs: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(sigs.len() + 2);
    out.push(Vec::new());
    for sig in sigs {
        out.push(sig.to_vec());
    }
    out.push(redeem.to_vec());
    out
}

// --- Tapscript multisig (v0.3, P2TR script-path) ---------------------

/// Build the canonical M-of-N tapscript leaf (v0.3, specs/spec.md R-MS-7 —
/// the BIP-342 «Alternatives to CHECKMULTISIG» idiom, Miniscript
/// `multi_a`):
///
/// ```text
/// 0x20‖pk_1 OP_CHECKSIG 0x20‖pk_2 OP_CHECKSIGADD … 0x20‖pk_N
/// OP_CHECKSIGADD OP_M OP_NUMEQUAL
/// ```
///
/// Every key push is exactly `0x20 ‖ <32 x-only bytes>` (33 bytes —
/// BIP-340/342 keys are x-only in tapscript pushes); the first key's
/// `OP_CHECKSIG (0xac)` result initializes the accumulator, keys
/// `2..N` use `OP_CHECKSIGADD (0xba)`, and the final `OP_M (0x50+M)`
/// / `OP_NUMEQUAL (0x9d)` compare the counter with the threshold
/// (plain `NUMEQUAL`, never `NUMEQUALVERIFY` — the mirror of the
/// non-VERIFY `OP_CHECKMULTISIG` form, R-MS-3 carried over). Total
/// size `34N + 2`.
///
/// Validation and determinism mirror
/// [`make_multisig_redeem_script`]: `1 ≤ m ≤ n ≤`
/// [`MS_MAX_PUBKEYS`] ([`ScriptError::InvalidMultisigTapscript`]
/// otherwise — the unified bound is exactly the 520-byte
/// `MAX_SCRIPT_ELEMENT_SIZE` limit of the leaf element, R-MS-9), no
/// duplicate keys, and **R-MS-4/R-MS-10 sorting**: the keys are
/// sorted lexicographically by their 32 x-only bytes (sorting the
/// compressed encodings would give a different order — the same key
/// set must always yield the same script and therefore the same
/// address).
pub fn make_multisig_tapscript(m: usize, keys: &[[u8; 32]]) -> Result<Vec<u8>, ScriptError> {
    let n = keys.len();
    if n == 0 || m == 0 || m > n || n > MS_MAX_PUBKEYS as usize {
        return Err(ScriptError::InvalidMultisigTapscript);
    }
    let mut sorted = keys.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(ScriptError::InvalidMultisigTapscript);
    }
    // Exact capacity: 34·N + 2 = 512 bytes at the maximal quorum
    // (15 keys) — inside the 520-byte MAX_SCRIPT_ELEMENT_SIZE limit
    // the leaf element is subject to as an initial-stack item
    // (R-MS-9).
    let mut out = Vec::with_capacity(34 * n + 2);
    for (i, key) in sorted.iter().enumerate() {
        out.push(0x20);
        out.extend_from_slice(key);
        out.push(if i == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD });
    }
    out.push(op_n(m));
    out.push(OP_NUMEQUAL);
    Ok(out)
}

/// Extract the quorum `(m, keys)` from a canonical tapscript leaf —
/// keys in **script order** (the order the witness slots of the final
/// spend follow, R-MS-11).
///
/// Strict shape check, symmetric with [`extract_multisig_quorum`] —
/// not a general script decoder: the script must be exactly the
/// R-MS-7 idiom with `1 ≤ m ≤ n ≤` [`MS_MAX_PUBKEYS`], single-opcode
/// `0x20` pushes only (no `OP_PUSHDATA` wrappers, no 33-byte
/// compressed keys), `OP_CHECKSIG` after the first key and
/// `OP_CHECKSIGADD` after every other, `OP_M ‖ OP_NUMEQUAL`
/// (`NUMEQUALVERIFY` and `OP_CHECKMULTISIG` are rejections) terminus,
/// no trailing bytes, and no duplicate keys. Anything else is
/// [`ScriptError::InvalidMultisigTapscript`].
pub fn extract_multisig_tapscript(script: &[u8]) -> Result<(usize, Vec<[u8; 32]>), ScriptError> {
    // The minimal canonical script is 1-of-1: 36 bytes.
    if script.len() < 34 + 2 {
        return Err(ScriptError::InvalidMultisigTapscript);
    }
    // The fixed 3-byte tail: OP_M ‖ OP_NUMEQUAL.
    let m_op = script[script.len() - 2];
    if script[script.len() - 1] != OP_NUMEQUAL || !(0x51..=0x5f).contains(&m_op) {
        return Err(ScriptError::InvalidMultisigTapscript);
    }
    let m = (m_op - 0x50) as usize;
    // The body must decompose into an exact number of 34-byte
    // (0x20 ‖ 32) key slots — a trailing fragment or an
    // OP_PUSHDATA-wrapped key shifts the frame and fails here.
    let body = script.len() - 2;
    if body % 34 != 0 {
        return Err(ScriptError::InvalidMultisigTapscript);
    }
    let n = body / 34;
    if m > n || n > MS_MAX_PUBKEYS as usize {
        return Err(ScriptError::InvalidMultisigTapscript);
    }
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let start = i * 34;
        if script[start] != 0x20 {
            return Err(ScriptError::InvalidMultisigTapscript);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&script[start + 1..start + 33]);
        let opcode = script[start + 33];
        let expected = if i == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD };
        if opcode != expected {
            return Err(ScriptError::InvalidMultisigTapscript);
        }
        keys.push(key);
    }
    // R-MS-3 carried over: duplicates make the quorum degenerate.
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(ScriptError::InvalidMultisigTapscript);
    }
    Ok((m, keys))
}

/// BIP-341 `hashTapLeaf` of a tapscript (the single-leaf Merkle root):
/// `tagged_hash("TapLeaf", 0xc0 ‖ compact_size(|script|) ‖ script)`.
///
/// There is deliberately **no** `0x00` prefix before the leaf version:
/// the BIP-341 definition commits to `leaf_version ‖ compact_size ‖
/// script` directly, and the `compact_size` is the minimal length
/// encoding (512 → `fd 00 02`), never an `OP_PUSHDATA` push.
pub fn tapscript_leaf_hash(script: &[u8]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(script.len() + 5);
    msg.push(TAPSCRIPT_LEAF_VERSION);
    msg.extend_from_slice(&crate::transaction::compact_size(script.len() as u64));
    msg.extend_from_slice(script);
    crate::misc::tagged_hash(b"TapLeaf", &msg)
}

/// Assemble the finalized **P2TR script-path** witness stack (v0.3,
/// specs/spec.md R-MS-11):
///
/// ```text
/// [w_N, …, w_1] ‖ tapscript ‖ control_block
/// ```
///
/// `sig_slots` is indexed in **script-key order** (`w_1` first): each
/// slot is `Some(64-byte Schnorr signature)` for a signer or `None`
/// for a non-signer — the assembler reverses the slots because BIP-342
/// fixes the witness as `<w_n> … <w_1>` (the stack must present `pk_i`
/// on top of its signature at execution time). There is **no** dummy
/// element: `OP_CHECKSIGADD` has no off-by-one stack error, so the
/// R-MS-5 dummy of the CHECKMULTISIG forms does not exist here. The
/// `M + 2`-item stack is valid as long as exactly `M` slots are
/// `Some`; enforcing the count is the Finalizer's job, not the
/// assembler's.
pub fn make_multisig_tapscript_witness(
    script: &[u8],
    control_block: &[u8],
    sig_slots: &[Option<&[u8]>],
) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(sig_slots.len() + 2);
    for slot in sig_slots.iter().rev() {
        out.push(slot.map(|s| s.to_vec()).unwrap_or_default());
    }
    out.push(script.to_vec());
    out.push(control_block.to_vec());
    out
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    // --- opcode constants --------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn opcodes_have_expected_byte_values() {
        // Pins the 5 opcodes the wallet references. Any shift here is
        // balance-breaking -- a wrong byte would change every address
        // the wallet ever builds, with no compile-time signal.
        assert_eq!(OP_DUP, 0x76);
        assert_eq!(OP_HASH160, 0xa9);
        assert_eq!(OP_EQUAL, 0x87);
        assert_eq!(OP_EQUALVERIFY, 0x88);
        assert_eq!(OP_CHECKSIG, 0xac);
    }

    // --- make_p2pkh_lock_script ---------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2pkh_lock_script_has_canonical_25_byte_layout() {
        let hash = [0xaau8; 20];
        let out = make_p2pkh_lock_script(&hash);
        // OP_DUP OP_HASH160 <0x14> <20B hash> OP_EQUALVERIFY OP_CHECKSIG
        let mut expected = Vec::with_capacity(25);
        expected.push(OP_DUP);
        expected.push(OP_HASH160);
        expected.push(0x14);
        expected.extend_from_slice(&hash);
        expected.push(OP_EQUALVERIFY);
        expected.push(OP_CHECKSIG);
        assert_eq!(out, expected);
        assert_eq!(out.len(), 25);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2pkh_lock_script_varying_hash_input() {
        // Different inputs must yield different scripts at every
        // byte position (no caching, no prefix reuse).
        let h1 = [0x00u8; 20];
        let h2 = [0xffu8; 20];
        let s1 = make_p2pkh_lock_script(&h1);
        let s2 = make_p2pkh_lock_script(&h2);
        assert_ne!(s1, s2);
        assert_eq!(s1[3..23], h1);
        assert_eq!(s2[3..23], h2);
        assert_eq!(&s1[..3], &s2[..3]);
        assert_eq!(&s1[23..], &s2[23..]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    #[should_panic(expected = "hash160 must be 20 bytes")]
    fn p2pkh_lock_script_rejects_wrong_length_hash() {
        // Wallet passes only [u8;20] in production; the runtime check
        // here is a defensive guard against future refactors losing
        // the type. Belt-and-braces: panicked inputs can't be sent
        // over the wire.
        let short = [0u8; 19];
        let _ = make_p2pkh_lock_script(&short);
    }

    // --- make_p2sh_lock_script ----------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2sh_lock_script_has_canonical_23_byte_layout() {
        let hash = [0xabu8; 20];
        let out = make_p2sh_lock_script(&hash);
        // OP_HASH160 <0x14> <20B hash> OP_EQUAL
        let mut expected = Vec::with_capacity(23);
        expected.push(OP_HASH160);
        expected.push(0x14);
        expected.extend_from_slice(&hash);
        expected.push(OP_EQUAL);
        assert_eq!(out, expected);
        assert_eq!(out.len(), 23);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2sh_lock_script_uses_hash_in_middle() {
        let hash = [0x55u8; 20];
        let out = make_p2sh_lock_script(&hash);
        // The hash sits between push-prefix and trailing OP_EQUAL.
        assert_eq!(out[0], OP_HASH160);
        assert_eq!(out[1], 0x14);
        assert_eq!(&out[2..22], &hash[..]);
        assert_eq!(out[22], OP_EQUAL);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    #[should_panic(expected = "hash160 must be 20 bytes")]
    fn p2sh_lock_script_rejects_wrong_length_hash() {
        let long = [0u8; 21];
        let _ = make_p2sh_lock_script(&long);
    }

    // --- extract_p2pkh_hash -------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_p2pkh_hash_round_trip() {
        let hash = [0x77u8; 20];
        let script = make_p2pkh_lock_script(&hash);
        assert_eq!(extract_p2pkh_hash(&script).unwrap(), hash);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_p2pkh_hash_known_input() {
        // Pin the exact 25 bytes for an obviously-distinct hash, so
        // future byte-level drift in any of the 5 opcodes or push
        // prefix fails this test.
        let payload = [0xaa, 0x55, 0xaa, 0x55]
            .into_iter()
            .chain(std::iter::repeat(0u8).take(16))
            .collect::<Vec<u8>>();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&payload);
        let script = make_p2pkh_lock_script(&hash);
        assert_eq!(extract_p2pkh_hash(&script).unwrap(), hash);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_p2pkh_hash_rejects_wrong_length() {
        // 24 bytes (one short of canonical P2PKH).
        let short = vec![0u8; 24];
        let err = extract_p2pkh_hash(&short).unwrap_err();
        assert_eq!(err, ScriptError::InvalidScript(24));

        // 26 bytes (one over).
        let long = vec![0u8; 26];
        let err = extract_p2pkh_hash(&long).unwrap_err();
        assert_eq!(err, ScriptError::InvalidScript(26));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_p2pkh_hash_rejects_non_p2pkh_opcodes() {
        // Build a 25-byte blob matching the canonical length but
        // corrupting each fixed-position opcode in turn. Each variant
        // must be rejected -- a decoder that lets the wrong byte
        // through would silently accept any P2SH script (which has
        // OP_HASH160 + push + OP_EQUAL but no OP_DUP/OP_EQUALVERIFY).
        let canonical = make_p2pkh_lock_script(&[0u8; 20]);
        let len = canonical.len();
        assert_eq!(len, 25);
        let corrupt = [
            // OP_DUP -> 0x00
            std::iter::once(0x00u8)
                .chain(canonical[1..].iter().copied())
                .collect::<Vec<u8>>(),
            // OP_HASH160 -> 0x00
            std::iter::once(canonical[0])
                .chain(std::iter::once(0x00u8))
                .chain(canonical[2..].iter().copied())
                .collect::<Vec<u8>>(),
            // push prefix 0x14 -> 21 (off-by-one in push size)
            canonical[..2]
                .iter()
                .copied()
                .chain(std::iter::once(21u8))
                .chain(canonical[3..].iter().copied())
                .collect::<Vec<u8>>(),
            // OP_EQUALVERIFY -> 0x00
            canonical[..23]
                .iter()
                .copied()
                .chain(std::iter::once(0x00u8))
                .chain(canonical[24..].iter().copied())
                .collect::<Vec<u8>>(),
            // OP_CHECKSIG -> 0x00
            canonical[..24]
                .iter()
                .copied()
                .chain(std::iter::once(0x00u8))
                .collect::<Vec<u8>>(),
        ];
        for (i, bad) in corrupt.iter().enumerate() {
            let err = extract_p2pkh_hash(bad).unwrap_err();
            assert_eq!(
                err,
                ScriptError::InvalidScript(bad.len()),
                "corruption {i} should be rejected"
            );
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_p2pkh_hash_rejects_p2sh_script() {
        // A real P2SH script has the right hash160 bytes layout but
        // wrong opcodes -- must not be accepted as P2PKH.
        let p2sh = make_p2sh_lock_script(&[0x33u8; 20]);
        assert_eq!(p2sh.len(), 23);
        let err = extract_p2pkh_hash(&p2sh).unwrap_err();
        // The error is InvalidScript(23) -- length guard fires before
        // opcode check, which is the intended ordering.
        assert_eq!(err, ScriptError::InvalidScript(23));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_p2pkh_hash_accepts_all_zero_hash() {
        // All-zero hash is valid; the decoder mustn't treat it as a
        // sentinel.
        let script = make_p2pkh_lock_script(&[0u8; 20]);
        assert_eq!(extract_p2pkh_hash(&script).unwrap(), [0u8; 20]);
    }

    // --- witness scripts (Phase 13) -----------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2wpkh_lock_script_has_canonical_22_byte_layout() {
        let hash = [0x5au8; 20];
        let out = make_p2wpkh_lock_script(&hash);
        assert_eq!(out.len(), 22);
        assert_eq!(&out[..2], &[OP_0, OP_PUSHBYTES_20]);
        assert_eq!(&out[2..], &hash);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2tr_lock_script_has_canonical_34_byte_layout() {
        let key = [0xa5u8; 32];
        let out = make_p2tr_lock_script(&key);
        assert_eq!(out.len(), 34);
        assert_eq!(&out[..2], &[OP_1, OP_PUSHBYTES_32]);
        assert_eq!(&out[2..], &key);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn witness_scripts_pin_official_bytes() {
        // Official BIP-341 wallet test vector: scriptPubKey of the
        // first (null script tree) output key.
        let key: [u8; 32] =
            hex::decode("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343")
                .unwrap()
                .try_into()
                .unwrap();
        let spk = make_p2tr_lock_script(&key);
        assert_eq!(
            hex::encode(spk),
            "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
        );
        // BIP-173 example P2WPKH scriptPubKey.
        let hash: [u8; 20] = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(make_p2wpkh_lock_script(&hash)),
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_p2wpkh_hash_round_trip_and_rejections() {
        let hash = [0x77u8; 20];
        let script = make_p2wpkh_lock_script(&hash);
        assert_eq!(extract_p2wpkh_hash(&script).unwrap(), hash);
        // All-zero program extracts fine.
        assert_eq!(
            extract_p2wpkh_hash(&make_p2wpkh_lock_script(&[0u8; 20])).unwrap(),
            [0u8; 20]
        );
        // Wrong lengths: one short, one over.
        assert_eq!(
            extract_p2wpkh_hash(&[0u8; 21]).unwrap_err(),
            ScriptError::InvalidScript(21)
        );
        assert_eq!(
            extract_p2wpkh_hash(&[0u8; 23]).unwrap_err(),
            ScriptError::InvalidScript(23)
        );
        // P2TR script must not decode as P2WPKH.
        assert_eq!(
            extract_p2wpkh_hash(&make_p2tr_lock_script(&[0u8; 32])).unwrap_err(),
            ScriptError::InvalidScript(34)
        );
        // Wrong version opcode (0x51 instead of 0x00) at P2WPKH
        // length.
        let mut bad = make_p2wpkh_lock_script(&hash);
        bad[0] = OP_1;
        assert_eq!(
            extract_p2wpkh_hash(&bad).unwrap_err(),
            ScriptError::InvalidScript(22)
        );
        // Wrong push size (0x14 → 0x15).
        let mut bad_push = make_p2wpkh_lock_script(&hash);
        bad_push[1] = 0x15;
        assert_eq!(
            extract_p2wpkh_hash(&bad_push).unwrap_err(),
            ScriptError::InvalidScript(22)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_p2tr_output_key_round_trip_and_rejections() {
        let key = [0x33u8; 32];
        let script = make_p2tr_lock_script(&key);
        assert_eq!(extract_p2tr_output_key(&script).unwrap(), key);
        // Wrong lengths.
        assert_eq!(
            extract_p2tr_output_key(&[0u8; 33]).unwrap_err(),
            ScriptError::InvalidScript(33)
        );
        assert_eq!(
            extract_p2tr_output_key(&[0u8; 35]).unwrap_err(),
            ScriptError::InvalidScript(35)
        );
        // P2WPKH script must not decode as P2TR.
        assert_eq!(
            extract_p2tr_output_key(&make_p2wpkh_lock_script(&[0u8; 20])).unwrap_err(),
            ScriptError::InvalidScript(22)
        );
        // Wrong version opcode (0x00 instead of 0x51) at P2TR length.
        let mut bad = make_p2tr_lock_script(&key);
        bad[0] = OP_0;
        assert_eq!(
            extract_p2tr_output_key(&bad).unwrap_err(),
            ScriptError::InvalidScript(34)
        );
        // Wrong push size (0x20 → 0x1f).
        let mut bad_push = make_p2tr_lock_script(&key);
        bad_push[1] = 0x1f;
        assert_eq!(
            extract_p2tr_output_key(&bad_push).unwrap_err(),
            ScriptError::InvalidScript(34)
        );
    }
    // --- push_data (single/OP_PUSHDATA1/OP_PUSHDATA2) -----------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn push_data_opcodes_have_expected_byte_values() {
        assert_eq!(OP_CHECKMULTISIG, 0xae);
        assert_eq!(OP_PUSHDATA1, 0x4c);
        assert_eq!(OP_PUSHDATA2, 0x4d);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn push_data_single_opcode_form_and_boundaries() {
        // Empty push: length prefix 0x00 only.
        assert_eq!(push_data(&[]), vec![0x00]);
        // Single-opcode form below the escalation point.
        assert_eq!(push_data(&[0xaa; 33])[0], 33);
        assert_eq!(push_data(&[0xaa; 33]).len(), 34);
        // The 0x4b boundary is still single-opcode.
        assert_eq!(push_data(&[0xaa; 0x4b])[0], 0x4b);
        assert_eq!(push_data(&[0xaa; 0x4b]).len(), 0x4c);
        assert_eq!(push_data_len(0x4b), 1);
        assert_eq!(push_data_len(75), 1);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn push_data_escalates_to_op_pushdata1_above_75_bytes() {
        // One byte past the single-opcode limit: OP_PUSHDATA1.
        assert_eq!(push_data(&[0xaa; 76])[0], OP_PUSHDATA1);
        assert_eq!(push_data(&[0xaa; 76])[1], 76);
        assert_eq!(push_data(&[0xaa; 76]).len(), 78);
        // The 255-byte OP_PUSHDATA1 boundary.
        assert_eq!(push_data(&[0xaa; 255])[0], OP_PUSHDATA1);
        assert_eq!(push_data(&[0xaa; 255])[1], 255);
        assert_eq!(push_data_len(76), 2);
        assert_eq!(push_data_len(255), 2);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn push_data_escalates_to_op_pushdata2_above_255_bytes() {
        // One byte past the OP_PUSHDATA1 limit: OP_PUSHDATA2, 2-byte LE.
        assert_eq!(push_data(&[0xaa; 256])[0], OP_PUSHDATA2);
        assert_eq!(&push_data(&[0xaa; 256])[1..3], &[0x00, 0x01]);
        // A maximal 15-key redeem script (514 bytes) stays within reach.
        assert_eq!(push_data(&[0xaa; 514])[0], OP_PUSHDATA2);
        assert_eq!(&push_data(&[0xaa; 514])[1..3], &0x0202u16.to_le_bytes());
        assert_eq!(push_data(&[0xaa; 514]).len(), 517);
        assert_eq!(push_data_len(256), 3);
        assert_eq!(push_data_len(514), 3);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    #[should_panic(expected = "item too long")]
    fn push_data_panics_above_the_op_pushdata2_reach() {
        let _ = push_data(&[0xaa; 0x1_0000]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn push_data_round_trips_through_a_length_prefix_read() {
        // The pushed item is recoverable by reading the same length
        // prefix the encoder wrote (single-opcode and both escalations).
        for len in [0usize, 1, 33, 75, 76, 255, 256, 514] {
            let item = vec![0x5au8; len];
            let encoded = push_data(&item);
            let prefix = usize::from(encoded[0]);
            let op1 = usize::from(OP_PUSHDATA1);
            let (header, payload) = if prefix <= 0x4b {
                (1, &encoded[1..])
            } else if prefix == op1 {
                (2, &encoded[2..])
            } else {
                let n = u16::from_le_bytes([encoded[1], encoded[2]]) as usize;
                (3, &encoded[3..3 + n])
            };
            assert_eq!(encoded.len(), header + len);
            assert_eq!(payload, &item[..]);
        }
    }

    // --- make_multisig_redeem_script -----------------------------------

    /// Three syntactically-distinct canonical keys in deliberately
    /// unsorted order (0x03 > 0x02 first byte; different bodies).
    fn ms_keys() -> [[u8; 33]; 3] {
        let mut k1 = [0x02u8; 33];
        k1[32] = 0x01;
        let mut k2 = [0x02u8; 33];
        k2[32] = 0x02;
        let mut k3 = [0x03u8; 33];
        k3[32] = 0x01;
        [k3, k1, k2]
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_redeem_has_canonical_layout_2_of_3() {
        // keys are (k3, k1, k2); the script carries them sorted.
        let [k3, k1, k2] = ms_keys();
        let redeem = make_multisig_redeem_script(2, &[k3, k1, k2]).unwrap();
        // OP_m + 3·(1 + 33) + OP_n + OP_CHECKMULTISIG = 105 bytes.
        assert_eq!(redeem.len(), 105);
        // OP_2, three 0x21 pushes, OP_3, OP_CHECKMULTISIG.
        assert_eq!(redeem[0], 0x52);
        assert_eq!(redeem[1], 0x21);
        assert_eq!(&redeem[2..35], &k1); // 0x02…01 is the smallest
        assert_eq!(redeem[35], 0x21);
        assert_eq!(&redeem[36..69], &k2);
        assert_eq!(redeem[69], 0x21);
        assert_eq!(&redeem[70..103], &k3);
        assert_eq!(redeem[103], 0x53);
        assert_eq!(redeem[104], OP_CHECKMULTISIG);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_redeem_sorts_keys_bip67() {
        // The same set in any argument order yields byte-identical
        // scripts (R-MS-4) — and the script order is lexicographic.
        let [k3, k1, k2] = ms_keys();
        let a = make_multisig_redeem_script(2, &[k3, k1, k2]).unwrap();
        let b = make_multisig_redeem_script(2, &[k2, k1, k3]).unwrap();
        let c = make_multisig_redeem_script(2, &[k1, k2, k3]).unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
        // Sorted: 0x02…01 < 0x02…02 < 0x03…01.
        let keys = [k1, k2, k3];
        let mut pos = 2;
        for key in &keys {
            assert_eq!(&a[pos..pos + 33], key);
            pos += 34;
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_redeem_bounds_rejections() {
        let keys = ms_keys();
        // m = 0.
        assert_eq!(
            make_multisig_redeem_script(0, &keys),
            Err(ScriptError::InvalidMultisigRedeem)
        );
        // m > n.
        assert_eq!(
            make_multisig_redeem_script(4, &keys),
            Err(ScriptError::InvalidMultisigRedeem)
        );
        // n = 16 (above MS_MAX_PUBKEYS) with 16 distinct keys, so the
        // duplicate check is not what fires.
        let distinct: Vec<[u8; 33]> = (0..16)
            .map(|i| {
                let mut k = [0x02u8; 33];
                k[32] = i;
                k
            })
            .collect();
        assert_eq!(
            make_multisig_redeem_script(16, &distinct),
            Err(ScriptError::InvalidMultisigRedeem)
        );
        // Empty key set.
        assert_eq!(
            make_multisig_redeem_script(1, &[]),
            Err(ScriptError::InvalidMultisigRedeem)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_redeem_rejects_duplicate_keys() {
        let mut k1 = [0x02u8; 33];
        k1[32] = 0x01;
        let mut k2 = [0x02u8; 33];
        k2[32] = 0x02;
        assert_eq!(
            make_multisig_redeem_script(2, &[k1, k1, k2]),
            Err(ScriptError::InvalidMultisigRedeem)
        );
        // Even one duplicated pair inside an otherwise valid 2-of-2.
        assert_eq!(
            make_multisig_redeem_script(2, &[k1, k1]),
            Err(ScriptError::InvalidMultisigRedeem)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_redeem_boundaries_1_of_1_and_15_of_15() {
        let mut single = [0x02u8; 33];
        single[32] = 0x07;
        let one = make_multisig_redeem_script(1, &[single]).unwrap();
        assert_eq!(one.len(), 37);
        assert_eq!(one[0], 0x51);
        assert_eq!(one[35], 0x51);
        assert_eq!(one[36], OP_CHECKMULTISIG);
        assert_eq!(extract_multisig_quorum(&one).unwrap(), (1, vec![single]));

        // 15-of-15: 34·15 + 4 = 514 bytes — inside the 520-byte push
        // limit (the R-MS-2 rationale).
        let distinct: Vec<[u8; 33]> = (0..15)
            .map(|i| {
                let mut k = [0x02u8; 33];
                k[32] = i as u8 + 1; // avoid all-zero low bytes colliding
                k
            })
            .collect();
        let big = make_multisig_redeem_script(15, &distinct).unwrap();
        assert_eq!(big.len(), 513);
        assert_eq!(big[0], 0x5f);
        assert_eq!(big[511], 0x5f);
        assert_eq!(big[512], OP_CHECKMULTISIG);
        let (m, keys) = extract_multisig_quorum(&big).unwrap();
        assert_eq!(m, 15);
        assert_eq!(keys, distinct);
    }

    // --- extract_multisig_quorum ---------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_extract_round_trip_and_script_order() {
        let [k3, k1, k2] = ms_keys();
        // Script order is sorted: k1 < k2 < k3.
        let redeem = make_multisig_redeem_script(1, &[k3, k1, k2]).unwrap();
        let (m, keys) = extract_multisig_quorum(&redeem).unwrap();
        assert_eq!(m, 1);
        assert_eq!(keys, vec![k1, k2, k3]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_extract_rejects_bad_lengths_and_opcodes() {
        let [k1v, k2v, k3v] = ms_keys();
        let canonical = make_multisig_redeem_script(2, &[k1v, k2v, k3v]).unwrap();
        assert_eq!(canonical.len(), 105);

        // Truncations and extensions.
        assert_eq!(
            extract_multisig_quorum(&[]),
            Err(ScriptError::InvalidMultisigRedeem)
        );
        assert_eq!(
            extract_multisig_quorum(&canonical[..36]),
            Err(ScriptError::InvalidMultisigRedeem)
        );
        assert_eq!(
            extract_multisig_quorum(&canonical[..104]),
            Err(ScriptError::InvalidMultisigRedeem)
        );
        let mut trailing = canonical.clone();
        trailing.push(0x00);
        assert_eq!(
            extract_multisig_quorum(&trailing),
            Err(ScriptError::InvalidMultisigRedeem)
        );

        // Wrong OP_m at the head.
        let mut bad_m = canonical.clone();
        bad_m[0] = 0x00; // OP_0 is not a small-integer push
        assert_eq!(
            extract_multisig_quorum(&bad_m),
            Err(ScriptError::InvalidMultisigRedeem)
        );
        let mut m_after_n = canonical.clone();
        m_after_n[0] = 0x54; // m = 4 > n = 3
        assert_eq!(
            extract_multisig_quorum(&m_after_n),
            Err(ScriptError::InvalidMultisigRedeem)
        );

        // Wrong OP_n in the tail.
        let mut bad_n = canonical.clone();
        bad_n[103] = 0x60; // OP_16 — above MS_MAX_PUBKEYS
        assert_eq!(
            extract_multisig_quorum(&bad_n),
            Err(ScriptError::InvalidMultisigRedeem)
        );

        // Wrong terminal opcode.
        let mut bad_term = canonical.clone();
        bad_term[104] = 0xac; // OP_CHECKSIG
        assert_eq!(
            extract_multisig_quorum(&bad_term),
            Err(ScriptError::InvalidMultisigRedeem)
        );

        // Wrong push prefix (0x20 instead of 0x21).
        let mut bad_push = canonical.clone();
        bad_push[1] = 0x20;
        assert_eq!(
            extract_multisig_quorum(&bad_push),
            Err(ScriptError::InvalidMultisigRedeem)
        );

        // OP_PUSHDATA1 wrappers instead of the single-opcode pushes:
        // same pushed payload, different envelope — non-canonical form.
        let mut wrapped = vec![0x52];
        for key in [&k1v, &k2v, &k3v] {
            wrapped.push(OP_PUSHDATA1);
            wrapped.push(0x21);
            wrapped.extend_from_slice(key);
        }
        wrapped.push(0x53);
        wrapped.push(OP_CHECKMULTISIG);
        // 3-byte pushes make the body 9 bytes longer than the template.
        assert_eq!(
            extract_multisig_quorum(&wrapped),
            Err(ScriptError::InvalidMultisigRedeem)
        );

        // Non-canonical pubkey prefix inside a 0x21 push (0x04 =
        // uncompressed-style prefix does not fit the canonical form).
        let mut bad_prefix = canonical.clone();
        bad_prefix[2] = 0x04;
        assert_eq!(
            extract_multisig_quorum(&bad_prefix),
            Err(ScriptError::InvalidMultisigRedeem)
        );
        let mut bad_prefix2 = canonical.clone();
        bad_prefix2[2 + 34] = 0x05;
        assert_eq!(
            extract_multisig_quorum(&bad_prefix2),
            Err(ScriptError::InvalidMultisigRedeem)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_extract_rejects_duplicate_keys() {
        let mut k1 = [0x02u8; 33];
        k1[32] = 0x01;
        let mut k2 = [0x02u8; 33];
        k2[32] = 0x02;
        // Hand-assemble 2-of-2 with k1 twice (the builder rejects this,
        // so the raw bytes are constructed by hand).
        let mut script = vec![0x52];
        script.push(0x21);
        script.extend_from_slice(&k1);
        script.push(0x21);
        script.extend_from_slice(&k1);
        script.push(0x52);
        script.push(OP_CHECKMULTISIG);
        assert_eq!(
            extract_multisig_quorum(&script),
            Err(ScriptError::InvalidMultisigRedeem)
        );
        let _ = k2;
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_extract_rejects_body_length_mismatch() {
        // OP_1 / OP_2 headers with only ONE key push between — the
        // body length does not match n = 2.
        let mut k1 = [0x02u8; 33];
        k1[32] = 0x01;
        let mut script = vec![0x51];
        script.push(0x21);
        script.extend_from_slice(&k1);
        script.push(0x52);
        script.push(OP_CHECKMULTISIG);
        assert_eq!(
            extract_multisig_quorum(&script),
            Err(ScriptError::InvalidMultisigRedeem)
        );
    }

    // --- make_multisig_script_sig --------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_script_sig_layout_pins_dummy_sigs_and_redeem() {
        let [k3, k1, k2] = ms_keys();
        let redeem = make_multisig_redeem_script(2, &[k3, k1, k2]).unwrap();
        let sig_a = vec![0x30u8; 72];
        let sig_b = vec![0x31u8; 71];
        let script_sig = make_multisig_script_sig(&redeem, &[&sig_a, &sig_b]);
        // OP_0 dummy first (R-MS-5): a single 0x00 byte.
        assert_eq!(script_sig[0], OP_0);
        // sig pushes in script order…
        assert_eq!(script_sig[1], 72);
        assert_eq!(&script_sig[2..74], &sig_a[..]);
        assert_eq!(script_sig[74], 71);
        assert_eq!(&script_sig[75..146], &sig_b[..]);
        // …then the redeem push — 105 bytes > 75, so OP_PUSHDATA1.
        assert_eq!(script_sig[146], OP_PUSHDATA1);
        assert_eq!(script_sig[147], redeem.len() as u8);
        assert_eq!(&script_sig[148..], &redeem[..]);
        assert_eq!(script_sig.len(), 1 + 73 + 72 + 2 + 105);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_script_sig_pushes_long_redeem_with_pushdata() {
        // A 15-key redeem (513 bytes) must be pushed via OP_PUSHDATA2.
        let distinct: Vec<[u8; 33]> = (0..15)
            .map(|i| {
                let mut k = [0x02u8; 33];
                k[32] = i as u8 + 1;
                k
            })
            .collect();
        let redeem = make_multisig_redeem_script(15, &distinct).unwrap();
        let sig = vec![0x30u8; 72];
        let script_sig = make_multisig_script_sig(&redeem, &[&sig]);
        assert_eq!(script_sig[0], OP_0);
        assert_eq!(script_sig[1], 72);
        assert_eq!(script_sig[74], OP_PUSHDATA2);
        assert_eq!(&script_sig[75..77], &513u16.to_le_bytes());
        assert_eq!(script_sig.len(), 1 + 73 + 3 + 513);
    }

    // --- P2WSH lock script + extractor (v0.3) ---------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn p2wsh_lock_script_has_canonical_34_byte_layout() {
        let hash = [0x77u8; 32];
        let out = make_p2wsh_lock_script(&hash);
        assert_eq!(out.len(), 34);
        assert_eq!(&out[..2], &[OP_0, OP_PUSHBYTES_32]);
        assert_eq!(&out[2..], &hash);
        // Distinct from the 34-byte P2TR script (OP_1 head) at every
        // position a strict decoder checks.
        assert_ne!(&out[..2], &[OP_1, OP_PUSHBYTES_32]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn extract_p2wsh_program_round_trip_and_rejections() {
        let hash = [0x33u8; 32];
        let script = make_p2wsh_lock_script(&hash);
        assert_eq!(extract_p2wsh_program(&script).unwrap(), hash);
        // All-zero commitment extracts fine (no sentinel).
        assert_eq!(
            extract_p2wsh_program(&make_p2wsh_lock_script(&[0u8; 32])).unwrap(),
            [0u8; 32]
        );
        // Wrong lengths: one short, one over.
        assert_eq!(
            extract_p2wsh_program(&[0u8; 33]).unwrap_err(),
            ScriptError::InvalidScript(33)
        );
        assert_eq!(
            extract_p2wsh_program(&[0u8; 35]).unwrap_err(),
            ScriptError::InvalidScript(35)
        );
        // The 34-byte P2TR script must not decode as P2WSH.
        assert_eq!(
            extract_p2wsh_program(&make_p2tr_lock_script(&[0u8; 32])).unwrap_err(),
            ScriptError::InvalidScript(34)
        );
        // Wrong version opcode (OP_1 instead of OP_0) at P2WSH length.
        let mut bad = make_p2wsh_lock_script(&hash);
        bad[0] = OP_1;
        assert_eq!(
            extract_p2wsh_program(&bad).unwrap_err(),
            ScriptError::InvalidScript(34)
        );
        // Wrong push size (0x20 → 0x1f).
        let mut bad_push = make_p2wsh_lock_script(&hash);
        bad_push[1] = 0x1f;
        assert_eq!(
            extract_p2wsh_program(&bad_push).unwrap_err(),
            ScriptError::InvalidScript(34)
        );
    }

    // --- make_multisig_witness (v0.3) -----------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_witness_pins_bip141_layout() {
        let [k3, k1, k2] = ms_keys();
        let redeem = make_multisig_redeem_script(2, &[k3, k1, k2]).unwrap();
        let sig_a = vec![0x30u8; 72];
        let sig_b = vec![0x31u8; 71];
        let stack = make_multisig_witness(&redeem, &[&sig_a, &sig_b]);
        // M + 2 items: empty dummy, the M signatures, the redeem.
        assert_eq!(stack.len(), 4);
        // The dummy is the empty-string item — NOT a 0x00 byte (the
        // BIP-141 wire dummy is a zero-length item, unlike the P2SH
        // scriptSig's OP_0 byte).
        assert!(stack[0].is_empty());
        assert_eq!(stack[1], sig_a);
        assert_eq!(stack[2], sig_b);
        assert_eq!(stack[3], redeem);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn multisig_witness_m_of_m_and_long_redeem() {
        let [k3, k1, k2] = ms_keys();
        let redeem = make_multisig_redeem_script(3, &[k3, k1, k2]).unwrap();
        let sigs: Vec<Vec<u8>> = (0..3).map(|i| vec![0x40u8 + i; 72]).collect();
        let refs: Vec<&[u8]> = sigs.iter().map(|s| s.as_slice()).collect();
        let stack = make_multisig_witness(&redeem, &refs);
        assert_eq!(stack.len(), 5);
        assert!(stack[0].is_empty());
        assert_eq!(&stack[1..4], &sigs[..]);
        assert_eq!(stack[4], redeem);
        // A maximal 15-key redeem (513 bytes) rides as one item — no
        // push encoding involved (BIP-141 items are length-prefixed).
        let distinct: Vec<[u8; 33]> = (0..15)
            .map(|i| {
                let mut k = [0x02u8; 33];
                k[32] = i as u8 + 1;
                k
            })
            .collect();
        let big = make_multisig_redeem_script(15, &distinct).unwrap();
        let one = vec![0x30u8; 72];
        let big_stack = make_multisig_witness(&big, &[&one]);
        assert_eq!(big_stack.len(), 3);
        assert_eq!(big_stack[2].len(), 513);
    }

    // --- Tapscript multisig (v0.3, R-MS-7/9/10/11) ----------------------

    /// Three real x-only keys in deliberately unsorted order
    /// (x(G), x(3G), x(2G) — the lexicographic order is
    /// x(G) < x(2G) < x(3G) by first byte).
    fn tap_keys() -> [[u8; 32]; 3] {
        [
            hex::decode("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap()
                .try_into()
                .unwrap(),
        ]
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_opcodes_have_expected_byte_values() {
        // New pins for the v0.3 idiom (R-MS-7). Any shift is
        // consensus-breaking.
        assert_eq!(OP_CHECKSIGADD, 0xba);
        assert_eq!(OP_NUMEQUAL, 0x9d);
        assert_eq!(TAPSCRIPT_LEAF_VERSION, 0xc0);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_has_canonical_layout_2_of_3() {
        // Argument order is (x(3G), x(G), x(2G)); the script carries
        // them x-only-sorted (R-MS-10).
        let [k3g, k1g, k2g] = tap_keys();
        let script = make_multisig_tapscript(2, &[k3g, k1g, k2g]).unwrap();
        let mut expected = Vec::new();
        for (i, key) in [&k1g, &k2g, &k3g].into_iter().enumerate() {
            expected.push(0x20);
            expected.extend_from_slice(key);
            expected.push(if i == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD });
        }
        expected.push(0x52); // OP_2
        expected.push(OP_NUMEQUAL);
        assert_eq!(script, expected);
        assert_eq!(script.len(), 34 * 3 + 2);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_sorts_keys_lexicographically_by_x_only() {
        // R-MS-4/10: the same key set in any argument order yields the
        // same bytes, and the script order is the x-only byte sort —
        // which here differs from the compressed-byte sort only in
        // principle, but the identity of the script under permutation
        // is the determinism contract.
        let [k3g, k1g, k2g] = tap_keys();
        let a = make_multisig_tapscript(2, &[k3g, k1g, k2g]).unwrap();
        let b = make_multisig_tapscript(2, &[k2g, k1g, k3g]).unwrap();
        let c = make_multisig_tapscript(2, &[k1g, k2g, k3g]).unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
        let (m, keys) = extract_multisig_tapscript(&a).unwrap();
        assert_eq!(m, 2);
        assert_eq!(keys, vec![k1g, k2g, k3g]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_matches_the_independent_reference_vector() {
        // 2-of-3 over x(G), x(2G), x(3G): the exact canonical bytes
        // and the BIP-341 hashTapLeaf — computed independently with a
        // from-scratch Python secp256k1/hashlib reference (spec
        // vectors), so any drift in the idiom encoding or the leaf
        // hash fails here before anything downstream.
        let [k3g, k1g, k2g] = tap_keys();
        let script = make_multisig_tapscript(2, &[k1g, k2g, k3g]).unwrap();
        assert_eq!(
            hex::encode(&script),
            concat!(
                "2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
                "20c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ba",
                "20f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ba",
                "529d"
            )
        );
        assert_eq!(
            hex::encode(tapscript_leaf_hash(&script)),
            "640fca23685170704e436970f8ca462899442be7b8a4010bcb31eb579c65c004"
        );
        // 1-of-1 minimal leaf over x(G).
        let one = make_multisig_tapscript(1, &[k1g]).unwrap();
        assert_eq!(one.len(), 36);
        assert_eq!(
            hex::encode(tapscript_leaf_hash(&one)),
            "4c7ac8b22c633180138b87f6bc6d25b58423f90d9edc6c95727933cdc1480381"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_bounds_n15_spendable_n16_rejected() {
        // R-MS-9: N = 15 is the maximal quorum — the 512-byte leaf
        // fits the 520-byte element limit; the builder at N = 16 is a
        // typed rejection (the 546-byte leaf could not be spent at
        // all).
        let distinct: Vec<[u8; 32]> = (0..15)
            .map(|i| {
                let mut k = [0u8; 32];
                k[31] = i as u8 + 1;
                k
            })
            .collect();
        let big = make_multisig_tapscript(15, &distinct).unwrap();
        assert_eq!(big.len(), 512);
        assert_eq!(big[0], 0x20);
        assert_eq!(big[33], OP_CHECKSIG);
        assert_eq!(big[34], 0x20);
        assert_eq!(big[67], OP_CHECKSIGADD);
        assert_eq!(big[509], OP_CHECKSIGADD); // the 15th key's opcode
        assert_eq!(big[510], 0x5f); // OP_15
        assert_eq!(big[511], OP_NUMEQUAL);
        let (m, keys) = extract_multisig_tapscript(&big).unwrap();
        assert_eq!(m, 15);
        assert_eq!(keys, distinct);

        let sixteen: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let mut k = [0u8; 32];
                k[31] = i as u8 + 1;
                k
            })
            .collect();
        assert_eq!(
            make_multisig_tapscript(16, &sixteen),
            Err(ScriptError::InvalidMultisigTapscript)
        );
        // The remaining shape bounds, mirroring the P2SH builder.
        assert_eq!(
            make_multisig_tapscript(0, &distinct),
            Err(ScriptError::InvalidMultisigTapscript)
        );
        assert_eq!(
            make_multisig_tapscript(16, &distinct),
            Err(ScriptError::InvalidMultisigTapscript)
        );
        assert_eq!(
            make_multisig_tapscript(1, &[]),
            Err(ScriptError::InvalidMultisigTapscript)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_rejects_duplicate_keys() {
        let [k1g, _, _] = tap_keys();
        let mut k2 = [0u8; 32];
        k2[31] = 0x09;
        assert_eq!(
            make_multisig_tapscript(2, &[k1g, k1g, k2]),
            Err(ScriptError::InvalidMultisigTapscript)
        );
        // The extractor rejects a hand-assembled duplicate too (the
        // first key closes with OP_CHECKSIG so the shape parse reaches
        // the duplicate check).
        let mut script = vec![0x20];
        script.extend_from_slice(&k1g);
        script.push(OP_CHECKSIG);
        script.push(0x20);
        script.extend_from_slice(&k1g);
        script.push(OP_CHECKSIGADD);
        script.push(0x52);
        script.push(OP_NUMEQUAL);
        assert_eq!(
            extract_multisig_tapscript(&script),
            Err(ScriptError::InvalidMultisigTapscript)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_extract_strict_shape_rejections() {
        let [k1g, k2g, k3g] = tap_keys();
        let canonical = make_multisig_tapscript(2, &[k1g, k2g, k3g]).unwrap();
        assert_eq!(canonical.len(), 104);

        // Truncations and extensions.
        assert_eq!(
            extract_multisig_tapscript(&[]),
            Err(ScriptError::InvalidMultisigTapscript)
        );
        assert_eq!(
            extract_multisig_tapscript(&canonical[..60]),
            Err(ScriptError::InvalidMultisigTapscript)
        );
        let mut trailing = canonical.clone();
        trailing.push(0x00);
        assert_eq!(
            extract_multisig_tapscript(&trailing),
            Err(ScriptError::InvalidMultisigTapscript)
        );

        // CHECKMULTISIG instead of the idiom (disabled under
        // tapscript consensus — must not parse).
        let mut checkmultisig = canonical.clone();
        *checkmultisig.last_mut().unwrap() = OP_CHECKMULTISIG;
        assert_eq!(
            extract_multisig_tapscript(&checkmultisig),
            Err(ScriptError::InvalidMultisigTapscript)
        );

        // NUMEQUALVERIFY instead of plain NUMEQUAL.
        let mut verify_form = canonical.clone();
        *verify_form.last_mut().unwrap() = 0x9d + 1; // 0x9e OP_NUMEQUALVERIFY
        assert_eq!(
            extract_multisig_tapscript(&verify_form),
            Err(ScriptError::InvalidMultisigTapscript)
        );

        // 33-byte compressed-style push (0x21 prefix, key first byte
        // re-aligned so the total length stays a multiple of 34… it
        // is not: 33-byte pushes break the frame — exactly the
        // rejection the strict shape check exists for).
        let mut compressed_push = canonical.clone();
        compressed_push[0] = 0x21;
        assert_eq!(
            extract_multisig_tapscript(&compressed_push),
            Err(ScriptError::InvalidMultisigTapscript)
        );

        // OP_PUSHDATA1 wrapper around the first key (same payload,
        // different envelope — non-canonical).
        let mut wrapped = vec![OP_PUSHDATA1, 0x20];
        wrapped.extend_from_slice(&k1g);
        wrapped.push(OP_CHECKSIG);
        for key in [&k2g, &k3g] {
            wrapped.push(0x20);
            wrapped.extend_from_slice(key);
            wrapped.push(OP_CHECKSIGADD);
        }
        wrapped.push(0x52);
        wrapped.push(OP_NUMEQUAL);
        assert_eq!(
            extract_multisig_tapscript(&wrapped),
            Err(ScriptError::InvalidMultisigTapscript)
        );

        // Wrong opcode order: OP_CHECKSIG on the second key.
        let mut wrong_order = canonical.clone();
        wrong_order[33 + 34] = OP_CHECKSIG;
        assert_eq!(
            extract_multisig_tapscript(&wrong_order),
            Err(ScriptError::InvalidMultisigTapscript)
        );

        // OP_M above the key count (m = 4 > n = 3).
        let mut m_over_n = canonical.clone();
        let m_pos = m_over_n.len() - 2;
        m_over_n[m_pos] = 0x54;
        assert_eq!(
            extract_multisig_tapscript(&m_over_n),
            Err(ScriptError::InvalidMultisigTapscript)
        );

        // OP_16 as the threshold — above the unified 15 bound.
        let mut m16 = canonical.clone();
        let m16_pos = m16.len() - 2;
        m16[m16_pos] = 0x60;
        assert_eq!(
            extract_multisig_tapscript(&m16),
            Err(ScriptError::InvalidMultisigTapscript)
        );

        // A body whose length is not a multiple of 34 (a stray byte
        // before the tail keeps the counters valid).
        let mut stray = Vec::new();
        stray.push(0x51); // a lone OP_1 in the body
        stray.extend_from_slice(&canonical);
        assert_eq!(
            extract_multisig_tapscript(&stray),
            Err(ScriptError::InvalidMultisigTapscript)
        );

        // A well-formed 16-key body under an OP_15 threshold: the
        // shape parses but the unified 15-key bound (R-MS-9) rejects
        // the extract.
        let mut oversized = Vec::new();
        let keys16: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let mut k = [0u8; 32];
                k[31] = i as u8 + 1;
                k
            })
            .collect();
        for (i, key) in keys16.iter().enumerate() {
            oversized.push(0x20);
            oversized.extend_from_slice(key);
            oversized.push(if i == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD });
        }
        oversized.push(0x5f); // OP_15 ≤ N range check
        oversized.push(OP_NUMEQUAL);
        assert_eq!(oversized.len(), 34 * 16 + 2);
        assert_eq!(
            extract_multisig_tapscript(&oversized),
            Err(ScriptError::InvalidMultisigTapscript)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_extract_round_trip_all_quorums() {
        // Builder ↔ extractor round trip over every 1 ≤ M ≤ N ≤ 3
        // combination (the exhaustive small-quorum sweep; the N = 15
        // boundary is pinned in the bounds test).
        let [k1g, k2g, k3g] = tap_keys();
        // The script carries the keys x-only-sorted; the round trip is
        // against that sorted order, not the fixture argument order.
        let mut all = [k1g, k2g, k3g];
        all.sort_unstable();
        for n in 1..=3 {
            for m in 1..=n {
                let script = make_multisig_tapscript(m, &all[..n]).unwrap();
                assert_eq!(script.len(), 34 * n + 2);
                assert_eq!(
                    extract_multisig_tapscript(&script).unwrap(),
                    (m, all[..n].to_vec())
                );
            }
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_leaf_hash_uses_minimal_compact_size() {
        // The 512-byte 15-key leaf must be committed with the
        // 3-byte minimal CompactSize `fd 00 02` (never an
        // OP_PUSHDATA push) — pinned via the independent reference
        // leaf hash.
        let distinct: Vec<[u8; 32]> = (0..15)
            .map(|i| {
                let mut k = [0u8; 32];
                k[31] = i as u8 + 1;
                k
            })
            .collect();
        let big = make_multisig_tapscript(15, &distinct).unwrap();
        assert_eq!(
            hex::encode(tapscript_leaf_hash(&big)),
            "f3f2d3c44bfe8a37bbfbecc2ddd4915d7b960aa78847fe94ecf3d6ed5e6b6e18"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_witness_reverses_slots_appends_script_and_control() {
        // R-MS-11: slots arrive in script-key order (w_1 first) and
        // go out reversed; non-signer slots are empty vectors; the
        // script and the control block close the stack; there is no
        // dummy element.
        let [_, kx, _] = tap_keys();
        let script = make_multisig_tapscript(1, &[kx]).unwrap();
        let control = [0xc0u8; 33];
        let w1 = vec![0xaau8; 64];
        let w3 = vec![0xbbu8; 64];
        let stack =
            make_multisig_tapscript_witness(&script, &control, &[Some(&w1), None, Some(&w3)]);
        assert_eq!(stack.len(), 5);
        assert_eq!(stack[0], w3, "w_N is the first wire item");
        assert!(stack[1].is_empty(), "non-signer slot is the empty item");
        assert_eq!(stack[2], w1, "w_1 is the top of the final stack");
        assert_eq!(stack[3], script);
        assert_eq!(stack[4], control.to_vec());
        // All-empty slots still assemble (an unsigned stack is not
        // the assembler's concern).
        let empty = make_multisig_tapscript_witness(&script, &control, &[None, None, None]);
        assert!(empty[..3].iter().all(|s| s.is_empty()));
    }
}
