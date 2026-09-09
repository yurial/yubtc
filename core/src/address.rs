//! Address derivation: P2PKH/P2SH (base58check), native SegWit
//! P2WPKH (bech32) and Taproot P2TR (bech32m), plus mainnet WIF.
//!
//! Legacy base58 addresses and WIF are encoded as
//! `base58check(version_byte ‖ body)` where the checksum is the
//! leading 4 bytes of `double-SHA256(payload)`; these paths are
//! bit-for-bit frozen (guarded by the Phase 1–12 KATs).
//!
//! SegWit/Taproot (Phase 13): P2WPKH is `bech32` (BIP-173) with
//! witness version 0 and a 20-byte hash160 program; P2TR is `bech32m`
//! (BIP-350) with witness version 1 and a 32-byte x-only output key
//! obtained by the BIP-86 key-path TapTweak. Decoding is strict and
//! reports [`SegWitAddrError`] for every malformed case.
//!
//! The Bitcoin protocol constants are mainnet-only; see
//! [`yubtc/specs/spec.md`](../specs/spec.md) for the deliberate "mainnet only"
//! scope. Testnet (`0x6f`/`0xc4`, WIF `0xef`, HRP `tb`) and witness
//! versions ≥ 2 are rejected.

use base58::ToBase58;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::group::Group as _;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{ProjectivePoint, PublicKey};
use ripemd::Ripemd160;
use sha2::{Digest as _, Sha256};

use crate::bech32::{self, Encoding};
use crate::fwd::MS_TAPSCRIPT_INTERNAL_KEY;
use crate::misc::TAddress;
use crate::privkey::privkey_to_pubkey;

// --- Bitcoin protocol constants ------------------------------------

/// Mainnet P2PKH version byte.
pub const PREFIX_P2PKH: u8 = 0x00;

/// Mainnet bech32/bech32m human-readable part (BIP-173/350). Testnet
/// (`tb`) is out of scope and rejected on decode.
pub const HRP_MAINNET: &str = "bc";

/// Mainnet P2SH version byte.
pub const PREFIX_P2SH: u8 = 0x05;

/// Testnet P2PKH version byte (rejected).
pub const PREFIX_TESTNET_P2PKH: u8 = 0x6f;

/// Testnet P2SH version byte (rejected).
pub const PREFIX_TESTNET_P2SH: u8 = 0xc4;

/// Mainnet WIF version byte.
pub const PREFIX_PRIVKEY: u8 = 0x80;

/// Testnet WIF version byte (rejected).
pub const PREFIX_TESTNET_PRIVKEY: u8 = 0xef;

/// Compressed-WIF trailing byte.
pub const SUFFIX_PRIVKEY_COMPRESSED: u8 = 0x01;

// --- Errors ---------------------------------------------------------

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("invalid base58check address: {0}")]
    Invalid(String),

    #[error("address version 0x{0:02x} not supported (mainnet P2PKH=0x00, P2SH=0x05 only)")]
    UnsupportedVersion(u8),

    #[error("address body must be 20 bytes (hash160), got {0}")]
    BadBodyLength(usize),

    /// The BIP-86 TapTweak could not be applied: either the supplied
    /// internal key is not a valid curve point, or `Q = P + t·G` came
    /// out as the point at infinity (probability ~2⁻¹²⁸, but reported
    /// as a typed error rather than a panic — same policy as
    /// `PrivKeyError::InvalidScalar`).
    #[error("taproot tweak failed: {0}")]
    TapTweak(String),
}

/// Errors of the strict SegWit-address decoder
/// ([`decode_segwit_address`]). One variant per rejection rule of
/// BIP-173/BIP-350 plus the yubtc scope limits.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SegWitAddrError {
    /// A character outside the printable US-ASCII range or outside
    /// the bech32 charset.
    #[error("invalid character {0:?} in bech32 address")]
    InvalidCharacter(char),

    /// Neither the bech32 nor the bech32m checksum matches — or the
    /// checksum constant does not correspond to the witness version
    /// (BIP-350 rule 2: v0 → bech32, v1+ → bech32m).
    #[error("bech32 checksum mismatch")]
    InvalidChecksum,

    /// The string mixes lowercase and uppercase characters (BIP-173
    /// decoders MUST reject mixed case).
    #[error("mixed-case bech32 address")]
    MixedCase,

    /// The address exceeds the 90-character BIP-173 limit.
    #[error("bech32 address longer than 90 characters")]
    TooLong,

    /// The human-readable part is not `bc` (yubtc is mainnet-only;
    /// `tb` and every other HRP are rejected).
    #[error("invalid bech32 human-readable part {0:?} (mainnet \"bc\" only)")]
    InvalidHrp(String),

    /// The witness program length is invalid: BIP-141 allows
    /// 2..=40 bytes, v0 must be exactly 20 (P2WPKH), v1 exactly 32
    /// (P2TR).
    #[error("invalid witness program length {0}")]
    InvalidProgramLength(usize),

    /// The witness version is outside the yubtc scope. Versions ≥ 2
    /// are structurally valid BIP-350 addresses but the wallet neither
    /// creates nor spends them.
    #[error("unknown witness version {0} (yubtc supports v0/v1 only)")]
    UnknownWitnessVersion(u8),

    /// A valid v0 P2WSH address (32-byte program, bech32): recognized
    /// by the parser but explicitly out of scope — the wallet does not
    /// create or spend P2WSH outputs.
    #[error("P2WSH addresses (witness v0, 32-byte program) are out of scope")]
    UnsupportedProgram,

    /// The string is structurally malformed: no `1` separator, empty
    /// HRP, no witness-version character, or a padding violation in
    /// the 5→8 bit regrouping.
    #[error("malformed bech32 address structure")]
    InvalidStructure,
}

/// A decoded native-SegWit witness program: the `OP_n` witness
/// version plus the raw witness program bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TWitnessProgram {
    /// Witness version: 0 (P2WPKH) or 1 (P2TR) for addresses yubtc
    /// creates/spends. Values up to 16 parse but are rejected by
    /// [`decode_segwit_address`] with `UnknownWitnessVersion`.
    pub version: u8,

    /// Witness program: 20 bytes (hash160) for P2WPKH, 32 bytes
    /// (x-only output key) for P2TR.
    pub program: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WifError {
    #[error("invalid base58check WIF: {0}")]
    Invalid(String),

    #[error("WIF version 0x{0:02x} not supported (mainnet 0x80 only)")]
    UnsupportedVersion(u8),

    #[error("WIF body must be 33 bytes (compressed 0x01 suffix), got {0}")]
    BadBodyLength(usize),

    #[error("WIF compressed flag must be 0x01, got 0x{0:02x}")]
    Uncompressed(u8),
}

// --- base58check ---------------------------------------------------

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Test-only accessor for the `double_sha256` helper so wallet
/// tests can construct payload checksums without going through a
/// `P2PKH` address.
#[cfg(test)]
pub fn double_sha256_for_test(data: &[u8]) -> [u8; 32] {
    double_sha256(data)
}

fn base58check_encode(payload: &[u8]) -> String {
    let mut with_checksum = Vec::with_capacity(payload.len() + 4);
    with_checksum.extend_from_slice(payload);
    let checksum = double_sha256(payload);
    with_checksum.extend_from_slice(&checksum[..4]);
    with_checksum.to_base58()
}

// The Bitcoin base58 alphabet. Same as the `base58` crate's
// `ALPHABET` — kept verbatim so any string we accept round-trips
// through `base58::ToBase58` on the encode side.
const B58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Per-character digit value for the base58 alphabet. `-1` marks
// characters that are not in the alphabet; the decoder treats
// those as a hard error rather than panicking (this is the bug
// `base58-0.2.0` has — see TODO.md).
//
// Kept as `[i16; 256]` so the lookup can index by raw byte
// without an extra `usize` conversion at every step.
const B58_DIGITS_MAP: [i16; 256] = {
    let mut m = [0i16; 256];
    let mut i = 0;
    while i < 256 {
        m[i] = -1;
        i += 1;
    }
    let mut idx = 0i16;
    while (idx as usize) < B58_ALPHABET.len() {
        m[B58_ALPHABET[idx as usize] as usize] = idx;
        idx += 1;
    }
    m
};

/// Total base58 decoder for arbitrary byte slices.
///
/// Replacement for `base58::FromBase58::from_base58` — see TODO.md
/// for the upstream bug this works around. The decoder rejects
/// every malformed input with `Err` and never panics, even on
/// inputs designed to underflow the leading-zero arithmetic in
/// `base58-0.2.0/src/lib.rs:165` (e.g. many leading `'1'` chars
/// followed by a single non-zero digit).
///
/// `s` must be valid UTF-8 — the Bitcoin protocol only emits
/// base58 strings as ASCII. Callers in this crate feed it
/// `&str` from user input or from `wif_to_secret`'s argument,
/// which is documented as a `&str`.
fn base58_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    // 132-byte scratch matches the original `base58` crate's bin
    // capacity. Bitcoin addresses and WIFs are far below this
    // (≤ ~52 chars), so the fixed allocation is fine.
    const BIN_SIZE: usize = 132;
    const OUT_SIZE: usize = BIN_SIZE.div_ceil(4); // 33

    // The reference algorithm supports scratch sizes that are not a
    // multiple of 4 via a `bytesleft` zero-mask and a partial-word
    // flattening prologue. 132 % 4 == 0, so that whole sub-algorithm
    // (zeromask, the `out[0] & zeromask` overflow check, and the
    // partial-word `bin[0]` arms) is dead by construction here. Pin
    // the invariant so a future BIN_SIZE change re-visits this
    // simplification instead of silently dropping the masking.
    debug_assert_eq!(BIN_SIZE % 4, 0, "BIN_SIZE must stay 4-byte aligned");

    let mut bin = [0u8; BIN_SIZE];
    let mut out = [0u32; OUT_SIZE];

    // Count of leading `'1'` characters (each represents one
    // leading zero byte in the decoded result). We cap at BIN_SIZE
    // so an adversarial `11111...` string can't trigger an
    // arithmetic underflow later in the algorithm.
    let zcount = s.bytes().take_while(|b| *b == b'1').count();
    if zcount > BIN_SIZE {
        return Err("too many leading zeros");
    }

    let bytes = s.as_bytes();
    let mut i = zcount;
    while i < bytes.len() {
        let d = B58_DIGITS_MAP[bytes[i] as usize];
        if d < 0 {
            return Err("invalid base58 character");
        }
        let mut c = d as u64;
        // Walk the big-endian u32 array right-to-left, multiplying
        // by 58 and adding the new digit.
        let mut j = OUT_SIZE;
        while j != 0 {
            j -= 1;
            let t = out[j] as u64 * 58 + c;
            c = (t & 0x3f00000000) >> 32;
            out[j] = (t & 0xffffffff) as u32;
        }
        if c != 0 {
            return Err("output number too big");
        }
        i += 1;
    }

    // Flatten the u32 array back into bytes. BIN_SIZE is a multiple
    // of 4 (see the debug_assert above), so flattening starts at
    // out[0] with no partial leading word.
    let mut i = 0usize;
    let mut j = 0usize;
    while j < OUT_SIZE {
        bin[i] = ((out[j] >> 0x18) & 0xff) as u8;
        bin[i + 1] = ((out[j] >> 0x10) & 0xff) as u8;
        bin[i + 2] = ((out[j] >> 8) & 0xff) as u8;
        bin[i + 3] = (out[j] & 0xff) as u8;
        i += 4;
        j += 1;
    }

    // Safety check: the original algorithm assumes the number of
    // decoded leading zeros (`leading_zeros`) is at least `zcount`.
    // For inputs like `111...15` (17 `'1'` then `'5'`), the decoded
    // number has only 3 leading zeros, and `leading_zeros - zcount`
    // would underflow on `usize`. Cap zcount earlier in the loop
    // doesn't help (the bin capacity is 132 but the decoded length
    // can be smaller); we verify the invariant here and return
    // `Err` instead.
    let leading_zeros = bin.iter().take_while(|b| **b == 0).count();
    if leading_zeros < zcount {
        return Err("malformed base58 input");
    }
    Ok(bin[leading_zeros - zcount..].to_vec())
}

fn base58check_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let decoded = base58_decode(s).map_err(|_| "base58 decode failed")?;
    if decoded.len() < 4 {
        return Err("decoded body shorter than checksum");
    }
    let (body, checksum_in) = decoded.split_at(decoded.len() - 4);
    let checksum_expected = double_sha256(body);
    if checksum_in != &checksum_expected[..4] {
        return Err("checksum mismatch");
    }
    Ok(body.to_vec())
}

// --- hash160 -------------------------------------------------------

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let mut ripe = Ripemd160::new();
    ripe.update(sha);
    let out = ripe.finalize();
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&out);
    arr
}

/// Public `hash160` helper for callers that need to verify a UTXO's
/// `scriptPubKey` matches the privkey they're spending with (the
/// wallet's input builder). Internal callers use the private `hash160`
/// to avoid leaking the impl details.
pub fn hash160_pubkey(pubkey: &[u8; 33]) -> [u8; 20] {
    hash160(pubkey)
}

/// `hash160` of an arbitrary byte string — the P2SH commitment over a
/// redeem script (Phase 15): the Creator, Signer and Finalizer check
/// `hash160(redeem) == hash160` embedded in the canonical P2SH
/// `scriptPubKey` before touching a multisig input.
pub fn hash160_script(data: &[u8]) -> [u8; 20] {
    hash160(data)
}

/// `SHA-256` of an arbitrary byte string — the P2WSH commitment over a
/// redeem script (spec «Multi-sig», форма P2WSH): the Creator, Signer and
/// Finalizer check `SHA256(redeem) == program` embedded in the
/// canonical P2WSH witness `scriptPubKey` before touching a
/// witness-form multisig input.
pub fn sha256_script(data: &[u8]) -> [u8; 32] {
    let sha = Sha256::digest(data);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&sha);
    arr
}

// --- pubkey -> address ---------------------------------------------

/// Compressed public key → mainnet P2PKH address.
///
/// Infallible: every 33-byte input hashes to a 20-byte `hash160`, and
/// base58check encoding of a fixed 21-byte payload cannot fail. There
/// is deliberately no `Result` here — a fake error branch would be
/// untestable and would push callers into meaningless error handling.
pub fn pubkey_to_address(pubkey: &[u8; 33]) -> TAddress {
    let h = hash160(pubkey);
    let mut payload = [0u8; 21];
    payload[0] = PREFIX_P2PKH;
    payload[1..].copy_from_slice(&h);
    TAddress::new(base58check_encode(&payload))
}

/// Private key → mainnet P2PKH address (compressed). Infallible for
/// the same reason as [`pubkey_to_address`].
pub fn privkey_to_address(privkey: &SigningKey) -> TAddress {
    let pk = privkey_to_pubkey(privkey);
    pubkey_to_address(&pk)
}

/// Decode a mainnet P2PKH or P2SH address to `(version, hash160)`.
/// Testnet / Bech32 / any other version is rejected.
pub fn decode_address(addr: &TAddress) -> Result<(u8, [u8; 20]), AddressError> {
    let body =
        base58check_decode(addr.as_str()).map_err(|e| AddressError::Invalid(e.to_string()))?;
    if body.len() != 21 {
        return Err(AddressError::BadBodyLength(body.len()));
    }
    let version = body[0];
    if version != PREFIX_P2PKH && version != PREFIX_P2SH {
        return Err(AddressError::UnsupportedVersion(version));
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&body[1..]);
    Ok((version, hash))
}

// --- SegWit / Taproot (Phase 13) -----------------------------------

/// Add the tweak to a lifted internal key and return the x-only
/// output key. Split out of [`taproot_output_key`] so the
/// infinity branch stays testable with crafted `(P, t)` inputs
/// (unreachable through real keys: p ~ 2⁻¹²⁸).
fn tweak_output_key(p: ProjectivePoint, t: k256::Scalar) -> Result<[u8; 32], AddressError> {
    let q = p + (ProjectivePoint::GENERATOR * t);
    if bool::from(q.is_identity()) {
        return Err(AddressError::TapTweak(
            "output key Q is the point at infinity (p ~ 2^-128)".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&q.to_affine().x());
    Ok(out)
}

/// Apply the BIP-86 key-path TapTweak to an x-only internal key.
///
/// Contract: returns the 32-byte x-only output key
/// `Q = lift_x(x(P)) + tagged_hash("TapTweak", x(P))·G` with the
/// Merkle root empty (BIP-86: no script-path commitment). Fails with
/// [`AddressError::TapTweak`] when `internal_xonly` is not a valid
/// curve point or when `Q` is the point at infinity (probability
/// ~2⁻¹²⁸; reported, never panicked).
pub fn taproot_output_key(internal_xonly: &[u8; 32]) -> Result<[u8; 32], AddressError> {
    // lift_x per BIP-340: an x-only key denotes the even-Y point.
    // Building the 0x02-prefixed SEC1 form and parsing it delegates
    // the on-curve check to k256.
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(internal_xonly);
    let pk = PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| AddressError::TapTweak("internal pubkey is not a valid curve point".into()))?;

    let t = crate::misc::taproot_tweak_scalar(internal_xonly);
    tweak_output_key(ProjectivePoint::from(pk.as_affine()), t)
}

/// lift_x of an x-only key: the even-Y point the 32 bytes denote
/// ([`AddressError::TapTweak`] when the bytes are not a curve point).
fn lift_x(internal_xonly: &[u8; 32]) -> Result<ProjectivePoint, AddressError> {
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(internal_xonly);
    let pk = PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| AddressError::TapTweak("internal pubkey is not a valid curve point".into()))?;
    Ok(ProjectivePoint::from(pk.as_affine()))
}

/// BIP-341 **script-path** output key of a Tapscript quorum leaf
/// (v0.3, specs/spec.md «Адрес и leaf-хеш»):
///
/// ```text
/// t = int(tagged_hash("TapTweak", internal_key ‖ leaf_hash))
/// Q = lift_x(internal_key) + t·G
/// ```
///
/// `internal_key` is the NUMS point ([`MS_TAPSCRIPT_INTERNAL_KEY`])
/// for every quorum yubtc builds; `leaf_hash` comes from
/// [`tapscript_leaf_hash`](crate::script::tapscript_leaf_hash).
/// Fails with [`AddressError::TapTweak`] when the internal key is not
/// a curve point or when the tweak scalar is ≥ the curve order
/// (BIP-341 MUST-fail, probability ~2⁻¹²⁸).
pub fn tapscript_output_key(
    internal_xonly: &[u8; 32],
    leaf_hash: &[u8; 32],
) -> Result<[u8; 32], AddressError> {
    let p = lift_x(internal_xonly)?;
    let t = crate::misc::taproot_tweak_script_scalar(internal_xonly, leaf_hash)?;
    tweak_output_key(p, t)
}

/// The BIP-341 control block of a single-leaf tapscript tree:
/// `c[0] ‖ internal_key` — `33 = 33 + 32·depth` bytes at `depth = 0`
/// (empty Merkle path), where `c[0] = 0xc0 | (y(Q) mod 2)` packs the
/// leaf version and the output-key parity (`c[0] & 0xfe == 0xc0`).
///
/// Fails under the same conditions as [`tapscript_output_key`] (the
/// point arithmetic is shared).
pub fn tapscript_control_block(
    internal_xonly: &[u8; 32],
    leaf_hash: &[u8; 32],
) -> Result<[u8; 33], AddressError> {
    let p = lift_x(internal_xonly)?;
    let t = crate::misc::taproot_tweak_script_scalar(internal_xonly, leaf_hash)?;
    let q = (p + (ProjectivePoint::GENERATOR * t)).to_affine();
    let mut out = [0u8; 33];
    out[0] = 0xc0 | (bool::from(q.y_is_odd()) as u8);
    out[1..33].copy_from_slice(internal_xonly);
    Ok(out)
}

/// Tapscript leaf → mainnet P2TR quorum address (`bc1p…`, bech32m
/// v1). The commitment is the tweaked output key
/// `Q = lift_x(H) + t·G` over the NUMS internal key `H` and the
/// leaf's `hashTapLeaf` — the same value
/// [`make_p2tr_lock_script`](crate::script::make_p2tr_lock_script)
/// embeds in the lock script, so an output paid to the returned
/// address is spendable exactly by revealing the tapscript and the
/// control block in the witness (the v0.3 quorum address of the
/// `p2tr` form; ОВ-13 — fixed by the `(N, M, keys)` tuple, no
/// scan/gap walk).
///
/// Errors: [`AddressError::TapTweak`] per [`tapscript_output_key`].
pub fn redeem_to_tapscript_address(script: &[u8]) -> Result<TAddress, AddressError> {
    let leaf_hash = crate::script::tapscript_leaf_hash(script);
    let output_key = tapscript_output_key(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)?;
    let wp = TWitnessProgram {
        version: 1,
        program: output_key.to_vec(),
    };
    Ok(TAddress::new(encode_segwit_string(&wp)))
}

/// Strictly decode a mainnet **P2TR** address (`bc1p…` with a 32-byte
/// program) into its x-only output key.
///
/// The dedicated P2TR decoder of the v0.3 multisig surface (the
/// tapscript counterpart of
/// [`decode_p2wsh_address`]): bech32 structure and checksum, HRP
/// `bc`, witness version 1, program exactly 32 bytes, and the bech32m
/// checksum constant (BIP-350 rule 2). v0 programs and 20-byte
/// programs are [`SegWitAddrError::UnsupportedProgram`] — this
/// decoder is P2TR-only by contract.
pub fn decode_taproot_address(addr: &str) -> Result<[u8; 32], SegWitAddrError> {
    let (hrp, encoding, data) = bech32::decode(addr).map_err(|e| match e {
        bech32::Bech32Error::TooLong => SegWitAddrError::TooLong,
        bech32::Bech32Error::InvalidCharacter(c) => SegWitAddrError::InvalidCharacter(c),
        bech32::Bech32Error::MixedCase => SegWitAddrError::MixedCase,
        bech32::Bech32Error::InvalidChecksum => SegWitAddrError::InvalidChecksum,
        bech32::Bech32Error::InvalidStructure | bech32::Bech32Error::InvalidDataValue(_) => {
            SegWitAddrError::InvalidStructure
        }
    })?;
    if hrp != HRP_MAINNET {
        return Err(SegWitAddrError::InvalidHrp(hrp.to_string()));
    }
    let (version, payload) = match data.split_first() {
        Some(v) => (*v.0, v.1),
        None => return Err(SegWitAddrError::InvalidStructure),
    };
    let program = bech32::five_bit_to_bytes(payload).ok_or(SegWitAddrError::InvalidStructure)?;
    if version != 1 {
        return Err(SegWitAddrError::UnsupportedProgram);
    }
    if program.len() != 32 {
        return Err(SegWitAddrError::UnsupportedProgram);
    }
    if encoding != Encoding::Bech32m {
        return Err(SegWitAddrError::InvalidChecksum);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&program);
    Ok(out)
}

// The SegWit-address encoder lives behind `encode_segwit_string`; it
// is intentionally private — the wallet only ever encodes programs
// derived from its own keys via the two `pubkey_to_*` constructors.

/// Encode a witness program as a mainnet SegWit address string.
///
/// v0 uses bech32 (BIP-173), every other version bech32m (BIP-350).
/// Infallible for every program the wallet creates: a v0/20-byte
/// program yields a 42-character address and a v1/32-byte program a
/// 62-character address — both far below the 90-character BIP-173
/// limit — and `bytes_to_5bit` only emits 5-bit values. `expect`
/// documents that invariant instead of threading a statically
/// unreachable error through the callers.
fn encode_segwit_string(wp: &TWitnessProgram) -> String {
    let encoding = match wp.version {
        0 => Encoding::Bech32,
        _ => Encoding::Bech32m,
    };
    let mut data = Vec::with_capacity(1 + wp.program.len() * 8 / 5 + 1);
    data.push(wp.version);
    data.extend_from_slice(&bech32::bytes_to_5bit(&wp.program));
    bech32::encode(HRP_MAINNET, encoding, &data)
        .expect("witness program encodes within the bech32 limits")
}

/// Compressed public key → mainnet P2WPKH address (`bc1q…`, bech32).
///
/// Infallible: hash160 of any 33-byte key is a 20-byte program, and a
/// v0/20-byte program always encodes within the BIP-173 length limit.
pub fn pubkey_to_segwit_address(pubkey: &[u8; 33]) -> TAddress {
    let h = hash160(pubkey);
    let wp = TWitnessProgram {
        version: 0,
        program: h.to_vec(),
    };
    TAddress::new(encode_segwit_string(&wp))
}

/// Compressed public key → mainnet P2TR address (`bc1p…`, bech32m).
///
/// The output key is the BIP-86 key-path TapTweak of the internal key
/// (empty Merkle root); only the x coordinate of the input pubkey is
/// used, so 0x02/0x03 prefixes of the same key yield the same address.
///
/// Errors: [`AddressError::TapTweak`] when the internal key is not a
/// valid curve point, or when the tweaked point is the identity
/// (probability ~2⁻¹²⁸).
pub fn pubkey_to_taproot_address(pubkey: &[u8; 33]) -> Result<TAddress, AddressError> {
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&pubkey[1..33]);
    let output_key = taproot_output_key(&xonly)?;
    let wp = TWitnessProgram {
        version: 1,
        program: output_key.to_vec(),
    };
    Ok(TAddress::new(encode_segwit_string(&wp)))
}

/// Redeem script → mainnet P2SH address (`3…`, base58check with
/// version `0x05`).
///
/// The hash is `hash160(redeem)` — the same commitment
/// [`make_p2sh_lock_script`](crate::script::make_p2sh_lock_script)
/// embeds in the lock script, so an output paid to the returned
/// address is spendable exactly by revealing and satisfying `redeem`
/// (Phase 15: the multisig quorum address, ОВ-13 — fixed by the
/// `(N, M, keys)` tuple, no scan/gap walk).
///
/// Infallible: hash160 of any byte string is 20 bytes, and
/// base58check of the fixed 21-byte payload cannot fail — the same
/// no-`Result` reasoning as [`pubkey_to_address`].
pub fn redeem_to_p2sh_address(redeem: &[u8]) -> TAddress {
    let h = hash160(redeem);
    let mut payload = [0u8; 21];
    payload[0] = PREFIX_P2SH;
    payload[1..].copy_from_slice(&h);
    TAddress::new(base58check_encode(&payload))
}

/// Redeem script → mainnet P2WSH address (`bc1q…`, bech32 with
/// witness version 0 and a 32-byte program).
///
/// The commitment is `SHA256(redeem)` — the same 32-byte value
/// [`make_p2wsh_lock_script`](crate::script::make_p2wsh_lock_script)
/// embeds in the witness lock script, so an output paid to the
/// returned address is spendable exactly by revealing and satisfying
/// `redeem` in the witness stack (v0.3 multisig quorum address, the
/// P2WSH counterpart of [`redeem_to_p2sh_address`]: same redeem
/// script, witness form — ОВ-13 applies unchanged).
///
/// Infallible: SHA-256 of any byte string is 32 bytes, and a v0/
/// 32-byte program always encodes within the BIP-173 length limit —
/// the same no-`Result` reasoning as [`pubkey_to_segwit_address`].
pub fn redeem_to_p2wsh_address(redeem: &[u8]) -> TAddress {
    let wp = TWitnessProgram {
        version: 0,
        program: sha256_script(redeem).to_vec(),
    };
    TAddress::new(encode_segwit_string(&wp))
}

/// Strictly decode a mainnet **P2WSH** address (`bc1q…` with a
/// 32-byte program) into its SHA-256 commitment.
///
/// The dedicated P2WSH decoder of the v0.3 multisig surface: the
/// general [`decode_segwit_address`] keeps its Phase-13 contract
/// (v0/32 programs answered `UnsupportedProgram` there), while the
/// quorum surface needs to recognize its own `bc1q…` addresses.
/// Rejection rules mirror the general decoder: bech32 structure and
/// checksum, HRP `bc`, witness version 0, program exactly 32 bytes,
/// the bech32 (not bech32m) checksum constant for v0 (BIP-350 rule 2).
/// Versions ≥ 1 and 20-byte v0 programs (P2WPKH) are
/// [`SegWitAddrError::UnsupportedProgram`] — this decoder is
/// P2WSH-only by contract.
pub fn decode_p2wsh_address(addr: &str) -> Result<[u8; 32], SegWitAddrError> {
    let (hrp, encoding, data) = bech32::decode(addr).map_err(|e| match e {
        bech32::Bech32Error::TooLong => SegWitAddrError::TooLong,
        bech32::Bech32Error::InvalidCharacter(c) => SegWitAddrError::InvalidCharacter(c),
        bech32::Bech32Error::MixedCase => SegWitAddrError::MixedCase,
        bech32::Bech32Error::InvalidChecksum => SegWitAddrError::InvalidChecksum,
        bech32::Bech32Error::InvalidStructure | bech32::Bech32Error::InvalidDataValue(_) => {
            SegWitAddrError::InvalidStructure
        }
    })?;
    if hrp != HRP_MAINNET {
        return Err(SegWitAddrError::InvalidHrp(hrp.to_string()));
    }
    let (version, payload) = match data.split_first() {
        Some(v) => (*v.0, v.1),
        None => return Err(SegWitAddrError::InvalidStructure),
    };
    let program = bech32::five_bit_to_bytes(payload).ok_or(SegWitAddrError::InvalidStructure)?;
    if version != 0 {
        return Err(SegWitAddrError::UnsupportedProgram);
    }
    if program.len() != 32 {
        return Err(SegWitAddrError::UnsupportedProgram);
    }
    if encoding != Encoding::Bech32 {
        return Err(SegWitAddrError::InvalidChecksum);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&program);
    Ok(out)
}

/// Strictly decode a mainnet SegWit address (`bc1…`) into its
/// witness program.
///
/// Rejection rules, in order:
/// 1. generic bech32 structure and checksum ([`bech32::decode`]):
///    length ≤ 90, printable ASCII, no mixed case, `1` separator,
///    charset, bech32/bech32m checksum;
/// 2. HRP must be `bc` ([`SegWitAddrError::InvalidHrp`]);
/// 3. the 5-bit payload must contain a witness-version value
///    ([`SegWitAddrError::InvalidStructure`]) that fits in a byte;
/// 4. the program must regroup into whole bytes with ≤ 4 zero
///    padding bits and be 2..=40 bytes long
///    ([`SegWitAddrError::InvalidStructure`] /
///    [`SegWitAddrError::InvalidProgramLength`]);
/// 5. BIP-141 per-version lengths: v0 → 20 bytes, v1 → 32
///    ([`SegWitAddrError::InvalidProgramLength`]);
/// 6. BIP-350 rule 2: v0 requires the bech32 checksum, v1+ bech32m
///    ([`SegWitAddrError::InvalidChecksum`]);
/// 7. yubtc scope: v0/32-byte programs are P2WSH — parsed but
///    rejected ([`SegWitAddrError::UnsupportedProgram`]); versions
///    ≥ 2 are rejected ([`SegWitAddrError::UnknownWitnessVersion`]).
pub fn decode_segwit_address(addr: &str) -> Result<TWitnessProgram, SegWitAddrError> {
    let (hrp, encoding, data) = bech32::decode(addr).map_err(|e| match e {
        bech32::Bech32Error::TooLong => SegWitAddrError::TooLong,
        bech32::Bech32Error::InvalidCharacter(c) => SegWitAddrError::InvalidCharacter(c),
        bech32::Bech32Error::MixedCase => SegWitAddrError::MixedCase,
        bech32::Bech32Error::InvalidChecksum => SegWitAddrError::InvalidChecksum,
        bech32::Bech32Error::InvalidStructure | bech32::Bech32Error::InvalidDataValue(_) => {
            SegWitAddrError::InvalidStructure
        }
    })?;
    if hrp != HRP_MAINNET {
        return Err(SegWitAddrError::InvalidHrp(hrp.to_string()));
    }
    let (version, payload) = match data.split_first() {
        Some(v) => (*v.0, v.1),
        None => return Err(SegWitAddrError::InvalidStructure),
    };
    let program = bech32::five_bit_to_bytes(payload).ok_or(SegWitAddrError::InvalidStructure)?;
    if program.len() < 2 || program.len() > 40 {
        return Err(SegWitAddrError::InvalidProgramLength(program.len()));
    }
    // Witness versions are 0..=16 (OP_0..OP_16); the 5-bit version
    // value can encode up to 31, which is unrepresentable on-chain.
    if version > 16 {
        return Err(SegWitAddrError::UnknownWitnessVersion(version));
    }
    if version == 0 && program.len() != 20 && program.len() != 32 {
        return Err(SegWitAddrError::InvalidProgramLength(program.len()));
    }
    // BIP-350 rule 2: the checksum constant must match the version.
    if version == 0 && encoding != Encoding::Bech32 {
        return Err(SegWitAddrError::InvalidChecksum);
    }
    if version != 0 && encoding != Encoding::Bech32m {
        return Err(SegWitAddrError::InvalidChecksum);
    }
    // yubtc scope: P2WPKH (v0/20) and P2TR (v1/32) only.
    if version == 0 && program.len() == 32 {
        return Err(SegWitAddrError::UnsupportedProgram);
    }
    if version > 1 {
        return Err(SegWitAddrError::UnknownWitnessVersion(version));
    }
    Ok(TWitnessProgram { version, program })
}

// --- WIF ----------------------------------------------------------

/// Private key → mainnet compressed WIF (`base58check(0x80 ‖ secret ‖ 0x01)`).
pub fn privkey_to_wif(privkey: &SigningKey) -> String {
    let secret = privkey.to_bytes();
    let mut payload = [0u8; 34];
    payload[0] = PREFIX_PRIVKEY;
    payload[1..33].copy_from_slice(&secret);
    payload[33] = SUFFIX_PRIVKEY_COMPRESSED;
    base58check_encode(&payload)
}

/// Decode a mainnet compressed WIF to a 32-byte secret.
pub fn wif_to_secret(wif: &str) -> Result<[u8; 32], WifError> {
    let body = base58check_decode(wif).map_err(|e| WifError::Invalid(e.to_string()))?;
    if body.is_empty() {
        return Err(WifError::BadBodyLength(0));
    }
    let version = body[0];
    if version != PREFIX_PRIVKEY {
        return Err(WifError::UnsupportedVersion(version));
    }
    let secret_body = &body[1..];
    if secret_body.len() != 33 {
        return Err(WifError::BadBodyLength(secret_body.len()));
    }
    if secret_body[32] != SUFFIX_PRIVKEY_COMPRESSED {
        return Err(WifError::Uncompressed(secret_body[32]));
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_body[..32]);
    Ok(secret)
}

/// Decode a mainnet compressed WIF to a `SigningKey`.
pub fn wif_to_privkey(wif: &str) -> Result<SigningKey, WifError> {
    let secret = wif_to_secret(wif)?;
    SigningKey::from_bytes((&secret).into()).map_err(|e| WifError::Invalid(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::misc::{TNonce, TPassphrase, TSeed};
    use crate::privkey::seed2privkey;

    // --- pubkey_to_address / privkey_to_address --------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn privkey_to_address_is_mainnet_p2pkh() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let addr = privkey_to_address(&pk);
        // Mainnet P2PKH addresses start with '1'.
        assert!(addr.as_str().starts_with('1'));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_round_trip_p2pkh() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let addr = privkey_to_address(&pk);
        let (version, hash) = decode_address(&addr).unwrap();
        assert_eq!(version, PREFIX_P2PKH);
        // hash matches the address's pubkey hash.
        let pubkey = privkey_to_pubkey(&pk);
        let h2 = hash160(&pubkey);
        assert_eq!(hash, h2);
    }

    // --- redeem_to_p2sh_address (Phase 15) -------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn redeem_to_p2sh_address_round_trips_through_decode() {
        use crate::script::make_multisig_redeem_script;
        let mut k1 = [0x02u8; 33];
        k1[32] = 0x01;
        let mut k2 = [0x02u8; 33];
        k2[32] = 0x02;
        let redeem = make_multisig_redeem_script(2, &[k1, k2]).unwrap();
        let addr = redeem_to_p2sh_address(&redeem);
        // Mainnet P2SH addresses start with '3'.
        assert!(addr.as_str().starts_with('3'));
        // The embedded hash is hash160(redeem) under version 0x05.
        let (version, hash) = decode_address(&addr).unwrap();
        assert_eq!(version, PREFIX_P2SH);
        assert_eq!(hash, hash160(&redeem));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn redeem_to_p2sh_address_matches_the_lock_script_and_is_deterministic() {
        use crate::script::make_multisig_redeem_script;
        use crate::wallet::make_lock_script_for_address;
        let mut k1 = [0x03u8; 33];
        k1[32] = 0x0a;
        let mut k2 = [0x02u8; 33];
        k2[32] = 0x0b;
        let redeem = make_multisig_redeem_script(1, &[k1, k2]).unwrap();
        let addr = redeem_to_p2sh_address(&redeem);
        // The lock script built from the address commits to the same
        // hash160 — paying it is spendable by revealing `redeem`.
        assert_eq!(
            make_lock_script_for_address(&addr).unwrap(),
            crate::script::make_p2sh_lock_script(&hash160(&redeem))
        );
        // Deterministic: same redeem → same address.
        assert_eq!(redeem_to_p2sh_address(&redeem), addr);
        // Different redeem → different address.
        let other = make_multisig_redeem_script(2, &[k1, k2]).unwrap();
        assert_ne!(redeem_to_p2sh_address(&other), addr);
    }

    // --- redeem_to_p2wsh_address + decode_p2wsh_address (v0.3) ------

    /// Canonical fixture redeem (2-of-2 over two syntactically
    /// distinct compressed keys).
    fn p2wsh_fixture_redeem() -> Vec<u8> {
        use crate::script::make_multisig_redeem_script;
        let mut k1 = [0x02u8; 33];
        k1[32] = 0x01;
        let mut k2 = [0x02u8; 33];
        k2[32] = 0x02;
        make_multisig_redeem_script(2, &[k1, k2]).unwrap()
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn redeem_to_p2wsh_address_round_trips_through_decode() {
        let redeem = p2wsh_fixture_redeem();
        let addr = redeem_to_p2wsh_address(&redeem);
        // Mainnet v0 SegWit addresses start with 'bc1q'.
        assert!(addr.as_str().starts_with("bc1q"));
        // The decoded program is exactly SHA256(redeem).
        let commitment = decode_p2wsh_address(addr.as_str()).unwrap();
        assert_eq!(commitment, sha256_script(&redeem));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn redeem_to_p2wsh_address_matches_the_lock_script_and_is_deterministic() {
        use crate::script::make_p2wsh_lock_script;
        use crate::wallet::make_lock_script_for_address;
        let redeem = p2wsh_fixture_redeem();
        let addr = redeem_to_p2wsh_address(&redeem);
        // The lock script built from the address commits to the same
        // SHA-256 — paying it is spendable by revealing `redeem`.
        assert_eq!(
            make_lock_script_for_address(&addr).unwrap(),
            make_p2wsh_lock_script(&sha256_script(&redeem))
        );
        // Deterministic: same redeem → same address.
        assert_eq!(redeem_to_p2wsh_address(&redeem), addr);
        // Same quorum, different form: the P2SH and P2WSH addresses
        // share the redeem script but differ everywhere else.
        let p2sh = redeem_to_p2sh_address(&redeem);
        assert_ne!(p2sh, addr);
        assert!(p2sh.as_str().starts_with('3'));
        // Different redeem → different address.
        let other = {
            use crate::script::make_multisig_redeem_script;
            let mut k1 = [0x02u8; 33];
            k1[32] = 0x01;
            let mut k3 = [0x03u8; 33];
            k3[32] = 0x02;
            make_multisig_redeem_script(2, &[k1, k3]).unwrap()
        };
        assert_ne!(redeem_to_p2wsh_address(&other), addr);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_p2wsh_address_rejects_non_p2wsh_and_malformed() {
        let redeem = p2wsh_fixture_redeem();
        let good = redeem_to_p2wsh_address(&redeem);
        // Round-trip sanity for the rejections below.
        assert!(decode_p2wsh_address(good.as_str()).is_ok());

        // A P2WPKH address (v0/20) is not a P2WSH program.
        let mut k = [0x02u8; 33];
        k[32] = 0x05;
        let p2wpkh = pubkey_to_segwit_address(&k);
        assert!(matches!(
            decode_p2wsh_address(p2wpkh.as_str()),
            Err(SegWitAddrError::UnsupportedProgram)
        ));

        // A P2TR address (v1) is out of this decoder's contract.
        // (A real curve point: the fixture key [0x02, 0, …, 0x05]
        // does not derive — use the address test suite's seed key.)
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let valid_pub = privkey_to_pubkey(&pk);
        let p2tr = pubkey_to_taproot_address(&valid_pub).unwrap();
        assert!(matches!(
            decode_p2wsh_address(p2tr.as_str()),
            Err(SegWitAddrError::UnsupportedProgram)
        ));

        // bech32m checksum (v1 spelling) on a v0 payload is a
        // checksum rejection (BIP-350 rule 2).
        let wp = TWitnessProgram {
            version: 0,
            program: sha256_script(&redeem).to_vec(),
        };
        let m_encoded = {
            let mut data = Vec::with_capacity(1 + wp.program.len() * 8 / 5 + 1);
            data.push(wp.version);
            data.extend_from_slice(&bech32::bytes_to_5bit(&wp.program));
            bech32::encode(HRP_MAINNET, Encoding::Bech32m, &data)
                .expect("program encodes within the bech32 limits")
        };
        assert!(matches!(
            decode_p2wsh_address(&m_encoded),
            Err(SegWitAddrError::InvalidChecksum)
        ));

        // Wrong HRP with a VALID tb checksum (built by the encoder):
        // the HRP rule fires before any commitment check.
        let tb_valid = bech32::encode("tb", Encoding::Bech32, &{
            let mut data = vec![0u8];
            data.extend_from_slice(&bech32::bytes_to_5bit(&sha256_script(&redeem)));
            data
        })
        .expect("the tb payload encodes within the bech32 limits");
        assert!(matches!(
            decode_p2wsh_address(&tb_valid),
            Err(SegWitAddrError::InvalidHrp(_))
        ));
        // A swapped-HRP string breaks the checksum first (the
        // checksum is computed over the HRP).
        let tb = good.as_str().replacen("bc1", "tb1", 1);
        assert!(matches!(
            decode_p2wsh_address(&tb),
            Err(SegWitAddrError::InvalidChecksum)
        ));
        // Too long: > 90 characters (BIP-173 length rule).
        let long = format!("bc1q{}", "q".repeat(95));
        assert!(matches!(
            decode_p2wsh_address(&long),
            Err(SegWitAddrError::TooLong)
        ));
        // Invalid character in the data part ('o' is excluded from
        // the bech32 charset — the BIP-350 invalid vector).
        let bad_char = "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4";
        assert!(matches!(
            decode_p2wsh_address(bad_char),
            Err(SegWitAddrError::InvalidCharacter('o'))
        ));
        // Mixed case is rejected before the checksum.
        let mixed = format!("BC1Q{}", &good.as_str()[4..]);
        assert!(matches!(
            decode_p2wsh_address(&mixed),
            Err(SegWitAddrError::MixedCase)
        ));
        // Garbage keeps the generic decode errors.
        assert!(matches!(
            decode_p2wsh_address("notabech32"),
            Err(SegWitAddrError::InvalidStructure)
        ));

        // A bech32 string with an EMPTY payload decodes structurally
        // but carries no witness version -> InvalidStructure (the
        // `split_first` arm).
        let empty_payload = bech32::encode(HRP_MAINNET, Encoding::Bech32, &[])
            .expect("an empty payload encodes within the bech32 limits");
        assert!(matches!(
            decode_p2wsh_address(&empty_payload),
            Err(SegWitAddrError::InvalidStructure)
        ));
        // A one-character 5-bit payload with a nonzero padding bit
        // cannot regroup into bytes -> InvalidStructure (the
        // `five_bit_to_bytes` arm), not a crash.
        let bad_padding = bech32::encode(HRP_MAINNET, Encoding::Bech32, &[0, 1])
            .expect("the crafted 5-bit payload encodes");
        assert!(matches!(
            decode_p2wsh_address(&bad_padding),
            Err(SegWitAddrError::InvalidStructure)
        ));
    }

    // --- WIF round-trip --------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_round_trip() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let wif = privkey_to_wif(&pk);
        // Mainnet compressed WIF starts with 'K' or 'L' (compressed).
        // Bitwise `|` (not `||`) so both prefix checks are evaluated —
        // the short-circuit form leaves one `||` arm permanently
        // uncovered for branch coverage.
        assert!(wif.starts_with('K') | wif.starts_with('L'));
        let back = wif_to_privkey(&wif).unwrap();
        assert_eq!(pk.to_bytes(), back.to_bytes());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_secret_round_trip() {
        let seed = TSeed::new("abandon ".repeat(11).trim().to_string() + " about");
        let pk = seed2privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY).unwrap();
        let wif = privkey_to_wif(&pk);
        let secret = wif_to_secret(&wif).unwrap();
        // Secret matches the SigningKey's bytes (post-clamp? no — the
        // SigningKey stores the post-clamp secret; the WIF encodes the
        // post-clamp secret too).
        assert_eq!(secret, pk.to_bytes().as_slice());
    }

    // --- error cases -----------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_address_rejects_testnet() {
        // Build a testnet P2PKH address manually:
        // base58check(0x6f ‖ 20 zero bytes).
        let mut payload = vec![PREFIX_TESTNET_P2PKH];
        payload.extend([0u8; 20]);
        let s = base58check_encode(&payload);
        let r = decode_address(&TAddress::new(s));
        assert!(matches!(r, Err(AddressError::UnsupportedVersion(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_address_rejects_bad_body_length() {
        // base58check(0x00 ‖ 19 zero bytes) — too short.
        let mut payload = vec![PREFIX_P2PKH];
        payload.extend([0u8; 19]);
        let s = base58check_encode(&payload);
        let r = decode_address(&TAddress::new(s));
        assert!(matches!(r, Err(AddressError::BadBodyLength(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_address_rejects_bad_checksum() {
        let good = base58check_encode(&[PREFIX_P2PKH; 21]);
        let mut tampered = good.clone();
        // Flip the last character. (Base58 alphabet: 1-9, A-H, J-N,
        // P-Z, a-k, m-z — note that 'a' is *not* in the alphabet, so
        // we must increment to a valid char.)
        let last = tampered.pop().unwrap();
        let new_last = (last as u8 + 1) as char;
        tampered.push(new_last);
        let r = decode_address(&TAddress::new(tampered));
        assert!(matches!(r, Err(AddressError::Invalid(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_rejects_testnet_prefix() {
        // Manually craft a testnet WIF (0xef ‖ 32 zero bytes ‖ 0x01).
        let mut payload = vec![PREFIX_TESTNET_PRIVKEY];
        payload.extend([0u8; 33]);
        let s = base58check_encode(&payload);
        let r = wif_to_secret(&s);
        assert!(matches!(r, Err(WifError::UnsupportedVersion(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_rejects_uncompressed() {
        // mainnet prefix, 32-byte secret, no 0x01 suffix.
        let mut payload = vec![PREFIX_PRIVKEY];
        payload.extend([0u8; 32]);
        let s = base58check_encode(&payload);
        let r = wif_to_secret(&s);
        assert!(matches!(r, Err(WifError::BadBodyLength(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_rejects_wrong_compressed_flag() {
        let mut payload = vec![PREFIX_PRIVKEY];
        payload.extend([0u8; 32]);
        payload.push(0x02); // not 0x01
        let s = base58check_encode(&payload);
        let r = wif_to_secret(&s);
        assert!(matches!(r, Err(WifError::Uncompressed(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_rejects_bad_checksum() {
        let good = base58check_encode(&{
            let mut p = vec![PREFIX_PRIVKEY];
            p.extend([0u8; 32]);
            p.push(SUFFIX_PRIVKEY_COMPRESSED);
            p
        });
        let mut bad = good.clone();
        let last = bad.pop().unwrap();
        let new_last = (last as u8 + 1) as char;
        bad.push(new_last);
        let r = wif_to_secret(&bad);
        assert!(matches!(r, Err(WifError::Invalid(_))));
    }

    // --- base58check helpers ---------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn base58check_round_trip() {
        let payload = b"hello world";
        let s = base58check_encode(payload);
        let back = base58check_decode(&s).unwrap();
        assert_eq!(back, payload);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn base58check_detects_corruption() {
        let s = base58check_encode(b"hello");
        let mut bad = s.clone();
        let last = bad.pop().unwrap();
        bad.push((last as u8 + 1) as char);
        assert!(base58check_decode(&bad).is_err());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn base58check_rejects_too_short_decoded() {
        // Empty string → empty decoded vec → shorter than 4-byte checksum.
        assert!(base58check_decode("").is_err());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_rejects_empty_decoded_body() {
        // Empty base58 string passes through base58check_decode as an
        // Err (body shorter than checksum) — wif_to_secret maps that
        // to Invalid.
        assert!(matches!(wif_to_secret(""), Err(WifError::Invalid(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_rejects_base58check_with_empty_body() {
        // Hand-crafted base58check string that decodes to exactly the
        // 4-byte double_sha256(b"") checksum. base58check_decode
        // succeeds with an empty body; wif_to_secret's `body.is_empty()`
        // guard fires.
        //
        // double_sha256(b"")[:4] == 5df6e0e2 → base58 = "3QJmnh".
        let r = wif_to_secret("3QJmnh");
        assert!(matches!(r, Err(WifError::BadBodyLength(0))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_address_rejects_invalid_base58() {
        // "0OIl" are NOT in the base58 alphabet → base58 decode fails.
        assert!(matches!(
            decode_address(&TAddress::new("0OIl")),
            Err(AddressError::Invalid(_))
        ));
        // Empty string → too short to contain checksum.
        assert!(matches!(
            decode_address(&TAddress::new("")),
            Err(AddressError::Invalid(_))
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_to_privkey_rejects_invalid_scalar() {
        // WIF encoding: 0x80 ‖ secret ‖ 0x01. We pick a secret that's
        // structurally valid base58check but the 32-byte secret value
        // exceeds the secp256k1 curve order, so k256 rejects it.
        //
        // secp256k1 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        // We use 0xFF..FF — definitely > n.
        let mut payload = vec![PREFIX_PRIVKEY];
        payload.extend([0xffu8; 32]);
        payload.push(SUFFIX_PRIVKEY_COMPRESSED);
        let wif = base58check_encode(&payload);
        assert!(matches!(wif_to_privkey(&wif), Err(WifError::Invalid(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_to_privkey_propagates_wif_secret_errors() {
        // Cover the `?` operator: wif_to_secret fails → wif_to_privkey
        // returns the same error without trying SigningKey::from_bytes.
        // Invalid base58 chars trigger base58check_decode failure.
        assert!(matches!(wif_to_privkey("0OIl"), Err(WifError::Invalid(_))));
    }

    // --- base58 underflow regression ---------------------------------
    //
    // `base58-0.2.0` panics with `attempt to subtract with overflow`
    // on inputs like `"111...15"` where the leading-`'1'` count
    // exceeds the number of leading-zero bytes in the decoded result.
    // The fuzz target `fuzz_wif` reproduced this within seconds;
    // this test pins the behaviour to a typed `Err` so a future
    // revert to the unfixed decoder would fail loudly in CI rather
    // than via a process kill during fuzzing.

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wif_rejects_base58_underflow_input() {
        // 17 `'1'`s followed by a single `'5'` (digit 5) and a
        // tail of `'h'` (digit 33). zcount=17, leading_zeros=3
        // after the multiply-by-58 loop — original code underflows.
        let mut s = String::from("1").repeat(17);
        s.push('5');
        s.push_str(&"h".repeat(110));
        let r = wif_to_secret(&s);
        assert!(
            matches!(r, Err(WifError::Invalid(_))),
            "wif_to_secret must return Err on underflow-prone input, got {:?}",
            r
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_address_rejects_base58_underflow_input() {
        // Same shape as the WIF regression — must surface as
        // AddressError::Invalid, never panic.
        let mut s = String::from("1").repeat(17);
        s.push('5');
        s.push_str(&"h".repeat(110));
        let r = decode_address(&TAddress::new(s));
        assert!(matches!(r, Err(AddressError::Invalid(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn base58check_decode_rejects_excessive_leading_ones() {
        // > 132 leading `'1'` chars — the bin scratch is only 132
        // bytes; an honest decoder must reject rather than truncate
        // silently. Pinned here so a future "trust the upstream
        // crate again" change is caught by CI.
        let s = "1".repeat(200);
        let r = base58check_decode(&s);
        assert!(r.is_err());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_address_rejects_output_number_too_big() {
        // 182 max-digits ('z' = 57) overflow the 1056-bit scratch:
        // 58^182 - 1 > 2^1056 - 1, so the multiply loop must surface
        // the carry check's "output number too big" error instead of
        // wrapping around. 181 'z' chars would just barely fit
        // (58^181 - 1 < 2^1056), so the bound is exact — keep the
        // digit count in sync with BIN_SIZE if it ever changes.
        let s = "z".repeat(182);
        let r = decode_address(&TAddress::new(s));
        assert!(
            matches!(r, Err(AddressError::Invalid(_))),
            "expected Err(Invalid) on 1056-bit overflow, got {r:?}"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_address_rejects_leading_zeros_exceeding_decoded_length() {
        // 17 leading '1's claim 17 leading zero bytes in the result,
        // but the 159 'z' digits decode to a ~117-byte number with
        // only 15 leading zero bytes — `leading_zeros - zcount` would
        // underflow, so the decoder must reject with "malformed
        // base58 input". The value stays below 2^1056 (58^159 - 1),
        // so this hits the invariant check, not the carry check.
        let mut s = "1".repeat(17);
        s.push_str(&"z".repeat(159));
        let r = decode_address(&TAddress::new(s));
        assert!(
            matches!(r, Err(AddressError::Invalid(_))),
            "expected Err(Invalid) on zcount underflow input, got {r:?}"
        );
    }

    // --- hash160 ---------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn hash160_known_vector() {
        // hash160 of empty string. Cross-checked against
        // PyCryptodome (RIPEMD160(SHA256(b""))).
        let h = hash160(b"");
        let expected = hex::decode("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb").unwrap();
        assert_eq!(h.to_vec(), expected);
    }

    // --- SegWit / Taproot (Phase 13) --------------------------------

    use crate::bech32;
    use k256::elliptic_curve::bigint::U256;
    use k256::elliptic_curve::ops::Reduce;
    use k256::{ProjectivePoint, Scalar};

    /// BIP-173 example pubkey 0279BE66...1798 (the generator's
    /// compressed form) — its hash160 is the official P2WPKH program.
    const BIP173_PUBKEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    /// Compressed form of the BIP-86 m/86'/0'/0'/0/0 internal key
    /// (x-only `cc8a4bc6...c115`, parity prefix as published).
    const BIP86_KEY0_COMPRESSED: [u8; 33] = [
        0x02, 0xcc, 0x8a, 0x4b, 0xc6, 0x4d, 0x89, 0x7b, 0xdd, 0xc5, 0xfb, 0xc2, 0xf6, 0x70, 0xf7,
        0xa8, 0xba, 0x0b, 0x38, 0x67, 0x79, 0x10, 0x6c, 0xf1, 0x22, 0x3c, 0x6f, 0xc5, 0xd7, 0xcd,
        0x6f, 0xc1, 0x15,
    ];

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn pubkey_to_segwit_address_matches_bip173_example() {
        // BIP-173: mainnet P2WPKH of 0279BE66...798 is
        // bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.
        let addr = pubkey_to_segwit_address(&BIP173_PUBKEY);
        assert_eq!(addr.as_str(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_segwit_round_trip_p2wpkh() {
        let addr = pubkey_to_segwit_address(&BIP173_PUBKEY);
        let wp = decode_segwit_address(addr.as_str()).unwrap();
        assert_eq!(wp.version, 0);
        assert_eq!(wp.program, hash160(&BIP173_PUBKEY).to_vec());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip86_vectors_match_official_output_keys_and_addresses() {
        // Official BIP-86 test vectors (account 0, receiving
        // addresses 0 and 1): TapTweak + bech32m must reproduce the
        // published output keys and addresses byte-for-byte.
        let vectors: &[(&str, &str, &str)] = &[
            (
                "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
                "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            ),
            (
                "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
                "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
                "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
            ),
        ];
        for (internal_hex, output_hex, address) in vectors {
            let internal: [u8; 32] = hex::decode(internal_hex).unwrap().try_into().unwrap();
            let tweaked = taproot_output_key(&internal).unwrap();
            assert_eq!(hex::encode(tweaked), *output_hex, "TapTweak mismatch");
            let wp = TWitnessProgram {
                version: 1,
                program: tweaked.to_vec(),
            };
            assert_eq!(encode_segwit_string(&wp), *address);
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip86_derivation_end_to_end() {
        // Full chain for the first BIP-86 vector: BIP-39 stretch →
        // BIP-32 m/86'/0'/0'/0/0 → x-only internal key → TapTweak →
        // address. Pins that the crate's BIP-32 walk agrees with the
        // BIP's published xprv chain and that the receiving-address
        // constructor lands on the official string.
        use bip32::{ChildNumber, ExtendedPrivateKey};
        use k256::ecdsa::SigningKey;

        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let mut stretched = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(mnemonic.as_bytes(), b"mnemonic", 2048, &mut stretched);
        let path = [
            ChildNumber::new(86, true).unwrap(),
            ChildNumber::new(0, true).unwrap(),
            ChildNumber::new(0, true).unwrap(),
            ChildNumber::new(0, false).unwrap(),
            ChildNumber::new(0, false).unwrap(),
        ];
        // Re-derive as a SigningKey to reach the pubkey layer; the
        // x-only internal key below is the published BIP-86 value and
        // transitively pins the whole walk.
        let signing = ExtendedPrivateKey::<SigningKey>::new(stretched)
            .unwrap()
            .derive_child(path[0])
            .unwrap()
            .derive_child(path[1])
            .unwrap()
            .derive_child(path[2])
            .unwrap()
            .derive_child(path[3])
            .unwrap()
            .derive_child(path[4])
            .unwrap();
        let pubkey = privkey_to_pubkey(signing.private_key());
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&pubkey[1..]);
        assert_eq!(
            hex::encode(xonly),
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        );
        let addr = pubkey_to_taproot_address(&pubkey).unwrap();
        assert_eq!(
            addr.as_str(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        // Sanity: the parity-free construction (0x02 prefix) yields
        // the same address.
        let even = pubkey_to_taproot_address(&BIP86_KEY0_COMPRESSED).unwrap();
        let mut odd = BIP86_KEY0_COMPRESSED;
        odd[0] = 0x03;
        let odd_addr = pubkey_to_taproot_address(&odd).unwrap();
        assert_eq!(addr, even);
        assert_eq!(addr, odd_addr);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taproot_output_key_rejects_non_curve_point() {
        // X = 0xffff...ff is not on secp256k1 — k256's SEC1 parser
        // must reject it, surfacing as AddressError::TapTweak.
        let bad = [0xffu8; 32];
        let err = taproot_output_key(&bad).unwrap_err();
        assert!(matches!(err, AddressError::TapTweak(_)));
        assert!(err.to_string().contains("curve point"));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tweak_output_key_reports_infinity() {
        // P = -5·G with t = 5 gives Q = 0 — the p ~ 2^-128 branch,
        // driven with crafted inputs since real keys cannot reach it.
        let mut five_bytes = [0u8; 32];
        five_bytes[31] = 5;
        let five = <Scalar as Reduce<U256>>::reduce_bytes(&five_bytes.into());
        let neg_five_g = -(ProjectivePoint::GENERATOR * five);
        let err = tweak_output_key(neg_five_g, five).unwrap_err();
        assert!(matches!(err, AddressError::TapTweak(_)));
        assert!(err.to_string().contains("infinity"));
        // The non-infinity twin still succeeds: G + 5G = 6G.
        let mut six_bytes = [0u8; 32];
        six_bytes[31] = 6;
        let six = <Scalar as Reduce<U256>>::reduce_bytes(&six_bytes.into());
        let out = tweak_output_key(ProjectivePoint::GENERATOR, five).unwrap();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&(ProjectivePoint::GENERATOR * six).to_affine().x());
        assert_eq!(out, expected);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn bip341_taproot_address_vector() {
        // Official BIP-341 wallet test vector (scriptPubKey section,
        // entry 0 with a null script tree): internal key
        // d6889cb0...961d → output key 53a1f6e4...a343 → address
        // bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5.
        let internal: [u8; 32] =
            hex::decode("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d")
                .unwrap()
                .try_into()
                .unwrap();
        let output = taproot_output_key(&internal).unwrap();
        assert_eq!(
            hex::encode(output),
            "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
        );
        let wp = TWitnessProgram {
            version: 1,
            program: output.to_vec(),
        };
        assert_eq!(
            encode_segwit_string(&wp),
            "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5"
        );
    }

    // --- Tapscript (v0.3): script-path output key / control block /
    //     address -----------------------------------------------------

    /// The canonical 2-of-3 tapscript over x(G), x(2G), x(3G) — the
    /// leaf-hash fixture shared with the script.rs vectors.
    fn tapscript_fixture_script() -> Vec<u8> {
        use crate::script::make_multisig_tapscript;
        let keys: Vec<[u8; 32]> = [
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ]
        .iter()
        .map(|k| hex::decode(k).unwrap().try_into().unwrap())
        .collect();
        make_multisig_tapscript(2, &keys).expect("fixture quorum is valid")
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_output_key_and_control_block_match_reference_vectors() {
        // Independent Python reference (spec vectors): NUMS internal
        // key + the 2-of-3 fixture leaf → the pinned output key with
        // even parity and the control block c0 ‖ H.
        let internal = MS_TAPSCRIPT_INTERNAL_KEY;
        let leaf: [u8; 32] =
            hex::decode("640fca23685170704e436970f8ca462899442be7b8a4010bcb31eb579c65c004")
                .unwrap()
                .try_into()
                .unwrap();
        let output = tapscript_output_key(&internal, &leaf).unwrap();
        assert_eq!(
            hex::encode(output),
            "8df67ad4ec3bfb01b66fb6fbdfec811f90b3fa0e9842ea523f6e09d387280688"
        );
        let control = tapscript_control_block(&internal, &leaf).unwrap();
        assert_eq!(
            hex::encode(control),
            concat!(
                "c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9a",
                "ce803ac0"
            )
        );
        assert_eq!(control[0] & 0xfe, 0xc0);
        assert_eq!(control[0] & 1, 1, "odd parity of the fixture output key");
        assert_eq!(&control[1..], &internal);
        // The 1-of-1 leaf lands on its own pinned key (a second,
        // differently-tweaked data point).
        let leaf1: [u8; 32] =
            hex::decode("4c7ac8b22c633180138b87f6bc6d25b58423f90d9edc6c95727933cdc1480381")
                .unwrap()
                .try_into()
                .unwrap();
        let output1 = tapscript_output_key(&internal, &leaf1).unwrap();
        assert_eq!(
            hex::encode(output1),
            "fa293d3d65c149b1e896c3f50d2f0991d23e5725df2b703c10f61f126b132630"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tapscript_output_key_rejects_non_curve_internal() {
        // The NUMS lift happens on the internal key: a non-curve
        // x-only input is the typed TapTweak failure, never a panic.
        let bad = [0xffu8; 32];
        let leaf = [7u8; 32];
        assert!(matches!(
            tapscript_output_key(&bad, &leaf),
            Err(AddressError::TapTweak(_))
        ));
        assert!(matches!(
            tapscript_control_block(&bad, &leaf),
            Err(AddressError::TapTweak(_))
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn redeem_to_tapscript_address_round_trips_through_decode() {
        let script = tapscript_fixture_script();
        let addr = redeem_to_tapscript_address(&script).expect("tweak is valid");
        // bech32m v1: `bc1p…`, 62 characters per the spec's size note.
        assert!(addr.as_str().starts_with("bc1p"));
        assert_eq!(addr.as_str().len(), 62);
        // The decoded program is exactly the tweaked output key.
        let program = decode_taproot_address(addr.as_str()).expect("p2tr address");
        let leaf_hash = crate::script::tapscript_leaf_hash(&script);
        assert_eq!(
            program,
            tapscript_output_key(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash).unwrap()
        );
        // The lock script built from the address commits to the same
        // key — paying it is spendable by revealing the tapscript.
        assert_eq!(
            crate::wallet::make_lock_script_for_address(&addr).unwrap(),
            crate::script::make_p2tr_lock_script(&program).to_vec()
        );
        // Deterministic; and a different leaf gives a different
        // address.
        assert_eq!(redeem_to_tapscript_address(&script).unwrap(), addr);
        let other = {
            use crate::script::make_multisig_tapscript;
            let keys: Vec<[u8; 32]> = [
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            ]
            .iter()
            .map(|k| hex::decode(k).unwrap().try_into().unwrap())
            .collect();
            make_multisig_tapscript(2, &keys).unwrap()
        };
        assert_ne!(redeem_to_tapscript_address(&other).unwrap(), addr);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_taproot_address_rejects_non_p2tr_and_malformed() {
        let script = tapscript_fixture_script();
        let good = redeem_to_tapscript_address(&script).unwrap();
        assert!(decode_taproot_address(good.as_str()).is_ok());

        // A P2WPKH address (v0/20) is not a P2TR program.
        let mut k = [0x02u8; 33];
        k[32] = 0x05;
        let p2wpkh = pubkey_to_segwit_address(&k);
        assert!(matches!(
            decode_taproot_address(p2wpkh.as_str()),
            Err(SegWitAddrError::UnsupportedProgram)
        ));
        // A P2WSH address (v0/32) is out of this decoder's contract.
        let p2wsh = redeem_to_p2wsh_address(&tapscript_fixture_script());
        assert!(matches!(
            decode_taproot_address(p2wsh.as_str()),
            Err(SegWitAddrError::UnsupportedProgram)
        ));
        // A v0 payload (bech32m spelling) is rejected by the version
        // rule before the checksum rule — this decoder is P2TR-only.
        let m_v0 = bech32::encode(HRP_MAINNET, Encoding::Bech32m, &{
            let mut data = vec![0u8];
            data.extend_from_slice(&bech32::bytes_to_5bit(&[0xabu8; 20]));
            data
        })
        .expect("v0 payload encodes");
        assert!(matches!(
            decode_taproot_address(&m_v0),
            Err(SegWitAddrError::UnsupportedProgram)
        ));
        // A v1 payload carrying a bech32 (not bech32m) checksum is a
        // BIP-350 rule-2 rejection (official invalid vector).
        assert_eq!(
            decode_taproot_address(
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd"
            ),
            Err(SegWitAddrError::InvalidChecksum)
        );
        // Wrong HRP with a valid tb checksum.
        let tb_valid = bech32::encode("tb", Encoding::Bech32m, &{
            let mut data = vec![1u8];
            data.extend_from_slice(&bech32::bytes_to_5bit(&[0xabu8; 32]));
            data
        })
        .expect("tb payload encodes");
        assert!(matches!(
            decode_taproot_address(&tb_valid),
            Err(SegWitAddrError::InvalidHrp(_))
        ));
        // Mixed case (BIP-173 decoders MUST reject).
        let mixed = format!("BC1P{}", &good.as_str()[4..]);
        assert!(matches!(
            decode_taproot_address(&mixed),
            Err(SegWitAddrError::MixedCase)
        ));
        // A corrupted checksum fails inside the generic bech32 decode
        // (the rule-2 arm above is a different rejection path).
        for alt in ['q', 'p'] {
            let mut corrupted = good.as_str().to_string();
            corrupted.pop();
            corrupted.push(alt);
            assert!(matches!(
                decode_taproot_address(&corrupted),
                Err(SegWitAddrError::InvalidChecksum)
            ));
        }
        // A v1 witness program of the wrong length (20 bytes) is the
        // program-length refusal, not the version one.
        let v1_short = bech32::encode(HRP_MAINNET, Encoding::Bech32m, &{
            let mut data = vec![1u8];
            data.extend_from_slice(&bech32::bytes_to_5bit(&[0xabu8; 20]));
            data
        })
        .expect("v1/20 payload encodes");
        assert!(matches!(
            decode_taproot_address(&v1_short),
            Err(SegWitAddrError::UnsupportedProgram)
        ));
        // Too long, invalid character, garbage, empty payload.
        let long = format!("bc1p{}", "p".repeat(95));
        assert!(matches!(
            decode_taproot_address(&long),
            Err(SegWitAddrError::TooLong)
        ));
        assert!(matches!(
            decode_taproot_address(
                "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4"
            ),
            Err(SegWitAddrError::InvalidCharacter('o'))
        ));
        assert!(matches!(
            decode_taproot_address("notabech32"),
            Err(SegWitAddrError::InvalidStructure)
        ));
        let empty_payload =
            bech32::encode(HRP_MAINNET, Encoding::Bech32m, &[]).expect("an empty payload encodes");
        assert!(matches!(
            decode_taproot_address(&empty_payload),
            Err(SegWitAddrError::InvalidStructure)
        ));
    }

    // --- decode_segwit_address: official vectors --------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_accepts_official_valid_addresses() {
        let cases: &[(&str, u8, &str)] = &[
            // BIP-173 mainnet P2WPKH (uppercase input, lowercase
            // program out).
            (
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                0,
                "751e76e8199196d454941c45d1b3a323f1433bd6",
            ),
            // BIP-350 v1-16 valid list, bc-prefixed P2TR.
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                1,
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
        ];
        for (s, version, program_hex) in cases {
            let wp = decode_segwit_address(s).expect(s);
            assert_eq!(wp.version, *version, "{s}");
            assert_eq!(hex::encode(&wp.program), *program_hex, "{s}");
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_rejects_official_invalid_addresses() {
        use SegWitAddrError as E;
        let cases: &[(&str, E)] = &[
            // Invalid human-readable part.
            (
                "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
                E::InvalidHrp("tc".into()),
            ),
            // v1 with a bech32 checksum (BIP-350 rule 2).
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
                E::InvalidChecksum,
            ),
            // v0 with a bech32m checksum.
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
                E::InvalidChecksum,
            ),
            // Invalid character in checksum: the scan hits the
            // excluded 'o' before the trailing '_' (BIP-350 vector).
            (
                "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
                E::InvalidCharacter('o'),
            ),
            // Witness version 17 (charset value of '3'): the BIP-350
            // decode order rejects version > 16 before the checksum
            // rule, so this surfaces as an unknown version, not as a
            // rule-2 failure (the string does carry a bech32
            // checksum, as the BIP list notes).
            (
                "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
                E::UnknownWitnessVersion(17),
            ),
            // Program length 1.
            ("bc1pw5dgrnzv", E::InvalidProgramLength(1)),
            // Program length 41.
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
                E::InvalidProgramLength(41),
            ),
            // v0 with a 16-byte program (BIP-141 violation).
            (
                "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
                E::InvalidProgramLength(16),
            ),
            // Mixed case.
            (
                "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
                E::MixedCase,
            ),
            // Zero padding of more than 4 bits.
            ("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", E::InvalidStructure),
            // Outright checksum corruption.
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
                E::InvalidChecksum,
            ),
            // Empty data section (no witness version).
            ("bc1gmk9yu", E::InvalidStructure),
        ];
        for (s, expected) in cases {
            assert_eq!(decode_segwit_address(s).unwrap_err(), *expected, "{s}");
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_rejects_p2wsh_as_unsupported() {
        // Valid v0/32-byte bech32 address (BIP-173 mainnet P2WSH
        // example): structurally valid, out of yubtc scope.
        let err =
            decode_segwit_address("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
                .unwrap_err();
        assert_eq!(err, SegWitAddrError::UnsupportedProgram);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_rejects_witness_versions_above_one() {
        // Structurally valid bech32m addresses with witness versions
        // 2 ('z', charset index 2) and 23 ('h', index 23): both parse
        // cleanly under BIP-173/350 but must be rejected by the
        // yubtc v0/v1 scope rule.
        let charset = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        for version_char in ['z', 'h'] {
            let version = charset
                .iter()
                .position(|&c| c == version_char as u8)
                .unwrap() as u8;
            let mut payload = vec![version];
            payload.extend_from_slice(&bech32::bytes_to_5bit(&[0xabu8; 20]));
            let s = bech32::encode("bc", bech32::Encoding::Bech32m, &payload).unwrap();
            let err = decode_segwit_address(&s).unwrap_err();
            assert_eq!(err, SegWitAddrError::UnknownWitnessVersion(version), "{s}");
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_rejects_malformed_minimal_inputs() {
        use SegWitAddrError as E;
        // No separator at all.
        assert_eq!(
            decode_segwit_address("bcqpw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            Err(E::InvalidStructure)
        );
        // Too long: > 90 characters.
        let long = format!("bc1q{}", "q".repeat(95));
        assert_eq!(decode_segwit_address(&long), Err(E::TooLong));
        // Empty input.
        assert_eq!(decode_segwit_address(""), Err(E::InvalidStructure));
    }

    // --- proptest --------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #[ntest_timeout::timeout(5000)]
    #[test]
        fn wif_round_trip_arbitrary(seed: Vec<u8>) {
            // We need a 32-byte secret that satisfies secp256k1 order.
            // Use the first 32 bytes of the proptest input; if it
            // overflows, clamp via SigningKey::from_bytes (which will
            // fail for invalid keys) — but we just want to round-trip
            // the encoding, so we craft a valid key manually.
            prop_assume!(seed.len() >= 32);
            let bytes: [u8; 32] = seed[..32].try_into().unwrap();
            if let Ok(pk) = SigningKey::from_bytes((&bytes).into()) {
                let wif = privkey_to_wif(&pk);
                let back = wif_to_privkey(&wif).unwrap();
                let a = pk.to_bytes();
                let b = back.to_bytes();
                prop_assert_eq!(a.as_slice(), b.as_slice());
            }
        }
    }
}
