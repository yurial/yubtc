//! Wallet: address forms, input selection, fee loop, transaction
//! assembly.
//!
//! Mirrors `yubtc-python/src/yubtc/wallet.py`.
//!
//! Concepts:
//! - [`AddrType`] — the receive-address form: `Legacy` (P2PKH,
//!   v0.1 behaviour), `Native` (P2WPKH, the Phase 13 default) and
//!   `Taproot` (P2TR key-path, opt-in).
//! - [`Utxo`] / [`AddressInfo`] — the wallet's view of an address's
//!   on-chain state, populated by a [`crate::net::NetworkBackend`].
//! - [`TPrivKey`] — a `(seed, nonce)` → `SigningKey` pair with cached
//!   network info and unspent list. Created via
//!   [`seed2privkey_with_purpose`] under the hood, so the same
//!   passphrase/KDF selection rules apply. For `pbkdf2` the
//!   `AddrType` selects the BIP-32 leaf (`m/44'…`/`m/84'…`/`m/86'…`);
//!   for the non-BIP-32 KDFs the same key encodes in every type
//!   (вариант A, spec ОВ-2).
//! - [`Wallet`] — owns the seed/passphrase/kdf/addr_type and the
//!   primary [`TPrivKey`]; builds and signs transactions via
//!   [`Wallet::make_transaction`]. Signing goes through
//!   `Transaction::sign_segwit` (per-input scheme dispatch), and the
//!   fee loop keys its candidates on **vsize** so witness
//!   transactions pay the discounted rate.
//!
//! The fee loop in [`pick_best_fee_loop_candidate`] mirrors Python's
//! `_pick_best_fee_loop_candidate` with the Phase 13 unit change: the
//! picker prefers the smallest vsize whose fee covers the rate
//! (`fee >= int(vsize * feekb / 1000)`), ties broken on the smaller
//! absolute fee, with a fallback to the smallest vsize produced so
//! far when no iteration pays the rate. For witness-free
//! transactions `vsize == bytes`, so v0.1 decisions reproduce
//! byte-for-byte.

use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};

use crate::address::{
    decode_address, decode_p2wsh_address, decode_segwit_address, privkey_to_address,
    privkey_to_wif, pubkey_to_segwit_address, pubkey_to_taproot_address, redeem_to_p2sh_address,
    redeem_to_p2wsh_address, wif_to_secret, PREFIX_P2PKH, PREFIX_P2SH,
};
use crate::fwd::{
    DEFAULT_ADDR_TYPE, DEFAULT_CONFIRMATIONS, DUST_THRESHOLD_P2PKH, DUST_THRESHOLD_P2SH,
    DUST_THRESHOLD_P2TR, DUST_THRESHOLD_P2WPKH, DUST_THRESHOLD_P2WSH, MS_MAX_PUBKEYS,
    MS_SIG_SIZE_ESTIMATE_TAP, MS_TAPSCRIPT_INTERNAL_KEY, PSBT_SIGN_MAX_NONCE,
    SEQUENCE_RBF_SIGNALED,
};
use crate::kdf::{KdfAlgo, PURPOSE_LEGACY, PURPOSE_NATIVE, PURPOSE_TAPROOT};
use crate::misc::{TAddress, TNonce, TPassphrase, TSatoshi, TSeed};
use crate::privkey::{privkey_to_pubkey, seed2privkey_with_purpose};
use crate::psbt::{CreateInput, PartiallySignedTransaction, PsbtError};
use crate::script::{
    extract_p2pkh_hash, extract_p2tr_output_key, extract_p2wpkh_hash, make_p2pkh_lock_script,
    make_p2sh_lock_script, make_p2tr_lock_script, make_p2wpkh_lock_script, push_data_len,
};
use crate::transaction::{SpendContext, SpendInput, Transaction, TxIn, TxOut};

// --- AddrType --------------------------------------------------------

/// Receive-address type (specs/spec.md «Адресная политика и nonce→path
/// mapping»). Default after Phase 13: [`AddrType::Native`] (ОВ-1);
/// [`AddrType::Taproot`] is opt-in; [`AddrType::Legacy`] reproduces
/// v0.1 bit-for-bit.
///
/// The type affects only the receiving/cashback encoding — the scan
/// always sees UTXOs of every form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrType {
    /// P2PKH, base58check `1…` (v0.1 behaviour, unchanged).
    Legacy,
    /// Native P2WPKH, bech32 `bc1q…` (BIP-84 for `pbkdf2` wallets).
    Native,
    /// P2TR key-path, bech32m `bc1p…` (BIP-86 for `pbkdf2` wallets).
    Taproot,
}

impl Default for AddrType {
    fn default() -> Self {
        DEFAULT_ADDR_TYPE
    }
}

impl AddrType {
    /// BIP-32 derivation purpose for BIP-39-standard (`pbkdf2`)
    /// wallets: 44 (legacy), 84 (BIP-84 native), 86 (BIP-86 taproot).
    /// Non-BIP-32 KDFs ignore this (вариант A — same key).
    pub fn purpose(self) -> u32 {
        match self {
            AddrType::Legacy => PURPOSE_LEGACY,
            AddrType::Native => PURPOSE_NATIVE,
            AddrType::Taproot => PURPOSE_TAPROOT,
        }
    }

    /// Canonical lowercase name — the spelling used by the CLI flag
    /// and the FFI enum.
    pub fn name(self) -> &'static str {
        match self {
            AddrType::Legacy => "legacy",
            AddrType::Native => "native",
            AddrType::Taproot => "taproot",
        }
    }

    /// Every type in canonical scan order (P2PKH → P2WPKH → P2TR).
    pub const ALL: [AddrType; 3] = [AddrType::Legacy, AddrType::Native, AddrType::Taproot];
}

// --- Errors ---------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("seed cannot be empty")]
    EmptySeed,

    #[error("address not supported: {0}")]
    UnsupportedAddress(String),

    #[error("UTXO required pubkey hash {expected} but privkey produced {actual}")]
    UnknownPubkeyRequired { expected: String, actual: String },

    #[error("cashback_addr not set")]
    CashbackAddrNotSet,

    #[error("input does not cover fee (in_amount={in_amount}, fee={fee})")]
    InputDoesNotCoverFee { in_amount: u64, fee: u64 },

    #[error("amount + fee exceeds input (amount={amount}, fee={fee}, in_amount={in_amount})")]
    AmountExceedsInput {
        amount: u64,
        fee: u64,
        in_amount: u64,
    },

    #[error("script is not P2PKH or P2SH")]
    UnsupportedUtxoScript,

    #[error("address could not be decoded: {0}")]
    AddressDecode(String),

    #[error("privkey derivation failed: {0}")]
    PrivKey(String),

    #[error("network error: {0}")]
    Network(String),
}

impl From<crate::net::NetError> for WalletError {
    fn from(e: crate::net::NetError) -> Self {
        WalletError::Network(e.to_string())
    }
}

// --- UTXO + address info --------------------------------------------

/// A single unspent output, in the shape the wallet consumes.
///
/// `txid` is the raw 32-byte double-SHA256 in display order (reversed).
/// `script_pubkey` is the locking script bytes (P2PKH or P2SH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub confirmations: u32,
}

impl Utxo {
    /// Construct a UTXO from network fields. The wallet validates the
    /// shape (`amount > 0`, `confirmations >= 0`, P2PKH/P2SH script)
    /// before accepting it; see [`Utxo::from_network`] for the strict
    /// parser.
    pub fn from_network(
        txid_hex: &str,
        vout: u32,
        amount: u64,
        script_pubkey: &[u8],
        confirmations: u32,
    ) -> Result<Self, WalletError> {
        let txid = parse_txid_hex(txid_hex)
            .ok_or_else(|| WalletError::UnsupportedAddress(format!("bad txid hex: {txid_hex}")))?;
        validate_utxo_script(script_pubkey)?;
        if amount == 0 {
            return Err(WalletError::UnsupportedAddress(
                "zero amount UTXO".to_string(),
            ));
        }
        Ok(Self {
            txid,
            vout,
            amount,
            script_pubkey: script_pubkey.to_vec(),
            confirmations,
        })
    }
}

/// Per-address network info. Mirrors `yubtc-python`'s `get_address_info`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressInfo {
    pub total_received: u64,
    pub final_balance: u64,
    pub n_tx: u64,
}

/// Parse a txid hex string (big-endian, the Bitcoin display order) into
/// 32 raw bytes.
pub(crate) fn parse_txid_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Reject anything that isn't a canonical lock script of a form the
/// wallet creates/spends: 25-byte P2PKH, 23-byte P2SH, 22-byte P2WPKH
/// (`0x00 0x14 <20>`), 34-byte P2WSH (`0x00 0x20 <32>`, v0.3 — the
/// quorum address UTXOs must be representable, symmetric with P2SH
/// since v0.1) or 34-byte P2TR (`0x51 0x20 <32>`). Anything
/// else is a backend mismatch the wallet doesn't know how to spend.
pub(crate) fn validate_utxo_script(script: &[u8]) -> Result<(), WalletError> {
    match script.len() {
        25 => {
            extract_p2pkh_hash(script).map_err(|_| WalletError::UnsupportedUtxoScript)?;
        }
        23 => {
            // P2SH: OP_HASH160 <20B> OP_EQUAL.
            if script[0] != 0xa9 || script[1] != 0x14 || script[22] != 0x87 {
                return Err(WalletError::UnsupportedUtxoScript);
            }
        }
        22 => {
            extract_p2wpkh_hash(script).map_err(|_| WalletError::UnsupportedUtxoScript)?;
        }
        34 => {
            // Both 34-byte forms start their push at index 1; the
            // witness-version opcode selects P2WSH (`00 20 <32>`,
            // v0.3) vs P2TR (`51 20 <32>`). `extract_p2wsh_program`
            // enforces the `0x20` itself, so a `00 <other>` shape
            // still fails closed.
            if script[0] == 0x00 {
                crate::script::extract_p2wsh_program(script)
                    .map_err(|_| WalletError::UnsupportedUtxoScript)?;
            } else {
                extract_p2tr_output_key(script).map_err(|_| WalletError::UnsupportedUtxoScript)?;
            }
        }
        _ => return Err(WalletError::UnsupportedUtxoScript),
    }
    Ok(())
}

/// True when the string is spelled like a native-SegWit address
/// (`bc1…` in any case). The dispatcher for
/// [`make_lock_script_for_address`] — matches the spec's decode
/// order: `bc1` prefix → bech32 path, otherwise the base58check path.
fn looks_like_segwit_address(s: &str) -> bool {
    s.len() >= 3 && s[..3].eq_ignore_ascii_case("bc1")
}

/// Build the lock script that pays to `address`.
///
/// Dispatch by address form (specs/spec.md «Скрипты»):
/// base58check → P2PKH/P2SH; `bc1` witness v0/20 → P2WPKH; `bc1`
/// witness v1 → P2TR; `bc1` witness v0/32 → P2WSH (unlocked by the
/// v0.3 multisig surface: the quorum's cashback address is a `bc1q…`
/// P2WSH output, so the shared `make_vout` path must build its lock
/// script — the same SHA-256 commitment
/// [`crate::script::make_p2wsh_lock_script`] embeds).
pub fn make_lock_script_for_address(address: &TAddress) -> Result<Vec<u8>, WalletError> {
    if looks_like_segwit_address(address.as_str()) {
        // P2WSH first: the general decode_segwit_address keeps its
        // Phase-13 contract (it answers UnsupportedProgram for v0/32),
        // so the P2WSH program is recognized by its dedicated decoder
        // before falling through to the P2WPKH/P2TR dispatch.
        if let Ok(program) = decode_p2wsh_address(address.as_str()) {
            return Ok(crate::script::make_p2wsh_lock_script(&program).to_vec());
        }
        let wp = decode_segwit_address(address.as_str())
            .map_err(|e| WalletError::AddressDecode(e.to_string()))?;
        if wp.version == 0 {
            let hash: [u8; 20] = wp.program.as_slice().try_into().expect(
                "decode_segwit_address enforces v0 ⇒ 20-byte program (P2WSH rejected there)",
            );
            Ok(make_p2wpkh_lock_script(&hash).to_vec())
        } else {
            let key: [u8; 32] = wp.program.as_slice().try_into().expect(
                "decode_segwit_address enforces v1 ⇒ 32-byte program (v ≥ 2 rejected there)",
            );
            Ok(make_p2tr_lock_script(&key).to_vec())
        }
    } else {
        let (version, hash) =
            decode_address(address).map_err(|e| WalletError::AddressDecode(e.to_string()))?;
        let hash_bytes: &[u8] = &hash;
        // decode_address restricts versions to P2PKH (0x00) or P2SH
        // (0x05); any other version is rejected upstream as
        // AddressDecode.
        if version == PREFIX_P2PKH {
            Ok(make_p2pkh_lock_script(hash_bytes))
        } else {
            debug_assert_eq!(version, PREFIX_P2SH);
            Ok(make_p2sh_lock_script(hash_bytes))
        }
    }
}

// --- VoutResult / TxResult ------------------------------------------

/// Output of [`make_vout`]: the vout list plus the satoshi amounts.
///
/// `cashback` is 0 in the drain branch (no change output) and the
/// genuine cashback value otherwise. `amount` is what leaves the wallet
/// for `dst` (the requested amount, or the drained input minus fee in
/// drain mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoutResult {
    pub vout: Vec<TxOut>,
    pub cashback: TSatoshi,
    pub amount: TSatoshi,
}

/// Output of [`Wallet::make_transaction`]: the signed tx plus the
/// satoshi amounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxResult {
    pub tx: Transaction,
    pub cashback: TSatoshi,
    pub amount: TSatoshi,
    pub fee: TSatoshi,
}

/// Build the vout list for a transaction.
///
/// Three branches:
/// - `amount is None` → drain. Single output to `dst` for
///   `in_amount - fee`. No cashback output.
/// - `amount + fee == in_amount` → exact match. Same as drain but
///   `amount` is the requested value; the caller asked for it
///   explicitly so we preserve that as `amount` (not "in_amount - fee").
/// - otherwise → standard send. Two outputs: cashback to `src`,
///   `amount` to `dst`.
pub fn make_vout(
    src: &TAddress,
    dst: &TAddress,
    in_amount: TSatoshi,
    amount: Option<TSatoshi>,
    fee: TSatoshi,
) -> Result<VoutResult, WalletError> {
    if in_amount.get() < fee.get() {
        return Err(WalletError::InputDoesNotCoverFee {
            in_amount: in_amount.get(),
            fee: fee.get(),
        });
    }
    if let Some(amt) = amount {
        if amt.get() + fee.get() > in_amount.get() {
            return Err(WalletError::AmountExceedsInput {
                amount: amt.get(),
                fee: fee.get(),
                in_amount: in_amount.get(),
            });
        }
    }
    let dst_script = make_lock_script_for_address(dst)?;
    let src_script = make_lock_script_for_address(src)?;
    match amount {
        None => {
            let amt = TSatoshi::new(in_amount.get() - fee.get());
            Ok(VoutResult {
                vout: vec![TxOut {
                    amount: amt.get(),
                    script: dst_script,
                }],
                cashback: TSatoshi::ZERO,
                amount: amt,
            })
        }
        Some(amt) if amt.get() + fee.get() == in_amount.get() => Ok(VoutResult {
            vout: vec![TxOut {
                amount: amt.get(),
                script: dst_script,
            }],
            cashback: TSatoshi::ZERO,
            amount: amt,
        }),
        Some(amt) => {
            let cashback = TSatoshi::new(in_amount.get() - amt.get() - fee.get());
            Ok(VoutResult {
                vout: vec![
                    TxOut {
                        amount: cashback.get(),
                        script: src_script,
                    },
                    TxOut {
                        amount: amt.get(),
                        script: dst_script,
                    },
                ],
                cashback,
                amount: amt,
            })
        }
    }
}

// --- TPrivKey -------------------------------------------------------

/// A `(seed, nonce)` → `SigningKey` pair with cached network info and
/// unspent list.
///
/// Since Phase 13 a key also knows which address form it was derived
/// for ([`AddrType`]) and which KDF produced it: for the
/// BIP-39-standard `pbkdf2` branch each `AddrType` is a distinct
/// BIP-32 leaf (`m/44'…` / `m/84'…` / `m/86'…`), so a key derived for
/// one type cannot be re-encoded for another; for the non-BIP-32 KDFs
/// (вариант A, spec ОВ-2) the same key encodes in every type.
#[derive(Clone, Debug)]
pub struct TPrivKey {
    pub nonce: TNonce,
    pub privkey: SigningKey,
    /// Address of this key in its own [`AddrType`] encoding.
    pub address: TAddress,
    /// KDF this key was derived with.
    pub kdf: KdfAlgo,
    /// The address form this key was derived/encoded for.
    pub addr_type: AddrType,
    info: Option<AddressInfo>,
    unspent: Option<Vec<Utxo>>,
}

/// Address of `privkey` in the given encoding.
///
/// Taproot goes through the BIP-86 TapTweak, which fails only when
/// `int(P) + int(t)·G` is the point at infinity — probability ~2^-128
/// for any real curve point, so the error path is a documented
/// invariant `expect` (the kdf.rs precedent), not a reachable branch.
fn address_for_key(privkey: &SigningKey, addr_type: AddrType) -> TAddress {
    let pubkey = privkey_to_pubkey(privkey);
    match addr_type {
        AddrType::Legacy => privkey_to_address(privkey),
        AddrType::Native => pubkey_to_segwit_address(&pubkey),
        AddrType::Taproot => pubkey_to_taproot_address(&pubkey)
            .expect("TapTweak infinity (p ≈ 2^-128) for a valid curve point: documented invariant"),
    }
}

impl TPrivKey {
    /// Construct a `TPrivKey` from a (seed, nonce, passphrase, kdf) —
    /// the v0.1 constructor: the legacy form ([`AddrType::Legacy`],
    /// P2PKH `m/44'…` leaf for `pbkdf2`). SegWit/Taproot wallets use
    /// [`TPrivKey::with_addr_type`].
    pub fn new(
        seed: &TSeed,
        nonce: TNonce,
        passphrase: &TPassphrase,
        kdf: KdfAlgo,
    ) -> Result<Self, WalletError> {
        Self::with_addr_type(seed, nonce, passphrase, kdf, AddrType::Legacy)
    }

    /// Construct a `TPrivKey` for a specific receive-address form.
    ///
    /// For `pbkdf2` (BIP-39-standard) the purpose selects the BIP-32
    /// leaf: `m/44'…` (legacy), `m/84'…` (BIP-84, native) or `m/86'…`
    /// (BIP-86, taproot) — addresses reproducible by external
    /// BIP-84/86 wallets. For the non-BIP-32 KDFs the nonce→secret
    /// mapping is unchanged (вариант A): the same key, encoded in the
    /// requested form; the WIF is identical across all types.
    pub fn with_addr_type(
        seed: &TSeed,
        nonce: TNonce,
        passphrase: &TPassphrase,
        kdf: KdfAlgo,
        addr_type: AddrType,
    ) -> Result<Self, WalletError> {
        if seed.as_str().is_empty() {
            return Err(WalletError::EmptySeed);
        }
        if !matches!(kdf, KdfAlgo::Yubtc) && passphrase.is_empty() {
            // The KDF layer rejects this as `PassphraseRequired`. Check
            // it up front so the error names the wallet-level cause
            // instead of surfacing a generic KdfError string.
            return Err(WalletError::PrivKey(
                "passphrase required for non-yubtc KDF".to_string(),
            ));
        }
        let privkey = seed2privkey_with_purpose(seed, nonce, passphrase, kdf, addr_type.purpose())
            .map_err(|e| WalletError::PrivKey(e.to_string()))?;
        let address = address_for_key(&privkey, addr_type);
        Ok(Self {
            nonce,
            privkey,
            address,
            kdf,
            addr_type,
            info: None,
            unspent: None,
        })
    }

    /// WIF export of the underlying private key. For the non-BIP-32
    /// KDFs (вариант A) this is identical for every [`AddrType`]; for
    /// `pbkdf2` each type has its own leaf and therefore its own WIF.
    pub fn get_privwif(&self) -> String {
        privkey_to_wif(&self.privkey)
    }

    /// Address of this key in its own [`AddrType`] encoding.
    pub fn get_address(&self) -> TAddress {
        self.address.clone()
    }

    /// v0.1 name, kept for call-site compatibility: returns
    /// [`TPrivKey::get_address`] — the P2PKH address for keys created
    /// with [`TPrivKey::new`] / [`AddrType::Legacy`].
    pub fn get_p2pkh_address(&self) -> TAddress {
        self.get_address()
    }

    /// Address of this key in the `addr_type` encoding.
    ///
    /// Allowed in two cases:
    /// - the key's own type (trivially — the cached address);
    /// - a non-`pbkdf2` (вариант A) key, which is the *same* secret
    ///   for every type and therefore re-encodes freely.
    ///
    /// A `pbkdf2` key asked for a *different* type is an error: its
    /// leaves are distinct BIP-32 subtrees, so re-encoding would hand
    /// back an address no external BIP-84/86 wallet would agree with.
    /// Derive the right key with [`TPrivKey::with_addr_type`] instead.
    pub fn address_of(&self, addr_type: AddrType) -> Result<TAddress, WalletError> {
        if self.kdf == KdfAlgo::Pbkdf2 && addr_type != self.addr_type {
            return Err(WalletError::UnsupportedAddress(format!(
                "pbkdf2 keys are purpose-bound: this key addresses {}, not {} \
                 (derive the key via TPrivKey::with_addr_type)",
                self.addr_type.name(),
                addr_type.name(),
            )));
        }
        if addr_type == self.addr_type {
            return Ok(self.address.clone());
        }
        Ok(address_for_key(&self.privkey, addr_type))
    }

    /// Address info (cached). First call queries `backend`
    /// (explicitly injected — see specs/spec.md «Явная передача бэкенда»);
    /// subsequent calls return the cached value.
    pub async fn get_info(
        &mut self,
        backend: &dyn crate::net::NetworkBackend,
    ) -> Result<AddressInfo, WalletError> {
        if self.info.is_none() {
            let info = backend.get_info(&self.address).await?;
            self.info = Some(info);
        }
        Ok(self.info.clone().unwrap_or_default())
    }

    /// Whether the address has never received funds.
    pub async fn is_unused(
        &mut self,
        backend: &dyn crate::net::NetworkBackend,
    ) -> Result<bool, WalletError> {
        let info = self.get_info(backend).await?;
        Ok(info.total_received == 0)
    }

    /// Cached unspent list. First call queries `backend`; subsequent
    /// calls return the cached value.
    pub async fn get_unspent(
        &mut self,
        backend: &dyn crate::net::NetworkBackend,
        confirmations: u32,
    ) -> Result<Vec<Utxo>, WalletError> {
        if self.unspent.is_none() {
            let list = backend.get_unspent(&self.address).await?;
            self.unspent = Some(list);
        }
        let list = self.unspent.clone().unwrap_or_default();
        Ok(list
            .into_iter()
            .filter(|u| u.confirmations >= confirmations)
            .collect())
    }
}

// --- Source / Wallet ------------------------------------------------

/// `(TPrivKey, Vec<Utxo>)` — one address that contributes inputs.
#[derive(Clone)]
pub struct Source {
    pub privkey: TPrivKey,
    pub unspent: Vec<Utxo>,
}

/// Top-level wallet. Holds the seed + passphrase + KDF + the primary
/// `TPrivKey` (and any gap-limit or `--new` siblings scanned at
/// construction).
// No `Debug`: the backend field (`Arc<dyn NetworkBackend>`) is not
// `Debug`, and deriving it would risk printing secret material in
// diagnostics anyway.
pub struct Wallet {
    seed: TSeed,
    passphrase: TPassphrase,
    kdf: KdfAlgo,
    /// Receive-address form of this wallet's keys (spec: affects only
    /// the receiving/cashback encoding, never the scan).
    addr_type: AddrType,
    /// Network backend this wallet talks to (explicitly injected —
    /// see specs/spec.md «Явная передача бэкенда»; no process-global
    /// backend exists).
    backend: std::sync::Arc<dyn crate::net::NetworkBackend>,
    /// All addresses the wallet knows about, in scan order.
    pub privkeys: Vec<TPrivKey>,
}

impl Wallet {
    /// Original seed (kept for re-creation / export diagnostics).
    #[allow(dead_code)]
    pub fn seed(&self) -> &TSeed {
        &self.seed
    }

    /// Passphrase the wallet was opened with (kept for re-creation).
    #[allow(dead_code)]
    pub fn passphrase(&self) -> &TPassphrase {
        &self.passphrase
    }

    /// KDF algorithm the wallet was opened with.
    #[allow(dead_code)]
    pub fn kdf(&self) -> KdfAlgo {
        self.kdf
    }

    /// Receive-address form this wallet was opened with.
    #[allow(dead_code)]
    pub fn addr_type(&self) -> AddrType {
        self.addr_type
    }

    /// Construct a wallet by walking the seed forward to its first
    /// unused address, then appending `new_addresses` more entries.
    /// `backend` is the network backend every scan uses (explicit
    /// injection; the caller resolves it once via
    /// [`crate::net::get_backend`]).
    ///
    /// `addr_type` selects the receive-address form of the wallet's
    /// keys (spec: the type affects only receiving/cashback — the gap
    /// walk itself checks *every* form, so a wallet opened as
    /// [`AddrType::Native`] still sees its legacy P2PKH history).
    pub async fn new(
        seed: TSeed,
        nonce: TNonce,
        new_addresses: usize,
        passphrase: TPassphrase,
        kdf: KdfAlgo,
        addr_type: AddrType,
        backend: std::sync::Arc<dyn crate::net::NetworkBackend>,
    ) -> Result<Self, WalletError> {
        if seed.as_str().is_empty() {
            return Err(WalletError::EmptySeed);
        }
        let mut privkeys: Vec<TPrivKey> = Vec::new();
        let mut current = nonce;
        loop {
            let mut forms = nonce_address_forms(&seed, current, &passphrase, kdf)?;
            if !nonce_is_used(&mut forms, backend.as_ref()).await? {
                break;
            }
            // `nonce_address_forms` always emits every `AddrType` —
            // including the wallet's receive type — so the find cannot
            // miss (documented invariant).
            let pk = forms
                .into_iter()
                .find(|f| f.addr_type == addr_type)
                .expect("nonce_address_forms always includes every AddrType: bug in the form list");
            privkeys.push(pk.privkey);
            current = TNonce::new(current.get() + 1);
        }
        for _ in 0..new_addresses {
            let pk = TPrivKey::with_addr_type(&seed, current, &passphrase, kdf, addr_type)?;
            privkeys.push(pk);
            current = TNonce::new(current.get() + 1);
        }
        Ok(Self {
            seed,
            passphrase,
            kdf,
            addr_type,
            backend,
            privkeys,
        })
    }

    /// The backend this wallet was constructed with.
    pub fn backend(&self) -> &std::sync::Arc<dyn crate::net::NetworkBackend> {
        &self.backend
    }

    /// Construct a wallet from a pre-built set of `TPrivKey`s — used
    /// by the UniFFI surface, which keeps the key derivation sync and
    /// therefore can't afford to scan the gap-limit for the first
    /// unused address.
    ///
    /// `seed`/`passphrase`/`kdf` are stored for parity with
    /// [`Wallet::new`] (export diagnostics, future-proofing) but are
    /// never used to re-derive keys; the supplied `privkeys` are the
    /// source of truth.
    pub fn from_privkeys(
        seed: TSeed,
        passphrase: TPassphrase,
        kdf: KdfAlgo,
        addr_type: AddrType,
        backend: std::sync::Arc<dyn crate::net::NetworkBackend>,
        privkeys: Vec<TPrivKey>,
    ) -> Self {
        Self {
            seed,
            passphrase,
            kdf,
            addr_type,
            backend,
            privkeys,
        }
    }

    /// Build and sign a transaction.
    ///
    /// Every input's signing scheme is derived from its UTXO
    /// `scriptPubKey` shape ([`SigScheme::from_script_pubkey`]): legacy
    /// P2PKH inputs sign as in v0.1, P2WPKH inputs via BIP-143 and
    /// P2TR key-path inputs via BIP-341 + BIP-340 Schnorr
    /// (`aux_rand = 0x00 × 32`). Mixed transactions are allowed. The
    /// fee loop keys its candidates on **vsize** (BIP-141 witness
    /// discount), so witness transactions pay for what they weigh.
    ///
    /// See [`crate::wallet::pick_best_fee_loop_candidate`] for the fee
    /// loop algorithm. When `fee` is non-zero the loop is skipped: the
    /// caller supplied the number, we trust it.
    #[allow(clippy::too_many_arguments)]
    pub async fn make_transaction(
        &self,
        dst: &TAddress,
        amount: Option<TSatoshi>,
        feekb: TSatoshi,
        fee: TSatoshi,
        confirmations: u32,
        sources: Option<Vec<Source>>,
        cashback_addr: Option<TAddress>,
    ) -> Result<TxResult, WalletError> {
        let (vin_sources, src) = self
            .select_inputs(confirmations, sources, cashback_addr)
            .await?;
        let (vin, in_amount, signers, spend) = build_vin(&vin_sources)?;

        if fee.get() > 0 {
            let vout_result = make_vout(&src, dst, TSatoshi::new(in_amount), amount, fee)?;
            let tx = Transaction {
                version: 2,
                vin,
                vout: vout_result.vout,
                locktime: 0,
            };
            let signers_owned: Vec<(SigningKey, [u8; 33])> = signers;
            let stx = tx.sign_segwit(&signers_owned, Some(&spend)).expect(
                "build_vin emits one signer and one SpendInput per input: bug in build_vin",
            );
            return Ok(TxResult {
                tx: stx,
                cashback: vout_result.cashback,
                amount: vout_result.amount,
                fee,
            });
        }

        // Fee loop. Termination is by cycle detection on the tx vsize:
        // each iteration derives a new fee from the previous vsize and
        // the vsize is a pure function of (inputs, fee), so a repeated
        // vsize means the iteration has entered a cycle — no further
        // candidates can appear. There is deliberately NO iteration
        // cap (decision C3): a cap would silently truncate the search
        // for pathological feekb values while cycle detection alone
        // always terminates.
        //
        // The candidate map is keyed on **vsize** (BIP-141 virtual
        // size, witness bytes counted at weight 1/4) instead of the
        // v0.1 stripped byte count. For transactions without witness
        // `vsize == bytes`, so the loop reproduces v0.1 decisions
        // byte-for-byte on legacy wallets.
        let mut candidates: FeeLoopCandidates = std::collections::BTreeMap::new();
        let mut seen_sizes = std::collections::BTreeSet::new();
        let mut current_fee: u64 = 0;
        loop {
            let vout_result = make_vout(
                &src,
                dst,
                TSatoshi::new(in_amount),
                amount,
                TSatoshi::new(current_fee),
            )?;
            let tx = Transaction {
                version: 2,
                vin: vin.clone(),
                vout: vout_result.vout.clone(),
                locktime: 0,
            };
            let stx = tx.sign_segwit(&signers, Some(&spend)).expect(
                "build_vin emits one signer and one SpendInput per input: bug in build_vin",
            );
            let vsize = stx.vsize();
            let new_fee = (vsize as u64) * feekb.get() / 1000;
            tracing::debug!(
                vsize,
                bytes = stx.serialize_wire().len(),
                fee = current_fee,
                next_fee = new_fee,
                "fee loop iteration"
            );
            candidates
                .entry(vsize)
                .or_default()
                .push((current_fee, vout_result, stx));
            if seen_sizes.contains(&vsize) {
                break;
            }
            seen_sizes.insert(vsize);
            current_fee = new_fee;
        }
        let (_, (best_fee, best_vout, best_stx)) =
            pick_best_fee_loop_candidate(&candidates, feekb.get());
        Ok(TxResult {
            tx: best_stx,
            cashback: best_vout.cashback,
            amount: best_vout.amount,
            fee: TSatoshi::new(best_fee),
        })
    }

    async fn select_inputs(
        &self,
        confirmations: u32,
        sources: Option<Vec<Source>>,
        cashback_addr: Option<TAddress>,
    ) -> Result<(Vec<Source>, TAddress), WalletError> {
        if let Some(s) = sources {
            let addr = cashback_addr.ok_or(WalletError::CashbackAddrNotSet)?;
            return Ok((s, addr));
        }
        // Default: use the primary address's UTXOs only, cashback to
        // itself (in the key's own address form).
        let mut pk = self.privkeys.first().ok_or(WalletError::EmptySeed)?.clone();
        let address = pk.get_address();
        let unspent = pk.get_unspent(self.backend.as_ref(), confirmations).await?;
        Ok((
            vec![Source {
                privkey: pk,
                unspent,
            }],
            address,
        ))
    }

    /// Signer role over the whole PSBT (spec «Роли», Signer + ОВ-9):
    /// a stateless wallet has no UTXO→key map, so "own" inputs are
    /// found by a bounded offline walk — for every nonce
    /// `0..PSBT_SIGN_MAX_NONCE` and all three address forms, the
    /// derived `scriptPubKey` is matched against each input's UTXO
    /// field; a match signs ([`PartiallySignedTransaction::sign_input`]).
    ///
    /// Per BIP-174 the Signer only *adds* data and never has to sign
    /// everything: inputs without UTXO data, foreign inputs and inputs
    /// keyed beyond the nonce bound stay unsigned (their indices are
    /// returned so the caller can report them). A pinned-sighash
    /// mismatch ([`PsbtError::UnsupportedSighashType`]) also leaves the
    /// input unsigned (ОВ-8); every other error
    /// ([`PsbtError::UtxoMismatch`], [`PsbtError::UnsupportedInputScript`])
    /// aborts the walk. Everything not ours — including unknown pairs —
    /// is carried through untouched.
    pub fn sign_psbt(
        &self,
        psbt: &mut PartiallySignedTransaction,
    ) -> Result<Vec<usize>, PsbtError> {
        sign_psbt_with(&self.seed, &self.passphrase, self.kdf, psbt)
    }
}

/// Free-function core of [`Wallet::sign_psbt`] — the Signer walk needs
/// only the derivation triple, not the network backend, so library
/// callers (and tests) can run it without constructing a `Wallet`.
///
/// Phase 15: a P2SH input is signed when the derived legacy key's
/// compressed pubkey is *a member of the input's redeem script*
/// (R-MS-4) — membership, not `scriptPubKey` shape. The check lives
/// in [`PartiallySignedTransaction::sign_input`]'s P2SH branch, so the
/// walk itself is unchanged.
///
/// See [`Wallet::sign_psbt`] for the full contract.
pub fn sign_psbt_with(
    seed: &TSeed,
    passphrase: &TPassphrase,
    kdf: KdfAlgo,
    psbt: &mut PartiallySignedTransaction,
) -> Result<Vec<usize>, PsbtError> {
    let n_inputs = psbt.inputs.len();
    let mut signed = vec![false; n_inputs];
    'walk: for nonce in 0..PSBT_SIGN_MAX_NONCE {
        if signed.iter().all(|&s| s) {
            break 'walk;
        }
        for form in AddrType::ALL {
            // The walk derives at construction-validated (seed,
            // passphrase, kdf) triples; KDF failure is impossible for
            // data that produced a wallet — documented invariant.
            let key = TPrivKey::with_addr_type(seed, TNonce::new(nonce), passphrase, kdf, form)
                .expect("walk derivation inputs come from a constructed wallet");
            for (i, is_signed) in signed.iter_mut().enumerate() {
                if *is_signed {
                    continue;
                }
                match psbt.sign_input(i, &key.privkey) {
                    Ok(true) => *is_signed = true,
                    Ok(false) => {}
                    // ОВ-8: an input that demands a different
                    // sighash is simply not signed.
                    Err(PsbtError::UnsupportedSighashType(_)) => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok((0..n_inputs).filter(|&i| !signed[i]).collect())
}

/// `(vin, total_input_sats, signers, spend_context)` — output of
/// [`build_vin`].
///
/// `spend_context` carries one [`SpendInput`] per input (amount +
/// `scriptPubKey`), parallel to `vin`: BIP-143 commits to the signed
/// input's amount, BIP-341 to the amounts and scriptPubKeys of all
/// inputs. Legacy-only transactions never read it, but building it is
/// free and keeps [`Transaction::sign_segwit`] the single signing
/// entry point.
pub type VinBundle = (Vec<TxIn>, u64, Vec<(SigningKey, [u8; 33])>, SpendContext);

/// Build the `vin` list, the `(privkey, pubkey)` signer list and the
/// per-input [`SpendContext`] from a `sources` slice.
///
/// Each UTXO's `scriptPubKey` shape selects both the validation and
/// the signing scheme:
///
/// - 25 bytes P2PKH — the hash160 must equal the source key's;
/// - 22 bytes P2WPKH (`00 14 <20>`) — same hash160 check (the source
///   key is the BIP-84 leaf for `pbkdf2` wallets, the same key for
///   вариант-A KDFs);
/// - 34 bytes P2TR (`51 20 <32>`) — the committed output key must
///   equal the BIP-86 TapTweak of the source key's x-only pubkey;
/// - anything else (including the 23-byte P2SH the wallet never
///   creates for itself) is rejected with
///   [`WalletError::UnsupportedUtxoScript`].
pub fn build_vin(sources: &[Source]) -> Result<VinBundle, WalletError> {
    let mut vin = Vec::new();
    let mut in_amount: u64 = 0;
    let mut signers = Vec::new();
    let mut spend = SpendContext::default();
    for source in sources {
        let pubkey = privkey_to_pubkey(&source.privkey.privkey);
        let pubhash = crate::address::hash160_pubkey(&pubkey);
        for u in &source.unspent {
            in_amount += u.amount;
            // Validate the UTXO script against the source key and
            // record the metadata for the SegWit digests.
            match u.script_pubkey.len() {
                25 | 22 => {
                    // P2PKH and P2WPKH both commit to hash160(compressed
                    // pubkey); the extractors enforce the exact shape.
                    let required = if u.script_pubkey.len() == 25 {
                        extract_p2pkh_hash(&u.script_pubkey)
                            .map_err(|_| WalletError::UnsupportedUtxoScript)?
                    } else {
                        extract_p2wpkh_hash(&u.script_pubkey)
                            .map_err(|_| WalletError::UnsupportedUtxoScript)?
                    };
                    if required != pubhash {
                        return Err(WalletError::UnknownPubkeyRequired {
                            expected: hex::encode(pubhash),
                            actual: hex::encode(required),
                        });
                    }
                }
                34 => {
                    let committed = extract_p2tr_output_key(&u.script_pubkey)
                        .map_err(|_| WalletError::UnsupportedUtxoScript)?;
                    let mut xonly = [0u8; 32];
                    xonly.copy_from_slice(&pubkey[1..33]);
                    let tweaked = crate::address::taproot_output_key(&xonly).expect(
                        "TapTweak infinity (p ≈ 2^-128) for a valid curve point: documented invariant",
                    );
                    if committed != tweaked {
                        return Err(WalletError::UnknownPubkeyRequired {
                            expected: hex::encode(tweaked),
                            actual: hex::encode(committed),
                        });
                    }
                }
                _ => {
                    return Err(WalletError::UnsupportedUtxoScript);
                }
            }
            vin.push(TxIn {
                txhash: u.txid,
                n: u.vout,
                script: u.script_pubkey.clone(),
                sequence: SEQUENCE_RBF_SIGNALED,
                // sign_segwit fills the witness stack per input scheme.
                witness: Vec::new(),
            });
            spend.inputs.push(SpendInput {
                amount: u.amount,
                script_pubkey: u.script_pubkey.clone(),
            });
            signers.push((source.privkey.privkey.clone(), pubkey));
        }
    }
    Ok((vin, in_amount, signers, spend))
}

// --- PSBT Signer (Phase 14, BIP-174, ОВ-9) ---------------------------

/// `scriptPubKey` of `privkey` in the given address form — the offline
/// derivation reused by the Signer walk (companion of
/// [`Wallet::sign_psbt`]). Taproot goes through the BIP-86 TapTweak;
/// the infinity outcome is a documented-invariant `expect` (same
/// precedent as [`TPrivKey::with_addr_type`]).
pub fn script_pubkey_for_key(privkey: &SigningKey, form: AddrType) -> Vec<u8> {
    let pubkey = privkey_to_pubkey(privkey);
    match form {
        AddrType::Legacy => make_p2pkh_lock_script(&crate::address::hash160_pubkey(&pubkey)),
        AddrType::Native => {
            make_p2wpkh_lock_script(&crate::address::hash160_pubkey(&pubkey)).to_vec()
        }
        AddrType::Taproot => {
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&pubkey[1..33]);
            let output = crate::address::taproot_output_key(&xonly).expect(
                "TapTweak infinity (p ≈ 2^-128) for a valid curve point: documented invariant",
            );
            make_p2tr_lock_script(&output).to_vec()
        }
    }
}

/// Offline derivation helper (spec «Rust API surface», wallet.rs): the
/// `scriptPubKey` of `(nonce, form)` under `(seed, passphrase, kdf)`.
///
/// This is the Signer walk's lookup primitive — like the multi-form
/// scan, but purely offline: derivation only, no network.
pub fn derive_script(
    seed: &TSeed,
    nonce: TNonce,
    passphrase: &TPassphrase,
    kdf: KdfAlgo,
    form: AddrType,
) -> Result<Vec<u8>, WalletError> {
    let key = TPrivKey::with_addr_type(seed, nonce, passphrase, kdf, form)?;
    Ok(script_pubkey_for_key(&key.privkey, form))
}

/// One fee-loop iteration: the assumed fee, the matching vout layout,
/// and the signed transaction at that fee.
pub type FeeLoopEntry = (u64, VoutResult, Transaction);

/// Map of `tx_vsize -> iterations` produced by the fee loop.
///
/// The key is the **vsize** (BIP-141 virtual size) of the signed
/// transaction, not the v0.1 stripped byte count: witness bytes weigh
/// 1/4, so candidate sizes for witness transactions shrink and the
/// fee formulas (`vsize * feekb / 1000`) keep their numeric shape.
/// For transactions without witness `vsize == bytes` — v0.1 fee
/// decisions reproduce byte-for-byte.
pub type FeeLoopCandidates = std::collections::BTreeMap<usize, Vec<FeeLoopEntry>>;

/// Pick the best iteration from the vsize-keyed fee-loop candidate
/// map.
///
/// Mirrors `_pick_best_fee_loop_candidate` from `yubtc-python` (with
/// the Phase 13 change that the size unit is vbytes). Prefer the
/// smallest vsize whose `fee` covers the rate; ties broken on smaller
/// absolute fee. Fallback: smallest vsize we ever produced when no
/// iteration pays the rate.
///
/// Rule 1 (validity): `fee >= vsize * feekb / 1000` AND
/// `fee >= vsize * DEFAULT_MIN_RELAY_TX_FEE / 1000` — the relay floor
/// from `bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE` (1000 sat/kvB,
/// Bitcoin Core `policy/policy.h`). A candidate below the relay floor
/// is dropped even when its vsize is the smallest: such a tx would not
/// be accepted into any mempool.
///
/// Rule 2 (preference): smallest vsize; tie-break — smallest fee for
/// the same vsize (less overpay at the same feerate).
///
/// Fallback: when no candidate satisfies rule 1 (pathological
/// `feekb`), the smallest vsize ever produced wins — "pays some fee"
/// still beats "relay rejected", and the tx remains structurally
/// valid.
///
/// Contract: `candidates` must be non-empty (the fee loop always
/// records the fee=0 iteration before any break).
pub fn pick_best_fee_loop_candidate(
    candidates: &FeeLoopCandidates,
    feekb: u64,
) -> (usize, FeeLoopEntry) {
    let relay_per_kb = u64::from(bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE);
    let mut best: Option<(usize, FeeLoopEntry)> = None;
    for (size, entries) in candidates {
        let needed = (size * feekb as usize) / 1000;
        let relay_floor = (size * relay_per_kb as usize) / 1000;
        for entry in entries {
            let fee = entry.0;
            if fee < needed as u64 || fee < relay_floor as u64 {
                continue;
            }
            let candidate = (*size, entry.clone());
            let dominated = match &best {
                None => false,
                Some((best_size, best_entry)) => {
                    // Iteration is ascending by size (BTreeMap), so a
                    // current entry is never smaller than the best:
                    // when the first arm is false the sizes are equal
                    // and the tie-break is the absolute fee.
                    *size > *best_size || fee >= best_entry.0
                }
            };
            if !dominated {
                best = Some(candidate);
            }
        }
    }
    if let Some((size, entry)) = best {
        return (size, entry);
    }
    let smallest = candidates
        .keys()
        .min()
        .copied()
        .expect("candidates must be non-empty");
    let entry = candidates[&smallest][0].clone();
    (smallest, entry)
}

/// Dust-warning helper. Returns true when the cashback at `amount`
/// satoshi for the given lock script falls below the protocol dust
/// threshold for that script type (Bitcoin Core `GetDustThreshold`
/// with the wallet's spending-input costs: witness-discounted inputs
/// for P2WPKH/P2WSH/P2TR — see `fwd.rs` for the frozen constants).
pub fn is_dust(amount: u64, script: &[u8]) -> bool {
    match script.len() {
        25 => amount < DUST_THRESHOLD_P2PKH,
        23 => amount < DUST_THRESHOLD_P2SH,
        22 => amount < DUST_THRESHOLD_P2WPKH,
        // Bitwise `|` (not `||`) so both shape arms stay measurable:
        // v0/32 P2WSH (330 — v0.3) vs v1/32 P2TR (330).
        34 => {
            let is_p2wsh = script[0] == 0x00;
            if is_p2wsh {
                amount < DUST_THRESHOLD_P2WSH
            } else {
                amount < DUST_THRESHOLD_P2TR
            }
        }
        _ => false,
    }
}

/// Minimum relay fee floor (sat/kvB) — Bitcoin Core's
/// `DEFAULT_MIN_RELAY_TX_FEE` taken from the `bitcoin` crate, not
/// duplicated in `fwd.rs` (decision C2). Candidates below
/// `size * minimal_fee() / 1000` are dropped by the fee loop.
pub const fn minimal_fee() -> u64 {
    bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE as u64
}

/// Default confirmations for `balance -c` and `send -c`.
pub const fn default_confirmations() -> u32 {
    DEFAULT_CONFIRMATIONS
}

// --- Scan helpers ----------------------------------------------------

/// One queryable address form at a nonce: the type, the key that
/// spends that form, and the address to ask the backend about.
///
/// For the BIP-39-standard `pbkdf2` KDF each form carries a *distinct*
/// key (the BIP-44/84/86 leaves); for the non-BIP-32 KDFs (вариант A,
/// spec ОВ-2) all three forms share the same key, re-encoded.
#[derive(Clone, Debug)]
pub struct AddressForm {
    pub addr_type: AddrType,
    pub privkey: TPrivKey,
    pub address: TAddress,
}

/// Every address form the wallet can own at `nonce`, in canonical
/// scan order (P2PKH → P2WPKH → P2TR).
///
/// - `pbkdf2`: three distinct keys, derived at `m/44'…`, `m/84'…`
///   (BIP-84) and `m/86'…` (BIP-86);
/// - `yubtc` / `argon2id` / `scrypt` (вариант A): one key, encoded
///   three ways.
///
/// P2SH is deliberately absent — the wallet never creates P2SH for
/// itself (it only ever *receives* to P2SH via external request).
pub fn nonce_address_forms(
    seed: &TSeed,
    nonce: TNonce,
    passphrase: &TPassphrase,
    kdf: KdfAlgo,
) -> Result<Vec<AddressForm>, WalletError> {
    if kdf == KdfAlgo::Pbkdf2 {
        // BIP-39-standard: each purpose is its own BIP-32 subtree.
        let mut forms = Vec::with_capacity(AddrType::ALL.len());
        for addr_type in AddrType::ALL {
            let pk = TPrivKey::with_addr_type(seed, nonce, passphrase, kdf, addr_type)?;
            let address = pk.get_address();
            forms.push(AddressForm {
                addr_type,
                privkey: pk,
                address,
            });
        }
        Ok(forms)
    } else {
        // Вариант A (spec ОВ-2): one secret, three encodings. The
        // cross-type re-encoding cannot fail for a non-pbkdf2 key —
        // the only error `address_of` can produce is the pbkdf2
        // purpose guard (documented invariant).
        //
        // Each form gets its own key view whose `address` field is
        // the form's address: the cached network methods
        // (`get_info`/`get_unspent`) always query the key's own
        // `address`, so a shared view would re-query the legacy
        // address three times instead of the three forms.
        let key = TPrivKey::with_addr_type(seed, nonce, passphrase, kdf, AddrType::Legacy)?;
        let mut forms = Vec::with_capacity(AddrType::ALL.len());
        for addr_type in AddrType::ALL {
            let address = key
                .address_of(addr_type)
                .expect("variant-A keys encode in every AddrType: no pbkdf2 purpose guard here");
            let mut form_key = key.clone();
            form_key.address = address.clone();
            form_key.addr_type = addr_type;
            forms.push(AddressForm {
                addr_type,
                privkey: form_key,
                address,
            });
        }
        Ok(forms)
    }
}

/// Whether *any* form of the nonce has ever received funds (spec:
/// a nonce is "used" when at least one form has `n_tx > 0` or a
/// UTXO — `total_received > 0` is the v0.1 `is_unused` sentinel,
/// kept bit-for-bit).
async fn nonce_is_used(
    forms: &mut [AddressForm],
    backend: &dyn crate::net::NetworkBackend,
) -> Result<bool, WalletError> {
    for form in forms.iter_mut() {
        let info = form.privkey.get_info(backend).await?;
        if info.total_received > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Walk forward from nonce 0 collecting every form's UTXOs.
///
/// Mirrors Python's `_scan_inputs` generalised to address forms
/// (specs/spec.md «Scan и cashback при нескольких формах», ОВ-4):
///
/// - On each nonce **all three forms** (P2PKH + P2WPKH + P2TR) are
///   queried; the walk stops at the first nonce where no form was
///   ever used (gap rule generalised to nonces).
/// - When `target` is `Some(t)`, stops as soon as `cumulative >= t`
///   (early termination for one-shot CLI sends).
/// - Returns `(sources, cashback_addr)`:
///   - a source per `(nonce, form)` that contributed UTXOs, with the
///     key that spends that form;
///   - `cashback_addr` is the gap-limit unused nonce's address in
///     the wallet's `addr_type` encoding (gap stop), or the address
///     of the **last contributing `(nonce, form)`** (target met) —
///     the v0.1 "last sourced address" rule generalised to forms.
/// - `confirmations` is currently accepted for API stability but
///   not applied at the scan layer — the scan returns all UTXOs it
///   finds at contributing addresses and lets the caller re-filter
///   the cached result. The FFI surface (see
///   `crate::uniffi_api::flatten_cache`) applies the confirmations
///   view at flatten time so changing the threshold doesn't
///   invalidate the cache.
///
/// Used by [`Wallet::scan_inputs_until`] (lazy, CLI/Python parity)
/// and [`Wallet::scan_all`] (eager, Android UI).
pub async fn scan_inputs_until(
    seed: &TSeed,
    passphrase: &TPassphrase,
    kdf: KdfAlgo,
    addr_type: AddrType,
    backend: &dyn crate::net::NetworkBackend,
    target: Option<TSatoshi>,
    _confirmations: u32,
) -> Result<(Vec<Source>, TAddress), WalletError> {
    let mut sources: Vec<Source> = Vec::new();
    let mut total: u64 = 0;
    let mut nonce: u32 = 0;
    let cashback_addr: TAddress;
    loop {
        let mut forms = nonce_address_forms(seed, TNonce::new(nonce), passphrase, kdf)?;
        // Usage check across every form (one `get_info` each —
        // K·R·T ≤ 3R round-trips per nonce, spec ОВ-4).
        if !nonce_is_used(&mut forms, backend).await? {
            // True gap: no form of this nonce ever received anything.
            // Cashback goes to the receive-type address of the gap
            // nonce.
            let gap = forms
                .into_iter()
                .find(|f| f.addr_type == addr_type)
                .expect("nonce_address_forms always includes every AddrType");
            cashback_addr = gap.address;
            break;
        }
        // Fetch the UTXOs of every used form (an unused form never
        // received anything, so it cannot hold UTXOs — the
        // `get_unspent` round-trip is skipped for it).
        let mut contributed = false;
        let mut last_addr: Option<TAddress> = None;
        for mut form in forms {
            let info = form.privkey.get_info(backend).await?;
            if info.total_received == 0 {
                continue;
            }
            // Raw UTXOs — the confirmations filter is applied at the
            // FFI flatten layer so the cache is re-filterable.
            let unspent = form.privkey.get_unspent(backend, 0).await?;
            if unspent.is_empty() {
                // Used form, but everything was spent.
                continue;
            }
            let amount: u64 = unspent.iter().map(|u| u.amount).sum();
            total += amount;
            sources.push(Source {
                privkey: form.privkey,
                unspent,
            });
            contributed = true;
            last_addr = Some(form.address);
        }
        if contributed {
            if let Some(t) = target {
                if total >= t.get() {
                    cashback_addr = last_addr
                        .expect("contributed is true only after a push, which sets last_addr");
                    break;
                }
            }
        }
        nonce += 1;
    }
    Ok((sources, cashback_addr))
}

/// Eager scan to gap-limit. Same as
/// [`scan_inputs_until`] with `target = None`. Convenience for
/// callers that need every contributing UTXO (Android UI picker).
pub async fn scan_all(
    seed: &TSeed,
    passphrase: &TPassphrase,
    kdf: KdfAlgo,
    addr_type: AddrType,
    backend: &dyn crate::net::NetworkBackend,
    confirmations: u32,
) -> Result<(Vec<Source>, TAddress), WalletError> {
    scan_inputs_until(
        seed,
        passphrase,
        kdf,
        addr_type,
        backend,
        None,
        confirmations,
    )
    .await
}

// --- Multi-sig --------------------------------------------------------

/// The quorum address form (specs/spec.md «Multi-sig»): the same
/// canonical redeem script addressed either
/// as P2SH (`3…`, hash160 commitment, legacy spend) or as native
/// P2WSH (`bc1q…`, SHA-256 commitment, witness spend). No default
/// exists — every surface (CLI `--form`, FFI `MsFormName`, Python
/// `form=`) passes the choice explicitly; the CLI flag *defaults* to
/// `P2sh` at the argument-parser layer only (documented spec
/// decision: R-MS-1 is about N/M, the legacy form is the conservative
/// quorum form).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsForm {
    /// P2SH `3…`: base58check `0x05 ‖ hash160(redeem)`,
    /// legacy `scriptSig` spend.
    P2sh,
    /// Native P2WSH `bc1q…`: bech32 v0 with the 32-byte
    /// `SHA256(redeem)` program, BIP-141 witness spend.
    P2wsh,
    /// P2TR script-path `bc1p…` (specs/spec.md «Multi-sig»,
    /// форма P2TR script-path): bech32m v1 with the 32-byte tweaked
    /// NUMS output key program. The quorum "redeem" is a **different
    /// script** than the p2sh/p2wsh forms — the canonical tapscript
    /// CHECKSIGADD idiom (R-MS-7) over x-only keys (R-MS-10), keyed
    /// by the single-leaf NUMS tree (R-MS-8).
    P2tr,
}

impl MsForm {
    /// Canonical lowercase name — the spelling of the CLI `--form`
    /// value and the Python mirror's `form` kwarg.
    pub fn name(self) -> &'static str {
        match self {
            MsForm::P2sh => "p2sh",
            MsForm::P2wsh => "p2wsh",
            MsForm::P2tr => "p2tr",
        }
    }

    /// Parse the canonical name (the CLI flag's value parser).
    pub fn parse(s: &str) -> Option<MsForm> {
        match s {
            "p2sh" => Some(MsForm::P2sh),
            "p2wsh" => Some(MsForm::P2wsh),
            "p2tr" => Some(MsForm::P2tr),
            _ => None,
        }
    }
}

/// Errors of the multisig quorum surface (specs/spec.md «Multi-sig»
/// → «Валидация (сводно)»). Mapped into `YubtcError` at
/// the FFI boundary exactly like `TransactionError`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MsError {
    /// The quorum is outside the spendable envelope (R-MS-2):
    /// `1 ≤ M ≤ N ≤` [`MS_MAX_PUBKEYS`] is violated. The 15 bound is
    /// the 520-byte `MAX_SCRIPT_ELEMENT_SIZE` push limit, not the
    /// consensus 20-key cap — an N = 16 redeem script (548 bytes)
    /// could not even be pushed into a `scriptSig`.
    #[error("quorum out of bounds: need 1 ≤ M ≤ N ≤ {MS_MAX_PUBKEYS}")]
    QuorumBounds,

    /// The number of distinct keys does not equal N (spec: «ровно N
    /// различных, иначе MsError::KeyCountMismatch»).
    #[error("key count mismatch: expected exactly {0} keys, got {1}")]
    KeyCountMismatch(usize, usize),

    /// A duplicate key in the quorum (R-MS-3): one key would have to
    /// supply two signatures — the quorum is degenerate.
    #[error("duplicate key in the quorum")]
    DuplicateKey,

    /// The supplied WIF does not match the own key derived at the
    /// given nonce (R-MS-6): yubtc only accepts a WIF for the *own*
    /// key and only when its secret is exactly the derived one —
    /// foreign secrets are never accepted or stored (ОВ-11).
    #[error("WIF does not match the key derived at this nonce")]
    ForeignWif,

    /// The own key is not part of the quorum (`ms send` without
    /// `-n`/WIF, or a quorum the wallet cannot co-sign): yubtc builds
    /// spends only of quorums it participates in.
    #[error("own key is not a participant of this quorum")]
    NotAParticipant,

    /// A quorum key argument has the wrong hex encoding for the form
    /// (v0.3, R-MS-10): p2sh/p2wsh take 66-hex compressed keys
    /// (`02…`/`03…`), p2tr takes 64-hex x-only keys — mixing the
    /// encodings in one call is refused (BIP-340 verification is
    /// x-only, and sorting the compressed encodings would give a
    /// different script order than sorting the x-only bytes).
    #[error("key encoding does not match the form: p2sh/p2wsh need 66-hex compressed keys, p2tr needs 64-hex x-only keys")]
    InvalidKeyEncoding,
}

/// Error of the `ms send` Creator orchestration: quorum validation,
/// wallet/network plumbing, and PSBT-role errors all surface here.
#[derive(Debug, thiserror::Error)]
pub enum MsSendError {
    /// Quorum validation (R-MS-1…R-MS-6).
    #[error(transparent)]
    Ms(#[from] MsError),

    /// Derivation, UTXO handling, make_vout arithmetic, network.
    #[error(transparent)]
    Wallet(#[from] WalletError),

    /// PSBT Creator/Signer construction.
    #[error("PSBT error: {0}")]
    Psbt(#[from] PsbtError),

    /// Network backend failure (UTXO fetch, raw prev-tx fetch).
    #[error("network error: {0}")]
    Network(#[from] crate::net::NetError),
}

/// Upper bound of one ECDSA signature inside a multisig `scriptSig`:
/// 72-byte maximal low-S DER + 1 sighash byte. Used by the fee loop to
/// size a not-yet-complete quorum spend (other signers' signatures
/// cannot be known at creation time; the estimate is the worst case,
/// so the fee never underpays because of a shorter DER).
pub const MS_SIG_SIZE_ESTIMATE: usize = 73;

/// Validate the quorum shape and derive the fixed quorum address +
/// canonical redeem script in the `form` encoding (specs/spec.md
/// «Multi-sig» → «Rust API surface», `wallet.rs`; `form` covers the
/// P2SH, P2WSH and P2TR-script-path forms).
///
/// `n` is the total key count, `m` the signature threshold, `keys`
/// the full quorum key set (own key already included by the caller —
/// derive it with [`ms_own_pubkey`] and append it before calling).
/// `form` selects the address encoding and — for p2tr — the script
/// itself:
///
/// - [`MsForm::P2sh`] — `base58check(0x05 ‖ hash160(redeem))` (`3…`,
///   Phase 15, ОВ-13);
/// - [`MsForm::P2wsh`] — bech32 v0 with the 32-byte `SHA256(redeem)`
///   program (`bc1q…`, v0.3);
/// - [`MsForm::P2tr`] — bech32m v1 with the tweaked NUMS output key
///   of the canonical **tapscript** (`bc1p…`, v0.3): the returned
///   "redeem" is the R-MS-7 CHECKSIGADD idiom over the x-only
///   projections (bytes `1..33`) of the compressed keys — different
///   bytes than the p2sh/p2wsh redeem for the same quorum.
///
/// Checks (in order): distinct-key count equals `n`
/// ([`MsError::KeyCountMismatch`]), `1 ≤ m ≤ n ≤` [`MS_MAX_PUBKEYS`]
/// ([`MsError::QuorumBounds`]), no duplicate keys
/// ([`MsError::DuplicateKey`]) — then the script is assembled with
/// the form's BIP-67 sort (R-MS-4: compressed bytes for
/// p2sh/p2wsh, x-only bytes for p2tr, R-MS-10). The address is fixed
/// by the `(N, M, keys)` tuple in every form (ОВ-13: no scan/gap
/// walk).
pub fn ms_create_address(
    n: usize,
    m: usize,
    keys: &[[u8; 33]],
    form: MsForm,
) -> Result<(TAddress, Vec<u8>), MsError> {
    if keys.len() != n {
        return Err(MsError::KeyCountMismatch(n, keys.len()));
    }
    if m == 0 || m > n || n > MS_MAX_PUBKEYS as usize {
        return Err(MsError::QuorumBounds);
    }
    let mut sorted = keys.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(MsError::DuplicateKey);
    }
    match form {
        MsForm::P2tr => {
            // The tapscript carries the x-only projections of the
            // compressed keys, sorted by those 32 bytes (R-MS-10) —
            // the script bytes differ from the p2sh/p2wsh redeem.
            let xonly: Vec<[u8; 32]> = sorted
                .iter()
                .map(|k| k[1..33].try_into().expect("33-byte key by type"))
                .collect();
            let script = crate::script::make_multisig_tapscript(m, &xonly)
                .expect("bounds and duplicates validated above; the builder cannot fail");
            let addr = crate::address::redeem_to_tapscript_address(&script)
                .expect("NUMS lift and tweak are total for the canonical internal key");
            Ok((addr, script))
        }
        MsForm::P2sh | MsForm::P2wsh => {
            let redeem = crate::script::make_multisig_redeem_script(m, &sorted).expect(
                "bounds and duplicates validated above; 33-byte keys by type — the builder cannot fail",
            );
            // The outer arm excludes P2tr, so this is exactly the
            // p2sh/p2wsh address encoding choice.
            let addr = if form == MsForm::P2sh {
                redeem_to_p2sh_address(&redeem)
            } else {
                redeem_to_p2wsh_address(&redeem)
            };
            Ok((addr, redeem))
        }
    }
}

/// The lock script paying to the quorum address of `redeem` in the
/// `form` encoding — the shared Creator-side derivation of
/// [`ms_build_psbt_from_selected`] and the FFI projection
/// (`uniffi_api::WalletHandle::ms_build_psbt`): one code path, so the
/// two surfaces cannot drift. For [`MsForm::P2tr`] the "redeem" is a
/// canonical tapscript and the lock script commits to its tweaked
/// NUMS output key.
pub fn ms_quorum_lock_script(redeem: &[u8], form: MsForm) -> Vec<u8> {
    match form {
        MsForm::P2sh => make_p2sh_lock_script(&crate::address::hash160_script(redeem)),
        MsForm::P2wsh => {
            crate::script::make_p2wsh_lock_script(&crate::address::sha256_script(redeem)).to_vec()
        }
        MsForm::P2tr => {
            let leaf_hash = crate::script::tapscript_leaf_hash(redeem);
            let output_key =
                crate::address::tapscript_output_key(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)
                    .expect("NUMS lift and tweak are total for the canonical internal key");
            crate::script::make_p2tr_lock_script(&output_key).to_vec()
        }
    }
}

/// Parse cosigner key hex arguments per the form's encoding (R-MS-10):
/// p2sh/p2wsh take 66-hex compressed keys (`02…`/`03…` prefix),
/// p2tr takes 64-hex x-only keys (carried internally as a
/// `0x02`-prefixed 33-byte key — only the x-only bytes ever enter the
/// tapscript, and BIP-340 signing normalizes the parity). Anything
/// else — wrong length, non-hex, wrong prefix — is
/// [`MsError::InvalidKeyEncoding`]. The FFI/CLI layer (stage 2) calls
/// this before [`ms_create_address`]; the core keeps byte arrays.
pub fn parse_ms_keys(keys: &[String], form: MsForm) -> Result<Vec<[u8; 33]>, MsError> {
    keys.iter()
        .map(|hex_key| match form {
            MsForm::P2sh | MsForm::P2wsh => {
                let raw = hex::decode(hex_key)
                    .ok()
                    .filter(|raw| raw.len() == 33)
                    .ok_or(MsError::InvalidKeyEncoding)?;
                if raw[0] == 0x02 || raw[0] == 0x03 {
                    Ok(raw.try_into().expect("33-byte length checked above"))
                } else {
                    Err(MsError::InvalidKeyEncoding)
                }
            }
            MsForm::P2tr => {
                let raw = hex::decode(hex_key)
                    .ok()
                    .filter(|raw| raw.len() == 32)
                    .ok_or(MsError::InvalidKeyEncoding)?;
                let mut key = [0u8; 33];
                key[0] = 0x02;
                key[1..].copy_from_slice(&raw);
                Ok(key)
            }
        })
        .collect()
}

/// The own key at `nonce` in its legacy form (R-MS-6, ОВ-10): the same
/// derivation as `dumpprivkey -n X` — the P2PKH leaf for `pbkdf2`
/// (`m/44'/0'/0'/0/n`), the single shared key for the non-BIP-32 KDFs
/// (вариант А, ОВ-2). The multisig membership test and every own
/// signature use exactly this key.
pub fn ms_own_privkey(
    seed: &TSeed,
    nonce: TNonce,
    passphrase: &TPassphrase,
    kdf: KdfAlgo,
) -> Result<SigningKey, WalletError> {
    if seed.as_str().is_empty() {
        return Err(WalletError::EmptySeed);
    }
    if !matches!(kdf, KdfAlgo::Yubtc) && passphrase.is_empty() {
        return Err(WalletError::PrivKey(
            "passphrase required for non-yubtc KDF".to_string(),
        ));
    }
    seed2privkey_with_purpose(seed, nonce, passphrase, kdf, PURPOSE_LEGACY)
        .map_err(|e| WalletError::PrivKey(e.to_string()))
}

/// Compressed pubkey of [`ms_own_privkey`] — the byte string that
/// must appear in the redeem script for the wallet to co-sign.
pub fn ms_own_pubkey(
    seed: &TSeed,
    nonce: TNonce,
    passphrase: &TPassphrase,
    kdf: KdfAlgo,
) -> Result<[u8; 33], WalletError> {
    Ok(privkey_to_pubkey(&ms_own_privkey(
        seed, nonce, passphrase, kdf,
    )?))
}

/// R-MS-6 / ОВ-11 primitive for the CLI `--key <WIF>` sugar (stage 2):
/// accept the WIF only when its secret is byte-identical to the
/// derived own key. Takes the *already derived* own key (from
/// [`ms_own_privkey`]); any malformed WIF or any mismatch — including
/// every foreign WIF — is [`MsError::ForeignWif`]. Returns the own
/// compressed pubkey (the quorum member).
pub fn ms_wif_own_key(derived: &SigningKey, wif: &str) -> Result<[u8; 33], MsError> {
    let secret = wif_to_secret(wif).map_err(|_| MsError::ForeignWif)?;
    if secret != derived.to_bytes().as_slice() {
        return Err(MsError::ForeignWif);
    }
    Ok(privkey_to_pubkey(derived))
}

/// Greedy smallest-prefix input selection over the UTXOs of the
/// quorum address (ОВ-12/ОВ-13): walk in the network's natural order
/// and take the smallest prefix whose sum reaches `target` — the same
/// principle as the CLI `default_selection`, applied to a single
/// address (nonce-walk grouping is meaningless for a fixed quorum
/// address). `target = None` selects everything (drain).
pub fn ms_select_utxos(utxos: &[Utxo], target: Option<TSatoshi>) -> Vec<Utxo> {
    let mut out = Vec::new();
    let mut total: u64 = 0;
    for u in utxos {
        out.push(u.clone());
        total = total.saturating_add(u.amount);
        if target.is_some_and(|t| total >= t.get()) {
            break;
        }
    }
    out
}

/// Result of [`ms_create_psbt`]: the base64 PSBT (own partial
/// signatures included) plus the fee-loop outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsPsbtOutcome {
    /// The PSBT in its base64 transport form (BIP-174).
    pub psbt_b64: String,
    /// The fee the fee loop settled on (or the explicit fee).
    pub fee: TSatoshi,
    /// The cashback sent back to the quorum address (0 in drain).
    pub cashback: TSatoshi,
    /// The amount that leaves the quorum for the destination.
    pub amount: TSatoshi,
}

/// Creator orchestration of `ms send` (ОВ-12): a thin composition of
/// the existing library stages, no new cryptography or serialization —
///
/// 1. derive the own legacy-form key at `own_nonce` (R-MS-6) and
///    validate the quorum (`n`, `m`, cosigner `keys` + own key);
/// 2. fetch the UTXOs of the fixed quorum address with one
///    `get_unspent` call (ОВ-13 — no nonce walk) and filter by
///    `confirmations`;
/// 3. greedily select the smallest UTXO prefix covering
///    `amount + fee` ([`ms_select_utxos`]);
/// 4. hand the selection to [`ms_build_psbt_from_selected`] — the
///    shared Creator core (fee loop → `create` → own signatures).
#[allow(clippy::too_many_arguments)]
pub async fn ms_create_psbt(
    seed: &TSeed,
    passphrase: &TPassphrase,
    kdf: KdfAlgo,
    backend: &dyn crate::net::NetworkBackend,
    dst: &TAddress,
    amount: TSatoshi,
    n: usize,
    m: usize,
    keys: &[[u8; 33]],
    own_nonce: Option<TNonce>,
    confirmations: u32,
    feekb: TSatoshi,
    fee: TSatoshi,
    form: MsForm,
) -> Result<MsPsbtOutcome, MsSendError> {
    let nonce = own_nonce.ok_or(MsError::NotAParticipant)?;
    let own_privkey = ms_own_privkey(seed, nonce, passphrase, kdf)?;
    let own_pubkey = privkey_to_pubkey(&own_privkey);
    let mut all_keys = keys.to_vec();
    all_keys.push(own_pubkey);
    let (quorum_addr, redeem) = ms_create_address(n, m, &all_keys, form)?;

    // One UTXO query for the fixed quorum address (ОВ-13).
    let unspent = backend.get_unspent(&quorum_addr).await?;
    let affordable: Vec<Utxo> = unspent
        .into_iter()
        .filter(|u| u.confirmations >= confirmations)
        .collect();
    let target = TSatoshi::new(amount.get().saturating_add(fee.get()));
    let selected = ms_select_utxos(&affordable, Some(target));

    ms_build_psbt_from_selected(
        &own_privkey,
        dst,
        amount,
        m,
        &redeem,
        &selected,
        backend,
        feekb,
        fee,
        form,
    )
    .await
}

/// Creator core of `ms send` (ОВ-12): build and sign the PSBT for an
/// **explicit** UTXO selection at the quorum address.
///
/// Shared by [`ms_create_psbt`] (greedy smallest-prefix selection over
/// a fresh `get_unspent`) and the FFI projection
/// `uniffi_api::WalletHandle::ms_build_psbt` (user-picked UTXO subset,
/// решение #12 Coin Control) — one code path, so the two surfaces
/// cannot drift. Steps (identical to `ms_create_psbt` from the fee
/// loop on):
///
/// 1. run the vsize-keyed fee loop ([`pick_best_fee_loop_candidate`])
///    with the final spend *sized* (never signed), per `form`:
///    `P2sh` — each input carries `1 + m·(1 +
///    [`MS_SIG_SIZE_ESTIMATE`]) + pushlen(redeem)` bytes of scriptSig;
///    `P2wsh` — empty scriptSig and a sized witness stack
///    (`[‖, sig×M, redeem]`, [`MS_SIG_SIZE_ESTIMATE`] per signature);
/// 2. build the PSBT via [`PartiallySignedTransaction::create`] —
///    `P2sh`: every input gets `NON_WITNESS_UTXO` (fetched with one
///    `raw_transaction` per selected UTXO) plus `REDEEM_SCRIPT`;
///    `P2wsh`: every input gets `WITNESS_UTXO` + `WITNESS_SCRIPT`
///    (no prev-tx fetch — BIP-143 commits the amount);
/// 3. add the own partial signatures (every input of the quorum
///    spend);
/// 4. emit base64. Cashback goes to the **quorum address** (shared
///    funds must not drift into single-key control) — in the form's
///    encoding (`3…` vs `bc1q…`).
///
/// The caller has already validated the quorum and derived the own
/// key: `redeem` must be the canonical redeem script of the quorum
/// (`ms_create_address` output) and `selected` must sit at its
/// `form`-encoded address — the FFI projection re-derives both from
/// the same `(n, m, keys)` tuple before calling.
#[allow(clippy::too_many_arguments)]
pub async fn ms_build_psbt_from_selected(
    own_privkey: &SigningKey,
    dst: &TAddress,
    amount: TSatoshi,
    m: usize,
    redeem: &[u8],
    selected: &[Utxo],
    backend: &dyn crate::net::NetworkBackend,
    feekb: TSatoshi,
    fee: TSatoshi,
    form: MsForm,
) -> Result<MsPsbtOutcome, MsSendError> {
    let quorum_addr = match form {
        MsForm::P2sh => redeem_to_p2sh_address(redeem),
        MsForm::P2wsh => redeem_to_p2wsh_address(redeem),
        MsForm::P2tr => crate::address::redeem_to_tapscript_address(redeem)
            .expect("NUMS lift and tweak are total for the canonical internal key"),
    };
    let quorum_script = ms_quorum_lock_script(redeem, form);
    let in_amount: u64 = selected.iter().map(|u| u.amount).sum();

    // P2SH form: the final scriptSig size per input (R-MS-4/5
    // layout, worst-case signature lengths): dummy byte + M pushes +
    // pushed redeem.
    let script_sig_len = 1 + m * (1 + MS_SIG_SIZE_ESTIMATE) + push_data_len(redeem.len());
    // P2WSH form: the final witness stack per input (BIP-141 layout):
    // empty dummy, M worst-case signatures, the redeem script.
    let p2wsh_sized_witness = || -> Vec<Vec<u8>> {
        let mut stack = vec![Vec::new()];
        for _ in 0..m {
            stack.push(vec![0u8; MS_SIG_SIZE_ESTIMATE]);
        }
        stack.push(redeem.to_vec());
        stack
    };
    // P2TR form: the final witness stack per input (R-MS-11 layout):
    // N slots (M worst-case 64-byte Schnorr signatures + N−M empty
    // non-signer slots), the tapscript, the 33-byte control block.
    // No dummy element (the fee model's `MS_SIG_SIZE_ESTIMATE_TAP`
    // covers the CompactSize + signature + sighash-byte worst case).
    let n_keys = if form == MsForm::P2tr {
        crate::script::extract_multisig_tapscript(redeem)
            .expect("the quorum redeem is the canonical tapscript ms_create_address produced")
            .1
            .len()
    } else {
        0
    };
    let p2tr_sized_witness = || -> Vec<Vec<u8>> {
        let mut stack = Vec::with_capacity(n_keys + 2);
        for _ in 0..m {
            // Worst-case slot: 66 bytes (CompactSize + 64-byte Schnorr
            // + 1 sighash byte); the canonical final is 65 — the fee
            // loop must never underpay.
            stack.push(vec![0u8; MS_SIG_SIZE_ESTIMATE_TAP]);
        }
        for _ in m..n_keys {
            stack.push(Vec::new());
        }
        stack.push(redeem.to_vec());
        let leaf_hash = crate::script::tapscript_leaf_hash(redeem);
        let control_block =
            crate::address::tapscript_control_block(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)
                .expect("NUMS lift and tweak are total for the canonical internal key");
        stack.push(control_block.to_vec());
        stack
    };

    let build_vin = |sized: bool| -> Vec<TxIn> {
        selected
            .iter()
            .map(|u| TxIn {
                txhash: u.txid,
                n: u.vout,
                script: if sized && form == MsForm::P2sh {
                    vec![0u8; script_sig_len]
                } else {
                    Vec::new()
                },
                sequence: SEQUENCE_RBF_SIGNALED,
                witness: if sized {
                    match form {
                        MsForm::P2wsh => p2wsh_sized_witness(),
                        MsForm::P2tr => p2tr_sized_witness(),
                        MsForm::P2sh => Vec::new(),
                    }
                } else {
                    Vec::new()
                },
            })
            .collect()
    };

    let (best_fee, best_vout);
    if fee.get() > 0 {
        // Explicit fee: the loop is skipped, exactly like
        // `Wallet::make_transaction`.
        best_vout = make_vout(
            &quorum_addr,
            dst,
            TSatoshi::new(in_amount),
            Some(amount),
            fee,
        )?;
        best_fee = fee.get();
    } else {
        // Fee loop keyed on vsize (cycle detection by repeated vsize —
        // decision C3). The sized vin makes `vsize == bytes` reflect
        // the final (still unsigned) scripts.
        let mut candidates: FeeLoopCandidates = std::collections::BTreeMap::new();
        let mut seen_sizes = std::collections::BTreeSet::new();
        let mut current_fee: u64 = 0;
        loop {
            let vout_result = make_vout(
                &quorum_addr,
                dst,
                TSatoshi::new(in_amount),
                Some(amount),
                TSatoshi::new(current_fee),
            )?;
            let tx = Transaction {
                version: 2,
                vin: build_vin(true),
                vout: vout_result.vout.clone(),
                locktime: 0,
            };
            let vsize = tx.vsize();
            let new_fee = (vsize as u64) * feekb.get() / 1000;
            tracing::debug!(
                vsize,
                fee = current_fee,
                next_fee = new_fee,
                "multisig fee loop iteration"
            );
            candidates
                .entry(vsize)
                .or_default()
                .push((current_fee, vout_result, tx));
            if seen_sizes.contains(&vsize) {
                break;
            }
            seen_sizes.insert(vsize);
            current_fee = new_fee;
        }
        let (_, (fee_sat, vout_result, _)) = pick_best_fee_loop_candidate(&candidates, feekb.get());
        best_fee = fee_sat;
        best_vout = vout_result;
    }

    // Creator: unsigned tx + per-form UTXO fields. P2sh:
    // NON_WITNESS_UTXO (one raw_transaction per selected UTXO) +
    // REDEEM_SCRIPT per input. P2wsh: WITNESS_UTXO + WITNESS_SCRIPT
    // per input (no prev-tx fetch — BIP-143 commits the amount, and
    // the network cost of `ms send --form p2wsh` is the single UTXO
    // query ОВ-13 already paid).
    let mut create_inputs = Vec::with_capacity(selected.len());
    for u in selected {
        match form {
            MsForm::P2sh => {
                let txid_hex = hex::encode(u.txid);
                let raw_hex = backend.raw_transaction(&txid_hex).await?;
                let raw = match hex::decode(raw_hex.trim()) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(WalletError::Network(format!(
                            "raw tx {txid_hex}: bad hex: {e}"
                        ))
                        .into());
                    }
                };
                let prev_tx = crate::psbt::parse_wire_tx(&raw)
                    .map_err(|e| WalletError::Network(format!("raw tx {txid_hex}: {e}")))?;
                create_inputs.push(CreateInput {
                    amount: u.amount,
                    script_pubkey: quorum_script.clone(),
                    prev_tx: Some(prev_tx),
                    redeem_script: Some(redeem.to_vec()),
                    witness_script: None,
                    tap_leaf_script: None,
                });
            }
            MsForm::P2wsh => {
                create_inputs.push(CreateInput {
                    amount: u.amount,
                    script_pubkey: quorum_script.clone(),
                    prev_tx: None,
                    redeem_script: None,
                    witness_script: Some(redeem.to_vec()),
                    tap_leaf_script: None,
                });
            }
            MsForm::P2tr => {
                // Script-path form: WITNESS_UTXO (BIP-341 commits the
                // amount) + TAP_LEAF_SCRIPT (value = script ‖ 0xc0;
                // the Creator derives the control-block key offline
                // from the NUMS internal key) + TAP_INTERNAL_KEY — no
                // prev-tx fetch, symmetric with P2WSH.
                let mut leaf_value = redeem.to_vec();
                leaf_value.push(crate::script::TAPSCRIPT_LEAF_VERSION);
                create_inputs.push(CreateInput {
                    amount: u.amount,
                    script_pubkey: quorum_script.clone(),
                    prev_tx: None,
                    redeem_script: None,
                    witness_script: None,
                    tap_leaf_script: Some(leaf_value),
                });
            }
        }
    }
    let unsigned = Transaction {
        version: 2,
        vin: build_vin(false),
        vout: best_vout.vout.clone(),
        locktime: 0,
    };
    let mut psbt = PartiallySignedTransaction::create(unsigned, create_inputs)?;

    // Signer: the own key signs every input of the quorum spend.
    for i in 0..psbt.inputs.len() {
        psbt.sign_input(i, own_privkey)?;
    }

    Ok(MsPsbtOutcome {
        psbt_b64: psbt.to_base64(),
        fee: TSatoshi::new(best_fee),
        cashback: best_vout.cashback,
        amount: best_vout.amount,
    })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::script::make_p2pkh_lock_script;

    /// Build a TPrivKey + matching UTXO with a fresh seed.
    /// Returns `(privkey, address, lock_script_bytes, utxo)`.
    fn fixture() -> (TPrivKey, [u8; 20]) {
        let seed = TSeed::new("phase3test");
        let nonce = TNonce::new(0);
        let pk = TPrivKey::new(&seed, nonce, &TPassphrase::EMPTY, KdfAlgo::Yubtc).unwrap();
        let pubkey = privkey_to_pubkey(&pk.privkey);
        let hash = crate::address::hash160_pubkey(&pubkey);
        (pk, hash)
    }

    fn utxo_for(hash: &[u8; 20], amount: u64, confirmations: u32) -> Utxo {
        Utxo {
            txid: [0xab; 32],
            vout: 0,
            amount,
            script_pubkey: make_p2pkh_lock_script(hash),
            confirmations,
        }
    }

    // --- Utxo::from_network -------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn utxo_from_network_accepts_p2pkh() {
        let (pk, hash) = fixture();
        let _ = pk;
        let u = Utxo::from_network(
            "abababababababababababababababababababababababababababababababab",
            0,
            1000,
            &make_p2pkh_lock_script(&hash),
            1,
        )
        .unwrap();
        assert_eq!(u.amount, 1000);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn utxo_from_network_rejects_bad_txid() {
        let (_, hash) = fixture();
        // 31 bytes hex, not 32.
        let r = Utxo::from_network(
            "ababababababababababababababababababababababababababababababab",
            0,
            1000,
            &make_p2pkh_lock_script(&hash),
            1,
        );
        assert!(r.is_err());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn utxo_from_network_rejects_zero_amount() {
        let (_, hash) = fixture();
        let r = Utxo::from_network(
            "abababababababababababababababababababababababababababababababab",
            0,
            0,
            &make_p2pkh_lock_script(&hash),
            1,
        );
        assert!(matches!(r, Err(WalletError::UnsupportedAddress(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn utxo_from_network_rejects_bad_script() {
        let r = Utxo::from_network(
            "abababababababababababababababababababababababababababababababab",
            0,
            1000,
            b"\x76\xa9",
            1,
        );
        assert!(matches!(r, Err(WalletError::UnsupportedUtxoScript)));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn utxo_from_network_accepts_p2sh() {
        let hash = [0x33u8; 20];
        let r = Utxo::from_network(
            "abababababababababababababababababababababababababababababababab",
            0,
            1000,
            &make_p2sh_lock_script(&hash),
            1,
        );
        assert!(r.is_ok());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn utxo_from_network_rejects_bad_p2sh_shape() {
        // 23 bytes but wrong opcodes.
        let bad = vec![0u8; 23];
        let r = Utxo::from_network(
            "abababababababababababababababababababababababababababababababab",
            0,
            1000,
            &bad,
            1,
        );
        assert!(matches!(r, Err(WalletError::UnsupportedUtxoScript)));
    }

    // --- validate_utxo_script ----------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_script_p2pkh_ok() {
        let (_, hash) = fixture();
        assert!(validate_utxo_script(&make_p2pkh_lock_script(&hash)).is_ok());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_script_p2sh_ok() {
        let hash = [0x33u8; 20];
        assert!(validate_utxo_script(&make_p2sh_lock_script(&hash)).is_ok());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_script_rejects_p2sh_bad_push_opcode() {
        // 23 bytes with the OP_HASH160 prefix but a non-OP_PUSH20
        // length opcode at index 1 — the second condition of the P2SH
        // shape check must reject it (the canonical bad-shape test
        // flips index 0, so this arm needs its own fixture).
        let mut bad = make_p2sh_lock_script(&[0x33u8; 20]);
        bad[1] = 0x13;
        assert!(matches!(
            validate_utxo_script(&bad),
            Err(WalletError::UnsupportedUtxoScript)
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_script_rejects_p2sh_bad_suffix_opcode() {
        // 23 bytes with valid OP_HASH160 + OP_PUSH20 prefix but a
        // non-OP_EQUAL terminator at index 22 — the third condition
        // of the P2SH shape check.
        let mut bad = make_p2sh_lock_script(&[0x33u8; 20]);
        bad[22] = 0x86;
        assert!(matches!(
            validate_utxo_script(&bad),
            Err(WalletError::UnsupportedUtxoScript)
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_script_rejects_other_length() {
        assert!(validate_utxo_script(&[0u8; 22]).is_err());
        assert!(validate_utxo_script(&[0u8; 30]).is_err());
    }

    // --- make_lock_script_for_address --------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_lock_for_address_p2pkh() {
        let (pk, _) = fixture();
        let addr = pk.get_p2pkh_address();
        let script = make_lock_script_for_address(&addr).unwrap();
        assert_eq!(script.len(), 25);
        assert_eq!(script[0], 0x76);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_lock_for_address_p2sh() {
        // Build a P2SH address from a known hash; P2SH = base58check(0x05 ‖ 20B).
        let hash = [0x33u8; 20];
        let mut payload = [0u8; 21];
        payload[0] = crate::address::PREFIX_P2SH;
        payload[1..].copy_from_slice(&hash);
        let s = crate::address::PREFIX_P2SH; // silence unused
        let _ = s;
        // Use the address module's base58check helper. We need to
        // access via the crate's private API. The simplest is to
        // construct via a test call.
        let encoded = {
            // base58check-encode payload via the bitcoin crate
            // (already available via the crate): use the same
            // helper as address.rs.
            use base58::ToBase58;
            let mut with_checksum = payload.to_vec();
            let cs = crate::address::double_sha256_for_test(&payload);
            with_checksum.extend_from_slice(&cs[..4]);
            with_checksum.to_base58()
        };
        let addr = TAddress::new(encoded);
        let script = make_lock_script_for_address(&addr).unwrap();
        assert_eq!(script.len(), 23);
        assert_eq!(script[0], 0xa9);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_lock_for_address_rejects_bad_base58check() {
        let r = make_lock_script_for_address(&TAddress::new("not-a-base58-address"));
        assert!(matches!(r, Err(WalletError::AddressDecode(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_lock_for_address_rejects_unsupported_version() {
        // Build a base58check payload with an unsupported version
        // (0x6f = testnet P2PKH). decode_address rejects this
        // before make_lock_script_for_address sees the version, so
        // the wallet-level error is AddressDecode.
        let mut payload = [0u8; 21];
        payload[0] = 0x6f;
        let mut with_checksum = payload.to_vec();
        let cs = crate::address::double_sha256_for_test(&payload);
        with_checksum.extend_from_slice(&cs[..4]);
        use base58::ToBase58;
        let s = with_checksum.to_base58();
        let err = make_lock_script_for_address(&TAddress::new(s)).expect_err("expected an error");
        // Variant + payload pinned guard-free (a `matches!` guard or
        // let-else would leave its false arm as an uncovered
        // branch/line, and this path provably only yields
        // AddressDecode).
        assert!(matches!(err, WalletError::AddressDecode(_)));
        assert!(err.to_string().contains("0x6f"));
    }

    // --- make_vout ----------------------------------------------------

    fn real_pair() -> (TAddress, TAddress) {
        let (pk_a, _) = fixture();
        let seed_b = TSeed::new("phase3test_other");
        let pk_b =
            TPrivKey::new(&seed_b, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc).unwrap();
        (pk_a.get_p2pkh_address(), pk_b.get_p2pkh_address())
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_vout_drain_branch() {
        let (src, dst) = real_pair();
        let r = make_vout(&src, &dst, TSatoshi::new(1000), None, TSatoshi::new(100)).unwrap();
        assert_eq!(r.amount.get(), 900);
        assert_eq!(r.cashback.get(), 0);
        assert_eq!(r.vout.len(), 1);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_vout_exact_match_branch() {
        let (src, dst) = real_pair();
        let r = make_vout(
            &src,
            &dst,
            TSatoshi::new(1000),
            Some(TSatoshi::new(900)),
            TSatoshi::new(100),
        )
        .unwrap();
        assert_eq!(r.amount.get(), 900);
        assert_eq!(r.cashback.get(), 0);
        assert_eq!(r.vout.len(), 1);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_vout_standard_branch() {
        let (src, dst) = real_pair();
        let r = make_vout(
            &src,
            &dst,
            TSatoshi::new(1000),
            Some(TSatoshi::new(400)),
            TSatoshi::new(100),
        )
        .unwrap();
        assert_eq!(r.amount.get(), 400);
        assert_eq!(r.cashback.get(), 500);
        assert_eq!(r.vout.len(), 2);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_vout_rejects_input_below_fee() {
        let (src, dst) = real_pair();
        let r = make_vout(&src, &dst, TSatoshi::new(50), None, TSatoshi::new(100));
        assert!(matches!(r, Err(WalletError::InputDoesNotCoverFee { .. })));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_vout_rejects_amount_plus_fee() {
        let (src, dst) = real_pair();
        let r = make_vout(
            &src,
            &dst,
            TSatoshi::new(1000),
            Some(TSatoshi::new(950)),
            TSatoshi::new(100),
        );
        assert!(matches!(r, Err(WalletError::AmountExceedsInput { .. })));
    }

    // --- TPrivKey ------------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tprivkey_new_rejects_empty_seed() {
        let r = TPrivKey::new(
            &TSeed::new(""),
            TNonce::new(0),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
        );
        assert!(matches!(r, Err(WalletError::EmptySeed)));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tprivkey_new_non_yubtc_kdf_requires_passphrase() {
        let err = TPrivKey::new(
            &TSeed::new("phase3test"),
            TNonce::new(0),
            &TPassphrase::EMPTY,
            KdfAlgo::Pbkdf2,
        )
        .expect_err("expected an error");
        // Guard-free assertion pair (see the note in
        // make_lock_for_address_rejects_unsupported_version).
        assert!(matches!(err, WalletError::PrivKey(_)));
        assert!(err.to_string().contains("passphrase required"));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tprivkey_new_yubtc_kdf_rejects_passphrase() {
        // The legacy `yubtc` cascade is passphrase-free. Accepting a
        // passphrase here and quietly deriving with pbkdf2 instead
        // would hand the caller a different address than they asked
        // for — the KDF selection must be honoured or refused.
        let pp = TPassphrase::new("phrase");
        let err = TPrivKey::new(
            &TSeed::new("phase3test"),
            TNonce::new(0),
            &pp,
            KdfAlgo::Yubtc,
        )
        .expect_err("expected an error");
        // Guard-free assertion pair (see the note in
        // make_lock_for_address_rejects_unsupported_version).
        assert!(matches!(err, WalletError::PrivKey(_)));
        assert!(err.to_string().contains("passphrase"));
    }

    #[ntest_timeout::timeout(180000)]
    #[test]
    fn tprivkey_new_honours_the_requested_kdf() {
        // Same seed/nonce/passphrase, different KDF => different key.
        let pp = TPassphrase::new("phrase");
        let seed = TSeed::new("phase3test");
        let a = TPrivKey::new(&seed, TNonce::new(0), &pp, KdfAlgo::Pbkdf2).unwrap();
        let b = TPrivKey::new(&seed, TNonce::new(0), &pp, KdfAlgo::Scrypt).unwrap();
        assert_ne!(
            a.get_p2pkh_address().as_str(),
            b.get_p2pkh_address().as_str()
        );
    }

    #[ntest_timeout::timeout(180000)]
    #[test]
    fn tprivkey_new_propagates_kdf_errors() {
        // scrypt/argon2id encode the nonce in a 4-byte BIP-44 index,
        // so an oversized nonce is rejected by the KDF layer and must
        // reach the caller as a WalletError.
        let err = TPrivKey::new(
            &TSeed::new("phase3test"),
            TNonce::new(0x8000_0000),
            &TPassphrase::new("phrase"),
            KdfAlgo::Scrypt,
        )
        .expect_err("expected an error");
        assert!(matches!(err, WalletError::PrivKey(_)));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn tprivkey_new_produces_address_and_wif() {
        let (pk, _) = fixture();
        let wif = pk.get_privwif();
        // Bitwise `|` (not `||`) so every prefix check is evaluated —
        // the short-circuit form leaves the later arms permanently
        // uncovered for branch coverage.
        assert!(wif.starts_with('L') | wif.starts_with('K') | wif.starts_with('5'));
        let addr = pk.get_p2pkh_address();
        assert!(addr.as_str().starts_with('1'));
    }

    // --- pick_best_fee_loop_candidate --------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn fee_loop_picker_prefers_smallest_size_paying_rate() {
        let mut candidates = std::collections::BTreeMap::new();
        candidates.insert(
            200,
            vec![(
                200,
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        candidates.insert(
            220,
            vec![(
                220,
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        // feekb=1000 sat/kB → needs 200 for size 200, 220 for size 220.
        // Size 200 pays 200 < 200 needed? No, fee=200 >= 200 needed.
        // Wait: needed = size*feekb/1000 = 200*1000/1000 = 200. 200 >= 200 ✓.
        let (size, entry) = pick_best_fee_loop_candidate(&candidates, 1000);
        assert_eq!(size, 200);
        assert_eq!(entry.0, 200);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn fee_loop_picker_breaks_size_tie_on_smaller_fee() {
        let mut candidates = std::collections::BTreeMap::new();
        // Two entries at the same size, with different fees. First
        // entry (smaller fee) wins.
        candidates.insert(
            225,
            vec![
                (
                    250,
                    VoutResult {
                        vout: vec![],
                        cashback: TSatoshi::ZERO,
                        amount: TSatoshi::new(0),
                    },
                    Transaction::default(),
                ),
                (
                    300,
                    VoutResult {
                        vout: vec![],
                        cashback: TSatoshi::ZERO,
                        amount: TSatoshi::new(0),
                    },
                    Transaction::default(),
                ),
            ],
        );
        let (_size, entry) = pick_best_fee_loop_candidate(&candidates, 1000);
        // First entry wins on smaller fee.
        assert_eq!(entry.0, 250);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn fee_loop_picker_replaces_same_size_entry_with_smaller_fee() {
        // Same size as the incumbent but a smaller fee: the
        // domination check must evaluate to false (no larger size,
        // no fee tie) and REPLACE the incumbent. Fees arrive in
        // descending order so the tie-break test's ascending order
        // can't cover this arm — the picker's `||` would otherwise
        // never see its false side.
        let mut candidates = std::collections::BTreeMap::new();
        candidates.insert(
            225,
            vec![
                (
                    300,
                    VoutResult {
                        vout: vec![],
                        cashback: TSatoshi::ZERO,
                        amount: TSatoshi::new(0),
                    },
                    Transaction::default(),
                ),
                (
                    250,
                    VoutResult {
                        vout: vec![],
                        cashback: TSatoshi::ZERO,
                        amount: TSatoshi::new(0),
                    },
                    Transaction::default(),
                ),
            ],
        );
        let (_size, entry) = pick_best_fee_loop_candidate(&candidates, 1000);
        assert_eq!(entry.0, 250);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn fee_loop_picker_falls_back_to_smallest_size() {
        // No iteration pays the rate; picker falls back to smallest size.
        let mut candidates = std::collections::BTreeMap::new();
        candidates.insert(
            300,
            vec![(
                0,
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        let (size, _entry) = pick_best_fee_loop_candidate(&candidates, 1000);
        assert_eq!(size, 300);
    }

    // --- is_dust ------------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn is_dust_thresholds() {
        let (_, hash) = fixture();
        let p2pkh = make_p2pkh_lock_script(&hash);
        assert!(is_dust(100, &p2pkh));
        assert!(!is_dust(DUST_THRESHOLD_P2PKH, &p2pkh));
        assert!(!is_dust(1000, &p2pkh));
        // P2SH: 23 bytes
        let p2sh = make_p2sh_lock_script(&[0x55; 20]);
        assert!(is_dust(100, &p2sh));
        assert!(!is_dust(DUST_THRESHOLD_P2SH, &p2sh));
        // Other length: false
        assert!(!is_dust(0, &[0u8; 30]));
    }

    // --- constants ----------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn constants_match_spec() {
        assert_eq!(minimal_fee(), 1000);
        assert_eq!(default_confirmations(), 6);
    }

    // --- build_vin ----------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn build_vin_happy_path() {
        let (pk, hash) = fixture();
        let source = Source {
            privkey: pk,
            unspent: vec![utxo_for(&hash, 1000, 6)],
        };
        let (vin, in_amount, signers, _spend) = build_vin(&[source]).unwrap();
        assert_eq!(vin.len(), 1);
        assert_eq!(in_amount, 1000);
        assert_eq!(signers.len(), 1);
        assert_eq!(vin[0].sequence, SEQUENCE_RBF_SIGNALED);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn build_vin_rejects_wrong_pubkey_hash() {
        let (pk, _) = fixture();
        let wrong_hash = [0xeeu8; 20];
        let source = Source {
            privkey: pk,
            unspent: vec![utxo_for(&wrong_hash, 1000, 6)],
        };
        let err = build_vin(&[source]).unwrap_err();
        assert!(matches!(err, WalletError::UnknownPubkeyRequired { .. }));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn build_vin_rejects_non_p2pkh_script() {
        let (pk, _) = fixture();
        let bad = Utxo {
            txid: [0xab; 32],
            vout: 0,
            amount: 1000,
            script_pubkey: vec![0u8; 22],
            confirmations: 6,
        };
        let source = Source {
            privkey: pk,
            unspent: vec![bad],
        };
        let err = build_vin(&[source]).unwrap_err();
        assert!(matches!(err, WalletError::UnsupportedUtxoScript));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn build_vin_multiple_inputs() {
        let (pk, hash) = fixture();
        let source = Source {
            privkey: pk,
            unspent: vec![utxo_for(&hash, 500, 6), utxo_for(&hash, 700, 6)],
        };
        let (vin, in_amount, signers, _spend) = build_vin(&[source]).unwrap();
        assert_eq!(vin.len(), 2);
        assert_eq!(in_amount, 1200);
        assert_eq!(signers.len(), 2);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn build_vin_empty_sources() {
        let (vin, in_amount, signers, _spend) = build_vin(&[]).unwrap();
        assert!(vin.is_empty());
        assert_eq!(in_amount, 0);
        assert!(signers.is_empty());
    }

    // --- network-backed wallet paths --------------------------------

    use crate::net::{NetError, NetworkBackend};

    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Test backend that returns canned data without hitting the
    /// network. Mirrors the one in `net::tests` but copy-local so
    /// wallet tests stay independent.
    #[derive(Debug)]
    struct WalletMockBackend {
        unspent: Mutex<HashMap<String, Vec<Utxo>>>,
        info: Mutex<HashMap<String, AddressInfo>>,
        // (still_unused, then_used) flips is_unused on the first call.
        flip_unused: Mutex<HashMap<String, bool>>,
    }

    impl WalletMockBackend {
        fn new() -> Self {
            Self {
                unspent: Mutex::new(HashMap::new()),
                info: Mutex::new(HashMap::new()),
                flip_unused: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl NetworkBackend for WalletMockBackend {
        async fn get_unspent(&self, address: &TAddress) -> Result<Vec<Utxo>, NetError> {
            Ok(self
                .unspent
                .lock()
                .unwrap()
                .get(address.as_str())
                .cloned()
                .unwrap_or_default())
        }
        async fn get_info(&self, address: &TAddress) -> Result<AddressInfo, NetError> {
            let mut map = self.info.lock().unwrap();
            let entry = map.entry(address.as_str().to_string()).or_default();
            let mut flip = self.flip_unused.lock().unwrap();
            let still_unused = flip.entry(address.as_str().to_string()).or_insert(true);
            let is_unused = *still_unused;
            *still_unused = false;
            if !is_unused {
                // Second call: n_tx > 0 so is_unused returns false.
                *entry = AddressInfo {
                    total_received: 1000,
                    final_balance: 1000,
                    n_tx: 1,
                };
            }
            Ok(entry.clone())
        }
        async fn broadcast(&self, _raw_tx: &[u8]) -> Result<(), NetError> {
            Ok(())
        }
        async fn raw_transaction(&self, _txid: &str) -> Result<String, NetError> {
            Ok(String::new())
        }
        fn name(&self) -> &'static str {
            "wallet-mock"
        }
    }

    fn mock_backend() -> std::sync::Arc<WalletMockBackend> {
        std::sync::Arc::new(WalletMockBackend::new())
    }

    /// A real, valid P2PKH mainnet address derivable independent of
    /// the network module's test scope.
    fn wallet_real_address() -> TAddress {
        let seed = TSeed::new("phase3walletmockaddr");
        let pk = TPrivKey::new(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc)
            .expect("known seed");
        pk.get_p2pkh_address()
    }

    #[tokio::test]
    async fn tprivkey_get_info_caches_result() {
        let (mut pk, _) = fixture();
        let m = mock_backend();
        let addr = pk.get_p2pkh_address();
        // First call returns AddressInfo::default (n_tx=0).
        let info1 = pk.get_info(m.as_ref()).await.unwrap();
        assert_eq!(info1.total_received, 0);
        // Inject different data after first call — cache should
        // still return the first value.
        m.info.lock().unwrap().insert(
            addr.as_str().to_string(),
            AddressInfo {
                total_received: 9999,
                final_balance: 9999,
                n_tx: 42,
            },
        );
        let info2 = pk.get_info(m.as_ref()).await.unwrap();
        assert_eq!(info2.total_received, 0);
    }

    #[tokio::test]
    async fn tprivkey_is_unused_returns_true_when_zero_received() {
        let (mut pk, _) = fixture();
        let m = mock_backend();
        let result = pk.is_unused(m.as_ref()).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn tprivkey_is_unused_returns_false_when_received() {
        let (mut pk, _) = fixture();
        let addr = pk.get_p2pkh_address();
        let m = mock_backend();
        m.info.lock().unwrap().insert(
            addr.as_str().to_string(),
            AddressInfo {
                total_received: 1000,
                final_balance: 0,
                n_tx: 1,
            },
        );
        let result = pk.is_unused(m.as_ref()).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn tprivkey_get_unspent_caches_result() {
        let (mut pk, hash) = fixture();
        let addr = pk.get_p2pkh_address();
        let m = mock_backend();
        m.unspent
            .lock()
            .unwrap()
            .insert(addr.as_str().to_string(), vec![utxo_for(&hash, 12345, 6)]);
        let list1 = pk.get_unspent(m.as_ref(), 0).await.unwrap();
        assert_eq!(list1.len(), 1);
        // Inject different data — cache should still return the
        // first value.
        m.unspent
            .lock()
            .unwrap()
            .insert(addr.as_str().to_string(), vec![utxo_for(&hash, 99999, 6)]);
        let list2 = pk.get_unspent(m.as_ref(), 0).await.unwrap();
        assert_eq!(list2.len(), 1);
        assert_eq!(list2[0].amount, 12345);
    }

    #[tokio::test]
    async fn tprivkey_get_unspent_filters_by_confirmations() {
        let (mut pk, hash) = fixture();
        let addr = pk.get_p2pkh_address();
        let m = mock_backend();
        m.unspent.lock().unwrap().insert(
            addr.as_str().to_string(),
            vec![
                utxo_for(&hash, 1000, 1),
                utxo_for(&hash, 2000, 6),
                utxo_for(&hash, 3000, 100),
            ],
        );
        let list = pk.get_unspent(m.as_ref(), 6).await.unwrap();
        assert_eq!(list.len(), 2);
        let amounts: Vec<u64> = list.iter().map(|u| u.amount).collect();
        assert!(amounts.contains(&2000));
        assert!(amounts.contains(&3000));
    }

    #[tokio::test]
    async fn wallet_new_rejects_empty_seed() {
        let r = Wallet::new(
            TSeed::new(""),
            TNonce::new(0),
            0,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            mock_backend(),
        )
        .await;
        assert!(matches!(r, Err(WalletError::EmptySeed)));
    }

    #[tokio::test]
    async fn wallet_new_walks_to_first_unused_after_one_used() {
        // First address used; wallet should walk to nonce=1 then
        // stop (new_addresses=0).
        let m = mock_backend();
        // Pre-populate the seed's nonce=0 address with n_tx > 0.
        let seed = TSeed::new("phase3walletload");
        let tmp_pk =
            TPrivKey::new(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc).unwrap();
        let addr0 = tmp_pk.get_p2pkh_address();
        m.info.lock().unwrap().insert(
            addr0.as_str().to_string(),
            AddressInfo {
                total_received: 1000,
                final_balance: 0,
                n_tx: 1,
            },
        );
        let w = Wallet::new(
            seed,
            TNonce::new(0),
            0,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.clone(),
        )
        .await
        .unwrap();
        // nonce=0 was used (added); nonce=1 was unused (stop). Total = 1.
        assert_eq!(w.privkeys.len(), 1);
        assert_eq!(w.privkeys[0].nonce.get(), 0);
    }

    #[tokio::test]
    async fn wallet_new_walks_then_appends_when_used_address_present() {
        // First address used; wallet asks for N new_addresses after
        // the gap-limit walk.
        let m = mock_backend();
        let seed = TSeed::new("phase3walletload2");
        let tmp_pk =
            TPrivKey::new(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc).unwrap();
        let addr0 = tmp_pk.get_p2pkh_address();
        m.info.lock().unwrap().insert(
            addr0.as_str().to_string(),
            AddressInfo {
                total_received: 1000,
                final_balance: 0,
                n_tx: 1,
            },
        );
        let w = Wallet::new(
            seed,
            TNonce::new(0),
            2,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.clone(),
        )
        .await
        .unwrap();
        // nonce=0 (used, added); nonce=1 (unused, stop); then 2 new.
        assert_eq!(w.privkeys.len(), 3);
        assert_eq!(w.privkeys[0].nonce.get(), 0);
        assert_eq!(w.privkeys[1].nonce.get(), 1);
        assert_eq!(w.privkeys[2].nonce.get(), 2);
    }

    #[tokio::test]
    async fn wallet_new_appends_new_addresses() {
        // First address unused → no scan; then append N.
        let m = mock_backend();
        let seed = TSeed::new("phase3walletnew");
        let w = Wallet::new(
            seed,
            TNonce::new(0),
            3,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.clone(),
        )
        .await
        .unwrap();
        assert_eq!(w.privkeys.len(), 3);
        for (i, pk) in w.privkeys.iter().enumerate() {
            assert_eq!(pk.nonce.get(), i as u32);
        }
    }

    #[tokio::test]
    async fn wallet_getters_round_trip() {
        let seed = TSeed::new("phase3walletgetters");
        let m = mock_backend();
        let w = Wallet::new(
            seed,
            TNonce::new(0),
            0,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.clone(),
        )
        .await
        .unwrap();
        assert_eq!(w.seed().as_str(), "phase3walletgetters");
        assert!(w.passphrase().is_empty());
        assert!(matches!(w.kdf(), KdfAlgo::Yubtc));
    }

    #[tokio::test]
    async fn wallet_make_transaction_with_explicit_fee() {
        let (pk, hash) = fixture();
        let addr = pk.get_p2pkh_address();
        let m = mock_backend();
        m.unspent
            .lock()
            .unwrap()
            .insert(addr.as_str().to_string(), vec![utxo_for(&hash, 100_000, 6)]);
        let w = Wallet::new(
            TSeed::new("phase3test"),
            TNonce::new(0),
            1,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.clone(),
        )
        .await
        .unwrap();
        let (dst, _) = real_pair();
        let src = w.privkeys[0].get_p2pkh_address();
        // Build sources manually so we don't have to mock the chain
        // gap-limit walk.
        let sources = vec![Source {
            privkey: w.privkeys[0].clone(),
            unspent: vec![utxo_for(&hash, 100_000, 6)],
        }];
        let result = w
            .make_transaction(
                &dst,
                Some(TSatoshi::new(50_000)),
                TSatoshi::new(1000),
                TSatoshi::new(1000),
                0,
                Some(sources),
                Some(src),
            )
            .await
            .unwrap();
        assert_eq!(result.amount.get(), 50_000);
        assert_eq!(result.fee.get(), 1000);
        assert_eq!(result.cashback.get(), 100_000 - 50_000 - 1000);
    }

    #[tokio::test]
    async fn wallet_make_transaction_fee_loop_propagates_make_vout_error() {
        // When amount + fee > in_amount, the fee loop's make_vout
        // call returns Err. The whole loop must surface that error.
        let (pk, hash) = fixture();
        let addr = pk.get_p2pkh_address();
        let m = mock_backend();
        // Tiny in_amount so even a small fee fails.
        m.unspent
            .lock()
            .unwrap()
            .insert(addr.as_str().to_string(), vec![utxo_for(&hash, 100, 6)]);
        let w = Wallet::new(
            TSeed::new("phase3test"),
            TNonce::new(0),
            1,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.clone(),
        )
        .await
        .unwrap();
        let (dst, _) = real_pair();
        let src = w.privkeys[0].get_p2pkh_address();
        let sources = vec![Source {
            privkey: w.privkeys[0].clone(),
            unspent: vec![utxo_for(&hash, 100, 6)],
        }];
        // amount=99 → make_vout(fee=0) succeeds initially. The loop
        // then computes new_fee = size*1000/1000 ≈ 200, which exceeds
        // in_amount=100, so the next iteration's make_vout fails.
        let err = w
            .make_transaction(
                &dst,
                Some(TSatoshi::new(99)),
                TSatoshi::new(1000),
                TSatoshi::new(0),
                0,
                Some(sources),
                Some(src),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WalletError::InputDoesNotCoverFee { .. }));
    }

    #[tokio::test]
    async fn wallet_make_transaction_fee_loop_picks_best() {
        let (pk, hash) = fixture();
        let addr = pk.get_p2pkh_address();
        let m = mock_backend();
        m.unspent
            .lock()
            .unwrap()
            .insert(addr.as_str().to_string(), vec![utxo_for(&hash, 200_000, 6)]);
        let w = Wallet::new(
            TSeed::new("phase3test"),
            TNonce::new(0),
            1,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.clone(),
        )
        .await
        .unwrap();
        let (dst, _) = real_pair();
        let src = w.privkeys[0].get_p2pkh_address();
        let sources = vec![Source {
            privkey: w.privkeys[0].clone(),
            unspent: vec![utxo_for(&hash, 200_000, 6)],
        }];
        // fee=0 → loop runs. feekb=1000 → 1 sat/byte.
        let result = w
            .make_transaction(
                &dst,
                Some(TSatoshi::new(150_000)),
                TSatoshi::new(1000),
                TSatoshi::new(0),
                0,
                Some(sources),
                Some(src),
            )
            .await
            .unwrap();
        // The fee should cover the rate at the produced size.
        assert!(result.fee.get() > 0);
    }

    #[tokio::test]
    async fn wallet_select_inputs_requires_cashback_when_sources_given() {
        let (pk, hash) = fixture();
        let m = mock_backend();
        m.unspent.lock().unwrap().insert(
            pk.get_p2pkh_address().as_str().to_string(),
            vec![utxo_for(&hash, 100_000, 6)],
        );
        let w = Wallet::new(
            TSeed::new("phase3test"),
            TNonce::new(0),
            1,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.clone(),
        )
        .await
        .unwrap();
        let (dst, _) = real_pair();
        let sources = vec![Source {
            privkey: w.privkeys[0].clone(),
            unspent: vec![utxo_for(&hash, 100_000, 6)],
        }];
        let err = w
            .make_transaction(
                &dst,
                Some(TSatoshi::new(50_000)),
                TSatoshi::new(1000),
                TSatoshi::new(1000),
                0,
                Some(sources),
                None, // no cashback
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WalletError::CashbackAddrNotSet));
    }

    #[tokio::test]
    async fn wallet_select_inputs_default_uses_primary_privkey() {
        let (pk, hash) = fixture();
        let addr = pk.get_p2pkh_address();
        let m = mock_backend();
        m.unspent
            .lock()
            .unwrap()
            .insert(addr.as_str().to_string(), vec![utxo_for(&hash, 100_000, 6)]);
        let w = Wallet::new(
            TSeed::new("phase3test"),
            TNonce::new(0),
            1,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.clone(),
        )
        .await
        .unwrap();
        let (dst, _) = real_pair();
        // Pass no sources + no cashback → wallet uses primary.
        let result = w
            .make_transaction(
                &dst,
                Some(TSatoshi::new(50_000)),
                TSatoshi::new(1000),
                TSatoshi::new(1000),
                0,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.amount.get(), 50_000);
    }

    #[tokio::test]
    async fn wallet_make_transaction_propagates_network_error() {
        let (pk, _) = fixture();
        let addr = pk.get_p2pkh_address();
        // Backend that always errors.
        #[derive(Debug)]
        struct ErrBackend;
        #[async_trait::async_trait]
        impl NetworkBackend for ErrBackend {
            async fn get_unspent(&self, _: &TAddress) -> Result<Vec<Utxo>, NetError> {
                Err(NetError::Http("nope".into()))
            }
            async fn get_info(&self, _: &TAddress) -> Result<AddressInfo, NetError> {
                Err(NetError::Http("nope".into()))
            }
            async fn broadcast(&self, _: &[u8]) -> Result<(), NetError> {
                Err(NetError::Http("nope".into()))
            }
            async fn raw_transaction(&self, _: &str) -> Result<String, NetError> {
                Err(NetError::Http("nope".into()))
            }
            fn name(&self) -> &'static str {
                "err"
            }
        }
        let err_backend = std::sync::Arc::new(ErrBackend);
        // Exercise all four methods directly to ensure the impl
        // body is covered (otherwise cargo-llvm-cov would flag the
        // empty Ok-path / Err-path branches as unreachable).
        let r1 = err_backend.get_unspent(&addr).await;
        let r2 = err_backend.get_info(&addr).await;
        let r3 = err_backend.broadcast(b"deadbeef").await;
        let r4 = err_backend.raw_transaction("aa").await;
        assert!(matches!(r1, Err(NetError::Http(_))));
        assert!(matches!(r2, Err(NetError::Http(_))));
        assert!(matches!(r3, Err(NetError::Http(_))));
        assert!(matches!(r4, Err(NetError::Http(_))));
        assert_eq!(err_backend.name(), "err");
        let w = Wallet::new(
            TSeed::new("phase3test"),
            TNonce::new(0),
            0,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            err_backend.clone(),
        )
        .await;
        // Wallet::new calls is_unused → network error.
        assert!(matches!(w, Err(WalletError::Network(_))));
    }

    #[tokio::test]
    async fn wallet_mock_backend_exercises_all_methods() {
        // Exercise every method on the WalletMockBackend so
        // cargo-llvm-cov counts the impl bodies as covered.
        let m = mock_backend();
        let addr = wallet_real_address();
        let _ = m.get_unspent(&addr).await;
        let _ = m.get_info(&addr).await;
        let _ = m.broadcast(b"deadbeef").await;
        let _ = m.raw_transaction("aa").await;
        assert_eq!(m.name(), "wallet-mock");
        // Second get_info on the same address flips the mock's
        // first-call state: the repeated-scan path reports the
        // address as used (n_tx=1) — the flip branch a re-scan of
        // an already-visited address would take.
        let second = m.get_info(&addr).await.unwrap();
        assert_eq!(second.n_tx, 1);
    }

    #[tokio::test]
    async fn pick_best_fee_loop_candidate_prefers_small_size_with_smaller_fee() {
        // Two entries at smaller size, both pay rate; smaller fee wins.
        let mut candidates: FeeLoopCandidates = std::collections::BTreeMap::new();
        candidates.insert(
            200,
            vec![(
                200,
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        candidates.insert(
            220,
            vec![(
                300,
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        let (size, entry) = pick_best_fee_loop_candidate(&candidates, 1000);
        assert_eq!(size, 200);
        assert_eq!(entry.0, 200);
    }

    #[tokio::test]
    async fn pick_best_fee_loop_candidate_falls_back_when_no_one_pays() {
        // All entries underpay; fallback = smallest size.
        let mut candidates: FeeLoopCandidates = std::collections::BTreeMap::new();
        candidates.insert(
            220,
            vec![(
                100,
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        candidates.insert(
            200,
            vec![(
                50,
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        let (size, entry) = pick_best_fee_loop_candidate(&candidates, 1000);
        assert_eq!(size, 200);
        assert_eq!(entry.0, 50);
    }

    /// spec test `test_fee_loop_respects_min_relay_tx_fee`: a candidate
    /// whose fee is below `size * DEFAULT_MIN_RELAY_TX_FEE / 1000` is
    /// dropped even when its size is the smallest — such a tx would be
    /// rejected by every mempool. The floor comes from
    /// `bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE` = 1000 sat/kvB
    /// (= 1 sat/vB), i.e. floor == size in satoshi here.
    #[tokio::test]
    async fn pick_best_fee_loop_candidate_respects_min_relay_tx_fee() {
        assert_eq!(minimal_fee(), 1000, "relay floor is 1 sat/vB");

        // fee == needed (feekb 1000 → needed == size) but BELOW the
        // relay floor? Not possible with feekb == floor; use a lower
        // user rate to isolate the floor: feekb 100 → needed = size/10.
        let mut candidates: FeeLoopCandidates = std::collections::BTreeMap::new();
        candidates.insert(
            100,
            vec![(
                50, // >= needed (10) but < relay floor (100) → dropped
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        candidates.insert(
            300,
            vec![(
                300, // >= needed (30) and >= relay floor (300) → kept
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        let (size, entry) = pick_best_fee_loop_candidate(&candidates, 100);
        assert_eq!(size, 300, "sub-floor candidate must not win by size");
        assert_eq!(entry.0, 300);
    }

    /// When every candidate is below the relay floor, the fallback
    /// still fires: "pays some fee" beats "no tx at all", and the tx
    /// remains structurally valid (spec: Phase 3 fallback).
    #[tokio::test]
    async fn pick_best_fee_loop_candidate_all_below_floor_falls_back() {
        let mut candidates: FeeLoopCandidates = std::collections::BTreeMap::new();
        candidates.insert(
            400,
            vec![(
                10,
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        candidates.insert(
            500,
            vec![(
                20,
                VoutResult {
                    vout: vec![],
                    cashback: TSatoshi::ZERO,
                    amount: TSatoshi::new(0),
                },
                Transaction::default(),
            )],
        );
        let (size, entry) = pick_best_fee_loop_candidate(&candidates, 100);
        assert_eq!(size, 400, "fallback: smallest size ever produced");
        assert_eq!(entry.0, 10);
    }

    #[tokio::test]
    async fn pick_best_fee_loop_candidate_same_size_prefers_smaller_fee() {
        // Two entries at the SAME size, both pay the rate; the later
        // entry has a strictly smaller fee and must replace the
        // current best (the tie-break's `fee >= best` false edge).
        let mut candidates: FeeLoopCandidates = std::collections::BTreeMap::new();
        candidates.insert(
            200,
            vec![
                (
                    300,
                    VoutResult {
                        vout: vec![],
                        cashback: TSatoshi::ZERO,
                        amount: TSatoshi::new(0),
                    },
                    Transaction::default(),
                ),
                (
                    200,
                    VoutResult {
                        vout: vec![],
                        cashback: TSatoshi::ZERO,
                        amount: TSatoshi::new(0),
                    },
                    Transaction::default(),
                ),
            ],
        );
        let (size, entry) = pick_best_fee_loop_candidate(&candidates, 1000);
        assert_eq!(size, 200);
        assert_eq!(entry.0, 200);
    }

    // --- scan_inputs_until / scan_all --------------------------------

    /// Helper: build a wallet from `seed`, mock backend, then return
    /// `(seed, nonce=0 address)`.
    fn seed_and_addr(seed_str: &str) -> (TSeed, TAddress) {
        let seed = TSeed::new(seed_str);
        let pk = TPrivKey::new(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc).unwrap();
        (seed, pk.get_p2pkh_address())
    }

    fn addr_for(seed_str: &str, nonce: u32) -> TAddress {
        let seed = TSeed::new(seed_str);
        let pk = TPrivKey::new(
            &seed,
            TNonce::new(nonce),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
        )
        .unwrap();
        pk.get_p2pkh_address()
    }

    /// Mock that marks the first N addresses used (n_tx>0) and the
    /// rest unused. Returns the mock backend.
    fn mock_with_used(m: &std::sync::Arc<WalletMockBackend>, seed_str: &str, used_count: usize) {
        for n in 0..used_count {
            let a = addr_for(seed_str, n as u32);
            m.info.lock().unwrap().insert(
                a.as_str().to_string(),
                AddressInfo {
                    total_received: 1000,
                    final_balance: 0,
                    n_tx: 1,
                },
            );
        }
    }

    /// Inject UTXOs at `(seed_str, nonce, amount)`.
    fn mock_with_utxos(
        m: &std::sync::Arc<WalletMockBackend>,
        seed_str: &str,
        nonce: u32,
        amount: u64,
    ) {
        let a = addr_for(seed_str, nonce);
        let pubkey = privkey_to_pubkey(
            &TPrivKey::new(
                &TSeed::new(seed_str),
                TNonce::new(nonce),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
            )
            .unwrap()
            .privkey,
        );
        let hash = crate::address::hash160_pubkey(&pubkey);
        m.unspent
            .lock()
            .unwrap()
            .insert(a.as_str().to_string(), vec![utxo_for(&hash, amount, 6)]);
    }

    #[tokio::test]
    async fn scan_all_returns_all_contributing_sources() {
        let m = mock_backend();
        let seed_str = "scan_all_multi";
        let (seed, _) = seed_and_addr(seed_str);
        // Nonce 0 used + has UTXO, nonce 1 used + has UTXO, nonce 2 unused empty → gap.
        mock_with_used(&m, seed_str, 2);
        mock_with_utxos(&m, seed_str, 0, 1000);
        mock_with_utxos(&m, seed_str, 1, 2000);
        let (sources, cashback_addr) = scan_all(
            &seed,
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.as_ref(),
            6,
        )
        .await
        .unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].privkey.nonce.get(), 0);
        assert_eq!(sources[1].privkey.nonce.get(), 1);
        // Cashback goes to the gap-limit unused address (nonce 2).
        assert_eq!(cashback_addr, addr_for(seed_str, 2));
    }

    #[tokio::test]
    async fn scan_all_stops_immediately_on_unused_with_no_utxos() {
        let m = mock_backend();
        let seed_str = "scan_all_immediate_gap";
        let (seed, _) = seed_and_addr(seed_str);
        // Nonce 0 is unused + no UTXOs → gap immediately.
        let (sources, cashback_addr) = scan_all(
            &seed,
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.as_ref(),
            6,
        )
        .await
        .unwrap();
        assert!(sources.is_empty());
        assert_eq!(cashback_addr, addr_for(seed_str, 0));
    }

    #[tokio::test]
    async fn scan_inputs_until_terminates_on_target_met() {
        let m = mock_backend();
        let seed_str = "scan_until_target";
        let (seed, _) = seed_and_addr(seed_str);
        mock_with_used(&m, seed_str, 3);
        mock_with_utxos(&m, seed_str, 0, 500);
        mock_with_utxos(&m, seed_str, 1, 700);
        mock_with_utxos(&m, seed_str, 2, 900);
        // Target 1500: 500+700 = 1200 < 1500; need nonce 2 (900) → total 2100 ≥ 1500. Stop.
        let (sources, cashback_addr) = scan_inputs_until(
            &seed,
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.as_ref(),
            Some(TSatoshi::new(1500)),
            6,
        )
        .await
        .unwrap();
        assert_eq!(sources.len(), 3);
        // Cashback = last sourced address (target met).
        assert_eq!(cashback_addr, addr_for(seed_str, 2));
    }

    #[tokio::test]
    async fn scan_inputs_until_terminates_on_gap_when_target_unmet() {
        let m = mock_backend();
        let seed_str = "scan_until_gap";
        let (seed, _) = seed_and_addr(seed_str);
        mock_with_used(&m, seed_str, 2);
        mock_with_utxos(&m, seed_str, 0, 500);
        mock_with_utxos(&m, seed_str, 1, 700);
        // No nonce 2: 500+700 = 1200 < 100_000. Gap-limit stop.
        let (sources, cashback_addr) = scan_inputs_until(
            &seed,
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.as_ref(),
            Some(TSatoshi::new(100_000)),
            6,
        )
        .await
        .unwrap();
        assert_eq!(sources.len(), 2);
        // Cashback = gap-limit unused address (nonce 2).
        assert_eq!(cashback_addr, addr_for(seed_str, 2));
    }

    #[tokio::test]
    async fn scan_inputs_until_skips_used_addresses_with_no_utxos() {
        // Nonce 0 used but no UTXOs (already spent). Nonce 1 has UTXOs.
        // scan should NOT stop at 0 (it's used → not gap); continue.
        let m = mock_backend();
        let seed_str = "scan_skip_used_empty";
        let (seed, _) = seed_and_addr(seed_str);
        mock_with_used(&m, seed_str, 2); // nonces 0 and 1 are used
                                         // No UTXO for nonce 0; UTXO for nonce 1.
        mock_with_utxos(&m, seed_str, 1, 500);
        let (sources, cashback_addr) = scan_inputs_until(
            &seed,
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.as_ref(),
            Some(TSatoshi::new(100)),
            6,
        )
        .await
        .unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].privkey.nonce.get(), 1);
        // target met at nonce 1.
        assert_eq!(cashback_addr, addr_for(seed_str, 1));
    }

    #[tokio::test]
    async fn scan_inputs_until_rejects_empty_seed() {
        let r = scan_inputs_until(
            &TSeed::new(""),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            mock_backend().as_ref(),
            None,
            6,
        )
        .await;
        assert!(matches!(r, Err(WalletError::EmptySeed)));
    }

    // --- Phase 13 stage 2: AddrType / derivation mapping ---------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn addr_type_purpose_names_and_default() {
        assert_eq!(AddrType::Legacy.purpose(), 44);
        assert_eq!(AddrType::Native.purpose(), 84);
        assert_eq!(AddrType::Taproot.purpose(), 86);
        assert_eq!(AddrType::Legacy.name(), "legacy");
        assert_eq!(AddrType::Native.name(), "native");
        assert_eq!(AddrType::Taproot.name(), "taproot");
        // Spec ОВ-1: the default receive type after Phase 13 is native.
        assert_eq!(AddrType::default(), AddrType::Native);
        // Canonical scan order.
        assert_eq!(
            AddrType::ALL,
            [AddrType::Legacy, AddrType::Native, AddrType::Taproot]
        );
    }

    #[ntest_timeout::timeout(180_000)]
    #[test]
    fn with_addr_type_pbkdf2_derives_distinct_leaves_per_type() {
        // BIP-39-standard KDF: each AddrType is its own BIP-32 leaf.
        let seed = TSeed::new("phase13wallet");
        let pp = TPassphrase::new("phrase");
        let legacy = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(0),
            &pp,
            KdfAlgo::Pbkdf2,
            AddrType::Legacy,
        )
        .unwrap();
        let native = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(0),
            &pp,
            KdfAlgo::Pbkdf2,
            AddrType::Native,
        )
        .unwrap();
        let taproot = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(0),
            &pp,
            KdfAlgo::Pbkdf2,
            AddrType::Taproot,
        )
        .unwrap();
        // Different secrets → different WIFs (purpose-bound keys).
        assert_ne!(legacy.get_privwif(), native.get_privwif());
        assert_ne!(legacy.get_privwif(), taproot.get_privwif());
        // Encodings match the type.
        assert!(legacy.get_address().as_str().starts_with('1'));
        assert!(native.get_address().as_str().starts_with("bc1q"));
        assert!(taproot.get_address().as_str().starts_with("bc1p"));
        // The legacy leaf is bit-for-bit the v0.1 key.
        let v01 = TPrivKey::new(&seed, TNonce::new(0), &pp, KdfAlgo::Pbkdf2).unwrap();
        assert_eq!(legacy.get_privwif(), v01.get_privwif());
        assert_eq!(legacy.get_address(), v01.get_address());
    }

    #[ntest_timeout::timeout(180_000)]
    #[test]
    fn with_addr_type_variant_a_keeps_one_key() {
        // Non-BIP-32 KDF (вариант A): same secret, different encoding —
        // the WIF is identical across all types.
        let seed = TSeed::new("phase13varianta");
        let kdf = KdfAlgo::Yubtc;
        let legacy = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(1),
            &TPassphrase::EMPTY,
            kdf,
            AddrType::Legacy,
        )
        .unwrap();
        let native = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(1),
            &TPassphrase::EMPTY,
            kdf,
            AddrType::Native,
        )
        .unwrap();
        let taproot = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(1),
            &TPassphrase::EMPTY,
            kdf,
            AddrType::Taproot,
        )
        .unwrap();
        assert_eq!(legacy.get_privwif(), native.get_privwif());
        assert_eq!(legacy.get_privwif(), taproot.get_privwif());
        assert!(native.get_address().as_str().starts_with("bc1q"));
        assert!(taproot.get_address().as_str().starts_with("bc1p"));
    }

    #[ntest_timeout::timeout(180_000)]
    #[test]
    fn with_addr_type_rejects_empty_seed_and_missing_passphrase() {
        assert!(matches!(
            TPrivKey::with_addr_type(
                &TSeed::new(""),
                TNonce::new(0),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                AddrType::Native,
            ),
            Err(WalletError::EmptySeed)
        ));
        let err = TPrivKey::with_addr_type(
            &TSeed::new("phase13"),
            TNonce::new(0),
            &TPassphrase::EMPTY,
            KdfAlgo::Pbkdf2,
            AddrType::Native,
        )
        .expect_err("pbkdf2 requires a passphrase");
        assert!(err.to_string().contains("passphrase required"));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn address_of_reencodes_variant_a_keys() {
        let seed = TSeed::new("phase13addressof");
        let key =
            TPrivKey::new(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc).unwrap();
        // Same type → the cached address.
        assert_eq!(key.address_of(AddrType::Legacy).unwrap(), key.get_address());
        // Cross-type encodings of the same key.
        let native = key.address_of(AddrType::Native).unwrap();
        let taproot = key.address_of(AddrType::Taproot).unwrap();
        assert!(native.as_str().starts_with("bc1q"));
        assert!(taproot.as_str().starts_with("bc1p"));
        // And they agree with the dedicated constructors (вариант A).
        let native_key = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(0),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Native,
        )
        .unwrap();
        assert_eq!(native, native_key.get_address());
    }

    #[ntest_timeout::timeout(180_000)]
    #[test]
    fn address_of_rejects_pbkdf2_cross_type() {
        let seed = TSeed::new("phase13guard");
        let pp = TPassphrase::new("phrase");
        let legacy = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(0),
            &pp,
            KdfAlgo::Pbkdf2,
            AddrType::Legacy,
        )
        .unwrap();
        let err = legacy
            .address_of(AddrType::Native)
            .expect_err("pbkdf2 keys are purpose-bound");
        assert!(err.to_string().contains("purpose-bound"), "{err}");
        assert!(err.to_string().contains("legacy"), "{err}");
        assert!(err.to_string().contains("native"), "{err}");
        // Own type is always fine.
        assert_eq!(
            legacy.address_of(AddrType::Legacy).unwrap(),
            legacy.get_address()
        );
    }

    #[ntest_timeout::timeout(180_000)]
    #[test]
    fn nonce_address_forms_pbkdf2_yields_three_keys() {
        let seed = TSeed::new("phase13forms");
        let pp = TPassphrase::new("phrase");
        let forms = nonce_address_forms(&seed, TNonce::new(0), &pp, KdfAlgo::Pbkdf2).unwrap();
        assert_eq!(forms.len(), 3);
        assert_eq!(forms[0].addr_type, AddrType::Legacy);
        assert_eq!(forms[1].addr_type, AddrType::Native);
        assert_eq!(forms[2].addr_type, AddrType::Taproot);
        // Distinct keys per form.
        assert_ne!(
            forms[0].privkey.get_privwif(),
            forms[1].privkey.get_privwif()
        );
        assert_ne!(
            forms[1].privkey.get_privwif(),
            forms[2].privkey.get_privwif()
        );
        // Addresses match the forms.
        assert!(forms[0].address.as_str().starts_with('1'));
        assert!(forms[1].address.as_str().starts_with("bc1q"));
        assert!(forms[2].address.as_str().starts_with("bc1p"));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn nonce_address_forms_variant_a_yields_one_key_three_encodings() {
        let seed = TSeed::new("phase13formsa");
        let forms = nonce_address_forms(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc)
            .unwrap();
        assert_eq!(forms.len(), 3);
        // Same WIF everywhere; per-form encodings; each form key's own
        // address matches the form address (the cached network calls
        // must query per-form addresses).
        assert_eq!(
            forms[0].privkey.get_privwif(),
            forms[1].privkey.get_privwif()
        );
        for (i, prefix) in ["1", "bc1q", "bc1p"].iter().enumerate() {
            assert!(forms[i].address.as_str().starts_with(prefix));
            assert_eq!(forms[i].privkey.get_address(), forms[i].address);
        }
    }

    // --- Phase 13 stage 2: make_lock_script_for_address dispatch ------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_lock_script_dispatches_segwit_forms() {
        let seed = TSeed::new("phase13dispatch");
        let key =
            TPrivKey::new(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc).unwrap();
        let pubkey = privkey_to_pubkey(&key.privkey);
        let hash = crate::address::hash160_pubkey(&pubkey);

        // bc1q → 22-byte P2WPKH script `00 14 <hash>`.
        let native = key.address_of(AddrType::Native).unwrap();
        let script = make_lock_script_for_address(&native).unwrap();
        assert_eq!(script, make_p2wpkh_lock_script(&hash).to_vec());

        // bc1p → 34-byte P2TR script `51 20 <output key>`.
        let taproot = key.address_of(AddrType::Taproot).unwrap();
        let script = make_lock_script_for_address(&taproot).unwrap();
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&pubkey[1..33]);
        let output_key = crate::address::taproot_output_key(&xonly).unwrap();
        assert_eq!(script, make_p2tr_lock_script(&output_key).to_vec());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_lock_script_short_strings_take_the_base58_path() {
        // Strings shorter than the `bc1` prefix cannot be SegWit: the
        // length gate must take its false edge and hand the string to
        // the base58check decoder (which rejects it).
        let err = make_lock_script_for_address(&TAddress::new("1K"))
            .expect_err("not a valid base58 address either");
        assert!(matches!(err, WalletError::AddressDecode(_)));
        let err = make_lock_script_for_address(&TAddress::new("bc"))
            .expect_err("'bc' alone is not an address");
        assert!(matches!(err, WalletError::AddressDecode(_)));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_lock_script_accepts_uppercase_bech32() {
        // BIP-173: decoders MUST accept all-uppercase; the `bc1`
        // prefix check is case-insensitive and the decoder
        // normalises before checksumming.
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let upper = TAddress::new(addr.to_uppercase());
        let script = make_lock_script_for_address(&upper).unwrap();
        assert_eq!(script.len(), 22);
        assert_eq!(&script[..2], &[0x00, 0x14]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn make_lock_script_rejects_broken_segwit_addresses() {
        // Uppercase is fine for the prefix check but the fixture below
        // is a malformed bech32 string (bad checksum).
        let err = make_lock_script_for_address(&TAddress::new(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        ))
        .expect_err("bad checksum");
        assert!(matches!(err, WalletError::AddressDecode(_)));

        // A valid bech32 string but the wrong HRP.
        let err = make_lock_script_for_address(&TAddress::new(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        ))
        .expect_err("testnet HRP rejected");
        assert!(matches!(err, WalletError::AddressDecode(_)));

        // P2WSH shape: out of scope at Phase 13, unlocked by the
        // v0.3 multisig surface — the lock script is the canonical
        // `00 20 ‖ <32>` witness script whose program round-trips
        // through the dedicated decoder (the BIP-173 P2WSH vector
        // address).
        let lock = make_lock_script_for_address(&TAddress::new(
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
        ))
        .expect("P2WSH lock scripts build since v0.3");
        assert_eq!(lock.len(), 34);
        assert_eq!(&lock[..2], &[0x00, 0x20]);
        let program = crate::address::decode_p2wsh_address(
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
        )
        .expect("the vector address decodes as P2WSH");
        assert_eq!(lock[2..], program);
    }

    // --- Phase 13 stage 2: UTXO validation -----------------------------

    fn p2wpkh_utxo(hash: &[u8; 20], amount: u64) -> Utxo {
        Utxo {
            txid: [0xcd; 32],
            vout: 0,
            amount,
            script_pubkey: crate::script::make_p2wpkh_lock_script(hash).to_vec(),
            confirmations: 6,
        }
    }

    fn p2tr_utxo(output_key: &[u8; 32], amount: u64) -> Utxo {
        Utxo {
            txid: [0xcd; 32],
            vout: 1,
            amount,
            script_pubkey: crate::script::make_p2tr_lock_script(output_key).to_vec(),
            confirmations: 6,
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_utxo_script_accepts_segwit_forms() {
        let (pk, hash) = fixture();
        assert!(validate_utxo_script(&make_p2wpkh_lock_script(&hash)).is_ok());
        // A real curve point: derive it from the fixture key.
        let pubkey = privkey_to_pubkey(&pk.privkey);
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&pubkey[1..33]);
        let key = crate::address::taproot_output_key(&xonly).unwrap();
        assert!(validate_utxo_script(&make_p2tr_lock_script(&key)).is_ok());
        // v0.3: the canonical P2WSH shape (the quorum address UTXOs)
        // is representable.
        assert!(validate_utxo_script(&crate::script::make_p2wsh_lock_script(&[0xab; 32])).is_ok());
        // A 0x00-starting 34-byte blob that is NOT `00 20 …` fails.
        let mut broken = vec![0x00u8, 0x1f];
        broken.extend_from_slice(&[0xab; 32]);
        assert!(matches!(
            validate_utxo_script(&broken),
            Err(WalletError::UnsupportedUtxoScript)
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_utxo_script_rejects_broken_segwit_shapes() {
        // 22 bytes with a non-zero witness version.
        let mut bad = make_p2wpkh_lock_script(&[0u8; 20]);
        bad[0] = 0x51;
        assert!(matches!(
            validate_utxo_script(&bad),
            Err(WalletError::UnsupportedUtxoScript)
        ));
        // 22 bytes with the wrong push opcode.
        let mut bad = make_p2wpkh_lock_script(&[0u8; 20]);
        bad[1] = 0x15;
        assert!(matches!(
            validate_utxo_script(&bad),
            Err(WalletError::UnsupportedUtxoScript)
        ));
        // 34 bytes with a non-OP_1 version.
        let mut bad = make_p2tr_lock_script(&[0u8; 32]);
        bad[0] = 0x52;
        assert!(matches!(
            validate_utxo_script(&bad),
            Err(WalletError::UnsupportedUtxoScript)
        ));
        // 34 bytes with the wrong push opcode.
        let mut bad = make_p2tr_lock_script(&[0u8; 32]);
        bad[1] = 0x21;
        assert!(matches!(
            validate_utxo_script(&bad),
            Err(WalletError::UnsupportedUtxoScript)
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn build_vin_accepts_p2wpkh_and_p2tr_and_fills_spend_context() {
        let seed = TSeed::new("phase13vin");
        let key =
            TPrivKey::new(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc).unwrap();
        let pubkey = privkey_to_pubkey(&key.privkey);
        let hash = crate::address::hash160_pubkey(&pubkey);
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&pubkey[1..33]);
        let output_key = crate::address::taproot_output_key(&xonly).unwrap();

        let source = Source {
            privkey: key,
            unspent: vec![p2wpkh_utxo(&hash, 700), p2tr_utxo(&output_key, 900)],
        };
        let (vin, in_amount, signers, spend) = build_vin(&[source]).unwrap();
        assert_eq!(vin.len(), 2);
        assert_eq!(in_amount, 1600);
        assert_eq!(signers.len(), 2);
        // The UTXO scriptPubKey rides in TxIn.script so
        // `sign_segwit` can dispatch the scheme per input.
        assert_eq!(
            vin[0].script,
            crate::script::make_p2wpkh_lock_script(&hash).to_vec()
        );
        assert_eq!(vin[1].script, make_p2tr_lock_script(&output_key).to_vec());
        // SpendContext is parallel to vin.
        assert_eq!(spend.inputs.len(), 2);
        assert_eq!(spend.inputs[0].amount, 700);
        assert_eq!(spend.inputs[0].script_pubkey, vin[0].script);
        assert_eq!(spend.inputs[1].amount, 900);
        assert_eq!(spend.inputs[1].script_pubkey, vin[1].script);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn build_vin_rejects_foreign_segwit_outputs() {
        let seed = TSeed::new("phase13foreign");
        let key =
            TPrivKey::new(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc).unwrap();
        // A P2WPKH output committed to a different pubkey hash.
        let foreign_hash = [0xeeu8; 20];
        let source = Source {
            privkey: key.clone(),
            unspent: vec![p2wpkh_utxo(&foreign_hash, 100)],
        };
        let err = build_vin(&[source]).unwrap_err();
        assert!(matches!(err, WalletError::UnknownPubkeyRequired { .. }));

        // A P2TR output committed to a different internal key.
        let foreign_xonly = [0x22u8; 32];
        let foreign_key = crate::address::taproot_output_key(&foreign_xonly).unwrap();
        let source = Source {
            privkey: key,
            unspent: vec![p2tr_utxo(&foreign_key, 100)],
        };
        let err = build_vin(&[source]).unwrap_err();
        assert!(matches!(err, WalletError::UnknownPubkeyRequired { .. }));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn build_vin_rejects_p2sh_utxo() {
        let (pk, _) = fixture();
        let source = Source {
            privkey: pk,
            unspent: vec![Utxo {
                txid: [0xab; 32],
                vout: 0,
                amount: 1000,
                script_pubkey: make_p2sh_lock_script(&[0x33u8; 20]).to_vec(),
                confirmations: 6,
            }],
        };
        let err = build_vin(&[source]).unwrap_err();
        assert!(matches!(err, WalletError::UnsupportedUtxoScript));
    }

    // --- Phase 13 stage 2: witness transactions & vsize fee loop -------

    /// Native-form source fixture: one P2WPKH UTXO owned by the
    /// variant-A native key.
    fn native_source_fixture(amount: u64) -> (TSeed, Source, TAddress) {
        let seed = TSeed::new("phase13wit");
        let key = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(0),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Native,
        )
        .unwrap();
        let pubkey = privkey_to_pubkey(&key.privkey);
        let hash = crate::address::hash160_pubkey(&pubkey);
        let address = key.get_address();
        (
            seed,
            Source {
                privkey: key,
                unspent: vec![p2wpkh_utxo(&hash, amount)],
            },
            address,
        )
    }

    fn taproot_dest() -> TAddress {
        let seed = TSeed::new("phase13witdst");
        let key = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(0),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Taproot,
        )
        .unwrap();
        key.get_address()
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn witness_tx_is_built_signed_and_sized_via_vsize() {
        let (_, source, src_addr) = native_source_fixture(200_000);
        let pubkey = privkey_to_pubkey(&source.privkey.privkey);
        let sources = vec![source];
        let dst = taproot_dest();
        // Drain: single P2TR output, no cashback output.
        let vout = make_vout(
            &src_addr,
            &dst,
            TSatoshi::new(200_000),
            None,
            TSatoshi::new(1000),
        )
        .unwrap();
        let (vin, in_amount, signers, spend) = build_vin(&sources).unwrap();
        assert_eq!(in_amount, 200_000);
        let tx = Transaction {
            version: 2,
            vin,
            vout: vout.vout,
            locktime: 0,
        };
        let stx = tx.sign_segwit(&signers, Some(&spend)).unwrap();
        // Witness stack of a P2WPKH input: [DER sig ‖ 0x01, pubkey33];
        // scriptSig is emptied.
        assert!(stx.has_witness());
        assert_eq!(stx.vin[0].witness.len(), 2);
        assert_eq!(stx.vin[0].witness[1], pubkey.to_vec());
        assert!(stx.vin[0].script.is_empty());
        // Wire ≠ stripped; the txid ignores the witness.
        assert_ne!(stx.serialize_wire(), stx.serialize_stripped());
        assert_ne!(stx.wtxid(), stx.id());
        // The witness discount is visible: vsize bills the witness
        // bytes at 1/4, so vsize < total (wire) bytes.
        assert!(stx.vsize() < stx.serialize_wire().len());
        assert!(stx.vsize() >= stx.serialize_stripped().len());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn witness_tx_witness_structure() {
        let (_, source, _addr) = native_source_fixture(100_000);
        let dst = taproot_dest();
        let (vin, _in, signers, spend) = build_vin(&[source]).unwrap();
        let tx = Transaction {
            version: 2,
            vin,
            vout: vec![TxOut {
                amount: 50_000,
                script: make_lock_script_for_address(&dst).unwrap(),
            }],
            locktime: 0,
        };
        let stx = tx.sign_segwit(&signers, Some(&spend)).unwrap();
        // 72/73-byte DER signature + the 33-byte compressed pubkey.
        assert!(stx.vin[0].witness[0].len() > 64);
        assert_eq!(stx.vin[0].witness[1].len(), 33);
    }

    #[tokio::test]
    async fn fee_loop_on_witness_tx_bills_vsize_not_bytes() {
        let (seed, source, src_addr) = native_source_fixture(500_000);
        let backend = mock_backend();
        let wallet = Wallet::from_privkeys(
            seed,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Native,
            backend,
            vec![source.privkey.clone()],
        );
        let dst = taproot_dest();
        let result = wallet
            .make_transaction(
                &dst,
                Some(TSatoshi::new(250_000)),
                TSatoshi::new(1000),
                TSatoshi::new(0), // fee loop
                0,
                Some(vec![source]),
                Some(src_addr),
            )
            .await
            .unwrap();
        // The fee must equal vsize · feekb / 1000 of the final
        // (fixed-point) transaction — the vsize fee loop contract.
        let vsize = result.tx.vsize();
        assert_eq!(result.fee.get(), vsize as u64 * 1000 / 1000);
        // And the signed tx carries a witness (the CLI will broadcast
        // the wire layout).
        assert!(result.tx.has_witness());
        assert!(result.tx.serialize_wire().len() > result.tx.serialize_stripped().len());
    }

    #[test]
    fn backend_accessor_returns_the_constructed_backend() {
        // `backend()` is the public read-back of the network backend
        // injected at construction (UniFFI keeps a handle on it); pin
        // the identity, not just "some backend".
        let (seed, _source, _src_addr) = native_source_fixture(500_000);
        let backend = mock_backend();
        let wallet = Wallet::from_privkeys(
            seed,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Native,
            backend.clone(),
            Vec::new(),
        );
        let constructed: std::sync::Arc<dyn crate::net::NetworkBackend> = backend;
        assert!(std::sync::Arc::ptr_eq(&constructed, wallet.backend()));
    }

    #[tokio::test]
    async fn legacy_only_tx_wire_equals_stripped() {
        // v0.1 compatibility: no witness → wire == stripped, vsize ==
        // bytes, so the vsize fee loop reproduces legacy decisions.
        let (pk, hash) = fixture();
        let dst = {
            let seed_b = TSeed::new("phase3test_other");
            TPrivKey::new(&seed_b, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc)
                .unwrap()
                .get_address()
        };
        let sources = vec![Source {
            privkey: pk,
            unspent: vec![utxo_for(&hash, 500_000, 6)],
        }];
        let (vin, in_amount, signers, spend) = build_vin(&sources).unwrap();
        let tx = Transaction {
            version: 2,
            vin,
            vout: vec![TxOut {
                amount: in_amount - 1000,
                script: make_lock_script_for_address(&dst).unwrap(),
            }],
            locktime: 0,
        };
        let stx = tx.sign_segwit(&signers, Some(&spend)).unwrap();
        assert!(!stx.has_witness());
        assert_eq!(stx.serialize_wire(), stx.serialize_stripped());
        assert_eq!(stx.vsize(), stx.serialize_stripped().len());
    }

    // --- Phase 13 stage 2: is_dust segwit arms -------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn is_dust_segwit_thresholds() {
        let (pk, hash) = fixture();
        let p2wpkh = make_p2wpkh_lock_script(&hash);
        assert!(is_dust(DUST_THRESHOLD_P2WPKH - 1, &p2wpkh));
        assert!(!is_dust(DUST_THRESHOLD_P2WPKH, &p2wpkh));
        let pubkey = privkey_to_pubkey(&pk.privkey);
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&pubkey[1..33]);
        let key = crate::address::taproot_output_key(&xonly).unwrap();
        let p2tr = make_p2tr_lock_script(&key);
        assert!(is_dust(DUST_THRESHOLD_P2TR - 1, &p2tr));
        assert!(!is_dust(DUST_THRESHOLD_P2TR, &p2tr));
        // v0.3: the P2WSH arm bills at its own (numerically equal)
        // threshold.
        let p2wsh = crate::script::make_p2wsh_lock_script(&[0xab; 32]);
        assert!(is_dust(DUST_THRESHOLD_P2WSH - 1, &p2wsh));
        assert!(!is_dust(DUST_THRESHOLD_P2WSH, &p2wsh));
        // The match is length-based (the wallet only ever produces
        // canonical shapes): a 22/34-byte blob is billed at the
        // segwit threshold regardless of its content.
        assert!(is_dust(0, &[0u8; 22]));
        assert!(is_dust(0, &[0u8; 34]));
    }

    // --- Phase 13 stage 2: multi-form scan ------------------------------

    use crate::script::{make_p2tr_lock_script, make_p2wpkh_lock_script};

    /// Extend the mock: mark `(nonce, form)` used and give it a UTXO
    /// of the matching script shape.
    fn mock_with_form_utxo(
        m: &std::sync::Arc<WalletMockBackend>,
        seed_str: &str,
        nonce: u32,
        form: AddrType,
        amount: u64,
    ) {
        let key = TPrivKey::with_addr_type(
            &TSeed::new(seed_str),
            TNonce::new(nonce),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            form,
        )
        .unwrap();
        let address = key.get_address();
        let pubkey = privkey_to_pubkey(&key.privkey);
        let script = match form {
            AddrType::Legacy => make_p2pkh_lock_script(&crate::address::hash160_pubkey(&pubkey)),
            AddrType::Native => {
                make_p2wpkh_lock_script(&crate::address::hash160_pubkey(&pubkey)).to_vec()
            }
            AddrType::Taproot => {
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&pubkey[1..33]);
                make_p2tr_lock_script(&crate::address::taproot_output_key(&xonly).unwrap()).to_vec()
            }
        };
        m.info.lock().unwrap().insert(
            address.as_str().to_string(),
            AddressInfo {
                total_received: amount,
                final_balance: amount,
                n_tx: 1,
            },
        );
        m.unspent.lock().unwrap().insert(
            address.as_str().to_string(),
            vec![Utxo {
                txid: [form.purpose() as u8; 32],
                vout: 0,
                amount,
                script_pubkey: script,
                confirmations: 6,
            }],
        );
    }

    #[tokio::test]
    async fn scan_finds_utxos_in_every_form() {
        let m = mock_backend();
        let seed_str = "phase13scanforms";
        let (seed, _) = seed_and_addr(seed_str);
        // Nonce 0: UTXOs in the native and taproot forms only; the
        // legacy form is used-but-empty. Nonce 1: unused → gap.
        mock_with_form_utxo(&m, seed_str, 0, AddrType::Legacy, 0);
        mock_with_form_utxo(&m, seed_str, 0, AddrType::Native, 1000);
        mock_with_form_utxo(&m, seed_str, 0, AddrType::Taproot, 2000);
        let (sources, cashback) = scan_all(
            &seed,
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Native,
            m.as_ref(),
            6,
        )
        .await
        .unwrap();
        assert_eq!(sources.len(), 2, "one source per contributing form");
        assert_eq!(sources[0].privkey.addr_type, AddrType::Native);
        assert_eq!(sources[1].privkey.addr_type, AddrType::Taproot);
        // The form keys are the same secret (вариант A) but the UTXO
        // scripts match the forms.
        assert_eq!(sources[0].unspent[0].amount, 1000);
        assert_eq!(sources[1].unspent[0].amount, 2000);
        // Target not involved → gap-limit stop at nonce 1, cashback in
        // the wallet's receive form.
        assert_eq!(cashback, addr_native_for(seed_str, 1));
    }

    fn addr_native_for(seed_str: &str, nonce: u32) -> TAddress {
        TPrivKey::with_addr_type(
            &TSeed::new(seed_str),
            TNonce::new(nonce),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Native,
        )
        .unwrap()
        .get_address()
    }

    #[tokio::test]
    async fn scan_gap_rule_spans_forms() {
        let m = mock_backend();
        let seed_str = "phase13gapforms";
        let (seed, _) = seed_and_addr(seed_str);
        // Nonce 0 is used ONLY via its taproot form → the walk must
        // not stop there even though the legacy/native forms are
        // fresh. Nonce 1 is unused → gap.
        mock_with_form_utxo(&m, seed_str, 0, AddrType::Taproot, 500);
        let (sources, cashback) = scan_all(
            &seed,
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.as_ref(),
            6,
        )
        .await
        .unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].privkey.addr_type, AddrType::Taproot);
        // Cashback in the wallet's receive form (legacy here).
        assert_eq!(cashback, addr_for(seed_str, 1));
    }

    #[tokio::test]
    async fn scan_cashback_form_is_last_source_form() {
        let m = mock_backend();
        let seed_str = "phase13cashbackform";
        let (seed, _) = seed_and_addr(seed_str);
        // Nonce 0 contributes in the native form and meets the target;
        // cashback must be that (nonce, form) — NOT the wallet's
        // receive type (legacy) and NOT the gap nonce.
        mock_with_form_utxo(&m, seed_str, 0, AddrType::Native, 1000);
        let (sources, cashback) = scan_inputs_until(
            &seed,
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
            m.as_ref(),
            Some(TSatoshi::new(1000)),
            6,
        )
        .await
        .unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].privkey.addr_type, AddrType::Native);
        assert_eq!(cashback, addr_native_for(seed_str, 0));
    }

    #[tokio::test]
    async fn scan_cashback_gap_stop_uses_wallet_addr_type() {
        let m = mock_backend();
        let seed_str = "phase13gaptype";
        let (seed, _) = seed_and_addr(seed_str);
        // Nothing used → gap at nonce 0. The taproot wallet receives
        // its cashback address in the taproot encoding.
        let (sources, cashback) = scan_all(
            &seed,
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Taproot,
            m.as_ref(),
            6,
        )
        .await
        .unwrap();
        assert!(sources.is_empty());
        assert_eq!(cashback, {
            TPrivKey::with_addr_type(
                &TSeed::new(seed_str),
                TNonce::new(0),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                AddrType::Taproot,
            )
            .unwrap()
            .get_address()
        });
        assert!(cashback.as_str().starts_with("bc1p"));
    }

    #[tokio::test]
    async fn scan_skips_used_forms_without_utxos() {
        let m = mock_backend();
        let seed_str = "phase13empties";
        let (seed, _) = seed_and_addr(seed_str);
        // Nonce 0: legacy used-but-empty, native used with funds;
        // only the native form contributes.
        mock_with_form_utxo(&m, seed_str, 0, AddrType::Legacy, 0);
        mock_with_form_utxo(&m, seed_str, 0, AddrType::Native, 700);
        let (sources, _) = scan_all(
            &seed,
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Native,
            m.as_ref(),
            6,
        )
        .await
        .unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].unspent[0].amount, 700);
    }

    #[tokio::test]
    async fn scan_pbkdf2_walks_three_purpose_leaves() {
        let m = mock_backend();
        let seed_str = "phase13pbkdf2scan";
        let seed = TSeed::new(seed_str);
        let pp = TPassphrase::new("phrase");
        // Fund the native (m/84') leaf of nonce 0. For pbkdf2 every
        // form is a distinct key; the mock must mark exactly the
        // native-form address used.
        let key = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(0),
            &pp,
            KdfAlgo::Pbkdf2,
            AddrType::Native,
        )
        .unwrap();
        let address = key.get_address();
        let pubkey = privkey_to_pubkey(&key.privkey);
        let hash = crate::address::hash160_pubkey(&pubkey);
        m.info.lock().unwrap().insert(
            address.as_str().to_string(),
            AddressInfo {
                total_received: 900,
                final_balance: 900,
                n_tx: 1,
            },
        );
        m.unspent
            .lock()
            .unwrap()
            .insert(address.as_str().to_string(), vec![p2wpkh_utxo(&hash, 900)]);
        let (sources, cashback) =
            scan_all(&seed, &pp, KdfAlgo::Pbkdf2, AddrType::Native, m.as_ref(), 6)
                .await
                .unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].privkey.addr_type, AddrType::Native);
        // The spending key is the m/84' leaf — its WIF differs from
        // the m/44' leaf (purpose-bound keys).
        let legacy_key = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(0),
            &pp,
            KdfAlgo::Pbkdf2,
            AddrType::Legacy,
        )
        .unwrap();
        assert_ne!(sources[0].privkey.get_privwif(), legacy_key.get_privwif());
        assert_eq!(cashback, {
            TPrivKey::with_addr_type(
                &seed,
                TNonce::new(1),
                &pp,
                KdfAlgo::Pbkdf2,
                AddrType::Native,
            )
            .unwrap()
            .get_address()
        });
    }

    // --- Phase 13 stage 2: Wallet::new / from_privkeys with AddrType ---

    #[tokio::test]
    async fn wallet_new_with_native_type_yields_native_keys() {
        let m = mock_backend();
        let seed_str = "phase13walletnative";
        let seed = TSeed::new(seed_str);
        let w = Wallet::new(
            seed,
            TNonce::new(0),
            1,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Native,
            m.clone(),
        )
        .await
        .unwrap();
        assert_eq!(w.privkeys.len(), 1);
        assert!(w.privkeys[0].get_address().as_str().starts_with("bc1q"));
        assert_eq!(w.privkeys[0].addr_type, AddrType::Native);
        assert_eq!(w.addr_type(), AddrType::Native);
    }

    #[tokio::test]
    async fn wallet_new_gap_walk_spans_forms() {
        // The legacy form of nonce 0 is unused, but its native form is
        // used → Wallet::new must include the nonce.
        let m = mock_backend();
        let seed_str = "phase13walletgap";
        let seed = TSeed::new(seed_str);
        mock_with_form_utxo(&m, seed_str, 0, AddrType::Native, 300);
        let w = Wallet::new(
            seed,
            TNonce::new(0),
            0,
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Taproot,
            m.clone(),
        )
        .await
        .unwrap();
        assert_eq!(w.privkeys.len(), 1);
        assert_eq!(w.privkeys[0].nonce.get(), 0);
        assert_eq!(w.privkeys[0].addr_type, AddrType::Taproot);
        assert!(w.privkeys[0].get_address().as_str().starts_with("bc1p"));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn wallet_accessor_round_trip_addr_type() {
        // from_privkeys carries the addr_type accessor.
        let (pk, _) = fixture();
        let w = Wallet::from_privkeys(
            TSeed::new("phase13accessor"),
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Taproot,
            mock_backend(),
            vec![pk],
        );
        assert_eq!(w.addr_type(), AddrType::Taproot);
    }

    // --- proptests: vsize fee-loop invariants (TODO.md item (c)) -------

    use proptest::prelude::*;

    /// Frozen dust threshold of an address form, naming the spec
    /// constants (546 P2PKH / 294 P2WPKH / 330 P2TR) explicitly in the
    /// property assertions. Mirrors the length dispatch of `is_dust`.
    fn form_dust_threshold(form: AddrType) -> u64 {
        match form {
            AddrType::Legacy => DUST_THRESHOLD_P2PKH,
            AddrType::Native => DUST_THRESHOLD_P2WPKH,
            AddrType::Taproot => DUST_THRESHOLD_P2TR,
        }
    }

    /// A UTXO of the given form owned by `key`, at a distinct outpoint.
    /// The `yubtc` KDF is вариант A — one secret, three encodings — so
    /// a single key owns P2PKH, P2WPKH and P2TR outputs alike.
    fn form_utxo(key: &TPrivKey, form: AddrType, idx: usize, amount: u64) -> Utxo {
        let pubkey = privkey_to_pubkey(&key.privkey);
        let script = match form {
            AddrType::Legacy => make_p2pkh_lock_script(&crate::address::hash160_pubkey(&pubkey)),
            AddrType::Native => {
                make_p2wpkh_lock_script(&crate::address::hash160_pubkey(&pubkey)).to_vec()
            }
            AddrType::Taproot => {
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&pubkey[1..33]);
                make_p2tr_lock_script(&crate::address::taproot_output_key(&xonly).expect(
                    "TapTweak infinity (p ≈ 2^-128) for a valid curve point: documented invariant",
                ))
                .to_vec()
            }
        };
        Utxo {
            txid: [0xde; 32],
            vout: idx as u32,
            amount,
            script_pubkey: script,
            confirmations: 6,
        }
    }

    /// Everything the fee-loop properties need: one funded source
    /// (single variant-A key, UTXOs in arbitrary forms), the
    /// cashback/destination addresses and the total input sum.
    struct FeeLoopFixture {
        sources: Vec<Source>,
        in_amount: u64,
        src_addr: TAddress,
        dst: TAddress,
        cb_form: AddrType,
    }

    /// Build the fixture: `counts` UTXOs per form (owned by the one
    /// variant-A key), amounts drawn round-robin from `amounts`.
    fn fee_loop_fixture(
        counts: [(AddrType, usize); 3],
        amounts: &[u64],
        cb_form: AddrType,
        dst_form: AddrType,
    ) -> FeeLoopFixture {
        let key = TPrivKey::with_addr_type(
            &TSeed::new("proptestfeeloop"),
            TNonce::new(0),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            AddrType::Legacy,
        )
        .expect("fixed seed derives a legacy key");
        let mut unspent = Vec::new();
        let mut idx = 0usize;
        for (form, count) in counts {
            for _ in 0..count {
                unspent.push(form_utxo(&key, form, idx, amounts[idx % amounts.len()]));
                idx += 1;
            }
        }
        let in_amount = unspent.iter().map(|u| u.amount).sum();
        let sources = vec![Source {
            privkey: key,
            unspent,
        }];
        let src_addr = sources[0]
            .privkey
            .address_of(cb_form)
            .expect("variant-A keys re-encode freely");
        let dst = TPrivKey::with_addr_type(
            &TSeed::new("proptestfeedst"),
            TNonce::new(0),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            dst_form,
        )
        .expect("fixed seed derives a key")
        .get_address();
        FeeLoopFixture {
            sources,
            in_amount,
            src_addr,
            dst,
            cb_form,
        }
    }

    /// vsize of the signed tx the fee loop sizes its candidates with,
    /// measured on a probe built at fee = 0 with the same output count
    /// as the converged iteration. Satoshi amounts do not affect
    /// serialized sizes; only ECDSA signature lengths can (see the
    /// jitter bound in the mixed-input property).
    fn probe_vsize(fixture: &FeeLoopFixture, drain: bool) -> usize {
        let (vin, _in_amount, signers, spend) =
            build_vin(&fixture.sources).expect("every UTXO is owned by the source key");
        let probe_vout = make_vout(
            &fixture.src_addr,
            &fixture.dst,
            TSatoshi::new(fixture.in_amount),
            if drain {
                None
            } else {
                Some(TSatoshi::new(fixture.in_amount / 2))
            },
            TSatoshi::ZERO,
        )
        .expect("probe vout at fee 0 is feasible");
        Transaction {
            version: 2,
            vin,
            vout: probe_vout.vout,
            locktime: 0,
        }
        .sign_segwit(&signers, Some(&spend))
        .expect("build_vin emits parallel signers and spend context")
        .vsize()
    }

    /// Run `make_transaction` through the fee loop (fee = 0) on a
    /// one-off current-thread tokio runtime — proptest bodies are sync.
    fn run_fee_loop(fixture: &FeeLoopFixture, amount: Option<TSatoshi>, feekb: u64) -> TxResult {
        let wallet = Wallet::from_privkeys(
            TSeed::new("proptestfeeloop"),
            TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            fixture.cb_form,
            mock_backend(),
            vec![fixture.sources[0].privkey.clone()],
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for the fee loop");
        rt.block_on(wallet.make_transaction(
            &fixture.dst,
            amount,
            TSatoshi::new(feekb),
            TSatoshi::ZERO, // fee = 0 → the fee loop runs
            0,
            Some(fixture.sources.clone()),
            Some(fixture.src_addr.clone()),
        ))
        .expect("conditioned inputs are feasible for the fee loop")
    }

    /// Output-side invariants shared by both fee-loop properties:
    /// selection sum − target − fee ≥ 0, the residue split exactly into
    /// (cashback ≥ its form's dust floor, amount), the output
    /// layout/scripts, every output at or above its form's frozen dust
    /// threshold (546/540/294/330), and the fee keyed on vsize, not
    /// wire bytes. The fee-vs-rate bound is property-specific and stays
    /// in the callers.
    #[allow(clippy::too_many_arguments)]
    fn assert_tx_outputs_above_dust(
        result: &TxResult,
        in_amount: u64,
        target: u64,
        drain: bool,
        cb_form: AddrType,
        dst_form: AddrType,
        src_addr: &TAddress,
        dst: &TAddress,
    ) -> proptest::test_runner::TestCaseResult {
        // Selection invariant: input sum − target − fee ≥ 0, and the
        // residue splits exactly into (cashback, amount).
        prop_assert!(in_amount >= target + result.fee.get());
        if drain {
            prop_assert_eq!(result.cashback.get(), 0);
            prop_assert_eq!(result.amount.get(), in_amount - result.fee.get());
        } else {
            prop_assert_eq!(result.cashback.get(), in_amount - target - result.fee.get());
            prop_assert_eq!(result.amount.get(), target);
            // Cashback ≥ dust (or absent, in the drain branch above).
            prop_assert!(result.cashback.get() >= form_dust_threshold(cb_form));
        }
        // Output layout: [cashback → src, amount → dst], or the single
        // drained output; amounts match the reported split.
        let dst_script = make_lock_script_for_address(dst).expect("destination lock script");
        if drain {
            prop_assert_eq!(result.tx.vout.len(), 1);
            prop_assert_eq!(&result.tx.vout[0].script, &dst_script);
            prop_assert_eq!(result.tx.vout[0].amount, result.amount.get());
            prop_assert!(!is_dust(
                result.tx.vout[0].amount,
                &result.tx.vout[0].script
            ));
            prop_assert!(result.tx.vout[0].amount >= form_dust_threshold(dst_form));
        } else {
            let src_script = make_lock_script_for_address(src_addr).expect("cashback lock script");
            prop_assert_eq!(result.tx.vout.len(), 2);
            prop_assert_eq!(&result.tx.vout[0].script, &src_script);
            prop_assert_eq!(&result.tx.vout[1].script, &dst_script);
            prop_assert_eq!(result.tx.vout[0].amount, result.cashback.get());
            prop_assert_eq!(result.tx.vout[1].amount, result.amount.get());
            for out in &result.tx.vout {
                prop_assert!(!is_dust(out.amount, &out.script));
            }
            prop_assert!(result.tx.vout[0].amount >= form_dust_threshold(cb_form));
            prop_assert!(result.tx.vout[1].amount >= form_dust_threshold(dst_form));
        }
        // Fee unit is vsize, not wire bytes (per spec): a witnessed tx
        // bills strictly below its byte length.
        let wire = result.tx.serialize_wire().len();
        prop_assert!(result.tx.vsize() <= wire);
        if result.tx.has_witness() {
            prop_assert!(result.tx.vsize() < wire);
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]

        // Exact fee identity (TODO (c)): with P2TR-only inputs every
        // signature is a fixed-width 64-byte Schnorr blob, so the tx
        // size is a pure function of the shape — the loop lands on the
        // fixed point after one step and the chosen candidate's fee is
        // exactly feerate · vsize of the built tx. Witnessed (vsize)
        // vs wire-byte charging is observable money: the byte-based
        // rate would cost strictly more.
        #[ntest_timeout::timeout(120000)]
        #[test]
        fn fee_loop_bills_exact_vsize_fee(
            n_taproot in 1usize..=3,
            amounts in proptest::collection::vec(10_000u64..=300_000, 3),
            feekb in 1000u64..=250_000,
            form_pair in 0u8..9,
            drain in any::<bool>(),
            cashback_extra in 0u64..=50_000,
        ) {
            let forms = [AddrType::Legacy, AddrType::Native, AddrType::Taproot];
            let cb_form = forms[usize::from(form_pair / 3)];
            let dst_form = forms[usize::from(form_pair % 3)];
            let fixture = fee_loop_fixture(
                [
                    (AddrType::Taproot, n_taproot),
                    (AddrType::Legacy, 0),
                    (AddrType::Native, 0),
                ],
                &amounts,
                cb_form,
                dst_form,
            );
            // Deterministic size: the probe vsize IS the fixed point.
            let vsize = probe_vsize(&fixture, drain);
            let fee = vsize as u64 * feekb / 1000;
            // Bound to feasible solutions (spec's fee/amount limits):
            // after the converged fee every output still clears its
            // form's dust floor.
            prop_assume!(fixture.in_amount > fee);
            let spendable = fixture.in_amount - fee;
            let (amount, target) = if drain {
                prop_assume!(spendable >= form_dust_threshold(dst_form));
                (None, spendable)
            } else {
                let cb = form_dust_threshold(cb_form) + cashback_extra;
                prop_assume!(spendable >= cb + form_dust_threshold(dst_form));
                (Some(TSatoshi::new(spendable - cb)), spendable - cb)
            };
            let result = run_fee_loop(&fixture, amount, feekb);
            // fee == feerate · vsize of the built tx, exactly: the
            // vsize-keyed loop converges on the branch-stable vsize and
            // the picker's rule 1 accepts the fixed-point entry
            // whenever feekb ≥ the 1 sat/vB relay floor.
            prop_assert_eq!(result.fee.get(), fee);
            prop_assert_eq!(
                result.fee.get(),
                (result.tx.vsize() as u64) * feekb / 1000
            );
            // The same rate on wire bytes would cost strictly more:
            // the witness discount is real money here.
            prop_assert!(
                result.fee.get()
                    < (result.tx.serialize_wire().len() as u64) * feekb / 1000
            );
            assert_tx_outputs_above_dust(
                &result,
                fixture.in_amount,
                target,
                drain,
                cb_form,
                dst_form,
                &fixture.src_addr,
                &fixture.dst,
            )?;
        }

        // Arbitrary input mix (legacy P2PKH + P2WPKH + P2TR, witness
        // and non-witness shapes side by side): ECDSA DER signatures
        // span 69..72 bytes, so the signed tx size jitters by a bounded
        // number of vbytes between loop iterations and the chosen fee
        // can be at most one (jittered) step stale. The guaranteed
        // invariants: the fee pays the user rate for the built tx's own
        // vsize (rule 1 — hence also the 1 sat/vB relay floor), stays
        // within the jitter bound, and every output clears its form's
        // dust floor.
        #[allow(clippy::too_many_arguments)]
        #[ntest_timeout::timeout(120000)]
        #[test]
        fn fee_loop_pays_rate_and_keeps_outputs_above_dust(
            n_legacy in 0usize..=2,
            n_native in 0usize..=2,
            n_taproot in 0usize..=2,
            amounts in proptest::collection::vec(10_000u64..=300_000, 6),
            feekb in 1000u64..=250_000,
            form_pair in 0u8..9,
            drain in any::<bool>(),
            cashback_extra in 0u64..=50_000,
        ) {
            prop_assume!(n_legacy + n_native + n_taproot >= 1);
            let forms = [AddrType::Legacy, AddrType::Native, AddrType::Taproot];
            let cb_form = forms[usize::from(form_pair / 3)];
            let dst_form = forms[usize::from(form_pair % 3)];
            let fixture = fee_loop_fixture(
                [
                    (AddrType::Legacy, n_legacy),
                    (AddrType::Native, n_native),
                    (AddrType::Taproot, n_taproot),
                ],
                &amounts,
                cb_form,
                dst_form,
            );
            // Conservative vsize jitter bound: a DER signature moves
            // ≤ 3 bytes per input (69..72 + the sighash byte), so the
            // weight moves ≤ 9·n and the vsize ≤ ⌈9·n / 4⌉ < 3·n + 1.
            let n_in = (n_legacy + n_native + n_taproot) as u64;
            let jitter = 3 * n_in + 1;
            let fee_bound =
                (probe_vsize(&fixture, drain) as u64 + jitter) * feekb / 1000;
            prop_assume!(fixture.in_amount > fee_bound);
            let spendable = fixture.in_amount - fee_bound;
            let (amount, target) = if drain {
                prop_assume!(spendable >= form_dust_threshold(dst_form));
                (None, spendable)
            } else {
                let cb = form_dust_threshold(cb_form) + cashback_extra;
                prop_assume!(spendable >= cb + form_dust_threshold(dst_form));
                (Some(TSatoshi::new(spendable - cb)), spendable - cb)
            };
            let result = run_fee_loop(&fixture, amount, feekb);
            // Pays the user rate for its own vsize (rule 1); the relay
            // floor follows (feekb ≥ 1000 ⇔ fee ≥ vsize). At most one
            // jittered step stale.
            prop_assert!(
                result.fee.get() >= (result.tx.vsize() as u64) * feekb / 1000
            );
            prop_assert!(result.fee.get() >= result.tx.vsize() as u64);
            prop_assert!(result.fee.get() <= fee_bound);
            assert_tx_outputs_above_dust(
                &result,
                fixture.in_amount,
                target,
                drain,
                cb_form,
                dst_form,
                &fixture.src_addr,
                &fixture.dst,
            )?;
        }
    }

    // --- Multi-sig (Phase 15) -----------------------------------------

    /// Fixture seed for the multisig wallet tests.
    const MS_WALLET_SEED: &str = "phase15wallet";

    fn ms_wallet_key(nonce: u32) -> SigningKey {
        seed2privkey_with_purpose(
            &TSeed::new(MS_WALLET_SEED),
            TNonce::new(nonce),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
            PURPOSE_LEGACY,
        )
        .expect("fixture derives")
    }

    fn ms_wallet_pubkey(nonce: u32) -> [u8; 33] {
        privkey_to_pubkey(&ms_wallet_key(nonce))
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_address_builds_sorted_redeem_and_p2sh_address() {
        let keys = [
            ms_wallet_pubkey(2),
            ms_wallet_pubkey(0),
            ms_wallet_pubkey(1),
        ];
        let (addr, redeem) = ms_create_address(3, 2, &keys, MsForm::P2sh).expect("valid quorum");
        // The redeem is canonical, sorted, and hashes to the address.
        let (m, script_keys) = crate::script::extract_multisig_quorum(&redeem).expect("canonical");
        assert_eq!(m, 2);
        // Script order is the BIP-67 byte sort of the three keys.
        let mut sorted = vec![
            ms_wallet_pubkey(0),
            ms_wallet_pubkey(1),
            ms_wallet_pubkey(2),
        ];
        sorted.sort();
        assert_eq!(script_keys, sorted);
        assert_eq!(addr, redeem_to_p2sh_address(&redeem));
        // The address decodes as P2SH carrying hash160(redeem).
        let (version, hash) = decode_address(&addr).expect("mainnet base58check");
        assert_eq!(version, PREFIX_P2SH);
        assert_eq!(hash, crate::address::hash160_script(&redeem));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_address_validation_errors() {
        let keys = [ms_wallet_pubkey(0), ms_wallet_pubkey(1)];
        // Count mismatch.
        assert_eq!(
            ms_create_address(3, 2, &keys, MsForm::P2sh),
            Err(MsError::KeyCountMismatch(3, 2))
        );
        assert_eq!(
            ms_create_address(1, 1, &keys, MsForm::P2sh),
            Err(MsError::KeyCountMismatch(1, 2))
        );
        // Bounds: m = 0, m > n, n > 15.
        assert_eq!(
            ms_create_address(2, 0, &keys, MsForm::P2sh),
            Err(MsError::QuorumBounds)
        );
        assert_eq!(
            ms_create_address(2, 3, &keys, MsForm::P2sh),
            Err(MsError::QuorumBounds)
        );
        let sixteen: Vec<[u8; 33]> = (0..16)
            .map(|i| {
                let mut k = [0x02u8; 33];
                k[32] = i as u8 + 1;
                k
            })
            .collect();
        assert_eq!(
            ms_create_address(16, 16, &sixteen, MsForm::P2sh),
            Err(MsError::QuorumBounds)
        );
        // Duplicates.
        assert_eq!(
            ms_create_address(
                2,
                1,
                &[ms_wallet_pubkey(0), ms_wallet_pubkey(0)],
                MsForm::P2sh
            ),
            Err(MsError::DuplicateKey)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_address_is_invariant_under_key_permutation_many_orders() {
        // R-MS-4 pin: the same (N, M, set) in any argument order gives
        // the same address and redeem — swept over deterministic
        // shuffles (factorial coverage of the 4-key fixture = 24
        // permutations, plus reversal cases).
        let keys = [
            ms_wallet_pubkey(0),
            ms_wallet_pubkey(1),
            ms_wallet_pubkey(2),
            ms_wallet_pubkey(3),
        ];
        let (canon_addr, canon_redeem) = ms_create_address(4, 3, &keys, MsForm::P2sh).unwrap();
        let mut order = keys.to_vec();
        // Deterministic LCG shuffle over 97 distinct orders.
        let mut state: u64 = 0x9e3779b97f4a7c15;
        for _ in 0..97 {
            for i in (1..order.len()).rev() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let j = (state >> 33) as usize % (i + 1);
                order.swap(i, j);
            }
            let (addr, redeem) = ms_create_address(4, 3, &order, MsForm::P2sh).unwrap();
            assert_eq!(addr, canon_addr);
            assert_eq!(redeem, canon_redeem);
        }
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(1000))]

        /// R-MS-4 property (≥ 1000 cases): any permutation of the
        /// quorum key arguments yields the identical address and
        /// redeem script.
        #[test]
        fn prop_ms_address_invariant_under_argument_permutation(
            order in proptest::collection::vec(any::<u64>(), 4),
        ) {
            let keys = [
                ms_wallet_pubkey(0),
                ms_wallet_pubkey(1),
                ms_wallet_pubkey(2),
                ms_wallet_pubkey(3),
            ];
            // Permute by sorting on the generated priorities (a total
            // order almost surely — equal priorities just fall through
            // to the stable sort, still a permutation).
            let mut indexed: Vec<(u64, [u8; 33])> =
                order.into_iter().zip(keys).collect();
            indexed.sort_by_key(|(p, _)| *p);
            let permuted: Vec<[u8; 33]> =
                indexed.into_iter().map(|(_, k)| k).collect();
            let (addr, redeem) = ms_create_address(4, 3, &permuted, MsForm::P2sh).unwrap();
            let (canon_addr, canon_redeem) =
                ms_create_address(4, 3, &keys, MsForm::P2sh).unwrap();
            prop_assert_eq!(addr, canon_addr);
            prop_assert_eq!(redeem, canon_redeem);
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_own_key_is_the_legacy_form_at_the_nonce() {
        // The own key equals `TPrivKey` legacy derivation (`dumpprivkey
        // -n X` — R-MS-6/ОВ-10), for the cascade KDF…
        let seed = TSeed::new("own-key-form");
        let own = ms_own_pubkey(&seed, TNonce::new(4), &TPassphrase::EMPTY, KdfAlgo::Yubtc)
            .expect("derives");
        let pk = TPrivKey::new(&seed, TNonce::new(4), &TPassphrase::EMPTY, KdfAlgo::Yubtc)
            .expect("derives");
        assert_eq!(own, privkey_to_pubkey(&pk.privkey));
    }

    #[ntest_timeout::timeout(180_000)]
    #[test]
    fn ms_own_key_pbkdf2_uses_the_legacy_leaf() {
        // …and for pbkdf2 the m/44' leaf (BIP-44 legacy), not the
        // native/taproot ones.
        use crate::kdf::PURPOSE_NATIVE;
        let seed = TSeed::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon about",
        );
        let passphrase = TPassphrase::new("x");
        let own =
            ms_own_pubkey(&seed, TNonce::new(0), &passphrase, KdfAlgo::Pbkdf2).expect("derives");
        let legacy = TPrivKey::with_addr_type(
            &seed,
            TNonce::new(0),
            &passphrase,
            KdfAlgo::Pbkdf2,
            AddrType::Legacy,
        )
        .expect("derives");
        assert_eq!(own, privkey_to_pubkey(&legacy.privkey));
        let native = seed2privkey_with_purpose(
            &seed,
            TNonce::new(0),
            &passphrase,
            KdfAlgo::Pbkdf2,
            PURPOSE_NATIVE,
        )
        .expect("derives");
        assert_ne!(own, privkey_to_pubkey(&native));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_wif_own_key_accepts_only_the_derived_secret() {
        let derived = ms_wallet_key(0);
        let wif = privkey_to_wif(&derived);
        assert_eq!(
            ms_wif_own_key(&derived, &wif).expect("own WIF"),
            ms_wallet_pubkey(0)
        );
        // A foreign (valid) WIF — different key — is rejected.
        let foreign = privkey_to_wif(&ms_wallet_key(9));
        assert_eq!(ms_wif_own_key(&derived, &foreign), Err(MsError::ForeignWif));
        // Garbage is rejected.
        assert_eq!(
            ms_wif_own_key(&derived, "not-a-wif"),
            Err(MsError::ForeignWif)
        );
        assert_eq!(ms_wif_own_key(&derived, ""), Err(MsError::ForeignWif));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_select_utxos_takes_the_smallest_reaching_prefix() {
        let utxos = vec![
            Utxo {
                txid: [1; 32],
                vout: 0,
                amount: 30_000,
                script_pubkey: vec![0xa9],
                confirmations: 6,
            },
            Utxo {
                txid: [2; 32],
                vout: 0,
                amount: 20_000,
                script_pubkey: vec![0xa9],
                confirmations: 6,
            },
            Utxo {
                txid: [3; 32],
                vout: 0,
                amount: 50_000,
                script_pubkey: vec![0xa9],
                confirmations: 6,
            },
        ];
        // The first two UTXOs cover 50_000 — the walk stops there.
        let picked = ms_select_utxos(&utxos, Some(TSatoshi::new(50_000)));
        assert_eq!(picked.len(), 2);
        assert_eq!(picked.iter().map(|u| u.amount).sum::<u64>(), 50_000);
        // Unreachable target selects everything.
        let all = ms_select_utxos(&utxos, Some(TSatoshi::new(u64::MAX)));
        assert_eq!(all.len(), 3);
        // Drain (no target) selects everything.
        assert_eq!(ms_select_utxos(&utxos, None).len(), 3);
        // Empty input → empty selection.
        assert!(ms_select_utxos(&[], Some(TSatoshi::new(1))).is_empty());
    }

    // --- ms_create_psbt (Creator orchestration over a mock backend) ---

    /// In-memory backend serving canned UTXOs and raw transactions for
    /// the multisig Creator tests.
    struct MsMockBackend {
        unspent: Vec<Utxo>,
        raw: std::collections::HashMap<String, String>,
        fail_unspent: bool,
    }

    #[async_trait::async_trait]
    impl crate::net::NetworkBackend for MsMockBackend {
        async fn get_unspent(
            &self,
            _address: &TAddress,
        ) -> Result<Vec<Utxo>, crate::net::NetError> {
            if self.fail_unspent {
                return Err(crate::net::NetError::Http("mock failure".to_string()));
            }
            Ok(self.unspent.clone())
        }
        async fn get_info(&self, _address: &TAddress) -> Result<AddressInfo, crate::net::NetError> {
            Ok(AddressInfo::default())
        }
        async fn broadcast(&self, _raw_tx: &[u8]) -> Result<(), crate::net::NetError> {
            Ok(())
        }
        async fn raw_transaction(&self, txid: &str) -> Result<String, crate::net::NetError> {
            self.raw
                .get(txid)
                .cloned()
                .ok_or_else(|| crate::net::NetError::BadResponse(format!("no raw tx {txid}")))
        }
        fn name(&self) -> &'static str {
            "ms-mock"
        }
    }

    /// The 2-of-3 fixture quorum: own key at nonce 0, cosigners at
    /// nonces 1–2 of the same fixture seed.
    fn ms_fixture_quorum() -> (TAddress, Vec<u8>, Vec<u8>) {
        let keys = [ms_wallet_pubkey(1), ms_wallet_pubkey(2)];
        let (addr, redeem) =
            ms_create_address(3, 2, &[ms_wallet_pubkey(0), keys[0], keys[1]], MsForm::P2sh)
                .expect("valid quorum");
        let script = make_p2sh_lock_script(&crate::address::hash160_script(&redeem));
        (addr, redeem, script)
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_psbt_builds_and_signs_over_a_mock_backend() {
        let (_, redeem, script) = ms_fixture_quorum();
        let prev = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x77; 32],
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 60_000,
                script: script.clone(),
            }],
            locktime: 0,
        };
        let backend = MsMockBackend {
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 60_000,
                script_pubkey: script.clone(),
                confirmations: 10,
            }],
            raw: std::collections::HashMap::from([(
                hex::encode(prev.id()),
                hex::encode(prev.serialize_wire()),
            )]),
            fail_unspent: false,
        };
        // A valid bech32 destination (fixture key's native address).
        let dst = pubkey_to_segwit_address(&ms_wallet_pubkey(8));

        block_on(async {
            let outcome = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(50_000),
                3,
                2,
                &[ms_wallet_pubkey(1), ms_wallet_pubkey(2)],
                Some(TNonce::new(0)),
                6,
                TSatoshi::new(1000),
                TSatoshi::ZERO,
                MsForm::P2sh,
            )
            .await
            .expect("Creator orchestration succeeds");

            // The PSBT carries the quorum input, its redeem script and
            // exactly one partial signature — the own key's.
            let psbt = PartiallySignedTransaction::from_base64(&outcome.psbt_b64)
                .expect("base64 round trip");
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(
                psbt.inputs[0].redeem_script.as_deref(),
                Some(redeem.as_slice())
            );
            assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
            assert_eq!(
                psbt.inputs[0].partial_sigs[0].0 .0,
                ms_wallet_pubkey(0).to_vec()
            );
            // Fee arithmetic: fee + amount + cashback == 60_000 and the
            // cashback went back to the QUORUM address.
            assert_eq!(
                outcome.fee.get() + outcome.amount.get() + outcome.cashback.get(),
                60_000
            );
            let cashback_script = &psbt.unsigned_tx.vout[0].script;
            assert_eq!(cashback_script, &script);
            // The fee covers the pinned rate for the actual vsize.
            assert!(outcome.fee.get() > 0);

            // Completion: the second cosigner (nonce 1 of the same
            // fixture seed) signs, the quorum finalizes and extracts.
            let mut psbt2 = psbt.clone();
            assert!(psbt2.sign_input(0, &ms_wallet_key(1)).unwrap());
            psbt2.finalize();
            let tx = psbt2.extract_transaction().expect("complete quorum");
            assert!(tx.vin[0].script.len() > redeem.len());
            assert!(tx.vin[0].witness.is_empty());
        });
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_address_form_p2wsh_matches_redeem_and_address() {
        let keys = [
            ms_wallet_pubkey(0),
            ms_wallet_pubkey(1),
            ms_wallet_pubkey(2),
        ];
        let (p2sh_addr, p2sh_redeem) =
            ms_create_address(3, 2, &keys, MsForm::P2sh).expect("valid quorum");
        let (p2wsh_addr, p2wsh_redeem) =
            ms_create_address(3, 2, &keys, MsForm::P2wsh).expect("valid quorum");
        // The redeem script is identical in both forms; only the
        // commitment/address differ.
        assert_eq!(p2sh_redeem, p2wsh_redeem);
        // The P2WSH address is a bech32 bc1q string decoding to
        // SHA256(redeem).
        assert!(p2wsh_addr.as_str().starts_with("bc1q"));
        let program =
            crate::address::decode_p2wsh_address(p2wsh_addr.as_str()).expect("p2wsh address");
        assert_eq!(program, crate::address::sha256_script(&p2wsh_redeem));
        // The P2SH address is untouched.
        assert!(p2sh_addr.as_str().starts_with('3'));
        // Lock-script round trip through the shared make_vout path.
        assert_eq!(
            make_lock_script_for_address(&p2wsh_addr).unwrap(),
            crate::script::make_p2wsh_lock_script(&program).to_vec()
        );
        // MsForm name/parser round trip (CLI flag spelling).
        assert_eq!(MsForm::P2sh.name(), "p2sh");
        assert_eq!(MsForm::P2wsh.name(), "p2wsh");
        assert_eq!(MsForm::parse("p2wsh"), Some(MsForm::P2wsh));
        assert_eq!(MsForm::parse("p2sh"), Some(MsForm::P2sh));
        assert_eq!(MsForm::parse("segwit"), None);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_psbt_p2wsh_builds_and_signs_over_a_mock_backend() {
        // The witness form needs NO raw prev-tx fetch: the raw map is
        // deliberately empty, so any raw_transaction call would fail
        // the test through the mock's error arm.
        let (_, redeem, _) = ms_fixture_quorum();
        let quorum_script =
            crate::script::make_p2wsh_lock_script(&crate::address::sha256_script(&redeem)).to_vec();
        let prev = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x77; 32],
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 60_000,
                script: quorum_script.clone(),
            }],
            locktime: 0,
        };
        let backend = MsMockBackend {
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 60_000,
                script_pubkey: quorum_script.clone(),
                confirmations: 10,
            }],
            raw: std::collections::HashMap::new(),
            fail_unspent: false,
        };
        let dst = pubkey_to_segwit_address(&ms_wallet_pubkey(8));

        block_on(async {
            let outcome = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(50_000),
                3,
                2,
                &[ms_wallet_pubkey(1), ms_wallet_pubkey(2)],
                Some(TNonce::new(0)),
                6,
                TSatoshi::new(1000),
                TSatoshi::ZERO,
                MsForm::P2wsh,
            )
            .await
            .expect("Creator orchestration succeeds");

            // The PSBT carries the witness-form fields and exactly one
            // partial signature (the own key's, by membership).
            let psbt = PartiallySignedTransaction::from_base64(&outcome.psbt_b64)
                .expect("base64 round trip");
            assert_eq!(psbt.inputs.len(), 1);
            assert!(psbt.inputs[0].non_witness_utxo.is_none());
            assert!(psbt.inputs[0].witness_utxo.is_some());
            assert_eq!(
                psbt.inputs[0].witness_script.as_deref(),
                Some(redeem.as_slice())
            );
            assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
            // Fee arithmetic and the cashback to the P2WSH quorum
            // address.
            assert_eq!(
                outcome.fee.get() + outcome.amount.get() + outcome.cashback.get(),
                60_000
            );
            assert_eq!(&psbt.unsigned_tx.vout[0].script, &quorum_script);
            assert!(outcome.fee.get() > 0);

            // Completion: the second cosigner signs, the quorum
            // finalizes and extracts a witness spend (empty scriptSig,
            // M + 2 witness items with the empty dummy first).
            let mut psbt2 = psbt.clone();
            assert!(psbt2.sign_input(0, &ms_wallet_key(1)).unwrap());
            psbt2.finalize();
            let tx = psbt2.extract_transaction().expect("complete quorum");
            assert!(tx.vin[0].script.is_empty());
            assert_eq!(tx.vin[0].witness.len(), 4);
            assert!(tx.vin[0].witness[0].is_empty());
            assert_eq!(tx.vin[0].witness.last().unwrap(), &redeem);
            // vsize reflects the witness discount: strictly below the
            // legacy byte size of the same transaction.
            assert!(tx.vsize() < tx.serialize_wire().len());
        });
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_address_form_p2tr_matches_script_and_address() {
        // The p2tr form's "redeem" is a DIFFERENT script than
        // p2sh/p2wsh — the canonical tapscript over the x-only
        // projections (R-MS-7/10) — and its address is bech32m v1
        // committing to the tweaked NUMS output key (R-MS-8).
        let keys = [
            ms_wallet_pubkey(0),
            ms_wallet_pubkey(1),
            ms_wallet_pubkey(2),
        ];
        let (p2tr_addr, tapscript) =
            ms_create_address(3, 2, &keys, MsForm::P2tr).expect("valid quorum");
        // The script is the canonical tapscript; a different byte
        // string than the shared p2sh/p2wsh redeem.
        let (p2sh_addr, p2sh_redeem) =
            ms_create_address(3, 2, &keys, MsForm::P2sh).expect("valid quorum");
        assert_ne!(tapscript, p2sh_redeem);
        let (m, script_keys) =
            crate::script::extract_multisig_tapscript(&tapscript).expect("canonical tapscript");
        assert_eq!(m, 2);
        let mut sorted_xonly: Vec<[u8; 32]> = keys
            .iter()
            .map(|k| k[1..33].try_into().expect("33-byte key"))
            .collect();
        sorted_xonly.sort();
        assert_eq!(script_keys, sorted_xonly, "x-only BIP-67 order (R-MS-10)");
        // The address is `bc1p…` (62 chars) decoding to the tweaked
        // NUMS output key of the tapscript's leaf.
        assert!(p2tr_addr.as_str().starts_with("bc1p"));
        assert_eq!(p2tr_addr.as_str().len(), 62);
        let program =
            crate::address::decode_taproot_address(p2tr_addr.as_str()).expect("p2tr address");
        let leaf_hash = crate::script::tapscript_leaf_hash(&tapscript);
        let output = crate::address::tapscript_output_key(&MS_TAPSCRIPT_INTERNAL_KEY, &leaf_hash)
            .expect("NUMS lift and tweak are total");
        assert_eq!(program, output);
        // The lock script built from the address commits to the same
        // key.
        assert_eq!(
            make_lock_script_for_address(&p2tr_addr).unwrap(),
            crate::script::make_p2tr_lock_script(&output).to_vec()
        );
        // The P2SH address is untouched.
        assert!(p2sh_addr.as_str().starts_with('3'));
        // MsForm name/parser round trip (CLI flag spelling).
        assert_eq!(MsForm::P2tr.name(), "p2tr");
        assert_eq!(MsForm::parse("p2tr"), Some(MsForm::P2tr));
        // Key-permutation invariance (R-MS-4 carried over to the
        // x-only sort).
        let reversed = [keys[2], keys[1], keys[0]];
        let (addr2, script2) =
            ms_create_address(3, 2, &reversed, MsForm::P2tr).expect("valid quorum");
        assert_eq!(addr2, p2tr_addr);
        assert_eq!(script2, tapscript);
        // Boundaries carry over: N = 16 and M = 0 refuse on the p2tr
        // form too (R-MS-9 — the unified 15 bound).
        let sixteen: Vec<[u8; 33]> = (0..16)
            .map(|i| {
                let mut k = [0x02u8; 33];
                k[32] = i as u8 + 1;
                k
            })
            .collect();
        assert_eq!(
            ms_create_address(16, 16, &sixteen, MsForm::P2tr),
            Err(MsError::QuorumBounds)
        );
        assert_eq!(
            ms_create_address(2, 0, &keys[..2], MsForm::P2tr),
            Err(MsError::QuorumBounds)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn parse_ms_keys_enforces_the_form_encoding() {
        // R-MS-10: p2sh/p2wsh take 66-hex compressed, p2tr takes
        // 64-hex x-only; mixing is InvalidKeyEncoding.
        let compressed = hex::encode(ms_wallet_pubkey(0));
        let xonly = hex::encode(&ms_wallet_pubkey(0)[1..33]);
        // Valid per form.
        assert_eq!(
            parse_ms_keys(std::slice::from_ref(&compressed), MsForm::P2sh).unwrap(),
            vec![ms_wallet_pubkey(0)]
        );
        assert_eq!(
            parse_ms_keys(std::slice::from_ref(&compressed), MsForm::P2wsh).unwrap(),
            vec![ms_wallet_pubkey(0)]
        );
        // The x-only key is carried 0x02-prefixed (the parity byte is
        // meaningless here — only the 32 bytes enter the tapscript and
        // BIP-340 signing normalizes): compare the x-only projection.
        assert_eq!(
            parse_ms_keys(std::slice::from_ref(&xonly), MsForm::P2tr).unwrap()[0][1..],
            ms_wallet_pubkey(0)[1..]
        );
        assert_eq!(parse_ms_keys(&[xonly], MsForm::P2tr).unwrap()[0][0], 0x02);
        // Cross-form mixing is refused in both directions.
        assert_eq!(
            parse_ms_keys(std::slice::from_ref(&compressed), MsForm::P2tr),
            Err(MsError::InvalidKeyEncoding)
        );
        assert_eq!(
            parse_ms_keys(&[hex::encode(&ms_wallet_pubkey(1)[1..33])], MsForm::P2sh),
            Err(MsError::InvalidKeyEncoding)
        );
        // The 03 prefix is equally valid on the compressed forms
        // (the fixture key's own prefix is irrelevant — both are
        // accepted, R-MS-3).
        let mut odd = ms_wallet_pubkey(3);
        odd[0] = 0x03;
        assert_eq!(
            parse_ms_keys(&[hex::encode(odd)], MsForm::P2sh).unwrap(),
            vec![odd]
        );
        // Wrong prefix (04) is refused on the compressed forms.
        let mut raw = ms_wallet_pubkey(2);
        raw[0] = 0x04;
        assert_eq!(
            parse_ms_keys(&[hex::encode(raw)], MsForm::P2sh),
            Err(MsError::InvalidKeyEncoding)
        );
        // Wrong lengths and non-hex.
        assert_eq!(
            parse_ms_keys(&["ab".repeat(31)], MsForm::P2tr),
            Err(MsError::InvalidKeyEncoding)
        );
        assert_eq!(
            parse_ms_keys(&["ab".repeat(32)], MsForm::P2sh),
            Err(MsError::InvalidKeyEncoding)
        );
        assert_eq!(
            parse_ms_keys(&["zz".repeat(32)], MsForm::P2sh),
            Err(MsError::InvalidKeyEncoding)
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_psbt_p2tr_builds_and_signs_over_a_mock_backend() {
        // The script-path form needs NO raw prev-tx fetch: the raw map
        // is deliberately empty, so any raw_transaction call would
        // fail the test through the mock's error arm (symmetric with
        // P2WSH — BIP-341 commits the amount via WITNESS_UTXO).
        let (quorum_addr, redeem) = ms_create_address(
            3,
            2,
            &[
                ms_wallet_pubkey(0),
                ms_wallet_pubkey(1),
                ms_wallet_pubkey(2),
            ],
            MsForm::P2tr,
        )
        .expect("valid quorum");
        let quorum_script = ms_quorum_lock_script(&redeem, MsForm::P2tr);
        assert_eq!(
            quorum_script,
            make_lock_script_for_address(&quorum_addr).unwrap()
        );
        let prev = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x77; 32],
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 60_000,
                script: quorum_script.clone(),
            }],
            locktime: 0,
        };
        let backend = MsMockBackend {
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 60_000,
                script_pubkey: quorum_script.clone(),
                confirmations: 10,
            }],
            raw: std::collections::HashMap::new(),
            fail_unspent: false,
        };
        let dst = pubkey_to_segwit_address(&ms_wallet_pubkey(8));

        block_on(async {
            let outcome = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(50_000),
                3,
                2,
                &[ms_wallet_pubkey(1), ms_wallet_pubkey(2)],
                Some(TNonce::new(0)),
                6,
                TSatoshi::new(1000),
                TSatoshi::ZERO,
                MsForm::P2tr,
            )
            .await
            .expect("Creator orchestration succeeds");

            // The PSBT carries the script-path fields and exactly one
            // tap partial signature (the own key's, by membership).
            let psbt = PartiallySignedTransaction::from_base64(&outcome.psbt_b64)
                .expect("base64 round trip");
            assert_eq!(psbt.inputs.len(), 1);
            assert!(psbt.inputs[0].non_witness_utxo.is_none());
            assert!(psbt.inputs[0].witness_utxo.is_some());
            assert_eq!(
                psbt.inputs[0].tap_internal_key,
                Some(MS_TAPSCRIPT_INTERNAL_KEY)
            );
            assert_eq!(psbt.inputs[0].tap_leaf_scripts.len(), 1);
            assert_eq!(
                psbt.inputs[0].tap_leaf_scripts[0].script_with_version,
                [&redeem[..], &[crate::script::TAPSCRIPT_LEAF_VERSION]].concat()
            );
            assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
            assert_eq!(psbt.inputs[0].tap_script_sigs[0].sig.len(), 64);
            // Fee arithmetic and the cashback to the P2TR quorum
            // address (the existing DUST_THRESHOLD_P2TR = 330 model —
            // no new dust constants).
            assert_eq!(
                outcome.fee.get() + outcome.amount.get() + outcome.cashback.get(),
                60_000
            );
            assert_eq!(&psbt.unsigned_tx.vout[0].script, &quorum_script);
            assert!(outcome.fee.get() > 0);

            // Completion: the second cosigner signs, the quorum
            // finalizes and extracts a script-path witness spend
            // (empty scriptSig, N + 2 items, no dummy).
            let mut psbt2 = psbt.clone();
            assert!(psbt2.sign_input(0, &ms_wallet_key(1)).unwrap());
            psbt2.finalize();
            let tx = psbt2.extract_transaction().expect("complete quorum");
            assert!(tx.vin[0].script.is_empty());
            assert_eq!(tx.vin[0].witness.len(), 5);
            assert_eq!(
                tx.vin[0].witness[..3]
                    .iter()
                    .filter(|s| !s.is_empty())
                    .count(),
                2,
                "exactly M signatures in the slots"
            );
            assert_eq!(tx.vin[0].witness[3], redeem);
            // The witness closes with the 33-byte control block.
            assert_eq!(tx.vin[0].witness[4].len(), 33);
            assert_eq!(tx.vin[0].witness[4][1..], MS_TAPSCRIPT_INTERNAL_KEY[..]);
        });
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_psbt_requires_participation_and_valid_quorum() {
        let (_, _, script) = ms_fixture_quorum();
        let prev = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x78; 32],
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 60_000,
                script: script.clone(),
            }],
            locktime: 0,
        };
        let backend = MsMockBackend {
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 60_000,
                script_pubkey: script.clone(),
                confirmations: 10,
            }],
            raw: std::collections::HashMap::from([(
                hex::encode(prev.id()),
                hex::encode(prev.serialize_wire()),
            )]),
            fail_unspent: false,
        };
        let dst = pubkey_to_segwit_address(&ms_wallet_pubkey(8));

        block_on(async {
            // No own nonce → NotAParticipant (never builds a foreign
            // quorum's spend).
            let err = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(50_000),
                3,
                2,
                &[ms_wallet_pubkey(1), ms_wallet_pubkey(2)],
                None,
                6,
                TSatoshi::new(1000),
                TSatoshi::ZERO,
                MsForm::P2sh,
            )
            .await
            .expect_err("must refuse");
            assert!(matches!(err, MsSendError::Ms(MsError::NotAParticipant)));

            // n = 16 → QuorumBounds.
            let sixteen: Vec<[u8; 33]> = (0..15)
                .map(|i| {
                    let mut k = [0x02u8; 33];
                    k[32] = i as u8 + 1;
                    k
                })
                .collect();
            let err = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(50_000),
                16,
                16,
                &sixteen,
                Some(TNonce::new(0)),
                6,
                TSatoshi::new(1000),
                TSatoshi::ZERO,
                MsForm::P2sh,
            )
            .await
            .expect_err("must refuse");
            assert!(matches!(err, MsSendError::Ms(MsError::QuorumBounds)));

            // Confirmations filter: the only UTXO has 10 confs, asking
            // for 50 leaves no funds → AmountExceedsInput.
            let err = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(50_000),
                3,
                2,
                &[ms_wallet_pubkey(1), ms_wallet_pubkey(2)],
                Some(TNonce::new(0)),
                50,
                TSatoshi::new(1000),
                TSatoshi::ZERO,
                MsForm::P2sh,
            )
            .await
            .expect_err("must refuse");
            assert!(matches!(
                err,
                MsSendError::Wallet(WalletError::AmountExceedsInput { .. })
            ));
        });
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_psbt_surfaces_network_and_raw_tx_failures() {
        let (addr, redeem, script) = ms_fixture_quorum();
        let _ = (addr, redeem);
        let backend = MsMockBackend {
            unspent: vec![],
            raw: std::collections::HashMap::new(),
            fail_unspent: true,
        };
        let dst = pubkey_to_segwit_address(&ms_wallet_pubkey(8));
        block_on(async {
            let err = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(50_000),
                3,
                2,
                &[ms_wallet_pubkey(1), ms_wallet_pubkey(2)],
                Some(TNonce::new(0)),
                6,
                TSatoshi::new(1000),
                TSatoshi::ZERO,
                MsForm::P2sh,
            )
            .await
            .expect_err("must propagate");
            assert!(matches!(
                err,
                MsSendError::Network(crate::net::NetError::Http(_))
            ));
        });

        // A UTXO whose raw prev tx is missing → Network(BadResponse).
        let prev = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x79; 32],
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 60_000,
                script: script.clone(),
            }],
            locktime: 0,
        };
        let backend = MsMockBackend {
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 60_000,
                script_pubkey: script.clone(),
                confirmations: 10,
            }],
            raw: std::collections::HashMap::new(),
            fail_unspent: false,
        };
        block_on(async {
            let err = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(50_000),
                3,
                2,
                &[ms_wallet_pubkey(1), ms_wallet_pubkey(2)],
                Some(TNonce::new(0)),
                6,
                TSatoshi::new(1000),
                TSatoshi::new(1000),
                MsForm::P2sh,
            )
            .await
            .expect_err("must propagate");
            assert!(matches!(
                err,
                MsSendError::Network(crate::net::NetError::BadResponse(_))
            ));
        });

        // Garbage raw prev tx → Network("raw tx …: …").
        let backend = MsMockBackend {
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 60_000,
                script_pubkey: script.clone(),
                confirmations: 10,
            }],
            raw: std::collections::HashMap::from([(
                hex::encode(prev.id()),
                "deadbeef".to_string(),
            )]),
            fail_unspent: false,
        };
        block_on(async {
            let err = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(50_000),
                3,
                2,
                &[ms_wallet_pubkey(1), ms_wallet_pubkey(2)],
                Some(TNonce::new(0)),
                6,
                TSatoshi::new(1000),
                TSatoshi::new(1000),
                MsForm::P2sh,
            )
            .await
            .expect_err("must propagate");
            let msg = err.to_string();
            assert!(msg.contains("raw tx"), "got: {msg}");
        });
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_quorum_cashback_dust_uses_the_p2sh_threshold() {
        // Cashback to the quorum address is a P2SH output: the dust
        // invariant must use DUST_THRESHOLD_P2SH (540), not the P2PKH
        // 546 — verified around the boundary for both directions.
        let (_, _, script) = ms_fixture_quorum();
        assert!(is_dust(DUST_THRESHOLD_P2SH - 1, &script));
        assert!(!is_dust(DUST_THRESHOLD_P2SH, &script));
        // End-to-end shape: a Creator run whose leftover falls below
        // the threshold reports a dust cashback; one above does not.
        let (addr, redeem, script) = ms_fixture_quorum();
        let _ = (addr, redeem);
        let prev = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x7a; 32],
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 60_000,
                script: script.clone(),
            }],
            locktime: 0,
        };
        let backend = MsMockBackend {
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 60_000,
                script_pubkey: script.clone(),
                confirmations: 10,
            }],
            raw: std::collections::HashMap::from([(
                hex::encode(prev.id()),
                hex::encode(prev.serialize_wire()),
            )]),
            fail_unspent: false,
        };
        let dst = pubkey_to_segwit_address(&ms_wallet_pubkey(8));
        block_on(async {
            // amount 59_600 → cashback below fee, dust-checked.
            let outcome = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(59_600),
                3,
                2,
                &[ms_wallet_pubkey(1), ms_wallet_pubkey(2)],
                Some(TNonce::new(0)),
                6,
                TSatoshi::new(1000),
                TSatoshi::new(350),
                MsForm::P2sh,
            )
            .await
            .expect("succeeds");
            assert!(is_dust(outcome.cashback.get(), &script));
            assert_eq!(outcome.cashback.get(), 50);
        });
    }

    /// One-shot runtime for the sync test fns above.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime builds")
            .block_on(fut)
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_own_pubkey_propagates_derivation_errors() {
        // The pubkey helper forwards the underlying derivation error.
        assert!(matches!(
            ms_own_pubkey(
                &TSeed::new(""),
                TNonce::new(0),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc
            ),
            Err(WalletError::EmptySeed)
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_own_privkey_reports_derivation_failures() {
        let seed = TSeed::new("derivation-failures");
        // Empty seed → EmptySeed.
        assert!(matches!(
            ms_own_privkey(
                &TSeed::new(""),
                TNonce::new(0),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc
            ),
            Err(WalletError::EmptySeed)
        ));
        // Non-yubtc KDF without a passphrase → PrivKey (the wallet-level
        // cause, not the generic KDF error).
        let err = ms_own_privkey(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Pbkdf2)
            .expect_err("passphrase required");
        assert!(
            err.to_string().contains("passphrase required"),
            "got: {err}"
        );
        // yubtc cascade with a (rejected) passphrase → PrivKey.
        let err = ms_own_privkey(
            &seed,
            TNonce::new(0),
            &TPassphrase::new("x"),
            KdfAlgo::Yubtc,
        )
        .expect_err("yubtc rejects passphrases");
        assert!(err.to_string().contains("privkey"), "got: {err}");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_create_psbt_explicit_fee_surfaces_vout_arithmetic_errors() {
        // The explicit-fee branch (`fee > 0`) propagates `make_vout`'s
        // arithmetic refusal: amount + fee above the input total.
        let (_, _, script) = ms_fixture_quorum();
        let prev = Transaction {
            version: 2,
            vin: vec![TxIn {
                txhash: [0x7b; 32],
                n: 0,
                script: vec![],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            vout: vec![TxOut {
                amount: 10_000,
                script: script.clone(),
            }],
            locktime: 0,
        };
        let backend = MsMockBackend {
            unspent: vec![Utxo {
                txid: prev.id(),
                vout: 0,
                amount: 10_000,
                script_pubkey: script.clone(),
                confirmations: 10,
            }],
            raw: std::collections::HashMap::from([(
                hex::encode(prev.id()),
                hex::encode(prev.serialize_wire()),
            )]),
            fail_unspent: false,
        };
        let dst = pubkey_to_segwit_address(&ms_wallet_pubkey(8));
        block_on(async {
            let err = ms_create_psbt(
                &TSeed::new(MS_WALLET_SEED),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
                &backend,
                &dst,
                TSatoshi::new(9_900),
                3,
                2,
                &[ms_wallet_pubkey(1), ms_wallet_pubkey(2)],
                Some(TNonce::new(0)),
                6,
                TSatoshi::new(1000),
                TSatoshi::new(500),
                MsForm::P2sh,
            )
            .await
            .expect_err("amount + fee exceeds input");
            assert!(matches!(
                err,
                MsSendError::Wallet(WalletError::AmountExceedsInput { .. })
            ));
        });
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn ms_mock_backend_stub_methods_are_driven() {
        // The mock only serves get_unspent/raw_transaction in the
        // Creator tests; drive the remaining trait methods so the stub
        // bodies stay measured, and pin `name`.
        let backend = MsMockBackend {
            unspent: vec![],
            raw: std::collections::HashMap::new(),
            fail_unspent: false,
        };
        block_on(async {
            let addr = TAddress::new("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
            let info = backend.get_info(&addr).await.expect("stub ok");
            assert_eq!(info, AddressInfo::default());
            backend.broadcast(&[0x01]).await.expect("stub ok");
        });
        assert_eq!(crate::net::NetworkBackend::name(&backend), "ms-mock");
    }
}
