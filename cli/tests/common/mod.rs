//! Shared fixtures for the CLI integration tests.
//!
//! Every subprocess test drives the `yubtc` binary with
//! `--provider mock`, which resolves to a [`BlockchainInfoBackend`]
//! pointed at `YUBTC_MOCK_BACKEND_URL`. The helpers below stand up a
//! wiremock server speaking the blockchain.info wire format:
//!
//! - `GET /balance?active={addr}` — JSON object keyed by address with
//!   `total_received` / `final_balance` / `n_tx` (missing fields
//!   default to 0 on the core side; `is_unused` is driven purely by
//!   `total_received`).
//! - `GET /unspent?active={addr}` — `{"unspent_outputs": [...]}` with
//!   `tx_hash` (hex), `tx_output_n`, `value`, `script` (hex of the
//!   25-byte P2PKH script), `confirmations`.
//! - `POST /pushtx` with form body `tx=<hex>` — any 2xx counts as a
//!   successful broadcast (the body is only surfaced on failure).
//!
//! The fixture seed + passphrase + `pbkdf2` KDF are deterministic, so
//! the addresses (and their P2PKH scripts) can be precomputed here via
//! `yubtc_core` and reused both for mock responses and for expected
//! stdout.
//!
//! Each test binary links this module but uses only a subset of the
//! helpers, so dead-code is allowed here on purpose.
//!
//! `serde_json::json!` expands to `unwrap()` internally, which trips
//! the repo-wide disallowed-methods lint — same allowance as the
//! core test modules.

#![allow(dead_code)]
#![allow(clippy::disallowed_methods)]
use std::collections::BTreeMap;

use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Deterministic fixture seed (valid BIP-39, 12 words, official
/// test vector #2). Vector #1 (abandon ×11 + about) is checksum-valid
/// but fails the C6 entropy floor (2 distinct of 12), so it can no
/// longer be used as an accepted-input fixture.
pub const SEED: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// Fixture passphrase (non-empty → pbkdf2 KDF path).
pub const PASSPHRASE: &str = "x";

/// The abandon ×11 + about BIP-39 official test vector #1:
/// checksum-valid, but rejected by the C6 entropy floor (2 distinct
/// words of 12 < 4). Under the permissive default it is accepted at
/// reception (R-1) — its long lowercase text estimates ~442 bits, so
/// it does NOT trigger the R-6 warning either.
pub const LOW_ENTROPY_SEED: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// An arbitrary non-BIP-39 phrase accepted permissively (R-1). Short
/// lowercase text: 19 chars × log2(27) ≈ 90 bits → the R-6 warning
/// fires (non-blocking).
pub const ARBITRARY_PHRASE: &str = "not a real mnemonic";

/// The two stdin lines the commands read when piped: seed, passphrase.
pub fn stdin_seed_pass() -> String {
    format!("{SEED}\n{PASSPHRASE}\n")
}

/// stdin lines for an arbitrary seed: seed, passphrase.
pub fn stdin_seed_pass_for(seed: &str) -> String {
    format!("{seed}\n{PASSPHRASE}\n")
}

/// stdin lines with the low-entropy seed: rejected at reception in
/// strict mode (`--strict-bip39`), accepted permissively.
pub fn stdin_low_entropy_seed_pass() -> String {
    format!("{LOW_ENTROPY_SEED}\n{PASSPHRASE}\n")
}

/// Fixture address at `nonce` for `(SEED, PASSPHRASE, pbkdf2)` in the
/// DEFAULT form (native P2WPKH — the Phase 13 CLI default). This is
/// what `address` / `balance` / `send` / `dumpprivkey` print without
/// `--addr-type`.
pub fn address(nonce: u32) -> String {
    address_for(SEED, nonce)
}

/// Default-form (native) address at `nonce` for an arbitrary
/// `(seed, PASSPHRASE, pbkdf2)` tuple — used by the
/// permissive-reception tests whose seed differs from [`SEED`].
pub fn address_for(seed: &str, nonce: u32) -> String {
    native_address_for(seed, nonce)
}

/// Native P2WPKH address (the BIP-84 `m/84'…` leaf of `pbkdf2`).
pub fn native_address_for(seed: &str, nonce: u32) -> String {
    privkey_for(seed, nonce).get_address().as_str().to_string()
}

/// Legacy P2PKH address (the v0.1 `m/44'…` leaf of `pbkdf2`).
pub fn legacy_address_for(seed: &str, nonce: u32) -> String {
    legacy_privkey_for(seed, nonce)
        .get_address()
        .as_str()
        .to_string()
}

/// Taproot P2TR address (the BIP-86 `m/86'…` leaf of `pbkdf2`).
pub fn taproot_address_for(seed: &str, nonce: u32) -> String {
    taproot_privkey_for(seed, nonce)
        .get_address()
        .as_str()
        .to_string()
}

/// Fixture native-form `TPrivKey` at `nonce` for `(SEED, PASSPHRASE,
/// pbkdf2)`.
pub fn privkey(nonce: u32) -> yubtc_core::wallet::TPrivKey {
    privkey_for(SEED, nonce)
}

/// `TPrivKey` at `nonce` for an arbitrary `(seed, PASSPHRASE,
/// pbkdf2)` tuple, derived at the default (native) form.
pub fn privkey_for(seed: &str, nonce: u32) -> yubtc_core::wallet::TPrivKey {
    with_addr_type_for(seed, nonce, yubtc_core::wallet::AddrType::Native)
}

/// `TPrivKey` at `nonce` for an arbitrary `(seed, PASSPHRASE,
/// pbkdf2)` tuple, derived at the given address form (Phase 13: for
/// `pbkdf2` every form is its own BIP-32 leaf).
pub fn with_addr_type_for(
    seed: &str,
    nonce: u32,
    addr_type: yubtc_core::wallet::AddrType,
) -> yubtc_core::wallet::TPrivKey {
    use yubtc_core::kdf::KdfAlgo;
    use yubtc_core::misc::{TNonce, TPassphrase, TSeed};
    yubtc_core::wallet::TPrivKey::with_addr_type(
        &TSeed::new(seed),
        TNonce::new(nonce),
        &TPassphrase::new(PASSPHRASE),
        KdfAlgo::Pbkdf2,
        addr_type,
    )
    .expect("derivation is deterministic")
}

/// Legacy-form fixture key at `nonce` (v0.1 `m/44'…` leaf).
pub fn legacy_privkey_for(seed: &str, nonce: u32) -> yubtc_core::wallet::TPrivKey {
    with_addr_type_for(seed, nonce, yubtc_core::wallet::AddrType::Legacy)
}

/// Taproot-form fixture key at `nonce` (BIP-86 `m/86'…` leaf).
#[allow(dead_code)]
pub fn taproot_privkey_for(seed: &str, nonce: u32) -> yubtc_core::wallet::TPrivKey {
    with_addr_type_for(seed, nonce, yubtc_core::wallet::AddrType::Taproot)
}

/// Hex of the 22-byte P2WPKH lock script for the fixture address at
/// `nonce` (the funded UTXOs live at the native-form addresses the
/// default CLI scans). Required by `/unspent` responses: the UTXO
/// script must match the address's pubkey hash or `build_vin`
/// rejects it.
pub fn p2wpkh_script_hex(nonce: u32) -> String {
    p2wpkh_script_hex_for(SEED, nonce)
}

/// P2WPKH lock-script hex for an arbitrary seed's native key at
/// `nonce`.
pub fn p2wpkh_script_hex_for(seed: &str, nonce: u32) -> String {
    use yubtc_core::address::hash160_pubkey;
    use yubtc_core::privkey::privkey_to_pubkey;
    use yubtc_core::script::make_p2wpkh_lock_script;
    let pk = privkey_for(seed, nonce);
    let pubkey = privkey_to_pubkey(&pk.privkey);
    hex::encode(make_p2wpkh_lock_script(&hash160_pubkey(&pubkey)))
}

/// Hex of the 25-byte P2PKH lock script for the legacy-form fixture
/// key at `nonce` (used by the legacy-funded fixture).
pub fn p2pkh_script_hex(nonce: u32) -> String {
    p2pkh_script_hex_for(SEED, nonce)
}

/// P2PKH lock-script hex for an arbitrary seed's legacy key at
/// `nonce`.
pub fn p2pkh_script_hex_for(seed: &str, nonce: u32) -> String {
    use yubtc_core::address::hash160_pubkey;
    use yubtc_core::privkey::privkey_to_pubkey;
    use yubtc_core::script::make_p2pkh_lock_script;
    let pk = legacy_privkey_for(seed, nonce);
    let pubkey = privkey_to_pubkey(&pk.privkey);
    hex::encode(make_p2pkh_lock_script(&hash160_pubkey(&pubkey)))
}

/// One canned UTXO for the `/unspent` response.
pub struct MockUtxo {
    pub txid_hex: String,
    pub vout: u32,
    pub value: u64,
    pub confirmations: u32,
    /// `false` (default): the UTXO sits at the native-form address
    /// with a P2WPKH script. `true`: legacy P2PKH form.
    pub legacy: bool,
}

/// Default canned UTXO: deterministic txid, deeply confirmed,
/// native (P2WPKH) form.
pub fn utxo(nonce: u32, value: u64) -> MockUtxo {
    MockUtxo {
        txid_hex: format!("{nonce:0>64x}"),
        vout: 0,
        value,
        confirmations: 100,
        legacy: false,
    }
}

/// Legacy-form canned UTXO (P2PKH script at the legacy address).
pub fn legacy_utxo(nonce: u32, value: u64) -> MockUtxo {
    MockUtxo {
        txid_hex: format!("{nonce:0>64x}"),
        vout: 0,
        value,
        confirmations: 100,
        legacy: true,
    }
}

impl MockUtxo {
    fn json(&self, seed: &str, nonce: u32) -> serde_json::Value {
        serde_json::json!({
            "tx_hash": self.txid_hex,
            "tx_output_n": self.vout,
            "value": self.value,
            "script": self.script_hex(seed, nonce),
            "confirmations": self.confirmations,
        })
    }

    /// Lock-script hex of this UTXO: the P2WPKH script of the
    /// native-form key (the default funded form). Legacy-funded
    /// fixtures override via [`MockUtxo::legacy`].
    fn script_hex(&self, seed: &str, nonce: u32) -> String {
        if self.legacy {
            p2pkh_script_hex_for(seed, nonce)
        } else {
            p2wpkh_script_hex_for(seed, nonce)
        }
    }
}

/// Mount `GET /balance` responding with one JSON object that covers
/// every address the wallet will scan. `received` maps address →
/// `total_received`; an address absent from the map would make core
/// fail with "address not in response", so callers must list all
/// scanned nonces.
pub async fn mount_balance(server: &MockServer, received: &BTreeMap<String, u64>) {
    let mut obj = serde_json::Map::new();
    for (addr, tr) in received {
        obj.insert(
            addr.clone(),
            serde_json::json!({
                "total_received": tr,
                "final_balance": tr,
                "n_tx": u64::from(*tr > 0),
            }),
        );
    }
    Mock::given(method("GET"))
        .and(path("/balance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::Value::Object(obj)))
        .mount(server)
        .await;
}

/// Convenience: balance map where nonces `0..used.len()` are "used"
/// with the given `total_received` values and every higher nonce up
/// to `used.len() + 10` is unused. Covers the whole scan (and then
/// some) in one response object.
pub fn balance_map(used: &[u64]) -> BTreeMap<String, u64> {
    balance_map_for(SEED, used)
}

/// [`balance_map`] for an arbitrary seed.
pub fn balance_map_for(seed: &str, used: &[u64]) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    // The scan queries every address form of every walked nonce, so
    // the response object must carry all three forms (missing keys
    // would fail with "address not in response"). The `used` value is
    // reported on the native form; the legacy/taproot forms of the
    // same nonce stay unused — the fixtures fund exactly one form.
    for nonce in 0..used.len() as u32 {
        map.insert(native_address_for(seed, nonce), used[nonce as usize]);
        map.insert(legacy_address_for(seed, nonce), 0);
        map.insert(taproot_address_for(seed, nonce), 0);
    }
    for nonce in used.len() as u32..used.len() as u32 + 10 {
        map.insert(native_address_for(seed, nonce), 0);
        map.insert(legacy_address_for(seed, nonce), 0);
        map.insert(taproot_address_for(seed, nonce), 0);
    }
    map
}

/// Extend a balance map with a "used" value on the LEGACY form of
/// `nonce` (the legacy-funded fixture used by the mixed-spend test).
pub fn balance_map_with_legacy_used(
    map: &mut BTreeMap<String, u64>,
    seed: &str,
    nonce: u32,
    received: u64,
) {
    map.insert(legacy_address_for(seed, nonce), received);
}

/// Mount `GET /unspent?active={addr}` for one address with the given
/// canned UTXOs (empty list → address has no unspent outputs).
pub async fn mount_unspent(server: &MockServer, nonce: u32, utxos: &[MockUtxo]) {
    mount_unspent_for(server, SEED, nonce, utxos).await;
}

/// [`mount_unspent`] for an arbitrary seed (both the address query
/// parameter and the UTXO lock scripts follow the seed and the
/// UTXOs' form).
pub async fn mount_unspent_for(server: &MockServer, seed: &str, nonce: u32, utxos: &[MockUtxo]) {
    let outputs: Vec<serde_json::Value> = utxos.iter().map(|u| u.json(seed, nonce)).collect();
    // The query key follows the UTXOs' form: legacy UTXOs are served
    // at the legacy address, native UTXOs at the native address.
    let addr = match utxos.first() {
        Some(u) if u.legacy => legacy_address_for(seed, nonce),
        _ => native_address_for(seed, nonce),
    };
    Mock::given(method("GET"))
        .and(path("/unspent"))
        .and(query_param("active", addr.as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "unspent_outputs": outputs })),
        )
        .mount(server)
        .await;
}

/// Mount `GET /unspent` failing with `status` for every address
/// (drives the `NetError` → `CliError::Network` path).
pub async fn mount_unspent_error(server: &MockServer, status: u16) {
    Mock::given(method("GET"))
        .and(path("/unspent"))
        .respond_with(ResponseTemplate::new(status))
        .mount(server)
        .await;
}

/// Mount `GET /balance` failing with `status` for every request.
pub async fn mount_balance_error(server: &MockServer, status: u16) {
    Mock::given(method("GET"))
        .and(path("/balance"))
        .respond_with(ResponseTemplate::new(status))
        .mount(server)
        .await;
}

/// Mount `POST /pushtx` returning 2xx (body is ignored on success).
pub async fn mount_pushtx_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/pushtx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(server)
        .await;
}

/// Mount `GET /rawtx/{txid}` returning `body_hex` — the raw
/// transaction the `psbt create` Creator fetches for legacy
/// (P2PKH) inputs' `NON_WITNESS_UTXO` (blockchain.info wire format:
/// the body IS the hex string).
pub async fn mount_rawtx(server: &MockServer, txid_hex: &str, body_hex: String) {
    Mock::given(method("GET"))
        .and(path(format!("/rawtx/{txid_hex}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(body_hex))
        .mount(server)
        .await;
}

/// Mount `POST /pushtx` failing with `status` (drives
/// `NetError::Broadcast` → `CliError::Network`).
pub async fn mount_pushtx_error(server: &MockServer, status: u16) {
    Mock::given(method("POST"))
        .and(path("/pushtx"))
        .respond_with(ResponseTemplate::new(status).set_body_string("rejected"))
        .mount(server)
        .await;
}

/// Bitcoin txid convention: reversed double-SHA256 of the raw bytes.
pub fn txid_of(raw: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let h1 = Sha256::digest(raw);
    let mut h2 = Sha256::digest(h1);
    h2.reverse();
    hex::encode(h2)
}
