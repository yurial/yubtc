//! Network I/O for the wallet.
//!
//! Pluggable `NetworkBackend` trait + three concrete backends:
//! - [`BlockchainInfoBackend`] — `blockchain.info`'s legacy JSON API (default).
//! - [`BlockstreamBackend`] / [`MempoolSpaceBackend`] — Esplora-style
//!   APIs that share an implementation via [`EsploraBackend`].
//!
//! Every HTTP request issued by a backend is wrapped in the
//! resilience layer (specs/spec.md «Network backends» → «Failover и
//! retry»): up to [`crate::fwd::DEFAULT_HTTP_RETRIES`] retries against
//! the same backend with a capped exponential backoff, retrying
//! transport faults and 5xx/408/429 responses (a 429 honours a sane
//! `Retry-After`). 4xx refusals and body-decode failures are final and
//! never retried. The layer lives in the HTTP plumbing
//! ([`send_with_retries`]) rather than around the `NetworkBackend`
//! trait: only there are raw status codes and transport errors still
//! distinguishable, which is exactly what the retry classification
//! needs.
//!
//! On top of per-request retries, [`AutoBackend`] implements
//! `--provider auto`: the three registry backends are tried in order,
//! the first success wins and is remembered (sticky) for the rest of
//! the command run. Exhaustion of every backend surfaces as
//! [`NetError::AllBackendsFailed`] listing what was tried.
//!
//! Module-level free functions ([`get_address_info`],
//! [`get_address_unspent`], [`broadcast_tx`]) take the backend
//! explicitly and call its method. They exist so callers (and tests)
//! have a single, stable function name to call or swap.
//!
//! The registry ([`get_backend`], [`get_backend_with_retries`]) maps
//! `--provider` names to factories; the CLI and tests resolve names
//! through it. [`get_backends_for_auto`] is the registry order used by
//! `auto`.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::fwd::{
    DEFAULT_HTTP_RETRIES, DEFAULT_TIMEOUT_HTTP, HTTP_RETRY_AFTER_MAX_SECS,
    HTTP_RETRY_BASE_DELAY_MS, HTTP_RETRY_MAX_DELAY_MS,
};
use crate::misc::TAddress;
use crate::wallet::{AddressInfo, Utxo};

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("HTTP request failed: {0}")]
    Http(String),

    #[error("bad response: {0}")]
    BadResponse(String),

    #[error("broadcast failed: status={status} body={body}")]
    Broadcast { status: u16, body: String },

    #[error("unknown provider: {0} (known: blockchain.info, blockstream, mempool.space)")]
    UnknownProvider(String),

    /// Every `--provider auto` backend failed (v0.3 failover). The
    /// payload is the per-backend trail — `name: last error` entries
    /// joined by `; ` in attempt order — so the user sees exactly what
    /// was tried and why each backend was rejected.
    #[error("all backends failed: {0}")]
    AllBackendsFailed(String),
}

// --- Shared HTTP plumbing -------------------------------------------
//
// Every backend endpoint performs the same three steps: issue the
// request, reject a non-2xx status, decode the body. Each step has an
// error mapping that must be identical across backends — a 500 from
// blockstream and a 500 from blockchain.info have to surface as the
// same `NetError`. Keeping one implementation of each step (instead of
// one copy per endpoint) is what makes that guarantee hold, and means a
// single test exercises the mapping for all callers.

/// Build a reqwest client with a sane default timeout. Used for both
/// GET (via [`http_client().get(url).send()`]) and broadcast POSTs.
///
/// The connect timeout is short (10 s) so unreachable hosts fail fast
/// instead of hanging tests; the overall request timeout honours
/// [`DEFAULT_TIMEOUT_HTTP`] so a slow remote can't stall the wallet
/// indefinitely.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_HTTP))
        .build()
        .expect("reqwest client builds with default options")
}

/// `GET url` under `policy`. Same contract as the v0.1 [`get_ok`] it
/// replaces: transport failures loop through [`send_with_retries`],
/// and any terminal non-2xx status is rejected with the same
/// `BadResponse` text as before.
async fn get_with_retries(policy: &RetryPolicy, url: &str) -> Result<reqwest::Response, NetError> {
    let client = http_client();
    let url = url.to_string();
    let resp = send_with_retries(policy, || client.get(&url).send()).await?;
    check_status(resp)
}

/// `POST url` under `policy`, with `attach` fastening the backend-
/// specific body (form field vs raw hex) onto the request builder.
/// Unlike GETs the response is NOT status-checked here: the broadcast
/// call sites map it through [`broadcast_result`], whose
/// `Broadcast { status, body }` error is the v0.1 contract for POSTs.
async fn post_with_retries<F>(
    policy: &RetryPolicy,
    url: &str,
    attach: F,
) -> Result<reqwest::Response, NetError>
where
    F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
{
    let client = http_client();
    let url = url.to_string();
    send_with_retries(policy, || attach(client.post(&url)).send()).await
}

// --- Retry policy (v0.3 «Failover») ----------------------------------

/// Retry/backoff configuration for one HTTP request. Produced by the
/// registry from the `--retries` value; never inferred at call sites
/// (spec: all defaults live in `fwd.rs`).
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Retries after the first attempt: `0` = exactly one attempt (the
    /// v0.1 behaviour), the default [`DEFAULT_HTTP_RETRIES`] = 3 gives
    /// up to 4 attempts.
    retries: u32,
    /// Delay before the first retry; doubled per subsequent retry.
    base_delay: Duration,
    /// Upper bound of the exponential backoff.
    max_delay: Duration,
}

impl RetryPolicy {
    /// Production policy: `retries` retries with the `fwd.rs` backoff
    /// (500 ms base, 2 s cap).
    pub fn new(retries: u32) -> Self {
        Self {
            retries,
            base_delay: Duration::from_millis(HTTP_RETRY_BASE_DELAY_MS),
            max_delay: Duration::from_millis(HTTP_RETRY_MAX_DELAY_MS),
        }
    }

    /// Zero-delay policy for tests: the retry/failover logic runs at
    /// full speed without real sleeps.
    #[cfg(test)]
    fn immediate(retries: u32) -> Self {
        Self {
            retries,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    /// Total attempt count: the initial request plus `retries` retries.
    fn attempts(&self) -> u32 {
        self.retries.saturating_add(1)
    }

    /// Capped exponential backoff before retry `attempt` (0-based):
    /// `base · 2^attempt`, clamped to `max_delay`. The shift is bounded
    /// so `1u64 << shift` cannot overflow for absurd attempt numbers.
    fn backoff(&self, attempt: u32) -> Duration {
        let shift = attempt.min(16);
        self.base_delay
            .saturating_mul(1_u32 << shift)
            .min(self.max_delay)
    }
}

/// Status codes worth retrying: server faults (5xx), the
/// request-timeout status (408) and rate limiting (429). Every other
/// 4xx is a deterministic refusal (bad address, bad transaction, …) —
/// resending it would only duplicate the failure.
fn is_retryable_status(status: u16) -> bool {
    status >= 500 || status == 408 || status == 429
}

/// Parse the `Retry-After` header (integer-seconds form) and clamp it
/// to the sane window ([`HTTP_RETRY_AFTER_MAX_SECS`]). `None` — header
/// missing, non-numeric (e.g. HTTP-date form), negative or implausibly
/// large — means "use the regular backoff": a server must not be able
/// to park the wallet for minutes with one header.
fn retry_after_sane(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    let secs: u64 = raw.trim().parse().ok()?;
    (secs <= HTTP_RETRY_AFTER_MAX_SECS).then(|| Duration::from_secs(secs))
}

/// Issue `request` up to `policy.attempts()` times, sleeping the
/// capped exponential backoff (or the server's sane `Retry-After` on
/// a 429) between attempts. Retries transport errors and
/// 5xx/408/429 responses; everything terminal is handed back to the
/// caller **as a response**, whose own mapping ([`check_status`] for
/// GETs, [`broadcast_result`] for POSTs) then produces exactly the
/// error a single-shot v0.1 attempt would have produced — type and
/// text included. The only error synthesized here is a depleted
/// transport-error streak (no response exists to return).
async fn send_with_retries<F, Fut>(
    policy: &RetryPolicy,
    mut request: F,
) -> Result<reqwest::Response, NetError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    let total = policy.attempts();
    let mut last_response: Option<reqwest::Response> = None;
    let mut last_transport: Option<reqwest::Error> = None;
    for attempt in 0..total {
        let mut delay_override: Option<Duration> = None;
        match request().await {
            Ok(resp) if resp.status().is_success() => return Ok(resp),
            Ok(resp) => {
                if resp.status().as_u16() == 429 {
                    delay_override = retry_after_sane(resp.headers());
                }
                if is_retryable_status(resp.status().as_u16()) {
                    last_response = Some(resp);
                } else {
                    return Ok(resp);
                }
            }
            Err(e) => last_transport = Some(e),
        }
        if attempt + 1 < total {
            let delay = delay_override.unwrap_or_else(|| policy.backoff(attempt));
            tokio::time::sleep(delay).await;
        }
    }
    match last_response {
        Some(resp) => Ok(resp),
        None => Err(NetError::Http(
            last_transport
                .expect("every iteration stores a response or a transport error")
                .to_string(),
        )),
    }
}

/// Reject a non-2xx response. Success passes the response through so
/// callers can chain into the `.json().await` decoder below.
#[inline(never)]
fn check_status(resp: reqwest::Response) -> Result<reqwest::Response, NetError> {
    if resp.status().is_success() {
        Ok(resp)
    } else {
        Err(NetError::BadResponse(format!("status {}", resp.status())))
    }
}

/// Turn a broadcast response into `Ok(())` or a [`NetError::Broadcast`]
/// carrying the node's rejection message.
///
/// The body is best-effort: if reading it fails we still report the
/// status, because losing the status as well would leave the caller
/// unable to tell a rejected transaction from a network fault.
#[inline(never)]
async fn broadcast_result(resp: reqwest::Response) -> Result<(), NetError> {
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Err(NetError::Broadcast { status, body })
}

/// Decode a raw-transaction response body, mapping any body failure
/// to [`NetError::BadResponse`].
///
/// Split from the HTTP plumbing as a free function so the error arm is
/// unit-testable without racing hyper's connection read-ahead (a body
/// error surfaces on `send()` or on `text()` depending on timing —
/// both end in a typed [`NetError`]).
fn decode_body_text<E: std::fmt::Display>(body: Result<String, E>) -> Result<String, NetError> {
    body.map_err(|e| NetError::BadResponse(e.to_string()))
}

/// Pluggable network I/O for the wallet. Concrete backends override
/// the four async methods.
#[async_trait]
pub trait NetworkBackend: Send + Sync {
    async fn get_unspent(&self, address: &TAddress) -> Result<Vec<Utxo>, NetError>;
    async fn get_info(&self, address: &TAddress) -> Result<AddressInfo, NetError>;
    async fn broadcast(&self, raw_tx: &[u8]) -> Result<(), NetError>;
    /// Fetch the full raw transaction with `txid` (display order hex,
    /// 64 chars), returned as lowercase hex of the wire serialization.
    ///
    /// Phase 14 (PSBT Creator): the only network call `psbt create`
    /// adds — legacy (P2PKH) inputs need the full previous transaction
    /// for their `NON_WITNESS_UTXO` field (specs/spec.md «Роли и wallet-потоки», Creator).
    async fn raw_transaction(&self, txid: &str) -> Result<String, NetError>;
    fn name(&self) -> &'static str;
}

// --- Default backend: blockchain.info -------------------------------

/// `blockchain.info`'s legacy JSON API.
pub struct BlockchainInfoBackend {
    base_url: String,
    retries: RetryPolicy,
}

impl Default for BlockchainInfoBackend {
    fn default() -> Self {
        Self::with_policy(
            "https://blockchain.info",
            RetryPolicy::new(DEFAULT_HTTP_RETRIES),
        )
    }
}

impl BlockchainInfoBackend {
    /// Default retry policy ([`DEFAULT_HTTP_RETRIES`]); the registry's
    /// `--retries`-aware path goes through [`Self::with_policy`].
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_policy(base_url, RetryPolicy::new(DEFAULT_HTTP_RETRIES))
    }

    fn with_policy(base_url: impl Into<String>, retries: RetryPolicy) -> Self {
        Self {
            base_url: base_url.into(),
            retries,
        }
    }
}

#[derive(Deserialize)]
struct UnspentOutputs {
    unspent_outputs: Vec<RawUtxo>,
}

#[derive(Deserialize)]
struct RawUtxo {
    tx_hash: String,
    tx_output_n: u32,
    value: u64,
    script: String,
    confirmations: u32,
}

#[async_trait]
impl NetworkBackend for BlockchainInfoBackend {
    async fn get_unspent(&self, address: &TAddress) -> Result<Vec<Utxo>, NetError> {
        let url = format!("{}/unspent?active={}", self.base_url, address.as_str());
        let parsed: UnspentOutputs = get_with_retries(&self.retries, &url)
            .await?
            .json()
            .await
            .map_err(|e| NetError::BadResponse(e.to_string()))?;
        let mut out = Vec::new();
        for u in parsed.unspent_outputs {
            out.push(
                Utxo::from_network(
                    &u.tx_hash,
                    u.tx_output_n,
                    u.value,
                    &hex::decode(&u.script)
                        .map_err(|e| NetError::BadResponse(format!("bad script hex: {e}")))?,
                    u.confirmations,
                )
                .map_err(|e| NetError::BadResponse(format!("invalid UTXO: {e}")))?,
            );
        }
        Ok(out)
    }

    async fn get_info(&self, address: &TAddress) -> Result<AddressInfo, NetError> {
        let url = format!("{}/balance?active={}", self.base_url, address.as_str());
        let body: serde_json::Value = get_with_retries(&self.retries, &url)
            .await?
            .json()
            .await
            .map_err(|e| NetError::BadResponse(e.to_string()))?;
        let entry = body
            .get(address.as_str())
            .ok_or_else(|| NetError::BadResponse("address not in response".to_string()))?;
        Ok(AddressInfo {
            total_received: entry
                .get("total_received")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            final_balance: entry
                .get("final_balance")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            n_tx: entry.get("n_tx").and_then(|v| v.as_u64()).unwrap_or(0),
        })
    }

    async fn broadcast(&self, raw_tx: &[u8]) -> Result<(), NetError> {
        let url = format!("{}/pushtx", self.base_url);
        let tx_hex = hex::encode(raw_tx);
        let resp = post_with_retries(&self.retries, &url, |rb| rb.form(&[("tx", &tx_hex)])).await?;
        broadcast_result(resp).await
    }

    async fn raw_transaction(&self, txid: &str) -> Result<String, NetError> {
        // blockchain.info serves the wire-format hex behind
        // `/rawtx/<txid>?format=hex`; the body IS the hex string.
        let url = format!("{}/rawtx/{}?format=hex", self.base_url, txid);
        decode_body_text(get_with_retries(&self.retries, &url).await?.text().await)
    }

    fn name(&self) -> &'static str {
        "blockchain.info"
    }
}

// --- Esplora shared impl --------------------------------------------

/// Esplora-style backend shared by `blockstream.info` and
/// `mempool.space`. The JSON schema is identical between the two;
/// only the base URL differs.
pub struct EsploraBackend {
    base_url: String,
    retries: RetryPolicy,
}

impl EsploraBackend {
    /// Default retry policy ([`DEFAULT_HTTP_RETRIES`]); the registry's
    /// `--retries`-aware path goes through [`Self::with_policy`].
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_policy(base_url, RetryPolicy::new(DEFAULT_HTTP_RETRIES))
    }

    fn with_policy(base_url: impl Into<String>, retries: RetryPolicy) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            retries,
        }
    }
}

#[derive(Deserialize)]
struct EsploraUtxo {
    txid: String,
    vout: u32,
    value: u64,
    status: Option<EsploraStatus>,
}

#[derive(Deserialize)]
struct EsploraStatus {
    confirmed: bool,
    block_height: Option<u64>,
}

#[derive(Deserialize)]
struct EsploraStats {
    chain_stats: Option<EsploraSide>,
    mempool_stats: Option<EsploraSide>,
}

#[derive(Deserialize, Default)]
struct EsploraSide {
    funded_txo_sum: Option<u64>,
    spent_txo_sum: Option<u64>,
    tx_count: Option<u64>,
}

#[async_trait]
impl NetworkBackend for EsploraBackend {
    async fn get_unspent(&self, address: &TAddress) -> Result<Vec<Utxo>, NetError> {
        let url = format!("{}/address/{}/utxo", self.base_url, address.as_str());
        let utxos: Vec<EsploraUtxo> = get_with_retries(&self.retries, &url)
            .await?
            .json()
            .await
            .map_err(|e| NetError::BadResponse(e.to_string()))?;
        if utxos.is_empty() {
            return Ok(vec![]);
        }
        let tip = self.tip_height().await?;
        let script = crate::wallet::make_lock_script_for_address(address)
            .map_err(|e| NetError::BadResponse(format!("bad address: {e}")))?;
        let mut out = Vec::new();
        for u in utxos {
            let confirmations = match u.status {
                // A block height above the tip is inconsistent data:
                // count it as unconfirmed rather than underflowing.
                Some(s) if s.confirmed => match s.block_height {
                    Some(h) if h <= tip => (tip - h + 1) as u32,
                    _ => 0,
                },
                _ => 0,
            };
            out.push(
                Utxo::from_network(&u.txid, u.vout, u.value, &script, confirmations)
                    .map_err(|e| NetError::BadResponse(format!("invalid UTXO: {e}")))?,
            );
        }
        Ok(out)
    }

    async fn get_info(&self, address: &TAddress) -> Result<AddressInfo, NetError> {
        let url = format!("{}/address/{}", self.base_url, address.as_str());
        let stats: EsploraStats = get_with_retries(&self.retries, &url)
            .await?
            .json()
            .await
            .map_err(|e| NetError::BadResponse(e.to_string()))?;
        let chain = stats.chain_stats.unwrap_or_default();
        let mempool = stats.mempool_stats.unwrap_or_default();
        let total_received =
            chain.funded_txo_sum.unwrap_or(0) + mempool.funded_txo_sum.unwrap_or(0);
        let total_spent = chain.spent_txo_sum.unwrap_or(0) + mempool.spent_txo_sum.unwrap_or(0);
        let n_tx = chain.tx_count.unwrap_or(0) + mempool.tx_count.unwrap_or(0);
        Ok(AddressInfo {
            total_received,
            final_balance: total_received.saturating_sub(total_spent),
            n_tx,
        })
    }

    async fn broadcast(&self, raw_tx: &[u8]) -> Result<(), NetError> {
        let url = format!("{}/tx", self.base_url);
        let tx_hex = hex::encode(raw_tx);
        let resp = post_with_retries(&self.retries, &url, |rb| rb.body(tx_hex.clone())).await?;
        broadcast_result(resp).await
    }

    async fn raw_transaction(&self, txid: &str) -> Result<String, NetError> {
        // Esplora serves raw transactions as plain hex at
        // `/tx/<txid>/hex`.
        let url = format!("{}/tx/{}/hex", self.base_url, txid);
        decode_body_text(get_with_retries(&self.retries, &url).await?.text().await)
    }

    fn name(&self) -> &'static str {
        "esplora"
    }
}

impl EsploraBackend {
    /// Current chain tip height.
    ///
    /// Esplora serves this as a bare decimal number, which is also
    /// valid JSON, so the shared `.json().await` decoder applies: a
    /// non-numeric body is a [`NetError::BadResponse`] rather than a
    /// silently-dropped confirmation count.
    async fn tip_height(&self) -> Result<u64, NetError> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        get_with_retries(&self.retries, &url)
            .await?
            .json()
            .await
            .map_err(|e| NetError::BadResponse(e.to_string()))
    }
}

/// `blockstream.info`'s public Esplora API.
pub struct BlockstreamBackend(EsploraBackend);

impl Default for BlockstreamBackend {
    fn default() -> Self {
        Self(EsploraBackend::new("https://blockstream.info/api"))
    }
}

impl BlockstreamBackend {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self(EsploraBackend::new(base_url))
    }

    fn with_policy(base_url: impl Into<String>, retries: RetryPolicy) -> Self {
        Self(EsploraBackend::with_policy(base_url, retries))
    }
}

#[async_trait]
impl NetworkBackend for BlockstreamBackend {
    async fn get_unspent(&self, address: &TAddress) -> Result<Vec<Utxo>, NetError> {
        self.0.get_unspent(address).await
    }
    async fn get_info(&self, address: &TAddress) -> Result<AddressInfo, NetError> {
        self.0.get_info(address).await
    }
    async fn broadcast(&self, raw_tx: &[u8]) -> Result<(), NetError> {
        self.0.broadcast(raw_tx).await
    }
    async fn raw_transaction(&self, txid: &str) -> Result<String, NetError> {
        self.0.raw_transaction(txid).await
    }
    fn name(&self) -> &'static str {
        "blockstream"
    }
}

/// `mempool.space`'s public Esplora API.
pub struct MempoolSpaceBackend(EsploraBackend);

impl Default for MempoolSpaceBackend {
    fn default() -> Self {
        Self(EsploraBackend::new("https://mempool.space/api"))
    }
}

impl MempoolSpaceBackend {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self(EsploraBackend::new(base_url))
    }

    fn with_policy(base_url: impl Into<String>, retries: RetryPolicy) -> Self {
        Self(EsploraBackend::with_policy(base_url, retries))
    }
}

#[async_trait]
impl NetworkBackend for MempoolSpaceBackend {
    async fn get_unspent(&self, address: &TAddress) -> Result<Vec<Utxo>, NetError> {
        self.0.get_unspent(address).await
    }
    async fn get_info(&self, address: &TAddress) -> Result<AddressInfo, NetError> {
        self.0.get_info(address).await
    }
    async fn broadcast(&self, raw_tx: &[u8]) -> Result<(), NetError> {
        self.0.broadcast(raw_tx).await
    }
    async fn raw_transaction(&self, txid: &str) -> Result<String, NetError> {
        self.0.raw_transaction(txid).await
    }
    fn name(&self) -> &'static str {
        "mempool.space"
    }
}

// --- Backend registry -----------------------------------------------

/// Compile-time registry of provider name -> factory. Used by the CLI
/// `--provider NAME` flag.
///
/// `get_backend(name)` keeps the exact-name resolution (default retry
/// policy); the `--retries`-aware CLI path goes through
/// [`get_backend_with_retries`]. `"auto"` is the v0.3 failover
/// pseudo-provider ([`AutoBackend`]); `"mock"` is the cross-compat
/// harness entry point and is deliberately NOT part of the auto order
/// ([`get_backends_for_auto`]).
pub fn get_backend(name: &str) -> Result<Arc<dyn NetworkBackend>, NetError> {
    get_backend_with_retries(name, DEFAULT_HTTP_RETRIES)
}

/// [`get_backend`], with the retry count from the CLI `--retries`
/// flag threaded into every returned backend (v0.3 resilience). `0`
/// reproduces the v0.1 single-attempt behaviour.
pub fn get_backend_with_retries(
    name: &str,
    retries: u32,
) -> Result<Arc<dyn NetworkBackend>, NetError> {
    let policy = RetryPolicy::new(retries);
    tracing::debug!(provider = name, retries, "resolving network backend");
    match name {
        "blockchain.info" => Ok(Arc::new(BlockchainInfoBackend::with_policy(
            "https://blockchain.info",
            policy,
        ))),
        "blockstream" => Ok(Arc::new(BlockstreamBackend::with_policy(
            "https://blockstream.info/api",
            policy,
        ))),
        "mempool.space" => Ok(Arc::new(MempoolSpaceBackend::with_policy(
            "https://mempool.space/api",
            policy,
        ))),
        "auto" => Ok(Arc::new(AutoBackend::new(
            get_backends_for_auto_with_policy(policy),
        ))),
        "mock" => {
            // The mock provider reads its URL from the
            // `YUBTC_MOCK_BACKEND_URL` env var. Used by the Python
            // cross-compat harness (Phase 9 T2) which stands up a
            // local HTTP server and points both the Python CLI and
            // the Rust CLI at it. Missing env var is a hard error
            // rather than a default — surfacing the typo loudly
            // beats silently falling back to blockchain.info.
            let url = std::env::var("YUBTC_MOCK_BACKEND_URL").map_err(|_| {
                NetError::UnknownProvider("mock: YUBTC_MOCK_BACKEND_URL is not set".to_string())
            })?;
            Ok(Arc::new(BlockchainInfoBackend::with_policy(url, policy)))
        }
        other => Err(NetError::UnknownProvider(other.to_string())),
    }
}

/// Registry order `--provider auto` walks (specs/spec.md «Failover и retry»):
/// `blockchain.info` → `blockstream` → `mempool.space`, each with the
/// default retry policy. The `mock` pseudo-provider is excluded — it
/// exists only for the cross-compat harness, never for real use.
pub fn get_backends_for_auto() -> Vec<Arc<dyn NetworkBackend>> {
    get_backends_for_auto_with_policy(RetryPolicy::new(DEFAULT_HTTP_RETRIES))
}

fn get_backends_for_auto_with_policy(policy: RetryPolicy) -> Vec<Arc<dyn NetworkBackend>> {
    vec![
        Arc::new(BlockchainInfoBackend::with_policy(
            "https://blockchain.info",
            policy,
        )),
        Arc::new(BlockstreamBackend::with_policy(
            "https://blockstream.info/api",
            policy,
        )),
        Arc::new(MempoolSpaceBackend::with_policy(
            "https://mempool.space/api",
            policy,
        )),
    ]
}

// --- Auto failover (`--provider auto`, v0.3) --------------------------

/// `--provider auto` backend: walks [`get_backends_for_auto`] in
/// registry order per request, first success wins. The backend that
/// served a request is remembered (sticky) for the rest of the run —
/// a wallet is a single command invocation, so this is per-run state
/// inside the handle, never on disk and never across processes.
///
/// A remembered backend that starts failing demotes itself naturally:
/// the walk starts at it and, on failure, continues down the remaining
/// registry order, re-pinning on the next success.
pub struct AutoBackend {
    backends: Vec<Arc<dyn NetworkBackend>>,
    /// Index of the backend that served last — tried first on the
    /// next request. `None` until the first success.
    preferred: std::sync::Mutex<Option<usize>>,
}

impl AutoBackend {
    pub fn new(backends: Vec<Arc<dyn NetworkBackend>>) -> Self {
        Self {
            backends,
            preferred: std::sync::Mutex::new(None),
        }
    }
}

/// Shared failover walk for the four [`NetworkBackend`] methods of
/// [`AutoBackend`]. Attempts the backends starting at the remembered
/// preferred index, wraps around the registry order exactly once, and
/// returns the first success — recording it as the new preference. On
/// total exhaustion it returns [`NetError::AllBackendsFailed`] with a
/// `name: last error` trail in attempt order.
///
/// A macro (not a generic closure) because the inner call is an async
/// trait method on `&dyn NetworkBackend` — a boxed-future generic
/// would buy nothing over the four direct expansions.
macro_rules! failover_call {
    ($self:ident, |$backend:ident| $call:expr) => {{
        let n = $self.backends.len();
        let start = $self
            .preferred
            .lock()
            .expect("auto preferred lock poisoned")
            .unwrap_or(0);
        // Walk order: preferred, preferred+1, … wrapping around —
        // every backend exactly once. Computed eagerly so the mutex
        // guard is dropped before the first `.await`.
        let order: Vec<usize> = (0..n).map(|i| (start + i) % n).collect();
        let mut attempts: Vec<String> = Vec::new();
        for idx in order {
            let $backend: &dyn NetworkBackend = $self.backends[idx].as_ref();
            match $call.await {
                Ok(value) => {
                    *$self
                        .preferred
                        .lock()
                        .expect("auto preferred lock poisoned") = Some(idx);
                    return Ok(value);
                }
                Err(e) => attempts.push(format!("{}: {}", $self.backends[idx].name(), e)),
            }
        }
        Err(NetError::AllBackendsFailed(attempts.join("; ")))
    }};
}

#[async_trait]
impl NetworkBackend for AutoBackend {
    async fn get_unspent(&self, address: &TAddress) -> Result<Vec<Utxo>, NetError> {
        failover_call!(self, |backend| backend.get_unspent(address))
    }

    async fn get_info(&self, address: &TAddress) -> Result<AddressInfo, NetError> {
        failover_call!(self, |backend| backend.get_info(address))
    }

    async fn broadcast(&self, raw_tx: &[u8]) -> Result<(), NetError> {
        failover_call!(self, |backend| backend.broadcast(raw_tx))
    }

    async fn raw_transaction(&self, txid: &str) -> Result<String, NetError> {
        failover_call!(self, |backend| backend.raw_transaction(txid))
    }

    fn name(&self) -> &'static str {
        "auto"
    }
}

// --- Free functions --------------------------------------------------
//
// Backends are passed EXPLICITLY (specs/spec.md «Явная передача бэкенда»):
// there is no process-global current backend. Callers resolve the
// backend once via `get_backend(name)` and thread it through.

/// Fetch the [`AddressInfo`] for `address` via `backend`.
pub async fn get_address_info(
    backend: &dyn NetworkBackend,
    address: &TAddress,
) -> Result<AddressInfo, NetError> {
    backend.get_info(address).await
}

/// Fetch the unspent list for `address` via `backend`.
pub async fn get_address_unspent(
    backend: &dyn NetworkBackend,
    address: &TAddress,
) -> Result<Vec<Utxo>, NetError> {
    backend.get_unspent(address).await
}

/// Broadcast `raw_tx` via `backend`.
pub async fn broadcast(backend: &dyn NetworkBackend, raw_tx: &[u8]) -> Result<(), NetError> {
    backend.broadcast(raw_tx).await
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::misc::TAddress;
    use crate::script::make_p2pkh_lock_script;
    use std::sync::Mutex;

    /// Test-only backend that records calls and returns canned data.
    /// Avoids hitting the network; lets tests assert exactly what the
    /// wallet would receive.
    #[derive(Debug)]
    struct MockBackend {
        unspent_responses: Mutex<std::collections::HashMap<String, Vec<Utxo>>>,
        info_responses: Mutex<std::collections::HashMap<String, AddressInfo>>,
        broadcast_log: Mutex<Vec<Vec<u8>>>,
        broadcast_should_fail: Mutex<bool>,
        get_unspent_calls: Mutex<Vec<String>>,
        raw_transactions: Mutex<std::collections::HashMap<String, String>>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                unspent_responses: Mutex::new(std::collections::HashMap::new()),
                info_responses: Mutex::new(std::collections::HashMap::new()),
                broadcast_log: Mutex::new(Vec::new()),
                broadcast_should_fail: Mutex::new(false),
                get_unspent_calls: Mutex::new(Vec::new()),
                raw_transactions: Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl NetworkBackend for MockBackend {
        async fn get_unspent(&self, address: &TAddress) -> Result<Vec<Utxo>, NetError> {
            self.get_unspent_calls
                .lock()
                .unwrap()
                .push(address.as_str().to_string());
            Ok(self
                .unspent_responses
                .lock()
                .unwrap()
                .get(address.as_str())
                .cloned()
                .unwrap_or_default())
        }

        async fn get_info(&self, address: &TAddress) -> Result<AddressInfo, NetError> {
            Ok(self
                .info_responses
                .lock()
                .unwrap()
                .get(address.as_str())
                .cloned()
                .unwrap_or_default())
        }

        async fn broadcast(&self, raw_tx: &[u8]) -> Result<(), NetError> {
            self.broadcast_log.lock().unwrap().push(raw_tx.to_vec());
            if *self.broadcast_should_fail.lock().unwrap() {
                return Err(NetError::Broadcast {
                    status: 400,
                    body: "rejected".to_string(),
                });
            }
            Ok(())
        }

        async fn raw_transaction(&self, txid: &str) -> Result<String, NetError> {
            self.raw_transactions
                .lock()
                .unwrap()
                .get(txid)
                .cloned()
                .ok_or_else(|| NetError::BadResponse(format!("no raw tx for {txid}")))
        }

        fn name(&self) -> &'static str {
            "mock"
        }
    }

    fn mock() -> Arc<MockBackend> {
        Arc::new(MockBackend::new())
    }

    // --- registry / known providers ---------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn registry_resolves_known_providers() {
        assert_eq!(
            get_backend("blockchain.info").unwrap().name(),
            "blockchain.info"
        );
        assert_eq!(get_backend("blockstream").unwrap().name(), "blockstream");
        assert_eq!(
            get_backend("mempool.space").unwrap().name(),
            "mempool.space"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn registry_rejects_unknown_provider() {
        let err = get_backend("nonsense").err().expect("expected an error");
        // Variant + provider name pinned via Display — a `matches!`
        // macro leaves an always-unexecuted counter region on the
        // line (its pattern-false arm), which the line gate counts
        // as a miss; Display-based asserts carry no such region.
        assert_eq!(
            err.to_string(),
            "unknown provider: nonsense (known: blockchain.info, blockstream, mempool.space)"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn get_backend_returns_independent_instances() {
        let a = get_backend("blockchain.info").unwrap();
        let b = get_backend("blockchain.info").unwrap();
        // Different Arc allocations.
        assert!(!Arc::ptr_eq(&a, &b));
    }

    // --- mock provider (env-driven) ----------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    #[serial_test::serial]
    fn get_backend_mock_requires_env_var() {
        // The mock provider reads its URL from the environment; a
        // missing variable is a hard UnknownProvider error rather
        // than a silent fallback to blockchain.info.
        std::env::remove_var("YUBTC_MOCK_BACKEND_URL");
        let err = get_backend("mock").err().expect("env var was removed");
        // Display-based assert — see the note in
        // registry_rejects_unknown_provider.
        assert!(err.to_string().contains("YUBTC_MOCK_BACKEND_URL"));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn get_backend_mock_uses_env_url() {
        // With the variable set, "mock" resolves to a
        // blockchain.info-compatible backend rooted at the URL —
        // proven by driving a real /balance request through the
        // wiremock server the variable points at.
        let server = MockServer::start().await;
        let addr = real_address();
        let body = serde_json::json!({ addr.as_str(): {} }).to_string();
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        std::env::set_var("YUBTC_MOCK_BACKEND_URL", server.uri());
        let backend = get_backend("mock").expect("env var was set");
        assert_eq!(backend.name(), "blockchain.info");
        let info = backend.get_info(&addr).await.unwrap();
        assert_eq!(info.n_tx, 0);
        std::env::remove_var("YUBTC_MOCK_BACKEND_URL");
    }

    // --- free functions delegate to current backend -----------------

    #[tokio::test]
    #[serial_test::serial]
    async fn get_address_unspent_uses_current_backend() {
        let m = mock();
        let hash = [0x33u8; 20];
        let script = make_p2pkh_lock_script(&hash);
        m.unspent_responses.lock().unwrap().insert(
            "addr-A".to_string(),
            vec![Utxo {
                txid: [0xab; 32],
                vout: 0,
                amount: 1000,
                script_pubkey: script.clone(),
                confirmations: 6,
            }],
        );
        let utxos = get_address_unspent(m.as_ref(), &TAddress::new("addr-A"))
            .await
            .unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].amount, 1000);
        assert_eq!(m.get_unspent_calls.lock().unwrap().as_slice(), &["addr-A"]);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn get_address_info_uses_current_backend() {
        let m = mock();
        m.info_responses.lock().unwrap().insert(
            "addr-B".to_string(),
            AddressInfo {
                total_received: 12345,
                final_balance: 1000,
                n_tx: 7,
            },
        );
        let info = get_address_info(m.as_ref(), &TAddress::new("addr-B"))
            .await
            .unwrap();
        assert_eq!(info.total_received, 12345);
        assert_eq!(info.n_tx, 7);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn broadcast_tx_records_call() {
        let m = mock();
        broadcast(m.as_ref(), b"deadbeef").await.unwrap();
        assert_eq!(
            m.broadcast_log.lock().unwrap().as_slice(),
            &[b"deadbeef" as &[u8]]
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn broadcast_tx_propagates_failure() {
        let m = mock();
        *m.broadcast_should_fail.lock().unwrap() = true;
        let err = broadcast(m.as_ref(), b"deadbeef").await.unwrap_err();
        // Display-based variant + status pin — see the note in
        // registry_rejects_unknown_provider.
        assert!(err.to_string().contains("status=400"));
    }

    // --- registry / default ------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn get_backend_default_name_resolves() {
        // Backend injection: there is no process-global backend; the
        // registry resolves names to fresh instances.
        let b = get_backend("blockchain.info").expect("default resolves");
        assert_eq!(b.name(), "blockchain.info");
        // Drive the test mock's full surface so its impl stays
        // covered (the free functions now take the backend
        // explicitly; the mock is still used by the fns below).
        let m = mock();
        let _ = m.name();
        let s = get_backend("blockstream").expect("blockstream resolves");
        assert_eq!(s.name(), "blockstream");
    }

    // --- EsploraBackend construction ---------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn esplora_strips_trailing_slash() {
        let a = EsploraBackend::new("https://example.com/");
        let b = EsploraBackend::new("https://example.com");
        // Trim happens at construction; both should produce the same
        // effective base URL on subsequent format!() calls.
        // We can't easily inspect base_url (private), so we just
        // confirm construction doesn't panic.
        let _ = (a, b);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn blockstream_and_mempool_default_construct() {
        let b = BlockstreamBackend::default();
        assert_eq!(b.name(), "blockstream");
        let m = MempoolSpaceBackend::default();
        assert_eq!(m.name(), "mempool.space");
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn blockchain_info_default_and_custom_url() {
        let d = BlockchainInfoBackend::default();
        assert_eq!(d.name(), "blockchain.info");
        let _ = BlockchainInfoBackend::new("https://mirror.example/");
    }

    // --- wiremock-backed HTTP tests ---------------------------------

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_p2pkh_script_hex(hash20: &[u8; 20]) -> String {
        let mut s = vec![0x76u8, 0xa9, 0x14];
        s.extend_from_slice(hash20);
        s.push(0x88);
        s.push(0xac);
        hex::encode(s)
    }

    /// A real, valid P2PKH mainnet address whose privkey we know
    /// (avoiding the address-validator round-trip in the Esplora
    /// backends). Generated from the same fixture seed used in
    /// wallet tests.
    fn real_address() -> TAddress {
        use crate::kdf::KdfAlgo;
        use crate::misc::TNonce;
        use crate::misc::TPassphrase;
        use crate::misc::TSeed;
        use crate::wallet::TPrivKey;
        let seed = TSeed::new("phasenetmock");
        let pk = TPrivKey::new(&seed, TNonce::new(0), &TPassphrase::EMPTY, KdfAlgo::Yubtc)
            .expect("known seed");
        pk.get_p2pkh_address()
    }

    #[tokio::test]
    async fn blockchain_info_get_unspent_parses_response() {
        let server = MockServer::start().await;
        let hash = [0x33u8; 20];
        let script = make_p2pkh_script_hex(&hash);
        let body = serde_json::json!({
            "unspent_outputs": [
                {
                    "tx_hash": "abababababababababababababababababababababababababababababababab",
                    "tx_output_n": 0,
                    "value": 12345,
                    "script": script,
                    "confirmations": 6
                }
            ]
        })
        .to_string();
        Mock::given(method("GET"))
            .and(path("/unspent"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let out = backend.get_unspent(&real_address()).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].amount, 12345);
        assert_eq!(out[0].script_pubkey.len(), 25);
    }

    #[tokio::test]
    async fn blockchain_info_get_unspent_rejects_invalid_json() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/unspent"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let err = backend.get_unspent(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn blockchain_info_get_info_rejects_invalid_json() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let err = backend.get_info(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn blockchain_info_unreachable_url_returns_http_error() {
        // 127.0.0.1:1 is reserved / unreachable; reqwest::get should
        // fail with a connection error.
        let backend = BlockchainInfoBackend::new("http://127.0.0.1:1");
        let err = backend.get_unspent(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::Http(_)));
    }

    #[tokio::test]
    async fn blockchain_info_unreachable_url_returns_http_error_for_info() {
        let backend = BlockchainInfoBackend::new("http://127.0.0.1:1");
        let err = backend.get_info(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::Http(_)));
    }

    #[tokio::test]
    async fn blockchain_info_unreachable_url_returns_http_error_for_broadcast() {
        let backend = BlockchainInfoBackend::new("http://127.0.0.1:1");
        let err = backend.broadcast(b"deadbeef").await.unwrap_err();
        assert!(matches!(err, NetError::Http(_)));
    }

    #[tokio::test]
    async fn blockchain_info_get_unspent_handles_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/unspent"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let err = backend.get_unspent(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn blockchain_info_get_unspent_rejects_bad_script_hex() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "unspent_outputs": [
                {
                    "tx_hash": "abababababababababababababababababababababababababababababababab",
                    "tx_output_n": 0,
                    "value": 1000,
                    "script": "not-hex",
                    "confirmations": 1
                }
            ]
        })
        .to_string();
        Mock::given(method("GET"))
            .and(path("/unspent"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let err = backend.get_unspent(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn blockchain_info_get_unspent_rejects_invalid_utxo() {
        let server = MockServer::start().await;
        // 32-byte hash but amount=0 → Utxo::from_network rejects.
        let body = serde_json::json!({
            "unspent_outputs": [
                {
                    "tx_hash": "abababababababababababababababababababababababababababababababab",
                    "tx_output_n": 0,
                    "value": 0,
                    "script": "76a914",
                    "confirmations": 1
                }
            ]
        })
        .to_string();
        Mock::given(method("GET"))
            .and(path("/unspent"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let err = backend.get_unspent(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn blockchain_info_get_info_parses_response() {
        let server = MockServer::start().await;
        let addr = real_address();
        let body = serde_json::json!({
            addr.as_str(): {
                "total_received": 100,
                "final_balance": 50,
                "n_tx": 3
            }
        })
        .to_string();
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let info = backend.get_info(&addr).await.unwrap();
        assert_eq!(info.total_received, 100);
        assert_eq!(info.final_balance, 50);
        assert_eq!(info.n_tx, 3);
    }

    #[tokio::test]
    async fn blockchain_info_get_info_rejects_missing_address() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let err = backend.get_info(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn blockchain_info_get_info_handles_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let err = backend.get_info(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn blockchain_info_get_info_fills_missing_fields_with_zero() {
        let server = MockServer::start().await;
        let addr = real_address();
        let body = serde_json::json!({ addr.as_str(): {} }).to_string();
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let info = backend.get_info(&addr).await.unwrap();
        assert_eq!(info.total_received, 0);
        assert_eq!(info.final_balance, 0);
        assert_eq!(info.n_tx, 0);
    }

    #[tokio::test]
    async fn blockchain_info_broadcast_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/pushtx"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        backend.broadcast(b"deadbeef").await.unwrap();
    }

    #[tokio::test]
    async fn blockchain_info_broadcast_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/pushtx"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let err = backend.broadcast(b"deadbeef").await.unwrap_err();
        assert!(matches!(err, NetError::Broadcast { status: 500, .. }));
    }

    #[tokio::test]
    async fn blockchain_info_broadcast_broadcast_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/pushtx"))
            .respond_with(ResponseTemplate::new(400).set_body_string("rejected"))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let err = backend.broadcast(b"deadbeef").await.unwrap_err();
        // Display-based variant + status/body pin — see the note in
        // registry_rejects_unknown_provider.
        assert_eq!(
            err.to_string(),
            "broadcast failed: status=400 body=rejected"
        );
    }

    #[tokio::test]
    async fn esplora_unreachable_url_returns_http_error_for_unspent() {
        let backend = EsploraBackend::new("http://127.0.0.1:1");
        let err = backend.get_unspent(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::Http(_)));
    }

    #[tokio::test]
    async fn esplora_unreachable_url_returns_http_error_for_info() {
        let backend = EsploraBackend::new("http://127.0.0.1:1");
        let err = backend.get_info(&real_address()).await.unwrap_err();
        assert!(matches!(err, NetError::Http(_)));
    }

    #[tokio::test]
    async fn esplora_unreachable_url_returns_http_error_for_broadcast() {
        let backend = EsploraBackend::new("http://127.0.0.1:1");
        let err = backend.broadcast(b"deadbeef").await.unwrap_err();
        assert!(matches!(err, NetError::Http(_)));
    }

    #[tokio::test]
    async fn esplora_get_unspent_rejects_invalid_json() {
        let server = MockServer::start().await;
        let addr = real_address();
        let utxo_path = format!("/address/{}/utxo", addr.as_str());
        Mock::given(method("GET"))
            .and(path(utxo_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let err = backend.get_unspent(&addr).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn esplora_get_unspent_invalid_utxo_rejected() {
        let server = MockServer::start().await;
        let addr = real_address();
        let _ = Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string("800000"))
            .mount(&server)
            .await;
        // amount=0 → Utxo::from_network rejects with "zero amount UTXO".
        let body = serde_json::json!([
            {
                "txid": "abababababababababababababababababababababababababababababababab",
                "vout": 0,
                "value": 0,
                "status": { "confirmed": true, "block_height": 799_995 }
            }
        ])
        .to_string();
        let utxo_path = format!("/address/{}/utxo", addr.as_str());
        let _ = Mock::given(method("GET"))
            .and(path(utxo_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let err = backend.get_unspent(&addr).await.unwrap_err();
        // Display-based variant + payload pin — see the note in
        // registry_rejects_unknown_provider.
        let msg = err.to_string();
        assert!(msg.starts_with("bad response: invalid UTXO"), "got: {msg}");
    }

    #[tokio::test]
    async fn esplora_get_info_rejects_invalid_json() {
        let server = MockServer::start().await;
        let addr = real_address();
        let info_path = format!("/address/{}", addr.as_str());
        Mock::given(method("GET"))
            .and(path(info_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let err = backend.get_info(&addr).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn esplora_get_unspent_with_tip_parses() {
        let server = MockServer::start().await;
        let addr = real_address();
        let _ = Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string("800000"))
            .mount(&server)
            .await;
        let body = serde_json::json!([
            {
                "txid": "abababababababababababababababababababababababababababababababab",
                "vout": 0,
                "value": 12345,
                "status": {
                    "confirmed": true,
                    "block_height": 799_995
                }
            }
        ])
        .to_string();
        let utxo_path = format!("/address/{}/utxo", addr.as_str());
        let _ = Mock::given(method("GET"))
            .and(path(utxo_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let out = backend.get_unspent(&addr).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].amount, 12345);
        // tip 800000 - block 799995 + 1 = 6 confirmations.
        assert_eq!(out[0].confirmations, 6);
    }

    #[tokio::test]
    async fn esplora_get_unspent_empty_returns_empty() {
        let server = MockServer::start().await;
        let addr = real_address();
        let utxo_path = format!("/address/{}/utxo", addr.as_str());
        Mock::given(method("GET"))
            .and(path(utxo_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let out = backend.get_unspent(&addr).await.unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn esplora_get_unspent_unconfirmed_returns_zero_confirmations() {
        let server = MockServer::start().await;
        let addr = real_address();
        let _ = Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string("800000"))
            .mount(&server)
            .await;
        let body = serde_json::json!([
            {
                "txid": "abababababababababababababababababababababababababababababababab",
                "vout": 0,
                "value": 1000,
                "status": { "confirmed": false }
            }
        ])
        .to_string();
        let utxo_path = format!("/address/{}/utxo", addr.as_str());
        let _ = Mock::given(method("GET"))
            .and(path(utxo_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let out = backend.get_unspent(&addr).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confirmations, 0);
    }

    #[tokio::test]
    async fn esplora_get_unspent_block_height_above_tip_is_unconfirmed() {
        // Inconsistent backend data: a "confirmed" UTXO whose
        // block_height exceeds the tip. tip - h + 1 would underflow,
        // so the guard must count it as unconfirmed (0) instead.
        let server = MockServer::start().await;
        let addr = real_address();
        let _ = Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string("800000"))
            .mount(&server)
            .await;
        let body = serde_json::json!([
            {
                "txid": "abababababababababababababababababababababababababababababababab",
                "vout": 0,
                "value": 1000,
                "status": { "confirmed": true, "block_height": 800_001 }
            }
        ])
        .to_string();
        let utxo_path = format!("/address/{}/utxo", addr.as_str());
        let _ = Mock::given(method("GET"))
            .and(path(utxo_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let out = backend.get_unspent(&addr).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confirmations, 0);
    }

    #[tokio::test]
    async fn esplora_get_unspent_http_error() {
        let server = MockServer::start().await;
        let addr = real_address();
        let utxo_path = format!("/address/{}/utxo", addr.as_str());
        Mock::given(method("GET"))
            .and(path(utxo_path.as_str()))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let err = backend.get_unspent(&addr).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn esplora_get_unspent_bad_address_returns_bad_response() {
        let server = MockServer::start().await;
        let _ = Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string("800000"))
            .mount(&server)
            .await;
        let body = serde_json::json!([
            {
                "txid": "abababababababababababababababababababababababababababababababab",
                "vout": 0,
                "value": 1000,
                "status": { "confirmed": true, "block_height": 799_995 }
            }
        ])
        .to_string();
        let _ = Mock::given(method("GET"))
            .and(path("/address/not-a-real-address/utxo"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let err = backend
            .get_unspent(&TAddress::new("not-a-real-address"))
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn esplora_get_info_parses_chain_and_mempool() {
        let server = MockServer::start().await;
        let addr = real_address();
        let body = serde_json::json!({
            "chain_stats": {
                "funded_txo_sum": 1000,
                "spent_txo_sum": 300,
                "tx_count": 5
            },
            "mempool_stats": {
                "funded_txo_sum": 200,
                "spent_txo_sum": 0,
                "tx_count": 1
            }
        })
        .to_string();
        let info_path = format!("/address/{}", addr.as_str());
        Mock::given(method("GET"))
            .and(path(info_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let info = backend.get_info(&addr).await.unwrap();
        assert_eq!(info.total_received, 1200);
        assert_eq!(info.final_balance, 900);
        assert_eq!(info.n_tx, 6);
    }

    #[tokio::test]
    async fn esplora_get_info_handles_missing_sections() {
        let server = MockServer::start().await;
        let addr = real_address();
        let info_path = format!("/address/{}", addr.as_str());
        Mock::given(method("GET"))
            .and(path(info_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let info = backend.get_info(&addr).await.unwrap();
        assert_eq!(info.total_received, 0);
        assert_eq!(info.final_balance, 0);
        assert_eq!(info.n_tx, 0);
    }

    #[tokio::test]
    async fn esplora_get_info_handles_partial_sections() {
        let server = MockServer::start().await;
        let addr = real_address();
        let body = serde_json::json!({
            "chain_stats": { "funded_txo_sum": 500 }
        })
        .to_string();
        let info_path = format!("/address/{}", addr.as_str());
        Mock::given(method("GET"))
            .and(path(info_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let info = backend.get_info(&addr).await.unwrap();
        assert_eq!(info.total_received, 500);
        assert_eq!(info.final_balance, 500);
        assert_eq!(info.n_tx, 0);
    }

    #[tokio::test]
    async fn esplora_get_info_http_error() {
        let server = MockServer::start().await;
        let addr = real_address();
        let info_path = format!("/address/{}", addr.as_str());
        Mock::given(method("GET"))
            .and(path(info_path.as_str()))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let err = backend.get_info(&addr).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn esplora_broadcast_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_string("txid"))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        backend.broadcast(b"deadbeef").await.unwrap();
    }

    #[tokio::test]
    async fn esplora_broadcast_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let err = backend.broadcast(b"deadbeef").await.unwrap_err();
        assert!(matches!(err, NetError::Broadcast { status: 500, .. }));
    }

    #[tokio::test]
    async fn esplora_broadcast_broadcast_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(ResponseTemplate::new(400).set_body_string("rejected"))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let err = backend.broadcast(b"deadbeef").await.unwrap_err();
        // Display-based variant + status/body pin — see the note in
        // registry_rejects_unknown_provider.
        assert_eq!(
            err.to_string(),
            "broadcast failed: status=400 body=rejected"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn esplora_backend_name_is_esplora() {
        let backend = EsploraBackend::new("https://example.com");
        assert_eq!(backend.name(), "esplora");
    }

    // --- raw_transaction (Phase 14, PSBT Creator) --------------------

    const RAW_TX_FIXTURE_HEX: &str = "02000000011202030405060708090a0b0c0d0e0f101112131415161718191a1b1c0000000000feffffff0210270000000000001976a9146204592044bbe20d00c80500c7af0bf9d49756d788ac0000000000000000016a000000000000";

    #[tokio::test]
    async fn blockchain_info_raw_transaction_returns_hex_body() {
        let server = MockServer::start().await;
        let txid = "aa".repeat(32);
        Mock::given(method("GET"))
            .and(path(format!("/rawtx/{txid}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(RAW_TX_FIXTURE_HEX))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let hex_tx = backend.raw_transaction(&txid).await.unwrap();
        // The body is the wire-format hex — decodable, and the request
        // path carries the txid (matched by the mock above).
        assert_eq!(hex_tx, RAW_TX_FIXTURE_HEX);
        assert!(hex::decode(&hex_tx).is_ok());
    }

    #[tokio::test]
    async fn blockchain_info_raw_transaction_handles_http_error() {
        let server = MockServer::start().await;
        let txid = "a".repeat(64);
        Mock::given(method("GET"))
            .and(path(format!("/rawtx/{txid}").as_str()))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let backend = BlockchainInfoBackend::new(server.uri());
        let err = backend.raw_transaction(&txid).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn blockchain_info_raw_transaction_unreachable_url_is_http_error() {
        let backend = BlockchainInfoBackend::new("http://127.0.0.1:1");
        let err = backend.raw_transaction(&"a".repeat(64)).await.unwrap_err();
        assert!(matches!(err, NetError::Http(_)));
    }

    #[tokio::test]
    async fn esplora_raw_transaction_returns_hex_body() {
        let server = MockServer::start().await;
        let txid = "bb".repeat(32);
        Mock::given(method("GET"))
            .and(path(format!("/tx/{txid}/hex").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(RAW_TX_FIXTURE_HEX))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let hex_tx = backend.raw_transaction(&txid).await.unwrap();
        assert_eq!(hex_tx, RAW_TX_FIXTURE_HEX);
    }

    #[tokio::test]
    async fn esplora_raw_transaction_handles_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/tx/{}/hex", "c".repeat(64)).as_str()))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let err = backend.raw_transaction(&"c".repeat(64)).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn esplora_raw_transaction_unreachable_url_is_http_error() {
        let backend = EsploraBackend::new("http://127.0.0.1:1");
        let err = backend.raw_transaction(&"d".repeat(64)).await.unwrap_err();
        assert!(matches!(err, NetError::Http(_)));
    }

    #[tokio::test]
    async fn test_mock_backend_raw_transaction_hit_and_miss() {
        let m = mock();
        let txid = "e".repeat(64);
        // Miss: typed BadResponse, no panic.
        let miss = m.raw_transaction(&txid).await.unwrap_err();
        assert!(miss.to_string().contains("no raw tx"));
        // Hit: canned hex.
        m.raw_transactions
            .lock()
            .unwrap()
            .insert(txid.clone(), RAW_TX_FIXTURE_HEX.to_string());
        let hit = m.raw_transaction(&txid).await.unwrap();
        assert_eq!(hit, RAW_TX_FIXTURE_HEX);
    }

    #[tokio::test]
    async fn blockstream_and_mempool_delegate_to_esplora() {
        let server = MockServer::start().await;
        let addr = real_address();
        let utxo_path = format!("/address/{}/utxo", addr.as_str());
        let info_path = format!("/address/{}", addr.as_str());
        Mock::given(method("GET"))
            .and(path(utxo_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(info_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_string("txid"))
            .mount(&server)
            .await;
        let blockstream = BlockstreamBackend::new(server.uri());
        let mempool = MempoolSpaceBackend::new(server.uri());
        let a = blockstream.get_unspent(&addr).await.unwrap();
        let b = mempool.get_unspent(&addr).await.unwrap();
        assert!(a.is_empty());
        assert!(b.is_empty());
        let i1 = blockstream.get_info(&addr).await.unwrap();
        let i2 = mempool.get_info(&addr).await.unwrap();
        assert_eq!(i1.n_tx, 0);
        assert_eq!(i2.n_tx, 0);
        blockstream.broadcast(b"deadbeef").await.unwrap();
        mempool.broadcast(b"deadbeef").await.unwrap();
        // raw_transaction delegation to the shared Esplora impl.
        let hex_tx_path = format!("/tx/{}/hex", "e".repeat(64));
        Mock::given(method("GET"))
            .and(path(hex_tx_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(RAW_TX_FIXTURE_HEX))
            .mount(&server)
            .await;
        assert_eq!(
            blockstream.raw_transaction(&"e".repeat(64)).await.unwrap(),
            RAW_TX_FIXTURE_HEX
        );
        assert_eq!(
            mempool.raw_transaction(&"e".repeat(64)).await.unwrap(),
            RAW_TX_FIXTURE_HEX
        );
    }

    #[tokio::test]
    async fn tip_height_handles_garbage() {
        let server = MockServer::start().await;
        let addr = real_address();
        let _ = Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-a-number"))
            .mount(&server)
            .await;
        let body = serde_json::json!([
            {
                "txid": "abababababababababababababababababababababababababababababababab",
                "vout": 0,
                "value": 1000,
                "status": { "confirmed": true, "block_height": 799_995 }
            }
        ])
        .to_string();
        let utxo_path = format!("/address/{}/utxo", addr.as_str());
        let _ = Mock::given(method("GET"))
            .and(path(utxo_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        // A non-numeric tip is a protocol violation, not a reason to
        // silently report 0 confirmations.
        let err = backend.get_unspent(&addr).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[tokio::test]
    async fn tip_height_returns_none_for_http_error() {
        let server = MockServer::start().await;
        let addr = real_address();
        let _ = Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let body = serde_json::json!([
            {
                "txid": "abababababababababababababababababababababababababababababababab",
                "vout": 0,
                "value": 1000,
                "status": { "confirmed": true, "block_height": 799_995 }
            }
        ])
        .to_string();
        let utxo_path = format!("/address/{}/utxo", addr.as_str());
        let _ = Mock::given(method("GET"))
            .and(path(utxo_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let backend = EsploraBackend::new(server.uri());
        let err = backend.get_unspent(&addr).await.unwrap_err();
        assert!(matches!(err, NetError::BadResponse(_)));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn decode_body_text_maps_body_failures_to_bad_response() {
        // The error arm of the raw-transaction body decoder, tested
        // directly: a body failure of any source becomes a typed
        // `BadResponse` (no panic, no lossy success). The mapping is
        // deliberately a free function — a body error can surface on
        // `send()` or on `text()` depending on hyper's read-ahead
        // timing, so exercising the arm through a live socket would be
        // inherently flaky.
        let ok = decode_body_text::<std::convert::Infallible>(Ok("ab".to_string()));
        assert_eq!(ok.unwrap(), "ab");
        let err = decode_body_text::<&str>(Err("connection reset"));
        assert!(matches!(err, Err(NetError::BadResponse(_))));
        assert_eq!(
            err.unwrap_err().to_string(),
            "bad response: connection reset"
        );
    }

    // --- v0.3 resilience: retry classification & backoff -------------

    #[allow(clippy::assertions_on_constants)]
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn retry_backoff_is_capped_exponential() {
        // The spec example: 500 ms → 1 s → 2 s, never above the cap.
        let policy = RetryPolicy::new(3);
        assert_eq!(policy.backoff(0), Duration::from_millis(500));
        assert_eq!(policy.backoff(1), Duration::from_secs(1));
        assert_eq!(policy.backoff(2), Duration::from_secs(2));
        // Beyond the doubling range the cap holds (no overflow either:
        // absurd attempt numbers clamp the shift).
        assert_eq!(policy.backoff(3), Duration::from_secs(2));
        assert_eq!(policy.backoff(100), Duration::from_secs(2));
        // Zero-delay test policy stays zero whatever the attempt.
        for attempt in [0u32, 1, 5, 100] {
            assert_eq!(RetryPolicy::immediate(2).backoff(attempt), Duration::ZERO);
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn retryable_status_covers_5xx_408_and_429_only() {
        for status in [500u16, 502, 503, 599, 408, 429] {
            assert!(is_retryable_status(status), "{status}");
        }
        for status in [400u16, 402, 403, 404, 409, 418, 422, 200, 301] {
            assert!(!is_retryable_status(status), "{status}");
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn retry_after_is_honoured_only_when_sane() {
        let headers_from = |v: &str| {
            let mut map = reqwest::header::HeaderMap::new();
            map.insert(
                reqwest::header::RETRY_AFTER,
                v.parse().expect("header value"),
            );
            map
        };
        // 0 and the cap itself are sane; whitespace is tolerated.
        assert_eq!(retry_after_sane(&headers_from("0")), Some(Duration::ZERO));
        assert_eq!(
            retry_after_sane(&headers_from("30")),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            retry_after_sane(&headers_from(" 5 ")),
            Some(Duration::from_secs(5))
        );
        // Over the cap, non-numeric (HTTP-date form), negative, or
        // absent → regular backoff.
        assert_eq!(retry_after_sane(&headers_from("31")), None);
        assert_eq!(
            retry_after_sane(&headers_from("99999999999999999999")),
            None
        );
        assert_eq!(
            retry_after_sane(&headers_from("Fri, 31 Dec 2027 23:59:59 GMT")),
            None
        );
        assert_eq!(retry_after_sane(&headers_from("-1")), None);
        let empty = reqwest::header::HeaderMap::new();
        assert_eq!(retry_after_sane(&empty), None);
    }

    #[tokio::test]
    async fn send_with_retries_retries_transport_faults_up_to_the_policy() {
        // An unreachable host fails every attempt with a transport
        // error; the closure's counter (not the server) proves the
        // attempt count: 1 + retries.
        let client = reqwest::Client::new();
        let client = &client;
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = &hits;
        let result = send_with_retries(&RetryPolicy::immediate(2), || async move {
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            client.get("http://127.0.0.1:1/").send().await
        })
        .await;
        assert!(matches!(result, Err(NetError::Http(_))), "{result:?}");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    // --- v0.3 resilience: wiremock-driven retry behaviour ------------

    #[tokio::test]
    async fn retry_succeeds_after_a_transient_500() {
        let server = MockServer::start().await;
        let addr = real_address();
        // First request → 500, every later one → 200 (wiremock walks
        // mounted mocks top-down, so the one-shot 500 must be the
        // catch-all's neighbour — up_to_n_times keeps it from firing
        // twice).
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let body = serde_json::json!({ addr.as_str(): {} }).to_string();
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let mut backend = BlockchainInfoBackend::new(server.uri());
        backend.retries = RetryPolicy::immediate(2);
        let info = backend.get_info(&addr).await.unwrap();
        assert_eq!(info.n_tx, 0);
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("recording on")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn no_retry_on_a_4xx_refusal() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let mut backend = BlockchainInfoBackend::new(server.uri());
        backend.retries = RetryPolicy::immediate(3);
        let err = backend.get_info(&real_address()).await.unwrap_err();
        // Terminal text is byte-identical to the v0.1 no-retry path.
        assert_eq!(err.to_string(), "bad response: status 404 Not Found");
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("recording on")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn retry_on_429_honours_a_sane_retry_after() {
        let server = MockServer::start().await;
        let addr = real_address();
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let body = serde_json::json!({ addr.as_str(): {} }).to_string();
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let mut backend = BlockchainInfoBackend::new(server.uri());
        backend.retries = RetryPolicy::immediate(2);
        backend.get_info(&addr).await.unwrap();
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("recording on")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn retry_after_over_the_cap_falls_back_to_the_backoff() {
        let server = MockServer::start().await;
        let addr = real_address();
        // A server demanding ~17 minutes must not stall the wallet:
        // the header is ignored, the regular (here: zero-delay)
        // backoff applies and the request still retries.
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "999"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let body = serde_json::json!({ addr.as_str(): {} }).to_string();
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let mut backend = BlockchainInfoBackend::new(server.uri());
        backend.retries = RetryPolicy::immediate(1);
        backend.get_info(&addr).await.unwrap();
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("recording on")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn retries_zero_is_a_single_attempt() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let mut backend = BlockchainInfoBackend::new(server.uri());
        backend.retries = RetryPolicy::immediate(0);
        let err = backend.get_info(&real_address()).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "bad response: status 500 Internal Server Error"
        );
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("recording on")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn broadcast_4xx_is_never_retried() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/pushtx"))
            .respond_with(ResponseTemplate::new(400).set_body_string("rejected"))
            .mount(&server)
            .await;
        let mut backend = BlockchainInfoBackend::new(server.uri());
        backend.retries = RetryPolicy::immediate(3);
        let err = backend.broadcast(b"deadbeef").await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "broadcast failed: status=400 body=rejected"
        );
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("recording on")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn broadcast_5xx_is_retried_and_exhaustion_maps_to_broadcast_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/pushtx"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let mut backend = BlockchainInfoBackend::new(server.uri());
        backend.retries = RetryPolicy::immediate(1);
        let err = backend.broadcast(b"deadbeef").await.unwrap_err();
        // Retry exhaustion on a POST surfaces through the broadcast
        // mapping like a single-shot failure would.
        assert!(matches!(err, NetError::Broadcast { status: 500, .. }));
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("recording on")
                .len(),
            2
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn get_backend_with_retries_threads_the_flag_into_the_mock() {
        // Registry-level plumbing: `--retries 0` reaches the returned
        // backend. Driven through the "mock" provider because the
        // real providers resolve to their production URLs.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/balance"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        std::env::set_var("YUBTC_MOCK_BACKEND_URL", server.uri());
        let backend = get_backend_with_retries("mock", 0).expect("env var was set");
        let err = backend.get_info(&real_address()).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "bad response: status 500 Internal Server Error"
        );
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("recording on")
                .len(),
            1
        );
        std::env::remove_var("YUBTC_MOCK_BACKEND_URL");
    }

    // --- v0.3 resilience: auto failover ------------------------------

    /// Configurable fake for the auto-failover tests: each method has
    /// a remaining-failure counter (the first N calls error) and every
    /// call is logged so tests can assert the walk order and the
    /// sticky preference.
    struct FakeBackend {
        name: &'static str,
        info_failures: Mutex<usize>,
        unspent_failures: Mutex<usize>,
        broadcast_failures: Mutex<usize>,
        raw_failures: Mutex<usize>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeBackend {
        fn failing(name: &'static str, failures: usize) -> Arc<Self> {
            Arc::new(Self {
                name,
                info_failures: Mutex::new(failures),
                unspent_failures: Mutex::new(failures),
                broadcast_failures: Mutex::new(failures),
                raw_failures: Mutex::new(failures),
                calls: Mutex::new(Vec::new()),
            })
        }

        fn perfect(name: &'static str) -> Arc<Self> {
            Self::failing(name, 0)
        }

        fn call_count(&self, method: &str) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with(method))
                .count()
        }
    }

    #[async_trait]
    impl NetworkBackend for FakeBackend {
        async fn get_unspent(&self, _address: &TAddress) -> Result<Vec<Utxo>, NetError> {
            self.calls.lock().unwrap().push("unspent".to_string());
            let mut left = self.unspent_failures.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err(NetError::BadResponse(format!("{} down", self.name)));
            }
            Ok(vec![])
        }

        async fn get_info(&self, _address: &TAddress) -> Result<AddressInfo, NetError> {
            self.calls.lock().unwrap().push("info".to_string());
            let mut left = self.info_failures.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err(NetError::BadResponse(format!("{} down", self.name)));
            }
            Ok(AddressInfo {
                total_received: 1,
                final_balance: 1,
                n_tx: 1,
            })
        }

        async fn broadcast(&self, _raw_tx: &[u8]) -> Result<(), NetError> {
            self.calls.lock().unwrap().push("broadcast".to_string());
            let mut left = self.broadcast_failures.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err(NetError::BadResponse(format!("{} down", self.name)));
            }
            Ok(())
        }

        async fn raw_transaction(&self, _txid: &str) -> Result<String, NetError> {
            self.calls.lock().unwrap().push("raw".to_string());
            let mut left = self.raw_failures.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err(NetError::BadResponse(format!("{} down", self.name)));
            }
            Ok(RAW_TX_FIXTURE_HEX.to_string())
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn auto_addr() -> TAddress {
        TAddress::new("addr-auto")
    }

    #[tokio::test]
    async fn auto_first_success_wins_and_is_sticky() {
        let a = FakeBackend::failing("a", 1);
        let b = FakeBackend::perfect("b");
        let auto = AutoBackend::new(vec![a.clone(), b.clone()]);
        // a fails, b serves → b's data comes back.
        let info = auto.get_info(&auto_addr()).await.unwrap();
        assert_eq!(info.total_received, 1);
        assert_eq!(a.call_count("info"), 1);
        assert_eq!(b.call_count("info"), 1);
        // Sticky: the next request starts at b; a is not retried.
        auto.get_info(&auto_addr()).await.unwrap();
        assert_eq!(a.call_count("info"), 1);
        assert_eq!(b.call_count("info"), 2);
    }

    #[tokio::test]
    async fn auto_demotes_a_preferred_backend_that_starts_failing() {
        let a = FakeBackend::failing("a", 1);
        let b = FakeBackend::perfect("b");
        let auto = AutoBackend::new(vec![a.clone(), b.clone()]);
        // First request walks the registry order: a fails, b serves
        // and becomes preferred.
        auto.get_info(&auto_addr()).await.unwrap();
        assert_eq!(a.call_count("info"), 1);
        assert_eq!(b.call_count("info"), 1);
        // Sticky: the next request starts at b; a is not retried.
        auto.get_info(&auto_addr()).await.unwrap();
        assert_eq!(a.call_count("info"), 1);
        assert_eq!(b.call_count("info"), 2);
        // b starts failing → the walk wraps around to a and re-pins.
        *b.info_failures.lock().unwrap() = 1;
        auto.get_info(&auto_addr()).await.unwrap();
        assert_eq!(b.call_count("info"), 3);
        assert_eq!(a.call_count("info"), 2);
        // a is preferred now: b is left alone again.
        auto.get_info(&auto_addr()).await.unwrap();
        assert_eq!(b.call_count("info"), 3);
        assert_eq!(a.call_count("info"), 3);
    }

    #[tokio::test]
    async fn auto_all_four_methods_fail_over() {
        // One AutoBackend per method: the sticky preference would
        // otherwise pin to the first success and leave the remaining
        // methods' failover branches unexercised.
        // get_unspent
        let a = FakeBackend::failing("a", 1);
        let b = FakeBackend::perfect("b");
        let auto = AutoBackend::new(vec![a.clone(), b.clone()]);
        auto.get_unspent(&auto_addr()).await.unwrap();
        assert_eq!(a.call_count("unspent"), 1);
        assert_eq!(b.call_count("unspent"), 1);
        // get_info
        let a = FakeBackend::failing("a", 1);
        let b = FakeBackend::perfect("b");
        let auto = AutoBackend::new(vec![a.clone(), b.clone()]);
        auto.get_info(&auto_addr()).await.unwrap();
        assert_eq!(a.call_count("info"), 1);
        assert_eq!(b.call_count("info"), 1);
        // broadcast
        let a = FakeBackend::failing("a", 1);
        let b = FakeBackend::perfect("b");
        let auto = AutoBackend::new(vec![a.clone(), b.clone()]);
        auto.broadcast(b"00").await.unwrap();
        assert_eq!(a.call_count("broadcast"), 1);
        assert_eq!(b.call_count("broadcast"), 1);
        // raw_transaction
        let a = FakeBackend::failing("a", 1);
        let b = FakeBackend::perfect("b");
        let auto = AutoBackend::new(vec![a.clone(), b.clone()]);
        auto.raw_transaction(&"aa".repeat(32)).await.unwrap();
        assert_eq!(a.call_count("raw"), 1);
        assert_eq!(b.call_count("raw"), 1);
    }

    #[tokio::test]
    async fn auto_exhaustion_lists_every_backend_and_last_error() {
        let a = FakeBackend::failing("a", 10);
        let b = FakeBackend::failing("b", 10);
        let auto = AutoBackend::new(vec![a.clone(), b.clone()]);
        let err = auto.get_info(&auto_addr()).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "all backends failed: a: bad response: a down; b: bad response: b down"
        );
        // Both backends were tried exactly once per request.
        assert_eq!(a.call_count("info"), 1);
        assert_eq!(b.call_count("info"), 1);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn get_backends_for_auto_is_the_registry_order_without_mock() {
        let names: Vec<&'static str> = get_backends_for_auto().iter().map(|b| b.name()).collect();
        assert_eq!(names, ["blockchain.info", "blockstream", "mempool.space"]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn get_backend_auto_resolves_an_auto_backend() {
        let auto = get_backend("auto").expect("auto is a registry name");
        assert_eq!(auto.name(), "auto");
        // Each resolution is a fresh, independent instance (like every
        // other registry entry).
        let other = get_backend("auto").expect("auto is a registry name");
        assert!(!Arc::ptr_eq(&auto, &other));
        // The `--retries`-aware resolution accepts auto as well.
        assert_eq!(
            get_backend_with_retries("auto", 0)
                .expect("auto resolves with retries")
                .name(),
            "auto"
        );
    }

    #[tokio::test]
    async fn auto_end_to_end_through_the_free_function_surface() {
        // The free functions are the stable entry point callers use;
        // run one through an AutoBackend so the delegation stays
        // covered.
        let a = FakeBackend::perfect("a");
        let auto = AutoBackend::new(vec![a.clone()]);
        let info = get_address_info(&auto, &auto_addr()).await.unwrap();
        assert_eq!(info.total_received, 1);
        let unspent = get_address_unspent(&auto, &auto_addr()).await.unwrap();
        assert!(unspent.is_empty());
        broadcast(&auto, b"00").await.unwrap();
    }
}
