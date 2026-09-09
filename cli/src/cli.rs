//! Clap-based argument parsing for the `yubtc` binary.
//!
//! This is the **interface only** — it defines the command tree and
//! per-command flags but does not implement them. Implementations live
//! in `cmd/<name>.rs` and are reached through
//! [`crate::cmd::run`].
//!
//! Flag names mirror the Python CLI (`yubtc-python/src/yubtc/cli.py`)
//! 1:1 so that shell history and muscle memory transfer:
//!
//! - `--provider NAME` selects a network backend (default
//!   `blockchain.info`).
//! - `--kdf NAME` selects a KDF algorithm (`auto`, `yubtc`, `pbkdf2`,
//!   `argon2id`, `scrypt`).
//! - `-n`, `--nonce` is the starting address nonce.
//! - `-c`, `--confirmations` filters UTXOs by depth.
//! - `-f`, `--fee` and `-k`, `--feekb` configure the fee loop.
//! - `--broadcast` / `-y`, `--yes` control the broadcast prompt.
//! - `-i`, `--interactive` opens the Coin Control TUI.
//!
//! The Python CLI uses click; we use clap's derive. Both end up with the
//! same surface, so a `yubtc-python` user can move to `yubtc` without
//! relearning flags.

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Provider names accepted by `--provider`. Kept in lock-step with
/// [`yubtc_core::net::get_backend`] — `UnknownProvider` errors surface
/// the registry list at runtime, so a typo here only costs a rebuild.
///
/// `Auto` (v0.3 «Failover») walks the three real providers in registry
/// order per request — blockchain.info → blockstream → mempool.space —
/// first success wins and is remembered for the rest of the command
/// run. It is opt-in; the default stays `blockchain.info` for
/// bit-for-bit v0.1 compatibility.
///
/// `Mock` is the cross-compat / test-runner entry point — it reads the
/// URL from `YUBTC_MOCK_BACKEND_URL` so the Python harness can stand
/// up a local HTTP mock and compare Python CLI output against the
/// Rust CLI subprocess bit-for-bit. It is **not** intended for real
/// use; the env var is the test's contract, not a UX — and it is
/// excluded from the `auto` order.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProviderName {
    #[value(name = "blockchain.info")]
    BlockchainInfo,
    #[value(name = "blockstream")]
    Blockstream,
    #[value(name = "mempool.space")]
    MempoolSpace,
    #[value(name = "auto")]
    Auto,
    #[value(name = "mock")]
    Mock,
}

impl ProviderName {
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderName::BlockchainInfo => "blockchain.info",
            ProviderName::Blockstream => "blockstream",
            ProviderName::MempoolSpace => "mempool.space",
            ProviderName::Auto => "auto",
            ProviderName::Mock => "mock",
        }
    }
}

/// KDF algorithm names accepted by `--kdf`. The `auto` value is CLI-only
/// — it picks yubtc (empty passphrase) or pbkdf2 (non-empty) per the
/// pre-flag behaviour; the four real algorithms are passed through.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KdfName {
    Auto,
    Yubtc,
    Pbkdf2,
    Argon2id,
    Scrypt,
}

impl KdfName {
    pub fn as_str(self) -> &'static str {
        match self {
            KdfName::Auto => "auto",
            KdfName::Yubtc => "yubtc",
            KdfName::Pbkdf2 => "pbkdf2",
            KdfName::Argon2id => "argon2id",
            KdfName::Scrypt => "scrypt",
        }
    }
}

/// Receive-address-type names accepted by `--addr-type`. Kept in
/// lock-step with [`yubtc_core::wallet::AddrType`] — `Native` is the
/// Phase 13 default (spec ОВ-1), `Taproot` is opt-in, `Legacy`
/// reproduces v0.1 bit-for-bit.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AddrTypeName {
    Native,
    Taproot,
    Legacy,
}

impl AddrTypeName {
    pub fn as_str(self) -> &'static str {
        match self {
            AddrTypeName::Native => "native",
            AddrTypeName::Taproot => "taproot",
            AddrTypeName::Legacy => "legacy",
        }
    }

    /// Map to the core enum (the conversion exists exactly once).
    pub fn to_core(self) -> yubtc_core::wallet::AddrType {
        match self {
            AddrTypeName::Native => yubtc_core::wallet::AddrType::Native,
            AddrTypeName::Taproot => yubtc_core::wallet::AddrType::Taproot,
            AddrTypeName::Legacy => yubtc_core::wallet::AddrType::Legacy,
        }
    }
}

/// Multi-sig quorum address form accepted by `ms create --form` /
/// `ms send --form` (spec «Multi-sig»). Kept in lock-step with
/// [`yubtc_core::wallet::MsForm`]. **Default `P2sh`** (documented
/// spec decision): R-MS-1 is about N/M defaults, not the form; the
/// legacy form is the conservative Phase-15 quorum encoding, so an
/// omitted flag preserves the previous behaviour bit-for-bit.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum MsFormName {
    #[value(name = "p2sh")]
    P2sh,
    #[value(name = "p2wsh")]
    P2wsh,
    #[value(name = "p2tr")]
    P2tr,
}

impl MsFormName {
    pub fn as_str(self) -> &'static str {
        match self {
            MsFormName::P2sh => "p2sh",
            MsFormName::P2wsh => "p2wsh",
            MsFormName::P2tr => "p2tr",
        }
    }

    /// Map to the core enum (the conversion exists exactly once).
    pub fn to_core(self) -> yubtc_core::wallet::MsForm {
        match self {
            MsFormName::P2sh => yubtc_core::wallet::MsForm::P2sh,
            MsFormName::P2wsh => yubtc_core::wallet::MsForm::P2wsh,
            MsFormName::P2tr => yubtc_core::wallet::MsForm::P2tr,
        }
    }
}

/// Shared `--provider` + `--retries` flag group. Wired into every
/// command that touches the network (`address`, `balance`, `send`,
/// `dumpprivkey`, `pushtx`, `psbt create`, `ms send`).
///
/// `newseed` does not take a provider — it never queries the chain, it
/// only generates an address for the freshly created seed.
#[derive(Debug, Clone, Args)]
pub struct ProviderOpt {
    /// Network backend. Known: `blockchain.info`, `blockstream`,
    /// `mempool.space`, plus `auto` (v0.3 failover across the three in
    /// registry order — first success wins, sticky within the run).
    #[arg(long, value_enum, default_value_t = ProviderName::BlockchainInfo)]
    pub provider: ProviderName,

    /// Retries per HTTP request before the provider is given up on
    /// (v0.3 resilience; capped exponential backoff between attempts).
    /// `0` = a single attempt (the v0.1 behaviour).
    #[arg(long, default_value_t = yubtc_core::fwd::DEFAULT_HTTP_RETRIES)]
    pub retries: u32,
}

/// Shared `--kdf` flag. Wired into every command that derives a key
/// from the seed (`address`, `balance`, `send`, `dumpprivkey`).
#[derive(Debug, Clone, Args)]
pub struct KdfOpt {
    /// KDF algorithm. `auto` selects `yubtc` for empty passphrase and
    /// `pbkdf2` for non-empty (legacy behaviour); the four named
    /// values override that heuristic.
    #[arg(long, value_enum, default_value_t = KdfName::Auto)]
    pub kdf: KdfName,
}

/// Shared `--addr-type` flag (specs/spec.md «Адресная политика и nonce→path
/// mapping»). Wired into every command that derives a receive address
/// (`newseed`, `address`, `balance`, `send`, `dumpprivkey`,
/// `psbt create`).
///
/// `native` (the default) shows/uses P2WPKH `bc1q…` addresses;
/// `taproot` opts into P2TR `bc1p…`; `legacy` reproduces the v0.1
/// P2PKH `1…` encoding bit-for-bit. The type affects only the
/// receiving/cashback encoding — `balance`/`send` still see and spend
/// UTXOs of every form.
#[derive(Debug, Clone, Args)]
pub struct AddrTypeOpt {
    /// Receive-address type: `native` (P2WPKH, default), `taproot`
    /// (P2TR) or `legacy` (P2PKH, v0.1 behaviour).
    #[arg(long, value_enum, default_value_t = AddrTypeName::Native)]
    pub addr_type: AddrTypeName,
}

/// Shared `--strict-bip39` flag (specs/spec.md «Seed policy», R-3;
/// DEVIATIONS.md D-001). Wired into every command that accepts a seed
/// from the user (`address`, `balance`, `send`, `dumpprivkey`,
/// `psbt create`, `psbt sign`).
///
/// Omitted (the default) = permissive reception: any non-empty
/// phrase is accepted, BIP-39 parse and the entropy floor are not
/// applied, and a low entropy-estimate only produces a warning
/// (R-1/R-6). Present = strict BIP-39 reception: full parse
/// (wordlist + checksum, 12/15/18/21/24 words) plus the C6 entropy
/// floor; violations reject blocking before any KDF work (R-4/R-5).
/// The empty phrase is an error in both modes (R-2).
#[derive(Debug, Clone, Args)]
pub struct SeedPolicyOpt {
    /// Strict BIP-39 seed reception (parse + entropy floor).
    /// Default: permissive (any non-empty phrase; low entropy only
    /// warns).
    #[arg(long, default_value_t = false)]
    pub strict_bip39: bool,
}

/// yubtc top-level command tree.
///
/// Mirrors `yubtc-python/src/yubtc/cli.py:cli.command(...)` 1:1.
/// A planned-but-unimplemented subcommand produces a clap error of the
/// form "error: unrecognized subcommand 'foo'", not a silent no-op —
/// see [`cmd::run`] for the dispatch logic.
#[derive(Debug, Parser)]
#[command(
    name = "yubtc",
    version,
    about = "Native Bitcoin wallet CLI (Rust core + UniFFI).",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Concrete subcommands. Each variant's `#[command(...)]` block is the
/// clap-side description; the implementation lives in
/// `cmd/<variant_name>.rs`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a new seed and print the address derived from it.
    Newseed(NewseedArgs),
    /// Show the receive address derived from `(seed, nonce)`.
    Address(AddressArgs),
    /// Show the balance across the wallet's scanned addresses.
    Balance(BalanceArgs),
    /// Build, sign, optionally broadcast a transaction.
    Send(SendArgs),
    /// BIP-174 PSBT tools: create, sign, combine, finalize, extract,
    /// decode (spec «PSBT — BIP-174»; ОВ-6).
    Psbt(PsbtArgs),
    /// Multi-sig quorum tools: create, send (specs/spec.md «Multi-sig»).
    Ms(MsArgs),
    /// Show the private key (WIF) for the address at `--nonce`.
    Dumpprivkey(DumpprivkeyArgs),
    /// Broadcast a raw transaction read from stdin.
    Pushtx(PushtxArgs),
}

/// `newseed` — generate a fresh seed and print the resulting address.
///
/// Behaviour matches `yubtc-python/src/yubtc/cli.py:newseed`:
///
/// - `-n N` — word count (12/15/18/21/24).
/// - `-u` / `--unique` — reject seeds with duplicate words.
/// - Always uses the yubtc cascade (no passphrase concept for a fresh
///   seed); prints `{seed}\r\nAddress: {address}` to stdout.
#[derive(Debug, Args)]
pub struct NewseedArgs {
    /// Number of words in the seed (12, 15, 18, 21, 24).
    #[arg(short = 'n', long, default_value_t = 15)]
    pub words: usize,
    /// Only unique words in the seed.
    #[arg(short = 'u', long, default_value_t = false)]
    pub unique: bool,
    #[command(flatten)]
    pub addr_type: AddrTypeOpt,
}

/// `address` — show the address derived from `(seed, nonce)`.
#[derive(Debug, Args)]
pub struct AddressArgs {
    /// Starting nonce for the address scan.
    #[arg(short = 'n', long, default_value_t = 0)]
    pub nonce: u32,
    /// Number of additional unused addresses to derive.
    #[arg(long, default_value_t = 1)]
    pub new: usize,
    #[command(flatten)]
    pub kdf: KdfOpt,
    #[command(flatten)]
    pub addr_type: AddrTypeOpt,
    #[command(flatten)]
    pub seed_policy: SeedPolicyOpt,
    #[command(flatten)]
    pub provider: ProviderOpt,
}

/// `dumpprivkey` — show the WIF for the address at `--nonce`.
#[derive(Debug, Args)]
pub struct DumpprivkeyArgs {
    #[arg(short = 'n', long, default_value_t = 0)]
    pub nonce: u32,
    #[command(flatten)]
    pub kdf: KdfOpt,
    #[command(flatten)]
    pub addr_type: AddrTypeOpt,
    #[command(flatten)]
    pub seed_policy: SeedPolicyOpt,
    #[command(flatten)]
    pub provider: ProviderOpt,
}

/// `balance` — show the wallet balance, optionally verbose.
#[derive(Debug, Args)]
pub struct BalanceArgs {
    #[arg(short = 'n', long, default_value_t = 0)]
    pub nonce: u32,
    /// Minimum confirmations for inputs to be counted.
    #[arg(short = 'c', long, default_value_t = 6)]
    pub confirmations: u32,
    /// Number of additional unused addresses to derive.
    #[arg(long, default_value_t = 1)]
    pub new: usize,
    /// Show used-but-currently-empty addresses.
    #[arg(short = 'e', long, default_value_t = false)]
    pub empty: bool,
    /// Print per-UTXO breakdown.
    #[arg(short = 'v', long, default_value_t = false)]
    pub verbose: bool,
    #[command(flatten)]
    pub kdf: KdfOpt,
    #[command(flatten)]
    pub addr_type: AddrTypeOpt,
    #[command(flatten)]
    pub seed_policy: SeedPolicyOpt,
    #[command(flatten)]
    pub provider: ProviderOpt,
}

/// `send` — build and broadcast a transaction.
///
/// `amount` accepts `"ALL"` (drain) or a decimal BTC amount. `address`
/// accepts base58 (`1…`/`3…`) and native-SegWit (`bc1q…` P2WPKH,
/// `bc1p…` P2TR) recipients — see
/// `core/src/wallet.rs:make_lock_script_for_address`.
#[derive(Debug, Args)]
pub struct SendArgs {
    #[arg(short = 'n', long, default_value_t = 0)]
    pub nonce: u32,
    #[arg(short = 'c', long, default_value_t = 6)]
    pub confirmations: u32,
    /// Hard-set fee in BTC. `0` runs the fee loop using `-k`.
    #[arg(short = 'f', long, default_value_t = 0.0)]
    pub fee: f64,
    /// Fee rate in sat/kB. Used when `-f` is `0`.
    #[arg(short = 'k', long, default_value_t = 1000)]
    pub feekb: u64,
    /// Broadcast the transaction; otherwise print the raw tx.
    #[arg(long, default_value_t = false)]
    pub broadcast: bool,
    /// Scan addresses from `--nonce` until the amount is met or an
    /// unused address is found.
    #[arg(long, default_value_t = false)]
    pub scan: bool,
    /// Open the Coin Control TUI to pick UTXOs.
    #[arg(short = 'i', long, default_value_t = false)]
    pub interactive: bool,
    /// Skip the broadcast confirmation prompt.
    #[arg(short = 'y', long, default_value_t = false)]
    pub yes: bool,
    #[command(flatten)]
    pub kdf: KdfOpt,
    #[command(flatten)]
    pub addr_type: AddrTypeOpt,
    #[command(flatten)]
    pub seed_policy: SeedPolicyOpt,
    #[command(flatten)]
    pub provider: ProviderOpt,
    /// Destination address: base58 (`1…`/`3…`) or native SegWit
    /// (`bc1q…` P2WPKH / `bc1p…` P2TR).
    pub address: String,
    /// Amount in BTC, or `ALL` to drain.
    pub amount: String,
}

/// `pushtx` — broadcast a raw tx read from stdin.
///
/// Reads one line (the raw tx as hex), prints `id:`, `txsize=` and
/// `rawtx:`, then prompts unless `-y` is set.
#[derive(Debug, Args)]
pub struct PushtxArgs {
    /// Skip the broadcast confirmation prompt.
    #[arg(short = 'y', long, default_value_t = false)]
    pub yes: bool,
    #[command(flatten)]
    pub provider: ProviderOpt,
}

/// `psbt` — the BIP-174 subcommand group (specs/spec.md «PSBT — BIP-174»,
/// ОВ-6). Roles map 1:1 onto the BIP-174 pipeline:
///
/// ```text
/// yubtc psbt create ADDR AMOUNT …   → unsigned PSBT (base64)
/// yubtc psbt sign                   → adds PARTIAL_SIGs (base64)
/// yubtc psbt combine                → merges ≥ 2 PSBTs (base64)
/// yubtc psbt finalize               → finalizes inputs (base64)
/// yubtc psbt extract                → raw tx hex (pipe into pushtx)
/// yubtc psbt decode                 → human-readable JSON dump + fee
/// ```
///
/// Everything except `create` (which scans) is fully offline. All
/// subcommands read the PSBT as base64 from stdin (one line; `combine`
/// ≥ 2 lines) and write base64/hex/JSON to stdout — filters composable
/// in the shell (`psbt finalize && psbt extract | yubtc pushtx`).
#[derive(Debug, Args)]
pub struct PsbtArgs {
    #[command(subcommand)]
    pub command: PsbtCommand,
}

/// `yubtc psbt` subcommands (spec ОВ-6). `create` is the only online
/// one; the rest work purely on PSBT data.
#[derive(Debug, Subcommand)]
pub enum PsbtCommand {
    /// Build an unsigned PSBT (Creator + Updater): scan, select
    /// inputs, run the fee loop — the `send` path without signing —
    /// and emit base64 on stdout.
    Create(PsbtCreateArgs),
    /// Sign a PSBT offline (Signer): prompts seed + passphrase, walks
    /// nonces `0..1000` × 3 address forms (ОВ-9) and adds
    /// `PARTIAL_SIG`s for own inputs. stdin: seed, passphrase, PSBT.
    Sign(PsbtSignArgs),
    /// Merge ≥ 2 PSBTs of the same transaction (Combiner): reads one
    /// base64 PSBT per stdin line, merges left-to-right.
    Combine,
    /// Finalize completed inputs (Finalizer): converts `PARTIAL_SIG`s
    /// into final scriptSig / witness stacks.
    Finalize,
    /// Extract the signed raw transaction (Extractor) as wire-format
    /// hex on stdout — pipeable into `yubtc pushtx`.
    Extract,
    /// Print a human-readable JSON dump (yubtc extension, not a
    /// BIP-174 role): txid, inputs, outputs, fee.
    Decode,
}

/// `psbt create` — Creator (+Updater): same scan → selector → fee
/// loop as `send`, stopping at the unsigned PSBT. The only `psbt`
/// subcommand that touches the network.
///
/// `amount` accepts `"ALL"` (drain) or a decimal BTC amount; `address`
/// accepts base58 and native-SegWit recipients, mirroring `send`.
#[derive(Debug, Args)]
pub struct PsbtCreateArgs {
    #[arg(short = 'n', long, default_value_t = 0)]
    pub nonce: u32,
    #[arg(short = 'c', long, default_value_t = 6)]
    pub confirmations: u32,
    /// Hard-set fee in BTC. `0` runs the fee loop using `-k`.
    #[arg(short = 'f', long, default_value_t = 0.0)]
    pub fee: f64,
    /// Fee rate in sat/kB. Used when `-f` is `0`.
    #[arg(short = 'k', long, default_value_t = 1000)]
    pub feekb: u64,
    /// Open the Coin Control TUI to pick UTXOs.
    #[arg(short = 'i', long, default_value_t = false)]
    pub interactive: bool,
    #[command(flatten)]
    pub addr_type: AddrTypeOpt,
    #[command(flatten)]
    pub seed_policy: SeedPolicyOpt,
    #[command(flatten)]
    pub provider: ProviderOpt,
    /// Destination address: base58 (`1…`/`3…`) or native SegWit
    /// (`bc1q…` P2WPKH / `bc1p…` P2TR).
    pub address: String,
    /// Amount in BTC, or `ALL` to drain.
    pub amount: String,
}

/// `psbt sign` — offline Signer. The seed is permissive by default;
/// `--strict-bip39` opts into the strict BIP-39 reception policy
/// (R-3). No `-n`: inputs are found by the bounded nonce walk (ОВ-9).
#[derive(Debug, Args)]
pub struct PsbtSignArgs {
    #[command(flatten)]
    pub seed_policy: SeedPolicyOpt,
}

/// `ms` — the multi-sig quorum subcommand group (specs/spec.md
/// «Multi-sig», ОВ-12/ОВ-13/ОВ-14/ОВ-19). M-of-N quorum addressed as `3…`/`bc1q…`/
/// `bc1p…` per `--form`:
///
/// ```text
/// yubtc ms create N M [--key HEX|WIF ...] [-n NONCE] [--form p2sh|p2wsh|p2tr]
/// yubtc ms send ADDR AMOUNT N M [--key HEX|WIF ...] [-n NONCE]
///              [-c CONFIRMATIONS] [-f FEE] [-k FEEKB] [--provider NAME]
///              [--form p2sh|p2wsh|p2tr]
/// ```
///
/// `ms create` is fully offline (seed only when `-n`/WIF is given);
/// `ms send` needs one UTXO query + one raw-transaction query per
/// input and emits the self-signed PSBT — the further pipeline is
/// the standard Phase 14 chain (`psbt sign` × cosigners → `combine`
/// → `finalize` → `extract` → `pushtx`). N and M are mandatory
/// positionals everywhere (R-MS-1 — no defaults exist).
#[derive(Debug, Args)]
pub struct MsArgs {
    #[command(subcommand)]
    pub command: MsCommand,
}

/// `yubtc ms` subcommands (specs/spec.md «Поверхность»).
#[derive(Debug, Subcommand)]
pub enum MsCommand {
    /// Build the fixed quorum address + redeem script (offline).
    /// Watch-only without `-n`/WIF: no seed is requested and the
    /// quorum consists of the passed pubkeys alone.
    Create(MsCreateArgs),
    /// Build + self-sign a quorum spend (Creator + Signer, ОВ-12):
    /// emit the base64 PSBT on stdout — cosigners sign it via
    /// `psbt sign`, then `psbt combine | finalize | extract | pushtx`.
    Send(MsSendArgs),
}

/// Positionals + flags of `ms create` (specs/spec.md «Поверхность»).
///
/// `N` and `M` are **required** positional arguments (R-MS-1:
/// missing either is a usage error — no default value exists and no
/// prompt substitutes one).
#[derive(Debug, Args)]
pub struct MsCreateArgs {
    /// Total number of keys in the quorum (`1 ≤ M ≤ N ≤ 15`,
    /// R-MS-2).
    pub n: u32,
    /// Signature threshold: how many of the N keys must sign.
    pub m: u32,
    /// Quorum key, repeatable. Cosigner keys are compressed pubkey
    /// hex (66 chars, `02`/`03` prefix) for p2sh/p2wsh, or x-only
    /// pubkey hex (64 chars) for p2tr (R-MS-10); the own key may be
    /// passed as WIF — it must match the key derived from the seed
    /// at `-n`, otherwise the command fails with `ForeignWif`
    /// (R-MS-6).
    #[arg(long = "key", value_name = "HEX|WIF")]
    pub keys: Vec<String>,
    /// Nonce of the own (seed-derived) key, legacy form (R-MS-6,
    /// ОВ-10 — the `dumpprivkey -n X` key). Omitted: watch-only
    /// create, no seed requested.
    #[arg(short = 'n', long)]
    pub nonce: Option<u32>,
    /// Quorum address form (v0.3): `p2sh` (`3…`, the Phase-15
    /// default), `p2wsh` (`bc1q…`, bech32 v0 / SHA-256 witness form)
    /// or `p2tr` (`bc1p…`, P2TR script-path — the key arguments use
    /// x-only encoding: 32 bytes as 64 hex chars per R-MS-10, while
    /// p2sh/p2wsh take compressed 66-char hex keys). The redeem
    /// script of p2tr is the CHECKSIGADD tapscript — different bytes
    /// than the p2sh/p2wsh redeem.
    #[arg(long, value_enum, default_value_t = MsFormName::P2sh)]
    pub form: MsFormName,
    #[command(flatten)]
    pub seed_policy: SeedPolicyOpt,
}

/// `ms send ADDR AMOUNT N M …` — the Creator+Signer wrapper (ОВ-12)
/// over the existing library stages. AMOUNT is a decimal BTC value
/// (no drain: the cashback always returns to the quorum address,
/// ОВ-13 — shared funds must not drift into single-key control).
#[derive(Debug, Args)]
pub struct MsSendArgs {
    /// Destination address: base58 (`1…`/`3…`) or native SegWit
    /// (`bc1q…` P2WPKH / `bc1p…` P2TR).
    pub address: String,
    /// Amount in BTC.
    pub amount: String,
    /// Total number of keys in the quorum (R-MS-1: mandatory).
    pub n: u32,
    /// Signature threshold (R-MS-1: mandatory).
    pub m: u32,
    /// Quorum key, repeatable — same grammar as `ms create --key`.
    #[arg(long = "key", value_name = "HEX|WIF")]
    pub keys: Vec<String>,
    /// Nonce of the own key (R-MS-6/ОВ-10). Mandatory in practice:
    /// without it the wallet is not a quorum participant and refuses
    /// with `NotAParticipant`.
    #[arg(short = 'n', long)]
    pub nonce: Option<u32>,
    /// Quorum address form (v0.3): selects the UTXO source address
    /// (`3…` vs `bc1q…` vs `bc1p…`), the cashback encoding and the
    /// `--key` encoding (R-MS-10: p2tr takes x-only 64-char hex,
    /// p2sh/p2wsh take compressed 66-char hex). Default `p2sh` —
    /// same rationale as `ms create --form`.
    #[arg(long, value_enum, default_value_t = MsFormName::P2sh)]
    pub form: MsFormName,
    /// Minimum confirmations for the quorum UTXOs.
    #[arg(short = 'c', long, default_value_t = 6)]
    pub confirmations: u32,
    /// Hard-set fee in BTC. `0` runs the fee loop using `-k`.
    #[arg(short = 'f', long, default_value_t = 0.0)]
    pub fee: f64,
    /// Fee rate in sat/kB. Used when `-f` is `0`.
    #[arg(short = 'k', long, default_value_t = 1000)]
    pub feekb: u64,
    #[command(flatten)]
    pub seed_policy: SeedPolicyOpt,
    #[command(flatten)]
    pub provider: ProviderOpt,
}

#[cfg(test)]
mod tests {
    //! Pin the flag-name strings: they are the wire contract with the
    //! user's shell history and the Python CLI (and the values passed
    //! to `yubtc_core::net::get_backend` / KDF dispatch).

    use super::{AddrTypeName, KdfName, MsFormName, ProviderName};

    #[test]
    fn addr_type_as_str_matches_flag_names() {
        assert_eq!(AddrTypeName::Native.as_str(), "native");
        assert_eq!(AddrTypeName::Taproot.as_str(), "taproot");
        assert_eq!(AddrTypeName::Legacy.as_str(), "legacy");
    }

    #[test]
    fn ms_form_as_str_matches_flag_names() {
        // The v0.3 `--form` values are the wire contract with the
        // user's shell history and the Python mirror's `form` kwarg.
        assert_eq!(MsFormName::P2sh.as_str(), "p2sh");
        assert_eq!(MsFormName::P2wsh.as_str(), "p2wsh");
        assert_eq!(MsFormName::P2tr.as_str(), "p2tr");
    }

    #[test]
    fn addr_type_to_core_matches_names() {
        use yubtc_core::wallet::AddrType;
        assert_eq!(AddrTypeName::Native.to_core(), AddrType::Native);
        assert_eq!(AddrTypeName::Taproot.to_core(), AddrType::Taproot);
        assert_eq!(AddrTypeName::Legacy.to_core(), AddrType::Legacy);
        // The mapping must agree with the flag spelling.
        assert_eq!(
            AddrTypeName::Native.to_core().name(),
            AddrTypeName::Native.as_str()
        );
        assert_eq!(
            AddrTypeName::Taproot.to_core().name(),
            AddrTypeName::Taproot.as_str()
        );
        assert_eq!(
            AddrTypeName::Legacy.to_core().name(),
            AddrTypeName::Legacy.as_str()
        );
    }

    #[test]
    fn ms_form_to_core_matches_names() {
        use yubtc_core::wallet::MsForm;
        assert_eq!(MsFormName::P2sh.to_core(), MsForm::P2sh);
        assert_eq!(MsFormName::P2wsh.to_core(), MsForm::P2wsh);
        assert_eq!(MsFormName::P2tr.to_core(), MsForm::P2tr);
        // The mapping must agree with the flag spelling.
        assert_eq!(MsFormName::P2sh.to_core().name(), MsFormName::P2sh.as_str());
        assert_eq!(
            MsFormName::P2wsh.to_core().name(),
            MsFormName::P2wsh.as_str()
        );
        assert_eq!(MsFormName::P2tr.to_core().name(), MsFormName::P2tr.as_str());
    }

    #[test]
    fn provider_as_str_matches_flag_names() {
        assert_eq!(ProviderName::BlockchainInfo.as_str(), "blockchain.info");
        assert_eq!(ProviderName::Blockstream.as_str(), "blockstream");
        assert_eq!(ProviderName::MempoolSpace.as_str(), "mempool.space");
        assert_eq!(ProviderName::Auto.as_str(), "auto");
        assert_eq!(ProviderName::Mock.as_str(), "mock");
    }

    #[test]
    fn kdf_as_str_matches_flag_names() {
        assert_eq!(KdfName::Auto.as_str(), "auto");
        assert_eq!(KdfName::Yubtc.as_str(), "yubtc");
        assert_eq!(KdfName::Pbkdf2.as_str(), "pbkdf2");
        assert_eq!(KdfName::Argon2id.as_str(), "argon2id");
        assert_eq!(KdfName::Scrypt.as_str(), "scrypt");
    }
}
