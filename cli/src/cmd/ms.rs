//! `yubtc ms` — multi-sig quorum surface (specs/spec.md
//! «Multi-sig»: `--form` covers `p2sh`/`p2wsh` and the P2TR
//! script-path form).
//!
//! Two commands, mirroring the spec «Поверхность» grammar:
//!
//! - [`create`] — offline pure function: validate the `(N, M, keys)`
//!   tuple (R-MS-1…R-MS-4, R-MS-10 key encodings), build the
//!   canonical redeem script + fixed address in the selected form.
//!   `p2tr` additionally prints the `internal:` (NUMS) and
//!   `control:` lines — the taproot witness material the address
//!   alone does not carry. The seed is requested (stderr) only when
//!   `-n` or a WIF `--key` is present; a watch-only create runs
//!   without any secret material.
//! - [`send`] — thin wrapper (ОВ-12) composing the existing library
//!   stages (no new cryptography or serialization): quorum
//!   reconstruction → UTXO fetch of the quorum address (ОВ-13) →
//!   greedy selection → fee loop →
//!   `PartiallySignedTransaction::create` with the own partial
//!   signatures. stdout carries exactly one payload line (the base64
//!   PSBT); prompts and the fee line go to stderr. Finalization
//!   stays with the standard Phase 14 chain (`psbt sign` × cosigners
//!   → `combine` → `finalize` → `extract` → `pushtx`) — a separate
//!   `ms sign` does not exist (ОВ-12).
//!
//! R-MS-1 at the CLI level: `N` and `M` are mandatory positionals —
//! clap rejects a missing value with its usage error (exit code 2);
//! no default and no prompt substitution exists (pinned by the
//! `cmd_ms` subprocess tests and the `fwd.rs` no-default guard).

use yubtc_core::kdf::KdfAlgo;
use yubtc_core::misc::{TAddress, TNonce, TSatoshi};
use yubtc_core::misc::{TPassphrase, TSeed};
use yubtc_core::net;
use yubtc_core::wallet::MsForm;

use crate::cli::{KdfName, MsCommand, MsCreateArgs, MsSendArgs};
use crate::error::CliError;
use crate::prompt::{prompt_seed_stderr, read_seed_and_passphrase, validate_entered_seed};

use super::address::resolve_kdf;

/// Dispatch a parsed `ms` subcommand.
pub async fn run(cmd: MsCommand) -> Result<(), CliError> {
    match cmd {
        MsCommand::Create(args) => create(args),
        MsCommand::Send(args) => send(args).await,
    }
}

// --- key parsing ------------------------------------------------------

/// One parsed `--key` value (specs/spec.md «Модель участников и ключей»):
/// a cosigner pubkey hex — compressed (66 chars) for p2sh/p2wsh or
/// x-only (64 chars) for p2tr, R-MS-10 — or the own-key WIF sugar
/// (which must match the seed-derived key at `-n`, R-MS-6).
#[derive(Debug, Clone, PartialEq, Eq)]
enum MsKeyArg {
    /// A cosigner pubkey. The x-only encoding of the p2tr form is
    /// carried as a `0x02`-prefixed 33-byte key (exactly the core
    /// `parse_ms_keys` semantics): only the x-only bytes
    /// `1..33` enter the tapscript, and BIP-340 signing normalizes
    /// the parity.
    Pubkey([u8; 33]),
    Wif(String),
}

/// Classify one `--key` value against the form's encoding (R-MS-10):
///
/// - p2sh/p2wsh: exactly 66 hex chars with the `02`/`03` prefix is a
///   cosigner pubkey; anything else is a WIF candidate, verified
///   against the derived own key in [`enter_own_key`] (a malformed
///   WIF fails there with `MsError::ForeignWif` — the same contract
///   as the core primitive).
/// - p2tr: exactly 64 hex chars is an x-only cosigner pubkey; a
///   66-char hex value is a **compressed** key in the wrong encoding
///   for this form — refused immediately with the typed
///   `MsError::InvalidKeyEncoding` (mixing the encodings in one
///   quorum is never a WIF: base58 WIFs are not hex, so the two
///   grammars do not collide); anything else is a WIF candidate.
fn parse_key_arg(value: &str, form: MsForm) -> Result<MsKeyArg, CliError> {
    match form {
        MsForm::P2sh | MsForm::P2wsh => {
            if value.len() == 66 {
                if let Ok(raw) = hex::decode(value) {
                    // 66 hex chars decode to exactly 33 bytes, so this copy
                    // cannot panic; keeping it total (instead of
                    // `try_from(...)?`) avoids an unreachable error arm.
                    let mut arr = [0u8; 33];
                    arr.copy_from_slice(&raw);
                    if arr[0] == 0x02 || arr[0] == 0x03 {
                        return Ok(MsKeyArg::Pubkey(arr));
                    }
                    return Err(CliError::Usage(format!(
                        "invalid --key: 66-char hex must be a compressed pubkey (02…/03… prefix), got prefix {:#04x}",
                        arr[0]
                    )));
                }
            }
            Ok(MsKeyArg::Wif(value.to_string()))
        }
        MsForm::P2tr => {
            if value.len() == 64 {
                if let Ok(raw) = hex::decode(value) {
                    // 64 hex chars decode to exactly 32 bytes.
                    let mut key = [0u8; 33];
                    key[0] = 0x02;
                    key[1..].copy_from_slice(&raw);
                    return Ok(MsKeyArg::Pubkey(key));
                }
            }
            if value.len() == 66 && hex::decode(value).is_ok() {
                // Compressed-shaped key under p2tr: the typed R-MS-10
                // encoding refusal (the error text carries the hint —
                // strip the 02/03 prefix byte for the p2tr form).
                return Err(yubtc_core::wallet::MsError::InvalidKeyEncoding.into());
            }
            Ok(MsKeyArg::Wif(value.to_string()))
        }
    }
}

/// Split the `--key` values into (cosigner pubkeys, WIF candidates),
/// preserving the command-line order.
fn classify_keys(
    values: &[String],
    form: MsForm,
) -> Result<(Vec<[u8; 33]>, Vec<String>), CliError> {
    let mut pubkeys = Vec::with_capacity(values.len());
    let mut wifs = Vec::new();
    for v in values {
        match parse_key_arg(v, form)? {
            MsKeyArg::Pubkey(k) => pubkeys.push(k),
            MsKeyArg::Wif(w) => wifs.push(w),
        }
    }
    Ok((pubkeys, wifs))
}

/// R-MS-6 guard: a WIF `--key` is only meaningful when the own key
/// can be derived to compare against — `-n` is required.
fn require_nonce_for_wifs(nonce: Option<u32>, wifs: &[String]) -> Result<(), CliError> {
    if !wifs.is_empty() && nonce.is_none() {
        return Err(CliError::Usage(
            "--key WIF requires -n NONCE: the WIF must match the own key derived \
             from the seed at that nonce (R-MS-6)"
                .to_string(),
        ));
    }
    Ok(())
}

/// The shared preamble of every `ms` invocation that participates in
/// the quorum: prompt the seed (stderr — stdout stays payload-only),
/// validate reception (permissive default / opt-in strict, R-1…R-6),
/// resolve the `auto` KDF (the ms surface has no `--kdf`, mirroring
/// the `psbt` grammar), derive the own legacy-form key at `nonce`
/// (R-MS-6/ОВ-10) and verify every WIF candidate against it (any
/// mismatch — including every foreign WIF — is `MsError::ForeignWif`,
/// ОВ-11). Returns the seed material (re-passed to the Creator by
/// `ms send`) and the own compressed pubkey (the quorum member).
fn enter_own_key(
    nonce: u32,
    wifs: &[String],
    strict_bip39: bool,
) -> Result<(TSeed, TPassphrase, KdfAlgo, [u8; 33]), CliError> {
    prompt_seed_stderr()?;
    let (seed, passphrase) = read_seed_and_passphrase()?;
    validate_entered_seed(&seed, strict_bip39)?;
    let kdf = resolve_kdf(KdfName::Auto, &passphrase);
    let derived = yubtc_core::wallet::ms_own_privkey(&seed, TNonce::new(nonce), &passphrase, kdf)?;
    for wif in wifs {
        yubtc_core::wallet::ms_wif_own_key(&derived, wif)?;
    }
    Ok((
        seed,
        passphrase,
        kdf,
        yubtc_core::privkey::privkey_to_pubkey(&derived),
    ))
}

// --- create -----------------------------------------------------------

/// `ms create` — offline pure function (specs/spec.md «Поверхность»).
/// Watch-only when neither `-n` nor a WIF is present: no seed is
/// requested and the quorum consists of the passed pubkeys alone.
/// `p2tr` additionally prints the `internal:` (NUMS) and `control:`
/// (33-byte BIP-341 control block, hex) lines — the p2tr spend
/// witness needs both, and the address alone does not carry them.
fn create(args: MsCreateArgs) -> Result<(), CliError> {
    let form = args.form.to_core();
    let (mut quorum, wifs) = classify_keys(&args.keys, form)?;
    require_nonce_for_wifs(args.nonce, &wifs)?;
    if let Some(nonce) = args.nonce {
        let (_, _, _, own_pubkey) = enter_own_key(nonce, &wifs, args.seed_policy.strict_bip39)?;
        quorum.push(own_pubkey);
    }
    let (addr, redeem) =
        yubtc_core::wallet::ms_create_address(args.n as usize, args.m as usize, &quorum, form)?;
    let redeem_hex = hex::encode(&redeem);
    let out = match form {
        MsForm::P2tr => {
            let (internal_hex, control_hex) = tap_witness_material_hex(&redeem);
            render_create_p2tr(
                args.m,
                args.n,
                addr.as_str(),
                &redeem_hex,
                &internal_hex,
                &control_hex,
            )
        }
        MsForm::P2sh | MsForm::P2wsh => render_create(args.m, args.n, addr.as_str(), &redeem_hex),
    };
    println!("{out}");
    Ok(())
}

/// The three output lines of `ms create` for p2sh/p2wsh (spec:
/// `m-of-n:`, `address:`, `redeem:` — hex). Split out so the exact
/// format is pinned by a unit test without capturing process stdout.
fn render_create(m: u32, n: u32, address: &str, redeem_hex: &str) -> String {
    format!("m-of-n: {m}-of-{n}\naddress: {address}\nredeem: {redeem_hex}")
}

/// The five output lines of `ms create --form p2tr` (spec «Поверхность»):
/// the three shared lines plus `internal:` (the NUMS internal key,
/// hex) and `control:` (the 33-byte BIP-341 control block, 66 hex
/// chars). Split out like [`render_create`] for unit-test pinning.
fn render_create_p2tr(
    m: u32,
    n: u32,
    address: &str,
    redeem_hex: &str,
    internal_hex: &str,
    control_hex: &str,
) -> String {
    format!(
        "m-of-n: {m}-of-{n}\naddress: {address}\nredeem: {redeem_hex}\ninternal: {internal_hex}\ncontrol: {control_hex}"
    )
}

/// The taproot witness material of a canonical quorum tapscript:
/// the NUMS internal key and its 33-byte single-leaf control block,
/// both hex-encoded (the `internal:`/`control:` lines of
/// `ms create --form p2tr`). The NUMS point is total, so are the
/// leaf hash and the tweak — the expects are invariant for any
/// script `ms_create_address` produced.
fn tap_witness_material_hex(tapscript: &[u8]) -> (String, String) {
    use yubtc_core::address::tapscript_control_block;
    use yubtc_core::fwd::MS_TAPSCRIPT_INTERNAL_KEY;
    use yubtc_core::script::tapscript_leaf_hash;
    let control =
        tapscript_control_block(&MS_TAPSCRIPT_INTERNAL_KEY, &tapscript_leaf_hash(tapscript))
            .expect("NUMS lift and tweak are total for the canonical internal key");
    (hex::encode(MS_TAPSCRIPT_INTERNAL_KEY), hex::encode(control))
}

// --- send -------------------------------------------------------------

/// `ms send ADDR AMOUNT N M …` — Creator+Signer wrapper (ОВ-12) over
/// [`yubtc_core::wallet::ms_create_psbt`]. Without `-n` the wallet is
/// not a quorum participant and refuses with `MsError::NotAParticipant`
/// before any network activity (yubtc spends only quorums it
/// co-signs). The base64 PSBT is the single stdout payload; the fee
/// line follows the `psbt sign` convention on stderr.
async fn send(args: MsSendArgs) -> Result<(), CliError> {
    let form = args.form.to_core();
    let (cosigners, wifs) = classify_keys(&args.keys, form)?;
    let nonce = match args.nonce {
        Some(n) => n,
        None => {
            // Distinguish the two refusals: a WIF without `-n` is a
            // usage error; an absent own key altogether is the typed
            // NotAParticipant (spec «Валидация» table).
            require_nonce_for_wifs(None, &wifs)?;
            return Err(yubtc_core::wallet::MsError::NotAParticipant.into());
        }
    };
    let (seed, passphrase, kdf, _) = enter_own_key(nonce, &wifs, args.seed_policy.strict_bip39)?;

    let dst = TAddress::new(args.address);
    let amount = yubtc_core::misc::btc2satoshi(&args.amount)
        .map_err(|e| CliError::Usage(format!("amount: {e}")))?;
    if amount.get() == 0 {
        return Err(CliError::Usage("amount must be > 0".to_string()));
    }
    let fee = if args.fee == 0.0 {
        TSatoshi::ZERO
    } else {
        let fee_btc = format!("{:.8}", args.fee);
        yubtc_core::misc::btc2satoshi(&fee_btc).map_err(|e| CliError::Usage(format!("fee: {e}")))?
    };
    let backend =
        net::get_backend_with_retries(args.provider.provider.as_str(), args.provider.retries)?;

    let outcome = yubtc_core::wallet::ms_create_psbt(
        &seed,
        &passphrase,
        kdf,
        backend.as_ref(),
        &dst,
        amount,
        args.n as usize,
        args.m as usize,
        &cosigners,
        Some(TNonce::new(nonce)),
        args.confirmations,
        TSatoshi::new(args.feekb),
        fee,
        form,
    )
    .await?;
    eprintln!("{}", super::psbt::fee_line(Some(outcome.fee.get())));
    println!("{}", outcome.psbt_b64);
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Pure-helper coverage: key classification (both encodings,
    //! R-MS-10), the WIF/nonce guards, and the exact `ms create`
    //! output formats. The stdin-driven preamble and the network
    //! paths are exercised by the `cmd_ms` subprocess tests.

    use super::{
        classify_keys, parse_key_arg, render_create, render_create_p2tr, require_nonce_for_wifs,
        MsKeyArg,
    };
    use crate::error::CliError;
    use yubtc_core::kdf::KdfAlgo;
    use yubtc_core::misc::{TNonce, TPassphrase, TSeed};
    use yubtc_core::privkey::{privkey_to_pubkey, seed2privkey};
    use yubtc_core::wallet::MsForm;

    #[test]
    fn parse_key_arg_accepts_compressed_pubkey_hex() {
        let k0 = {
            let k = seed2privkey(
                &TSeed::new("ms-key-parse"),
                TNonce::new(0),
                &TPassphrase::EMPTY,
            )
            .expect("fixture derivation is deterministic");
            privkey_to_pubkey(&k)
        };
        let k1 = {
            let k = seed2privkey(
                &TSeed::new("ms-key-parse"),
                TNonce::new(1),
                &TPassphrase::EMPTY,
            )
            .expect("fixture derivation is deterministic");
            privkey_to_pubkey(&k)
        };
        assert!(matches!(
            parse_key_arg(&hex::encode(k0), MsForm::P2sh),
            Ok(MsKeyArg::Pubkey(_))
        ));
        // 03-prefix keys classify the same way; p2wsh shares the
        // compressed grammar.
        assert!(matches!(
            parse_key_arg(&hex::encode(k1), MsForm::P2wsh),
            Ok(MsKeyArg::Pubkey(_))
        ));
    }

    #[test]
    fn parse_key_arg_rejects_wrong_prefix_hex() {
        let mut raw = [0x04u8; 33];
        raw[32] = 0x09;
        let err = parse_key_arg(&hex::encode(raw), MsForm::P2sh)
            .expect_err("uncompressed prefix is refused");
        assert!(matches!(err, CliError::Usage(_)), "got: {err}");
        assert!(err.to_string().contains("compressed pubkey"), "got: {err}");
    }

    #[test]
    fn parse_key_arg_p2tr_accepts_x_only_hex_and_carries_it_padded() {
        // The p2tr grammar: 64 hex chars (32 x-only bytes). The
        // internal carry is the 0x02-prefixed 33-byte key — only the
        // x-only bytes ever enter the tapscript (core parse_ms_keys
        // semantics, R-MS-10).
        let compressed = privkey_to_pubkey(
            &seed2privkey(
                &TSeed::new("ms-key-parse"),
                TNonce::new(2),
                &TPassphrase::EMPTY,
            )
            .expect("derives"),
        );
        let xonly_hex = hex::encode(&compressed[1..33]);
        // The carry is exactly the core parse_ms_keys encoding: the
        // 0x02-prefixed 33-byte key around the x-only body.
        let padded = {
            let mut key = [0u8; 33];
            key[0] = 0x02;
            key[1..].copy_from_slice(&compressed[1..33]);
            key
        };
        assert_eq!(
            parse_key_arg(&xonly_hex, MsForm::P2tr).map_err(|e| e.to_string()),
            Ok(MsKeyArg::Pubkey(padded))
        );
        // Uppercase hex is the same key.
        let upper = xonly_hex.to_uppercase();
        assert!(matches!(
            parse_key_arg(&upper, MsForm::P2tr),
            Ok(MsKeyArg::Pubkey(_))
        ));
    }

    #[test]
    fn parse_key_arg_p2tr_rejects_a_compressed_key_with_the_typed_error() {
        // A 66-char compressed key under p2tr is a wrong *encoding*,
        // not a WIF: refused immediately with the typed
        // MsError::InvalidKeyEncoding whose text carries the hint.
        let compressed = privkey_to_pubkey(
            &seed2privkey(
                &TSeed::new("ms-key-parse"),
                TNonce::new(3),
                &TPassphrase::EMPTY,
            )
            .expect("derives"),
        );
        let err = parse_key_arg(&hex::encode(compressed), MsForm::P2tr)
            .expect_err("compressed key under p2tr is the wrong encoding");
        assert!(matches!(err, CliError::Wallet(_)), "got: {err}");
        assert_eq!(
            err.to_string(),
            "wallet: key encoding does not match the form: p2sh/p2wsh need 66-hex \
             compressed keys, p2tr needs 64-hex x-only keys"
        );
        // A 66-char hex with a non-compressed prefix is refused the
        // same way (any 33-byte key is the wrong encoding here).
        let mut raw = [0x04u8; 33];
        raw[32] = 0x11;
        let err = parse_key_arg(&hex::encode(raw), MsForm::P2tr)
            .expect_err("uncompressed key under p2tr is refused too");
        assert!(
            err.to_string().contains("p2tr needs 64-hex x-only keys"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_key_arg_treats_non_hex_as_wif_candidate() {
        // A WIF-shaped value (base58, not 66 hex chars) is carried
        // as a WIF candidate; the authoritative verdict happens
        // against the derived own key (ForeignWif on mismatch).
        let wif = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJodSLu7S3xyQ";
        assert!(matches!(
            parse_key_arg(wif, MsForm::P2sh),
            Ok(MsKeyArg::Wif(_))
        ));
        // Garbage is a WIF candidate too — ms_wif_own_key rejects it.
        assert!(matches!(
            parse_key_arg("not-a-key", MsForm::P2sh),
            Ok(MsKeyArg::Wif(_))
        ));
        // 66 chars that are not hex also fall through to the WIF arm.
        let z66 = "z".repeat(66);
        assert!(matches!(
            parse_key_arg(&z66, MsForm::P2sh),
            Ok(MsKeyArg::Wif(_))
        ));
        // 65 hex chars: wrong length → not a pubkey candidate.
        let short = format!("{}a", "ab".repeat(32));
        assert!(matches!(
            parse_key_arg(&short, MsForm::P2sh),
            Ok(MsKeyArg::Wif(_))
        ));
        // The p2tr grammar falls through to the WIF arm the same way:
        // 64 chars that are not hex, 65-char junk, and 66-char
        // non-hex (not even decodable — a garbage WIF candidate).
        let z64 = "z".repeat(64);
        assert!(matches!(
            parse_key_arg(&z64, MsForm::P2tr),
            Ok(MsKeyArg::Wif(_))
        ));
        let short64 = format!("{}a", "ab".repeat(31));
        assert!(matches!(
            parse_key_arg(&short64, MsForm::P2tr),
            Ok(MsKeyArg::Wif(_))
        ));
        let z66 = "z".repeat(66);
        assert!(matches!(
            parse_key_arg(&z66, MsForm::P2tr),
            Ok(MsKeyArg::Wif(_))
        ));
        // 64 hex chars under p2sh are NOT a pubkey there (wrong
        // length) — WIF candidate.
        assert!(matches!(
            parse_key_arg(&"ab".repeat(32), MsForm::P2sh),
            Ok(MsKeyArg::Wif(_))
        ));
    }

    #[test]
    fn classify_keys_preserves_order_and_splits_kinds() {
        let k0 = {
            let k = seed2privkey(
                &TSeed::new("ms-key-parse"),
                TNonce::new(2),
                &TPassphrase::EMPTY,
            )
            .expect("derives");
            privkey_to_pubkey(&k)
        };
        let k1 = {
            let k = seed2privkey(
                &TSeed::new("ms-key-parse"),
                TNonce::new(3),
                &TPassphrase::EMPTY,
            )
            .expect("derives");
            privkey_to_pubkey(&k)
        };
        let values = vec![hex::encode(k0), "WifCandidate".to_string(), hex::encode(k1)];
        let (pubkeys, wifs) = classify_keys(&values, MsForm::P2sh).expect("all values classify");
        assert_eq!(pubkeys, vec![k0, k1]);
        assert_eq!(wifs, vec!["WifCandidate".to_string()]);
    }

    #[test]
    fn classify_keys_routes_the_form_encoding() {
        // The same 32-byte body is a valid p2tr key but a WIF
        // candidate under p2sh — the form argument decides.
        let body = [0xabu8; 32];
        let (pubkeys, _wifs) = classify_keys(&[hex::encode(body)], MsForm::P2tr).expect("p2tr key");
        assert_eq!(pubkeys.len(), 1);
        assert_eq!(&pubkeys[0][1..33], &body[..]);
        assert_eq!(pubkeys[0][0], 0x02);
        assert!(_wifs.is_empty());
        let (pubkeys, wifs) =
            classify_keys(&[hex::encode(body)], MsForm::P2sh).expect("falls to WIF");
        assert!(pubkeys.is_empty());
        assert_eq!(wifs.len(), 1);
    }

    #[test]
    fn wif_without_nonce_is_refused() {
        let err =
            require_nonce_for_wifs(None, &["x".to_string()]).expect_err("WIF requires -n (R-MS-6)");
        assert!(matches!(err, CliError::Usage(_)), "got: {err}");
        assert!(err.to_string().contains("requires -n"), "got: {err}");
        // No WIFs: watch-only is fine without -n…
        require_nonce_for_wifs(None, &[]).expect("watch-only create");
        // …and -n never needs the guard.
        require_nonce_for_wifs(Some(3), &["x".to_string()]).expect("-n present");
    }

    #[test]
    fn render_create_pins_the_three_output_lines() {
        assert_eq!(
            render_create(2, 3, "3P2shAddressExampleXXXXXXXXXXXXXXXXX", "aabb"),
            "m-of-n: 2-of-3\n\
             address: 3P2shAddressExampleXXXXXXXXXXXXXXXXX\n\
             redeem: aabb"
        );
    }

    #[test]
    fn render_create_p2tr_pins_the_five_output_lines() {
        // Spec «Поверхность»: m-of-n / address (bc1p…) / redeem
        // (tapscript hex) / internal (NUMS) / control (33 bytes hex).
        assert_eq!(
            render_create_p2tr(2, 3, "bc1pExample", "aabb", "cc00", "ddee"),
            "m-of-n: 2-of-3\n\
             address: bc1pExample\n\
             redeem: aabb\n\
             internal: cc00\n\
             control: ddee"
        );
    }

    #[test]
    fn tap_witness_material_hex_pins_the_nums_and_control_block_size() {
        // The material of any canonical quorum tapscript: the fixed
        // NUMS internal key and a 33-byte (66 hex) control block
        // whose second half is the NUMS point itself (depth 0).
        let k0 = privkey_to_pubkey(
            &seed2privkey(
                &TSeed::new("ms-key-parse"),
                TNonce::new(0),
                &TPassphrase::EMPTY,
            )
            .expect("derives"),
        );
        let k1 = privkey_to_pubkey(
            &seed2privkey(
                &TSeed::new("ms-key-parse"),
                TNonce::new(1),
                &TPassphrase::EMPTY,
            )
            .expect("derives"),
        );
        let script = yubtc_core::wallet::ms_create_address(2, 2, &[k0, k1], MsForm::P2tr)
            .expect("quorum builds")
            .1;
        let (internal_hex, control_hex) = super::tap_witness_material_hex(&script);
        assert_eq!(
            internal_hex, "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
            "the NUMS point (R-MS-8)"
        );
        assert_eq!(control_hex.len(), 66, "33-byte control block, hex");
        let control_prefix = u8::from_str_radix(&control_hex[..2], 16).expect("hex");
        assert_eq!(control_prefix & 0xfe, 0xc0, "leaf version + Q parity");
        assert!(control_hex.ends_with(&internal_hex), "c[0] ‖ H");
    }

    #[test]
    fn own_wif_verifies_and_foreign_wif_fails_via_the_cli_error() {
        // The end-to-end WIF paths run in cmd_ms (subprocess); here
        // the core primitive is pinned once through the CLI error
        // mapping: the derived key's own WIF is accepted, a foreign
        // one fails with ForeignWif → CliError::Wallet.
        let seed = TSeed::new("ms-wif-verify");
        let derived = yubtc_core::wallet::ms_own_privkey(
            &seed,
            TNonce::new(0),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
        )
        .expect("derives");
        let own_wif = yubtc_core::address::privkey_to_wif(&derived);
        assert_eq!(
            yubtc_core::wallet::ms_wif_own_key(&derived, &own_wif),
            Ok(privkey_to_pubkey(&derived))
        );
        let foreign = yubtc_core::address::privkey_to_wif(
            &yubtc_core::wallet::ms_own_privkey(
                &seed,
                TNonce::new(9),
                &TPassphrase::EMPTY,
                KdfAlgo::Yubtc,
            )
            .expect("derives"),
        );
        let err: CliError = yubtc_core::wallet::ms_wif_own_key(&derived, &foreign)
            .expect_err("foreign WIF is refused")
            .into();
        assert!(matches!(err, CliError::Wallet(_)), "got: {err}");
        assert_eq!(
            err.to_string(),
            "wallet: WIF does not match the key derived at this nonce"
        );
    }
}
