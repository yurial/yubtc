//! CLI error type.
//!
//! Every command returns `Result<(), CliError>`; `main` converts the
//! error to a stderr message + non-zero exit code. The error is
//! deliberately flat (`thiserror` `enum`) — no nested context — so a
//! caller reading the message knows exactly what went wrong without
//! chasing a chain.

use std::process::ExitCode;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    /// `stdin` could not be read (EOF, broken pipe, ...).
    #[error("stdin: {0}")]
    Stdin(String),

    /// The seed failed BIP-39 validation.
    #[error("seed: {0}")]
    Seed(String),

    /// Wallet construction or transaction building failed.
    #[error("wallet: {0}")]
    Wallet(String),

    /// Network backend error.
    #[error("network: {0}")]
    Network(String),

    /// A PSBT (BIP-174) operation failed — parsing, a role refusal
    /// (`combine` conflict, `extract` on an unfinalized PSBT), or a
    /// signature-walk error. Exit code 1 like every other failure.
    #[error("psbt: {0}")]
    Psbt(yubtc_core::psbt::PsbtError),

    /// A user-facing argument was rejected (bad address, bad amount,
    /// unknown provider, ...).
    #[error("{0}")]
    Usage(String),

    /// The Coin Control TUI was cancelled by the user (q / Esc).
    #[error("cancelled")]
    Cancelled,

    /// The broadcast prompt was answered "no".
    #[error("broadcast declined")]
    BroadcastDeclined,
}

impl From<yubtc_core::seed::SeedError> for CliError {
    fn from(value: yubtc_core::seed::SeedError) -> Self {
        CliError::Seed(value.to_string())
    }
}

impl From<yubtc_core::wallet::WalletError> for CliError {
    fn from(value: yubtc_core::wallet::WalletError) -> Self {
        CliError::Wallet(value.to_string())
    }
}

impl From<yubtc_core::net::NetError> for CliError {
    fn from(value: yubtc_core::net::NetError) -> Self {
        CliError::Network(value.to_string())
    }
}

impl From<yubtc_core::psbt::PsbtError> for CliError {
    fn from(value: yubtc_core::psbt::PsbtError) -> Self {
        CliError::Psbt(value)
    }
}

impl From<yubtc_core::misc::MiscError> for CliError {
    fn from(value: yubtc_core::misc::MiscError) -> Self {
        CliError::Usage(value.to_string())
    }
}

impl From<yubtc_core::wallet::MsError> for CliError {
    fn from(value: yubtc_core::wallet::MsError) -> Self {
        // Quorum-surface validation (R-MS-1…R-MS-6): rendered under
        // the wallet prefix like every other core validation failure.
        CliError::Wallet(value.to_string())
    }
}

impl From<yubtc_core::wallet::MsSendError> for CliError {
    fn from(value: yubtc_core::wallet::MsSendError) -> Self {
        // Delegate each arm to its existing mapping so `ms send`
        // failures render exactly like the equivalent standalone
        // failure (MsError/WalletError → wallet, PsbtError → psbt,
        // NetError → network).
        match value {
            yubtc_core::wallet::MsSendError::Ms(e) => e.into(),
            yubtc_core::wallet::MsSendError::Wallet(e) => e.into(),
            yubtc_core::wallet::MsSendError::Psbt(e) => e.into(),
            yubtc_core::wallet::MsSendError::Network(e) => e.into(),
        }
    }
}

/// Exit-code policy:
///
/// - 0: command succeeded.
/// - 1: command ran and failed (network error, invalid argument, ...).
/// - 2: command was never dispatched (arg parse error or `--help` /
///   `--version` handled by clap). 2 is also `clap`'s default usage
///   error code, so the binary stays internally consistent.
/// - 130: the user cancelled an interactive prompt (Ctrl-C / q / Esc)
///   — same as Python `KeyboardInterrupt`.
impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::Cancelled => 130,
            CliError::BroadcastDeclined => 0,
            _ => 1,
        }
    }
}

/// Helper used by `main` to write the error to stderr and emit the
/// exit code in one call.
pub fn report(err: &CliError) -> ExitCode {
    eprintln!("yubtc: {err}");
    ExitCode::from(err.exit_code())
}

#[cfg(test)]
mod tests {
    //! Conversion / exit-code / report coverage for every `CliError`
    //! arm — `main` funnels everything through these, so each mapping
    //! is pinned here instead of via failing end-to-end runs.

    use std::process::ExitCode;

    use super::{report, CliError};

    #[test]
    fn from_seed_error_maps_to_seed_variant() {
        // Asserting on the full Display output pins both the variant
        // (the `seed: ` prefix comes from CliError::Seed) and the
        // carried message — this is exactly what `report` prints.
        let err: CliError = yubtc_core::seed::SeedError::InvalidWordCount(13).into();
        assert_eq!(
            err.to_string(),
            "seed: invalid word count 13: must be 12, 15, 18, 21, or 24"
        );
    }

    #[test]
    fn from_wallet_error_maps_to_wallet_variant() {
        let err: CliError = yubtc_core::wallet::WalletError::EmptySeed.into();
        assert_eq!(err.to_string(), "wallet: seed cannot be empty");
    }

    #[test]
    fn from_net_error_maps_to_network_variant() {
        let err: CliError = yubtc_core::net::NetError::UnknownProvider("nope".to_string()).into();
        assert_eq!(
            err.to_string(),
            "network: unknown provider: nope (known: blockchain.info, blockstream, mempool.space)"
        );
    }

    #[test]
    fn from_psbt_error_maps_every_variant_with_exit_code_one() {
        use yubtc_core::psbt::PsbtError;
        // Every PsbtError variant through the From impl: the `psbt: `
        // prefix comes from CliError::Psbt, the inner text from the
        // variant's own Display — exactly what `report` prints. All
        // PSBT failures share the generic failure exit code 1.
        let cases: Vec<PsbtError> = vec![
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
            PsbtError::UnsupportedSighashType(0x03),
            PsbtError::ConflictingField,
            PsbtError::ForeignTransaction,
            PsbtError::IncompleteInput(1),
            PsbtError::NotFinalized,
            PsbtError::TooLarge,
        ];
        for e in cases {
            let err: CliError = e.into();
            assert!(err.to_string().starts_with("psbt: "), "{err}");
            assert_eq!(err.exit_code(), 1, "{err}");
        }
        // A representative full rendering per payload-carrying family,
        // pinning the inner Display against accidental rewording.
        let err: CliError = PsbtError::InvalidKeyLength(2).into();
        assert_eq!(
            err.to_string(),
            "psbt: invalid key data length for field type 2"
        );
        let err: CliError = PsbtError::UnsupportedVersion(2).into();
        assert_eq!(
            err.to_string(),
            "psbt: unsupported PSBT version 2 (only v0 is supported)"
        );
        let err: CliError = PsbtError::IncompleteInput(3).into();
        assert_eq!(
            err.to_string(),
            "psbt: input 3 is incomplete for the requested operation"
        );
    }

    #[test]
    fn from_misc_error_maps_to_usage_variant() {
        let err: CliError = yubtc_core::misc::MiscError::Overflow.into();
        assert_eq!(err.to_string(), "BTC amount overflows u64 satoshi");
    }

    #[test]
    fn from_ms_error_maps_every_variant_to_wallet_with_exit_code_one() {
        use yubtc_core::wallet::MsError;
        // Every MsError variant through the From impl: the `wallet: `
        // prefix comes from CliError::Wallet, the inner text from the
        // variant's own Display — exactly what `report` prints.
        let cases: Vec<(MsError, &str)> = vec![
            (
                MsError::QuorumBounds,
                "quorum out of bounds: need 1 ≤ M ≤ N ≤ 15",
            ),
            (
                MsError::KeyCountMismatch(3, 2),
                "key count mismatch: expected exactly 3 keys, got 2",
            ),
            (MsError::DuplicateKey, "duplicate key in the quorum"),
            (
                MsError::ForeignWif,
                "WIF does not match the key derived at this nonce",
            ),
            (
                MsError::NotAParticipant,
                "own key is not a participant of this quorum",
            ),
            (
                MsError::InvalidKeyEncoding,
                "key encoding does not match the form: p2sh/p2wsh need 66-hex \
                 compressed keys, p2tr needs 64-hex x-only keys",
            ),
        ];
        for (e, msg) in cases {
            let err: CliError = e.into();
            assert_eq!(err.to_string(), format!("wallet: {msg}"), "{msg}");
            assert_eq!(err.exit_code(), 1, "{msg}");
        }
    }

    #[test]
    fn from_ms_send_error_delegates_to_the_standalone_mappings() {
        use yubtc_core::net::NetError;
        use yubtc_core::psbt::PsbtError;
        use yubtc_core::wallet::{MsError, MsSendError, WalletError};
        // Ms arm → the MsError mapping.
        let err: CliError = MsSendError::Ms(MsError::NotAParticipant).into();
        assert_eq!(
            err.to_string(),
            "wallet: own key is not a participant of this quorum"
        );
        // Wallet arm → the WalletError mapping.
        let err: CliError = MsSendError::Wallet(WalletError::EmptySeed).into();
        assert_eq!(err.to_string(), "wallet: seed cannot be empty");
        // Psbt arm → the dedicated psbt variant.
        let err: CliError = MsSendError::Psbt(PsbtError::NotFinalized).into();
        assert_eq!(
            err.to_string(),
            "psbt: not all inputs are finalized; extraction refused"
        );
        // Network arm → the NetError mapping.
        let err: CliError =
            MsSendError::Network(NetError::UnknownProvider("foo".to_string())).into();
        assert!(
            err.to_string()
                .starts_with("network: unknown provider: foo"),
            "got: {err}"
        );
    }

    #[test]
    fn exit_code_cancelled_is_sigint_convention() {
        assert_eq!(CliError::Cancelled.exit_code(), 130);
    }

    #[test]
    fn exit_code_broadcast_declined_is_success() {
        assert_eq!(CliError::BroadcastDeclined.exit_code(), 0);
    }

    #[test]
    fn exit_code_every_failure_variant_is_one() {
        assert_eq!(CliError::Stdin("eof".to_string()).exit_code(), 1);
        assert_eq!(CliError::Seed("bad".to_string()).exit_code(), 1);
        assert_eq!(CliError::Wallet("bad".to_string()).exit_code(), 1);
        assert_eq!(CliError::Network("down".to_string()).exit_code(), 1);
        assert_eq!(CliError::Usage("bad flag".to_string()).exit_code(), 1);
    }

    #[test]
    fn report_returns_the_variant_exit_code() {
        // report() writes to stderr (captured by the test harness);
        // the contract under test is the returned ExitCode.
        assert_eq!(report(&CliError::Cancelled), ExitCode::from(130));
        assert_eq!(report(&CliError::BroadcastDeclined), ExitCode::SUCCESS);
        assert_eq!(
            report(&CliError::Usage("bad flag".to_string())),
            ExitCode::from(1)
        );
    }
}
