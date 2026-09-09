//! Logging bootstrap (decision C7, specs/spec.md «Logging policy»).
//!
//! Policy: release builds stay silent unless the user explicitly opts
//! in via `YUBTC_LOG=<level>`; debug builds log at `debug` to stderr
//! out of the box. Private material (seed, passphrase, WIF) is
//! **never** logged at any level — enforced by review of every
//! `debug!`/`info!` callsite, not by code here.
//!
//! Usage: called once from `main()` before command dispatch. Safe to
//! call when no tracing events exist (a no-op without a subscriber).

/// Install a stderr `tracing` subscriber at `level`.
fn install(level: tracing::Level) {
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .init();
}

/// Behaviour for "no usable `YUBTC_LOG`": debug builds install a
/// `debug`-level subscriber; release builds install nothing, so every
/// tracing event stays a no-op — nothing reaches stderr or logcat.
/// The split is compile-time, so neither profile carries an
/// unreachable branch.
fn install_default() {
    #[cfg(debug_assertions)]
    install(tracing::Level::DEBUG);
    // Release: intentionally silent (no subscriber installed).
    #[cfg(not(debug_assertions))]
    {}
}

/// Initialise the global tracing subscriber per the logging policy.
///
/// Contract:
/// - `YUBTC_LOG` set to one of `error|warn|info|debug|trace`
///   (case-insensitive) — subscriber at that level. Invalid values
///   fall back to the default rather than aborting: a typo in a debug
///   knob must not take the wallet down.
/// - `YUBTC_LOG` unset — [`install_default`].
///
/// Calling this more than once is harmless: the second initialisation
/// is dropped by `tracing` with a one-line self-report and the first
/// subscriber stays installed.
pub fn init() {
    match std::env::var("YUBTC_LOG") {
        Ok(value) => match value.to_ascii_lowercase().parse::<tracing::Level>() {
            Ok(level) => install(level),
            Err(_) => install_default(),
        },
        Err(_) => install_default(),
    }
}
