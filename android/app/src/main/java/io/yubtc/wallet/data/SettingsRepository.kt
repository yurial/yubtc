package io.yubtc.wallet.data

/**
 * Persistent settings store for the wallet's UI-level preferences.
 *
 * Scope of this store
 * -------------------
 *
 * The values stored here are **UI controls**, not secrets. They never
 * include the seed, passphrase, or any key material — the wallet is
 * stateless, so secrets cannot live on disk by construction.
 *
 * Defaults mirror `specs/spec.md «Wipe-on-lock»`: "Wipe wallet when leaving the app"
 * defaults to ON so a freshly installed wallet gives the user the
 * safest baseline; a security-conscious user does not have to dig
 * into Settings to enable it. `idleMinutes` defaults to `5` so a
 * momentary distraction (notification shade, task switcher preview)
 * does not kick the user out of their session, while a real
 * phone-down-for-coffee trip triggers the wipe.
 *
 * Choice of backing storage
 * -------------------------
 *
 * `SharedPreferences` is fine here — the values are non-sensitive
 * (a boolean and an integer enum). `EncryptedSharedPreferences`
 * would be misleading because the security model is "seed is in
 * memory only" and the persisted values prove nothing about
 * whether the wallet is locked. Spec explicitly rejects
 * `EncryptedSharedPreferences` for this scenario.
 *
 * Implementations
 * ---------------
 *
 * - [SharedPrefsSettingsRepository] — production backing store.
 * - Unit tests use [InMemorySettingsRepository] to avoid pulling
 *   Robolectric / Android instrumentation into the JVM test classpath.
 */
interface SettingsRepository {
    /** Whether the wallet should auto-wipe when the process leaves
     *  the foreground. Default: `true`. */
    var wipeOnIdle: Boolean

    /**
     * Minutes of backgrounded time before auto-wipe kicks in.
     * Allowed values: 1, 5, 15. Default: 5.
     *
     * Out-of-range writes are clamped: values `< 1` are stored as
     * `1`; values `> 15` round down to the nearest in-range step.
     * The Settings UI only offers the three valid choices, so the
     * clamp is a defensive fix for any caller that bypasses the UI.
     */
    var idleMinutes: Int

    /**
     * Whether seed reception requires the opt-in strict BIP-39
     * policy (spec.md «Seed policy», R-3/R-4): full BIP-39 parse
     * (wordlist + checksum) plus the C6 entropy floor, rejection
     * blocking before KDF. Default: `false` — the permissive mode
     * accepts any non-empty phrase (R-1) and only warns on a low
     * entropy estimate (R-6). Not a secret; stored alongside
     * [wipeOnIdle].
     */
    var strictBip39: Boolean

    /**
     * Receive-address form the wallet derives and displays (Phase 13,
     * mirrors the core's `AddrType { Legacy, Native, Taproot }` and
     * the CLI's `--addr-type`): one of `"legacy"` (P2PKH `1…`),
     * `"native"` (P2WPKH `bc1q…`) or `"taproot"` (P2TR `bc1p…`).
     * Default: `"native"` (ОВ-1). Not a secret; stored alongside
     * [strictBip39]. The value is passed to `WalletHandle::new` on
     * every unlock, so Home / Receive show the chosen form; unknown
     * stored values normalize back to the default (see
     * [SharedPrefsSettingsRepository]).
     */
    var addrType: String
}
