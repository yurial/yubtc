package io.yubtc.wallet.data

import android.content.SharedPreferences
import androidx.core.content.edit

/**
 * Production [SettingsRepository] backed by a real
 * [SharedPreferences] file (`yubtc_settings`).
 *
 * Thread safety: [SharedPreferences] is internally synchronised;
 * writes use `.edit { }` so the apply()/commit() decision is
 * handled per call site. The current implementation uses
 * `apply()` (async fsync) for non-blocking writes — these are
 * UI toggles, never a critical path.
 *
 * Clamping of [idleMinutes] mirrors [SettingsRepository.idleMinutes]
 * contract: anything below `1` lands on `1`; above `15` rounds
 * down to the nearest in-range step (`{1, 5, 15}`). This keeps
 * Settings state consistent even when restored from a corrupted
 * or older version of the prefs file.
 */
class SharedPrefsSettingsRepository(
    private val prefs: SharedPreferences,
) : SettingsRepository {

    override var wipeOnIdle: Boolean
        get() = prefs.getBoolean(KEY_WIPE_ON_IDLE, DEFAULT_WIPE_ON_IDLE)
        set(value) {
            prefs.edit { putBoolean(KEY_WIPE_ON_IDLE, value) }
        }

    override var idleMinutes: Int
        get() {
            val raw = prefs.getInt(KEY_IDLE_MINUTES, DEFAULT_IDLE_MINUTES)
            return clampIdle(raw)
        }
        set(value) {
            prefs.edit { putInt(KEY_IDLE_MINUTES, clampIdle(value)) }
        }

    override var strictBip39: Boolean
        get() = prefs.getBoolean(KEY_STRICT_BIP39, DEFAULT_STRICT_BIP39)
        set(value) {
            prefs.edit { putBoolean(KEY_STRICT_BIP39, value) }
        }

    override var addrType: String
        get() = normalizeAddrType(prefs.getString(KEY_ADDR_TYPE, DEFAULT_ADDR_TYPE))
        set(value) {
            prefs.edit { putString(KEY_ADDR_TYPE, normalizeAddrType(value)) }
        }

    /**
     * Normalize [value] into the whitelist `{legacy, native, taproot}`
     * (mirroring the core's `AddrType` / the CLI's `--addr-type`
     * names). Anything else — a corrupted prefs file, an older
     * version, a hand-edit — lands on the default `"native"`. The
     * read *and* the write paths normalize, so the persisted file can
     * never hold an unknown value (same defensive posture as
     * [clampIdle]).
     */
    private fun normalizeAddrType(value: String?): String =
        if (value != null && value in ADDR_TYPE_CHOICES) value else DEFAULT_ADDR_TYPE

    /**
     * Clamp `minutes` into the allowed set `{1, 5, 15}`:
     *
     * - `< 1` → `1` (smallest valid option).
     * - `> 15` → `15` (largest valid option).
     * - In-range but not a step → nearest step below (`4 → 1`,
     *   `7 → 5`, `9 → 5`, `13 → 5`).
     *
     * Exposed as a private companion helper so future tests can
     * exercise the clamp logic without going through the
     * SharedPreferences shim. The contract is part of the public
     * [SettingsRepository.idleMinutes] contract — keeping the
     * invariants in one place stops a future rewrite from
     * drifting.
     */
    private fun clampIdle(minutes: Int): Int {
        if (minutes <= 1) return 1
        if (minutes >= 15) return 15
        // Between 1 and 15 exclusive: snap to {1, 5, 15}.
        return when {
            minutes < 5 -> 1
            minutes < 15 -> 5
            else -> 15
        }
    }

    companion object {
        /** File name used by the production backing store. */
        const val PREFS_NAME = "yubtc_settings"

        /** Pref key for the auto-wipe toggle. */
        private const val KEY_WIPE_ON_IDLE = "wipe_on_idle"

        /** Pref key for the auto-wipe delay. */
        private const val KEY_IDLE_MINUTES = "idle_minutes"

        /** Pref key for the strict BIP-39 reception toggle. */
        private const val KEY_STRICT_BIP39 = "strict_bip39"

        /** Pref key for the receive-address form. */
        private const val KEY_ADDR_TYPE = "addr_type"

        /** Default: wipe is ON so the user's first run is safe. */
        const val DEFAULT_WIPE_ON_IDLE = true

        /** Default: 5 minutes. Long enough for a notification
         *  shade to be pulled without locking the user out, short
         *  enough that walking away trips the wipe. */
        const val DEFAULT_IDLE_MINUTES = 5

        /** Default: permissive seed reception (R-1 spec.md) —
         *  strict BIP-39 validation is strictly opt-in (R-3). */
        const val DEFAULT_STRICT_BIP39 = false

        /** Default receive-address form: native SegWit (`bc1q…`,
         *  Phase 13 ОВ-1 — same default as the core and the CLI). */
        const val DEFAULT_ADDR_TYPE = "native"

        /** Whitelisted [addrType] values, mirroring the core's
         *  `AddrType::ALL` (`legacy` / `native` / `taproot`). */
        val ADDR_TYPE_CHOICES = listOf("legacy", "native", "taproot")

        /** Whitelisted choices exposed in the Settings UI. */
        val IDLE_CHOICES = listOf(1, 5, 15)
    }
}
