package io.yubtc.wallet.data

/**
 * In-memory [SettingsRepository] used by unit tests.
 *
 * Holds the same defaults as [SharedPrefsSettingsRepository] so
 * tests can construct an empty store and observe what the
 * production wiring would do on a first launch. Clamping for
 * [idleMinutes] matches the real impl: any value below `1`
 * becomes `1`, anything above `15` rounds to `15`, values
 * between snap to the nearest allowed step (`{1, 5, 15}`).
 * [addrType] mirrors the production whitelist: an unknown initial
 * value falls back to [SharedPrefsSettingsRepository.DEFAULT_ADDR_TYPE].
 *
 * Tests that need a fresh store get a new instance. There is
 * no static mutation — the global "process singleton" lifetime
 * is owned by the production wiring, not by this test helper.
 */
class InMemorySettingsRepository(
    initialWipeOnIdle: Boolean = SharedPrefsSettingsRepository.DEFAULT_WIPE_ON_IDLE,
    initialIdleMinutes: Int = SharedPrefsSettingsRepository.DEFAULT_IDLE_MINUTES,
    initialStrictBip39: Boolean = SharedPrefsSettingsRepository.DEFAULT_STRICT_BIP39,
    initialAddrType: String = SharedPrefsSettingsRepository.DEFAULT_ADDR_TYPE,
) : SettingsRepository {

    override var wipeOnIdle: Boolean = initialWipeOnIdle
    override var idleMinutes: Int = clamp(initialIdleMinutes)
        set(value) {
            // The production SharedPrefsSettingsRepository clamps on
            // write (SharedPrefsSettingsRepository.clampIdle); mirror
            // that here so assignments observe the same contract.
            field = clamp(value)
        }
    override var strictBip39: Boolean = initialStrictBip39
    override var addrType: String = SharedPrefsSettingsRepository.ADDR_TYPE_CHOICES
        .firstOrNull { it == initialAddrType }
        ?: SharedPrefsSettingsRepository.DEFAULT_ADDR_TYPE

    private fun clamp(minutes: Int): Int = when {
        minutes <= 1 -> 1
        minutes >= 15 -> 15
        minutes < 5 -> 1
        minutes < 15 -> 5
        else -> 15
    }
}
