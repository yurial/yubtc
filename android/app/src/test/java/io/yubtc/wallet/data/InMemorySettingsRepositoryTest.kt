package io.yubtc.wallet.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [InMemorySettingsRepository].
 *
 * The in-memory repo mirrors the contract of
 * [SharedPrefsSettingsRepository] (default + clamp behaviour) so
 * these tests double as a specification of the production wiring.
 * SharedPreferences round-tripping is not exercised here — that is
 * the OS's contract — but the clamping logic *is*, because it is
 * the only piece of business logic in the persistent impl.
 */
class InMemorySettingsRepositoryTest {

    @Test
    fun defaultsMatchProductionRepo() {
        val repo = InMemorySettingsRepository()
        assertTrue(
            "default wipeOnIdle must be true (specs/spec.md «Wipe-on-lock»)",
            repo.wipeOnIdle,
        )
        assertEquals(
            "default idleMinutes must be 5",
            5, repo.idleMinutes,
        )
        assertEquals(
            "default strictBip39 must be false (permissive, R-1/R-3 spec.md)",
            false, repo.strictBip39,
        )
    }

    @Test
    fun explicitDefaultsConstructorArgsAreHonoured() {
        val repo = InMemorySettingsRepository(
            initialWipeOnIdle = false,
            initialIdleMinutes = 15,
            initialStrictBip39 = true,
        )
        assertEquals(false, repo.wipeOnIdle)
        assertEquals(15, repo.idleMinutes)
        assertEquals(true, repo.strictBip39)
    }

    @Test
    fun clampBelowMinimum() {
        val repo = InMemorySettingsRepository(initialIdleMinutes = 0)
        assertEquals(1, repo.idleMinutes)
    }

    @Test
    fun clampAboveMaximum() {
        val repo = InMemorySettingsRepository(initialIdleMinutes = 60)
        assertEquals(15, repo.idleMinutes)
    }

    @Test
    fun clampSnapsToNearestValidStep() {
        // Below the second step (5), clamp down to 1.
        assertEquals(1, InMemorySettingsRepository(initialIdleMinutes = 4).idleMinutes)
        assertEquals(1, InMemorySettingsRepository(initialIdleMinutes = 2).idleMinutes)
        // Between 5 and 15, snap to 5.
        assertEquals(5, InMemorySettingsRepository(initialIdleMinutes = 6).idleMinutes)
        assertEquals(5, InMemorySettingsRepository(initialIdleMinutes = 14).idleMinutes)
    }

    @Test
    fun clampOnWriteSnapsOutOfRangeValues() {
        val repo = InMemorySettingsRepository()
        repo.idleMinutes = 60
        assertEquals(15, repo.idleMinutes)
        repo.idleMinutes = 0
        assertEquals(1, repo.idleMinutes)
        repo.idleMinutes = 7
        assertEquals(5, repo.idleMinutes)
    }

    @Test
    fun wipeToggleRoundTrips() {
        val repo = InMemorySettingsRepository(initialWipeOnIdle = true)
        repo.wipeOnIdle = false
        assertEquals(false, repo.wipeOnIdle)
        repo.wipeOnIdle = true
        assertEquals(true, repo.wipeOnIdle)
    }

    @Test
    fun strictBip39ToggleRoundTrips() {
        // The strict toggle is a plain boolean: write/read round-trip
        // with no clamping (unlike idleMinutes). Default is OFF, and
        // the Setting mirrors the persisted value on the next read.
        val repo = InMemorySettingsRepository()
        assertEquals(false, repo.strictBip39)
        repo.strictBip39 = true
        assertEquals(true, repo.strictBip39)
        repo.strictBip39 = false
        assertEquals(false, repo.strictBip39)
    }

    @Test
    fun addrTypeDefaultsToNative() {
        // Phase 13 ОВ-1: the receive-address form defaults to native
        // SegWit, same default as the core and the CLI.
        assertEquals("native", InMemorySettingsRepository().addrType)
    }

    @Test
    fun addrTypeRoundTrips() {
        // The address form is a plain whitelisted string: write/read
        // round-trip with no clamping (unlike idleMinutes).
        val repo = InMemorySettingsRepository()
        repo.addrType = "taproot"
        assertEquals("taproot", repo.addrType)
        repo.addrType = "legacy"
        assertEquals("legacy", repo.addrType)
        repo.addrType = "native"
        assertEquals("native", repo.addrType)
    }

    @Test
    fun addrTypeUnknownValueFallsBackToDefault() {
        // Mirrors the production normalization: an unknown or null
        // value (corrupted prefs, older version) must not crash the
        // unlock — it lands on the default "native".
        assertEquals(
            "native",
            InMemorySettingsRepository(initialAddrType = "p2sh").addrType,
        )
    }
}
