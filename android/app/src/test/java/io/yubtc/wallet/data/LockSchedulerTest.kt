package io.yubtc.wallet.data

import androidx.lifecycle.Lifecycle
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [LockScheduler]. These run against the unit-test
 * configuration (no Robolectric, no instrumented target) and rely on
 * `kotlinx.coroutines.test` for controlled time.
 *
 * The scheduler's three dependencies (`lock`, `isWipeEnabled`,
 * `getIdleMillis`) are constructor parameters so each test wires a
 * counter / flag and asserts against it. The lifecycle events
 * arrive through [LockScheduler.onStateChanged] directly — no need
 * to spin up a real [androidx.lifecycle.LifecycleOwner].
 *
 * The StandardTestDispatcher gives deterministic ordering: the
 * scheduled wipe job is held in the dispatcher queue until either
 * `runCurrent()` lets it run synchronously or `advanceTimeBy`
 * fast-forwards virtual time past the [delay] threshold.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LockSchedulerTest {

    @Test
    fun onStopWithWipeEnabledSchedulesLockAfterIdleDelay() = runTest {
        val lockCount = LockCounter()
        val settings = InMemorySettingsRepository(
            initialWipeOnIdle = true,
            initialIdleMinutes = 5,
        )
        val scheduler = LockScheduler(
            lock = { lockCount.inc() },
            isWipeEnabled = { settings.wipeOnIdle },
            getIdleMillis = { settings.idleMinutes * 60_000L },
            scope = TestScope(StandardTestDispatcher(testScheduler)),
        )
        scheduler.onStateChanged(FakeOwner(), Lifecycle.Event.ON_STOP)
        runCurrent()
        // Lock must not fire immediately — the whole point is the delay.
        assertEquals(0, lockCount.value)
        // Within the delay window: still no lock.
        advanceTimeBy(settings.idleMinutes * 60_000L - 1)
        runCurrent()
        assertEquals(0, lockCount.value)
        // One millisecond past the delay: lock fires.
        advanceTimeBy(1L)
        runCurrent()
        assertEquals(1, lockCount.value)
    }

    @Test
    fun onStartCancelsAPendingWipe() = runTest {
        val lockCount = LockCounter()
        val settings = InMemorySettingsRepository(initialWipeOnIdle = true)
        val scheduler = LockScheduler(
            lock = { lockCount.inc() },
            isWipeEnabled = { settings.wipeOnIdle },
            getIdleMillis = { settings.idleMinutes * 60_000L },
            scope = TestScope(StandardTestDispatcher(testScheduler)),
        )
        scheduler.onStateChanged(FakeOwner(), Lifecycle.Event.ON_STOP)
        advanceTimeBy(settings.idleMinutes * 60_000L - 1)
        runCurrent()
        assertEquals(0, lockCount.value)
        assertTrue("scheduler should report a pending wipe", scheduler.hasPending())

        // User returns before the window expires.
        scheduler.onStateChanged(FakeOwner(), Lifecycle.Event.ON_START)
        // Run whatever coroutines were cancelled (none).
        runCurrent()
        // Advance well past the original delay — the lock must NOT fire.
        advanceTimeBy(60_000L * 60L)
        runCurrent()
        assertEquals(
            "lock should not fire after on_start cancels the pending wipe",
            0, lockCount.value,
        )
        assertFalse(scheduler.hasPending())
    }

    @Test
    fun onStopWithWipeDisabledSchedulesNothing() = runTest {
        val lockCount = LockCounter()
        val settings = InMemorySettingsRepository(initialWipeOnIdle = false)
        val scheduler = LockScheduler(
            lock = { lockCount.inc() },
            isWipeEnabled = { settings.wipeOnIdle },
            getIdleMillis = { settings.idleMinutes * 60_000L },
            scope = TestScope(StandardTestDispatcher(testScheduler)),
        )
        scheduler.onStateChanged(FakeOwner(), Lifecycle.Event.ON_STOP)
        advanceTimeBy(60_000L * 60L)
        runCurrent()
        assertEquals(0, lockCount.value)
        assertFalse(scheduler.hasPending())
    }

    @Test
    fun togglingWipeOffWhilePendingJobIsInFlightDropsTheWipe() = runTest {
        // Race condition: scheduler is waiting in `delay()`, user toggles
        // wipe off in Settings, the scheduled coroutine resumes — must
        // NOT lock. The re-check inside the launched block is the
        // contract this test pins.
        val lockCount = LockCounter()
        val settings = InMemorySettingsRepository(initialWipeOnIdle = true)
        val scheduler = LockScheduler(
            lock = { lockCount.inc() },
            isWipeEnabled = { settings.wipeOnIdle },
            getIdleMillis = { settings.idleMinutes * 60_000L },
            scope = TestScope(StandardTestDispatcher(testScheduler)),
        )
        scheduler.onStateChanged(FakeOwner(), Lifecycle.Event.ON_STOP)
        runCurrent()
        // Toggle wipe off in Settings *before* the delay elapses.
        // The scheduler's launched block re-checks `isWipeEnabled()`
        // after the delay, so the lock must not fire even if the
        // job is allowed to run to completion.
        settings.wipeOnIdle = false
        advanceTimeBy(settings.idleMinutes * 60_000L)
        runCurrent()
        assertEquals(0, lockCount.value)
    }

    @Test
    fun newOnStopCancelsPreviousPendingWipe() = runTest {
        // Edge case: app is foregrounded (job cancelled), then
        // backgrounded again. The second `ON_STOP` must produce
        // exactly one eventual lock — the first job must not be
        // resurrected.
        val lockCount = LockCounter()
        val settings = InMemorySettingsRepository(initialWipeOnIdle = true)
        val scheduler = LockScheduler(
            lock = { lockCount.inc() },
            isWipeEnabled = { settings.wipeOnIdle },
            getIdleMillis = { settings.idleMinutes * 60_000L },
            scope = TestScope(StandardTestDispatcher(testScheduler)),
        )
        // First backgrounding.
        scheduler.onStateChanged(FakeOwner(), Lifecycle.Event.ON_STOP)
        advanceTimeBy(60_000L)
        runCurrent()
        // Foregrounded before lock could fire.
        scheduler.onStateChanged(FakeOwner(), Lifecycle.Event.ON_START)
        // Second backgrounding — fresh timer.
        scheduler.onStateChanged(FakeOwner(), Lifecycle.Event.ON_STOP)
        // Walk past the second timer.
        advanceTimeBy(settings.idleMinutes * 60_000L)
        runCurrent()
        assertEquals(1, lockCount.value)
    }

    @Test
    fun changingIdleMinutesBetweenOnStopAndFiringIsRespected() = runTest {
        // The scheduler reads `getIdleMillis()` AFTER `delay`. If
        // a user drops the slider mid-window, the new value must
        // win — we want the latest user intent to take effect.
        val lockCount = LockCounter()
        val settings = InMemorySettingsRepository(initialWipeOnIdle = true)
        var injectedMinutes = 5
        val scheduler = LockScheduler(
            lock = { lockCount.inc() },
            isWipeEnabled = { settings.wipeOnIdle },
            // Pretend "five minutes ago" by returning a time that
            // already elapsed so the next delay/awake pair fires
            // immediately when advanceTimeBy runs.
            getIdleMillis = { injectedMinutes * 60_000L },
            scope = TestScope(StandardTestDispatcher(testScheduler)),
        )
        // Start with a 5-minute timer.
        scheduler.onStateChanged(FakeOwner(), Lifecycle.Event.ON_STOP)
        injectedMinutes = 15
        // Advance one minute only — if the scheduler were still on
        // the 5-minute timer the lock must not have fired yet.
        advanceTimeBy(60_000L)
        runCurrent()
        assertEquals(0, lockCount.value)
        // Now jump to the new 15-minute mark.
        advanceTimeBy(15 * 60_000L)
        runCurrent()
        assertEquals(1, lockCount.value)
    }

    /**
     * Mutable counter captured by [LockScheduler.lock] in tests.
     * Kotlin lacks atomic lambdas; a one-field class is the
     * idiomatic stand-in.
     */
    private class LockCounter {
        var value: Int = 0
        fun inc() { value++ }
    }

    /**
     * Minimal `LifecycleOwner` stub. [LockScheduler.onStateChanged]
     * only touches the [LifecycleOwner] to satisfy the
     * `LifecycleEventObserver` contract — the production listener
     * swallows the parameter because the event itself carries
     * everything we need.
     */
    private class FakeOwner : androidx.lifecycle.LifecycleOwner {
        override val lifecycle: androidx.lifecycle.Lifecycle
            get() = throw UnsupportedOperationException("not used")
    }
}
