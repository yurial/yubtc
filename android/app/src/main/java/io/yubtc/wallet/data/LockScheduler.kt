package io.yubtc.wallet.data

import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Auto-lock the wallet when the process leaves the foreground for
 * longer than the user-configured idle window.
 *
 * Architecture
 * ------------
 *
 * [LockScheduler] is a [LifecycleEventObserver] attached to
 * [androidx.lifecycle.ProcessLifecycleOwner]. The whole-process
 * owner survives `MainActivity` recreations and groups small
 * foreground stints (notification shade, recent-apps preview)
 * into a single `ON_START`/`ON_STOP` pair — exactly the
 * semantics specs/spec.md «Wipe-on-lock» wants ("open shutter, back to app"
 * should not count as backgrounding).
 *
 * Wiring:
 *
 * - On `ON_STOP`, if [isWipeEnabled] reads `true`, schedule a
 *   coroutine that sleeps [getIdleMillis] and then calls [lock].
 * - On `ON_START`, cancel any pending wipe job so a quick
 *   return to the app does not lock the user out.
 * - When the user toggles wipe off later, a stale `ON_STOP`
 *   job may still be in flight. The cancel in `ON_START` does
 *   not help that case — toggling itself cancels pending jobs
 *   via [cancelPending] (called by the ViewModel when the user
 *   flips the switch).
 *
 * The [lock] callback is a `var` rather than a constructor
 * `val` because the auto-wipe target is the live Compose
 * `YubtcViewModel` instance, which is constructed lazily
 * during `setContent`. Production wiring sets the action via
 * [setLockAction] inside a `LaunchedEffect(vm) { ... }` so the
 * closure rebinds once `viewModel()` returns. Before that
 * happens, the lock callback is the no-op default — a
 * background event during that tiny window does not crash.
 *
 * Testability
 * -----------
 *
 * Two seams make the scheduler pure-JVM testable:
 *
 * 1. `lock`, `isWipeEnabled`, `getIdleMillis`, and `scope` are
 *    constructor params. Tests substitute a fake `lock: () -> Unit`
 *    counter, an injectable `getIdleMillis: () -> Long` for fake
 *    time, and a [CoroutineScope] they own (via
 *    [kotlinx.coroutines.test.runTest]).
 * 2. The scheduler exposes [cancelPending] for the user-driven
 *    cancellation case, so tests can drive it from outside the
 *    lifecycle path.
 */
class LockScheduler(
    private var lock: () -> Unit,
    private val isWipeEnabled: () -> Boolean,
    private val getIdleMillis: () -> Long,
    private val scope: CoroutineScope,
) : LifecycleEventObserver {

    /**
     * Currently pending wipe job, or `null` if no wipe is scheduled.
     *
     * Held so a subsequent `ON_START` (or a settings toggle) can
     * cancel it. Exposed as `@Volatile` because the lifecycle
     * observer can be invoked from the main thread while the
     * pending coroutine is in flight on a worker.
     */
    @Volatile
    private var pending: Job? = null

    /**
     * Replace the [lock] callback. Production wiring uses this
     * once the Compose `YubtcViewModel` instance is built; tests
     * never call it (they wire a concrete counter in the
     * constructor).
     */
    fun setLockAction(action: () -> Unit) {
        lock = action
    }

    override fun onStateChanged(source: LifecycleOwner, event: Lifecycle.Event) {
        when (event) {
            Lifecycle.Event.ON_STOP -> scheduleIfEnabled()
            Lifecycle.Event.ON_START -> cancelPending()
            else -> Unit
        }
    }

    /**
     * Schedule the auto-wipe if and only if [isWipeEnabled] reads
     * `true`. Idempotent: re-entering this on a second `ON_STOP`
     * cancels any earlier pending job first so we always end up
     * with exactly one scheduled wipe.
     *
     * Spec contract: specs/spec.md «Wipe-on-lock» ("after N minutes of being
     * backgrounded, call vm.lock()"). The "N" comes from the
     * [SettingsRepository] at the time of the call, so flipping
     * the slider re-arms the wipe with the new delay.
     */
    private fun scheduleIfEnabled() {
        if (!isWipeEnabled()) {
            return
        }
        pending?.cancel()
        pending = scope.launch {
            val ms = getIdleMillis()
            // Negative or zero deltas are clamped out at the repo
            // layer; the defensive `coerceAtLeast` here protects
            // against a future caller that forgets to clamp.
            delay(ms.coerceAtLeast(0L))
            // Re-check the toggle before firing: if the user
            // disabled wipe while we were waiting, do not lock.
            if (isWipeEnabled()) {
                lock()
            }
        }
    }

    /**
     * Cancel a pending wipe (if any). Called both on
     * `ON_START` (foregrounded) and when the user toggles wipe
     * OFF. The previous behaviour left an in-flight job racing
     * with the toggle, which produced "I turned it off but my
     * wallet still locked 30s later" reports.
     */
    fun cancelPending() {
        pending?.cancel()
        pending = null
    }

    /**
     * Test seam: report whether a wipe job is currently in flight.
     *
     * Production code has no use for this — the lifecycle already
     * answers the same question. Tests use it to assert that a
     * toggle does (or does not) leave a stale job queued.
     */
    fun hasPending(): Boolean = pending?.isActive == true
}
