package io.yubtc.wallet

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import io.yubtc.wallet.data.LockScheduler
import io.yubtc.wallet.data.SharedPrefsSettingsRepository
import io.yubtc.wallet.data.YubtcViewModel
import io.yubtc.wallet.data.YubtcViewModelFactory
import io.yubtc.wallet.ui.YubtcNavHost
import io.yubtc.wallet.ui.theme.YubtcTheme
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob

/**
 * Single-activity host for the Compose tree.
 *
 * `enableEdgeToEdge()` lets the Compose content draw under the
 * status / navigation bars; the theme is configured with transparent
 * bars so the screen feels edge-to-edge without losing icon contrast.
 *
 * Phase 9 T3 — auto-lock on background (specs/spec.md «Wipe-on-lock»)
 * -----------------------------------------------
 *
 * [LockScheduler] is bound to [ProcessLifecycleOwner] so the whole
 * process — not just this `Activity` — drives the auto-wipe. The
 * scheduler reads settings through the same
 * [SharedPrefsSettingsRepository] the ViewModel persists, so flipping
 * the toggle in Settings takes effect on the very next `ON_STOP`
 * without any in-process wiring.
 *
 * Why both code paths? The Settings-button "Lock wallet" goes
 * through the VM's `lock()`, which additionally clears the state.
 * The auto-wipe path also goes through the VM's `lock()` —
 * `setContent { val vm = viewModel(...); scheduler.setLockAction(vm::lock) }`
 * is the bridge. The scheduler holds a `var` callback so the
 * late-binding works without a global registry.
 *
 * Scope: a [SupervisorJob] so one failing wipe attempt cannot tear
 * down the rest of the lock scheduler's coroutine tree. The
 * application lives across every Activity recreation, so this is
 * the right granularity for a process-lifetime observer.
 */
class MainActivity : ComponentActivity() {

    private val appScope = CoroutineScope(SupervisorJob())

    private lateinit var repo: SharedPrefsSettingsRepository
    private lateinit var scheduler: LockScheduler

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        repo = SharedPrefsSettingsRepository(
            applicationContext.getSharedPreferences(
                SharedPrefsSettingsRepository.PREFS_NAME,
                Context.MODE_PRIVATE,
            ),
        )
        scheduler = LockScheduler(
            lock = { /* setContent below rebinds this once vm is built */ },
            isWipeEnabled = { repo.wipeOnIdle },
            getIdleMillis = { repo.idleMinutes * 60_000L },
            scope = appScope,
        )
        ProcessLifecycleOwner.get().lifecycle.addObserver(scheduler)
        setContent {
            YubtcTheme {
                val vm: YubtcViewModel = viewModel(
                    factory = YubtcViewModelFactory(this@MainActivity),
                )
                LaunchedEffect(vm) {
                    scheduler.setLockAction(vm::lock)
                }
                YubtcNavHost(vm = vm)
            }
        }
    }
}
