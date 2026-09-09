package io.yubtc.wallet

import android.app.Application
import uniffi.yubtc_core.uniffiEnsureInitialized

/**
 * Application entry point. Registered as `android:name=".YubtcApp"` in
 * `AndroidManifest.xml`.
 *
 * The only responsibility is bootstrapping the UniFFI scaffolding
 * exactly once per process. The native library `libyubtc_core.so` is
 * loaded by JNA when the first generated type is touched; calling
 * [uniffiEnsureInitialized] up-front surfaces any load failure (wrong
 * ABI, missing `.so`, signature mismatch) at launch rather than at the
 * first user action.
 */
class YubtcApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Idempotent; safe to call repeatedly. Internally checks
        // the API contract version + every checksum and throws
        // RuntimeException on drift.
        uniffiEnsureInitialized()
    }
}
