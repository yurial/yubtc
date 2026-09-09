package io.yubtc.wallet.data

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.CreationExtras

/**
 * Compose-friendly [ViewModelProvider.Factory] that wires
 * [YubtcViewModel] with the production-grade
 * [SharedPrefsSettingsRepository].
 *
 * Why a factory?
 * --------------
 *
 * [YubtcViewModel] now takes a [SettingsRepository] in its
 * constructor (so test wiring can substitute
 * [InMemorySettingsRepository] without dragging Robolectric
 * into the JVM test classpath). The default `viewModel()`
 * Compose helper expects a no-arg constructor or a
 * [CreationExtras]-aware factory, so this implementation
 * wires the production dependencies explicitly.
 *
 * Lifetime: a single factory instance can build many
 * [YubtcViewModel] views — the [Context] is the application
 * context, which is process-scoped. `MainActivity` keeps
 * the factory alive across recompositions by handing it
 * to `viewModel(factory = ...)`.
 */
class YubtcViewModelFactory(
    private val context: Context,
) : ViewModelProvider.Factory {

    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        require(modelClass.isAssignableFrom(YubtcViewModel::class.java)) {
            "Unexpected ViewModel class: ${modelClass.name}"
        }
        @Suppress("UNCHECKED_CAST")
        return YubtcViewModel(
            settings = SharedPrefsSettingsRepository(
                context.applicationContext.getSharedPreferences(
                    SharedPrefsSettingsRepository.PREFS_NAME,
                    Context.MODE_PRIVATE,
                ),
            ),
        ) as T
    }
}
