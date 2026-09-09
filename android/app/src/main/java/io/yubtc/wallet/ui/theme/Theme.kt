package io.yubtc.wallet.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

/**
 * yubtc's Material 3 theme.
 *
 * The palette is fixed (no dynamic colour on Android 12+) — wallets
 * should look identical across devices regardless of the user's
 * Material You wallpaper. The dark / light switch follows the system
 * setting; the brand orange stays constant in both modes.
 */
@Composable
fun YubtcTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colors = if (darkTheme) {
        darkColorScheme(
            primary = YubtcPalette.Brand,
            onPrimary = YubtcPalette.Paper,
            primaryContainer = YubtcPalette.BrandDim,
            onPrimaryContainer = YubtcPalette.Paper,
            background = YubtcPalette.Ink,
            onBackground = YubtcPalette.Paper,
            surface = YubtcPalette.InkDim,
            onSurface = YubtcPalette.Paper,
            surfaceVariant = YubtcPalette.InkDim,
            onSurfaceVariant = YubtcPalette.PaperDim,
            error = YubtcPalette.Danger,
            onError = YubtcPalette.Paper,
        )
    } else {
        lightColorScheme(
            primary = YubtcPalette.Brand,
            onPrimary = YubtcPalette.Paper,
            primaryContainer = YubtcPalette.Brand,
            onPrimaryContainer = YubtcPalette.Paper,
            background = YubtcPalette.Paper,
            onBackground = YubtcPalette.Ink,
            surface = YubtcPalette.Paper,
            onSurface = YubtcPalette.Ink,
            surfaceVariant = YubtcPalette.PaperDim,
            onSurfaceVariant = YubtcPalette.InkDim,
            error = YubtcPalette.Danger,
            onError = YubtcPalette.Paper,
        )
    }
    MaterialTheme(
        colorScheme = colors,
        typography = YubtcTypography,
        content = content,
    )
}
