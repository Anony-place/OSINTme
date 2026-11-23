package com.oopssecurity.osintme.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val TacticalCyberColorScheme = darkColorScheme(
    primary = SkyCyan,
    onPrimary = SlateObsidian,
    primaryContainer = SurfaceElevated,
    onPrimaryContainer = SkyCyan,
    secondary = MatrixGreen,
    onSecondary = SlateObsidian,
    secondaryContainer = CharcoalNavy,
    onSecondaryContainer = OffWhite,
    tertiary = SoftIndigo,
    background = SlateObsidian,
    onBackground = OffWhite,
    surface = CharcoalNavy,
    onSurface = OffWhite,
    surfaceVariant = SurfaceElevated,
    onSurfaceVariant = SlateGrey,
    outline = CardBorder,
    error = StatusRisk,
    onError = OffWhite
)

@Composable
fun OsintMeTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = TacticalCyberColorScheme,
        typography = Typography,
        content = content
    )
}
