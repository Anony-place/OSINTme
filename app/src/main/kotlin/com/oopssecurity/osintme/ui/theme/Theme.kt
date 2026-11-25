package com.oopssecurity.osintme.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp

private val EditorialIntelligenceLightScheme = lightColorScheme(
    primary = EmeraldPrimary,
    onPrimary = PureWhite,
    primaryContainer = EmeraldSoft,
    onPrimaryContainer = EmeraldDeep,
    secondary = InkBlack,
    onSecondary = PureWhite,
    secondaryContainer = SurfaceElevated,
    onSecondaryContainer = InkBlack,
    tertiary = EmeraldDeep,
    onTertiary = PureWhite,
    background = PureWhite,
    onBackground = InkBlack,
    surface = CharcoalNavy,
    onSurface = InkBlack,
    surfaceVariant = SurfaceElevated,
    onSurfaceVariant = SlateGrey,
    outline = CardBorder,
    outlineVariant = SubtleHighlight,
    error = StatusRisk,
    onError = PureWhite
)

private val WorkbenchShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(20.dp)
)

@Composable
fun OsintMeTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = EditorialIntelligenceLightScheme,
        typography = Typography,
        shapes = WorkbenchShapes,
        content = content
    )
}
