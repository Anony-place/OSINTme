package com.oopssecurity.osintme.ui.theme

import androidx.compose.ui.graphics.Color

// Swiss Editorial Light Intelligence Palette — Crisp White, Jet Ink Black & Signal Emerald
val PureWhite = Color(0xFFFFFFFF)           // Pure Canvas White
val InkBlack = Color(0xFF090D16)            // Jet Ink Black (Primary Text & Solid Buttons)
val EmeraldPrimary = Color(0xFF059669)      // Signal Emerald Green (Live Telemetry & Accents)
val EmeraldDeep = Color(0xFF047857)         // Deep Forest Emerald (Secondary Highlights)
val EmeraldSoft = Color(0xFFECFDF5)         // Soft Mint Tint (Verified / Active Containers)
val EmeraldBorder = Color(0xFFA7F3D0)       // Crisp Mint Hairline Border

// Semantic Workbench Surface Tokens (mapped cleanly across all modules)
val SlateObsidian = PureWhite               // Pure White Canvas & On-Solid-Button White Ink
val CharcoalNavy = Color(0xFFF8FAFC)        // Crisp Alabaster Primary Card Surface
val SurfaceElevated = Color(0xFFF1F5F9)     // Cool Paper (Chips, Tabs, Elevated Controls)
val DarkerSurface = PureWhite               // Pure White Input & Form Surface
val TechCodeBackground = Color(0xFFF1F5F9)  // Cool Paper Code & Indicator Well
val CardBorder = Color(0xFFE2E8F0)          // Hairline Structural Divider & Border
val SubtleHighlight = Color(0xFFCBD5E1)     // Focused Border / Active Stroke

// Precision High-Contrast Accents (Ink Black + Signal Emerald)
val SkyCyan = InkBlack                      // Jet Ink Black (Primary Interactive Buttons & Icons)
val AccentSkyDeep = Color(0xFF1E293B)       // Deep Slate Ink
val SoftIndigo = EmeraldDeep                // Deep Forest Emerald (Category Tags & Accents)
val MatrixGreen = EmeraldPrimary            // Signal Emerald (Verified / Live / Active AI)

// Editorial Typography Ink Scale (High Daylight Readability)
val OffWhite = InkBlack                     // Jet Ink Black (Primary Headings & Values)
val SlateGrey = Color(0xFF334155)           // Charcoal Slate (Body Copy & Subtitles)
val MutedSlate = Color(0xFF64748B)          // Muted Steel (Captions & Placeholders)

// Semantic Threat & Posture States (High Contrast on White)
val StatusSafe = EmeraldPrimary             // Signal Emerald — Verified Clean / Secure
val StatusWarning = Color(0xFFD97706)       // Deep Amber — Advisory / Rate-Limited / Caution
val StatusRisk = Color(0xFFDC2626)          // Signal Crimson — Breach / Malicious / Exposed
