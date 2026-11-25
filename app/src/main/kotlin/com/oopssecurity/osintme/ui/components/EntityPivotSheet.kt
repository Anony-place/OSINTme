package com.oopssecurity.osintme.ui.components

import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.AltRoute
import androidx.compose.material.icons.filled.AlternateEmail
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotAction
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType
import com.oopssecurity.osintme.util.PivotTargetModule
import com.oopssecurity.osintme.util.SafeBrowserLauncher

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntityPivotSheet(
    entity: PivotEntity,
    onPivot: (PivotAction) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val actions = remember(entity) { PivotEngine.buildActions(entity) }
    val defanged = remember(entity.normalizedValue) { PivotEngine.defang(entity.normalizedValue) }

    val typeAccent = when (entity.type) {
        PivotEntityType.DOMAIN -> SkyCyan
        PivotEntityType.IP_ADDRESS -> MatrixGreen
        PivotEntityType.EMAIL -> StatusRisk
        PivotEntityType.USERNAME -> SoftIndigo
        PivotEntityType.URL -> StatusWarning
        PivotEntityType.PHONE -> SkyCyan
        PivotEntityType.HASH -> StatusWarning
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = CharcoalNavy,
        contentColor = OffWhite,
        shape = RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 18.dp, vertical = 6.dp)
        ) {
            // Header badges
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.CallSplit,
                        contentDescription = null,
                        tint = SkyCyan,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "ENTITY PIVOT",
                        color = SkyCyan,
                        fontSize = 11.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.8.sp
                    )
                }

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(5.dp))
                        .background(typeAccent.copy(alpha = 0.14f))
                        .border(1.dp, typeAccent.copy(alpha = 0.4f), RoundedCornerShape(5.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = entity.type.badgeLabel,
                        color = typeAccent,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Normalized Indicator Well
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(DarkerSurface)
                    .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                    .padding(12.dp)
            ) {
                Text(
                    text = entity.normalizedValue,
                    color = OffWhite,
                    fontSize = 14.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis
                )
                if (entity.sourceContext.isNotBlank()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Source: ${entity.sourceContext}",
                        color = MutedSlate,
                        fontSize = 11.sp,
                        fontFamily = MonoFontFamily
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Quick Utility Row: Copy Raw, Copy Defanged, Open URL
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = {
                        copyText(context, "Indicator", entity.normalizedValue)
                        Toast.makeText(context, "Copied indicator", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 44.dp)
                        .testTag("pivot_copy_raw_button"),
                    colors = ButtonDefaults.outlinedButtonColors(
                        containerColor = SurfaceElevated,
                        contentColor = OffWhite
                    ),
                    border = BorderStroke(1.dp, CardBorder),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(15.dp), tint = SkyCyan)
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Copy", fontSize = 12.sp, fontWeight = FontWeight.Medium)
                }

                if (defanged != entity.normalizedValue) {
                    OutlinedButton(
                        onClick = {
                            copyText(context, "Defanged IOC", defanged)
                            Toast.makeText(context, "Copied defanged: $defanged", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 44.dp)
                            .testTag("pivot_copy_defanged_button"),
                        colors = ButtonDefaults.outlinedButtonColors(
                            containerColor = SurfaceElevated,
                            contentColor = OffWhite
                        ),
                        border = BorderStroke(1.dp, CardBorder),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(Icons.Default.Shield, contentDescription = null, modifier = Modifier.size(15.dp), tint = MatrixGreen)
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Defang", fontSize = 12.sp, fontWeight = FontWeight.Medium)
                    }
                }

                if (entity.type == PivotEntityType.URL) {
                    OutlinedButton(
                        onClick = {
                            if (!SafeBrowserLauncher.openExternalUrl(context, entity.normalizedValue)) {
                                Toast.makeText(context, "Blocked unsafe or invalid URL", Toast.LENGTH_SHORT).show()
                            }
                            onDismiss()
                        },
                        modifier = Modifier
                            .heightIn(min = 44.dp)
                            .testTag("pivot_open_url_button"),
                        colors = ButtonDefaults.outlinedButtonColors(
                            containerColor = SurfaceElevated,
                            contentColor = SkyCyan
                        ),
                        border = BorderStroke(1.dp, CardBorder),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = "Open URL in browser", modifier = Modifier.size(16.dp))
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))
            HorizontalDivider(color = CardBorder)
            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = "INVESTIGATE IN MODULE",
                color = MutedSlate,
                fontSize = 10.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.8.sp
            )

            Spacer(modifier = Modifier.height(8.dp))

            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                actions.forEach { action ->
                    val (icon, accent) = moduleVisuals(action.module)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 58.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(SurfaceElevated)
                            .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                            .clickable {
                                onDismiss()
                                onPivot(action)
                            }
                            .testTag("pivot_action_${action.module.name.lowercase()}")
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(accent.copy(alpha = 0.14f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = icon,
                                contentDescription = null,
                                tint = accent,
                                modifier = Modifier.size(18.dp)
                            )
                        }

                        Spacer(modifier = Modifier.width(12.dp))

                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = action.label,
                                color = OffWhite,
                                fontSize = 13.sp,
                                fontFamily = DisplayFontFamily,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = action.subtitle,
                                color = SlateGrey,
                                fontSize = 11.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }

                        Spacer(modifier = Modifier.width(8.dp))

                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                            contentDescription = "Pivot to ${action.label}",
                            tint = accent,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

private fun moduleVisuals(module: PivotTargetModule): Pair<ImageVector, Color> {
    return when (module) {
        PivotTargetModule.TARGET_DOSSIER -> Icons.Default.Shield to SkyCyan
        PivotTargetModule.DOMAIN_RECON -> Icons.Default.Router to SkyCyan
        PivotTargetModule.WAYBACK_ARCHIVE -> Icons.Default.History to MatrixGreen
        PivotTargetModule.TLS_TAKEOVER -> Icons.Default.Lock to MatrixGreen
        PivotTargetModule.REDIRECT_AUDIT -> Icons.Default.AltRoute to StatusWarning
        PivotTargetModule.THREAT_INTEL -> Icons.Default.BugReport to StatusRisk
        PivotTargetModule.BREACH_AUDIT -> Icons.Default.AlternateEmail to StatusRisk
        PivotTargetModule.USERNAME_RECON -> Icons.Default.PersonSearch to SoftIndigo
        PivotTargetModule.LINK_SANITIZER -> Icons.Default.AltRoute to StatusWarning
        PivotTargetModule.DORK_GENERATOR -> Icons.Default.Search to MatrixGreen
        PivotTargetModule.PHONE_RECON -> Icons.Default.Phone to SkyCyan
        PivotTargetModule.HASH_PAYLOAD -> Icons.Default.BugReport to StatusWarning
        PivotTargetModule.AI_ANALYST -> Icons.Default.AutoAwesome to MatrixGreen
    }
}

private fun copyText(context: Context, label: String, text: String) {
    SafeBrowserLauncher.copyToClipboard(context, label, text, isSensitive = true)
}
