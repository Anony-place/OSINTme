package com.oopssecurity.osintme.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AlternateEmail
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.FolderSpecial
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Http
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MarkEmailRead
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation3.runtime.NavKey
import com.oopssecurity.osintme.AiAnalystNav
import com.oopssecurity.osintme.ApiVaultNav
import com.oopssecurity.osintme.BreachAuditorNav
import com.oopssecurity.osintme.CaseManagementNav
import com.oopssecurity.osintme.ComplianceDisclaimerNav
import com.oopssecurity.osintme.DashboardNav
import com.oopssecurity.osintme.DomainReconNav
import com.oopssecurity.osintme.DorkGeneratorNav
import com.oopssecurity.osintme.EmailHeaderNav
import com.oopssecurity.osintme.ExifInspectorNav
import com.oopssecurity.osintme.HashPayloadNav
import com.oopssecurity.osintme.HygieneChecklistNav
import com.oopssecurity.osintme.IocWorkbenchNav
import com.oopssecurity.osintme.LinkSanitizerNav
import com.oopssecurity.osintme.OpsecSettingsNav
import com.oopssecurity.osintme.PhoneReconNav
import com.oopssecurity.osintme.RedirectAuditNav
import com.oopssecurity.osintme.ScanHistoryNav
import com.oopssecurity.osintme.TargetDossierNav
import com.oopssecurity.osintme.ThreatIntelNav
import com.oopssecurity.osintme.TlsTakeoverNav
import com.oopssecurity.osintme.UsernameReconNav
import com.oopssecurity.osintme.WaybackNav
import com.oopssecurity.osintme.data.local.AiProvider
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.local.ApiProvider
import com.oopssecurity.osintme.data.network.OpsecManager
import com.oopssecurity.osintme.data.network.ProxyMode
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
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SoftIndigo

@Composable
fun TacticalNavigationDrawerSheet(
    currentKey: Any,
    onNavigate: (NavKey) -> Unit,
    onCloseDrawer: () -> Unit
) {
    val scrollState = rememberScrollState()
    val isProxyActive = (OpsecManager.currentProxyMode != ProxyMode.DIRECT)

    ModalDrawerSheet(
        drawerContainerColor = SlateObsidian,
        drawerContentColor = OffWhite,
        modifier = Modifier
            .width(312.dp)
            .fillMaxHeight()
    ) {
        Column(
            modifier = Modifier
                .fillMaxHeight()
                .statusBarsPadding()
                .navigationBarsPadding()
                .verticalScroll(scrollState)
                .padding(vertical = 12.dp)
        ) {
            // Workbench Header
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 8.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(SkyCyan.copy(alpha = 0.14f))
                            .border(1.dp, SkyCyan.copy(alpha = 0.35f), RoundedCornerShape(10.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = SkyCyan,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "OSINTme",
                            color = OffWhite,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = DisplayFontFamily
                        )
                        Text(
                            text = "Intelligence Workbench",
                            color = SlateGrey,
                            fontSize = 11.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // Live Network Route Pill
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(DarkerSurface)
                        .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                        .clickable {
                            onNavigate(OpsecSettingsNav)
                            onCloseDrawer()
                        }
                        .padding(horizontal = 10.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "ROUTE",
                        color = MutedSlate,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = if (isProxyActive) "PROXY / TOR" else "DIRECT TLS",
                        color = if (isProxyActive) MatrixGreen else SkyCyan,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider(color = CardBorder, thickness = 1.dp)
            Spacer(modifier = Modifier.height(8.dp))

            DrawerCategoryHeader("WORKSPACE")
            DrawerNavItem(
                label = "Dashboard",
                icon = Icons.Default.Radar,
                isSelected = currentKey is DashboardNav,
                onClick = { onNavigate(DashboardNav); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "One-Shot Target Dossier",
                icon = Icons.Default.Shield,
                badge = "ALL-IN-1",
                badgeColor = SkyCyan,
                isSelected = currentKey is TargetDossierNav,
                onClick = { onNavigate(TargetDossierNav("")); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "BYOK AI OSINT Analyst",
                icon = Icons.Default.AutoAwesome,
                badge = if (ApiKeyVault.activeAiCount() > 0) "LIVE AI" else "BYOK",
                badgeColor = MatrixGreen,
                isSelected = currentKey is AiAnalystNav,
                onClick = { onNavigate(AiAnalystNav()); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Case Dossiers & Graph",
                icon = Icons.Default.FolderSpecial,
                badge = "SQLITE",
                badgeColor = MatrixGreen,
                isSelected = currentKey is CaseManagementNav,
                onClick = { onNavigate(CaseManagementNav); onCloseDrawer() }
            )

            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider(color = CardBorder, thickness = 1.dp)
            Spacer(modifier = Modifier.height(8.dp))

            DrawerCategoryHeader("HIGH-IMPACT RECON LABS")
            DrawerNavItem(
                label = "Wayback Archive Explorer",
                icon = Icons.Default.Timeline,
                badge = "CDX",
                badgeColor = MatrixGreen,
                isSelected = currentKey is WaybackNav,
                onClick = { onNavigate(WaybackNav("")); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Live TLS & CNAME Takeover",
                icon = Icons.Default.Lock,
                badge = "X.509",
                badgeColor = SkyCyan,
                isSelected = currentKey is TlsTakeoverNav,
                onClick = { onNavigate(TlsTakeoverNav("")); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Redirect & Header Auditor",
                icon = Icons.Default.Http,
                badge = "A+-F",
                badgeColor = MatrixGreen,
                isSelected = currentKey is RedirectAuditNav,
                onClick = { onNavigate(RedirectAuditNav("")); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Precision Dorks & Shodan",
                icon = Icons.Default.Search,
                badge = "7 ENGINES",
                badgeColor = SoftIndigo,
                isSelected = currentKey is DorkGeneratorNav,
                onClick = { onNavigate(DorkGeneratorNav("")); onCloseDrawer() }
            )

            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider(color = CardBorder, thickness = 1.dp)
            Spacer(modifier = Modifier.height(8.dp))

            DrawerCategoryHeader("PRO FORENSIC WORKBENCHES")
            DrawerNavItem(
                label = "Bulk IOC Extractor & Triage",
                icon = Icons.Default.FilterAlt,
                badge = "BATCH",
                badgeColor = MatrixGreen,
                isSelected = currentKey is IocWorkbenchNav,
                onClick = { onNavigate(IocWorkbenchNav("")); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Email Header Forensics",
                icon = Icons.Default.MarkEmailRead,
                badge = "AI+HOPS",
                badgeColor = SkyCyan,
                isSelected = currentKey is EmailHeaderNav,
                onClick = { onNavigate(EmailHeaderNav); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Hash Lookup & Payload Lab",
                icon = Icons.Default.Code,
                badge = "JWT/B64",
                badgeColor = SoftIndigo,
                isSelected = currentKey is HashPayloadNav,
                onClick = { onNavigate(HashPayloadNav("")); onCloseDrawer() }
            )

            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider(color = CardBorder, thickness = 1.dp)
            Spacer(modifier = Modifier.height(8.dp))

            DrawerCategoryHeader("INTELLIGENCE MODULES")
            DrawerNavItem(
                label = "Network, Web Stack & BGP",
                icon = Icons.Default.Router,
                badge = "7 FEEDS",
                isSelected = currentKey is DomainReconNav,
                onClick = { onNavigate(DomainReconNav("")); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Breach, Email & Passwords",
                icon = Icons.Default.AlternateEmail,
                badge = "K-ANON",
                isSelected = currentKey is BreachAuditorNav,
                onClick = { onNavigate(BreachAuditorNav("")); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Username Hunter",
                icon = Icons.Default.PersonSearch,
                badge = "106+ SITES",
                isSelected = currentKey is UsernameReconNav,
                onClick = { onNavigate(UsernameReconNav("")); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Phone E.164 & Pivots",
                icon = Icons.Default.Phone,
                isSelected = currentKey is PhoneReconNav,
                onClick = { onNavigate(PhoneReconNav("")); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "EXIF & Image Forensics",
                icon = Icons.Default.Image,
                badge = "LOCAL",
                badgeColor = MatrixGreen,
                isSelected = currentKey is ExifInspectorNav,
                onClick = { onNavigate(ExifInspectorNav(null)); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Threat Intel & Dorks",
                icon = Icons.Default.BugReport,
                badge = "1.1.1.2",
                badgeColor = SoftIndigo,
                isSelected = currentKey is ThreatIntelNav,
                onClick = { onNavigate(ThreatIntelNav("")); onCloseDrawer() }
            )

            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider(color = CardBorder, thickness = 1.dp)
            Spacer(modifier = Modifier.height(8.dp))

            DrawerCategoryHeader("DEFENSIVE TOOLS")
            DrawerNavItem(
                label = "Link Sanitizer & Redirects",
                icon = Icons.Default.CleaningServices,
                isSelected = currentKey is LinkSanitizerNav,
                onClick = { onNavigate(LinkSanitizerNav("")); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Security Hygiene Checklist",
                icon = Icons.Default.Security,
                isSelected = currentKey is HygieneChecklistNav,
                onClick = { onNavigate(HygieneChecklistNav); onCloseDrawer() }
            )

            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider(color = CardBorder, thickness = 1.dp)
            Spacer(modifier = Modifier.height(8.dp))

            DrawerCategoryHeader("SETTINGS & AUDIT")
            DrawerNavItem(
                label = "BYOK AI & API Key Vault",
                icon = Icons.Default.Key,
                badge = "${ApiKeyVault.activeAiCount() + ApiKeyVault.activeCount()}/${AiProvider.entries.size + ApiProvider.entries.size}",
                badgeColor = if (ApiKeyVault.activeAiCount() + ApiKeyVault.activeCount() > 0) MatrixGreen else SkyCyan,
                isSelected = currentKey is ApiVaultNav,
                onClick = { onNavigate(ApiVaultNav); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "OPSEC & Proxy Router",
                icon = Icons.Default.VpnLock,
                badge = if (isProxyActive) "ON" else "OFF",
                badgeColor = if (isProxyActive) MatrixGreen else SlateGrey,
                isSelected = currentKey is OpsecSettingsNav,
                onClick = { onNavigate(OpsecSettingsNav); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Investigation History",
                icon = Icons.Default.History,
                isSelected = currentKey is ScanHistoryNav,
                onClick = { onNavigate(ScanHistoryNav); onCloseDrawer() }
            )
            DrawerNavItem(
                label = "Legal Ethics & Policy",
                icon = Icons.Default.Policy,
                isSelected = currentKey is ComplianceDisclaimerNav,
                onClick = { onNavigate(ComplianceDisclaimerNav); onCloseDrawer() }
            )

            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "ON-DEVICE SQLITE • ZERO-CLOUD ARCHITECTURE",
                color = MutedSlate,
                fontSize = 10.sp,
                fontFamily = MonoFontFamily,
                modifier = Modifier.padding(horizontal = 18.dp)
            )
        }
    }
}

@Composable
private fun DrawerCategoryHeader(title: String) {
    Text(
        text = title,
        color = MutedSlate,
        fontSize = 10.sp,
        fontFamily = MonoFontFamily,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = 1.sp,
        modifier = Modifier.padding(horizontal = 18.dp, vertical = 6.dp)
    )
}

@Composable
private fun DrawerNavItem(
    label: String,
    icon: ImageVector,
    badge: String? = null,
    badgeColor: Color = SkyCyan,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 10.dp, vertical = 2.dp)
            .heightIn(min = 48.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(if (isSelected) CharcoalNavy else Color.Transparent)
            .border(
                width = if (isSelected) 1.dp else 0.dp,
                color = if (isSelected) SkyCyan.copy(alpha = 0.45f) else Color.Transparent,
                shape = RoundedCornerShape(10.dp)
            )
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.weight(1f)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = if (isSelected) SkyCyan else MutedSlate,
                modifier = Modifier.size(19.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                color = if (isSelected) OffWhite else SlateGrey,
                fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal
            )
        }

        if (badge != null) {
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(4.dp))
                    .background(badgeColor.copy(alpha = 0.14f))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            ) {
                Text(
                    text = badge,
                    color = badgeColor,
                    fontSize = 9.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
