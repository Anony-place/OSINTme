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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AlternateEmail
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.FolderSpecial
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.DrawerState
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation3.runtime.NavKey
import com.oopssecurity.osintme.BreachAuditorNav
import com.oopssecurity.osintme.CaseManagementNav
import com.oopssecurity.osintme.ComplianceDisclaimerNav
import com.oopssecurity.osintme.DashboardNav
import com.oopssecurity.osintme.DomainReconNav
import com.oopssecurity.osintme.DorkGeneratorNav
import com.oopssecurity.osintme.ExifInspectorNav
import com.oopssecurity.osintme.HygieneChecklistNav
import com.oopssecurity.osintme.LinkSanitizerNav
import com.oopssecurity.osintme.OpsecSettingsNav
import com.oopssecurity.osintme.PhoneReconNav
import com.oopssecurity.osintme.ScanHistoryNav
import com.oopssecurity.osintme.ThreatIntelNav
import com.oopssecurity.osintme.UsernameReconNav
import com.oopssecurity.osintme.data.network.OpsecManager
import com.oopssecurity.osintme.data.network.ProxyMode
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.MatrixGreen
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
    val isTorActive = (OpsecManager.currentProxyMode != ProxyMode.DIRECT)

    ModalDrawerSheet(
        drawerContainerColor = SlateObsidian,
        drawerContentColor = OffWhite,
        modifier = Modifier
            .width(310.dp)
            .fillMaxHeight()
            .border(width = 1.dp, color = CardBorder)
    ) {
        Column(
            modifier = Modifier
                .fillMaxHeight()
                .padding(vertical = 12.dp)
                .verticalScroll(scrollState)
        ) {
            // Station Branding Header
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 8.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(32.dp)
                            .background(SkyCyan.copy(alpha = 0.15f), RoundedCornerShape(8.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = SkyCyan,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Column {
                        Text(
                            text = "OSINTme",
                            color = OffWhite,
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            letterSpacing = 1.sp
                        )
                        Text(
                            text = "BY OOPS SECURITY",
                            color = SlateGrey,
                            fontSize = 9.sp,
                            fontFamily = FontFamily.Monospace,
                            letterSpacing = 0.5.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Telemetry badge
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(6.dp))
                        .background(DarkerSurface)
                        .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "OPSEC ROUTE:",
                        color = MutedSlate,
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = if (isTorActive) "TOR / PROXY ACTIVE" else "DIRECT CLEARCHANNEL",
                        color = if (isTorActive) MatrixGreen else SkyCyan,
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(6.dp))
            HorizontalDivider(color = CardBorder, thickness = 1.dp)
            Spacer(modifier = Modifier.height(8.dp))

            // SECTION 1: WORKSPACE & CASES
            DrawerCategoryHeader("INVESTIGATIVE WORKSPACE")
            DrawerNavItem(
                label = "Tactical Station Dashboard",
                icon = Icons.Default.Radar,
                isSelected = currentKey is DashboardNav,
                onClick = {
                    onNavigate(DashboardNav)
                    onCloseDrawer()
                }
            )
            DrawerNavItem(
                label = "Case Dossiers & Evidence Graph",
                icon = Icons.Default.FolderSpecial,
                badge = "ROOM DB",
                badgeColor = MatrixGreen,
                isSelected = currentKey is CaseManagementNav,
                onClick = {
                    onNavigate(CaseManagementNav)
                    onCloseDrawer()
                }
            )

            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider(color = CardBorder, thickness = 1.dp)
            Spacer(modifier = Modifier.height(8.dp))

            // SECTION 2: OPERATIONAL WINGS
            DrawerCategoryHeader("WING 01 // NETWORK & INFRA")
            DrawerNavItem(
                label = "Host, Shodan & Subdomains",
                icon = Icons.Default.Router,
                badge = "REALTIME",
                isSelected = currentKey is DomainReconNav,
                onClick = {
                    onNavigate(DomainReconNav(""))
                    onCloseDrawer()
                }
            )

            DrawerCategoryHeader("WING 02 // IDENTITY & BREACHES")
            DrawerNavItem(
                label = "Breach & Gravatar Auditor",
                icon = Icons.Default.AlternateEmail,
                badge = "LIVE AUDIT",
                isSelected = currentKey is BreachAuditorNav,
                onClick = {
                    onNavigate(BreachAuditorNav(""))
                    onCloseDrawer()
                }
            )

            DrawerCategoryHeader("WING 03 // SOCIAL & TELEPHONY")
            DrawerNavItem(
                label = "Multi-Platform Username Hunter",
                icon = Icons.Default.PersonSearch,
                badge = "38+ APIS",
                isSelected = currentKey is UsernameReconNav,
                onClick = {
                    onNavigate(UsernameReconNav(""))
                    onCloseDrawer()
                }
            )
            DrawerNavItem(
                label = "Phone & Messaging Pivots",
                icon = Icons.Default.Phone,
                badge = "LIVE PIVOTS",
                isSelected = currentKey is PhoneReconNav,
                onClick = {
                    onNavigate(PhoneReconNav(""))
                    onCloseDrawer()
                }
            )

            DrawerCategoryHeader("WING 04 // MEDIA FORENSICS")
            DrawerNavItem(
                label = "EXIF & Reverse Image Pivots",
                icon = Icons.Default.Image,
                badge = "OFFLINE",
                isSelected = currentKey is ExifInspectorNav,
                onClick = {
                    onNavigate(ExifInspectorNav(null))
                    onCloseDrawer()
                }
            )

            DrawerCategoryHeader("WING 05 // THREAT INTEL & ABUSE")
            DrawerNavItem(
                label = "URLhaus Malware & Google Dorks",
                icon = Icons.Default.BugReport,
                badge = "ABUSE.CH",
                badgeColor = SoftIndigo,
                isSelected = currentKey is ThreatIntelNav,
                onClick = {
                    onNavigate(ThreatIntelNav(""))
                    onCloseDrawer()
                }
            )

            DrawerCategoryHeader("DEFENSIVE UTILITIES")
            DrawerNavItem(
                label = "Link & Tracker Sanitizer",
                icon = Icons.Default.CleaningServices,
                isSelected = currentKey is LinkSanitizerNav,
                onClick = {
                    onNavigate(LinkSanitizerNav(""))
                    onCloseDrawer()
                }
            )
            DrawerNavItem(
                label = "Security Hygiene Posture",
                icon = Icons.Default.Security,
                isSelected = currentKey is HygieneChecklistNav,
                onClick = {
                    onNavigate(HygieneChecklistNav)
                    onCloseDrawer()
                }
            )

            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider(color = CardBorder, thickness = 1.dp)
            Spacer(modifier = Modifier.height(8.dp))

            // SECTION 3: OPSEC & AUDIT
            DrawerCategoryHeader("OPSEC & STATION SETTINGS")
            DrawerNavItem(
                label = "OPSEC & Tor Proxy Router",
                icon = Icons.Default.VpnLock,
                badge = if (isTorActive) "ON" else "OFF",
                badgeColor = if (isTorActive) MatrixGreen else SlateGrey,
                isSelected = currentKey is OpsecSettingsNav,
                onClick = {
                    onNavigate(OpsecSettingsNav)
                    onCloseDrawer()
                }
            )
            DrawerNavItem(
                label = "Local Investigation Audit Trail",
                icon = Icons.Default.History,
                isSelected = currentKey is ScanHistoryNav,
                onClick = {
                    onNavigate(ScanHistoryNav)
                    onCloseDrawer()
                }
            )
            DrawerNavItem(
                label = "Legal Compliance & Ethics",
                icon = Icons.Default.Policy,
                isSelected = currentKey is ComplianceDisclaimerNav,
                onClick = {
                    onNavigate(ComplianceDisclaimerNav)
                    onCloseDrawer()
                }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Footer
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp)
            ) {
                Text(
                    text = "ZERO-CLOUD LOCAL STORAGE • AES-256",
                    color = MutedSlate,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    letterSpacing = 0.5.sp
                )
            }
        }
    }
}

@Composable
private fun DrawerCategoryHeader(title: String) {
    Text(
        text = title,
        color = SlateGrey,
        fontSize = 9.sp,
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        letterSpacing = 1.sp,
        modifier = Modifier.padding(horizontal = 18.dp, vertical = 6.dp)
    )
}

@Composable
private fun DrawerNavItem(
    label: String,
    icon: ImageVector,
    badge: String? = null,
    badgeColor: androidx.compose.ui.graphics.Color = SkyCyan,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 10.dp, vertical = 2.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(if (isSelected) CharcoalNavy else androidx.compose.ui.graphics.Color.Transparent)
            .border(
                width = if (isSelected) 1.dp else 0.dp,
                color = if (isSelected) SkyCyan.copy(alpha = 0.5f) else androidx.compose.ui.graphics.Color.Transparent,
                shape = RoundedCornerShape(8.dp)
            )
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 9.dp),
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
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = label,
                color = if (isSelected) OffWhite else SlateGrey,
                fontSize = 12.sp,
                fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal
            )
        }

        if (badge != null) {
            Box(
                modifier = Modifier
                    .background(badgeColor.copy(alpha = 0.15f), RoundedCornerShape(4.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            ) {
                Text(
                    text = badge,
                    color = badgeColor,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
