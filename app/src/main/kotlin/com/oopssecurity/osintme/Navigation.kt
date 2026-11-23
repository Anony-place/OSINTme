package com.oopssecurity.osintme

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AlternateEmail
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Router
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.ui.NavDisplay
import com.oopssecurity.osintme.ui.breach.BreachAuditorScreen
import com.oopssecurity.osintme.ui.cases.CaseDetailScreen
import com.oopssecurity.osintme.ui.cases.CaseManagementScreen
import com.oopssecurity.osintme.ui.compliance.ComplianceDisclaimerScreen
import com.oopssecurity.osintme.ui.components.TacticalNavigationDrawerSheet
import com.oopssecurity.osintme.ui.dashboard.DashboardScreen
import com.oopssecurity.osintme.ui.domain.DomainReconScreen
import com.oopssecurity.osintme.ui.dorks.DorkGeneratorScreen
import com.oopssecurity.osintme.ui.exif.ExifInspectorScreen
import com.oopssecurity.osintme.ui.history.ScanHistoryScreen
import com.oopssecurity.osintme.ui.hygiene.HygieneChecklistScreen
import com.oopssecurity.osintme.ui.opsec.OpsecSettingsScreen
import com.oopssecurity.osintme.ui.phone.PhoneReconScreen
import com.oopssecurity.osintme.ui.sanitizer.LinkSanitizerScreen
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.ui.threat.ThreatIntelScreen
import com.oopssecurity.osintme.ui.username.UsernameReconScreen
import kotlinx.coroutines.launch

@Composable
fun MainNavigation(initialKey: NavKey = DashboardNav) {
    val backStack = rememberNavBackStack(initialKey)
    val currentKey = backStack.lastOrNull() ?: DashboardNav
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            TacticalNavigationDrawerSheet(
                currentKey = currentKey,
                onNavigate = { key ->
                    scope.launch { drawerState.close() }
                    if (key is DashboardNav) {
                        while (backStack.size > 1) {
                            backStack.removeLastOrNull()
                        }
                    } else {
                        backStack.add(key)
                    }
                },
                onCloseDrawer = {
                    scope.launch { drawerState.close() }
                }
            )
        }
    ) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = SlateObsidian,
            bottomBar = {
                TacticalBottomBar(
                    currentKey = currentKey,
                    onSelectTab = { targetKey ->
                        if (targetKey is DashboardNav) {
                            while (backStack.size > 1) {
                                backStack.removeLastOrNull()
                            }
                        } else if (currentKey != targetKey) {
                            backStack.add(targetKey)
                        }
                    }
                )
            }
        ) { padding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
            ) {
                NavDisplay(
                    backStack = backStack,
                    onBack = { backStack.removeLastOrNull() },
                    entryProvider = entryProvider {
                        entry<DashboardNav> {
                            DashboardScreen(
                                onNavigate = { key ->
                                    if (key is NavKey) backStack.add(key)
                                },
                                onMenuClick = {
                                    scope.launch {
                                        if (drawerState.isClosed) drawerState.open() else drawerState.close()
                                    }
                                }
                            )
                        }
                        entry<CaseManagementNav> {
                            CaseManagementScreen(
                                onSelectCase = { caseId -> backStack.add(CaseDetailNav(caseId)) },
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<CaseDetailNav> { key ->
                            CaseDetailScreen(
                                caseId = key.caseId,
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<ThreatIntelNav> { key ->
                            ThreatIntelScreen(
                                initialTarget = key.initialTarget,
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<OpsecSettingsNav> {
                            OpsecSettingsScreen(
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<BreachAuditorNav> { key ->
                            BreachAuditorScreen(
                                initialEmail = key.initialEmail,
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<UsernameReconNav> { key ->
                            UsernameReconScreen(
                                initialUsername = key.initialUsername,
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<PhoneReconNav> { key ->
                            PhoneReconScreen(
                                initialNumber = key.initialNumber,
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<DomainReconNav> { key ->
                            DomainReconScreen(
                                initialTarget = key.initialTarget,
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<ExifInspectorNav> { key ->
                            ExifInspectorScreen(
                                imageUriString = key.imageUriString,
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<DorkGeneratorNav> { key ->
                            DorkGeneratorScreen(
                                initialTarget = key.initialTarget,
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<LinkSanitizerNav> { key ->
                            LinkSanitizerScreen(
                                initialUrl = key.initialUrl,
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<HygieneChecklistNav> {
                            HygieneChecklistScreen(
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<ScanHistoryNav> {
                            ScanHistoryScreen(
                                onBackClick = { backStack.removeLastOrNull() },
                                onSelectItem = { scan ->
                                    when (scan.type) {
                                        "Email Breach" -> backStack.add(BreachAuditorNav(scan.target))
                                        "Username Recon" -> backStack.add(UsernameReconNav(scan.target))
                                        "Domain Recon", "IP Recon" -> backStack.add(DomainReconNav(scan.target))
                                        "Phone Recon" -> backStack.add(PhoneReconNav(scan.target))
                                        "Link Sanitizer" -> backStack.add(LinkSanitizerNav(scan.target))
                                        "Threat Intel", "Malware URLhaus" -> backStack.add(ThreatIntelNav(scan.target))
                                        else -> backStack.add(DorkGeneratorNav(scan.target))
                                    }
                                }
                            )
                        }
                        entry<ComplianceDisclaimerNav> {
                            ComplianceDisclaimerScreen(
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                    }
                )
            }
        }
    }
}

@Composable
private fun TacticalBottomBar(
    currentKey: Any,
    onSelectTab: (NavKey) -> Unit
) {
    val items = listOf(
        BottomNavItem("STATION", Icons.Default.Radar, DashboardNav),
        BottomNavItem("NETWORK", Icons.Default.Router, DomainReconNav("")),
        BottomNavItem("BREACHES", Icons.Default.AlternateEmail, BreachAuditorNav("")),
        BottomNavItem("SOCIAL", Icons.Default.PersonSearch, UsernameReconNav("")),
        BottomNavItem("FORENSICS", Icons.Default.Image, ExifInspectorNav(null))
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(SlateObsidian)
            .border(width = 1.dp, color = CardBorder)
            .padding(horizontal = 8.dp, vertical = 6.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceAround,
            verticalAlignment = Alignment.CenterVertically
        ) {
            items.forEach { item ->
                val isSelected = when (item.key) {
                    is DashboardNav -> currentKey is DashboardNav
                    is DomainReconNav -> currentKey is DomainReconNav
                    is BreachAuditorNav -> currentKey is BreachAuditorNav
                    is UsernameReconNav -> currentKey is UsernameReconNav
                    is ExifInspectorNav -> currentKey is ExifInspectorNav
                    else -> false
                }

                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .clickable { onSelectTab(item.key) }
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Icon(
                        imageVector = item.icon,
                        contentDescription = item.label,
                        tint = if (isSelected) SkyCyan else MutedSlate,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = item.label,
                        color = if (isSelected) SkyCyan else MutedSlate,
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                        letterSpacing = 0.5.sp
                    )
                    if (isSelected) {
                        Spacer(modifier = Modifier.height(2.dp))
                        Box(
                            modifier = Modifier
                                .width(12.dp)
                                .height(2.dp)
                                .background(SkyCyan)
                        )
                    }
                }
            }
        }
    }
}

private data class BottomNavItem(
    val label: String,
    val icon: ImageVector,
    val key: NavKey
)
