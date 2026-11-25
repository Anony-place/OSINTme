package com.oopssecurity.osintme

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.AlternateEmail
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.FolderSpecial
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Router
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.ui.NavDisplay
import com.oopssecurity.osintme.ui.ai.AiAnalystScreen
import com.oopssecurity.osintme.ui.breach.BreachAuditorScreen
import com.oopssecurity.osintme.ui.cases.CaseDetailScreen
import com.oopssecurity.osintme.ui.cases.CaseManagementScreen
import com.oopssecurity.osintme.ui.compliance.ComplianceDisclaimerScreen
import com.oopssecurity.osintme.ui.components.EntityPivotSheet
import com.oopssecurity.osintme.ui.components.TacticalNavigationDrawerSheet
import com.oopssecurity.osintme.ui.dashboard.DashboardScreen
import com.oopssecurity.osintme.ui.domain.DomainReconScreen
import com.oopssecurity.osintme.ui.dorks.DorkGeneratorScreen
import com.oopssecurity.osintme.ui.dossier.TargetDossierScreen
import com.oopssecurity.osintme.ui.email.EmailHeaderScreen
import com.oopssecurity.osintme.ui.exif.ExifInspectorScreen
import com.oopssecurity.osintme.ui.hash.HashPayloadScreen
import com.oopssecurity.osintme.ui.history.ScanHistoryScreen
import com.oopssecurity.osintme.ui.hygiene.HygieneChecklistScreen
import com.oopssecurity.osintme.ui.ioc.IocWorkbenchScreen
import com.oopssecurity.osintme.ui.opsec.OpsecSettingsScreen
import com.oopssecurity.osintme.ui.phone.PhoneReconScreen
import com.oopssecurity.osintme.ui.redirect.RedirectAuditScreen
import com.oopssecurity.osintme.ui.sanitizer.LinkSanitizerScreen
import com.oopssecurity.osintme.ui.theme.BodyFontFamily
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.EmeraldSoft
import com.oopssecurity.osintme.ui.theme.InkBlack
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.ui.threat.ThreatIntelScreen
import com.oopssecurity.osintme.ui.tls.TlsTakeoverScreen
import com.oopssecurity.osintme.ui.username.UsernameReconScreen
import com.oopssecurity.osintme.ui.vault.ApiVaultScreen
import com.oopssecurity.osintme.ui.wayback.WaybackScreen
import com.oopssecurity.osintme.util.PivotAction
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotTargetModule
import kotlinx.coroutines.launch

@Composable
fun MainNavigation(initialKey: NavKey = DashboardNav) {
    val backStack = rememberNavBackStack(initialKey)
    val currentKey = backStack.lastOrNull() ?: DashboardNav
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()

    var activePivotEntity by remember { mutableStateOf<PivotEntity?>(null) }

    fun navigateToPivot(action: PivotAction) {
        val nextKey: NavKey = when (action.module) {
            PivotTargetModule.TARGET_DOSSIER -> TargetDossierNav(action.targetValue)
            PivotTargetModule.DOMAIN_RECON -> DomainReconNav(action.targetValue)
            PivotTargetModule.WAYBACK_ARCHIVE -> WaybackNav(action.targetValue)
            PivotTargetModule.TLS_TAKEOVER -> TlsTakeoverNav(action.targetValue)
            PivotTargetModule.REDIRECT_AUDIT -> RedirectAuditNav(action.targetValue)
            PivotTargetModule.THREAT_INTEL -> ThreatIntelNav(action.targetValue)
            PivotTargetModule.BREACH_AUDIT -> BreachAuditorNav(action.targetValue)
            PivotTargetModule.USERNAME_RECON -> UsernameReconNav(action.targetValue)
            PivotTargetModule.LINK_SANITIZER -> LinkSanitizerNav(action.targetValue)
            PivotTargetModule.DORK_GENERATOR -> DorkGeneratorNav(action.targetValue)
            PivotTargetModule.PHONE_RECON -> PhoneReconNav(action.targetValue)
            PivotTargetModule.HASH_PAYLOAD -> HashPayloadNav(action.targetValue)
            PivotTargetModule.AI_ANALYST -> AiAnalystNav(initialPrompt = action.targetValue)
        }
        if (backStack.lastOrNull() != nextKey) {
            backStack.add(nextKey)
        }
    }

    // Build investigation breadcrumb trail from target-bearing backstack entries
    val pivotTrail = backStack.mapIndexedNotNull { index, key ->
        extractTrailCrumb(index, key)
    }

    // Handle warm intents (e.g. Android Share sheet delivering an image or URL while app is open)
    LaunchedEffect(initialKey) {
        if (backStack.lastOrNull() != initialKey) {
            if (initialKey is DashboardNav) {
                while (backStack.size > 1) {
                    backStack.removeLastOrNull()
                }
            } else {
                backStack.add(initialKey)
            }
        }
    }

    activePivotEntity?.let { entity ->
        EntityPivotSheet(
            entity = entity,
            onPivot = { action -> navigateToPivot(action) },
            onDismiss = { activePivotEntity = null }
        )
    }

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
                    } else if (currentKey != key) {
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
            contentWindowInsets = WindowInsets(0, 0, 0, 0),
            bottomBar = {
                Column(modifier = Modifier.fillMaxWidth()) {
                    if (pivotTrail.size >= 2) {
                        PivotTrailBar(
                            crumbs = pivotTrail,
                            onSelectCrumb = { targetStackIndex ->
                                while (backStack.size - 1 > targetStackIndex) {
                                    backStack.removeLastOrNull()
                                }
                            }
                        )
                    }
                    WorkbenchBottomBar(
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
                        entry<TargetDossierNav> { key ->
                            TargetDossierScreen(
                                initialTarget = key.target,
                                onBackClick = { backStack.removeLastOrNull() },
                                onOpenApiVault = { backStack.add(ApiVaultNav) },
                                onOpenCase = { caseId -> backStack.add(CaseDetailNav(caseId)) },
                                onPivot = { activePivotEntity = it }
                            )
                        }
                        entry<ApiVaultNav> {
                            ApiVaultScreen(
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<AiAnalystNav> { key ->
                            AiAnalystScreen(
                                initialPrompt = key.initialPrompt,
                                initialCaseId = key.caseId,
                                onOpenVault = { backStack.add(ApiVaultNav) },
                                onBackClick = { backStack.removeLastOrNull() }
                            )
                        }
                        entry<WaybackNav> { key ->
                            WaybackScreen(
                                initialTarget = key.initialTarget,
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivotEntity = { raw, type, src ->
                                    activePivotEntity = PivotEngine.normalize(raw, type, src)
                                }
                            )
                        }
                        entry<TlsTakeoverNav> { key ->
                            TlsTakeoverScreen(
                                initialTarget = key.initialTarget,
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivotEntity = { raw, type, src ->
                                    activePivotEntity = PivotEngine.normalize(raw, type, src)
                                }
                            )
                        }
                        entry<RedirectAuditNav> { key ->
                            RedirectAuditScreen(
                                initialUrl = key.initialUrl,
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivotEntity = { raw, type, src ->
                                    activePivotEntity = PivotEngine.normalize(raw, type, src)
                                }
                            )
                        }
                        entry<IocWorkbenchNav> { key ->
                            IocWorkbenchScreen(
                                initialText = key.initialText,
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivot = { activePivotEntity = it }
                            )
                        }
                        entry<EmailHeaderNav> {
                            EmailHeaderScreen(
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivot = { activePivotEntity = it },
                                onOpenApiVault = { backStack.add(ApiVaultNav) }
                            )
                        }
                        entry<HashPayloadNav> { key ->
                            HashPayloadScreen(
                                initialInput = key.initialInput,
                                onBackClick = { backStack.removeLastOrNull() },
                                onOpenApiVault = { backStack.add(ApiVaultNav) }
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
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivot = { activePivotEntity = it },
                                onOpenApiVault = { backStack.add(ApiVaultNav) },
                                onOpenAiAnalyst = { cid -> backStack.add(AiAnalystNav(caseId = cid)) }
                            )
                        }
                        entry<ThreatIntelNav> { key ->
                            ThreatIntelScreen(
                                initialTarget = key.initialTarget,
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivot = { activePivotEntity = it }
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
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivot = { activePivotEntity = it }
                            )
                        }
                        entry<UsernameReconNav> { key ->
                            UsernameReconScreen(
                                initialUsername = key.initialUsername,
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivot = { activePivotEntity = it }
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
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivot = { activePivotEntity = it }
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
                                onBackClick = { backStack.removeLastOrNull() },
                                onOpenApiVault = { backStack.add(ApiVaultNav) }
                            )
                        }
                        entry<LinkSanitizerNav> { key ->
                            LinkSanitizerScreen(
                                initialUrl = key.initialUrl,
                                onBackClick = { backStack.removeLastOrNull() },
                                onPivot = { activePivotEntity = it }
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
                                        "Target Dossier" ->
                                            backStack.add(TargetDossierNav(scan.target))
                                        "Email Breach", "Password Audit", "Password Check" ->
                                            backStack.add(BreachAuditorNav(if (scan.target.contains("@")) scan.target else ""))
                                        "Username Recon" ->
                                            backStack.add(UsernameReconNav(scan.target.removePrefix("@")))
                                        "Domain Recon", "IP Recon" ->
                                            backStack.add(DomainReconNav(scan.target))
                                        "Phone Recon" ->
                                            backStack.add(PhoneReconNav(scan.target))
                                        "Link Sanitizer", "Redirect Trace" ->
                                            backStack.add(LinkSanitizerNav(scan.target))
                                        "Threat Intel", "Malware URLhaus" ->
                                            backStack.add(ThreatIntelNav(scan.target))
                                        "EXIF Inspection", "EXIF Sanitizer" ->
                                            backStack.add(ExifInspectorNav(null))
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

private data class TrailCrumb(
    val stackIndex: Int,
    val moduleTag: String,
    val targetLabel: String
)

private fun extractTrailCrumb(index: Int, key: NavKey): TrailCrumb? {
    return when (key) {
        is TargetDossierNav -> key.target.takeIf { it.isNotBlank() }?.let { TrailCrumb(index, "DOSSIER", it) }
        is DomainReconNav -> key.initialTarget.takeIf { it.isNotBlank() }?.let { TrailCrumb(index, "NET", it) }
        is WaybackNav -> key.initialTarget.takeIf { it.isNotBlank() }?.let { TrailCrumb(index, "WAYBACK", it) }
        is TlsTakeoverNav -> key.initialTarget.takeIf { it.isNotBlank() }?.let { TrailCrumb(index, "TLS", it) }
        is RedirectAuditNav -> key.initialUrl.takeIf { it.isNotBlank() }?.let {
            val short = it.removePrefix("https://").removePrefix("http://").take(20)
            TrailCrumb(index, "AUDIT", short)
        }
        is AiAnalystNav -> TrailCrumb(index, "AI", key.initialPrompt.take(16).ifBlank { "Analyst" })
        is BreachAuditorNav -> key.initialEmail.takeIf { it.isNotBlank() }?.let { TrailCrumb(index, "MAIL", it) }
        is UsernameReconNav -> key.initialUsername.takeIf { it.isNotBlank() }?.let { TrailCrumb(index, "USER", "@$it") }
        is ThreatIntelNav -> key.initialTarget.takeIf { it.isNotBlank() }?.let { TrailCrumb(index, "THREAT", it) }
        is HashPayloadNav -> key.initialInput.takeIf { it.isNotBlank() }?.let { TrailCrumb(index, "HASH", it.take(12)) }
        is LinkSanitizerNav -> key.initialUrl.takeIf { it.isNotBlank() }?.let {
            val short = it.removePrefix("https://").removePrefix("http://").take(22)
            TrailCrumb(index, "URL", short)
        }
        is DorkGeneratorNav -> key.initialTarget.takeIf { it.isNotBlank() }?.let { TrailCrumb(index, "DORK", it) }
        is PhoneReconNav -> key.initialNumber.takeIf { it.isNotBlank() }?.let { TrailCrumb(index, "TEL", it) }
        is CaseDetailNav -> TrailCrumb(index, "CASE", "Dossier")
        else -> null
    }
}

@Composable
private fun PivotTrailBar(
    crumbs: List<TrailCrumb>,
    onSelectCrumb: (Int) -> Unit
) {
    val scrollState = rememberScrollState()
    LaunchedEffect(crumbs.size) {
        scrollState.animateScrollTo(scrollState.maxValue)
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(DarkerSurface)
            .testTag("pivot_trail_bar")
    ) {
        HorizontalDivider(color = CardBorder, thickness = 1.dp)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(scrollState)
                .padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.CallSplit,
                contentDescription = "Pivot trail",
                tint = SkyCyan,
                modifier = Modifier.size(14.dp)
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = "PIVOT:",
                color = MutedSlate,
                fontSize = 10.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.width(8.dp))

            crumbs.forEachIndexed { idx, crumb ->
                val isCurrent = idx == crumbs.lastIndex
                Row(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(if (isCurrent) SkyCyan.copy(alpha = 0.16f) else SurfaceElevated)
                        .border(
                            1.dp,
                            if (isCurrent) SkyCyan.copy(alpha = 0.5f) else CardBorder,
                            RoundedCornerShape(6.dp)
                        )
                        .clickable(enabled = !isCurrent) { onSelectCrumb(crumb.stackIndex) }
                        .padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = crumb.moduleTag,
                        color = if (isCurrent) SkyCyan else MutedSlate,
                        fontSize = 9.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = crumb.targetLabel,
                        color = if (isCurrent) OffWhite else SlateGrey,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                if (!isCurrent) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                        contentDescription = null,
                        tint = MutedSlate,
                        modifier = Modifier
                            .padding(horizontal = 2.dp)
                            .size(14.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun WorkbenchBottomBar(
    currentKey: Any,
    onSelectTab: (NavKey) -> Unit
) {
    val items = listOf(
        BottomNavItem("Home", "nav_home", Icons.Default.Radar, DashboardNav),
        BottomNavItem("AI", "nav_ai_analyst", Icons.Default.AutoAwesome, AiAnalystNav()),
        BottomNavItem("Network", "nav_network", Icons.Default.Router, DomainReconNav("")),
        BottomNavItem("Breaches", "nav_breaches", Icons.Default.AlternateEmail, BreachAuditorNav("")),
        BottomNavItem("Cases", "nav_cases", Icons.Default.FolderSpecial, CaseManagementNav)
    )

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(PureWhite)
            .navigationBarsPadding()
    ) {
        HorizontalDivider(color = CardBorder, thickness = 1.dp)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically
        ) {
            items.forEach { item ->
                val isSelected = when (item.key) {
                    is DashboardNav -> currentKey is DashboardNav
                    is AiAnalystNav -> currentKey is AiAnalystNav
                    is DomainReconNav -> currentKey is DomainReconNav
                    is BreachAuditorNav -> currentKey is BreachAuditorNav
                    is CaseManagementNav -> currentKey is CaseManagementNav || currentKey is CaseDetailNav
                    else -> false
                }
                val isAiTab = item.key is AiAnalystNav

                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 52.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .clickable { onSelectTab(item.key) }
                        .testTag(item.tag)
                        .padding(vertical = 4.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(14.dp))
                            .background(
                                when {
                                    isSelected && isAiTab -> EmeraldSoft
                                    isSelected -> InkBlack.copy(alpha = 0.08f)
                                    else -> Color.Transparent
                                }
                            )
                            .padding(horizontal = 14.dp, vertical = 4.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = item.icon,
                            contentDescription = item.label,
                            tint = when {
                                isSelected && isAiTab -> EmeraldPrimary
                                isSelected -> InkBlack
                                isAiTab -> EmeraldPrimary.copy(alpha = 0.8f)
                                else -> MutedSlate
                            },
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = item.label,
                        color = when {
                            isSelected && isAiTab -> EmeraldPrimary
                            isSelected -> InkBlack
                            else -> MutedSlate
                        },
                        fontSize = 11.sp,
                        fontFamily = BodyFontFamily,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium
                    )
                }
            }
        }
    }
}

private data class BottomNavItem(
    val label: String,
    val tag: String,
    val icon: ImageVector,
    val key: NavKey
)
