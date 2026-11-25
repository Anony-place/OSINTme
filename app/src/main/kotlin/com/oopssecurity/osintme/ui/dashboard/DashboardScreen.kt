package com.oopssecurity.osintme.ui.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
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
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.AiAnalystNav
import com.oopssecurity.osintme.ApiVaultNav
import com.oopssecurity.osintme.BreachAuditorNav
import com.oopssecurity.osintme.CaseManagementNav
import com.oopssecurity.osintme.ComplianceDisclaimerNav
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
import com.oopssecurity.osintme.data.local.ApiProvider
import com.oopssecurity.osintme.ui.components.ExposureScoreCard
import com.oopssecurity.osintme.ui.components.SmartSearchBar
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.EmeraldBorder
import com.oopssecurity.osintme.ui.theme.EmeraldDeep
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.EmeraldSoft
import com.oopssecurity.osintme.ui.theme.InkBlack
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.InputType

@Composable
fun DashboardScreen(
    onNavigate: (Any) -> Unit,
    onMenuClick: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: DashboardViewModel = viewModel { DashboardViewModel(context) }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) {
        viewModel.refresh()
    }

    if (uiState.isFirstLaunch) {
        ComplianceDisclaimerDialog(onAccept = { viewModel.acceptDisclaimer() })
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            WorkbenchTopBar(
                isProxyActive = uiState.isProxyActive,
                activeAiProviderName = uiState.activeAiProviderName,
                activeTotalKeys = uiState.activeApiKeysCount + uiState.activeAiKeysCount,
                onMenuClick = onMenuClick,
                onAiClick = {
                    if (uiState.activeAiKeysCount > 0) onNavigate(AiAnalystNav())
                    else onNavigate(ApiVaultNav)
                },
                onVaultClick = { onNavigate(ApiVaultNav) },
                onOpsecClick = { onNavigate(OpsecSettingsNav) },
                onHistoryClick = { onNavigate(ScanHistoryNav) },
                onPolicyClick = { onNavigate(ComplianceDisclaimerNav) }
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item { Spacer(modifier = Modifier.height(2.dp)) }

            // 1. Hero: One-Shot Full Target Dossier Bar
            item {
                SmartSearchBar(
                    query = uiState.query,
                    onQueryChange = { viewModel.onQueryChange(it) },
                    onScanClick = { query, _ ->
                        onNavigate(TargetDossierNav(query))
                    }
                )
            }

            // 1b. BYOK AI OSINT Analyst Hero Card (Ink Black + Signal Emerald editorial contrast)
            item {
                val aiReady = uiState.activeAiKeysCount > 0
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(if (aiReady) InkBlack else EmeraldSoft)
                        .border(
                            1.dp,
                            if (aiReady) InkBlack else EmeraldBorder,
                            RoundedCornerShape(14.dp)
                        )
                        .clickable { onNavigate(AiAnalystNav()) }
                        .testTag("dashboard_ai_analyst_card")
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.weight(1f)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(42.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .background(if (aiReady) EmeraldPrimary else InkBlack),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.AutoAwesome,
                                contentDescription = null,
                                tint = PureWhite,
                                modifier = Modifier.size(21.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "BYOK AI OSINT Analyst",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = if (aiReady) PureWhite else InkBlack,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(if (aiReady) EmeraldPrimary.copy(alpha = 0.25f) else PureWhite)
                                        .border(
                                            1.dp,
                                            if (aiReady) EmeraldPrimary else EmeraldBorder,
                                            RoundedCornerShape(4.dp)
                                        )
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        text = uiState.activeAiProviderName?.uppercase() ?: "10 PROVIDERS",
                                        color = if (aiReady) EmeraldBorder else EmeraldDeep,
                                        fontSize = 9.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = if (aiReady) {
                                    "Chat with saved dossiers, triage phishing, craft custom dorks"
                                } else {
                                    "Connect your own OpenRouter, Claude, OpenAI, Gemini, Groq or DeepSeek key"
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = if (aiReady) PureWhite.copy(alpha = 0.78f) else SlateGrey
                            )
                        }
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                        contentDescription = "Open BYOK AI Analyst",
                        tint = if (aiReady) EmeraldPrimary else InkBlack,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            // 2. High-Impact Passive Recon Labs (4 New Core Utilities)
            item {
                SectionLabel("HIGH-IMPACT RECON LABS")
                Spacer(modifier = Modifier.height(10.dp))
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        ModuleCard(
                            title = "Wayback Explorer",
                            subtitle = "Deleted pages, leaked configs & historical subdomain snapshots",
                            badge = "CDX LIVE",
                            icon = Icons.Default.Timeline,
                            accent = EmeraldPrimary,
                            modifier = Modifier.weight(1f).testTag("module_wayback"),
                            onClick = { onNavigate(WaybackNav(uiState.query)) }
                        )
                        ModuleCard(
                            title = "TLS & Takeover",
                            subtitle = "Live X.509 cert SANs & 14-cloud dangling CNAME scanner",
                            badge = "X.509/DNS",
                            icon = Icons.Default.Lock,
                            accent = InkBlack,
                            modifier = Modifier.weight(1f).testTag("module_tls_takeover"),
                            onClick = { onNavigate(TlsTakeoverNav(uiState.query)) }
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        ModuleCard(
                            title = "Redirect & Headers",
                            subtitle = "Safe shortlink hop unmasker + A+–F HSTS, CSP & cookie audit",
                            badge = "AUDIT A+",
                            icon = Icons.Default.Http,
                            accent = EmeraldDeep,
                            modifier = Modifier.weight(1f).testTag("module_redirect_audit"),
                            onClick = { onNavigate(RedirectAuditNav(uiState.query)) }
                        )
                        ModuleCard(
                            title = "Precision Dorks",
                            subtitle = "Google, Shodan, Censys, GitHub + BYOK AI custom dork crafter",
                            badge = "7 ENGINES",
                            icon = Icons.Default.Search,
                            accent = InkBlack,
                            modifier = Modifier.weight(1f).testTag("module_precision_dorks"),
                            onClick = { onNavigate(DorkGeneratorNav(uiState.query)) }
                        )
                    }
                }
            }

            // 2b. Case Dossiers Quick Access Banner (Local SQLite)
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 64.dp)
                        .clip(RoundedCornerShape(14.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                        .clickable { onNavigate(CaseManagementNav) }
                        .testTag("dashboard_cases_card")
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.weight(1f)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .background(EmeraldSoft)
                                .border(1.dp, EmeraldBorder, RoundedCornerShape(10.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.FolderSpecial,
                                contentDescription = null,
                                tint = EmeraldPrimary,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "Investigation Cases & Entity Graph",
                                style = MaterialTheme.typography.titleSmall,
                                color = OffWhite
                            )
                            Text(
                                text = "${uiState.activeCasesCount} active dossier(s) • AI Brief + HTML/JSON/CSV export",
                                style = MaterialTheme.typography.bodySmall,
                                color = SlateGrey
                            )
                        }
                    }
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                        contentDescription = "Open cases",
                        tint = InkBlack,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            // 2c. Pro Investigator Workbenches
            item {
                SectionLabel("PRO FORENSIC WORKBENCHES")
                Spacer(modifier = Modifier.height(10.dp))
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        ModuleCard(
                            title = "Bulk IOC Triage",
                            subtitle = "Extract & defang IPs, domains, hashes & run live batch triage",
                            badge = "BATCH",
                            icon = Icons.Default.FilterAlt,
                            accent = MatrixGreen,
                            modifier = Modifier.weight(1f).testTag("module_ioc_workbench"),
                            onClick = { onNavigate(IocWorkbenchNav("")) }
                        )
                        ModuleCard(
                            title = "Email Headers",
                            subtitle = "Trace mail relay hops, SPF/DKIM/DMARC & AI phishing verdict",
                            badge = "AI+HOPS",
                            icon = Icons.Default.MarkEmailRead,
                            accent = SkyCyan,
                            modifier = Modifier.weight(1f).testTag("module_email_header"),
                            onClick = { onNavigate(EmailHeaderNav) }
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        ModuleCard(
                            title = "Hash & Payload",
                            subtitle = "MalwareBazaar/VT hashes, Base64/Hex/Epoch & JWT audit",
                            badge = "JWT/HASH",
                            icon = Icons.Default.Code,
                            accent = SoftIndigo,
                            modifier = Modifier.weight(1f).testTag("module_hash_payload"),
                            onClick = { onNavigate(HashPayloadNav(uiState.query)) }
                        )
                        ModuleCard(
                            title = "BYOK AI & API Vault",
                            subtitle = "Hardware-encrypted keys for 10 AI providers & 5 threat feeds",
                            badge = "${uiState.activeAiKeysCount + uiState.activeApiKeysCount}/${AiProvider.entries.size + ApiProvider.entries.size} KEYS",
                            icon = Icons.Default.Key,
                            accent = if (uiState.activeAiKeysCount + uiState.activeApiKeysCount > 0) MatrixGreen else StatusWarning,
                            modifier = Modifier.weight(1f).testTag("module_api_vault"),
                            onClick = { onNavigate(ApiVaultNav) }
                        )
                    }
                }
            }

            // 3. Intelligence Modules Grid
            item {
                SectionLabel("SPECIALIST RECON MODULES")
                Spacer(modifier = Modifier.height(10.dp))
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        ModuleCard(
                            title = "Network, Web & BGP",
                            subtitle = "Shodan, Web stack/robots, RIPEstat BGP, TLS, CT & RDAP",
                            badge = "7 FEEDS",
                            icon = Icons.Default.Router,
                            accent = SkyCyan,
                            modifier = Modifier.weight(1f).testTag("module_network"),
                            onClick = { onNavigate(DomainReconNav(uiState.query)) }
                        )
                        ModuleCard(
                            title = "Breach & Leaks",
                            subtitle = "XposedOrNot breaches, Gravatar, SPF/DMARC & HIBP",
                            badge = "K-ANON",
                            icon = Icons.Default.AlternateEmail,
                            accent = StatusRisk,
                            modifier = Modifier.weight(1f).testTag("module_breach"),
                            onClick = { onNavigate(BreachAuditorNav(uiState.query)) }
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        ModuleCard(
                            title = "Username Hunter",
                            subtitle = "Maigret-class probes across 106+ live sites with bio extraction",
                            badge = "106+ SITES",
                            icon = Icons.Default.PersonSearch,
                            accent = MatrixGreen,
                            modifier = Modifier.weight(1f).testTag("module_username"),
                            onClick = { onNavigate(UsernameReconNav(uiState.query)) }
                        )
                        ModuleCard(
                            title = "Threat Intel",
                            subtitle = "Cloudflare 1.1.1.2 malware DNS, URLhaus & Google Dorks",
                            badge = "LIVE DNS",
                            icon = Icons.Default.BugReport,
                            accent = StatusWarning,
                            modifier = Modifier.weight(1f).testTag("module_threat"),
                            onClick = { onNavigate(ThreatIntelNav(uiState.query)) }
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        ModuleCard(
                            title = "EXIF Forensics",
                            subtitle = "SHA-256 hash, GPS/lens tags, reverse search & clean strip",
                            badge = "LOCAL",
                            icon = Icons.Default.Image,
                            accent = SoftIndigo,
                            modifier = Modifier.weight(1f).testTag("module_exif"),
                            onClick = { onNavigate(ExifInspectorNav(null)) }
                        )
                        ModuleCard(
                            title = "Phone E.164",
                            subtitle = "115+ ITU-T country plans, validation & messaging pivots",
                            badge = "E.164",
                            icon = Icons.Default.Phone,
                            accent = SkyCyan,
                            modifier = Modifier.weight(1f).testTag("module_phone"),
                            onClick = { onNavigate(PhoneReconNav(uiState.query)) }
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        ModuleCard(
                            title = "Link & Redirects",
                            subtitle = "Trace live 301/302 hop chains & strip 60+ tracking tokens",
                            badge = "HOP TRACE",
                            icon = Icons.Default.CleaningServices,
                            accent = MatrixGreen,
                            modifier = Modifier.weight(1f).testTag("module_sanitizer"),
                            onClick = { onNavigate(LinkSanitizerNav(uiState.query)) }
                        )
                        ModuleCard(
                            title = "OPSEC Router",
                            subtitle = "Tor SOCKS5/HTTP proxy, anti-tracking & live Exit IP check",
                            badge = if (uiState.isProxyActive) "PROXY ON" else "DIRECT",
                            icon = Icons.Default.VpnLock,
                            accent = if (uiState.isProxyActive) MatrixGreen else SoftIndigo,
                            modifier = Modifier.weight(1f).testTag("module_opsec"),
                            onClick = { onNavigate(OpsecSettingsNav) }
                        )
                    }
                }
            }

            // 4. Security Posture Card
            item {
                ExposureScoreCard(
                    scoreState = uiState.exposureScoreState,
                    onViewChecklistClick = { onNavigate(HygieneChecklistNav) }
                )
            }

            // 5. Recent Local Investigations
            if (uiState.recentScans.isNotEmpty()) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        SectionLabel("RECENT INVESTIGATIONS")
                        Text(
                            text = "View all",
                            color = SkyCyan,
                            style = MaterialTheme.typography.labelLarge,
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .clickable { onNavigate(ScanHistoryNav) }
                                .padding(horizontal = 6.dp, vertical = 4.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        uiState.recentScans.take(3).forEach { scan ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(CharcoalNavy)
                                    .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                                    .clickable {
                                        when (scan.type) {
                                            "Target Dossier" ->
                                                onNavigate(TargetDossierNav(scan.target))
                                            "Email Breach", "Password Audit", "Password Check" ->
                                                onNavigate(BreachAuditorNav(if (scan.target.contains("@")) scan.target else ""))
                                            "Username Recon" ->
                                                onNavigate(UsernameReconNav(scan.target.removePrefix("@")))
                                            "Domain Recon", "IP Recon" ->
                                                onNavigate(DomainReconNav(scan.target))
                                            "Phone Recon" ->
                                                onNavigate(PhoneReconNav(scan.target))
                                            "Link Sanitizer", "Redirect Trace" ->
                                                onNavigate(LinkSanitizerNav(scan.target))
                                            "Threat Intel", "Malware URLhaus" ->
                                                onNavigate(ThreatIntelNav(scan.target))
                                            "EXIF Inspection", "EXIF Sanitizer" ->
                                                onNavigate(ExifInspectorNav(null))
                                            else -> onNavigate(DorkGeneratorNav(scan.target))
                                        }
                                    }
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Box(
                                            modifier = Modifier
                                                .clip(RoundedCornerShape(4.dp))
                                                .background(SurfaceElevated)
                                                .padding(horizontal = 6.dp, vertical = 2.dp)
                                        ) {
                                            Text(
                                                text = scan.type.uppercase(),
                                                color = SkyCyan,
                                                fontSize = 9.sp,
                                                fontFamily = MonoFontFamily,
                                                fontWeight = FontWeight.Bold
                                            )
                                        }
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text(
                                            text = scan.target,
                                            color = OffWhite,
                                            fontSize = 13.sp,
                                            fontFamily = MonoFontFamily,
                                            fontWeight = FontWeight.Medium,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = scan.summary,
                                        color = SlateGrey,
                                        style = MaterialTheme.typography.bodySmall,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                                    contentDescription = null,
                                    tint = MutedSlate,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        }
                    }
                }
            }

            item { Spacer(modifier = Modifier.height(16.dp)) }
        }
    }
}

@Composable
private fun WorkbenchTopBar(
    isProxyActive: Boolean,
    activeAiProviderName: String?,
    activeTotalKeys: Int,
    onMenuClick: () -> Unit,
    onAiClick: () -> Unit,
    onVaultClick: () -> Unit,
    onOpsecClick: () -> Unit,
    onHistoryClick: () -> Unit,
    onPolicyClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(PureWhite)
            .statusBarsPadding()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(
                    onClick = onMenuClick,
                    modifier = Modifier
                        .size(48.dp)
                        .testTag("dashboard_menu_button")
                ) {
                    Icon(
                        imageVector = Icons.Default.Menu,
                        contentDescription = "Open navigation menu",
                        tint = InkBlack
                    )
                }
                Spacer(modifier = Modifier.width(2.dp))
                Column {
                    Text(
                        text = "OSINTme",
                        color = InkBlack,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = DisplayFontFamily
                    )
                    Text(
                        text = "Passive OSINT & BYOK AI",
                        color = SlateGrey,
                        fontSize = 11.sp
                    )
                }
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(5.dp)
            ) {
                Row(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (activeAiProviderName != null) EmeraldSoft else SurfaceElevated)
                        .border(
                            1.dp,
                            if (activeAiProviderName != null) EmeraldBorder else CardBorder,
                            RoundedCornerShape(8.dp)
                        )
                        .clickable { onAiClick() }
                        .testTag("dashboard_ai_status_pill")
                        .padding(horizontal = 8.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.AutoAwesome,
                        contentDescription = "BYOK AI status",
                        tint = if (activeAiProviderName != null) EmeraldPrimary else InkBlack,
                        modifier = Modifier.size(12.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = if (activeAiProviderName != null) "AI ON" else "SET AI",
                        color = if (activeAiProviderName != null) EmeraldDeep else InkBlack,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }

                Row(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(CharcoalNavy)
                        .border(
                            1.dp,
                            if (activeTotalKeys > 0) EmeraldBorder else CardBorder,
                            RoundedCornerShape(8.dp)
                        )
                        .clickable { onVaultClick() }
                        .testTag("dashboard_api_vault_pill")
                        .padding(horizontal = 7.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.Key,
                        contentDescription = "API Vault",
                        tint = if (activeTotalKeys > 0) EmeraldPrimary else InkBlack,
                        modifier = Modifier.size(12.dp)
                    )
                    Spacer(modifier = Modifier.width(3.dp))
                    Text(
                        text = "$activeTotalKeys",
                        color = if (activeTotalKeys > 0) EmeraldDeep else SlateGrey,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }

                Row(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(CharcoalNavy)
                        .border(
                            1.dp,
                            if (isProxyActive) EmeraldBorder else CardBorder,
                            RoundedCornerShape(8.dp)
                        )
                        .clickable { onOpsecClick() }
                        .padding(horizontal = 7.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .clip(CircleShape)
                            .background(if (isProxyActive) EmeraldPrimary else InkBlack)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = if (isProxyActive) "TOR" else "TLS",
                        color = if (isProxyActive) EmeraldDeep else SlateGrey,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }

                IconButton(
                    onClick = onHistoryClick,
                    modifier = Modifier.size(40.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.History,
                        contentDescription = "Investigation history",
                        tint = SlateGrey,
                        modifier = Modifier.size(19.dp)
                    )
                }

                IconButton(
                    onClick = onPolicyClick,
                    modifier = Modifier.size(40.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Policy,
                        contentDescription = "Legal policy",
                        tint = SlateGrey,
                        modifier = Modifier.size(19.dp)
                    )
                }
            }
        }
        HorizontalDivider(color = CardBorder, thickness = 1.dp)
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text = text,
        fontSize = 11.sp,
        color = MutedSlate,
        fontWeight = FontWeight.SemiBold,
        fontFamily = MonoFontFamily,
        letterSpacing = 1.sp
    )
}

@Composable
private fun ModuleCard(
    title: String,
    subtitle: String,
    badge: String,
    icon: ImageVector,
    accent: Color,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Column(
        modifier = modifier
            .heightIn(min = 132.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .clickable { onClick() }
            .padding(14.dp),
        verticalArrangement = Arrangement.SpaceBetween
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(RoundedCornerShape(9.dp))
                    .background(accent.copy(alpha = 0.14f))
                    .border(1.dp, accent.copy(alpha = 0.3f), RoundedCornerShape(9.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(18.dp)
                )
            }

            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(5.dp))
                    .background(DarkerSurface)
                    .border(1.dp, CardBorder, RoundedCornerShape(5.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            ) {
                Text(
                    text = badge,
                    color = accent,
                    fontSize = 9.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        Column {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = OffWhite,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = SlateGrey,
                lineHeight = 16.sp,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
fun ComplianceDisclaimerDialog(onAccept: () -> Unit) {
    AlertDialog(
        onDismissRequest = { /* Require explicit acknowledgment */ },
        containerColor = CharcoalNavy,
        shape = RoundedCornerShape(14.dp),
        icon = {
            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null,
                tint = SkyCyan,
                modifier = Modifier.size(30.dp)
            )
        },
        title = {
            Text(
                text = "Ethical OSINT & Defensive Use",
                style = MaterialTheme.typography.titleMedium,
                color = OffWhite
            )
        },
        text = {
            Column {
                Text(
                    text = "OSINTme queries publicly accessible intelligence sources (DNS, TLS certificates, RDAP, breach indexes, and public profiles) strictly for authorized security auditing, threat research, and personal exposure defense.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = SlateGrey
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "• Zero cloud accounts or central telemetry.\n• Passwords are checked via k-Anonymity (5-char SHA-1 prefix only).\n• Case dossiers and photos stay strictly on your device.",
                    color = MutedSlate,
                    fontSize = 11.sp,
                    lineHeight = 17.sp,
                    fontFamily = MonoFontFamily
                )
            }
        },
        confirmButton = {
            Button(
                onClick = onAccept,
                colors = ButtonDefaults.buttonColors(
                    containerColor = EmeraldPrimary,
                    contentColor = PureWhite
                ),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text("Acknowledge & Continue", fontWeight = FontWeight.SemiBold)
            }
        }
    )
}
