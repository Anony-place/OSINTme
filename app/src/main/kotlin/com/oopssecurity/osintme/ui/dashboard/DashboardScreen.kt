package com.oopssecurity.osintme.ui.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AlternateEmail
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PermIdentity
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TravelExplore
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.BreachAuditorNav
import com.oopssecurity.osintme.ComplianceDisclaimerNav
import com.oopssecurity.osintme.DomainReconNav
import com.oopssecurity.osintme.DorkGeneratorNav
import com.oopssecurity.osintme.ExifInspectorNav
import com.oopssecurity.osintme.HygieneChecklistNav
import com.oopssecurity.osintme.LinkSanitizerNav
import com.oopssecurity.osintme.PhoneReconNav
import com.oopssecurity.osintme.ScanHistoryNav
import com.oopssecurity.osintme.UsernameReconNav
import com.oopssecurity.osintme.ui.components.ExposureScoreCard
import com.oopssecurity.osintme.ui.components.PartnerOfferCard
import com.oopssecurity.osintme.ui.components.SmartSearchBar
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
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.InputType

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun DashboardScreen(
    onNavigate: (Any) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: DashboardViewModel = viewModel { DashboardViewModel(context) }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    if (uiState.isFirstLaunch) {
        ComplianceDisclaimerDialog(onAccept = { viewModel.acceptDisclaimer() })
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        topBar = {
            TacticalStationHeader(
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
            // 1. Live Telemetry Status Bar
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    StatusIndicator(label = "ENGINE: ACTIVE", color = MatrixGreen)
                    StatusIndicator(label = "STORAGE: ZERO-CLOUD", color = SkyCyan)
                    StatusIndicator(label = "APIS: LIVE", color = SoftIndigo)
                }
            }

            // 2. HERO: Universal Recon Command Bar
            item {
                SmartSearchBar(
                    query = uiState.query,
                    onQueryChange = { viewModel.onQueryChange(it) },
                    onScanClick = { query, type ->
                        when (type) {
                            InputType.EMAIL -> onNavigate(BreachAuditorNav(query))
                            InputType.IP_ADDRESS, InputType.DOMAIN -> onNavigate(DomainReconNav(query))
                            InputType.PHONE_NUMBER -> onNavigate(PhoneReconNav(query))
                            InputType.TRACKING_URL -> onNavigate(LinkSanitizerNav(query))
                            InputType.USERNAME -> onNavigate(UsernameReconNav(query))
                            InputType.GENERIC_KEYWORD -> onNavigate(DorkGeneratorNav(query))
                        }
                    }
                )
            }

            // 3. Threat Posture & Hygiene Score
            item {
                ExposureScoreCard(
                    scoreState = uiState.exposureScoreState,
                    onViewChecklistClick = { onNavigate(HygieneChecklistNav) }
                )
            }

            // 4. STRUCTURED SUITE 1: NETWORK & INFRASTRUCTURE RECON
            item {
                CategoryHeader("WING 01 // NETWORK & INFRASTRUCTURE INTELLIGENCE", SkyCyan)
                Spacer(modifier = Modifier.height(8.dp))
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        TacticalToolCard(
                            title = "Network & Host Recon",
                            subtitle = "Shodan open ports, CVEs & real GeoIP/ASN",
                            badge = "REALTIME",
                            icon = Icons.Default.Router,
                            accentColor = SkyCyan,
                            modifier = Modifier.weight(1f),
                            onClick = { onNavigate(DomainReconNav(uiState.query)) }
                        )
                        TacticalToolCard(
                            title = "Subdomain Discovery",
                            subtitle = "HackerTarget & crt.sh CT-Log intelligence",
                            badge = "DUAL-ENGINE",
                            icon = Icons.Default.TravelExplore,
                            accentColor = SoftIndigo,
                            modifier = Modifier.weight(1f),
                            onClick = { onNavigate(DomainReconNav(uiState.query)) }
                        )
                    }
                }
            }

            // 5. STRUCTURED SUITE 2: IDENTITY & BREACH TELEMETRY
            item {
                CategoryHeader("WING 02 // IDENTITY & COMPROMISE INTELLIGENCE", StatusRisk)
                Spacer(modifier = Modifier.height(8.dp))
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        TacticalToolCard(
                            title = "Public Breach Auditor",
                            subtitle = "XposedOrNot real breach & exposed data types",
                            badge = "LIVE AUDIT",
                            icon = Icons.Default.AlternateEmail,
                            accentColor = StatusRisk,
                            modifier = Modifier.weight(1f),
                            onClick = { onNavigate(BreachAuditorNav(uiState.query)) }
                        )
                        TacticalToolCard(
                            title = "Password Leak Auditor",
                            subtitle = "k-Anonymity SHA-1 zero-knowledge lookups",
                            badge = "HIBP API",
                            icon = Icons.Default.Lock,
                            accentColor = StatusWarning,
                            modifier = Modifier.weight(1f),
                            onClick = { onNavigate(BreachAuditorNav(uiState.query)) }
                        )
                    }
                }
            }

            // 6. STRUCTURED SUITE 3: SOCIAL & TELEPHONY INTELLIGENCE
            item {
                CategoryHeader("WING 03 // SOCIAL & TELEPHONY INTELLIGENCE", MatrixGreen)
                Spacer(modifier = Modifier.height(8.dp))
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    TacticalToolCard(
                        title = "Multi-Platform Username Hunter",
                        subtitle = "Probe 38+ platforms via direct APIs (GitHub, GitLab, Docker, Dev.to, Reddit) with zero false-positives",
                        badge = "38+ PLATFORMS",
                        icon = Icons.Default.PersonSearch,
                        accentColor = MatrixGreen,
                        modifier = Modifier.fillMaxWidth(),
                        onClick = { onNavigate(UsernameReconNav(uiState.query)) }
                    )
                    TacticalToolCard(
                        title = "Phone & Messaging Pivot Recon",
                        subtitle = "Carrier heuristics, VoIP/Cellular identification & direct WhatsApp/Telegram verification probes",
                        badge = "LIVE PIVOTS",
                        icon = Icons.Default.Phone,
                        accentColor = SkyCyan,
                        modifier = Modifier.fillMaxWidth(),
                        onClick = { onNavigate(PhoneReconNav(uiState.query)) }
                    )
                }
            }

            // 7. STRUCTURED SUITE 4: DIGITAL FORENSICS & PRIVACY TOOLS
            item {
                CategoryHeader("WING 04 // DIGITAL FORENSICS & PRIVACY TOOLS", SoftIndigo)
                Spacer(modifier = Modifier.height(8.dp))
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        TacticalToolCard(
                            title = "EXIF Forensics & Stripper",
                            subtitle = "Camera, GPS coordinates & 1-tap clean share",
                            badge = "100% OFFLINE",
                            icon = Icons.Default.Image,
                            accentColor = SoftIndigo,
                            modifier = Modifier.weight(1f),
                            onClick = { onNavigate(ExifInspectorNav(null)) }
                        )
                        TacticalToolCard(
                            title = "Google Dorks Generator",
                            subtitle = "Weaponized presets for docs, logins & buckets",
                            badge = "8 PRESETS",
                            icon = Icons.Default.Search,
                            accentColor = SkyCyan,
                            modifier = Modifier.weight(1f),
                            onClick = { onNavigate(DorkGeneratorNav(uiState.query)) }
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        TacticalToolCard(
                            title = "Link & Tracker Sanitizer",
                            subtitle = "Strip 60+ UTM, telemetry & affiliate parameters",
                            badge = "TRACKER KILLER",
                            icon = Icons.Default.CleaningServices,
                            accentColor = MatrixGreen,
                            modifier = Modifier.weight(1f),
                            onClick = { onNavigate(LinkSanitizerNav(uiState.query)) }
                        )
                        TacticalToolCard(
                            title = "Security Hygiene Audit",
                            subtitle = "7-point defense checklist & exposure rating",
                            badge = "DEFENSE",
                            icon = Icons.Default.Security,
                            accentColor = StatusSafe,
                            modifier = Modifier.weight(1f),
                            onClick = { onNavigate(HygieneChecklistNav) }
                        )
                    }
                }
            }

            // 8. Recent Target Dossiers (On-Device Local History)
            if (uiState.recentScans.isNotEmpty()) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CategoryHeader("RECENT LOCAL TARGET DOSSIERS", SlateGrey)
                        Text(
                            text = "VIEW ALL",
                            color = SkyCyan,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.clickable { onNavigate(ScanHistoryNav) }
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        uiState.recentScans.take(3).forEach { scan ->
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                                    .clickable {
                                        when (scan.type) {
                                            "Email Breach" -> onNavigate(BreachAuditorNav(scan.target))
                                            "Username Recon" -> onNavigate(UsernameReconNav(scan.target))
                                            "Domain Recon", "IP Recon" -> onNavigate(DomainReconNav(scan.target))
                                            "Phone Recon" -> onNavigate(PhoneReconNav(scan.target))
                                            "Link Sanitizer" -> onNavigate(LinkSanitizerNav(scan.target))
                                            else -> onNavigate(DorkGeneratorNav(scan.target))
                                        }
                                    },
                                colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp),
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
                                                Text(scan.type, color = SkyCyan, fontSize = 9.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                                            }
                                            Spacer(modifier = Modifier.width(8.dp))
                                            Text(scan.target, color = OffWhite, fontSize = 12.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium)
                                        }
                                        Spacer(modifier = Modifier.height(2.dp))
                                        Text(scan.summary, color = SlateGrey, fontSize = 11.sp)
                                    }
                                    Icon(Icons.Default.ArrowForward, contentDescription = null, tint = MutedSlate, modifier = Modifier.size(16.dp))
                                }
                            }
                        }
                    }
                }
            }

            // 9. Contextual Partner Defense Cards
            if (uiState.partnerOffers.isNotEmpty()) {
                item {
                    CategoryHeader("SECURITY PARTNER DEFENSES", SoftIndigo)
                    Spacer(modifier = Modifier.height(8.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        uiState.partnerOffers.forEach { offer ->
                            PartnerOfferCard(offer = offer)
                        }
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

@Composable
private fun TacticalStationHeader(
    onHistoryClick: () -> Unit,
    onPolicyClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(SlateObsidian)
            .border(width = 1.dp, color = CardBorder)
            .padding(horizontal = 16.dp, vertical = 14.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        tint = SkyCyan,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "OSINTme",
                        color = OffWhite,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 1.sp
                    )
                }
                Text(
                    text = "BY OOPS SECURITY // TACTICAL RECON STATION",
                    color = MutedSlate,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                        .clickable { onHistoryClick() }
                        .padding(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.History,
                        contentDescription = "Scan History",
                        tint = SkyCyan,
                        modifier = Modifier.size(18.dp)
                    )
                }

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                        .clickable { onPolicyClick() }
                        .padding(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Policy,
                        contentDescription = "Policy",
                        tint = SlateGrey,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun StatusIndicator(label: String, color: androidx.compose.ui.graphics.Color) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .clip(RoundedCornerShape(3.dp))
                .background(color)
        )
        Spacer(modifier = Modifier.width(5.dp))
        Text(
            text = label,
            color = color,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun CategoryHeader(text: String, accent: androidx.compose.ui.graphics.Color) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .width(3.dp)
                .height(12.dp)
                .background(accent)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = text,
            fontSize = 11.sp,
            color = SlateGrey,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace,
            letterSpacing = 1.sp
        )
    }
}

@Composable
private fun TacticalToolCard(
    title: String,
    subtitle: String,
    badge: String,
    icon: ImageVector,
    accentColor: androidx.compose.ui.graphics.Color,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Card(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
            .clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(accentColor.copy(alpha = 0.12f))
                        .border(1.dp, accentColor.copy(alpha = 0.3f), RoundedCornerShape(8.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = accentColor,
                        modifier = Modifier.size(18.dp)
                    )
                }

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(DarkerSurface)
                        .border(1.dp, CardBorder, RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = badge,
                        color = accentColor,
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = title,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = OffWhite
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = subtitle,
                fontSize = 11.sp,
                color = SlateGrey,
                lineHeight = 15.sp
            )
        }
    }
}

@Composable
fun ComplianceDisclaimerDialog(onAccept: () -> Unit) {
    AlertDialog(
        onDismissRequest = { /* Require explicit accept */ },
        containerColor = CharcoalNavy,
        shape = RoundedCornerShape(12.dp),
        icon = {
            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null,
                tint = SkyCyan,
                modifier = Modifier.size(32.dp)
            )
        },
        title = {
            Text(
                text = "ETHICAL OSINT & COMPLIANCE",
                color = OffWhite,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
        },
        text = {
            Column {
                Text(
                    text = "OSINTme aggregates exclusively public records, breach indexes and certificate transparency logs strictly for authorized self-auditing and personal defense research.",
                    color = SlateGrey,
                    fontSize = 13.sp,
                    lineHeight = 18.sp
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "• Zero Cloud Telemetry: No personal queries or photos are sent to external servers.\n• All local history remains in private device sandbox.",
                    color = MutedSlate,
                    fontSize = 11.sp,
                    lineHeight = 16.sp,
                    fontFamily = FontFamily.Monospace
                )
            }
        },
        confirmButton = {
            Button(
                onClick = onAccept,
                colors = ButtonDefaults.buttonColors(containerColor = SkyCyan),
                shape = RoundedCornerShape(6.dp)
            ) {
                Text("I Understand & Accept", color = SlateObsidian, fontWeight = FontWeight.Bold)
            }
        }
    )
}
