package com.oopssecurity.osintme.ui.domain

import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MarkEmailRead
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.PrimaryScrollableTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.data.model.DnsRecordItem
import com.oopssecurity.osintme.data.model.EmailSecurityAudit
import com.oopssecurity.osintme.data.model.IpReconResult
import com.oopssecurity.osintme.data.model.RdapDomainInfo
import com.oopssecurity.osintme.data.model.SubdomainResult
import com.oopssecurity.osintme.data.model.TlsHeaderAuditResult
import com.oopssecurity.osintme.data.model.WaybackUrlItem
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.SaveToCaseDialog
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
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
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType
import com.oopssecurity.osintme.util.SafeBrowserLauncher

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DomainReconScreen(
    initialTarget: String = "",
    onBackClick: () -> Unit,
    onPivot: (PivotEntity) -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val focusManager = LocalFocusManager.current
    val viewModel: DomainViewModel = viewModel(key = "domain_${initialTarget.ifBlank { "root" }}") {
        DomainViewModel(context)
    }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    var showSaveDialog by remember { mutableStateOf(false) }

    val hasAnyResult = uiState.ipResult != null ||
        uiState.tlsAudit != null ||
        uiState.subdomainResult != null ||
        uiState.dnsRecords.isNotEmpty() ||
        uiState.rdapInfo != null

    LaunchedEffect(initialTarget) {
        if (initialTarget.isNotEmpty() && uiState.target.isEmpty()) {
            viewModel.setTarget(initialTarget)
            viewModel.executeScan(initialTarget)
        }
    }

    if (showSaveDialog && hasAnyResult) {
        val summaryParts = buildList {
            uiState.ipResult?.let { add("IP ${it.ip} (${it.ports.size} open ports, ${it.vulns.size} CVEs)") }
            uiState.tlsAudit?.let { add("TLS ${it.tlsProtocol}, Headers Grade ${it.securityGrade}") }
            uiState.subdomainResult?.let { add("${it.totalCount} subdomains") }
            if (uiState.dnsRecords.isNotEmpty()) add("${uiState.dnsRecords.size} DNS records")
            uiState.emailSecurity?.let { add("Email Auth ${it.grade}") }
        }
        SaveToCaseDialog(
            wingType = "NETWORK",
            artifactType = if (uiState.isIpTarget) "IP_RECON" else "DOMAIN_RECON",
            queryTarget = uiState.target,
            title = "Network & TLS Audit: ${uiState.target}",
            summary = summaryParts.joinToString(" • ").ifBlank { "Network reconnaissance completed." },
            sourceApi = "Shodan InternetDB + TLS Handshake + Cloudflare DoH + CT Logs + RDAP",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Network & TLS Recon",
                subtitle = "Ports, GeoIP, TLS headers, subdomains & DNS",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (hasAnyResult) {
                    {
                        IconButton(
                            onClick = { showSaveDialog = true },
                            modifier = Modifier.size(48.dp).testTag("domain_save_case_button")
                        ) {
                            Icon(
                                imageVector = Icons.Default.BookmarkAdd,
                                contentDescription = "Save findings to case",
                                tint = SkyCyan
                            )
                        }
                    }
                } else null
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Search Bar Row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = uiState.target,
                    onValueChange = { viewModel.setTarget(it) },
                    placeholder = {
                        Text("Domain (github.com) or IPv4 (1.1.1.1)", color = MutedSlate, fontSize = 13.sp)
                    },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("domain_target_input"),
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(
                        fontFamily = MonoFontFamily,
                        color = OffWhite
                    ),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = CharcoalNavy,
                        unfocusedContainerColor = CharcoalNavy,
                        focusedBorderColor = SkyCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedTextColor = OffWhite,
                        unfocusedTextColor = OffWhite
                    ),
                    shape = RoundedCornerShape(10.dp),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = {
                        focusManager.clearFocus()
                        viewModel.executeScan()
                    })
                )

                Spacer(modifier = Modifier.width(10.dp))

                Button(
                    onClick = {
                        focusManager.clearFocus()
                        viewModel.executeScan()
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .height(54.dp)
                        .testTag("domain_scan_button"),
                    enabled = !uiState.isLoading && uiState.target.isNotBlank()
                ) {
                    if (uiState.isLoading) {
                        CircularProgressIndicator(
                            color = PureWhite,
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(Icons.Default.Search, contentDescription = "Scan target")
                    }
                }
            }

            // Modern M3 Scrollable Tab Row (6 Real Intelligence Feeds)
            val tabs = listOf(
                "Host & IP",
                "Web & BGP",
                "TLS & Headers",
                "Subdomains${uiState.subdomainResult?.let { " (${it.totalCount})" } ?: ""}",
                "DNS & Email",
                "WHOIS",
                "Wayback"
            )
            PrimaryScrollableTabRow(
                selectedTabIndex = uiState.activeTab.coerceIn(0, tabs.lastIndex),
                containerColor = CharcoalNavy,
                contentColor = SkyCyan,
                edgePadding = 12.dp,
                divider = { HorizontalDivider(color = CardBorder) }
            ) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        selected = uiState.activeTab == index,
                        onClick = { viewModel.selectTab(index) },
                        text = {
                            Text(
                                text = title,
                                fontSize = 12.sp,
                                fontWeight = if (uiState.activeTab == index) FontWeight.SemiBold else FontWeight.Normal,
                                color = if (uiState.activeTab == index) SkyCyan else SlateGrey
                            )
                        }
                    )
                }
            }

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (uiState.error != null) {
                    item {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(StatusRisk.copy(alpha = 0.12f))
                                .border(1.dp, StatusRisk.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = StatusRisk, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(uiState.error ?: "", color = StatusRisk, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }

                when (uiState.activeTab) {
                    0 -> item { IpOverviewSection(uiState.ipResult, onPivot) }
                    1 -> item { WebAndBgpSection(uiState.webTech, uiState.bgpAsn, onPivot) }
                    2 -> item { TlsAndHeadersSection(uiState.tlsAudit, onPivot) }
                    3 -> item { SubdomainsSection(uiState.subdomainResult, context, onPivot) }
                    4 -> item { DnsAndEmailSection(uiState.dnsRecords, uiState.emailSecurity, onPivot) }
                    5 -> item { RdapSection(uiState.rdapInfo, onPivot) }
                    6 -> item { WaybackSection(uiState.waybackUrls, context, onPivot) }
                }

                item { Spacer(modifier = Modifier.height(16.dp)) }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun IpOverviewSection(
    result: IpReconResult?,
    onPivot: (PivotEntity) -> Unit
) {
    if (result == null) {
        EmptyStateBox("Enter a domain or IPv4 address and tap Search to query Shodan InternetDB & HTTPS GeoIP.")
        return
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Router, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("Host, ASN & Open Ports", style = MaterialTheme.typography.titleSmall, color = OffWhite)
        }

        Spacer(modifier = Modifier.height(14.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .clickable {
                    onPivot(
                        PivotEngine.normalize(
                            raw = result.ip,
                            hintType = PivotEntityType.IP_ADDRESS,
                            sourceContext = "Shodan InternetDB Resolved IP"
                        )
                    )
                },
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("RESOLVED IP • TAP TO PIVOT", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
                    Spacer(modifier = Modifier.width(4.dp))
                    Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(12.dp))
                }
                Text(result.ip, color = SkyCyan, fontSize = 16.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
            }
            if (result.country.isNotBlank() && result.country != "Unknown") {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(DarkerSurface)
                        .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                        .padding(horizontal = 10.dp, vertical = 5.dp)
                ) {
                    Text(
                        text = listOf(result.city, result.country).filter { it.isNotBlank() }.joinToString(", "),
                        color = OffWhite,
                        fontSize = 11.sp,
                        fontFamily = MonoFontFamily
                    )
                }
            }
        }

        if (result.isp.isNotBlank() || result.asn.isNotBlank() || result.org.isNotBlank()) {
            Spacer(modifier = Modifier.height(12.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(DarkerSurface)
                    .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                    .padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                if (result.isp.isNotBlank()) KeyValueRow("ISP", result.isp)
                if (result.asn.isNotBlank()) KeyValueRow("ASN", result.asn, SkyCyan)
                if (result.org.isNotBlank() && result.org != result.isp) KeyValueRow("Organization", result.org)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "OPEN PORTS (${result.ports.size})",
            color = if (result.ports.isNotEmpty()) StatusWarning else StatusSafe,
            fontSize = 11.sp,
            fontFamily = MonoFontFamily,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.height(8.dp))

        if (result.ports.isEmpty()) {
            Text(
                text = "No exposed ports currently indexed by Shodan InternetDB.",
                color = StatusSafe,
                style = MaterialTheme.typography.bodySmall
            )
        } else {
            val riskyPorts = setOf(21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                result.ports.sorted().forEach { port ->
                    val isRisky = port in riskyPorts
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(if (isRisky) StatusRisk.copy(alpha = 0.14f) else SurfaceElevated)
                            .border(
                                1.dp,
                                if (isRisky) StatusRisk.copy(alpha = 0.45f) else CardBorder,
                                RoundedCornerShape(6.dp)
                            )
                            .padding(horizontal = 10.dp, vertical = 5.dp)
                    ) {
                        Text(
                            text = "TCP/$port",
                            color = if (isRisky) StatusRisk else SkyCyan,
                            fontSize = 12.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }
        }

        if (result.vulns.isNotEmpty()) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "INDEXED CVES (${result.vulns.size})",
                color = StatusRisk,
                fontSize = 11.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                result.vulns.forEach { cve ->
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(StatusRisk.copy(alpha = 0.14f))
                            .border(1.dp, StatusRisk.copy(alpha = 0.45f), RoundedCornerShape(6.dp))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text(cve, color = StatusRisk, fontSize = 11.sp, fontFamily = MonoFontFamily)
                    }
                }
            }
        }

        if (result.hostnames.isNotEmpty()) {
            Spacer(modifier = Modifier.height(14.dp))
            Text("REVERSE HOSTNAMES • TAP TO PIVOT", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
            Spacer(modifier = Modifier.height(6.dp))
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                result.hostnames.forEach { host ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(DarkerSurface)
                            .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                            .clickable {
                                onPivot(
                                    PivotEngine.normalize(
                                        raw = host,
                                        hintType = PivotEntityType.DOMAIN,
                                        sourceContext = "Reverse DNS (${result.ip})"
                                    )
                                )
                            }
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(host, color = OffWhite, fontSize = 12.sp, fontFamily = MonoFontFamily, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = "Pivot hostname", tint = SkyCyan, modifier = Modifier.size(14.dp))
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TlsAndHeadersSection(
    audit: TlsHeaderAuditResult?,
    onPivot: (PivotEntity) -> Unit
) {
    if (audit == null) {
        EmptyStateBox("No live HTTPS handshake data yet. Scan a domain to inspect its TLS certificate and HTTP security headers.")
        return
    }

    val gradeColor = when (audit.securityGrade) {
        "A+", "A" -> StatusSafe
        "B" -> SkyCyan
        "C" -> StatusWarning
        else -> StatusRisk
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        // TLS & Grade Summary Card
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(CharcoalNavy)
                .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = gradeColor, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text("TLS & Security Headers", style = MaterialTheme.typography.titleSmall, color = OffWhite)
                        Text(
                            text = "HTTP ${audit.httpStatus} • ${audit.responseTimeMs}ms",
                            color = SlateGrey,
                            fontSize = 11.sp,
                            fontFamily = MonoFontFamily
                        )
                    }
                }

                Box(
                    modifier = Modifier
                        .size(44.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(gradeColor.copy(alpha = 0.14f))
                        .border(1.dp, gradeColor.copy(alpha = 0.45f), RoundedCornerShape(10.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = audit.securityGrade,
                        color = gradeColor,
                        fontFamily = DisplayFontFamily,
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(DarkerSurface)
                    .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                    .padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                KeyValueRow("TLS Protocol", audit.tlsProtocol, if (audit.tlsProtocol.contains("1.3")) StatusSafe else SkyCyan)
                KeyValueRow("Cipher Suite", audit.cipherSuite)
                KeyValueRow("Certificate CN", audit.certSubject)
                KeyValueRow("Issuer", audit.certIssuer)
                KeyValueRow("Valid From", audit.certValidFrom)
                KeyValueRow("Expires", audit.certValidUntil)
                if (audit.serverHeader.isNotBlank()) {
                    KeyValueRow("Server Header", audit.serverHeader, StatusWarning)
                }
            }

            if (audit.certSans.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "SUBJECT ALT NAMES (${audit.certSanCount}) • TAP TO PIVOT",
                    color = MutedSlate,
                    fontSize = 10.sp,
                    fontFamily = MonoFontFamily
                )
                Spacer(modifier = Modifier.height(6.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    audit.certSans.take(16).forEach { san ->
                        Row(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(SurfaceElevated)
                                .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                                .clickable {
                                    onPivot(
                                        PivotEngine.normalize(
                                            raw = san,
                                            hintType = PivotEntityType.DOMAIN,
                                            sourceContext = "TLS Certificate SAN"
                                        )
                                    )
                                }
                                .padding(horizontal = 8.dp, vertical = 5.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(san, color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily)
                            Spacer(modifier = Modifier.width(4.dp))
                            Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = "Pivot SAN", tint = SkyCyan.copy(alpha = 0.8f), modifier = Modifier.size(11.dp))
                        }
                    }
                }
            }
        }

        // Security Header Checklist
        Text(
            text = "HTTP SECURITY HEADERS",
            color = MutedSlate,
            fontSize = 11.sp,
            fontFamily = MonoFontFamily,
            fontWeight = FontWeight.SemiBold
        )

        audit.headers.forEach { h ->
            val badgeColor = if (h.present) StatusSafe else StatusWarning
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(CharcoalNavy)
                    .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                    .padding(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = h.name,
                        color = OffWhite,
                        fontSize = 12.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.SemiBold
                    )
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(badgeColor.copy(alpha = 0.14f))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = if (h.present) "PRESENT" else "MISSING",
                            color = badgeColor,
                            fontSize = 9.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = h.value,
                    color = if (h.present) SkyCyan else SlateGrey,
                    fontSize = 11.sp,
                    fontFamily = if (h.present) MonoFontFamily else null,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun SubdomainsSection(
    result: SubdomainResult?,
    context: Context,
    onPivot: (PivotEntity) -> Unit
) {
    if (result == null) {
        EmptyStateBox("No subdomain enumeration performed yet.")
        return
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "${result.totalCount} SUBDOMAINS • TAP ANY TO PIVOT",
                    color = SkyCyan,
                    fontSize = 11.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                )
                if (result.sources.isNotEmpty()) {
                    Text(
                        text = "Sources: ${result.sources.joinToString(", ")}",
                        color = SlateGrey,
                        fontSize = 11.sp
                    )
                }
            }

            if (result.subdomains.isNotEmpty()) {
                IconButton(
                    onClick = {
                        SafeBrowserLauncher.copyToClipboard(context, "Subdomains", result.subdomains.joinToString("\n"), isSensitive = true)
                        Toast.makeText(context, "Copied ${result.subdomains.size} subdomains", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.size(44.dp)
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy all subdomains", tint = SkyCyan, modifier = Modifier.size(18.dp))
                }
            }
        }

        if (result.subdomains.isEmpty()) {
            EmptyStateBox("No public subdomains found in Certificate Transparency or passive DNS indexes for ${result.rootDomain}.")
        } else {
            result.subdomains.forEach { sub ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                        .clickable {
                            onPivot(
                                PivotEngine.normalize(
                                    raw = sub,
                                    hintType = PivotEntityType.DOMAIN,
                                    sourceContext = "Subdomain of ${result.rootDomain}"
                                )
                            )
                        }
                        .padding(horizontal = 12.dp, vertical = 11.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = sub,
                        color = OffWhite,
                        fontSize = 12.sp,
                        fontFamily = MonoFontFamily,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.CallSplit,
                        contentDescription = "Pivot subdomain",
                        tint = SkyCyan,
                        modifier = Modifier.size(15.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun DnsAndEmailSection(
    records: List<DnsRecordItem>,
    emailSecurity: EmailSecurityAudit?,
    onPivot: (PivotEntity) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (emailSecurity != null) {
            EmailSecurityAuditCard(emailSecurity)
        }

        if (records.isEmpty()) {
            EmptyStateBox("No DNS records resolved via Cloudflare 1.1.1.1 DoH.")
        } else {
            Text(
                text = "CLOUDFLARE DNS-OVER-HTTPS (${records.size} RECORDS)",
                color = MutedSlate,
                fontSize = 11.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.SemiBold
            )

            records.forEach { rec ->
                val pivotHint = when (rec.type.uppercase()) {
                    "A", "AAAA" -> PivotEntityType.IP_ADDRESS
                    "MX", "NS", "CNAME" -> PivotEntityType.DOMAIN
                    else -> null
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                        .clickable(enabled = pivotHint != null) {
                            if (pivotHint != null) {
                                onPivot(
                                    PivotEngine.normalize(
                                        raw = rec.data,
                                        hintType = pivotHint,
                                        sourceContext = "DNS ${rec.type} Record (${rec.name})"
                                    )
                                )
                            }
                        }
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(5.dp))
                            .background(SkyCyan.copy(alpha = 0.14f))
                            .padding(horizontal = 8.dp, vertical = 3.dp)
                    ) {
                        Text(
                            text = rec.type,
                            color = SkyCyan,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp,
                            fontFamily = MonoFontFamily
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(rec.data, color = OffWhite, fontSize = 12.sp, fontFamily = MonoFontFamily)
                        Spacer(modifier = Modifier.height(2.dp))
                        Text("${rec.name} • TTL ${rec.ttl}s", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
                    }
                    if (pivotHint != null) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.CallSplit,
                            contentDescription = "Pivot DNS record",
                            tint = SkyCyan,
                            modifier = Modifier.size(15.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun EmailSecurityAuditCard(audit: EmailSecurityAudit) {
    val gradeColor = when (audit.grade) {
        "A" -> StatusSafe
        "B" -> SkyCyan
        "C" -> StatusWarning
        else -> StatusRisk
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.MarkEmailRead, contentDescription = null, tint = gradeColor, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Column {
                    Text("Email Anti-Spoofing (SPF / DMARC)", style = MaterialTheme.typography.titleSmall, color = OffWhite)
                    Text(audit.domain, color = SlateGrey, fontSize = 11.sp, fontFamily = MonoFontFamily)
                }
            }
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(gradeColor.copy(alpha = 0.14f))
                    .border(1.dp, gradeColor.copy(alpha = 0.45f), RoundedCornerShape(8.dp))
                    .padding(horizontal = 10.dp, vertical = 5.dp)
            ) {
                Text("GRADE ${audit.grade}", color = gradeColor, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
            }
        }

        Spacer(modifier = Modifier.height(10.dp))
        Text(audit.riskSummary, style = MaterialTheme.typography.bodySmall, color = SlateGrey)
        Spacer(modifier = Modifier.height(10.dp))

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(DarkerSurface)
                .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            KeyValueRow("MX Mail Exchanger", if (audit.hasMx) "${audit.mxHosts.size} configured" else "None found", if (audit.hasMx) StatusSafe else MutedSlate)
            KeyValueRow("SPF Record", if (audit.hasSpf) "Configured" else "Missing", if (audit.hasSpf) StatusSafe else StatusRisk)
            KeyValueRow("DMARC Policy", if (audit.hasDmarc) audit.dmarcPolicy.uppercase() else "Missing", if (audit.hasDmarc) StatusSafe else StatusRisk)
        }

        audit.spfRecord?.let { spf ->
            Spacer(modifier = Modifier.height(8.dp))
            Text(spf, color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily)
        }
        audit.dmarcRecord?.let { dmarc ->
            Spacer(modifier = Modifier.height(4.dp))
            Text(dmarc, color = SoftIndigo, fontSize = 11.sp, fontFamily = MonoFontFamily)
        }
    }
}

@Composable
private fun RdapSection(
    rdap: RdapDomainInfo?,
    onPivot: (PivotEntity) -> Unit
) {
    if (rdap == null) {
        EmptyStateBox("No RDAP registration records available for this target.")
        return
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text("RDAP REGISTRATION / WHOIS", color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
        KeyValueRow("Domain", rdap.domain)
        KeyValueRow("Registrar", rdap.registrar)
        if (rdap.registrationDate.isNotEmpty()) KeyValueRow("Registered", rdap.registrationDate)
        if (rdap.expirationDate.isNotEmpty()) KeyValueRow("Expires", rdap.expirationDate)
        if (rdap.lastUpdated.isNotEmpty()) KeyValueRow("Updated", rdap.lastUpdated)

        if (rdap.nameServers.isNotEmpty()) {
            Spacer(modifier = Modifier.height(6.dp))
            Text("NAMESERVERS • TAP TO PIVOT", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
            rdap.nameServers.forEach { ns ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(DarkerSurface)
                        .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                        .clickable {
                            onPivot(
                                PivotEngine.normalize(
                                    raw = ns,
                                    hintType = PivotEntityType.DOMAIN,
                                    sourceContext = "RDAP Nameserver (${rdap.domain})"
                                )
                            )
                        }
                        .padding(horizontal = 10.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(ns, color = OffWhite, fontSize = 12.sp, fontFamily = MonoFontFamily, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = "Pivot nameserver", tint = SkyCyan, modifier = Modifier.size(14.dp))
                }
            }
        }
    }
}

@Composable
private fun WaybackSection(
    urls: List<WaybackUrlItem>,
    context: Context,
    onPivot: (PivotEntity) -> Unit
) {
    if (urls.isEmpty()) {
        EmptyStateBox("No archived URLs indexed on Wayback Machine CDX.")
        return
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "WAYBACK CDX ARCHIVES (${urls.size}) • TAP TO PIVOT",
                color = SkyCyan,
                fontSize = 11.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold
            )
            IconButton(
                onClick = {
                    SafeBrowserLauncher.copyToClipboard(context, "Wayback URLs", urls.joinToString("\n") { it.url }, isSensitive = true)
                    Toast.makeText(context, "Copied ${urls.size} archived URLs", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.size(44.dp)
            ) {
                Icon(Icons.Default.ContentCopy, contentDescription = "Copy archived URLs", tint = SkyCyan, modifier = Modifier.size(18.dp))
            }
        }

        urls.forEach { item ->
            val statusColor = when {
                item.statusCode.startsWith("2") -> MatrixGreen
                item.statusCode.startsWith("3") -> SkyCyan
                item.statusCode.startsWith("4") -> StatusWarning
                else -> StatusRisk
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(CharcoalNavy)
                    .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                    .clickable {
                        onPivot(
                            PivotEngine.normalize(
                                raw = item.url,
                                hintType = PivotEntityType.URL,
                                sourceContext = "Wayback CDX (${item.timestamp})"
                            )
                        )
                    }
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(statusColor.copy(alpha = 0.14f))
                        .padding(horizontal = 6.dp, vertical = 3.dp)
                ) {
                    Text(item.statusCode, color = statusColor, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(item.url, color = OffWhite, fontSize = 12.sp, fontFamily = MonoFontFamily, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    Text("Snapshot: ${item.timestamp}", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
                }
                IconButton(
                    onClick = {
                        SafeBrowserLauncher.openExternalUrl(context, item.archiveUrl)
                    },
                    modifier = Modifier.size(44.dp)
                ) {
                    Icon(Icons.Default.OpenInBrowser, contentDescription = "Open Wayback snapshot", tint = SkyCyan, modifier = Modifier.size(18.dp))
                }
            }
        }
    }
}

@Composable
private fun KeyValueRow(label: String, value: String, valueColor: androidx.compose.ui.graphics.Color = OffWhite) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top
    ) {
        Text(label, color = SlateGrey, fontSize = 12.sp, modifier = Modifier.padding(end = 12.dp))
        Text(
            text = value,
            color = valueColor,
            fontSize = 12.sp,
            fontFamily = MonoFontFamily,
            fontWeight = FontWeight.Medium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun EmptyStateBox(message: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(12.dp))
            .padding(24.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(message, color = MutedSlate, style = MaterialTheme.typography.bodySmall)
    }
}
