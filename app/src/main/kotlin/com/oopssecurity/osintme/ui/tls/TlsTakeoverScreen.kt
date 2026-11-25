package com.oopssecurity.osintme.ui.tls

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.network.SubdomainTakeoverFinding
import com.oopssecurity.osintme.data.network.TakeoverScanSummary
import com.oopssecurity.osintme.data.network.TakeoverSeverity
import com.oopssecurity.osintme.data.network.TlsAndTakeoverService
import com.oopssecurity.osintme.data.network.TlsCertReport
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.SaveToCaseDialog
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.EmeraldBorder
import com.oopssecurity.osintme.ui.theme.EmeraldDeep
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.EmeraldSoft
import com.oopssecurity.osintme.ui.theme.InkBlack
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEntityType
import kotlinx.coroutines.launch

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun TlsTakeoverScreen(
    initialTarget: String = "",
    onBackClick: () -> Unit,
    onPivotEntity: (String, PivotEntityType?, String) -> Unit = { _, _, _ -> },
    modifier: Modifier = Modifier
) {
    val scope = rememberCoroutineScope()
    var targetInput by remember { mutableStateOf(initialTarget) }
    var selectedTab by remember { mutableIntStateOf(0) } // 0 = Live TLS Cert, 1 = CNAME Takeover

    var tlsLoading by remember { mutableStateOf(false) }
    var tlsError by remember { mutableStateOf<String?>(null) }
    var tlsReport by remember { mutableStateOf<TlsCertReport?>(null) }

    var takeoverLoading by remember { mutableStateOf(false) }
    var takeoverError by remember { mutableStateOf<String?>(null) }
    var takeoverSummary by remember { mutableStateOf<TakeoverScanSummary?>(null) }

    var showSaveDialog by remember { mutableStateOf(false) }

    fun runInspect(domain: String) {
        val clean = domain.trim()
        if (clean.isBlank()) return
        if (selectedTab == 0) {
            tlsLoading = true
            tlsError = null
            scope.launch {
                TlsAndTakeoverService.inspectTlsCertificate(clean).fold(
                    onSuccess = { tlsReport = it },
                    onFailure = { tlsError = it.message ?: "TLS handshake failed" }
                )
                tlsLoading = false
            }
        } else {
            takeoverLoading = true
            takeoverError = null
            scope.launch {
                TlsAndTakeoverService.scanSubdomainTakeovers(clean).fold(
                    onSuccess = { takeoverSummary = it },
                    onFailure = { takeoverError = it.message ?: "Takeover scan failed" }
                )
                takeoverLoading = false
            }
        }
    }

    LaunchedEffect(initialTarget) {
        if (initialTarget.isNotBlank() && tlsReport == null) {
            runInspect(initialTarget)
        }
    }

    if (showSaveDialog && (tlsReport != null || takeoverSummary != null)) {
        val summaryText = buildString {
            tlsReport?.let {
                append("TLS ${it.protocol} • Issuer: ${it.issuerCn} • Expires: ${it.validUntil} (${it.daysRemaining}d) • ${it.sanDomains.size} SANs. ")
            }
            takeoverSummary?.let {
                val vuln = it.findings.count { f -> f.severity == TakeoverSeverity.CONFIRMED_VULNERABLE }
                val dangling = it.findings.count { f -> f.severity == TakeoverSeverity.POTENTIAL_DANGLING }
                append("Takeover scan: ${it.totalSubdomainsChecked} subdomains checked, $vuln confirmed vulnerable, $dangling potential dangling.")
            }
        }
        SaveToCaseDialog(
            wingType = "TLS_TAKEOVER",
            artifactType = "TLS_AND_CNAME",
            queryTarget = tlsReport?.host ?: takeoverSummary?.rootDomain ?: targetInput,
            title = "TLS & Subdomain Takeover Audit",
            summary = summaryText,
            sourceApi = "Live X.509 SSLSocket + crt.sh + Cloudflare DoH",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = PureWhite,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "TLS & Takeover Lab",
                subtitle = "Live SSL certificate SANs & CNAME takeover checks",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (tlsReport != null || takeoverSummary != null) {
                    {
                        IconButton(onClick = { showSaveDialog = true }) {
                            Icon(Icons.Default.BookmarkAdd, contentDescription = "Save to Case", tint = EmeraldPrimary)
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
                .navigationBarsPadding()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = targetInput,
                    onValueChange = { targetInput = it },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("tls_target_input"),
                    singleLine = true,
                    placeholder = { Text("Domain (e.g. github.com)", color = MutedSlate, fontSize = 13.sp) },
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = InkBlack),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = CharcoalNavy,
                        unfocusedContainerColor = CharcoalNavy,
                        focusedBorderColor = InkBlack,
                        unfocusedBorderColor = CardBorder,
                        focusedTextColor = InkBlack,
                        unfocusedTextColor = InkBlack
                    ),
                    shape = RoundedCornerShape(10.dp),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { runInspect(targetInput) })
                )

                val busy = (selectedTab == 0 && tlsLoading) || (selectedTab == 1 && takeoverLoading)
                Button(
                    onClick = { runInspect(targetInput) },
                    enabled = targetInput.isNotBlank() && !busy,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .heightIn(min = 52.dp)
                        .testTag("tls_scan_button")
                ) {
                    if (busy) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = EmeraldPrimary)
                    } else {
                        Text(if (selectedTab == 0) "Inspect" else "Scan", fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            // Segmented Switcher
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(SurfaceElevated)
                    .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                    .padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                listOf("Live TLS Certificate", "CNAME Takeover").forEachIndexed { idx, label ->
                    val sel = selectedTab == idx
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 40.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(if (sel) EmeraldPrimary else SurfaceElevated)
                            .clickable { selectedTab = idx }
                            .padding(horizontal = 8.dp, vertical = 6.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = label,
                            color = if (sel) PureWhite else SlateGrey,
                            fontSize = 12.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            if (selectedTab == 0) {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    if (!tlsError.isNullOrBlank()) {
                        item {
                            Text(
                                text = tlsError!!,
                                color = StatusRisk,
                                fontSize = 12.sp,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(StatusRisk.copy(alpha = 0.08f))
                                    .padding(10.dp)
                            )
                        }
                    }

                    val cert = tlsReport
                    if (cert == null && !tlsLoading) {
                        item {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(14.dp))
                                    .background(CharcoalNavy)
                                    .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                                    .padding(18.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Icon(Icons.Default.Lock, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(30.dp))
                                Spacer(modifier = Modifier.height(8.dp))
                                Text("Live X.509 SSL/TLS Handshake", color = InkBlack, fontFamily = DisplayFontFamily, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = "Connects directly to port 443 with SNI to extract the live certificate chain, issuer, expiry countdown, cipher suite, SHA-256 fingerprint, and pivotable SAN domains.",
                                    color = SlateGrey,
                                    fontSize = 12.sp,
                                    lineHeight = 18.sp
                                )
                            }
                        }
                    } else if (cert != null) {
                        item {
                            val badgeColor = when {
                                cert.isExpired -> StatusRisk
                                cert.isExpiringSoon -> StatusWarning
                                else -> EmeraldPrimary
                            }
                            val statusText = when {
                                cert.isExpired -> "EXPIRED (${cert.daysRemaining}d)"
                                cert.isExpiringSoon -> "EXPIRING SOON (${cert.daysRemaining}d left)"
                                else -> "VALID • ${cert.daysRemaining} DAYS LEFT"
                            }

                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(14.dp))
                                    .background(CharcoalNavy)
                                    .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                                    .padding(14.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(cert.subjectCn, color = InkBlack, fontFamily = DisplayFontFamily, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(6.dp))
                                            .background(badgeColor.copy(alpha = 0.14f))
                                            .padding(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Text(statusText, color = badgeColor, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                                    }
                                }

                                CertRow("ISSUER", cert.issuerCn)
                                CertRow("PROTOCOL", "${cert.protocol} • Chain Depth: ${cert.chainDepth}")
                                CertRow("CIPHER", cert.cipherSuite)
                                CertRow("VALIDITY", "${cert.validFrom} → ${cert.validUntil}")
                                CertRow("SERIAL", cert.serialHex)
                                CertRow("SHA-256", cert.sha256Fingerprint)
                            }
                        }

                        if (cert.sanDomains.isNotEmpty()) {
                            item {
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(14.dp))
                                        .background(EmeraldSoft)
                                        .border(1.dp, EmeraldBorder, RoundedCornerShape(14.dp))
                                        .padding(14.dp)
                                ) {
                                    Text(
                                        text = "SUBJECT ALTERNATIVE NAMES (${cert.sanDomains.size}) — TAP TO PIVOT",
                                        color = EmeraldDeep,
                                        fontSize = 10.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    FlowRow(
                                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                                        verticalArrangement = Arrangement.spacedBy(6.dp)
                                    ) {
                                        cert.sanDomains.forEach { san ->
                                            Box(
                                                modifier = Modifier
                                                    .clip(RoundedCornerShape(6.dp))
                                                    .background(PureWhite)
                                                    .border(1.dp, EmeraldBorder, RoundedCornerShape(6.dp))
                                                    .clickable { onPivotEntity(san, PivotEntityType.DOMAIN, "Live TLS SAN") }
                                                    .padding(horizontal = 8.dp, vertical = 5.dp)
                                            ) {
                                                Text(san, color = InkBlack, fontSize = 11.sp, fontFamily = MonoFontFamily)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    item { Spacer(modifier = Modifier.height(20.dp)) }
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    if (!takeoverError.isNullOrBlank()) {
                        item {
                            Text(
                                text = takeoverError!!,
                                color = StatusRisk,
                                fontSize = 12.sp,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(StatusRisk.copy(alpha = 0.08f))
                                    .padding(10.dp)
                            )
                        }
                    }

                    val scan = takeoverSummary
                    if (scan == null && !takeoverLoading) {
                        item {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(14.dp))
                                    .background(CharcoalNavy)
                                    .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                                    .padding(18.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Icon(Icons.Default.Security, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(30.dp))
                                Spacer(modifier = Modifier.height(8.dp))
                                Text("Passive CNAME Subdomain Takeover Audit", color = InkBlack, fontFamily = DisplayFontFamily, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = "Discovers subdomains via crt.sh Certificate Transparency logs, queries live CNAME records over Cloudflare DoH, and checks 14 cloud provider takeover signatures (GitHub Pages, S3, Heroku, Azure, Fastly, Shopify, Netlify, etc.).",
                                    color = SlateGrey,
                                    fontSize = 12.sp,
                                    lineHeight = 18.sp
                                )
                            }
                        }
                    } else if (scan != null) {
                        item {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(EmeraldSoft)
                                    .border(1.dp, EmeraldBorder, RoundedCornerShape(12.dp))
                                    .padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("Checked ${scan.totalSubdomainsChecked} subdomains", color = EmeraldDeep, fontSize = 12.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                                Text("${scan.findings.size} cloud CNAMEs", color = InkBlack, fontSize = 12.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                            }
                        }

                        if (scan.findings.isEmpty()) {
                            item {
                                Text(
                                    text = "No dangling cloud-hosted CNAME records matched across ${scan.totalSubdomainsChecked} checked subdomains.",
                                    color = EmeraldDeep,
                                    fontSize = 13.sp,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(12.dp))
                                        .background(CharcoalNavy)
                                        .border(1.dp, CardBorder, RoundedCornerShape(12.dp))
                                        .padding(14.dp)
                                )
                            }
                        } else {
                            items(scan.findings, key = { it.subdomain }) { finding ->
                                TakeoverFindingCard(
                                    finding = finding,
                                    onPivot = { onPivotEntity(finding.subdomain, PivotEntityType.DOMAIN, "CNAME Takeover Audit") }
                                )
                            }
                        }
                    }

                    item { Spacer(modifier = Modifier.height(20.dp)) }
                }
            }
        }
    }
}

@Composable
private fun CertRow(label: String, value: String) {
    Column {
        Text(label, color = MutedSlate, fontSize = 9.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
        Text(value, color = InkBlack, fontSize = 12.sp, fontFamily = MonoFontFamily)
    }
}

@Composable
private fun TakeoverFindingCard(
    finding: SubdomainTakeoverFinding,
    onPivot: () -> Unit
) {
    val (color, badge) = when (finding.severity) {
        TakeoverSeverity.CONFIRMED_VULNERABLE -> StatusRisk to "CONFIRMED VULNERABLE"
        TakeoverSeverity.POTENTIAL_DANGLING -> StatusWarning to "POTENTIAL DANGLING"
        TakeoverSeverity.CLAIMED_SAFE -> EmeraldPrimary to "CLAIMED / SAFE"
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(CharcoalNavy)
            .border(1.dp, color.copy(alpha = 0.45f), RoundedCornerShape(12.dp))
            .clickable(onClick = onPivot)
            .padding(12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(finding.subdomain, color = InkBlack, fontSize = 13.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(4.dp))
                    .background(color.copy(alpha = 0.14f))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            ) {
                Text(badge, color = color, fontSize = 9.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
            }
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text("CNAME → ${finding.cnameTarget} (${finding.cloudProvider})", color = SlateGrey, fontSize = 11.sp, fontFamily = MonoFontFamily)
        Spacer(modifier = Modifier.height(4.dp))
        Text(finding.evidence, color = InkBlack, fontSize = 12.sp)
    }
}
