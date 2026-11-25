package com.oopssecurity.osintme.ui.threat

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
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
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.UrlhausResult
import com.oopssecurity.osintme.data.network.UrlhausService
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.SaveToCaseDialog
import com.oopssecurity.osintme.ui.dorks.DorkGeneratorScreen
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatIntelScreen(
    initialTarget: String = "",
    onBackClick: () -> Unit,
    onPivot: (PivotEntity) -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val focusManager = LocalFocusManager.current
    val historyManager = remember(context) { LocalScanHistoryManager(context) }

    var selectedTab by remember { mutableIntStateOf(0) }
    var hostInput by remember(initialTarget) { mutableStateOf(initialTarget) }
    var isLoading by remember(initialTarget) { mutableStateOf(false) }
    var urlhausResult by remember(initialTarget) { mutableStateOf<UrlhausResult?>(null) }
    var error by remember(initialTarget) { mutableStateOf<String?>(null) }
    var showSaveDialog by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun runCheck() {
        val target = hostInput.trim()
        if (target.isEmpty()) return
        focusManager.clearFocus()
        isLoading = true
        error = null
        scope.launch {
            UrlhausService.checkHost(target).fold(
                onSuccess = { res ->
                    urlhausResult = res
                    isLoading = false
                    historyManager.addScan(
                        type = "Threat Intel",
                        target = res.target,
                        summary = if (res.isMalicious) {
                            "FLAGGED • CF 1.1.1.2=${if (res.cloudflareMalwareBlocked) "BLOCKED" else "OK"} • URLhaus=${res.urlCount}"
                        } else {
                            "Clean across Cloudflare 1.1.1.2 & abuse feeds"
                        }
                    )
                },
                onFailure = {
                    error = it.message ?: "Failed to query threat intelligence feeds"
                    isLoading = false
                }
            )
        }
    }

    LaunchedEffect(initialTarget) {
        if (initialTarget.isNotEmpty() && urlhausResult == null) {
            runCheck()
        }
    }

    if (showSaveDialog && urlhausResult != null) {
        val r = urlhausResult!!
        SaveToCaseDialog(
            wingType = "THREAT_INTEL",
            artifactType = "MALWARE_REPUTATION",
            queryTarget = r.target,
            title = "Threat Reputation: ${r.target}",
            summary = if (r.isMalicious) {
                "Malicious indicators: CF1.1.1.2=${r.cloudflareMalwareBlocked}, URLhaus=${r.urlCount}, Spamhaus=${r.spamhausListed}, SURBL=${r.surblListed}"
            } else {
                "No malware blocks detected on Cloudflare 1.1.1.2 or public threat feeds."
            },
            sourceApi = "Cloudflare 1.1.1.2 Security DNS + abuse.ch URLhaus",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Threat Intel & Dorks",
                subtitle = "Cloudflare 1.1.1.2 malware DNS, URLhaus & search operators",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (selectedTab == 0 && urlhausResult != null) {
                    {
                        IconButton(
                            onClick = { showSaveDialog = true },
                            modifier = Modifier.size(48.dp).testTag("threat_save_case_button")
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
            PrimaryTabRow(
                selectedTabIndex = selectedTab,
                containerColor = CharcoalNavy,
                contentColor = SkyCyan,
                divider = { HorizontalDivider(color = CardBorder) }
            ) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("Malware & DNS Block", fontWeight = FontWeight.Medium) }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("Google Dorks", fontWeight = FontWeight.Medium) }
                )
            }

            if (selectedTab == 0) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp, vertical = 14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = hostInput,
                            onValueChange = { hostInput = it },
                            placeholder = { Text("Domain or IP (e.g. example.com)", color = MutedSlate, fontSize = 13.sp) },
                            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = OffWhite),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = OffWhite,
                                unfocusedTextColor = OffWhite,
                                focusedBorderColor = SkyCyan,
                                unfocusedBorderColor = CardBorder,
                                focusedContainerColor = CharcoalNavy,
                                unfocusedContainerColor = CharcoalNavy
                            ),
                            shape = RoundedCornerShape(10.dp),
                            singleLine = true,
                            modifier = Modifier.weight(1f).testTag("threat_host_input"),
                            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                            keyboardActions = KeyboardActions(onSearch = { runCheck() })
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Button(
                            onClick = { runCheck() },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = EmeraldPrimary,
                                contentColor = PureWhite,
                                disabledContainerColor = SurfaceElevated,
                                disabledContentColor = MutedSlate
                            ),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.height(54.dp).testTag("threat_scan_button"),
                            enabled = !isLoading && hostInput.isNotBlank()
                        ) {
                            if (isLoading) {
                                CircularProgressIndicator(color = PureWhite, modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(Icons.Default.Search, contentDescription = "Scan threat feeds")
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    if (error != null) {
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
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(error ?: "", color = StatusRisk, style = MaterialTheme.typography.bodySmall)
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                    }

                    val res = urlhausResult
                    if (res != null) {
                        LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            item { ThreatVerdictCard(res = res, onPivot = onPivot) }

                            if (res.payloads.isNotEmpty()) {
                                item {
                                    Text(
                                        text = "REPORTED MALWARE URLS (${res.payloads.size}) • TAP TO PIVOT",
                                        color = SkyCyan,
                                        fontSize = 11.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                items(res.payloads) { payload ->
                                    Column(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clip(RoundedCornerShape(10.dp))
                                            .background(CharcoalNavy)
                                            .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                                            .clickable {
                                                onPivot(
                                                    PivotEngine.normalize(
                                                        raw = payload.url,
                                                        hintType = PivotEntityType.URL,
                                                        sourceContext = "URLhaus Payload (${payload.threat})"
                                                    )
                                                )
                                            }
                                            .padding(12.dp)
                                    ) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Box(
                                                modifier = Modifier
                                                    .clip(RoundedCornerShape(4.dp))
                                                    .background(StatusRisk.copy(alpha = 0.14f))
                                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                                            ) {
                                                Text(payload.threat, color = StatusRisk, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                                            }
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                Text(payload.dateAdded, color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
                                                Spacer(modifier = Modifier.width(6.dp))
                                                Icon(
                                                    imageVector = Icons.AutoMirrored.Filled.CallSplit,
                                                    contentDescription = "Pivot payload URL",
                                                    tint = SkyCyan,
                                                    modifier = Modifier.size(14.dp)
                                                )
                                            }
                                        }
                                        Spacer(modifier = Modifier.height(6.dp))
                                        Text(payload.url, color = OffWhite, fontSize = 11.sp, fontFamily = MonoFontFamily, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                    }
                                }
                            }
                            item { Spacer(modifier = Modifier.height(12.dp)) }
                        }
                    } else if (!isLoading) {
                        Box(
                            modifier = Modifier.fillMaxSize().padding(bottom = 48.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(
                                horizontalAlignment = Alignment.CenterHorizontally,
                                modifier = Modifier.padding(horizontal = 24.dp)
                            ) {
                                Icon(Icons.Default.BugReport, contentDescription = null, tint = MutedSlate, modifier = Modifier.size(44.dp))
                                Spacer(modifier = Modifier.height(10.dp))
                                Text("Real-Time Malware & Phishing Check", style = MaterialTheme.typography.titleSmall, color = OffWhite)
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = "Cross-checks domains against Cloudflare 1.1.1.2 Security DNS malware blocking and abuse.ch URLhaus.",
                                    color = SlateGrey,
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }
                    }
                }
            } else {
                DorkGeneratorScreen(
                    initialTarget = hostInput,
                    onBackClick = onBackClick,
                    embedded = true
                )
            }
        }
    }
}

@Composable
private fun ThreatVerdictCard(
    res: UrlhausResult,
    onPivot: (PivotEntity) -> Unit
) {
    val accent = if (res.isMalicious) StatusRisk else MatrixGreen

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, accent.copy(alpha = 0.45f), RoundedCornerShape(14.dp))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .clickable {
                    onPivot(
                        PivotEngine.normalize(
                            raw = res.target,
                            sourceContext = "Threat Intel Target"
                        )
                    )
                },
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                Icon(
                    imageVector = if (res.isMalicious) Icons.Default.Warning else Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = res.target,
                    color = OffWhite,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = MonoFontFamily,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(accent.copy(alpha = 0.14f))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = if (res.isMalicious) "FLAGGED" else "CLEAN",
                    color = accent,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = MonoFontFamily
                )
            }
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(DarkerSurface)
                .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            VerdictRow(
                label = "Cloudflare 1.1.1.2 Malware DNS",
                value = if (res.cloudflareMalwareBlocked) "BLOCKED (0.0.0.0)" else "NOT BLOCKED",
                valueColor = if (res.cloudflareMalwareBlocked) StatusRisk else MatrixGreen
            )
            if (res.cloudflareStandardIps.isNotEmpty()) {
                res.cloudflareStandardIps.take(3).forEach { ip ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(6.dp))
                            .clickable {
                                onPivot(
                                    PivotEngine.normalize(
                                        raw = ip,
                                        hintType = PivotEntityType.IP_ADDRESS,
                                        sourceContext = "Cloudflare A Record (${res.target})"
                                    )
                                )
                            }
                            .padding(vertical = 2.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Resolved IP (Tap to pivot)", color = SlateGrey, fontSize = 12.sp)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(ip, color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.SemiBold)
                            Spacer(modifier = Modifier.width(4.dp))
                            Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = "Pivot IP", tint = SkyCyan, modifier = Modifier.size(13.dp))
                        }
                    }
                }
            }
            VerdictRow(
                label = "URLhaus Reported Payloads",
                value = "${res.urlCount}",
                valueColor = if (res.urlCount > 0) StatusRisk else MatrixGreen
            )
            if (res.firstSeen.isNotEmpty()) {
                VerdictRow("URLhaus First Seen", res.firstSeen, OffWhite)
            }
            VerdictRow(
                label = "Spamhaus DBL",
                value = if (res.spamhausListed) "LISTED" else "NOT LISTED",
                valueColor = if (res.spamhausListed) StatusRisk else MatrixGreen
            )
            VerdictRow(
                label = "SURBL",
                value = if (res.surblListed) "LISTED" else "NOT LISTED",
                valueColor = if (res.surblListed) StatusRisk else MatrixGreen
            )
        }

        res.urlhausNote?.let { note ->
            Text(
                text = note,
                color = StatusWarning,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

@Composable
private fun VerdictRow(label: String, value: String, valueColor: androidx.compose.ui.graphics.Color) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = SlateGrey, fontSize = 12.sp)
        Text(value, color = valueColor, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.SemiBold)
    }
}
