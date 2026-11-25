package com.oopssecurity.osintme.ui.ioc

import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.local.ApiProvider
import com.oopssecurity.osintme.data.network.ProThreatApiServices
import com.oopssecurity.osintme.data.network.ShodanService
import com.oopssecurity.osintme.data.network.UrlhausService
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.SaveToCaseDialog
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.EmeraldDeep
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.EmeraldSoft
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
import com.oopssecurity.osintme.util.ExtractedIoc
import com.oopssecurity.osintme.util.IocCategory
import com.oopssecurity.osintme.util.IocExtractor
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType
import com.oopssecurity.osintme.util.SafeBrowserLauncher
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch

private data class TriageVerdict(
    val status: String, // CHECKING, MALICIOUS, SUSPICIOUS, CLEAN, INFO
    val summary: String
)

@Composable
fun IocWorkbenchScreen(
    initialText: String = "",
    onBackClick: () -> Unit,
    onPivot: (PivotEntity) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var rawText by remember { mutableStateOf(initialText) }
    var defangDisplay by remember { mutableStateOf(true) }
    var selectedCategory by remember { mutableStateOf<IocCategory?>(null) }
    var isBatchTriaging by remember { mutableStateOf(false) }
    var showSaveDialog by remember { mutableStateOf(false) }
    val triageMap = remember { mutableStateMapOf<String, TriageVerdict>() }

    val extraction = remember(rawText) { IocExtractor.extract(rawText) }
    val visibleItems = remember(extraction, selectedCategory) {
        if (selectedCategory == null) extraction.items
        else extraction.items.filter { it.category == selectedCategory }
    }

    if (showSaveDialog && extraction.totalCount > 0) {
        SaveToCaseDialog(
            wingType = "IOC_TRIAGE",
            artifactType = "BULK_IOC_EXTRACTION",
            queryTarget = extraction.items.firstOrNull()?.value.orEmpty(),
            title = "Bulk IOC Extraction (${extraction.totalCount} indicators)",
            summary = extraction.countsByCategory.entries.joinToString(" • ") { "${it.key.badge}: ${it.value}" },
            rawJson = IocExtractor.toJson(extraction.items, defanged = true),
            sourceApi = "Local IOC Extractor + Batch Threat Triage",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Bulk IOC Extractor & Triage",
                subtitle = "Extract, defang & batch-check logs or phishing dumps",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (extraction.totalCount > 0) {
                    {
                        IconButton(
                            onClick = { showSaveDialog = true },
                            modifier = Modifier.size(48.dp).testTag("ioc_save_case_button")
                        ) {
                            Icon(Icons.Default.BookmarkAdd, contentDescription = "Save IOCs to case", tint = SkyCyan)
                        }
                    }
                } else null
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item { Spacer(modifier = Modifier.height(4.dp)) }

            // Raw Dump Input
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                    border = BorderStroke(1.dp, CardBorder),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "PASTE LOGS, PHISHING EMAIL, OR THREAT REPORT",
                                color = SkyCyan,
                                fontSize = 10.sp,
                                fontFamily = MonoFontFamily,
                                fontWeight = FontWeight.Bold
                            )
                            Row(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(SurfaceElevated)
                                    .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                                    .clickable {
                                        runCatching {
                                            val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                            val pasted = cb.primaryClip?.takeIf { it.itemCount > 0 }
                                                ?.getItemAt(0)?.text?.toString().orEmpty()
                                            if (pasted.isNotBlank()) rawText = pasted
                                        }
                                    }
                                    .padding(horizontal = 8.dp, vertical = 5.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.ContentPaste, contentDescription = "Paste", tint = SoftIndigo, modifier = Modifier.size(13.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Paste", color = SoftIndigo, fontSize = 11.sp, fontWeight = FontWeight.Medium)
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        OutlinedTextField(
                            value = rawText,
                            onValueChange = { rawText = it },
                            placeholder = {
                                Text(
                                    text = "Paste raw text with IPs, domains, hxxps://defanged[.]urls, emails, SHA-256 hashes, or BTC/ETH wallets...",
                                    color = MutedSlate,
                                    fontSize = 12.sp
                                )
                            },
                            minLines = 4,
                            maxLines = 7,
                            textStyle = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = MonoFontFamily,
                                color = OffWhite
                            ),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedContainerColor = DarkerSurface,
                                unfocusedContainerColor = DarkerSurface,
                                focusedBorderColor = SkyCyan,
                                unfocusedBorderColor = CardBorder
                            ),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ioc_raw_input")
                        )

                        Spacer(modifier = Modifier.height(10.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Shield, contentDescription = null, tint = MatrixGreen, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Defang Output", color = OffWhite, fontSize = 12.sp)
                                Spacer(modifier = Modifier.width(8.dp))
                                Switch(
                                    checked = defangDisplay,
                                    onCheckedChange = { defangDisplay = it },
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = SlateObsidian,
                                        checkedTrackColor = MatrixGreen
                                    )
                                )
                            }

                            Button(
                                onClick = {
                                    val triageTargets = extraction.items.filter {
                                        it.category in setOf(
                                            IocCategory.IPV4,
                                            IocCategory.DOMAIN,
                                            IocCategory.SHA256,
                                            IocCategory.MD5,
                                            IocCategory.SHA1
                                        )
                                    }.take(12)
                                    if (triageTargets.isEmpty()) {
                                        Toast.makeText(context, "No IPs, domains, or hashes to triage", Toast.LENGTH_SHORT).show()
                                        return@Button
                                    }
                                    isBatchTriaging = true
                                    scope.launch {
                                        triageTargets.forEach { ioc ->
                                            triageMap[ioc.value] = TriageVerdict("CHECKING", "Querying threat feeds...")
                                        }
                                        triageTargets.map { ioc ->
                                            async {
                                                triageMap[ioc.value] = runSingleIocTriage(ioc)
                                            }
                                        }.awaitAll()
                                        isBatchTriaging = false
                                    }
                                },
                                enabled = !isBatchTriaging && extraction.totalCount > 0,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = EmeraldPrimary,
                                    contentColor = PureWhite,
                                    disabledContainerColor = SurfaceElevated,
                                    disabledContentColor = MutedSlate
                                ),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.testTag("ioc_batch_triage_button")
                            ) {
                                if (isBatchTriaging) {
                                    CircularProgressIndicator(
                                        color = PureWhite,
                                        modifier = Modifier.size(15.dp),
                                        strokeWidth = 2.dp
                                    )
                                } else {
                                    Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp))
                                }
                                Spacer(modifier = Modifier.width(5.dp))
                                Text("Batch Triage", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // Copy CSV / JSON Row
            if (extraction.totalCount > 0) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                val csv = IocExtractor.toCsv(visibleItems, defangDisplay)
                                copyToClipboard(context, "IOCs CSV", csv)
                                Toast.makeText(context, "Copied ${visibleItems.size} IOCs as CSV", Toast.LENGTH_SHORT).show()
                            },
                            border = BorderStroke(1.dp, CardBorder),
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = CharcoalNavy, contentColor = OffWhite),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(5.dp))
                            Text("Copy CSV", fontSize = 12.sp)
                        }
                        OutlinedButton(
                            onClick = {
                                val json = IocExtractor.toJson(visibleItems, defangDisplay)
                                copyToClipboard(context, "IOCs JSON", json)
                                Toast.makeText(context, "Copied ${visibleItems.size} IOCs as JSON", Toast.LENGTH_SHORT).show()
                            },
                            border = BorderStroke(1.dp, CardBorder),
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = CharcoalNavy, contentColor = OffWhite),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null, tint = MatrixGreen, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(5.dp))
                            Text("Copy JSON", fontSize = 12.sp)
                        }
                    }
                }

                // Category Filter Chips
                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        FilterChip(
                            selected = selectedCategory == null,
                            onClick = { selectedCategory = null },
                            label = { Text("ALL (${extraction.totalCount})", fontSize = 11.sp, fontFamily = MonoFontFamily) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = EmeraldSoft,
                                selectedLabelColor = EmeraldDeep,
                                containerColor = CharcoalNavy,
                                labelColor = SlateGrey
                            )
                        )
                        extraction.countsByCategory.forEach { (cat, count) ->
                            FilterChip(
                                selected = selectedCategory == cat,
                                onClick = { selectedCategory = if (selectedCategory == cat) null else cat },
                                label = { Text("${cat.badge} ($count)", fontSize = 11.sp, fontFamily = MonoFontFamily) },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = EmeraldSoft,
                                    selectedLabelColor = EmeraldDeep,
                                    containerColor = CharcoalNavy,
                                    labelColor = SlateGrey
                                )
                            )
                        }
                    }
                }
            }

            // Extracted IOC Rows
            items(visibleItems, key = { "${it.category.name}_${it.value}" }) { ioc ->
                val displayText = if (defangDisplay) ioc.defangedValue else ioc.value
                val triage = triageMap[ioc.value]
                val verdictColor = when (triage?.status) {
                    "MALICIOUS" -> StatusRisk
                    "SUSPICIOUS" -> StatusWarning
                    "CLEAN" -> StatusSafe
                    else -> SkyCyan
                }

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            val hint = when (ioc.category) {
                                IocCategory.IPV4, IocCategory.IPV6 -> PivotEntityType.IP_ADDRESS
                                IocCategory.DOMAIN -> PivotEntityType.DOMAIN
                                IocCategory.URL -> PivotEntityType.URL
                                IocCategory.EMAIL -> PivotEntityType.EMAIL
                                IocCategory.SHA256, IocCategory.SHA1, IocCategory.MD5 -> PivotEntityType.HASH
                                IocCategory.PHONE -> PivotEntityType.PHONE
                                IocCategory.CRYPTO_WALLET -> null
                            }
                            onPivot(PivotEngine.normalize(ioc.value, hint, "Bulk IOC Workbench"))
                        },
                    colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                    border = BorderStroke(
                        1.dp,
                        if (triage != null) verdictColor.copy(alpha = 0.45f) else CardBorder
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(SurfaceElevated)
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        text = ioc.category.badge,
                                        color = SkyCyan,
                                        fontSize = 9.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                if (triage != null) {
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(4.dp))
                                            .background(verdictColor.copy(alpha = 0.16f))
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = triage.status,
                                            color = verdictColor,
                                            fontSize = 9.sp,
                                            fontFamily = MonoFontFamily,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.CallSplit,
                                contentDescription = "Pivot indicator",
                                tint = SkyCyan,
                                modifier = Modifier.size(16.dp)
                            )
                        }

                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = displayText,
                            color = OffWhite,
                            fontSize = 12.sp,
                            fontFamily = MonoFontFamily,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                        if (triage != null && triage.summary.isNotBlank()) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = triage.summary,
                                color = verdictColor,
                                fontSize = 11.sp,
                                fontFamily = MonoFontFamily
                            )
                        }
                    }
                }
            }

            item { Spacer(modifier = Modifier.height(24.dp)) }
        }
    }
}

private suspend fun runSingleIocTriage(ioc: ExtractedIoc): TriageVerdict {
    return when (ioc.category) {
        IocCategory.IPV4 -> {
            val shodan = ShodanService.lookupIp(ioc.value).getOrNull()
            val abuse = if (ApiKeyVault.hasKey(ApiProvider.ABUSEIPDB)) {
                ProThreatApiServices.lookupAbuseIpdb(ioc.value).getOrNull()
            } else null
            val vt = if (ApiKeyVault.hasKey(ApiProvider.VIRUSTOTAL)) {
                ProThreatApiServices.lookupVirusTotalIp(ioc.value).getOrNull()
            } else null

            val mal = (vt?.maliciousCount ?: 0) > 0 || (abuse?.abuseConfidenceScore ?: 0) >= 50
            val susp = (shodan?.vulns?.isNotEmpty() == true) || (abuse?.abuseConfidenceScore ?: 0) >= 15
            val details = buildList {
                shodan?.let { add("${it.ports.size} ports, ${it.vulns.size} CVEs (${it.country})") }
                abuse?.let { add("AbuseIPDB ${it.abuseConfidenceScore}%") }
                vt?.let { add("VT ${it.maliciousCount}/${it.totalEngines}") }
            }.joinToString(" • ").ifBlank { "No records" }

            TriageVerdict(
                status = when {
                    mal -> "MALICIOUS"
                    susp -> "SUSPICIOUS"
                    else -> "CLEAN"
                },
                summary = details
            )
        }

        IocCategory.DOMAIN -> {
            val uh = UrlhausService.checkHost(ioc.value).getOrNull()
            val vt = if (ApiKeyVault.hasKey(ApiProvider.VIRUSTOTAL)) {
                ProThreatApiServices.lookupVirusTotalDomain(ioc.value).getOrNull()
            } else null

            val mal = (uh?.isMalicious == true) || (vt?.maliciousCount ?: 0) > 0
            val details = buildList {
                uh?.let {
                    add(if (it.cloudflareMalwareBlocked) "CF 1.1.1.2 BLOCKED" else "CF 1.1.1.2 Clean")
                    if (it.urlCount > 0) add("URLhaus ${it.urlCount} URLs")
                }
                vt?.let { add("VT ${it.maliciousCount}/${it.totalEngines}") }
            }.joinToString(" • ").ifBlank { "Resolved" }

            TriageVerdict(if (mal) "MALICIOUS" else "CLEAN", details)
        }

        IocCategory.SHA256, IocCategory.SHA1, IocCategory.MD5 -> {
            val mb = ProThreatApiServices.lookupMalwareBazaarHash(ioc.value).getOrNull()
            val vt = if (ApiKeyVault.hasKey(ApiProvider.VIRUSTOTAL)) {
                ProThreatApiServices.lookupVirusTotalHash(ioc.value).getOrNull()
            } else null

            val mal = (mb?.found == true) || (vt?.maliciousCount ?: 0) > 0
            val details = buildList {
                mb?.let { if (it.found) add("MB: ${it.signature}") else if (it.note.isNotBlank()) add(it.note) }
                vt?.let { add("VT ${it.maliciousCount}/${it.totalEngines}") }
            }.joinToString(" • ").ifBlank { "No public match" }

            TriageVerdict(if (mal) "MALICIOUS" else "CLEAN", details)
        }

        else -> TriageVerdict("INFO", "Extracted indicator")
    }
}

private fun copyToClipboard(context: Context, label: String, text: String) {
    SafeBrowserLauncher.copyToClipboard(context, label, text, isSensitive = true)
}
