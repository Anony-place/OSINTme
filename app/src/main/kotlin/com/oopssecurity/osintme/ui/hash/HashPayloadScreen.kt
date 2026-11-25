package com.oopssecurity.osintme.ui.hash

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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.local.ApiProvider
import com.oopssecurity.osintme.data.model.MalwareBazaarReport
import com.oopssecurity.osintme.data.model.VirusTotalReport
import com.oopssecurity.osintme.data.network.ProThreatApiServices
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.CodeBlock
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
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.HashFormat
import com.oopssecurity.osintme.util.PayloadDecoder
import com.oopssecurity.osintme.util.SafeBrowserLauncher
import kotlinx.coroutines.async
import kotlinx.coroutines.launch

private enum class PayloadOperation(val label: String) {
    BASE64_DECODE("Base64 Dec"),
    BASE64_ENCODE("Base64 Enc"),
    JWT_INSPECT("JWT Inspect"),
    HEX_DECODE("Hex Dec"),
    HEX_ENCODE("Hex Enc"),
    URL_DECODE("URL Dec"),
    URL_ENCODE("URL Enc"),
    ROT13("ROT13"),
    EPOCH("Unix Epoch"),
    HASH_GEN("Generate Hashes")
}

@Composable
fun HashPayloadScreen(
    initialInput: String = "",
    onBackClick: () -> Unit,
    onOpenApiVault: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var selectedTab by remember { mutableIntStateOf(0) } // 0 = Hash Reputation, 1 = Payload & JWT Lab
    var hashQuery by remember { mutableStateOf(initialInput) }
    var isSearchingHash by remember { mutableStateOf(false) }
    var mbReport by remember { mutableStateOf<MalwareBazaarReport?>(null) }
    var vtReport by remember { mutableStateOf<VirusTotalReport?>(null) }
    var hashError by remember { mutableStateOf<String?>(null) }
    var showSaveDialog by remember { mutableStateOf(false) }

    // Payload Lab state
    var payloadInput by remember { mutableStateOf("") }
    var selectedOp by remember { mutableStateOf(PayloadOperation.BASE64_DECODE) }

    fun executeHashLookup(target: String) {
        val clean = target.trim().lowercase()
        if (clean.isBlank()) return
        isSearchingHash = true
        hashError = null
        mbReport = null
        vtReport = null
        scope.launch {
            val mbDeferred = async { ProThreatApiServices.lookupMalwareBazaarHash(clean) }
            val vtDeferred = async {
                if (ApiKeyVault.hasKey(ApiProvider.VIRUSTOTAL)) {
                    ProThreatApiServices.lookupVirusTotalHash(clean)
                } else null
            }
            val mbRes = mbDeferred.await()
            val vtRes = vtDeferred.await()

            mbReport = mbRes.getOrNull()
            vtReport = vtRes?.getOrNull()
            if (mbReport == null && vtReport == null) {
                hashError = mbRes.exceptionOrNull()?.message ?: vtRes?.exceptionOrNull()?.message ?: "Hash lookup failed"
            }
            isSearchingHash = false
        }
    }

    LaunchedEffect(initialInput) {
        if (initialInput.isNotBlank() && PayloadDecoder.detectHashFormat(initialInput) != HashFormat.UNKNOWN) {
            hashQuery = initialInput
            executeHashLookup(initialInput)
        }
    }

    if (showSaveDialog && (mbReport != null || vtReport != null)) {
        val summary = buildString {
            mbReport?.let { append(if (it.found) "MalwareBazaar: ${it.signature} (${it.fileName})" else "MalwareBazaar: Not listed") }
            vtReport?.let {
                if (isNotEmpty()) append(" • ")
                append("VirusTotal: ${it.maliciousCount}/${it.totalEngines} malicious")
            }
        }
        SaveToCaseDialog(
            wingType = "HASH_INTEL",
            artifactType = "FILE_HASH_REPUTATION",
            queryTarget = hashQuery.trim(),
            title = "Hash Reputation: ${hashQuery.trim().take(16)}…",
            summary = summary,
            sourceApi = "MalwareBazaar + VirusTotal v3",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Hash & Payload Lab",
                subtitle = "Malware hash lookup, Base64/Hex/Epoch & JWT audit",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (mbReport != null || vtReport != null) {
                    {
                        IconButton(
                            onClick = { showSaveDialog = true },
                            modifier = Modifier.size(48.dp)
                        ) {
                            Icon(Icons.Default.BookmarkAdd, contentDescription = "Save hash report", tint = SkyCyan)
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
                contentColor = SkyCyan
            ) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("Hash Reputation", fontSize = 13.sp, fontWeight = FontWeight.SemiBold) }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("Payload & JWT Lab", fontSize = 13.sp, fontWeight = FontWeight.SemiBold) }
                )
            }

            if (selectedTab == 0) {
                val detectedFormat = remember(hashQuery) { PayloadDecoder.detectHashFormat(hashQuery) }
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    item { Spacer(modifier = Modifier.height(6.dp)) }

                    item {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            OutlinedTextField(
                                value = hashQuery,
                                onValueChange = { hashQuery = it },
                                placeholder = { Text("Paste MD5, SHA-1, or SHA-256 hash...", color = MutedSlate, fontSize = 12.sp) },
                                singleLine = true,
                                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily, color = OffWhite),
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedContainerColor = CharcoalNavy,
                                    unfocusedContainerColor = CharcoalNavy,
                                    focusedBorderColor = SkyCyan,
                                    unfocusedBorderColor = CardBorder
                                ),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("hash_lookup_input")
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Button(
                                onClick = { executeHashLookup(hashQuery) },
                                enabled = !isSearchingHash && hashQuery.isNotBlank(),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = EmeraldPrimary,
                                    contentColor = PureWhite,
                                    disabledContainerColor = SurfaceElevated,
                                    disabledContentColor = MutedSlate
                                ),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier
                                    .height(54.dp)
                                    .testTag("hash_lookup_button")
                            ) {
                                if (isSearchingHash) {
                                    CircularProgressIndicator(color = PureWhite, modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                                } else {
                                    Icon(Icons.Default.Search, contentDescription = "Check hash")
                                }
                            }
                        }

                        if (hashQuery.isNotBlank()) {
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "Detected format: ${detectedFormat.label}",
                                color = if (detectedFormat != HashFormat.UNKNOWN) MatrixGreen else StatusWarning,
                                fontSize = 11.sp,
                                fontFamily = MonoFontFamily
                            )
                        }
                    }

                    if (!ApiKeyVault.hasKey(ApiProvider.VIRUSTOTAL)) {
                        item {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(DarkerSurface)
                                    .border(1.dp, StatusWarning.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
                                    .clickable { onOpenApiVault() }
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.Key, contentDescription = null, tint = StatusWarning, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    text = "Add a free VirusTotal v3 key in API Vault to unlock 70+ AV engine verdicts alongside MalwareBazaar.",
                                    color = SlateGrey,
                                    fontSize = 11.sp,
                                    lineHeight = 16.sp
                                )
                            }
                        }
                    }

                    if (hashError != null) {
                        item {
                            Text(text = hashError!!, color = StatusRisk, fontSize = 12.sp, fontFamily = MonoFontFamily)
                        }
                    }

                    mbReport?.let { mb ->
                        item {
                            val accent = if (mb.found) StatusRisk else StatusSafe
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                                border = BorderStroke(1.dp, accent.copy(alpha = 0.5f)),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Default.BugReport, contentDescription = null, tint = accent, modifier = Modifier.size(18.dp))
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text(
                                            text = if (mb.found) "MALWAREBAZAAR MATCH: ${mb.signature}" else "MALWAREBAZAAR",
                                            color = accent,
                                            fontSize = 12.sp,
                                            fontFamily = MonoFontFamily,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                    if (mb.found) {
                                        Text("File: ${mb.fileName} (${mb.fileType}, ${mb.fileSizeBytes} bytes)", color = OffWhite, fontSize = 12.sp, fontFamily = MonoFontFamily)
                                        if (mb.firstSeen.isNotBlank()) Text("First Seen: ${mb.firstSeen}", color = SlateGrey, fontSize = 11.sp, fontFamily = MonoFontFamily)
                                        if (mb.tags.isNotEmpty()) Text("Tags: ${mb.tags.joinToString(", ")}", color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily)
                                    } else {
                                        Text(mb.note.ifBlank { "No match found." }, color = SlateGrey, fontSize = 12.sp)
                                    }
                                }
                            }
                        }
                    }

                    vtReport?.let { vt ->
                        item {
                            val accent = if (vt.maliciousCount > 0) StatusRisk else StatusSafe
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                                border = BorderStroke(1.dp, accent.copy(alpha = 0.5f)),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text(
                                        text = "VIRUSTOTAL v3 (${vt.maliciousCount}/${vt.totalEngines} MALICIOUS)",
                                        color = accent,
                                        fontSize = 12.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        text = "Suspicious: ${vt.suspiciousCount} • Harmless: ${vt.harmlessCount} • Undetected: ${vt.undetectedCount}",
                                        color = OffWhite,
                                        fontSize = 12.sp,
                                        fontFamily = MonoFontFamily
                                    )
                                    if (vt.popularThreatName.isNotBlank()) {
                                        Text(text = "Threat Label: ${vt.popularThreatName}", color = StatusWarning, fontSize = 12.sp, fontFamily = MonoFontFamily)
                                    }
                                }
                            }
                        }
                    }

                    item { Spacer(modifier = Modifier.height(24.dp)) }
                }
            } else {
                // Offline Payload & JWT Lab
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    item { Spacer(modifier = Modifier.height(6.dp)) }

                    item {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            PayloadOperation.entries.forEach { op ->
                                FilterChip(
                                    selected = selectedOp == op,
                                    onClick = { selectedOp = op },
                                    label = { Text(op.label, fontSize = 11.sp, fontFamily = MonoFontFamily) },
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

                    item {
                        OutlinedTextField(
                            value = payloadInput,
                            onValueChange = { payloadInput = it },
                            placeholder = {
                                Text(
                                    text = when (selectedOp) {
                                        PayloadOperation.JWT_INSPECT -> "Paste eyJhbGciOi... JWT token here"
                                        PayloadOperation.EPOCH -> "Paste Unix timestamp (e.g. 1700000000)"
                                        else -> "Paste text, Base64, Hex, URL-encoded string, or payload..."
                                    },
                                    color = MutedSlate,
                                    fontSize = 12.sp
                                )
                            },
                            minLines = 3,
                            maxLines = 7,
                            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily, color = OffWhite),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedContainerColor = CharcoalNavy,
                                unfocusedContainerColor = CharcoalNavy,
                                focusedBorderColor = SkyCyan,
                                unfocusedBorderColor = CardBorder
                            ),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("payload_lab_input")
                        )
                    }

                    if (payloadInput.isNotBlank()) {
                        item {
                            when (selectedOp) {
                                PayloadOperation.JWT_INSPECT -> {
                                    val res = remember(payloadInput) { PayloadDecoder.inspectJwt(payloadInput) }
                                    res.fold(
                                        onSuccess = { jwt ->
                                            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                                if (jwt.securityWarnings.isNotEmpty()) {
                                                    Card(
                                                        colors = CardDefaults.cardColors(containerColor = DarkerSurface),
                                                        border = BorderStroke(1.dp, StatusWarning.copy(alpha = 0.5f)),
                                                        shape = RoundedCornerShape(10.dp),
                                                        modifier = Modifier.fillMaxWidth()
                                                    ) {
                                                        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                                            jwt.securityWarnings.forEach { warn ->
                                                                Row(verticalAlignment = Alignment.CenterVertically) {
                                                                    Icon(Icons.Default.Warning, contentDescription = null, tint = StatusWarning, modifier = Modifier.size(14.dp))
                                                                    Spacer(modifier = Modifier.width(6.dp))
                                                                    Text(warn, color = OffWhite, fontSize = 11.sp)
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                Text("Algorithm: ${jwt.algorithm} • Expires: ${jwt.expiresAtReadable}", color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily)
                                                Text("HEADER", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                                                CodeBlock(code = jwt.headerJson)
                                                Text("PAYLOAD CLAIMS", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                                                CodeBlock(code = jwt.payloadJson)
                                            }
                                        },
                                        onFailure = { err ->
                                            Text(err.message ?: "Invalid JWT", color = StatusRisk, fontSize = 12.sp, fontFamily = MonoFontFamily)
                                        }
                                    )
                                }

                                PayloadOperation.HASH_GEN -> {
                                    val bundle = remember(payloadInput) { PayloadDecoder.computeHashes(payloadInput) }
                                    val output = "MD5:\n${bundle.md5}\n\nSHA-1:\n${bundle.sha1}\n\nSHA-256:\n${bundle.sha256}"
                                    PayloadOutputCard(context = context, title = "CRYPTOGRAPHIC DIGESTS", output = output)
                                }

                                else -> {
                                    val transformed: Result<String> = remember(payloadInput, selectedOp) {
                                        when (selectedOp) {
                                            PayloadOperation.BASE64_DECODE -> PayloadDecoder.decodeBase64(payloadInput)
                                            PayloadOperation.BASE64_ENCODE -> Result.success(PayloadDecoder.encodeBase64(payloadInput))
                                            PayloadOperation.HEX_DECODE -> PayloadDecoder.decodeHex(payloadInput)
                                            PayloadOperation.HEX_ENCODE -> Result.success(PayloadDecoder.encodeHex(payloadInput))
                                            PayloadOperation.URL_DECODE -> PayloadDecoder.decodeUrl(payloadInput)
                                            PayloadOperation.URL_ENCODE -> Result.success(PayloadDecoder.encodeUrl(payloadInput))
                                            PayloadOperation.ROT13 -> Result.success(PayloadDecoder.rot13(payloadInput))
                                            PayloadOperation.EPOCH -> PayloadDecoder.decodeEpoch(payloadInput)
                                            else -> Result.success("")
                                        }
                                    }
                                    transformed.fold(
                                        onSuccess = { out ->
                                            PayloadOutputCard(context = context, title = "${selectedOp.label.uppercase()} OUTPUT", output = out)
                                        },
                                        onFailure = { err ->
                                            Text(err.message ?: "Decode error", color = StatusRisk, fontSize = 12.sp, fontFamily = MonoFontFamily)
                                        }
                                    )
                                }
                            }
                        }
                    }

                    item { Spacer(modifier = Modifier.height(24.dp)) }
                }
            }
        }
    }
}

@Composable
private fun PayloadOutputCard(
    context: Context,
    title: String,
    output: String
) {
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
                Text(title, color = MatrixGreen, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                IconButton(
                    onClick = {
                        SafeBrowserLauncher.copyToClipboard(context, title, output, isSensitive = true)
                        Toast.makeText(context, "Copied output", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy output", tint = SkyCyan, modifier = Modifier.size(16.dp))
                }
            }
            CodeBlock(code = output)
        }
    }
}
