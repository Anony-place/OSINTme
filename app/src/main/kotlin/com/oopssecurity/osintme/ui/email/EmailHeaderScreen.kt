package com.oopssecurity.osintme.ui.email

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.MarkEmailRead
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.model.EmailSecurityAudit
import com.oopssecurity.osintme.data.network.ByokAiService
import com.oopssecurity.osintme.data.network.CloudflareDohService
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.SaveToCaseDialog
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
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.EmailHeaderAnalyzer
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType
import kotlinx.coroutines.launch

@Composable
fun EmailHeaderScreen(
    onBackClick: () -> Unit,
    onPivot: (PivotEntity) -> Unit,
    onOpenApiVault: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val activeAi by ApiKeyVault.activeAiProvider.collectAsStateWithLifecycle()

    var rawHeaders by remember { mutableStateOf("") }
    var liveDomainPolicy by remember { mutableStateOf<EmailSecurityAudit?>(null) }
    var isCheckingDns by remember { mutableStateOf(false) }
    var showSaveDialog by remember { mutableStateOf(false) }
    var aiVerdictText by remember { mutableStateOf<String?>(null) }
    var aiVerdictMeta by remember { mutableStateOf<String?>(null) }
    var aiVerdictError by remember { mutableStateOf<String?>(null) }
    var isAiAnalyzing by remember { mutableStateOf(false) }

    val report = remember(rawHeaders) {
        if (rawHeaders.isBlank()) null else EmailHeaderAnalyzer.analyze(rawHeaders)
    }

    if (showSaveDialog && report != null) {
        SaveToCaseDialog(
            wingType = "EMAIL_FORENSICS",
            artifactType = "HEADER_ANALYSIS",
            queryTarget = report.fromDomain.ifBlank { report.fromAddress },
            title = "Email Header Forensics: ${report.subject.take(40)}",
            summary = "Verdict: ${report.riskVerdict} • From: ${report.fromAddress} • Hops: ${report.hops.size} • Alerts: ${report.spoofingAlerts.size}",
            sourceApi = "Local RFC-5322 Parser + Cloudflare DoH",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Email Header Forensics",
                subtitle = "Trace mail relay hops & detect spoofing/BEC",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (report != null) {
                    {
                        IconButton(
                            onClick = { showSaveDialog = true },
                            modifier = Modifier.size(48.dp).testTag("email_header_save_case_button")
                        ) {
                            Icon(Icons.Default.BookmarkAdd, contentDescription = "Save header report", tint = SkyCyan)
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
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item { Spacer(modifier = Modifier.height(4.dp)) }

            // Header Paste Input
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
                                text = "RAW EMAIL HEADERS (SHOW ORIGINAL)",
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
                                            if (pasted.isNotBlank()) {
                                                rawHeaders = pasted
                                                liveDomainPolicy = null
                                            }
                                        }
                                    }
                                    .padding(horizontal = 8.dp, vertical = 5.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.ContentPaste, contentDescription = "Paste headers", tint = SoftIndigo, modifier = Modifier.size(13.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Paste", color = SoftIndigo, fontSize = 11.sp, fontWeight = FontWeight.Medium)
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        OutlinedTextField(
                            value = rawHeaders,
                            onValueChange = {
                                rawHeaders = it
                                liveDomainPolicy = null
                            },
                            placeholder = {
                                Text(
                                    text = "Paste Received:, Authentication-Results:, From:, Return-Path:, Reply-To: headers here...",
                                    color = MutedSlate,
                                    fontSize = 12.sp
                                )
                            },
                            minLines = 4,
                            maxLines = 8,
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
                                .testTag("email_header_input")
                        )
                    }
                }
            }

            if (report != null) {
                // Spoofing Verdict & Metadata Card
                item {
                    val verdictColor = when (report.riskVerdict) {
                        "HIGH" -> StatusRisk
                        "MEDIUM" -> StatusWarning
                        else -> StatusSafe
                    }
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                        border = BorderStroke(1.dp, verdictColor.copy(alpha = 0.5f)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = if (report.riskVerdict == "LOW") Icons.Default.MarkEmailRead else Icons.Default.Warning,
                                        contentDescription = null,
                                        tint = verdictColor,
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = "SPOOFING RISK: ${report.riskVerdict}",
                                        color = verdictColor,
                                        fontSize = 13.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                report.totalTransitSeconds?.let { sec ->
                                    Text(
                                        text = "Transit: ${sec}s",
                                        color = SlateGrey,
                                        fontSize = 11.sp,
                                        fontFamily = MonoFontFamily
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(10.dp))
                            HeaderKv("Subject", report.subject)
                            HeaderKv("From", report.fromAddress) {
                                if (report.fromAddress.contains("@")) {
                                    onPivot(PivotEngine.normalize(report.fromAddress, PivotEntityType.EMAIL, "Email Header From"))
                                }
                            }
                            if (report.returnPath.isNotBlank()) HeaderKv("Return-Path", report.returnPath)
                            if (report.replyTo.isNotBlank()) HeaderKv("Reply-To", report.replyTo)
                            if (!report.originatingIp.isNullOrBlank()) {
                                HeaderKv("X-Originating-IP", report.originatingIp) {
                                    onPivot(PivotEngine.normalize(report.originatingIp, PivotEntityType.IP_ADDRESS, "X-Originating-IP"))
                                }
                            }
                            if (report.xMailer.isNotBlank()) HeaderKv("Client / Mailer", report.xMailer)

                            if (report.spoofingAlerts.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(10.dp))
                                report.spoofingAlerts.forEach { alert ->
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(vertical = 3.dp)
                                            .clip(RoundedCornerShape(6.dp))
                                            .background(verdictColor.copy(alpha = 0.12f))
                                            .padding(8.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Icon(Icons.Default.Warning, contentDescription = null, tint = verdictColor, modifier = Modifier.size(14.dp))
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text(text = alert, color = OffWhite, fontSize = 11.sp, lineHeight = 16.sp)
                                    }
                                }
                            }

                            // Live DNS Policy Verification Button
                            if (report.fromDomain.contains(".")) {
                                Spacer(modifier = Modifier.height(10.dp))
                                Button(
                                    onClick = {
                                        isCheckingDns = true
                                        scope.launch {
                                            liveDomainPolicy = CloudflareDohService.auditEmailSecurity(report.fromDomain).getOrNull()
                                            isCheckingDns = false
                                        }
                                    },
                                    enabled = !isCheckingDns,
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = EmeraldPrimary,
                                        contentColor = PureWhite,
                                        disabledContainerColor = SurfaceElevated,
                                        disabledContentColor = MutedSlate
                                    ),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .testTag("email_verify_dns_button")
                                ) {
                                    if (isCheckingDns) {
                                        CircularProgressIndicator(
                                            color = PureWhite,
                                            modifier = Modifier.size(15.dp),
                                            strokeWidth = 2.dp
                                        )
                                    } else {
                                        Icon(Icons.Default.Dns, contentDescription = null, modifier = Modifier.size(16.dp))
                                    }
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Verify Live SPF/DMARC for ${report.fromDomain}", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                }
                            }

                            liveDomainPolicy?.let { audit ->
                                Spacer(modifier = Modifier.height(10.dp))
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(8.dp))
                                        .background(DarkerSurface)
                                        .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                                        .padding(10.dp)
                                ) {
                                    Text(
                                        text = "LIVE DNS POLICY (${audit.domain}) — GRADE ${audit.grade}",
                                        color = SkyCyan,
                                        fontSize = 10.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(text = audit.riskSummary, color = OffWhite, fontSize = 12.sp)
                                    if (audit.spfRecord.isNotBlank()) {
                                        Text(text = "SPF: ${audit.spfRecord}", color = SlateGrey, fontSize = 10.sp, fontFamily = MonoFontFamily)
                                    }
                                    if (audit.dmarcRecord.isNotBlank()) {
                                        Text(text = "DMARC: ${audit.dmarcRecord}", color = SlateGrey, fontSize = 10.sp, fontFamily = MonoFontFamily)
                                    }
                                }
                            }
                        }
                    }
                }

                // BYOK AI Phishing & Spoofing Verdict Card
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = EmeraldSoft),
                        border = BorderStroke(1.dp, EmeraldBorder),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "BYOK AI PHISHING & BEC VERDICT",
                                        color = EmeraldDeep,
                                        fontSize = 10.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                Text(
                                    text = activeAi?.shortBadge ?: "NO KEY",
                                    color = if (activeAi != null) EmeraldPrimary else MutedSlate,
                                    fontSize = 10.sp,
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold
                                )
                            }

                            Spacer(modifier = Modifier.height(6.dp))
                            if (!aiVerdictText.isNullOrBlank()) {
                                if (!aiVerdictMeta.isNullOrBlank()) {
                                    Text(aiVerdictMeta!!, color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
                                    Spacer(modifier = Modifier.height(4.dp))
                                }
                                Text(aiVerdictText!!, color = InkBlack, fontSize = 12.5.sp, lineHeight = 19.sp)
                            } else {
                                Text(
                                    text = "Send parsed hops, SPF/DKIM/DMARC alignment, and Return-Path anomalies to your connected LLM for a SOC phishing/BEC verdict.",
                                    color = SlateGrey,
                                    fontSize = 12.sp
                                )
                            }

                            if (!aiVerdictError.isNullOrBlank()) {
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(aiVerdictError!!, color = StatusRisk, fontSize = 11.sp)
                            }

                            Spacer(modifier = Modifier.height(10.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = {
                                        if (ApiKeyVault.getActiveAiConfig() == null) {
                                            aiVerdictError = "Connect your own AI key in AI Vault first."
                                            return@Button
                                        }
                                        isAiAnalyzing = true
                                        aiVerdictError = null
                                        scope.launch {
                                            val summary = buildString {
                                                appendLine("Subject: ${report.subject}")
                                                appendLine("From: ${report.fromAddress} (domain: ${report.fromDomain})")
                                                appendLine("Return-Path: ${report.returnPath} (domain: ${report.returnPathDomain})")
                                                appendLine("Reply-To: ${report.replyTo} (domain: ${report.replyToDomain})")
                                                appendLine("Originating IP: ${report.originatingIp ?: "None"} | Risk Verdict: ${report.riskVerdict}")
                                                appendLine("Auth Checks: ${report.authChecks.joinToString("; ") { "${it.mechanism}=${it.status} (${it.detail})" }}")
                                                appendLine("Spoofing Alerts: ${report.spoofingAlerts.joinToString("; ")}")
                                                appendLine("Hops (${report.hops.size}):")
                                                report.hops.forEach { h ->
                                                    appendLine("  Hop #${h.hopNumber}: from ${h.fromHost} [${h.ipAddress ?: "no-ip"}] by ${h.byHost} delay=${h.delaySeconds ?: 0}s anomaly=${h.isDelayAnomaly}")
                                                }
                                                liveDomainPolicy?.let { p ->
                                                    appendLine("Live DNS Policy Grade ${p.grade}: SPF=${p.spfRecord} DMARC=${p.dmarcRecord}")
                                                }
                                            }
                                            ByokAiService.analyzeEmailHeaders(summary).fold(
                                                onSuccess = { res ->
                                                    aiVerdictText = res.text
                                                    aiVerdictMeta = "${res.providerName} • ${res.modelId} • ${res.latencyMs}ms"
                                                },
                                                onFailure = { aiVerdictError = it.message ?: "AI verdict failed" }
                                            )
                                            isAiAnalyzing = false
                                        }
                                    },
                                    enabled = !isAiAnalyzing,
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = EmeraldPrimary,
                                        contentColor = PureWhite,
                                        disabledContainerColor = SurfaceElevated,
                                        disabledContentColor = MutedSlate
                                    ),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier
                                        .weight(1f)
                                        .testTag("email_ai_verdict_button")
                                ) {
                                    if (isAiAnalyzing) {
                                        CircularProgressIndicator(color = PureWhite, modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text("Analyzing...", fontSize = 12.sp)
                                    } else {
                                        Icon(Icons.Default.AutoAwesome, contentDescription = null, modifier = Modifier.size(15.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(if (aiVerdictText == null) "Run AI Phishing Verdict" else "Re-Run Verdict", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                                    }
                                }
                                if (activeAi == null) {
                                    OutlinedButton(
                                        onClick = onOpenApiVault,
                                        border = BorderStroke(1.dp, EmeraldPrimary),
                                        colors = ButtonDefaults.outlinedButtonColors(containerColor = PureWhite, contentColor = EmeraldDeep),
                                        shape = RoundedCornerShape(8.dp)
                                    ) {
                                        Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(14.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("AI Key", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                        }
                    }
                }

                // Authentication Results Badges
                if (report.authChecks.isNotEmpty()) {
                    item {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                            border = BorderStroke(1.dp, CardBorder),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(
                                    text = "AUTHENTICATION-RESULTS BREAKDOWN",
                                    color = SkyCyan,
                                    fontSize = 10.sp,
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold
                                )
                                report.authChecks.forEach { check ->
                                    val color = when (check.status) {
                                        "PASS" -> StatusSafe
                                        "FAIL", "PERMERROR" -> StatusRisk
                                        else -> StatusWarning
                                    }
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clip(RoundedCornerShape(8.dp))
                                            .background(DarkerSurface)
                                            .padding(10.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = check.mechanism,
                                                color = OffWhite,
                                                fontSize = 12.sp,
                                                fontFamily = MonoFontFamily,
                                                fontWeight = FontWeight.Bold
                                            )
                                            Text(text = check.detail, color = SlateGrey, fontSize = 10.sp, fontFamily = MonoFontFamily)
                                        }
                                        Box(
                                            modifier = Modifier
                                                .clip(RoundedCornerShape(5.dp))
                                                .background(color.copy(alpha = 0.16f))
                                                .padding(horizontal = 8.dp, vertical = 3.dp)
                                        ) {
                                            Text(
                                                text = check.status,
                                                color = color,
                                                fontSize = 10.sp,
                                                fontFamily = MonoFontFamily,
                                                fontWeight = FontWeight.Bold
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Chronological Mail Hop Timeline
                if (report.hops.isNotEmpty()) {
                    item {
                        Text(
                            text = "CHRONOLOGICAL MAIL RELAY HOPS (${report.hops.size})",
                            color = SkyCyan,
                            fontSize = 11.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    items(report.hops, key = { it.hopNumber }) { hop ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                            border = BorderStroke(
                                1.dp,
                                if (hop.isDelayAnomaly) StatusWarning.copy(alpha = 0.6f) else CardBorder
                            ),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "HOP #${hop.hopNumber} • ${hop.protocol}",
                                        color = SkyCyan,
                                        fontSize = 10.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                    hop.delaySeconds?.let { delay ->
                                        Text(
                                            text = if (delay >= 0) "+${delay}s" else "${delay}s (skew)",
                                            color = if (hop.isDelayAnomaly) StatusWarning else MatrixGreen,
                                            fontSize = 10.sp,
                                            fontFamily = MonoFontFamily,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(text = "From: ${hop.fromHost}", color = OffWhite, fontSize = 12.sp, fontFamily = MonoFontFamily)
                                Text(text = "By:   ${hop.byHost}", color = SlateGrey, fontSize = 12.sp, fontFamily = MonoFontFamily)
                                if (!hop.ipAddress.isNullOrBlank()) {
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Row(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(6.dp))
                                            .background(SurfaceElevated)
                                            .border(1.dp, SkyCyan.copy(alpha = 0.4f), RoundedCornerShape(6.dp))
                                            .clickable {
                                                onPivot(
                                                    PivotEngine.normalize(
                                                        hop.ipAddress,
                                                        PivotEntityType.IP_ADDRESS,
                                                        "Mail Hop #${hop.hopNumber}"
                                                    )
                                                )
                                            }
                                            .padding(horizontal = 8.dp, vertical = 5.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = "Pivot Hop IP", tint = SkyCyan, modifier = Modifier.size(13.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = "Pivot Relay IP: ${hop.ipAddress}",
                                            color = SkyCyan,
                                            fontSize = 11.sp,
                                            fontFamily = MonoFontFamily,
                                            fontWeight = FontWeight.SemiBold
                                        )
                                    }
                                }
                                if (hop.rawTimestamp.isNotBlank()) {
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(text = hop.rawTimestamp, color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
                                }
                            }
                        }
                    }
                }
            }

            item { Spacer(modifier = Modifier.height(24.dp)) }
        }
    }
}

@Composable
private fun HeaderKv(label: String, value: String, onTap: (() -> Unit)? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onTap != null) Modifier.clickable { onTap() } else Modifier)
            .padding(vertical = 2.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text = label,
            color = MutedSlate,
            fontSize = 11.sp,
            fontFamily = DisplayFontFamily,
            modifier = Modifier.width(105.dp)
        )
        Text(
            text = value,
            color = if (onTap != null) SkyCyan else OffWhite,
            fontSize = 12.sp,
            fontFamily = MonoFontFamily,
            modifier = Modifier.weight(1f)
        )
    }
}
