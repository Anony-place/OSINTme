package com.oopssecurity.osintme.ui.dossier

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
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
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.ui.theme.EmeraldBorder
import com.oopssecurity.osintme.ui.theme.EmeraldDeep
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.EmeraldSoft
import com.oopssecurity.osintme.ui.theme.InkBlack
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType
import com.oopssecurity.osintme.util.SafeBrowserLauncher
import kotlinx.coroutines.launch

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun TargetDossierScreen(
    initialTarget: String = "",
    onBackClick: () -> Unit,
    onOpenApiVault: () -> Unit,
    onOpenCase: (String) -> Unit,
    onPivot: (PivotEntity) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val focusManager = LocalFocusManager.current
    val scope = rememberCoroutineScope()
    val viewModel: TargetDossierViewModel = viewModel(key = "dossier_${initialTarget.ifBlank { "root" }}") {
        TargetDossierViewModel(context)
    }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    var showExportMenu by remember { mutableStateOf(false) }

    val saveHtmlLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/html")
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use { out ->
                    out.write(viewModel.exportDossierHtml().toByteArray(Charsets.UTF_8))
                }
                Toast.makeText(context, "HTML dossier saved", Toast.LENGTH_SHORT).show()
            }.onFailure {
                Toast.makeText(context, "Export failed: ${it.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    val saveJsonLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use { out ->
                    out.write(viewModel.exportDossierJson().toByteArray(Charsets.UTF_8))
                }
                Toast.makeText(context, "JSON dossier saved", Toast.LENGTH_SHORT).show()
            }.onFailure {
                Toast.makeText(context, "Export failed: ${it.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    LaunchedEffect(initialTarget) {
        if (initialTarget.isNotBlank() && uiState.normalizedTarget.isBlank()) {
            viewModel.setQuery(initialTarget)
            viewModel.runDossier(initialTarget)
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "One-Shot Target Dossier",
                subtitle = uiState.normalizedTarget.ifBlank { "Parallel multi-feed intelligence brief" },
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (uiState.normalizedTarget.isNotBlank()) {
                    {
                        Box {
                            IconButton(
                                onClick = { showExportMenu = true },
                                modifier = Modifier
                                    .size(48.dp)
                                    .testTag("dossier_export_menu_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Download,
                                    contentDescription = "Export dossier",
                                    tint = SkyCyan
                                )
                            }
                            DropdownMenu(
                                expanded = showExportMenu,
                                onDismissRequest = { showExportMenu = false },
                                containerColor = CharcoalNavy
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Save HTML Report (.html)", color = OffWhite, fontSize = 13.sp) },
                                    onClick = {
                                        showExportMenu = false
                                        val slug = uiState.normalizedTarget.replace(Regex("[^a-zA-Z0-9._-]"), "_").take(32)
                                        saveHtmlLauncher.launch("osintme_dossier_$slug.html")
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("Save Structured JSON (.json)", color = OffWhite, fontSize = 13.sp) },
                                    onClick = {
                                        showExportMenu = false
                                        val slug = uiState.normalizedTarget.replace(Regex("[^a-zA-Z0-9._-]"), "_").take(32)
                                        saveJsonLauncher.launch("osintme_dossier_$slug.json")
                                    }
                                )
                            }
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

            // Target Input Bar
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = uiState.inputQuery,
                        onValueChange = { viewModel.setQuery(it) },
                        placeholder = {
                            Text("Domain, IP, email, handle, name/org, URL, or hash...", color = MutedSlate, fontSize = 13.sp)
                        },
                        singleLine = true,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("dossier_target_input"),
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
                            viewModel.runDossier()
                        })
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = {
                            focusManager.clearFocus()
                            viewModel.runDossier()
                        },
                        enabled = uiState.inputQuery.isNotBlank(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = EmeraldPrimary,
                            contentColor = PureWhite,
                            disabledContainerColor = SurfaceElevated,
                            disabledContentColor = MutedSlate
                        ),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .height(54.dp)
                            .testTag("dossier_run_button")
                    ) {
                        if (uiState.isRunning) {
                            CircularProgressIndicator(
                                color = PureWhite,
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp
                            )
                        } else {
                            Icon(Icons.Default.Radar, contentDescription = "Run Dossier")
                        }
                    }
                }
            }

            // Live Feed Progress Strip
            if (uiState.feeds.isNotEmpty()) {
                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        uiState.feeds.forEach { feed ->
                            val (accent, icon) = when (feed.state) {
                                FeedState.RUNNING -> SkyCyan to null
                                FeedState.SUCCESS -> MatrixGreen to Icons.Default.CheckCircle
                                FeedState.NEEDS_KEY -> StatusWarning to Icons.Default.Key
                                FeedState.ERROR -> MutedSlate to Icons.Default.ErrorOutline
                            }
                            Row(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(CharcoalNavy)
                                    .border(1.dp, accent.copy(alpha = 0.45f), RoundedCornerShape(8.dp))
                                    .clickable(enabled = feed.state == FeedState.NEEDS_KEY) { onOpenApiVault() }
                                    .padding(horizontal = 10.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                if (feed.state == FeedState.RUNNING) {
                                    CircularProgressIndicator(
                                        color = SkyCyan,
                                        modifier = Modifier.size(12.dp),
                                        strokeWidth = 1.8.dp
                                    )
                                } else if (icon != null) {
                                    Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(13.dp))
                                }
                                Spacer(modifier = Modifier.width(6.dp))
                                Column {
                                    Text(
                                        text = feed.label,
                                        color = OffWhite,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.SemiBold
                                    )
                                    if (feed.note.isNotBlank()) {
                                        Text(
                                            text = feed.note,
                                            color = accent,
                                            fontSize = 9.sp,
                                            fontFamily = MonoFontFamily,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Intelligence Highlights Board (Instant real-world findings & Stage-2 Auto-Chain)
            if (uiState.normalizedTarget.isNotBlank()) {
                item {
                    IntelligenceHighlightsCard(
                        uiState = uiState,
                        onPivot = onPivot
                    )
                }
            }

            // BYOK AI Dossier Intelligence Synthesis Card
            if (uiState.normalizedTarget.isNotBlank()) {
                item {
                    val activeAi by ApiKeyVault.activeAiProvider.collectAsStateWithLifecycle()
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = EmeraldSoft),
                        border = BorderStroke(1.dp, EmeraldBorder),
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "BYOK AI INTELLIGENCE BRIEF",
                                        color = EmeraldDeep,
                                        fontSize = 11.sp,
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

                            if (uiState.aiInsight != null) {
                                val insight = uiState.aiInsight!!
                                Text(
                                    text = "${insight.providerName} • ${insight.modelId} • ${insight.latencyMs}ms",
                                    color = MutedSlate,
                                    fontSize = 10.sp,
                                    fontFamily = MonoFontFamily
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = insight.briefText,
                                    color = InkBlack,
                                    fontSize = 12.5.sp,
                                    lineHeight = 19.sp
                                )
                                if (insight.suggestedPivots.isNotEmpty()) {
                                    Spacer(modifier = Modifier.height(10.dp))
                                    Text(
                                        text = "AI-SUGGESTED NEXT PIVOTS (TAP TO PIVOT)",
                                        color = EmeraldDeep,
                                        fontSize = 10.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Spacer(modifier = Modifier.height(6.dp))
                                    FlowRow(
                                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                                        verticalArrangement = Arrangement.spacedBy(6.dp)
                                    ) {
                                        insight.suggestedPivots.forEach { piv ->
                                            Box(
                                                modifier = Modifier
                                                    .clip(RoundedCornerShape(6.dp))
                                                    .background(PureWhite)
                                                    .border(1.dp, EmeraldBorder, RoundedCornerShape(6.dp))
                                                    .clickable { onPivot(PivotEngine.normalize(piv, sourceContext = "BYOK AI Pivot")) }
                                                    .padding(horizontal = 8.dp, vertical = 5.dp)
                                            ) {
                                                Text(piv, color = InkBlack, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.SemiBold)
                                            }
                                        }
                                    }
                                }
                            } else {
                                Text(
                                    text = "Synthesize all resolved passive telemetry into an executive verdict and next passive pivot plan using your own AI API key.",
                                    color = SlateGrey,
                                    fontSize = 12.sp,
                                    lineHeight = 17.sp
                                )
                            }

                            if (!uiState.aiError.isNullOrBlank()) {
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(uiState.aiError!!, color = StatusRisk, fontSize = 11.sp)
                            }

                            Spacer(modifier = Modifier.height(10.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = { viewModel.analyzeWithByokAi() },
                                    enabled = !uiState.isAiAnalyzing,
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = EmeraldPrimary,
                                        contentColor = PureWhite,
                                        disabledContainerColor = SurfaceElevated,
                                        disabledContentColor = MutedSlate
                                    ),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier
                                        .weight(1f)
                                        .testTag("dossier_ai_analyze_button")
                                ) {
                                    if (uiState.isAiAnalyzing) {
                                        CircularProgressIndicator(color = EmeraldPrimary, modifier = Modifier.size(15.dp), strokeWidth = 2.dp)
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text("Synthesizing...", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                                    } else {
                                        Icon(Icons.Default.AutoAwesome, contentDescription = null, modifier = Modifier.size(15.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = if (uiState.aiInsight == null) "Analyze with AI" else "Re-Analyze",
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.SemiBold
                                        )
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
                                        Text("Setup AI", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Executive Risk & Action Card
            if (uiState.normalizedTarget.isNotBlank()) {
                item {
                    val verdictColor = when (uiState.riskVerdict) {
                        "HIGH" -> StatusRisk
                        "MEDIUM" -> StatusWarning
                        "LOW" -> StatusSafe
                        else -> SkyCyan
                    }
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                        border = BorderStroke(1.dp, verdictColor.copy(alpha = 0.45f)),
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                                    Icon(Icons.Default.Shield, contentDescription = null, tint = verdictColor, modifier = Modifier.size(22.dp))
                                    Spacer(modifier = Modifier.width(10.dp))
                                    Column {
                                        Text(
                                            text = uiState.normalizedTarget,
                                            color = OffWhite,
                                            fontSize = 15.sp,
                                            fontFamily = MonoFontFamily,
                                            fontWeight = FontWeight.Bold,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            text = "${if (uiState.isEntityKeyword) "PERSON / ORG" else uiState.entityType?.badgeLabel ?: "TARGET"} • ${uiState.feeds.count { it.state == FeedState.SUCCESS }}/${uiState.feeds.size} feeds resolved",
                                            color = SlateGrey,
                                            fontSize = 11.sp,
                                            fontFamily = MonoFontFamily
                                        )
                                    }
                                }
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(verdictColor.copy(alpha = 0.16f))
                                        .padding(horizontal = 10.dp, vertical = 4.dp)
                                ) {
                                    Text(
                                        text = if (uiState.isRunning) "SCANNING" else "RISK: ${uiState.riskVerdict}",
                                        color = verdictColor,
                                        fontSize = 11.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }

                            if (uiState.riskReasons.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(10.dp))
                                uiState.riskReasons.forEach { reason ->
                                    Row(
                                        modifier = Modifier.padding(vertical = 2.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Box(
                                            modifier = Modifier
                                                .size(6.dp)
                                                .clip(CircleShape)
                                                .background(verdictColor)
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text(text = reason, color = OffWhite, fontSize = 12.sp)
                                    }
                                }
                            }

                            Spacer(modifier = Modifier.height(12.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Button(
                                    onClick = {
                                        scope.launch {
                                            val id = uiState.savedCaseId ?: viewModel.saveFullDossierToNewCase()
                                            Toast.makeText(context, "Full dossier saved to Case", Toast.LENGTH_SHORT).show()
                                            onOpenCase(id)
                                        }
                                    },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = MatrixGreen,
                                        contentColor = SlateObsidian
                                    ),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier
                                        .weight(1f)
                                        .testTag("dossier_save_case_button")
                                ) {
                                    Icon(Icons.Default.BookmarkAdd, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = if (uiState.savedCaseId != null) "Open Saved Case" else "Save Full Dossier",
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }

                                OutlinedButton(
                                    onClick = onOpenApiVault,
                                    border = BorderStroke(1.dp, CardBorder),
                                    colors = ButtonDefaults.outlinedButtonColors(
                                        containerColor = SurfaceElevated,
                                        contentColor = SkyCyan
                                    ),
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(15.dp))
                                    Spacer(modifier = Modifier.width(5.dp))
                                    Text("API Vault", fontSize = 12.sp)
                                }
                            }
                        }
                    }
                }
            }

            // Universal Person / Org Entity Search Card
            uiState.entitySearch?.let { ent ->
                if (ent.wikiTitle.isNotBlank() || ent.githubProfiles.isNotEmpty() || ent.webMentions.isNotEmpty()) {
                    item {
                        EntitySearchCard(report = ent, onPivot = onPivot)
                    }
                }
            }

            // Deep Web & JS Scraper Card (SpiderFoot / LinkFinder)
            uiState.deepWebCrawl?.let { crawl ->
                if (crawl.emails.isNotEmpty() || crawl.socialLinks.isNotEmpty() || crawl.trackingIds.isNotEmpty() || crawl.apiEndpoints.isNotEmpty() || crawl.cloudBuckets.isNotEmpty()) {
                    item {
                        DeepWebCrawlCard(crawl = crawl, onPivot = onPivot)
                    }
                }
            }

            // Deep Identity, GitHub Commit Emails, Keybase & OpenPGP Card
            if (uiState.githubProfile != null || uiState.keybaseIdentity != null || uiState.emailFootprint != null) {
                item {
                    IdentityDeepIntelCard(
                        github = uiState.githubProfile,
                        keybase = uiState.keybaseIdentity,
                        emailFootprint = uiState.emailFootprint,
                        onPivot = onPivot
                    )
                }
            }

            // AlienVault OTX & Wayback CDX Card
            if (uiState.otxReport != null || uiState.waybackReport != null) {
                item {
                    OtxAndWaybackCard(
                        otx = uiState.otxReport,
                        wayback = uiState.waybackReport,
                        onPivot = onPivot
                    )
                }
            }

            // Live X.509 TLS Cert & Subdomain Takeover Card
            if (uiState.tlsCertReport != null || uiState.takeoverSummary != null) {
                item {
                    LiveTlsAndTakeoverCard(
                        tlsCert = uiState.tlsCertReport,
                        takeover = uiState.takeoverSummary,
                        onPivot = onPivot
                    )
                }
            }

            // Network, Shodan & BGP/ASN Card
            if (uiState.ipRecon != null || uiState.bgpAsn != null) {
                item {
                    DossierSectionCard(title = "NETWORK, PORTS & BGP/ASN", accent = SkyCyan) {
                        uiState.ipRecon?.let { ip ->
                            DossierKvRow("Resolved IP", ip.ip, onTap = {
                                onPivot(PivotEngine.normalize(ip.ip, PivotEntityType.IP_ADDRESS, "Dossier IP"))
                            })
                            DossierKvRow("Organization", ip.org)
                            DossierKvRow("Location", listOf(ip.city, ip.country).filter { it.isNotBlank() }.joinToString(", "))
                            if (ip.ports.isNotEmpty()) {
                                DossierKvRow("Open Ports", ip.ports.joinToString(", "))
                            }
                            if (ip.vulns.isNotEmpty()) {
                                DossierKvRow("CVEs", ip.vulns.take(6).joinToString(", "), valueColor = StatusRisk)
                            }
                        }
                        uiState.bgpAsn?.let { bgp ->
                            DossierKvRow("BGP Origin", "${bgp.asn} — ${bgp.holder}")
                            DossierKvRow("Routed Prefix", "${bgp.prefix} (${bgp.totalAnnouncedCount} total announced)")
                        }
                    }
                }
            }

            // Threat & BYOK Reputation Card
            if (uiState.urlhaus != null || uiState.virusTotal != null || uiState.abuseIpdb != null || uiState.malwareBazaar != null) {
                item {
                    DossierSectionCard(title = "THREAT & REPUTATION FEEDS", accent = StatusRisk) {
                        uiState.urlhaus?.let { uh ->
                            DossierKvRow(
                                "Cloudflare 1.1.1.2",
                                if (uh.cloudflareMalwareBlocked) "BLOCKED (Malware/Phishing)" else "Not blocked",
                                valueColor = if (uh.cloudflareMalwareBlocked) StatusRisk else StatusSafe
                            )
                            DossierKvRow("URLhaus Records", "${uh.urlCount} (${uh.queryStatus})")
                        }
                        uiState.virusTotal?.let { vt ->
                            DossierKvRow(
                                "VirusTotal v3",
                                "${vt.maliciousCount} malicious / ${vt.suspiciousCount} suspicious / ${vt.totalEngines} engines",
                                valueColor = if (vt.maliciousCount > 0) StatusRisk else StatusSafe
                            )
                            if (vt.popularThreatName.isNotBlank()) {
                                DossierKvRow("VT Threat Label", vt.popularThreatName)
                            }
                        }
                        uiState.abuseIpdb?.let { ab ->
                            DossierKvRow(
                                "AbuseIPDB v2",
                                "${ab.abuseConfidenceScore}% confidence (${ab.totalReports} reports, Tor: ${ab.isTor})",
                                valueColor = if (ab.abuseConfidenceScore >= 50) StatusRisk else if (ab.abuseConfidenceScore > 0) StatusWarning else StatusSafe
                            )
                        }
                        uiState.malwareBazaar?.let { mb ->
                            DossierKvRow(
                                "MalwareBazaar",
                                if (mb.found) "${mb.signature} — ${mb.fileName} (${mb.fileType})" else mb.note.ifBlank { "Not listed" },
                                valueColor = if (mb.found) StatusRisk else StatusSafe
                            )
                        }
                    }
                }
            }

            // Web Stack, TLS & Robots Card
            if (uiState.webTech != null || uiState.tlsAudit != null) {
                item {
                    DossierSectionCard(title = "WEB STACK, TLS & ROBOTS.TXT", accent = MatrixGreen) {
                        uiState.tlsAudit?.let { tls ->
                            DossierKvRow("TLS & Headers", "${tls.tlsProtocol} • Grade ${tls.securityGrade} (${tls.passedHeadersCount}/${tls.totalCheckedHeaders})")
                            if (tls.certIssuer.isNotBlank()) DossierKvRow("Cert Issuer", tls.certIssuer)
                        }
                        uiState.webTech?.let { web ->
                            if (web.pageTitle.isNotBlank()) DossierKvRow("Page Title", web.pageTitle)
                            if (web.technologies.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(6.dp))
                                FlowRow(
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    web.technologies.forEach { tech ->
                                        Box(
                                            modifier = Modifier
                                                .clip(RoundedCornerShape(6.dp))
                                                .background(DarkerSurface)
                                                .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                                                .padding(horizontal = 8.dp, vertical = 4.dp)
                                        ) {
                                            Text(
                                                text = "${tech.name} (${tech.category})",
                                                color = SkyCyan,
                                                fontSize = 10.sp,
                                                fontFamily = MonoFontFamily
                                            )
                                        }
                                    }
                                }
                            }
                            if (web.robotsDisallowed.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(6.dp))
                                DossierKvRow("robots.txt Disallow", web.robotsDisallowed.take(5).joinToString(", "))
                            }
                            if (web.securityContacts.isNotEmpty()) {
                                DossierKvRow("security.txt", web.securityContacts.first())
                            }
                        }
                    }
                }
            }

            // DNS, Subdomains, RDAP & URLScan
            if (uiState.subdomains != null || uiState.rdapInfo != null || uiState.urlScan != null || uiState.emailSecurity != null) {
                item {
                    DossierSectionCard(title = "DNS, SUBDOMAINS, WHOIS & URLSCAN", accent = SoftIndigo) {
                        uiState.emailSecurity?.let { mail ->
                            DossierKvRow(
                                "Email Auth",
                                "Grade ${mail.grade} • SPF=${mail.hasSpf} • DMARC=${mail.dmarcPolicy.ifBlank { "none" }}",
                                valueColor = if (mail.isSpoofable) StatusWarning else StatusSafe
                            )
                        }
                        uiState.rdapInfo?.let { rdap ->
                            DossierKvRow("Registrar", rdap.registrar)
                            if (rdap.registrationDate.isNotBlank()) DossierKvRow("Registered", rdap.registrationDate.take(10))
                            if (rdap.expirationDate.isNotBlank()) DossierKvRow("Expires", rdap.expirationDate.take(10))
                        }
                        uiState.subdomains?.let { subs ->
                            DossierKvRow("CT Subdomains", "${subs.totalCount} discovered")
                        }
                        uiState.urlScan?.let { us ->
                            DossierKvRow("URLScan History", "${us.totalHits} public sandbox scan(s)")
                        }
                    }
                }
            }

            // Identity, Breach, Redirects & Phone
            if (uiState.breachResult != null || uiState.gravatar != null || uiState.usernameHits.isNotEmpty() || uiState.redirectChain != null || uiState.phoneResult != null) {
                item {
                    DossierSectionCard(title = "IDENTITY, FOOTPRINT & TELEMETRY", accent = StatusWarning) {
                        uiState.breachResult?.let { br ->
                            DossierKvRow(
                                "Breach Exposure",
                                if (br.isBreached) "${br.totalBreaches} leak(s): ${br.breaches.take(5).joinToString(", ") { it.siteName }}" else "No known breaches",
                                valueColor = if (br.isBreached) StatusRisk else StatusSafe
                            )
                        }
                        uiState.gravatar?.let { grav ->
                            DossierKvRow("Gravatar Profile", grav.displayName.ifBlank { grav.preferredUsername })
                        }
                        if (uiState.usernameHits.isNotEmpty()) {
                            DossierKvRow(
                                "Confirmed Profiles",
                                "${uiState.usernameHits.size} found across ${uiState.usernameProbedCount} probed sites",
                                valueColor = MatrixGreen
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                uiState.usernameHits.take(18).forEach { hit ->
                                    Column(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(8.dp))
                                            .background(EmeraldSoft)
                                            .border(1.dp, EmeraldBorder, RoundedCornerShape(8.dp))
                                            .clickable {
                                                SafeBrowserLauncher.openExternalUrl(context, hit.profileUrl)
                                            }
                                            .padding(horizontal = 8.dp, vertical = 5.dp)
                                    ) {
                                        Text(
                                            text = hit.platformName,
                                            color = EmeraldDeep,
                                            fontSize = 11.sp,
                                            fontFamily = MonoFontFamily,
                                            fontWeight = FontWeight.Bold
                                        )
                                        if (!hit.metadata.isNullOrBlank()) {
                                            Text(
                                                text = hit.metadata.take(42),
                                                color = SlateGrey,
                                                fontSize = 9.sp,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        }
                                    }
                                }
                            }
                        }
                        uiState.redirectChain?.let { rc ->
                            DossierKvRow("Redirect Hops", "${rc.hops.size} hop(s) -> ${rc.finalUrl}")
                        }
                        uiState.phoneResult?.let { ph ->
                            DossierKvRow("E.164 Format", ph.e164Format)
                            DossierKvRow("Country / Type", "${ph.countryName} • ${ph.lineType}")
                            DossierKvRow("Timezone", ph.timezone)
                        }
                    }
                }
            }

            // Correlated Pivot Entities
            if (uiState.discoveredEntities.isNotEmpty()) {
                item {
                    DossierSectionCard(
                        title = "DISCOVERED PIVOT ENTITIES (${uiState.discoveredEntities.size})",
                        accent = SkyCyan
                    ) {
                        Text(
                            text = "Tap any discovered entity to pivot deeper or defang for reports.",
                            color = SlateGrey,
                            fontSize = 11.sp
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            uiState.discoveredEntities.forEach { entity ->
                                Row(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(8.dp))
                                        .background(SurfaceElevated)
                                        .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                                        .clickable { onPivot(entity) }
                                        .padding(horizontal = 10.dp, vertical = 7.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.AutoMirrored.Filled.CallSplit,
                                        contentDescription = "Pivot",
                                        tint = SkyCyan,
                                        modifier = Modifier.size(13.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "${entity.type.badgeLabel}: ${entity.normalizedValue}",
                                        color = OffWhite,
                                        fontSize = 11.sp,
                                        fontFamily = MonoFontFamily,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
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
private fun DossierSectionCard(
    title: String,
    accent: Color,
    content: @Composable () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        border = BorderStroke(1.dp, CardBorder),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = title,
                color = accent,
                fontSize = 11.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.8.sp
            )
            Spacer(modifier = Modifier.height(8.dp))
            content()
        }
    }
}

@Composable
private fun DossierKvRow(
    label: String,
    value: String,
    valueColor: Color = OffWhite,
    onTap: (() -> Unit)? = null
) {
    if (value.isBlank()) return
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onTap != null) Modifier.clickable { onTap() } else Modifier)
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text = label,
            color = MutedSlate,
            fontSize = 11.sp,
            fontFamily = DisplayFontFamily,
            modifier = Modifier.width(116.dp)
        )
        Text(
            text = value,
            color = valueColor,
            fontSize = 12.sp,
            fontFamily = MonoFontFamily,
            modifier = Modifier.weight(1f)
        )
    }
}
