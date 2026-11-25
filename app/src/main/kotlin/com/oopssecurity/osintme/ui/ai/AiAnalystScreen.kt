package com.oopssecurity.osintme.ui.ai

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.FolderSpecial
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.runtime.mutableStateListOf
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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.local.case.CaseRepository
import com.oopssecurity.osintme.data.model.InvestigationCase
import com.oopssecurity.osintme.data.network.AiChatMessage
import com.oopssecurity.osintme.data.network.ByokAiService
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
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.SafeBrowserLauncher
import kotlinx.coroutines.launch

private data class AnalystBubble(
    val id: String,
    val role: String,
    val content: String,
    val meta: String = ""
)

@Composable
fun AiAnalystScreen(
    initialPrompt: String = "",
    initialCaseId: String = "",
    onOpenVault: () -> Unit,
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val repo = remember(context) { CaseRepository(context) }

    val configuredAi by ApiKeyVault.configuredAiProviders.collectAsStateWithLifecycle()
    val activeProvider by ApiKeyVault.activeAiProvider.collectAsStateWithLifecycle()

    var cases by remember { mutableStateOf<List<InvestigationCase>>(emptyList()) }
    var attachedCase by remember { mutableStateOf<InvestigationCase?>(null) }
    var attachedCaseContext by remember { mutableStateOf("") }

    var inputDraft by remember { mutableStateOf(initialPrompt) }
    var isThinking by remember { mutableStateOf(false) }
    var errorBanner by remember { mutableStateOf<String?>(null) }
    var saveCandidateText by remember { mutableStateOf<String?>(null) }

    val bubbles = remember { mutableStateListOf<AnalystBubble>() }
    val listState = rememberLazyListState()

    LaunchedEffect(Unit) {
        val loaded = repo.getAllCases()
        cases = loaded
        if (initialCaseId.isNotBlank()) {
            val match = loaded.firstOrNull { it.id == initialCaseId }
            if (match != null) {
                attachedCase = match
                val arts = repo.getArtifactsForCase(match.id)
                attachedCaseContext = buildCaseContextDigest(match, arts)
            }
        }
    }

    fun attachCase(caseItem: InvestigationCase?) {
        attachedCase = caseItem
        if (caseItem == null) {
            attachedCaseContext = ""
            return
        }
        scope.launch {
            val arts = repo.getArtifactsForCase(caseItem.id)
            attachedCaseContext = buildCaseContextDigest(caseItem, arts)
            Toast.makeText(context, "Attached \"${caseItem.title}\" (${arts.size} artifacts)", Toast.LENGTH_SHORT).show()
        }
    }

    fun sendPrompt(rawText: String) {
        val prompt = rawText.trim()
        if (prompt.isBlank() || isThinking) return
        if (ApiKeyVault.getActiveAiConfig() == null) {
            errorBanner = "Connect your own OpenRouter, Claude, OpenAI, Gemini, or Groq key in AI Vault first."
            return
        }

        errorBanner = null
        bubbles.add(AnalystBubble("u_${System.currentTimeMillis()}", "user", prompt))
        inputDraft = ""
        isThinking = true

        scope.launch {
            val history = bubbles.map { AiChatMessage(role = it.role, content = it.content) }
            val sysPrompt = buildString {
                append(
                    "You are OSINTme AI Analyst, an expert passive OSINT & threat-intelligence copilot. " +
                        "Provide crisp, factual, structured defensive analysis with concrete passive next steps."
                )
                if (attachedCaseContext.isNotBlank()) {
                    append("\n\nATTACHED LOCAL CASE DOSSIER CONTEXT:\n")
                    append(attachedCaseContext.take(6500))
                }
            }

            ByokAiService.chat(messages = history, systemPrompt = sysPrompt, maxTokens = 950).fold(
                onSuccess = { res ->
                    bubbles.add(
                        AnalystBubble(
                            id = "a_${System.currentTimeMillis()}",
                            role = "assistant",
                            content = res.text,
                            meta = "${res.providerName} • ${res.modelId} • ${res.latencyMs}ms"
                        )
                    )
                    if (bubbles.isNotEmpty()) {
                        listState.animateScrollToItem(bubbles.lastIndex)
                    }
                },
                onFailure = { err ->
                    errorBanner = err.message ?: "AI request failed"
                }
            )
            isThinking = false
        }
    }

    if (saveCandidateText != null) {
        SaveToCaseDialog(
            wingType = "BYOK_AI_ANALYST",
            artifactType = "AI_BRIEF",
            queryTarget = attachedCase?.target ?: "OSINT AI Analysis",
            title = "AI Analyst Insight (${activeProvider?.displayName ?: "BYOK"})",
            summary = saveCandidateText!!.take(2200),
            sourceApi = activeProvider?.let { "${it.displayName} (${ApiKeyVault.getAiModel(it)})" } ?: "BYOK AI",
            onDismiss = { saveCandidateText = null }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = PureWhite,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "BYOK AI Analyst",
                subtitle = activeProvider?.let { "${it.displayName} • ${ApiKeyVault.getAiModel(it)}" }
                    ?: "Connect your own LLM API key",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (bubbles.isNotEmpty()) {
                            IconButton(onClick = { bubbles.clear(); errorBanner = null }) {
                                Icon(Icons.Default.Refresh, contentDescription = "New session", tint = InkBlack)
                            }
                        }
                        IconButton(onClick = onOpenVault) {
                            Icon(
                                Icons.Default.Key,
                                contentDescription = "Configure BYOK AI Keys",
                                tint = if (activeProvider != null) EmeraldPrimary else InkBlack
                            )
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .navigationBarsPadding()
                .imePadding()
        ) {
            // Provider Switcher Strip (if multiple BYOK AI keys configured)
            if (configuredAi.isNotEmpty()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 16.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    configuredAi.forEach { prov ->
                        val selected = prov == activeProvider
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .background(if (selected) EmeraldSoft else SurfaceElevated)
                                .border(1.dp, if (selected) EmeraldPrimary else CardBorder, RoundedCornerShape(8.dp))
                                .clickable { ApiKeyVault.setActiveAiProvider(prov) }
                                .padding(horizontal = 10.dp, vertical = 6.dp)
                        ) {
                            Text(
                                text = prov.shortBadge,
                                color = if (selected) EmeraldDeep else SlateGrey,
                                fontSize = 10.sp,
                                fontFamily = MonoFontFamily,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .background(PureWhite)
                            .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                            .clickable(onClick = onOpenVault)
                            .padding(horizontal = 10.dp, vertical = 6.dp)
                    ) {
                        Text("+ Add Provider", color = InkBlack, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.SemiBold)
                    }
                }
            } else {
                // First-run BYOK AI setup banner
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(EmeraldSoft)
                        .border(1.dp, EmeraldBorder, RoundedCornerShape(12.dp))
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Bring Your Own AI Key",
                            color = InkBlack,
                            fontSize = 14.sp,
                            fontFamily = DisplayFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "Connect OpenRouter, Claude, OpenAI, Gemini, Groq, DeepSeek, Mistral, Perplexity, or Custom URL.",
                            color = SlateGrey,
                            fontSize = 12.sp
                        )
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Button(
                        onClick = onOpenVault,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = EmeraldPrimary,
                            contentColor = PureWhite,
                            disabledContainerColor = SurfaceElevated,
                            disabledContentColor = MutedSlate
                        ),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.testTag("ai_chat_connect_key_button")
                    ) {
                        Text("Setup", color = PureWhite, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            // Optional Saved Case Dossier Context Strip
            if (cases.isNotEmpty()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.FolderSpecial, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(14.dp))
                    Text("CASE CONTEXT:", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                    if (attachedCase != null) {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(InkBlack)
                                .clickable { attachCase(null) }
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text("Clear", color = PureWhite, fontSize = 10.sp, fontFamily = MonoFontFamily)
                        }
                    }
                    cases.take(8).forEach { c ->
                        val isAttached = attachedCase?.id == c.id
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(if (isAttached) EmeraldSoft else CharcoalNavy)
                                .border(1.dp, if (isAttached) EmeraldPrimary else CardBorder, RoundedCornerShape(6.dp))
                                .clickable { attachCase(if (isAttached) null else c) }
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = c.title.take(24),
                                color = if (isAttached) EmeraldDeep else InkBlack,
                                fontSize = 11.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }

            HorizontalDivider(color = CardBorder)

            // Conversation Feed
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                if (bubbles.isEmpty()) {
                    item {
                        Spacer(modifier = Modifier.height(16.dp))
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(14.dp))
                                .background(CharcoalNavy)
                                .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                                .padding(16.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "OSINT AI Analyst Ready",
                                    color = InkBlack,
                                    fontSize = 15.sp,
                                    fontFamily = DisplayFontFamily,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "Attach any saved Case Dossier above or paste logs, headers, WHOIS, or indicators for instant correlation.",
                                color = SlateGrey,
                                fontSize = 12.sp,
                                lineHeight = 18.sp
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            val starters = listOf(
                                "Correlate all indicators in my attached case and list top 3 passive pivots",
                                "Build a defensive recon checklist for investigating a suspicious phishing domain",
                                "Explain how to spot BEC spoofing across SPF, DKIM, DMARC, and Return-Path headers",
                                "Generate Google & Shodan dorks to check exposed cloud storage and admin panels"
                            )
                            starters.forEach { starter ->
                                OutlinedButton(
                                    onClick = { sendPrompt(starter) },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 3.dp),
                                    border = BorderStroke(1.dp, CardBorder),
                                    colors = ButtonDefaults.outlinedButtonColors(containerColor = PureWhite, contentColor = InkBlack),
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    Text(
                                        text = starter,
                                        fontSize = 12.sp,
                                        modifier = Modifier.fillMaxWidth(),
                                        maxLines = 2,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                        }
                    }
                } else {
                    item { Spacer(modifier = Modifier.height(8.dp)) }
                    items(bubbles, key = { it.id }) { bubble ->
                        if (bubble.role == "user") {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth(0.86f)
                                        .clip(RoundedCornerShape(14.dp, 14.dp, 4.dp, 14.dp))
                                        .background(InkBlack)
                                        .padding(12.dp)
                                ) {
                                    Text(text = bubble.content, color = PureWhite, fontSize = 13.sp, lineHeight = 19.sp)
                                }
                            }
                        } else {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(14.dp, 14.dp, 14.dp, 4.dp))
                                    .background(CharcoalNavy)
                                    .border(1.dp, EmeraldBorder, RoundedCornerShape(14.dp, 14.dp, 14.dp, 4.dp))
                                    .padding(13.dp)
                            ) {
                                if (bubble.meta.isNotBlank()) {
                                    Text(
                                        text = bubble.meta,
                                        color = EmeraldDeep,
                                        fontSize = 10.sp,
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Spacer(modifier = Modifier.height(6.dp))
                                }
                                Text(text = bubble.content, color = InkBlack, fontSize = 13.sp, lineHeight = 20.sp)
                                Spacer(modifier = Modifier.height(8.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    OutlinedButton(
                                        onClick = {
                                            SafeBrowserLauncher.copyToClipboard(
                                                context = context,
                                                label = "AI Insight",
                                                text = bubble.content,
                                                isSensitive = true
                                            )
                                            Toast.makeText(context, "Copied response", Toast.LENGTH_SHORT).show()
                                        },
                                        border = BorderStroke(1.dp, CardBorder),
                                        colors = ButtonDefaults.outlinedButtonColors(contentColor = InkBlack),
                                        shape = RoundedCornerShape(6.dp),
                                        modifier = Modifier.heightIn(min = 34.dp)
                                    ) {
                                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(13.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Copy", fontSize = 11.sp)
                                    }
                                    OutlinedButton(
                                        onClick = { saveCandidateText = bubble.content },
                                        border = BorderStroke(1.dp, EmeraldPrimary),
                                        colors = ButtonDefaults.outlinedButtonColors(contentColor = EmeraldDeep),
                                        shape = RoundedCornerShape(6.dp),
                                        modifier = Modifier.heightIn(min = 34.dp)
                                    ) {
                                        Icon(Icons.Default.BookmarkAdd, contentDescription = null, modifier = Modifier.size(13.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Save to Case", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                                    }
                                }
                            }
                        }
                    }
                }

                if (isThinking) {
                    item {
                        Row(
                            modifier = Modifier
                                .clip(RoundedCornerShape(10.dp))
                                .background(EmeraldSoft)
                                .border(1.dp, EmeraldBorder, RoundedCornerShape(10.dp))
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp, color = EmeraldPrimary)
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = "Querying ${activeProvider?.displayName ?: "BYOK AI"}...",
                                color = EmeraldDeep,
                                fontSize = 12.sp,
                                fontFamily = MonoFontFamily
                            )
                        }
                    }
                }

                if (!errorBanner.isNullOrBlank()) {
                    item {
                        Text(
                            text = errorBanner!!,
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

                item { Spacer(modifier = Modifier.height(8.dp)) }
            }

            // Bottom Composer
            HorizontalDivider(color = CardBorder)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(PureWhite)
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = inputDraft,
                    onValueChange = { inputDraft = it },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("ai_chat_input"),
                    placeholder = { Text("Ask your OSINT AI analyst...", color = MutedSlate, fontSize = 13.sp) },
                    maxLines = 4,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = CharcoalNavy,
                        unfocusedContainerColor = CharcoalNavy,
                        focusedBorderColor = InkBlack,
                        unfocusedBorderColor = CardBorder,
                        focusedTextColor = InkBlack,
                        unfocusedTextColor = InkBlack
                    ),
                    shape = RoundedCornerShape(10.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Button(
                    onClick = { sendPrompt(inputDraft) },
                    enabled = inputDraft.isNotBlank() && !isThinking,
                    contentPadding = PaddingValues(0.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .size(50.dp)
                        .testTag("ai_chat_send_button")
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.Send,
                        contentDescription = "Send message",
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        }
    }
}

private fun buildCaseContextDigest(
    caseItem: InvestigationCase,
    artifacts: List<com.oopssecurity.osintme.data.model.ScanArtifact>
): String {
    return buildString {
        appendLine("Case: ${caseItem.title}")
        appendLine("Primary Target: ${caseItem.target}")
        if (caseItem.notes.isNotBlank()) appendLine("Notes: ${caseItem.notes}")
        appendLine("Artifacts (${artifacts.size}):")
        artifacts.take(20).forEachIndexed { idx, art ->
            appendLine("${idx + 1}. [${art.wingType}/${art.artifactType}] ${art.title} — Target: ${art.queryTarget}")
            appendLine("   Summary: ${art.summary.take(350)}")
        }
    }
}
