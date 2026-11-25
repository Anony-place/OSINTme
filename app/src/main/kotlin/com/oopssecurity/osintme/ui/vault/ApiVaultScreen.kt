package com.oopssecurity.osintme.ui.vault

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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oopssecurity.osintme.data.local.ActiveAiConfig
import com.oopssecurity.osintme.data.local.AiProvider
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.local.ApiProvider
import com.oopssecurity.osintme.data.local.CUSTOM_ENDPOINT_PRESETS
import com.oopssecurity.osintme.data.model.ApiKeyTestResult
import com.oopssecurity.osintme.data.network.AiConnectionTestResult
import com.oopssecurity.osintme.data.network.ByokAiService
import com.oopssecurity.osintme.data.network.ProThreatApiServices
import java.net.URI
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
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

@Composable
fun ApiVaultScreen(
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val configuredThreat by ApiKeyVault.configuredProviders.collectAsStateWithLifecycle()
    val configuredAi by ApiKeyVault.configuredAiProviders.collectAsStateWithLifecycle()
    val activeAi by ApiKeyVault.activeAiProvider.collectAsStateWithLifecycle()
    val vaultVersion by ApiKeyVault.vaultVersion.collectAsStateWithLifecycle()

    var selectedTab by remember { mutableIntStateOf(0) } // 0 = BYOK AI Models, 1 = Threat Intel Feeds

    // AI provider test states
    val aiTesting = remember { mutableStateMapOf<AiProvider, Boolean>() }
    val aiTestResults = remember { mutableStateMapOf<AiProvider, AiConnectionTestResult>() }

    // Threat provider test states
    val threatTesting = remember { mutableStateMapOf<ApiProvider, Boolean>() }
    val threatTestResults = remember { mutableStateMapOf<ApiProvider, ApiKeyTestResult>() }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = PureWhite,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "AI & API Key Vault",
                subtitle = "100% your own keys • Hardware AES-256-GCM",
                showBackButton = true,
                onBackClick = onBackClick
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .navigationBarsPadding()
        ) {
            // Segmented Switcher: BYOK AI Providers vs Threat Intel Feeds
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(SurfaceElevated)
                    .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                    .padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                VaultTabButton(
                    label = "BYOK AI (${configuredAi.size}/10)",
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("vault_tab_ai")
                )
                VaultTabButton(
                    label = "Threat Feeds (${configuredThreat.size}/5)",
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("vault_tab_threat")
                )
            }

            if (selectedTab == 0) {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    item {
                        ActiveAiBanner(
                            activeProvider = activeAi,
                            configuredCount = configuredAi.size,
                            vaultVersion = vaultVersion
                        )
                    }

                    items(AiProvider.entries, key = { it.id }) { provider ->
                        val isSaved = provider in configuredAi
                        val isActive = activeAi == provider
                        val savedEndpoint = remember(provider.id, vaultVersion) { ApiKeyVault.getAiEndpoint(provider) }
                        val savedModel = remember(provider.id, vaultVersion) { ApiKeyVault.getAiModel(provider) }
                        val hasCustomUrl = remember(provider.id, vaultVersion) { ApiKeyVault.hasCustomEndpoint(provider) }
                        AiProviderCard(
                            provider = provider,
                            isSaved = isSaved,
                            isActive = isActive,
                            hasCustomEndpoint = hasCustomUrl,
                            maskedPreview = if (isSaved) ApiKeyVault.getAiMaskedPreview(provider) else null,
                            initialModel = savedModel,
                            initialCustomUrl = savedEndpoint,
                            isTesting = aiTesting[provider] == true,
                            testResult = aiTestResults[provider],
                            onSave = { rawKey, modelId, customUrl ->
                                val candidateUrl = customUrl.trim().ifBlank { provider.defaultBaseUrl }
                                val validUrl = ByokAiService.validateEndpointUrl(candidateUrl, provider.protocol)
                                if (validUrl.isFailure) {
                                    val msg = validUrl.exceptionOrNull()?.message ?: "Invalid HTTPS endpoint URL"
                                    aiTestResults[provider] = AiConnectionTestResult(
                                        provider = provider,
                                        modelId = modelId.trim().ifBlank { provider.defaultModel },
                                        success = false,
                                        message = msg,
                                        latencyMs = 0L
                                    )
                                    Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                                    return@AiProviderCard
                                }
                                val normalizedUrl = validUrl.getOrThrow()
                                val cleanModel = modelId.trim().ifBlank { provider.defaultModel }

                                if (rawKey.isNotBlank()) {
                                    val ok = ApiKeyVault.saveAiKey(provider, rawKey, cleanModel, normalizedUrl)
                                    if (ok) {
                                        ApiKeyVault.setActiveAiProvider(provider)
                                        Toast.makeText(context, "${provider.displayName} saved & activated", Toast.LENGTH_SHORT).show()
                                    } else {
                                        Toast.makeText(context, "Keystore encryption error", Toast.LENGTH_SHORT).show()
                                    }
                                } else if (isSaved) {
                                    ApiKeyVault.setAiModel(provider, cleanModel)
                                    ApiKeyVault.setAiEndpoint(provider, normalizedUrl)
                                    Toast.makeText(context, "Model & endpoint updated", Toast.LENGTH_SHORT).show()
                                }
                            },
                            onSetActive = {
                                ApiKeyVault.setActiveAiProvider(provider)
                                Toast.makeText(context, "${provider.displayName} set as Active AI", Toast.LENGTH_SHORT).show()
                            },
                            onClear = {
                                ApiKeyVault.clearAiKey(provider)
                                aiTestResults.remove(provider)
                                Toast.makeText(context, "${provider.displayName} key cleared", Toast.LENGTH_SHORT).show()
                            },
                            onTest = { rawOrEmpty, modelId, customUrl ->
                                val keyToUse = rawOrEmpty.trim().ifBlank { ApiKeyVault.getAiKey(provider).orEmpty() }
                                if (keyToUse.isBlank()) {
                                    Toast.makeText(context, "Enter your API key first", Toast.LENGTH_SHORT).show()
                                    return@AiProviderCard
                                }
                                val candidateUrl = customUrl.trim().ifBlank { provider.defaultBaseUrl }
                                val cleanModel = modelId.trim().ifBlank { provider.defaultModel }
                                val validUrl = ByokAiService.validateEndpointUrl(candidateUrl, provider.protocol)
                                if (validUrl.isFailure) {
                                    val msg = validUrl.exceptionOrNull()?.message ?: "Invalid HTTPS endpoint URL"
                                    aiTestResults[provider] = AiConnectionTestResult(
                                        provider = provider,
                                        modelId = cleanModel,
                                        success = false,
                                        message = msg,
                                        latencyMs = 0L
                                    )
                                    Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                                    return@AiProviderCard
                                }
                                val endpoint = validUrl.getOrThrow()
                                aiTesting[provider] = true
                                scope.launch {
                                    val result = ByokAiService.testConnection(
                                        ActiveAiConfig(
                                            provider = provider,
                                            apiKey = keyToUse,
                                            modelId = cleanModel,
                                            endpointUrl = endpoint
                                        )
                                    )
                                    aiTestResults[provider] = result
                                    aiTesting[provider] = false
                                }
                            },
                            onOpenDocs = {
                                SafeBrowserLauncher.openExternalUrl(context, provider.docsUrl)
                            }
                        )
                    }

                    item { Spacer(modifier = Modifier.height(24.dp)) }
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    item {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .background(EmeraldSoft)
                                .border(1.dp, EmeraldBorder, RoundedCornerShape(12.dp))
                                .padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.Lock, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "OPTIONAL THREAT INTEL ENRICHMENT",
                                    color = EmeraldDeep,
                                    fontSize = 11.sp,
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "Core passive OSINT works free without keys. Add your own threat-feed keys to unlock VirusTotal, AbuseIPDB, Full Shodan, URLScan live scans & abuse.ch.",
                                    color = SlateGrey,
                                    fontSize = 12.sp,
                                    lineHeight = 17.sp
                                )
                            }
                        }
                    }

                    items(ApiProvider.entries, key = { it.id }) { provider ->
                        val isConfigured = provider in configuredThreat
                        ThreatProviderCard(
                            provider = provider,
                            isConfigured = isConfigured,
                            maskedPreview = if (isConfigured) ApiKeyVault.getMaskedPreview(provider) else null,
                            isTesting = threatTesting[provider] == true,
                            testResult = threatTestResults[provider],
                            onSave = { rawKey ->
                                val ok = ApiKeyVault.saveKey(provider, rawKey)
                                if (ok) {
                                    Toast.makeText(context, "${provider.displayName} key encrypted locally", Toast.LENGTH_SHORT).show()
                                }
                            },
                            onClear = {
                                ApiKeyVault.clearKey(provider)
                                threatTestResults.remove(provider)
                                Toast.makeText(context, "${provider.displayName} key removed", Toast.LENGTH_SHORT).show()
                            },
                            onTest = { rawKey ->
                                val key = rawKey.trim().ifBlank { ApiKeyVault.getKey(provider).orEmpty() }
                                if (key.isBlank()) {
                                    Toast.makeText(context, "Enter a key first", Toast.LENGTH_SHORT).show()
                                    return@ThreatProviderCard
                                }
                                threatTesting[provider] = true
                                scope.launch {
                                    threatTestResults[provider] = ProThreatApiServices.testProviderKey(provider, key)
                                    threatTesting[provider] = false
                                }
                            },
                            onOpenDocs = {
                                SafeBrowserLauncher.openExternalUrl(context, provider.docsUrl)
                            }
                        )
                    }

                    item { Spacer(modifier = Modifier.height(24.dp)) }
                }
            }
        }
    }
}

@Composable
private fun VaultTabButton(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .heightIn(min = 42.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(if (selected) EmeraldPrimary else SurfaceElevated)
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            color = if (selected) PureWhite else SlateGrey,
            fontSize = 12.sp,
            fontFamily = MonoFontFamily,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun ActiveAiBanner(
    activeProvider: AiProvider?,
    configuredCount: Int,
    vaultVersion: Long
) {
    val activeModel = remember(activeProvider, vaultVersion) { activeProvider?.let { ApiKeyVault.getAiModel(it) } }
    val activeEndpoint = remember(activeProvider, vaultVersion) { activeProvider?.let { ApiKeyVault.getAiEndpoint(it) } }
    val activeEndpointHost = remember(activeEndpoint) {
        activeEndpoint?.let { url ->
            try {
                URI(url).host
            } catch (_: Exception) {
                null
            }
        }
    }
    val isCustomUrl = remember(activeProvider, vaultVersion) {
        activeProvider != null && (ApiKeyVault.hasCustomEndpoint(activeProvider) || activeProvider == AiProvider.CUSTOM_OPENAI)
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(if (activeProvider != null) EmeraldSoft else CharcoalNavy)
            .border(1.dp, if (activeProvider != null) EmeraldBorder else CardBorder, RoundedCornerShape(12.dp))
            .padding(14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Default.AutoAwesome,
                contentDescription = null,
                tint = if (activeProvider != null) EmeraldPrimary else InkBlack,
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = if (activeProvider != null) {
                    "ACTIVE BYOK AI: ${activeProvider.displayName.uppercase()}"
                } else {
                    "CONNECT YOUR OWN AI API KEY OR CUSTOM ENDPOINT"
                },
                color = if (activeProvider != null) EmeraldDeep else InkBlack,
                fontSize = 11.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold
            )
        }
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = if (activeProvider != null) {
                val endpointNote = if (isCustomUrl && !activeEndpointHost.isNullOrBlank()) {
                    " • Custom Endpoint: $activeEndpointHost"
                } else {
                    ""
                }
                "Model: $activeModel$endpointNote • $configuredCount provider(s) encrypted locally in AndroidKeyStore. Keys go strictly to your chosen HTTPS endpoint."
            } else {
                "Zero server keys or subscriptions. Connect OpenRouter, any Custom OpenAI-Compatible gateway (Together, Fireworks, LiteLLM, vLLM, Cloudflare AI Gateway), Claude, OpenAI, Gemini, Groq, or DeepSeek — custom HTTPS endpoints supported on every provider."
            },
            color = SlateGrey,
            fontSize = 12.sp,
            lineHeight = 17.sp
        )
    }
}

@Composable
private fun AiProviderCard(
    provider: AiProvider,
    isSaved: Boolean,
    isActive: Boolean,
    hasCustomEndpoint: Boolean,
    maskedPreview: String?,
    initialModel: String,
    initialCustomUrl: String,
    isTesting: Boolean,
    testResult: AiConnectionTestResult?,
    onSave: (String, String, String) -> Unit,
    onSetActive: () -> Unit,
    onClear: () -> Unit,
    onTest: (String, String, String) -> Unit,
    onOpenDocs: () -> Unit
) {
    var expanded by remember(provider.id) {
        mutableStateOf(isActive || provider == AiProvider.OPENROUTER || provider == AiProvider.CUSTOM_OPENAI)
    }
    var keyDraft by remember(provider.id) { mutableStateOf("") }
    var modelDraft by remember(provider.id, initialModel) { mutableStateOf(initialModel) }
    var urlDraft by remember(provider.id, initialCustomUrl) { mutableStateOf(initialCustomUrl) }
    var showKey by remember(provider.id) { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(if (isActive) EmeraldSoft.copy(alpha = 0.45f) else CharcoalNavy)
            .border(
                width = if (isActive) 1.5.dp else 1.dp,
                color = if (isActive) EmeraldPrimary else CardBorder,
                shape = RoundedCornerShape(14.dp)
            )
            .padding(14.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded },
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(if (isActive) EmeraldPrimary else InkBlack)
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = provider.shortBadge,
                        color = PureWhite,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            text = provider.displayName,
                            color = InkBlack,
                            fontSize = 14.sp,
                            fontFamily = DisplayFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                        if (hasCustomEndpoint) {
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(EmeraldSoft)
                                    .border(1.dp, EmeraldBorder, RoundedCornerShape(4.dp))
                                    .padding(horizontal = 5.dp, vertical = 1.dp)
                            ) {
                                Text(
                                    text = "CUSTOM URL",
                                    color = EmeraldDeep,
                                    fontSize = 8.sp,
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                    Text(
                        text = if (isSaved) "Key: $maskedPreview • $initialModel" else provider.defaultModel,
                        color = if (isSaved) EmeraldDeep else MutedSlate,
                        fontSize = 11.sp,
                        fontFamily = MonoFontFamily
                    )
                }
            }

            if (isActive) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(EmeraldPrimary)
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text("ACTIVE", color = PureWhite, fontSize = 9.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                }
            } else if (isSaved) {
                OutlinedButton(
                    onClick = onSetActive,
                    border = BorderStroke(1.dp, EmeraldPrimary),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = EmeraldDeep),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.heightIn(min = 34.dp)
                ) {
                    Text("Use", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }
        }

        Spacer(modifier = Modifier.height(6.dp))
        Text(text = provider.description, color = SlateGrey, fontSize = 12.sp, lineHeight = 16.sp)

        if (expanded) {
            Spacer(modifier = Modifier.height(10.dp))

            OutlinedTextField(
                value = keyDraft,
                onValueChange = { keyDraft = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("ai_key_input_${provider.id}"),
                singleLine = true,
                label = { Text("Your ${provider.displayName} API Key", fontSize = 11.sp) },
                placeholder = {
                    Text(
                        text = if (isSaved) "Saved ($maskedPreview) — paste to replace" else "Paste API key...",
                        color = MutedSlate,
                        fontSize = 12.sp
                    )
                },
                visualTransformation = if (showKey) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                    IconButton(onClick = { showKey = !showKey }) {
                        Icon(
                            imageVector = if (showKey) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            contentDescription = "Toggle key visibility",
                            tint = SlateGrey
                        )
                    }
                },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = PureWhite,
                    unfocusedContainerColor = PureWhite,
                    focusedBorderColor = InkBlack,
                    unfocusedBorderColor = CardBorder,
                    focusedTextColor = InkBlack,
                    unfocusedTextColor = InkBlack
                ),
                shape = RoundedCornerShape(8.dp)
            )

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = modelDraft,
                onValueChange = { modelDraft = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Model ID", fontSize = 11.sp) },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily, color = InkBlack),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = PureWhite,
                    unfocusedContainerColor = PureWhite,
                    focusedBorderColor = InkBlack,
                    unfocusedBorderColor = CardBorder,
                    focusedTextColor = InkBlack,
                    unfocusedTextColor = InkBlack
                ),
                shape = RoundedCornerShape(8.dp)
            )

            Spacer(modifier = Modifier.height(6.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                provider.presetModels.forEach { preset ->
                    val selected = modelDraft.trim() == preset
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(if (selected) EmeraldSoft else SurfaceElevated)
                            .border(1.dp, if (selected) EmeraldPrimary else CardBorder, RoundedCornerShape(6.dp))
                            .clickable { modelDraft = preset }
                            .padding(horizontal = 8.dp, vertical = 5.dp)
                    ) {
                        Text(
                            text = preset,
                            color = if (selected) EmeraldDeep else SlateGrey,
                            fontSize = 10.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            if (provider == AiProvider.CUSTOM_OPENAI) {
                Text(
                    text = "QUICK ENDPOINT PRESETS",
                    color = SlateGrey,
                    fontSize = 10.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    CUSTOM_ENDPOINT_PRESETS.forEach { preset ->
                        val isPresetSelected = urlDraft.trim().equals(preset.endpointUrl, ignoreCase = true)
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(if (isPresetSelected) EmeraldPrimary else SurfaceElevated)
                                .border(1.dp, if (isPresetSelected) EmeraldPrimary else CardBorder, RoundedCornerShape(6.dp))
                                .clickable {
                                    urlDraft = preset.endpointUrl
                                    modelDraft = preset.defaultModel
                                }
                                .padding(horizontal = 10.dp, vertical = 6.dp)
                                .testTag("ai_preset_${preset.label.lowercase().replace(" ", "_")}")
                        ) {
                            Text(
                                text = preset.label,
                                color = if (isPresetSelected) PureWhite else InkBlack,
                                fontSize = 10.sp,
                                fontFamily = MonoFontFamily,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "API ENDPOINT URL (CUSTOM / PROXY SUPPORTED)",
                    color = SlateGrey,
                    fontSize = 10.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                )
                if (!urlDraft.trim().equals(provider.defaultBaseUrl, ignoreCase = true)) {
                    Text(
                        text = "Reset Default",
                        color = EmeraldDeep,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(EmeraldSoft)
                            .clickable { urlDraft = provider.defaultBaseUrl }
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                            .testTag("ai_endpoint_reset_${provider.id}")
                    )
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
            OutlinedTextField(
                value = urlDraft,
                onValueChange = { urlDraft = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("ai_endpoint_input_${provider.id}"),
                singleLine = true,
                placeholder = {
                    Text(
                        text = provider.defaultBaseUrl,
                        color = MutedSlate,
                        fontSize = 11.sp,
                        fontFamily = MonoFontFamily
                    )
                },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily, color = InkBlack),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = PureWhite,
                    unfocusedContainerColor = PureWhite,
                    focusedBorderColor = InkBlack,
                    unfocusedBorderColor = CardBorder,
                    focusedTextColor = InkBlack,
                    unfocusedTextColor = InkBlack
                ),
                shape = RoundedCornerShape(8.dp)
            )
            Spacer(modifier = Modifier.height(3.dp))
            Text(
                text = "Accepts base URLs (auto-completes protocol path) or full HTTPS proxy/gateway URLs.",
                color = MutedSlate,
                fontSize = 10.sp,
                lineHeight = 14.sp
            )

            if (testResult != null) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (testResult.success) EmeraldSoft else StatusRisk.copy(alpha = 0.08f))
                        .border(
                            1.dp,
                            if (testResult.success) EmeraldBorder else StatusRisk.copy(alpha = 0.35f),
                            RoundedCornerShape(8.dp)
                        )
                        .padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (testResult.success) Icons.Default.CheckCircle else Icons.Default.ErrorOutline,
                        contentDescription = null,
                        tint = if (testResult.success) EmeraldPrimary else StatusRisk,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = testResult.message,
                        color = if (testResult.success) EmeraldDeep else StatusRisk,
                        fontSize = 11.sp,
                        fontFamily = MonoFontFamily
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Button(
                    onClick = {
                        onSave(keyDraft, modelDraft, urlDraft)
                        keyDraft = ""
                    },
                    enabled = keyDraft.isNotBlank() || isSaved,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag("ai_save_${provider.id}")
                ) {
                    Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(15.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(if (keyDraft.isNotBlank()) "Save & Use" else "Save Settings", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                }

                OutlinedButton(
                    onClick = { onTest(keyDraft, modelDraft, urlDraft) },
                    enabled = !isTesting && (keyDraft.isNotBlank() || isSaved),
                    border = BorderStroke(1.dp, EmeraldPrimary),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = EmeraldDeep),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.heightIn(min = 44.dp)
                ) {
                    if (isTesting) {
                        CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp, color = EmeraldPrimary)
                    } else {
                        Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Test", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }

                if (isSaved) {
                    IconButton(onClick = onClear) {
                        Icon(Icons.Default.Delete, contentDescription = "Delete key", tint = StatusRisk)
                    }
                }

                IconButton(onClick = onOpenDocs) {
                    Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = "Get API key", tint = SlateGrey)
                }
            }
        }
    }
}

@Composable
private fun ThreatProviderCard(
    provider: ApiProvider,
    isConfigured: Boolean,
    maskedPreview: String?,
    isTesting: Boolean,
    testResult: ApiKeyTestResult?,
    onSave: (String) -> Unit,
    onClear: () -> Unit,
    onTest: (String) -> Unit,
    onOpenDocs: () -> Unit
) {
    var draft by remember(provider.id) { mutableStateOf("") }
    var visible by remember(provider.id) { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, if (isConfigured) EmeraldBorder else CardBorder, RoundedCornerShape(14.dp))
            .padding(14.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(if (isConfigured) EmeraldPrimary else InkBlack)
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(provider.shortBadge, color = PureWhite, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column {
                    Text(provider.displayName, color = InkBlack, fontSize = 14.sp, fontFamily = DisplayFontFamily, fontWeight = FontWeight.Bold)
                    Text(
                        text = if (isConfigured) "Encrypted: $maskedPreview" else provider.freeTierNote,
                        color = if (isConfigured) EmeraldDeep else MutedSlate,
                        fontSize = 11.sp
                    )
                }
            }
            IconButton(onClick = onOpenDocs) {
                Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = "Open provider docs", tint = SlateGrey)
            }
        }

        Spacer(modifier = Modifier.height(6.dp))
        Text(provider.description, color = SlateGrey, fontSize = 12.sp)
        Spacer(modifier = Modifier.height(10.dp))

        OutlinedTextField(
            value = draft,
            onValueChange = { draft = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            placeholder = {
                Text(if (isConfigured) "Paste new key to overwrite" else "Paste ${provider.displayName} key...", color = MutedSlate, fontSize = 12.sp)
            },
            visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                IconButton(onClick = { visible = !visible }) {
                    Icon(
                        imageVector = if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = "Toggle visibility",
                        tint = SlateGrey
                    )
                }
            },
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = DarkerSurface,
                unfocusedContainerColor = DarkerSurface,
                focusedBorderColor = InkBlack,
                unfocusedBorderColor = CardBorder,
                focusedTextColor = InkBlack,
                unfocusedTextColor = InkBlack
            ),
            shape = RoundedCornerShape(8.dp)
        )

        if (testResult != null) {
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(if (testResult.success) EmeraldSoft else StatusRisk.copy(alpha = 0.08f))
                    .padding(10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = if (testResult.success) Icons.Default.Shield else Icons.Default.ErrorOutline,
                    contentDescription = null,
                    tint = if (testResult.success) EmeraldPrimary else StatusRisk,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(testResult.statusMessage, color = if (testResult.success) EmeraldDeep else StatusRisk, fontSize = 11.sp, fontFamily = MonoFontFamily)
            }
        }

        Spacer(modifier = Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(
                onClick = {
                    onSave(draft)
                    draft = ""
                },
                enabled = draft.isNotBlank(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = EmeraldPrimary,
                    contentColor = PureWhite,
                    disabledContainerColor = SurfaceElevated,
                    disabledContentColor = MutedSlate
                ),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = 44.dp)
            ) {
                Text("Save Key", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            }

            OutlinedButton(
                onClick = { onTest(draft) },
                enabled = !isTesting && (draft.isNotBlank() || isConfigured),
                border = BorderStroke(1.dp, EmeraldPrimary),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = EmeraldDeep),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.heightIn(min = 44.dp)
            ) {
                if (isTesting) {
                    CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp, color = EmeraldPrimary)
                } else {
                    Text("Test", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }
            }

            if (isConfigured) {
                IconButton(onClick = onClear) {
                    Icon(Icons.Default.Delete, contentDescription = "Remove key", tint = StatusRisk)
                }
            }
        }
    }
}
