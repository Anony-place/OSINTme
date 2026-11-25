package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.local.ActiveAiConfig
import com.oopssecurity.osintme.data.local.AiProtocol
import com.oopssecurity.osintme.data.local.AiProvider
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.util.IocExtractor
import com.oopssecurity.osintme.util.NetworkSecurityGuard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.InetAddress
import java.net.URI
import java.util.concurrent.TimeUnit

data class AiChatMessage(
    val role: String, // "user" or "assistant"
    val content: String,
    val timestamp: Long = System.currentTimeMillis()
)

data class AiCompletionResult(
    val text: String,
    val providerName: String,
    val modelId: String,
    val latencyMs: Long
)

data class AiConnectionTestResult(
    val provider: AiProvider,
    val modelId: String,
    val success: Boolean,
    val message: String,
    val latencyMs: Long
)

data class AiDossierInsight(
    val briefText: String,
    val providerName: String,
    val modelId: String,
    val latencyMs: Long,
    val suggestedPivots: List<String>
)

data class AiCraftedDork(
    val engine: String,
    val title: String,
    val query: String
)

/**
 * Multi-Provider BYOK AI Client (100% user-supplied API keys).
 * Supports OpenAI-Compatible (OpenRouter, OpenAI, Groq, DeepSeek, Mistral, Perplexity, xAI, Custom),
 * Anthropic Messages API v1 (Claude), and Google Gemini REST API (user's own AI Studio key).
 * Routes all requests over HTTPS through OsintApiClient so OPSEC proxy/Tor rules apply.
 */
object ByokAiService {

    private val json = Json { ignoreUnknownKeys = true }
    private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

    private const val OSINT_SYSTEM_PROMPT =
        "You are an expert defensive OSINT & Threat Intelligence Analyst inside the OSINTme mobile workbench. " +
            "Provide concise, objective, structured passive-intelligence analysis. " +
            "Never suggest illegal exploitation or active intrusion. Highlight observable facts, infrastructure links, " +
            "spoofing/threat indicators, and safe next passive pivots."

    private fun aiHttpClient() = OsintApiClient.client.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(55, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .build()

    /**
     * Normalizes user-supplied custom base URLs or gateway paths into complete protocol endpoints
     * without clobbering already-complete custom routes.
     */
    fun normalizeEndpointUrl(protocol: AiProtocol, rawUrl: String): String {
        val trimmed = rawUrl.trim()
        if (trimmed.isEmpty()) return trimmed
        val uri = try {
            URI(trimmed)
        } catch (_: Exception) {
            return trimmed
        }
        if (uri.scheme.isNullOrBlank() || uri.host.isNullOrBlank()) return trimmed

        val rawPath = (uri.rawPath ?: "").trimEnd('/')
        val querySuffix = uri.rawQuery?.let { "?$it" }.orEmpty()
        val authorityBase = buildString {
            append(uri.scheme.lowercase())
            append("://")
            append(uri.rawAuthority)
        }

        val normalizedPath = when (protocol) {
            AiProtocol.OPENAI_COMPATIBLE -> when {
                rawPath.isEmpty() -> "/v1/chat/completions"
                rawPath.endsWith("/chat/completions", ignoreCase = true) -> rawPath
                rawPath.endsWith("/v1", ignoreCase = true) ||
                    rawPath.endsWith("/openai/v1", ignoreCase = true) ||
                    rawPath.endsWith("/api/v1", ignoreCase = true) ||
                    rawPath.endsWith("/compatible-mode/v1", ignoreCase = true) ||
                    rawPath.endsWith("/v1/openai", ignoreCase = true) -> "$rawPath/chat/completions"
                else -> rawPath
            }
            AiProtocol.ANTHROPIC_MESSAGES -> when {
                rawPath.isEmpty() -> "/v1/messages"
                rawPath.endsWith("/messages", ignoreCase = true) -> rawPath
                rawPath.endsWith("/v1", ignoreCase = true) -> "$rawPath/messages"
                else -> rawPath
            }
            AiProtocol.GEMINI_REST -> when {
                rawPath.isEmpty() -> "/v1beta/models"
                rawPath.contains(":generateContent", ignoreCase = true) -> rawPath
                rawPath.endsWith("/models", ignoreCase = true) -> rawPath
                rawPath.endsWith("/v1beta", ignoreCase = true) ||
                    rawPath.endsWith("/v1", ignoreCase = true) -> "$rawPath/models"
                else -> rawPath
            }
        }
        return "$authorityBase$normalizedPath$querySuffix"
    }

    fun validateEndpointUrl(
        rawUrl: String,
        protocol: AiProtocol = AiProtocol.OPENAI_COMPATIBLE
    ): Result<String> {
        val preValidated = NetworkSecurityGuard.validatePublicHttpUrl(rawUrl, requireHttps = true)
            .getOrElse { return Result.failure(it) }
        val normalized = normalizeEndpointUrl(protocol, preValidated)
        return NetworkSecurityGuard.validatePublicHttpUrl(normalized, requireHttps = true)
    }

    suspend fun chat(
        messages: List<AiChatMessage>,
        systemPrompt: String = OSINT_SYSTEM_PROMPT,
        overrideConfig: ActiveAiConfig? = null,
        maxTokens: Int = 900
    ): Result<AiCompletionResult> = withContext(Dispatchers.IO) {
        val config = overrideConfig ?: ApiKeyVault.getActiveAiConfig()
            ?: return@withContext Result.failure(
                Exception("No BYOK AI key configured. Add your OpenRouter, Claude, OpenAI, Gemini, Groq, or Custom Endpoint key in AI & API Vault.")
            )

        val validatedUrl = validateEndpointUrl(config.endpointUrl, config.provider.protocol).getOrElse {
            return@withContext Result.failure(it)
        }

        val startMs = System.currentTimeMillis()
        try {
            val request = buildRequestForConfig(config, validatedUrl, systemPrompt, messages, maxTokens)

            aiHttpClient().newCall(request).execute().use { resp ->
                val rawBody = NetworkSecurityGuard.readBodyBounded(resp, 512_000)
                val elapsed = System.currentTimeMillis() - startMs

                if (!resp.isSuccessful) {
                    val errDetail = extractErrorDetail(rawBody).ifBlank { "HTTP ${resp.code}" }
                    return@withContext Result.failure(
                        Exception("${config.provider.displayName} rejected request (${resp.code}): $errDetail")
                    )
                }

                val contentText = parseResponseText(config.provider.protocol, rawBody).getOrElse {
                    return@withContext Result.failure(it)
                }

                Result.success(
                    AiCompletionResult(
                        text = contentText.trim(),
                        providerName = config.provider.displayName,
                        modelId = config.modelId,
                        latencyMs = elapsed
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(Exception("${config.provider.displayName} request failed: ${e.message ?: "network error"}"))
        }
    }

    suspend fun testConnection(config: ActiveAiConfig): AiConnectionTestResult {
        val startMs = System.currentTimeMillis()
        val res = chat(
            messages = listOf(AiChatMessage("user", "Reply with exactly: OK")),
            systemPrompt = "You are a connectivity check endpoint. Reply with OK only.",
            overrideConfig = config,
            maxTokens = 16
        )
        val elapsed = System.currentTimeMillis() - startMs
        return res.fold(
            onSuccess = {
                AiConnectionTestResult(
                    provider = config.provider,
                    modelId = config.modelId,
                    success = true,
                    message = "Verified ${config.modelId} (${it.latencyMs} ms)",
                    latencyMs = it.latencyMs
                )
            },
            onFailure = {
                AiConnectionTestResult(
                    provider = config.provider,
                    modelId = config.modelId,
                    success = false,
                    message = it.message ?: "Connection failed",
                    latencyMs = elapsed
                )
            }
        )
    }

    suspend fun analyzeTargetDossier(
        target: String,
        telemetrySummary: String
    ): Result<AiDossierInsight> {
        val prompt = """
            Analyze this passive OSINT dossier for target: $target
            
            Collected Passive Telemetry:
            ${telemetrySummary.take(6500)}
            
            Respond concisely with these exact headings:
            1. EXECUTIVE ASSESSMENT (2-3 sentences + overall risk: LOW / MEDIUM / HIGH)
            2. KEY INFRASTRUCTURE & EXPOSURE SIGNALS (3-5 crisp bullets referencing actual observed facts)
            3. RECOMMENDED NEXT PASSIVE PIVOTS (3-5 concrete domains, IPs, handles, or checks to inspect next)
        """.trimIndent()

        return chat(messages = listOf(AiChatMessage("user", prompt)), maxTokens = 750).map { completion ->
            val extracted = IocExtractor.extract(completion.text).items
                .map { it.value }
                .filter { !it.equals(target, ignoreCase = true) }
                .distinct()
                .take(8)
            AiDossierInsight(
                briefText = completion.text,
                providerName = completion.providerName,
                modelId = completion.modelId,
                latencyMs = completion.latencyMs,
                suggestedPivots = extracted
            )
        }
    }

    suspend fun analyzeEmailHeaders(reportSummary: String): Result<AiCompletionResult> {
        val prompt = """
            Evaluate these parsed RFC-5322 email forensic headers for phishing, BEC, or domain spoofing:
            
            ${reportSummary.take(5500)}
            
            Provide:
            1. SPOOFING / PHISHING VERDICT (Legitimate / Suspicious / High-Confidence Spoof or BEC)
            2. AUTHENTICATION & RELAY ANALYSIS (explain SPF/DKIM/DMARC alignment, Return-Path/Reply-To, and hop delays)
            3. DEFENSIVE ACTION & NEXT PIVOTS (what IPs/domains to check next and how SOC should respond)
        """.trimIndent()
        return chat(messages = listOf(AiChatMessage("user", prompt)), maxTokens = 650)
    }

    suspend fun generateCustomDorks(
        target: String,
        huntingGoal: String
    ): Result<Pair<List<AiCraftedDork>, AiCompletionResult>> {
        val prompt = """
            Generate 6 high-precision defensive OSINT search queries for target "$target" matching this investigation objective:
            "$huntingGoal"
            
            Use a mix of GOOGLE, SHODAN, GITHUB, and CENSYS where appropriate.
            Output STRICTLY one query per line in this exact pipe-delimited format (no markdown code fences, no numbering):
            ENGINE | Short Descriptive Title | exact search query
        """.trimIndent()

        return chat(
            messages = listOf(AiChatMessage("user", prompt)),
            systemPrompt = "You are a defensive OSINT query specialist. Output only pipe-delimited ENGINE | Title | Query lines.",
            maxTokens = 600
        ).map { completion ->
            val parsed = parseDorkLines(completion.text)
            parsed to completion
        }
    }

    suspend fun generateCaseExecutiveBrief(
        caseTitle: String,
        caseTarget: String,
        artifactsDigest: String
    ): Result<AiCompletionResult> {
        val prompt = """
            Draft a formal executive OSINT investigation brief suitable for inclusion in an exported Case Report.
            Case Title: $caseTitle
            Primary Target: $caseTarget
            
            Recorded Evidence Artifacts:
            ${artifactsDigest.take(7000)}
            
            Structure the brief cleanly (plain text, no raw HTML):
            - EXECUTIVE SUMMARY (3-4 sentences)
            - CORROBORATED FINDINGS (bullet list grounded strictly in the artifacts above)
            - RISK POSTURE & REMEDIATION / NEXT STEPS (3 concise bullets)
        """.trimIndent()
        return chat(messages = listOf(AiChatMessage("user", prompt)), maxTokens = 850)
    }

    fun parseDorkLines(rawText: String): List<AiCraftedDork> {
        val results = mutableListOf<AiCraftedDork>()
        rawText.lines().forEach { rawLine ->
            val line = rawLine.trim()
                .removePrefix("-")
                .removePrefix("*")
                .replace(Regex("^\\d+[.)]\\s*"), "")
                .trim()
            if (line.count { it == '|' } >= 2) {
                val parts = line.split("|", limit = 3)
                val engine = parts[0].trim().uppercase().let {
                    when {
                        it.contains("SHODAN") -> "SHODAN"
                        it.contains("GITHUB") -> "GITHUB"
                        it.contains("CENSYS") -> "CENSYS"
                        it.contains("WAYBACK") -> "WAYBACK"
                        it.contains("CRT") -> "CRTSH"
                        else -> "GOOGLE"
                    }
                }
                val title = parts[1].trim().removeSurrounding("\"").removeSurrounding("`")
                val query = parts[2].trim().removeSurrounding("`")
                if (title.isNotBlank() && query.isNotBlank()) {
                    results.add(AiCraftedDork(engine = engine, title = title, query = query))
                }
            }
        }
        return results
    }

    // ---- Protocol-Specific Request Builders ----

    internal fun buildRequestForConfig(
        config: ActiveAiConfig,
        validatedUrl: String,
        systemPrompt: String,
        messages: List<AiChatMessage>,
        maxTokens: Int
    ): Request {
        return when (config.provider.protocol) {
            AiProtocol.OPENAI_COMPATIBLE -> buildOpenAiRequest(config, validatedUrl, systemPrompt, messages, maxTokens)
            AiProtocol.ANTHROPIC_MESSAGES -> buildAnthropicRequest(config, validatedUrl, systemPrompt, messages, maxTokens)
            AiProtocol.GEMINI_REST -> buildGeminiRequest(config, validatedUrl, systemPrompt, messages, maxTokens)
        }
    }

    private fun buildOpenAiRequest(
        config: ActiveAiConfig,
        url: String,
        systemPrompt: String,
        messages: List<AiChatMessage>,
        maxTokens: Int
    ): Request {
        val bodyObj = buildJsonObject {
            put("model", config.modelId)
            put("max_tokens", maxTokens)
            put("temperature", 0.25)
            put("messages", buildJsonArray {
                add(buildJsonObject {
                    put("role", "system")
                    put("content", systemPrompt)
                })
                messages.takeLast(14).forEach { msg ->
                    add(buildJsonObject {
                        put("role", if (msg.role == "assistant") "assistant" else "user")
                        put("content", msg.content)
                    })
                }
            })
        }

        val builder = Request.Builder()
            .url(url)
            .header("Authorization", "Bearer ${config.apiKey}")
            .header("Content-Type", "application/json")
            .post(bodyObj.toString().toRequestBody(JSON_MEDIA))

        if (config.provider == AiProvider.OPENROUTER) {
            builder.header("HTTP-Referer", "https://osintme.app")
            builder.header("X-Title", "OSINTme Workbench")
        }
        return builder.build()
    }

    private fun buildAnthropicRequest(
        config: ActiveAiConfig,
        url: String,
        systemPrompt: String,
        messages: List<AiChatMessage>,
        maxTokens: Int
    ): Request {
        val bodyObj = buildJsonObject {
            put("model", config.modelId)
            put("max_tokens", maxTokens)
            put("system", systemPrompt)
            put("messages", buildJsonArray {
                messages.takeLast(14).forEach { msg ->
                    add(buildJsonObject {
                        put("role", if (msg.role == "assistant") "assistant" else "user")
                        put("content", msg.content)
                    })
                }
            })
        }
        return Request.Builder()
            .url(url)
            .header("x-api-key", config.apiKey)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .post(bodyObj.toString().toRequestBody(JSON_MEDIA))
            .build()
    }

    private fun buildGeminiRequest(
        config: ActiveAiConfig,
        baseUrl: String,
        systemPrompt: String,
        messages: List<AiChatMessage>,
        maxTokens: Int
    ): Request {
        val cleanBase = baseUrl.trimEnd('/')
        val fullUrl = if (cleanBase.contains(":generateContent", ignoreCase = true)) {
            cleanBase
        } else {
            "$cleanBase/${config.modelId}:generateContent"
        }

        val bodyObj = buildJsonObject {
            put("systemInstruction", buildJsonObject {
                put("parts", buildJsonArray {
                    add(buildJsonObject { put("text", systemPrompt) })
                })
            })
            put("contents", buildJsonArray {
                messages.takeLast(14).forEach { msg ->
                    add(buildJsonObject {
                        put("role", if (msg.role == "assistant") "model" else "user")
                        put("parts", buildJsonArray {
                            add(buildJsonObject { put("text", msg.content) })
                        })
                    })
                }
            })
            put("generationConfig", buildJsonObject {
                put("maxOutputTokens", maxTokens)
                put("temperature", 0.25)
            })
        }

        return Request.Builder()
            .url(fullUrl)
            .header("x-goog-api-key", config.apiKey)
            .header("Content-Type", "application/json")
            .post(bodyObj.toString().toRequestBody(JSON_MEDIA))
            .build()
    }

    // ---- Protocol-Specific Response Parsers ----

    internal fun parseResponseText(protocol: AiProtocol, rawBody: String): Result<String> {
        return try {
            val root = json.parseToJsonElement(rawBody).jsonObject
            val text = when (protocol) {
                AiProtocol.OPENAI_COMPATIBLE -> {
                    val choices = root["choices"]?.jsonArray
                    val msgObj = choices?.firstOrNull()?.jsonObject?.get("message")?.jsonObject
                    msgObj?.get("content")?.jsonPrimitive?.contentOrNull
                }
                AiProtocol.ANTHROPIC_MESSAGES -> {
                    val contentArr = root["content"]?.jsonArray
                    contentArr?.mapNotNull { it.jsonObject["text"]?.jsonPrimitive?.contentOrNull }
                        ?.joinToString("\n")
                }
                AiProtocol.GEMINI_REST -> {
                    val candidates = root["candidates"]?.jsonArray
                    val parts = candidates?.firstOrNull()?.jsonObject
                        ?.get("content")?.jsonObject
                        ?.get("parts")?.jsonArray
                    parts?.mapNotNull { it.jsonObject["text"]?.jsonPrimitive?.contentOrNull }
                        ?.joinToString("\n")
                }
            }
            if (text.isNullOrBlank()) {
                Result.failure(Exception("Model returned an empty response"))
            } else {
                Result.success(text)
            }
        } catch (e: Exception) {
            Result.failure(Exception("Unable to parse AI response JSON: ${e.message}"))
        }
    }

    private fun extractErrorDetail(rawBody: String): String {
        return try {
            val root = json.parseToJsonElement(rawBody).jsonObject
            val errEl = root["error"]
            when (errEl) {
                is JsonObject -> errEl["message"]?.jsonPrimitive?.contentOrNull
                    ?: errEl["type"]?.jsonPrimitive?.contentOrNull
                    ?: errEl["code"]?.jsonPrimitive?.intOrNull?.toString()
                    ?: rawBody.take(160)
                else -> root["message"]?.jsonPrimitive?.contentOrNull ?: rawBody.take(160)
            }
        } catch (_: Exception) {
            rawBody.take(160)
        }
    }

    private fun isBlockedPrivateHost(host: String): Boolean {
        return NetworkSecurityGuard.isBlockedPrivateHost(host)
    }
}
