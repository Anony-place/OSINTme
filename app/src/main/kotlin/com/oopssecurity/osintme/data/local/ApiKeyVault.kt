package com.oopssecurity.osintme.data.local

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

enum class ApiProvider(
    val id: String,
    val displayName: String,
    val shortBadge: String,
    val description: String,
    val freeTierNote: String,
    val docsUrl: String
) {
    VIRUSTOTAL(
        id = "virustotal",
        displayName = "VirusTotal v3",
        shortBadge = "VT",
        description = "70+ AV & threat engines for domains, IPs, URLs, and file hashes.",
        freeTierNote = "Free community tier: 500 lookups/day (4/min)",
        docsUrl = "https://www.virustotal.com/gui/my-apikey"
    ),
    ABUSEIPDB(
        id = "abuseipdb",
        displayName = "AbuseIPDB v2",
        shortBadge = "ABUSEIP",
        description = "Crowdsourced IP abuse confidence score, ISP, usage type, and Tor/VPN flags.",
        freeTierNote = "Free tier: 1,000 IP checks/day",
        docsUrl = "https://www.abuseipdb.com/account/api"
    ),
    SHODAN(
        id = "shodan",
        displayName = "Shodan Full API",
        shortBadge = "SHODAN",
        description = "Upgrades free InternetDB with full service banners, OS, versions, and org intel.",
        freeTierNote = "Optional — free InternetDB always works without a key",
        docsUrl = "https://account.shodan.io/"
    ),
    URLSCAN(
        id = "urlscan",
        displayName = "URLScan.io",
        shortBadge = "URLSCAN",
        description = "Unlocks live sandbox scan submissions alongside public historical search.",
        freeTierNote = "Public search works without key; free account enables live scans",
        docsUrl = "https://urlscan.io/user/profile/"
    ),
    ABUSECH(
        id = "abusech",
        displayName = "abuse.ch Auth-Key",
        shortBadge = "ABUSE.CH",
        description = "Authenticates URLhaus malware host lookups and MalwareBazaar hash queries.",
        freeTierNote = "Free community Auth-Key from abuse.ch portal",
        docsUrl = "https://auth.abuse.ch/"
    )
}

enum class AiProtocol {
    OPENAI_COMPATIBLE,
    ANTHROPIC_MESSAGES,
    GEMINI_REST
}

data class CustomEndpointPreset(
    val label: String,
    val endpointUrl: String,
    val defaultModel: String
)

val CUSTOM_ENDPOINT_PRESETS: List<CustomEndpointPreset> = listOf(
    CustomEndpointPreset(
        label = "Together AI",
        endpointUrl = "https://api.together.xyz/v1/chat/completions",
        defaultModel = "meta-llama/Llama-3.3-70B-Instruct-Turbo"
    ),
    CustomEndpointPreset(
        label = "Fireworks AI",
        endpointUrl = "https://api.fireworks.ai/inference/v1/chat/completions",
        defaultModel = "accounts/fireworks/models/llama-v3p3-70b-instruct"
    ),
    CustomEndpointPreset(
        label = "Cerebras",
        endpointUrl = "https://api.cerebras.ai/v1/chat/completions",
        defaultModel = "llama-3.3-70b"
    ),
    CustomEndpointPreset(
        label = "SiliconFlow",
        endpointUrl = "https://api.siliconflow.cn/v1/chat/completions",
        defaultModel = "deepseek-ai/DeepSeek-V3"
    ),
    CustomEndpointPreset(
        label = "NVIDIA NIM",
        endpointUrl = "https://integrate.api.nvidia.com/v1/chat/completions",
        defaultModel = "meta/llama-3.3-70b-instruct"
    ),
    CustomEndpointPreset(
        label = "HuggingFace",
        endpointUrl = "https://router.huggingface.co/v1/chat/completions",
        defaultModel = "Qwen/Qwen2.5-72B-Instruct"
    )
)

enum class AiProvider(
    val id: String,
    val displayName: String,
    val shortBadge: String,
    val protocol: AiProtocol,
    val defaultBaseUrl: String,
    val defaultModel: String,
    val presetModels: List<String>,
    val description: String,
    val docsUrl: String
) {
    OPENROUTER(
        id = "ai_openrouter",
        displayName = "OpenRouter",
        shortBadge = "OPENROUTER",
        protocol = AiProtocol.OPENAI_COMPATIBLE,
        defaultBaseUrl = "https://openrouter.ai/api/v1/chat/completions",
        defaultModel = "anthropic/claude-3.5-sonnet",
        presetModels = listOf(
            "anthropic/claude-3.5-sonnet",
            "openai/gpt-4o-mini",
            "google/gemini-2.5-flash",
            "deepseek/deepseek-chat",
            "meta-llama/llama-3.3-70b-instruct:free"
        ),
        description = "One key unlocks Claude, GPT-4o, Gemini, Llama, DeepSeek & free models.",
        docsUrl = "https://openrouter.ai/keys"
    ),
    CUSTOM_OPENAI(
        id = "ai_custom",
        displayName = "Custom Endpoint (OpenAI-Compatible)",
        shortBadge = "CUSTOM",
        protocol = AiProtocol.OPENAI_COMPATIBLE,
        defaultBaseUrl = "https://api.together.xyz/v1/chat/completions",
        defaultModel = "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        presetModels = listOf(
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "Qwen/Qwen2.5-72B-Instruct-Turbo",
            "deepseek-ai/DeepSeek-V3"
        ),
        description = "Any HTTPS OpenAI-compatible gateway, reverse proxy, LiteLLM, vLLM, Together, Fireworks, or Cerebras endpoint.",
        docsUrl = "https://docs.together.ai/"
    ),
    ANTHROPIC_CLAUDE(
        id = "ai_anthropic",
        displayName = "Anthropic Claude",
        shortBadge = "CLAUDE",
        protocol = AiProtocol.ANTHROPIC_MESSAGES,
        defaultBaseUrl = "https://api.anthropic.com/v1/messages",
        defaultModel = "claude-3-5-haiku-latest",
        presetModels = listOf(
            "claude-3-5-haiku-latest",
            "claude-3-7-sonnet-latest",
            "claude-sonnet-4-20250514"
        ),
        description = "Direct Anthropic Messages API — excels at deep phishing & dossier reasoning.",
        docsUrl = "https://console.anthropic.com/settings/keys"
    ),
    OPENAI(
        id = "ai_openai",
        displayName = "OpenAI",
        shortBadge = "OPENAI",
        protocol = AiProtocol.OPENAI_COMPATIBLE,
        defaultBaseUrl = "https://api.openai.com/v1/chat/completions",
        defaultModel = "gpt-4o-mini",
        presetModels = listOf(
            "gpt-4o-mini",
            "gpt-4o",
            "o3-mini"
        ),
        description = "Direct OpenAI Chat Completions API (or compatible proxy) for fast triage and dorks.",
        docsUrl = "https://platform.openai.com/api-keys"
    ),
    GEMINI_BYOK(
        id = "ai_gemini_byok",
        displayName = "Google Gemini (BYOK)",
        shortBadge = "GEMINI",
        protocol = AiProtocol.GEMINI_REST,
        defaultBaseUrl = "https://generativelanguage.googleapis.com/v1beta/models",
        defaultModel = "gemini-2.5-flash",
        presetModels = listOf(
            "gemini-2.5-flash",
            "gemini-2.5-pro",
            "gemini-2.0-flash"
        ),
        description = "Connect using your own Google AI Studio key or custom Gemini gateway — generous free tier & huge context.",
        docsUrl = "https://aistudio.google.com/apikey"
    ),
    GROQ(
        id = "ai_groq",
        displayName = "Groq",
        shortBadge = "GROQ",
        protocol = AiProtocol.OPENAI_COMPATIBLE,
        defaultBaseUrl = "https://api.groq.com/openai/v1/chat/completions",
        defaultModel = "llama-3.3-70b-versatile",
        presetModels = listOf(
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "mixtral-8x7b-32768"
        ),
        description = "Ultra-low latency LPU inference for instant dossier briefs and dorks.",
        docsUrl = "https://console.groq.com/keys"
    ),
    DEEPSEEK(
        id = "ai_deepseek",
        displayName = "DeepSeek",
        shortBadge = "DEEPSEEK",
        protocol = AiProtocol.OPENAI_COMPATIBLE,
        defaultBaseUrl = "https://api.deepseek.com/chat/completions",
        defaultModel = "deepseek-chat",
        presetModels = listOf(
            "deepseek-chat",
            "deepseek-reasoner"
        ),
        description = "High-efficiency reasoning models ideal for log correlation & threat reports.",
        docsUrl = "https://platform.deepseek.com/api_keys"
    ),
    MISTRAL(
        id = "ai_mistral",
        displayName = "Mistral AI",
        shortBadge = "MISTRAL",
        protocol = AiProtocol.OPENAI_COMPATIBLE,
        defaultBaseUrl = "https://api.mistral.ai/v1/chat/completions",
        defaultModel = "mistral-small-latest",
        presetModels = listOf(
            "mistral-small-latest",
            "mistral-large-latest",
            "codestral-latest"
        ),
        description = "European open-weight and enterprise models with crisp technical accuracy.",
        docsUrl = "https://console.mistral.ai/api-keys/"
    ),
    PERPLEXITY(
        id = "ai_perplexity",
        displayName = "Perplexity",
        shortBadge = "PPLX",
        protocol = AiProtocol.OPENAI_COMPATIBLE,
        defaultBaseUrl = "https://api.perplexity.ai/chat/completions",
        defaultModel = "sonar",
        presetModels = listOf(
            "sonar",
            "sonar-pro"
        ),
        description = "Web-grounded Sonar models that cross-reference live public OSINT sources.",
        docsUrl = "https://www.perplexity.ai/settings/api"
    ),
    XAI_GROK(
        id = "ai_xai",
        displayName = "xAI Grok",
        shortBadge = "GROK",
        protocol = AiProtocol.OPENAI_COMPATIBLE,
        defaultBaseUrl = "https://api.x.ai/v1/chat/completions",
        defaultModel = "grok-3-mini",
        presetModels = listOf(
            "grok-3-mini",
            "grok-3"
        ),
        description = "Direct xAI API for fast open-source intelligence analysis and triage.",
        docsUrl = "https://console.x.ai/"
    )
}

data class ActiveAiConfig(
    val provider: AiProvider,
    val apiKey: String,
    val modelId: String,
    val endpointUrl: String
)

/**
 * Hardware-backed on-device API key vault using AndroidKeyStore AES-256-GCM.
 * Secures both Threat Intel BYOK keys and Multi-Provider BYOK AI keys + custom endpoints.
 * Keys never leave the device except in HTTPS headers sent directly to the user's chosen endpoint.
 */
object ApiKeyVault {

    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "osintme_byok_vault_aes_key_v1"
    private const val PREFS_NAME = "osintme_byok_vault_enc"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128

    private const val KEY_ACTIVE_AI_PROVIDER = "meta_active_ai_provider"
    private const val PREFIX_AI_MODEL = "meta_ai_model_"
    private const val PREFIX_AI_ENDPOINT = "meta_ai_endpoint_"
    private const val KEY_CUSTOM_AI_URL = "meta_ai_custom_url"

    private var prefs: SharedPreferences? = null

    private val _configuredProviders = MutableStateFlow<Set<ApiProvider>>(emptySet())
    val configuredProviders: StateFlow<Set<ApiProvider>> = _configuredProviders.asStateFlow()

    private val _configuredAiProviders = MutableStateFlow<Set<AiProvider>>(emptySet())
    val configuredAiProviders: StateFlow<Set<AiProvider>> = _configuredAiProviders.asStateFlow()

    private val _activeAiProvider = MutableStateFlow<AiProvider?>(null)
    val activeAiProvider: StateFlow<AiProvider?> = _activeAiProvider.asStateFlow()

    private val _vaultVersion = MutableStateFlow(0L)
    val vaultVersion: StateFlow<Long> = _vaultVersion.asStateFlow()

    fun init(context: Context) {
        if (prefs == null) {
            prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        }
        refreshState()
    }

    // ---- Threat Intelligence BYOK Keys ----

    fun saveKey(provider: ApiProvider, rawKey: String): Boolean = saveEncrypted(provider.id, rawKey)

    fun getKey(provider: ApiProvider): String? = getDecrypted(provider.id)

    fun getMaskedPreview(provider: ApiProvider): String? = maskSecret(getKey(provider))

    fun hasKey(provider: ApiProvider): Boolean = !getKey(provider).isNullOrBlank()

    fun activeCount(): Int = _configuredProviders.value.size

    fun clearKey(provider: ApiProvider) {
        prefs?.edit()?.remove(provider.id)?.apply()
        refreshState()
    }

    // ---- Multi-Provider BYOK AI Keys, Models & Custom Endpoints ----

    fun saveAiKey(provider: AiProvider, rawKey: String, modelId: String? = null, customBaseUrl: String? = null): Boolean {
        val ok = saveEncrypted(provider.id, rawKey)
        if (!ok) return false
        val sp = prefs ?: return false
        val editor = sp.edit()
        if (!modelId.isNullOrBlank()) {
            editor.putString("$PREFIX_AI_MODEL${provider.id}", modelId.trim())
        }
        if (customBaseUrl != null) {
            val cleanUrl = customBaseUrl.trim()
            if (cleanUrl.isBlank() || cleanUrl.equals(provider.defaultBaseUrl, ignoreCase = true)) {
                editor.remove("$PREFIX_AI_ENDPOINT${provider.id}")
                if (provider == AiProvider.CUSTOM_OPENAI) {
                    editor.remove(KEY_CUSTOM_AI_URL)
                }
            } else {
                editor.putString("$PREFIX_AI_ENDPOINT${provider.id}", cleanUrl)
                if (provider == AiProvider.CUSTOM_OPENAI) {
                    editor.putString(KEY_CUSTOM_AI_URL, cleanUrl)
                }
            }
        }
        // Automatically promote to active AI provider if none is active yet
        if (rawKey.trim().isNotEmpty() && _activeAiProvider.value == null) {
            editor.putString(KEY_ACTIVE_AI_PROVIDER, provider.id)
        }
        editor.apply()
        refreshState()
        return true
    }

    fun getAiKey(provider: AiProvider): String? = getDecrypted(provider.id)

    fun getAiMaskedPreview(provider: AiProvider): String? = maskSecret(getAiKey(provider))

    fun hasAiKey(provider: AiProvider): Boolean = !getAiKey(provider).isNullOrBlank()

    fun setActiveAiProvider(provider: AiProvider) {
        prefs?.edit()?.putString(KEY_ACTIVE_AI_PROVIDER, provider.id)?.apply()
        refreshState()
    }

    fun getAiModel(provider: AiProvider): String {
        val saved = prefs?.getString("$PREFIX_AI_MODEL${provider.id}", null)?.trim()
        return if (!saved.isNullOrBlank()) saved else provider.defaultModel
    }

    fun setAiModel(provider: AiProvider, modelId: String) {
        val clean = modelId.trim()
        if (clean.isNotBlank()) {
            prefs?.edit()?.putString("$PREFIX_AI_MODEL${provider.id}", clean)?.apply()
            refreshState()
        }
    }

    fun getAiEndpoint(provider: AiProvider): String {
        val perProvider = prefs?.getString("$PREFIX_AI_ENDPOINT${provider.id}", null)?.trim()
        if (!perProvider.isNullOrBlank()) return perProvider
        if (provider == AiProvider.CUSTOM_OPENAI) {
            val legacy = prefs?.getString(KEY_CUSTOM_AI_URL, null)?.trim()
            if (!legacy.isNullOrBlank()) return legacy
        }
        return provider.defaultBaseUrl
    }

    fun setAiEndpoint(provider: AiProvider, url: String) {
        val sp = prefs ?: return
        val clean = url.trim()
        val editor = sp.edit()
        if (clean.isBlank() || clean.equals(provider.defaultBaseUrl, ignoreCase = true)) {
            editor.remove("$PREFIX_AI_ENDPOINT${provider.id}")
            if (provider == AiProvider.CUSTOM_OPENAI) {
                editor.remove(KEY_CUSTOM_AI_URL)
            }
        } else {
            editor.putString("$PREFIX_AI_ENDPOINT${provider.id}", clean)
            if (provider == AiProvider.CUSTOM_OPENAI) {
                editor.putString(KEY_CUSTOM_AI_URL, clean)
            }
        }
        editor.apply()
        refreshState()
    }

    fun resetAiEndpoint(provider: AiProvider) {
        val sp = prefs ?: return
        val editor = sp.edit().remove("$PREFIX_AI_ENDPOINT${provider.id}")
        if (provider == AiProvider.CUSTOM_OPENAI) {
            editor.remove(KEY_CUSTOM_AI_URL)
        }
        editor.apply()
        refreshState()
    }

    fun hasCustomEndpoint(provider: AiProvider): Boolean {
        return !getAiEndpoint(provider).equals(provider.defaultBaseUrl, ignoreCase = true)
    }

    fun getCustomAiUrl(): String = getAiEndpoint(AiProvider.CUSTOM_OPENAI)

    fun setCustomAiUrl(url: String) = setAiEndpoint(AiProvider.CUSTOM_OPENAI, url)

    fun clearAiKey(provider: AiProvider) {
        val sp = prefs ?: return
        val editor = sp.edit().remove(provider.id)
        if (sp.getString(KEY_ACTIVE_AI_PROVIDER, null) == provider.id) {
            val fallback = AiProvider.entries.firstOrNull { it != provider && hasAiKey(it) }
            if (fallback != null) {
                editor.putString(KEY_ACTIVE_AI_PROVIDER, fallback.id)
            } else {
                editor.remove(KEY_ACTIVE_AI_PROVIDER)
            }
        }
        editor.apply()
        refreshState()
    }

    fun getActiveAiConfig(): ActiveAiConfig? {
        val provider = _activeAiProvider.value
            ?: AiProvider.entries.firstOrNull { hasAiKey(it) }
            ?: return null
        val key = getAiKey(provider) ?: return null
        val model = getAiModel(provider)
        val endpoint = getAiEndpoint(provider)
        return ActiveAiConfig(
            provider = provider,
            apiKey = key,
            modelId = model,
            endpointUrl = endpoint
        )
    }

    fun getAiConfigFor(provider: AiProvider): ActiveAiConfig? {
        val key = getAiKey(provider) ?: return null
        val model = getAiModel(provider)
        val endpoint = getAiEndpoint(provider)
        return ActiveAiConfig(
            provider = provider,
            apiKey = key,
            modelId = model,
            endpointUrl = endpoint
        )
    }

    fun activeAiCount(): Int = _configuredAiProviders.value.size

    fun clearAll() {
        prefs?.edit()?.clear()?.apply()
        refreshState()
    }

    // ---- Internal AES-256-GCM Encryption ----

    private fun saveEncrypted(prefKey: String, rawValue: String): Boolean {
        val clean = rawValue.trim()
        val sp = prefs ?: return false
        if (clean.isEmpty()) {
            sp.edit().remove(prefKey).apply()
            refreshState()
            return true
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())
            val iv = cipher.iv
            val encrypted = cipher.doFinal(clean.toByteArray(StandardCharsets.UTF_8))

            val payload = ByteArray(1 + iv.size + encrypted.size)
            payload[0] = iv.size.toByte()
            System.arraycopy(iv, 0, payload, 1, iv.size)
            System.arraycopy(encrypted, 0, payload, 1 + iv.size, encrypted.size)

            val encoded = Base64.encodeToString(payload, Base64.NO_WRAP)
            sp.edit().putString(prefKey, encoded).apply()
            refreshState()
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun getDecrypted(prefKey: String): String? {
        val sp = prefs ?: return null
        val encoded = sp.getString(prefKey, null) ?: return null
        return try {
            val payload = Base64.decode(encoded, Base64.NO_WRAP)
            if (payload.size < 14) return null
            val ivLength = payload[0].toInt() and 0xFF
            if (ivLength <= 0 || payload.size <= 1 + ivLength) return null

            val iv = payload.copyOfRange(1, 1 + ivLength)
            val cipherText = payload.copyOfRange(1 + ivLength, payload.size)

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateSecretKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            String(cipher.doFinal(cipherText), StandardCharsets.UTF_8).takeIf { it.isNotBlank() }
        } catch (_: Exception) {
            null
        }
    }

    private fun maskSecret(key: String?): String? {
        if (key.isNullOrBlank()) return null
        return when {
            key.length <= 8 -> "••••••••"
            else -> "${key.take(4)}••••••••${key.takeLast(4)}"
        }
    }

    private fun refreshState() {
        val activeThreat = ApiProvider.entries.filter { hasKey(it) }.toSet()
        _configuredProviders.value = activeThreat

        val activeAiSet = AiProvider.entries.filter { hasAiKey(it) }.toSet()
        _configuredAiProviders.value = activeAiSet

        val savedId = prefs?.getString(KEY_ACTIVE_AI_PROVIDER, null)
        val chosen = AiProvider.entries.firstOrNull { it.id == savedId && it in activeAiSet }
            ?: activeAiSet.firstOrNull()
        _activeAiProvider.value = chosen
        _vaultVersion.value += 1L
    }

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val existing = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }
}
