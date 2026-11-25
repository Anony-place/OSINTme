package com.oopssecurity.osintme.ui.dorks

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.model.DorkPreset
import com.oopssecurity.osintme.data.network.AiCraftedDork
import com.oopssecurity.osintme.data.network.ByokAiService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.net.URLEncoder

enum class SearchEngineTarget(val badge: String, val label: String) {
    ALL("ALL", "All Engines"),
    GOOGLE("GOOGLE", "Google"),
    SHODAN("SHODAN", "Shodan"),
    GITHUB("GITHUB", "GitHub"),
    CENSYS("CENSYS", "Censys"),
    CRTSH("CRTSH", "crt.sh"),
    WAYBACK("WAYBACK", "Wayback"),
    VIRUSTOTAL("VT", "VirusTotal")
}

data class MultiEngineDork(
    val id: String,
    val engine: SearchEngineTarget,
    val category: String,
    val label: String,
    val explanation: String,
    val formattedQuery: String,
    val launchUrl: String
)

data class DorkUiState(
    val target: String = "",
    val selectedEngine: SearchEngineTarget = SearchEngineTarget.ALL,
    val dorks: List<MultiEngineDork> = emptyList(),
    val aiGoalInput: String = "",
    val aiGenerating: Boolean = false,
    val aiError: String? = null,
    val aiProviderMeta: String? = null,
    val aiCraftedDorks: List<MultiEngineDork> = emptyList()
)

class DorkViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(DorkUiState(dorks = buildMatrix("", SearchEngineTarget.ALL)))
    val uiState: StateFlow<DorkUiState> = _uiState.asStateFlow()

    fun setTarget(target: String) {
        val clean = target.trim()
            .removePrefix("https://")
            .removePrefix("http://")
            .removePrefix("www.")
            .substringBefore("/")
            .substringBefore("?")
            .substringBefore("#")
            .replace(Regex("\\s+"), "")
        _uiState.update { state ->
            state.copy(
                target = clean,
                dorks = buildMatrix(clean, state.selectedEngine)
            )
        }
    }

    fun selectEngine(engine: SearchEngineTarget) {
        _uiState.update { state ->
            state.copy(
                selectedEngine = engine,
                dorks = buildMatrix(state.target, engine)
            )
        }
    }

    fun updateAiGoal(goal: String) {
        _uiState.update { it.copy(aiGoalInput = goal) }
    }

    fun generateAiDorks() {
        val state = _uiState.value
        val goal = state.aiGoalInput.trim()
        val target = state.target.trim().ifBlank { "example.com" }
        if (goal.isBlank() || state.aiGenerating) return

        if (ApiKeyVault.getActiveAiConfig() == null) {
            _uiState.update { it.copy(aiError = "No BYOK AI key connected. Tap Setup AI Key to add OpenRouter, Claude, OpenAI, Gemini, or Groq.") }
            return
        }

        _uiState.update { it.copy(aiGenerating = true, aiError = null) }
        viewModelScope.launch {
            ByokAiService.generateCustomDorks(target, goal).fold(
                onSuccess = { (crafted, meta) ->
                    val mapped = crafted.mapIndexed { idx, item ->
                        val eng = mapAiEngine(item.engine)
                        MultiEngineDork(
                            id = "ai_${idx}_${System.currentTimeMillis()}",
                            engine = eng,
                            category = "AI CRAFTED",
                            label = item.title,
                            explanation = "Crafted by ${meta.providerName} (${meta.modelId})",
                            formattedQuery = item.query,
                            launchUrl = buildLaunchUrl(eng, item.query, target)
                        )
                    }
                    _uiState.update {
                        it.copy(
                            aiGenerating = false,
                            aiProviderMeta = "${meta.providerName} • ${meta.modelId} • ${meta.latencyMs}ms",
                            aiCraftedDorks = mapped,
                            aiError = if (mapped.isEmpty()) "AI returned no structured queries — try rephrasing your goal." else null
                        )
                    }
                },
                onFailure = { err ->
                    _uiState.update { it.copy(aiGenerating = false, aiError = err.message ?: "AI generation failed") }
                }
            )
        }
    }

    private fun mapAiEngine(raw: String): SearchEngineTarget = when (raw.uppercase()) {
        "SHODAN" -> SearchEngineTarget.SHODAN
        "GITHUB" -> SearchEngineTarget.GITHUB
        "CENSYS" -> SearchEngineTarget.CENSYS
        "CRTSH" -> SearchEngineTarget.CRTSH
        "WAYBACK" -> SearchEngineTarget.WAYBACK
        "VT", "VIRUSTOTAL" -> SearchEngineTarget.VIRUSTOTAL
        else -> SearchEngineTarget.GOOGLE
    }

    private fun buildMatrix(rawTarget: String, filter: SearchEngineTarget): List<MultiEngineDork> {
        val t = rawTarget.ifBlank { "example.com" }
        val all = listOf(
            // GOOGLE
            dork("g_configs", SearchEngineTarget.GOOGLE, "EXPOSURE", "Exposed .env, YAML & Config Files", "Finds indexed environment secrets, credentials, and YAML configs.", "site:$t (ext:env OR ext:yml OR ext:yaml OR ext:xml OR ext:json) \"DB_PASSWORD\" OR \"API_KEY\" OR \"secret\"", t),
            dork("g_docs", SearchEngineTarget.GOOGLE, "DOCS", "Confidential PDFs & Spreadsheets", "Surfaces internal documents and reports indexed publicly.", "site:$t (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv) \"confidential\" OR \"internal\"", t),
            dork("g_admin", SearchEngineTarget.GOOGLE, "AUTH", "Admin Consoles & Login Portals", "Locates exposed management panels, SSO gateways, and staging logins.", "site:$t (inurl:admin OR inurl:login OR inurl:portal OR inurl:dashboard OR inurl:sso)", t),
            dork("g_dir", SearchEngineTarget.GOOGLE, "DIRS", "Open Directory Listings (Index Of)", "Detects misconfigured servers exposing backups, logs, or dumps.", "site:$t intitle:\"index of\" (backup OR dump OR logs OR private OR sql)", t),
            dork("g_cloud", SearchEngineTarget.GOOGLE, "CLOUD", "Public S3 / Azure / GCP Buckets", "Hunts cloud object storage containers referencing the target.", "(site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com) \"$t\"", t),
            dork("g_git", SearchEngineTarget.GOOGLE, "SECRETS", "Exposed .git & wp-config Endpoints", "Checks for accidentally indexed source repositories and PHP configs.", "site:$t (inurl:/.git/ OR inurl:/.env OR inurl:/wp-config.php OR inurl:phpinfo.php)", t),
            dork("g_sub", SearchEngineTarget.GOOGLE, "SUBDOMAINS", "Indexed Subdomains Excluding www", "Enumerates subdomains indexed by Google search.", "site:*.$t -www.$t", t),
            dork("g_paste", SearchEngineTarget.GOOGLE, "LEAKS", "Pastebin & Public Paste Mentions", "Searches public paste dumps for mentions of target domain or credentials.", "(site:pastebin.com OR site:rentry.co OR site:dpaste.org) \"$t\"", t),
            // SHODAN
            dork("s_ssl", SearchEngineTarget.SHODAN, "INFRA", "Shodan SSL Certificate Host Hunt", "Discovers origin IPs and hidden infrastructure presenting target TLS certs.", "ssl.cert.subject.cn:\"$t\"", t),
            dork("s_host", SearchEngineTarget.SHODAN, "PORTS", "Shodan Hostname & Exposed Services", "Lists open ports, banners, and CVEs matching target hostname.", "hostname:\"$t\"", t),
            dork("s_http", SearchEngineTarget.SHODAN, "WEB", "Shodan HTTP Title & Favicons", "Finds web servers and staging mirrors serving target domain content.", "http.html:\"$t\" OR http.title:\"$t\"", t),
            // GITHUB
            dork("gh_secrets", SearchEngineTarget.GITHUB, "CODE LEAKS", "GitHub Leaked Keys & Passwords", "Hunts public repositories referencing target with credential keywords.", "\"$t\" (password OR api_key OR secret OR token OR Authorization)", t),
            dork("gh_env", SearchEngineTarget.GITHUB, "CONFIGS", "GitHub .env & Internal Endpoints", "Discovers staging hosts, internal API URLs, and config files in public code.", "\"$t\" (filename:.env OR filename:config.json OR \"staging.\" OR \"internal.\")", t),
            // CENSYS
            dork("ce_hosts", SearchEngineTarget.CENSYS, "CERTS", "Censys TLS & Origin IP Search", "Maps origin IPs behind CDNs using Censys certificate & service indexes.", "services.tls.certificates.leaf_data.names: $t", t),
            // CRTSH
            dork("crt_sub", SearchEngineTarget.CRTSH, "CT LOGS", "crt.sh Certificate Transparency Logs", "Enumerates every historical TLS certificate issued for subdomains.", "%.$t", t),
            // WAYBACK
            dork("wb_urls", SearchEngineTarget.WAYBACK, "ARCHIVE", "Wayback Machine Wildcard History", "Browse archived snapshots and historical URL trees on archive.org.", "https://web.archive.org/web/*/$t/*", t),
            // VIRUSTOTAL
            dork("vt_dom", SearchEngineTarget.VIRUSTOTAL, "THREAT", "VirusTotal Domain Graph & Relations", "Open VirusTotal passive DNS, communicating files, and subdomain relations.", t, t)
        )

        return if (filter == SearchEngineTarget.ALL) all else all.filter { it.engine == filter }
    }

    private fun dork(
        id: String,
        engine: SearchEngineTarget,
        category: String,
        label: String,
        explanation: String,
        query: String,
        target: String
    ): MultiEngineDork {
        return MultiEngineDork(
            id = id,
            engine = engine,
            category = category,
            label = label,
            explanation = explanation,
            formattedQuery = query,
            launchUrl = buildLaunchUrl(engine, query, target)
        )
    }

    private fun buildLaunchUrl(engine: SearchEngineTarget, query: String, target: String): String {
        val enc = URLEncoder.encode(query, "UTF-8")
        val encTarget = URLEncoder.encode(target.trim(), "UTF-8")
        return when (engine) {
            SearchEngineTarget.SHODAN -> "https://www.shodan.io/search?query=$enc"
            SearchEngineTarget.GITHUB -> "https://github.com/search?q=$enc&type=code"
            SearchEngineTarget.CENSYS -> "https://search.censys.io/search?resource=hosts&q=$enc"
            SearchEngineTarget.CRTSH -> "https://crt.sh/?q=${URLEncoder.encode("%.$target", "UTF-8")}"
            SearchEngineTarget.WAYBACK -> "https://web.archive.org/web/*/$encTarget/*"
            SearchEngineTarget.VIRUSTOTAL -> "https://www.virustotal.com/gui/domain/$encTarget"
            else -> "https://www.google.com/search?q=$enc"
        }
    }
}
