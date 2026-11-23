package com.oopssecurity.osintme.ui.dorks

import androidx.lifecycle.ViewModel
import com.oopssecurity.osintme.data.model.DorkPreset
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class GeneratedDorkItem(
    val preset: DorkPreset,
    val formattedQuery: String
)

data class DorkUiState(
    val target: String = "",
    val selectedCategory: String = "ALL",
    val dorks: List<GeneratedDorkItem> = emptyList()
)

class DorkViewModel : ViewModel() {

    val PRESET_CATEGORIES = listOf("ALL", "DOCS", "AUTH", "STORAGE", "DIRECTORIES", "CONFIGS", "PASTES")

    private val ALL_PRESETS = listOf(
        DorkPreset(
            id = "docs_pdf",
            category = "DOCS",
            label = "Exposed Confidential Documents",
            queryTemplate = "site:%s (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx) \"confidential\" OR \"internal use only\"",
            explanation = "Locates indexing of sensitive PDFs and Office spreadsheets tagged as confidential."
        ),
        DorkPreset(
            id = "login_admin",
            category = "AUTH",
            label = "Admin & Authentication Portals",
            queryTemplate = "site:%s inurl:admin OR inurl:login OR inurl:signin OR inurl:portal OR inurl:dashboard",
            explanation = "Discovers administrative consoles and exposed employee sign-in pages."
        ),
        DorkPreset(
            id = "cloud_s3",
            category = "STORAGE",
            label = "Exposed AWS S3 Buckets",
            queryTemplate = "site:s3.amazonaws.com \"%s\"",
            explanation = "Scans Amazon S3 cloud buckets referencing target domain or company name."
        ),
        DorkPreset(
            id = "cloud_azure",
            category = "STORAGE",
            label = "Exposed Azure Blob Storage",
            queryTemplate = "site:blob.core.windows.net \"%s\"",
            explanation = "Finds public Microsoft Azure blob containers holding target files."
        ),
        DorkPreset(
            id = "cloud_gcp",
            category = "STORAGE",
            label = "Google Cloud Storage Buckets",
            queryTemplate = "site:storage.googleapis.com \"%s\"",
            explanation = "Identifies public Google Cloud Platform asset and data buckets."
        ),
        DorkPreset(
            id = "open_directories",
            category = "DIRECTORIES",
            label = "Open Server Directories (Index of)",
            queryTemplate = "site:%s intitle:\"index of\" OR intitle:\"index.of\" (backup OR logs OR dump OR private)",
            explanation = "Uncovers misconfigured web servers with public file browsing enabled."
        ),
        DorkPreset(
            id = "env_configs",
            category = "CONFIGS",
            label = "Exposed Environment & Database Configs",
            queryTemplate = "site:%s (ext:env OR ext:yml OR ext:yaml OR ext:xml OR ext:json) \"DB_PASSWORD\" OR \"API_KEY\" OR \"secret\"",
            explanation = "Searches for leaked environment variables, API secrets, and database credentials."
        ),
        DorkPreset(
            id = "git_exposed",
            category = "CONFIGS",
            label = "Exposed .git Repository Folders",
            queryTemplate = "site:%s inurl:/.git/ OR inurl:/.env OR inurl:/wp-config.php",
            explanation = "Identifies exposed source control repositories and framework secrets."
        ),
        DorkPreset(
            id = "paste_sites",
            category = "PASTES",
            label = "Pastebin & Public Paste Leaks",
            queryTemplate = "site:pastebin.com OR site:rentry.co OR site:ghostbin.com \"%s\"",
            explanation = "Finds credential dumps or source code snippets shared on public paste sites."
        ),
        DorkPreset(
            id = "subdomains_google",
            category = "DOCS",
            label = "Discovered Subdomains Index",
            queryTemplate = "site:*.%s -www.%s",
            explanation = "Lists subdomains cataloged in Google's index omitting the primary www site."
        )
    )

    private val _uiState = MutableStateFlow(DorkUiState(dorks = generateDorks("", "ALL")))
    val uiState: StateFlow<DorkUiState> = _uiState.asStateFlow()

    fun setTarget(target: String) {
        val clean = target.trim().removePrefix("https://").removePrefix("http://").removePrefix("www.")
        _uiState.value = _uiState.value.copy(
            target = clean,
            dorks = generateDorks(clean, _uiState.value.selectedCategory)
        )
    }

    fun selectCategory(category: String) {
        _uiState.value = _uiState.value.copy(
            selectedCategory = category,
            dorks = generateDorks(_uiState.value.target, category)
        )
    }

    private fun generateDorks(target: String, category: String): List<GeneratedDorkItem> {
        val effectiveTarget = if (target.isEmpty()) "example.com" else target
        val filtered = if (category == "ALL") {
            ALL_PRESETS
        } else {
            ALL_PRESETS.filter { it.category == category }
        }

        return filtered.map { preset ->
            val formatted = when {
                preset.queryTemplate.count { it == '%' } == 2 -> String.format(preset.queryTemplate, effectiveTarget, effectiveTarget)
                preset.queryTemplate.contains("%s") -> String.format(preset.queryTemplate, effectiveTarget)
                else -> preset.queryTemplate
            }
            GeneratedDorkItem(preset, formatted)
        }
    }
}
