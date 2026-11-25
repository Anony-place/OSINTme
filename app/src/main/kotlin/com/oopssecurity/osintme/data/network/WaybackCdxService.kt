package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.util.PivotEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Request
import java.net.URLEncoder

enum class WaybackCategory(val label: String) {
    SENSITIVE("Sensitive"),
    DOCUMENT("Docs & Data"),
    DELETED("Deleted / 4xx"),
    PAGE("Pages")
}

data class WaybackSnapshot(
    val timestamp: String,
    val formattedDate: String,
    val originalUrl: String,
    val statusCode: String,
    val mimeType: String,
    val contentLength: String,
    val category: WaybackCategory,
    val matchedSignal: String?,
    val archiveUrl: String
)

data class WaybackReport(
    val targetDomain: String,
    val snapshots: List<WaybackSnapshot>,
    val sensitiveCount: Int,
    val documentCount: Int,
    val deletedCount: Int,
    val earliestYear: String?,
    val latestYear: String?,
    val discoveredHosts: List<String>
)

/**
 * Live passive Wayback Machine CDX Index Explorer (web.archive.org).
 * Surfaces historical URLs, deleted pages, leaked backup/config endpoints,
 * archived documents, and historical subdomains with direct snapshot viewing.
 */
object WaybackCdxService {

    private val json = Json { ignoreUnknownKeys = true }

    private val SENSITIVE_PATTERNS = listOf(
        ".env", ".git", ".sql", ".bak", ".backup", ".old", ".zip", ".tar", ".gz",
        "wp-config", "phpinfo", "config.", "admin", "login", "dashboard",
        "swagger", "graphql", "api/v", "secret", "token", "credentials", "debug", "phpMyAdmin"
    )

    private val DOCUMENT_EXTENSIONS = listOf(
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".json", ".xml", ".txt", ".yml", ".yaml"
    )

    suspend fun searchArchive(rawTarget: String, limit: Int = 120): Result<WaybackReport> = withContext(Dispatchers.IO) {
        val domain = PivotEngine.cleanDomainCandidate(rawTarget)
        if (domain.isBlank() || !domain.contains(".")) {
            return@withContext Result.failure(Exception("Enter a valid domain or URL (e.g., example.com)"))
        }

        try {
            val encodedQuery = URLEncoder.encode("$domain/*", "UTF-8")
            val cdxUrl = "https://web.archive.org/cdx/search/cdx" +
                "?url=$encodedQuery&output=json&collapse=urlkey&limit=$limit" +
                "&fl=timestamp,original,statuscode,mimetype,length"

            val req = Request.Builder()
                .url(cdxUrl)
                .header("Accept", "application/json")
                .get()
                .build()

            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) {
                    return@withContext Result.failure(Exception("Wayback CDX returned HTTP ${resp.code}"))
                }
                val body = resp.body?.string().orEmpty().trim()
                if (body.isBlank() || body == "[]") {
                    return@withContext Result.success(
                        WaybackReport(
                            targetDomain = domain,
                            snapshots = emptyList(),
                            sensitiveCount = 0,
                            documentCount = 0,
                            deletedCount = 0,
                            earliestYear = null,
                            latestYear = null,
                            discoveredHosts = emptyList()
                        )
                    )
                }

                val report = parseCdxJson(domain, body)
                Result.success(report)
            }
        } catch (e: Exception) {
            Result.failure(Exception("Wayback archive lookup failed: ${e.message ?: "timeout"}"))
        }
    }

    internal fun parseCdxJson(domain: String, rawJson: String): WaybackReport {
        val rows = json.parseToJsonElement(rawJson).jsonArray
        val snapshots = mutableListOf<WaybackSnapshot>()
        val hosts = linkedSetOf<String>()

        // Row 0 is header: ["timestamp","original","statuscode","mimetype","length"]
        rows.drop(1).forEach { rowEl ->
            val cols = rowEl.jsonArray
            if (cols.size >= 5) {
                val ts = cols[0].jsonPrimitive.contentOrNull.orEmpty()
                val original = cols[1].jsonPrimitive.contentOrNull.orEmpty()
                val status = cols[2].jsonPrimitive.contentOrNull.orEmpty().ifBlank { "-" }
                val mime = cols[3].jsonPrimitive.contentOrNull.orEmpty().ifBlank { "unknown" }
                val length = cols[4].jsonPrimitive.contentOrNull.orEmpty().ifBlank { "-" }

                if (ts.length >= 8 && original.isNotBlank()) {
                    val (cat, signal) = classifySnapshot(original, status, mime)
                    PivotEngine.extractHost(original)?.let { h ->
                        if (h != domain && hosts.size < 25) hosts.add(h)
                    }
                    snapshots.add(
                        WaybackSnapshot(
                            timestamp = ts,
                            formattedDate = formatCdxTimestamp(ts),
                            originalUrl = original,
                            statusCode = status,
                            mimeType = mime,
                            contentLength = length,
                            category = cat,
                            matchedSignal = signal,
                            archiveUrl = "https://web.archive.org/web/$ts/$original"
                        )
                    )
                }
            }
        }

        // Prioritize sensitive & document hits near top while preserving recency
        val sorted = snapshots.sortedWith(
            compareBy<WaybackSnapshot> {
                when (it.category) {
                    WaybackCategory.SENSITIVE -> 0
                    WaybackCategory.DOCUMENT -> 1
                    WaybackCategory.DELETED -> 2
                    WaybackCategory.PAGE -> 3
                }
            }.thenByDescending { it.timestamp }
        )

        val years = snapshots.mapNotNull { it.timestamp.take(4).takeIf { y -> y.all(Char::isDigit) } }
        return WaybackReport(
            targetDomain = domain,
            snapshots = sorted,
            sensitiveCount = sorted.count { it.category == WaybackCategory.SENSITIVE },
            documentCount = sorted.count { it.category == WaybackCategory.DOCUMENT },
            deletedCount = sorted.count { it.category == WaybackCategory.DELETED },
            earliestYear = years.minOrNull(),
            latestYear = years.maxOrNull(),
            discoveredHosts = hosts.toList()
        )
    }

    fun classifySnapshot(url: String, statusCode: String, mimeType: String): Pair<WaybackCategory, String?> {
        val lowerUrl = url.lowercase()
        val matchedSensitive = SENSITIVE_PATTERNS.firstOrNull { lowerUrl.contains(it.lowercase()) }
        if (matchedSensitive != null) {
            return WaybackCategory.SENSITIVE to "Matched '$matchedSensitive'"
        }
        val lowerPath = lowerUrl.substringBefore('?')
        val matchedDoc = DOCUMENT_EXTENSIONS.firstOrNull { lowerPath.endsWith(it) }
        if (matchedDoc != null || mimeType.contains("pdf", true) || mimeType.contains("json", true)) {
            return WaybackCategory.DOCUMENT to (matchedDoc ?: mimeType)
        }
        if (statusCode.startsWith("4") || statusCode == "410") {
            return WaybackCategory.DELETED to "HTTP $statusCode archived"
        }
        return WaybackCategory.PAGE to null
    }

    private fun formatCdxTimestamp(ts: String): String {
        return if (ts.length >= 14) {
            "${ts.substring(0, 4)}-${ts.substring(4, 6)}-${ts.substring(6, 8)} ${ts.substring(8, 10)}:${ts.substring(10, 12)}"
        } else if (ts.length >= 8) {
            "${ts.substring(0, 4)}-${ts.substring(4, 6)}-${ts.substring(6, 8)}"
        } else ts
    }
}
