package com.oopssecurity.osintme.data.network

import android.util.Base64
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.local.ApiProvider
import com.oopssecurity.osintme.data.model.AbuseIpdbReport
import com.oopssecurity.osintme.data.model.ApiKeyTestResult
import com.oopssecurity.osintme.data.model.MalwareBazaarReport
import com.oopssecurity.osintme.data.model.UrlScanHit
import com.oopssecurity.osintme.data.model.UrlScanSummary
import com.oopssecurity.osintme.data.model.VirusTotalReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Real threat intelligence integrations supporting both free public endpoints
 * (URLScan search, MalwareBazaar) and user-supplied BYOK keys from ApiKeyVault
 * (VirusTotal v3, AbuseIPDB v2, Full Shodan, URLScan live scan, abuse.ch Auth-Key).
 */
object ProThreatApiServices {

    private fun authClient() = OsintApiClient.client.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    // -------------------------------------------------------------------------
    // VirusTotal v3 (BYOK)
    // -------------------------------------------------------------------------

    suspend fun lookupVirusTotalDomain(domain: String): Result<VirusTotalReport> =
        lookupVirusTotal("domains/${encodePath(domain)}", domain, "domain")

    suspend fun lookupVirusTotalIp(ip: String): Result<VirusTotalReport> =
        lookupVirusTotal("ip_addresses/${encodePath(ip)}", ip, "ip")

    suspend fun lookupVirusTotalHash(hash: String): Result<VirusTotalReport> =
        lookupVirusTotal("files/${encodePath(hash.trim().lowercase())}", hash.trim().lowercase(), "file")

    suspend fun lookupVirusTotalUrl(url: String): Result<VirusTotalReport> {
        val urlId = Base64.encodeToString(
            url.trim().toByteArray(StandardCharsets.UTF_8),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
        return lookupVirusTotal("urls/$urlId", url.trim(), "url")
    }

    private suspend fun lookupVirusTotal(
        endpointPath: String,
        target: String,
        type: String
    ): Result<VirusTotalReport> = withContext(Dispatchers.IO) {
        val apiKey = ApiKeyVault.getKey(ApiProvider.VIRUSTOTAL)
            ?: return@withContext Result.failure(Exception("VirusTotal API key not configured in API Vault"))

        try {
            val req = Request.Builder()
                .url("https://www.virustotal.com/api/v3/$endpointPath")
                .header("x-apikey", apiKey)
                .header("Accept", "application/json")
                .get()
                .build()

            authClient().newCall(req).execute().use { resp ->
                if (resp.code == 404) {
                    return@withContext Result.success(
                        VirusTotalReport(
                            target = target,
                            targetType = type,
                            popularThreatName = "Not found in VirusTotal database"
                        )
                    )
                }
                if (resp.code == 401 || resp.code == 403) {
                    return@withContext Result.failure(Exception("VirusTotal rejected API key (HTTP ${resp.code})"))
                }
                if (resp.code == 429) {
                    return@withContext Result.failure(Exception("VirusTotal rate limit exceeded (HTTP 429)"))
                }
                if (!resp.isSuccessful) {
                    return@withContext Result.failure(Exception("VirusTotal returned HTTP ${resp.code}"))
                }

                val root = JSONObject(resp.body?.string() ?: "{}")
                val attrs = root.optJSONObject("data")?.optJSONObject("attributes")
                    ?: return@withContext Result.failure(Exception("Unexpected VirusTotal response"))

                val stats = attrs.optJSONObject("last_analysis_stats")
                val categoriesObj = attrs.optJSONObject("categories")
                val categories = mutableListOf<String>()
                categoriesObj?.keys()?.forEach { k ->
                    val v = categoriesObj.optString(k, "")
                    if (v.isNotBlank() && !categories.contains(v)) categories.add(v)
                }

                val threatLabel = attrs.optJSONObject("popular_threat_classification")
                    ?.optString("suggested_threat_label", "")
                    .orEmpty()

                Result.success(
                    VirusTotalReport(
                        target = target,
                        targetType = type,
                        maliciousCount = stats?.optInt("malicious", 0) ?: 0,
                        suspiciousCount = stats?.optInt("suspicious", 0) ?: 0,
                        harmlessCount = stats?.optInt("harmless", 0) ?: 0,
                        undetectedCount = stats?.optInt("undetected", 0) ?: 0,
                        reputation = attrs.optInt("reputation", 0),
                        categories = categories.take(6),
                        popularThreatName = threatLabel,
                        lastAnalysisDate = attrs.optLong("last_analysis_date", 0L)
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(Exception("VirusTotal query failed: ${e.message ?: "network error"}"))
        }
    }

    // -------------------------------------------------------------------------
    // AbuseIPDB v2 (BYOK)
    // -------------------------------------------------------------------------

    suspend fun lookupAbuseIpdb(ip: String): Result<AbuseIpdbReport> = withContext(Dispatchers.IO) {
        val apiKey = ApiKeyVault.getKey(ApiProvider.ABUSEIPDB)
            ?: return@withContext Result.failure(Exception("AbuseIPDB API key not configured in API Vault"))

        try {
            val encodedIp = URLEncoder.encode(ip.trim(), "UTF-8")
            val req = Request.Builder()
                .url("https://api.abuseipdb.com/api/v2/check?ipAddress=$encodedIp&maxAgeInDays=90")
                .header("Key", apiKey)
                .header("Accept", "application/json")
                .get()
                .build()

            authClient().newCall(req).execute().use { resp ->
                if (resp.code == 401 || resp.code == 403) {
                    return@withContext Result.failure(Exception("AbuseIPDB rejected API key (HTTP ${resp.code})"))
                }
                if (resp.code == 429) {
                    return@withContext Result.failure(Exception("AbuseIPDB daily quota reached (HTTP 429)"))
                }
                if (!resp.isSuccessful) {
                    return@withContext Result.failure(Exception("AbuseIPDB returned HTTP ${resp.code}"))
                }

                val data = JSONObject(resp.body?.string() ?: "{}").optJSONObject("data")
                    ?: return@withContext Result.failure(Exception("Unexpected AbuseIPDB response"))

                Result.success(
                    AbuseIpdbReport(
                        ipAddress = data.optString("ipAddress", ip),
                        abuseConfidenceScore = data.optInt("abuseConfidenceScore", 0),
                        totalReports = data.optInt("totalReports", 0),
                        numDistinctUsers = data.optInt("numDistinctUsers", 0),
                        isp = data.optString("isp", ""),
                        domain = data.optString("domain", ""),
                        usageType = data.optString("usageType", ""),
                        countryCode = data.optString("countryCode", ""),
                        isTor = data.optBoolean("isTor", false),
                        isWhitelisted = data.optBoolean("isWhitelisted", false),
                        lastReportedAt = data.optString("lastReportedAt", "")
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(Exception("AbuseIPDB query failed: ${e.message ?: "network error"}"))
        }
    }

    // -------------------------------------------------------------------------
    // URLScan.io (Public Search + optional BYOK Live Submission)
    // -------------------------------------------------------------------------

    suspend fun searchUrlScan(domainOrIp: String, isIp: Boolean = false): Result<UrlScanSummary> =
        withContext(Dispatchers.IO) {
            try {
                val queryExpr = if (isIp) "ip:${domainOrIp.trim()}" else "domain:${domainOrIp.trim()}"
                val encodedQ = URLEncoder.encode(queryExpr, "UTF-8")
                val reqBuilder = Request.Builder()
                    .url("https://urlscan.io/api/v1/search/?q=$encodedQ&size=8")
                    .header("Accept", "application/json")
                    .get()

                ApiKeyVault.getKey(ApiProvider.URLSCAN)?.let { key ->
                    reqBuilder.header("API-Key", key)
                }

                authClient().newCall(reqBuilder.build()).execute().use { resp ->
                    if (!resp.isSuccessful) {
                        return@withContext Result.failure(Exception("URLScan search returned HTTP ${resp.code}"))
                    }
                    val root = JSONObject(resp.body?.string() ?: "{}")
                    val total = root.optInt("total", 0)
                    val arr = root.optJSONArray("results")
                    val hits = mutableListOf<UrlScanHit>()

                    if (arr != null) {
                        for (i in 0 until minOf(arr.length(), 8)) {
                            val item = arr.optJSONObject(i) ?: continue
                            val page = item.optJSONObject("page")
                            val task = item.optJSONObject("task")
                            hits.add(
                                UrlScanHit(
                                    scanId = item.optString("_id", ""),
                                    pageUrl = page?.optString("url", "") ?: task?.optString("url", "").orEmpty(),
                                    pageDomain = page?.optString("domain", "").orEmpty(),
                                    ip = page?.optString("ip", "").orEmpty(),
                                    asnName = page?.optString("asnname", "").orEmpty(),
                                    country = page?.optString("country", "").orEmpty(),
                                    server = page?.optString("server", "").orEmpty(),
                                    timestamp = task?.optString("time", "").orEmpty(),
                                    resultUrl = item.optString("result", "")
                                )
                            )
                        }
                    }

                    Result.success(
                        UrlScanSummary(
                            query = queryExpr,
                            totalHits = total,
                            recentScans = hits
                        )
                    )
                }
            } catch (e: Exception) {
                Result.failure(Exception("URLScan search failed: ${e.message ?: "network error"}"))
            }
        }

    suspend fun submitUrlScanLive(targetUrl: String): Result<String> = withContext(Dispatchers.IO) {
        val apiKey = ApiKeyVault.getKey(ApiProvider.URLSCAN)
            ?: return@withContext Result.failure(Exception("URLScan API key required for live submissions"))
        try {
            val payload = JSONObject().apply {
                put("url", targetUrl.trim())
                put("visibility", "unlisted")
            }.toString()
            val req = Request.Builder()
                .url("https://urlscan.io/api/v1/scan/")
                .header("API-Key", apiKey)
                .header("Content-Type", "application/json")
                .post(payload.toRequestBody("application/json".toMediaType()))
                .build()

            authClient().newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) {
                    return@withContext Result.failure(Exception("URLScan submit failed (HTTP ${resp.code})"))
                }
                val root = JSONObject(resp.body?.string() ?: "{}")
                val resultLink = root.optString("result", "")
                if (resultLink.isNotBlank()) Result.success(resultLink)
                else Result.failure(Exception("URLScan accepted request without result URL"))
            }
        } catch (e: Exception) {
            Result.failure(Exception("URLScan submission failed: ${e.message ?: "network error"}"))
        }
    }

    // -------------------------------------------------------------------------
    // abuse.ch MalwareBazaar Hash Lookup (Optional BYOK Auth-Key)
    // -------------------------------------------------------------------------

    suspend fun lookupMalwareBazaarHash(hash: String): Result<MalwareBazaarReport> =
        withContext(Dispatchers.IO) {
            val cleanHash = hash.trim().lowercase()
            try {
                val formBody = FormBody.Builder()
                    .add("query", "get_info")
                    .add("hash", cleanHash)
                    .build()

                val reqBuilder = Request.Builder()
                    .url("https://mb-api.abuse.ch/api/v1/")
                    .post(formBody)

                ApiKeyVault.getKey(ApiProvider.ABUSECH)?.let { authKey ->
                    reqBuilder.header("Auth-Key", authKey)
                }

                authClient().newCall(reqBuilder.build()).execute().use { resp ->
                    if (resp.code == 401 || resp.code == 403) {
                        return@withContext Result.success(
                            MalwareBazaarReport(
                                hash = cleanHash,
                                found = false,
                                note = "MalwareBazaar requires a free abuse.ch Auth-Key in API Vault."
                            )
                        )
                    }
                    if (!resp.isSuccessful) {
                        return@withContext Result.failure(Exception("MalwareBazaar returned HTTP ${resp.code}"))
                    }
                    val root = JSONObject(resp.body?.string() ?: "{}")
                    val status = root.optString("query_status", "")
                    if (status == "hash_not_found" || status == "no_results") {
                        return@withContext Result.success(
                            MalwareBazaarReport(
                                hash = cleanHash,
                                found = false,
                                note = "No known malware sample matching this hash in MalwareBazaar."
                            )
                        )
                    }
                    if (status != "ok") {
                        return@withContext Result.success(
                            MalwareBazaarReport(
                                hash = cleanHash,
                                found = false,
                                note = "MalwareBazaar status: $status"
                            )
                        )
                    }

                    val dataArr = root.optJSONArray("data")
                    val first = dataArr?.optJSONObject(0)
                        ?: return@withContext Result.success(MalwareBazaarReport(hash = cleanHash, found = false))

                    val tags = mutableListOf<String>()
                    val tagsArr = first.optJSONArray("tags")
                    if (tagsArr != null) {
                        for (i in 0 until tagsArr.length()) {
                            tags.add(tagsArr.optString(i, ""))
                        }
                    }

                    Result.success(
                        MalwareBazaarReport(
                            hash = cleanHash,
                            found = true,
                            fileName = first.optString("file_name", ""),
                            fileType = first.optString("file_type_mime", first.optString("file_type", "")),
                            fileSizeBytes = first.optLong("file_size", 0L),
                            signature = first.optString("signature", "Malware Sample"),
                            sha256 = first.optString("sha256_hash", ""),
                            md5 = first.optString("md5_hash", ""),
                            sha1 = first.optString("sha1_hash", ""),
                            firstSeen = first.optString("first_seen", ""),
                            tags = tags.filter { it.isNotBlank() },
                            reporter = first.optString("reporter", "")
                        )
                    )
                }
            } catch (e: Exception) {
                Result.failure(Exception("MalwareBazaar lookup failed: ${e.message ?: "network error"}"))
            }
        }

    // -------------------------------------------------------------------------
    // Live API Key Verification for API Vault
    // -------------------------------------------------------------------------

    suspend fun testProviderKey(provider: ApiProvider, candidateKey: String): ApiKeyTestResult =
        withContext(Dispatchers.IO) {
            val key = candidateKey.trim()
            if (key.isEmpty()) {
                return@withContext ApiKeyTestResult(false, "Enter an API key first")
            }
            try {
                when (provider) {
                    ApiProvider.VIRUSTOTAL -> {
                        val req = Request.Builder()
                            .url("https://www.virustotal.com/api/v3/domains/example.com")
                            .header("x-apikey", key)
                            .get()
                            .build()
                        authClient().newCall(req).execute().use { resp ->
                            when (resp.code) {
                                200 -> ApiKeyTestResult(true, "Verified — VirusTotal v3 key active (HTTP 200)")
                                401, 403 -> ApiKeyTestResult(false, "Rejected — Invalid VirusTotal API key (HTTP ${resp.code})")
                                429 -> ApiKeyTestResult(true, "Key accepted — currently rate-limited (HTTP 429)")
                                else -> ApiKeyTestResult(false, "VirusTotal returned HTTP ${resp.code}")
                            }
                        }
                    }

                    ApiProvider.ABUSEIPDB -> {
                        val req = Request.Builder()
                            .url("https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=30")
                            .header("Key", key)
                            .header("Accept", "application/json")
                            .get()
                            .build()
                        authClient().newCall(req).execute().use { resp ->
                            when (resp.code) {
                                200 -> ApiKeyTestResult(true, "Verified — AbuseIPDB v2 key active (HTTP 200)")
                                401, 403 -> ApiKeyTestResult(false, "Rejected — Invalid AbuseIPDB key (HTTP ${resp.code})")
                                429 -> ApiKeyTestResult(true, "Key accepted — daily quota reached (HTTP 429)")
                                else -> ApiKeyTestResult(false, "AbuseIPDB returned HTTP ${resp.code}")
                            }
                        }
                    }

                    ApiProvider.SHODAN -> {
                        val encoded = URLEncoder.encode(key, "UTF-8")
                        val req = Request.Builder()
                            .url("https://api.shodan.io/api-info?key=$encoded")
                            .get()
                            .build()
                        authClient().newCall(req).execute().use { resp ->
                            when (resp.code) {
                                200 -> {
                                    val json = JSONObject(resp.body?.string() ?: "{}")
                                    val credits = json.optInt("query_credits", 0)
                                    val plan = json.optString("plan", "oss")
                                    ApiKeyTestResult(true, "Verified — Shodan plan '$plan' ($credits query credits)")
                                }
                                401, 403 -> ApiKeyTestResult(false, "Rejected — Invalid Shodan API key (HTTP ${resp.code})")
                                else -> ApiKeyTestResult(false, "Shodan returned HTTP ${resp.code}")
                            }
                        }
                    }

                    ApiProvider.URLSCAN -> {
                        val req = Request.Builder()
                            .url("https://urlscan.io/user/quotas/")
                            .header("API-Key", key)
                            .get()
                            .build()
                        authClient().newCall(req).execute().use { resp ->
                            when (resp.code) {
                                200 -> ApiKeyTestResult(true, "Verified — URLScan.io API key active (HTTP 200)")
                                401, 403 -> ApiKeyTestResult(false, "Rejected — Invalid URLScan API key (HTTP ${resp.code})")
                                else -> ApiKeyTestResult(false, "URLScan returned HTTP ${resp.code}")
                            }
                        }
                    }

                    ApiProvider.ABUSECH -> {
                        val form = FormBody.Builder().add("host", "example.com").build()
                        val req = Request.Builder()
                            .url("https://urlhaus-api.abuse.ch/v1/host/")
                            .header("Auth-Key", key)
                            .post(form)
                            .build()
                        authClient().newCall(req).execute().use { resp ->
                            when (resp.code) {
                                200 -> ApiKeyTestResult(true, "Verified — abuse.ch Auth-Key accepted (HTTP 200)")
                                401, 403 -> ApiKeyTestResult(false, "Rejected — Invalid abuse.ch Auth-Key (HTTP ${resp.code})")
                                else -> ApiKeyTestResult(false, "abuse.ch returned HTTP ${resp.code}")
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                ApiKeyTestResult(false, "Network error: ${e.message ?: "unable to reach provider"}")
            }
        }

    private fun encodePath(value: String): String = URLEncoder.encode(value.trim(), "UTF-8")
}
