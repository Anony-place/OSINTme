package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.UrlhausPayload
import com.oopssecurity.osintme.data.model.UrlhausResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.Request
import org.json.JSONObject

object UrlhausService {

    private const val URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"

    suspend fun checkHost(hostOrIp: String): Result<UrlhausResult> = withContext(Dispatchers.IO) {
        try {
            var cleanHost = hostOrIp.trim().lowercase()
            cleanHost = cleanHost.removePrefix("https://").removePrefix("http://")
            if (cleanHost.contains("/")) cleanHost = cleanHost.substringBefore("/")
            if (cleanHost.contains(":")) cleanHost = cleanHost.substringBefore(":")

            coroutineScope {
                val cfDeferred = async { CloudflareDohService.checkCloudflareSecurityBlock(cleanHost) }
                val urlhausDeferred = async { queryUrlhausHost(cleanHost) }

                val (cfBlocked, stdIps) = cfDeferred.await()
                val uh = urlhausDeferred.await()

                val isMalicious = cfBlocked || uh.urlCount > 0 || uh.spamhausListed || uh.surblListed

                Result.success(
                    UrlhausResult(
                        target = cleanHost,
                        queryStatus = uh.queryStatus,
                        isMalicious = isMalicious,
                        firstSeen = uh.firstSeen,
                        urlCount = uh.urlCount,
                        spamhausListed = uh.spamhausListed,
                        surblListed = uh.surblListed,
                        payloads = uh.payloads,
                        cloudflareMalwareBlocked = cfBlocked,
                        cloudflareStandardIps = stdIps,
                        urlhausNote = uh.note
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private data class UrlhausRaw(
        val queryStatus: String = "unavailable",
        val firstSeen: String = "",
        val urlCount: Int = 0,
        val spamhausListed: Boolean = false,
        val surblListed: Boolean = false,
        val payloads: List<UrlhausPayload> = emptyList(),
        val note: String = ""
    )

    private fun queryUrlhausHost(cleanHost: String): UrlhausRaw {
        return try {
            val formBody = FormBody.Builder()
                .add("host", cleanHost)
                .build()

            val reqBuilder = Request.Builder()
                .url(URLHAUS_HOST_API)
                .post(formBody)

            com.oopssecurity.osintme.data.local.ApiKeyVault.getKey(
                com.oopssecurity.osintme.data.local.ApiProvider.ABUSECH
            )?.let { authKey ->
                reqBuilder.header("Auth-Key", authKey)
            }

            val request = reqBuilder.build()

            OsintApiClient.client.newCall(request).execute().use { response ->
                if (response.code == 401 || response.code == 403) {
                    return UrlhausRaw(
                        queryStatus = "auth_required",
                        note = "URLhaus API requires a free abuse.ch Auth-Key (add it in API Vault); Cloudflare 1.1.1.2 malware DNS verdict shown above."
                    )
                }
                if (!response.isSuccessful) {
                    return UrlhausRaw(
                        queryStatus = "http_${response.code}",
                        note = "URLhaus returned HTTP ${response.code}; Cloudflare 1.1.1.2 Security DNS verdict shown above."
                    )
                }

                val body = response.body?.string() ?: return UrlhausRaw()
                val root = JSONObject(body)
                val queryStatus = root.optString("query_status", "no_results")

                if (queryStatus == "ok") {
                    val firstSeen = root.optString("firstseen", "")
                    val urlCount = root.optInt("url_count", 0)
                    val blacklists = root.optJSONObject("blacklists")
                    val spamhaus = blacklists?.optString("spamhaus_dbl", "not listed")?.contains("listed", ignoreCase = true) == true &&
                        !blacklists.optString("spamhaus_dbl", "").contains("not listed", ignoreCase = true)
                    val surbl = blacklists?.optString("surbl", "not listed")?.contains("listed", ignoreCase = true) == true &&
                        !blacklists.optString("surbl", "").contains("not listed", ignoreCase = true)

                    val payloadList = mutableListOf<UrlhausPayload>()
                    val urlsArr = root.optJSONArray("urls")
                    if (urlsArr != null) {
                        for (i in 0 until minOf(urlsArr.length(), 20)) {
                            val uObj = urlsArr.getJSONObject(i)
                            val tagsArr = uObj.optJSONArray("tags")
                            val tags = mutableListOf<String>()
                            if (tagsArr != null) {
                                for (t in 0 until tagsArr.length()) {
                                    tags.add(tagsArr.getString(t))
                                }
                            }
                            payloadList.add(
                                UrlhausPayload(
                                    url = uObj.optString("url", ""),
                                    urlStatus = uObj.optString("url_status", "unknown"),
                                    threat = uObj.optString("threat", "malware_download"),
                                    tags = tags,
                                    dateAdded = uObj.optString("date_added", "")
                                )
                            )
                        }
                    }

                    UrlhausRaw(
                        queryStatus = queryStatus,
                        firstSeen = firstSeen,
                        urlCount = urlCount,
                        spamhausListed = spamhaus,
                        surblListed = surbl,
                        payloads = payloadList
                    )
                } else {
                    UrlhausRaw(queryStatus = queryStatus)
                }
            }
        } catch (e: Exception) {
            UrlhausRaw(
                queryStatus = "error",
                note = "URLhaus unreachable (${e.message ?: "network error"}); Cloudflare 1.1.1.2 Security DNS verdict shown above."
            )
        }
    }
}
