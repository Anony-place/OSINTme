package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.UrlhausPayload
import com.oopssecurity.osintme.data.model.UrlhausResult
import kotlinx.coroutines.Dispatchers
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

            val formBody = FormBody.Builder()
                .add("host", cleanHost)
                .build()

            val request = Request.Builder()
                .url(URLHAUS_HOST_API)
                .header("User-Agent", "OSINTme-Threat-Audit/1.0")
                .post(formBody)
                .build()

            val response = OsintApiClient.client.newCall(request).execute()
            if (!response.isSuccessful) {
                return@withContext Result.failure(Exception("URLhaus responded with HTTP ${response.code}"))
            }

            val body = response.body?.string() ?: return@withContext Result.failure(Exception("Empty URLhaus body"))
            val root = JSONObject(body)
            val queryStatus = root.optString("query_status", "no_results")

            if (queryStatus == "ok") {
                val firstSeen = root.optString("firstseen", "")
                val urlCount = root.optInt("url_count", 0)
                val blacklists = root.optJSONObject("blacklists")
                val spamhaus = blacklists?.optString("spamhaus_dbl", "not listed")?.contains("listed", ignoreCase = true) == true
                val surbl = blacklists?.optString("surbl", "not listed")?.contains("listed", ignoreCase = true) == true

                val payloadList = mutableListOf<UrlhausPayload>()
                val urlsArr = root.optJSONArray("urls")
                if (urlsArr != null) {
                    for (i in 0 until minOf(urlsArr.length(), 20)) {
                        val uObj = urlsArr.getJSONObject(i)
                        val pUrl = uObj.optString("url", "")
                        val status = uObj.optString("url_status", "unknown")
                        val threat = uObj.optString("threat", "malware_download")
                        val date = uObj.optString("date_added", "")
                        val tagsArr = uObj.optJSONArray("tags")
                        val tags = mutableListOf<String>()
                        if (tagsArr != null) {
                            for (t in 0 until tagsArr.length()) {
                                tags.add(tagsArr.getString(t))
                            }
                        }

                        payloadList.add(
                            UrlhausPayload(
                                url = pUrl,
                                urlStatus = status,
                                threat = threat,
                                tags = tags,
                                dateAdded = date
                            )
                        )
                    }
                }

                Result.success(
                    UrlhausResult(
                        target = cleanHost,
                        queryStatus = queryStatus,
                        isMalicious = urlCount > 0,
                        firstSeen = firstSeen,
                        urlCount = urlCount,
                        spamhausListed = spamhaus,
                        surblListed = surbl,
                        payloads = payloadList
                    )
                )
            } else {
                Result.success(
                    UrlhausResult(
                        target = cleanHost,
                        queryStatus = queryStatus,
                        isMalicious = false,
                        firstSeen = "",
                        urlCount = 0,
                        spamhausListed = false,
                        surblListed = false,
                        payloads = emptyList()
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
