package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.WaybackUrlItem
import com.oopssecurity.osintme.util.NetworkSecurityGuard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONArray
import java.net.URLEncoder

object WaybackService {
    private const val CDX_API_URL = "https://web.archive.org/cdx/search/cdx"

    suspend fun fetchArchivedUrls(domain: String): Result<List<WaybackUrlItem>> = withContext(Dispatchers.IO) {
        try {
            var clean = domain.trim().lowercase()
            clean = clean.removePrefix("https://").removePrefix("http://").removePrefix("www.")
            if (clean.contains("/")) clean = clean.substringBefore("/")
            if (clean.contains(":")) clean = clean.substringBefore(":")

            if (clean.isBlank() || !clean.contains(".") || NetworkSecurityGuard.isBlockedPrivateHost(clean)) {
                return@withContext Result.failure(Exception("Enter a valid public domain for Wayback archive lookup"))
            }

            val encoded = URLEncoder.encode("*.$clean/*", "UTF-8")
            val url = "$CDX_API_URL?url=$encoded&output=json&collapse=urlkey&fl=original,statuscode,timestamp&limit=50"

            val request = Request.Builder()
                .url(url)
                .header("User-Agent", "OSINTme-Investigator/1.0")
                .get()
                .build()

            val body = OsintApiClient.client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return@withContext Result.failure(Exception("Wayback CDX responded with HTTP ${response.code}"))
                }
                response.body?.string() ?: return@withContext Result.success(emptyList())
            }
            val rootArray = JSONArray(body)

            if (rootArray.length() <= 1) {
                return@withContext Result.success(emptyList())
            }

            val items = mutableListOf<WaybackUrlItem>()
            // Skip index 0 (header row)
            for (i in 1 until rootArray.length()) {
                val row = rootArray.getJSONArray(i)
                val original = row.optString(0, "")
                val status = row.optString(1, "200")
                val timestamp = row.optString(2, "")

                if (original.isNotEmpty()) {
                    val formattedTs = if (timestamp.length >= 8) {
                        "${timestamp.substring(0, 4)}-${timestamp.substring(4, 6)}-${timestamp.substring(6, 8)}"
                    } else timestamp

                    val archiveUrl = if (timestamp.isNotEmpty()) {
                        "https://web.archive.org/web/$timestamp/$original"
                    } else {
                        "https://web.archive.org/web/*/$original"
                    }

                    items.add(
                        WaybackUrlItem(
                            url = original,
                            statusCode = status,
                            timestamp = formattedTs,
                            archiveUrl = archiveUrl
                        )
                    )
                }
            }

            Result.success(items)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
