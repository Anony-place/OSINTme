package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.DnsRecordItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONObject

object CloudflareDohService {
    private const val DOH_URL = "https://cloudflare-dns.com/dns-query"
    private val RECORD_TYPES = listOf("A", "AAAA", "MX", "TXT", "NS")

    suspend fun resolveAll(domain: String): Result<List<DnsRecordItem>> = withContext(Dispatchers.IO) {
        val cleanDomain = domain.trim().lowercase()
            .removePrefix("https://").removePrefix("http://")
            .substringBefore("/")

        val allRecords = mutableListOf<DnsRecordItem>()

        for (type in RECORD_TYPES) {
            try {
                val url = "$DOH_URL?name=$cleanDomain&type=$type"
                val request = Request.Builder()
                    .url(url)
                    .header("Accept", "application/dns-json")
                    .get()
                    .build()

                val response = OsintApiClient.client.newCall(request).execute()
                if (response.isSuccessful) {
                    val body = response.body?.string() ?: ""
                    val json = JSONObject(body)
                    if (json.has("Answer")) {
                        val answers = json.getJSONArray("Answer")
                        for (i in 0 until answers.length()) {
                            val ans = answers.getJSONObject(i)
                            val name = ans.optString("name", cleanDomain)
                            val data = ans.optString("data", "").trim('"')
                            val ttl = ans.optInt("TTL", 300)
                            allRecords.add(
                                DnsRecordItem(
                                    type = type,
                                    name = name,
                                    data = data,
                                    ttl = ttl
                                )
                            )
                        }
                    }
                }
            } catch (e: Exception) {
                // Continue with other record types
            }
        }

        Result.success(allRecords)
    }
}
