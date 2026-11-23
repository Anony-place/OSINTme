package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.SubdomainResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONArray

object CrtShService {
    private const val HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q="
    private const val CRT_URL = "https://crt.sh/?output=json&q="

    suspend fun findSubdomains(domain: String): Result<SubdomainResult> = withContext(Dispatchers.IO) {
        try {
            var clean = domain.trim().lowercase()
            clean = clean.removePrefix("https://").removePrefix("http://").removePrefix("www.")
            if (clean.contains("/")) {
                clean = clean.substringBefore("/")
            }
            if (clean.contains(":")) {
                clean = clean.substringBefore(":")
            }

            val subdomainsSet = sortedSetOf<String>()

            // 1. Primary Engine: HackerTarget Fast Host Search
            try {
                val htRequest = Request.Builder()
                    .url("$HACKERTARGET_URL$clean")
                    .header("User-Agent", "OSINTme-Network-Audit/1.0")
                    .get()
                    .build()

                val htResp = OsintApiClient.client.newCall(htRequest).execute()
                if (htResp.isSuccessful) {
                    val htBody = htResp.body?.string() ?: ""
                    if (!htBody.contains("error check your search") && !htBody.contains("API count exceeded")) {
                        htBody.lines().forEach { line ->
                            val sub = line.substringBefore(",").trim().lowercase()
                            if (sub.isNotEmpty() && sub.endsWith(clean)) {
                                subdomainsSet.add(sub)
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                // Fallback to secondary CT Logs
            }

            // 2. Secondary Engine: crt.sh Certificate Transparency Logs
            try {
                val query = "%.${clean}"
                val crtRequest = Request.Builder()
                    .url("$CRT_URL$query")
                    .header("User-Agent", "Mozilla/5.0")
                    .get()
                    .build()

                val crtResp = OsintApiClient.client.newCall(crtRequest).execute()
                if (crtResp.isSuccessful) {
                    val crtBody = crtResp.body?.string() ?: "[]"
                    if (crtBody.startsWith("[")) {
                        val jsonArray = JSONArray(crtBody)
                        for (i in 0 until jsonArray.length().coerceAtMost(250)) {
                            val item = jsonArray.getJSONObject(i)
                            val nameValue = item.optString("name_value", "")
                            val names = nameValue.split("\n")
                            for (name in names) {
                                val trimmed = name.trim().lowercase().removePrefix("*.")
                                if (trimmed.endsWith(clean) && !trimmed.contains(" ")) {
                                    subdomainsSet.add(trimmed)
                                }
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                // Secondary engine network issue handled gracefully
            }

            // If empty, at least include common root
            if (subdomainsSet.isEmpty()) {
                subdomainsSet.add("www.$clean")
                subdomainsSet.add(clean)
            }

            Result.success(
                SubdomainResult(
                    rootDomain = clean,
                    subdomains = subdomainsSet.toList(),
                    totalCount = subdomainsSet.size
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
