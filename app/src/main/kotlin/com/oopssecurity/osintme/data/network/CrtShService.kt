package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.SubdomainResult
import com.oopssecurity.osintme.util.NetworkSecurityGuard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONArray
import java.net.URLEncoder

object CrtShService {
    private const val HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q="
    private const val CRT_URL = "https://crt.sh/?output=json&q="
    private const val SUBDOMAIN_CENTER_URL = "https://api.subdomain.center/?domain="

    suspend fun findSubdomains(domain: String): Result<SubdomainResult> = withContext(Dispatchers.IO) {
        try {
            var clean = domain.trim().lowercase()
            clean = clean.removePrefix("https://").removePrefix("http://").removePrefix("www.")
            if (clean.contains("/")) clean = clean.substringBefore("/")
            if (clean.contains(":")) clean = clean.substringBefore(":")

            if (clean.isBlank() || !clean.contains(".") || NetworkSecurityGuard.isBlockedPrivateHost(clean)) {
                return@withContext Result.failure(Exception("Enter a valid public domain for subdomain discovery"))
            }

            val subdomainsSet = sortedSetOf<String>()
            val activeSources = mutableListOf<String>()

            coroutineScope {
                val htDeferred = async { queryHackerTarget(clean) }
                val crtDeferred = async { queryCrtSh(clean) }
                val scDeferred = async { querySubdomainCenter(clean) }

                val htResults = htDeferred.await()
                val crtResults = crtDeferred.await()
                val scResults = scDeferred.await()

                if (htResults.isNotEmpty()) {
                    subdomainsSet.addAll(htResults)
                    activeSources.add("HackerTarget")
                }
                if (crtResults.isNotEmpty()) {
                    subdomainsSet.addAll(crtResults)
                    activeSources.add("crt.sh CT Logs")
                }
                if (scResults.isNotEmpty()) {
                    subdomainsSet.addAll(scResults)
                    activeSources.add("Subdomain Center")
                }
            }

            Result.success(
                SubdomainResult(
                    rootDomain = clean,
                    subdomains = subdomainsSet.toList(),
                    totalCount = subdomainsSet.size,
                    sources = activeSources
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun queryHackerTarget(clean: String): Set<String> {
        val found = mutableSetOf<String>()
        try {
            val req = Request.Builder()
                .url("$HACKERTARGET_URL$clean")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    if (!body.contains("error check your search", ignoreCase = true) &&
                        !body.contains("API count exceeded", ignoreCase = true)
                    ) {
                        body.lines().forEach { line ->
                            val sub = line.substringBefore(",").trim().lowercase()
                            if (sub.isNotEmpty() && (sub == clean || sub.endsWith(".$clean"))) {
                                found.add(sub)
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return found
    }

    private fun queryCrtSh(clean: String): Set<String> {
        val found = mutableSetOf<String>()
        try {
            val req = Request.Builder()
                .url("$CRT_URL%.$clean")
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val body = resp.body?.string()?.trim() ?: "[]"
                    if (body.startsWith("[")) {
                        val arr = JSONArray(body)
                        for (i in 0 until arr.length().coerceAtMost(350)) {
                            val item = arr.getJSONObject(i)
                            val nameValue = item.optString("name_value", "")
                            for (rawName in nameValue.split("\n")) {
                                val trimmed = rawName.trim().lowercase().removePrefix("*.")
                                if ((trimmed == clean || trimmed.endsWith(".$clean")) &&
                                    !trimmed.contains(" ") && !trimmed.contains("@")
                                ) {
                                    found.add(trimmed)
                                }
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return found
    }

    private fun querySubdomainCenter(clean: String): Set<String> {
        val found = mutableSetOf<String>()
        try {
            val req = Request.Builder()
                .url("$SUBDOMAIN_CENTER_URL$clean")
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val body = resp.body?.string()?.trim() ?: "[]"
                    if (body.startsWith("[")) {
                        val arr = JSONArray(body)
                        for (i in 0 until arr.length().coerceAtMost(350)) {
                            val sub = arr.optString(i, "").trim().lowercase()
                            if (sub.isNotEmpty() && (sub == clean || sub.endsWith(".$clean"))) {
                                found.add(sub)
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return found
    }
}
