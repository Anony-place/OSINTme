package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.BgpAsnInfo
import com.oopssecurity.osintme.util.NetworkSecurityGuard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONObject
import java.net.InetAddress

/**
 * Authoritative BGP / ASN & CIDR routing intelligence via RIPE NCC RIPEstat public API.
 * No API key required; routes through OsintApiClient (respects OPSEC/Tor proxy).
 */
object BgpAsnService {

    private const val NETWORK_INFO_URL = "https://stat.ripe.net/data/network-info/data.json?resource="
    private const val AS_OVERVIEW_URL = "https://stat.ripe.net/data/as-overview/data.json?resource="
    private const val ANNOUNCED_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource="

    suspend fun lookupIpOrHost(hostOrIp: String): Result<BgpAsnInfo> = withContext(Dispatchers.IO) {
        try {
            val clean = hostOrIp.trim()
                .removePrefix("https://")
                .removePrefix("http://")
                .substringBefore("/")
                .substringBefore(":")

            if (clean.isBlank() || NetworkSecurityGuard.isBlockedPrivateHost(clean)) {
                return@withContext Result.failure(Exception("Private, loopback, or invalid targets are blocked for BGP lookup"))
            }

            val ip = if (clean.matches(Regex("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$"))) {
                clean
            } else {
                InetAddress.getByName(clean).hostAddress
                    ?: return@withContext Result.failure(Exception("Could not resolve host to IP for BGP lookup"))
            }

            if (NetworkSecurityGuard.isBlockedPrivateHost(ip)) {
                return@withContext Result.failure(Exception("Resolved IP ($ip) is private or loopback — BGP lookup blocked"))
            }

            val netInfoReq = Request.Builder()
                .url("$NETWORK_INFO_URL$ip")
                .header("Accept", "application/json")
                .get()
                .build()

            val (asnNum, prefix) = OsintApiClient.client.newCall(netInfoReq).execute().use { resp ->
                if (!resp.isSuccessful) {
                    return@withContext Result.failure(Exception("RIPEstat network-info returned HTTP ${resp.code}"))
                }
                val root = JSONObject(resp.body?.string() ?: "{}")
                val data = root.optJSONObject("data")
                val asnsArr = data?.optJSONArray("asns")
                val firstAsn = if (asnsArr != null && asnsArr.length() > 0) asnsArr.optString(0, "") else ""
                val matchedPrefix = data?.optString("prefix", "") ?: ""
                firstAsn to matchedPrefix
            }

            if (asnNum.isBlank()) {
                return@withContext Result.success(
                    BgpAsnInfo(
                        ip = ip,
                        asn = "Unannounced",
                        holder = "No public BGP origin ASN found",
                        prefix = prefix.ifBlank { "N/A" }
                    )
                )
            }

            val asnTag = if (asnNum.startsWith("AS", ignoreCase = true)) asnNum.uppercase() else "AS$asnNum"

            coroutineScope {
                val overviewDeferred = async { fetchAsHolder(asnTag) }
                val prefixesDeferred = async { fetchAnnouncedPrefixes(asnTag) }

                val holder = overviewDeferred.await()
                val (prefixes, totalCount) = prefixesDeferred.await()

                Result.success(
                    BgpAsnInfo(
                        ip = ip,
                        asn = asnTag,
                        holder = holder.ifBlank { asnTag },
                        prefix = prefix.ifBlank { prefixes.firstOrNull().orEmpty() },
                        announcedPrefixes = prefixes,
                        totalAnnouncedCount = totalCount
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(Exception("BGP/ASN lookup failed: ${e.message ?: "network error"}"))
        }
    }

    private fun fetchAsHolder(asnTag: String): String {
        return try {
            val req = Request.Builder()
                .url("$AS_OVERVIEW_URL$asnTag")
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return ""
                val root = JSONObject(resp.body?.string() ?: "{}")
                root.optJSONObject("data")?.optString("holder", "") ?: ""
            }
        } catch (_: Exception) {
            ""
        }
    }

    private fun fetchAnnouncedPrefixes(asnTag: String): Pair<List<String>, Int> {
        return try {
            val req = Request.Builder()
                .url("$ANNOUNCED_PREFIXES_URL$asnTag")
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return emptyList<String>() to 0
                val root = JSONObject(resp.body?.string() ?: "{}")
                val arr = root.optJSONObject("data")?.optJSONArray("prefixes") ?: return emptyList<String>() to 0
                val list = mutableListOf<String>()
                val limit = minOf(arr.length(), 24)
                for (i in 0 until limit) {
                    val p = arr.optJSONObject(i)?.optString("prefix", "").orEmpty()
                    if (p.isNotBlank()) list.add(p)
                }
                list to arr.length()
            }
        } catch (_: Exception) {
            emptyList<String>() to 0
        }
    }
}
