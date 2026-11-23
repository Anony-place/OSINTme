package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.IpReconResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress

object ShodanService {
    private const val INTERNETDB_URL = "https://internetdb.shodan.io/"
    private const val GEOIP_URL = "http://ip-api.com/json/"

    suspend fun lookupIp(target: String): Result<IpReconResult> = withContext(Dispatchers.IO) {
        try {
            var clean = target.trim().removePrefix("https://").removePrefix("http://")
            if (clean.contains("/")) {
                clean = clean.substringBefore("/")
            }
            if (clean.contains(":")) {
                clean = clean.substringBefore(":")
            }

            // Resolve domain to IP if domain provided
            val resolvedIp = try {
                if (clean.matches(Regex("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$"))) {
                    clean
                } else {
                    InetAddress.getByName(clean).hostAddress ?: clean
                }
            } catch (e: Exception) {
                clean
            }

            // 1. Shodan InternetDB lookup
            val shodanRequest = Request.Builder()
                .url("$INTERNETDB_URL$resolvedIp")
                .header("User-Agent", "OSINTme-Network-Audit/1.0")
                .get()
                .build()

            val shodanResp = OsintApiClient.client.newCall(shodanRequest).execute()
            val shodanBody = if (shodanResp.isSuccessful) shodanResp.body?.string() ?: "{}" else "{}"

            val json = JSONObject(shodanBody)
            val hostnames = json.optJSONArray("hostnames")?.toStringList() ?: emptyList()
            val ports = json.optJSONArray("ports")?.toIntList() ?: emptyList()
            val cpes = json.optJSONArray("cpes")?.toStringList() ?: emptyList()
            val tags = json.optJSONArray("tags")?.toStringList() ?: emptyList()
            val vulns = json.optJSONArray("vulns")?.toStringList() ?: emptyList()

            // 2. Real GeoIP & ASN lookup via ip-api
            var country = "Unknown"
            var city = ""
            var isp = ""
            var org = ""
            var asn = ""
            var lat = 0.0
            var lon = 0.0

            try {
                val geoReq = Request.Builder()
                    .url("$GEOIP_URL$resolvedIp")
                    .get()
                    .build()
                val geoResp = OsintApiClient.client.newCall(geoReq).execute()
                if (geoResp.isSuccessful) {
                    val geoBody = geoResp.body?.string() ?: "{}"
                    val geoJson = JSONObject(geoBody)
                    if (geoJson.optString("status") == "success") {
                        country = geoJson.optString("country", "Unknown")
                        city = geoJson.optString("city", "")
                        isp = geoJson.optString("isp", "")
                        org = geoJson.optString("org", "")
                        asn = geoJson.optString("as", "")
                        lat = geoJson.optDouble("lat", 0.0)
                        lon = geoJson.optDouble("lon", 0.0)
                    }
                }
            } catch (e: Exception) {
                // GeoIP fallback
            }

            Result.success(
                IpReconResult(
                    ip = resolvedIp,
                    hostnames = hostnames,
                    ports = ports.sorted(),
                    cpes = cpes,
                    tags = tags,
                    vulns = vulns,
                    org = org.ifEmpty { if (ports.isEmpty()) "No open ports indexed" else "Indexed Infrastructure" },
                    country = country,
                    city = city,
                    isp = isp,
                    asn = asn,
                    latitude = lat,
                    longitude = lon
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun JSONArray.toStringList(): List<String> {
        val list = mutableListOf<String>()
        for (i in 0 until length()) {
            list.add(getString(i))
        }
        return list
    }

    private fun JSONArray.toIntList(): List<Int> {
        val list = mutableListOf<Int>()
        for (i in 0 until length()) {
            list.add(getInt(i))
        }
        return list
    }
}
