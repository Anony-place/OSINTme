package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.IpReconResult
import com.oopssecurity.osintme.data.model.OpsecRouteCheckResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress

object ShodanService {
    private const val INTERNETDB_URL = "https://internetdb.shodan.io/"
    private const val IPWHO_HTTPS_URL = "https://ipwho.is/"
    private const val IPAPI_HTTPS_URL = "https://ipapi.co/"
    private const val IPIFY_URL = "https://api.ipify.org?format=json"

    suspend fun lookupIp(target: String): Result<IpReconResult> = withContext(Dispatchers.IO) {
        try {
            var clean = target.trim().removePrefix("https://").removePrefix("http://")
            if (clean.contains("/")) clean = clean.substringBefore("/")
            if (clean.contains(":")) clean = clean.substringBefore(":")

            val resolvedIp = try {
                if (clean.matches(Regex("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$"))) {
                    clean
                } else {
                    InetAddress.getByName(clean).hostAddress ?: clean
                }
            } catch (e: Exception) {
                clean
            }

            coroutineScope {
                val shodanDeferred = async { fetchInternetDb(resolvedIp) }
                val fullShodanDeferred = async { fetchFullShodanHost(resolvedIp) }
                val geoDeferred = async { fetchHttpsGeoIp(resolvedIp) }

                val shodanJson = shodanDeferred.await()
                val fullJson = fullShodanDeferred.await()
                val geo = geoDeferred.await()

                val hostnames = (
                    (shodanJson?.optJSONArray("hostnames")?.toStringList() ?: emptyList()) +
                        (fullJson?.optJSONArray("hostnames")?.toStringList() ?: emptyList())
                    ).distinct()

                val ports = (
                    (shodanJson?.optJSONArray("ports")?.toIntList() ?: emptyList()) +
                        (fullJson?.optJSONArray("ports")?.toIntList() ?: emptyList())
                    ).distinct().sorted()

                val cpes = (
                    (shodanJson?.optJSONArray("cpes")?.toStringList() ?: emptyList()) +
                        extractFullShodanServices(fullJson)
                    ).distinct()

                val tags = (
                    (shodanJson?.optJSONArray("tags")?.toStringList() ?: emptyList()) +
                        (fullJson?.optJSONArray("tags")?.toStringList() ?: emptyList()) +
                        (if (fullJson != null) listOf("shodan-full-api") else emptyList())
                    ).distinct()

                val fullVulns = fullJson?.optJSONArray("vulns")?.toStringList() ?: emptyList()
                val vulns = (
                    (shodanJson?.optJSONArray("vulns")?.toStringList() ?: emptyList()) + fullVulns
                    ).distinct()

                val fullOrg = fullJson?.optString("org", "").orEmpty()
                val fullIsp = fullJson?.optString("isp", "").orEmpty()
                val fullAsn = fullJson?.optString("asn", "").orEmpty()
                val fullCountry = fullJson?.optString("country_name", "").orEmpty()
                val fullCity = fullJson?.optString("city", "").orEmpty()

                Result.success(
                    IpReconResult(
                        ip = resolvedIp,
                        hostnames = hostnames,
                        ports = ports,
                        cpes = cpes,
                        tags = tags,
                        vulns = vulns,
                        org = fullOrg.ifBlank { geo.org }.ifEmpty {
                            if (ports.isEmpty()) "No public Shodan record" else "Public Infrastructure"
                        },
                        country = fullCountry.ifBlank { geo.country }.ifEmpty { "Unknown" },
                        city = fullCity.ifBlank { geo.city },
                        isp = fullIsp.ifBlank { geo.isp },
                        asn = fullAsn.ifBlank { geo.asn },
                        latitude = geo.lat,
                        longitude = geo.lon
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun checkActiveExitRoute(): Result<OpsecRouteCheckResult> = withContext(Dispatchers.IO) {
        val start = System.currentTimeMillis()
        try {
            val ipReq = Request.Builder()
                .url(IPIFY_URL)
                .header("Accept", "application/json")
                .get()
                .build()

            val publicIp = OsintApiClient.client.newCall(ipReq).execute().use { resp ->
                if (!resp.isSuccessful) {
                    return@withContext Result.failure(Exception("Exit IP probe failed (HTTP ${resp.code})"))
                }
                val body = resp.body?.string() ?: "{}"
                JSONObject(body).optString("ip", "")
            }

            if (publicIp.isEmpty()) {
                return@withContext Result.failure(Exception("Could not determine public exit IP"))
            }

            val geo = fetchHttpsGeoIp(publicIp)
            val latency = System.currentTimeMillis() - start

            Result.success(
                OpsecRouteCheckResult(
                    publicIp = publicIp,
                    country = geo.country.ifEmpty { "Unknown" },
                    city = geo.city,
                    isp = geo.isp.ifEmpty { geo.org },
                    asn = geo.asn,
                    latencyMs = latency,
                    proxyUsed = OpsecManager.currentProxyMode.label
                )
            )
        } catch (e: Exception) {
            Result.failure(Exception("Route check failed: ${e.message ?: "Unable to connect through active route"}"))
        }
    }

    private fun fetchInternetDb(ip: String): JSONObject? {
        return try {
            val req = Request.Builder()
                .url("$INTERNETDB_URL$ip")
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    JSONObject(resp.body?.string() ?: "{}")
                } else null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun fetchFullShodanHost(ip: String): JSONObject? {
        val apiKey = com.oopssecurity.osintme.data.local.ApiKeyVault.getKey(
            com.oopssecurity.osintme.data.local.ApiProvider.SHODAN
        ) ?: return null
        return try {
            val encodedKey = java.net.URLEncoder.encode(apiKey, "UTF-8")
            val req = Request.Builder()
                .url("https://api.shodan.io/shodan/host/$ip?key=$encodedKey")
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) JSONObject(resp.body?.string() ?: "{}") else null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun extractFullShodanServices(fullJson: JSONObject?): List<String> {
        val dataArr = fullJson?.optJSONArray("data") ?: return emptyList()
        val services = mutableListOf<String>()
        for (i in 0 until minOf(dataArr.length(), 15)) {
            val item = dataArr.optJSONObject(i) ?: continue
            val port = item.optInt("port", 0)
            val product = item.optString("product", "").trim()
            val version = item.optString("version", "").trim()
            if (product.isNotBlank()) {
                val label = buildString {
                    append("$port/tcp: $product")
                    if (version.isNotBlank()) append(" $version")
                }
                services.add(label)
            }
        }
        return services
    }

    private data class GeoData(
        val country: String = "",
        val city: String = "",
        val isp: String = "",
        val org: String = "",
        val asn: String = "",
        val lat: Double = 0.0,
        val lon: Double = 0.0
    )

    private fun fetchHttpsGeoIp(ip: String): GeoData {
        // Primary HTTPS endpoint: ipwho.is (no key required, full ASN & GeoIP over HTTPS)
        try {
            val req = Request.Builder()
                .url("$IPWHO_HTTPS_URL$ip")
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val json = JSONObject(resp.body?.string() ?: "{}")
                    if (json.optBoolean("success", false)) {
                        val conn = json.optJSONObject("connection")
                        val asnNum = conn?.optLong("asn", 0L) ?: 0L
                        val asnStr = if (asnNum > 0L) "AS$asnNum" else ""
                        return GeoData(
                            country = json.optString("country", ""),
                            city = json.optString("city", ""),
                            isp = conn?.optString("isp", "") ?: "",
                            org = conn?.optString("org", "") ?: "",
                            asn = asnStr,
                            lat = json.optDouble("latitude", 0.0),
                            lon = json.optDouble("longitude", 0.0)
                        )
                    }
                }
            }
        } catch (_: Exception) {
            // Fall through to secondary HTTPS GeoIP
        }

        // Secondary HTTPS fallback: ipapi.co
        try {
            val req = Request.Builder()
                .url("${IPAPI_HTTPS_URL}$ip/json/")
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val json = JSONObject(resp.body?.string() ?: "{}")
                    if (!json.optBoolean("error", false)) {
                        return GeoData(
                            country = json.optString("country_name", ""),
                            city = json.optString("city", ""),
                            isp = json.optString("org", ""),
                            org = json.optString("org", ""),
                            asn = json.optString("asn", ""),
                            lat = json.optDouble("latitude", 0.0),
                            lon = json.optDouble("longitude", 0.0)
                        )
                    }
                }
            }
        } catch (_: Exception) {
            // Both GeoIP endpoints unreachable
        }

        return GeoData()
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
