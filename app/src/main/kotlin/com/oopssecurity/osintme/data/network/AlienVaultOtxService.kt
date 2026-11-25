package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.util.PivotEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Request
import java.net.URLEncoder

data class OtxPulseSummary(
    val name: String,
    val created: String,
    val tags: List<String>,
    val adversary: String
)

data class OtxThreatReport(
    val indicator: String,
    val indicatorType: String, // DOMAIN, IPV4, HASH
    val pulseCount: Int,
    val pulses: List<OtxPulseSummary>,
    val tags: List<String>,
    val asn: String = "",
    val countryName: String = "",
    val passiveDnsHosts: List<String> = emptyList(),
    val relatedUrls: List<String> = emptyList()
)

/**
 * Zero-key AlienVault OTX public threat intelligence & passive DNS connector.
 * Mirrors theHarvester / SpiderFoot OTX modules natively in Kotlin.
 */
object AlienVaultOtxService {

    private const val BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    suspend fun lookupDomain(domain: String): Result<OtxThreatReport> = withContext(Dispatchers.IO) {
        val clean = PivotEngine.cleanDomainCandidate(domain)
        if (clean.isBlank() || !clean.contains(".")) {
            return@withContext Result.failure(Exception("Invalid domain for OTX lookup"))
        }
        try {
            val encoded = URLEncoder.encode(clean, "UTF-8")
            coroutineScope {
                val generalDef = async { fetchJson("$BASE_URL/domain/$encoded/general") }
                val pdnsDef = async { fetchJson("$BASE_URL/domain/$encoded/passive_dns") }
                val urlsDef = async { fetchJson("$BASE_URL/domain/$encoded/url_list?limit=25") }

                val generalRaw = generalDef.await()
                val pdnsRaw = pdnsDef.await()
                val urlsRaw = urlsDef.await()

                if (generalRaw == null && pdnsRaw == null && urlsRaw == null) {
                    return@coroutineScope Result.failure(Exception("OTX public endpoint did not return data"))
                }

                val base = generalRaw?.let { parseGeneralJson(clean, "DOMAIN", it) }
                    ?: OtxThreatReport(clean, "DOMAIN", 0, emptyList(), emptyList())
                val passiveHosts = pdnsRaw?.let { parsePassiveDnsJson(it, clean) }.orEmpty()
                val relatedUrls = urlsRaw?.let { parseUrlListJson(it) }.orEmpty()

                Result.success(
                    base.copy(
                        passiveDnsHosts = passiveHosts,
                        relatedUrls = relatedUrls
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(Exception("OTX lookup failed: ${e.message ?: "network error"}"))
        }
    }

    suspend fun lookupIp(ip: String): Result<OtxThreatReport> = withContext(Dispatchers.IO) {
        val clean = ip.trim()
        if (clean.isBlank()) {
            return@withContext Result.failure(Exception("Empty IP"))
        }
        try {
            val section = if (clean.contains(":")) "IPv6" else "IPv4"
            val encoded = URLEncoder.encode(clean, "UTF-8")
            coroutineScope {
                val generalDef = async { fetchJson("$BASE_URL/$section/$encoded/general") }
                val pdnsDef = async { fetchJson("$BASE_URL/$section/$encoded/passive_dns") }
                val urlsDef = async { fetchJson("$BASE_URL/$section/$encoded/url_list?limit=20") }

                val generalRaw = generalDef.await()
                val pdnsRaw = pdnsDef.await()
                val urlsRaw = urlsDef.await()

                if (generalRaw == null && pdnsRaw == null) {
                    return@coroutineScope Result.failure(Exception("OTX IP endpoint unavailable"))
                }

                val base = generalRaw?.let { parseGeneralJson(clean, "IPV4", it) }
                    ?: OtxThreatReport(clean, "IPV4", 0, emptyList(), emptyList())
                val passiveHosts = pdnsRaw?.let { parsePassiveDnsJson(it, clean) }.orEmpty()
                val relatedUrls = urlsRaw?.let { parseUrlListJson(it) }.orEmpty()

                Result.success(base.copy(passiveDnsHosts = passiveHosts, relatedUrls = relatedUrls))
            }
        } catch (e: Exception) {
            Result.failure(Exception("OTX IP lookup failed: ${e.message ?: "network error"}"))
        }
    }

    suspend fun lookupHash(hash: String): Result<OtxThreatReport> = withContext(Dispatchers.IO) {
        val clean = hash.trim().lowercase()
        if (clean.length !in setOf(32, 40, 64)) {
            return@withContext Result.failure(Exception("Unsupported hash length"))
        }
        try {
            val raw = fetchJson("$BASE_URL/file/$clean/general")
                ?: return@withContext Result.failure(Exception("OTX file lookup returned empty"))
            Result.success(parseGeneralJson(clean, "HASH", raw))
        } catch (e: Exception) {
            Result.failure(Exception("OTX hash lookup failed: ${e.message ?: "network error"}"))
        }
    }

    internal fun parseGeneralJson(indicator: String, type: String, rawJson: String): OtxThreatReport {
        val root = json.parseToJsonElement(rawJson).jsonObject
        val pulseInfo = root["pulse_info"] as? JsonObject
        val pulseCount = pulseInfo?.get("count")?.jsonPrimitive?.intOrNull ?: 0
        val pulseItems = mutableListOf<OtxPulseSummary>()
        val tagSet = linkedSetOf<String>()

        pulseInfo?.get("pulses")?.jsonArray?.take(12)?.forEach { el ->
            val obj = el.jsonObject
            val name = obj["name"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
            val created = obj["created"]?.jsonPrimitive?.contentOrNull?.take(10).orEmpty()
            val adversary = obj["adversary"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
            val pTags = obj["tags"]?.jsonArray?.mapNotNull { t ->
                t.jsonPrimitive.contentOrNull?.trim()?.takeIf { it.isNotBlank() }
            }.orEmpty()
            tagSet.addAll(pTags.take(5))
            if (name.isNotBlank()) {
                pulseItems.add(OtxPulseSummary(name = name, created = created, tags = pTags.take(4), adversary = adversary))
            }
        }

        val asn = root["asn"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
        val country = root["country_name"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()

        return OtxThreatReport(
            indicator = indicator,
            indicatorType = type,
            pulseCount = pulseCount,
            pulses = pulseItems,
            tags = tagSet.take(12),
            asn = asn,
            countryName = country
        )
    }

    internal fun parsePassiveDnsJson(rawJson: String, selfIndicator: String): List<String> {
        val root = runCatching { json.parseToJsonElement(rawJson).jsonObject }.getOrNull() ?: return emptyList()
        val entries = root["passive_dns"]?.jsonArray ?: return emptyList()
        val results = linkedSetOf<String>()
        for (el in entries) {
            val obj = el.jsonObject
            val hostname = obj["hostname"]?.jsonPrimitive?.contentOrNull?.trim()?.lowercase()?.removeSuffix(".").orEmpty()
            val address = obj["address"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
            if (hostname.isNotBlank() && hostname != selfIndicator && !hostname.contains("*")) {
                results.add(hostname)
            }
            if (address.isNotBlank() && address != selfIndicator && results.size < 45) {
                results.add(address)
            }
            if (results.size >= 45) break
        }
        return results.toList()
    }

    internal fun parseUrlListJson(rawJson: String): List<String> {
        val root = runCatching { json.parseToJsonElement(rawJson).jsonObject }.getOrNull() ?: return emptyList()
        val list = root["url_list"]?.jsonArray ?: return emptyList()
        val urls = linkedSetOf<String>()
        for (el in list) {
            val url = el.jsonObject["url"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
            if (url.startsWith("http://", true) || url.startsWith("https://", true)) {
                urls.add(url)
            }
            if (urls.size >= 20) break
        }
        return urls.toList()
    }

    private fun fetchJson(url: String): String? {
        return try {
            val req = Request.Builder()
                .url(url)
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return null
                val body = resp.body?.string()?.trim().orEmpty()
                if (body.startsWith("{") || body.startsWith("[")) body else null
            }
        } catch (_: Exception) {
            null
        }
    }
}
