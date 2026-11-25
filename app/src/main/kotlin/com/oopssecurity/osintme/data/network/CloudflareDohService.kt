package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.DnsRecordItem
import com.oopssecurity.osintme.data.model.EmailSecurityAudit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONObject

object CloudflareDohService {
    private const val DOH_URL = "https://cloudflare-dns.com/dns-query"
    private const val SECURITY_DOH_URL = "https://security.cloudflare-dns.com/dns-query"
    private val RECORD_TYPES = listOf("A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA")

    suspend fun resolveAll(domain: String): Result<List<DnsRecordItem>> = withContext(Dispatchers.IO) {
        val cleanDomain = normalizeDomain(domain)
        val allRecords = coroutineScope {
            RECORD_TYPES.map { type ->
                async { queryRecords(DOH_URL, cleanDomain, type) }
            }.awaitAll().flatten()
        }
        Result.success(allRecords)
    }

    suspend fun queryRecord(name: String, type: String): Result<List<DnsRecordItem>> = withContext(Dispatchers.IO) {
        try {
            Result.success(queryRecords(DOH_URL, normalizeDomain(name), type))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun auditEmailSecurity(domainOrEmail: String): Result<EmailSecurityAudit> = withContext(Dispatchers.IO) {
        try {
            val cleanDomain = if (domainOrEmail.contains("@")) {
                domainOrEmail.substringAfter("@").trim().lowercase()
            } else {
                normalizeDomain(domainOrEmail)
            }

            coroutineScope {
                val mxDeferred = async { queryRecords(DOH_URL, cleanDomain, "MX") }
                val txtDeferred = async { queryRecords(DOH_URL, cleanDomain, "TXT") }
                val dmarcDeferred = async { queryRecords(DOH_URL, "_dmarc.$cleanDomain", "TXT") }

                val mxRecords = mxDeferred.await()
                val txtRecords = txtDeferred.await()
                val dmarcRecords = dmarcDeferred.await()

                val spfRecord = txtRecords.firstOrNull {
                    it.data.startsWith("v=spf1", ignoreCase = true)
                }?.data ?: ""

                val spfPolicy = when {
                    spfRecord.isEmpty() -> "Missing"
                    spfRecord.contains("-all") -> "-all (Strict Reject)"
                    spfRecord.contains("~all") -> "~all (SoftFail)"
                    spfRecord.contains("?all") -> "?all (Neutral)"
                    spfRecord.contains("+all") -> "+all (Permissive / Risky)"
                    else -> "Configured"
                }

                val dmarcRecord = dmarcRecords.firstOrNull {
                    it.data.startsWith("v=DMARC1", ignoreCase = true)
                }?.data ?: ""

                val dmarcPolicy = when {
                    dmarcRecord.isEmpty() -> "Missing"
                    dmarcRecord.contains("p=reject", ignoreCase = true) -> "reject (Strong)"
                    dmarcRecord.contains("p=quarantine", ignoreCase = true) -> "quarantine (Moderate)"
                    dmarcRecord.contains("p=none", ignoreCase = true) -> "none (Monitor Only)"
                    else -> "Configured"
                }

                val hasSpf = spfRecord.isNotEmpty()
                val hasDmarc = dmarcRecord.isNotEmpty()
                val isSpoofable = !hasSpf || !hasDmarc ||
                    spfRecord.contains("+all") ||
                    dmarcRecord.contains("p=none", ignoreCase = true)

                val summary = when {
                    !hasSpf && !hasDmarc -> "No SPF or DMARC records found. Domain is vulnerable to email spoofing."
                    hasSpf && hasDmarc && !isSpoofable -> "Strong anti-spoofing posture: both SPF and enforcing DMARC policy are active."
                    hasSpf && !hasDmarc -> "SPF is present ($spfPolicy), but DMARC record is missing."
                    !hasSpf && hasDmarc -> "DMARC is configured ($dmarcPolicy), but SPF record is missing."
                    else -> "SPF and DMARC exist, but enforcement is weak ($dmarcPolicy)."
                }

                Result.success(
                    EmailSecurityAudit(
                        domain = cleanDomain,
                        hasMx = mxRecords.isNotEmpty(),
                        mxHosts = mxRecords.map { it.data },
                        hasSpf = hasSpf,
                        spfRecord = spfRecord,
                        spfPolicy = spfPolicy,
                        hasDmarc = hasDmarc,
                        dmarcRecord = dmarcRecord,
                        dmarcPolicy = dmarcPolicy,
                        isSpoofable = isSpoofable,
                        riskSummary = summary
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Real-time malware/phishing check using Cloudflare 1.1.1.2 (Security DoH) vs standard 1.1.1.1.
     * Cloudflare 1.1.1.2 responds with 0.0.0.0 when a host is actively categorized as malware/phishing.
     */
    suspend fun checkCloudflareSecurityBlock(host: String): Pair<Boolean, List<String>> = withContext(Dispatchers.IO) {
        val cleanHost = normalizeDomain(host)
        coroutineScope {
            val stdDeferred = async { queryRecords(DOH_URL, cleanHost, "A") }
            val secDeferred = async { queryRecords(SECURITY_DOH_URL, cleanHost, "A") }

            val stdIps = stdDeferred.await().map { it.data }
            val secIps = secDeferred.await().map { it.data }

            val blockedBySecurityDns = secIps.any { it == "0.0.0.0" } ||
                (stdIps.isNotEmpty() && stdIps.none { it == "0.0.0.0" } && secIps.isEmpty())

            blockedBySecurityDns to stdIps
        }
    }

    private fun queryRecords(baseUrl: String, name: String, type: String): List<DnsRecordItem> {
        val records = mutableListOf<DnsRecordItem>()
        try {
            val url = "$baseUrl?name=$name&type=$type"
            val request = Request.Builder()
                .url(url)
                .header("Accept", "application/dns-json")
                .get()
                .build()

            OsintApiClient.client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val body = response.body?.string() ?: ""
                    val json = JSONObject(body)
                    if (json.has("Answer")) {
                        val answers = json.getJSONArray("Answer")
                        for (i in 0 until answers.length()) {
                            val ans = answers.getJSONObject(i)
                            val recName = ans.optString("name", name).trimEnd('.')
                            val data = ans.optString("data", "").trim().trim('"')
                            val ttl = ans.optInt("TTL", 300)
                            if (data.isNotEmpty()) {
                                records.add(
                                    DnsRecordItem(
                                        type = type,
                                        name = recName,
                                        data = data,
                                        ttl = ttl
                                    )
                                )
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Skip failed record type cleanly
        }
        return records
    }

    private fun normalizeDomain(input: String): String {
        return input.trim().lowercase()
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore("/")
            .substringBefore(":")
    }
}
