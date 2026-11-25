package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.util.NetworkSecurityGuard
import com.oopssecurity.osintme.util.PivotEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class TlsCertReport(
    val host: String,
    val port: Int,
    val subjectCn: String,
    val subjectDn: String,
    val issuerCn: String,
    val issuerDn: String,
    val validFrom: String,
    val validUntil: String,
    val daysRemaining: Long,
    val isExpired: Boolean,
    val isExpiringSoon: Boolean,
    val protocol: String,
    val cipherSuite: String,
    val serialHex: String,
    val sha256Fingerprint: String,
    val sanDomains: List<String>,
    val chainDepth: Int
)

enum class TakeoverSeverity {
    CONFIRMED_VULNERABLE,
    POTENTIAL_DANGLING,
    CLAIMED_SAFE
}

data class SubdomainTakeoverFinding(
    val subdomain: String,
    val cnameTarget: String,
    val cloudProvider: String,
    val severity: TakeoverSeverity,
    val evidence: String
)

data class TakeoverScanSummary(
    val rootDomain: String,
    val totalSubdomainsChecked: Int,
    val findings: List<SubdomainTakeoverFinding>
)

private data class TakeoverProviderSignature(
    val providerName: String,
    val cnamePatterns: List<String>,
    val bodyFingerprints: List<String>
)

/**
 * Live TLS X.509 Certificate Inspector (real SSLSocket SNI handshake)
 * + Passive Subdomain CNAME Takeover Scanner (crt.sh + Cloudflare DoH CNAME + HTTP signature verification).
 * Blocks loopback/private/link-local targets strictly for safety.
 */
object TlsAndTakeoverService {

    private val TAKEOVER_SIGNATURES = listOf(
        TakeoverProviderSignature(
            "GitHub Pages",
            listOf("github.io", "github.map.fastly.net"),
            listOf("There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file")
        ),
        TakeoverProviderSignature(
            "AWS S3 Bucket",
            listOf("s3.amazonaws.com", "s3-website", ".amazonaws.com"),
            listOf("NoSuchBucket", "The specified bucket does not exist")
        ),
        TakeoverProviderSignature(
            "Heroku",
            listOf("herokudns.com", "herokuapp.com"),
            listOf("No such app", "herokucdn.com/error-pages/no-such-app")
        ),
        TakeoverProviderSignature(
            "Microsoft Azure",
            listOf("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azureedge.net"),
            listOf("404 Web Site not found", "The resource you are looking for has been removed")
        ),
        TakeoverProviderSignature(
            "Shopify",
            listOf("shops.myshopify.com"),
            listOf("Sorry, this shop is currently unavailable", "Only one step left")
        ),
        TakeoverProviderSignature(
            "Fastly",
            listOf("fastly.net"),
            listOf("Fastly error: unknown domain")
        ),
        TakeoverProviderSignature(
            "Pantheon",
            listOf("pantheonsite.io"),
            listOf("404 error unknown site!", "The gods are wise, but do not know of the site")
        ),
        TakeoverProviderSignature(
            "Netlify",
            listOf("netlify.app", "netlify.com"),
            listOf("Not Found - Request ID")
        ),
        TakeoverProviderSignature(
            "Surge.sh",
            listOf("surge.sh"),
            listOf("project not found")
        ),
        TakeoverProviderSignature(
            "Ghost",
            listOf("ghost.io"),
            listOf("The thing you were looking for is no longer here")
        ),
        TakeoverProviderSignature(
            "Bitbucket",
            listOf("bitbucket.io"),
            listOf("Repository not found")
        ),
        TakeoverProviderSignature(
            "Zendesk",
            listOf("zendesk.com"),
            listOf("Help Center Closed")
        ),
        TakeoverProviderSignature(
            "ReadTheDocs",
            listOf("readthedocs.io"),
            listOf("unknown to Read the Docs")
        ),
        TakeoverProviderSignature(
            "Tumblr",
            listOf("domains.tumblr.com"),
            listOf("Whatever you were looking for doesn't currently exist at this address")
        )
    )

    suspend fun inspectTlsCertificate(rawHost: String, port: Int = 443): Result<TlsCertReport> = withContext(Dispatchers.IO) {
        val host = PivotEngine.cleanDomainCandidate(rawHost)
        if (host.isBlank() || !host.contains(".")) {
            return@withContext Result.failure(Exception("Enter a valid public domain (e.g., cloudflare.com)"))
        }
        if (isPrivateOrLocalHost(host)) {
            return@withContext Result.failure(Exception("Private or loopback targets are blocked"))
        }

        var socket: SSLSocket? = null
        try {
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            socket = factory.createSocket() as SSLSocket
            val params = socket.sslParameters
            params.serverNames = listOf(SNIHostName(host))
            socket.sslParameters = params
            socket.soTimeout = 10_000
            socket.connect(InetSocketAddress(host, port), 10_000)
            socket.startHandshake()

            val session = socket.session
            val certs = session.peerCertificates
            val leaf = certs.firstOrNull() as? X509Certificate
                ?: return@withContext Result.failure(Exception("No X.509 leaf certificate presented by $host"))

            val subjectDn = leaf.subjectX500Principal.name
            val issuerDn = leaf.issuerX500Principal.name
            val nowMs = System.currentTimeMillis()
            val daysLeft = (leaf.notAfter.time - nowMs) / 86_400_000L

            val sans = mutableListOf<String>()
            runCatching {
                leaf.subjectAlternativeNames?.forEach { entry ->
                    if (entry.size >= 2 && entry[0] == 2) { // dNSName
                        val dnsName = entry[1]?.toString()?.trim()
                        if (!dnsName.isNullOrBlank()) sans.add(dnsName)
                    }
                }
            }

            val sha256 = MessageDigest.getInstance("SHA-256")
                .digest(leaf.encoded)
                .joinToString(":") { "%02X".format(it) }

            Result.success(
                TlsCertReport(
                    host = host,
                    port = port,
                    subjectCn = extractCn(subjectDn).ifBlank { host },
                    subjectDn = subjectDn,
                    issuerCn = extractCn(issuerDn).ifBlank { issuerDn },
                    issuerDn = issuerDn,
                    validFrom = formatUtcDate(leaf.notBefore),
                    validUntil = formatUtcDate(leaf.notAfter),
                    daysRemaining = daysLeft,
                    isExpired = daysLeft < 0,
                    isExpiringSoon = daysLeft in 0..30,
                    protocol = session.protocol.orEmpty().ifBlank { "TLS" },
                    cipherSuite = session.cipherSuite.orEmpty(),
                    serialHex = leaf.serialNumber.toString(16).uppercase(),
                    sha256Fingerprint = sha256,
                    sanDomains = sans.distinct().take(60),
                    chainDepth = certs.size
                )
            )
        } catch (e: Exception) {
            Result.failure(Exception("TLS handshake failed for $host:$port — ${e.message ?: "unreachable"}"))
        } finally {
            runCatching { socket?.close() }
        }
    }

    suspend fun scanSubdomainTakeovers(
        rawDomain: String,
        extraSubdomains: List<String> = emptyList(),
        maxSubdomains: Int = 24
    ): Result<TakeoverScanSummary> = withContext(Dispatchers.IO) {
        val rootDomain = PivotEngine.cleanDomainCandidate(rawDomain)
        if (rootDomain.isBlank() || !rootDomain.contains(".")) {
            return@withContext Result.failure(Exception("Enter a valid domain (e.g., example.com)"))
        }
        if (isPrivateOrLocalHost(rootDomain)) {
            return@withContext Result.failure(Exception("Private or loopback domains are blocked"))
        }

        try {
            val discovered = linkedSetOf<String>()
            discovered.add(rootDomain)
            discovered.add("www.$rootDomain")
            extraSubdomains.forEach { s ->
                val clean = PivotEngine.cleanDomainCandidate(s)
                if (clean.endsWith(rootDomain) && !clean.contains("*")) discovered.add(clean)
            }

            // Enrich from crt.sh Certificate Transparency logs
            CrtShService.findSubdomains(rootDomain).onSuccess { res ->
                res.subdomains.take(maxSubdomains).forEach { s ->
                    val clean = PivotEngine.cleanDomainCandidate(s)
                    if (clean.isNotBlank() && !clean.contains("*")) discovered.add(clean)
                }
            }

            val targets = discovered.take(maxSubdomains)
            val semaphore = Semaphore(6)

            val findings = coroutineScope {
                targets.map { sub ->
                    async {
                        semaphore.withPermit {
                            evaluateSubdomainCname(sub)
                        }
                    }
                }.awaitAll().filterNotNull()
            }.sortedBy { it.severity.ordinal }

            Result.success(
                TakeoverScanSummary(
                    rootDomain = rootDomain,
                    totalSubdomainsChecked = targets.size,
                    findings = findings
                )
            )
        } catch (e: Exception) {
            Result.failure(Exception("Subdomain takeover scan failed: ${e.message ?: "error"}"))
        }
    }

    fun matchTakeoverProvider(cname: String): String? {
        val lower = cname.lowercase().trimEnd('.')
        return TAKEOVER_SIGNATURES.firstOrNull { sig ->
            sig.cnamePatterns.any { pat -> lower.endsWith(pat) || lower.contains(pat) }
        }?.providerName
    }

    private suspend fun evaluateSubdomainCname(subdomain: String): SubdomainTakeoverFinding? {
        val cnames = CloudflareDohService.queryRecord(subdomain, "CNAME").getOrNull().orEmpty()
        val primaryCname = cnames.firstOrNull()?.data?.trimEnd('.') ?: return null
        val matchedSig = TAKEOVER_SIGNATURES.firstOrNull { sig ->
            sig.cnamePatterns.any { pat -> primaryCname.lowercase().contains(pat) }
        } ?: return null

        // Check if CNAME target resolves cleanly or returns NXDOMAIN / takeover body signature
        val aRecords = CloudflareDohService.queryRecord(subdomain, "A").getOrNull().orEmpty()
        if (aRecords.isEmpty()) {
            return SubdomainTakeoverFinding(
                subdomain = subdomain,
                cnameTarget = primaryCname,
                cloudProvider = matchedSig.providerName,
                severity = TakeoverSeverity.POTENTIAL_DANGLING,
                evidence = "CNAME points to ${matchedSig.providerName} ($primaryCname) with no resolving A record (NXDOMAIN/dangling)"
            )
        }

        // Verify passive HTTP response body against known unclaimed-service fingerprints
        val bodySnippet = fetchSmallHttpBody(subdomain)
        val matchedFingerprint = matchedSig.bodyFingerprints.firstOrNull { fp ->
            bodySnippet.contains(fp, ignoreCase = true)
        }

        return if (matchedFingerprint != null) {
            SubdomainTakeoverFinding(
                subdomain = subdomain,
                cnameTarget = primaryCname,
                cloudProvider = matchedSig.providerName,
                severity = TakeoverSeverity.CONFIRMED_VULNERABLE,
                evidence = "Unclaimed ${matchedSig.providerName} signature detected: \"$matchedFingerprint\""
            )
        } else {
            SubdomainTakeoverFinding(
                subdomain = subdomain,
                cnameTarget = primaryCname,
                cloudProvider = matchedSig.providerName,
                severity = TakeoverSeverity.CLAIMED_SAFE,
                evidence = "Active ${matchedSig.providerName} CNAME ($primaryCname) — no unclaimed takeover banner found"
            )
        }
    }

    private fun fetchSmallHttpBody(host: String): String {
        if (isPrivateOrLocalHost(host)) return ""
        val httpsResp = NetworkSecurityGuard.executeSafeGetWithRedirectChecks(
            baseClient = OsintApiClient.client,
            startUrl = "https://$host",
            maxBytes = 25_000,
            maxHops = 3
        )
        if (httpsResp != null) return httpsResp.body
        val httpResp = NetworkSecurityGuard.executeSafeGetWithRedirectChecks(
            baseClient = OsintApiClient.client,
            startUrl = "http://$host",
            maxBytes = 25_000,
            maxHops = 3
        )
        return httpResp?.body.orEmpty()
    }

    private fun extractCn(dn: String): String {
        return Regex("""(?:^|,\s*)CN=([^,]+)""", RegexOption.IGNORE_CASE)
            .find(dn)?.groupValues?.getOrNull(1)?.trim().orEmpty()
    }

    private fun formatUtcDate(date: Date): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm 'UTC'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        return fmt.format(date)
    }

    private fun isPrivateOrLocalHost(host: String): Boolean {
        return NetworkSecurityGuard.isBlockedPrivateHost(host)
    }
}
