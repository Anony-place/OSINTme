package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.SecurityHeaderItem
import com.oopssecurity.osintme.data.model.TlsHeaderAuditResult
import com.oopssecurity.osintme.util.NetworkSecurityGuard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale

object TlsHeaderAuditService {

    suspend fun inspectTarget(domainOrUrl: String): Result<TlsHeaderAuditResult> = withContext(Dispatchers.IO) {
        val cleanHost = domainOrUrl.trim().lowercase()
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore("/")
            .substringBefore(":")

        if (cleanHost.isBlank() || !cleanHost.contains(".") || NetworkSecurityGuard.isBlockedPrivateHost(cleanHost)) {
            return@withContext Result.failure(Exception("Private, loopback, or invalid targets are blocked for safety"))
        }

        val targetUrl = "https://$cleanHost"
        val start = System.currentTimeMillis()

        try {
            val noRedirectClient = OsintApiClient.client.newBuilder()
                .followRedirects(false)
                .followSslRedirects(false)
                .build()
            val request = Request.Builder()
                .url(targetUrl)
                .get()
                .build()

            noRedirectClient.newCall(request).execute().use { response ->
                val elapsed = System.currentTimeMillis() - start
                val handshake = response.handshake
                val tlsProtocol = handshake?.tlsVersion?.javaName ?: "Unknown"
                val cipherSuite = handshake?.cipherSuite?.javaName ?: ""

                var subject = ""
                var issuer = ""
                var validFrom = ""
                var validUntil = ""
                val sans = mutableListOf<String>()

                val cert = handshake?.peerCertificates?.firstOrNull() as? X509Certificate
                if (cert != null) {
                    val fmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
                    subject = cert.subjectX500Principal?.name ?: ""
                    issuer = cert.issuerX500Principal?.name ?: ""
                    validFrom = fmt.format(cert.notBefore)
                    validUntil = fmt.format(cert.notAfter)
                    try {
                        cert.subjectAlternativeNames?.forEach { entry ->
                            if (entry.size >= 2) {
                                val value = entry[1]?.toString()
                                if (!value.isNullOrBlank()) sans.add(value)
                            }
                        }
                    } catch (_: Exception) {
                        // SAN extraction optional
                    }
                }

                val hsts = response.header("Strict-Transport-Security")
                val csp = response.header("Content-Security-Policy")
                val xfo = response.header("X-Frame-Options")
                val xcto = response.header("X-Content-Type-Options")
                val refPolicy = response.header("Referrer-Policy")
                val permPolicy = response.header("Permissions-Policy")
                val server = response.header("Server") ?: ""
                val poweredBy = response.header("X-Powered-By") ?: ""

                val headerItems = mutableListOf(
                    SecurityHeaderItem(
                        name = "Strict-Transport-Security (HSTS)",
                        present = !hsts.isNullOrBlank(),
                        value = hsts ?: "Missing — downgrade to HTTP possible",
                        severity = if (!hsts.isNullOrBlank()) "GOOD" else "MISSING"
                    ),
                    SecurityHeaderItem(
                        name = "Content-Security-Policy (CSP)",
                        present = !csp.isNullOrBlank(),
                        value = csp?.take(140) ?: "Missing — XSS defense header absent",
                        severity = if (!csp.isNullOrBlank()) "GOOD" else "MISSING"
                    ),
                    SecurityHeaderItem(
                        name = "X-Frame-Options",
                        present = !xfo.isNullOrBlank(),
                        value = xfo ?: "Missing — clickjacking protection relies on CSP",
                        severity = if (!xfo.isNullOrBlank()) "GOOD" else "WARN"
                    ),
                    SecurityHeaderItem(
                        name = "X-Content-Type-Options",
                        present = !xcto.isNullOrBlank(),
                        value = xcto ?: "Missing — MIME sniffing not disabled",
                        severity = if (!xcto.isNullOrBlank()) "GOOD" else "MISSING"
                    ),
                    SecurityHeaderItem(
                        name = "Referrer-Policy",
                        present = !refPolicy.isNullOrBlank(),
                        value = refPolicy ?: "Not explicitly configured",
                        severity = if (!refPolicy.isNullOrBlank()) "GOOD" else "WARN"
                    ),
                    SecurityHeaderItem(
                        name = "Permissions-Policy",
                        present = !permPolicy.isNullOrBlank(),
                        value = permPolicy?.take(120) ?: "Not explicitly configured",
                        severity = if (!permPolicy.isNullOrBlank()) "GOOD" else "WARN"
                    )
                )

                if (poweredBy.isNotBlank()) {
                    headerItems.add(
                        SecurityHeaderItem(
                            name = "X-Powered-By (Tech Disclosure)",
                            present = true,
                            value = poweredBy,
                            severity = "WARN"
                        )
                    )
                }

                val passedCount = headerItems.take(6).count { it.present }
                val grade = when {
                    passedCount >= 6 && tlsProtocol.contains("1.3") -> "A+"
                    passedCount >= 5 -> "A"
                    passedCount == 4 -> "B"
                    passedCount == 3 -> "C"
                    passedCount >= 1 -> "D"
                    else -> "F"
                }

                Result.success(
                    TlsHeaderAuditResult(
                        targetUrl = targetUrl,
                        finalUrl = response.request.url.toString(),
                        httpStatus = response.code,
                        responseTimeMs = elapsed,
                        serverHeader = server,
                        tlsProtocol = tlsProtocol,
                        cipherSuite = cipherSuite,
                        certSubject = extractCn(subject),
                        certIssuer = extractCn(issuer),
                        certValidFrom = validFrom,
                        certValidUntil = validUntil,
                        certSanCount = sans.size,
                        certSans = sans.distinct().take(20),
                        securityGrade = grade,
                        passedHeadersCount = passedCount,
                        totalCheckedHeaders = 6,
                        headers = headerItems
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(Exception("TLS/HTTP inspection failed: ${e.message ?: "Host unreachable over HTTPS"}"))
        }
    }

    private fun extractCn(dn: String): String {
        if (dn.isBlank()) return ""
        val cnMatch = Regex("CN=([^,]+)").find(dn)
        val orgMatch = Regex("O=([^,]+)").find(dn)
        val cn = cnMatch?.groupValues?.getOrNull(1)?.trim() ?: ""
        val org = orgMatch?.groupValues?.getOrNull(1)?.trim() ?: ""
        return when {
            cn.isNotEmpty() && org.isNotEmpty() && cn != org -> "$cn ($org)"
            cn.isNotEmpty() -> cn
            org.isNotEmpty() -> org
            else -> dn
        }
    }
}
