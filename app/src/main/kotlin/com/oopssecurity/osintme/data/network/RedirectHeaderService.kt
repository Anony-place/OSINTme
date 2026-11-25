package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.util.NetworkSecurityGuard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import java.net.URI

data class RedirectHop(
    val hopNumber: Int,
    val url: String,
    val host: String,
    val statusCode: Int,
    val locationHeader: String?,
    val serverHeader: String,
    val latencyMs: Long
)

data class HeaderSecurityCheck(
    val headerName: String,
    val present: Boolean,
    val value: String,
    val status: String, // PASS, WARN, FAIL
    val recommendation: String
)

data class CookieSecurityCheck(
    val cookieName: String,
    val hasSecure: Boolean,
    val hasHttpOnly: Boolean,
    val sameSite: String
)

data class RedirectAuditReport(
    val initialUrl: String,
    val finalUrl: String,
    val finalHost: String,
    val finalStatusCode: Int,
    val isFinalHttps: Boolean,
    val hops: List<RedirectHop>,
    val securityScore: Int,
    val securityGrade: String, // A+, A, B, C, D, F
    val headerChecks: List<HeaderSecurityCheck>,
    val cookieChecks: List<CookieSecurityCheck>,
    val infoLeakHeaders: List<String>,
    val corsWarning: String?
)

/**
 * Live Safe Redirect Chain Tracer & HTTP Security Header / Cookie Auditor.
 * Unmasks shortlinks (bit.ly, t.co, tracking redirects) hop-by-hop without opening a browser.
 * Enforces strict private/loopback/link-local IP blocking on EVERY hop before connecting.
 */
object RedirectHeaderService {

    private const val MAX_HOPS = 10
    private val META_REFRESH_REGEX = Regex(
        """(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url=([^"'\s>]+)["']"""
    )

    suspend fun traceAndAudit(rawUrl: String): Result<RedirectAuditReport> = withContext(Dispatchers.IO) {
        val trimmed = rawUrl.trim()
        if (trimmed.isBlank()) {
            return@withContext Result.failure(Exception("Enter a URL or domain to trace"))
        }

        val startUrl = if (trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true)) {
            trimmed
        } else {
            "https://$trimmed"
        }

        val noRedirectClient = OsintApiClient.client.newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

        val hops = mutableListOf<RedirectHop>()
        var currentUrl = startUrl
        var finalHeaders = emptyMap<String, String>()
        var finalCookies = emptyList<String>()
        var finalCode = 0

        try {
            for (hopIdx in 1..MAX_HOPS) {
                val uri = try {
                    URI(currentUrl)
                } catch (_: Exception) {
                    return@withContext Result.failure(Exception("Invalid URL at hop $hopIdx: $currentUrl"))
                }

                val scheme = uri.scheme?.lowercase().orEmpty()
                val host = uri.host?.lowercase().orEmpty()
                if (scheme !in setOf("http", "https") || host.isBlank()) {
                    return@withContext Result.failure(Exception("Unsupported URL scheme or empty host at hop $hopIdx"))
                }
                if (isBlockedPrivateHost(host)) {
                    return@withContext Result.failure(Exception("Blocked redirect to private/local network host ($host)"))
                }

                val startMs = System.currentTimeMillis()
                val req = Request.Builder()
                    .url(currentUrl)
                    .header("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
                    .get()
                    .build()

                var nextLocation: String? = null
                noRedirectClient.newCall(req).execute().use { resp ->
                    val elapsed = System.currentTimeMillis() - startMs
                    finalCode = resp.code
                    val location = resp.header("Location")?.trim()
                    val server = resp.header("Server").orEmpty()

                    val hMap = mutableMapOf<String, String>()
                    resp.headers.names().forEach { name ->
                        hMap[name.lowercase()] = resp.headers.values(name).joinToString("; ")
                    }
                    finalHeaders = hMap
                    finalCookies = resp.headers.values("Set-Cookie")

                    hops.add(
                        RedirectHop(
                            hopNumber = hopIdx,
                            url = currentUrl,
                            host = host,
                            statusCode = resp.code,
                            locationHeader = location,
                            serverHeader = server,
                            latencyMs = elapsed
                        )
                    )

                    if (resp.code in setOf(301, 302, 303, 307, 308) && !location.isNullOrBlank()) {
                        nextLocation = resolveRelativeUrl(uri, location)
                    } else if (resp.code in 200..299) {
                        // Also check for client-side HTML meta-refresh redirects on shortlinks
                        val smallBody = NetworkSecurityGuard.readBodyBounded(resp, 16_384)
                        val metaTarget = META_REFRESH_REGEX.find(smallBody)?.groupValues?.getOrNull(1)?.trim()
                        if (!metaTarget.isNullOrBlank() && hopIdx < MAX_HOPS) {
                            nextLocation = resolveRelativeUrl(uri, metaTarget)
                        }
                    }
                }

                if (nextLocation == null || nextLocation == currentUrl) {
                    break
                }
                currentUrl = nextLocation!!
            }

            val finalUri = runCatching { URI(currentUrl) }.getOrNull()
            val finalHost = finalUri?.host?.lowercase().orEmpty()
            val isHttps = finalUri?.scheme.equals("https", ignoreCase = true)

            val (score, grade, checks, leaks, corsWarn) = gradeSecurityHeaders(finalHeaders, isHttps)
            val cookieChecks = auditSetCookies(finalCookies)

            Result.success(
                RedirectAuditReport(
                    initialUrl = startUrl,
                    finalUrl = currentUrl,
                    finalHost = finalHost,
                    finalStatusCode = finalCode,
                    isFinalHttps = isHttps,
                    hops = hops,
                    securityScore = score,
                    securityGrade = grade,
                    headerChecks = checks,
                    cookieChecks = cookieChecks,
                    infoLeakHeaders = leaks,
                    corsWarning = corsWarn
                )
            )
        } catch (e: Exception) {
            Result.failure(Exception("Redirect trace failed: ${e.message ?: "connection error"}"))
        }
    }

    data class HeaderGradeBundle(
        val score: Int,
        val grade: String,
        val checks: List<HeaderSecurityCheck>,
        val infoLeaks: List<String>,
        val corsWarning: String?
    )

    /**
     * Pure deterministic HTTP security header grader (unit-testable).
     */
    fun gradeSecurityHeaders(
        rawHeaders: Map<String, String>,
        isHttps: Boolean
    ): HeaderGradeBundle {
        val headers = rawHeaders.entries.associate { it.key.lowercase() to it.value }
        val checks = mutableListOf<HeaderSecurityCheck>()
        var score = 0

        // 1. HSTS (20 pts)
        val hsts = headers["strict-transport-security"].orEmpty()
        if (isHttps && hsts.isNotBlank()) {
            score += 20
            checks.add(HeaderSecurityCheck("Strict-Transport-Security", true, hsts, "PASS", "Enforces HTTPS transport"))
        } else {
            checks.add(
                HeaderSecurityCheck(
                    "Strict-Transport-Security",
                    false,
                    "Missing",
                    if (isHttps) "FAIL" else "FAIL",
                    "Add max-age=31536000; includeSubDomains"
                )
            )
        }

        // 2. CSP (25 pts)
        val csp = headers["content-security-policy"].orEmpty()
        if (csp.isNotBlank()) {
            val unsafeInline = csp.contains("'unsafe-inline'", true) || csp.contains("'unsafe-eval'", true)
            score += if (unsafeInline) 15 else 25
            checks.add(
                HeaderSecurityCheck(
                    "Content-Security-Policy",
                    true,
                    csp.take(120),
                    if (unsafeInline) "WARN" else "PASS",
                    if (unsafeInline) "Present, but allows unsafe-inline/unsafe-eval" else "Strong script & frame isolation"
                )
            )
        } else {
            checks.add(HeaderSecurityCheck("Content-Security-Policy", false, "Missing", "FAIL", "Define strict default-src / script-src policy"))
        }

        // 3. Clickjacking protection: X-Frame-Options or frame-ancestors (15 pts)
        val xfo = headers["x-frame-options"].orEmpty()
        val hasFrameAncestors = csp.contains("frame-ancestors", ignoreCase = true)
        if (xfo.isNotBlank() || hasFrameAncestors) {
            score += 15
            checks.add(
                HeaderSecurityCheck(
                    "X-Frame-Options",
                    true,
                    xfo.ifBlank { "Covered by CSP frame-ancestors" },
                    "PASS",
                    "Protects against clickjacking"
                )
            )
        } else {
            checks.add(HeaderSecurityCheck("X-Frame-Options", false, "Missing", "FAIL", "Set DENY or SAMEORIGIN"))
        }

        // 4. X-Content-Type-Options (15 pts)
        val xcto = headers["x-content-type-options"].orEmpty()
        if (xcto.equals("nosniff", ignoreCase = true)) {
            score += 15
            checks.add(HeaderSecurityCheck("X-Content-Type-Options", true, xcto, "PASS", "Prevents MIME-sniffing"))
        } else {
            checks.add(HeaderSecurityCheck("X-Content-Type-Options", false, xcto.ifBlank { "Missing" }, "FAIL", "Set to nosniff"))
        }

        // 5. Referrer-Policy (15 pts)
        val refPol = headers["referrer-policy"].orEmpty()
        if (refPol.isNotBlank()) {
            score += 15
            checks.add(HeaderSecurityCheck("Referrer-Policy", true, refPol, "PASS", "Controls cross-origin referrer leakage"))
        } else {
            checks.add(HeaderSecurityCheck("Referrer-Policy", false, "Missing", "WARN", "Set strict-origin-when-cross-origin"))
        }

        // 6. Permissions-Policy (10 pts)
        val permPol = headers["permissions-policy"].orEmpty()
        if (permPol.isNotBlank()) {
            score += 10
            checks.add(HeaderSecurityCheck("Permissions-Policy", true, permPol.take(100), "PASS", "Restricts browser hardware APIs"))
        } else {
            checks.add(HeaderSecurityCheck("Permissions-Policy", false, "Missing", "WARN", "Restrict unused camera/mic/geolocation APIs"))
        }

        // Information disclosure headers
        val leaks = buildList {
            headers["server"]?.takeIf { it.isNotBlank() }?.let { add("Server: $it") }
            headers["x-powered-by"]?.takeIf { it.isNotBlank() }?.let { add("X-Powered-By: $it") }
            headers["x-aspnet-version"]?.takeIf { it.isNotBlank() }?.let { add("X-AspNet-Version: $it") }
        }

        // Wildcard CORS check
        val acao = headers["access-control-allow-origin"].orEmpty()
        val acac = headers["access-control-allow-credentials"].orEmpty()
        val corsWarning = when {
            acao == "*" && acac.equals("true", ignoreCase = true) ->
                "CRITICAL: Wildcard Access-Control-Allow-Origin (*) combined with Allow-Credentials"
            acao == "*" ->
                "Advisory: Access-Control-Allow-Origin is set to wildcard (*)"
            else -> null
        }

        val finalScore = score.coerceIn(0, 100)
        val grade = when {
            finalScore >= 95 -> "A+"
            finalScore >= 85 -> "A"
            finalScore >= 70 -> "B"
            finalScore >= 55 -> "C"
            finalScore >= 35 -> "D"
            else -> "F"
        }

        return HeaderGradeBundle(finalScore, grade, checks, leaks, corsWarning)
    }

    fun auditSetCookies(setCookieHeaders: List<String>): List<CookieSecurityCheck> {
        return setCookieHeaders.mapNotNull { raw ->
            val parts = raw.split(";").map { it.trim() }
            val name = parts.firstOrNull()?.substringBefore("=")?.trim().orEmpty()
            if (name.isBlank()) return@mapNotNull null
            val attrs = parts.drop(1)
            val hasSecure = attrs.any { it.equals("Secure", ignoreCase = true) }
            val hasHttpOnly = attrs.any { it.equals("HttpOnly", ignoreCase = true) }
            val sameSite = attrs.firstOrNull { it.startsWith("SameSite=", ignoreCase = true) }
                ?.substringAfter("=")?.trim().orEmpty().ifBlank { "Unset" }
            CookieSecurityCheck(
                cookieName = name,
                hasSecure = hasSecure,
                hasHttpOnly = hasHttpOnly,
                sameSite = sameSite
            )
        }
    }

    private fun resolveRelativeUrl(base: URI, location: String): String {
        return try {
            base.resolve(location).toString()
        } catch (_: Exception) {
            location
        }
    }

    private fun isBlockedPrivateHost(host: String): Boolean =
        NetworkSecurityGuard.isBlockedPrivateHost(host)
}
