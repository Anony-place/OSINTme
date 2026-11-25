package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.WebTechReconResult
import com.oopssecurity.osintme.data.model.WebTechSignature
import com.oopssecurity.osintme.util.NetworkSecurityGuard
import com.oopssecurity.osintme.util.PivotEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext

/**
 * Live passive Deep Web Reconnaissance:
 * - Fingerprints CMS, JS frameworks, CDN/WAF, servers & analytics from live HTML + headers
 * - Parses /robots.txt (Disallowed paths & Sitemaps)
 * - Parses /.well-known/security.txt (security contacts)
 * - Extracts pivotable external linked domains
 *
 * Security hygiene: only allows public HTTP/HTTPS hosts and blocks loopback/private/link-local IPs.
 */
object WebTechReconService {

    private val TITLE_REGEX = Regex("""(?is)<title[^>]*>(.*?)</title>""")
    private val GENERATOR_REGEX = Regex("""(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""")
    private val HREF_SRC_REGEX = Regex("""(?i)(?:href|src)=["'](https?://[^"'\s>]+)["']""")

    suspend fun inspectHost(rawHostOrUrl: String): Result<WebTechReconResult> = withContext(Dispatchers.IO) {
        try {
            val host = PivotEngine.cleanDomainCandidate(rawHostOrUrl)
            if (host.isBlank() || !host.contains(".")) {
                return@withContext Result.failure(Exception("Provide a valid public hostname for web recon"))
            }

            if (isDisallowedLocalTarget(host)) {
                return@withContext Result.failure(Exception("Private or loopback targets are blocked for safety"))
            }

            val baseUrl = "https://$host"

            coroutineScope {
                val homeDeferred = async { fetchHomepage(baseUrl) }
                val robotsDeferred = async { fetchRobotsTxt(baseUrl) }
                val secTxtDeferred = async { fetchSecurityTxt(baseUrl) }

                val home = homeDeferred.await()
                    ?: return@coroutineScope Result.failure(Exception("Unable to reach $baseUrl"))

                val (robotsFound, disallowed, sitemaps) = robotsDeferred.await()
                val (secFound, contacts) = secTxtDeferred.await()

                val fingerprint = analyzeHtmlFingerprint(
                    targetHost = host,
                    finalUrl = home.finalUrl,
                    httpStatus = home.statusCode,
                    headers = home.headers,
                    html = home.body
                )

                Result.success(
                    fingerprint.copy(
                        robotsFound = robotsFound,
                        robotsDisallowed = disallowed,
                        robotsSitemaps = sitemaps,
                        securityTxtFound = secFound,
                        securityContacts = contacts
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(Exception("Deep web recon failed: ${e.message ?: "connection error"}"))
        }
    }

    /**
     * Pure deterministic HTML & HTTP header fingerprinting (directly unit-testable).
     */
    fun analyzeHtmlFingerprint(
        targetHost: String,
        finalUrl: String,
        httpStatus: Int,
        headers: Map<String, String>,
        html: String
    ): WebTechReconResult {
        val lowerHeaders = headers.entries.associate { it.key.lowercase() to it.value }
        val server = lowerHeaders["server"].orEmpty()
        val poweredBy = lowerHeaders["x-powered-by"].orEmpty()
        val setCookie = lowerHeaders["set-cookie"].orEmpty()
        val lowerHtml = html.lowercase()

        val title = TITLE_REGEX.find(html)?.groupValues?.getOrNull(1)
            ?.replace(Regex("\\s+"), " ")
            ?.trim()
            ?.take(120)
            .orEmpty()

        val generator = GENERATOR_REGEX.find(html)?.groupValues?.getOrNull(1)?.trim().orEmpty()

        val techs = LinkedHashMap<String, WebTechSignature>()
        fun addTech(name: String, category: String, evidence: String) {
            techs.putIfAbsent(name, WebTechSignature(name, category, evidence))
        }

        // CDN / WAF / Edge
        if (lowerHeaders.containsKey("cf-ray") || server.contains("cloudflare", true)) {
            addTech("Cloudflare", "CDN / WAF", lowerHeaders["cf-ray"]?.let { "cf-ray: $it" } ?: "Server header")
        }
        if (lowerHeaders.containsKey("x-amz-cf-id") || lowerHeaders["via"].orEmpty().contains("cloudfront", true)) {
            addTech("AWS CloudFront", "CDN", "x-amz-cf-id / Via header")
        }
        if (lowerHeaders.containsKey("x-served-by") && lowerHeaders["x-served-by"].orEmpty().contains("cache", true) ||
            lowerHeaders.containsKey("fastly-restarts")
        ) {
            addTech("Fastly", "CDN", "Fastly cache headers")
        }
        if (lowerHeaders.containsKey("x-vercel-id") || server.contains("vercel", true)) {
            addTech("Vercel", "Hosting / Edge", "x-vercel-id")
        }
        if (lowerHeaders.containsKey("x-nf-request-id") || server.contains("netlify", true)) {
            addTech("Netlify", "Hosting / Edge", "x-nf-request-id")
        }
        if (lowerHeaders.containsKey("x-github-request-id") || server.contains("github.com", true)) {
            addTech("GitHub Infrastructure", "Hosting", "x-github-request-id")
        }
        if (lowerHeaders["x-akamai-transformed"] != null || server.contains("akamai", true)) {
            addTech("Akamai", "CDN / WAF", "Akamai headers")
        }

        // Web Servers & Runtimes
        if (server.contains("nginx", true)) addTech("Nginx", "Web Server", server)
        if (server.contains("apache", true)) addTech("Apache HTTPD", "Web Server", server)
        if (server.contains("litespeed", true)) addTech("LiteSpeed", "Web Server", server)
        if (server.contains("iis", true)) addTech("Microsoft IIS", "Web Server", server)
        if (poweredBy.contains("php", true) || setCookie.contains("PHPSESSID", true)) {
            addTech("PHP", "Runtime", poweredBy.ifBlank { "PHPSESSID cookie" })
        }
        if (poweredBy.contains("express", true)) addTech("Express.js", "Backend", poweredBy)
        if (poweredBy.contains("next.js", true) || lowerHtml.contains("__next_data__") || lowerHtml.contains("/_next/static")) {
            addTech("Next.js", "JS Framework", "__NEXT_DATA__ / _next/static")
        }
        if (lowerHtml.contains("__nuxt") || lowerHtml.contains("/_nuxt/")) {
            addTech("Nuxt.js", "JS Framework", "_nuxt bundle")
        }
        if (poweredBy.contains("asp.net", true) || setCookie.contains("ASP.NET_SessionId", true)) {
            addTech("ASP.NET", "Backend", poweredBy.ifBlank { "ASP.NET cookie" })
        }

        // CMS & Commerce
        if (lowerHtml.contains("wp-content/") || lowerHtml.contains("wp-includes/") || generator.contains("wordpress", true)) {
            addTech("WordPress", "CMS", generator.ifBlank { "wp-content paths" })
        }
        if (lowerHtml.contains("cdn.shopify.com") || lowerHeaders.containsKey("x-shopid")) {
            addTech("Shopify", "E-Commerce", "cdn.shopify.com")
        }
        if (lowerHtml.contains("drupal.settings") || generator.contains("drupal", true)) {
            addTech("Drupal", "CMS", generator.ifBlank { "Drupal.settings" })
        }
        if (lowerHtml.contains("squarespace.com") || lowerHtml.contains("static1.squarespace")) {
            addTech("Squarespace", "CMS", "Squarespace static assets")
        }
        if (lowerHtml.contains("wixstatic.com") || generator.contains("wix", true)) {
            addTech("Wix", "CMS", "wixstatic.com")
        }
        if (lowerHtml.contains("webflow.js") || generator.contains("webflow", true)) {
            addTech("Webflow", "CMS", "Webflow generator/script")
        }
        if (lowerHtml.contains("ghost.org") || generator.contains("ghost", true)) {
            addTech("Ghost", "CMS", generator.ifBlank { "Ghost meta" })
        }

        // Frontend & Analytics
        if (lowerHtml.contains("data-reactroot") || lowerHtml.contains("react-dom") || lowerHtml.contains("__react")) {
            addTech("React", "Frontend", "React DOM markers")
        }
        if (lowerHtml.contains("ng-version=") || lowerHtml.contains("ng-app")) {
            addTech("Angular", "Frontend", "ng-version attribute")
        }
        if (lowerHtml.contains("data-v-") || lowerHtml.contains("vue.runtime") || lowerHtml.contains("vue.global")) {
            addTech("Vue.js", "Frontend", "Vue markers")
        }
        if (lowerHtml.contains("tailwindcss") || Regex("""class=["'][^"']*\b(?:bg-slate-|text-gray-|flex-col|rounded-lg)\b""").containsMatchIn(lowerHtml)) {
            addTech("Tailwind CSS", "CSS", "Utility classes")
        }
        if (lowerHtml.contains("bootstrap.min.css") || lowerHtml.contains("bootstrap.bundle")) {
            addTech("Bootstrap", "CSS", "Bootstrap stylesheet")
        }
        if (lowerHtml.contains("googletagmanager.com/gtag") || lowerHtml.contains("googletagmanager.com/gtm")) {
            addTech("Google Tag Manager / GA", "Analytics", "googletagmanager.com")
        }
        if (lowerHtml.contains("connect.facebook.net") || lowerHtml.contains("fbq(")) {
            addTech("Meta Pixel", "Analytics", "connect.facebook.net")
        }
        if (lowerHtml.contains("challenges.cloudflare.com/turnstile")) {
            addTech("Cloudflare Turnstile", "Bot Defense", "turnstile script")
        }
        if (lowerHtml.contains("google.com/recaptcha") || lowerHtml.contains("gstatic.com/recaptcha")) {
            addTech("Google reCAPTCHA", "Bot Defense", "recaptcha script")
        }
        if (lowerHtml.contains("js.stripe.com")) {
            addTech("Stripe", "Payments", "js.stripe.com")
        }
        if (lowerHtml.contains("sentry.io") || lowerHtml.contains("browser.sentry-cdn.com")) {
            addTech("Sentry", "Monitoring", "Sentry SDK")
        }

        // Extract pivotable external domains referenced in HTML
        val rootTarget = targetHost.lowercase()
        val externalDomains = linkedSetOf<String>()
        HREF_SRC_REGEX.findAll(html).forEach { match ->
            val url = match.groupValues[1]
            val extHost = PivotEngine.extractHost(url)
            if (!extHost.isNullOrBlank() &&
                extHost != rootTarget &&
                !extHost.endsWith(".$rootTarget") &&
                externalDomains.size < 25
            ) {
                externalDomains.add(extHost)
            }
        }

        return WebTechReconResult(
            targetHost = targetHost,
            finalUrl = finalUrl,
            httpStatus = httpStatus,
            pageTitle = title,
            metaGenerator = generator,
            serverHeader = server,
            poweredBy = poweredBy,
            technologies = techs.values.toList(),
            externalDomains = externalDomains.toList()
        )
    }

    private data class PageSnapshot(
        val finalUrl: String,
        val statusCode: Int,
        val headers: Map<String, String>,
        val body: String
    )

    private fun fetchHomepage(baseUrl: String): PageSnapshot? {
        val resp = NetworkSecurityGuard.executeSafeGetWithRedirectChecks(
            baseClient = OsintApiClient.client,
            startUrl = baseUrl,
            maxBytes = 200_000,
            maxHops = 5,
            headers = mapOf("Accept" to "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
        ) ?: return null
        return PageSnapshot(
            finalUrl = resp.finalUrl,
            statusCode = resp.statusCode,
            headers = resp.headers,
            body = resp.body
        )
    }

    private fun fetchRobotsTxt(baseUrl: String): Triple<Boolean, List<String>, List<String>> {
        val resp = NetworkSecurityGuard.executeSafeGetWithRedirectChecks(
            baseClient = OsintApiClient.client,
            startUrl = "$baseUrl/robots.txt",
            maxBytes = 40_000,
            maxHops = 3
        ) ?: return Triple(false, emptyList(), emptyList())
        if (resp.statusCode !in 200..299) return Triple(false, emptyList(), emptyList())
        val text = resp.body
        if (text.contains("<html", ignoreCase = true)) {
            return Triple(false, emptyList(), emptyList())
        }
        val disallowed = linkedSetOf<String>()
        val sitemaps = linkedSetOf<String>()
        text.lines().forEach { rawLine ->
            val line = rawLine.substringBefore('#').trim()
            when {
                line.startsWith("Disallow:", ignoreCase = true) -> {
                    val path = line.substringAfter(':').trim()
                    if (path.isNotBlank() && disallowed.size < 30) disallowed.add(path)
                }
                line.startsWith("Sitemap:", ignoreCase = true) -> {
                    val sm = line.substringAfter(':').trim()
                    if (sm.isNotBlank() && sitemaps.size < 10) sitemaps.add(sm)
                }
            }
        }
        return Triple(true, disallowed.toList(), sitemaps.toList())
    }

    private fun fetchSecurityTxt(baseUrl: String): Pair<Boolean, List<String>> {
        val resp = NetworkSecurityGuard.executeSafeGetWithRedirectChecks(
            baseClient = OsintApiClient.client,
            startUrl = "$baseUrl/.well-known/security.txt",
            maxBytes = 20_000,
            maxHops = 3
        ) ?: return false to emptyList()
        if (resp.statusCode !in 200..299) return false to emptyList()
        val text = resp.body
        if (text.contains("<html", ignoreCase = true)) return false to emptyList()
        val contacts = text.lines()
            .map { it.trim() }
            .filter {
                it.startsWith("Contact:", ignoreCase = true) ||
                    it.startsWith("Policy:", ignoreCase = true) ||
                    it.startsWith("Encryption:", ignoreCase = true) ||
                    it.startsWith("Expires:", ignoreCase = true)
            }
            .take(10)
        return (contacts.isNotEmpty()) to contacts
    }

    private fun isDisallowedLocalTarget(host: String): Boolean {
        return NetworkSecurityGuard.isBlockedPrivateHost(host)
    }
}
