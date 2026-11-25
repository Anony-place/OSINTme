package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.util.NetworkSecurityGuard
import com.oopssecurity.osintme.util.PivotEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.net.URI

data class SocialProfileLink(
    val platform: String,
    val url: String,
    val handle: String
)

data class TrackingIdHit(
    val provider: String,
    val id: String
)

data class DeepWebCrawlReport(
    val targetHost: String,
    val finalUrl: String,
    val pageTitle: String,
    val metaDescription: String,
    val metaAuthorOrOrg: String,
    val emails: List<String>,
    val socialLinks: List<SocialProfileLink>,
    val trackingIds: List<TrackingIdHit>,
    val apiEndpoints: List<String>,
    val cloudBuckets: List<String>,
    val securityTxtContacts: List<String>,
    val sitemapSampleUrls: List<String>,
    val jsFilesScanned: Int
)

/**
 * SpiderFoot / LinkFinder-class live passive Web & JavaScript Intelligence Scraper.
 * Inspects homepage HTML, /.well-known/security.txt, sitemap.xml, and up to 4 public
 * first-party JS bundles to mine emails, social profiles, analytics/tracking IDs,
 * API endpoints, and cloud storage references — strictly blocking private/loopback hosts.
 */
object DeepWebCrawlerService {

    private const val MAX_BYTES_PER_RESOURCE = 262_144 // 256 KB cap
    private const val MAX_JS_BUNDLES = 4

    private val EMAIL_REGEX = Regex("\\b[A-Za-z0-9._%+\\-]{2,64}@[A-Za-z0-9.\\-]{2,128}\\.[A-Za-z]{2,12}\\b")
    private val TITLE_REGEX = Regex("(?is)<title[^>]*>(.*?)</title>")
    private val META_DESC_REGEX = Regex("(?is)<meta[^>]+name=[\"']description[\"'][^>]+content=[\"']([^\"']{4,260})[\"']")
    private val OG_SITE_REGEX = Regex("(?is)<meta[^>]+property=[\"']og:site_name[\"'][^>]+content=[\"']([^\"']{2,120})[\"']")
    private val META_AUTHOR_REGEX = Regex("(?is)<meta[^>]+name=[\"']author[\"'][^>]+content=[\"']([^\"']{2,120})[\"']")
    private val SCRIPT_SRC_REGEX = Regex("(?is)<script[^>]+src=[\"']([^\"']+)[\"']")

    private val GA4_REGEX = Regex("\\bG-[A-Z0-9]{7,12}\\b")
    private val UA_REGEX = Regex("\\bUA-\\d{4,10}-\\d{1,4}\\b")
    private val GTM_REGEX = Regex("\\bGTM-[A-Z0-9]{5,10}\\b")
    private val ADSENSE_REGEX = Regex("\\b(?:ca-)?pub-\\d{12,18}\\b")
    private val FB_PIXEL_REGEX = Regex("fbq\\(['\"]init['\"]\\s*,\\s*['\"](\\d{10,20})['\"]")

    private val API_PATH_REGEX = Regex("['\"]((?:/api/|/v[1-4]/|/graphql|/swagger|/openapi|/wp-json/|/oauth/|/auth/)[A-Za-z0-9_\\-/.:?=&%]{1,90})['\"]")
    private val CLOUD_BUCKET_REGEX = Regex(
        "(?i)\\b(?:https?://)?([a-z0-9.\\-]{3,63}\\.s3(?:[.\\-][a-z0-9\\-]+)?\\.amazonaws\\.com(?:/[a-z0-9._\\-/]+)?|" +
            "s3\\.amazonaws\\.com/[a-z0-9.\\-_]{3,63}|" +
            "storage\\.googleapis\\.com/[a-z0-9.\\-_]{3,63}|" +
            "[a-z0-9.\\-]{3,63}\\.blob\\.core\\.windows\\.net(?:/[a-z0-9._\\-]+)?|" +
            "[a-z0-9\\-]{3,63}\\.firebaseio\\.com|" +
            "[a-z0-9\\-]{3,63}\\.r2\\.dev)"
    )

    private val SOCIAL_PATTERNS = listOf(
        "GitHub" to Regex("(?i)https?://(?:www\\.)?github\\.com/([A-Za-z0-9_\\-]{2,40})(?:/|\\b)"),
        "X / Twitter" to Regex("(?i)https?://(?:www\\.)?(?:twitter\\.com|x\\.com)/([A-Za-z0-9_]{2,30})(?:/|\\b)"),
        "LinkedIn" to Regex("(?i)https?://(?:www\\.)?linkedin\\.com/(?:company|in)/([A-Za-z0-9_\\-%]{2,60})"),
        "Instagram" to Regex("(?i)https?://(?:www\\.)?instagram\\.com/([A-Za-z0-9._]{2,35})(?:/|\\b)"),
        "YouTube" to Regex("(?i)https?://(?:www\\.)?youtube\\.com/(?:@|channel/|c/|user/)([A-Za-z0-9_\\-]{2,50})"),
        "Telegram" to Regex("(?i)https?://(?:www\\.)?(?:t\\.me|telegram\\.me)/([A-Za-z0-9_]{3,40})(?:/|\\b)"),
        "Discord" to Regex("(?i)https?://(?:www\\.)?(?:discord\\.gg|discord\\.com/invite)/([A-Za-z0-9\\-]{3,32})"),
        "Facebook" to Regex("(?i)https?://(?:www\\.)?facebook\\.com/([A-Za-z0-9._\\-]{3,50})(?:/|\\b)")
    )

    private val IGNORED_EMAIL_EXTS = setOf(".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".woff", ".woff2", ".js", ".css")
    private val IGNORED_SOCIAL_HANDLES = setOf("share", "sharer", "intent", "home", "explore", "login", "signup", "privacy", "terms", "about", "status", "watch", "embed")

    suspend fun crawlTarget(domainOrUrl: String): Result<DeepWebCrawlReport> = withContext(Dispatchers.IO) {
        val trimmed = domainOrUrl.trim()
        val host = PivotEngine.cleanDomainCandidate(trimmed)
        if (host.isBlank() || !host.contains(".")) {
            return@withContext Result.failure(Exception("Invalid target host for deep web crawl"))
        }
        if (isPrivateOrUnsafeHost(host)) {
            return@withContext Result.failure(Exception("Private or local network targets are blocked"))
        }

        val startUrl = if (trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true)) {
            trimmed
        } else {
            "https://$host/"
        }

        try {
            val homeFetch = (fetchTextBounded(startUrl)
                ?: if (startUrl.startsWith("https://")) fetchTextBounded("http://$host/") else null)
                ?: return@withContext Result.failure(Exception("Host did not respond with crawlable content"))

            val (finalUrl, html) = homeFetch
            val baseOrigin = runCatching {
                val u = URI(finalUrl)
                "${u.scheme}://${u.host}"
            }.getOrDefault("https://$host")

            // Identify up to 4 first-party public JS bundles
            val jsUrls = SCRIPT_SRC_REGEX.findAll(html)
                .map { it.groupValues[1].trim() }
                .mapNotNull { resolveSameOriginScript(baseOrigin, host, it) }
                .distinct()
                .take(MAX_JS_BUNDLES)
                .toList()

            coroutineScope {
                val secTxtDef = async { fetchTextBounded("$baseOrigin/.well-known/security.txt")?.second.orEmpty() }
                val sitemapDef = async { fetchTextBounded("$baseOrigin/sitemap.xml")?.second.orEmpty() }
                val jsDefs = jsUrls.map { jsUrl ->
                    async { fetchTextBounded(jsUrl)?.second.orEmpty() }
                }

                val securityTxt = secTxtDef.await()
                val sitemapXml = sitemapDef.await()
                val jsBodies = jsDefs.awaitAll().filter { it.isNotBlank() }

                val report = extractIntelligence(
                    targetHost = host,
                    finalUrl = finalUrl,
                    html = html,
                    jsBundles = jsBodies,
                    securityTxt = securityTxt,
                    sitemapXml = sitemapXml
                )
                Result.success(report)
            }
        } catch (e: Exception) {
            Result.failure(Exception("Deep web crawl failed: ${e.message ?: "error"}"))
        }
    }

    /**
     * Pure deterministic HTML / JS / security.txt / sitemap extractor (100% JVM unit-testable).
     */
    fun extractIntelligence(
        targetHost: String,
        finalUrl: String,
        html: String,
        jsBundles: List<String> = emptyList(),
        securityTxt: String = "",
        sitemapXml: String = ""
    ): DeepWebCrawlReport {
        val combinedCorpus = buildString {
            append(html)
            append("\n")
            append(securityTxt)
            jsBundles.forEach {
                append("\n")
                append(it)
            }
        }

        val pageTitle = TITLE_REGEX.find(html)?.groupValues?.getOrNull(1)
            ?.replace(Regex("\\s+"), " ")?.trim()?.take(120).orEmpty()
        val metaDesc = META_DESC_REGEX.find(html)?.groupValues?.getOrNull(1)?.trim().orEmpty()
        val metaOrg = OG_SITE_REGEX.find(html)?.groupValues?.getOrNull(1)?.trim()
            ?: META_AUTHOR_REGEX.find(html)?.groupValues?.getOrNull(1)?.trim().orEmpty()

        // 1. Emails
        val emails = EMAIL_REGEX.findAll(combinedCorpus)
            .map { it.value.lowercase().trim() }
            .filter { email ->
                IGNORED_EMAIL_EXTS.none { ext -> email.endsWith(ext) } &&
                    !email.endsWith(".wixpress.com") &&
                    !email.startsWith("noreply@") &&
                    !email.contains("example.com") &&
                    !email.contains("sentry.io")
            }
            .distinct()
            .take(25)
            .toList()

        // 2. Social profiles
        val socials = linkedMapOf<String, SocialProfileLink>()
        for ((platform, regex) in SOCIAL_PATTERNS) {
            regex.findAll(combinedCorpus).forEach { match ->
                val url = match.value.trimEnd('/', '"', '\'', ')')
                val handle = match.groupValues[1].trim()
                if (handle.lowercase() !in IGNORED_SOCIAL_HANDLES && socials.size < 20) {
                    socials.putIfAbsent("$platform:${handle.lowercase()}", SocialProfileLink(platform, url, handle))
                }
            }
        }

        // 3. Analytics & Tracking IDs (owner cross-linking goldmine)
        val trackingMap = linkedMapOf<String, TrackingIdHit>()
        GA4_REGEX.findAll(combinedCorpus).forEach { m ->
            trackingMap.putIfAbsent(m.value, TrackingIdHit("Google Analytics 4", m.value))
        }
        UA_REGEX.findAll(combinedCorpus).forEach { m ->
            trackingMap.putIfAbsent(m.value, TrackingIdHit("Universal Analytics", m.value))
        }
        GTM_REGEX.findAll(combinedCorpus).forEach { m ->
            trackingMap.putIfAbsent(m.value, TrackingIdHit("Google Tag Manager", m.value))
        }
        ADSENSE_REGEX.findAll(combinedCorpus).forEach { m ->
            trackingMap.putIfAbsent(m.value, TrackingIdHit("Google AdSense", m.value))
        }
        FB_PIXEL_REGEX.findAll(combinedCorpus).forEach { m ->
            val pid = m.groupValues[1]
            trackingMap.putIfAbsent("fb:$pid", TrackingIdHit("Meta Pixel", pid))
        }

        // 4. API & Hidden Endpoints
        val endpoints = API_PATH_REGEX.findAll(combinedCorpus)
            .map { it.groupValues[1].trim() }
            .filter { path -> path.length in 5..90 && !path.contains(" ") }
            .distinct()
            .take(25)
            .toList()

        // 5. Cloud Buckets / Storage endpoints
        val buckets = CLOUD_BUCKET_REGEX.findAll(combinedCorpus)
            .map { it.groupValues[1].lowercase().trimEnd('/', '"', '\'') }
            .distinct()
            .take(15)
            .toList()

        // 6. security.txt contacts
        val secContacts = securityTxt.lines()
            .map { it.trim() }
            .filter { line ->
                line.startsWith("Contact:", true) ||
                    line.startsWith("Encryption:", true) ||
                    line.startsWith("Policy:", true)
            }
            .map { it.substringAfter(":").trim() }
            .filter { it.isNotBlank() }
            .distinct()
            .take(8)

        // 7. Sitemap URLs sample
        val sitemapUrls = Regex("<loc>\\s*(https?://[^<\\s]+)\\s*</loc>", RegexOption.IGNORE_CASE)
            .findAll(sitemapXml)
            .map { it.groupValues[1].trim() }
            .distinct()
            .take(15)
            .toList()

        return DeepWebCrawlReport(
            targetHost = targetHost,
            finalUrl = finalUrl,
            pageTitle = pageTitle,
            metaDescription = metaDesc,
            metaAuthorOrOrg = metaOrg,
            emails = emails,
            socialLinks = socials.values.toList(),
            trackingIds = trackingMap.values.take(12),
            apiEndpoints = endpoints,
            cloudBuckets = buckets,
            securityTxtContacts = secContacts,
            sitemapSampleUrls = sitemapUrls,
            jsFilesScanned = jsBundles.size
        )
    }

    private fun resolveSameOriginScript(baseOrigin: String, targetHost: String, rawSrc: String): String? {
        if (rawSrc.isBlank() || rawSrc.startsWith("data:", true) || rawSrc.startsWith("javascript:", true)) return null
        val resolved = when {
            rawSrc.startsWith("https://", true) || rawSrc.startsWith("http://", true) -> rawSrc
            rawSrc.startsWith("//") -> "https:$rawSrc"
            rawSrc.startsWith("/") -> "$baseOrigin$rawSrc"
            else -> "$baseOrigin/$rawSrc"
        }
        val scriptHost = PivotEngine.extractHost(resolved) ?: return null
        // Restrict JS fetching to target domain or its direct subdomains (skip third-party ad CDNs)
        val rootDomain = targetHost.removePrefix("www.")
        val isFirstParty = scriptHost == targetHost || scriptHost.endsWith(".$rootDomain")
        if (!isFirstParty || isPrivateOrUnsafeHost(scriptHost)) return null
        // Skip common vendor minified libs that rarely hold target endpoints
        val lower = resolved.lowercase()
        if (lower.contains("jquery") || lower.contains("bootstrap") || lower.contains("gtag") || lower.contains("analytics.js")) {
            return null
        }
        return resolved
    }

    private fun fetchTextBounded(url: String): Pair<String, String>? {
        return NetworkSecurityGuard.executeSafeGetWithRedirectChecks(
            baseClient = OsintApiClient.client,
            startUrl = url,
            maxHops = 5,
            maxBytes = MAX_BYTES_PER_RESOURCE,
            headers = mapOf(
                "Accept" to "text/html,application/javascript,text/plain,application/xml;q=0.9,*/*;q=0.8"
            )
        )?.let { safeResp ->
            if (safeResp.statusCode in 200..299) safeResp.finalUrl to safeResp.body else null
        }
    }

    internal fun isPrivateOrUnsafeHost(host: String): Boolean =
        NetworkSecurityGuard.isBlockedPrivateHost(host)
}
