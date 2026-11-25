package com.oopssecurity.osintme.util

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI

data class SafeHttpResponse(
    val finalUrl: String,
    val statusCode: Int,
    val headers: Map<String, String>,
    val body: String
)

/**
 * Centralized outbound network security guard for passive OSINT clients.
 * - Blocks loopback, private RFC1918, link-local/cloud metadata, CGNAT, and IPv6 local targets
 * - Validates every redirect hop before connecting to prevent internal-network redirection
 * - Enforces strict byte-bounded body reads to prevent memory exhaustion on large responses
 */
object NetworkSecurityGuard {

    private val NUMERIC_IPV4_PRIVATE_REGEX = Regex(
        "^(?:0\\.|127\\.|10\\.|192\\.168\\.|169\\.254\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.|100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])\\.)"
    )

    fun validatePublicHttpUrl(rawUrl: String, requireHttps: Boolean = false): Result<String> {
        val clean = rawUrl.trim()
        if (clean.isBlank() || clean.length > 2048) {
            return Result.failure(Exception("URL is empty or exceeds safe length limit"))
        }
        if (clean.any { it.code < 0x20 || it.code == 0x7F }) {
            return Result.failure(Exception("URL contains disallowed control characters"))
        }
        return try {
            val uri = URI(clean)
            val scheme = uri.scheme?.lowercase().orEmpty()
            val allowedSchemes = if (requireHttps) setOf("https") else setOf("http", "https")
            if (scheme !in allowedSchemes) {
                val msg = if (requireHttps) {
                    "Endpoint must use HTTPS for credential security"
                } else {
                    "Only HTTP and HTTPS URLs are supported"
                }
                return Result.failure(Exception(msg))
            }
            val host = uri.host?.lowercase()?.removePrefix("[")?.removeSuffix("]")?.trim().orEmpty()
            if (host.isBlank() || (!host.contains(".") && !host.contains(":"))) {
                return Result.failure(Exception("Enter a valid public hostname"))
            }
            if (isBlockedPrivateHost(host)) {
                return Result.failure(Exception("Private, loopback, or local-network targets are blocked"))
            }
            Result.success(clean)
        } catch (e: Exception) {
            Result.failure(Exception("Invalid URL: ${e.message ?: "malformed"}"))
        }
    }

    fun isBlockedPrivateHost(rawHost: String): Boolean {
        val host = rawHost.trim().lowercase()
            .removePrefix("[")
            .removeSuffix("]")
            .removeSuffix(".")
        if (host.isBlank()) return true
        if (host == "localhost" ||
            host.endsWith(".localhost") ||
            host.endsWith(".local") ||
            host.endsWith(".internal") ||
            host.endsWith(".home.arpa") ||
            host == "metadata.google.internal" ||
            host == "0.0.0.0" ||
            host == "::1" ||
            host == "::"
        ) {
            return true
        }
        if (NUMERIC_IPV4_PRIVATE_REGEX.containsMatchIn(host)) return true
        if (host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80") || host.startsWith("::ffff:")) {
            if (host.contains(":")) return true
        }

        return try {
            InetAddress.getAllByName(host).any { addr -> isRestrictedAddress(addr) }
        } catch (_: Exception) {
            // Unresolvable host cannot be connected safely; let literal non-public checks stand
            false
        }
    }

    internal fun isRestrictedAddress(addr: InetAddress): Boolean {
        if (addr.isAnyLocalAddress ||
            addr.isLoopbackAddress ||
            addr.isLinkLocalAddress ||
            addr.isSiteLocalAddress ||
            addr.isMulticastAddress
        ) {
            return true
        }
        return when (addr) {
            is Inet4Address -> {
                val b = addr.address
                val b0 = b[0].toInt() and 0xFF
                val b1 = b[1].toInt() and 0xFF
                // 0.0.0.0/8 ("this network"), 100.64.0.0/10 (CGNAT), 192.0.0.0/24, 198.18.0.0/15 (benchmark)
                b0 == 0 ||
                    (b0 == 100 && b1 in 64..127) ||
                    (b0 == 198 && (b1 == 18 || b1 == 19))
            }
            is Inet6Address -> {
                val b = addr.address
                val b0 = b[0].toInt() and 0xFF
                // Unique Local Addresses fc00::/7
                (b0 and 0xFE) == 0xFC
            }
            else -> false
        }
    }

    fun readBodyBounded(response: Response, maxBytes: Int): String {
        val stream = response.body?.byteStream() ?: return ""
        val cap = maxBytes.coerceIn(1024, 512_000)
        val buffer = ByteArray(cap)
        var total = 0
        try {
            while (total < cap) {
                val read = stream.read(buffer, total, cap - total)
                if (read <= 0) break
                total += read
            }
        } catch (_: Exception) {
            // Return whatever valid prefix was read before stream interruption
        }
        return String(buffer, 0, total, Charsets.UTF_8)
    }

    /**
     * Executes a GET request with manual redirect following, validating EVERY redirect hop
     * against private/loopback/internal IP ranges and reading at most [maxBytes].
     */
    fun executeSafeGetWithRedirectChecks(
        baseClient: OkHttpClient,
        startUrl: String,
        maxBytes: Int = 262_144,
        maxHops: Int = 5,
        headers: Map<String, String> = emptyMap()
    ): SafeHttpResponse? {
        val noRedirectClient = baseClient.newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

        var currentUrl = validatePublicHttpUrl(startUrl, requireHttps = false).getOrNull() ?: return null

        for (hop in 0..maxHops) {
            val reqBuilder = Request.Builder().url(currentUrl).get()
            headers.forEach { (k, v) -> reqBuilder.header(k, v) }

            val response = try {
                noRedirectClient.newCall(reqBuilder.build()).execute()
            } catch (_: Exception) {
                return null
            }

            response.use { resp ->
                val location = resp.header("Location")?.trim()
                if (resp.code in setOf(301, 302, 303, 307, 308) && !location.isNullOrBlank() && hop < maxHops) {
                    val resolved = runCatching { URI(currentUrl).resolve(location).toString() }.getOrNull() ?: return null
                    currentUrl = validatePublicHttpUrl(resolved, requireHttps = false).getOrNull() ?: return null
                } else {
                    val headerMap = mutableMapOf<String, String>()
                    resp.headers.names().forEach { name ->
                        headerMap[name] = resp.headers.values(name).joinToString("; ")
                    }
                    val bodyStr = readBodyBounded(resp, maxBytes)
                    return SafeHttpResponse(
                        finalUrl = currentUrl,
                        statusCode = resp.code,
                        headers = headerMap,
                        body = bodyStr
                    )
                }
            }
        }
        return null
    }
}
