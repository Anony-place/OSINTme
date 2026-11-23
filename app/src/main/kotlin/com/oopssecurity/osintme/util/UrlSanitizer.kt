package com.oopssecurity.osintme.util

data class SanitizationResult(
    val originalUrl: String,
    val sanitizedUrl: String,
    val removedParams: List<String>,
    val bytesSaved: Int,
    val reductionPercent: Int
)

object UrlSanitizer {
    // Known marketing & tracking parameters to strip
    private val TRACKER_PATTERNS = setOf(
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "utm_id", "utm_reader", "utm_name", "utm_cid", "utm_swu", "utm_viz_id",
        "fbclid", "gclid", "gclsrc", "dclid", "wbraid", "gbraid",
        "si", "igsh", "igshid", "ref", "ref_src", "ref_url", "source",
        "mc_cid", "mc_eid", "_hsenc", "_hsmi", "yclid", "spjobid",
        "trk", "trk_campaign", "vero_id", "vero_conv", "sc_campaign",
        "mkt_tok", "zanpid", "aff_id", "click_id", "irclickid",
        "_ga", "_gl", "twclid", "ncid", "guccounter", "cmpid"
    )

    fun sanitize(url: String): SanitizationResult {
        var cleanInput = url.trim()
        if (!cleanInput.startsWith("http://") && !cleanInput.startsWith("https://")) {
            cleanInput = "https://$cleanInput"
        }

        val questionIdx = cleanInput.indexOf('?')
        if (questionIdx == -1) {
            return SanitizationResult(
                originalUrl = cleanInput,
                sanitizedUrl = cleanInput,
                removedParams = emptyList(),
                bytesSaved = 0,
                reductionPercent = 0
            )
        }

        val base = cleanInput.substring(0, questionIdx)
        val queryString = cleanInput.substring(questionIdx + 1)
        val hashIdx = queryString.indexOf('#')
        val queryOnly = if (hashIdx != -1) queryString.substring(0, hashIdx) else queryString
        val fragment = if (hashIdx != -1) queryString.substring(hashIdx) else ""

        val pairs = queryOnly.split("&")
        val keptPairs = mutableListOf<String>()
        val removed = mutableListOf<String>()

        for (pair in pairs) {
            if (pair.isEmpty()) continue
            val eqIdx = pair.indexOf('=')
            val key = (if (eqIdx != -1) pair.substring(0, eqIdx) else pair).trim()
            val lowerKey = key.lowercase()

            val isTracker = TRACKER_PATTERNS.contains(lowerKey) ||
                    lowerKey.startsWith("utm_") ||
                    lowerKey.startsWith("fb_") ||
                    lowerKey.startsWith("ga_")

            if (isTracker) {
                removed.add(pair)
            } else {
                keptPairs.add(pair)
            }
        }

        val newQuery = if (keptPairs.isNotEmpty()) "?" + keptPairs.joinToString("&") else ""
        val sanitized = "$base$newQuery$fragment"

        val originalBytes = cleanInput.toByteArray().size
        val sanitizedBytes = sanitized.toByteArray().size
        val bytesSaved = (originalBytes - sanitizedBytes).coerceAtLeast(0)
        val reductionPercent = if (originalBytes > 0) ((bytesSaved.toDouble() / originalBytes) * 100).toInt() else 0

        return SanitizationResult(
            originalUrl = cleanInput,
            sanitizedUrl = sanitized,
            removedParams = removed,
            bytesSaved = bytesSaved,
            reductionPercent = reductionPercent
        )
    }
}
