package com.oopssecurity.osintme.util

import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

data class MailHop(
    val hopNumber: Int,
    val fromHost: String,
    val byHost: String,
    val ipAddress: String?,
    val protocol: String,
    val rawTimestamp: String,
    val epochMillis: Long?,
    val delaySeconds: Long?,
    val isDelayAnomaly: Boolean = false
)

data class AuthCheckVerdict(
    val mechanism: String, // SPF, DKIM, DMARC, ARC
    val status: String,    // PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, PERMERROR
    val detail: String
)

data class EmailHeaderReport(
    val subject: String,
    val fromAddress: String,
    val fromDomain: String,
    val returnPath: String,
    val returnPathDomain: String,
    val replyTo: String,
    val replyToDomain: String,
    val messageId: String,
    val dateHeader: String,
    val originatingIp: String?,
    val xMailer: String,
    val hops: List<MailHop>,
    val authChecks: List<AuthCheckVerdict>,
    val spoofingAlerts: List<String>,
    val riskVerdict: String, // LOW, MEDIUM, HIGH
    val allExtractedIps: List<String>,
    val totalTransitSeconds: Long?
)

/**
 * Deterministic RFC-5322 Email Header Forensic Analyzer.
 * Unfolds multi-line headers, reconstructs chronological mail relay hops,
 * calculates hop-by-hop transit delays, checks SPF/DKIM/DMARC/ARC results,
 * and flags From / Return-Path / Reply-To spoofing mismatches.
 */
object EmailHeaderAnalyzer {

    private val IPV4_REGEX = Regex("""\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b""")
    private val EMAIL_REGEX = Regex("""[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}""")
    private val FROM_HOP_REGEX = Regex("""(?i)\bfrom\s+([^\s;()]+)""")
    private val BY_HOP_REGEX = Regex("""(?i)\bby\s+([^\s;()]+)""")
    private val WITH_HOP_REGEX = Regex("""(?i)\bwith\s+([A-Za-z0-9\-/]+)""")
    private val AUTH_TOKEN_REGEX = Regex("""(?i)\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)([^;]*)""")

    private val DATE_PATTERNS = listOf(
        "EEE, d MMM yyyy HH:mm:ss Z",
        "d MMM yyyy HH:mm:ss Z",
        "EEE, dd MMM yyyy HH:mm:ss z",
        "EEE, d MMM yyyy HH:mm:ss z",
        "yyyy-MM-dd'T'HH:mm:ssZ",
        "yyyy-MM-dd HH:mm:ss Z"
    )

    fun analyze(rawHeaders: String): EmailHeaderReport {
        val unfolded = unfoldHeaders(rawHeaders)
        val headerList = mutableListOf<Pair<String, String>>()

        unfolded.lines().forEach { line ->
            val colonIdx = line.indexOf(':')
            if (colonIdx > 0) {
                val name = line.substring(0, colonIdx).trim()
                val value = line.substring(colonIdx + 1).trim()
                if (name.matches(Regex("^[A-Za-z0-9\\-]+$"))) {
                    headerList.add(name to value)
                }
            }
        }

        fun firstHeader(name: String): String =
            headerList.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second.orEmpty()

        fun allHeaders(name: String): List<String> =
            headerList.filter { it.first.equals(name, ignoreCase = true) }.map { it.second }

        val subject = firstHeader("Subject").ifBlank { "(No Subject)" }
        val fromRaw = firstHeader("From")
        val returnPathRaw = firstHeader("Return-Path")
        val replyToRaw = firstHeader("Reply-To")
        val messageId = firstHeader("Message-ID")
        val dateHeader = firstHeader("Date")
        val xMailer = firstHeader("X-Mailer").ifBlank { firstHeader("User-Agent") }
        val originatingIp = firstHeader("X-Originating-IP").let { raw ->
            IPV4_REGEX.find(raw)?.value
        }

        val fromAddress = extractEmail(fromRaw)
        val returnPath = extractEmail(returnPathRaw)
        val replyTo = extractEmail(replyToRaw)

        val fromDomain = extractDomain(fromAddress)
        val returnPathDomain = extractDomain(returnPath)
        val replyToDomain = extractDomain(replyTo)

        // Parse Received headers in chronological order (bottom-most Received header is hop #1)
        val receivedRaw = allHeaders("Received").reversed()
        val parsedHops = mutableListOf<MailHop>()
        var previousEpoch: Long? = null

        receivedRaw.forEachIndexed { idx, value ->
            val fromHost = FROM_HOP_REGEX.find(value)?.groupValues?.getOrNull(1).orEmpty().ifBlank { "Unknown" }
            val byHost = BY_HOP_REGEX.find(value)?.groupValues?.getOrNull(1).orEmpty().ifBlank { "Unknown" }
            val protocol = WITH_HOP_REGEX.find(value)?.groupValues?.getOrNull(1).orEmpty().ifBlank { "SMTP" }
            val hopIp = IPV4_REGEX.find(value)?.value
            val timestampPart = value.substringAfterLast(';', "").trim()
            val epoch = parseRfc2822Date(timestampPart)

            val delaySec = if (epoch != null && previousEpoch != null) {
                (epoch - previousEpoch!!) / 1000L
            } else null

            // Flag negative clock skew (< -120s) or suspicious delay (> 10 minutes)
            val anomaly = delaySec != null && (delaySec < -120L || delaySec > 600L)
            if (epoch != null) previousEpoch = epoch

            parsedHops.add(
                MailHop(
                    hopNumber = idx + 1,
                    fromHost = fromHost,
                    byHost = byHost,
                    ipAddress = hopIp,
                    protocol = protocol,
                    rawTimestamp = timestampPart,
                    epochMillis = epoch,
                    delaySeconds = delaySec,
                    isDelayAnomaly = anomaly
                )
            )
        }

        val validEpochs = parsedHops.mapNotNull { it.epochMillis }
        val totalTransit = if (validEpochs.size >= 2) {
            ((validEpochs.last() - validEpochs.first()) / 1000L).coerceAtLeast(0L)
        } else null

        // Parse Authentication-Results / Received-SPF / ARC-Authentication-Results
        val authMap = linkedMapOf<String, AuthCheckVerdict>()
        val authSources = allHeaders("Authentication-Results") +
            allHeaders("ARC-Authentication-Results")

        authSources.forEach { authVal ->
            AUTH_TOKEN_REGEX.findAll(authVal).forEach { m ->
                val mech = m.groupValues[1].uppercase()
                val status = m.groupValues[2].uppercase()
                val detail = m.groupValues[3].trim().take(120)
                if (!authMap.containsKey(mech)) {
                    authMap[mech] = AuthCheckVerdict(mech, status, detail.ifBlank { "Reported in Authentication-Results" })
                }
            }
        }

        val receivedSpf = firstHeader("Received-SPF")
        if (receivedSpf.isNotBlank() && !authMap.containsKey("SPF")) {
            val spfStatus = receivedSpf.substringBefore(" ").uppercase()
                .replace("(", "").replace(")", "")
            authMap["SPF"] = AuthCheckVerdict("SPF", spfStatus.ifBlank { "UNKNOWN" }, receivedSpf.take(120))
        }

        val authChecks = listOf("SPF", "DKIM", "DMARC", "ARC").mapNotNull { authMap[it] }

        // Detect spoofing & alignment red flags
        val alerts = mutableListOf<String>()
        if (fromDomain.isNotBlank() && returnPathDomain.isNotBlank() &&
            !domainsAligned(fromDomain, returnPathDomain)
        ) {
            alerts.add("Return-Path mismatch: From domain ($fromDomain) differs from bounce envelope ($returnPathDomain)")
        }
        if (fromDomain.isNotBlank() && replyToDomain.isNotBlank() &&
            !domainsAligned(fromDomain, replyToDomain)
        ) {
            alerts.add("Reply-To diversion: Replies route to $replyToDomain instead of $fromDomain (common BEC/phishing pattern)")
        }
        authChecks.forEach { check ->
            if (check.status in setOf("FAIL", "SOFTFAIL", "PERMERROR", "TEMPORARYERROR")) {
                alerts.add("${check.mechanism} ${check.status}: ${check.detail}")
            }
        }
        if (authChecks.isEmpty() && headerList.isNotEmpty()) {
            alerts.add("No Authentication-Results (SPF/DKIM/DMARC) header found in pasted snippet")
        }
        if (parsedHops.any { it.isDelayAnomaly }) {
            alerts.add("Hop timestamp anomaly detected (clock skew or >10m transit delay)")
        }

        val hasHardFail = authChecks.any { it.status == "FAIL" } ||
            alerts.any { it.startsWith("Reply-To diversion") }
        val riskVerdict = when {
            hasHardFail || alerts.size >= 2 -> "HIGH"
            alerts.size == 1 -> "MEDIUM"
            else -> "LOW"
        }

        val allIps = buildList {
            if (!originatingIp.isNullOrBlank()) add(originatingIp)
            parsedHops.mapNotNull { it.ipAddress }.forEach { add(it) }
            IPV4_REGEX.findAll(rawHeaders).forEach { add(it.value) }
        }.distinct().filterNot { isPrivateIp(it) }

        return EmailHeaderReport(
            subject = subject,
            fromAddress = fromAddress.ifBlank { fromRaw.ifBlank { "Unknown" } },
            fromDomain = fromDomain,
            returnPath = returnPath.ifBlank { returnPathRaw },
            returnPathDomain = returnPathDomain,
            replyTo = replyTo.ifBlank { replyToRaw },
            replyToDomain = replyToDomain,
            messageId = messageId,
            dateHeader = dateHeader,
            originatingIp = originatingIp,
            xMailer = xMailer,
            hops = parsedHops,
            authChecks = authChecks,
            spoofingAlerts = alerts,
            riskVerdict = riskVerdict,
            allExtractedIps = allIps,
            totalTransitSeconds = totalTransit
        )
    }

    private fun unfoldHeaders(raw: String): String {
        val sb = StringBuilder()
        raw.replace("\r\n", "\n").replace("\r", "\n").lines().forEach { line ->
            if ((line.startsWith(" ") || line.startsWith("\t")) && sb.isNotEmpty()) {
                sb.append(' ').append(line.trim())
            } else {
                if (sb.isNotEmpty()) sb.append('\n')
                sb.append(line)
            }
        }
        return sb.toString()
    }

    private fun extractEmail(raw: String): String {
        return EMAIL_REGEX.find(raw)?.value?.lowercase().orEmpty()
    }

    private fun extractDomain(email: String): String {
        return email.substringAfter("@", "").lowercase().trim()
    }

    private fun domainsAligned(d1: String, d2: String): Boolean {
        if (d1.equals(d2, ignoreCase = true)) return true
        val root1 = organizationalDomain(d1)
        val root2 = organizationalDomain(d2)
        return root1.equals(root2, ignoreCase = true)
    }

    private fun organizationalDomain(domain: String): String {
        val parts = domain.lowercase().split(".").filter { it.isNotBlank() }
        return if (parts.size >= 2) parts.takeLast(2).joinToString(".") else domain.lowercase()
    }

    private fun parseRfc2822Date(raw: String): Long? {
        if (raw.isBlank()) return null
        val cleaned = raw
            .replace(Regex("""\s*\([^)]*\)\s*"""), " ")
            .replace(Regex("""\s+"""), " ")
            .trim()
        for (pattern in DATE_PATTERNS) {
            try {
                val fmt = SimpleDateFormat(pattern, Locale.US).apply {
                    timeZone = TimeZone.getTimeZone("UTC")
                    isLenient = true
                }
                val parsed = fmt.parse(cleaned)
                if (parsed != null) return parsed.time
            } catch (_: Exception) {
                // Try next pattern
            }
        }
        return null
    }

    private fun isPrivateIp(ip: String): Boolean {
        return ip.startsWith("10.") ||
            ip.startsWith("127.") ||
            ip.startsWith("192.168.") ||
            ip.startsWith("169.254.") ||
            Regex("^172\\.(1[6-9]|2\\d|3[01])\\.").containsMatchIn(ip)
    }
}
