package com.oopssecurity.osintme.util

enum class IocCategory(val label: String, val badge: String) {
    IPV4("IPv4 Addresses", "IPV4"),
    IPV6("IPv6 Addresses", "IPV6"),
    DOMAIN("Domains", "DOMAIN"),
    URL("URLs", "URL"),
    EMAIL("Email Addresses", "EMAIL"),
    SHA256("SHA-256 Hashes", "SHA256"),
    SHA1("SHA-1 Hashes", "SHA1"),
    MD5("MD5 Hashes", "MD5"),
    CRYPTO_WALLET("Crypto Wallets", "WALLET"),
    PHONE("Phone Numbers", "PHONE")
}

data class ExtractedIoc(
    val value: String,
    val defangedValue: String,
    val category: IocCategory
)

data class IocExtractionResult(
    val items: List<ExtractedIoc>,
    val countsByCategory: Map<IocCategory, Int>
) {
    val totalCount: Int get() = items.size
}

/**
 * Deterministic IOC Extractor, Refanger & Defanger for incident logs, phishing emails,
 * threat reports, and firewall dumps. Handles already-defanged indicators seamlessly.
 */
object IocExtractor {

    private val URL_REGEX = Regex(
        """(?i)\b(?:https?|hxxps?|ftp)://[^\s<>"'\)\]]+"""
    )
    private val EMAIL_REGEX = Regex(
        """\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b"""
    )
    private val IPV4_REGEX = Regex(
        """\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"""
    )
    private val IPV6_REGEX = Regex(
        """(?i)\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b"""
    )
    private val DOMAIN_REGEX = Regex(
        """(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|gov|edu|mil|info|biz|me|xyz|top|ru|cn|uk|de|fr|in|jp|br|ca|au|nl|se|ch|pl|ua|ir|kp|dev|app|ai|cloud|tech|online|site|shop|store|pro|live|link|click|zip|mov|cc|tv|gg|ly|to|sh|su|pw|tk|ml|ga|cf|gq|work|support|security|bank|finance|pay|login)\b"""
    )
    private val SHA256_REGEX = Regex("""(?i)\b[0-9a-f]{64}\b""")
    private val SHA1_REGEX = Regex("""(?i)\b[0-9a-f]{40}\b""")
    private val MD5_REGEX = Regex("""(?i)\b[0-9a-f]{32}\b""")
    private val BTC_REGEX = Regex("""\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b""")
    private val ETH_REGEX = Regex("""\b0x[a-fA-F0-9]{40}\b""")
    private val PHONE_REGEX = Regex("""(?<!\w)\+[1-9]\d{0,2}[\s.\-]?(?:\(?\d{2,4}\)?[\s.\-]?){2,4}\d{2,4}\b""")

    /**
     * Converts defanged notation back to live canonical indicators before regex extraction.
     */
    fun refang(rawText: String): String {
        return rawText
            .replace(Regex("(?i)hxxps\\[:\\]//"), "https://")
            .replace(Regex("(?i)hxxp\\[:\\]//"), "http://")
            .replace(Regex("(?i)hxxps://"), "https://")
            .replace(Regex("(?i)hxxp://"), "http://")
            .replace(Regex("(?i)hXXps://"), "https://")
            .replace(Regex("(?i)hXXp://"), "http://")
            .replace("[:]", ":")
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace("{.}", ".")
            .replace("[dot]", ".", ignoreCase = true)
            .replace("[@]", "@")
            .replace("[at]", "@", ignoreCase = true)
            .replace("[/]", "/")
    }

    fun defang(value: String): String = PivotEngine.defang(value)

    fun extract(rawText: String): IocExtractionResult {
        if (rawText.isBlank()) {
            return IocExtractionResult(emptyList(), emptyMap())
        }

        val normalized = refang(rawText)
        val results = LinkedHashMap<String, ExtractedIoc>()

        fun add(value: String, category: IocCategory) {
            val clean = value.trim().trimEnd('.', ',', ';', ':', ')', ']', '>', '"', '\'')
            if (clean.isBlank()) return
            val key = "${category.name}::${clean.lowercase()}"
            if (!results.containsKey(key)) {
                results[key] = ExtractedIoc(
                    value = clean,
                    defangedValue = if (category in setOf(IocCategory.URL, IocCategory.DOMAIN, IocCategory.EMAIL, IocCategory.IPV4)) {
                        defang(clean)
                    } else clean,
                    category = category
                )
            }
        }

        // 1. URLs
        val foundUrls = mutableSetOf<String>()
        URL_REGEX.findAll(normalized).forEach { m ->
            val u = m.value.trimEnd('.', ',', ';', ')', ']', '"', '\'')
            foundUrls.add(u)
            add(u, IocCategory.URL)
            PivotEngine.extractHost(u)?.let { host ->
                if (IPV4_REGEX.matches(host)) add(host, IocCategory.IPV4)
                else if (host.contains(".")) add(host, IocCategory.DOMAIN)
            }
        }

        // 2. Emails
        val emailDomains = mutableSetOf<String>()
        EMAIL_REGEX.findAll(normalized).forEach { m ->
            val email = m.value.lowercase()
            add(email, IocCategory.EMAIL)
            email.substringAfter("@", "").takeIf { it.contains(".") }?.let { emailDomains.add(it) }
        }

        // 3. IPv4 & IPv6
        IPV4_REGEX.findAll(normalized).forEach { m ->
            add(m.value, IocCategory.IPV4)
        }
        IPV6_REGEX.findAll(normalized).forEach { m ->
            if (m.value.count { it == ':' } >= 3) {
                add(m.value.lowercase(), IocCategory.IPV6)
            }
        }

        // 4. Hashes (check longest first to avoid substring collisions)
        val sha256Set = mutableSetOf<String>()
        SHA256_REGEX.findAll(normalized).forEach { m ->
            val h = m.value.lowercase()
            sha256Set.add(h)
            add(h, IocCategory.SHA256)
        }
        val sha1Set = mutableSetOf<String>()
        SHA1_REGEX.findAll(normalized).forEach { m ->
            val h = m.value.lowercase()
            if (sha256Set.none { it.contains(h) }) {
                sha1Set.add(h)
                add(h, IocCategory.SHA1)
            }
        }
        MD5_REGEX.findAll(normalized).forEach { m ->
            val h = m.value.lowercase()
            if (sha256Set.none { it.contains(h) } && sha1Set.none { it.contains(h) }) {
                add(h, IocCategory.MD5)
            }
        }

        // 5. Crypto Wallets
        ETH_REGEX.findAll(normalized).forEach { m ->
            add(m.value, IocCategory.CRYPTO_WALLET)
        }
        BTC_REGEX.findAll(normalized).forEach { m ->
            val candidate = m.value
            // Avoid classifying pure hex hashes as BTC addresses
            if (!candidate.matches(Regex("^[0-9a-fA-F]{32,64}$"))) {
                add(candidate, IocCategory.CRYPTO_WALLET)
            }
        }

        // 6. Domains (exclude filename extensions like report.pdf or image.png already skipped by TLD list)
        DOMAIN_REGEX.findAll(normalized).forEach { m ->
            val dom = m.value.lowercase()
            if (!IPV4_REGEX.matches(dom)) {
                add(dom, IocCategory.DOMAIN)
            }
        }
        emailDomains.forEach { add(it, IocCategory.DOMAIN) }

        // 7. International Phone Numbers
        PHONE_REGEX.findAll(normalized).forEach { m ->
            val digits = m.value.replace(Regex("[^0-9+]"), "")
            if (digits.length in 9..16) {
                add(m.value.trim(), IocCategory.PHONE)
            }
        }

        val items = results.values.toList()
        val counts = items.groupingBy { it.category }.eachCount()
        return IocExtractionResult(items = items, countsByCategory = counts)
    }

    fun toCsv(items: List<ExtractedIoc>, defanged: Boolean): String {
        val sb = StringBuilder("category,indicator,defanged\n")
        items.forEach { item ->
            val raw = if (defanged) item.defangedValue else item.value
            sb.append(csvEscape(item.category.badge))
                .append(',')
                .append(csvEscape(raw))
                .append(',')
                .append(csvEscape(item.defangedValue))
                .append('\n')
        }
        return sb.toString()
    }

    fun toJson(items: List<ExtractedIoc>, defanged: Boolean): String {
        val sb = StringBuilder("[\n")
        items.forEachIndexed { idx, item ->
            val value = if (defanged) item.defangedValue else item.value
            sb.append("  {\"category\": \"")
                .append(jsonEscape(item.category.badge))
                .append("\", \"indicator\": \"")
                .append(jsonEscape(value))
                .append("\", \"defanged\": \"")
                .append(jsonEscape(item.defangedValue))
                .append("\"}")
            if (idx < items.lastIndex) sb.append(',')
            sb.append('\n')
        }
        sb.append(']')
        return sb.toString()
    }

    private fun csvEscape(value: String): String {
        val neutralized = if (value.isNotEmpty() && value[0] in charArrayOf('=', '+', '-', '@', '\t', '\r')) {
            "'$value"
        } else value
        val escaped = neutralized.replace("\"", "\"\"")
        return "\"$escaped\""
    }

    private fun jsonEscape(value: String): String {
        return value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
    }
}
