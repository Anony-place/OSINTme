package com.oopssecurity.osintme.util

import java.net.URI

enum class PivotEntityType(val badgeLabel: String) {
    DOMAIN("DOMAIN"),
    IP_ADDRESS("IP ADDRESS"),
    EMAIL("EMAIL"),
    USERNAME("HANDLE"),
    URL("URL"),
    PHONE("PHONE"),
    HASH("FILE HASH")
}

data class PivotEntity(
    val rawValue: String,
    val normalizedValue: String,
    val type: PivotEntityType,
    val sourceContext: String = ""
)

enum class PivotTargetModule {
    TARGET_DOSSIER,
    DOMAIN_RECON,
    WAYBACK_ARCHIVE,
    TLS_TAKEOVER,
    REDIRECT_AUDIT,
    THREAT_INTEL,
    BREACH_AUDIT,
    USERNAME_RECON,
    LINK_SANITIZER,
    DORK_GENERATOR,
    PHONE_RECON,
    HASH_PAYLOAD,
    AI_ANALYST
}

data class PivotAction(
    val module: PivotTargetModule,
    val label: String,
    val subtitle: String,
    val targetValue: String
)

object PivotEngine {

    private val IPV4_REGEX = Regex("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$")
    private val IPV6_REGEX = Regex("^[0-9a-fA-F:]+$")
    private val EMAIL_REGEX = Regex("^[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}$")
    private val DOMAIN_REGEX = Regex("^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$")
    private val HASH_REGEX = Regex("^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
    private val MX_PRIORITY_REGEX = Regex("^\\d+\\s+(.+)$")

    fun normalize(
        raw: String,
        hintType: PivotEntityType? = null,
        sourceContext: String = ""
    ): PivotEntity {
        val trimmed = raw.trim().trim('"', '\'')

        val cleanedForType = when (hintType) {
            PivotEntityType.URL -> trimmed
            PivotEntityType.EMAIL -> trimmed.lowercase()
            PivotEntityType.USERNAME -> trimmed.removePrefix("@").trim()
            PivotEntityType.PHONE -> trimmed
            PivotEntityType.IP_ADDRESS -> trimmed
            PivotEntityType.HASH -> trimmed.lowercase()
            PivotEntityType.DOMAIN -> cleanDomainCandidate(trimmed)
            null -> trimmed
        }

        val resolvedType = hintType ?: detectType(cleanedForType)
        val finalNormalized = when (resolvedType) {
            PivotEntityType.DOMAIN -> cleanDomainCandidate(cleanedForType)
            PivotEntityType.USERNAME -> cleanedForType.removePrefix("@").trim()
            PivotEntityType.EMAIL -> cleanedForType.lowercase()
            PivotEntityType.HASH -> cleanedForType.lowercase()
            else -> cleanedForType
        }

        return PivotEntity(
            rawValue = raw,
            normalizedValue = finalNormalized,
            type = resolvedType,
            sourceContext = sourceContext
        )
    }

    fun cleanDomainCandidate(input: String): String {
        var value = input.trim().trim('"', '\'')
        val mxMatch = MX_PRIORITY_REGEX.matchEntire(value)
        if (mxMatch != null) {
            value = mxMatch.groupValues[1].trim()
        }
        if (value.startsWith("http://", ignoreCase = true) || value.startsWith("https://", ignoreCase = true)) {
            extractHost(value)?.let { value = it }
        }
        return value
            .removePrefix("*.")
            .removeSuffix(".")
            .substringBefore("/")
            .substringBefore(":")
            .lowercase()
            .trim()
    }

    fun detectType(input: String): PivotEntityType {
        val trimmed = input.trim()
        if (trimmed.startsWith("http://", ignoreCase = true) ||
            trimmed.startsWith("https://", ignoreCase = true)
        ) {
            return PivotEntityType.URL
        }
        if (EMAIL_REGEX.matches(trimmed)) {
            return PivotEntityType.EMAIL
        }
        if (HASH_REGEX.matches(trimmed)) {
            return PivotEntityType.HASH
        }
        if (IPV4_REGEX.matches(trimmed) || (trimmed.contains(":") && trimmed.count { it == ':' } >= 2 && IPV6_REGEX.matches(trimmed))) {
            return PivotEntityType.IP_ADDRESS
        }
        val digitsOnly = trimmed.replace(Regex("[\\s()\\-.]"), "")
        if (digitsOnly.startsWith("+") && digitsOnly.length in 8..16 && digitsOnly.drop(1).all { it.isDigit() }) {
            return PivotEntityType.PHONE
        }
        val domainCandidate = cleanDomainCandidate(trimmed)
        if (DOMAIN_REGEX.matches(domainCandidate)) {
            return PivotEntityType.DOMAIN
        }
        return PivotEntityType.USERNAME
    }

    fun extractHost(url: String): String? {
        return try {
            val normalized = if (url.startsWith("http://", ignoreCase = true) ||
                url.startsWith("https://", ignoreCase = true)
            ) {
                url
            } else {
                "https://$url"
            }
            URI(normalized).host?.lowercase()?.removeSuffix(".")?.takeIf { it.isNotBlank() }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Defangs indicators for safe sharing in OSINT reports and analyst notes
     * (e.g. https://evil.com -> hxxps://evil[.]com, user@evil.com -> user[@]evil[.]com).
     */
    fun defang(value: String): String {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return ""
        var out = trimmed
            .replace(Regex("(?i)^https://"), "hxxps://")
            .replace(Regex("(?i)^http://"), "hxxp://")
        if (!out.contains("[@]")) {
            out = out.replace("@", "[@]")
        }
        out = out.replace(Regex("(?<!\\[)\\.(?!\\])"), "[.]")
        return out
    }

    fun buildActions(entity: PivotEntity): List<PivotAction> {
        val target = entity.normalizedValue
        if (target.isBlank()) return emptyList()

        val dossierAction = PivotAction(
            module = PivotTargetModule.TARGET_DOSSIER,
            label = "One-Shot Full Target Dossier",
            subtitle = "Run all parallel passive & BYOK feeds into one report",
            targetValue = target
        )

        return when (entity.type) {
            PivotEntityType.DOMAIN -> listOf(
                dossierAction,
                PivotAction(
                    module = PivotTargetModule.DOMAIN_RECON,
                    label = "Network, Web Stack & BGP",
                    subtitle = "Shodan, DNS, Web Tech, RIPEstat BGP, CT logs & RDAP",
                    targetValue = target
                ),
                PivotAction(
                    module = PivotTargetModule.TLS_TAKEOVER,
                    label = "Live TLS Cert & CNAME Takeover",
                    subtitle = "Inspect live SSL certificate SANs & scan dangling subdomains",
                    targetValue = target
                ),
                PivotAction(
                    module = PivotTargetModule.WAYBACK_ARCHIVE,
                    label = "Wayback Historical Archive",
                    subtitle = "Explore deleted pages, leaked configs & snapshot history",
                    targetValue = target
                ),
                PivotAction(
                    module = PivotTargetModule.REDIRECT_AUDIT,
                    label = "Redirect Chain & HTTP Security",
                    subtitle = "Trace redirects & grade HSTS, CSP, CORS & Cookies",
                    targetValue = "https://$target"
                ),
                PivotAction(
                    module = PivotTargetModule.THREAT_INTEL,
                    label = "Malware & DNS Reputation Check",
                    subtitle = "Cloudflare 1.1.1.2 Security DNS & abuse.ch URLhaus",
                    targetValue = target
                ),
                PivotAction(
                    module = PivotTargetModule.DORK_GENERATOR,
                    label = "Precision Dorks & Shodan Matrix",
                    subtitle = "Google, Shodan, Censys, GitHub & AI custom dorks",
                    targetValue = target
                ),
                PivotAction(
                    module = PivotTargetModule.AI_ANALYST,
                    label = "Ask BYOK AI Analyst",
                    subtitle = "Investigate '$target' with your connected LLM",
                    targetValue = "Build a passive OSINT investigation plan and threat checklist for domain: $target"
                )
            )

            PivotEntityType.IP_ADDRESS -> listOf(
                dossierAction,
                PivotAction(
                    module = PivotTargetModule.DOMAIN_RECON,
                    label = "IP, Open Ports, BGP & GeoIP Recon",
                    subtitle = "Shodan ports/CVEs, RIPEstat BGP prefixes & reverse hostnames",
                    targetValue = target
                ),
                PivotAction(
                    module = PivotTargetModule.THREAT_INTEL,
                    label = "Threat & Abuse Reputation",
                    subtitle = "Check IP against URLhaus & abuse blocklists",
                    targetValue = target
                ),
                PivotAction(
                    module = PivotTargetModule.DORK_GENERATOR,
                    label = "Generate OSINT Search Dorks",
                    subtitle = "Search indexed mentions and configs referencing this IP",
                    targetValue = target
                )
            )

            PivotEntityType.EMAIL -> buildList {
                add(dossierAction)
                add(
                    PivotAction(
                        module = PivotTargetModule.BREACH_AUDIT,
                        label = "Breach, Gravatar & Email Audit",
                        subtitle = "XposedOrNot leaks, Gravatar identity & SPF/DMARC",
                        targetValue = target
                    )
                )
                val localPart = target.substringBefore("@").trim()
                val emailDomain = target.substringAfter("@", "").trim()
                if (localPart.length >= 2) {
                    add(
                        PivotAction(
                            module = PivotTargetModule.USERNAME_RECON,
                            label = "Hunt Handle '@$localPart'",
                            subtitle = "Probe 106+ live platforms for the email username prefix",
                            targetValue = localPart
                        )
                    )
                }
                if (emailDomain.contains(".")) {
                    add(
                        PivotAction(
                            module = PivotTargetModule.DOMAIN_RECON,
                            label = "Inspect Domain '$emailDomain'",
                            subtitle = "Audit mail infrastructure, TLS, DNS & subdomains",
                            targetValue = emailDomain
                        )
                    )
                }
                add(
                    PivotAction(
                        module = PivotTargetModule.DORK_GENERATOR,
                        label = "Generate OSINT Search Dorks",
                        subtitle = "Cross-reference email across public indexed documents",
                        targetValue = target
                    )
                )
            }

            PivotEntityType.USERNAME -> listOf(
                dossierAction,
                PivotAction(
                    module = PivotTargetModule.USERNAME_RECON,
                    label = "106+ Platform Handle Recon",
                    subtitle = "Concurrent live presence check across social, dev & security APIs",
                    targetValue = target
                ),
                PivotAction(
                    module = PivotTargetModule.DORK_GENERATOR,
                    label = "Generate OSINT Search Dorks",
                    subtitle = "Find public posts, code & mentions of '@$target'",
                    targetValue = target
                )
            )

            PivotEntityType.URL -> buildList {
                add(dossierAction)
                add(
                    PivotAction(
                        module = PivotTargetModule.REDIRECT_AUDIT,
                        label = "Safe Redirect Tracer & Header Audit",
                        subtitle = "Unmask shortlink hops & grade HSTS/CSP/Cookie security",
                        targetValue = target
                    )
                )
                add(
                    PivotAction(
                        module = PivotTargetModule.LINK_SANITIZER,
                        label = "Strip Tracking Parameters",
                        subtitle = "Remove UTM, fbclid, gclid & click IDs cleanly",
                        targetValue = target
                    )
                )
                val host = extractHost(target)
                if (!host.isNullOrBlank()) {
                    add(
                        PivotAction(
                            module = PivotTargetModule.WAYBACK_ARCHIVE,
                            label = "Wayback Archive for '$host'",
                            subtitle = "View historical snapshots & deleted URLs",
                            targetValue = host
                        )
                    )
                    add(
                        PivotAction(
                            module = PivotTargetModule.DOMAIN_RECON,
                            label = "Inspect Host '$host'",
                            subtitle = "Shodan ports, Web Stack, BGP & DNS records",
                            targetValue = host
                        )
                    )
                    add(
                        PivotAction(
                            module = PivotTargetModule.THREAT_INTEL,
                            label = "Check Host '$host' Threat Feeds",
                            subtitle = "Cloudflare 1.1.1.2 malware DNS & URLhaus lookup",
                            targetValue = host
                        )
                    )
                }
                add(
                    PivotAction(
                        module = PivotTargetModule.DORK_GENERATOR,
                        label = "Precision Dorks & Shodan Matrix",
                        subtitle = "Search indexed references to ${host ?: "this URL"}",
                        targetValue = host ?: target
                    )
                )
            }

            PivotEntityType.PHONE -> listOf(
                dossierAction,
                PivotAction(
                    module = PivotTargetModule.PHONE_RECON,
                    label = "Phone E.164 & Numbering Plan",
                    subtitle = "Country prefix, line classification & messaging links",
                    targetValue = target
                ),
                PivotAction(
                    module = PivotTargetModule.DORK_GENERATOR,
                    label = "Generate OSINT Search Dorks",
                    subtitle = "Search public records & listings for this phone number",
                    targetValue = target
                )
            )

            PivotEntityType.HASH -> listOf(
                dossierAction,
                PivotAction(
                    module = PivotTargetModule.HASH_PAYLOAD,
                    label = "Hash Reputation & Malware Lookup",
                    subtitle = "MalwareBazaar & BYOK VirusTotal v3 detection report",
                    targetValue = target
                ),
                PivotAction(
                    module = PivotTargetModule.DORK_GENERATOR,
                    label = "Search Indexed Hash Mentions",
                    subtitle = "Look up public threat blogs & paste dumps for this hash",
                    targetValue = target
                )
            )
        }
    }
}
