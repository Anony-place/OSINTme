package com.oopssecurity.osintme.data.model

import kotlinx.serialization.Serializable

@Serializable
data class BreachedSite(
    val siteName: String,
    val domain: String = "",
    val breachDate: String = "",
    val exposedData: List<String> = emptyList(),
    val description: String = "",
    val industry: String = "",
    val pwnCount: Long = 0
)

@Serializable
data class EmailBreachResult(
    val email: String,
    val isBreached: Boolean,
    val breaches: List<BreachedSite> = emptyList(),
    val totalBreaches: Int = 0,
    val exposedDataTypes: List<String> = emptyList(),
    val riskLabel: String = "",
    val scanTimestamp: Long = System.currentTimeMillis()
)

data class PasswordLeakResult(
    val isLeaked: Boolean,
    val leakCount: Long,
    val sha1Prefix: String,
    val securityAdvice: String
)

enum class ReconStatus {
    IDLE,
    CHECKING,
    FOUND,
    AVAILABLE,
    RATE_LIMITED,
    ERROR
}

data class UsernameCheckResult(
    val platformName: String,
    val profileUrl: String,
    val category: String,
    val status: ReconStatus = ReconStatus.IDLE,
    val httpCode: Int = 0,
    val responseTimeMs: Long = 0,
    val metadata: String = ""
)

@Serializable
data class IpReconResult(
    val ip: String,
    val hostnames: List<String> = emptyList(),
    val ports: List<Int> = emptyList(),
    val cpes: List<String> = emptyList(),
    val tags: List<String> = emptyList(),
    val vulns: List<String> = emptyList(),
    val org: String = "",
    val country: String = "",
    val city: String = "",
    val isp: String = "",
    val asn: String = "",
    val latitude: Double = 0.0,
    val longitude: Double = 0.0,
    val scanTimestamp: Long = System.currentTimeMillis()
)

@Serializable
data class SubdomainResult(
    val rootDomain: String,
    val subdomains: List<String> = emptyList(),
    val totalCount: Int = 0,
    val sources: List<String> = emptyList(),
    val scanTimestamp: Long = System.currentTimeMillis()
)

@Serializable
data class DnsRecordItem(
    val type: String,
    val name: String,
    val data: String,
    val ttl: Int = 300
)

@Serializable
data class SecurityHeaderItem(
    val name: String,
    val present: Boolean,
    val value: String = "",
    val severity: String = "INFO" // "GOOD", "WARN", "MISSING", "INFO"
)

@Serializable
data class TlsHeaderAuditResult(
    val targetUrl: String,
    val finalUrl: String,
    val httpStatus: Int,
    val responseTimeMs: Long,
    val serverHeader: String = "",
    val tlsProtocol: String = "",
    val cipherSuite: String = "",
    val certSubject: String = "",
    val certIssuer: String = "",
    val certValidFrom: String = "",
    val certValidUntil: String = "",
    val certSanCount: Int = 0,
    val certSans: List<String> = emptyList(),
    val securityGrade: String = "C",
    val passedHeadersCount: Int = 0,
    val totalCheckedHeaders: Int = 6,
    val headers: List<SecurityHeaderItem> = emptyList()
)

@Serializable
data class RdapDomainInfo(
    val domain: String,
    val registrar: String = "Unknown",
    val registrationDate: String = "",
    val expirationDate: String = "",
    val lastUpdated: String = "",
    val status: List<String> = emptyList(),
    val nameServers: List<String> = emptyList()
)

@Serializable
data class PhoneReconResult(
    val rawInput: String,
    val e164Format: String,
    val nationalFormat: String,
    val countryName: String,
    val countryCode: String,
    val dialCode: String = "",
    val lineType: String,
    val numberingPlanNote: String,
    val timezone: String,
    val whatsappUrl: String,
    val telegramUrl: String,
    val isValidLength: Boolean = true,
    val scanTimestamp: Long = System.currentTimeMillis()
)

@Serializable
data class WaybackUrlItem(
    val url: String,
    val statusCode: String,
    val timestamp: String,
    val archiveUrl: String
)

@Serializable
data class EmailSecurityAudit(
    val domain: String,
    val hasMx: Boolean = false,
    val mxHosts: List<String> = emptyList(),
    val hasSpf: Boolean,
    val spfRecord: String,
    val spfPolicy: String,
    val hasDmarc: Boolean,
    val dmarcRecord: String,
    val dmarcPolicy: String,
    val isSpoofable: Boolean,
    val riskSummary: String
) {
    val grade: String
        get() = when {
            hasSpf && hasDmarc && (dmarcPolicy.equals("reject", true) || dmarcPolicy.equals("quarantine", true)) -> "A"
            hasSpf && hasDmarc -> "B"
            hasSpf || hasDmarc -> "C"
            else -> "F"
        }
}

data class ExifMetadata(
    val make: String? = null,
    val model: String? = null,
    val lensModel: String? = null,
    val software: String? = null,
    val dateTime: String? = null,
    val imageWidth: Int = 0,
    val imageHeight: Int = 0,
    val iso: String? = null,
    val exposureTime: String? = null,
    val fNumber: String? = null,
    val focalLength: String? = null,
    val latitude: Double? = null,
    val longitude: Double? = null,
    val altitude: Double? = null,
    val hasGps: Boolean = false,
    val originalUri: String = "",
    val fileSizeFormatted: String = "",
    val sha256Hash: String = ""
)

data class DorkPreset(
    val id: String,
    val category: String,
    val label: String,
    val queryTemplate: String,
    val explanation: String
)

data class HygieneCheckItem(
    val id: String,
    val title: String,
    val description: String,
    val weight: Int,
    val isChecked: Boolean = false
)

@Serializable
data class ScanHistoryItem(
    val id: String,
    val type: String,
    val target: String,
    val summary: String,
    val timestamp: Long = System.currentTimeMillis()
)

@Serializable
data class GravatarAccount(
    val domain: String = "",
    val display: String = "",
    val url: String = "",
    val username: String = "",
    val verified: Boolean = false
)

@Serializable
data class GravatarProfile(
    val emailHash: String,
    val preferredUsername: String = "",
    val displayName: String = "",
    val aboutMe: String = "",
    val currentLocation: String = "",
    val thumbnailUrl: String = "",
    val profileUrl: String = "",
    val accounts: List<GravatarAccount> = emptyList(),
    val personalUrls: List<String> = emptyList()
)

@Serializable
data class UrlhausPayload(
    val url: String,
    val urlStatus: String = "online",
    val threat: String = "malware_download",
    val tags: List<String> = emptyList(),
    val dateAdded: String = ""
)

@Serializable
data class UrlhausResult(
    val target: String,
    val queryStatus: String,
    val isMalicious: Boolean,
    val firstSeen: String = "",
    val urlCount: Int = 0,
    val spamhausListed: Boolean = false,
    val surblListed: Boolean = false,
    val payloads: List<UrlhausPayload> = emptyList(),
    val cloudflareMalwareBlocked: Boolean = false,
    val cloudflareStandardIps: List<String> = emptyList(),
    val urlhausNote: String = "",
    val scanTimestamp: Long = System.currentTimeMillis()
)

data class RedirectHop(
    val hopIndex: Int = 1,
    val url: String,
    val statusCode: Int,
    val locationHeader: String? = null,
    val latencyMs: Long = 0L
)

data class RedirectChainResult(
    val originalUrl: String,
    val finalUrl: String,
    val hops: List<RedirectHop>,
    val error: String? = null
)

data class OpsecRouteCheckResult(
    val publicIp: String,
    val country: String,
    val city: String,
    val isp: String,
    val asn: String,
    val latencyMs: Long,
    val proxyUsed: String
)

@Serializable
data class InvestigationCase(
    val id: String,
    val title: String,
    val target: String,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    val notes: String = "",
    val tags: List<String> = emptyList(),
    val status: String = "ACTIVE"
)

@Serializable
data class ScanArtifact(
    val id: String,
    val caseId: String,
    val wingType: String,
    val artifactType: String,
    val queryTarget: String,
    val title: String,
    val summary: String,
    val rawJson: String,
    val confidence: String = "HIGH",
    val sourceApi: String = "",
    val timestamp: Long = System.currentTimeMillis()
)
