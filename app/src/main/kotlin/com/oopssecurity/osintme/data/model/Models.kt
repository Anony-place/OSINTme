package com.oopssecurity.osintme.data.model

import kotlinx.serialization.Serializable

@Serializable
data class BreachedSite(
    val siteName: String,
    val domain: String = "",
    val breachDate: String = "",
    val exposedData: List<String> = emptyList(),
    val description: String = "",
    val pwnCount: Long = 0
)

@Serializable
data class EmailBreachResult(
    val email: String,
    val isBreached: Boolean,
    val breaches: List<BreachedSite> = emptyList(),
    val totalBreaches: Int = 0,
    val exposedDataTypes: List<String> = emptyList(),
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
    ERROR
}

data class UsernameCheckResult(
    val platformName: String,
    val profileUrl: String,
    val category: String,
    val status: ReconStatus = ReconStatus.IDLE,
    val httpCode: Int = 0,
    val responseTimeMs: Long = 0
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
    val lineType: String, // "Mobile / Cellular", "VoIP / Virtual", "Landline / Fixed"
    val carrierEstimate: String,
    val timezone: String,
    val whatsappUrl: String,
    val telegramUrl: String,
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
    val hasSpf: Boolean,
    val spfRecord: String,
    val spfPolicy: String, // "-all" (Strict), "~all" (SoftFail), "?all" (Neutral), "+all" (Vulnerable)
    val hasDmarc: Boolean,
    val dmarcRecord: String,
    val dmarcPolicy: String, // "reject", "quarantine", "none"
    val isSpoofable: Boolean,
    val riskSummary: String
)

data class ExifMetadata(
    val make: String? = null,
    val model: String? = null,
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
    val fileSizeFormatted: String = ""
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
data class AffiliateOffer(
    val id: String,
    val trigger_type: String, // "BREACH", "IP_EXPOSURE", "EXIF", "GENERAL"
    val title: String,
    val description: String,
    val cta_text: String,
    val affiliate_url: String,
    val badge_text: String = "Sponsored Partner",
    val is_active: Boolean = true
)
