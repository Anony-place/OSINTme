package com.oopssecurity.osintme.data.model

import kotlinx.serialization.Serializable

@Serializable
data class BgpAsnInfo(
    val ip: String,
    val asn: String,
    val holder: String,
    val prefix: String,
    val announcedPrefixes: List<String> = emptyList(),
    val totalAnnouncedCount: Int = 0
)

@Serializable
data class WebTechSignature(
    val name: String,
    val category: String,
    val evidence: String = ""
)

@Serializable
data class WebTechReconResult(
    val targetHost: String,
    val finalUrl: String,
    val httpStatus: Int,
    val pageTitle: String = "",
    val metaGenerator: String = "",
    val serverHeader: String = "",
    val poweredBy: String = "",
    val technologies: List<WebTechSignature> = emptyList(),
    val robotsFound: Boolean = false,
    val robotsDisallowed: List<String> = emptyList(),
    val robotsSitemaps: List<String> = emptyList(),
    val securityTxtFound: Boolean = false,
    val securityContacts: List<String> = emptyList(),
    val externalDomains: List<String> = emptyList()
)

@Serializable
data class VirusTotalReport(
    val target: String,
    val targetType: String, // domain, ip, url, file
    val maliciousCount: Int = 0,
    val suspiciousCount: Int = 0,
    val harmlessCount: Int = 0,
    val undetectedCount: Int = 0,
    val reputation: Int = 0,
    val categories: List<String> = emptyList(),
    val popularThreatName: String = "",
    val lastAnalysisDate: Long = 0L
) {
    val totalEngines: Int get() = maliciousCount + suspiciousCount + harmlessCount + undetectedCount
}

@Serializable
data class AbuseIpdbReport(
    val ipAddress: String,
    val abuseConfidenceScore: Int = 0,
    val totalReports: Int = 0,
    val numDistinctUsers: Int = 0,
    val isp: String = "",
    val domain: String = "",
    val usageType: String = "",
    val countryCode: String = "",
    val isTor: Boolean = false,
    val isWhitelisted: Boolean = false,
    val lastReportedAt: String = ""
)

@Serializable
data class UrlScanHit(
    val scanId: String,
    val pageUrl: String,
    val pageDomain: String,
    val ip: String,
    val asnName: String,
    val country: String,
    val server: String,
    val timestamp: String,
    val resultUrl: String
)

@Serializable
data class UrlScanSummary(
    val query: String,
    val totalHits: Int = 0,
    val recentScans: List<UrlScanHit> = emptyList(),
    val submittedScanUrl: String = ""
)

@Serializable
data class MalwareBazaarReport(
    val hash: String,
    val found: Boolean,
    val fileName: String = "",
    val fileType: String = "",
    val fileSizeBytes: Long = 0L,
    val signature: String = "",
    val sha256: String = "",
    val md5: String = "",
    val sha1: String = "",
    val firstSeen: String = "",
    val tags: List<String> = emptyList(),
    val reporter: String = "",
    val note: String = ""
)

data class ApiKeyTestResult(
    val success: Boolean,
    val statusMessage: String
)
