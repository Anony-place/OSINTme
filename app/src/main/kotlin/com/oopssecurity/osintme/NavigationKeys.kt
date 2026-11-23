package com.oopssecurity.osintme

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable

@Serializable
data object DashboardNav : NavKey

@Serializable
data object CaseManagementNav : NavKey

@Serializable
data class CaseDetailNav(val caseId: String) : NavKey

@Serializable
data class ThreatIntelNav(val initialTarget: String = "") : NavKey

@Serializable
data object OpsecSettingsNav : NavKey

@Serializable
data class BreachAuditorNav(val initialEmail: String = "") : NavKey

@Serializable
data class UsernameReconNav(val initialUsername: String = "") : NavKey

@Serializable
data class PhoneReconNav(val initialNumber: String = "") : NavKey

@Serializable
data class DomainReconNav(val initialTarget: String = "") : NavKey

@Serializable
data class ExifInspectorNav(val imageUriString: String? = null) : NavKey

@Serializable
data class DorkGeneratorNav(val initialTarget: String = "") : NavKey

@Serializable
data class LinkSanitizerNav(val initialUrl: String = "") : NavKey

@Serializable
data object HygieneChecklistNav : NavKey

@Serializable
data object ScanHistoryNav : NavKey

@Serializable
data object ComplianceDisclaimerNav : NavKey
