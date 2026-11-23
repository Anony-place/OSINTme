package com.oopssecurity.osintme.data.local

import android.content.Context
import android.content.SharedPreferences
import com.oopssecurity.osintme.data.model.HygieneCheckItem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class ExposureScoreState(
    val score: Int,                  // 0 to 100
    val ratingLabel: String,         // e.g. "MINIMAL EXPOSURE", "MODERATE RISK", "HIGH EXPOSURE"
    val completedChecksCount: Int,
    val totalChecksCount: Int,
    val knownBreachesDeduction: Int,
    val checklist: List<HygieneCheckItem>
)

class HygienePreferencesManager(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("osintme_hygiene_prefs", Context.MODE_PRIVATE)

    private val defaultItems = listOf(
        HygieneCheckItem("2fa", "Two-Factor Authentication (2FA)", "FIDO2 / TOTP authenticator app enabled on primary email and banking accounts.", 20),
        HygieneCheckItem("pwd_manager", "Dedicated Password Manager", "Bitwarden, 1Password, or Proton Pass with zero reused passwords.", 15),
        HygieneCheckItem("email_aliases", "Email Masking / Alias Service", "SimpleLogin, DuckDuckGo, or Firefox Relay used for external signups.", 15),
        HygieneCheckItem("private_dns", "Encrypted DNS / DoH Enabled", "DNS-over-HTTPS or NextDNS / Quad9 configured on mobile and home router.", 15),
        HygieneCheckItem("exif_cleanup", "EXIF Metadata Stripping", "Location and device metadata stripped before posting media online.", 15),
        HygieneCheckItem("social_privacy", "Social Media Privacy Audit", "Profiles set to private; phone number and email hidden from public lookups.", 10),
        HygieneCheckItem("vpn_public_wifi", "VPN on Untrusted Networks", "Secure VPN active when connecting to public coffee shop, airport, or hotel Wi-Fi.", 10)
    )

    companion object {
        private var _sharedScoreFlow: MutableStateFlow<ExposureScoreState>? = null
    }

    val scoreFlow: StateFlow<ExposureScoreState>
        get() {
            val flow = _sharedScoreFlow
            if (flow != null) return flow.asStateFlow()
            val newFlow = MutableStateFlow(calculateScore())
            _sharedScoreFlow = newFlow
            return newFlow.asStateFlow()
        }

    fun getChecklist(): List<HygieneCheckItem> {
        return defaultItems.map { item ->
            val checked = prefs.getBoolean("check_${item.id}", false)
            item.copy(isChecked = checked)
        }
    }

    fun toggleCheckItem(id: String) {
        val current = prefs.getBoolean("check_$id", false)
        prefs.edit().putBoolean("check_$id", !current).apply()
        _sharedScoreFlow?.value = calculateScore()
    }

    fun recordBreachDeduction(breachCount: Int) {
        val current = prefs.getInt("breach_deductions", 0)
        val newDeduction = (current + breachCount * 5).coerceAtMost(30)
        prefs.edit().putInt("breach_deductions", newDeduction).apply()
        _sharedScoreFlow?.value = calculateScore()
    }

    fun calculateScore(): ExposureScoreState {
        val list = getChecklist()
        val earnedPoints = list.filter { it.isChecked }.sumOf { it.weight }
        val deductions = prefs.getInt("breach_deductions", 0)

        // Raw score 0..100
        val finalScore = (earnedPoints - deductions).coerceIn(0, 100)

        val rating = when {
            finalScore >= 80 -> "EXCELLENT PRIVACY"
            finalScore >= 50 -> "MODERATE EXPOSURE"
            else -> "HIGH DIGITAL EXPOSURE"
        }

        return ExposureScoreState(
            score = finalScore,
            ratingLabel = rating,
            completedChecksCount = list.count { it.isChecked },
            totalChecksCount = list.size,
            knownBreachesDeduction = deductions,
            checklist = list
        )
    }
}
