package com.oopssecurity.osintme

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.navigation3.runtime.NavKey
import com.oopssecurity.osintme.ui.theme.OsintMeTheme
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.util.InputClassifier
import com.oopssecurity.osintme.util.InputType

class MainActivity : ComponentActivity() {

    private var currentNavKey by mutableStateOf<NavKey>(DashboardNav)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        extractNavFromIntent(intent)?.let {
            currentNavKey = it
        }

        setContent {
            OsintMeTheme {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(SlateObsidian)
                ) {
                    MainNavigation(initialKey = currentNavKey)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        extractNavFromIntent(intent)?.let {
            currentNavKey = it
        }
    }

    private fun extractNavFromIntent(intent: Intent?): NavKey? {
        if (intent == null) return null

        intent.getStringExtra("navigate_to")?.let { target ->
            val targetArg = intent.getStringExtra("target_arg") ?: ""
            return when (target.lowercase()) {
                "cases", "case_management" -> CaseManagementNav
                "case_detail" -> CaseDetailNav(targetArg)
                "threat_intel", "urlhaus" -> ThreatIntelNav(targetArg)
                "opsec" -> OpsecSettingsNav
                "breach" -> BreachAuditorNav(targetArg)
                "username" -> UsernameReconNav(targetArg)
                "phone" -> PhoneReconNav(targetArg)
                "domain" -> DomainReconNav(targetArg)
                "dorks" -> DorkGeneratorNav(targetArg)
                "sanitizer" -> LinkSanitizerNav(targetArg)
                "hygiene" -> HygieneChecklistNav
                "history" -> ScanHistoryNav
                "compliance" -> ComplianceDisclaimerNav
                else -> null
            }
        }

        if (intent.action != Intent.ACTION_SEND) return null

        val type = intent.type ?: return null

        if (type.startsWith("image/")) {
            val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(Intent.EXTRA_STREAM)
            }
            if (uri != null) {
                return ExifInspectorNav(uri.toString())
            }
        } else if (type == "text/plain") {
            val text = intent.getStringExtra(Intent.EXTRA_TEXT)?.trim()
            if (!text.isNullOrEmpty()) {
                return when (InputClassifier.classify(text)) {
                    InputType.TRACKING_URL -> LinkSanitizerNav(text)
                    InputType.EMAIL -> BreachAuditorNav(text)
                    InputType.IP_ADDRESS, InputType.DOMAIN -> DomainReconNav(text)
                    InputType.PHONE_NUMBER -> PhoneReconNav(text)
                    InputType.USERNAME -> UsernameReconNav(text)
                    InputType.GENERIC_KEYWORD -> DorkGeneratorNav(text)
                }
            }
        }

        return null
    }
}
