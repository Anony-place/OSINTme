package com.oopssecurity.osintme

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation3.runtime.NavKey
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.network.OpsecManager
import com.oopssecurity.osintme.ui.theme.OsintMeTheme
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.util.InputClassifier
import com.oopssecurity.osintme.util.InputType

class MainActivity : ComponentActivity() {

    private var currentNavKey by mutableStateOf<NavKey>(DashboardNav)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(
                android.graphics.Color.TRANSPARENT,
                android.graphics.Color.TRANSPARENT
            ),
            navigationBarStyle = SystemBarStyle.light(
                android.graphics.Color.TRANSPARENT,
                android.graphics.Color.TRANSPARENT
            )
        )
        OpsecManager.init(this)
        ApiKeyVault.init(this)
        applyScreenShield(OpsecManager.screenShieldEnabled)

        extractNavFromIntent(intent)?.let {
            currentNavKey = it
        }

        setContent {
            val shieldOn by OpsecManager.screenShieldEnabledFlow.collectAsStateWithLifecycle()
            LaunchedEffect(shieldOn) {
                applyScreenShield(shieldOn)
            }

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

    private fun applyScreenShield(enabled: Boolean) {
        if (enabled) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    private fun extractNavFromIntent(intent: Intent?): NavKey? {
        if (intent == null) return null
        if (intent.action != Intent.ACTION_SEND) return null

        val type = intent.type ?: return null

        if (type.startsWith("image/")) {
            val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(Intent.EXTRA_STREAM)
            }
            // Strictly accept content:// URIs only — block file:// traversal attempts from external apps
            if (uri != null && uri.scheme.equals("content", ignoreCase = true)) {
                return ExifInspectorNav(uri.toString())
            }
        } else if (type == "text/plain") {
            val rawText = intent.getStringExtra(Intent.EXTRA_TEXT)
                ?.filter { it.code >= 0x20 && it.code != 0x7F }
                ?.trim()
                ?.take(512)
            if (!rawText.isNullOrEmpty()) {
                return when (InputClassifier.classify(rawText)) {
                    InputType.TRACKING_URL -> TargetDossierNav(rawText)
                    InputType.EMAIL -> TargetDossierNav(rawText)
                    InputType.IP_ADDRESS, InputType.DOMAIN -> TargetDossierNav(rawText)
                    InputType.HASH -> HashPayloadNav(rawText)
                    InputType.PHONE_NUMBER -> PhoneReconNav(rawText)
                    InputType.USERNAME -> TargetDossierNav(rawText)
                    InputType.GENERIC_KEYWORD -> TargetDossierNav(rawText)
                }
            }
        }

        return null
    }
}
