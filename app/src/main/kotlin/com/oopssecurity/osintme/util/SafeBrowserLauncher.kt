package com.oopssecurity.osintme.util

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PersistableBundle
import android.widget.Toast

/**
 * Hardened browser & clipboard helper:
 * - Strictly allows only public http:// and https:// schemes when launching external browsers
 * - Blocks unsafe URI schemes (intent://, file://, content://, javascript:, data:, tel:)
 * - Marks sensitive clipboard copies with EXTRA_IS_SENSITIVE on Android 13+
 */
object SafeBrowserLauncher {

    fun validateExternalWebUrl(rawUrl: String): String? {
        val clean = rawUrl.trim()
        if (clean.isBlank() || clean.length > 2048) return null
        if (clean.any { it.code < 0x20 || it.code == 0x7F || it.isWhitespace() }) return null
        val validated = NetworkSecurityGuard.validatePublicHttpUrl(clean, requireHttps = false).getOrNull()
            ?: return null
        return validated
    }

    fun openExternalUrl(context: Context, rawUrl: String): Boolean {
        val safeUrl = validateExternalWebUrl(rawUrl)
        if (safeUrl == null) {
            Toast.makeText(context, "Blocked unsafe or invalid external URL", Toast.LENGTH_SHORT).show()
            return false
        }
        return runCatching {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(safeUrl)).apply {
                addCategory(Intent.CATEGORY_BROWSABLE)
            }
            context.startActivity(intent)
            true
        }.getOrElse {
            Toast.makeText(context, "No browser available to open link", Toast.LENGTH_SHORT).show()
            false
        }
    }

    fun openGeoLocation(
        context: Context,
        latitude: Double,
        longitude: Double,
        label: String = "EXIF Location"
    ): Boolean {
        if (!latitude.isFinite() || !longitude.isFinite() || latitude !in -90.0..90.0 || longitude !in -180.0..180.0) {
            Toast.makeText(context, "Invalid GPS coordinates", Toast.LENGTH_SHORT).show()
            return false
        }
        val safeLabel = Uri.encode(label.take(40))
        val geoUri = Uri.parse("geo:$latitude,$longitude?q=$latitude,$longitude($safeLabel)")
        return runCatching {
            context.startActivity(Intent(Intent.ACTION_VIEW, geoUri))
            true
        }.getOrElse {
            Toast.makeText(context, "No maps app available", Toast.LENGTH_SHORT).show()
            false
        }
    }

    fun copyToClipboard(
        context: Context,
        label: String,
        text: String,
        isSensitive: Boolean = false,
        toastMessage: String? = null
    ) {
        val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        if (isSensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        cb.setPrimaryClip(clip)
        if (!toastMessage.isNullOrBlank()) {
            Toast.makeText(context, toastMessage, Toast.LENGTH_SHORT).show()
        }
    }
}
