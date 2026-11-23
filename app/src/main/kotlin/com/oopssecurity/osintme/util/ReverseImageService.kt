package com.oopssecurity.osintme.util

import android.content.Context
import android.content.Intent
import android.net.Uri

object ReverseImageService {

    enum class SearchEngine(val title: String, val badge: String) {
        GOOGLE_LENS("Google Lens", "LENS"),
        YANDEX("Yandex Visual", "YANDEX"),
        TINEYE("TinEye Match", "TINEYE"),
        BING("Bing Visual Search", "BING")
    }

    fun buildSearchIntent(engine: SearchEngine, imageUrl: String): Intent {
        val encodedUrl = Uri.encode(imageUrl.trim())
        val targetUrl = when (engine) {
            SearchEngine.GOOGLE_LENS -> "https://lens.google.com/uploadbyurl?url=$encodedUrl"
            SearchEngine.YANDEX -> "https://yandex.com/images/search?rpt=imageview&url=$encodedUrl"
            SearchEngine.TINEYE -> "https://www.tineye.com/search?url=$encodedUrl"
            SearchEngine.BING -> "https://www.bing.com/images/search?view=detailv2&iss=sbi&FORM=SBIHMP&q=imgurl:$encodedUrl"
        }
        return Intent(Intent.ACTION_VIEW, Uri.parse(targetUrl))
    }

    fun launchSearch(context: Context, engine: SearchEngine, imageUrl: String) {
        try {
            val intent = buildSearchIntent(engine, imageUrl)
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
        } catch (e: Exception) {
            // fallback handled
        }
    }
}
