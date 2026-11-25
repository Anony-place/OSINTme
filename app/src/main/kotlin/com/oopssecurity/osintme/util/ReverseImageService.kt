package com.oopssecurity.osintme.util

import android.content.Context
import android.content.Intent
import android.net.Uri
import java.net.URLEncoder

object ReverseImageService {

    enum class SearchEngine(val title: String, val badge: String) {
        GOOGLE_LENS("Google Lens", "LENS"),
        YANDEX("Yandex Visual", "YANDEX"),
        TINEYE("TinEye Match", "TINEYE"),
        BING("Bing Visual Search", "BING")
    }

    fun buildSearchUrl(engine: SearchEngine, imageUrl: String): String {
        val encodedUrl = URLEncoder.encode(imageUrl.trim(), "UTF-8")
        return when (engine) {
            SearchEngine.GOOGLE_LENS -> "https://lens.google.com/uploadbyurl?url=$encodedUrl"
            SearchEngine.YANDEX -> "https://yandex.com/images/search?rpt=imageview&url=$encodedUrl"
            SearchEngine.TINEYE -> "https://www.tineye.com/search?url=$encodedUrl"
            SearchEngine.BING -> "https://www.bing.com/images/search?view=detailv2&iss=sbi&FORM=SBIHMP&q=imgurl:$encodedUrl"
        }
    }

    fun buildSearchIntent(engine: SearchEngine, imageUrl: String): Intent {
        return Intent(Intent.ACTION_VIEW, Uri.parse(buildSearchUrl(engine, imageUrl))).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
    }

    fun launchSearch(context: Context, engine: SearchEngine, imageUrl: String) {
        SafeBrowserLauncher.openExternalUrl(context, buildSearchUrl(engine, imageUrl))
    }
}
