package com.oopssecurity.osintme.data.network

import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

object OsintApiClient {

    @Volatile
    private var internalClient: OkHttpClient = buildClient()

    val client: OkHttpClient
        get() = internalClient

    fun rebuildClient() {
        internalClient = buildClient()
    }

    private fun buildClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(12, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .followRedirects(true)
            .retryOnConnectionFailure(true)
            .addInterceptor { chain ->
                val originalRequest = chain.request()
                val reqBuilder = originalRequest.newBuilder()

                if (OpsecManager.antiTrackingHeaders) {
                    reqBuilder.header("DNT", "1")
                    reqBuilder.header("Sec-GPC", "1")
                }

                if (originalRequest.header("User-Agent") == null) {
                    val ua = if (OpsecManager.randomizeUserAgent) {
                        OpsecManager.getRandomUserAgent()
                    } else {
                        "Mozilla/5.0 (Android; OSINTme Privacy Toolkit/1.0; Oops Security)"
                    }
                    reqBuilder.header("User-Agent", ua)
                }

                chain.proceed(reqBuilder.build())
            }

        val proxy = OpsecManager.getActiveProxy()
        if (proxy != null) {
            builder.proxy(proxy)
        }

        return builder.build()
    }
}
