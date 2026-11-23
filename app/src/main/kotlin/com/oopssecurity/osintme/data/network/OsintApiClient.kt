package com.oopssecurity.osintme.data.network

import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

object OsintApiClient {
    val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(12, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .followRedirects(true)
            .retryOnConnectionFailure(true)
            .addInterceptor { chain ->
                val request = chain.request().newBuilder()
                    .header("User-Agent", "Mozilla/5.0 (Android; OSINTme Privacy Toolkit/1.0; Oops Security)")
                    .build()
                chain.proceed(request)
            }
            .build()
    }
}
