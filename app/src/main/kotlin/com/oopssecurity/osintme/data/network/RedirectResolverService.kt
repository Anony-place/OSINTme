package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.RedirectChainResult
import com.oopssecurity.osintme.data.model.RedirectHop
import com.oopssecurity.osintme.util.NetworkSecurityGuard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Request
import java.util.concurrent.TimeUnit

object RedirectResolverService {

    private const val MAX_HOPS = 10

    suspend fun traceRedirects(rawUrl: String): Result<RedirectChainResult> = withContext(Dispatchers.IO) {
        try {
            val trimmed = rawUrl.trim()
            val normalizedUrl = if (trimmed.startsWith("http://", ignoreCase = true) ||
                trimmed.startsWith("https://", ignoreCase = true)
            ) {
                trimmed
            } else {
                "https://$trimmed"
            }

            NetworkSecurityGuard.validatePublicHttpUrl(normalizedUrl, requireHttps = false).getOrElse { err ->
                return@withContext Result.failure(err)
            }

            if (normalizedUrl.toHttpUrlOrNull() == null) {
                return@withContext Result.failure(IllegalArgumentException("Enter a valid HTTP or HTTPS URL."))
            }

            val noRedirectClient = OsintApiClient.client.newBuilder()
                .followRedirects(false)
                .followSslRedirects(false)
                .connectTimeout(8, TimeUnit.SECONDS)
                .readTimeout(8, TimeUnit.SECONDS)
                .build()

            val hops = mutableListOf<RedirectHop>()
            var currentUrl = normalizedUrl
            val visited = mutableSetOf<String>()

            for (step in 1..MAX_HOPS) {
                if (!visited.add(currentUrl)) break
                NetworkSecurityGuard.validatePublicHttpUrl(currentUrl, requireHttps = false).getOrElse { err ->
                    return@withContext Result.failure(err)
                }

                val start = System.currentTimeMillis()
                var code = 0
                var location: String? = null

                // Try HEAD first (lightweight), fall back to GET if server blocks HEAD
                val headReq = Request.Builder().url(currentUrl).head().build()
                noRedirectClient.newCall(headReq).execute().use { resp ->
                    code = resp.code
                    location = resp.header("Location")
                }

                if (code == 405 || code == 403 || code == 501) {
                    val getReq = Request.Builder().url(currentUrl).get().build()
                    noRedirectClient.newCall(getReq).execute().use { resp ->
                        code = resp.code
                        location = resp.header("Location")
                    }
                }

                val latency = System.currentTimeMillis() - start
                val isRedirect = code in listOf(301, 302, 303, 307, 308) && !location.isNullOrBlank()
                val resolvedNext = if (isRedirect) {
                    currentUrl.toHttpUrlOrNull()?.resolve(location!!)?.toString() ?: location!!
                } else null

                hops.add(
                    RedirectHop(
                        hopIndex = step,
                        url = currentUrl,
                        statusCode = code,
                        locationHeader = resolvedNext,
                        latencyMs = latency
                    )
                )

                if (resolvedNext != null) {
                    currentUrl = resolvedNext
                } else {
                    break
                }
            }

            Result.success(
                RedirectChainResult(
                    originalUrl = normalizedUrl,
                    finalUrl = currentUrl,
                    hops = hops
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
