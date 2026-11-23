package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.PasswordLeakResult
import com.oopssecurity.osintme.util.CryptoUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request

object HibpPasswordService {
    private const val RANGE_URL = "https://api.pwnedpasswords.com/range/"

    /**
     * Checks if password has appeared in data leaks using k-Anonymity model.
     * Raw passwords are NEVER sent over the network. Only the 5-character SHA-1 prefix is sent.
     */
    suspend fun checkPassword(password: String): Result<PasswordLeakResult> = withContext(Dispatchers.IO) {
        try {
            if (password.isEmpty()) {
                return@withContext Result.success(
                    PasswordLeakResult(
                        isLeaked = false,
                        leakCount = 0,
                        sha1Prefix = "",
                        securityAdvice = "Password is empty."
                    )
                )
            }

            // 1. Compute SHA-1 hash locally
            val fullHash = CryptoUtil.sha1(password).uppercase()
            val prefix = fullHash.substring(0, 5)
            val suffix = fullHash.substring(5)

            // 2. Query k-Anonymity range API with prefix only
            val request = Request.Builder()
                .url("$RANGE_URL$prefix")
                .header("Add-Padding", "true") // Mitigate response size analysis
                .get()
                .build()

            val response = OsintApiClient.client.newCall(request).execute()
            if (!response.isSuccessful) {
                return@withContext Result.failure(Exception("HTTP ${response.code} received from leak database"))
            }

            val body = response.body?.string() ?: ""
            var count = 0L

            // 3. Search for matching suffix locally
            val lines = body.lineSequence()
            for (line in lines) {
                val parts = line.split(":")
                if (parts.size >= 2) {
                    val returnedSuffix = parts[0].trim().uppercase()
                    if (returnedSuffix == suffix) {
                        count = parts[1].trim().toLongOrNull() ?: 0L
                        break
                    }
                }
            }

            val isLeaked = count > 0
            val advice = if (isLeaked) {
                "This password appeared in $count known data breaches! Change it immediately on all services where it was used."
            } else {
                "No public breach records found for this password hash prefix. Ensure you use unique passwords per service."
            }

            Result.success(
                PasswordLeakResult(
                    isLeaked = isLeaked,
                    leakCount = count,
                    sha1Prefix = prefix,
                    securityAdvice = advice
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
