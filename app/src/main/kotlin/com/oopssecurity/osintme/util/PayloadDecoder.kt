package com.oopssecurity.osintme.util

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Date
import java.util.Locale
import java.util.TimeZone

data class JwtInspectionResult(
    val headerJson: String,
    val payloadJson: String,
    val algorithm: String,
    val issuer: String,
    val subject: String,
    val issuedAtReadable: String,
    val expiresAtReadable: String,
    val isExpired: Boolean?,
    val securityWarnings: List<String>
)

data class HashDigestBundle(
    val md5: String,
    val sha1: String,
    val sha256: String
)

enum class HashFormat(val label: String) {
    MD5("MD5 (128-bit)"),
    SHA1("SHA-1 (160-bit)"),
    SHA256("SHA-256 (256-bit)"),
    UNKNOWN("Not a standard hash")
}

/**
 * Offline CyberChef-lite decoder, encoder, hash generator, and JWT security inspector.
 * Uses pure JDK + kotlinx.serialization APIs so it works identically on Android runtime and JVM unit tests.
 */
object PayloadDecoder {

    private val prettyJson = Json { prettyPrint = true; ignoreUnknownKeys = true }

    private val MD5_REGEX = Regex("^[0-9a-fA-F]{32}$")
    private val SHA1_REGEX = Regex("^[0-9a-fA-F]{40}$")
    private val SHA256_REGEX = Regex("^[0-9a-fA-F]{64}$")

    fun detectHashFormat(input: String): HashFormat {
        val clean = input.trim()
        return when {
            SHA256_REGEX.matches(clean) -> HashFormat.SHA256
            SHA1_REGEX.matches(clean) -> HashFormat.SHA1
            MD5_REGEX.matches(clean) -> HashFormat.MD5
            else -> HashFormat.UNKNOWN
        }
    }

    fun computeHashes(input: String): HashDigestBundle {
        val bytes = input.toByteArray(StandardCharsets.UTF_8)
        return HashDigestBundle(
            md5 = digestHex("MD5", bytes),
            sha1 = digestHex("SHA-1", bytes),
            sha256 = digestHex("SHA-256", bytes)
        )
    }

    fun encodeBase64(input: String): String {
        return Base64.getEncoder().encodeToString(input.toByteArray(StandardCharsets.UTF_8))
    }

    fun decodeBase64(input: String): Result<String> {
        return try {
            val clean = input.trim().replace("\n", "").replace("\r", "")
            val padded = when (clean.length % 4) {
                2 -> "$clean=="
                3 -> "$clean="
                else -> clean
            }
            val bytes = if (padded.contains('-') || padded.contains('_')) {
                Base64.getUrlDecoder().decode(padded)
            } else {
                Base64.getDecoder().decode(padded)
            }
            Result.success(String(bytes, StandardCharsets.UTF_8))
        } catch (e: Exception) {
            Result.failure(Exception("Invalid Base64 payload: ${e.message}"))
        }
    }

    fun encodeHex(input: String): String {
        return input.toByteArray(StandardCharsets.UTF_8).joinToString("") { "%02x".format(it) }
    }

    fun decodeHex(input: String): Result<String> {
        return try {
            val clean = input.trim()
                .replace("0x", "", ignoreCase = true)
                .replace(Regex("[\\s:\\-]"), "")
            if (clean.isEmpty() || clean.length % 2 != 0 || !clean.matches(Regex("^[0-9a-fA-F]+$"))) {
                return Result.failure(Exception("Hex string must have an even number of 0-9 / A-F characters"))
            }
            val bytes = ByteArray(clean.length / 2) { i ->
                clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
            Result.success(String(bytes, StandardCharsets.UTF_8))
        } catch (e: Exception) {
            Result.failure(Exception("Invalid Hex payload: ${e.message}"))
        }
    }

    fun encodeUrl(input: String): String = URLEncoder.encode(input, StandardCharsets.UTF_8.name())

    fun decodeUrl(input: String): Result<String> {
        return try {
            Result.success(URLDecoder.decode(input.trim(), StandardCharsets.UTF_8.name()))
        } catch (e: Exception) {
            Result.failure(Exception("Invalid URL-encoded string: ${e.message}"))
        }
    }

    fun rot13(input: String): String {
        val sb = StringBuilder(input.length)
        for (c in input) {
            sb.append(
                when (c) {
                    in 'a'..'m', in 'A'..'M' -> (c.code + 13).toChar()
                    in 'n'..'z', in 'N'..'Z' -> (c.code - 13).toChar()
                    else -> c
                }
            )
        }
        return sb.toString()
    }

    fun decodeEpoch(input: String): Result<String> {
        val clean = input.trim()
        val numeric = clean.toLongOrNull()
            ?: return Result.failure(Exception("Enter a numeric Unix timestamp (seconds or milliseconds)"))
        val millis = if (kotlin.math.abs(numeric) < 10_000_000_000L) numeric * 1000L else numeric
        val utcFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val isoFmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val date = Date(millis)
        val unitLabel = if (kotlin.math.abs(numeric) < 10_000_000_000L) "Seconds" else "Milliseconds"
        return Result.success(
            "UTC: ${utcFmt.format(date)}\nISO-8601: ${isoFmt.format(date)}\nDetected Unit: $unitLabel"
        )
    }

    fun inspectJwt(rawToken: String): Result<JwtInspectionResult> {
        val clean = rawToken.trim().removePrefix("Bearer ").trim()
        val parts = clean.split(".")
        if (parts.size < 2 || parts.size > 3) {
            return Result.failure(Exception("JWT must have 2 or 3 dot-separated Base64URL segments"))
        }

        val headerStr = decodeBase64(parts[0]).getOrElse {
            return Result.failure(Exception("Invalid JWT header encoding"))
        }
        val payloadStr = decodeBase64(parts[1]).getOrElse {
            return Result.failure(Exception("Invalid JWT payload encoding"))
        }

        return try {
            val headerObj = prettyJson.parseToJsonElement(headerStr).jsonObject
            val payloadObj = prettyJson.parseToJsonElement(payloadStr).jsonObject

            val alg = headerObj["alg"]?.jsonPrimitive?.contentOrNull?.ifBlank { "MISSING" } ?: "MISSING"
            val iss = payloadObj["iss"]?.jsonPrimitive?.contentOrNull.orEmpty()
            val sub = payloadObj["sub"]?.jsonPrimitive?.contentOrNull.orEmpty()

            val nowSec = System.currentTimeMillis() / 1000L
            val iatSec = payloadObj["iat"]?.jsonPrimitive?.longOrNull?.takeIf { it > 0 }
            val expSec = payloadObj["exp"]?.jsonPrimitive?.longOrNull?.takeIf { it > 0 }
            val nbfSec = payloadObj["nbf"]?.jsonPrimitive?.longOrNull?.takeIf { it > 0 }

            val isExpired = expSec?.let { it < nowSec }
            val warnings = mutableListOf<String>()

            if (alg.equals("none", ignoreCase = true) || alg == "MISSING") {
                warnings.add("CRITICAL: Unsigned token (alg=$alg) — vulnerable to signature bypass")
            } else if (alg.equals("HS256", ignoreCase = true)) {
                warnings.add("Symmetric HMAC (HS256) — verify server does not accept RS256-to-HS256 confusion")
            }
            if (parts.size == 2 || parts.getOrNull(2).isNullOrBlank()) {
                warnings.add("Signature segment is empty — token integrity cannot be verified")
            }
            if (expSec == null) {
                warnings.add("No 'exp' claim present — non-expiring token increases replay window")
            } else if (isExpired == true) {
                warnings.add("Token expired at ${formatUtc(expSec)}")
            }
            if (nbfSec != null && nbfSec > nowSec) {
                warnings.add("Token not valid before ${formatUtc(nbfSec)}")
            }

            Result.success(
                JwtInspectionResult(
                    headerJson = prettyJson.encodeToString(JsonObject.serializer(), headerObj),
                    payloadJson = prettyJson.encodeToString(JsonObject.serializer(), payloadObj),
                    algorithm = alg,
                    issuer = iss,
                    subject = sub,
                    issuedAtReadable = iatSec?.let { formatUtc(it) } ?: "Not specified",
                    expiresAtReadable = expSec?.let { formatUtc(it) } ?: "No expiration",
                    isExpired = isExpired,
                    securityWarnings = warnings
                )
            )
        } catch (e: Exception) {
            Result.failure(Exception("JWT segments are not valid JSON: ${e.message}"))
        }
    }

    private fun digestHex(algorithm: String, bytes: ByteArray): String {
        val md = MessageDigest.getInstance(algorithm)
        return md.digest(bytes).joinToString("") { "%02x".format(it) }
    }

    private fun formatUtc(epochSeconds: Long): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        return fmt.format(Date(epochSeconds * 1000L))
    }
}
