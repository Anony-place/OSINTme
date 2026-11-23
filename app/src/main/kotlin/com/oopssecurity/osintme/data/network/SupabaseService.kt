package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.AffiliateOffer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject

object SupabaseService {
    // Configurable Supabase REST endpoint (Free-Tier Safe & Anonymous Key support)
    var supabaseUrl: String = "https://example.supabase.co"
    var anonKey: String = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy"

    // Default built-in contextual partner offers (works seamlessly offline or without configured keys)
    val DEFAULT_OFFERS = listOf(
        AffiliateOffer(
            id = "proton_pass",
            trigger_type = "BREACH",
            title = "Proton Pass - Encrypted Password & Alias Manager",
            description = "Generate unique email aliases and end-to-end encrypted passwords to make breach leaks useless.",
            cta_text = "Secure Your Accounts",
            affiliate_url = "https://proton.me/pass",
            badge_text = "Recommended Defense"
        ),
        AffiliateOffer(
            id = "mullvad_vpn",
            trigger_type = "IP_EXPOSURE",
            title = "Mullvad / Proton VPN",
            description = "Shield your residential IP address and protect exposed open ports from network reconnaissance.",
            cta_text = "Mask Public IP",
            affiliate_url = "https://mullvad.net",
            badge_text = "Network Protection"
        ),
        AffiliateOffer(
            id = "simple_login",
            trigger_type = "BREACH",
            title = "SimpleLogin by Proton",
            description = "Create on-the-fly forwarding aliases so you never expose your primary email on signups.",
            cta_text = "Create Email Aliases",
            affiliate_url = "https://simplelogin.io",
            badge_text = "Privacy Partner"
        ),
        AffiliateOffer(
            id = "bitwarden",
            trigger_type = "GENERAL",
            title = "Bitwarden Open Source Security",
            description = "Open source, zero-knowledge credential vault audited by third-party cybersecurity teams.",
            cta_text = "Explore Bitwarden",
            affiliate_url = "https://bitwarden.com",
            badge_text = "Open Source"
        )
    )

    suspend fun getAffiliateOffers(triggerType: String? = null): List<AffiliateOffer> = withContext(Dispatchers.IO) {
        if (supabaseUrl.contains("example.supabase.co")) {
            return@withContext filterDefaultOffers(triggerType)
        }

        try {
            val url = "$supabaseUrl/rest/v1/affiliate_offers?is_active=eq.true"
            val request = Request.Builder()
                .url(url)
                .header("apikey", anonKey)
                .header("Authorization", "Bearer $anonKey")
                .get()
                .build()

            val response = OsintApiClient.client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: "[]"
                val jsonArray = JSONArray(body)
                val list = mutableListOf<AffiliateOffer>()
                for (i in 0 until jsonArray.length()) {
                    val obj = jsonArray.getJSONObject(i)
                    list.add(
                        AffiliateOffer(
                            id = obj.optString("id", ""),
                            trigger_type = obj.optString("trigger_type", "GENERAL"),
                            title = obj.optString("title", ""),
                            description = obj.optString("description", ""),
                            cta_text = obj.optString("cta_text", "Learn More"),
                            affiliate_url = obj.optString("affiliate_url", ""),
                            badge_text = obj.optString("badge_text", "Partner"),
                            is_active = obj.optBoolean("is_active", true)
                        )
                    )
                }
                if (list.isNotEmpty()) {
                    return@withContext if (triggerType != null) {
                        list.filter { it.trigger_type.equals(triggerType, ignoreCase = true) || it.trigger_type == "GENERAL" }
                    } else list
                }
            }
        } catch (e: Exception) {
            // Fall back to built-in offers
        }
        filterDefaultOffers(triggerType)
    }

    private fun filterDefaultOffers(triggerType: String?): List<AffiliateOffer> {
        return if (triggerType != null) {
            DEFAULT_OFFERS.filter { it.trigger_type.equals(triggerType, ignoreCase = true) || it.trigger_type == "GENERAL" }
        } else {
            DEFAULT_OFFERS
        }
    }

    suspend fun getCachedRecon(cacheKey: String): String? = withContext(Dispatchers.IO) {
        if (supabaseUrl.contains("example.supabase.co")) return@withContext null
        try {
            val url = "$supabaseUrl/rest/v1/osint_cache?cache_key=eq.$cacheKey&select=data,expires_at"
            val request = Request.Builder()
                .url(url)
                .header("apikey", anonKey)
                .header("Authorization", "Bearer $anonKey")
                .get()
                .build()

            val response = OsintApiClient.client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: "[]"
                val arr = JSONArray(body)
                if (arr.length() > 0) {
                    val obj = arr.getJSONObject(0)
                    val expiresAt = obj.optLong("expires_at", 0L)
                    if (expiresAt > System.currentTimeMillis()) {
                        return@withContext obj.optString("data", null)
                    }
                }
            }
        } catch (e: Exception) {
            // Cache miss / offline
        }
        null
    }

    suspend fun setCachedRecon(cacheKey: String, reconType: String, dataJson: String): Boolean = withContext(Dispatchers.IO) {
        if (supabaseUrl.contains("example.supabase.co")) return@withContext false
        try {
            val url = "$supabaseUrl/rest/v1/osint_cache"
            val json = JSONObject().apply {
                put("cache_key", cacheKey)
                put("recon_type", reconType)
                put("data", dataJson)
                put("expires_at", System.currentTimeMillis() + (24 * 60 * 60 * 1000L)) // 24hr TTL
            }

            val request = Request.Builder()
                .url(url)
                .header("apikey", anonKey)
                .header("Authorization", "Bearer $anonKey")
                .header("Prefer", "resolution=merge-duplicates")
                .post(json.toString().toRequestBody("application/json".toMediaType()))
                .build()

            val response = OsintApiClient.client.newCall(request).execute()
            response.isSuccessful
        } catch (e: Exception) {
            false
        }
    }
}
