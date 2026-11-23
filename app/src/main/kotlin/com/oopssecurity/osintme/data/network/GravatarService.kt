package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.GravatarAccount
import com.oopssecurity.osintme.data.model.GravatarProfile
import com.oopssecurity.osintme.util.CryptoUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONObject

object GravatarService {

    suspend fun lookupProfile(email: String): Result<GravatarProfile?> = withContext(Dispatchers.IO) {
        try {
            val cleanEmail = email.trim().lowercase()
            if (cleanEmail.isEmpty() || !cleanEmail.contains("@")) {
                return@withContext Result.success(null)
            }

            val hash = CryptoUtil.md5(cleanEmail)
            val url = "https://en.gravatar.com/$hash.json"

            val request = Request.Builder()
                .url(url)
                .header("User-Agent", "OSINTme-Investigator/1.0")
                .get()
                .build()

            val response = OsintApiClient.client.newCall(request).execute()
            if (response.code == 404) {
                return@withContext Result.success(null)
            }

            if (!response.isSuccessful) {
                return@withContext Result.failure(Exception("Gravatar query failed with code ${response.code}"))
            }

            val body = response.body?.string() ?: return@withContext Result.success(null)
            val root = JSONObject(body)
            val entryArr = root.optJSONArray("entry") ?: return@withContext Result.success(null)
            if (entryArr.length() == 0) return@withContext Result.success(null)

            val entry = entryArr.getJSONObject(0)
            val preferredUsername = entry.optString("preferredUsername", "")
            val displayName = entry.optString("displayName", "")
            val aboutMe = entry.optString("aboutMe", "")
            val currentLocation = entry.optString("currentLocation", "")
            val thumbnailUrl = entry.optString("thumbnailUrl", "")
            val profileUrl = entry.optString("profileUrl", "")

            val accountsList = mutableListOf<GravatarAccount>()
            val accountsArr = entry.optJSONArray("accounts")
            if (accountsArr != null) {
                for (i in 0 until accountsArr.length()) {
                    val acc = accountsArr.getJSONObject(i)
                    accountsList.add(
                        GravatarAccount(
                            domain = acc.optString("domain", ""),
                            display = acc.optString("display", ""),
                            url = acc.optString("url", ""),
                            username = acc.optString("username", ""),
                            verified = acc.optString("verified", "false").toBoolean()
                        )
                    )
                }
            }

            val personalUrlsList = mutableListOf<String>()
            val urlsArr = entry.optJSONArray("urls")
            if (urlsArr != null) {
                for (i in 0 until urlsArr.length()) {
                    val u = urlsArr.getJSONObject(i)
                    val value = u.optString("value", "")
                    if (value.isNotEmpty()) personalUrlsList.add(value)
                }
            }

            Result.success(
                GravatarProfile(
                    emailHash = hash,
                    preferredUsername = preferredUsername,
                    displayName = displayName,
                    aboutMe = aboutMe,
                    currentLocation = currentLocation,
                    thumbnailUrl = thumbnailUrl,
                    profileUrl = profileUrl,
                    accounts = accountsList,
                    personalUrls = personalUrlsList
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
