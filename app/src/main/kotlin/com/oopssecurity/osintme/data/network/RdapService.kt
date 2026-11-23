package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.RdapDomainInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONObject

object RdapService {
    private const val RDAP_BASE = "https://rdap.org/domain/"

    suspend fun fetchWhois(domain: String): Result<RdapDomainInfo> = withContext(Dispatchers.IO) {
        try {
            val clean = domain.trim().lowercase()
                .removePrefix("https://").removePrefix("http://")
                .substringBefore("/")

            val request = Request.Builder()
                .url("$RDAP_BASE$clean")
                .header("Accept", "application/rdap+json")
                .get()
                .build()

            val response = OsintApiClient.client.newCall(request).execute()
            if (!response.isSuccessful) {
                return@withContext Result.failure(Exception("RDAP returned HTTP ${response.code}"))
            }

            val body = response.body?.string() ?: "{}"
            val json = JSONObject(body)

            var registrar = "Unknown"
            if (json.has("entities")) {
                val entities = json.getJSONArray("entities")
                for (i in 0 until entities.length()) {
                    val entity = entities.getJSONObject(i)
                    val roles = entity.optJSONArray("roles")
                    var isRegistrar = false
                    if (roles != null) {
                        for (r in 0 until roles.length()) {
                            if (roles.getString(r).equals("registrar", ignoreCase = true)) {
                                isRegistrar = true
                                break
                            }
                        }
                    }
                    if (isRegistrar) {
                        registrar = entity.optString("handle", registrar)
                        val vcard = entity.optJSONArray("vcardArray")
                        if (vcard != null && vcard.length() > 1) {
                            val props = vcard.getJSONArray(1)
                            for (p in 0 until props.length()) {
                                val item = props.getJSONArray(p)
                                if (item.getString(0) == "fn") {
                                    registrar = item.getString(3)
                                }
                            }
                        }
                        break
                    }
                }
            }

            var regDate = ""
            var expDate = ""
            var updatedDate = ""
            if (json.has("events")) {
                val events = json.getJSONArray("events")
                for (i in 0 until events.length()) {
                    val ev = events.getJSONObject(i)
                    val action = ev.optString("eventAction", "")
                    val date = ev.optString("eventDate", "")
                    when (action) {
                        "registration" -> regDate = date
                        "expiration" -> expDate = date
                        "last changed", "last update" -> updatedDate = date
                    }
                }
            }

            val statusList = mutableListOf<String>()
            if (json.has("status")) {
                val statusArr = json.getJSONArray("status")
                for (i in 0 until statusArr.length()) {
                    statusList.add(statusArr.getString(i))
                }
            }

            val nsList = mutableListOf<String>()
            if (json.has("nameservers")) {
                val nsArr = json.getJSONArray("nameservers")
                for (i in 0 until nsArr.length()) {
                    val nsObj = nsArr.getJSONObject(i)
                    nsList.add(nsObj.optString("ldhName", ""))
                }
            }

            Result.success(
                RdapDomainInfo(
                    domain = clean,
                    registrar = registrar,
                    registrationDate = regDate,
                    expirationDate = expDate,
                    lastUpdated = updatedDate,
                    status = statusList,
                    nameServers = nsList.filter { it.isNotEmpty() }
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
