package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.BreachedSite
import com.oopssecurity.osintme.data.model.EmailBreachResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder

object XposedOrNotService {
    private const val CHECK_EMAIL_URL = "https://api.xposedornot.com/v1/check-email/"
    private const val ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics?email="

    suspend fun checkEmail(email: String): Result<EmailBreachResult> = withContext(Dispatchers.IO) {
        try {
            val trimmed = email.trim().lowercase()
            val encodedEmail = URLEncoder.encode(trimmed, "UTF-8")

            coroutineScope {
                val checkDeferred = async { fetchCheckEmail(encodedEmail) }
                val analyticsDeferred = async { fetchAnalytics(encodedEmail) }

                val (checkCode, checkBody) = checkDeferred.await()
                val analyticsJson = analyticsDeferred.await()

                if (checkCode == 404 && analyticsJson == null) {
                    return@coroutineScope Result.success(
                        EmailBreachResult(
                            email = trimmed,
                            isBreached = false,
                            breaches = emptyList(),
                            totalBreaches = 0,
                            exposedDataTypes = emptyList(),
                            riskLabel = "Clean"
                        )
                    )
                }

                val breachesByName = linkedMapOf<String, BreachedSite>()
                val exposedTypes = linkedSetOf<String>()
                var riskLabel = ""

                // 1. Parse rich ExposedBreaches.breaches_details from analytics first
                if (analyticsJson != null) {
                    val exposedBreachesObj = analyticsJson.optJSONObject("ExposedBreaches")
                    val detailsArr = exposedBreachesObj?.optJSONArray("breaches_details")
                    if (detailsArr != null) {
                        for (i in 0 until detailsArr.length()) {
                            val b = detailsArr.optJSONObject(i) ?: continue
                            val name = b.optString("breach", "").trim()
                            if (name.isEmpty()) continue
                            val domain = b.optString("domain", "").trim()
                            val date = b.optString("xposed_date", "").trim()
                            val industry = b.optString("industry", "").trim()
                            val records = b.optLong("xposed_records", 0L)
                            val desc = b.optString("details", "").trim()
                            val xDataRaw = b.optString("xposed_data", "")
                            val dataList = xDataRaw.split(";", ",")
                                .map { it.trim() }
                                .filter { it.isNotEmpty() }

                            exposedTypes.addAll(dataList)
                            breachesByName[name.lowercase()] = BreachedSite(
                                siteName = name,
                                domain = domain,
                                breachDate = date.ifEmpty { "Date unspecified" },
                                exposedData = dataList,
                                description = desc,
                                industry = industry,
                                pwnCount = records
                            )
                        }
                    }

                    // Parse risk score label if present
                    val metrics = analyticsJson.optJSONObject("BreachMetrics")
                    val riskArr = metrics?.optJSONArray("risk")
                    if (riskArr != null && riskArr.length() > 0) {
                        riskLabel = riskArr.optJSONObject(0)?.optString("risk_label", "") ?: ""
                    }

                    // Parse exposed data categories tree
                    val xposedTree = metrics?.optJSONArray("xposed_data")
                    if (xposedTree != null) {
                        for (i in 0 until xposedTree.length()) {
                            val cat = xposedTree.optJSONObject(i) ?: continue
                            val children = cat.optJSONArray("children") ?: continue
                            for (j in 0 until children.length()) {
                                val sub = children.optJSONObject(j) ?: continue
                                val subChildren = sub.optJSONArray("children") ?: continue
                                for (k in 0 until subChildren.length()) {
                                    val dataItem = subChildren.optJSONObject(k) ?: continue
                                    val cleanName = dataItem.optString("name", "")
                                        .removePrefix("data_")
                                        .replace("_", " ")
                                        .trim()
                                    if (cleanName.isNotEmpty()) exposedTypes.add(cleanName)
                                }
                            }
                        }
                    }

                    // Fallback site names from BreachesSummary if details were absent
                    val summary = analyticsJson.optJSONObject("BreachesSummary")
                    val siteField = summary?.optString("site", "") ?: ""
                    if (siteField.isNotEmpty()) {
                        siteField.split(";").map { it.trim() }.filter { it.isNotEmpty() }.forEach { s ->
                            breachesByName.putIfAbsent(
                                s.lowercase(),
                                BreachedSite(siteName = s, breachDate = "Confirmed public breach")
                            )
                        }
                    }
                }

                // 2. Merge any site names from primary check-email endpoint
                if (checkCode in 200..299 && checkBody.isNotEmpty() && !checkBody.contains("Not Found", ignoreCase = true)) {
                    try {
                        val json = JSONObject(checkBody)
                        val breachesField = json.opt("breaches")
                        if (breachesField is JSONArray) {
                            for (i in 0 until breachesField.length()) {
                                when (val item = breachesField.get(i)) {
                                    is JSONArray -> {
                                        for (j in 0 until item.length()) {
                                            val siteName = item.optString(j, "").trim()
                                            if (siteName.isNotEmpty()) {
                                                breachesByName.putIfAbsent(
                                                    siteName.lowercase(),
                                                    BreachedSite(siteName = siteName, breachDate = "Confirmed public breach")
                                                )
                                            }
                                        }
                                    }
                                    is String -> {
                                        val siteName = item.trim()
                                        if (siteName.isNotEmpty()) {
                                            breachesByName.putIfAbsent(
                                                siteName.lowercase(),
                                                BreachedSite(siteName = siteName, breachDate = "Confirmed public breach")
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    } catch (_: Exception) {
                        // Malformed response handled gracefully
                    }
                }

                if (checkCode !in 200..299 && checkCode != 404 && breachesByName.isEmpty() && analyticsJson == null) {
                    return@coroutineScope Result.failure(
                        Exception("XposedOrNot API returned HTTP $checkCode (rate limit or temporary outage)")
                    )
                }

                val list = breachesByName.values.toList()
                Result.success(
                    EmailBreachResult(
                        email = trimmed,
                        isBreached = list.isNotEmpty(),
                        breaches = list,
                        totalBreaches = list.size,
                        exposedDataTypes = exposedTypes.toList(),
                        riskLabel = riskLabel
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun fetchCheckEmail(encodedEmail: String): Pair<Int, String> {
        return try {
            val req = Request.Builder()
                .url("$CHECK_EMAIL_URL$encodedEmail")
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                resp.code to (resp.body?.string() ?: "")
            }
        } catch (e: Exception) {
            0 to ""
        }
    }

    private fun fetchAnalytics(encodedEmail: String): JSONObject? {
        return try {
            val req = Request.Builder()
                .url("$ANALYTICS_URL$encodedEmail")
                .header("Accept", "application/json")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    if (body.startsWith("{")) JSONObject(body) else null
                } else null
            }
        } catch (_: Exception) {
            null
        }
    }
}
