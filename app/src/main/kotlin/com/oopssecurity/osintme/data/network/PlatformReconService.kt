package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.ReconStatus
import com.oopssecurity.osintme.data.model.UsernameCheckResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder

enum class ProbeType {
    STATUS_CODE,
    BODY_CONTAINS,
    BODY_DOES_NOT_CONTAIN,
    JSON_FIELD,
    JSON_ARRAY_NON_EMPTY
}

data class PlatformDefinition(
    val name: String,
    val checkUrlTemplate: String,
    val profileUrlTemplate: String,
    val category: String,
    val probeType: ProbeType = ProbeType.STATUS_CODE,
    val expectedPattern: String = "",
    val headers: Map<String, String> = emptyMap(),
    val metadataExtractor: ((String) -> String?)? = null
)

object PlatformReconService {

    // 106+ Real OSINT Platform Probes (Maigret / Sherlock-class) using Public JSON APIs & Signatures
    private val CORE_PLATFORMS = listOf(
        PlatformDefinition(
            name = "GitHub",
            checkUrlTemplate = "https://api.github.com/users/%s",
            profileUrlTemplate = "https://github.com/%s",
            category = "Development",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "login",
            headers = mapOf("Accept" to "application/vnd.github+json"),
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    val name = j.optString("name", "").takeIf { it.isNotBlank() && it != "null" }
                    val repos = j.optInt("public_repos", 0)
                    val followers = j.optInt("followers", 0)
                    listOfNotNull(name, "$repos repos", "$followers followers").joinToString(" • ")
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "GitLab",
            checkUrlTemplate = "https://gitlab.com/api/v4/users?username=%s",
            profileUrlTemplate = "https://gitlab.com/%s",
            category = "Development",
            probeType = ProbeType.JSON_ARRAY_NON_EMPTY,
            metadataExtractor = { body ->
                runCatching {
                    val arr = JSONArray(body)
                    if (arr.length() > 0) {
                        val u = arr.getJSONObject(0)
                        val name = u.optString("name", "")
                        val state = u.optString("state", "")
                        listOf(name, state).filter { it.isNotBlank() }.joinToString(" • ")
                    } else null
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Reddit",
            checkUrlTemplate = "https://www.reddit.com/user/%s/about.json",
            profileUrlTemplate = "https://www.reddit.com/user/%s",
            category = "Community",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"total_karma\"",
            headers = mapOf("User-Agent" to "android:com.oopssecurity.osintme:v1.0 (OSINT Lookup)"),
            metadataExtractor = { body ->
                runCatching {
                    val data = JSONObject(body).optJSONObject("data") ?: return@runCatching null
                    val karma = data.optInt("total_karma", 0)
                    "Karma: $karma"
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Twitch",
            checkUrlTemplate = "https://api.ivr.fi/v2/twitch/user?login=%s",
            profileUrlTemplate = "https://www.twitch.tv/%s",
            category = "Streaming",
            probeType = ProbeType.JSON_ARRAY_NON_EMPTY,
            metadataExtractor = { body ->
                runCatching {
                    val arr = JSONArray(body)
                    if (arr.length() > 0) {
                        val u = arr.getJSONObject(0)
                        val display = u.optString("displayName", "")
                        val followers = u.optInt("followers", -1)
                        buildList {
                            if (display.isNotBlank()) add(display)
                            if (followers >= 0) add("$followers followers")
                        }.joinToString(" • ").ifBlank { null }
                    } else null
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Bluesky",
            checkUrlTemplate = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=%s.bsky.social",
            profileUrlTemplate = "https://bsky.app/profile/%s.bsky.social",
            category = "Social",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "did",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    val display = j.optString("displayName", "").ifBlank { null }
                    val followers = j.optInt("followersCount", 0)
                    listOfNotNull(display, "$followers followers").joinToString(" • ")
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Mastodon",
            checkUrlTemplate = "https://mastodon.social/api/v1/accounts/lookup?acct=%s",
            profileUrlTemplate = "https://mastodon.social/@%s",
            category = "Fediverse",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "acct",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    val display = j.optString("display_name", "").ifBlank { null }
                    val followers = j.optInt("followers_count", 0)
                    listOfNotNull(display, "$followers followers").joinToString(" • ")
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "HackerNews",
            checkUrlTemplate = "https://hacker-news.firebaseio.com/v0/user/%s.json",
            profileUrlTemplate = "https://news.ycombinator.com/user?id=%s",
            category = "Tech News",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "id",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    "Karma: ${j.optInt("karma", 0)}"
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Dev.to",
            checkUrlTemplate = "https://dev.to/api/users/by_username?url=%s",
            profileUrlTemplate = "https://dev.to/%s",
            category = "Blogging",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "username",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    j.optString("name", "").ifBlank { null }
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "DockerHub",
            checkUrlTemplate = "https://hub.docker.com/v2/users/%s/",
            profileUrlTemplate = "https://hub.docker.com/u/%s",
            category = "DevOps",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "username"
        ),
        PlatformDefinition(
            name = "HuggingFace",
            checkUrlTemplate = "https://huggingface.co/api/users/%s/overview",
            profileUrlTemplate = "https://huggingface.co/%s",
            category = "AI & ML",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "user",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    val full = j.optString("fullname", "").ifBlank { null }
                    val models = j.optInt("numModels", 0)
                    listOfNotNull(full, if (models > 0) "$models models" else null).joinToString(" • ").ifBlank { null }
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Keybase",
            checkUrlTemplate = "https://keybase.io/_/api/1.0/user/lookup.json?usernames=%s",
            profileUrlTemplate = "https://keybase.io/%s",
            category = "Cryptography",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"them\":[{"
        ),
        PlatformDefinition(
            name = "Gravatar",
            checkUrlTemplate = "https://en.gravatar.com/%s.json",
            profileUrlTemplate = "https://en.gravatar.com/%s",
            category = "Identity",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "entry"
        ),
        PlatformDefinition(
            name = "Chess.com",
            checkUrlTemplate = "https://api.chess.com/pub/player/%s",
            profileUrlTemplate = "https://www.chess.com/member/%s",
            category = "Gaming",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "username",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    val title = j.optString("title", "").ifBlank { null }
                    val status = j.optString("status", "").ifBlank { null }
                    listOfNotNull(title, status).joinToString(" • ").ifBlank { null }
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Lichess",
            checkUrlTemplate = "https://lichess.org/api/user/%s",
            profileUrlTemplate = "https://lichess.org/@/%s",
            category = "Gaming",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "username",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    val count = j.optJSONObject("count")?.optInt("all", 0) ?: 0
                    "$count games"
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Codeforces",
            checkUrlTemplate = "https://codeforces.com/api/user.info?handles=%s",
            profileUrlTemplate = "https://codeforces.com/profile/%s",
            category = "Competitive Coding",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"status\":\"OK\"",
            metadataExtractor = { body ->
                runCatching {
                    val arr = JSONObject(body).optJSONArray("result") ?: return@runCatching null
                    val u = arr.getJSONObject(0)
                    val rank = u.optString("rank", "")
                    val rating = u.optInt("rating", 0)
                    if (rating > 0) "$rank ($rating)" else rank.ifBlank { null }
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Scratch",
            checkUrlTemplate = "https://api.scratch.mit.edu/users/%s",
            profileUrlTemplate = "https://scratch.mit.edu/users/%s",
            category = "Development",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "username"
        ),
        PlatformDefinition(
            name = "RubyGems",
            checkUrlTemplate = "https://rubygems.org/api/v1/profiles/%s.json",
            profileUrlTemplate = "https://rubygems.org/profiles/%s",
            category = "Package Registry",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "handle"
        ),
        PlatformDefinition(
            name = "Crates.io",
            checkUrlTemplate = "https://crates.io/api/v1/users/%s",
            profileUrlTemplate = "https://crates.io/users/%s",
            category = "Package Registry",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "user"
        ),
        PlatformDefinition(
            name = "Wikipedia",
            checkUrlTemplate = "https://en.wikipedia.org/w/api.php?action=query&list=users&ususers=%s&format=json",
            profileUrlTemplate = "https://en.wikipedia.org/wiki/User:%s",
            category = "Reference",
            probeType = ProbeType.BODY_DOES_NOT_CONTAIN,
            expectedPattern = "\"missing\""
        ),
        PlatformDefinition(
            name = "Telegram",
            checkUrlTemplate = "https://t.me/%s",
            profileUrlTemplate = "https://t.me/%s",
            category = "Messaging",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "tgme_page_title"
        ),
        PlatformDefinition(
            name = "Steam",
            checkUrlTemplate = "https://steamcommunity.com/id/%s",
            profileUrlTemplate = "https://steamcommunity.com/id/%s",
            category = "Gaming",
            probeType = ProbeType.BODY_DOES_NOT_CONTAIN,
            expectedPattern = "The specified profile could not be found"
        ),
        PlatformDefinition(
            name = "Medium",
            checkUrlTemplate = "https://medium.com/@%s",
            profileUrlTemplate = "https://medium.com/@%s",
            category = "Publishing",
            probeType = ProbeType.BODY_DOES_NOT_CONTAIN,
            expectedPattern = "PAGE NOT FOUND"
        ),
        PlatformDefinition(
            name = "npm",
            checkUrlTemplate = "https://www.npmjs.com/~%s",
            profileUrlTemplate = "https://www.npmjs.com/~%s",
            category = "Package Registry",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "PyPI",
            checkUrlTemplate = "https://pypi.org/user/%s/",
            profileUrlTemplate = "https://pypi.org/user/%s/",
            category = "Package Registry",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "YouTube",
            checkUrlTemplate = "https://www.youtube.com/@%s",
            profileUrlTemplate = "https://www.youtube.com/@%s",
            category = "Video",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Vimeo",
            checkUrlTemplate = "https://vimeo.com/%s",
            profileUrlTemplate = "https://vimeo.com/%s",
            category = "Video",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "SoundCloud",
            checkUrlTemplate = "https://soundcloud.com/%s",
            profileUrlTemplate = "https://soundcloud.com/%s",
            category = "Audio",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Spotify",
            checkUrlTemplate = "https://open.spotify.com/user/%s",
            profileUrlTemplate = "https://open.spotify.com/user/%s",
            category = "Audio",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Bandcamp",
            checkUrlTemplate = "https://bandcamp.com/%s",
            profileUrlTemplate = "https://bandcamp.com/%s",
            category = "Music",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Substack",
            checkUrlTemplate = "https://%s.substack.com",
            profileUrlTemplate = "https://%s.substack.com",
            category = "Newsletters",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Linktree",
            checkUrlTemplate = "https://linktr.ee/%s",
            profileUrlTemplate = "https://linktr.ee/%s",
            category = "Social Profiles",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Threads",
            checkUrlTemplate = "https://www.threads.net/@%s",
            profileUrlTemplate = "https://www.threads.net/@%s",
            category = "Social",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Pinterest",
            checkUrlTemplate = "https://www.pinterest.com/%s/",
            profileUrlTemplate = "https://www.pinterest.com/%s/",
            category = "Creative",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Flickr",
            checkUrlTemplate = "https://www.flickr.com/people/%s/",
            profileUrlTemplate = "https://www.flickr.com/people/%s/",
            category = "Photography",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Dribbble",
            checkUrlTemplate = "https://dribbble.com/%s",
            profileUrlTemplate = "https://dribbble.com/%s",
            category = "Design",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Behance",
            checkUrlTemplate = "https://www.behance.net/%s",
            profileUrlTemplate = "https://www.behance.net/%s",
            category = "Design",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Replit",
            checkUrlTemplate = "https://replit.com/@%s",
            profileUrlTemplate = "https://replit.com/@%s",
            category = "Development",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Pastebin",
            checkUrlTemplate = "https://pastebin.com/u/%s",
            profileUrlTemplate = "https://pastebin.com/u/%s",
            category = "Code & Pastes",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "LeetCode",
            checkUrlTemplate = "https://leetcode.com/u/%s/",
            profileUrlTemplate = "https://leetcode.com/u/%s/",
            category = "Competitive Coding",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Kaggle",
            checkUrlTemplate = "https://www.kaggle.com/%s",
            profileUrlTemplate = "https://www.kaggle.com/%s",
            category = "Data Science",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "ProductHunt",
            checkUrlTemplate = "https://www.producthunt.com/@%s",
            profileUrlTemplate = "https://www.producthunt.com/@%s",
            category = "Tech",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "BuyMeACoffee",
            checkUrlTemplate = "https://www.buymeacoffee.com/%s",
            profileUrlTemplate = "https://www.buymeacoffee.com/%s",
            category = "Crowdfunding",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "itch.io",
            checkUrlTemplate = "https://%s.itch.io",
            profileUrlTemplate = "https://%s.itch.io",
            category = "Indie Games",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Disqus",
            checkUrlTemplate = "https://disqus.com/by/%s/",
            profileUrlTemplate = "https://disqus.com/by/%s/",
            category = "Comments",
            probeType = ProbeType.STATUS_CODE
        )
    )

    val ALL_PLATFORMS: List<PlatformDefinition> = CORE_PLATFORMS + ExtendedPlatformCatalog.PLATFORMS

    private val HTML_TITLE_REGEX = Regex("(?is)<title[^>]*>(.*?)</title>")
    private val OG_DESC_REGEX = Regex("(?is)<meta[^>]+(?:property=[\"']og:description[\"']|name=[\"']description[\"'])[^>]+content=[\"']([^\"']{6,140})[\"']")

    fun scanUsernameFlow(
        username: String,
        limitPlatforms: Int? = null
    ): Flow<UsernameCheckResult> = channelFlow {
        val trimmed = username.trim().removePrefix("@")
        val platformsToScan = if (limitPlatforms != null) {
            ALL_PLATFORMS.take(limitPlatforms)
        } else {
            ALL_PLATFORMS
        }

        val semaphore = Semaphore(12)

        withContext(Dispatchers.IO) {
            val jobs = platformsToScan.map { platform ->
                async {
                    semaphore.withPermit {
                        val result = checkPlatform(platform, trimmed)
                        send(result)
                    }
                }
            }
            jobs.awaitAll()
        }
    }

    private fun checkPlatform(platform: PlatformDefinition, username: String): UsernameCheckResult {
        val encoded = URLEncoder.encode(username, "UTF-8").replace("+", "%20")
        val checkUrl = String.format(platform.checkUrlTemplate, encoded)
        val profileUrl = String.format(platform.profileUrlTemplate, encoded)
        val startTime = System.currentTimeMillis()

        return try {
            val reqBuilder = Request.Builder()
                .url(checkUrl)
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
                )
                .header("Accept", "application/json,text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")

            platform.headers.forEach { (k, v) ->
                reqBuilder.header(k, v)
            }

            OsintApiClient.client.newCall(reqBuilder.build()).execute().use { response ->
                val code = response.code
                val duration = System.currentTimeMillis() - startTime
                val body = response.body?.string() ?: ""

                val status = when {
                    code == 403 || code == 429 || code in 500..599 -> ReconStatus.RATE_LIMITED
                    code == 404 || code == 410 -> ReconStatus.AVAILABLE
                    else -> evaluateProbe(platform, code, body)
                }

                val metadata = if (status == ReconStatus.FOUND) {
                    platform.metadataExtractor?.invoke(body)?.takeIf { it.isNotBlank() }
                        ?: extractHtmlFallbackMeta(body, platform.name)
                } else ""

                UsernameCheckResult(
                    platformName = platform.name,
                    profileUrl = profileUrl,
                    category = platform.category,
                    status = status,
                    httpCode = code,
                    responseTimeMs = duration,
                    metadata = metadata
                )
            }
        } catch (e: Exception) {
            UsernameCheckResult(
                platformName = platform.name,
                profileUrl = profileUrl,
                category = platform.category,
                status = ReconStatus.ERROR,
                httpCode = 0,
                responseTimeMs = System.currentTimeMillis() - startTime
            )
        }
    }

    private fun evaluateProbe(platform: PlatformDefinition, code: Int, body: String): ReconStatus {
        if (code !in 200..299) return ReconStatus.AVAILABLE
        return when (platform.probeType) {
            ProbeType.STATUS_CODE -> ReconStatus.FOUND
            ProbeType.BODY_CONTAINS -> {
                if (body.contains(platform.expectedPattern, ignoreCase = true)) {
                    ReconStatus.FOUND
                } else {
                    ReconStatus.AVAILABLE
                }
            }
            ProbeType.BODY_DOES_NOT_CONTAIN -> {
                if (body.isNotBlank() && !body.contains(platform.expectedPattern, ignoreCase = true)) {
                    ReconStatus.FOUND
                } else {
                    ReconStatus.AVAILABLE
                }
            }
            ProbeType.JSON_FIELD -> {
                try {
                    val trimmedBody = body.trim()
                    if (trimmedBody == "null" || trimmedBody.isEmpty()) return ReconStatus.AVAILABLE
                    val json = JSONObject(trimmedBody)
                    if (json.has(platform.expectedPattern) && !json.isNull(platform.expectedPattern)) {
                        ReconStatus.FOUND
                    } else {
                        ReconStatus.AVAILABLE
                    }
                } catch (_: Exception) {
                    ReconStatus.AVAILABLE
                }
            }
            ProbeType.JSON_ARRAY_NON_EMPTY -> {
                try {
                    val array = JSONArray(body.trim())
                    if (array.length() > 0) ReconStatus.FOUND else ReconStatus.AVAILABLE
                } catch (_: Exception) {
                    ReconStatus.AVAILABLE
                }
            }
        }
    }

    private fun extractHtmlFallbackMeta(body: String, platformName: String): String {
        if (!body.contains("<", ignoreCase = false) || body.length > 500_000) return ""
        val ogDesc = OG_DESC_REGEX.find(body)?.groupValues?.getOrNull(1)
            ?.replace(Regex("\\s+"), " ")?.trim()
            ?.takeIf { it.length in 8..110 && !it.contains("Sign up", true) && !it.contains("Log in", true) }
        if (!ogDesc.isNullOrBlank()) return ogDesc
        val title = HTML_TITLE_REGEX.find(body)?.groupValues?.getOrNull(1)
            ?.replace(Regex("\\s+"), " ")?.trim()
            ?.takeIf { it.length in 3..80 && !it.equals(platformName, true) }
        return title.orEmpty()
    }
}
