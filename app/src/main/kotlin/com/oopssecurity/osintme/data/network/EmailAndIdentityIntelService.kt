package com.oopssecurity.osintme.data.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Request
import java.net.URLEncoder

data class GithubDeepProfile(
    val username: String,
    val displayName: String,
    val bio: String,
    val company: String,
    val location: String,
    val blogUrl: String,
    val twitterHandle: String,
    val publicRepos: Int,
    val followers: Int,
    val createdAt: String,
    val profileUrl: String,
    val organizations: List<String>,
    val commitEmails: List<String>,
    val commitNames: List<String>
)

data class KeybaseIdentity(
    val username: String,
    val fullName: String,
    val bio: String,
    val location: String,
    val pgpFingerprint: String,
    val verifiedProofs: List<Pair<String, String>> // (service, handle/domain)
)

data class EmailFootprintReport(
    val email: String,
    val mailProviderSuite: String,
    val hasOpenPgpKey: Boolean,
    val pgpKeySummary: String,
    val githubMatchedUsers: List<String>,
    val keybaseIdentity: KeybaseIdentity?
)

data class EntityMention(
    val source: String,
    val title: String,
    val subtitle: String,
    val url: String
)

data class EntitySearchReport(
    val query: String,
    val wikiTitle: String,
    val wikiSummary: String,
    val wikiUrl: String,
    val githubProfiles: List<EntityMention>,
    val webMentions: List<EntityMention>,
    val topHandleCandidate: String?
)

/**
 * Holehe-style passive Email Footprinter + GitHub Deep Commit-Email Harvester +
 * Keybase Cryptographic Proofs + Universal Person/Org Entity Search (100% Zero-Key).
 */
object EmailAndIdentityIntelService {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    /**
     * Fingerprints corporate / consumer email providers from MX host records.
     */
    fun detectMailProviderSuite(mxHosts: List<String>): String {
        val joined = mxHosts.joinToString(" ").lowercase()
        return when {
            joined.isBlank() -> "No MX Records"
            joined.contains("aspmx.l.google.com") || joined.contains("googlemail.com") || joined.contains("smtp.google.com") -> "Google Workspace / Gmail"
            joined.contains("protection.outlook.com") || joined.contains("mail.eo.outlook.com") -> "Microsoft 365 / Exchange Online"
            joined.contains("protonmail.ch") || joined.contains("proton.me") -> "Proton Mail"
            joined.contains("messagingengine.com") -> "Fastmail"
            joined.contains("zoho.com") || joined.contains("zoho.eu") || joined.contains("zoho.in") -> "Zoho Mail"
            joined.contains("pphosted.com") || joined.contains("proofpoint.com") -> "Proofpoint Enterprise Gateway"
            joined.contains("mimecast.com") -> "Mimecast Secure Email"
            joined.contains("route1.mx.cloudflare.net") || joined.contains("mx.cloudflare.net") -> "Cloudflare Email Routing"
            joined.contains("amazonses.com") -> "Amazon SES"
            joined.contains("yahoodns.net") -> "Yahoo Mail"
            joined.contains("icloud.com") || joined.contains("me.com") -> "Apple iCloud Mail"
            joined.contains("yandex.net") || joined.contains("yandex.ru") -> "Yandex Mail"
            joined.contains("mailgun.org") -> "Mailgun"
            joined.contains("sendgrid.net") -> "SendGrid"
            else -> "Custom / Self-Hosted SMTP (${mxHosts.firstOrNull()?.substringAfter(" ")?.trimEnd('.') ?: "MX"})"
        }
    }

    suspend fun analyzeEmailFootprint(
        email: String,
        mxHosts: List<String> = emptyList()
    ): Result<EmailFootprintReport> = withContext(Dispatchers.IO) {
        val clean = email.trim().lowercase()
        if (!clean.contains("@")) return@withContext Result.failure(Exception("Invalid email"))
        val localPart = clean.substringBefore("@")

        coroutineScope {
            val pgpDef = async { checkOpenPgpKey(clean) }
            val ghDef = async { searchGithubByEmail(clean) }
            val kbDef = async {
                if (localPart.length in 2..20 && localPart.all { it.isLetterOrDigit() || it == '_' }) {
                    fetchKeybaseIdentity(localPart).getOrNull()
                } else null
            }

            val (hasPgp, pgpSummary) = pgpDef.await()
            val ghUsers = ghDef.await()
            val kb = kbDef.await()

            Result.success(
                EmailFootprintReport(
                    email = clean,
                    mailProviderSuite = detectMailProviderSuite(mxHosts),
                    hasOpenPgpKey = hasPgp,
                    pgpKeySummary = pgpSummary,
                    githubMatchedUsers = ghUsers,
                    keybaseIdentity = kb
                )
            )
        }
    }

    suspend fun fetchGithubDeepProfile(username: String): Result<GithubDeepProfile> = withContext(Dispatchers.IO) {
        val clean = username.trim().removePrefix("@")
        if (clean.isBlank()) return@withContext Result.failure(Exception("Empty username"))
        val enc = URLEncoder.encode(clean, "UTF-8")

        try {
            coroutineScope {
                val userDef = async { fetchJson("https://api.github.com/users/$enc") }
                val eventsDef = async { fetchJson("https://api.github.com/users/$enc/events/public?per_page=30") }
                val orgsDef = async { fetchJson("https://api.github.com/users/$enc/orgs") }

                val userRaw = userDef.await() ?: return@coroutineScope Result.failure(Exception("GitHub user not found"))
                val eventsRaw = eventsDef.await()
                val orgsRaw = orgsDef.await()

                Result.success(parseGithubDeepJson(userRaw, eventsRaw, orgsRaw))
            }
        } catch (e: Exception) {
            Result.failure(Exception("GitHub profile lookup failed: ${e.message ?: "error"}"))
        }
    }

    internal fun parseGithubDeepJson(
        userJson: String,
        eventsJson: String?,
        orgsJson: String?
    ): GithubDeepProfile {
        val u = json.parseToJsonElement(userJson).jsonObject
        val login = u["login"]?.jsonPrimitive?.contentOrNull.orEmpty()
        val name = u["name"]?.jsonPrimitive?.contentOrNull?.takeIf { it != "null" }.orEmpty()
        val bio = u["bio"]?.jsonPrimitive?.contentOrNull?.takeIf { it != "null" }.orEmpty()
        val company = u["company"]?.jsonPrimitive?.contentOrNull?.takeIf { it != "null" }.orEmpty()
        val location = u["location"]?.jsonPrimitive?.contentOrNull?.takeIf { it != "null" }.orEmpty()
        val blog = u["blog"]?.jsonPrimitive?.contentOrNull?.takeIf { it != "null" }.orEmpty()
        val twitter = u["twitter_username"]?.jsonPrimitive?.contentOrNull?.takeIf { it != "null" }.orEmpty()
        val repos = u["public_repos"]?.jsonPrimitive?.intOrNull ?: 0
        val followers = u["followers"]?.jsonPrimitive?.intOrNull ?: 0
        val created = u["created_at"]?.jsonPrimitive?.contentOrNull?.take(10).orEmpty()
        val htmlUrl = u["html_url"]?.jsonPrimitive?.contentOrNull ?: "https://github.com/$login"

        val commitEmails = linkedSetOf<String>()
        val commitNames = linkedSetOf<String>()
        u["email"]?.jsonPrimitive?.contentOrNull?.takeIf { it.contains("@") && it != "null" }?.let {
            commitEmails.add(it.lowercase())
        }

        if (!eventsJson.isNullOrBlank()) {
            runCatching {
                val arr = json.parseToJsonElement(eventsJson).jsonArray
                for (ev in arr) {
                    val payload = ev.jsonObject["payload"] as? JsonObject ?: continue
                    val commits = payload["commits"]?.jsonArray ?: continue
                    for (c in commits) {
                        val author = c.jsonObject["author"] as? JsonObject ?: continue
                        val em = author["email"]?.jsonPrimitive?.contentOrNull?.trim()?.lowercase().orEmpty()
                        val nm = author["name"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
                        if (em.contains("@") && !em.contains("users.noreply.github.com")) {
                            commitEmails.add(em)
                        }
                        if (nm.isNotBlank() && nm.length <= 60) {
                            commitNames.add(nm)
                        }
                    }
                }
            }
        }

        val orgs = mutableListOf<String>()
        if (!orgsJson.isNullOrBlank()) {
            runCatching {
                json.parseToJsonElement(orgsJson).jsonArray.take(10).forEach { o ->
                    o.jsonObject["login"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }?.let {
                        orgs.add(it)
                    }
                }
            }
        }

        return GithubDeepProfile(
            username = login,
            displayName = name,
            bio = bio,
            company = company,
            location = location,
            blogUrl = blog,
            twitterHandle = twitter,
            publicRepos = repos,
            followers = followers,
            createdAt = created,
            profileUrl = htmlUrl,
            organizations = orgs,
            commitEmails = commitEmails.take(8),
            commitNames = commitNames.take(6)
        )
    }

    suspend fun fetchKeybaseIdentity(username: String): Result<KeybaseIdentity> = withContext(Dispatchers.IO) {
        val clean = username.trim().removePrefix("@").lowercase()
        if (clean.isBlank()) return@withContext Result.failure(Exception("Empty handle"))
        try {
            val enc = URLEncoder.encode(clean, "UTF-8")
            val raw = fetchJson("https://keybase.io/_/api/1.0/user/lookup.json?usernames=$enc")
                ?: return@withContext Result.failure(Exception("Keybase lookup unavailable"))
            val parsed = parseKeybaseJson(raw)
                ?: return@withContext Result.failure(Exception("No Keybase account for '$clean'"))
            Result.success(parsed)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    internal fun parseKeybaseJson(rawJson: String): KeybaseIdentity? {
        val root = runCatching { json.parseToJsonElement(rawJson).jsonObject }.getOrNull() ?: return null
        val them = root["them"]?.jsonArray?.firstOrNull() as? JsonObject ?: return null
        val basics = them["basics"] as? JsonObject ?: return null
        val username = basics["username"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() } ?: return null
        val profile = them["profile"] as? JsonObject
        val fullName = profile?.get("full_name")?.jsonPrimitive?.contentOrNull.orEmpty()
        val bio = profile?.get("bio")?.jsonPrimitive?.contentOrNull.orEmpty()
        val location = profile?.get("location")?.jsonPrimitive?.contentOrNull.orEmpty()

        val pgpFp = (them["public_keys"] as? JsonObject)
            ?.get("primary")?.let { it as? JsonObject }
            ?.get("key_fingerprint")?.jsonPrimitive?.contentOrNull.orEmpty()

        val proofs = mutableListOf<Pair<String, String>>()
        (them["proofs_summary"] as? JsonObject)?.get("all")?.jsonArray?.forEach { p ->
            val po = p.jsonObject
            val pType = po["proof_type"]?.jsonPrimitive?.contentOrNull.orEmpty()
            val pNam = po["nametag"]?.jsonPrimitive?.contentOrNull.orEmpty()
            if (pType.isNotBlank() && pNam.isNotBlank()) {
                proofs.add(pType to pNam)
            }
        }

        return KeybaseIdentity(
            username = username,
            fullName = fullName,
            bio = bio,
            location = location,
            pgpFingerprint = pgpFp,
            verifiedProofs = proofs.take(12)
        )
    }

    /**
     * Real multi-source zero-key entity search for Person Names, Companies, Brands, or Keywords.
     */
    suspend fun searchEntityMentions(query: String): Result<EntitySearchReport> = withContext(Dispatchers.IO) {
        val clean = query.trim()
        if (clean.isBlank()) return@withContext Result.failure(Exception("Empty search query"))
        val enc = URLEncoder.encode(clean, "UTF-8")

        coroutineScope {
            val wikiDef = async { fetchWikipediaSummary(clean) }
            val ghDef = async { searchGithubUsers(enc) }
            val hnDef = async { searchHackerNews(enc) }
            val redditDef = async { searchRedditMentions(enc) }

            val (wikiTitle, wikiSummary, wikiUrl) = wikiDef.await()
            val ghProfiles = ghDef.await()
            val mentions = buildList {
                addAll(hnDef.await())
                addAll(redditDef.await())
            }
            val topHandle = ghProfiles.firstOrNull()?.title?.removePrefix("@")

            Result.success(
                EntitySearchReport(
                    query = clean,
                    wikiTitle = wikiTitle,
                    wikiSummary = wikiSummary,
                    wikiUrl = wikiUrl,
                    githubProfiles = ghProfiles,
                    webMentions = mentions,
                    topHandleCandidate = topHandle
                )
            )
        }
    }

    private fun checkOpenPgpKey(email: String): Pair<Boolean, String> {
        return try {
            val enc = URLEncoder.encode(email, "UTF-8")
            val req = Request.Builder()
                .url("https://keys.openpgp.org/vks/v1/by-email/$enc")
                .header("Accept", "application/pgp-keys,text/plain")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val body = resp.body?.string().orEmpty()
                    if (body.contains("BEGIN PGP PUBLIC KEY BLOCK")) {
                        true to "Verified public PGP key published on keys.openpgp.org (${body.length} bytes)"
                    } else {
                        false to "No public PGP key"
                    }
                } else {
                    false to "No public PGP key on keys.openpgp.org"
                }
            }
        } catch (_: Exception) {
            false to "OpenPGP lookup unavailable"
        }
    }

    private fun searchGithubByEmail(email: String): List<String> {
        val enc = URLEncoder.encode("$email in:email", "UTF-8")
        val raw = fetchJson("https://api.github.com/search/users?q=$enc&per_page=5") ?: return emptyList()
        return runCatching {
            json.parseToJsonElement(raw).jsonObject["items"]?.jsonArray?.mapNotNull {
                it.jsonObject["login"]?.jsonPrimitive?.contentOrNull
            }.orEmpty()
        }.getOrDefault(emptyList())
    }

    private fun searchGithubUsers(encodedQuery: String): List<EntityMention> {
        val raw = fetchJson("https://api.github.com/search/users?q=$encodedQuery&per_page=6") ?: return emptyList()
        return runCatching {
            json.parseToJsonElement(raw).jsonObject["items"]?.jsonArray?.mapNotNull { el ->
                val obj = el.jsonObject
                val login = obj["login"]?.jsonPrimitive?.contentOrNull ?: return@mapNotNull null
                val type = obj["type"]?.jsonPrimitive?.contentOrNull ?: "User"
                val url = obj["html_url"]?.jsonPrimitive?.contentOrNull ?: "https://github.com/$login"
                EntityMention(source = "GitHub $type", title = "@$login", subtitle = url, url = url)
            }.orEmpty()
        }.getOrDefault(emptyList())
    }

    private fun fetchWikipediaSummary(query: String): Triple<String, String, String> {
        return try {
            val slug = URLEncoder.encode(query.replace(" ", "_"), "UTF-8")
            val direct = fetchJson("https://en.wikipedia.org/api/rest_v1/page/summary/$slug")
            val raw = direct ?: run {
                val searchRaw = fetchJson(
                    "https://en.wikipedia.org/w/api.php?action=opensearch&search=${URLEncoder.encode(query, "UTF-8")}&limit=1&format=json"
                ) ?: return Triple("", "", "")
                val arr = json.parseToJsonElement(searchRaw).jsonArray
                val firstTitle = arr.getOrNull(1)?.jsonArray?.firstOrNull()?.jsonPrimitive?.contentOrNull ?: return Triple("", "", "")
                fetchJson("https://en.wikipedia.org/api/rest_v1/page/summary/${URLEncoder.encode(firstTitle.replace(" ", "_"), "UTF-8")}")
            } ?: return Triple("", "", "")

            val obj = json.parseToJsonElement(raw).jsonObject
            val title = obj["title"]?.jsonPrimitive?.contentOrNull.orEmpty()
            val extract = obj["extract"]?.jsonPrimitive?.contentOrNull.orEmpty()
            val url = (obj["content_urls"] as? JsonObject)
                ?.get("desktop")?.let { it as? JsonObject }
                ?.get("page")?.jsonPrimitive?.contentOrNull.orEmpty()
            Triple(title, extract.take(420), url)
        } catch (_: Exception) {
            Triple("", "", "")
        }
    }

    private fun searchHackerNews(encodedQuery: String): List<EntityMention> {
        val raw = fetchJson("https://hn.algolia.com/api/v1/search?query=$encodedQuery&hitsPerPage=5") ?: return emptyList()
        return runCatching {
            json.parseToJsonElement(raw).jsonObject["hits"]?.jsonArray?.mapNotNull { el ->
                val obj = el.jsonObject
                val title = obj["title"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                val author = obj["author"]?.jsonPrimitive?.contentOrNull.orEmpty()
                val points = obj["points"]?.jsonPrimitive?.intOrNull ?: 0
                val objectId = obj["objectID"]?.jsonPrimitive?.contentOrNull.orEmpty()
                val url = obj["url"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }
                    ?: "https://news.ycombinator.com/item?id=$objectId"
                EntityMention("HackerNews", title, "by $author • $points pts", url)
            }.orEmpty()
        }.getOrDefault(emptyList())
    }

    private fun searchRedditMentions(encodedQuery: String): List<EntityMention> {
        val raw = fetchJson("https://www.reddit.com/search.json?q=$encodedQuery&limit=5&sort=relevance") ?: return emptyList()
        return runCatching {
            val data = json.parseToJsonElement(raw).jsonObject["data"] as? JsonObject ?: return emptyList()
            data["children"]?.jsonArray?.mapNotNull { child ->
                val post = child.jsonObject["data"] as? JsonObject ?: return@mapNotNull null
                val title = post["title"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                val sub = post["subreddit_name_prefixed"]?.jsonPrimitive?.contentOrNull.orEmpty()
                val permalink = post["permalink"]?.jsonPrimitive?.contentOrNull.orEmpty()
                EntityMention("Reddit $sub", title, "Public discussion", "https://www.reddit.com$permalink")
            }.orEmpty()
        }.getOrDefault(emptyList())
    }

    private fun fetchJson(url: String): String? {
        return try {
            val req = Request.Builder()
                .url(url)
                .header("Accept", "application/json,application/vnd.github+json")
                .header("User-Agent", "OSINTme/4.0 (Android Passive OSINT Workbench)")
                .get()
                .build()
            OsintApiClient.client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return null
                resp.body?.string()?.trim()?.takeIf { it.isNotEmpty() }
            }
        } catch (_: Exception) {
            null
        }
    }
}
