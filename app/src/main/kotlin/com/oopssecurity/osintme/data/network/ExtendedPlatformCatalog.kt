package com.oopssecurity.osintme.data.network

import org.json.JSONArray
import org.json.JSONObject

/**
 * Extended Maigret / Sherlock-class OSINT platform catalog (62+ additional verified sites),
 * merged with PlatformReconService to deliver 106+ live concurrent zero-key platform probes
 * with rich bio, display-name, stats, and cross-link extraction.
 */
object ExtendedPlatformCatalog {

    val PLATFORMS: List<PlatformDefinition> = listOf(
        // ---- Security, Bug Bounty & CTF ----
        PlatformDefinition(
            name = "HackerOne",
            checkUrlTemplate = "https://hackerone.com/%s",
            profileUrlTemplate = "https://hackerone.com/%s",
            category = "Security",
            probeType = ProbeType.BODY_DOES_NOT_CONTAIN,
            expectedPattern = "Page not found"
        ),
        PlatformDefinition(
            name = "Bugcrowd",
            checkUrlTemplate = "https://bugcrowd.com/%s",
            profileUrlTemplate = "https://bugcrowd.com/%s",
            category = "Security",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "TryHackMe",
            checkUrlTemplate = "https://tryhackme.com/api/user/exist/%s",
            profileUrlTemplate = "https://tryhackme.com/p/%s",
            category = "Security",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"success\":true"
        ),
        PlatformDefinition(
            name = "RootMe",
            checkUrlTemplate = "https://www.root-me.org/%s",
            profileUrlTemplate = "https://www.root-me.org/%s",
            category = "Security",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Intigriti",
            checkUrlTemplate = "https://app.intigriti.com/profile/%s",
            profileUrlTemplate = "https://app.intigriti.com/profile/%s",
            category = "Security",
            probeType = ProbeType.BODY_DOES_NOT_CONTAIN,
            expectedPattern = "not found"
        ),
        PlatformDefinition(
            name = "ExploitDB",
            checkUrlTemplate = "https://www.exploit-db.com/author/?a=%s",
            profileUrlTemplate = "https://www.exploit-db.com/author/?a=%s",
            category = "Security",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "Exploits"
        ),

        // ---- Developer, Code & Package Registries ----
        PlatformDefinition(
            name = "Bitbucket",
            checkUrlTemplate = "https://api.bitbucket.org/2.0/users/%s",
            profileUrlTemplate = "https://bitbucket.org/%s/",
            category = "Development",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "display_name",
            metadataExtractor = { body ->
                runCatching { JSONObject(body).optString("display_name", "").ifBlank { null } }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Codeberg",
            checkUrlTemplate = "https://codeberg.org/api/v1/users/%s",
            profileUrlTemplate = "https://codeberg.org/%s",
            category = "Development",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "login",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    listOf(j.optString("full_name", ""), j.optString("location", ""))
                        .filter { it.isNotBlank() }.joinToString(" • ").ifBlank { null }
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "SourceForge",
            checkUrlTemplate = "https://sourceforge.net/u/%s/profile/",
            profileUrlTemplate = "https://sourceforge.net/u/%s/profile/",
            category = "Development",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Launchpad",
            checkUrlTemplate = "https://api.launchpad.net/1.0/~%s",
            profileUrlTemplate = "https://launchpad.net/~%s",
            category = "Development",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "display_name",
            metadataExtractor = { body ->
                runCatching { JSONObject(body).optString("display_name", "").ifBlank { null } }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "GitHub Gist",
            checkUrlTemplate = "https://gist.github.com/%s",
            profileUrlTemplate = "https://gist.github.com/%s",
            category = "Development",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "CodePen",
            checkUrlTemplate = "https://codepen.io/%s",
            profileUrlTemplate = "https://codepen.io/%s",
            category = "Development",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "CodeSandbox",
            checkUrlTemplate = "https://codesandbox.io/u/%s",
            profileUrlTemplate = "https://codesandbox.io/u/%s",
            category = "Development",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Glitch",
            checkUrlTemplate = "https://glitch.com/@%s",
            profileUrlTemplate = "https://glitch.com/@%s",
            category = "Development",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Hashnode",
            checkUrlTemplate = "https://hashnode.com/@%s",
            profileUrlTemplate = "https://hashnode.com/@%s",
            category = "Development",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Packagist",
            checkUrlTemplate = "https://packagist.org/users/%s/",
            profileUrlTemplate = "https://packagist.org/users/%s/",
            category = "Packages",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "NuGet",
            checkUrlTemplate = "https://www.nuget.org/profiles/%s",
            profileUrlTemplate = "https://www.nuget.org/profiles/%s",
            category = "Packages",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "CPAN / MetaCPAN",
            checkUrlTemplate = "https://fastapi.metacpan.org/v1/author/%s",
            profileUrlTemplate = "https://metacpan.org/author/%s",
            category = "Packages",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "pauseid",
            metadataExtractor = { body ->
                runCatching { JSONObject(body).optString("name", "").ifBlank { null } }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "WakaTime",
            checkUrlTemplate = "https://wakatime.com/@%s",
            profileUrlTemplate = "https://wakatime.com/@%s",
            category = "Development",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Codewars",
            checkUrlTemplate = "https://www.codewars.com/api/v1/users/%s",
            profileUrlTemplate = "https://www.codewars.com/users/%s",
            category = "Competitive Coding",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "username",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    val honor = j.optInt("honor", 0)
                    val clan = j.optString("clan", "").ifBlank { null }
                    listOfNotNull("Honor: $honor", clan).joinToString(" • ")
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "HackerRank",
            checkUrlTemplate = "https://www.hackerrank.com/rest/contests/master/hackers/%s/profile",
            profileUrlTemplate = "https://www.hackerrank.com/profile/%s",
            category = "Competitive Coding",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"model\":{",
            metadataExtractor = { body ->
                runCatching {
                    val m = JSONObject(body).optJSONObject("model") ?: return@runCatching null
                    listOf(m.optString("name", ""), m.optString("country", ""))
                        .filter { it.isNotBlank() && it != "null" }.joinToString(" • ").ifBlank { null }
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "AtCoder",
            checkUrlTemplate = "https://atcoder.jp/users/%s",
            profileUrlTemplate = "https://atcoder.jp/users/%s",
            category = "Competitive Coding",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Exercism",
            checkUrlTemplate = "https://exercism.org/profiles/%s",
            profileUrlTemplate = "https://exercism.org/profiles/%s",
            category = "Competitive Coding",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Lobsters",
            checkUrlTemplate = "https://lobste.rs/u/%s.json",
            profileUrlTemplate = "https://lobste.rs/u/%s",
            category = "Tech News",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "username",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    val karma = j.optInt("karma", 0)
                    val about = j.optString("about", "").take(70).ifBlank { null }
                    listOfNotNull("Karma: $karma", about).joinToString(" • ")
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "StackExchange",
            checkUrlTemplate = "https://api.stackexchange.com/2.3/users?inname=%s&site=stackoverflow&pagesize=1",
            profileUrlTemplate = "https://stackoverflow.com/users?tab=users&filter=%s",
            category = "Development",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"user_id\"",
            metadataExtractor = { body ->
                runCatching {
                    val items = JSONObject(body).optJSONArray("items") ?: return@runCatching null
                    if (items.length() > 0) {
                        val u = items.getJSONObject(0)
                        "${u.optString("display_name")} • Rep ${u.optInt("reputation")}"
                    } else null
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "npm Author",
            checkUrlTemplate = "https://registry.npmjs.org/-/v1/search?text=maintainer:%s&size=1",
            profileUrlTemplate = "https://www.npmjs.com/~%s",
            category = "Packages",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"package\"",
            metadataExtractor = { body ->
                runCatching {
                    val total = JSONObject(body).optInt("total", 0)
                    if (total > 0) "$total public packages" else null
                }.getOrNull()
            }
        ),

        // ---- Social, Identity & Link Hubs ----
        PlatformDefinition(
            name = "About.me",
            checkUrlTemplate = "https://about.me/%s",
            profileUrlTemplate = "https://about.me/%s",
            category = "Identity",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Bento.me",
            checkUrlTemplate = "https://bento.me/%s",
            profileUrlTemplate = "https://bento.me/%s",
            category = "Identity",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Bio.link",
            checkUrlTemplate = "https://bio.link/%s",
            profileUrlTemplate = "https://bio.link/%s",
            category = "Identity",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Carrd",
            checkUrlTemplate = "https://%s.carrd.co",
            profileUrlTemplate = "https://%s.carrd.co",
            category = "Identity",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Tumblr",
            checkUrlTemplate = "https://%s.tumblr.com",
            profileUrlTemplate = "https://%s.tumblr.com",
            category = "Social",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "VK",
            checkUrlTemplate = "https://vk.com/%s",
            profileUrlTemplate = "https://vk.com/%s",
            category = "Social",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "TikTok",
            checkUrlTemplate = "https://www.tiktok.com/@%s",
            profileUrlTemplate = "https://www.tiktok.com/@%s",
            category = "Social",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"uniqueId\""
        ),
        PlatformDefinition(
            name = "Snapchat",
            checkUrlTemplate = "https://www.snapchat.com/add/%s",
            profileUrlTemplate = "https://www.snapchat.com/add/%s",
            category = "Social",
            probeType = ProbeType.BODY_DOES_NOT_CONTAIN,
            expectedPattern = "Sorry, couldn't find"
        ),
        PlatformDefinition(
            name = "Quora",
            checkUrlTemplate = "https://www.quora.com/profile/%s",
            profileUrlTemplate = "https://www.quora.com/profile/%s",
            category = "Community",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "SlideShare",
            checkUrlTemplate = "https://www.slideshare.net/%s",
            profileUrlTemplate = "https://www.slideshare.net/%s",
            category = "Professional",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "SpeakerDeck",
            checkUrlTemplate = "https://speakerdeck.com/%s",
            profileUrlTemplate = "https://speakerdeck.com/%s",
            category = "Professional",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Polywork",
            checkUrlTemplate = "https://www.polywork.com/%s",
            profileUrlTemplate = "https://www.polywork.com/%s",
            category = "Professional",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Fiverr",
            checkUrlTemplate = "https://www.fiverr.com/%s",
            profileUrlTemplate = "https://www.fiverr.com/%s",
            category = "Freelance",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Patreon",
            checkUrlTemplate = "https://www.patreon.com/%s",
            profileUrlTemplate = "https://www.patreon.com/%s",
            category = "Crowdfunding",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Ko-fi",
            checkUrlTemplate = "https://ko-fi.com/%s",
            profileUrlTemplate = "https://ko-fi.com/%s",
            category = "Crowdfunding",
            probeType = ProbeType.STATUS_CODE
        ),

        // ---- Gaming & Esports ----
        PlatformDefinition(
            name = "Minecraft (Ashcon)",
            checkUrlTemplate = "https://api.ashcon.app/mojang/v2/user/%s",
            profileUrlTemplate = "https://namemc.com/profile/%s",
            category = "Gaming",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "uuid",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    "UUID: ${j.optString("uuid", "").take(13)}…"
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Roblox",
            checkUrlTemplate = "https://users.roblox.com/v1/users/search?keyword=%s&limit=10",
            profileUrlTemplate = "https://www.roblox.com/search/users?keyword=%s",
            category = "Gaming",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"displayName\"",
            metadataExtractor = { body ->
                runCatching {
                    val arr = JSONObject(body).optJSONArray("data") ?: return@runCatching null
                    if (arr.length() > 0) arr.getJSONObject(0).optString("displayName") else null
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Speedrun.com",
            checkUrlTemplate = "https://www.speedrun.com/api/v1/users/%s",
            profileUrlTemplate = "https://www.speedrun.com/users/%s",
            category = "Gaming",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"weblink\"",
            metadataExtractor = { body ->
                runCatching {
                    val d = JSONObject(body).optJSONObject("data") ?: return@runCatching null
                    d.optJSONObject("names")?.optString("international")
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "MyAnimeList",
            checkUrlTemplate = "https://api.jikan.moe/v4/users/%s",
            profileUrlTemplate = "https://myanimelist.net/profile/%s",
            category = "Community",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"mal_id\"",
            metadataExtractor = { body ->
                runCatching {
                    val d = JSONObject(body).optJSONObject("data") ?: return@runCatching null
                    val loc = d.optString("location", "").takeIf { it.isNotBlank() && it != "null" }
                    val joined = d.optString("joined", "").take(10).ifBlank { null }
                    listOfNotNull(loc, joined?.let { "Joined $it" }).joinToString(" • ").ifBlank { null }
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "AniList",
            checkUrlTemplate = "https://anilist.co/user/%s",
            profileUrlTemplate = "https://anilist.co/user/%s",
            category = "Community",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Letterboxd",
            checkUrlTemplate = "https://letterboxd.com/%s/",
            profileUrlTemplate = "https://letterboxd.com/%s/",
            category = "Media",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Goodreads",
            checkUrlTemplate = "https://www.goodreads.com/%s",
            profileUrlTemplate = "https://www.goodreads.com/%s",
            category = "Media",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Duolingo",
            checkUrlTemplate = "https://www.duolingo.com/2017-06-30/users?username=%s",
            profileUrlTemplate = "https://www.duolingo.com/profile/%s",
            category = "Learning",
            probeType = ProbeType.BODY_CONTAINS,
            expectedPattern = "\"streak\"",
            metadataExtractor = { body ->
                runCatching {
                    val users = JSONObject(body).optJSONArray("users") ?: return@runCatching null
                    if (users.length() > 0) {
                        val u = users.getJSONObject(0)
                        val name = u.optString("name", "").ifBlank { null }
                        val xp = u.optInt("totalXp", 0)
                        listOfNotNull(name, "$xp XP").joinToString(" • ")
                    } else null
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "osu!",
            checkUrlTemplate = "https://osu.ppy.sh/users/%s",
            profileUrlTemplate = "https://osu.ppy.sh/users/%s",
            category = "Gaming",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Trackmania.io",
            checkUrlTemplate = "https://trackmania.io/#/player/%s",
            profileUrlTemplate = "https://trackmania.io/#/player/%s",
            category = "Gaming",
            probeType = ProbeType.STATUS_CODE
        ),

        // ---- Creative, Design, Audio & Video ----
        PlatformDefinition(
            name = "DeviantArt",
            checkUrlTemplate = "https://www.deviantart.com/%s",
            profileUrlTemplate = "https://www.deviantart.com/%s",
            category = "Design",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Unsplash",
            checkUrlTemplate = "https://unsplash.com/@%s",
            profileUrlTemplate = "https://unsplash.com/@%s",
            category = "Photography",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "500px",
            checkUrlTemplate = "https://500px.com/p/%s",
            profileUrlTemplate = "https://500px.com/p/%s",
            category = "Photography",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "ArtStation",
            checkUrlTemplate = "https://www.artstation.com/%s",
            profileUrlTemplate = "https://www.artstation.com/%s",
            category = "Design",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Last.fm",
            checkUrlTemplate = "https://www.last.fm/user/%s",
            profileUrlTemplate = "https://www.last.fm/user/%s",
            category = "Music",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Mixcloud",
            checkUrlTemplate = "https://api.mixcloud.com/%s/",
            profileUrlTemplate = "https://www.mixcloud.com/%s/",
            category = "Music",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "username",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    listOf(j.optString("name", ""), j.optString("city", ""))
                        .filter { it.isNotBlank() }.joinToString(" • ").ifBlank { null }
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Dailymotion",
            checkUrlTemplate = "https://api.dailymotion.com/user/%s?fields=screenname,followers_total",
            profileUrlTemplate = "https://www.dailymotion.com/%s",
            category = "Video",
            probeType = ProbeType.JSON_FIELD,
            expectedPattern = "screenname",
            metadataExtractor = { body ->
                runCatching {
                    val j = JSONObject(body)
                    "${j.optString("screenname")} • ${j.optInt("followers_total")} followers"
                }.getOrNull()
            }
        ),
        PlatformDefinition(
            name = "Rumble",
            checkUrlTemplate = "https://rumble.com/user/%s",
            profileUrlTemplate = "https://rumble.com/user/%s",
            category = "Video",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Archive.org",
            checkUrlTemplate = "https://archive.org/details/@%s",
            profileUrlTemplate = "https://archive.org/details/@%s",
            category = "Archives",
            probeType = ProbeType.BODY_DOES_NOT_CONTAIN,
            expectedPattern = "Cannot find account"
        ),
        PlatformDefinition(
            name = "OpenStreetMap",
            checkUrlTemplate = "https://www.openstreetmap.org/user/%s",
            profileUrlTemplate = "https://www.openstreetmap.org/user/%s",
            category = "Geo / Maps",
            probeType = ProbeType.STATUS_CODE
        ),
        PlatformDefinition(
            name = "Instructables",
            checkUrlTemplate = "https://www.instructables.com/member/%s/",
            profileUrlTemplate = "https://www.instructables.com/member/%s/",
            category = "Maker",
            probeType = ProbeType.STATUS_CODE
        )
    )
}
