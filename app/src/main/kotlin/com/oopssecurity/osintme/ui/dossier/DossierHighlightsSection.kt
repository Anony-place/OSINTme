package com.oopssecurity.osintme.ui.dossier

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.AlternateEmail
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.network.DeepWebCrawlReport
import com.oopssecurity.osintme.data.network.EmailFootprintReport
import com.oopssecurity.osintme.data.network.EntitySearchReport
import com.oopssecurity.osintme.data.network.GithubDeepProfile
import com.oopssecurity.osintme.data.network.KeybaseIdentity
import com.oopssecurity.osintme.data.network.OtxThreatReport
import com.oopssecurity.osintme.data.network.TakeoverScanSummary
import com.oopssecurity.osintme.data.network.TakeoverSeverity
import com.oopssecurity.osintme.data.network.TlsCertReport
import com.oopssecurity.osintme.data.network.WaybackReport
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.EmeraldBorder
import com.oopssecurity.osintme.ui.theme.EmeraldDeep
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.EmeraldSoft
import com.oopssecurity.osintme.ui.theme.InkBlack
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType
import com.oopssecurity.osintme.util.SafeBrowserLauncher

/**
 * Executive Intelligence Highlights board shown right at the top of the Universal Target Dossier
 * so users immediately see real extracted identities, emails, social profiles, analytics IDs,
 * open ports, subdomains, OTX pulses, Wayback hits, and Stage-2 Auto-Chained discoveries.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun IntelligenceHighlightsCard(
    uiState: TargetDossierUiState,
    onPivot: (PivotEntity) -> Unit
) {
    val metrics = buildList {
        val totalSubs = (uiState.subdomains?.totalCount ?: 0) +
            (uiState.waybackReport?.discoveredHosts?.size ?: 0) +
            (uiState.otxReport?.passiveDnsHosts?.size ?: 0)
        if (totalSubs > 0) add("HOSTS" to "$totalSubs")
        val emailsCount = (uiState.deepWebCrawl?.emails?.size ?: 0) +
            (uiState.githubProfile?.commitEmails?.size ?: 0)
        if (emailsCount > 0) add("EMAILS" to "$emailsCount")
        val profilesCount = uiState.usernameHits.size + (uiState.deepWebCrawl?.socialLinks?.size ?: 0)
        if (profilesCount > 0) add("PROFILES" to "$profilesCount")
        val portsCount = uiState.ipRecon?.ports?.size ?: 0
        if (portsCount > 0) add("PORTS" to "$portsCount")
        val waybackCount = uiState.waybackReport?.snapshots?.size ?: 0
        if (waybackCount > 0) add("ARCHIVES" to "$waybackCount")
        val otxPulses = uiState.otxReport?.pulseCount ?: 0
        if (otxPulses > 0) add("OTX PULSES" to "$otxPulses")
        val apiPaths = uiState.deepWebCrawl?.apiEndpoints?.size ?: 0
        if (apiPaths > 0) add("API PATHS" to "$apiPaths")
        val tracking = uiState.deepWebCrawl?.trackingIds?.size ?: 0
        if (tracking > 0) add("TRACKERS" to "$tracking")
    }

    val realIdentityName = listOfNotNull(
        uiState.githubProfile?.displayName?.takeIf { it.isNotBlank() },
        uiState.keybaseIdentity?.fullName?.takeIf { it.isNotBlank() },
        uiState.gravatar?.displayName?.takeIf { it.isNotBlank() },
        uiState.entitySearch?.wikiTitle?.takeIf { it.isNotBlank() },
        uiState.deepWebCrawl?.metaAuthorOrOrg?.takeIf { it.isNotBlank() }
    ).firstOrNull()

    val foundEmails = buildList {
        uiState.githubProfile?.commitEmails?.forEach { add(it) }
        uiState.deepWebCrawl?.emails?.forEach { add(it) }
    }.distinct().take(6)

    if (metrics.isEmpty() && realIdentityName == null && foundEmails.isEmpty() && uiState.autoChainNotes.isEmpty()) {
        return
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = InkBlack),
        border = BorderStroke(1.dp, InkBlack),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "INTELLIGENCE HIGHLIGHTS",
                    color = EmeraldBorder,
                    fontSize = 10.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "ZERO-KEY DEEP ENGINE",
                    color = PureWhite.copy(alpha = 0.65f),
                    fontSize = 9.sp,
                    fontFamily = MonoFontFamily
                )
            }

            if (realIdentityName != null) {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = realIdentityName,
                    color = PureWhite,
                    fontSize = 17.sp,
                    fontFamily = DisplayFontFamily,
                    fontWeight = FontWeight.Bold
                )
                val subtitle = listOfNotNull(
                    uiState.githubProfile?.company?.takeIf { it.isNotBlank() },
                    uiState.githubProfile?.location?.takeIf { it.isNotBlank() },
                    uiState.ipRecon?.org?.takeIf { it.isNotBlank() },
                    uiState.emailFootprint?.mailProviderSuite?.takeIf { it.isNotBlank() && it != "No MX Records" }
                ).distinct().joinToString(" • ")
                if (subtitle.isNotBlank()) {
                    Text(
                        text = subtitle,
                        color = PureWhite.copy(alpha = 0.78f),
                        fontSize = 12.sp
                    )
                }
            }

            if (metrics.isNotEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    metrics.forEach { (label, count) ->
                        Column(
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .background(PureWhite.copy(alpha = 0.09f))
                                .border(1.dp, PureWhite.copy(alpha = 0.16f), RoundedCornerShape(8.dp))
                                .padding(horizontal = 10.dp, vertical = 6.dp)
                        ) {
                            Text(
                                text = count,
                                color = EmeraldBorder,
                                fontSize = 15.sp,
                                fontFamily = MonoFontFamily,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = label,
                                color = PureWhite.copy(alpha = 0.75f),
                                fontSize = 9.sp,
                                fontFamily = MonoFontFamily
                            )
                        }
                    }
                }
            }

            if (foundEmails.isNotEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "HARVESTED EMAILS (TAP TO PIVOT)",
                    color = PureWhite.copy(alpha = 0.65f),
                    fontSize = 9.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(5.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    foundEmails.forEach { em ->
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(EmeraldPrimary.copy(alpha = 0.22f))
                                .border(1.dp, EmeraldPrimary.copy(alpha = 0.6f), RoundedCornerShape(6.dp))
                                .clickable { onPivot(PivotEngine.normalize(em, PivotEntityType.EMAIL, "Harvested Email")) }
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = em,
                                color = PureWhite,
                                fontSize = 11.sp,
                                fontFamily = MonoFontFamily
                            )
                        }
                    }
                }
            }

            if (uiState.autoChainNotes.isNotEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                HorizontalDivider(color = PureWhite.copy(alpha = 0.14f))
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "STAGE-2 AUTO-CHAINED ENRICHMENT",
                    color = EmeraldBorder,
                    fontSize = 9.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(4.dp))
                uiState.autoChainNotes.take(4).forEach { note ->
                    Text(
                        text = "↳ $note",
                        color = PureWhite.copy(alpha = 0.85f),
                        fontSize = 11.sp,
                        fontFamily = MonoFontFamily
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun DeepWebCrawlCard(
    crawl: DeepWebCrawlReport,
    onPivot: (PivotEntity) -> Unit
) {
    val context = LocalContext.current
    IntelSurfaceCard(
        title = "DEEP WEB & JS SCRAPER (${crawl.jsFilesScanned} JS BUNDLES)",
        icon = Icons.Default.Code,
        accent = EmeraldPrimary
    ) {
        if (crawl.metaDescription.isNotBlank()) {
            Text(crawl.metaDescription, color = SlateGrey, fontSize = 12.sp, lineHeight = 17.sp)
            Spacer(modifier = Modifier.height(8.dp))
        }

        if (crawl.emails.isNotEmpty()) {
            MiniSectionHeader("EXPOSED EMAILS (${crawl.emails.size})")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                crawl.emails.take(10).forEach { email ->
                    InteractiveTagChip(
                        text = email,
                        bg = EmeraldSoft,
                        border = EmeraldBorder,
                        fg = EmeraldDeep,
                        onClick = { onPivot(PivotEngine.normalize(email, PivotEntityType.EMAIL, "Web/JS Scraper")) }
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        if (crawl.socialLinks.isNotEmpty()) {
            MiniSectionHeader("LINKED SOCIAL PROFILES (${crawl.socialLinks.size})")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                crawl.socialLinks.take(10).forEach { link ->
                    InteractiveTagChip(
                        text = "${link.platform}: @${link.handle}",
                        bg = SurfaceElevated,
                        border = CardBorder,
                        fg = InkBlack,
                        onClick = {
                            SafeBrowserLauncher.openExternalUrl(context, link.url)
                        }
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        if (crawl.trackingIds.isNotEmpty()) {
            MiniSectionHeader("ANALYTICS & OWNERSHIP TRACKING IDS")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                crawl.trackingIds.forEach { hit ->
                    InteractiveTagChip(
                        text = "${hit.provider}: ${hit.id}",
                        bg = SurfaceElevated,
                        border = CardBorder,
                        fg = InkBlack,
                        onClick = { onPivot(PivotEngine.normalize(hit.id, sourceContext = "Tracking ID")) }
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        if (crawl.apiEndpoints.isNotEmpty()) {
            MiniSectionHeader("DISCOVERED API & HIDDEN ENDPOINTS (${crawl.apiEndpoints.size})")
            crawl.apiEndpoints.take(8).forEach { path ->
                Text("• $path", color = InkBlack, fontSize = 11.sp, fontFamily = MonoFontFamily)
            }
            Spacer(modifier = Modifier.height(6.dp))
        }

        if (crawl.cloudBuckets.isNotEmpty()) {
            MiniSectionHeader("CLOUD STORAGE BUCKETS (${crawl.cloudBuckets.size})")
            crawl.cloudBuckets.take(6).forEach { bucket ->
                Text(
                    text = "• $bucket",
                    color = StatusWarning,
                    fontSize = 11.sp,
                    fontFamily = MonoFontFamily,
                    modifier = Modifier.clickable {
                        onPivot(PivotEngine.normalize(bucket, PivotEntityType.DOMAIN, "Cloud Bucket Ref"))
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun OtxAndWaybackCard(
    otx: OtxThreatReport?,
    wayback: WaybackReport?,
    onPivot: (PivotEntity) -> Unit
) {
    val context = LocalContext.current
    IntelSurfaceCard(
        title = "ALIENVAULT OTX & WAYBACK ARCHIVE",
        icon = Icons.Default.Timeline,
        accent = if ((otx?.pulseCount ?: 0) > 0) StatusRisk else EmeraldPrimary
    ) {
        otx?.let { report ->
            MiniSectionHeader("ALIENVAULT OTX THREAT PULSES (${report.pulseCount})")
            Text(
                text = if (report.pulseCount > 0) {
                    "${report.pulseCount} threat pulse(s) • Tags: ${report.tags.take(6).joinToString(", ").ifBlank { "General" }}"
                } else {
                    "Zero malicious OTX threat pulses • Passive DNS hosts: ${report.passiveDnsHosts.size}"
                },
                color = if (report.pulseCount > 0) StatusRisk else EmeraldDeep,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold
            )
            report.pulses.take(3).forEach { p ->
                Text("• [${p.created}] ${p.name}", color = SlateGrey, fontSize = 11.sp, fontFamily = MonoFontFamily)
            }
            if (report.passiveDnsHosts.isNotEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    report.passiveDnsHosts.take(8).forEach { h ->
                        InteractiveTagChip(
                            text = h,
                            bg = SurfaceElevated,
                            border = CardBorder,
                            fg = InkBlack,
                            onClick = { onPivot(PivotEngine.normalize(h, sourceContext = "OTX Passive DNS")) }
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(10.dp))
        }

        wayback?.let { wb ->
            MiniSectionHeader("WAYBACK CDX ARCHIVE (${wb.snapshots.size} SNAPSHOTS)")
            Text(
                text = "Sensitive: ${wb.sensitiveCount} • Docs: ${wb.documentCount} • Deleted/4xx: ${wb.deletedCount}" +
                    (if (wb.earliestYear != null) " • Span ${wb.earliestYear}–${wb.latestYear}" else ""),
                color = if (wb.sensitiveCount > 0) StatusWarning else SlateGrey,
                fontSize = 11.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(modifier = Modifier.height(4.dp))
            wb.snapshots.take(5).forEach { snap ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            SafeBrowserLauncher.openExternalUrl(context, snap.archiveUrl)
                        }
                        .padding(vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "[${snap.category.label.uppercase()}] ",
                        color = if (snap.category.name == "SENSITIVE") StatusRisk else EmeraldDeep,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = snap.originalUrl,
                        color = InkBlack,
                        fontSize = 11.sp,
                        fontFamily = MonoFontFamily,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = "Open archive", tint = MutedSlate, modifier = Modifier.size(13.dp))
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun LiveTlsAndTakeoverCard(
    tlsCert: TlsCertReport?,
    takeover: TakeoverScanSummary?,
    onPivot: (PivotEntity) -> Unit
) {
    IntelSurfaceCard(
        title = "LIVE X.509 TLS CERT & CNAME TAKEOVER",
        icon = Icons.Default.Lock,
        accent = if (takeover?.findings?.any { it.severity == TakeoverSeverity.CONFIRMED_VULNERABLE } == true) StatusRisk else InkBlack
    ) {
        tlsCert?.let { cert ->
            Text(
                text = "${cert.protocol} • ${cert.issuerCn.ifBlank { cert.issuerDn }} • ${cert.daysRemaining}d remaining",
                color = if (cert.isExpired) StatusRisk else EmeraldDeep,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = "SHA-256: ${cert.sha256Fingerprint.take(36)}…",
                color = MutedSlate,
                fontSize = 10.sp,
                fontFamily = MonoFontFamily
            )
            if (cert.sanDomains.isNotEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    cert.sanDomains.take(10).forEach { san ->
                        InteractiveTagChip(
                            text = san,
                            bg = SurfaceElevated,
                            border = CardBorder,
                            fg = InkBlack,
                            onClick = { onPivot(PivotEngine.normalize(san, PivotEntityType.DOMAIN, "Live TLS SAN")) }
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        takeover?.let { scan ->
            MiniSectionHeader("SUBDOMAIN TAKEOVER AUDIT (${scan.totalSubdomainsChecked} CHECKED)")
            if (scan.findings.isEmpty()) {
                Text("No dangling cloud CNAME takeover signatures detected.", color = StatusSafe, fontSize = 12.sp)
            } else {
                scan.findings.take(5).forEach { f ->
                    val col = when (f.severity) {
                        TakeoverSeverity.CONFIRMED_VULNERABLE -> StatusRisk
                        TakeoverSeverity.POTENTIAL_DANGLING -> StatusWarning
                        TakeoverSeverity.CLAIMED_SAFE -> EmeraldDeep
                    }
                    Text(
                        text = "[${f.severity.name}] ${f.subdomain} → ${f.cnameTarget} (${f.cloudProvider})",
                        color = col,
                        fontSize = 11.sp,
                        fontFamily = MonoFontFamily,
                        modifier = Modifier
                            .clickable { onPivot(PivotEngine.normalize(f.subdomain, PivotEntityType.DOMAIN, "CNAME Takeover")) }
                            .padding(vertical = 2.dp)
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun IdentityDeepIntelCard(
    github: GithubDeepProfile?,
    keybase: KeybaseIdentity?,
    emailFootprint: EmailFootprintReport?,
    onPivot: (PivotEntity) -> Unit
) {
    IntelSurfaceCard(
        title = "DEEP IDENTITY, GITHUB, KEYBASE & PGP",
        icon = Icons.Default.Fingerprint,
        accent = EmeraldPrimary
    ) {
        emailFootprint?.let { ef ->
            MiniSectionHeader("HOLEHE-STYLE EMAIL FOOTPRINT")
            Text("Mail Suite: ${ef.mailProviderSuite}", color = InkBlack, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            Text(
                text = "OpenPGP: ${ef.pgpKeySummary}",
                color = if (ef.hasOpenPgpKey) EmeraldDeep else SlateGrey,
                fontSize = 11.sp,
                fontFamily = MonoFontFamily
            )
            if (ef.githubMatchedUsers.isNotEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    ef.githubMatchedUsers.forEach { ghUser ->
                        InteractiveTagChip(
                            text = "GitHub: @$ghUser",
                            bg = EmeraldSoft,
                            border = EmeraldBorder,
                            fg = EmeraldDeep,
                            onClick = { onPivot(PivotEngine.normalize(ghUser, PivotEntityType.USERNAME, "GitHub Email Match")) }
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        github?.let { gh ->
            MiniSectionHeader("GITHUB DEEP PROFILE & COMMIT HARVEST")
            Text(
                text = "${gh.displayName.ifBlank { "@${gh.username}" }} • ${gh.publicRepos} repos • ${gh.followers} followers • Joined ${gh.createdAt}",
                color = InkBlack,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold
            )
            if (gh.bio.isNotBlank()) {
                Text(gh.bio, color = SlateGrey, fontSize = 12.sp)
            }
            val metaLine = listOfNotNull(
                gh.company.takeIf { it.isNotBlank() },
                gh.location.takeIf { it.isNotBlank() },
                gh.twitterHandle.takeIf { it.isNotBlank() }?.let { "X: @$it" }
            ).joinToString(" • ")
            if (metaLine.isNotBlank()) {
                Text(metaLine, color = MutedSlate, fontSize = 11.sp, fontFamily = MonoFontFamily)
            }
            if (gh.blogUrl.isNotBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                InteractiveTagChip(
                    text = "Website: ${gh.blogUrl}",
                    bg = SurfaceElevated,
                    border = CardBorder,
                    fg = InkBlack,
                    onClick = { onPivot(PivotEngine.normalize(gh.blogUrl, sourceContext = "GitHub Blog")) }
                )
            }
            if (gh.commitEmails.isNotEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
                MiniSectionHeader("PUBLIC GIT COMMIT EMAILS FOUND")
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    gh.commitEmails.forEach { ce ->
                        InteractiveTagChip(
                            text = ce,
                            bg = EmeraldSoft,
                            border = EmeraldBorder,
                            fg = EmeraldDeep,
                            onClick = { onPivot(PivotEngine.normalize(ce, PivotEntityType.EMAIL, "GitHub Commit Email")) }
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        keybase?.let { kb ->
            MiniSectionHeader("KEYBASE CRYPTOGRAPHIC IDENTITY")
            Text(
                text = "${kb.fullName.ifBlank { kb.username }} ${if (kb.location.isNotBlank()) "• ${kb.location}" else ""}".trim(),
                color = InkBlack,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold
            )
            if (kb.pgpFingerprint.isNotBlank()) {
                Text("PGP: ${kb.pgpFingerprint}", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
            }
            if (kb.verifiedProofs.isNotEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    kb.verifiedProofs.forEach { (svc, handle) ->
                        InteractiveTagChip(
                            text = "$svc: $handle",
                            bg = EmeraldSoft,
                            border = EmeraldBorder,
                            fg = EmeraldDeep,
                            onClick = { onPivot(PivotEngine.normalize(handle, sourceContext = "Keybase Proof ($svc)")) }
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun EntitySearchCard(
    report: EntitySearchReport,
    onPivot: (PivotEntity) -> Unit
) {
    val context = LocalContext.current
    IntelSurfaceCard(
        title = "UNIVERSAL PERSON / ORG INTELLIGENCE",
        icon = Icons.Default.Public,
        accent = InkBlack
    ) {
        if (report.wikiTitle.isNotBlank()) {
            MiniSectionHeader("PUBLIC KNOWLEDGE GRAPH (WIKIPEDIA)")
            Text(report.wikiTitle, color = InkBlack, fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Spacer(modifier = Modifier.height(3.dp))
            Text(report.wikiSummary, color = SlateGrey, fontSize = 12.sp, lineHeight = 17.sp)
            Spacer(modifier = Modifier.height(8.dp))
        }

        if (report.githubProfiles.isNotEmpty()) {
            MiniSectionHeader("MATCHED GITHUB USERS & ORGS (${report.githubProfiles.size})")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                report.githubProfiles.forEach { gh ->
                    InteractiveTagChip(
                        text = "${gh.title} (${gh.source.removePrefix("GitHub ")})",
                        bg = EmeraldSoft,
                        border = EmeraldBorder,
                        fg = EmeraldDeep,
                        onClick = {
                            onPivot(PivotEngine.normalize(gh.title.removePrefix("@"), PivotEntityType.USERNAME, "GitHub Search"))
                        }
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        if (report.webMentions.isNotEmpty()) {
            MiniSectionHeader("PUBLIC WEB MENTIONS (HN & REDDIT)")
            report.webMentions.take(8).forEach { m ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            SafeBrowserLauncher.openExternalUrl(context, m.url)
                        }
                        .padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(m.title, color = InkBlack, fontSize = 12.sp, fontWeight = FontWeight.Medium, maxLines = 2, overflow = TextOverflow.Ellipsis)
                        Text("${m.source} • ${m.subtitle}", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
                    }
                    Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = "Open source", tint = MutedSlate, modifier = Modifier.size(14.dp))
                }
            }
        }
    }
}

@Composable
private fun IntelSurfaceCard(
    title: String,
    icon: ImageVector,
    accent: Color,
    content: @Composable () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        border = BorderStroke(1.dp, CardBorder),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = title,
                    color = accent,
                    fontSize = 10.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.8.sp
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            content()
        }
    }
}

@Composable
private fun MiniSectionHeader(text: String) {
    Text(
        text = text,
        color = MutedSlate,
        fontSize = 9.sp,
        fontFamily = MonoFontFamily,
        fontWeight = FontWeight.Bold,
        letterSpacing = 0.6.sp,
        modifier = Modifier.padding(bottom = 4.dp)
    )
}

@Composable
private fun InteractiveTagChip(
    text: String,
    bg: Color,
    border: Color,
    fg: Color,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(bg)
            .border(1.dp, border, RoundedCornerShape(6.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 5.dp)
    ) {
        Text(
            text = text,
            color = fg,
            fontSize = 11.sp,
            fontFamily = MonoFontFamily,
            fontWeight = FontWeight.Medium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}
