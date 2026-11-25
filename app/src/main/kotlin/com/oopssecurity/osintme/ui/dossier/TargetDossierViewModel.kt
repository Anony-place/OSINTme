package com.oopssecurity.osintme.ui.dossier

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.local.ApiProvider
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.local.case.CaseRepository
import com.oopssecurity.osintme.data.model.AbuseIpdbReport
import com.oopssecurity.osintme.data.model.BgpAsnInfo
import com.oopssecurity.osintme.data.model.DnsRecordItem
import com.oopssecurity.osintme.data.model.EmailBreachResult
import com.oopssecurity.osintme.data.model.EmailSecurityAudit
import com.oopssecurity.osintme.data.model.GravatarProfile
import com.oopssecurity.osintme.data.model.InvestigationCase
import com.oopssecurity.osintme.data.model.IpReconResult
import com.oopssecurity.osintme.data.model.MalwareBazaarReport
import com.oopssecurity.osintme.data.model.PhoneReconResult
import com.oopssecurity.osintme.data.model.RdapDomainInfo
import com.oopssecurity.osintme.data.model.ReconStatus
import com.oopssecurity.osintme.data.model.RedirectChainResult
import com.oopssecurity.osintme.data.model.ScanArtifact
import com.oopssecurity.osintme.data.model.SubdomainResult
import com.oopssecurity.osintme.data.model.TlsHeaderAuditResult
import com.oopssecurity.osintme.data.model.UrlScanSummary
import com.oopssecurity.osintme.data.model.UrlhausResult
import com.oopssecurity.osintme.data.model.UsernameCheckResult
import com.oopssecurity.osintme.data.model.VirusTotalReport
import com.oopssecurity.osintme.data.model.WebTechReconResult
import com.oopssecurity.osintme.data.network.AiDossierInsight
import com.oopssecurity.osintme.data.network.AlienVaultOtxService
import com.oopssecurity.osintme.data.network.BgpAsnService
import com.oopssecurity.osintme.data.network.ByokAiService
import com.oopssecurity.osintme.data.network.CloudflareDohService
import com.oopssecurity.osintme.data.network.CrtShService
import com.oopssecurity.osintme.data.network.DeepWebCrawlReport
import com.oopssecurity.osintme.data.network.DeepWebCrawlerService
import com.oopssecurity.osintme.data.network.EmailAndIdentityIntelService
import com.oopssecurity.osintme.data.network.EmailFootprintReport
import com.oopssecurity.osintme.data.network.EntitySearchReport
import com.oopssecurity.osintme.data.network.GithubDeepProfile
import com.oopssecurity.osintme.data.network.GravatarService
import com.oopssecurity.osintme.data.network.KeybaseIdentity
import com.oopssecurity.osintme.data.network.OtxThreatReport
import com.oopssecurity.osintme.data.network.PhoneReconService
import com.oopssecurity.osintme.data.network.PlatformReconService
import com.oopssecurity.osintme.data.network.ProThreatApiServices
import com.oopssecurity.osintme.data.network.RdapService
import com.oopssecurity.osintme.data.network.RedirectResolverService
import com.oopssecurity.osintme.data.network.ShodanService
import com.oopssecurity.osintme.data.network.TakeoverScanSummary
import com.oopssecurity.osintme.data.network.TakeoverSeverity
import com.oopssecurity.osintme.data.network.TlsAndTakeoverService
import com.oopssecurity.osintme.data.network.TlsCertReport
import com.oopssecurity.osintme.data.network.TlsHeaderAuditService
import com.oopssecurity.osintme.data.network.UrlhausService
import com.oopssecurity.osintme.data.network.WaybackCdxService
import com.oopssecurity.osintme.data.network.WaybackReport
import com.oopssecurity.osintme.data.network.WebTechReconService
import com.oopssecurity.osintme.data.network.XposedOrNotService
import com.oopssecurity.osintme.util.CaseReportExporter
import com.oopssecurity.osintme.util.InputClassifier
import com.oopssecurity.osintme.util.InputType
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID

enum class FeedState {
    RUNNING,
    SUCCESS,
    NEEDS_KEY,
    ERROR
}

data class FeedProgress(
    val id: String,
    val label: String,
    val state: FeedState,
    val note: String = ""
)

data class TargetDossierUiState(
    val inputQuery: String = "",
    val normalizedTarget: String = "",
    val entityType: PivotEntityType? = null,
    val isEntityKeyword: Boolean = false,
    val isRunning: Boolean = false,
    val feeds: List<FeedProgress> = emptyList(),
    // Network & Infra
    val ipRecon: IpReconResult? = null,
    val bgpAsn: BgpAsnInfo? = null,
    val dnsRecords: List<DnsRecordItem> = emptyList(),
    val tlsAudit: TlsHeaderAuditResult? = null,
    val tlsCertReport: TlsCertReport? = null,
    val takeoverSummary: TakeoverScanSummary? = null,
    val webTech: WebTechReconResult? = null,
    val deepWebCrawl: DeepWebCrawlReport? = null,
    val subdomains: SubdomainResult? = null,
    val rdapInfo: RdapDomainInfo? = null,
    val emailSecurity: EmailSecurityAudit? = null,
    // Threat, Archive & BYOK
    val otxReport: OtxThreatReport? = null,
    val waybackReport: WaybackReport? = null,
    val urlhaus: UrlhausResult? = null,
    val virusTotal: VirusTotalReport? = null,
    val abuseIpdb: AbuseIpdbReport? = null,
    val urlScan: UrlScanSummary? = null,
    val malwareBazaar: MalwareBazaarReport? = null,
    // Identity / Deep OSINT / Link / Phone
    val breachResult: EmailBreachResult? = null,
    val gravatar: GravatarProfile? = null,
    val emailFootprint: EmailFootprintReport? = null,
    val githubProfile: GithubDeepProfile? = null,
    val keybaseIdentity: KeybaseIdentity? = null,
    val entitySearch: EntitySearchReport? = null,
    val usernameHits: List<UsernameCheckResult> = emptyList(),
    val usernameProbedCount: Int = 0,
    val redirectChain: RedirectChainResult? = null,
    val phoneResult: PhoneReconResult? = null,
    // Stage-2 Auto-Chaining Log & Correlated Pivot Entities
    val autoChainNotes: List<String> = emptyList(),
    val discoveredEntities: List<PivotEntity> = emptyList(),
    val riskVerdict: String = "PENDING", // LOW, MEDIUM, HIGH, PENDING
    val riskReasons: List<String> = emptyList(),
    val savedCaseId: String? = null,
    // BYOK AI Dossier Synthesis
    val isAiAnalyzing: Boolean = false,
    val aiInsight: AiDossierInsight? = null,
    val aiError: String? = null
)

class TargetDossierViewModel(
    private val context: Context,
    private val historyManager: LocalScanHistoryManager = LocalScanHistoryManager(context),
    private val caseRepository: CaseRepository = CaseRepository(context)
) : ViewModel() {

    companion object {
        private val CONSUMER_MAIL_DOMAINS = setOf(
            "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.co.uk",
            "outlook.com", "hotmail.com", "live.com", "msn.com",
            "icloud.com", "me.com", "mac.com",
            "proton.me", "protonmail.com", "pm.me",
            "aol.com", "gmx.com", "zoho.com", "yandex.com", "yandex.ru", "mail.com", "fastmail.com"
        )
    }

    private val _uiState = MutableStateFlow(TargetDossierUiState())
    val uiState: StateFlow<TargetDossierUiState> = _uiState.asStateFlow()

    private var activeJob: Job? = null

    fun setQuery(q: String) {
        _uiState.update { it.copy(inputQuery = q) }
    }

    fun runDossier(targetOverride: String? = null) {
        val raw = (targetOverride ?: _uiState.value.inputQuery).trim()
        if (raw.isEmpty()) return

        activeJob?.cancel()
        val classified = InputClassifier.classify(raw)
        val isKeyword = classified == InputType.GENERIC_KEYWORD
        val entity = PivotEngine.normalize(raw, sourceContext = "Universal Target Dossier")
        val target = if (isKeyword) raw else entity.normalizedValue

        val initialFeeds = buildPlannedFeeds(entity.type, isKeyword)
        _uiState.value = TargetDossierUiState(
            inputQuery = raw,
            normalizedTarget = target,
            entityType = entity.type,
            isEntityKeyword = isKeyword,
            isRunning = true,
            feeds = initialFeeds,
            riskVerdict = "PENDING"
        )

        activeJob = viewModelScope.launch {
            if (isKeyword) {
                orchestrateEntityKeyword(raw)
            } else {
                when (entity.type) {
                    PivotEntityType.DOMAIN -> orchestrateDomain(target)
                    PivotEntityType.IP_ADDRESS -> orchestrateIp(target)
                    PivotEntityType.EMAIL -> orchestrateEmail(target)
                    PivotEntityType.USERNAME -> orchestrateUsername(target)
                    PivotEntityType.URL -> orchestrateUrl(target)
                    PivotEntityType.HASH -> orchestrateHash(target)
                    PivotEntityType.PHONE -> orchestratePhone(target)
                }
            }
            recomputeCorrelations()
            _uiState.update { it.copy(isRunning = false) }
            val state = _uiState.value
            val label = if (isKeyword) "ENTITY" else entity.type.badgeLabel
            historyManager.addScan(
                type = "Target Dossier",
                target = target,
                summary = "$label • Risk ${state.riskVerdict} • ${state.discoveredEntities.size} pivots"
            )
        }
    }

    private fun buildPlannedFeeds(type: PivotEntityType, isEntityKeyword: Boolean): List<FeedProgress> {
        val hasVt = ApiKeyVault.hasKey(ApiProvider.VIRUSTOTAL)
        val hasAbuse = ApiKeyVault.hasKey(ApiProvider.ABUSEIPDB)

        if (isEntityKeyword) {
            return listOf(
                FeedProgress("entity", "Wiki/GitHub/HN/Reddit", FeedState.RUNNING),
                FeedProgress("github", "GitHub Deep & Commits", FeedState.RUNNING),
                FeedProgress("keybase", "Keybase Proofs", FeedState.RUNNING),
                FeedProgress("handles", "40-Site Auto-Chain", FeedState.RUNNING)
            )
        }

        return when (type) {
            PivotEntityType.DOMAIN -> listOf(
                FeedProgress("dns", "Cloudflare DoH & Mail", FeedState.RUNNING),
                FeedProgress("crawl", "JS/HTML/Email Scraper", FeedState.RUNNING),
                FeedProgress("web", "Web Stack & Robots", FeedState.RUNNING),
                FeedProgress("tls", "Live X.509 & Headers", FeedState.RUNNING),
                FeedProgress("otx", "AlienVault OTX", FeedState.RUNNING),
                FeedProgress("wayback", "Wayback CDX Archive", FeedState.RUNNING),
                FeedProgress("crt", "CT Subdomains", FeedState.RUNNING),
                FeedProgress("takeover", "CNAME Takeover Scan", FeedState.RUNNING),
                FeedProgress("shodan", "Shodan & GeoIP", FeedState.RUNNING),
                FeedProgress("bgp", "RIPEstat BGP/ASN", FeedState.RUNNING),
                FeedProgress("rdap", "RDAP WHOIS", FeedState.RUNNING),
                FeedProgress("threat", "1.1.1.2 & URLhaus", FeedState.RUNNING),
                FeedProgress("urlscan", "URLScan.io", FeedState.RUNNING),
                FeedProgress("vt", "VirusTotal v3", if (hasVt) FeedState.RUNNING else FeedState.NEEDS_KEY, if (!hasVt) "Optional BYOK" else "")
            )
            PivotEntityType.IP_ADDRESS -> listOf(
                FeedProgress("shodan", "Shodan & GeoIP", FeedState.RUNNING),
                FeedProgress("bgp", "RIPEstat BGP/ASN", FeedState.RUNNING),
                FeedProgress("otx", "AlienVault OTX", FeedState.RUNNING),
                FeedProgress("threat", "URLhaus & DNS", FeedState.RUNNING),
                FeedProgress("urlscan", "URLScan.io", FeedState.RUNNING),
                FeedProgress("abuseipdb", "AbuseIPDB v2", if (hasAbuse) FeedState.RUNNING else FeedState.NEEDS_KEY, if (!hasAbuse) "Optional BYOK" else ""),
                FeedProgress("vt", "VirusTotal v3", if (hasVt) FeedState.RUNNING else FeedState.NEEDS_KEY, if (!hasVt) "Optional BYOK" else "")
            )
            PivotEntityType.EMAIL -> listOf(
                FeedProgress("breach", "XposedOrNot Leaks", FeedState.RUNNING),
                FeedProgress("footprint", "PGP / GitHub / Keybase", FeedState.RUNNING),
                FeedProgress("gravatar", "Gravatar Identity", FeedState.RUNNING),
                FeedProgress("mailsec", "SPF / DMARC / Suite", FeedState.RUNNING),
                FeedProgress("handles", "60-Site Handle Chain", FeedState.RUNNING),
                FeedProgress("corpweb", "Domain Auto-Chain", FeedState.RUNNING)
            )
            PivotEntityType.USERNAME -> listOf(
                FeedProgress("handles", "${PlatformReconService.ALL_PLATFORMS.size}-Site Live Hunt", FeedState.RUNNING),
                FeedProgress("github", "GitHub & Commit Emails", FeedState.RUNNING),
                FeedProgress("keybase", "Keybase PGP & Proofs", FeedState.RUNNING),
                FeedProgress("entity", "HN / Reddit / Wiki", FeedState.RUNNING)
            )
            PivotEntityType.URL -> listOf(
                FeedProgress("redirect", "Redirect Chain", FeedState.RUNNING),
                FeedProgress("crawl", "JS/HTML/Email Scraper", FeedState.RUNNING),
                FeedProgress("threat", "1.1.1.2 & URLhaus", FeedState.RUNNING),
                FeedProgress("otx", "AlienVault OTX", FeedState.RUNNING),
                FeedProgress("wayback", "Wayback CDX Archive", FeedState.RUNNING),
                FeedProgress("web", "Host Web Stack", FeedState.RUNNING),
                FeedProgress("urlscan", "URLScan.io", FeedState.RUNNING),
                FeedProgress("vt", "VirusTotal v3", if (hasVt) FeedState.RUNNING else FeedState.NEEDS_KEY, if (!hasVt) "Optional BYOK" else "")
            )
            PivotEntityType.HASH -> listOf(
                FeedProgress("mb", "MalwareBazaar", FeedState.RUNNING),
                FeedProgress("otx", "AlienVault OTX", FeedState.RUNNING),
                FeedProgress("vt", "VirusTotal v3", if (hasVt) FeedState.RUNNING else FeedState.NEEDS_KEY, if (!hasVt) "Optional BYOK" else "")
            )
            PivotEntityType.PHONE -> listOf(
                FeedProgress("phone", "E.164 Numbering Plan", FeedState.RUNNING),
                FeedProgress("entity", "Public Web Mentions", FeedState.RUNNING)
            )
        }
    }

    private suspend fun orchestrateDomain(domain: String) {
        val jobs = mutableListOf<Job>()

        jobs += viewModelScope.launch {
            val dnsRes = CloudflareDohService.resolveAll(domain)
            val mailRes = CloudflareDohService.auditEmailSecurity(domain)
            val records = dnsRes.getOrDefault(emptyList())
            val mxHosts = records.filter { it.type == "MX" }.map { it.data }
            val suite = EmailAndIdentityIntelService.detectMailProviderSuite(mxHosts)
            _uiState.update { it.copy(dnsRecords = records, emailSecurity = mailRes.getOrNull()) }
            markFeed("dns", if (records.isNotEmpty()) FeedState.SUCCESS else FeedState.ERROR, "${records.size} recs • $suite")
            recomputeCorrelations()

            // Stage-2 IP Auto-Chain off resolved A record
            val firstIp = records.firstOrNull { it.type == "A" }?.data
            if (!firstIp.isNullOrBlank()) {
                addAutoChainNote("DNS A record '$firstIp' → Shodan ports, GeoIP & RIPEstat BGP")
                launch {
                    ShodanService.lookupIp(firstIp).fold(
                        onSuccess = { ip ->
                            _uiState.update { it.copy(ipRecon = ip) }
                            markFeed("shodan", FeedState.SUCCESS, "${ip.ports.size} ports")
                        },
                        onFailure = { markFeed("shodan", FeedState.ERROR, it.message.orEmpty()) }
                    )
                    recomputeCorrelations()
                }
                launch {
                    BgpAsnService.lookupIpOrHost(firstIp).fold(
                        onSuccess = { bgp ->
                            _uiState.update { it.copy(bgpAsn = bgp) }
                            markFeed("bgp", FeedState.SUCCESS, bgp.asn)
                        },
                        onFailure = { markFeed("bgp", FeedState.ERROR, it.message.orEmpty()) }
                    )
                    recomputeCorrelations()
                }
            } else {
                markFeed("shodan", FeedState.ERROR, "No A record")
                markFeed("bgp", FeedState.ERROR, "No A record")
            }
        }

        jobs += viewModelScope.launch {
            DeepWebCrawlerService.crawlTarget(domain).fold(
                onSuccess = { crawl ->
                    _uiState.update { it.copy(deepWebCrawl = crawl) }
                    val summary = buildList {
                        if (crawl.emails.isNotEmpty()) add("${crawl.emails.size} emails")
                        if (crawl.socialLinks.isNotEmpty()) add("${crawl.socialLinks.size} socials")
                        if (crawl.apiEndpoints.isNotEmpty()) add("${crawl.apiEndpoints.size} APIs")
                    }.joinToString(", ").ifBlank { "${crawl.jsFilesScanned} JS scanned" }
                    markFeed("crawl", FeedState.SUCCESS, summary)
                    if (crawl.emails.isNotEmpty()) {
                        addAutoChainNote("Scraped ${crawl.emails.size} email(s) & ${crawl.trackingIds.size} tracker ID(s) from HTML/JS")
                    }
                },
                onFailure = { markFeed("crawl", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            val headerRes = TlsHeaderAuditService.inspectTarget(domain)
            val certRes = TlsAndTakeoverService.inspectTlsCertificate(domain)
            headerRes.onSuccess { tls -> _uiState.update { it.copy(tlsAudit = tls) } }
            certRes.onSuccess { cert -> _uiState.update { it.copy(tlsCertReport = cert) } }
            val grade = headerRes.getOrNull()?.securityGrade
            val certDays = certRes.getOrNull()?.daysRemaining
            if (grade != null || certDays != null) {
                val note = listOfNotNull(grade?.let { "Grade $it" }, certDays?.let { "${it}d left" }).joinToString(" • ")
                markFeed("tls", FeedState.SUCCESS, note)
            } else {
                markFeed("tls", FeedState.ERROR, "TLS unreachable")
            }
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            WebTechReconService.inspectHost(domain).fold(
                onSuccess = { web ->
                    _uiState.update { it.copy(webTech = web) }
                    markFeed("web", FeedState.SUCCESS, "${web.technologies.size} tech")
                },
                onFailure = { markFeed("web", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            AlienVaultOtxService.lookupDomain(domain).fold(
                onSuccess = { otx ->
                    _uiState.update { it.copy(otxReport = otx) }
                    markFeed("otx", FeedState.SUCCESS, "${otx.pulseCount} pulses • ${otx.passiveDnsHosts.size} pDNS")
                },
                onFailure = { markFeed("otx", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            WaybackCdxService.searchArchive(domain, limit = 80).fold(
                onSuccess = { wb ->
                    _uiState.update { it.copy(waybackReport = wb) }
                    markFeed("wayback", FeedState.SUCCESS, "${wb.snapshots.size} URLs • ${wb.sensitiveCount} sens")
                },
                onFailure = { markFeed("wayback", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            val subsResult = CrtShService.findSubdomains(domain)
            val discoveredSubs = subsResult.getOrNull()?.subdomains.orEmpty()
            subsResult.fold(
                onSuccess = { subs ->
                    _uiState.update { it.copy(subdomains = subs) }
                    markFeed("crt", FeedState.SUCCESS, "${subs.totalCount} subs")
                },
                onFailure = { markFeed("crt", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()

            // Stage-2 CNAME Takeover Auto-Chain on discovered CT subdomains
            TlsAndTakeoverService.scanSubdomainTakeovers(
                rawDomain = domain,
                extraSubdomains = discoveredSubs.take(14),
                maxSubdomains = 16
            ).fold(
                onSuccess = { scan ->
                    _uiState.update { it.copy(takeoverSummary = scan) }
                    val vulnCount = scan.findings.count { it.severity == TakeoverSeverity.CONFIRMED_VULNERABLE }
                    markFeed(
                        "takeover",
                        FeedState.SUCCESS,
                        if (vulnCount > 0) "$vulnCount VULNERABLE!" else "${scan.totalSubdomainsChecked} checked"
                    )
                    if (vulnCount > 0) {
                        addAutoChainNote("Subdomain takeover alert: $vulnCount dangling cloud CNAME(s) verified")
                    }
                },
                onFailure = { markFeed("takeover", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            RdapService.fetchWhois(domain).fold(
                onSuccess = { rdap ->
                    _uiState.update { it.copy(rdapInfo = rdap) }
                    markFeed("rdap", FeedState.SUCCESS, rdap.registrar.take(18))
                },
                onFailure = { markFeed("rdap", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            UrlhausService.checkHost(domain).fold(
                onSuccess = { uh ->
                    _uiState.update { it.copy(urlhaus = uh) }
                    markFeed("threat", FeedState.SUCCESS, if (uh.isMalicious) "FLAGGED" else "Clean")
                },
                onFailure = { markFeed("threat", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            ProThreatApiServices.searchUrlScan(domain, isIp = false).fold(
                onSuccess = { us ->
                    _uiState.update { it.copy(urlScan = us) }
                    markFeed("urlscan", FeedState.SUCCESS, "${us.totalHits} scans")
                },
                onFailure = { markFeed("urlscan", FeedState.ERROR, it.message.orEmpty()) }
            )
        }

        if (ApiKeyVault.hasKey(ApiProvider.VIRUSTOTAL)) {
            jobs += viewModelScope.launch {
                ProThreatApiServices.lookupVirusTotalDomain(domain).fold(
                    onSuccess = { vt ->
                        _uiState.update { it.copy(virusTotal = vt) }
                        markFeed("vt", FeedState.SUCCESS, "${vt.maliciousCount}/${vt.totalEngines} mal")
                    },
                    onFailure = { markFeed("vt", FeedState.ERROR, it.message.orEmpty()) }
                )
                recomputeCorrelations()
            }
        }

        jobs.forEach { it.join() }
    }

    private suspend fun orchestrateIp(ip: String) {
        val jobs = mutableListOf<Job>()

        jobs += viewModelScope.launch {
            ShodanService.lookupIp(ip).fold(
                onSuccess = { res ->
                    _uiState.update { it.copy(ipRecon = res) }
                    markFeed("shodan", FeedState.SUCCESS, "${res.ports.size} ports")
                },
                onFailure = { markFeed("shodan", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            BgpAsnService.lookupIpOrHost(ip).fold(
                onSuccess = { bgp ->
                    _uiState.update { it.copy(bgpAsn = bgp) }
                    markFeed("bgp", FeedState.SUCCESS, bgp.asn)
                },
                onFailure = { markFeed("bgp", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            AlienVaultOtxService.lookupIp(ip).fold(
                onSuccess = { otx ->
                    _uiState.update { it.copy(otxReport = otx) }
                    markFeed("otx", FeedState.SUCCESS, "${otx.pulseCount} pulses • ${otx.passiveDnsHosts.size} hosts")
                },
                onFailure = { markFeed("otx", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            UrlhausService.checkHost(ip).fold(
                onSuccess = { uh ->
                    _uiState.update { it.copy(urlhaus = uh) }
                    markFeed("threat", FeedState.SUCCESS, if (uh.isMalicious) "FLAGGED" else "Clean")
                },
                onFailure = { markFeed("threat", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            ProThreatApiServices.searchUrlScan(ip, isIp = true).fold(
                onSuccess = { us ->
                    _uiState.update { it.copy(urlScan = us) }
                    markFeed("urlscan", FeedState.SUCCESS, "${us.totalHits} scans")
                },
                onFailure = { markFeed("urlscan", FeedState.ERROR, it.message.orEmpty()) }
            )
        }

        if (ApiKeyVault.hasKey(ApiProvider.ABUSEIPDB)) {
            jobs += viewModelScope.launch {
                ProThreatApiServices.lookupAbuseIpdb(ip).fold(
                    onSuccess = { ab ->
                        _uiState.update { it.copy(abuseIpdb = ab) }
                        markFeed("abuseipdb", FeedState.SUCCESS, "${ab.abuseConfidenceScore}% abuse")
                    },
                    onFailure = { markFeed("abuseipdb", FeedState.ERROR, it.message.orEmpty()) }
                )
                recomputeCorrelations()
            }
        }

        if (ApiKeyVault.hasKey(ApiProvider.VIRUSTOTAL)) {
            jobs += viewModelScope.launch {
                ProThreatApiServices.lookupVirusTotalIp(ip).fold(
                    onSuccess = { vt ->
                        _uiState.update { it.copy(virusTotal = vt) }
                        markFeed("vt", FeedState.SUCCESS, "${vt.maliciousCount}/${vt.totalEngines} mal")
                    },
                    onFailure = { markFeed("vt", FeedState.ERROR, it.message.orEmpty()) }
                )
                recomputeCorrelations()
            }
        }

        jobs.forEach { it.join() }
    }

    private suspend fun orchestrateEmail(email: String) {
        val domain = email.substringAfter("@", "").lowercase()
        val localPart = email.substringBefore("@", "")
        val jobs = mutableListOf<Job>()

        jobs += viewModelScope.launch {
            XposedOrNotService.checkEmail(email).fold(
                onSuccess = { res ->
                    _uiState.update { it.copy(breachResult = res) }
                    markFeed("breach", FeedState.SUCCESS, "${res.totalBreaches} leaks")
                },
                onFailure = { markFeed("breach", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            GravatarService.lookupProfile(email).fold(
                onSuccess = { profile ->
                    _uiState.update { it.copy(gravatar = profile) }
                    markFeed("gravatar", FeedState.SUCCESS, if (profile != null) "Profile found" else "No profile")
                },
                onFailure = { markFeed("gravatar", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            val mxRecords = if (domain.contains(".")) {
                CloudflareDohService.queryRecord(domain, "MX").getOrDefault(emptyList()).map { it.data }
            } else emptyList()

            if (domain.contains(".")) {
                CloudflareDohService.auditEmailSecurity(domain).fold(
                    onSuccess = { audit ->
                        _uiState.update { it.copy(emailSecurity = audit) }
                        val suite = EmailAndIdentityIntelService.detectMailProviderSuite(mxRecords)
                        markFeed("mailsec", FeedState.SUCCESS, "Grade ${audit.grade} • $suite")
                    },
                    onFailure = { markFeed("mailsec", FeedState.ERROR, it.message.orEmpty()) }
                )
            } else {
                markFeed("mailsec", FeedState.ERROR, "Invalid domain")
            }

            // Holehe-style footprint: OpenPGP + GitHub email lookup + Keybase
            EmailAndIdentityIntelService.analyzeEmailFootprint(email, mxRecords).fold(
                onSuccess = { fp ->
                    _uiState.update { it.copy(emailFootprint = fp, keybaseIdentity = fp.keybaseIdentity) }
                    val note = buildList {
                        if (fp.hasOpenPgpKey) add("PGP Found")
                        if (fp.githubMatchedUsers.isNotEmpty()) add("GH @${fp.githubMatchedUsers.first()}")
                        if (fp.keybaseIdentity != null) add("Keybase")
                    }.joinToString(" • ").ifBlank { fp.mailProviderSuite }
                    markFeed("footprint", FeedState.SUCCESS, note)

                    // Stage-2 Auto-Chain: deep GitHub profile on matched user or email prefix
                    val targetHandle = fp.githubMatchedUsers.firstOrNull() ?: localPart
                    if (targetHandle.length >= 3) {
                        EmailAndIdentityIntelService.fetchGithubDeepProfile(targetHandle).onSuccess { gh ->
                            _uiState.update { it.copy(githubProfile = gh) }
                            addAutoChainNote("Linked GitHub '@${gh.username}' (${gh.publicRepos} repos, ${gh.commitEmails.size} commit email(s))")
                        }
                    }
                },
                onFailure = { markFeed("footprint", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            if (localPart.length >= 3) {
                var checked = 0
                PlatformReconService.scanUsernameFlow(localPart, limitPlatforms = 60).collect { res ->
                    checked++
                    _uiState.update { state ->
                        val updatedHits = if (res.status == ReconStatus.FOUND) state.usernameHits + res else state.usernameHits
                        state.copy(usernameHits = updatedHits, usernameProbedCount = checked)
                    }
                }
                markFeed("handles", FeedState.SUCCESS, "${_uiState.value.usernameHits.size}/$checked hits")
            } else {
                markFeed("handles", FeedState.ERROR, "Prefix too short")
            }
            recomputeCorrelations()
        }

        // Stage-2 Corporate Domain Auto-Chain (skip generic consumer webmail domains)
        jobs += viewModelScope.launch {
            if (domain.contains(".") && domain !in CONSUMER_MAIL_DOMAINS) {
                addAutoChainNote("Corporate email domain '$domain' → Deep Web/JS Crawl & AlienVault OTX")
                val crawlRes = DeepWebCrawlerService.crawlTarget(domain)
                val otxRes = AlienVaultOtxService.lookupDomain(domain)
                crawlRes.onSuccess { c -> _uiState.update { it.copy(deepWebCrawl = c) } }
                otxRes.onSuccess { o -> _uiState.update { it.copy(otxReport = o) } }
                if (crawlRes.isSuccess || otxRes.isSuccess) {
                    markFeed("corpweb", FeedState.SUCCESS, "Crawled $domain")
                } else {
                    markFeed("corpweb", FeedState.ERROR, "Domain unreachable")
                }
            } else {
                markFeed("corpweb", FeedState.SUCCESS, "Consumer provider")
            }
            recomputeCorrelations()
        }

        jobs.forEach { it.join() }
    }

    private suspend fun orchestrateUsername(username: String) {
        val jobs = mutableListOf<Job>()

        jobs += viewModelScope.launch {
            var checked = 0
            PlatformReconService.scanUsernameFlow(username).collect { res ->
                checked++
                _uiState.update { state ->
                    val updatedHits = if (res.status == ReconStatus.FOUND) state.usernameHits + res else state.usernameHits
                    state.copy(usernameHits = updatedHits, usernameProbedCount = checked)
                }
            }
            markFeed("handles", FeedState.SUCCESS, "${_uiState.value.usernameHits.size} / $checked found")
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            EmailAndIdentityIntelService.fetchGithubDeepProfile(username).fold(
                onSuccess = { gh ->
                    _uiState.update { it.copy(githubProfile = gh) }
                    markFeed("github", FeedState.SUCCESS, "${gh.publicRepos} repos • ${gh.commitEmails.size} emails")
                    // Stage-2 Auto-Chain: if public git commits reveal a real email, audit breaches & OpenPGP automatically!
                    val leakedEmail = gh.commitEmails.firstOrNull()
                    if (!leakedEmail.isNullOrBlank()) {
                        addAutoChainNote("GitHub commit email '$leakedEmail' → XposedOrNot breaches & OpenPGP audit")
                        XposedOrNotService.checkEmail(leakedEmail).onSuccess { br ->
                            _uiState.update { it.copy(breachResult = br) }
                        }
                        EmailAndIdentityIntelService.analyzeEmailFootprint(leakedEmail).onSuccess { fp ->
                            _uiState.update { it.copy(emailFootprint = fp) }
                        }
                    }
                },
                onFailure = { markFeed("github", FeedState.ERROR, "Not on GitHub") }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            EmailAndIdentityIntelService.fetchKeybaseIdentity(username).fold(
                onSuccess = { kb ->
                    _uiState.update { it.copy(keybaseIdentity = kb) }
                    markFeed("keybase", FeedState.SUCCESS, "${kb.verifiedProofs.size} proofs")
                },
                onFailure = { markFeed("keybase", FeedState.ERROR, "Not on Keybase") }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            EmailAndIdentityIntelService.searchEntityMentions(username).fold(
                onSuccess = { ent ->
                    _uiState.update { it.copy(entitySearch = ent) }
                    val total = ent.githubProfiles.size + ent.webMentions.size + (if (ent.wikiTitle.isNotBlank()) 1 else 0)
                    markFeed("entity", FeedState.SUCCESS, "$total mentions")
                },
                onFailure = { markFeed("entity", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs.forEach { it.join() }
    }

    private suspend fun orchestrateEntityKeyword(query: String) {
        val searchRes = EmailAndIdentityIntelService.searchEntityMentions(query)
        val report = searchRes.getOrNull()
        searchRes.fold(
            onSuccess = { ent ->
                _uiState.update { it.copy(entitySearch = ent) }
                val total = ent.githubProfiles.size + ent.webMentions.size + (if (ent.wikiTitle.isNotBlank()) 1 else 0)
                markFeed("entity", FeedState.SUCCESS, "$total results")
            },
            onFailure = { markFeed("entity", FeedState.ERROR, it.message.orEmpty()) }
        )
        recomputeCorrelations()

        // Stage-2 Auto-Chain on top discovered GitHub handle or compact slug
        val handleCandidate = report?.topHandleCandidate
            ?: query.lowercase().replace(Regex("[^a-z0-9]"), "").takeIf { it.length in 3..24 }

        if (handleCandidate.isNullOrBlank()) {
            markFeed("github", FeedState.ERROR, "No handle candidate")
            markFeed("keybase", FeedState.ERROR, "No handle candidate")
            markFeed("handles", FeedState.ERROR, "No handle candidate")
            return
        }

        addAutoChainNote("Entity search resolved handle '@$handleCandidate' → GitHub, Keybase & 40-site hunt")
        val jobs = mutableListOf<Job>()
        jobs += viewModelScope.launch {
            EmailAndIdentityIntelService.fetchGithubDeepProfile(handleCandidate).fold(
                onSuccess = { gh ->
                    _uiState.update { it.copy(githubProfile = gh) }
                    markFeed("github", FeedState.SUCCESS, "${gh.publicRepos} repos • ${gh.commitEmails.size} emails")
                },
                onFailure = { markFeed("github", FeedState.ERROR, "No GitHub profile") }
            )
            recomputeCorrelations()
        }
        jobs += viewModelScope.launch {
            EmailAndIdentityIntelService.fetchKeybaseIdentity(handleCandidate).fold(
                onSuccess = { kb ->
                    _uiState.update { it.copy(keybaseIdentity = kb) }
                    markFeed("keybase", FeedState.SUCCESS, "${kb.verifiedProofs.size} proofs")
                },
                onFailure = { markFeed("keybase", FeedState.ERROR, "No Keybase") }
            )
            recomputeCorrelations()
        }
        jobs += viewModelScope.launch {
            var checked = 0
            PlatformReconService.scanUsernameFlow(handleCandidate, limitPlatforms = 40).collect { res ->
                checked++
                _uiState.update { state ->
                    val updatedHits = if (res.status == ReconStatus.FOUND) state.usernameHits + res else state.usernameHits
                    state.copy(usernameHits = updatedHits, usernameProbedCount = checked)
                }
            }
            markFeed("handles", FeedState.SUCCESS, "${_uiState.value.usernameHits.size}/$checked found")
            recomputeCorrelations()
        }
        jobs.forEach { it.join() }
    }

    private suspend fun orchestrateUrl(url: String) {
        val host = PivotEngine.extractHost(url).orEmpty()
        val jobs = mutableListOf<Job>()

        jobs += viewModelScope.launch {
            RedirectResolverService.traceRedirects(url).fold(
                onSuccess = { chain ->
                    _uiState.update { it.copy(redirectChain = chain) }
                    markFeed("redirect", FeedState.SUCCESS, "${chain.hops.size} hop(s)")
                },
                onFailure = { markFeed("redirect", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            DeepWebCrawlerService.crawlTarget(url).fold(
                onSuccess = { crawl ->
                    _uiState.update { it.copy(deepWebCrawl = crawl) }
                    markFeed("crawl", FeedState.SUCCESS, "${crawl.emails.size} emails • ${crawl.apiEndpoints.size} APIs")
                },
                onFailure = { markFeed("crawl", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        if (host.isNotBlank()) {
            jobs += viewModelScope.launch {
                UrlhausService.checkHost(host).fold(
                    onSuccess = { uh ->
                        _uiState.update { it.copy(urlhaus = uh) }
                        markFeed("threat", FeedState.SUCCESS, if (uh.isMalicious) "FLAGGED" else "Clean")
                    },
                    onFailure = { markFeed("threat", FeedState.ERROR, it.message.orEmpty()) }
                )
                recomputeCorrelations()
            }

            jobs += viewModelScope.launch {
                AlienVaultOtxService.lookupDomain(host).fold(
                    onSuccess = { otx ->
                        _uiState.update { it.copy(otxReport = otx) }
                        markFeed("otx", FeedState.SUCCESS, "${otx.pulseCount} pulses")
                    },
                    onFailure = { markFeed("otx", FeedState.ERROR, it.message.orEmpty()) }
                )
                recomputeCorrelations()
            }

            jobs += viewModelScope.launch {
                WaybackCdxService.searchArchive(host, limit = 60).fold(
                    onSuccess = { wb ->
                        _uiState.update { it.copy(waybackReport = wb) }
                        markFeed("wayback", FeedState.SUCCESS, "${wb.snapshots.size} URLs")
                    },
                    onFailure = { markFeed("wayback", FeedState.ERROR, it.message.orEmpty()) }
                )
                recomputeCorrelations()
            }

            jobs += viewModelScope.launch {
                WebTechReconService.inspectHost(host).fold(
                    onSuccess = { web ->
                        _uiState.update { it.copy(webTech = web) }
                        markFeed("web", FeedState.SUCCESS, "${web.technologies.size} tech")
                    },
                    onFailure = { markFeed("web", FeedState.ERROR, it.message.orEmpty()) }
                )
                recomputeCorrelations()
            }

            jobs += viewModelScope.launch {
                ProThreatApiServices.searchUrlScan(host, isIp = false).fold(
                    onSuccess = { us ->
                        _uiState.update { it.copy(urlScan = us) }
                        markFeed("urlscan", FeedState.SUCCESS, "${us.totalHits} scans")
                    },
                    onFailure = { markFeed("urlscan", FeedState.ERROR, it.message.orEmpty()) }
                )
            }
        }

        if (ApiKeyVault.hasKey(ApiProvider.VIRUSTOTAL)) {
            jobs += viewModelScope.launch {
                ProThreatApiServices.lookupVirusTotalUrl(url).fold(
                    onSuccess = { vt ->
                        _uiState.update { it.copy(virusTotal = vt) }
                        markFeed("vt", FeedState.SUCCESS, "${vt.maliciousCount}/${vt.totalEngines} mal")
                    },
                    onFailure = { markFeed("vt", FeedState.ERROR, it.message.orEmpty()) }
                )
                recomputeCorrelations()
            }
        }

        jobs.forEach { it.join() }
    }

    private suspend fun orchestrateHash(hash: String) {
        val jobs = mutableListOf<Job>()

        jobs += viewModelScope.launch {
            ProThreatApiServices.lookupMalwareBazaarHash(hash).fold(
                onSuccess = { mb ->
                    _uiState.update { it.copy(malwareBazaar = mb) }
                    markFeed("mb", FeedState.SUCCESS, if (mb.found) mb.signature else "Not listed")
                },
                onFailure = { markFeed("mb", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        jobs += viewModelScope.launch {
            AlienVaultOtxService.lookupHash(hash).fold(
                onSuccess = { otx ->
                    _uiState.update { it.copy(otxReport = otx) }
                    markFeed("otx", FeedState.SUCCESS, "${otx.pulseCount} pulses")
                },
                onFailure = { markFeed("otx", FeedState.ERROR, it.message.orEmpty()) }
            )
            recomputeCorrelations()
        }

        if (ApiKeyVault.hasKey(ApiProvider.VIRUSTOTAL)) {
            jobs += viewModelScope.launch {
                ProThreatApiServices.lookupVirusTotalHash(hash).fold(
                    onSuccess = { vt ->
                        _uiState.update { it.copy(virusTotal = vt) }
                        markFeed("vt", FeedState.SUCCESS, "${vt.maliciousCount}/${vt.totalEngines} mal")
                    },
                    onFailure = { markFeed("vt", FeedState.ERROR, it.message.orEmpty()) }
                )
                recomputeCorrelations()
            }
        }

        jobs.forEach { it.join() }
    }

    private suspend fun orchestratePhone(phone: String) {
        PhoneReconService.analyzeNumber(phone).fold(
            onSuccess = { res ->
                _uiState.update { it.copy(phoneResult = res) }
                markFeed("phone", FeedState.SUCCESS, res.countryName)
            },
            onFailure = { markFeed("phone", FeedState.ERROR, it.message.orEmpty()) }
        )

        EmailAndIdentityIntelService.searchEntityMentions(phone).fold(
            onSuccess = { ent ->
                _uiState.update { it.copy(entitySearch = ent) }
                markFeed("entity", FeedState.SUCCESS, "${ent.webMentions.size} mentions")
            },
            onFailure = { markFeed("entity", FeedState.ERROR, it.message.orEmpty()) }
        )
    }

    private fun addAutoChainNote(note: String) {
        _uiState.update { state ->
            if (note in state.autoChainNotes) state
            else state.copy(autoChainNotes = state.autoChainNotes + note)
        }
    }

    private fun markFeed(id: String, state: FeedState, note: String = "") {
        _uiState.update { ui ->
            ui.copy(
                feeds = ui.feeds.map { f ->
                    if (f.id == id) f.copy(state = state, note = note) else f
                }
            )
        }
    }

    private fun recomputeCorrelations() {
        val s = _uiState.value
        val reasons = mutableListOf<String>()
        var score = 0

        if (s.urlhaus?.isMalicious == true) {
            score += 60
            reasons.add("Flagged malicious by Cloudflare 1.1.1.2 / URLhaus")
        }
        if ((s.otxReport?.pulseCount ?: 0) >= 3) {
            score += 45
            reasons.add("AlienVault OTX: listed in ${s.otxReport?.pulseCount} threat pulse(s)")
        } else if ((s.otxReport?.pulseCount ?: 0) > 0) {
            score += 20
            reasons.add("AlienVault OTX: referenced in ${s.otxReport?.pulseCount} public pulse(s)")
        }
        if (s.takeoverSummary?.findings?.any { it.severity == TakeoverSeverity.CONFIRMED_VULNERABLE } == true) {
            score += 55
            reasons.add("Confirmed dangling cloud CNAME subdomain takeover vulnerability")
        }
        if ((s.virusTotal?.maliciousCount ?: 0) > 0) {
            score += 70
            reasons.add("VirusTotal: ${s.virusTotal?.maliciousCount} security vendors flagged malicious")
        }
        if ((s.abuseIpdb?.abuseConfidenceScore ?: 0) >= 50) {
            score += 50
            reasons.add("AbuseIPDB confidence ${s.abuseIpdb?.abuseConfidenceScore}% (${s.abuseIpdb?.totalReports} reports)")
        } else if ((s.abuseIpdb?.abuseConfidenceScore ?: 0) >= 15) {
            score += 20
            reasons.add("AbuseIPDB moderate reports (${s.abuseIpdb?.abuseConfidenceScore}%)")
        }
        if (s.malwareBazaar?.found == true) {
            score += 80
            reasons.add("Known MalwareBazaar sample: ${s.malwareBazaar.signature}")
        }
        if ((s.ipRecon?.vulns?.size ?: 0) > 0) {
            score += 35
            reasons.add("${s.ipRecon?.vulns?.size} CVE(s) associated with exposed services")
        }
        if (s.breachResult?.isBreached == true) {
            score += 40
            reasons.add("Exposed in ${s.breachResult.totalBreaches} public data breach(es)")
        }
        if (s.emailSecurity?.isSpoofable == true) {
            score += 20
            reasons.add("Weak SPF/DMARC policy (${s.emailSecurity.grade}) — spoofable domain")
        }
        if (s.tlsAudit?.securityGrade in setOf("D", "F")) {
            score += 15
            reasons.add("HTTP security headers grade ${s.tlsAudit?.securityGrade}")
        }
        if (s.tlsCertReport?.isExpired == true) {
            score += 25
            reasons.add("Live TLS X.509 certificate is expired")
        }

        val verdict = when {
            score >= 50 -> "HIGH"
            score >= 20 -> "MEDIUM"
            else -> "LOW"
        }

        // Collect deduplicated pivotable child entities across all 12+ free feeds
        val pivots = LinkedHashMap<String, PivotEntity>()
        fun addPivot(raw: String, hint: PivotEntityType? = null, source: String) {
            if (raw.isBlank()) return
            val ent = PivotEngine.normalize(raw, hint, source)
            if (ent.normalizedValue.equals(s.normalizedTarget, ignoreCase = true)) return
            val key = "${ent.type.name}::${ent.normalizedValue.lowercase()}"
            pivots.putIfAbsent(key, ent)
        }

        s.ipRecon?.ip?.let { addPivot(it, PivotEntityType.IP_ADDRESS, "Resolved Host IP") }
        s.ipRecon?.hostnames?.take(5)?.forEach { addPivot(it, PivotEntityType.DOMAIN, "Reverse DNS") }
        s.deepWebCrawl?.emails?.take(8)?.forEach { addPivot(it, PivotEntityType.EMAIL, "Web/JS Scraper") }
        s.deepWebCrawl?.cloudBuckets?.take(4)?.forEach { addPivot(it, PivotEntityType.DOMAIN, "Cloud Bucket") }
        s.githubProfile?.commitEmails?.take(6)?.forEach { addPivot(it, PivotEntityType.EMAIL, "GitHub Commit") }
        s.githubProfile?.blogUrl?.takeIf { it.isNotBlank() }?.let { addPivot(it, source = "GitHub Blog") }
        s.githubProfile?.twitterHandle?.takeIf { it.isNotBlank() }?.let { addPivot(it, PivotEntityType.USERNAME, "GitHub X Handle") }
        s.keybaseIdentity?.verifiedProofs?.take(6)?.forEach { (svc, handle) ->
            addPivot(handle, source = "Keybase $svc")
        }
        s.emailFootprint?.githubMatchedUsers?.forEach { addPivot(it, PivotEntityType.USERNAME, "GitHub Email Match") }
        s.dnsRecords.filter { it.type in setOf("A", "MX", "NS") }.take(8).forEach { rec ->
            val hint = if (rec.type == "A") PivotEntityType.IP_ADDRESS else PivotEntityType.DOMAIN
            addPivot(rec.data, hint, "DNS ${rec.type}")
        }
        s.tlsCertReport?.sanDomains?.take(6)?.forEach { addPivot(it, PivotEntityType.DOMAIN, "Live TLS SAN") }
        s.tlsAudit?.certSans?.take(6)?.forEach { addPivot(it, PivotEntityType.DOMAIN, "TLS SAN") }
        s.otxReport?.passiveDnsHosts?.take(6)?.forEach { addPivot(it, source = "OTX Passive DNS") }
        s.waybackReport?.discoveredHosts?.take(5)?.forEach { addPivot(it, PivotEntityType.DOMAIN, "Wayback Host") }
        s.subdomains?.subdomains?.take(6)?.forEach { addPivot(it, PivotEntityType.DOMAIN, "CT Subdomain") }
        s.webTech?.externalDomains?.take(6)?.forEach { addPivot(it, PivotEntityType.DOMAIN, "Linked External Host") }
        s.redirectChain?.finalUrl?.let { addPivot(it, PivotEntityType.URL, "Final Redirect URL") }
        s.gravatar?.preferredUsername?.takeIf { it.isNotBlank() }?.let {
            addPivot(it, PivotEntityType.USERNAME, "Gravatar Handle")
        }
        if (s.entityType == PivotEntityType.EMAIL) {
            val dom = s.normalizedTarget.substringAfter("@", "")
            val user = s.normalizedTarget.substringBefore("@", "")
            if (dom.contains(".")) addPivot(dom, PivotEntityType.DOMAIN, "Email Domain")
            if (user.length >= 2) addPivot(user, PivotEntityType.USERNAME, "Email Prefix")
        }

        _uiState.update {
            it.copy(
                riskVerdict = verdict,
                riskReasons = reasons,
                discoveredEntities = pivots.values.take(28).toList()
            )
        }
    }

    suspend fun saveFullDossierToNewCase(): String {
        val s = _uiState.value
        val newCase = caseRepository.createCase(
            title = "Target Dossier: ${s.normalizedTarget}",
            target = s.normalizedTarget,
            notes = buildExecutiveSummaryText()
        )
        buildArtifactsForExport(newCase.id).forEach { art ->
            caseRepository.attachArtifact(art)
        }
        _uiState.update { it.copy(savedCaseId = newCase.id) }
        return newCase.id
    }

    fun exportDossierHtml(): String {
        val s = _uiState.value
        val tempCase = InvestigationCase(
            id = s.savedCaseId ?: "temp-dossier",
            title = "Target Dossier: ${s.normalizedTarget}",
            target = s.normalizedTarget,
            notes = buildExecutiveSummaryText()
        )
        return CaseReportExporter.exportHtml(
            targetCase = tempCase,
            artifacts = buildArtifactsForExport(tempCase.id),
            aiExecutiveSummary = s.aiInsight?.briefText
        )
    }

    fun analyzeWithByokAi() {
        val s = _uiState.value
        if (s.normalizedTarget.isBlank() || s.isAiAnalyzing) return
        if (ApiKeyVault.getActiveAiConfig() == null) {
            _uiState.update { it.copy(aiError = "No BYOK AI key connected. Tap Setup AI to add OpenRouter, Claude, OpenAI, Gemini, or Groq.") }
            return
        }

        _uiState.update { it.copy(isAiAnalyzing = true, aiError = null) }
        viewModelScope.launch {
            val digest = buildString {
                appendLine(buildExecutiveSummaryText())
                buildArtifactsForExport("preview").forEach { art ->
                    appendLine("- [${art.wingType}] ${art.title}: ${art.summary}")
                }
                if (s.discoveredEntities.isNotEmpty()) {
                    appendLine("Correlated Entities: ${s.discoveredEntities.take(24).joinToString(", ") { it.normalizedValue }}")
                }
            }
            ByokAiService.analyzeTargetDossier(s.normalizedTarget, digest).fold(
                onSuccess = { insight ->
                    _uiState.update { it.copy(isAiAnalyzing = false, aiInsight = insight, aiError = null) }
                },
                onFailure = { err ->
                    _uiState.update { it.copy(isAiAnalyzing = false, aiError = err.message ?: "AI analysis failed") }
                }
            )
        }
    }

    fun exportDossierJson(): String {
        val s = _uiState.value
        val tempCase = InvestigationCase(
            id = s.savedCaseId ?: "temp-dossier",
            title = "Target Dossier: ${s.normalizedTarget}",
            target = s.normalizedTarget,
            notes = buildExecutiveSummaryText()
        )
        return CaseReportExporter.exportJson(tempCase, buildArtifactsForExport(tempCase.id))
    }

    private fun buildExecutiveSummaryText(): String {
        val s = _uiState.value
        val typeLabel = if (s.isEntityKeyword) "PERSON/ORG" else (s.entityType?.badgeLabel ?: "TARGET")
        return buildString {
            append("Universal Deep Auto-Chain Dossier for ${s.normalizedTarget} ($typeLabel). ")
            append("Risk Verdict: ${s.riskVerdict}. ")
            if (s.riskReasons.isNotEmpty()) {
                append("Findings: ${s.riskReasons.joinToString("; ")}.")
            } else {
                append("No critical threat flags detected across queried passive feeds.")
            }
        }
    }

    private fun buildArtifactsForExport(caseId: String): List<ScanArtifact> {
        val s = _uiState.value
        val list = mutableListOf<ScanArtifact>()

        s.deepWebCrawl?.let { c ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "DEEP_WEB",
                    artifactType = "JS_HTML_SCRAPE",
                    queryTarget = c.targetHost,
                    title = "Deep Web & JS Scraper (${c.jsFilesScanned} JS bundles)",
                    summary = "Emails: ${c.emails.take(6).joinToString(", ").ifBlank { "None" }} • Socials: ${c.socialLinks.size} • Trackers: ${c.trackingIds.joinToString(", ") { it.id }.ifBlank { "None" }} • APIs: ${c.apiEndpoints.size} • Buckets: ${c.cloudBuckets.size}",
                    rawJson = "{}",
                    sourceApi = "OSINTme Passive Web/JS Crawler"
                )
            )
        }
        s.otxReport?.let { otx ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "THREAT_INTEL",
                    artifactType = "ALIENVAULT_OTX",
                    queryTarget = otx.indicator,
                    title = "AlienVault OTX (${otx.pulseCount} Pulses)",
                    summary = "Pulses: ${otx.pulseCount} • Tags: ${otx.tags.take(6).joinToString(", ").ifBlank { "None" }} • Passive DNS hosts: ${otx.passiveDnsHosts.size}",
                    rawJson = "{}",
                    sourceApi = "AlienVault OTX Public API"
                )
            )
        }
        s.waybackReport?.let { wb ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "ARCHIVE",
                    artifactType = "WAYBACK_CDX",
                    queryTarget = wb.targetDomain,
                    title = "Wayback CDX Archive (${wb.snapshots.size} URLs)",
                    summary = "Sensitive: ${wb.sensitiveCount} • Docs: ${wb.documentCount} • Deleted/4xx: ${wb.deletedCount} • Span: ${wb.earliestYear ?: "?"}–${wb.latestYear ?: "?"}",
                    rawJson = "{}",
                    sourceApi = "Internet Archive Wayback CDX"
                )
            )
        }
        s.tlsCertReport?.let { cert ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "TLS_CERT",
                    artifactType = "LIVE_X509",
                    queryTarget = cert.host,
                    title = "Live TLS X.509 Certificate (${cert.protocol})",
                    summary = "Issuer: ${cert.issuerCn} • Days left: ${cert.daysRemaining} • SANs: ${cert.sanDomains.size} • SHA-256: ${cert.sha256Fingerprint.take(28)}...",
                    rawJson = "{}",
                    sourceApi = "Live SNI SSLSocket Handshake"
                )
            )
        }
        s.takeoverSummary?.let { tk ->
            val vuln = tk.findings.count { it.severity == TakeoverSeverity.CONFIRMED_VULNERABLE }
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "SUBDOMAIN_TAKEOVER",
                    artifactType = "CNAME_AUDIT",
                    queryTarget = tk.rootDomain,
                    title = "Subdomain Takeover Scan (${tk.totalSubdomainsChecked} Checked)",
                    summary = "Confirmed vulnerable: $vuln • Cloud CNAME findings: ${tk.findings.size}",
                    rawJson = "{}",
                    sourceApi = "OSINTme CNAME Takeover Engine"
                )
            )
        }
        s.githubProfile?.let { gh ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "IDENTITY",
                    artifactType = "GITHUB_DEEP",
                    queryTarget = gh.username,
                    title = "GitHub Deep Profile (@${gh.username})",
                    summary = "${gh.displayName.ifBlank { gh.username }} • ${gh.publicRepos} repos • ${gh.followers} followers • Commit emails: ${gh.commitEmails.joinToString(", ").ifBlank { "None" }}",
                    rawJson = "{}",
                    sourceApi = "GitHub Public API"
                )
            )
        }
        s.keybaseIdentity?.let { kb ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "IDENTITY",
                    artifactType = "KEYBASE_PROOFS",
                    queryTarget = kb.username,
                    title = "Keybase Identity (${kb.verifiedProofs.size} Proofs)",
                    summary = "${kb.fullName.ifBlank { kb.username }} • Proofs: ${kb.verifiedProofs.joinToString(", ") { "${it.first}:${it.second}" }}",
                    rawJson = "{}",
                    sourceApi = "Keybase Public API"
                )
            )
        }
        s.emailFootprint?.let { ef ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "IDENTITY",
                    artifactType = "EMAIL_FOOTPRINT",
                    queryTarget = ef.email,
                    title = "Email Provider & OpenPGP Footprint",
                    summary = "Suite: ${ef.mailProviderSuite} • OpenPGP: ${ef.pgpKeySummary} • GitHub matches: ${ef.githubMatchedUsers.joinToString(", ").ifBlank { "None" }}",
                    rawJson = "{}",
                    sourceApi = "OpenPGP + GitHub + MX Fingerprint"
                )
            )
        }
        s.entitySearch?.let { ent ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "ENTITY_SEARCH",
                    artifactType = "PUBLIC_MENTIONS",
                    queryTarget = ent.query,
                    title = "Universal Entity Mentions (${ent.query})",
                    summary = "Wiki: ${ent.wikiTitle.ifBlank { "None" }} • GitHub matches: ${ent.githubProfiles.size} • HN/Reddit mentions: ${ent.webMentions.size}",
                    rawJson = "{}",
                    sourceApi = "Wikipedia + GitHub + HackerNews + Reddit"
                )
            )
        }
        s.ipRecon?.let { ip ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "NETWORK",
                    artifactType = "IP_PORTS",
                    queryTarget = ip.ip,
                    title = "Shodan & GeoIP (${ip.ip})",
                    summary = "${ip.org} (${ip.city}, ${ip.country}) • Ports: ${ip.ports.joinToString(", ").ifBlank { "None" }} • CVEs: ${ip.vulns.size}",
                    rawJson = "{}",
                    sourceApi = "Shodan + GeoIP"
                )
            )
        }
        s.bgpAsn?.let { bgp ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "BGP_ASN",
                    artifactType = "ASN_ROUTING",
                    queryTarget = bgp.ip,
                    title = "BGP Origin ${bgp.asn}",
                    summary = "Holder: ${bgp.holder} • Prefix: ${bgp.prefix} • ${bgp.totalAnnouncedCount} announced prefixes",
                    rawJson = "{}",
                    sourceApi = "RIPEstat"
                )
            )
        }
        s.webTech?.let { web ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "WEB_RECON",
                    artifactType = "TECH_STACK",
                    queryTarget = web.targetHost,
                    title = "Web Stack & Reconnaissance",
                    summary = "HTTP ${web.httpStatus} • Title: ${web.pageTitle.ifBlank { "N/A" }} • Tech: ${web.technologies.joinToString(", ") { it.name }.ifBlank { "Generic" }} • robots.txt disallowed: ${web.robotsDisallowed.size}",
                    rawJson = "{}",
                    sourceApi = "Direct Passive Web Recon"
                )
            )
        }
        s.tlsAudit?.let { tls ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "TLS_AUDIT",
                    artifactType = "CERT_HEADERS",
                    queryTarget = s.normalizedTarget,
                    title = "TLS & Security Headers (Grade ${tls.securityGrade})",
                    summary = "${tls.tlsProtocol} • Issuer: ${tls.certIssuer} • ${tls.passedHeadersCount}/${tls.totalCheckedHeaders} headers passed",
                    rawJson = "{}",
                    sourceApi = "Direct TLS Handshake"
                )
            )
        }
        s.urlhaus?.let { uh ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "THREAT_INTEL",
                    artifactType = "MALWARE_REP",
                    queryTarget = uh.target,
                    title = "Threat DNS & URLhaus Verdict",
                    summary = "Malicious: ${uh.isMalicious} • Cloudflare 1.1.1.2 blocked: ${uh.cloudflareMalwareBlocked} • URLhaus entries: ${uh.urlCount}",
                    rawJson = "{}",
                    sourceApi = "Cloudflare 1.1.1.2 + URLhaus"
                )
            )
        }
        s.virusTotal?.let { vt ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "BYOK_INTEL",
                    artifactType = "VIRUSTOTAL",
                    queryTarget = vt.target,
                    title = "VirusTotal v3 Detection Report",
                    summary = "Malicious: ${vt.maliciousCount}/${vt.totalEngines} • Suspicious: ${vt.suspiciousCount} • Reputation: ${vt.reputation}",
                    rawJson = "{}",
                    sourceApi = "VirusTotal v3 (BYOK)"
                )
            )
        }
        s.abuseIpdb?.let { ab ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "BYOK_INTEL",
                    artifactType = "ABUSEIPDB",
                    queryTarget = ab.ipAddress,
                    title = "AbuseIPDB Confidence (${ab.abuseConfidenceScore}%)",
                    summary = "Reports: ${ab.totalReports} • ISP: ${ab.isp} • Usage: ${ab.usageType} • Tor: ${ab.isTor}",
                    rawJson = "{}",
                    sourceApi = "AbuseIPDB v2 (BYOK)"
                )
            )
        }
        s.malwareBazaar?.let { mb ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "HASH_INTEL",
                    artifactType = "MALWAREBAZAAR",
                    queryTarget = mb.hash,
                    title = "MalwareBazaar Hash Check",
                    summary = if (mb.found) "FOUND: ${mb.signature} (${mb.fileName}, ${mb.fileType})" else mb.note.ifBlank { "Not listed" },
                    rawJson = "{}",
                    sourceApi = "abuse.ch MalwareBazaar"
                )
            )
        }
        s.breachResult?.let { br ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "IDENTITY",
                    artifactType = "BREACH_AUDIT",
                    queryTarget = br.email,
                    title = "Breach Exposure (${br.totalBreaches} Leaks)",
                    summary = if (br.isBreached) "Breaches: ${br.breaches.take(8).joinToString(", ") { it.siteName }}" else "No public breaches found",
                    rawJson = "{}",
                    sourceApi = "XposedOrNot"
                )
            )
        }
        if (s.usernameHits.isNotEmpty()) {
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "IDENTITY",
                    artifactType = "USERNAME_HITS",
                    queryTarget = s.normalizedTarget,
                    title = "Confirmed Platform Profiles (${s.usernameHits.size})",
                    summary = s.usernameHits.take(30).joinToString(", ") { "${it.platformName} (${it.profileUrl})" },
                    rawJson = "{}",
                    sourceApi = "OSINTme 106+ Platform Engine"
                )
            )
        }
        s.aiInsight?.let { ai ->
            list.add(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseId,
                    wingType = "BYOK_AI",
                    artifactType = "AI_EXECUTIVE_BRIEF",
                    queryTarget = s.normalizedTarget,
                    title = "AI Dossier Synthesis (${ai.providerName})",
                    summary = ai.briefText.take(2200),
                    rawJson = "{}",
                    sourceApi = "${ai.providerName} (${ai.modelId})"
                )
            )
        }
        return list
    }
}
