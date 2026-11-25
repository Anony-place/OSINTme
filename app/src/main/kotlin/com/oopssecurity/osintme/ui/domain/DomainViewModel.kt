package com.oopssecurity.osintme.ui.domain

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.BgpAsnInfo
import com.oopssecurity.osintme.data.model.DnsRecordItem
import com.oopssecurity.osintme.data.model.EmailSecurityAudit
import com.oopssecurity.osintme.data.model.IpReconResult
import com.oopssecurity.osintme.data.model.RdapDomainInfo
import com.oopssecurity.osintme.data.model.SubdomainResult
import com.oopssecurity.osintme.data.model.TlsHeaderAuditResult
import com.oopssecurity.osintme.data.model.WaybackUrlItem
import com.oopssecurity.osintme.data.model.WebTechReconResult
import com.oopssecurity.osintme.data.network.BgpAsnService
import com.oopssecurity.osintme.data.network.CloudflareDohService
import com.oopssecurity.osintme.data.network.CrtShService
import com.oopssecurity.osintme.data.network.RdapService
import com.oopssecurity.osintme.data.network.ShodanService
import com.oopssecurity.osintme.data.network.TlsHeaderAuditService
import com.oopssecurity.osintme.data.network.WaybackService
import com.oopssecurity.osintme.data.network.WebTechReconService
import com.oopssecurity.osintme.util.InputClassifier
import com.oopssecurity.osintme.util.InputType
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class DomainUiState(
    val target: String = "",
    val isLoading: Boolean = false,
    val isIpTarget: Boolean = false,
    val ipResult: IpReconResult? = null,
    val tlsAudit: TlsHeaderAuditResult? = null,
    val webTech: WebTechReconResult? = null,
    val bgpAsn: BgpAsnInfo? = null,
    val subdomainResult: SubdomainResult? = null,
    val dnsRecords: List<DnsRecordItem> = emptyList(),
    val emailSecurity: EmailSecurityAudit? = null,
    val rdapInfo: RdapDomainInfo? = null,
    val waybackUrls: List<WaybackUrlItem> = emptyList(),
    val error: String? = null,
    val activeTab: Int = 0 // 0: Host & IP, 1: Web & BGP, 2: TLS & Headers, 3: Subdomains, 4: DNS & Email, 5: WHOIS, 6: Wayback
)

class DomainViewModel(
    context: Context,
    private val historyManager: LocalScanHistoryManager = LocalScanHistoryManager(context)
) : ViewModel() {

    private val _uiState = MutableStateFlow(DomainUiState())
    val uiState: StateFlow<DomainUiState> = _uiState.asStateFlow()

    fun setTarget(target: String) {
        _uiState.value = _uiState.value.copy(target = target)
    }

    fun selectTab(tab: Int) {
        _uiState.value = _uiState.value.copy(activeTab = tab)
    }

    fun executeScan(targetOverride: String? = null) {
        val raw = (targetOverride ?: _uiState.value.target).trim()
        if (raw.isEmpty()) return

        val target = raw
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore("/")
            .trim()

        val inputType = InputClassifier.classify(target)
        val isIp = (inputType == InputType.IP_ADDRESS)

        _uiState.value = _uiState.value.copy(
            target = target,
            isLoading = true,
            isIpTarget = isIp,
            ipResult = null,
            tlsAudit = null,
            webTech = null,
            bgpAsn = null,
            subdomainResult = null,
            dnsRecords = emptyList(),
            emailSecurity = null,
            rdapInfo = null,
            waybackUrls = emptyList(),
            error = null
        )

        viewModelScope.launch {
            if (isIp) {
                val shodanDeferred = async { ShodanService.lookupIp(target) }
                val bgpDeferred = async { BgpAsnService.lookupIpOrHost(target) }
                val tlsDeferred = async { TlsHeaderAuditService.inspectTarget(target) }

                val shodanResult = shodanDeferred.await()
                val bgpResult = bgpDeferred.await().getOrNull()
                val tlsResult = tlsDeferred.await().getOrNull()

                shodanResult.fold(
                    onSuccess = { ipData ->
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            ipResult = ipData,
                            bgpAsn = bgpResult,
                            tlsAudit = tlsResult
                        )
                        historyManager.addScan(
                            type = "IP Recon",
                            target = target,
                            summary = "${ipData.ports.size} open ports • ${bgpResult?.asn ?: ipData.asn} • ${ipData.isp.ifBlank { ipData.country }}"
                        )
                    },
                    onFailure = { err ->
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            bgpAsn = bgpResult,
                            tlsAudit = tlsResult,
                            error = err.message ?: "Failed to query IP intelligence"
                        )
                    }
                )
            } else {
                val crtDeferred = async { CrtShService.findSubdomains(target) }
                val dohDeferred = async { CloudflareDohService.resolveAll(target) }
                val emailSecDeferred = async { CloudflareDohService.auditEmailSecurity(target) }
                val tlsDeferred = async { TlsHeaderAuditService.inspectTarget(target) }
                val webTechDeferred = async { WebTechReconService.inspectHost(target) }
                val rdapDeferred = async { RdapService.fetchWhois(target) }
                val waybackDeferred = async { WaybackService.fetchArchivedUrls(target) }

                val dns = dohDeferred.await().getOrDefault(emptyList())
                val firstA = dns.firstOrNull { it.type == "A" }?.data
                val ipDeferred = async {
                    if (firstA != null && InputClassifier.classify(firstA) == InputType.IP_ADDRESS) {
                        ShodanService.lookupIp(firstA).getOrNull()
                    } else null
                }
                val bgpDeferred = async {
                    if (firstA != null && InputClassifier.classify(firstA) == InputType.IP_ADDRESS) {
                        BgpAsnService.lookupIpOrHost(firstA).getOrNull()
                    } else null
                }

                val subdomains = crtDeferred.await().getOrNull()
                val emailSec = emailSecDeferred.await().getOrNull()
                val tlsAudit = tlsDeferred.await().getOrNull()
                val webTech = webTechDeferred.await().getOrNull()
                val rdap = rdapDeferred.await().getOrNull()
                val wayback = waybackDeferred.await().getOrDefault(emptyList())
                val ipData = ipDeferred.await()
                val bgp = bgpDeferred.await()

                val allFailed = subdomains == null && dns.isEmpty() && tlsAudit == null &&
                    rdap == null && ipData == null && webTech == null

                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    subdomainResult = subdomains,
                    dnsRecords = dns,
                    emailSecurity = emailSec,
                    tlsAudit = tlsAudit,
                    webTech = webTech,
                    bgpAsn = bgp,
                    rdapInfo = rdap,
                    waybackUrls = wayback,
                    ipResult = ipData,
                    error = if (allFailed) "Unable to resolve domain intelligence. Check spelling or network connectivity." else null
                )

                if (!allFailed) {
                    val gradeStr = tlsAudit?.let { " • TLS ${it.securityGrade}" } ?: ""
                    historyManager.addScan(
                        type = "Domain Recon",
                        target = target,
                        summary = "${subdomains?.totalCount ?: 0} subs • ${webTech?.technologies?.size ?: 0} tech$gradeStr"
                    )
                }
            }
        }
    }
}
