package com.oopssecurity.osintme.ui.domain

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.ads.AdMediationManager
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.AffiliateOffer
import com.oopssecurity.osintme.data.model.DnsRecordItem
import com.oopssecurity.osintme.data.model.IpReconResult
import com.oopssecurity.osintme.data.model.RdapDomainInfo
import com.oopssecurity.osintme.data.model.SubdomainResult
import com.oopssecurity.osintme.data.model.WaybackUrlItem
import com.oopssecurity.osintme.data.network.CloudflareDohService
import com.oopssecurity.osintme.data.network.CrtShService
import com.oopssecurity.osintme.data.network.RdapService
import com.oopssecurity.osintme.data.network.ShodanService
import com.oopssecurity.osintme.data.network.SupabaseService
import com.oopssecurity.osintme.data.network.WaybackService
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
    val subdomainResult: SubdomainResult? = null,
    val dnsRecords: List<DnsRecordItem> = emptyList(),
    val rdapInfo: RdapDomainInfo? = null,
    val waybackUrls: List<WaybackUrlItem> = emptyList(),
    val partnerOffers: List<AffiliateOffer> = emptyList(),
    val error: String? = null,
    val activeTab: Int = 0 // 0: Overview/Ports, 1: Subdomains, 2: DNS & RDAP, 3: WHOIS, 4: Wayback
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
        val target = (targetOverride ?: _uiState.value.target).trim()
        if (target.isEmpty()) return

        val inputType = InputClassifier.classify(target)
        val isIp = (inputType == InputType.IP_ADDRESS)

        _uiState.value = _uiState.value.copy(
            target = target,
            isLoading = true,
            isIpTarget = isIp,
            ipResult = null,
            subdomainResult = null,
            dnsRecords = emptyList(),
            rdapInfo = null,
            waybackUrls = emptyList(),
            error = null
        )

        viewModelScope.launch {
            if (isIp) {
                val shodanDeferred = async { ShodanService.lookupIp(target) }
                val shodanResult = shodanDeferred.await()

                shodanResult.fold(
                    onSuccess = { ipData ->
                        val hasExposure = ipData.ports.isNotEmpty() || ipData.vulns.isNotEmpty()
                        val offers = if (hasExposure) {
                            SupabaseService.getAffiliateOffers("IP_EXPOSURE")
                        } else emptyList()

                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            ipResult = ipData,
                            partnerOffers = offers
                        )
                        historyManager.addScan(
                            type = "IP Recon",
                            target = target,
                            summary = "${ipData.ports.size} open ports, ${ipData.vulns.size} vulnerabilities"
                        )
                        AdMediationManager.recordCompletedScan()
                    },
                    onFailure = { err ->
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            error = err.message ?: "Failed to query IP intelligence"
                        )
                    }
                )
            } else {
                // Domain Recon: Execute crt.sh, DoH DNS, RDAP WHOIS, Wayback CDX concurrently
                val crtDeferred = async { CrtShService.findSubdomains(target) }
                val dohDeferred = async { CloudflareDohService.resolveAll(target) }
                val rdapDeferred = async { RdapService.fetchWhois(target) }
                val waybackDeferred = async { WaybackService.fetchArchivedUrls(target) }

                val crtResult = crtDeferred.await()
                val dohResult = dohDeferred.await()
                val rdapResult = rdapDeferred.await()
                val waybackResult = waybackDeferred.await()

                val subdomains = crtResult.getOrNull()
                val dns = dohResult.getOrDefault(emptyList())
                val rdap = rdapResult.getOrNull()
                val wayback = waybackResult.getOrDefault(emptyList())

                // Check if any resolved A record can be checked via Shodan
                val firstA = dns.firstOrNull { it.type == "A" }?.data
                var ipData: IpReconResult? = null
                if (firstA != null && InputClassifier.classify(firstA) == InputType.IP_ADDRESS) {
                    ipData = ShodanService.lookupIp(firstA).getOrNull()
                }

                val hasExposure = (ipData?.ports?.isNotEmpty() == true) || (subdomains?.totalCount ?: 0) > 20
                val offers = if (hasExposure) {
                    SupabaseService.getAffiliateOffers("IP_EXPOSURE")
                } else emptyList()

                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    subdomainResult = subdomains,
                    dnsRecords = dns,
                    rdapInfo = rdap,
                    waybackUrls = wayback,
                    ipResult = ipData,
                    partnerOffers = offers
                )

                historyManager.addScan(
                    type = "Domain Recon",
                    target = target,
                    summary = "${subdomains?.totalCount ?: 0} subdomains, ${dns.size} DNS, ${wayback.size} archives"
                )
                AdMediationManager.recordCompletedScan()
            }
        }
    }
}
