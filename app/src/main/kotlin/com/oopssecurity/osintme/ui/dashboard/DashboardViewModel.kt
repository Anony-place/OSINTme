package com.oopssecurity.osintme.ui.dashboard

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.local.ExposureScoreState
import com.oopssecurity.osintme.data.local.HygienePreferencesManager
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.local.case.CaseRepository
import com.oopssecurity.osintme.data.model.ScanHistoryItem
import com.oopssecurity.osintme.data.network.OpsecManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class DashboardUiState(
    val query: String = "",
    val exposureScoreState: ExposureScoreState,
    val recentScans: List<ScanHistoryItem> = emptyList(),
    val activeCasesCount: Int = 0,
    val activeApiKeysCount: Int = 0,
    val activeAiKeysCount: Int = 0,
    val activeAiProviderName: String? = null,
    val isProxyActive: Boolean = false,
    val opsecSummary: String = "Direct TLS",
    val isFirstLaunch: Boolean = false
)

class DashboardViewModel(
    context: Context,
    private val historyManager: LocalScanHistoryManager = LocalScanHistoryManager(context),
    private val hygieneManager: HygienePreferencesManager = HygienePreferencesManager(context),
    private val caseRepository: CaseRepository = CaseRepository(context)
) : ViewModel() {

    private val prefs = context.getSharedPreferences("osintme_app_prefs", Context.MODE_PRIVATE)

    private val _uiState = MutableStateFlow(
        DashboardUiState(
            exposureScoreState = hygieneManager.calculateScore(),
            activeApiKeysCount = ApiKeyVault.activeCount(),
            activeAiKeysCount = ApiKeyVault.activeAiCount(),
            activeAiProviderName = ApiKeyVault.getActiveAiConfig()?.provider?.displayName,
            isProxyActive = OpsecManager.getActiveProxy() != null,
            opsecSummary = OpsecManager.getActiveConfigSummary(),
            isFirstLaunch = !prefs.getBoolean("disclaimer_accepted", false)
        )
    )
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            historyManager.historyFlow.collect { scans ->
                _uiState.value = _uiState.value.copy(recentScans = scans.take(5))
            }
        }

        viewModelScope.launch {
            hygieneManager.scoreFlow.collect { score ->
                _uiState.value = _uiState.value.copy(exposureScoreState = score)
            }
        }

        viewModelScope.launch {
            ApiKeyVault.configuredProviders.collect { providers ->
                _uiState.value = _uiState.value.copy(activeApiKeysCount = providers.size)
            }
        }

        viewModelScope.launch {
            ApiKeyVault.configuredAiProviders.collect { aiProviders ->
                _uiState.value = _uiState.value.copy(
                    activeAiKeysCount = aiProviders.size,
                    activeAiProviderName = ApiKeyVault.getActiveAiConfig()?.provider?.displayName
                )
            }
        }

        viewModelScope.launch {
            ApiKeyVault.activeAiProvider.collect {
                _uiState.value = _uiState.value.copy(
                    activeAiProviderName = ApiKeyVault.getActiveAiConfig()?.provider?.displayName
                )
            }
        }

        refresh()
    }

    fun onQueryChange(newQuery: String) {
        _uiState.value = _uiState.value.copy(query = newQuery)
    }

    fun refresh() {
        viewModelScope.launch {
            val cases = caseRepository.getAllCases()
            _uiState.value = _uiState.value.copy(
                exposureScoreState = hygieneManager.calculateScore(),
                activeCasesCount = cases.size,
                activeApiKeysCount = ApiKeyVault.activeCount(),
                activeAiKeysCount = ApiKeyVault.activeAiCount(),
                activeAiProviderName = ApiKeyVault.getActiveAiConfig()?.provider?.displayName,
                isProxyActive = OpsecManager.getActiveProxy() != null,
                opsecSummary = OpsecManager.getActiveConfigSummary()
            )
        }
    }

    fun acceptDisclaimer() {
        prefs.edit().putBoolean("disclaimer_accepted", true).apply()
        _uiState.value = _uiState.value.copy(isFirstLaunch = false)
    }
}
