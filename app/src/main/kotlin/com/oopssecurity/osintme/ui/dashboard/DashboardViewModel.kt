package com.oopssecurity.osintme.ui.dashboard

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.local.ExposureScoreState
import com.oopssecurity.osintme.data.local.HygienePreferencesManager
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.AffiliateOffer
import com.oopssecurity.osintme.data.model.ScanHistoryItem
import com.oopssecurity.osintme.data.network.SupabaseService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class DashboardUiState(
    val query: String = "",
    val exposureScoreState: ExposureScoreState,
    val recentScans: List<ScanHistoryItem> = emptyList(),
    val partnerOffers: List<AffiliateOffer> = emptyList(),
    val isFirstLaunch: Boolean = false
)

class DashboardViewModel(
    context: Context,
    private val historyManager: LocalScanHistoryManager = LocalScanHistoryManager(context),
    private val hygieneManager: HygienePreferencesManager = HygienePreferencesManager(context)
) : ViewModel() {

    private val prefs = context.getSharedPreferences("osintme_app_prefs", Context.MODE_PRIVATE)

    private val _uiState = MutableStateFlow(
        DashboardUiState(
            exposureScoreState = hygieneManager.calculateScore(),
            isFirstLaunch = !prefs.getBoolean("disclaimer_accepted", false)
        )
    )
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    init {
        // Collect local history
        viewModelScope.launch {
            historyManager.historyFlow.collect { scans ->
                _uiState.value = _uiState.value.copy(recentScans = scans.take(5))
            }
        }

        // Collect exposure score
        viewModelScope.launch {
            hygieneManager.scoreFlow.collect { score ->
                _uiState.value = _uiState.value.copy(exposureScoreState = score)
            }
        }

        // Fetch partner offers
        viewModelScope.launch {
            val offers = SupabaseService.getAffiliateOffers("GENERAL")
            _uiState.value = _uiState.value.copy(partnerOffers = offers.take(2))
        }
    }

    fun onQueryChange(newQuery: String) {
        _uiState.value = _uiState.value.copy(query = newQuery)
    }

    fun refresh() {
        _uiState.value = _uiState.value.copy(
            exposureScoreState = hygieneManager.calculateScore()
        )
    }

    fun acceptDisclaimer() {
        prefs.edit().putBoolean("disclaimer_accepted", true).apply()
        _uiState.value = _uiState.value.copy(isFirstLaunch = false)
    }
}
