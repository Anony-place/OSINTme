package com.oopssecurity.osintme.ui.phone

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.ads.AdMediationManager
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.PhoneReconResult
import com.oopssecurity.osintme.data.network.PhoneReconService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class PhoneUiState(
    val inputNumber: String = "",
    val isLoading: Boolean = false,
    val result: PhoneReconResult? = null,
    val error: String? = null
)

class PhoneViewModel(
    context: Context,
    private val historyManager: LocalScanHistoryManager = LocalScanHistoryManager(context)
) : ViewModel() {

    private val _uiState = MutableStateFlow(PhoneUiState())
    val uiState: StateFlow<PhoneUiState> = _uiState.asStateFlow()

    fun setInputNumber(number: String) {
        _uiState.value = _uiState.value.copy(inputNumber = number)
    }

    fun executeScan(overrideNumber: String? = null) {
        val numberToScan = (overrideNumber ?: _uiState.value.inputNumber).trim()
        if (numberToScan.isEmpty()) return

        _uiState.value = _uiState.value.copy(
            inputNumber = numberToScan,
            isLoading = true,
            error = null,
            result = null
        )

        viewModelScope.launch {
            val analysis = PhoneReconService.analyzeNumber(numberToScan)
            analysis.fold(
                onSuccess = { res ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        result = res
                    )
                    historyManager.addScan(
                        type = "Phone Recon",
                        target = res.e164Format,
                        summary = "${res.countryName} • ${res.lineType}"
                    )
                    AdMediationManager.recordCompletedScan()
                },
                onFailure = { err ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        error = err.message ?: "Failed to analyze phone number"
                    )
                }
            )
        }
    }
}
