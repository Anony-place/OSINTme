package com.oopssecurity.osintme.ui.sanitizer

import androidx.lifecycle.ViewModel
import com.oopssecurity.osintme.data.ads.AdMediationManager
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.util.SanitizationResult
import com.oopssecurity.osintme.util.UrlSanitizer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class SanitizerUiState(
    val inputUrl: String = "",
    val result: SanitizationResult? = null
)

class LinkSanitizerViewModel(
    private val historyManager: LocalScanHistoryManager? = null
) : ViewModel() {

    private val _uiState = MutableStateFlow(SanitizerUiState())
    val uiState: StateFlow<SanitizerUiState> = _uiState.asStateFlow()

    fun setInputUrl(url: String) {
        _uiState.value = _uiState.value.copy(inputUrl = url)
    }

    fun sanitize(urlOverride: String? = null) {
        val target = (urlOverride ?: _uiState.value.inputUrl).trim()
        if (target.isEmpty()) return

        val cleanResult = UrlSanitizer.sanitize(target)
        _uiState.value = _uiState.value.copy(
            inputUrl = target,
            result = cleanResult
        )

        historyManager?.addScan(
            type = "Link Sanitizer",
            target = target.take(40) + "...",
            summary = "Stripped ${cleanResult.removedParams.size} tracking tokens (${cleanResult.bytesSaved} bytes saved)"
        )
        AdMediationManager.recordCompletedScan()
    }
}
