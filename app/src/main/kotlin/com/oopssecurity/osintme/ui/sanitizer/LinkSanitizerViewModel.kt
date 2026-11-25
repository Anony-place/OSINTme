package com.oopssecurity.osintme.ui.sanitizer

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.RedirectChainResult
import com.oopssecurity.osintme.data.network.RedirectResolverService
import com.oopssecurity.osintme.util.SanitizationResult
import com.oopssecurity.osintme.util.UrlSanitizer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class SanitizerUiState(
    val inputUrl: String = "",
    val result: SanitizationResult? = null,
    val isResolvingRedirects: Boolean = false,
    val redirectChain: RedirectChainResult? = null,
    val redirectError: String? = null
)

class LinkSanitizerViewModel(
    private val historyManager: LocalScanHistoryManager? = null
) : ViewModel() {

    private val _uiState = MutableStateFlow(SanitizerUiState())
    val uiState: StateFlow<SanitizerUiState> = _uiState.asStateFlow()

    fun setInputUrl(url: String) {
        _uiState.value = _uiState.value.copy(inputUrl = url, redirectError = null)
    }

    fun sanitize(urlOverride: String? = null) {
        val target = (urlOverride ?: _uiState.value.inputUrl).trim()
        if (target.isEmpty()) return

        val cleanResult = UrlSanitizer.sanitize(target)
        _uiState.value = _uiState.value.copy(
            inputUrl = target,
            result = cleanResult,
            redirectError = null
        )

        historyManager?.addScan(
            type = "Link Sanitizer",
            target = if (target.length > 42) target.take(42) + "…" else target,
            summary = "Stripped ${cleanResult.removedParams.size} tracking tokens (${cleanResult.bytesSaved} bytes saved)"
        )
    }

    fun traceRedirects(urlOverride: String? = null) {
        val target = (urlOverride ?: _uiState.value.inputUrl).trim()
        if (target.isEmpty()) return

        _uiState.value = _uiState.value.copy(
            inputUrl = target,
            isResolvingRedirects = true,
            redirectChain = null,
            redirectError = null
        )

        viewModelScope.launch {
            RedirectResolverService.traceRedirects(target).fold(
                onSuccess = { chain ->
                    val sanitizedFinal = UrlSanitizer.sanitize(chain.finalUrl)
                    _uiState.value = _uiState.value.copy(
                        isResolvingRedirects = false,
                        redirectChain = chain,
                        result = sanitizedFinal
                    )
                    historyManager?.addScan(
                        type = "Redirect Trace",
                        target = if (target.length > 42) target.take(42) + "…" else target,
                        summary = "${chain.hops.size} hop(s) resolved • ${sanitizedFinal.removedParams.size} trackers stripped"
                    )
                },
                onFailure = { err ->
                    _uiState.value = _uiState.value.copy(
                        isResolvingRedirects = false,
                        redirectError = err.message ?: "Unable to resolve redirect chain"
                    )
                }
            )
        }
    }
}
