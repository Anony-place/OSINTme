package com.oopssecurity.osintme.ui.username

import android.app.Activity
import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.ads.AdMediationManager
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.ReconStatus
import com.oopssecurity.osintme.data.model.UsernameCheckResult
import com.oopssecurity.osintme.data.network.PlatformReconService
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class UsernameUiState(
    val usernameInput: String = "",
    val isScanning: Boolean = false,
    val results: List<UsernameCheckResult> = emptyList(),
    val totalToScan: Int = 0,
    val scannedCount: Int = 0,
    val selectedFilter: Int = 0, // 0 = All, 1 = Found Only, 2 = Available Only
    val isDeepScanUnlocked: Boolean = false
)

class UsernameViewModel(
    context: Context,
    initialUsername: String = "",
    private val historyManager: LocalScanHistoryManager = LocalScanHistoryManager(context)
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        UsernameUiState(
            usernameInput = initialUsername,
            isDeepScanUnlocked = AdMediationManager.deepScanUnlocked.value
        )
    )
    val uiState: StateFlow<UsernameUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null

    init {
        viewModelScope.launch {
            AdMediationManager.deepScanUnlocked.collect { unlocked ->
                _uiState.value = _uiState.value.copy(isDeepScanUnlocked = unlocked)
            }
        }
        if (initialUsername.isNotBlank()) {
            startScan(initialUsername)
        }
    }

    fun onUsernameChange(name: String) {
        _uiState.value = _uiState.value.copy(usernameInput = name)
    }

    fun selectFilter(filterIndex: Int) {
        _uiState.value = _uiState.value.copy(selectedFilter = filterIndex)
    }

    fun startScan(username: String = _uiState.value.usernameInput) {
        val target = username.trim()
        if (target.isEmpty()) return

        scanJob?.cancel()
        val limit = if (_uiState.value.isDeepScanUnlocked) null else 15
        val total = limit ?: PlatformReconService.ALL_PLATFORMS.size

        _uiState.value = _uiState.value.copy(
            isScanning = true,
            results = emptyList(),
            totalToScan = total,
            scannedCount = 0
        )

        scanJob = viewModelScope.launch {
            val accumulated = mutableListOf<UsernameCheckResult>()
            PlatformReconService.scanUsernameFlow(target, limit).collect { check ->
                accumulated.add(check)
                _uiState.value = _uiState.value.copy(
                    results = accumulated.toList(),
                    scannedCount = accumulated.size
                )
            }

            _uiState.value = _uiState.value.copy(isScanning = false)
            val foundCount = accumulated.count { it.status == ReconStatus.FOUND }
            historyManager.addScan(
                type = "Username Recon",
                target = target,
                summary = "Found on $foundCount/${accumulated.size} platforms"
            )
            AdMediationManager.recordCompletedScan()
        }
    }

    fun unlockDeepScanWithReward(activity: Activity?) {
        AdMediationManager.showRewardedVideo(activity) {
            _uiState.value = _uiState.value.copy(isDeepScanUnlocked = true)
            // Re-run scan with full platform list
            startScan()
        }
    }
}
