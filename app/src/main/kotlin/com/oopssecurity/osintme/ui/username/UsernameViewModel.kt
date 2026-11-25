package com.oopssecurity.osintme.ui.username

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
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
    val totalToScan: Int = PlatformReconService.ALL_PLATFORMS.size,
    val scannedCount: Int = 0,
    val selectedFilter: Int = 0 // 0 = All, 1 = Found, 2 = Not Found, 3 = Unverified/Rate-Limited
)

class UsernameViewModel(
    context: Context,
    initialUsername: String = "",
    private val historyManager: LocalScanHistoryManager = LocalScanHistoryManager(context)
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        UsernameUiState(usernameInput = initialUsername)
    )
    val uiState: StateFlow<UsernameUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null

    init {
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

    fun stopScan() {
        scanJob?.cancel()
        _uiState.value = _uiState.value.copy(isScanning = false)
    }

    fun startScan(username: String = _uiState.value.usernameInput) {
        val target = username.trim().removePrefix("@")
        if (target.isEmpty()) return

        scanJob?.cancel()
        val total = PlatformReconService.ALL_PLATFORMS.size

        _uiState.value = _uiState.value.copy(
            usernameInput = target,
            isScanning = true,
            results = emptyList(),
            totalToScan = total,
            scannedCount = 0
        )

        scanJob = viewModelScope.launch {
            val accumulated = mutableListOf<UsernameCheckResult>()
            PlatformReconService.scanUsernameFlow(target, limitPlatforms = null).collect { check ->
                accumulated.add(check)
                val sorted = accumulated.sortedWith(
                    compareBy<UsernameCheckResult> {
                        when (it.status) {
                            ReconStatus.FOUND -> 0
                            ReconStatus.RATE_LIMITED -> 1
                            ReconStatus.AVAILABLE -> 2
                            ReconStatus.ERROR -> 3
                            ReconStatus.IDLE, ReconStatus.CHECKING -> 4
                        }
                    }.thenBy { it.platformName }
                )
                _uiState.value = _uiState.value.copy(
                    results = sorted,
                    scannedCount = accumulated.size
                )
            }

            _uiState.value = _uiState.value.copy(isScanning = false)
            val foundCount = accumulated.count { it.status == ReconStatus.FOUND }
            historyManager.addScan(
                type = "Username Recon",
                target = "@$target",
                summary = "Found on $foundCount of ${accumulated.size} platforms"
            )
        }
    }
}
