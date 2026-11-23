package com.oopssecurity.osintme.ui.breach

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.ads.AdMediationManager
import com.oopssecurity.osintme.data.local.HygienePreferencesManager
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.AffiliateOffer
import com.oopssecurity.osintme.data.model.EmailBreachResult
import com.oopssecurity.osintme.data.model.PasswordLeakResult
import com.oopssecurity.osintme.data.network.HibpPasswordService
import com.oopssecurity.osintme.data.network.SupabaseService
import com.oopssecurity.osintme.data.network.XposedOrNotService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class BreachUiState(
    val selectedTab: Int = 0, // 0 = Email, 1 = Password
    val emailInput: String = "",
    val passwordInput: String = "",
    val isCheckingEmail: Boolean = false,
    val isCheckingPassword: Boolean = false,
    val emailResult: EmailBreachResult? = null,
    val passwordResult: PasswordLeakResult? = null,
    val errorMessage: String? = null,
    val partnerOffers: List<AffiliateOffer> = emptyList()
)

class BreachViewModel(
    context: Context,
    initialEmail: String = "",
    private val historyManager: LocalScanHistoryManager = LocalScanHistoryManager(context),
    private val hygieneManager: HygienePreferencesManager = HygienePreferencesManager(context)
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        BreachUiState(
            emailInput = initialEmail
        )
    )
    val uiState: StateFlow<BreachUiState> = _uiState.asStateFlow()

    init {
        if (initialEmail.isNotBlank()) {
            checkEmail(initialEmail)
        }
        viewModelScope.launch {
            val offers = SupabaseService.getAffiliateOffers("BREACH")
            _uiState.value = _uiState.value.copy(partnerOffers = offers)
        }
    }

    fun selectTab(tabIndex: Int) {
        _uiState.value = _uiState.value.copy(selectedTab = tabIndex, errorMessage = null)
    }

    fun onEmailChange(email: String) {
        _uiState.value = _uiState.value.copy(emailInput = email)
    }

    fun onPasswordChange(pwd: String) {
        _uiState.value = _uiState.value.copy(passwordInput = pwd)
    }

    fun checkEmail(email: String = _uiState.value.emailInput) {
        val target = email.trim()
        if (target.isEmpty()) return

        _uiState.value = _uiState.value.copy(isCheckingEmail = true, errorMessage = null)

        viewModelScope.launch {
            val result = XposedOrNotService.checkEmail(target)
            result.onSuccess { breachData ->
                _uiState.value = _uiState.value.copy(
                    isCheckingEmail = false,
                    emailResult = breachData
                )
                // Record in private local history
                historyManager.addScan(
                    type = "Email Breach",
                    target = target,
                    summary = if (breachData.isBreached) "${breachData.totalBreaches} breaches found" else "0 breaches (Clean)"
                )
                // Deduct points from hygiene if breached
                if (breachData.isBreached) {
                    hygieneManager.recordBreachDeduction(breachData.totalBreaches)
                }
                AdMediationManager.recordCompletedScan()
            }.onFailure { err ->
                _uiState.value = _uiState.value.copy(
                    isCheckingEmail = false,
                    errorMessage = err.message ?: "Failed to query breach database"
                )
            }
        }
    }

    fun checkPassword() {
        val pwd = _uiState.value.passwordInput
        if (pwd.isEmpty()) return

        _uiState.value = _uiState.value.copy(isCheckingPassword = true, errorMessage = null)

        viewModelScope.launch {
            val result = HibpPasswordService.checkPassword(pwd)
            result.onSuccess { leakData ->
                _uiState.value = _uiState.value.copy(
                    isCheckingPassword = false,
                    passwordResult = leakData
                )
                historyManager.addScan(
                    type = "Password Check",
                    target = "Hash Prefix: ${leakData.sha1Prefix}***",
                    summary = if (leakData.isLeaked) "${leakData.leakCount} leak occurrences" else "Safe (0 leaks)"
                )
                if (leakData.isLeaked) {
                    hygieneManager.recordBreachDeduction(1)
                }
                AdMediationManager.recordCompletedScan()
            }.onFailure { err ->
                _uiState.value = _uiState.value.copy(
                    isCheckingPassword = false,
                    errorMessage = err.message ?: "Failed to evaluate password"
                )
            }
        }
    }
}
