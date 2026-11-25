package com.oopssecurity.osintme.ui.breach

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.local.HygienePreferencesManager
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.EmailBreachResult
import com.oopssecurity.osintme.data.model.EmailSecurityAudit
import com.oopssecurity.osintme.data.model.GravatarProfile
import com.oopssecurity.osintme.data.model.PasswordLeakResult
import com.oopssecurity.osintme.data.network.CloudflareDohService
import com.oopssecurity.osintme.data.network.GravatarService
import com.oopssecurity.osintme.data.network.HibpPasswordService
import com.oopssecurity.osintme.data.network.XposedOrNotService
import kotlinx.coroutines.async
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
    val gravatarProfile: GravatarProfile? = null,
    val emailSecurity: EmailSecurityAudit? = null,
    val passwordResult: PasswordLeakResult? = null,
    val errorMessage: String? = null
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

        _uiState.value = _uiState.value.copy(
            emailInput = target,
            isCheckingEmail = true,
            errorMessage = null,
            emailResult = null,
            gravatarProfile = null,
            emailSecurity = null
        )

        viewModelScope.launch {
            val breachDeferred = async { XposedOrNotService.checkEmail(target) }
            val gravatarDeferred = async { GravatarService.lookupProfile(target) }
            val domainSecDeferred = async {
                if (target.contains("@")) CloudflareDohService.auditEmailSecurity(target).getOrNull() else null
            }

            val breachResult = breachDeferred.await()
            val gravatarResult = gravatarDeferred.await().getOrNull()
            val domainSecResult = domainSecDeferred.await()

            breachResult.onSuccess { breachData ->
                _uiState.value = _uiState.value.copy(
                    isCheckingEmail = false,
                    emailResult = breachData,
                    gravatarProfile = gravatarResult,
                    emailSecurity = domainSecResult
                )
                historyManager.addScan(
                    type = "Email Breach",
                    target = target,
                    summary = if (breachData.isBreached) "${breachData.totalBreaches} breaches detected" else "0 public breaches"
                )
                if (breachData.isBreached) {
                    hygieneManager.recordBreachDeduction(breachData.totalBreaches)
                }
            }.onFailure { err ->
                _uiState.value = _uiState.value.copy(
                    isCheckingEmail = false,
                    gravatarProfile = gravatarResult,
                    emailSecurity = domainSecResult,
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
                    type = "Password Audit",
                    target = "SHA-1 Prefix: ${leakData.sha1Prefix}***",
                    summary = if (leakData.isLeaked) "${leakData.leakCount} corpus hits" else "0 corpus hits"
                )
                if (leakData.isLeaked) {
                    hygieneManager.recordBreachDeduction(1)
                }
            }.onFailure { err ->
                _uiState.value = _uiState.value.copy(
                    isCheckingPassword = false,
                    errorMessage = err.message ?: "Failed to evaluate password"
                )
            }
        }
    }
}
