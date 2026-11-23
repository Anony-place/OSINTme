package com.oopssecurity.osintme.ui.exif

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.oopssecurity.osintme.data.ads.AdMediationManager
import com.oopssecurity.osintme.data.local.ImageExifCleaner
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.ExifMetadata
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class ExifUiState(
    val imageUri: Uri? = null,
    val isExtracting: Boolean = false,
    val isStripping: Boolean = false,
    val metadata: ExifMetadata? = null,
    val cleanUri: Uri? = null,
    val error: String? = null
)

class ExifViewModel(
    private val context: Context,
    initialUriString: String? = null,
    private val historyManager: LocalScanHistoryManager = LocalScanHistoryManager(context)
) : ViewModel() {

    private val _uiState = MutableStateFlow(ExifUiState())
    val uiState: StateFlow<ExifUiState> = _uiState.asStateFlow()

    init {
        if (!initialUriString.isNullOrBlank()) {
            try {
                setImageUri(Uri.parse(initialUriString))
            } catch (e: Exception) {
                // Ignore parse errors
            }
        }
    }

    fun setImageUri(uri: Uri) {
        _uiState.value = _uiState.value.copy(
            imageUri = uri,
            isExtracting = true,
            metadata = null,
            cleanUri = null,
            error = null
        )

        viewModelScope.launch {
            val result = ImageExifCleaner.extractMetadata(context, uri)
            result.onSuccess { meta ->
                _uiState.value = _uiState.value.copy(
                    isExtracting = false,
                    metadata = meta
                )
                historyManager.addScan(
                    type = "EXIF Inspection",
                    target = meta.model ?: "Photo Metadata",
                    summary = if (meta.hasGps) "Exposed GPS (${meta.latitude}, ${meta.longitude})" else "Device info extracted"
                )
                AdMediationManager.recordCompletedScan()
            }.onFailure { err ->
                _uiState.value = _uiState.value.copy(
                    isExtracting = false,
                    error = err.message ?: "Failed to read image metadata"
                )
            }
        }
    }

    fun stripAndShare(onReadyToShare: (Uri) -> Unit) {
        val uri = _uiState.value.imageUri ?: return
        _uiState.value = _uiState.value.copy(isStripping = true)

        viewModelScope.launch {
            val result = ImageExifCleaner.stripAndCreateCleanImage(context, uri)
            result.onSuccess { cleanUri ->
                _uiState.value = _uiState.value.copy(
                    isStripping = false,
                    cleanUri = cleanUri
                )
                historyManager.addScan(
                    type = "EXIF Stripper",
                    target = "Metadata Cleared",
                    summary = "Generated sanitized image without device or GPS tags"
                )
                onReadyToShare(cleanUri)
            }.onFailure { err ->
                _uiState.value = _uiState.value.copy(
                    isStripping = false,
                    error = err.message ?: "Failed to strip metadata"
                )
            }
        }
    }
}
