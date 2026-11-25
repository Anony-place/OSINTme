package com.oopssecurity.osintme.ui.exif

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
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
            runCatching { Uri.parse(initialUriString) }.getOrNull()?.let { setImageUri(it) }
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
                    target = meta.model ?: "Image Forensics",
                    summary = if (meta.hasGps) {
                        "GPS exposed (${String.format("%.4f", meta.latitude)}, ${String.format("%.4f", meta.longitude)})"
                    } else {
                        "SHA-256 & EXIF extracted (${meta.fileSizeFormatted})"
                    }
                )
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
                    type = "EXIF Sanitizer",
                    target = "Clean Copy Exported",
                    summary = "Stripped camera, software, and GPS metadata segments"
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
