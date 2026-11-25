package com.oopssecurity.osintme.ui.exif

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddPhotoAlternate
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Map
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import coil.compose.AsyncImage
import com.oopssecurity.osintme.data.model.ExifMetadata
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.CodeBlock
import com.oopssecurity.osintme.ui.components.SaveToCaseDialog
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.util.SafeBrowserLauncher

@Composable
fun ExifInspectorScreen(
    imageUriString: String? = null,
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: ExifViewModel = viewModel { ExifViewModel(context) }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    var showSaveDialog by remember { mutableStateOf(false) }

    // Play-compliant zero-permission Android Photo Picker
    val photoPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { uri: Uri? ->
        if (uri != null) {
            viewModel.setImageUri(uri)
        }
    }

    LaunchedEffect(imageUriString) {
        if (!imageUriString.isNullOrEmpty() && uiState.imageUri == null) {
            runCatching { Uri.parse(imageUriString) }.getOrNull()?.let { viewModel.setImageUri(it) }
        }
    }

    if (showSaveDialog && uiState.metadata != null) {
        val m = uiState.metadata!!
        val summary = buildList {
            if (m.hasGps) add("GPS: ${m.latitude}, ${m.longitude}") else add("No GPS tags")
            m.model?.let { add("Device: ${m.make.orEmpty()} $it".trim()) }
            if (m.sha256Hash.isNotBlank()) add("SHA-256: ${m.sha256Hash.take(16)}…")
        }.joinToString(" • ")

        SaveToCaseDialog(
            wingType = "FORENSICS",
            artifactType = "EXIF_IMAGE_FORENSICS",
            queryTarget = m.model ?: "Image Artifact",
            title = "EXIF Forensics (${m.fileSizeFormatted})",
            summary = summary,
            sourceApi = "On-Device ExifInterface + SHA-256",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "EXIF & Image Forensics",
                subtitle = "Zero-permission Photo Picker, SHA-256 & sanitizer",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (uiState.metadata != null) {
                    {
                        IconButton(
                            onClick = { showSaveDialog = true },
                            modifier = Modifier.size(48.dp).testTag("exif_save_case_button")
                        ) {
                            Icon(
                                imageVector = Icons.Default.BookmarkAdd,
                                contentDescription = "Save findings to case",
                                tint = SkyCyan
                            )
                        }
                    }
                } else null
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // Zero-permission Photo Picker Card
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                        .clickable {
                            photoPickerLauncher.launch(
                                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
                            )
                        }
                        .testTag("exif_pick_photo_button")
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(48.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(SkyCyan.copy(alpha = 0.14f))
                            .border(1.dp, SkyCyan.copy(alpha = 0.35f), RoundedCornerShape(10.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.AddPhotoAlternate, contentDescription = null, tint = SkyCyan)
                    }

                    Spacer(modifier = Modifier.width(14.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = if (uiState.imageUri == null) "Select Photo to Inspect" else "Choose Different Photo",
                            style = MaterialTheme.typography.titleSmall,
                            color = OffWhite
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "Uses Android Photo Picker (no storage permission needed). 100% on-device.",
                            style = MaterialTheme.typography.bodySmall,
                            color = SlateGrey
                        )
                    }
                }
            }

            if (uiState.imageUri != null) {
                item {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(14.dp))
                            .background(CharcoalNavy)
                            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                            .padding(16.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(200.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .background(DarkerSurface),
                            contentAlignment = Alignment.Center
                        ) {
                            AsyncImage(
                                model = uiState.imageUri,
                                contentDescription = "Selected photo preview",
                                modifier = Modifier.fillMaxSize()
                            )
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        Button(
                            onClick = {
                                viewModel.stripAndShare { cleanUri ->
                                    val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                        type = "image/jpeg"
                                        putExtra(Intent.EXTRA_STREAM, cleanUri)
                                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                    }
                                    context.startActivity(Intent.createChooser(shareIntent, "Share Sanitized Photo"))
                                }
                            },
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("exif_strip_share_button"),
                            colors = ButtonDefaults.buttonColors(containerColor = StatusSafe, contentColor = SlateObsidian),
                            shape = RoundedCornerShape(10.dp),
                            enabled = !uiState.isStripping && !uiState.isExtracting
                        ) {
                            if (uiState.isStripping) {
                                CircularProgressIndicator(color = SlateObsidian, modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Sanitizing Image…", fontWeight = FontWeight.SemiBold)
                            } else {
                                Icon(Icons.Default.CleaningServices, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Strip All EXIF & Share Clean Copy", fontWeight = FontWeight.SemiBold)
                            }
                        }
                    }
                }
            }

            if (uiState.isExtracting) {
                item {
                    Box(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 28.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator(color = SkyCyan)
                    }
                }
            }

            uiState.metadata?.let { meta ->
                item { MetadataCard(meta, context) }
            }

            if (uiState.imageUri != null) {
                item { ReverseImageSearchCard(context = context) }
            }

            if (uiState.error != null) {
                item {
                    Text(uiState.error ?: "", color = StatusRisk, style = MaterialTheme.typography.bodySmall)
                }
            }

            item { Spacer(modifier = Modifier.height(12.dp)) }
        }
    }
}

@Composable
private fun MetadataCard(meta: ExifMetadata, context: android.content.Context) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // GPS Status Banner
        if (meta.hasGps && meta.latitude != null && meta.longitude != null) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(StatusRisk.copy(alpha = 0.12f))
                    .border(1.dp, StatusRisk.copy(alpha = 0.45f), RoundedCornerShape(10.dp))
                    .padding(14.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.LocationOn, contentDescription = null, tint = StatusRisk, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("EMBEDDED GPS COORDINATES", color = StatusRisk, fontWeight = FontWeight.Bold, fontSize = 12.sp, fontFamily = MonoFontFamily)
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "${String.format("%.6f", meta.latitude)}, ${String.format("%.6f", meta.longitude)}",
                    color = OffWhite,
                    fontFamily = MonoFontFamily,
                    fontSize = 13.sp
                )
                meta.altitude?.let {
                    Text("Altitude: ${String.format("%.1f", it)} m", color = SlateGrey, fontSize = 11.sp, fontFamily = MonoFontFamily)
                }
                Spacer(modifier = Modifier.height(10.dp))
                Button(
                    onClick = {
                        SafeBrowserLauncher.openGeoLocation(context, meta.latitude, meta.longitude, "EXIF Location")
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = DarkerSurface, contentColor = SkyCyan),
                    border = BorderStroke(1.dp, CardBorder),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Icon(Icons.Default.Map, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Open Coordinates in Maps", fontSize = 12.sp)
                }
            }
        } else {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(StatusSafe.copy(alpha = 0.12f))
                    .border(1.dp, StatusSafe.copy(alpha = 0.35f), RoundedCornerShape(10.dp))
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Security, contentDescription = null, tint = StatusSafe, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("No GPS geolocation coordinates found in header.", color = StatusSafe, style = MaterialTheme.typography.bodySmall)
            }
        }

        // Cryptographic Chain-of-Custody Hash
        if (meta.sha256Hash.isNotBlank()) {
            CodeBlock(
                code = meta.sha256Hash,
                title = "SHA-256 FILE DIGEST (CHAIN OF CUSTODY)"
            )
        }

        // Device & Capture
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text("DEVICE & FILE ATTRIBUTES", color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
            ExifDataRow("File Size", meta.fileSizeFormatted)
            if (meta.imageWidth > 0 && meta.imageHeight > 0) {
                ExifDataRow("Dimensions", "${meta.imageWidth} × ${meta.imageHeight} px")
            }
            meta.make?.let { ExifDataRow("Manufacturer", it) }
            meta.model?.let { ExifDataRow("Camera Model", it) }
            meta.lensModel?.let { ExifDataRow("Lens Model", it) }
            meta.software?.let { ExifDataRow("Software / OS", it) }
            meta.dateTime?.let { ExifDataRow("Capture Time", it) }
        }

        // Optical Settings (only if present)
        val hasOptics = listOf(meta.iso, meta.exposureTime, meta.fNumber, meta.focalLength).any { it != null }
        if (hasOptics) {
            Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text("OPTICAL PARAMETERS", color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                meta.iso?.let { ExifDataRow("ISO", it) }
                meta.exposureTime?.let { ExifDataRow("Shutter Speed", it) }
                meta.fNumber?.let { ExifDataRow("Aperture", it) }
                meta.focalLength?.let { ExifDataRow("Focal Length", it) }
            }
        }
    }
}

@Composable
private fun ExifDataRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = SlateGrey, fontSize = 12.sp)
        Text(value, color = OffWhite, fontSize = 12.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun ReverseImageSearchCard(context: android.content.Context) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp)
    ) {
        Text("REVERSE IMAGE SEARCH PIVOTS", color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Open reverse visual search engines in your browser to trace duplicate appearances.",
            color = SlateGrey,
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(modifier = Modifier.height(12.dp))

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PivotButton("Google Lens", "https://lens.google.com/", context, Modifier.weight(1f))
            PivotButton("Yandex Visual", "https://yandex.com/images/", context, Modifier.weight(1f))
        }
        Spacer(modifier = Modifier.height(8.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PivotButton("TinEye", "https://tineye.com/", context, Modifier.weight(1f))
            PivotButton("Bing Visual", "https://www.bing.com/visualsearch", context, Modifier.weight(1f))
        }
    }
}

@Composable
private fun PivotButton(label: String, url: String, context: android.content.Context, modifier: Modifier = Modifier) {
    Button(
        onClick = { SafeBrowserLauncher.openExternalUrl(context, url) },
        colors = ButtonDefaults.buttonColors(containerColor = DarkerSurface, contentColor = OffWhite),
        border = BorderStroke(1.dp, CardBorder),
        shape = RoundedCornerShape(8.dp),
        modifier = modifier.heightIn(min = 44.dp)
    ) {
        Text(label, fontSize = 12.sp, fontWeight = FontWeight.Medium)
    }
}
