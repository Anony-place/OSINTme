package com.oopssecurity.osintme.ui.exif

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddPhotoAlternate
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Map
import androidx.compose.material.icons.filled.Photo
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import coil.compose.AsyncImage
import com.oopssecurity.osintme.data.model.ExifMetadata
import com.oopssecurity.osintme.ui.components.AdBannerView
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning

@Composable
fun ExifInspectorScreen(
    imageUriString: String? = null,
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: ExifViewModel = viewModel { ExifViewModel(context) }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    val photoPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            viewModel.setImageUri(uri)
        }
    }

    LaunchedEffect(imageUriString) {
        if (!imageUriString.isNullOrEmpty() && uiState.imageUri == null) {
            try {
                viewModel.setImageUri(Uri.parse(imageUriString))
            } catch (e: Exception) {
                // Ignore parse error
            }
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        topBar = {
            AppHeader(
                title = "EXIF Metadata Inspector",
                subtitle = "Extract camera, GPS & strip metadata offline",
                showBackButton = true,
                onBackClick = onBackClick
            )
        },
        bottomBar = {
            AdBannerView()
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            // Pick image action card
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                        .clickable { photoPickerLauncher.launch("image/*") },
                    colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(48.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(SkyCyan.copy(alpha = 0.15f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.AddPhotoAlternate, contentDescription = null, tint = SkyCyan)
                        }

                        Spacer(modifier = Modifier.width(16.dp))

                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = if (uiState.imageUri == null) "Select Image from Device" else "Change Image",
                                color = OffWhite,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 14.sp
                            )
                            Text(
                                text = "100% On-device inspection. Photos are never uploaded.",
                                color = SlateGrey,
                                fontSize = 12.sp
                            )
                        }
                    }
                }
            }

            // Image Preview + Strip Button
            if (uiState.imageUri != null) {
                item {
                    Spacer(modifier = Modifier.height(16.dp))
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
                        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(180.dp)
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(DarkerSurface),
                                contentAlignment = Alignment.Center
                            ) {
                                AsyncImage(
                                    model = uiState.imageUri,
                                    contentDescription = "Selected image preview",
                                    modifier = Modifier.fillMaxSize()
                                )
                            }

                            Spacer(modifier = Modifier.height(16.dp))

                            // Action button: Strip & Share
                            Button(
                                onClick = {
                                    viewModel.stripAndShare { cleanUri ->
                                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                            type = "image/jpeg"
                                            putExtra(Intent.EXTRA_STREAM, cleanUri)
                                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                        }
                                        context.startActivity(Intent.createChooser(shareIntent, "Share Clean Sanitized Photo"))
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.buttonColors(containerColor = StatusSafe),
                                shape = RoundedCornerShape(8.dp),
                                enabled = !uiState.isStripping && !uiState.isExtracting
                            ) {
                                if (uiState.isStripping) {
                                    CircularProgressIndicator(
                                        color = SlateObsidian,
                                        modifier = Modifier.size(18.dp),
                                        strokeWidth = 2.dp
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Stripping Metadata...", color = SlateObsidian, fontWeight = FontWeight.Bold)
                                } else {
                                    Icon(Icons.Default.CleaningServices, contentDescription = null, tint = SlateObsidian)
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Strip & Share Clean Image", color = SlateObsidian, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }

            if (uiState.imageUri != null) {
                item {
                    ReverseImageSearchCard(context = context)
                }
            }

            // Loading state
            if (uiState.isExtracting) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator(color = SkyCyan)
                    }
                }
            }

            // Metadata Breakdown Card
            if (uiState.metadata != null) {
                val meta = uiState.metadata!!
                item {
                    Spacer(modifier = Modifier.height(16.dp))
                    MetadataCard(meta, context)
                }
            }

            // Error
            if (uiState.error != null) {
                item {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(uiState.error ?: "", color = StatusRisk, fontSize = 13.sp)
                }
            }
        }
    }
}

@Composable
private fun MetadataCard(meta: ExifMetadata, context: android.content.Context) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Geolocation Exposure Status
            if (meta.hasGps && meta.latitude != null && meta.longitude != null) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(StatusRisk.copy(alpha = 0.15f))
                        .border(1.dp, StatusRisk.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
                        .padding(12.dp)
                ) {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.LocationOn, contentDescription = null, tint = StatusRisk, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("EXACT GPS COORDINATES EMBEDDED", color = StatusRisk, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "Lat: ${meta.latitude}, Lon: ${meta.longitude}",
                            color = OffWhite,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 13.sp
                        )
                        if (meta.altitude != null) {
                            Text("Altitude: ${meta.altitude}m", color = SlateGrey, fontSize = 11.sp)
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        Button(
                            onClick = {
                                val geoUri = Uri.parse("geo:${meta.latitude},${meta.longitude}?q=${meta.latitude},${meta.longitude}(Photo Location)")
                                val mapIntent = Intent(Intent.ACTION_VIEW, geoUri)
                                context.startActivity(mapIntent)
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = CharcoalNavy),
                            shape = RoundedCornerShape(6.dp),
                            modifier = Modifier.border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                        ) {
                            Icon(Icons.Default.Map, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Open in Maps", color = SkyCyan, fontSize = 12.sp)
                        }
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            } else {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(StatusSafe.copy(alpha = 0.12f))
                        .border(1.dp, StatusSafe.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                        .padding(10.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Security, contentDescription = null, tint = StatusSafe, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("No GPS location tags found in image header", color = StatusSafe, fontSize = 12.sp)
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            }

            // Hardware & Software Details
            Text("DEVICE HARDWARE & CAPTURE", color = SkyCyan, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            Spacer(modifier = Modifier.height(8.dp))

            meta.make?.let { ExifDataRow("Manufacturer", it) }
            meta.model?.let { ExifDataRow("Camera Model", it) }
            meta.software?.let { ExifDataRow("Software / OS", it) }
            meta.dateTime?.let { ExifDataRow("Original Timestamp", it) }

            if (meta.imageWidth > 0 && meta.imageHeight > 0) {
                ExifDataRow("Resolution", "${meta.imageWidth} × ${meta.imageHeight}")
            }

            // Camera Settings
            Spacer(modifier = Modifier.height(12.dp))
            Text("OPTICAL SETTINGS", color = SkyCyan, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            Spacer(modifier = Modifier.height(8.dp))

            meta.iso?.let { ExifDataRow("ISO", it) }
            meta.exposureTime?.let { ExifDataRow("Exposure", it) }
            meta.fNumber?.let { ExifDataRow("Aperture", "f/$it") }
            meta.focalLength?.let { ExifDataRow("Focal Length", it) }
        }
    }
}

@Composable
private fun ExifDataRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = SlateGrey, fontSize = 12.sp)
        Text(value, color = OffWhite, fontSize = 12.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun ReverseImageSearchCard(context: android.content.Context) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = "REVERSE IMAGE SEARCH PIVOTS",
                color = SkyCyan,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Launch browser pivots to identify faces, locations, and duplicate appearances online.",
                color = SlateGrey,
                fontSize = 12.sp
            )
            Spacer(modifier = Modifier.height(10.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://lens.google.com/"))
                        context.startActivity(intent)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = DarkerSurface),
                    border = androidx.compose.foundation.BorderStroke(1.dp, CardBorder),
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Google Lens", color = OffWhite, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                }

                Button(
                    onClick = {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://yandex.com/images/"))
                        context.startActivity(intent)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = DarkerSurface),
                    border = androidx.compose.foundation.BorderStroke(1.dp, CardBorder),
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Yandex Visual", color = OffWhite, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://tineye.com/"))
                        context.startActivity(intent)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = DarkerSurface),
                    border = androidx.compose.foundation.BorderStroke(1.dp, CardBorder),
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("TinEye", color = OffWhite, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                }

                Button(
                    onClick = {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.bing.com/visualsearch"))
                        context.startActivity(intent)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = DarkerSurface),
                    border = androidx.compose.foundation.BorderStroke(1.dp, CardBorder),
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Bing Visual", color = OffWhite, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}
