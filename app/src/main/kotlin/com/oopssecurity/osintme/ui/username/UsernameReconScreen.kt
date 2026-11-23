package com.oopssecurity.osintme.ui.username

import android.app.Activity
import android.content.Intent
import android.net.Uri
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.data.model.ReconStatus
import com.oopssecurity.osintme.data.model.UsernameCheckResult
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated

@Composable
fun UsernameReconScreen(
    initialUsername: String = "",
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val activity = context as? Activity
    val viewModel: UsernameViewModel = viewModel { UsernameViewModel(context, initialUsername) }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val focusManager = LocalFocusManager.current

    val foundCount = uiState.results.count { it.status == ReconStatus.FOUND }
    val availableCount = uiState.results.count { it.status == ReconStatus.AVAILABLE }

    val filteredResults = when (uiState.selectedFilter) {
        1 -> uiState.results.filter { it.status == ReconStatus.FOUND }
        2 -> uiState.results.filter { it.status == ReconStatus.AVAILABLE }
        else -> uiState.results
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        topBar = {
            AppHeader(
                title = "Multi-Platform Username Recon",
                subtitle = "Concurrent search across 35+ services",
                showBackButton = true,
                onBackClick = onBackClick
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // Search Input Box
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(CharcoalNavy)
                    .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                    .padding(14.dp)
            ) {
                Text(
                    text = "TARGET USERNAME / HANDLE",
                    fontSize = 11.sp,
                    color = SlateGrey,
                    style = MaterialTheme.typography.labelSmall
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = uiState.usernameInput,
                    onValueChange = { viewModel.onUsernameChange(it) },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("e.g. ghostrcr, satoshi, privacydev", color = MutedSlate, fontSize = 13.sp) },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace, fontSize = 13.sp),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = {
                        focusManager.clearFocus()
                        viewModel.startScan()
                    }),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = SkyCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedContainerColor = SlateObsidian,
                        unfocusedContainerColor = SlateObsidian
                    ),
                    shape = RoundedCornerShape(8.dp)
                )
                Spacer(modifier = Modifier.height(10.dp))
                Button(
                    onClick = {
                        focusManager.clearFocus()
                        viewModel.startScan()
                    },
                    enabled = uiState.usernameInput.isNotBlank() && !uiState.isScanning,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = SkyCyan, contentColor = SlateObsidian),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    if (uiState.isScanning) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), color = SlateObsidian, strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Scanning ${uiState.scannedCount}/${uiState.totalToScan} Platforms...")
                    } else {
                        Icon(imageVector = Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Scan Platforms", style = MaterialTheme.typography.labelLarge)
                    }
                }
            }

            // Progress bar while scanning
            if (uiState.isScanning && uiState.totalToScan > 0) {
                Column {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "Live Concurrency Progress",
                            fontSize = 11.sp,
                            color = SlateGrey,
                            style = MaterialTheme.typography.labelSmall
                        )
                        Text(
                            text = "${uiState.scannedCount}/${uiState.totalToScan}",
                            fontSize = 11.sp,
                            color = SkyCyan,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    LinearProgressIndicator(
                        progress = { uiState.scannedCount.toFloat() / uiState.totalToScan },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp)
                            .clip(RoundedCornerShape(3.dp)),
                        color = SkyCyan,
                        trackColor = CardBorder
                    )
                }
            }

            // Rewarded ad trigger for Deep Scan (when on basic 15 platforms)
            if (!uiState.isDeepScanUnlocked) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, SoftIndigo.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                        .padding(10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Top 15 Platforms (Free Tier)",
                            style = MaterialTheme.typography.titleMedium,
                            fontSize = 12.sp,
                            color = OffWhite
                        )
                        Text(
                            text = "Watch short rewarded video to unlock Deep Scan (all 35+ platforms)",
                            style = MaterialTheme.typography.bodyMedium,
                            fontSize = 10.sp,
                            color = SlateGrey
                        )
                    }
                    Button(
                        onClick = { viewModel.unlockDeepScanWithReward(activity) },
                        colors = ButtonDefaults.buttonColors(containerColor = SoftIndigo, contentColor = SlateObsidian),
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(imageVector = Icons.Default.LockOpen, contentDescription = null, modifier = Modifier.size(12.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Deep Scan", fontSize = 11.sp)
                        }
                    }
                }
            }

            // Filter Tabs
            if (uiState.results.isNotEmpty()) {
                TabRow(
                    selectedTabIndex = uiState.selectedFilter,
                    containerColor = CharcoalNavy,
                    contentColor = SkyCyan,
                    indicator = { tabPositions ->
                        TabRowDefaults.SecondaryIndicator(
                            Modifier.tabIndicatorOffset(tabPositions[uiState.selectedFilter]),
                            color = SkyCyan
                        )
                    },
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                ) {
                    Tab(
                        selected = uiState.selectedFilter == 0,
                        onClick = { viewModel.selectFilter(0) },
                        text = { Text("All (${uiState.results.size})", fontSize = 11.sp) }
                    )
                    Tab(
                        selected = uiState.selectedFilter == 1,
                        onClick = { viewModel.selectFilter(1) },
                        text = { Text("Found ($foundCount)", fontSize = 11.sp, color = if (foundCount > 0) StatusSafe else SlateGrey) }
                    )
                    Tab(
                        selected = uiState.selectedFilter == 2,
                        onClick = { viewModel.selectFilter(2) },
                        text = { Text("Available ($availableCount)", fontSize = 11.sp) }
                    )
                }

                // Results list
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(filteredResults) { item ->
                        PlatformResultRow(item = item)
                    }
                }
            }
        }
    }
}

@Composable
fun PlatformResultRow(item: UsernameCheckResult) {
    val context = LocalContext.current
    val (statusLabel, statusColor, statusBg) = when (item.status) {
        ReconStatus.FOUND -> Triple("FOUND", StatusSafe, StatusSafe.copy(alpha = 0.15f))
        ReconStatus.AVAILABLE -> Triple("AVAILABLE", SlateGrey, SurfaceElevated)
        ReconStatus.ERROR -> Triple("ERROR", StatusWarning, StatusWarning.copy(alpha = 0.15f))
        ReconStatus.CHECKING -> Triple("CHECKING", SkyCyan, SurfaceElevated)
        else -> Triple("IDLE", MutedSlate, SurfaceElevated)
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
            .clickable(enabled = item.status == ReconStatus.FOUND) {
                try {
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(item.profileUrl))
                    context.startActivity(intent)
                } catch (e: Exception) {
                    // Fallback
                }
            }
            .padding(12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.weight(1f)
        ) {
            Box(
                modifier = Modifier
                    .size(28.dp)
                    .clip(RoundedCornerShape(4.dp))
                    .background(SurfaceElevated),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.PersonSearch,
                    contentDescription = null,
                    tint = if (item.status == ReconStatus.FOUND) SkyCyan else MutedSlate,
                    modifier = Modifier.size(16.dp)
                )
            }
            Spacer(modifier = Modifier.width(10.dp))
            Column {
                Text(
                    text = item.platformName,
                    style = MaterialTheme.typography.titleMedium,
                    fontSize = 13.sp,
                    color = OffWhite
                )
                Text(
                    text = item.category,
                    style = MaterialTheme.typography.labelSmall,
                    fontSize = 10.sp,
                    color = MutedSlate
                )
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(4.dp))
                    .background(statusBg)
                    .border(1.dp, statusColor.copy(alpha = 0.4f), RoundedCornerShape(4.dp))
                    .padding(horizontal = 8.dp, vertical = 3.dp)
            ) {
                Text(
                    text = statusLabel,
                    fontSize = 10.sp,
                    color = statusColor,
                    style = MaterialTheme.typography.labelSmall
                )
            }

            if (item.status == ReconStatus.FOUND) {
                Spacer(modifier = Modifier.width(8.dp))
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.OpenInNew,
                    contentDescription = "Open Profile",
                    tint = SkyCyan,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}
