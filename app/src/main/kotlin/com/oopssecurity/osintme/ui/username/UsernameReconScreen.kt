package com.oopssecurity.osintme.ui.username

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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.PrimaryScrollableTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.data.model.ReconStatus
import com.oopssecurity.osintme.data.model.UsernameCheckResult
import com.oopssecurity.osintme.data.network.PlatformReconService
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.SaveToCaseDialog
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType
import com.oopssecurity.osintme.util.SafeBrowserLauncher

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UsernameReconScreen(
    initialUsername: String = "",
    onBackClick: () -> Unit,
    onPivot: (PivotEntity) -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: UsernameViewModel = viewModel(key = "username_${initialUsername.ifBlank { "root" }}") {
        UsernameViewModel(context, initialUsername)
    }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val focusManager = LocalFocusManager.current
    var showSaveDialog by remember { mutableStateOf(false) }

    val foundCount = uiState.results.count { it.status == ReconStatus.FOUND }
    val availableCount = uiState.results.count { it.status == ReconStatus.AVAILABLE }
    val limitedCount = uiState.results.count { it.status == ReconStatus.RATE_LIMITED || it.status == ReconStatus.ERROR }

    val filteredResults = when (uiState.selectedFilter) {
        1 -> uiState.results.filter { it.status == ReconStatus.FOUND }
        2 -> uiState.results.filter { it.status == ReconStatus.AVAILABLE }
        3 -> uiState.results.filter { it.status == ReconStatus.RATE_LIMITED || it.status == ReconStatus.ERROR }
        else -> uiState.results
    }

    if (showSaveDialog && uiState.results.isNotEmpty()) {
        val foundPlatforms = uiState.results.filter { it.status == ReconStatus.FOUND }
        SaveToCaseDialog(
            wingType = "SOCIAL",
            artifactType = "USERNAME_RECON",
            queryTarget = "@${uiState.usernameInput}",
            title = "Handle Footprint: @${uiState.usernameInput}",
            summary = "Confirmed on $foundCount of ${uiState.results.size} platforms: ${foundPlatforms.take(8).joinToString(", ") { it.platformName }}",
            sourceApi = "OSINTme 106+ Platform Concurrent Probe Engine",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Username Hunter",
                subtitle = "Concurrent recon across ${PlatformReconService.ALL_PLATFORMS.size} real platforms",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (uiState.results.isNotEmpty() && !uiState.isScanning) {
                    {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            if (uiState.usernameInput.isNotBlank()) {
                                IconButton(
                                    onClick = {
                                        onPivot(
                                            PivotEngine.normalize(
                                                raw = uiState.usernameInput,
                                                hintType = PivotEntityType.USERNAME,
                                                sourceContext = "Username Hunter"
                                            )
                                        )
                                    },
                                    modifier = Modifier.size(48.dp).testTag("username_pivot_handle_button")
                                ) {
                                    Icon(
                                        imageVector = Icons.AutoMirrored.Filled.CallSplit,
                                        contentDescription = "Pivot handle",
                                        tint = SkyCyan
                                    )
                                }
                            }
                            IconButton(
                                onClick = { showSaveDialog = true },
                                modifier = Modifier.size(48.dp).testTag("username_save_case_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.BookmarkAdd,
                                    contentDescription = "Save findings to case",
                                    tint = SkyCyan
                                )
                            }
                        }
                    }
                } else null
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp)
                    .clip(RoundedCornerShape(14.dp))
                    .background(CharcoalNavy)
                    .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                    .padding(14.dp)
            ) {
                Text(
                    text = "TARGET HANDLE",
                    fontSize = 11.sp,
                    color = SlateGrey,
                    fontFamily = MonoFontFamily
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = uiState.usernameInput,
                        onValueChange = { viewModel.onUsernameChange(it) },
                        modifier = Modifier.weight(1f).testTag("username_target_input"),
                        placeholder = { Text("e.g. torvalds, octocat", color = MutedSlate, fontSize = 13.sp) },
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = OffWhite),
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                        keyboardActions = KeyboardActions(onSearch = {
                            focusManager.clearFocus()
                            viewModel.startScan()
                        }),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = SkyCyan,
                            unfocusedBorderColor = CardBorder,
                            focusedContainerColor = DarkerSurface,
                            unfocusedContainerColor = DarkerSurface,
                            focusedTextColor = OffWhite,
                            unfocusedTextColor = OffWhite
                        ),
                        shape = RoundedCornerShape(10.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = {
                            focusManager.clearFocus()
                            if (uiState.isScanning) viewModel.stopScan() else viewModel.startScan()
                        },
                        enabled = uiState.usernameInput.isNotBlank() || uiState.isScanning,
                        modifier = Modifier.height(54.dp).testTag("username_scan_button"),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (uiState.isScanning) StatusRisk else EmeraldPrimary,
                            contentColor = PureWhite,
                            disabledContainerColor = SurfaceElevated,
                            disabledContentColor = MutedSlate
                        ),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Icon(
                            imageVector = if (uiState.isScanning) Icons.Default.Stop else Icons.Default.Search,
                            contentDescription = if (uiState.isScanning) "Stop scan" else "Start scan"
                        )
                    }
                }

                if (uiState.isScanning && uiState.totalToScan > 0) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "Probing ${uiState.totalToScan} platforms • $foundCount found",
                            fontSize = 11.sp,
                            color = SlateGrey,
                            fontFamily = MonoFontFamily
                        )
                        Text(
                            text = "${uiState.scannedCount}/${uiState.totalToScan}",
                            fontSize = 11.sp,
                            color = SkyCyan,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    LinearProgressIndicator(
                        progress = { uiState.scannedCount.toFloat() / uiState.totalToScan },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(5.dp)
                            .clip(RoundedCornerShape(3.dp)),
                        color = SkyCyan,
                        trackColor = CardBorder
                    )
                }
            }

            if (uiState.results.isNotEmpty()) {
                PrimaryScrollableTabRow(
                    selectedTabIndex = uiState.selectedFilter.coerceIn(0, 3),
                    containerColor = CharcoalNavy,
                    contentColor = SkyCyan,
                    edgePadding = 12.dp,
                    divider = { HorizontalDivider(color = CardBorder) }
                ) {
                    Tab(
                        selected = uiState.selectedFilter == 0,
                        onClick = { viewModel.selectFilter(0) },
                        text = { Text("All (${uiState.results.size})", fontSize = 12.sp) }
                    )
                    Tab(
                        selected = uiState.selectedFilter == 1,
                        onClick = { viewModel.selectFilter(1) },
                        text = {
                            Text(
                                "Found ($foundCount)",
                                fontSize = 12.sp,
                                color = if (foundCount > 0) StatusSafe else SlateGrey
                            )
                        }
                    )
                    Tab(
                        selected = uiState.selectedFilter == 2,
                        onClick = { viewModel.selectFilter(2) },
                        text = { Text("Not Found ($availableCount)", fontSize = 12.sp) }
                    )
                    Tab(
                        selected = uiState.selectedFilter == 3,
                        onClick = { viewModel.selectFilter(3) },
                        text = { Text("Rate-Limited ($limitedCount)", fontSize = 12.sp) }
                    )
                }

                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(filteredResults, key = { it.platformName }) { item ->
                        PlatformResultRow(item = item, onPivot = onPivot)
                    }
                    item { Spacer(modifier = Modifier.height(12.dp)) }
                }
            }
        }
    }
}

@Composable
private fun PlatformResultRow(
    item: UsernameCheckResult,
    onPivot: (PivotEntity) -> Unit
) {
    val context = LocalContext.current
    val (statusLabel, statusColor, statusBg) = when (item.status) {
        ReconStatus.FOUND -> Triple("FOUND", StatusSafe, StatusSafe.copy(alpha = 0.14f))
        ReconStatus.AVAILABLE -> Triple("NOT FOUND", SlateGrey, SurfaceElevated)
        ReconStatus.RATE_LIMITED -> Triple("LIMITED ${item.httpCode}", StatusWarning, StatusWarning.copy(alpha = 0.14f))
        ReconStatus.ERROR -> Triple("TIMEOUT", StatusRisk, StatusRisk.copy(alpha = 0.14f))
        ReconStatus.CHECKING -> Triple("PROBING", SkyCyan, SurfaceElevated)
        ReconStatus.IDLE -> Triple("IDLE", MutedSlate, SurfaceElevated)
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(CharcoalNavy)
            .border(
                1.dp,
                if (item.status == ReconStatus.FOUND) StatusSafe.copy(alpha = 0.35f) else CardBorder,
                RoundedCornerShape(10.dp)
            )
            .clickable(enabled = item.status == ReconStatus.FOUND) {
                onPivot(
                    PivotEngine.normalize(
                        raw = item.profileUrl,
                        hintType = PivotEntityType.URL,
                        sourceContext = "${item.platformName} Profile"
                    )
                )
            }
            .padding(horizontal = 12.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.weight(1f)
        ) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(if (item.status == ReconStatus.FOUND) StatusSafe.copy(alpha = 0.14f) else SurfaceElevated),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.PersonSearch,
                    contentDescription = null,
                    tint = if (item.status == ReconStatus.FOUND) StatusSafe else MutedSlate,
                    modifier = Modifier.size(16.dp)
                )
            }
            Spacer(modifier = Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.platformName,
                    style = MaterialTheme.typography.titleSmall,
                    color = OffWhite,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                val sub = buildList {
                    add(item.category)
                    item.metadata?.let { add(it) }
                    if (item.responseTimeMs > 0) add("${item.responseTimeMs}ms")
                }.joinToString(" • ")
                Text(
                    text = sub,
                    color = if (item.metadata != null) SkyCyan else MutedSlate,
                    fontSize = 11.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }

        Spacer(modifier = Modifier.width(8.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(5.dp))
                    .background(statusBg)
                    .border(1.dp, statusColor.copy(alpha = 0.35f), RoundedCornerShape(5.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = statusLabel,
                    fontSize = 10.sp,
                    color = statusColor,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                )
            }

            if (item.status == ReconStatus.FOUND) {
                Spacer(modifier = Modifier.width(6.dp))
                IconButton(
                    onClick = {
                        SafeBrowserLauncher.openExternalUrl(context, item.profileUrl)
                    },
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.OpenInNew,
                        contentDescription = "Open profile in browser",
                        tint = SkyCyan,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}
