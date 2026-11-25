package com.oopssecurity.osintme.ui.wayback

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.History
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.network.WaybackCategory
import com.oopssecurity.osintme.data.network.WaybackCdxService
import com.oopssecurity.osintme.data.network.WaybackReport
import com.oopssecurity.osintme.data.network.WaybackSnapshot
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.SaveToCaseDialog
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.EmeraldBorder
import com.oopssecurity.osintme.ui.theme.EmeraldDeep
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.EmeraldSoft
import com.oopssecurity.osintme.ui.theme.InkBlack
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEntityType
import com.oopssecurity.osintme.util.SafeBrowserLauncher
import kotlinx.coroutines.launch

@Composable
fun WaybackScreen(
    initialTarget: String = "",
    onBackClick: () -> Unit,
    onPivotEntity: (String, PivotEntityType?, String) -> Unit = { _, _, _ -> },
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var targetInput by remember { mutableStateOf(initialTarget) }
    var isLoading by remember { mutableStateOf(false) }
    var errorMsg by remember { mutableStateOf<String?>(null) }
    var report by remember { mutableStateOf<WaybackReport?>(null) }
    var selectedFilter by remember { mutableStateOf<WaybackCategory?>(null) }
    var showSaveDialog by remember { mutableStateOf(false) }

    fun runSearch(query: String) {
        val clean = query.trim()
        if (clean.isBlank() || isLoading) return
        isLoading = true
        errorMsg = null
        scope.launch {
            WaybackCdxService.searchArchive(clean).fold(
                onSuccess = { report = it },
                onFailure = { errorMsg = it.message ?: "Wayback lookup failed" }
            )
            isLoading = false
        }
    }

    LaunchedEffect(initialTarget) {
        if (initialTarget.isNotBlank() && report == null) {
            runSearch(initialTarget)
        }
    }

    if (showSaveDialog && report != null) {
        val r = report!!
        SaveToCaseDialog(
            wingType = "WAYBACK_ARCHIVE",
            artifactType = "HISTORICAL_URLS",
            queryTarget = r.targetDomain,
            title = "Wayback Archive: ${r.targetDomain} (${r.snapshots.size} URLs)",
            summary = "Archived ${r.earliestYear ?: "?"}–${r.latestYear ?: "?"} • ${r.sensitiveCount} sensitive paths, ${r.documentCount} docs, ${r.deletedCount} deleted 4xx.",
            sourceApi = "Internet Archive Wayback CDX",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = PureWhite,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Wayback Explorer",
                subtitle = "Historical URLs, deleted pages & leaked paths",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (report != null) {
                    {
                        IconButton(onClick = { showSaveDialog = true }) {
                            Icon(Icons.Default.BookmarkAdd, contentDescription = "Save to Case", tint = EmeraldPrimary)
                        }
                    }
                } else null
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .navigationBarsPadding()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = targetInput,
                    onValueChange = { targetInput = it },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("wayback_target_input"),
                    singleLine = true,
                    placeholder = { Text("Domain (e.g. example.com)", color = MutedSlate, fontSize = 13.sp) },
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = InkBlack),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = CharcoalNavy,
                        unfocusedContainerColor = CharcoalNavy,
                        focusedBorderColor = InkBlack,
                        unfocusedBorderColor = CardBorder,
                        focusedTextColor = InkBlack,
                        unfocusedTextColor = InkBlack
                    ),
                    shape = RoundedCornerShape(10.dp),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { runSearch(targetInput) })
                )

                Button(
                    onClick = { runSearch(targetInput) },
                    enabled = targetInput.isNotBlank() && !isLoading,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .heightIn(min = 52.dp)
                        .testTag("wayback_search_button")
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = EmeraldPrimary)
                    } else {
                        Text("Explore", fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            if (!errorMsg.isNullOrBlank()) {
                Text(
                    text = errorMsg!!,
                    color = StatusRisk,
                    fontSize = 12.sp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(StatusRisk.copy(alpha = 0.08f))
                        .padding(10.dp)
                )
            }

            val current = report
            if (current == null && !isLoading) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                        .clip(RoundedCornerShape(14.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                        .padding(18.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(Icons.Default.History, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(30.dp))
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Live Internet Archive CDX Index", color = InkBlack, fontFamily = DisplayFontFamily, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Uncover deleted pages, forgotten staging URLs, exposed .env/.bak/.sql paths, and archived PDF/JSON files passively without touching the target server.",
                        color = SlateGrey,
                        fontSize = 12.sp,
                        lineHeight = 18.sp
                    )
                }
            } else if (current != null) {
                // Summary KPI Row
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    WaybackStatPill("TOTAL", "${current.snapshots.size}", InkBlack, Modifier.weight(1f))
                    WaybackStatPill("SENSITIVE", "${current.sensitiveCount}", if (current.sensitiveCount > 0) StatusRisk else EmeraldPrimary, Modifier.weight(1f))
                    WaybackStatPill("DOCS", "${current.documentCount}", EmeraldDeep, Modifier.weight(1f))
                    WaybackStatPill("SPAN", "${current.earliestYear ?: "-"}-${current.latestYear?.takeLast(2) ?: "-"}", SlateGrey, Modifier.weight(1f))
                }

                // Filter Chips
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    FilterChipBox("ALL (${current.snapshots.size})", selectedFilter == null) { selectedFilter = null }
                    WaybackCategory.entries.forEach { cat ->
                        val count = current.snapshots.count { it.category == cat }
                        FilterChipBox("${cat.label} ($count)", selectedFilter == cat) { selectedFilter = cat }
                    }
                }

                val filtered = remember(current, selectedFilter) {
                    if (selectedFilter == null) current.snapshots else current.snapshots.filter { it.category == selectedFilter }
                }

                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    if (current.discoveredHosts.isNotEmpty()) {
                        item {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(EmeraldSoft)
                                    .border(1.dp, EmeraldBorder, RoundedCornerShape(12.dp))
                                    .padding(12.dp)
                            ) {
                                Text("ARCHIVED SUBDOMAINS (TAP TO PIVOT)", color = EmeraldDeep, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                                Spacer(modifier = Modifier.height(6.dp))
                                Row(
                                    modifier = Modifier.horizontalScroll(rememberScrollState()),
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    current.discoveredHosts.forEach { host ->
                                        Box(
                                            modifier = Modifier
                                                .clip(RoundedCornerShape(6.dp))
                                                .background(PureWhite)
                                                .border(1.dp, EmeraldBorder, RoundedCornerShape(6.dp))
                                                .clickable { onPivotEntity(host, PivotEntityType.DOMAIN, "Wayback Archive") }
                                                .padding(horizontal = 8.dp, vertical = 5.dp)
                                        ) {
                                            Text(host, color = InkBlack, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.SemiBold)
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (filtered.isEmpty()) {
                        item {
                            Text(
                                text = "No snapshots matched this filter.",
                                color = MutedSlate,
                                fontSize = 13.sp,
                                modifier = Modifier.padding(vertical = 18.dp)
                            )
                        }
                    } else {
                        items(filtered, key = { "${it.timestamp}_${it.originalUrl}" }) { snap ->
                            WaybackSnapshotCard(
                                snapshot = snap,
                                onOpenArchive = {
                                    if (!SafeBrowserLauncher.openExternalUrl(context, snap.archiveUrl)) {
                                        Toast.makeText(context, "Blocked unsafe or unopenable URL", Toast.LENGTH_SHORT).show()
                                    }
                                },
                                onPivot = { onPivotEntity(snap.originalUrl, PivotEntityType.URL, "Wayback Snapshot") }
                            )
                        }
                    }

                    item { Spacer(modifier = Modifier.height(20.dp)) }
                }
            }
        }
    }
}

@Composable
private fun WaybackStatPill(label: String, value: String, valueColor: androidx.compose.ui.graphics.Color, modifier: Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
            .padding(vertical = 8.dp, horizontal = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(value, color = valueColor, fontSize = 15.sp, fontFamily = DisplayFontFamily, fontWeight = FontWeight.Bold)
        Text(label, color = MutedSlate, fontSize = 9.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun FilterChipBox(label: String, selected: Boolean, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(if (selected) EmeraldPrimary else SurfaceElevated)
            .border(1.dp, if (selected) EmeraldPrimary else CardBorder, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 6.dp)
    ) {
        Text(
            text = label,
            color = if (selected) PureWhite else SlateGrey,
            fontSize = 11.sp,
            fontFamily = MonoFontFamily,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
private fun WaybackSnapshotCard(
    snapshot: WaybackSnapshot,
    onOpenArchive: () -> Unit,
    onPivot: () -> Unit
) {
    val badgeColor = when (snapshot.category) {
        WaybackCategory.SENSITIVE -> StatusRisk
        WaybackCategory.DOCUMENT -> EmeraldPrimary
        WaybackCategory.DELETED -> StatusWarning
        WaybackCategory.PAGE -> SlateGrey
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(CharcoalNavy)
            .border(1.dp, if (snapshot.category == WaybackCategory.SENSITIVE) StatusRisk.copy(alpha = 0.4f) else CardBorder, RoundedCornerShape(12.dp))
            .padding(12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(badgeColor.copy(alpha = 0.12f))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(snapshot.category.label.uppercase(), color = badgeColor, fontSize = 9.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                }
                Text("HTTP ${snapshot.statusCode}", color = SlateGrey, fontSize = 10.sp, fontFamily = MonoFontFamily)
            }
            Text(snapshot.formattedDate, color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
        }

        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = snapshot.originalUrl,
            color = InkBlack,
            fontSize = 12.sp,
            fontFamily = MonoFontFamily,
            maxLines = 3,
            overflow = TextOverflow.Ellipsis
        )

        if (!snapshot.matchedSignal.isNullOrBlank()) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "${snapshot.matchedSignal} • ${snapshot.mimeType}",
                color = badgeColor,
                fontSize = 11.sp,
                fontWeight = FontWeight.Medium
            )
        }

        Spacer(modifier = Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = onOpenArchive,
                colors = ButtonDefaults.buttonColors(
                    containerColor = EmeraldPrimary,
                    contentColor = PureWhite,
                    disabledContainerColor = SurfaceElevated,
                    disabledContentColor = MutedSlate
                ),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.heightIn(min = 38.dp)
            ) {
                Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = null, modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(5.dp))
                Text("Open Snapshot", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
            }

            OutlinedButton(
                onClick = onPivot,
                border = BorderStroke(1.dp, EmeraldPrimary),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = EmeraldDeep),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.heightIn(min = 38.dp)
            ) {
                Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = null, modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(5.dp))
                Text("Pivot", fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}
