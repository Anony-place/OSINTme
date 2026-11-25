package com.oopssecurity.osintme.ui.history

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.ScanHistoryItem
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusWarning
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ScanHistoryScreen(
    onBackClick: () -> Unit,
    onSelectItem: (ScanHistoryItem) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val historyManager = remember(context) { LocalScanHistoryManager(context) }
    val scans by historyManager.historyFlow.collectAsStateWithLifecycle()
    var showClearDialog by remember { mutableStateOf(false) }

    if (showClearDialog) {
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            containerColor = CharcoalNavy,
            shape = RoundedCornerShape(14.dp),
            icon = {
                Icon(Icons.Default.DeleteSweep, contentDescription = null, tint = StatusRisk, modifier = Modifier.size(28.dp))
            },
            title = {
                Text("Clear Scan History?", color = OffWhite, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, fontFamily = DisplayFontFamily)
            },
            text = {
                Text(
                    "All local scan records will be permanently wiped from this device. OSINTme never mirrors history to external servers.",
                    color = SlateGrey,
                    fontSize = 13.sp,
                    lineHeight = 19.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        historyManager.clearHistory()
                        showClearDialog = false
                        Toast.makeText(context, "Local scan history wiped", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = StatusRisk,
                        contentColor = PureWhite
                    ),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.testTag("confirm_clear_history_button")
                ) {
                    Text("Wipe History", color = PureWhite, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearDialog = false }) {
                    Text("Cancel", color = SlateGrey)
                }
            }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Scan History",
                subtitle = "100% on-device private audit log",
                showBackButton = true,
                onBackClick = onBackClick
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            // Privacy Assurance Banner
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = DarkerSurface),
                border = BorderStroke(1.dp, CardBorder),
                shape = RoundedCornerShape(10.dp)
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = "Zero-cloud logging. Records remain strictly inside the app's private local sandbox.",
                        color = SlateGrey,
                        fontSize = 12.sp,
                        lineHeight = 17.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Action row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "STORED RECORDS (${scans.size})",
                    color = SkyCyan,
                    fontSize = 11.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.8.sp
                )

                if (scans.isNotEmpty()) {
                    TextButton(
                        onClick = { showClearDialog = true },
                        modifier = Modifier.testTag("clear_history_button")
                    ) {
                        Icon(Icons.Default.DeleteSweep, contentDescription = null, tint = StatusRisk, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Clear All", color = StatusRisk, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            if (scans.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(bottom = 56.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.History, contentDescription = null, tint = MutedSlate, modifier = Modifier.size(40.dp))
                        Spacer(modifier = Modifier.height(12.dp))
                        Text("No Scan History Yet", color = OffWhite, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, fontFamily = DisplayFontFamily)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("Past domain, breach, identity, and forensic checks appear here.", color = SlateGrey, fontSize = 12.sp)
                    }
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    contentPadding = PaddingValues(bottom = 28.dp)
                ) {
                    items(scans, key = { it.id }) { scan ->
                        HistoryCard(scan = scan, onClick = { onSelectItem(scan) })
                    }
                }
            }
        }
    }
}

@Composable
private fun HistoryCard(scan: ScanHistoryItem, onClick: () -> Unit) {
    val dateFormatted = remember(scan.timestamp) {
        SimpleDateFormat("MMM dd, yyyy • HH:mm", Locale.getDefault()).format(Date(scan.timestamp))
    }

    val badgeColor = when (scan.type.uppercase()) {
        "DOMAIN", "IP" -> SkyCyan
        "BREACH", "EMAIL" -> StatusRisk
        "USERNAME", "IDENTITY" -> SoftIndigo
        "PHONE" -> StatusWarning
        else -> MatrixGreen
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
            .clickable { onClick() }
            .testTag("history_item_${scan.id}"),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        shape = RoundedCornerShape(10.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(badgeColor.copy(alpha = 0.14f))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = scan.type,
                            color = badgeColor,
                            fontSize = 9.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    Text(
                        text = dateFormatted,
                        color = MutedSlate,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily
                    )
                }

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = scan.target,
                    color = OffWhite,
                    fontSize = 13.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )

                Spacer(modifier = Modifier.height(3.dp))

                Text(
                    text = scan.summary,
                    color = SlateGrey,
                    fontSize = 12.sp,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            Icon(
                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = "Open Scan",
                tint = MutedSlate,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}
