package com.oopssecurity.osintme.ui.threat

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
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
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.model.UrlhausResult
import com.oopssecurity.osintme.data.network.UrlhausService
import com.oopssecurity.osintme.ui.components.AdBannerView
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.CodeBlock
import com.oopssecurity.osintme.ui.dorks.DorkGeneratorScreen
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import kotlinx.coroutines.launch

@Composable
fun ThreatIntelScreen(
    initialTarget: String = "",
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var selectedTab by remember { mutableIntStateOf(0) }
    var hostInput by remember { mutableStateOf(initialTarget) }
    var isLoading by remember { mutableStateOf(false) }
    var urlhausResult by remember { mutableStateOf<UrlhausResult?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun runCheck() {
        if (hostInput.isNotBlank()) {
            isLoading = true
            error = null
            scope.launch {
                UrlhausService.checkHost(hostInput).fold(
                    onSuccess = {
                        urlhausResult = it
                        isLoading = false
                    },
                    onFailure = {
                        error = it.message ?: "Failed to query URLhaus"
                        isLoading = false
                    }
                )
            }
        }
    }

    LaunchedEffect(initialTarget) {
        if (initialTarget.isNotEmpty() && urlhausResult == null) {
            runCheck()
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        topBar = {
            AppHeader(
                title = "Threat Intelligence & Abuse Feeds",
                subtitle = "URLhaus (abuse.ch) malware lookups & weaponized Google Dorks",
                showBackButton = true,
                onBackClick = onBackClick
            )
        },
        bottomBar = {
            AdBannerView()
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            TabRow(
                selectedTabIndex = selectedTab,
                containerColor = CharcoalNavy,
                contentColor = SkyCyan,
                indicator = { tabPositions ->
                    TabRowDefaults.SecondaryIndicator(
                        Modifier.tabIndicatorOffset(tabPositions[selectedTab]),
                        color = SkyCyan
                    )
                }
            ) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = {
                        Text(
                            text = "URLhaus Malware Check",
                            fontSize = 12.sp,
                            fontWeight = if (selectedTab == 0) FontWeight.Bold else FontWeight.Normal,
                            color = if (selectedTab == 0) SkyCyan else SlateGrey
                        )
                    }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = {
                        Text(
                            text = "Google Dorks Matrix",
                            fontSize = 12.sp,
                            fontWeight = if (selectedTab == 1) FontWeight.Bold else FontWeight.Normal,
                            color = if (selectedTab == 1) SkyCyan else SlateGrey
                        )
                    }
                )
            }

            if (selectedTab == 0) {
                // URLhaus Host Scanner
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp, vertical = 12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = hostInput,
                            onValueChange = { hostInput = it },
                            placeholder = { Text("Enter domain or IP (e.g. example.com)", color = MutedSlate, fontSize = 13.sp) },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = OffWhite,
                                unfocusedTextColor = OffWhite,
                                focusedBorderColor = SkyCyan,
                                unfocusedBorderColor = CardBorder,
                                focusedContainerColor = CharcoalNavy,
                                unfocusedContainerColor = CharcoalNavy
                            ),
                            shape = RoundedCornerShape(8.dp),
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                            keyboardActions = KeyboardActions(onSearch = { runCheck() })
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Button(
                            onClick = { runCheck() },
                            colors = ButtonDefaults.buttonColors(containerColor = SkyCyan),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.height(54.dp),
                            enabled = !isLoading
                        ) {
                            if (isLoading) {
                                CircularProgressIndicator(color = SlateObsidian, modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(Icons.Default.Search, contentDescription = "Scan", tint = SlateObsidian)
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    if (error != null) {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, StatusRisk.copy(alpha = 0.5f), RoundedCornerShape(8.dp)),
                            colors = CardDefaults.cardColors(containerColor = CharcoalNavy)
                        ) {
                            Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Warning, contentDescription = null, tint = StatusRisk)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(error ?: "", color = StatusRisk, fontSize = 13.sp)
                            }
                        }
                    }

                    val res = urlhausResult
                    if (res != null) {
                        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            item {
                                UrlhausSummaryCard(res = res)
                            }

                            if (res.payloads.isNotEmpty()) {
                                item {
                                    Text(
                                        text = "ASSOCIATED MALWARE PAYLOADS (${res.payloads.size})",
                                        color = SkyCyan,
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        letterSpacing = 1.sp
                                    )
                                }

                                items(res.payloads) { payload ->
                                    Card(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .border(1.dp, CardBorder, RoundedCornerShape(6.dp)),
                                        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                                        shape = RoundedCornerShape(6.dp)
                                    ) {
                                        Column(modifier = Modifier.padding(10.dp)) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Box(
                                                    modifier = Modifier
                                                        .background(StatusRisk.copy(alpha = 0.15f), RoundedCornerShape(4.dp))
                                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                                ) {
                                                    Text(payload.threat, color = StatusRisk, fontSize = 9.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                                                }
                                                Text(payload.dateAdded, color = MutedSlate, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                                            }
                                            Spacer(modifier = Modifier.height(4.dp))
                                            Text(payload.url, color = OffWhite, fontSize = 11.sp, fontFamily = FontFamily.Monospace, maxLines = 2)
                                        }
                                    }
                                }
                            }
                        }
                    } else if (!isLoading) {
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(bottom = 64.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(Icons.Default.BugReport, contentDescription = null, tint = MutedSlate, modifier = Modifier.size(44.dp))
                                Spacer(modifier = Modifier.height(10.dp))
                                Text("URLHAUS MALWARE DOMAIN INTELLIGENCE", color = OffWhite, fontSize = 13.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                                Spacer(modifier = Modifier.height(4.dp))
                                Text("Check any domain or IP against abuse.ch active cybercrime malware feeds.", color = SlateGrey, fontSize = 12.sp)
                            }
                        }
                    }
                }
            } else {
                // Google Dorks matrix
                DorkGeneratorScreen(initialTarget = hostInput, onBackClick = onBackClick)
            }
        }
    }
}

@Composable
private fun UrlhausSummaryCard(res: UrlhausResult) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(res.target, color = OffWhite, fontSize = 15.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                Box(
                    modifier = Modifier
                        .background(if (res.isMalicious) StatusRisk.copy(alpha = 0.15f) else MatrixGreen.copy(alpha = 0.15f), RoundedCornerShape(4.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = if (res.isMalicious) "MALICIOUS // LISTED" else "CLEAN // NOT LISTED",
                        color = if (res.isMalicious) StatusRisk else MatrixGreen,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Total Malware URLs:", color = MutedSlate, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                Text("${res.urlCount}", color = if (res.urlCount > 0) StatusRisk else MatrixGreen, fontSize = 12.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
            }
            if (res.firstSeen.isNotEmpty()) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("First Seen on Abuse.ch:", color = MutedSlate, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    Text(res.firstSeen, color = OffWhite, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                }
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Spamhaus DBL Listed:", color = MutedSlate, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                Text(if (res.spamhausListed) "YES (BLOCKED)" else "NO", color = if (res.spamhausListed) StatusRisk else MatrixGreen, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("SURBL Listed:", color = MutedSlate, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                Text(if (res.surblListed) "YES (BLOCKED)" else "NO", color = if (res.surblListed) StatusRisk else MatrixGreen, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            }
        }
    }
}
