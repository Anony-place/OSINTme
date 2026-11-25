package com.oopssecurity.osintme.ui.redirect

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
import androidx.compose.foundation.layout.navigationBarsPadding
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
import androidx.compose.material.icons.filled.AltRoute
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Warning
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.network.HeaderSecurityCheck
import com.oopssecurity.osintme.data.network.RedirectAuditReport
import com.oopssecurity.osintme.data.network.RedirectHeaderService
import com.oopssecurity.osintme.data.network.RedirectHop
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
import kotlinx.coroutines.launch

@Composable
fun RedirectAuditScreen(
    initialUrl: String = "",
    onBackClick: () -> Unit,
    onPivotEntity: (String, PivotEntityType?, String) -> Unit = { _, _, _ -> },
    modifier: Modifier = Modifier
) {
    val scope = rememberCoroutineScope()
    var urlInput by remember { mutableStateOf(initialUrl) }
    var isLoading by remember { mutableStateOf(false) }
    var errorMsg by remember { mutableStateOf<String?>(null) }
    var report by remember { mutableStateOf<RedirectAuditReport?>(null) }
    var showSaveDialog by remember { mutableStateOf(false) }

    fun runTrace(raw: String) {
        val clean = raw.trim()
        if (clean.isBlank() || isLoading) return
        isLoading = true
        errorMsg = null
        scope.launch {
            RedirectHeaderService.traceAndAudit(clean).fold(
                onSuccess = { report = it },
                onFailure = { errorMsg = it.message ?: "Trace failed" }
            )
            isLoading = false
        }
    }

    LaunchedEffect(initialUrl) {
        if (initialUrl.isNotBlank() && report == null) {
            runTrace(initialUrl)
        }
    }

    if (showSaveDialog && report != null) {
        val r = report!!
        SaveToCaseDialog(
            wingType = "REDIRECT_HTTP_AUDIT",
            artifactType = "REDIRECT_CHAIN",
            queryTarget = r.finalHost.ifBlank { r.finalUrl },
            title = "Redirect & Header Audit: Grade ${r.securityGrade} (${r.hops.size} hop(s))",
            summary = "Initial: ${r.initialUrl} -> Final: ${r.finalUrl} (HTTP ${r.finalStatusCode}) • Security Score ${r.securityScore}/100 (${r.securityGrade}).",
            sourceApi = "Passive Hop-by-Hop Redirect Tracer",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = PureWhite,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Redirect & Header Audit",
                subtitle = "Unmask shortlinks & grade HTTP security headers",
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
                    value = urlInput,
                    onValueChange = { urlInput = it },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("redirect_url_input"),
                    singleLine = true,
                    placeholder = { Text("https://bit.ly/... or domain", color = MutedSlate, fontSize = 13.sp) },
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
                    keyboardActions = KeyboardActions(onSearch = { runTrace(urlInput) })
                )

                Button(
                    onClick = { runTrace(urlInput) },
                    enabled = urlInput.isNotBlank() && !isLoading,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .heightIn(min = 52.dp)
                        .testTag("redirect_trace_button")
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = EmeraldPrimary)
                    } else {
                        Text("Trace", fontWeight = FontWeight.SemiBold)
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
                    Icon(Icons.Default.AltRoute, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(30.dp))
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Safe Phishing & Shortlink Unmasker", color = InkBlack, fontFamily = DisplayFontFamily, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Follows up to 10 HTTP/Meta-Refresh redirects without opening a browser, blocks private-network targets at every hop, and grades HSTS, CSP, X-Frame, CORS & Cookie security flags.",
                        color = SlateGrey,
                        fontSize = 12.sp,
                        lineHeight = 18.sp
                    )
                }
            } else if (current != null) {
                val gradeColor = when (current.securityGrade) {
                    "A+", "A" -> EmeraldPrimary
                    "B", "C" -> StatusWarning
                    else -> StatusRisk
                }

                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    // Grade + Final Destination Banner
                    item {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(14.dp))
                                .background(EmeraldSoft.copy(alpha = 0.55f))
                                .border(1.dp, EmeraldBorder, RoundedCornerShape(14.dp))
                                .padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(56.dp)
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(gradeColor),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = current.securityGrade,
                                    color = PureWhite,
                                    fontSize = 24.sp,
                                    fontFamily = DisplayFontFamily,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "SECURITY SCORE: ${current.securityScore}/100 • ${current.hops.size} HOP(S)",
                                    color = EmeraldDeep,
                                    fontSize = 10.sp,
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(modifier = Modifier.height(3.dp))
                                Text(
                                    text = current.finalUrl,
                                    color = InkBlack,
                                    fontSize = 12.sp,
                                    fontFamily = MonoFontFamily,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                OutlinedButton(
                                    onClick = { onPivotEntity(current.finalHost, PivotEntityType.DOMAIN, "Redirect Final Host") },
                                    border = BorderStroke(1.dp, InkBlack),
                                    colors = ButtonDefaults.outlinedButtonColors(containerColor = PureWhite, contentColor = InkBlack),
                                    shape = RoundedCornerShape(6.dp),
                                    modifier = Modifier.heightIn(min = 34.dp)
                                ) {
                                    Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = null, modifier = Modifier.size(13.dp))
                                    Spacer(modifier = Modifier.width(5.dp))
                                    Text("Pivot ${current.finalHost}", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                                }
                            }
                        }
                    }

                    // Redirect Hops
                    item {
                        Text("REDIRECT CHAIN (${current.hops.size})", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                    }
                    items(current.hops, key = { it.hopNumber }) { hop ->
                        RedirectHopCard(
                            hop = hop,
                            onPivot = { onPivotEntity(hop.host, PivotEntityType.DOMAIN, "Redirect Hop #${hop.hopNumber}") }
                        )
                    }

                    if (!current.corsWarning.isNullOrBlank()) {
                        item {
                            Text(
                                text = current.corsWarning,
                                color = StatusRisk,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(StatusRisk.copy(alpha = 0.08f))
                                    .border(1.dp, StatusRisk.copy(alpha = 0.3f), RoundedCornerShape(10.dp))
                                    .padding(12.dp)
                            )
                        }
                    }

                    // HTTP Security Headers
                    item {
                        Text("HTTP SECURITY HEADERS", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                    }
                    items(current.headerChecks, key = { it.headerName }) { check ->
                        HeaderCheckCard(check)
                    }

                    // Info Disclosure Headers
                    if (current.infoLeakHeaders.isNotEmpty()) {
                        item {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(CharcoalNavy)
                                    .border(1.dp, CardBorder, RoundedCornerShape(12.dp))
                                    .padding(12.dp)
                            ) {
                                Text("SERVER BANNER / INFO DISCLOSURE", color = StatusWarning, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                                Spacer(modifier = Modifier.height(6.dp))
                                current.infoLeakHeaders.forEach { leak ->
                                    Text("• $leak", color = InkBlack, fontSize = 12.sp, fontFamily = MonoFontFamily)
                                }
                            }
                        }
                    }

                    // Cookies
                    if (current.cookieChecks.isNotEmpty()) {
                        item {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(CharcoalNavy)
                                    .border(1.dp, CardBorder, RoundedCornerShape(12.dp))
                                    .padding(12.dp)
                            ) {
                                Text("SET-COOKIE SECURITY FLAGS (${current.cookieChecks.size})", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                                Spacer(modifier = Modifier.height(6.dp))
                                current.cookieChecks.forEach { ck ->
                                    val flags = "Secure:${if (ck.hasSecure) "YES" else "NO"} • HttpOnly:${if (ck.hasHttpOnly) "YES" else "NO"} • SameSite:${ck.sameSite}"
                                    Text(ck.cookieName, color = InkBlack, fontSize = 12.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                                    Text(
                                        text = flags,
                                        color = if (ck.hasSecure && ck.hasHttpOnly) EmeraldDeep else StatusWarning,
                                        fontSize = 11.sp,
                                        fontFamily = MonoFontFamily
                                    )
                                    Spacer(modifier = Modifier.height(6.dp))
                                }
                            }
                        }
                    }

                    item { Spacer(modifier = Modifier.height(20.dp)) }
                }
            }
        }
    }
}

@Composable
private fun RedirectHopCard(hop: RedirectHop, onPivot: () -> Unit) {
    val codeColor = when (hop.statusCode) {
        in 200..299 -> EmeraldPrimary
        in 300..399 -> StatusWarning
        else -> StatusRisk
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(12.dp))
            .clickable(onClick = onPivot)
            .padding(12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("HOP #${hop.hopNumber} • HTTP ${hop.statusCode}", color = codeColor, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
            Text("${hop.latencyMs}ms", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(hop.url, color = InkBlack, fontSize = 12.sp, fontFamily = MonoFontFamily, maxLines = 2, overflow = TextOverflow.Ellipsis)
        if (!hop.locationHeader.isNullOrBlank()) {
            Spacer(modifier = Modifier.height(3.dp))
            Text("Location → ${hop.locationHeader}", color = EmeraldDeep, fontSize = 11.sp, fontFamily = MonoFontFamily, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        if (hop.serverHeader.isNotBlank()) {
            Text("Server: ${hop.serverHeader}", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
        }
    }
}

@Composable
private fun HeaderCheckCard(check: HeaderSecurityCheck) {
    val (icon, color) = when (check.status) {
        "PASS" -> Icons.Default.CheckCircle to EmeraldPrimary
        "WARN" -> Icons.Default.Warning to StatusWarning
        else -> Icons.Default.ErrorOutline to StatusRisk
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
            .padding(12.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(18.dp))
        Spacer(modifier = Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(check.headerName, color = InkBlack, fontSize = 12.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
            Text(check.value, color = SlateGrey, fontSize = 11.sp, fontFamily = MonoFontFamily, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(check.recommendation, color = MutedSlate, fontSize = 11.sp)
        }
    }
}
