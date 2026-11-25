package com.oopssecurity.osintme.ui.sanitizer

import android.content.Intent
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.filled.AltRoute
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
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
import com.oopssecurity.osintme.data.local.LocalScanHistoryManager
import com.oopssecurity.osintme.data.model.RedirectChainResult
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.CodeBlock
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
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
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType
import com.oopssecurity.osintme.util.SafeBrowserLauncher

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun LinkSanitizerScreen(
    initialUrl: String = "",
    onBackClick: () -> Unit,
    onPivot: (PivotEntity) -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val focusManager = LocalFocusManager.current
    val viewModel: LinkSanitizerViewModel = viewModel(key = "sanitizer_${initialUrl.ifBlank { "root" }}") {
        LinkSanitizerViewModel(LocalScanHistoryManager(context))
    }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(initialUrl) {
        if (initialUrl.isNotEmpty() && uiState.inputUrl.isEmpty()) {
            viewModel.setInputUrl(initialUrl)
            viewModel.sanitize(initialUrl)
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Link & Redirect Inspector",
                subtitle = "Unshorten HTTP redirect hops & strip 60+ trackers",
                showBackButton = true,
                onBackClick = onBackClick
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
            item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                        .padding(16.dp)
                ) {
                    Text("URL TO SANITIZE OR UNSHORTEN", fontSize = 11.sp, color = SlateGrey, fontFamily = MonoFontFamily)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = uiState.inputUrl,
                        onValueChange = { viewModel.setInputUrl(it) },
                        placeholder = { Text("Paste bit.ly, t.co, or tracked URL…", color = MutedSlate, fontSize = 13.sp) },
                        modifier = Modifier.fillMaxWidth().testTag("sanitizer_url_input"),
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = OffWhite),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedContainerColor = DarkerSurface,
                            unfocusedContainerColor = DarkerSurface,
                            focusedBorderColor = SkyCyan,
                            unfocusedBorderColor = CardBorder,
                            focusedTextColor = OffWhite,
                            unfocusedTextColor = OffWhite
                        ),
                        shape = RoundedCornerShape(10.dp),
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                        keyboardActions = KeyboardActions(onDone = {
                            focusManager.clearFocus()
                            viewModel.sanitize()
                        })
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                focusManager.clearFocus()
                                viewModel.sanitize()
                            },
                            enabled = uiState.inputUrl.isNotBlank() && !uiState.isResolvingRedirects,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = EmeraldPrimary,
                                contentColor = PureWhite,
                                disabledContainerColor = SurfaceElevated,
                                disabledContentColor = MutedSlate
                            ),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag("sanitizer_clean_button")
                        ) {
                            Icon(Icons.Default.CleaningServices, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Strip Trackers", fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                        }

                        Button(
                            onClick = {
                                focusManager.clearFocus()
                                viewModel.traceRedirects()
                            },
                            enabled = uiState.inputUrl.isNotBlank() && !uiState.isResolvingRedirects,
                            colors = ButtonDefaults.buttonColors(containerColor = DarkerSurface, contentColor = SoftIndigo),
                            border = BorderStroke(1.dp, SoftIndigo.copy(alpha = 0.5f)),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag("sanitizer_trace_button")
                        ) {
                            if (uiState.isResolvingRedirects) {
                                CircularProgressIndicator(color = SoftIndigo, modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Tracing…", fontSize = 12.sp)
                            } else {
                                Icon(Icons.Default.AltRoute, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Trace Redirects", fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                            }
                        }
                    }
                }
            }

            if (uiState.redirectError != null) {
                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(StatusRisk.copy(alpha = 0.12f))
                            .border(1.dp, StatusRisk.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = StatusRisk, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(uiState.redirectError ?: "", color = StatusRisk, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            uiState.redirectChain?.let { chain ->
                item { RedirectChainCard(chain = chain, onPivot = onPivot) }
            }

            uiState.result?.let { res ->
                item {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(14.dp))
                            .background(CharcoalNavy)
                            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                            .padding(16.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Security, contentDescription = null, tint = StatusSafe, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("SANITIZED DESTINATION URL", color = StatusSafe, fontWeight = FontWeight.Bold, fontSize = 12.sp, fontFamily = MonoFontFamily)
                            }
                            if (res.removedParams.isNotEmpty()) {
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(5.dp))
                                        .background(StatusRisk.copy(alpha = 0.14f))
                                        .padding(horizontal = 8.dp, vertical = 3.dp)
                                ) {
                                    Text("${res.removedParams.size} Stripped", color = StatusRisk, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))
                        CodeBlock(code = res.sanitizedUrl)
                        Spacer(modifier = Modifier.height(12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = {
                                    SafeBrowserLauncher.copyToClipboard(context, "Sanitized Link", res.sanitizedUrl, isSensitive = false)
                                    Toast.makeText(context, "Clean URL copied", Toast.LENGTH_SHORT).show()
                                },
                                modifier = Modifier.weight(1f).heightIn(min = 44.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = DarkerSurface, contentColor = SkyCyan),
                                shape = RoundedCornerShape(8.dp),
                                border = BorderStroke(1.dp, CardBorder)
                            ) {
                                Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(15.dp))
                                Spacer(modifier = Modifier.width(5.dp))
                                Text("Copy", fontSize = 12.sp)
                            }

                            Button(
                                onClick = {
                                    val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                        type = "text/plain"
                                        putExtra(Intent.EXTRA_TEXT, res.sanitizedUrl)
                                    }
                                    context.startActivity(Intent.createChooser(shareIntent, "Share Clean Link"))
                                },
                                modifier = Modifier.weight(1f).heightIn(min = 44.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = DarkerSurface, contentColor = SkyCyan),
                                shape = RoundedCornerShape(8.dp),
                                border = BorderStroke(1.dp, CardBorder)
                            ) {
                                Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(15.dp))
                                Spacer(modifier = Modifier.width(5.dp))
                                Text("Share", fontSize = 12.sp)
                            }

                            Button(
                                onClick = {
                                    if (!SafeBrowserLauncher.openExternalUrl(context, res.sanitizedUrl)) {
                                        Toast.makeText(context, "Blocked unsafe or unopenable URL", Toast.LENGTH_SHORT).show()
                                    }
                                },
                                modifier = Modifier.weight(1f).heightIn(min = 44.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = EmeraldPrimary,
                                    contentColor = PureWhite,
                                    disabledContainerColor = SurfaceElevated,
                                    disabledContentColor = MutedSlate
                                ),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Icon(Icons.Default.OpenInBrowser, contentDescription = null, modifier = Modifier.size(15.dp))
                                Spacer(modifier = Modifier.width(5.dp))
                                Text("Open", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        Button(
                            onClick = {
                                onPivot(
                                    PivotEngine.normalize(
                                        raw = res.sanitizedUrl,
                                        hintType = PivotEntityType.URL,
                                        sourceContext = "Sanitized Destination URL"
                                    )
                                )
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 46.dp)
                                .testTag("sanitizer_pivot_host_button"),
                            colors = ButtonDefaults.buttonColors(containerColor = DarkerSurface, contentColor = SoftIndigo),
                            shape = RoundedCornerShape(8.dp),
                            border = BorderStroke(1.dp, SoftIndigo.copy(alpha = 0.45f))
                        ) {
                            Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Pivot Destination Host / Threat Intel", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        }

                        if (res.removedParams.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(14.dp))
                            Text("REMOVED TRACKING TOKENS", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
                            Spacer(modifier = Modifier.height(6.dp))
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                res.removedParams.forEach { param ->
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(5.dp))
                                            .background(DarkerSurface)
                                            .border(1.dp, CardBorder, RoundedCornerShape(5.dp))
                                            .padding(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Text(param, color = StatusRisk, fontSize = 11.sp, fontFamily = MonoFontFamily)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            item { Spacer(modifier = Modifier.height(12.dp)) }
        }
    }
}

@Composable
private fun RedirectChainCard(
    chain: RedirectChainResult,
    onPivot: (PivotEntity) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "HTTP REDIRECT CHAIN (${chain.hops.size} HOP${if (chain.hops.size == 1) "" else "S"})",
                color = SoftIndigo,
                fontSize = 11.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = if (chain.hops.size > 1) "UNSHORTENED • TAP HOP" else "DIRECT • TAP HOP",
                color = if (chain.hops.size > 1) StatusWarning else MatrixGreen,
                fontSize = 10.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold
            )
        }

        chain.hops.forEach { hop ->
            val codeColor = when {
                hop.statusCode in 200..299 -> MatrixGreen
                hop.statusCode in 300..399 -> StatusWarning
                else -> StatusRisk
            }
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(DarkerSurface)
                    .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                    .clickable {
                        onPivot(
                            PivotEngine.normalize(
                                raw = hop.url,
                                hintType = PivotEntityType.URL,
                                sourceContext = "Redirect Hop #${hop.hopIndex} (HTTP ${hop.statusCode})"
                            )
                        )
                    }
                    .padding(10.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(codeColor.copy(alpha = 0.14f))
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text("HTTP ${hop.statusCode}", color = codeColor, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Hop #${hop.hopIndex}", color = SlateGrey, fontSize = 11.sp, fontFamily = MonoFontFamily)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("${hop.latencyMs}ms", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
                        Spacer(modifier = Modifier.width(6.dp))
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.CallSplit,
                            contentDescription = "Pivot hop URL",
                            tint = SkyCyan,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = hop.url,
                    color = OffWhite,
                    fontSize = 11.sp,
                    fontFamily = MonoFontFamily,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}
