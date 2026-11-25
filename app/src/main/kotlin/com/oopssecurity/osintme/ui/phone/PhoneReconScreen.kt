package com.oopssecurity.osintme.ui.phone

import android.content.Context
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.data.model.PhoneReconResult
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.CodeBlock
import com.oopssecurity.osintme.ui.components.SaveToCaseDialog
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
import com.oopssecurity.osintme.util.SafeBrowserLauncher

@Composable
fun PhoneReconScreen(
    initialNumber: String = "",
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val focusManager = LocalFocusManager.current
    val viewModel: PhoneViewModel = viewModel { PhoneViewModel(context) }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    var showSaveDialog by remember { mutableStateOf(false) }

    LaunchedEffect(initialNumber) {
        if (initialNumber.isNotEmpty() && uiState.inputNumber.isEmpty()) {
            viewModel.setInputNumber(initialNumber)
            viewModel.executeScan(initialNumber)
        }
    }

    if (showSaveDialog && uiState.result != null) {
        val r = uiState.result!!
        SaveToCaseDialog(
            wingType = "TELEPHONY",
            artifactType = "PHONE_E164_RECON",
            queryTarget = r.e164Format,
            title = "Phone E.164 Analysis: ${r.e164Format}",
            summary = "${r.countryName} (${r.countryCode}) • ${r.lineType} • ${r.timezone}",
            sourceApi = "ITU-T E.164 Numbering Plan Analyzer",
            onDismiss = { showSaveDialog = false }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Phone E.164 & Pivots",
                subtitle = "115+ ITU-T country plans & messaging probes",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (uiState.result != null) {
                    {
                        IconButton(
                            onClick = { showSaveDialog = true },
                            modifier = Modifier.size(48.dp).testTag("phone_save_case_button")
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = uiState.inputNumber,
                    onValueChange = { viewModel.setInputNumber(it) },
                    placeholder = { Text("+1 415 555 2671 or +91 9876543210", color = MutedSlate, fontSize = 13.sp) },
                    modifier = Modifier.weight(1f).testTag("phone_number_input"),
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = OffWhite),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = CharcoalNavy,
                        unfocusedContainerColor = CharcoalNavy,
                        focusedBorderColor = SkyCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedTextColor = OffWhite,
                        unfocusedTextColor = OffWhite
                    ),
                    shape = RoundedCornerShape(10.dp),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone, imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = {
                        focusManager.clearFocus()
                        viewModel.executeScan()
                    })
                )

                Spacer(modifier = Modifier.width(8.dp))

                Button(
                    onClick = {
                        focusManager.clearFocus()
                        viewModel.executeScan()
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.height(54.dp).testTag("phone_scan_button"),
                    enabled = !uiState.isLoading && uiState.inputNumber.isNotBlank()
                ) {
                    if (uiState.isLoading) {
                        CircularProgressIndicator(color = PureWhite, modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Default.Search, contentDescription = "Analyze phone number")
                    }
                }
            }

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                if (uiState.error != null) {
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
                            Text(uiState.error ?: "", color = StatusRisk, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }

                val result = uiState.result
                if (result != null) {
                    item { PhoneDossierCard(result = result, context = context) }
                    item { OperationalPivotsCard(result = result, context = context) }
                    item { PhoneDorkSection(result = result, context = context) }
                } else if (!uiState.isLoading && uiState.error == null) {
                    item { PhoneEmptyGuidance() }
                }

                item { Spacer(modifier = Modifier.height(14.dp)) }
            }
        }
    }
}

@Composable
private fun PhoneDossierCard(result: PhoneReconResult, context: Context) {
    val validColor = if (result.isValidLength) StatusSafe else StatusWarning

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(SkyCyan.copy(alpha = 0.14f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Default.Phone, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(18.dp))
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(
                        text = result.e164Format,
                        color = OffWhite,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = MonoFontFamily
                    )
                    Text(result.countryName, color = SlateGrey, fontSize = 12.sp)
                }
            }

            IconButton(
                onClick = {
                    SafeBrowserLauncher.copyToClipboard(context, "E.164 Number", result.e164Format, isSensitive = true)
                    Toast.makeText(context, "Copied ${result.e164Format}", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.size(44.dp)
            ) {
                Icon(Icons.Default.ContentCopy, contentDescription = "Copy E.164 number", tint = SkyCyan, modifier = Modifier.size(18.dp))
            }
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(DarkerSurface)
                .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp)
        ) {
            SpecRow("E.164 Validation", if (result.isValidLength) "VALID LENGTH" else "CHECK DIGITS", validColor)
            SpecRow("National Format", result.nationalFormat)
            SpecRow("Dial / ISO Code", "${result.dialCode} (${result.countryCode})")
            SpecRow("Classification", result.lineType, SkyCyan)
            SpecRow("Timezone", result.timezone)
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(DarkerSurface)
                .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                .padding(12.dp)
        ) {
            Text("NUMBERING PLAN ANALYSIS", color = SoftIndigo, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
            Spacer(modifier = Modifier.height(4.dp))
            Text(result.numberingPlanNote, color = SlateGrey, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun OperationalPivotsCard(result: PhoneReconResult, context: Context) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("MESSAGING & DIRECTORY PIVOTS", color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)

        PivotActionRow(
            title = "WhatsApp Click-to-Chat Probe",
            subtitle = "Check whether number resolves to an active WhatsApp account",
            badge = "WA.ME",
            badgeColor = MatrixGreen,
            onClick = { SafeBrowserLauncher.openExternalUrl(context, result.whatsappUrl) }
        )

        PivotActionRow(
            title = "Telegram Direct Link Probe",
            subtitle = "Open Telegram deep link to check public profile or avatar",
            badge = "T.ME",
            badgeColor = SkyCyan,
            onClick = { SafeBrowserLauncher.openExternalUrl(context, result.telegramUrl) }
        )

        val nationalClean = result.nationalFormat.replace(Regex("[^0-9]"), "")
        val isoLookup = result.countryCode.substringBefore("/").lowercase()
        PivotActionRow(
            title = "Truecaller Directory Lookup",
            subtitle = "Search public caller directory in your browser",
            badge = "WEB",
            badgeColor = SoftIndigo,
            onClick = {
                val url = "https://www.truecaller.com/search/$isoLookup/$nationalClean"
                SafeBrowserLauncher.openExternalUrl(context, url)
            }
        )
    }
}

@Composable
private fun PhoneDorkSection(result: PhoneReconResult, context: Context) {
    val cleanDigits = result.e164Format.removePrefix("+")
    val dorkQuery = "\"${result.e164Format}\" OR \"${result.nationalFormat}\" OR \"$cleanDigits\""
    val dorkUrl = "https://www.google.com/search?q=" + Uri.encode(dorkQuery)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp)
    ) {
        Text("PUBLIC EXPOSURE GOOGLE DORK", color = SoftIndigo, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Search indexed documents, directories, and public pages referencing this number.",
            color = SlateGrey,
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(modifier = Modifier.height(10.dp))
        CodeBlock(code = dorkQuery)
        Spacer(modifier = Modifier.height(12.dp))
        Button(
            onClick = { SafeBrowserLauncher.openExternalUrl(context, dorkUrl) },
            colors = ButtonDefaults.buttonColors(
                containerColor = EmeraldPrimary,
                contentColor = PureWhite,
                disabledContainerColor = SurfaceElevated,
                disabledContentColor = MutedSlate
            ),
            shape = RoundedCornerShape(10.dp),
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
        ) {
            Icon(Icons.Default.OpenInBrowser, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("Run Google Search Query", fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
private fun PivotActionRow(
    title: String,
    subtitle: String,
    badge: String,
    badgeColor: Color,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(DarkerSurface)
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
            .padding(12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, color = OffWhite, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                Spacer(modifier = Modifier.width(8.dp))
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(badgeColor.copy(alpha = 0.14f))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(badge, color = badgeColor, fontSize = 9.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                }
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(subtitle, color = SlateGrey, fontSize = 11.sp)
        }
        Spacer(modifier = Modifier.width(8.dp))
        Icon(Icons.Default.OpenInBrowser, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(18.dp))
    }
}

@Composable
private fun SpecRow(label: String, value: String, valueColor: Color = OffWhite) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = SlateGrey, fontSize = 12.sp)
        Text(value, color = valueColor, fontSize = 12.sp, fontWeight = FontWeight.Medium, fontFamily = MonoFontFamily)
    }
}

@Composable
private fun PhoneEmptyGuidance() {
    Column(
        modifier = Modifier.fillMaxWidth().padding(top = 36.dp, start = 20.dp, end = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(Icons.Default.Phone, contentDescription = null, tint = MutedSlate, modifier = Modifier.size(44.dp))
        Spacer(modifier = Modifier.height(12.dp))
        Text("International E.164 Number Analyzer", style = MaterialTheme.typography.titleSmall, color = OffWhite)
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = "Include the country dial code (e.g. +1, +44, +91) to inspect ITU-T numbering rules across 115+ countries and launch messaging pivots.",
            color = SlateGrey,
            style = MaterialTheme.typography.bodySmall
        )
    }
}
