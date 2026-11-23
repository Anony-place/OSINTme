package com.oopssecurity.osintme.ui.phone

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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Shield
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.data.model.PhoneReconResult
import com.oopssecurity.osintme.ui.components.AdBannerView
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.CodeBlock
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

@Composable
fun PhoneReconScreen(
    initialNumber: String = "",
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: PhoneViewModel = viewModel { PhoneViewModel(context) }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(initialNumber) {
        if (initialNumber.isNotEmpty() && uiState.inputNumber.isEmpty()) {
            viewModel.setInputNumber(initialNumber)
            viewModel.executeScan(initialNumber)
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        topBar = {
            AppHeader(
                title = "Phone & Pivot Intelligence",
                subtitle = "Carrier heuristics, line identification & messaging probes",
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
            // Input Row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = uiState.inputNumber,
                    onValueChange = { viewModel.setInputNumber(it) },
                    placeholder = {
                        Text(
                            text = "+1 415 555 2671 or +91 9876543210",
                            color = MutedSlate,
                            fontSize = 13.sp
                        )
                    },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = CharcoalNavy,
                        unfocusedContainerColor = CharcoalNavy,
                        focusedBorderColor = SkyCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedTextColor = OffWhite,
                        unfocusedTextColor = OffWhite
                    ),
                    shape = RoundedCornerShape(8.dp),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Phone,
                        imeAction = ImeAction.Search
                    ),
                    keyboardActions = KeyboardActions(onSearch = { viewModel.executeScan() })
                )

                Spacer(modifier = Modifier.width(8.dp))

                Button(
                    onClick = { viewModel.executeScan() },
                    colors = ButtonDefaults.buttonColors(containerColor = SkyCyan),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.height(54.dp),
                    enabled = !uiState.isLoading
                ) {
                    if (uiState.isLoading) {
                        CircularProgressIndicator(
                            color = SlateObsidian,
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(Icons.Default.Search, contentDescription = "Scan", tint = SlateObsidian)
                    }
                }
            }

            // Body Content
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                if (uiState.error != null) {
                    item {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, StatusRisk.copy(alpha = 0.5f), RoundedCornerShape(8.dp)),
                            colors = CardDefaults.cardColors(containerColor = CharcoalNavy)
                        ) {
                            Row(
                                modifier = Modifier.padding(14.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.Warning, contentDescription = null, tint = StatusRisk)
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    text = uiState.error ?: "",
                                    color = StatusRisk,
                                    fontSize = 13.sp
                                )
                            }
                        }
                    }
                }

                val result = uiState.result
                if (result != null) {
                    // 1. Core Telemetry Dossier Card
                    item {
                        PhoneDossierCard(result = result, context = context)
                    }

                    // 2. Operational Pivots Card
                    item {
                        OperationalPivotsCard(result = result, context = context)
                    }

                    // 3. Google Dork Leak Infiltration Card
                    item {
                        PhoneDorkSection(result = result, context = context)
                    }
                } else if (!uiState.isLoading && uiState.error == null) {
                    item {
                        PhoneEmptyGuidance()
                    }
                }
            }
        }
    }
}

@Composable
private fun PhoneDossierCard(result: PhoneReconResult, context: Context) {
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
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(32.dp)
                            .background(SkyCyan.copy(alpha = 0.15f), RoundedCornerShape(6.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Phone,
                            contentDescription = null,
                            tint = SkyCyan,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Column {
                        Text(
                            text = result.e164Format,
                            color = OffWhite,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            text = result.countryName,
                            color = SlateGrey,
                            fontSize = 12.sp
                        )
                    }
                }

                IconButton(
                    onClick = {
                        val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cb.setPrimaryClip(ClipData.newPlainText("E.164 Number", result.e164Format))
                        Toast.makeText(context, "Copied ${result.e164Format}", Toast.LENGTH_SHORT).show()
                    }
                ) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = "Copy",
                        tint = MutedSlate,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Spec Grid
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SpecRow(label = "NATIONAL FORMAT", value = result.nationalFormat)
                SpecRow(
                    label = "LINE TYPE",
                    value = result.lineType,
                    valueColor = if (result.lineType.contains("Cellular")) MatrixGreen else StatusWarning
                )
                SpecRow(label = "CARRIER / EXCHANGE", value = result.carrierEstimate, valueColor = SoftIndigo)
                SpecRow(label = "PRIMARY TIMEZONE", value = result.timezone)
                SpecRow(label = "ISO REGION CODE", value = result.countryCode)
            }
        }
    }
}

@Composable
private fun OperationalPivotsCard(result: PhoneReconResult, context: Context) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "OPERATIONAL TARGET PIVOTS",
                color = SkyCyan,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.sp
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Direct application and web pivots to verify account presence and identity.",
                color = MutedSlate,
                fontSize = 12.sp
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Pivot 1: WhatsApp
            PivotActionRow(
                title = "WhatsApp Click-to-Chat Probe",
                subtitle = "Probe if target has an active WhatsApp registration",
                badge = "WA.ME",
                badgeColor = MatrixGreen,
                onClick = {
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(result.whatsappUrl))
                    context.startActivity(intent)
                }
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Pivot 2: Telegram
            PivotActionRow(
                title = "Telegram Direct Profile Probe",
                subtitle = "Query Telegram deep link for active username or avatar",
                badge = "T.ME",
                badgeColor = SkyCyan,
                onClick = {
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(result.telegramUrl))
                    context.startActivity(intent)
                }
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Pivot 3: Truecaller Web Lookup
            val nationalClean = result.nationalFormat.replace(Regex("[^0-9]"), "")
            PivotActionRow(
                title = "Truecaller Directory Search",
                subtitle = "Inspect caller ID registration and name reputation",
                badge = "TRUECALLER",
                badgeColor = SoftIndigo,
                onClick = {
                    val url = "https://www.truecaller.com/search/${result.countryCode.lowercase()}/$nationalClean"
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                    context.startActivity(intent)
                }
            )
        }
    }
}

@Composable
private fun PhoneDorkSection(result: PhoneReconResult, context: Context) {
    val cleanDigits = result.e164Format.removePrefix("+")
    val dorkQuery = "\"${result.e164Format}\" OR \"${result.nationalFormat}\" OR \"$cleanDigits\""
    val dorkUrl = "https://www.google.com/search?q=" + Uri.encode(dorkQuery)

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "PUBLIC LEAK & DOCUMENT DORK",
                color = SoftIndigo,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.sp
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Scrape indexed PDFs, paste sites, spreadsheets, and registries matching this phone number.",
                color = MutedSlate,
                fontSize = 12.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            CodeBlock(code = dorkQuery)

            Spacer(modifier = Modifier.height(10.dp))

            Button(
                onClick = {
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(dorkUrl))
                    context.startActivity(intent)
                },
                colors = ButtonDefaults.buttonColors(containerColor = SoftIndigo),
                shape = RoundedCornerShape(6.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Default.OpenInBrowser,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Launch Google Intelligence Query",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
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
            .clip(RoundedCornerShape(8.dp))
            .background(DarkerSurface)
            .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = title,
                    color = OffWhite,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(modifier = Modifier.width(8.dp))
                Box(
                    modifier = Modifier
                        .background(badgeColor.copy(alpha = 0.15f), RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = badge,
                        color = badgeColor,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = subtitle,
                color = SlateGrey,
                fontSize = 11.sp
            )
        }

        Spacer(modifier = Modifier.width(8.dp))

        Icon(
            imageVector = Icons.Default.OpenInBrowser,
            contentDescription = null,
            tint = SkyCyan,
            modifier = Modifier.size(20.dp)
        )
    }
}

@Composable
private fun SpecRow(label: String, value: String, valueColor: Color = OffWhite) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            color = MutedSlate,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace
        )
        Text(
            text = value,
            color = valueColor,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
private fun PhoneEmptyGuidance() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = Icons.Default.Phone,
            contentDescription = null,
            tint = MutedSlate,
            modifier = Modifier.size(44.dp)
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = "ENTER AN INTERNATIONAL TELEPHONE TARGET",
            color = OffWhite,
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = "Supports E.164 and national formats across 38+ countries with live carrier identification and WhatsApp/Telegram probe links.",
            color = SlateGrey,
            fontSize = 12.sp,
            modifier = Modifier.padding(horizontal = 24.dp)
        )
    }
}
