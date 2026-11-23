package com.oopssecurity.osintme.ui.opsec

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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.network.OpsecManager
import com.oopssecurity.osintme.data.network.ProxyMode
import com.oopssecurity.osintme.ui.components.AdBannerView
import com.oopssecurity.osintme.ui.components.AppHeader
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
import com.oopssecurity.osintme.ui.theme.StatusWarning

@Composable
fun OpsecSettingsScreen(
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    OpsecManager.init(context)

    var currentMode by remember { mutableStateOf(OpsecManager.currentProxyMode) }
    var customHost by remember { mutableStateOf(OpsecManager.customHost) }
    var customPortStr by remember { mutableStateOf(OpsecManager.customPort.toString()) }
    var randomUa by remember { mutableStateOf(OpsecManager.randomizeUserAgent) }
    var antiTrack by remember { mutableStateOf(OpsecManager.antiTrackingHeaders) }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        topBar = {
            AppHeader(
                title = "OPSEC & Network Privacy",
                subtitle = "Tor SOCKS5 routing, user-agent randomization & local privacy",
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
                .padding(horizontal = 16.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // Active Telemetry Status Card
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
                    colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.VpnLock, contentDescription = null, tint = if (currentMode != ProxyMode.DIRECT) MatrixGreen else SkyCyan, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(10.dp))
                            Text("ACTIVE OUTBOUND NETWORK ROUTE", color = OffWhite, fontSize = 13.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                        }
                        Spacer(modifier = Modifier.height(10.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Routing Mode:", color = MutedSlate, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                            Text(currentMode.label, color = if (currentMode != ProxyMode.DIRECT) MatrixGreen else SkyCyan, fontSize = 12.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                        }
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Local Storage:", color = MutedSlate, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                            Text("100% On-Device (Zero-Cloud)", color = MatrixGreen, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                        }
                    }
                }
            }

            // Proxy Configuration Section
            item {
                Text(
                    text = "PROXY & TOR ROUTING (ORBOT SOCKS5)",
                    color = SkyCyan,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Route all outgoing OSINT API calls through Tor via Orbot or a local SOCKS5 proxy to mask your device's public IP.",
                    color = SlateGrey,
                    fontSize = 12.sp
                )
            }

            items(ProxyMode.values().toList()) { mode ->
                val isSelected = (mode == currentMode)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(if (isSelected) DarkerSurface else CharcoalNavy)
                        .border(1.dp, if (isSelected) SkyCyan else CardBorder, RoundedCornerShape(8.dp))
                        .clickable {
                            currentMode = mode
                            OpsecManager.currentProxyMode = mode
                        }
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(mode.label, color = if (isSelected) SkyCyan else OffWhite, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                        if (mode.defaultPort > 0) {
                            Text("Default: ${mode.defaultHost}:${mode.defaultPort}", color = MutedSlate, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                        }
                    }
                    Box(
                        modifier = Modifier
                            .size(16.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(if (isSelected) SkyCyan else MutedSlate.copy(alpha = 0.3f))
                    )
                }
            }

            if (currentMode == ProxyMode.CUSTOM_SOCKS5 || currentMode == ProxyMode.CUSTOM_HTTP) {
                item {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = customHost,
                            onValueChange = {
                                customHost = it
                                OpsecManager.customHost = it
                            },
                            label = { Text("Proxy Host", color = MutedSlate, fontSize = 12.sp) },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = OffWhite,
                                unfocusedTextColor = OffWhite,
                                focusedBorderColor = SkyCyan,
                                unfocusedBorderColor = CardBorder,
                                focusedContainerColor = CharcoalNavy,
                                unfocusedContainerColor = CharcoalNavy
                            ),
                            singleLine = true,
                            modifier = Modifier.weight(2f)
                        )
                        OutlinedTextField(
                            value = customPortStr,
                            onValueChange = {
                                customPortStr = it
                                it.toIntOrNull()?.let { p -> OpsecManager.customPort = p }
                            },
                            label = { Text("Port", color = MutedSlate, fontSize = 12.sp) },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = OffWhite,
                                unfocusedTextColor = OffWhite,
                                focusedBorderColor = SkyCyan,
                                unfocusedBorderColor = CardBorder,
                                focusedContainerColor = CharcoalNavy,
                                unfocusedContainerColor = CharcoalNavy
                            ),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }

            // Headers & Anti-Correlation
            item {
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "FINGERPRINT DE-CORRELATION",
                    color = SkyCyan,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
            }

            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
                    colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Randomize User-Agent Headers", color = OffWhite, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                                Text("Rotates standard desktop Chrome, Firefox and Safari headers per query.", color = SlateGrey, fontSize = 11.sp)
                            }
                            Switch(
                                checked = randomUa,
                                onCheckedChange = {
                                    randomUa = it
                                    OpsecManager.randomizeUserAgent = it
                                },
                                colors = SwitchDefaults.colors(checkedThumbColor = SkyCyan, checkedTrackColor = SkyCyan.copy(alpha = 0.3f))
                            )
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Anti-Tracking Headers (DNT & GPC)", color = OffWhite, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                                Text("Injects DNT: 1 and Sec-GPC: 1 into all outgoing HTTP calls.", color = SlateGrey, fontSize = 11.sp)
                            }
                            Switch(
                                checked = antiTrack,
                                onCheckedChange = {
                                    antiTrack = it
                                    OpsecManager.antiTrackingHeaders = it
                                },
                                colors = SwitchDefaults.colors(checkedThumbColor = SkyCyan, checkedTrackColor = SkyCyan.copy(alpha = 0.3f))
                            )
                        }
                    }
                }
            }
        }
    }
}
