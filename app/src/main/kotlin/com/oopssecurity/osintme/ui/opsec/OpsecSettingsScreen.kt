package com.oopssecurity.osintme.ui.opsec

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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.model.OpsecRouteCheckResult
import com.oopssecurity.osintme.data.network.OpsecManager
import com.oopssecurity.osintme.data.network.ProxyMode
import com.oopssecurity.osintme.data.network.ShodanService
import com.oopssecurity.osintme.ui.components.AppHeader
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
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import kotlinx.coroutines.launch

@Composable
fun OpsecSettingsScreen(
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    remember(context) { OpsecManager.init(context) }

    var currentMode by remember { mutableStateOf(OpsecManager.currentProxyMode) }
    var customHost by remember { mutableStateOf(OpsecManager.customHost) }
    var customPortStr by remember { mutableStateOf(OpsecManager.customPort.toString()) }
    var randomUa by remember { mutableStateOf(OpsecManager.randomizeUserAgent) }
    var antiTrack by remember { mutableStateOf(OpsecManager.antiTrackingHeaders) }
    var screenShield by remember { mutableStateOf(OpsecManager.screenShieldEnabled) }

    var isTestingRoute by remember { mutableStateOf(false) }
    var routeResult by remember { mutableStateOf<OpsecRouteCheckResult?>(null) }
    var routeError by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun testActiveRoute() {
        isTestingRoute = true
        routeError = null
        scope.launch {
            ShodanService.checkActiveExitRoute().fold(
                onSuccess = {
                    routeResult = it
                    isTestingRoute = false
                },
                onFailure = {
                    routeError = it.message ?: "Route verification failed. Check proxy host/port or Orbot status."
                    isTestingRoute = false
                }
            )
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "OPSEC & Proxy Router",
                subtitle = "Tor SOCKS5 routing, headers & live Exit IP check",
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
            // Active Route & Live Exit IP Verification Card
            item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.VpnLock,
                            contentDescription = null,
                            tint = if (currentMode != ProxyMode.DIRECT) MatrixGreen else SkyCyan,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text("ACTIVE OUTBOUND ROUTE", style = MaterialTheme.typography.titleSmall, color = OffWhite)
                    }

                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(DarkerSurface)
                            .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                            .padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        RouteStatRow("Routing Mode", currentMode.label, if (currentMode != ProxyMode.DIRECT) MatrixGreen else SkyCyan)
                        RouteStatRow("Local Storage", "On-Device SQLite (Zero-Cloud)", MatrixGreen)
                        routeResult?.let { r ->
                            RouteStatRow("Verified Exit IP", r.publicIp, SkyCyan)
                            RouteStatRow("Exit Location", listOf(r.city, r.country).filter { it.isNotBlank() }.joinToString(", "))
                            if (r.isp.isNotBlank()) RouteStatRow("Exit ISP / ASN", listOf(r.isp, r.asn).filter { it.isNotBlank() }.joinToString(" • "))
                            RouteStatRow("Round-Trip Latency", "${r.latencyMs}ms", MatrixGreen)
                        }
                    }

                    routeError?.let { err ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .background(StatusRisk.copy(alpha = 0.12f))
                                .border(1.dp, StatusRisk.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                                .padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = StatusRisk, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(err, color = StatusRisk, style = MaterialTheme.typography.bodySmall)
                        }
                    }

                    Button(
                        onClick = { testActiveRoute() },
                        enabled = !isTestingRoute,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("opsec_verify_route_button"),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = EmeraldPrimary,
                            contentColor = PureWhite,
                            disabledContainerColor = SurfaceElevated,
                            disabledContentColor = MutedSlate
                        ),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        if (isTestingRoute) {
                            CircularProgressIndicator(color = PureWhite, modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Verifying Live Exit IP…", fontWeight = FontWeight.SemiBold)
                        } else {
                            Icon(Icons.Default.NetworkCheck, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Verify Active Route & Exit IP", fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }

            // Proxy Routing Modes
            item {
                Text("PROXY & TOR ROUTING", color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Route all outgoing OSINT queries through Tor (Orbot) or a custom SOCKS5 / HTTP proxy.",
                    color = SlateGrey,
                    style = MaterialTheme.typography.bodySmall
                )
            }

            items(ProxyMode.entries) { mode ->
                val isSelected = (mode == currentMode)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 56.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(if (isSelected) DarkerSurface else CharcoalNavy)
                        .border(1.dp, if (isSelected) SkyCyan else CardBorder, RoundedCornerShape(10.dp))
                        .clickable {
                            currentMode = mode
                            OpsecManager.currentProxyMode = mode
                            routeResult = null
                            routeError = null
                        }
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(mode.label, color = if (isSelected) SkyCyan else OffWhite, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                        if (mode.defaultPort > 0) {
                            Text("Endpoint: ${mode.defaultHost}:${mode.defaultPort}", color = MutedSlate, fontSize = 11.sp, fontFamily = MonoFontFamily)
                        }
                    }
                    Box(
                        modifier = Modifier
                            .size(16.dp)
                            .clip(CircleShape)
                            .background(if (isSelected) SkyCyan else MutedSlate.copy(alpha = 0.25f))
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
                            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = OffWhite),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = OffWhite,
                                unfocusedTextColor = OffWhite,
                                focusedBorderColor = SkyCyan,
                                unfocusedBorderColor = CardBorder,
                                focusedContainerColor = CharcoalNavy,
                                unfocusedContainerColor = CharcoalNavy
                            ),
                            singleLine = true,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(2f)
                        )
                        OutlinedTextField(
                            value = customPortStr,
                            onValueChange = {
                                customPortStr = it
                                it.toIntOrNull()?.let { p -> OpsecManager.customPort = p }
                            },
                            label = { Text("Port", color = MutedSlate, fontSize = 12.sp) },
                            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = OffWhite),
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
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }

            // On-Device Privacy & Screen Capture Protection
            item {
                Spacer(modifier = Modifier.height(4.dp))
                Text("DEVICE PRIVACY & APP HARDENING", color = EmeraldPrimary, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
            }

            item {
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
                        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Security, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Screen Capture Shield", color = OffWhite, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                            }
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "Blocks screenshots, screen recording, and streamed/mirrored previews on physical devices. Leave off during remote previews.",
                                color = SlateGrey,
                                fontSize = 11.sp
                            )
                        }
                        Switch(
                            checked = screenShield,
                            onCheckedChange = {
                                screenShield = it
                                OpsecManager.screenShieldEnabled = it
                            },
                            modifier = Modifier.testTag("opsec_screen_shield_switch"),
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = PureWhite,
                                checkedTrackColor = EmeraldPrimary,
                                uncheckedThumbColor = SlateGrey,
                                uncheckedTrackColor = SurfaceElevated
                            )
                        )
                    }

                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(DarkerSurface)
                            .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                            .padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        RouteStatRow("Screen Capture Shield", if (screenShield) "ACTIVE" else "OFF (OPTIONAL)", if (screenShield) MatrixGreen else SlateGrey)
                        RouteStatRow("Cloud / ADB Backup", "BLOCKED", MatrixGreen)
                        RouteStatRow("BYOK Key Storage", "HARDWARE AES-256-GCM", MatrixGreen)
                        RouteStatRow("Private-Network Guard", "ENFORCED ON ALL HOPS", MatrixGreen)
                        RouteStatRow("External Link Guard", "STRICT PUBLIC HTTP/S", MatrixGreen)
                    }
                }
            }

            // Fingerprint Controls
            item {
                Spacer(modifier = Modifier.height(4.dp))
                Text("REQUEST FINGERPRINTING", color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
            }

            item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                            Text("Rotate User-Agent Headers", color = OffWhite, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                            Text("Rotates desktop browser headers on outgoing requests.", color = SlateGrey, fontSize = 11.sp)
                        }
                        Switch(
                            checked = randomUa,
                            onCheckedChange = {
                                randomUa = it
                                OpsecManager.randomizeUserAgent = it
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = PureWhite,
                                checkedTrackColor = EmeraldPrimary,
                                uncheckedThumbColor = SlateGrey,
                                uncheckedTrackColor = SurfaceElevated
                            )
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                            Text("Anti-Tracking Headers (DNT & GPC)", color = OffWhite, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                            Text("Appends DNT: 1 and Sec-GPC: 1 to outgoing requests.", color = SlateGrey, fontSize = 11.sp)
                        }
                        Switch(
                            checked = antiTrack,
                            onCheckedChange = {
                                antiTrack = it
                                OpsecManager.antiTrackingHeaders = it
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = PureWhite,
                                checkedTrackColor = EmeraldPrimary,
                                uncheckedThumbColor = SlateGrey,
                                uncheckedTrackColor = SurfaceElevated
                            )
                        )
                    }
                }
            }

            item { Spacer(modifier = Modifier.height(12.dp)) }
        }
    }
}

@Composable
private fun RouteStatRow(label: String, value: String, valueColor: androidx.compose.ui.graphics.Color = OffWhite) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = SlateGrey, fontSize = 12.sp)
        Text(value, color = valueColor, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.SemiBold)
    }
}
