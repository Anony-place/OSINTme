package com.oopssecurity.osintme.ui.compliance

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SoftIndigo

@Composable
fun ComplianceDisclaimerScreen(
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Ethics & Compliance",
                subtitle = "Authorized passive OSINT & privacy guardrails",
                showBackButton = true,
                onBackClick = onBackClick
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 14.dp)
        ) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                border = BorderStroke(1.dp, CardBorder),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(38.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .background(SkyCyan.copy(alpha = 0.14f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.Shield, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(20.dp))
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "OSINTme Defensive Charter",
                                color = OffWhite,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 16.sp,
                                fontFamily = DisplayFontFamily
                            )
                            Text(
                                text = "PASSIVE INTELLIGENCE WORKBENCH",
                                color = SkyCyan,
                                fontSize = 10.sp,
                                fontFamily = MonoFontFamily,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = "OSINTme is engineered strictly for personal digital footprint auditing, defensive security assessments, and authorized threat intelligence research. It inspects publicly observable metadata, DNS/TLS posture, breach disclosures, and local media forensics without invasive probing.",
                        color = SlateGrey,
                        fontSize = 13.sp,
                        lineHeight = 20.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = "OPERATIONAL GUARDRAILS",
                color = SkyCyan,
                fontSize = 11.sp,
                fontFamily = MonoFontFamily,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.8.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            PolicyCard(
                icon = Icons.Default.Lock,
                accent = MatrixGreen,
                title = "Zero-Cloud Local Sandbox",
                description = "Your cases, scan history, passwords (checked strictly via SHA-1 k-anonymity 5-char prefix), and EXIF images remain on-device. Media inspection uses the zero-permission Android Photo Picker."
            )

            Spacer(modifier = Modifier.height(10.dp))

            PolicyCard(
                icon = Icons.Default.Public,
                accent = SkyCyan,
                title = "Public Passive Telemetry Feeds",
                description = "All online modules query open, legitimate OSINT and infrastructure endpoints exclusively: Cloudflare DoH (1.1.1.1 / 1.1.1.2), Shodan InternetDB, crt.sh, RDAP, XposedOrNot, HIBP Pwned Passwords, URLhaus, and Wayback Machine."
            )

            Spacer(modifier = Modifier.height(10.dp))

            PolicyCard(
                icon = Icons.Default.GppGood,
                accent = SoftIndigo,
                title = "No Intrusion or Exploitation",
                description = "OSINTme includes no active port scanners, credential stuffing, vulnerability exploits, or unauthorized access tools. Use this software only on assets you own or are explicitly authorized to investigate."
            )

            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
private fun PolicyCard(
    icon: ImageVector,
    accent: Color,
    title: String,
    description: String
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        border = BorderStroke(1.dp, CardBorder),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.Top) {
            Box(
                modifier = Modifier
                    .size(34.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(accent.copy(alpha = 0.14f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(18.dp))
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    color = OffWhite,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp,
                    fontFamily = DisplayFontFamily
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = description,
                    color = SlateGrey,
                    fontSize = 12.sp,
                    lineHeight = 18.sp
                )
            }
        }
    }
}
