package com.oopssecurity.osintme.ui.domain

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Router
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.model.BgpAsnInfo
import com.oopssecurity.osintme.data.model.WebTechReconResult
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun WebAndBgpSection(
    webTech: WebTechReconResult?,
    bgpAsn: BgpAsnInfo?,
    onPivot: (PivotEntity) -> Unit
) {
    if (webTech == null && bgpAsn == null) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(CharcoalNavy)
                .border(1.dp, CardBorder, RoundedCornerShape(12.dp))
                .padding(20.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "Run a domain or IP scan to inspect live Web Tech Stack, robots.txt, security.txt, linked hosts, and RIPEstat BGP/ASN prefixes.",
                color = SlateGrey,
                fontSize = 12.sp,
                lineHeight = 18.sp
            )
        }
        return
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        // RIPEstat BGP / ASN Card
        bgpAsn?.let { bgp ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                border = BorderStroke(1.dp, CardBorder),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Router, contentDescription = null, tint = MatrixGreen, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "RIPESTAT BGP / ASN ROUTING",
                            color = MatrixGreen,
                            fontSize = 11.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    BgpRow("Origin ASN", bgp.asn)
                    BgpRow("AS Holder", bgp.holder)
                    BgpRow("Active Prefix", bgp.prefix)
                    BgpRow("Announced CIDRs", "${bgp.totalAnnouncedCount} prefix(es)")

                    if (bgp.announcedPrefixes.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            bgp.announcedPrefixes.take(12).forEach { cidr ->
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(DarkerSurface)
                                        .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                                        .padding(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Text(text = cidr, color = SkyCyan, fontSize = 10.sp, fontFamily = MonoFontFamily)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Deep Web Tech Stack, robots.txt & security.txt
        webTech?.let { web ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                border = BorderStroke(1.dp, CardBorder),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Language, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "WEB STACK & FINGERPRINT (HTTP ${web.httpStatus})",
                            color = SkyCyan,
                            fontSize = 11.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    if (web.pageTitle.isNotBlank()) BgpRow("Page Title", web.pageTitle)
                    if (web.serverHeader.isNotBlank()) BgpRow("Server", web.serverHeader)
                    if (web.poweredBy.isNotBlank()) BgpRow("X-Powered-By", web.poweredBy)
                    if (web.metaGenerator.isNotBlank()) BgpRow("Generator", web.metaGenerator)

                    if (web.technologies.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = "DETECTED TECHNOLOGIES (${web.technologies.size})",
                            color = MutedSlate,
                            fontSize = 10.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            web.technologies.forEach { tech ->
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(SkyCyan.copy(alpha = 0.12f))
                                        .border(1.dp, SkyCyan.copy(alpha = 0.35f), RoundedCornerShape(6.dp))
                                        .padding(horizontal = 8.dp, vertical = 5.dp)
                                ) {
                                    Text(
                                        text = "${tech.name} • ${tech.category}",
                                        color = OffWhite,
                                        fontSize = 10.sp,
                                        fontFamily = MonoFontFamily
                                    )
                                }
                            }
                        }
                    }

                    if (web.robotsFound) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "ROBOTS.TXT DISALLOWED PATHS (${web.robotsDisallowed.size})",
                            color = SoftIndigo,
                            fontSize = 10.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        if (web.robotsDisallowed.isEmpty()) {
                            Text("robots.txt present with no Disallow entries.", color = SlateGrey, fontSize = 11.sp)
                        } else {
                            web.robotsDisallowed.take(12).forEach { path ->
                                Text(text = "• $path", color = OffWhite, fontSize = 11.sp, fontFamily = MonoFontFamily)
                            }
                        }
                    }

                    if (web.securityTxtFound && web.securityContacts.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "/.WELL-KNOWN/SECURITY.TXT",
                            color = MatrixGreen,
                            fontSize = 10.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        web.securityContacts.forEach { line ->
                            Text(text = line, color = OffWhite, fontSize = 11.sp, fontFamily = MonoFontFamily)
                        }
                    }

                    if (web.externalDomains.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "LINKED EXTERNAL DOMAINS (${web.externalDomains.size}) — TAP TO PIVOT",
                            color = SkyCyan,
                            fontSize = 10.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            web.externalDomains.forEach { dom ->
                                Row(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(SurfaceElevated)
                                        .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                                        .clickable {
                                            onPivot(PivotEngine.normalize(dom, PivotEntityType.DOMAIN, "External HTML Link"))
                                        }
                                        .padding(horizontal = 8.dp, vertical = 5.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(12.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(text = dom, color = OffWhite, fontSize = 10.sp, fontFamily = MonoFontFamily)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun BgpRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text = label,
            color = MutedSlate,
            fontSize = 11.sp,
            modifier = Modifier.width(114.dp)
        )
        Text(
            text = value,
            color = OffWhite,
            fontSize = 12.sp,
            fontFamily = MonoFontFamily,
            modifier = Modifier.weight(1f)
        )
    }
}
