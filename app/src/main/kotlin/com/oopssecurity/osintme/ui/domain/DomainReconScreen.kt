package com.oopssecurity.osintme.ui.domain

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
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Router
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
import androidx.compose.material3.MaterialTheme
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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.data.model.DnsRecordItem
import com.oopssecurity.osintme.data.model.IpReconResult
import com.oopssecurity.osintme.data.model.RdapDomainInfo
import com.oopssecurity.osintme.data.model.SubdomainResult
import com.oopssecurity.osintme.data.model.WaybackUrlItem
import com.oopssecurity.osintme.ui.components.AdBannerView
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.CodeBlock
import com.oopssecurity.osintme.ui.components.PartnerOfferCard
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
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.ui.theme.TechCodeBackground

@Composable
fun DomainReconScreen(
    initialTarget: String = "",
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: DomainViewModel = viewModel { DomainViewModel(context) }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(initialTarget) {
        if (initialTarget.isNotEmpty() && uiState.target.isEmpty()) {
            viewModel.setTarget(initialTarget)
            viewModel.executeScan(initialTarget)
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        topBar = {
            AppHeader(
                title = "Network & Domain Recon",
                subtitle = "IP intelligence, subdomains, DNS & WHOIS",
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
            // Search Input Row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = uiState.target,
                    onValueChange = { viewModel.setTarget(it) },
                    placeholder = {
                        Text("Enter Domain (e.g. example.com) or IPv4", color = MutedSlate, fontSize = 13.sp)
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
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
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

            // Tab bar
            val tabs = listOf("Overview / Ports", "Subdomains", "DNS Records", "WHOIS", "Wayback CDX")
            TabRow(
                selectedTabIndex = uiState.activeTab,
                containerColor = CharcoalNavy,
                contentColor = SkyCyan,
                indicator = { tabPositions ->
                    TabRowDefaults.SecondaryIndicator(
                        Modifier.tabIndicatorOffset(tabPositions[uiState.activeTab]),
                        color = SkyCyan
                    )
                }
            ) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        selected = uiState.activeTab == index,
                        onClick = { viewModel.selectTab(index) },
                        text = {
                            Text(
                                text = title,
                                fontSize = 11.sp,
                                fontWeight = if (uiState.activeTab == index) FontWeight.Bold else FontWeight.Normal,
                                color = if (uiState.activeTab == index) SkyCyan else SlateGrey
                            )
                        }
                    )
                }
            }

            // Tab Content
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp, vertical = 12.dp)
            ) {
                // Error message
                if (uiState.error != null) {
                    item {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, StatusRisk.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
                                .padding(bottom = 12.dp),
                            colors = CardDefaults.cardColors(containerColor = CharcoalNavy)
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.Warning, contentDescription = null, tint = StatusRisk)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(uiState.error ?: "", color = StatusRisk, fontSize = 13.sp)
                            }
                        }
                    }
                }

                when (uiState.activeTab) {
                    0 -> { // Overview & Shodan IP Ports
                        item {
                            IpOverviewSection(uiState.ipResult, uiState.target)
                        }
                        if (uiState.partnerOffers.isNotEmpty()) {
                            items(uiState.partnerOffers) { offer ->
                                PartnerOfferCard(offer = offer, modifier = Modifier.padding(top = 8.dp))
                            }
                        }
                    }
                    1 -> { // Subdomains
                        item {
                            SubdomainsSection(uiState.subdomainResult, context)
                        }
                    }
                    2 -> { // DNS Records
                        item {
                            DnsRecordsSection(uiState.dnsRecords)
                        }
                    }
                    3 -> { // RDAP / WHOIS
                        item {
                            RdapSection(uiState.rdapInfo)
                        }
                    }
                    4 -> { // Wayback Machine Historical CDX
                        item {
                            WaybackSection(uiState.waybackUrls, context)
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun IpOverviewSection(result: IpReconResult?, target: String) {
    if (result == null) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 32.dp),
            contentAlignment = Alignment.Center
        ) {
            Text("Enter a domain or IP and tap Scan to query network intel.", color = MutedSlate, fontSize = 13.sp)
        }
        return
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Router, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(20.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Host, ISP & Port Intel (Shodan + IP-API)", color = OffWhite, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
            }

            Spacer(modifier = Modifier.height(12.dp))

            // IP & Routing telemetry
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text("RESOLVED IP", color = SlateGrey, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                    Text(result.ip, color = SkyCyan, fontSize = 14.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                }

                if (result.country.isNotEmpty() && result.country != "Unknown") {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(DarkerSurface)
                            .border(1.dp, CardBorder, RoundedCornerShape(4.dp))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = if (result.city.isNotEmpty()) "${result.city}, ${result.country}" else result.country,
                            color = OffWhite,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }

            // ISP & ASN Details
            if (result.isp.isNotEmpty() || result.asn.isNotEmpty() || result.org.isNotEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(6.dp))
                        .background(DarkerSurface)
                        .padding(10.dp)
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        if (result.isp.isNotEmpty()) {
                            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                Text("ISP:", color = SlateGrey, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                                Text(result.isp, color = OffWhite, fontSize = 11.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium)
                            }
                        }
                        if (result.asn.isNotEmpty()) {
                            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                Text("ASN:", color = SlateGrey, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                                Text(result.asn, color = SkyCyan, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                            }
                        }
                        if (result.org.isNotEmpty()) {
                            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                Text("ORGANIZATION:", color = SlateGrey, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                                Text(result.org, color = OffWhite, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Open Ports
            Text(
                text = "OPEN PORTS (${result.ports.size})",
                color = if (result.ports.isNotEmpty()) StatusWarning else StatusSafe,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold
            )

            if (result.ports.isEmpty()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text("No open ports found in public scans (Filtered / Safe)", color = StatusSafe, fontSize = 12.sp)
            } else {
                FlowRow(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    result.ports.forEach { port ->
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(if (port in listOf(21, 22, 23, 3389, 445)) StatusRisk.copy(alpha = 0.15f) else SurfaceElevated)
                                .border(1.dp, if (port in listOf(21, 22, 23, 3389, 445)) StatusRisk.copy(alpha = 0.5f) else CardBorder, RoundedCornerShape(6.dp))
                                .padding(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = "PORT $port",
                                color = if (port in listOf(21, 22, 23, 3389, 445)) StatusRisk else SkyCyan,
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }

            // Vulnerabilities (CVEs)
            if (result.vulns.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Text("KNOWN VULNERABILITIES (${result.vulns.size})", color = StatusRisk, fontSize = 11.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                FlowRow(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    result.vulns.forEach { cve ->
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(StatusRisk.copy(alpha = 0.15f))
                                .border(1.dp, StatusRisk.copy(alpha = 0.5f), RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(text = cve, color = StatusRisk, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                        }
                    }
                }
            }

            // Hostnames
            if (result.hostnames.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Text("HOSTNAMES", color = SlateGrey, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                result.hostnames.forEach { host ->
                    Text("• $host", color = OffWhite, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}

@Composable
private fun SubdomainsSection(result: SubdomainResult?, context: Context) {
    if (result == null) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 32.dp),
            contentAlignment = Alignment.Center
        ) {
            Text("No subdomain discovery performed yet.", color = MutedSlate, fontSize = 13.sp)
        }
        return
    }

    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "CERTIFICATE TRANSPARENCY LOGS (${result.totalCount} FOUND)",
                color = SlateGrey,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace
            )

            if (result.subdomains.isNotEmpty()) {
                IconButton(onClick = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = ClipData.newPlainText("Subdomains", result.subdomains.joinToString("\n"))
                    clipboard.setPrimaryClip(clip)
                    Toast.makeText(context, "Copied ${result.subdomains.size} subdomains to clipboard", Toast.LENGTH_SHORT).show()
                }) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy all", tint = SkyCyan, modifier = Modifier.size(18.dp))
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        result.subdomains.forEach { sub ->
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 3.dp)
                    .clip(RoundedCornerShape(6.dp))
                    .background(DarkerSurface)
                    .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                    .padding(horizontal = 12.dp, vertical = 8.dp)
            ) {
                Text(
                    text = sub,
                    color = OffWhite,
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace
                )
            }
        }
    }
}

@Composable
private fun DnsRecordsSection(records: List<DnsRecordItem>) {
    if (records.isEmpty()) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 32.dp),
            contentAlignment = Alignment.Center
        ) {
            Text("No DNS records resolved via Cloudflare DoH.", color = MutedSlate, fontSize = 13.sp)
        }
        return
    }

    Column {
        Text("DNS-OVER-HTTPS (CLOUDFLARE 1.1.1.1)", color = SlateGrey, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
        Spacer(modifier = Modifier.height(8.dp))

        records.forEach { rec ->
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 3.dp)
                    .border(1.dp, CardBorder, RoundedCornerShape(6.dp)),
                colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                shape = RoundedCornerShape(6.dp)
            ) {
                Row(
                    modifier = Modifier.padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(SkyCyan.copy(alpha = 0.15f))
                            .padding(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Text(rec.type, color = SkyCyan, fontWeight = FontWeight.Bold, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    }

                    Spacer(modifier = Modifier.width(12.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(rec.data, color = OffWhite, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
                        Text("Name: ${rec.name} | TTL: ${rec.ttl}s", color = SlateGrey, fontSize = 11.sp)
                    }
                }
            }
        }
    }
}

@Composable
private fun RdapSection(rdap: RdapDomainInfo?) {
    if (rdap == null) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 32.dp),
            contentAlignment = Alignment.Center
        ) {
            Text("No registration records found via RDAP.", color = MutedSlate, fontSize = 13.sp)
        }
        return
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("REGISTRATION & WHOIS (RDAP)", color = SkyCyan, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            Spacer(modifier = Modifier.height(12.dp))

            RdapRow("Domain", rdap.domain)
            RdapRow("Registrar", rdap.registrar)
            if (rdap.registrationDate.isNotEmpty()) RdapRow("Registered", rdap.registrationDate)
            if (rdap.expirationDate.isNotEmpty()) RdapRow("Expires", rdap.expirationDate)
            if (rdap.lastUpdated.isNotEmpty()) RdapRow("Last Updated", rdap.lastUpdated)

            if (rdap.nameServers.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Text("NAME SERVERS", color = SlateGrey, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                rdap.nameServers.forEach { ns ->
                    Text("• $ns", color = OffWhite, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}

@Composable
private fun RdapRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = SlateGrey, fontSize = 12.sp)
        Text(value, color = OffWhite, fontSize = 12.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun WaybackSection(urls: List<WaybackUrlItem>, context: Context) {
    if (urls.isEmpty()) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 32.dp),
            contentAlignment = Alignment.Center
        ) {
            Text("No archived endpoints discovered on Wayback Machine.", color = MutedSlate, fontSize = 13.sp)
        }
        return
    }

    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "WAYBACK CDX ENDPOINTS (${urls.size} DISCOVERED)",
                color = SkyCyan,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold
            )

            IconButton(onClick = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("Wayback URLs", urls.joinToString("\n") { it.url })
                clipboard.setPrimaryClip(clip)
                Toast.makeText(context, "Copied ${urls.size} URLs to clipboard", Toast.LENGTH_SHORT).show()
            }) {
                Icon(Icons.Default.ContentCopy, contentDescription = "Copy all", tint = SkyCyan, modifier = Modifier.size(18.dp))
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        urls.forEach { item ->
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 3.dp)
                    .border(1.dp, CardBorder, RoundedCornerShape(6.dp)),
                colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                shape = RoundedCornerShape(6.dp)
            ) {
                Row(
                    modifier = Modifier.padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val statusColor = when {
                        item.statusCode.startsWith("2") -> MatrixGreen
                        item.statusCode.startsWith("3") -> SkyCyan
                        item.statusCode.startsWith("4") -> StatusWarning
                        else -> StatusRisk
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(statusColor.copy(alpha = 0.15f))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = item.statusCode,
                            color = statusColor,
                            fontWeight = FontWeight.Bold,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Spacer(modifier = Modifier.width(10.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = item.url,
                            color = OffWhite,
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 2
                        )
                        Text(
                            text = "Archived: ${item.timestamp}",
                            color = SlateGrey,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Spacer(modifier = Modifier.width(8.dp))

                    IconButton(
                        onClick = {
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(item.archiveUrl))
                            context.startActivity(intent)
                        },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            Icons.Default.OpenInBrowser,
                            contentDescription = "View Archive",
                            tint = SkyCyan,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }
        }
    }
}
