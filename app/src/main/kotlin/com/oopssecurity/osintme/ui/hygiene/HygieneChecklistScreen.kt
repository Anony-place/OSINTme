package com.oopssecurity.osintme.ui.hygiene

import android.content.Intent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oopssecurity.osintme.data.local.HygienePreferencesManager
import com.oopssecurity.osintme.data.model.HygieneCheckItem
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.ExposureScoreCard
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.StatusSafe

@Composable
fun HygieneChecklistScreen(
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val manager = remember(context) { HygienePreferencesManager(context) }
    val scoreState by manager.scoreFlow.collectAsStateWithLifecycle()

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Security & Privacy Hygiene",
                subtitle = "Digital exposure score & defensive checklist",
                showBackButton = true,
                onBackClick = onBackClick
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp)
        ) {
            item {
                ExposureScoreCard(
                    scoreState = scoreState,
                    onViewChecklistClick = { /* Already on checklist */ }
                )
            }

            item {
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = {
                        val text = """
                            OSINTme Digital Footprint Audit
                            Exposure Score: ${scoreState.score}/100 (${scoreState.ratingLabel})
                            Defense Controls: ${scoreState.completedChecksCount}/${scoreState.totalChecksCount} practices enabled
                        """.trimIndent()

                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, text)
                        }
                        context.startActivity(Intent.createChooser(shareIntent, "Share Privacy Audit Summary"))
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                        .testTag("share_hygiene_audit_button"),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CharcoalNavy,
                        contentColor = SkyCyan
                    ),
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, CardBorder)
                ) {
                    Icon(Icons.Default.Share, contentDescription = null, tint = SkyCyan, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Share Privacy Audit Summary", color = SkyCyan, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }
            }

            item {
                Spacer(modifier = Modifier.height(20.dp))
                Text(
                    text = "CORE DEFENSE CONTROLS (${scoreState.completedChecksCount}/${scoreState.totalChecksCount})",
                    color = SkyCyan,
                    fontSize = 11.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.8.sp
                )
                Spacer(modifier = Modifier.height(10.dp))
            }

            items(scoreState.checklist, key = { it.id }) { item ->
                HygieneItemRow(
                    item = item,
                    onToggle = { manager.toggleCheckItem(item.id) }
                )
                Spacer(modifier = Modifier.height(8.dp))
            }

            item {
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }
}

@Composable
private fun HygieneItemRow(
    item: HygieneCheckItem,
    onToggle: () -> Unit
) {
    val borderColor = if (item.isChecked) StatusSafe.copy(alpha = 0.45f) else CardBorder

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .border(1.dp, borderColor, RoundedCornerShape(10.dp))
            .clickable { onToggle() }
            .testTag("hygiene_item_${item.id}"),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        shape = RoundedCornerShape(10.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(
                checked = item.isChecked,
                onCheckedChange = { onToggle() },
                colors = CheckboxDefaults.colors(
                    checkedColor = SkyCyan,
                    checkmarkColor = SlateObsidian,
                    uncheckedColor = MutedSlate
                )
            )

            Spacer(modifier = Modifier.width(8.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.title,
                    color = if (item.isChecked) OffWhite else SlateGrey,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 13.sp
                )
                Spacer(modifier = Modifier.height(3.dp))
                Text(
                    text = item.description,
                    color = MutedSlate,
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )
            }

            Spacer(modifier = Modifier.width(10.dp))

            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(if (item.isChecked) StatusSafe.copy(alpha = 0.14f) else DarkerSurface)
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = "+${item.weight} pts",
                    color = if (item.isChecked) StatusSafe else SlateGrey,
                    fontSize = 10.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
