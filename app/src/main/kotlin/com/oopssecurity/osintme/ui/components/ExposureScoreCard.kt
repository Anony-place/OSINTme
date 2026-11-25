package com.oopssecurity.osintme.ui.components

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.local.ExposureScoreState
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated

@Composable
fun ExposureScoreCard(
    scoreState: ExposureScoreState,
    onViewChecklistClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val score = scoreState.score
    val scoreColor = when {
        score >= 80 -> StatusSafe
        score >= 50 -> StatusWarning
        else -> StatusRisk
    }

    Column(
        modifier = modifier
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
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = null,
                    tint = scoreColor,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "SECURITY POSTURE",
                    style = MaterialTheme.typography.labelSmall,
                    color = SlateGrey,
                    fontFamily = MonoFontFamily
                )
            }

            Row(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(SurfaceElevated)
                    .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                    .clickable {
                        val shareText = """
                            OSINTme Security Posture Summary
                            Score: $score/100 (${scoreState.ratingLabel})
                            Verified Practices: ${scoreState.completedChecksCount}/${scoreState.totalChecksCount}
                            Known Breach Deductions: -${scoreState.knownBreachesDeduction} pts
                        """.trimIndent()
                        val sendIntent = Intent().apply {
                            action = Intent.ACTION_SEND
                            putExtra(Intent.EXTRA_TEXT, shareText)
                            type = "text/plain"
                        }
                        context.startActivity(Intent.createChooser(sendIntent, "Share Security Posture"))
                    }
                    .padding(horizontal = 10.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Default.Share,
                    contentDescription = "Share security posture",
                    tint = SoftIndigo,
                    modifier = Modifier.size(13.dp)
                )
                Spacer(modifier = Modifier.width(5.dp))
                Text(
                    text = "Share",
                    fontSize = 11.sp,
                    color = SoftIndigo,
                    fontWeight = FontWeight.Medium
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier.size(68.dp),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator(
                    progress = { score / 100f },
                    modifier = Modifier.size(68.dp),
                    color = scoreColor,
                    trackColor = CardBorder,
                    strokeWidth = 6.dp
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "$score",
                        fontFamily = DisplayFontFamily,
                        fontWeight = FontWeight.Bold,
                        fontSize = 20.sp,
                        color = OffWhite
                    )
                    Text(
                        text = "/100",
                        fontSize = 10.sp,
                        color = SlateGrey,
                        fontFamily = MonoFontFamily
                    )
                }
            }

            Spacer(modifier = Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(scoreColor.copy(alpha = 0.14f))
                        .border(1.dp, scoreColor.copy(alpha = 0.35f), RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = scoreState.ratingLabel,
                        fontSize = 10.sp,
                        color = scoreColor,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = "${scoreState.completedChecksCount} of ${scoreState.totalChecksCount} hygiene controls verified.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = SlateGrey
                )

                if (scoreState.knownBreachesDeduction > 0) {
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "Breach exposure impact: -${scoreState.knownBreachesDeduction} pts",
                        fontSize = 11.sp,
                        color = StatusRisk,
                        fontFamily = MonoFontFamily
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 44.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(SurfaceElevated)
                .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                .clickable { onViewChecklistClick() }
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Open Security Hygiene Checklist",
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = SkyCyan
            )
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = SkyCyan,
                modifier = Modifier.size(18.dp)
            )
        }
    }
}
