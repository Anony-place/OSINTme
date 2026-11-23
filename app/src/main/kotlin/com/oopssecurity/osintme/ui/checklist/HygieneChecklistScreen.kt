package com.oopssecurity.osintme.ui.checklist

import android.content.Context
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.data.local.ExposureScoreState
import com.oopssecurity.osintme.data.local.HygienePreferencesManager
import com.oopssecurity.osintme.data.model.HygieneCheckItem
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.ExposureScoreCard
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import kotlinx.coroutines.flow.StateFlow

class ChecklistViewModel(context: Context) : ViewModel() {
    private val hygieneManager = HygienePreferencesManager(context)
    val scoreState: StateFlow<ExposureScoreState> = hygieneManager.scoreFlow

    fun toggleItem(id: String) {
        hygieneManager.toggleCheckItem(id)
    }
}

@Composable
fun HygieneChecklistScreen(
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: ChecklistViewModel = viewModel { ChecklistViewModel(context) }
    val scoreState by viewModel.scoreState.collectAsStateWithLifecycle()

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        topBar = {
            AppHeader(
                title = "Security Hygiene Checklist",
                subtitle = "Interactive self-audit & posture scoring",
                showBackButton = true,
                onBackClick = onBackClick
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            item {
                ExposureScoreCard(
                    scoreState = scoreState,
                    onViewChecklistClick = { /* Already on checklist */ }
                )
            }

            item {
                Text(
                    text = "DEFENSIVE POSTURE BEST PRACTICES",
                    fontSize = 11.sp,
                    color = SlateGrey,
                    style = MaterialTheme.typography.labelSmall
                )
            }

            items(scoreState.checklist) { item ->
                HygieneRow(
                    item = item,
                    onToggle = { viewModel.toggleItem(item.id) }
                )
            }
        }
    }
}

@Composable
fun HygieneRow(
    item: HygieneCheckItem,
    onToggle: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(CharcoalNavy)
            .border(
                1.dp,
                if (item.isChecked) StatusSafe.copy(alpha = 0.4f) else CardBorder,
                RoundedCornerShape(8.dp)
            )
            .clickable { onToggle() }
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(
            checked = item.isChecked,
            onCheckedChange = { onToggle() },
            colors = CheckboxDefaults.colors(
                checkedColor = SkyCyan,
                uncheckedColor = SlateGrey,
                checkmarkColor = SlateObsidian
            )
        )
        Spacer(modifier = Modifier.width(8.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = item.title,
                    style = MaterialTheme.typography.titleMedium,
                    fontSize = 13.sp,
                    color = if (item.isChecked) OffWhite else SlateGrey
                )
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(SurfaceElevated)
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = "+${item.weight} pts",
                        fontSize = 10.sp,
                        color = SkyCyan,
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = item.description,
                style = MaterialTheme.typography.bodyMedium,
                fontSize = 11.sp,
                color = MutedSlate
            )
        }
    }
}
