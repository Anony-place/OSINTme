package com.oopssecurity.osintme.ui.cases

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oopssecurity.osintme.data.local.case.CaseRepository
import com.oopssecurity.osintme.data.model.InvestigationCase
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.InkBlack
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun CaseManagementScreen(
    onSelectCase: (String) -> Unit,
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val repository = remember(context) { CaseRepository(context) }
    val cases by repository.casesFlow.collectAsStateWithLifecycle(emptyList())
    val scope = rememberCoroutineScope()

    var showCreateDialog by remember { mutableStateOf(false) }
    var newTitle by remember { mutableStateOf("") }
    var newTarget by remember { mutableStateOf("") }
    var newNotes by remember { mutableStateOf("") }

    if (showCreateDialog) {
        AlertDialog(
            onDismissRequest = { showCreateDialog = false },
            containerColor = CharcoalNavy,
            shape = RoundedCornerShape(14.dp),
            title = {
                Text(
                    text = "Open Investigation Dossier",
                    color = OffWhite,
                    fontSize = 17.sp,
                    fontWeight = FontWeight.SemiBold,
                    fontFamily = DisplayFontFamily
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "Correlate indicators (domains, emails, handles, EXIF hashes) in a local SQLite evidence dossier.",
                        color = SlateGrey,
                        fontSize = 12.sp,
                        lineHeight = 18.sp
                    )

                    OutlinedTextField(
                        value = newTitle,
                        onValueChange = { newTitle = it },
                        label = { Text("Case Name (e.g. Domain Audit)", color = MutedSlate, fontSize = 12.sp) },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = OffWhite,
                            unfocusedTextColor = OffWhite,
                            focusedBorderColor = SkyCyan,
                            unfocusedBorderColor = CardBorder,
                            focusedContainerColor = DarkerSurface,
                            unfocusedContainerColor = DarkerSurface
                        ),
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("case_title_input")
                    )

                    OutlinedTextField(
                        value = newTarget,
                        onValueChange = { newTarget = it },
                        label = { Text("Primary Target Indicator *", color = MutedSlate, fontSize = 12.sp) },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = OffWhite,
                            unfocusedTextColor = OffWhite,
                            focusedBorderColor = SkyCyan,
                            unfocusedBorderColor = CardBorder,
                            focusedContainerColor = DarkerSurface,
                            unfocusedContainerColor = DarkerSurface
                        ),
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("case_target_input")
                    )

                    OutlinedTextField(
                        value = newNotes,
                        onValueChange = { newNotes = it },
                        label = { Text("Initial Analyst Notes (Optional)", color = MutedSlate, fontSize = 12.sp) },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = OffWhite,
                            unfocusedTextColor = OffWhite,
                            focusedBorderColor = SkyCyan,
                            unfocusedBorderColor = CardBorder,
                            focusedContainerColor = DarkerSurface,
                            unfocusedContainerColor = DarkerSurface
                        ),
                        maxLines = 3,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (newTarget.isNotBlank()) {
                            scope.launch {
                                repository.createCase(newTitle, newTarget, newNotes)
                                newTitle = ""
                                newTarget = ""
                                newNotes = ""
                                showCreateDialog = false
                            }
                        }
                    },
                    enabled = newTarget.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.testTag("confirm_create_case_button")
                ) {
                    Text("Create Dossier", fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showCreateDialog = false }) {
                    Text("Cancel", color = SlateGrey)
                }
            }
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Cases & Dossiers",
                subtitle = "Local SQLite evidence correlation & reports",
                showBackButton = true,
                onBackClick = onBackClick
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showCreateDialog = true },
                containerColor = EmeraldPrimary,
                contentColor = PureWhite,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.testTag("create_case_fab")
            ) {
                Icon(Icons.Default.Add, contentDescription = "Create Investigation Case")
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            // Storage & count header bar
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = DarkerSurface),
                border = BorderStroke(1.dp, CardBorder),
                shape = RoundedCornerShape(10.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Storage,
                            contentDescription = null,
                            tint = MatrixGreen,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "LOCAL SQLITE • ZERO CLOUD",
                            color = MatrixGreen,
                            fontSize = 10.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 0.6.sp
                        )
                    }
                    Text(
                        text = "${cases.size} ACTIVE",
                        color = SkyCyan,
                        fontSize = 11.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            if (cases.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(bottom = 72.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.padding(horizontal = 24.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(60.dp)
                                .clip(RoundedCornerShape(16.dp))
                                .background(SurfaceElevated)
                                .border(1.dp, CardBorder, RoundedCornerShape(16.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.FolderOpen,
                                contentDescription = null,
                                tint = SkyCyan,
                                modifier = Modifier.size(30.dp)
                            )
                        }
                        Spacer(modifier = Modifier.height(14.dp))
                        Text(
                            text = "No Active Dossiers",
                            color = OffWhite,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold,
                            fontFamily = DisplayFontFamily
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "Create a case to collect evidence from Domain, Breach, Identity, Threat, Phone, or EXIF investigations.",
                            color = SlateGrey,
                            fontSize = 12.sp,
                            lineHeight = 18.sp
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = { showCreateDialog = true },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = EmeraldPrimary,
                                contentColor = PureWhite
                            ),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier
                                .height(48.dp)
                                .testTag("empty_create_case_button")
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Open First Dossier", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(bottom = 88.dp)
                ) {
                    items(cases, key = { it.id }) { item ->
                        CaseCard(caseItem = item, onClick = { onSelectCase(item.id) })
                    }
                }
            }
        }
    }
}

@Composable
private fun CaseCard(caseItem: InvestigationCase, onClick: () -> Unit) {
    val dateStr = remember(caseItem.updatedAt) {
        SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(caseItem.updatedAt))
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .border(1.dp, CardBorder, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .testTag("case_item_card_${caseItem.id}"),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .background(SkyCyan.copy(alpha = 0.14f), RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = caseItem.status,
                            color = SkyCyan,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = MonoFontFamily
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = caseItem.title,
                        color = OffWhite,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold,
                        fontFamily = DisplayFontFamily,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = caseItem.target,
                    color = MatrixGreen,
                    fontSize = 12.sp,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )

                if (caseItem.notes.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = caseItem.notes,
                        color = SlateGrey,
                        fontSize = 12.sp,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "UPDATED $dateStr",
                    color = MutedSlate,
                    fontSize = 10.sp,
                    fontFamily = MonoFontFamily
                )
            }

            Spacer(modifier = Modifier.width(10.dp))

            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                contentDescription = "Open Case Dossier",
                tint = SkyCyan,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}
