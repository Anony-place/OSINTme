package com.oopssecurity.osintme.ui.components

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.FolderSpecial
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.data.local.case.CaseRepository
import com.oopssecurity.osintme.data.model.InvestigationCase
import com.oopssecurity.osintme.data.model.ScanArtifact
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
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import kotlinx.coroutines.launch
import java.util.UUID

@Composable
fun SaveToCaseDialog(
    wingType: String,
    artifactType: String,
    queryTarget: String,
    title: String,
    summary: String,
    rawJson: String = "{}",
    confidence: String = "HIGH",
    sourceApi: String,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val repo = remember(context) { CaseRepository(context) }
    val scope = rememberCoroutineScope()

    var cases by remember { mutableStateOf<List<InvestigationCase>>(emptyList()) }
    var newCaseTitle by remember { mutableStateOf("Investigation: $queryTarget") }
    var isSaving by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        cases = repo.getAllCases()
    }

    fun attachTo(caseItem: InvestigationCase) {
        if (isSaving) return
        isSaving = true
        scope.launch {
            repo.attachArtifact(
                ScanArtifact(
                    id = UUID.randomUUID().toString(),
                    caseId = caseItem.id,
                    wingType = wingType,
                    artifactType = artifactType,
                    queryTarget = queryTarget,
                    title = title,
                    summary = summary,
                    rawJson = rawJson,
                    confidence = confidence,
                    sourceApi = sourceApi
                )
            )
            Toast.makeText(context, "Evidence attached to \"${caseItem.title}\"", Toast.LENGTH_SHORT).show()
            onDismiss()
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = CharcoalNavy,
        titleContentColor = OffWhite,
        textContentColor = SlateGrey,
        title = {
            Text(
                text = "Save Evidence to Case Dossier",
                style = MaterialTheme.typography.titleMedium,
                color = OffWhite
            )
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodySmall,
                    color = SlateGrey,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )

                Spacer(modifier = Modifier.height(12.dp))

                if (cases.isNotEmpty()) {
                    Text(
                        text = "EXISTING CASES (${cases.size})",
                        style = MaterialTheme.typography.labelSmall,
                        color = SkyCyan,
                        fontFamily = MonoFontFamily
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 180.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        items(cases, key = { it.id }) { item ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(SurfaceElevated)
                                    .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                                    .clickable(enabled = !isSaving) { attachTo(item) }
                                    .padding(horizontal = 12.dp, vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.FolderSpecial,
                                    contentDescription = null,
                                    tint = SkyCyan,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = item.title,
                                        color = OffWhite,
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = item.target,
                                        color = MutedSlate,
                                        fontSize = 11.sp,
                                        fontFamily = MonoFontFamily,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    HorizontalDivider(color = CardBorder)
                    Spacer(modifier = Modifier.height(12.dp))
                }

                Text(
                    text = "OR CREATE NEW CASE",
                    style = MaterialTheme.typography.labelSmall,
                    color = MatrixGreen,
                    fontFamily = MonoFontFamily
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = newCaseTitle,
                    onValueChange = { newCaseTitle = it },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    placeholder = { Text("Case dossier title", color = MutedSlate) },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = SkyCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedContainerColor = DarkerSurface,
                        unfocusedContainerColor = DarkerSurface,
                        focusedTextColor = OffWhite,
                        unfocusedTextColor = OffWhite
                    ),
                    shape = RoundedCornerShape(8.dp)
                )
            }
        },
        confirmButton = {
            Button(
                enabled = !isSaving && newCaseTitle.isNotBlank(),
                onClick = {
                    isSaving = true
                    scope.launch {
                        val created = repo.createCase(
                            title = newCaseTitle.trim(),
                            target = queryTarget,
                            notes = "Created automatically from $wingType inspection."
                        )
                        repo.attachArtifact(
                            ScanArtifact(
                                id = UUID.randomUUID().toString(),
                                caseId = created.id,
                                wingType = wingType,
                                artifactType = artifactType,
                                queryTarget = queryTarget,
                                title = title,
                                summary = summary,
                                rawJson = rawJson,
                                confidence = confidence,
                                sourceApi = sourceApi
                            )
                        )
                        Toast.makeText(context, "Created case & saved evidence", Toast.LENGTH_SHORT).show()
                        onDismiss()
                    }
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = EmeraldPrimary,
                    contentColor = PureWhite,
                    disabledContainerColor = SurfaceElevated,
                    disabledContentColor = MutedSlate
                ),
                shape = RoundedCornerShape(8.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Add,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text("New Case & Save", fontWeight = FontWeight.SemiBold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel", color = SlateGrey)
            }
        }
    )
}
