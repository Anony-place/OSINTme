package com.oopssecurity.osintme.ui.cases

import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.automirrored.filled.NoteAdd
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.ViewList
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.data.local.case.CaseRepository
import com.oopssecurity.osintme.data.model.ScanArtifact
import com.oopssecurity.osintme.data.network.ByokAiService
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.CodeBlock
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.EmeraldBorder
import com.oopssecurity.osintme.ui.theme.EmeraldDeep
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.EmeraldSoft
import com.oopssecurity.osintme.ui.theme.InkBlack
import com.oopssecurity.osintme.ui.theme.MatrixGreen
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.SafeBrowserLauncher
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

@Composable
fun CaseDetailScreen(
    caseId: String,
    onBackClick: () -> Unit,
    onPivot: (PivotEntity) -> Unit = {},
    onOpenApiVault: () -> Unit = {},
    onOpenAiAnalyst: (String) -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val repository = remember(context) { CaseRepository(context) }
    val cases by repository.casesFlow.collectAsStateWithLifecycle(emptyList())
    val targetCase = cases.find { it.id == caseId }
    val scope = rememberCoroutineScope()
    val activeAi by ApiKeyVault.activeAiProvider.collectAsStateWithLifecycle()

    var artifacts by remember { mutableStateOf<List<ScanArtifact>>(emptyList()) }
    var showNoteDialog by remember { mutableStateOf(false) }
    var noteText by remember { mutableStateOf("") }
    var showEditCaseNotesDialog by remember { mutableStateOf(false) }
    var editableCaseNotes by remember(targetCase?.notes) { mutableStateOf(targetCase?.notes ?: "") }
    var showDeleteDialog by remember { mutableStateOf(false) }
    var showExportMenu by remember { mutableStateOf(false) }
    var viewMode by remember { mutableIntStateOf(0) } // 0 = Timeline, 1 = Entity Graph

    var aiExecutiveBrief by remember { mutableStateOf<String?>(null) }
    var aiBriefMeta by remember { mutableStateOf<String?>(null) }
    var aiBriefError by remember { mutableStateOf<String?>(null) }
    var isGeneratingBrief by remember { mutableStateOf(false) }

    val saveHtmlLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/html")
    ) { uri ->
        if (uri != null && targetCase != null) {
            runCatching {
                val html = com.oopssecurity.osintme.util.CaseReportExporter.exportHtml(
                    targetCase = targetCase,
                    artifacts = artifacts,
                    aiExecutiveSummary = aiExecutiveBrief
                )
                context.contentResolver.openOutputStream(uri)?.use { it.write(html.toByteArray(Charsets.UTF_8)) }
                Toast.makeText(context, "HTML Dossier saved", Toast.LENGTH_SHORT).show()
            }.onFailure { Toast.makeText(context, "Export failed: ${it.message}", Toast.LENGTH_SHORT).show() }
        }
    }

    val saveJsonLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        if (uri != null && targetCase != null) {
            runCatching {
                val json = com.oopssecurity.osintme.util.CaseReportExporter.exportJson(targetCase, artifacts)
                context.contentResolver.openOutputStream(uri)?.use { it.write(json.toByteArray(Charsets.UTF_8)) }
                Toast.makeText(context, "JSON Dossier saved", Toast.LENGTH_SHORT).show()
            }.onFailure { Toast.makeText(context, "Export failed: ${it.message}", Toast.LENGTH_SHORT).show() }
        }
    }

    val saveCsvLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/csv")
    ) { uri ->
        if (uri != null && targetCase != null) {
            runCatching {
                val csv = com.oopssecurity.osintme.util.CaseReportExporter.exportCsv(targetCase, artifacts)
                context.contentResolver.openOutputStream(uri)?.use { it.write(csv.toByteArray(Charsets.UTF_8)) }
                Toast.makeText(context, "CSV IOC table saved", Toast.LENGTH_SHORT).show()
            }.onFailure { Toast.makeText(context, "Export failed: ${it.message}", Toast.LENGTH_SHORT).show() }
        }
    }

    val entityGraph = remember(targetCase, artifacts) {
        targetCase?.let { com.oopssecurity.osintme.util.CaseReportExporter.buildEntityGraph(it, artifacts) }
    }

    LaunchedEffect(caseId) {
        artifacts = repository.getArtifactsForCase(caseId)
    }

    if (showNoteDialog) {
        AlertDialog(
            onDismissRequest = { showNoteDialog = false },
            containerColor = CharcoalNavy,
            shape = RoundedCornerShape(14.dp),
            title = {
                Text(
                    text = "Attach Analyst Field Note",
                    color = OffWhite,
                    fontSize = 16.sp,
                    fontFamily = DisplayFontFamily,
                    fontWeight = FontWeight.SemiBold
                )
            },
            text = {
                OutlinedTextField(
                    value = noteText,
                    onValueChange = { noteText = it },
                    placeholder = { Text("Enter observation, pivot lead, or hypothesis...", color = MutedSlate, fontSize = 12.sp) },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = OffWhite,
                        unfocusedTextColor = OffWhite,
                        focusedBorderColor = SkyCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedContainerColor = DarkerSurface,
                        unfocusedContainerColor = DarkerSurface
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("field_note_input"),
                    minLines = 3,
                    maxLines = 5
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (noteText.isNotBlank()) {
                            scope.launch {
                                val newArtifact = ScanArtifact(
                                    id = UUID.randomUUID().toString(),
                                    caseId = caseId,
                                    wingType = "ANALYST_NOTE",
                                    artifactType = "FIELD_NOTE",
                                    queryTarget = targetCase?.target ?: "",
                                    title = "Analyst Assessment Note",
                                    summary = noteText.trim(),
                                    rawJson = "{}",
                                    confidence = "HIGH",
                                    sourceApi = "Local Analyst",
                                    timestamp = System.currentTimeMillis()
                                )
                                repository.attachArtifact(newArtifact)
                                artifacts = repository.getArtifactsForCase(caseId)
                                noteText = ""
                                showNoteDialog = false
                            }
                        }
                    },
                    enabled = noteText.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.testTag("confirm_attach_note_button")
                ) {
                    Text("Attach Note", fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showNoteDialog = false }) {
                    Text("Cancel", color = SlateGrey)
                }
            }
        )
    }

    if (showEditCaseNotesDialog) {
        AlertDialog(
            onDismissRequest = { showEditCaseNotesDialog = false },
            containerColor = CharcoalNavy,
            shape = RoundedCornerShape(14.dp),
            title = {
                Text(
                    text = "Edit Dossier Summary Notes",
                    color = OffWhite,
                    fontSize = 16.sp,
                    fontFamily = DisplayFontFamily,
                    fontWeight = FontWeight.SemiBold
                )
            },
            text = {
                OutlinedTextField(
                    value = editableCaseNotes,
                    onValueChange = { editableCaseNotes = it },
                    placeholder = { Text("Scope, authorization reference, or key findings...", color = MutedSlate, fontSize = 12.sp) },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = OffWhite,
                        unfocusedTextColor = OffWhite,
                        focusedBorderColor = SkyCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedContainerColor = DarkerSurface,
                        unfocusedContainerColor = DarkerSurface
                    ),
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3,
                    maxLines = 6
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        scope.launch {
                            repository.updateCaseNotes(caseId, editableCaseNotes.trim())
                            showEditCaseNotesDialog = false
                            Toast.makeText(context, "Dossier notes updated", Toast.LENGTH_SHORT).show()
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
                    Text("Save Notes", fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showEditCaseNotesDialog = false }) {
                    Text("Cancel", color = SlateGrey)
                }
            }
        )
    }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            containerColor = CharcoalNavy,
            shape = RoundedCornerShape(14.dp),
            title = {
                Text("Delete Case Dossier?", color = StatusRisk, fontWeight = FontWeight.Bold, fontFamily = DisplayFontFamily)
            },
            text = {
                Text(
                    "This permanently removes this dossier and all attached evidence artifacts from local SQLite storage.",
                    color = SlateGrey,
                    fontSize = 13.sp,
                    lineHeight = 19.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        scope.launch {
                            repository.deleteCase(caseId)
                            showDeleteDialog = false
                            onBackClick()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = StatusRisk,
                        contentColor = PureWhite
                    ),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.testTag("confirm_delete_case_button")
                ) {
                    Text("Delete Permanently", color = PureWhite, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
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
                title = targetCase?.title ?: "Investigation Dossier",
                subtitle = targetCase?.target?.let { "Target: $it" } ?: "Local Evidence Dossier",
                showBackButton = true,
                onBackClick = onBackClick
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            // Case Overview Card
            if (targetCase != null) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = DarkerSurface),
                    border = BorderStroke(1.dp, CardBorder),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "PRIMARY INDICATOR",
                                    color = MutedSlate,
                                    fontSize = 10.sp,
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = targetCase.target,
                                    color = MatrixGreen,
                                    fontSize = 13.sp,
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            IconButton(
                                onClick = {
                                    onPivot(
                                        PivotEngine.normalize(
                                            raw = targetCase.target,
                                            sourceContext = "Case Dossier: ${targetCase.title}"
                                        )
                                    )
                                },
                                modifier = Modifier
                                    .size(48.dp)
                                    .testTag("case_pivot_target_button")
                            ) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.CallSplit,
                                    contentDescription = "Pivot Primary Target",
                                    tint = SkyCyan,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                            IconButton(
                                onClick = { showEditCaseNotesDialog = true },
                                modifier = Modifier
                                    .size(48.dp)
                                    .testTag("edit_case_notes_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Edit,
                                    contentDescription = "Edit Case Notes",
                                    tint = SkyCyan,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }

                        if (targetCase.notes.isNotBlank()) {
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = targetCase.notes,
                                color = SlateGrey,
                                fontSize = 12.sp,
                                lineHeight = 18.sp
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            // Action Bar
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(modifier = Modifier.weight(1f)) {
                    Button(
                        onClick = { showExportMenu = true },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = EmeraldPrimary,
                            contentColor = PureWhite,
                            disabledContainerColor = SurfaceElevated,
                            disabledContentColor = MutedSlate
                        ),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp)
                            .testTag("export_case_report_button")
                    ) {
                        Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Export Dossier", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }

                    DropdownMenu(
                        expanded = showExportMenu,
                        onDismissRequest = { showExportMenu = false },
                        containerColor = CharcoalNavy
                    ) {
                        val slug = (targetCase?.target ?: "case").replace(Regex("[^a-zA-Z0-9._-]"), "_").take(28)
                        DropdownMenuItem(
                            text = { Text("Save HTML Report (.html)", color = OffWhite, fontSize = 13.sp) },
                            onClick = {
                                showExportMenu = false
                                saveHtmlLauncher.launch("osintme_$slug.html")
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Save Structured JSON (.json)", color = OffWhite, fontSize = 13.sp) },
                            onClick = {
                                showExportMenu = false
                                saveJsonLauncher.launch("osintme_$slug.json")
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Save CSV IOC Table (.csv)", color = OffWhite, fontSize = 13.sp) },
                            onClick = {
                                showExportMenu = false
                                saveCsvLauncher.launch("osintme_${slug}_iocs.csv")
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Share / Copy Markdown", color = SkyCyan, fontSize = 13.sp) },
                            onClick = {
                                showExportMenu = false
                                scope.launch {
                                    val md = repository.generateCaseMarkdownReport(caseId)
                                    SafeBrowserLauncher.copyToClipboard(context, "Investigation Report", md, isSensitive = true)
                                    Toast.makeText(context, "Markdown report copied", Toast.LENGTH_SHORT).show()
                                    val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                        type = "text/plain"
                                        putExtra(Intent.EXTRA_SUBJECT, "OSINTme Report: ${targetCase?.title}")
                                        putExtra(Intent.EXTRA_TEXT, md)
                                    }
                                    context.startActivity(Intent.createChooser(shareIntent, "Share Investigation Report"))
                                }
                            }
                        )
                    }
                }

                OutlinedButton(
                    onClick = { showNoteDialog = true },
                    border = BorderStroke(1.dp, SoftIndigo.copy(alpha = 0.6f)),
                    colors = ButtonDefaults.outlinedButtonColors(
                        containerColor = SurfaceElevated,
                        contentColor = OffWhite
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .height(48.dp)
                        .testTag("add_field_note_button")
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.NoteAdd,
                        contentDescription = null,
                        tint = SoftIndigo,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Note", color = OffWhite, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                }

                IconButton(
                    onClick = { showDeleteDialog = true },
                    modifier = Modifier
                        .size(48.dp)
                        .testTag("delete_case_button")
                ) {
                    Icon(Icons.Default.Delete, contentDescription = "Delete Case", tint = StatusRisk)
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // BYOK AI Executive Brief & Analyst Chat Bar
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(EmeraldSoft)
                    .border(1.dp, EmeraldBorder, RoundedCornerShape(12.dp))
                    .padding(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = EmeraldPrimary, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "AI EXECUTIVE BRIEF (FOR EXPORTS)",
                            color = EmeraldDeep,
                            fontSize = 10.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Text(
                        text = activeAi?.shortBadge ?: "NO KEY",
                        color = if (activeAi != null) EmeraldPrimary else MutedSlate,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }

                if (!aiExecutiveBrief.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(6.dp))
                    if (!aiBriefMeta.isNullOrBlank()) {
                        Text(aiBriefMeta!!, color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
                        Spacer(modifier = Modifier.height(4.dp))
                    }
                    Text(
                        text = aiExecutiveBrief!!,
                        color = InkBlack,
                        fontSize = 12.sp,
                        lineHeight = 18.sp,
                        maxLines = 8,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                if (!aiBriefError.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(aiBriefError!!, color = StatusRisk, fontSize = 11.sp)
                }

                Spacer(modifier = Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            if (ApiKeyVault.getActiveAiConfig() == null) {
                                aiBriefError = "Connect your own AI key in AI Vault first."
                                return@Button
                            }
                            if (targetCase == null) return@Button
                            isGeneratingBrief = true
                            aiBriefError = null
                            scope.launch {
                                val digest = buildString {
                                    if (targetCase.notes.isNotBlank()) appendLine("Notes: ${targetCase.notes}")
                                    artifacts.take(20).forEachIndexed { idx, art ->
                                        appendLine("${idx + 1}. [${art.wingType}] ${art.title} (${art.queryTarget}): ${art.summary}")
                                    }
                                }
                                ByokAiService.generateCaseExecutiveBrief(
                                    caseTitle = targetCase.title,
                                    caseTarget = targetCase.target,
                                    artifactsDigest = digest
                                ).fold(
                                    onSuccess = { res ->
                                        aiExecutiveBrief = res.text
                                        aiBriefMeta = "${res.providerName} • ${res.modelId} • included in HTML export"
                                        val briefArtifact = ScanArtifact(
                                            id = UUID.randomUUID().toString(),
                                            caseId = caseId,
                                            wingType = "BYOK_AI",
                                            artifactType = "AI_EXECUTIVE_BRIEF",
                                            queryTarget = targetCase.target,
                                            title = "AI Executive Brief (${res.providerName})",
                                            summary = res.text.take(2200),
                                            rawJson = "{}",
                                            confidence = "HIGH",
                                            sourceApi = "${res.providerName} (${res.modelId})",
                                            timestamp = System.currentTimeMillis()
                                        )
                                        repository.attachArtifact(briefArtifact)
                                        artifacts = repository.getArtifactsForCase(caseId)
                                    },
                                    onFailure = { aiBriefError = it.message ?: "Failed to generate brief" }
                                )
                                isGeneratingBrief = false
                            }
                        },
                        enabled = !isGeneratingBrief,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = EmeraldPrimary,
                            contentColor = PureWhite,
                            disabledContainerColor = SurfaceElevated,
                            disabledContentColor = MutedSlate
                        ),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("case_generate_ai_brief_button")
                    ) {
                        if (isGeneratingBrief) {
                            CircularProgressIndicator(color = PureWhite, modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Drafting...", fontSize = 11.sp)
                        } else {
                            Icon(Icons.Default.AutoAwesome, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(5.dp))
                            Text(if (aiExecutiveBrief == null) "Generate AI Brief" else "Refresh Brief", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }

                    OutlinedButton(
                        onClick = {
                            if (activeAi == null) onOpenApiVault() else onOpenAiAnalyst(caseId)
                        },
                        border = BorderStroke(1.dp, EmeraldPrimary),
                        colors = ButtonDefaults.outlinedButtonColors(containerColor = PureWhite, contentColor = EmeraldDeep),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(if (activeAi == null) Icons.Default.Key else Icons.Default.AutoAwesome, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(if (activeAi == null) "AI Vault" else "Ask AI", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Timeline vs Entity Graph Segmented Toggle
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(DarkerSurface)
                    .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                    .padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(7.dp))
                        .background(if (viewMode == 0) SkyCyan.copy(alpha = 0.16f) else DarkerSurface)
                        .clickable { viewMode = 0 }
                        .testTag("case_view_timeline_tab")
                        .padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.ViewList, contentDescription = null, tint = if (viewMode == 0) SkyCyan else MutedSlate, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Evidence (${artifacts.size})",
                        color = if (viewMode == 0) SkyCyan else SlateGrey,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }

                Row(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(7.dp))
                        .background(if (viewMode == 1) MatrixGreen.copy(alpha = 0.16f) else DarkerSurface)
                        .clickable { viewMode = 1 }
                        .testTag("case_view_graph_tab")
                        .padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Hub, contentDescription = null, tint = if (viewMode == 1) MatrixGreen else MutedSlate, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Entity Graph (${entityGraph?.nodes?.size ?: 0})",
                        color = if (viewMode == 1) MatrixGreen else SlateGrey,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            if (viewMode == 1 && entityGraph != null) {
                CaseGraphView(
                    graph = entityGraph,
                    onPivot = onPivot,
                    modifier = Modifier.fillMaxSize()
                )
            } else if (artifacts.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(bottom = 48.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.padding(horizontal = 24.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Description,
                            contentDescription = null,
                            tint = MutedSlate,
                            modifier = Modifier.size(40.dp)
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = "No Evidence Artifacts Yet",
                            color = OffWhite,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            fontFamily = DisplayFontFamily
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Run a One-Shot Target Dossier or any recon module and tap 'Save to Case'.",
                            color = SlateGrey,
                            fontSize = 12.sp,
                            lineHeight = 18.sp
                        )
                    }
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(bottom = 28.dp)
                ) {
                    items(artifacts, key = { it.id }) { artifact ->
                        ArtifactCard(artifact = artifact, onPivot = onPivot)
                    }
                }
            }
        }
    }
}

@Composable
private fun ArtifactCard(
    artifact: ScanArtifact,
    onPivot: (PivotEntity) -> Unit
) {
    val context = LocalContext.current
    val dateStr = remember(artifact.timestamp) {
        SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(artifact.timestamp))
    }
    var showRawJson by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, CardBorder, RoundedCornerShape(12.dp)),
        colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .background(SkyCyan.copy(alpha = 0.14f), RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = artifact.wingType,
                            color = SkyCyan,
                            fontSize = 9.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = artifact.title,
                        color = OffWhite,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                Box(
                    modifier = Modifier
                        .background(MatrixGreen.copy(alpha = 0.14f), RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = artifact.confidence,
                        color = MatrixGreen,
                        fontSize = 9.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = artifact.summary,
                color = OffWhite,
                fontSize = 12.sp,
                lineHeight = 18.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${artifact.sourceApi} • $dateStr",
                    color = MutedSlate,
                    fontSize = 10.sp,
                    fontFamily = MonoFontFamily,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )

                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (artifact.queryTarget.isNotBlank()) {
                        IconButton(
                            onClick = {
                                onPivot(
                                    PivotEngine.normalize(
                                        raw = artifact.queryTarget,
                                        sourceContext = "Case Artifact: ${artifact.title}"
                                    )
                                )
                            },
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.CallSplit,
                                contentDescription = "Pivot Artifact Target",
                                tint = SkyCyan,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }

                    IconButton(
                        onClick = {
                            SafeBrowserLauncher.copyToClipboard(
                                context,
                                artifact.title,
                                "${artifact.title}\n${artifact.summary}",
                                isSensitive = true
                            )
                            Toast.makeText(context, "Artifact copied", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.ContentCopy,
                            contentDescription = "Copy Artifact Summary",
                            tint = SlateGrey,
                            modifier = Modifier.size(15.dp)
                        )
                    }

                    if (artifact.rawJson.isNotEmpty() && artifact.rawJson != "{}") {
                        Text(
                            text = if (showRawJson) "HIDE RAW" else "VIEW RAW",
                            color = SoftIndigo,
                            fontSize = 10.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier
                                .clickable { showRawJson = !showRawJson }
                                .padding(horizontal = 6.dp, vertical = 8.dp)
                        )
                    }
                }
            }

            if (showRawJson && artifact.rawJson.isNotEmpty() && artifact.rawJson != "{}") {
                Spacer(modifier = Modifier.height(8.dp))
                CodeBlock(code = artifact.rawJson)
            }
        }
    }
}
