package com.oopssecurity.osintme.data.local.case

import android.content.ContentValues
import android.content.Context
import com.oopssecurity.osintme.data.model.InvestigationCase
import com.oopssecurity.osintme.data.model.ScanArtifact
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

class CaseRepository(context: Context) {

    private val dbHelper = CaseDatabaseHelper(context)
    private val _casesFlow = MutableStateFlow<List<InvestigationCase>>(emptyList())
    val casesFlow: Flow<List<InvestigationCase>> = _casesFlow.asStateFlow()

    init {
        refreshCases()
    }

    fun refreshCases() {
        val list = mutableListOf<InvestigationCase>()
        val db = dbHelper.readableDatabase
        val cursor = db.query(
            CaseDatabaseHelper.TABLE_CASES,
            null,
            null,
            null,
            null,
            null,
            "updated_at DESC"
        )
        cursor.use { c ->
            while (c.moveToNext()) {
                val id = c.getString(c.getColumnIndexOrThrow("id"))
                val title = c.getString(c.getColumnIndexOrThrow("title"))
                val target = c.getString(c.getColumnIndexOrThrow("target"))
                val createdAt = c.getLong(c.getColumnIndexOrThrow("created_at"))
                val updatedAt = c.getLong(c.getColumnIndexOrThrow("updated_at"))
                val notes = c.getString(c.getColumnIndexOrThrow("notes")) ?: ""
                val tagsStr = c.getString(c.getColumnIndexOrThrow("tags")) ?: ""
                val status = c.getString(c.getColumnIndexOrThrow("status"))
                val tags = if (tagsStr.isNotEmpty()) tagsStr.split(",") else emptyList()

                list.add(
                    InvestigationCase(
                        id = id,
                        title = title,
                        target = target,
                        createdAt = createdAt,
                        updatedAt = updatedAt,
                        notes = notes,
                        tags = tags,
                        status = status
                    )
                )
            }
        }
        _casesFlow.value = list
    }

    suspend fun getAllCases(): List<InvestigationCase> = withContext(Dispatchers.IO) {
        refreshCases()
        _casesFlow.value
    }

    suspend fun createCase(title: String, target: String, notes: String = ""): InvestigationCase = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        val newCase = InvestigationCase(
            id = UUID.randomUUID().toString(),
            title = title.trim().ifEmpty { "Target Dossier: $target" },
            target = target.trim(),
            createdAt = now,
            updatedAt = now,
            notes = notes.trim(),
            tags = listOf("OSINT", "AUDIT"),
            status = "ACTIVE"
        )

        val db = dbHelper.writableDatabase
        val cv = ContentValues().apply {
            put("id", newCase.id)
            put("title", newCase.title)
            put("target", newCase.target)
            put("created_at", newCase.createdAt)
            put("updated_at", newCase.updatedAt)
            put("notes", newCase.notes)
            put("tags", newCase.tags.joinToString(","))
            put("status", newCase.status)
        }
        db.insert(CaseDatabaseHelper.TABLE_CASES, null, cv)
        refreshCases()
        newCase
    }

    suspend fun deleteCase(caseId: String) = withContext(Dispatchers.IO) {
        val db = dbHelper.writableDatabase
        db.delete(CaseDatabaseHelper.TABLE_CASES, "id = ?", arrayOf(caseId))
        refreshCases()
    }

    suspend fun updateCaseNotes(caseId: String, notes: String) = withContext(Dispatchers.IO) {
        val db = dbHelper.writableDatabase
        val cv = ContentValues().apply {
            put("notes", notes)
            put("updated_at", System.currentTimeMillis())
        }
        db.update(CaseDatabaseHelper.TABLE_CASES, cv, "id = ?", arrayOf(caseId))
        refreshCases()
    }

    suspend fun getArtifactsForCase(caseId: String): List<ScanArtifact> = withContext(Dispatchers.IO) {
        val list = mutableListOf<ScanArtifact>()
        val db = dbHelper.readableDatabase
        val cursor = db.query(
            CaseDatabaseHelper.TABLE_ARTIFACTS,
            null,
            "case_id = ?",
            arrayOf(caseId),
            null,
            null,
            "timestamp DESC"
        )
        cursor.use { c ->
            while (c.moveToNext()) {
                list.add(
                    ScanArtifact(
                        id = c.getString(c.getColumnIndexOrThrow("id")),
                        caseId = c.getString(c.getColumnIndexOrThrow("case_id")),
                        wingType = c.getString(c.getColumnIndexOrThrow("wing_type")),
                        artifactType = c.getString(c.getColumnIndexOrThrow("artifact_type")),
                        queryTarget = c.getString(c.getColumnIndexOrThrow("query_target")),
                        title = c.getString(c.getColumnIndexOrThrow("title")),
                        summary = c.getString(c.getColumnIndexOrThrow("summary")),
                        rawJson = c.getString(c.getColumnIndexOrThrow("raw_json")),
                        confidence = c.getString(c.getColumnIndexOrThrow("confidence")),
                        sourceApi = c.getString(c.getColumnIndexOrThrow("source_api")) ?: "",
                        timestamp = c.getLong(c.getColumnIndexOrThrow("timestamp"))
                    )
                )
            }
        }
        list
    }

    suspend fun attachArtifact(artifact: ScanArtifact) = withContext(Dispatchers.IO) {
        val db = dbHelper.writableDatabase
        val cv = ContentValues().apply {
            put("id", artifact.id)
            put("case_id", artifact.caseId)
            put("wing_type", artifact.wingType)
            put("artifact_type", artifact.artifactType)
            put("query_target", artifact.queryTarget)
            put("title", artifact.title)
            put("summary", artifact.summary)
            put("raw_json", artifact.rawJson)
            put("confidence", artifact.confidence)
            put("source_api", artifact.sourceApi)
            put("timestamp", artifact.timestamp)
        }
        db.insert(CaseDatabaseHelper.TABLE_ARTIFACTS, null, cv)

        // update parent case's updated_at timestamp
        val updateCv = ContentValues().apply {
            put("updated_at", System.currentTimeMillis())
        }
        db.update(CaseDatabaseHelper.TABLE_CASES, updateCv, "id = ?", arrayOf(artifact.caseId))
        refreshCases()
    }

    suspend fun generateCaseMarkdownReport(caseId: String): String = withContext(Dispatchers.IO) {
        val targetCase = _casesFlow.value.find { it.id == caseId } ?: return@withContext "# ERROR: Case not found"
        val artifacts = getArtifactsForCase(caseId)
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.getDefault())

        val sb = StringBuilder()
        sb.append("# OSINTme Investigation Dossier: ${targetCase.title}\n")
        sb.append("> **Confidential Threat Intelligence & Target Assessment Report**  \n")
        sb.append("> Generated: ${dateFormat.format(Date())}  \n\n")

        sb.append("## Target Metadata\n")
        sb.append("- **Primary Target:** `${targetCase.target}`\n")
        sb.append("- **Case ID:** `${targetCase.id}`\n")
        sb.append("- **Opened Date:** ${dateFormat.format(Date(targetCase.createdAt))}\n")
        sb.append("- **Status:** `${targetCase.status}`\n")
        if (targetCase.notes.isNotEmpty()) {
            sb.append("\n### Analyst Assessment & Field Notes\n")
            sb.append("${targetCase.notes}\n\n")
        }

        sb.append("## Corroborated Evidence & Artifacts (${artifacts.size})\n\n")
        if (artifacts.isEmpty()) {
            sb.append("_No evidentiary artifacts attached to this case yet._\n")
        } else {
            artifacts.groupBy { it.wingType }.forEach { (wing, items) ->
                sb.append("### WING: $wing\n")
                items.forEach { art ->
                    val artTime = dateFormat.format(Date(art.timestamp))
                    sb.append("#### ${art.title} (`${art.artifactType}`)\n")
                    sb.append("- **Target Indicator:** `${art.queryTarget}`\n")
                    sb.append("- **Source API / Intelligence Feed:** `${art.sourceApi}`\n")
                    sb.append("- **Confidence Level:** `${art.confidence}`\n")
                    sb.append("- **Logged At:** $artTime\n")
                    sb.append("- **Findings Summary:** ${art.summary}\n\n")

                    if (art.rawJson.isNotEmpty() && art.rawJson != "{}") {
                        sb.append("<details>\n<summary>Raw Technical Evidence (JSON)</summary>\n\n```json\n")
                        sb.append(art.rawJson)
                        sb.append("\n```\n</details>\n\n")
                    }
                }
            }
        }

        sb.append("\n---\n")
        sb.append("_Report compiled on-device by OSINTme Tactical Station // Zero-Cloud Architecture._\n")
        sb.toString()
    }
}
