package com.oopssecurity.osintme.util

import com.oopssecurity.osintme.data.model.InvestigationCase
import com.oopssecurity.osintme.data.model.ScanArtifact
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class CaseGraphNode(
    val id: String,
    val label: String,
    val entityType: String, // CASE_ROOT, DOMAIN, IP, EMAIL, USERNAME, URL, HASH, PHONE, MODULE
    val detail: String,
    val pivotValue: String?,
    val isRoot: Boolean = false
)

data class CaseGraphEdge(
    val fromId: String,
    val toId: String,
    val label: String
)

data class CaseEntityGraph(
    val nodes: List<CaseGraphNode>,
    val edges: List<CaseGraphEdge>
)

/**
 * Generates self-contained dark-mode HTML reports (with strict HTML escaping),
 * structured JSON bundles, CSV IOC tables (formula-injection protected),
 * and entity relationship graphs from saved Investigation Cases & Artifacts.
 */
object CaseReportExporter {

    fun buildEntityGraph(
        targetCase: InvestigationCase,
        artifacts: List<ScanArtifact>
    ): CaseEntityGraph {
        val nodes = LinkedHashMap<String, CaseGraphNode>()
        val edges = LinkedHashSet<CaseGraphEdge>()
        val entityNodeIdByValue = LinkedHashMap<String, String>()

        val rootId = "root::${targetCase.id}"
        nodes[rootId] = CaseGraphNode(
            id = rootId,
            label = targetCase.target.ifBlank { targetCase.title },
            entityType = "CASE_ROOT",
            detail = "${targetCase.title} • ${artifacts.size} artifact(s)",
            pivotValue = targetCase.target.takeIf { it.isNotBlank() },
            isRoot = true
        )
        if (targetCase.target.isNotBlank()) {
            entityNodeIdByValue[targetCase.target.trim().lowercase()] = rootId
        }

        artifacts.forEach { art ->
            val wingId = "wing::${art.wingType}"
            if (!nodes.containsKey(wingId)) {
                nodes[wingId] = CaseGraphNode(
                    id = wingId,
                    label = art.wingType.replace("_", " "),
                    entityType = "MODULE",
                    detail = art.sourceApi.ifBlank { "OSINT Module" },
                    pivotValue = null
                )
            }
            edges.add(CaseGraphEdge(rootId, wingId, "INVESTIGATED"))

            if (art.queryTarget.isNotBlank() && !art.queryTarget.equals(targetCase.target, ignoreCase = true)) {
                val targetEntity = PivotEngine.normalize(art.queryTarget)
                val normKey = targetEntity.normalizedValue.lowercase()
                val targetNodeId = entityNodeIdByValue.getOrPut(normKey) {
                    "ent::${targetEntity.type.name}::$normKey"
                }
                if (!nodes.containsKey(targetNodeId)) {
                    nodes[targetNodeId] = CaseGraphNode(
                        id = targetNodeId,
                        label = targetEntity.normalizedValue,
                        entityType = targetEntity.type.name,
                        detail = "${art.title} (${art.sourceApi})",
                        pivotValue = targetEntity.normalizedValue
                    )
                }
                edges.add(CaseGraphEdge(wingId, targetNodeId, art.artifactType))
            }

            // Extract child IOCs discovered inside the artifact summary & rawJson (capped to keep graph readable)
            val extracted = IocExtractor.extract("${art.summary}\n${art.rawJson.take(2500)}")
            extracted.items.take(8).forEach { ioc ->
                val iocKey = ioc.value.trim().lowercase()
                if (iocKey.isNotEmpty() && !ioc.value.equals(targetCase.target, ignoreCase = true)) {
                    val existingId = entityNodeIdByValue[iocKey]
                    val iocId = existingId ?: "ioc::${ioc.category.badge}::$iocKey"
                    if (existingId == null && !nodes.containsKey(iocId) && nodes.size < 36) {
                        nodes[iocId] = CaseGraphNode(
                            id = iocId,
                            label = ioc.value,
                            entityType = ioc.category.badge,
                            detail = "Discovered in ${art.title}",
                            pivotValue = ioc.value
                        )
                        entityNodeIdByValue[iocKey] = iocId
                    }
                    if (nodes.containsKey(iocId) && iocId != rootId) {
                        edges.add(CaseGraphEdge(wingId, iocId, "EXTRACTED"))
                    }
                }
            }
        }

        return CaseEntityGraph(nodes = nodes.values.toList(), edges = edges.toList())
    }

    fun exportHtml(
        targetCase: InvestigationCase,
        artifacts: List<ScanArtifact>,
        aiExecutiveSummary: String? = null
    ): String {
        val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)
        val generatedAt = dateFmt.format(Date())
        val allText = buildString {
            append(targetCase.target).append('\n')
            append(targetCase.notes).append('\n')
            artifacts.forEach {
                append(it.queryTarget).append('\n')
                append(it.summary).append('\n')
                append(it.rawJson.take(4000)).append('\n')
            }
        }
        val extractedIocs = IocExtractor.extract(allText)

        val sb = StringBuilder()
        sb.append(
            """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINTme Dossier — ${escapeHtml(targetCase.title)}</title>
<style>
  body { background:#FFFFFF; color:#090D16; font-family:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',Roboto,sans-serif; margin:0; padding:28px 20px; line-height:1.6; }
  .wrap { max-width:940px; margin:0 auto; }
  .header { background:#F8FAFC; border:1px solid #090D16; border-radius:12px; padding:22px 26px; margin-bottom:20px; }
  .tag { display:inline-block; background:#ECFDF5; color:#059669; border:1px solid #A7F3D0; font-family:monospace; font-size:11px; font-weight:700; padding:3px 9px; border-radius:6px; letter-spacing:0.6px; }
  h1 { margin:10px 0 6px; font-size:24px; color:#090D16; }
  .meta { color:#475569; font-size:12.5px; font-family:monospace; }
  .section { background:#FFFFFF; border:1px solid #E2E8F0; border-radius:12px; padding:18px 22px; margin-bottom:16px; }
  .ai-box { background:#ECFDF5; border:1px solid #A7F3D0; border-radius:12px; padding:18px 22px; margin-bottom:16px; }
  h2 { margin:0 0 12px; font-size:13px; color:#059669; font-family:monospace; letter-spacing:0.9px; text-transform:uppercase; }
  .artifact { background:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:14px; margin-bottom:12px; }
  .art-head { display:flex; justify-content:space-between; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:6px; }
  .art-title { font-weight:700; font-size:15px; color:#090D16; }
  .badge { font-family:monospace; font-size:11px; padding:2px 8px; border-radius:4px; background:#090D16; color:#FFFFFF; font-weight:700; }
  pre { background:#F1F5F9; border:1px solid #CBD5E1; border-radius:8px; padding:12px; overflow-x:auto; color:#0F172A; font-size:12px; }
  table { width:100%; border-collapse:collapse; font-size:13px; font-family:monospace; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #E2E8F0; word-break:break-all; }
  th { color:#475569; font-size:11px; text-transform:uppercase; background:#F8FAFC; }
  .footer { text-align:center; color:#64748B; font-size:12px; margin-top:24px; font-family:monospace; }
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <span class="tag">OSINTME INVESTIGATION DOSSIER</span>
    <h1>${escapeHtml(targetCase.title)}</h1>
    <div class="meta">Primary Target: ${escapeHtml(targetCase.target)} &bull; Status: ${escapeHtml(targetCase.status)} &bull; Generated: ${escapeHtml(generatedAt)}</div>
  </div>
"""
        )

        if (!aiExecutiveSummary.isNullOrBlank()) {
            sb.append("  <div class=\"ai-box\"><h2>AI Executive Intelligence Brief</h2><p>")
                .append(escapeHtml(aiExecutiveSummary).replace("\n", "<br>"))
                .append("</p></div>\n")
        }

        if (targetCase.notes.isNotBlank()) {
            sb.append("  <div class=\"section\"><h2>Analyst Notes</h2><p>")
                .append(escapeHtml(targetCase.notes).replace("\n", "<br>"))
                .append("</p></div>\n")
        }

        sb.append("  <div class=\"section\"><h2>Corroborated Evidence Artifacts (${artifacts.size})</h2>\n")
        if (artifacts.isEmpty()) {
            sb.append("    <p style=\"color:#64748B;\">No evidence artifacts recorded yet.</p>\n")
        } else {
            artifacts.forEach { art ->
                sb.append("    <div class=\"artifact\">\n")
                sb.append("      <div class=\"art-head\"><span class=\"art-title\">")
                    .append(escapeHtml(art.title))
                    .append("</span><span class=\"badge\">")
                    .append(escapeHtml(art.wingType))
                    .append(" &bull; ")
                    .append(escapeHtml(art.confidence))
                    .append("</span></div>\n")
                sb.append("      <div class=\"meta\">Target: ")
                    .append(escapeHtml(art.queryTarget))
                    .append(" &bull; Feed: ")
                    .append(escapeHtml(art.sourceApi))
                    .append(" &bull; ")
                    .append(escapeHtml(dateFmt.format(Date(art.timestamp))))
                    .append("</div>\n")
                sb.append("      <p>")
                    .append(escapeHtml(art.summary).replace("\n", "<br>"))
                    .append("</p>\n")
                if (art.rawJson.isNotBlank() && art.rawJson != "{}") {
                    sb.append("      <pre>").append(escapeHtml(art.rawJson)).append("</pre>\n")
                }
                sb.append("    </div>\n")
            }
        }
        sb.append("  </div>\n")

        if (extractedIocs.items.isNotEmpty()) {
            sb.append("  <div class=\"section\"><h2>Extracted Indicators (${extractedIocs.totalCount})</h2>\n")
            sb.append("    <table><thead><tr><th>Type</th><th>Defanged Indicator</th></tr></thead><tbody>\n")
            extractedIocs.items.forEach { ioc ->
                sb.append("      <tr><td>")
                    .append(escapeHtml(ioc.category.badge))
                    .append("</td><td>")
                    .append(escapeHtml(ioc.defangedValue))
                    .append("</td></tr>\n")
            }
            sb.append("    </tbody></table>\n  </div>\n")
        }

        sb.append("  <div class=\"footer\">Compiled locally on-device by OSINTme Intelligence Workbench &bull; Zero-Cloud Architecture</div>\n")
        sb.append("</div>\n</body>\n</html>\n")
        return sb.toString()
    }

    private val prettyJson = Json { prettyPrint = true }

    fun exportJson(targetCase: InvestigationCase, artifacts: List<ScanArtifact>): String {
        val graph = buildEntityGraph(targetCase, artifacts)
        val root = buildJsonObject {
            put("schema", "osintme.dossier.v1")
            put("exportedAt", System.currentTimeMillis())
            put("case", buildJsonObject {
                put("id", targetCase.id)
                put("title", targetCase.title)
                put("target", targetCase.target)
                put("status", targetCase.status)
                put("notes", targetCase.notes)
                put("createdAt", targetCase.createdAt)
                put("updatedAt", targetCase.updatedAt)
            })
            put("artifacts", buildJsonArray {
                artifacts.forEach { art ->
                    add(buildJsonObject {
                        put("id", art.id)
                        put("wingType", art.wingType)
                        put("artifactType", art.artifactType)
                        put("queryTarget", art.queryTarget)
                        put("title", art.title)
                        put("summary", art.summary)
                        put("confidence", art.confidence)
                        put("sourceApi", art.sourceApi)
                        put("timestamp", art.timestamp)
                        put("rawJson", art.rawJson)
                    })
                }
            })
            put("graphSummary", buildJsonObject {
                put("nodeCount", graph.nodes.size)
                put("edgeCount", graph.edges.size)
            })
        }
        return prettyJson.encodeToString(JsonObject.serializer(), root)
    }

    fun exportCsv(targetCase: InvestigationCase, artifacts: List<ScanArtifact>): String {
        val sb = StringBuilder("case_target,wing,artifact_type,indicator,defanged_indicator,source_api,confidence,summary\n")
        artifacts.forEach { art ->
            val defanged = PivotEngine.defang(art.queryTarget)
            sb.append(csvCell(targetCase.target)).append(',')
                .append(csvCell(art.wingType)).append(',')
                .append(csvCell(art.artifactType)).append(',')
                .append(csvCell(art.queryTarget)).append(',')
                .append(csvCell(defanged)).append(',')
                .append(csvCell(art.sourceApi)).append(',')
                .append(csvCell(art.confidence)).append(',')
                .append(csvCell(art.summary))
                .append('\n')
        }
        return sb.toString()
    }

    fun escapeHtml(raw: String): String {
        return raw
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;")
    }

    private fun csvCell(raw: String): String {
        val flat = raw.replace("\r", " ").replace("\n", " ")
        val safe = if (flat.isNotEmpty() && flat[0] in charArrayOf('=', '+', '-', '@', '\t')) {
            "'$flat"
        } else flat
        return "\"${safe.replace("\"", "\"\"")}\""
    }
}
