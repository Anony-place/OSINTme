package com.oopssecurity.osintme.ui.cases

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.filled.CenterFocusStrong
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
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
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.util.CaseEntityGraph
import com.oopssecurity.osintme.util.CaseGraphNode
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.sin

@Composable
fun CaseGraphView(
    graph: CaseEntityGraph,
    onPivot: (PivotEntity) -> Unit,
    modifier: Modifier = Modifier
) {
    var panOffset by remember { mutableStateOf(Offset.Zero) }
    var selectedNode by remember(graph) { mutableStateOf(graph.nodes.firstOrNull()) }

    val nodePositions = remember(graph) {
        computeRadialLayout(graph)
    }

    Column(modifier = modifier.fillMaxSize()) {
        // Legend & Reset Row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                GraphLegendDot("Root", SkyCyan)
                GraphLegendDot("Module", SoftIndigo)
                GraphLegendDot("Host/IP", MatrixGreen)
                GraphLegendDot("IOC", StatusWarning)
            }

            IconButton(
                onClick = { panOffset = Offset.Zero },
                modifier = Modifier.size(36.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.CenterFocusStrong,
                    contentDescription = "Reset graph view",
                    tint = SkyCyan,
                    modifier = Modifier.size(18.dp)
                )
            }
        }

        // Interactive Canvas Area
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clip(RoundedCornerShape(14.dp))
                .background(DarkerSurface)
                .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                .testTag("case_entity_graph_canvas")
        ) {
            Canvas(
                modifier = Modifier
                    .fillMaxSize()
                    .pointerInput(graph) {
                        detectDragGestures { change, dragAmount ->
                            change.consume()
                            panOffset += dragAmount
                        }
                    }
                    .pointerInput(graph, panOffset) {
                        detectTapGestures { tapOffset ->
                            val center = Offset(size.width / 2f, size.height / 2f)
                            val radiusScale = minOf(size.width, size.height) * 0.40f
                            val hit = graph.nodes.minByOrNull { node ->
                                val norm = nodePositions[node.id] ?: Offset.Zero
                                val screenPos = center + panOffset + Offset(norm.x * radiusScale, norm.y * radiusScale)
                                hypot(tapOffset.x - screenPos.x, tapOffset.y - screenPos.y)
                            }
                            if (hit != null) {
                                val norm = nodePositions[hit.id] ?: Offset.Zero
                                val screenPos = center + panOffset + Offset(norm.x * radiusScale, norm.y * radiusScale)
                                if (hypot(tapOffset.x - screenPos.x, tapOffset.y - screenPos.y) <= 58f) {
                                    selectedNode = hit
                                }
                            }
                        }
                    }
            ) {
                // Tactical grid backdrop
                val step = 56f
                var gx = (panOffset.x % step + step) % step
                while (gx < size.width) {
                    drawLine(
                        color = CardBorder.copy(alpha = 0.25f),
                        start = Offset(gx, 0f),
                        end = Offset(gx, size.height),
                        strokeWidth = 1f
                    )
                    gx += step
                }
                var gy = (panOffset.y % step + step) % step
                while (gy < size.height) {
                    drawLine(
                        color = CardBorder.copy(alpha = 0.25f),
                        start = Offset(0f, gy),
                        end = Offset(size.width, gy),
                        strokeWidth = 1f
                    )
                    gy += step
                }

                val center = Offset(size.width / 2f, size.height / 2f)
                val radiusScale = minOf(size.width, size.height) * 0.40f

                fun toScreen(nodeId: String): Offset {
                    val norm = nodePositions[nodeId] ?: Offset.Zero
                    return center + panOffset + Offset(norm.x * radiusScale, norm.y * radiusScale)
                }

                // Draw edges
                graph.edges.forEach { edge ->
                    val start = toScreen(edge.fromId)
                    val end = toScreen(edge.toId)
                    val isHighlighted = selectedNode != null &&
                        (edge.fromId == selectedNode?.id || edge.toId == selectedNode?.id)
                    drawLine(
                        color = if (isHighlighted) SkyCyan.copy(alpha = 0.85f) else MutedSlate.copy(alpha = 0.35f),
                        start = start,
                        end = end,
                        strokeWidth = if (isHighlighted) 3.2f else 1.6f
                    )
                }

                // Draw nodes + labels
                val textPaint = android.graphics.Paint().apply {
                    color = android.graphics.Color.parseColor("#090D16")
                    textSize = 26f
                    isAntiAlias = true
                    textAlign = android.graphics.Paint.Align.CENTER
                    typeface = android.graphics.Typeface.MONOSPACE
                }

                graph.nodes.forEach { node ->
                    val pos = toScreen(node.id)
                    val nodeColor = nodeColorFor(node.entityType)
                    val isSelected = selectedNode?.id == node.id
                    val radius = when {
                        node.isRoot -> 28f
                        node.entityType == "MODULE" -> 20f
                        else -> 16f
                    }

                    if (isSelected) {
                        drawCircle(
                            color = nodeColor.copy(alpha = 0.25f),
                            radius = radius + 12f,
                            center = pos
                        )
                    }
                    drawCircle(
                        color = CharcoalNavy,
                        radius = radius,
                        center = pos
                    )
                    drawCircle(
                        color = nodeColor,
                        radius = radius,
                        center = pos,
                        style = androidx.compose.ui.graphics.drawscope.Stroke(width = if (isSelected) 4.5f else 2.8f)
                    )

                    val shortLabel = if (node.label.length > 18) node.label.take(16) + "…" else node.label
                    drawContext.canvas.nativeCanvas.drawText(
                        shortLabel,
                        pos.x,
                        pos.y + radius + 28f,
                        textPaint
                    )
                }
            }

            // Node count badge
            Box(
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(10.dp)
                    .clip(RoundedCornerShape(6.dp))
                    .background(CharcoalNavy.copy(alpha = 0.9f))
                    .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = "${graph.nodes.size} nodes • ${graph.edges.size} links • Drag to pan",
                    color = SlateGrey,
                    fontSize = 10.sp,
                    fontFamily = MonoFontFamily
                )
            }
        }

        // Selected Node Inspector Card
        selectedNode?.let { node ->
            Spacer(modifier = Modifier.height(10.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CharcoalNavy),
                border = BorderStroke(1.dp, nodeColorFor(node.entityType).copy(alpha = 0.5f)),
                shape = RoundedCornerShape(12.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = node.entityType,
                            color = nodeColorFor(node.entityType),
                            fontSize = 10.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = node.label,
                            color = OffWhite,
                            fontSize = 13.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = node.detail,
                            color = SlateGrey,
                            fontSize = 11.sp,
                            fontFamily = DisplayFontFamily,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    if (!node.pivotValue.isNullOrBlank()) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                onPivot(
                                    PivotEngine.normalize(
                                        raw = node.pivotValue,
                                        sourceContext = "Case Graph Node"
                                    )
                                )
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = EmeraldPrimary,
                                contentColor = PureWhite
                            ),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = null, modifier = Modifier.size(15.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Pivot", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun GraphLegendDot(label: String, color: Color) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(color)
        )
        Spacer(modifier = Modifier.width(4.dp))
        Text(text = label, color = SlateGrey, fontSize = 10.sp, fontFamily = MonoFontFamily)
    }
}

private fun nodeColorFor(entityType: String): Color {
    return when (entityType.uppercase()) {
        "CASE_ROOT" -> SkyCyan
        "MODULE" -> SoftIndigo
        "DOMAIN", "IP_ADDRESS", "IPV4", "IPV6" -> MatrixGreen
        "EMAIL" -> StatusRisk
        else -> StatusWarning
    }
}

private fun computeRadialLayout(graph: CaseEntityGraph): Map<String, Offset> {
    val map = mutableMapOf<String, Offset>()
    val root = graph.nodes.firstOrNull { it.isRoot }
    val modules = graph.nodes.filter { !it.isRoot && it.entityType == "MODULE" }
    val leaves = graph.nodes.filter { !it.isRoot && it.entityType != "MODULE" }

    if (root != null) {
        map[root.id] = Offset.Zero
    }

    val modCount = modules.size.coerceAtLeast(1)
    modules.forEachIndexed { idx, node ->
        val angle = (2.0 * PI * idx / modCount) - (PI / 2.0)
        map[node.id] = Offset((cos(angle) * 0.45).toFloat(), (sin(angle) * 0.45).toFloat())
    }

    val leafCount = leaves.size.coerceAtLeast(1)
    leaves.forEachIndexed { idx, node ->
        val angle = (2.0 * PI * idx / leafCount) - (PI / 4.0)
        val ring = if (idx % 2 == 0) 0.88 else 1.12
        map[node.id] = Offset((cos(angle) * ring).toFloat(), (sin(angle) * ring).toFloat())
    }

    return map
}
