package com.oopssecurity.osintme.ui.dorks

import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.data.local.ApiKeyVault
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.CodeBlock
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DisplayFontFamily
import com.oopssecurity.osintme.ui.theme.EmeraldBorder
import com.oopssecurity.osintme.ui.theme.EmeraldDeep
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.EmeraldSoft
import com.oopssecurity.osintme.ui.theme.InkBlack
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.SafeBrowserLauncher

@Composable
fun DorkGeneratorScreen(
    initialTarget: String = "",
    onBackClick: () -> Unit,
    onOpenApiVault: () -> Unit = {},
    embedded: Boolean = false,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: DorkViewModel = viewModel(key = "dorks_${initialTarget.ifBlank { "root" }}")
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val activeAi by ApiKeyVault.activeAiProvider.collectAsStateWithLifecycle()

    LaunchedEffect(initialTarget) {
        if (initialTarget.isNotEmpty() && uiState.target.isEmpty()) {
            viewModel.setTarget(initialTarget)
        }
    }

    val content: @Composable (Modifier) -> Unit = { contentMod ->
        Column(modifier = contentMod.fillMaxSize().navigationBarsPadding()) {
            OutlinedTextField(
                value = uiState.target,
                onValueChange = { viewModel.setTarget(it) },
                placeholder = { Text("Target domain or entity (e.g. example.com)", color = MutedSlate, fontSize = 13.sp) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp)
                    .testTag("dork_target_input"),
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = InkBlack),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = CharcoalNavy,
                    unfocusedContainerColor = CharcoalNavy,
                    focusedBorderColor = InkBlack,
                    unfocusedBorderColor = CardBorder,
                    focusedTextColor = InkBlack,
                    unfocusedTextColor = InkBlack
                ),
                shape = RoundedCornerShape(10.dp),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done)
            )

            // Search Engine Filter Chips
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                SearchEngineTarget.entries.forEach { engine ->
                    val isSelected = uiState.selectedEngine == engine
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .background(if (isSelected) EmeraldPrimary else SurfaceElevated)
                            .border(1.dp, if (isSelected) EmeraldPrimary else CardBorder, RoundedCornerShape(8.dp))
                            .clickable { viewModel.selectEngine(engine) }
                            .padding(horizontal = 11.dp, vertical = 7.dp)
                    ) {
                        Text(
                            text = engine.label,
                            fontSize = 11.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                            color = if (isSelected) PureWhite else SlateGrey
                        )
                    }
                }
            }

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                // BYOK AI Custom Dork Crafter Card
                item {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(14.dp))
                            .background(EmeraldSoft)
                            .border(1.dp, EmeraldBorder, RoundedCornerShape(14.dp))
                            .padding(14.dp)
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
                                    text = "BYOK AI CUSTOM DORK CRAFTER",
                                    color = EmeraldDeep,
                                    fontSize = 11.sp,
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                            if (activeAi == null) {
                                Text(
                                    text = "Setup Key →",
                                    color = InkBlack,
                                    fontSize = 11.sp,
                                    fontFamily = MonoFontFamily,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.clickable(onClick = onOpenApiVault)
                                )
                            } else {
                                Text(activeAi!!.shortBadge, color = EmeraldPrimary, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                            }
                        }

                        Spacer(modifier = Modifier.height(6.dp))
                        OutlinedTextField(
                            value = uiState.aiGoalInput,
                            onValueChange = { viewModel.updateAiGoal(it) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ai_dork_goal_input"),
                            placeholder = { Text("Describe what to hunt (e.g. exposed staging APIs, Swagger docs, leaked keys)", color = MutedSlate, fontSize = 12.sp) },
                            maxLines = 2,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedContainerColor = PureWhite,
                                unfocusedContainerColor = PureWhite,
                                focusedBorderColor = EmeraldPrimary,
                                unfocusedBorderColor = EmeraldBorder,
                                focusedTextColor = InkBlack,
                                unfocusedTextColor = InkBlack
                            ),
                            shape = RoundedCornerShape(8.dp)
                        )

                        if (!uiState.aiError.isNullOrBlank()) {
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(uiState.aiError!!, color = StatusRisk, fontSize = 11.sp)
                        }

                        Spacer(modifier = Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { viewModel.generateAiDorks() },
                                enabled = uiState.aiGoalInput.isNotBlank() && !uiState.aiGenerating,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = EmeraldPrimary,
                                    contentColor = PureWhite,
                                    disabledContainerColor = SurfaceElevated,
                                    disabledContentColor = MutedSlate
                                ),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .heightIn(min = 42.dp)
                                    .testTag("ai_dork_generate_button")
                            ) {
                                if (uiState.aiGenerating) {
                                    CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp, color = PureWhite)
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Crafting...", fontSize = 12.sp)
                                } else {
                                    Icon(Icons.Default.AutoAwesome, contentDescription = null, modifier = Modifier.size(15.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Craft AI Queries", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                                }
                            }

                            if (activeAi == null) {
                                OutlinedButton(
                                    onClick = onOpenApiVault,
                                    border = BorderStroke(1.dp, EmeraldPrimary),
                                    colors = ButtonDefaults.outlinedButtonColors(containerColor = PureWhite, contentColor = EmeraldDeep),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.heightIn(min = 42.dp)
                                ) {
                                    Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(14.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("AI Vault", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }

                if (uiState.aiCraftedDorks.isNotEmpty()) {
                    item {
                        Text(
                            text = "AI CRAFTED QUERIES (${uiState.aiProviderMeta.orEmpty()})",
                            color = EmeraldDeep,
                            fontSize = 10.sp,
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    items(uiState.aiCraftedDorks, key = { it.id }) { item ->
                        MultiEngineDorkCard(item, context, isAi = true)
                    }
                }

                item {
                    Text(
                        text = "VERIFIED PRECISION MATRIX (${uiState.dorks.size})",
                        color = MutedSlate,
                        fontSize = 10.sp,
                        fontFamily = MonoFontFamily,
                        fontWeight = FontWeight.Bold
                    )
                }

                items(uiState.dorks, key = { it.id }) { item ->
                    MultiEngineDorkCard(item, context, isAi = false)
                }

                item { Spacer(modifier = Modifier.height(16.dp)) }
            }
        }
    }

    if (embedded) {
        content(modifier)
    } else {
        Scaffold(
            modifier = modifier.fillMaxSize(),
            containerColor = PureWhite,
            contentWindowInsets = WindowInsets(0, 0, 0, 0),
            topBar = {
                AppHeader(
                    title = "Precision Dork Matrix",
                    subtitle = "Google, Shodan, GitHub, Censys & BYOK AI queries",
                    showBackButton = true,
                    onBackClick = onBackClick
                )
            }
        ) { padding ->
            content(Modifier.padding(padding))
        }
    }
}

@Composable
private fun MultiEngineDorkCard(item: MultiEngineDork, context: Context, isAi: Boolean) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, if (isAi) EmeraldBorder else CardBorder, RoundedCornerShape(14.dp))
            .padding(14.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = item.label,
                color = InkBlack,
                fontSize = 14.sp,
                fontFamily = DisplayFontFamily,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(5.dp))
                    .background(if (isAi) EmeraldPrimary else InkBlack)
                    .padding(horizontal = 7.dp, vertical = 3.dp)
            ) {
                Text(item.engine.badge, color = PureWhite, fontSize = 9.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
            }
        }

        Spacer(modifier = Modifier.height(4.dp))
        Text(item.explanation, color = SlateGrey, fontSize = 12.sp)
        Spacer(modifier = Modifier.height(8.dp))
        CodeBlock(code = item.formattedQuery)
        Spacer(modifier = Modifier.height(10.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedButton(
                onClick = {
                    SafeBrowserLauncher.copyToClipboard(context, "OSINT Dork", item.formattedQuery, isSensitive = false)
                    Toast.makeText(context, "Query copied to clipboard", Toast.LENGTH_SHORT).show()
                },
                colors = ButtonDefaults.outlinedButtonColors(containerColor = PureWhite, contentColor = InkBlack),
                border = BorderStroke(1.dp, CardBorder),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.heightIn(min = 40.dp)
            ) {
                Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(5.dp))
                Text("Copy", fontSize = 12.sp)
            }

            Spacer(modifier = Modifier.width(8.dp))

            Button(
                onClick = {
                    if (!SafeBrowserLauncher.openExternalUrl(context, item.launchUrl)) {
                        Toast.makeText(context, "Unable to launch URL", Toast.LENGTH_SHORT).show()
                    }
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = EmeraldPrimary,
                    contentColor = PureWhite,
                    disabledContainerColor = SurfaceElevated,
                    disabledContentColor = MutedSlate
                ),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.heightIn(min = 40.dp)
            ) {
                Icon(Icons.Default.OpenInBrowser, contentDescription = null, modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(5.dp))
                Text("Launch ${item.engine.label}", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}
