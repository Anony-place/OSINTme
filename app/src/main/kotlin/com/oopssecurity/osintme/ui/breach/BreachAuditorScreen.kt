package com.oopssecurity.osintme.ui.breach

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.filled.AlternateEmail
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.data.model.EmailBreachResult
import com.oopssecurity.osintme.data.model.EmailSecurityAudit
import com.oopssecurity.osintme.data.model.GravatarProfile
import com.oopssecurity.osintme.data.model.PasswordLeakResult
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.SaveToCaseDialog
import com.oopssecurity.osintme.ui.domain.EmailSecurityAuditCard
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.DarkerSurface
import com.oopssecurity.osintme.ui.theme.EmeraldPrimary
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.PureWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.SoftIndigo
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntity
import com.oopssecurity.osintme.util.PivotEntityType

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BreachAuditorScreen(
    initialEmail: String = "",
    onBackClick: () -> Unit,
    onPivot: (PivotEntity) -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: BreachViewModel = viewModel(key = "breach_${initialEmail.ifBlank { "root" }}") {
        BreachViewModel(context, initialEmail)
    }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val focusManager = LocalFocusManager.current
    var showSaveDialog by remember { mutableStateOf(false) }

    val canSave = (uiState.selectedTab == 0 && uiState.emailResult != null) ||
        (uiState.selectedTab == 1 && uiState.passwordResult != null)

    if (showSaveDialog && canSave) {
        if (uiState.selectedTab == 0 && uiState.emailResult != null) {
            val res = uiState.emailResult!!
            SaveToCaseDialog(
                wingType = "IDENTITY",
                artifactType = "EMAIL_BREACH_AUDIT",
                queryTarget = res.email,
                title = "Breach Audit: ${res.email}",
                summary = if (res.isBreached) {
                    "${res.totalBreaches} breach(es): ${res.breaches.take(5).joinToString(", ") { it.siteName }}"
                } else {
                    "0 public breaches found on XposedOrNot."
                },
                sourceApi = "XposedOrNot + Gravatar + Cloudflare DoH",
                onDismiss = { showSaveDialog = false }
            )
        } else if (uiState.passwordResult != null) {
            val pwd = uiState.passwordResult!!
            SaveToCaseDialog(
                wingType = "IDENTITY",
                artifactType = "PASSWORD_K_ANON_AUDIT",
                queryTarget = "SHA-1:${pwd.sha1Prefix}***",
                title = "Password k-Anonymity Check (${pwd.sha1Prefix}***)",
                summary = if (pwd.isLeaked) "Observed ${pwd.leakCount} times in HIBP corpus." else "0 occurrences in HIBP corpus.",
                sourceApi = "HIBP Pwned Passwords v2 (k-Anonymity)",
                onDismiss = { showSaveDialog = false }
            )
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            AppHeader(
                title = "Breach & Leak Auditor",
                subtitle = "XposedOrNot, Gravatar, SPF/DMARC & HIBP k-Anonymity",
                showBackButton = true,
                onBackClick = onBackClick,
                trailingContent = if (canSave) {
                    {
                        IconButton(
                            onClick = { showSaveDialog = true },
                            modifier = Modifier.size(48.dp).testTag("breach_save_case_button")
                        ) {
                            Icon(
                                imageVector = Icons.Default.BookmarkAdd,
                                contentDescription = "Save findings to case",
                                tint = SkyCyan
                            )
                        }
                    }
                } else null
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            PrimaryTabRow(
                selectedTabIndex = uiState.selectedTab,
                containerColor = CharcoalNavy,
                contentColor = SkyCyan,
                divider = { HorizontalDivider(color = CardBorder) }
            ) {
                Tab(
                    selected = uiState.selectedTab == 0,
                    onClick = { viewModel.selectTab(0) },
                    text = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.AlternateEmail, contentDescription = null, modifier = Modifier.size(15.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Email Auditor", fontWeight = FontWeight.Medium)
                        }
                    }
                )
                Tab(
                    selected = uiState.selectedTab == 1,
                    onClick = { viewModel.selectTab(1) },
                    text = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(15.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Password Audit", fontWeight = FontWeight.Medium)
                        }
                    }
                )
            }

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp, vertical = 14.dp)
            ) {
                if (uiState.selectedTab == 0) {
                    EmailBreachSection(
                        email = uiState.emailInput,
                        isLoading = uiState.isCheckingEmail,
                        result = uiState.emailResult,
                        gravatar = uiState.gravatarProfile,
                        emailSecurity = uiState.emailSecurity,
                        error = uiState.errorMessage,
                        onEmailChange = { viewModel.onEmailChange(it) },
                        onCheckClick = {
                            focusManager.clearFocus()
                            viewModel.checkEmail()
                        },
                        onPivot = onPivot
                    )
                } else {
                    PasswordLeakSection(
                        password = uiState.passwordInput,
                        isLoading = uiState.isCheckingPassword,
                        result = uiState.passwordResult,
                        error = uiState.errorMessage,
                        onPasswordChange = { viewModel.onPasswordChange(it) },
                        onCheckClick = {
                            focusManager.clearFocus()
                            viewModel.checkPassword()
                        }
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun EmailBreachSection(
    email: String,
    isLoading: Boolean,
    result: EmailBreachResult?,
    gravatar: GravatarProfile?,
    emailSecurity: EmailSecurityAudit?,
    error: String?,
    onEmailChange: (String) -> Unit,
    onCheckClick: () -> Unit,
    onPivot: (PivotEntity) -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(CharcoalNavy)
                    .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                    .padding(16.dp)
            ) {
                Text(
                    text = "TARGET EMAIL ADDRESS",
                    style = MaterialTheme.typography.labelSmall,
                    color = SlateGrey,
                    fontFamily = MonoFontFamily
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = email,
                    onValueChange = onEmailChange,
                    modifier = Modifier.fillMaxWidth().testTag("breach_email_input"),
                    placeholder = { Text("analyst@domain.com", color = MutedSlate, fontSize = 13.sp) },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = OffWhite),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { onCheckClick() }),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = SkyCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedContainerColor = DarkerSurface,
                        unfocusedContainerColor = DarkerSurface,
                        focusedTextColor = OffWhite,
                        unfocusedTextColor = OffWhite
                    ),
                    shape = RoundedCornerShape(10.dp)
                )
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = onCheckClick,
                    enabled = email.isNotBlank() && !isLoading,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("breach_email_button"),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), color = PureWhite, strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Querying Breach & DNS Feeds…", fontWeight = FontWeight.SemiBold)
                    } else {
                        Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Audit Email Exposure", fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        if (error != null) {
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(StatusRisk.copy(alpha = 0.12f))
                        .border(1.dp, StatusRisk.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Warning, contentDescription = null, tint = StatusRisk, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(text = error, color = StatusRisk, style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        if (result != null) {
            item {
                val isBreached = result.isBreached
                val badgeColor = if (isBreached) StatusRisk else StatusSafe

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, badgeColor.copy(alpha = 0.45f), RoundedCornerShape(14.dp))
                        .padding(16.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .clickable {
                                onPivot(
                                    PivotEngine.normalize(
                                        raw = result.email,
                                        hintType = PivotEntityType.EMAIL,
                                        sourceContext = "Email Breach Audit"
                                    )
                                )
                            },
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = if (isBreached) Icons.Default.Warning else Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = badgeColor,
                            modifier = Modifier.size(22.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = if (isBreached) "${result.totalBreaches} Public Breach(es) Detected" else "No Public Breaches Indexed",
                                style = MaterialTheme.typography.titleSmall,
                                color = badgeColor
                            )
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = result.email,
                                    color = SlateGrey,
                                    fontSize = 12.sp,
                                    fontFamily = MonoFontFamily
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = "Pivot email", tint = SkyCyan, modifier = Modifier.size(13.dp))
                            }
                        }
                        if (result.riskLabel.isNotBlank()) {
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(5.dp))
                                    .background(badgeColor.copy(alpha = 0.14f))
                                    .padding(horizontal = 8.dp, vertical = 3.dp)
                            ) {
                                Text(result.riskLabel.uppercase(), color = badgeColor, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                            }
                        }
                    }

                    if (isBreached && result.exposedDataTypes.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text("EXPOSED DATA CLASSES", fontSize = 10.sp, color = MutedSlate, fontFamily = MonoFontFamily)
                        Spacer(modifier = Modifier.height(6.dp))
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            result.exposedDataTypes.forEach { type ->
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(5.dp))
                                        .background(SurfaceElevated)
                                        .border(1.dp, CardBorder, RoundedCornerShape(5.dp))
                                        .padding(horizontal = 8.dp, vertical = 3.dp)
                                ) {
                                    Text(type, fontSize = 11.sp, color = SkyCyan, fontFamily = MonoFontFamily)
                                }
                            }
                        }
                    }
                }
            }
        }

        if (emailSecurity != null) {
            item { EmailSecurityAuditCard(emailSecurity) }
        }

        if (gravatar != null) {
            item { GravatarProfileCard(profile = gravatar, onPivot = onPivot) }
        }

        if (result != null && result.isBreached) {
            item {
                Text(
                    text = "BREACH INCIDENT RECORDS (${result.breaches.size}) • TAP TO PIVOT",
                    fontSize = 11.sp,
                    color = MutedSlate,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.SemiBold
                )
            }
            items(result.breaches) { breach ->
                val pivotDomain = breach.domain.ifBlank { "" }
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, CardBorder, RoundedCornerShape(12.dp))
                        .clickable(enabled = pivotDomain.contains(".")) {
                            onPivot(
                                PivotEngine.normalize(
                                    raw = pivotDomain,
                                    hintType = PivotEntityType.DOMAIN,
                                    sourceContext = "Breach Record: ${breach.siteName}"
                                )
                            )
                        }
                        .padding(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(breach.siteName, style = MaterialTheme.typography.titleSmall, color = OffWhite)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            if (breach.breachDate.isNotBlank()) {
                                Text(breach.breachDate, fontSize = 11.sp, color = MutedSlate, fontFamily = MonoFontFamily)
                            }
                            if (pivotDomain.contains(".")) {
                                Spacer(modifier = Modifier.width(6.dp))
                                Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = "Pivot breached domain", tint = SkyCyan, modifier = Modifier.size(14.dp))
                            }
                        }
                    }

                    val metaLine = buildList {
                        if (breach.domain.isNotBlank()) add(breach.domain)
                        if (breach.industry.isNotBlank()) add(breach.industry)
                        if (breach.pwnCount > 0) add("${breach.pwnCount} records")
                    }.joinToString(" • ")

                    if (metaLine.isNotBlank()) {
                        Spacer(modifier = Modifier.height(3.dp))
                        Text(metaLine, color = SlateGrey, fontSize = 11.sp, fontFamily = MonoFontFamily)
                    }

                    if (breach.exposedData.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            breach.exposedData.forEach { d ->
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(StatusWarning.copy(alpha = 0.12f))
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text(d, color = StatusWarning, fontSize = 10.sp, fontFamily = MonoFontFamily)
                                }
                            }
                        }
                    }

                    if (breach.description.isNotBlank()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(breach.description, style = MaterialTheme.typography.bodySmall, color = SlateGrey)
                    }
                }
            }
        }

        item { Spacer(modifier = Modifier.height(16.dp)) }
    }
}

@Composable
private fun PasswordLeakSection(
    password: String,
    isLoading: Boolean,
    result: PasswordLeakResult?,
    error: String?,
    onPasswordChange: (String) -> Unit,
    onCheckClick: () -> Unit
) {
    var passwordVisible by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(CharcoalNavy)
                    .border(1.dp, StatusSafe.copy(alpha = 0.3f), RoundedCornerShape(10.dp))
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Security, contentDescription = null, tint = StatusSafe, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = "k-Anonymity Guarantee: Passwords are hashed locally with SHA-1. Only the first 5 hex characters are transmitted to HIBP with response padding enabled.",
                    style = MaterialTheme.typography.bodySmall,
                    color = SlateGrey
                )
            }
        }

        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(CharcoalNavy)
                    .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
                    .padding(16.dp)
            ) {
                Text("PASSWORD TO AUDIT", fontSize = 11.sp, color = SlateGrey, fontFamily = MonoFontFamily)
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = onPasswordChange,
                    modifier = Modifier.fillMaxWidth().testTag("breach_password_input"),
                    placeholder = { Text("Enter password…", color = MutedSlate, fontSize = 13.sp) },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily, color = OffWhite),
                    visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Icon(
                                imageVector = if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = "Toggle password visibility",
                                tint = SlateGrey,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { onCheckClick() }),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = SkyCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedContainerColor = DarkerSurface,
                        unfocusedContainerColor = DarkerSurface,
                        focusedTextColor = OffWhite,
                        unfocusedTextColor = OffWhite
                    ),
                    shape = RoundedCornerShape(10.dp)
                )
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = onCheckClick,
                    enabled = password.isNotBlank() && !isLoading,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("breach_password_button"),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldPrimary,
                        contentColor = PureWhite,
                        disabledContainerColor = SurfaceElevated,
                        disabledContentColor = MutedSlate
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), color = PureWhite, strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Checking HIBP Range…", fontWeight = FontWeight.SemiBold)
                    } else {
                        Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Check Password Exposure", fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        if (error != null) {
            item {
                Text(text = error, color = StatusRisk, style = MaterialTheme.typography.bodySmall)
            }
        }

        if (result != null) {
            item {
                val badgeColor = if (result.isLeaked) StatusRisk else StatusSafe
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, badgeColor.copy(alpha = 0.45f), RoundedCornerShape(14.dp))
                        .padding(16.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (result.isLeaked) Icons.Default.Warning else Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = badgeColor,
                            modifier = Modifier.size(22.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = if (result.isLeaked) "Compromised (${result.leakCount} corpus hits)" else "Not Found in Known Leaks",
                                style = MaterialTheme.typography.titleSmall,
                                color = badgeColor
                            )
                            Text(
                                text = "SHA-1 Prefix Queried: ${result.sha1Prefix}***",
                                color = SlateGrey,
                                fontSize = 11.sp,
                                fontFamily = MonoFontFamily
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(result.securityAdvice, style = MaterialTheme.typography.bodySmall, color = OffWhite)
                }
            }
        }
    }
}

@Composable
private fun GravatarProfileCard(
    profile: GravatarProfile,
    onPivot: (PivotEntity) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .clickable(enabled = profile.preferredUsername.isNotBlank()) {
                    onPivot(
                        PivotEngine.normalize(
                            raw = profile.preferredUsername,
                            hintType = PivotEntityType.USERNAME,
                            sourceContext = "Gravatar Preferred Handle"
                        )
                    )
                },
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("GRAVATAR IDENTITY PIVOT", color = SkyCyan, fontSize = 10.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(2.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = profile.displayName.ifBlank { profile.preferredUsername },
                        style = MaterialTheme.typography.titleSmall,
                        color = OffWhite
                    )
                    if (profile.preferredUsername.isNotBlank()) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("@${profile.preferredUsername}", color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily)
                        Spacer(modifier = Modifier.width(4.dp))
                        Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = "Pivot Gravatar handle", tint = SkyCyan, modifier = Modifier.size(13.dp))
                    }
                }
            }
            if (profile.currentLocation.isNotBlank()) {
                Text(profile.currentLocation, color = SlateGrey, fontSize = 11.sp)
            }
        }

        if (profile.aboutMe.isNotBlank()) {
            Spacer(modifier = Modifier.height(6.dp))
            Text(profile.aboutMe, style = MaterialTheme.typography.bodySmall, color = SlateGrey)
        }

        if (profile.accounts.isNotEmpty()) {
            Spacer(modifier = Modifier.height(10.dp))
            Text("LINKED ACCOUNTS • TAP TO PIVOT", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
            Spacer(modifier = Modifier.height(6.dp))
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                profile.accounts.forEach { acc ->
                    val targetHandle = acc.username.ifBlank { acc.display }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(DarkerSurface)
                            .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                            .clickable {
                                if (acc.username.isNotBlank()) {
                                    onPivot(
                                        PivotEngine.normalize(
                                            raw = acc.username,
                                            hintType = PivotEntityType.USERNAME,
                                            sourceContext = "Gravatar Linked (${acc.domain})"
                                        )
                                    )
                                } else if (acc.url.isNotBlank()) {
                                    onPivot(
                                        PivotEngine.normalize(
                                            raw = acc.url,
                                            hintType = PivotEntityType.URL,
                                            sourceContext = "Gravatar Account (${acc.domain})"
                                        )
                                    )
                                }
                            }
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(acc.domain.uppercase(), color = SoftIndigo, fontSize = 11.sp, fontFamily = MonoFontFamily, fontWeight = FontWeight.SemiBold)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(if (acc.username.isNotBlank()) "@$targetHandle" else targetHandle, color = OffWhite, fontSize = 11.sp, fontFamily = MonoFontFamily)
                            Spacer(modifier = Modifier.width(6.dp))
                            Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = "Pivot linked account", tint = SkyCyan, modifier = Modifier.size(13.dp))
                        }
                    }
                }
            }
        }

        if (profile.personalUrls.isNotEmpty()) {
            Spacer(modifier = Modifier.height(10.dp))
            Text("PERSONAL LINKS • TAP TO PIVOT", color = MutedSlate, fontSize = 10.sp, fontFamily = MonoFontFamily)
            Spacer(modifier = Modifier.height(6.dp))
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                profile.personalUrls.forEach { link ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(DarkerSurface)
                            .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                            .clickable {
                                onPivot(
                                    PivotEngine.normalize(
                                        raw = link,
                                        hintType = PivotEntityType.URL,
                                        sourceContext = "Gravatar Personal Link"
                                    )
                                )
                            }
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(link, color = SkyCyan, fontSize = 11.sp, fontFamily = MonoFontFamily, modifier = Modifier.weight(1f))
                        Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = "Pivot personal URL", tint = SkyCyan, modifier = Modifier.size(13.dp))
                    }
                }
            }
        }
    }
}
