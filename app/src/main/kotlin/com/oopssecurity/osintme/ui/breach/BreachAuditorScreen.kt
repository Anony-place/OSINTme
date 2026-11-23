package com.oopssecurity.osintme.ui.breach

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
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AlternateEmail
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
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.oopssecurity.osintme.ui.components.AppHeader
import com.oopssecurity.osintme.ui.components.PartnerOfferCard
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian
import com.oopssecurity.osintme.ui.theme.StatusRisk
import com.oopssecurity.osintme.ui.theme.StatusSafe
import com.oopssecurity.osintme.ui.theme.StatusWarning
import com.oopssecurity.osintme.ui.theme.SurfaceElevated

@Composable
fun BreachAuditorScreen(
    initialEmail: String = "",
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val viewModel: BreachViewModel = viewModel { BreachViewModel(context, initialEmail) }
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val focusManager = LocalFocusManager.current

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = SlateObsidian,
        topBar = {
            AppHeader(
                title = "Breach & Leak Auditor",
                subtitle = "Public breach check & k-Anonymity model",
                showBackButton = true,
                onBackClick = onBackClick
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
        ) {
            // Tabs: Email vs Password
            TabRow(
                selectedTabIndex = uiState.selectedTab,
                containerColor = CharcoalNavy,
                contentColor = SkyCyan,
                indicator = { tabPositions ->
                    TabRowDefaults.SecondaryIndicator(
                        Modifier.tabIndicatorOffset(tabPositions[uiState.selectedTab]),
                        color = SkyCyan
                    )
                },
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
            ) {
                Tab(
                    selected = uiState.selectedTab == 0,
                    onClick = { viewModel.selectTab(0) },
                    text = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(imageVector = Icons.Default.AlternateEmail, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Email Auditor", style = MaterialTheme.typography.labelLarge)
                        }
                    }
                )
                Tab(
                    selected = uiState.selectedTab == 1,
                    onClick = { viewModel.selectTab(1) },
                    text = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(imageVector = Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Password Leak Check", style = MaterialTheme.typography.labelLarge)
                        }
                    }
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            if (uiState.selectedTab == 0) {
                // Email Breach Checker
                EmailBreachSection(
                    email = uiState.emailInput,
                    isLoading = uiState.isCheckingEmail,
                    result = uiState.emailResult,
                    error = uiState.errorMessage,
                    offers = uiState.partnerOffers,
                    onEmailChange = { viewModel.onEmailChange(it) },
                    onCheckClick = {
                        focusManager.clearFocus()
                        viewModel.checkEmail()
                    }
                )
            } else {
                // Password k-Anonymity Checker
                PasswordLeakSection(
                    password = uiState.passwordInput,
                    isLoading = uiState.isCheckingPassword,
                    result = uiState.passwordResult,
                    error = uiState.errorMessage,
                    offers = uiState.partnerOffers,
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

@Composable
fun EmailBreachSection(
    email: String,
    isLoading: Boolean,
    result: com.oopssecurity.osintme.data.model.EmailBreachResult?,
    error: String?,
    offers: List<com.oopssecurity.osintme.data.model.AffiliateOffer>,
    onEmailChange: (String) -> Unit,
    onCheckClick: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(CharcoalNavy)
                    .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                    .padding(14.dp)
            ) {
                Text(
                    text = "CHECK EMAIL EXPOSURE",
                    fontSize = 11.sp,
                    color = SlateGrey,
                    style = MaterialTheme.typography.labelSmall
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = email,
                    onValueChange = onEmailChange,
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("Enter target email (e.g. user@example.com)", color = MutedSlate, fontSize = 13.sp) },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace, fontSize = 13.sp),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { onCheckClick() }),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = SkyCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedContainerColor = SlateObsidian,
                        unfocusedContainerColor = SlateObsidian
                    ),
                    shape = RoundedCornerShape(8.dp)
                )
                Spacer(modifier = Modifier.height(10.dp))
                Button(
                    onClick = onCheckClick,
                    enabled = email.isNotBlank() && !isLoading,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = SkyCyan, contentColor = SlateObsidian),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), color = SlateObsidian, strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Querying Breach Database...")
                    } else {
                        Icon(imageVector = Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Audit Email Breaches", style = MaterialTheme.typography.labelLarge)
                    }
                }
            }
        }

        if (error != null) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(StatusRisk.copy(alpha = 0.15f))
                        .border(1.dp, StatusRisk.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                        .padding(12.dp)
                ) {
                    Text(text = error, color = StatusRisk, style = MaterialTheme.typography.bodyMedium)
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
                        .clip(RoundedCornerShape(10.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, badgeColor.copy(alpha = 0.5f), RoundedCornerShape(10.dp))
                        .padding(16.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = if (isBreached) Icons.Default.Warning else Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = badgeColor,
                            modifier = Modifier.size(22.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = if (isBreached) "EXPOSURE DETECTED: ${result.totalBreaches} BREACHES" else "CLEAN: ZERO PUBLIC BREACHES",
                                style = MaterialTheme.typography.titleMedium,
                                color = badgeColor,
                                fontSize = 14.sp
                            )
                            Text(
                                text = result.email,
                                style = MaterialTheme.typography.labelSmall,
                                color = SlateGrey
                            )
                        }
                    }

                    if (isBreached && result.exposedDataTypes.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(text = "Exposed Data Types:", style = MaterialTheme.typography.labelSmall, color = MutedSlate)
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            result.exposedDataTypes.forEach { type ->
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(SurfaceElevated)
                                        .border(1.dp, CardBorder, RoundedCornerShape(4.dp))
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text(text = type, fontSize = 10.sp, color = SkyCyan, style = MaterialTheme.typography.labelSmall)
                                }
                            }
                        }
                    }
                }
            }

            if (result.isBreached) {
                item {
                    Text(text = "BREACH DETAILS", fontSize = 11.sp, color = SlateGrey, style = MaterialTheme.typography.labelSmall)
                }
                items(result.breaches) { breach ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(CharcoalNavy)
                            .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                            .padding(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(text = breach.siteName, style = MaterialTheme.typography.titleMedium, color = OffWhite, fontSize = 13.sp)
                            Text(text = breach.breachDate, fontSize = 10.sp, color = MutedSlate, style = MaterialTheme.typography.labelSmall)
                        }
                        if (breach.exposedData.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "Exposed: ${breach.exposedData.joinToString(", ")}",
                                style = MaterialTheme.typography.bodyMedium,
                                fontSize = 11.sp,
                                color = StatusWarning
                            )
                        }
                    }
                }

                // Contextual affiliate recommendation
                if (offers.isNotEmpty()) {
                    item {
                        Text(text = "DEFENSIVE RECOMMENDATIONS", fontSize = 11.sp, color = SlateGrey, style = MaterialTheme.typography.labelSmall)
                        Spacer(modifier = Modifier.height(6.dp))
                        PartnerOfferCard(offer = offers.first())
                    }
                }
            }
        }
    }
}

@Composable
fun PasswordLeakSection(
    password: String,
    isLoading: Boolean,
    result: com.oopssecurity.osintme.data.model.PasswordLeakResult?,
    error: String?,
    offers: List<com.oopssecurity.osintme.data.model.AffiliateOffer>,
    onPasswordChange: (String) -> Unit,
    onCheckClick: () -> Unit
) {
    var passwordVisible by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            // Privacy guardrail notice
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(CharcoalNavy)
                    .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                    .padding(12.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(imageVector = Icons.Default.Security, contentDescription = null, tint = StatusSafe, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "k-Anonymity Guardrail: Your password NEVER leaves your device. Only the first 5 characters of its SHA-1 hash are queried.",
                        style = MaterialTheme.typography.bodyMedium,
                        fontSize = 11.sp,
                        color = SlateGrey
                    )
                }
            }
        }

        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(CharcoalNavy)
                    .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
                    .padding(14.dp)
            ) {
                Text(
                    text = "ENTER PASSWORD TO EVALUATE",
                    fontSize = 11.sp,
                    color = SlateGrey,
                    style = MaterialTheme.typography.labelSmall
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = onPasswordChange,
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("Enter password to check leaks...", color = MutedSlate, fontSize = 13.sp) },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace, fontSize = 13.sp),
                    visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Icon(
                                imageVector = if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = "Toggle visibility",
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
                        focusedContainerColor = SlateObsidian,
                        unfocusedContainerColor = SlateObsidian
                    ),
                    shape = RoundedCornerShape(8.dp)
                )
                Spacer(modifier = Modifier.height(10.dp))
                Button(
                    onClick = onCheckClick,
                    enabled = password.isNotBlank() && !isLoading,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = SkyCyan, contentColor = SlateObsidian),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), color = SlateObsidian, strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Computing SHA-1 & Querying...")
                    } else {
                        Icon(imageVector = Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Check Password In Leaks", style = MaterialTheme.typography.labelLarge)
                    }
                }
            }
        }

        if (error != null) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(StatusRisk.copy(alpha = 0.15f))
                        .border(1.dp, StatusRisk.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                        .padding(12.dp)
                ) {
                    Text(text = error, color = StatusRisk, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        if (result != null) {
            item {
                val isLeaked = result.isLeaked
                val badgeColor = if (isLeaked) StatusRisk else StatusSafe

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(CharcoalNavy)
                        .border(1.dp, badgeColor.copy(alpha = 0.5f), RoundedCornerShape(10.dp))
                        .padding(16.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = if (isLeaked) Icons.Default.Warning else Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = badgeColor,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = if (isLeaked) "LEAKED IN ${result.leakCount} COMPROMISED RECORDS" else "SAFE: 0 KNOWN LEAKS",
                                style = MaterialTheme.typography.titleMedium,
                                color = badgeColor,
                                fontSize = 14.sp
                            )
                            Text(
                                text = "SHA-1 Hash Prefix: ${result.sha1Prefix}***",
                                style = MaterialTheme.typography.labelSmall,
                                color = SlateGrey
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Text(
                        text = result.securityAdvice,
                        style = MaterialTheme.typography.bodyMedium,
                        color = OffWhite,
                        fontSize = 12.sp
                    )
                }
            }

            if (result.isLeaked && offers.isNotEmpty()) {
                item {
                    Text(text = "PASSWORD MANAGER RECOMMENDATIONS", fontSize = 11.sp, color = SlateGrey, style = MaterialTheme.typography.labelSmall)
                    Spacer(modifier = Modifier.height(6.dp))
                    PartnerOfferCard(offer = offers.first())
                }
            }
        }
    }
}
