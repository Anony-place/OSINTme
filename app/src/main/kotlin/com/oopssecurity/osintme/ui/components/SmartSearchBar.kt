package com.oopssecurity.osintme.ui.components

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
import com.oopssecurity.osintme.ui.theme.SurfaceElevated
import com.oopssecurity.osintme.util.InputClassifier
import com.oopssecurity.osintme.util.InputType

@Composable
fun SmartSearchBar(
    query: String,
    onQueryChange: (String) -> Unit,
    onScanClick: (query: String, type: InputType) -> Unit,
    modifier: Modifier = Modifier
) {
    val detectedType = remember(query) { InputClassifier.classify(query) }
    val context = LocalContext.current
    val focusManager = LocalFocusManager.current

    val sampleQueries = listOf(
        "github.com" to InputType.DOMAIN,
        "1.1.1.1" to InputType.IP_ADDRESS,
        "torvalds" to InputType.USERNAME,
        "Linus Torvalds" to InputType.GENERIC_KEYWORD,
        "+1 415 555 2671" to InputType.PHONE_NUMBER
    )

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CharcoalNavy)
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp))
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "ONE-SHOT TARGET DOSSIER",
                style = MaterialTheme.typography.labelSmall,
                color = SkyCyan,
                fontFamily = MonoFontFamily
            )

            Row(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(SurfaceElevated)
                    .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                    .clickable {
                        runCatching {
                            val clipMgr = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val pasted = clipMgr.primaryClip?.takeIf { it.itemCount > 0 }
                                ?.getItemAt(0)?.text?.toString()?.trim().orEmpty()
                            if (pasted.isNotEmpty()) onQueryChange(pasted)
                        }
                    }
                    .padding(horizontal = 10.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Default.ContentPaste,
                    contentDescription = "Paste from clipboard",
                    tint = SoftIndigo,
                    modifier = Modifier.size(13.dp)
                )
                Spacer(modifier = Modifier.width(5.dp))
                Text(
                    text = "Paste",
                    fontSize = 11.sp,
                    color = SoftIndigo,
                    fontWeight = FontWeight.Medium
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        OutlinedTextField(
            value = query,
            onValueChange = onQueryChange,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("universal_search_input"),
            placeholder = {
                Text(
                    text = "Domain, IP, email, handle, name/org, hash, or URL...",
                    fontSize = 13.sp,
                    color = MutedSlate
                )
            },
            singleLine = true,
            textStyle = MaterialTheme.typography.bodyMedium.copy(
                fontFamily = MonoFontFamily,
                color = OffWhite,
                fontWeight = FontWeight.Medium
            ),
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Search,
                    contentDescription = null,
                    tint = if (query.isNotEmpty()) SkyCyan else MutedSlate,
                    modifier = Modifier.size(20.dp)
                )
            },
            trailingIcon = {
                if (query.isNotEmpty()) {
                    IconButton(onClick = { onQueryChange("") }) {
                        Icon(
                            imageVector = Icons.Default.Clear,
                            contentDescription = "Clear target",
                            tint = SlateGrey,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            },
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Text,
                imeAction = ImeAction.Search
            ),
            keyboardActions = KeyboardActions(
                onSearch = {
                    if (query.isNotBlank()) {
                        focusManager.clearFocus()
                        onScanClick(query.trim(), detectedType)
                    }
                }
            ),
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

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(DarkerSurface)
                    .border(1.dp, CardBorder, RoundedCornerShape(8.dp))
                    .padding(horizontal = 10.dp, vertical = 7.dp)
            ) {
                Text(
                    text = "DOSSIER: ",
                    fontSize = 10.sp,
                    color = MutedSlate,
                    fontFamily = MonoFontFamily
                )
                Text(
                    text = if (query.isNotBlank()) detectedType.label.uppercase() else "AUTO-DETECT",
                    fontSize = 11.sp,
                    color = if (query.isNotBlank()) SkyCyan else SlateGrey,
                    fontFamily = MonoFontFamily,
                    fontWeight = FontWeight.Bold
                )
            }

            Button(
                onClick = {
                    if (query.isNotBlank()) {
                        focusManager.clearFocus()
                        onScanClick(query.trim(), detectedType)
                    }
                },
                enabled = query.isNotBlank(),
                modifier = Modifier
                    .heightIn(min = 44.dp)
                    .testTag("universal_scan_button"),
                colors = ButtonDefaults.buttonColors(
                    containerColor = EmeraldPrimary,
                    contentColor = PureWhite,
                    disabledContainerColor = SurfaceElevated,
                    disabledContentColor = MutedSlate
                ),
                shape = RoundedCornerShape(10.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Radar,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "Full Dossier",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 13.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            sampleQueries.forEach { (sample, type) ->
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(SurfaceElevated)
                        .border(1.dp, CardBorder, RoundedCornerShape(6.dp))
                        .clickable {
                            onQueryChange(sample)
                            onScanClick(sample, type)
                        }
                        .padding(horizontal = 10.dp, vertical = 6.dp)
                ) {
                    Text(
                        text = if (sample.length > 26) sample.take(26) + "…" else sample,
                        fontSize = 11.sp,
                        color = SlateGrey,
                        fontFamily = MonoFontFamily
                    )
                }
            }
        }
    }
}
