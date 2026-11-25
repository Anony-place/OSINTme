package com.oopssecurity.osintme.ui.components

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.MonoFontFamily
import com.oopssecurity.osintme.ui.theme.MutedSlate
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.TechCodeBackground
import com.oopssecurity.osintme.util.SafeBrowserLauncher

@Composable
fun CodeBlock(
    text: String = "",
    code: String = text,
    title: String? = null,
    modifier: Modifier = Modifier
) {
    val displayContent = if (code.isNotEmpty()) code else text
    val context = LocalContext.current

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(TechCodeBackground)
            .border(1.dp, CardBorder, RoundedCornerShape(10.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (title != null) {
                Text(
                    text = title,
                    color = MutedSlate,
                    style = MaterialTheme.typography.labelSmall
                )
            } else {
                Spacer(modifier = Modifier.size(1.dp))
            }

            IconButton(
                onClick = {
                    SafeBrowserLauncher.copyToClipboard(context, title ?: "OSINTme", displayContent, isSensitive = true)
                    Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.size(36.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.ContentCopy,
                    contentDescription = "Copy to clipboard",
                    tint = SkyCyan,
                    modifier = Modifier.size(16.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(4.dp))

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
        ) {
            Text(
                text = displayContent,
                fontFamily = MonoFontFamily,
                fontSize = 12.sp,
                color = SkyCyan,
                lineHeight = 18.sp
            )
        }
    }
}
