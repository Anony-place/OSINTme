package com.oopssecurity.osintme.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.oopssecurity.osintme.ui.theme.CardBorder
import com.oopssecurity.osintme.ui.theme.CharcoalNavy
import com.oopssecurity.osintme.ui.theme.OffWhite
import com.oopssecurity.osintme.ui.theme.SkyCyan
import com.oopssecurity.osintme.ui.theme.SlateGrey
import com.oopssecurity.osintme.ui.theme.SlateObsidian

@Composable
fun AppHeader(
    title: String,
    subtitle: String? = null,
    showBackButton: Boolean = false,
    onBackClick: (() -> Unit)? = null,
    showMenuButton: Boolean = false,
    onMenuClick: (() -> Unit)? = null,
    trailingContent: (@Composable () -> Unit)? = null
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(SlateObsidian)
            .statusBarsPadding()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                if (showBackButton && onBackClick != null) {
                    IconButton(
                        onClick = onBackClick,
                        modifier = Modifier
                            .size(48.dp)
                            .testTag("header_back_button")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Navigate back",
                            tint = OffWhite
                        )
                    }
                    Spacer(modifier = Modifier.width(4.dp))
                } else if (showMenuButton && onMenuClick != null) {
                    IconButton(
                        onClick = onMenuClick,
                        modifier = Modifier
                            .size(48.dp)
                            .testTag("header_menu_button")
                    ) {
                        Icon(
                            imageVector = Icons.Default.Menu,
                            contentDescription = "Open navigation menu",
                            tint = SkyCyan
                        )
                    }
                    Spacer(modifier = Modifier.width(4.dp))
                } else {
                    Box(
                        modifier = Modifier
                            .padding(start = 4.dp)
                            .size(40.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(CharcoalNavy)
                            .border(1.dp, CardBorder, RoundedCornerShape(10.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = "OSINTme Shield",
                            tint = SkyCyan,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                }

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleLarge,
                        color = OffWhite,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    if (!subtitle.isNullOrBlank()) {
                        Text(
                            text = subtitle,
                            style = MaterialTheme.typography.bodySmall,
                            color = SlateGrey,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }

            if (trailingContent != null) {
                Spacer(modifier = Modifier.width(8.dp))
                trailingContent()
            }
        }
        HorizontalDivider(color = CardBorder.copy(alpha = 0.7f), thickness = 1.dp)
    }
}
