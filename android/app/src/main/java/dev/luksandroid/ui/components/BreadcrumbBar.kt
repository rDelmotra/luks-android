package dev.luksandroid.ui.components

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Home
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

data class BreadcrumbSegment(
    val name: String,
    val path: String,
    val isLast: Boolean,
)

/**
 * Parses a Unix-style absolute path into breadcrumb segments.
 * e.g., "/media/photos" -> [("/", "/"), ("media", "/media"), ("photos", "/media/photos")]
 */
fun parseBreadcrumbs(path: String): List<BreadcrumbSegment> {
    val normalized = "/" + path.trim('/').let { if (it.isEmpty()) "" else it }
    if (normalized == "/") {
        return listOf(BreadcrumbSegment(name = "/", path = "/", isLast = true))
    }

    val parts = normalized.split('/').filter { it.isNotEmpty() }
    val segments = mutableListOf<BreadcrumbSegment>()

    // Root crumb
    segments.add(BreadcrumbSegment(name = "/", path = "/", isLast = false))

    var accumulated = ""
    parts.forEachIndexed { index, part ->
        accumulated += "/$part"
        val isLast = index == parts.lastIndex
        segments.add(BreadcrumbSegment(name = part, path = accumulated, isLast = isLast))
    }

    return segments
}

/**
 * Computes parent path of a directory.
 */
fun parentOfPath(path: String): String {
    val trimmed = path.trimEnd('/')
    if (trimmed.isEmpty() || trimmed == "/") return "/"
    val parent = trimmed.substringBeforeLast('/')
    return if (parent.isEmpty()) "/" else parent
}

@Composable
fun BreadcrumbBar(
    currentPath: String,
    onNavigate: (String) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val scrollState = rememberScrollState()
    val segments = remember(currentPath) { parseBreadcrumbs(currentPath) }
    val isRoot = currentPath == "/" || currentPath.isEmpty()

    LaunchedEffect(currentPath) {
        scrollState.animateScrollTo(scrollState.maxValue)
    }

    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        shape = RoundedCornerShape(8.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (!isRoot) {
                IconButton(
                    onClick = { onNavigate(parentOfPath(currentPath)) },
                    enabled = enabled,
                    modifier = Modifier.size(36.dp),
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = "Navigate Up",
                        modifier = Modifier.size(20.dp),
                        tint = if (enabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
                    )
                }
            }

            Row(
                modifier = Modifier
                    .weight(1f)
                    .horizontalScroll(scrollState)
                    .padding(horizontal = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                segments.forEach { segment ->
                    if (segment.name == "/" && segment.path == "/") {
                        TextButton(
                            onClick = { if (!segment.isLast) onNavigate("/") },
                            enabled = enabled && !segment.isLast,
                            shape = RoundedCornerShape(6.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Default.Home,
                                contentDescription = "Root Directory",
                                modifier = Modifier.size(18.dp),
                                tint = if (segment.isLast) {
                                    MaterialTheme.colorScheme.primary
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                },
                            )
                        }
                    } else {
                        Text(
                            text = "›",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                            fontWeight = FontWeight.Bold,
                        )

                        if (segment.isLast) {
                            Surface(
                                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f),
                                shape = RoundedCornerShape(6.dp),
                            ) {
                                Text(
                                    text = segment.name,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        } else {
                            TextButton(
                                onClick = { onNavigate(segment.path) },
                                enabled = enabled,
                                shape = RoundedCornerShape(6.dp),
                            ) {
                                Text(
                                    text = segment.name,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
