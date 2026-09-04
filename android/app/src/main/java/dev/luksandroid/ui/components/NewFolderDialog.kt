package dev.luksandroid.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.unit.dp

fun validateFolderName(name: String): String? {
    val trimmed = name.trim()
    return when {
        trimmed.isEmpty() -> "Folder name cannot be empty"
        trimmed == "." || trimmed == ".." -> "Folder name cannot be '.' or '..'"
        trimmed.contains('/') || trimmed.contains('\\') -> "Folder name cannot contain '/' or '\\'"
        trimmed.contains('\u0000') -> "Folder name cannot contain null characters"
        trimmed.toByteArray(Charsets.UTF_8).size > 255 -> "Folder name exceeds maximum length (255 bytes)"
        else -> null
    }
}

@Composable
fun NewFolderDialog(
    onDismissRequest: () -> Unit,
    onConfirm: (folderName: String) -> Unit,
    isCreating: Boolean = false,
    errorMessage: String? = null,
) {
    var folderName by remember { mutableStateOf("") }
    val focusRequester = remember { FocusRequester() }
    val validationError = remember(folderName) {
        if (folderName.isEmpty()) null else validateFolderName(folderName)
    }
    val isValid = folderName.isNotBlank() && validationError == null

    LaunchedEffect(Unit) {
        focusRequester.requestFocus()
    }

    AlertDialog(
        onDismissRequest = { if (!isCreating) onDismissRequest() },
        title = {
            Text(text = "New Folder", style = MaterialTheme.typography.titleLarge)
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = folderName,
                    onValueChange = { folderName = it },
                    label = { Text("Folder Name") },
                    singleLine = true,
                    isError = validationError != null || errorMessage != null,
                    supportingText = {
                        val error = validationError ?: errorMessage
                        if (error != null) {
                            Text(
                                text = error,
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    },
                    enabled = !isCreating,
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(focusRequester),
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (isValid && !isCreating) {
                        onConfirm(folderName.trim())
                    }
                },
                enabled = isValid && !isCreating,
            ) {
                if (isCreating) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                        Text("Creating…")
                    }
                } else {
                    Text("Create")
                }
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismissRequest,
                enabled = !isCreating,
            ) {
                Text("Cancel")
            }
        },
    )
}
