package dev.luksandroid.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp

fun validateNewName(newName: String, currentName: String): String? {
    val trimmed = newName.trim()
    return when {
        trimmed.isEmpty() -> "Name cannot be empty"
        trimmed == currentName -> "New name must be different from current name"
        trimmed == "." || trimmed == ".." -> "Name cannot be '.' or '..'"
        trimmed.contains('/') || trimmed.contains('\\') -> "Name cannot contain '/' or '\\'"
        trimmed.contains('\u0000') -> "Name cannot contain null characters"
        trimmed.toByteArray(Charsets.UTF_8).size > 255 -> "Name exceeds maximum length (255 bytes)"
        else -> null
    }
}

@Composable
fun RenameDialog(
    currentName: String,
    isDir: Boolean,
    onDismissRequest: () -> Unit,
    onConfirm: (newName: String) -> Unit,
    isRenaming: Boolean = false,
    errorMessage: String? = null,
) {
    // Select name part excluding extension for regular files
    val initialSelection = remember(currentName) {
        val dotIndex = if (!isDir) currentName.lastIndexOf('.') else -1
        val end = if (dotIndex > 0) dotIndex else currentName.length
        TextRange(0, end)
    }

    var textFieldValue by remember {
        mutableStateOf(
            TextFieldValue(
                text = currentName,
                selection = initialSelection,
            )
        )
    }

    val focusRequester = remember { FocusRequester() }
    val validationError = remember(textFieldValue.text, currentName) {
        validateNewName(textFieldValue.text, currentName)
    }
    val isValid = textFieldValue.text.isNotBlank() && validationError == null

    LaunchedEffect(Unit) {
        focusRequester.requestFocus()
    }

    AlertDialog(
        onDismissRequest = { if (!isRenaming) onDismissRequest() },
        title = {
            Text(
                text = if (isDir) "Rename Folder" else "Rename File",
                style = MaterialTheme.typography.titleLarge,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = textFieldValue,
                    onValueChange = { textFieldValue = it },
                    label = { Text(if (isDir) "Folder Name" else "File Name") },
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
                    enabled = !isRenaming,
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(focusRequester),
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (isValid && !isRenaming) {
                        onConfirm(textFieldValue.text.trim())
                    }
                },
                enabled = isValid && !isRenaming,
            ) {
                if (isRenaming) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                        Text("Renaming…")
                    }
                } else {
                    Text("Rename")
                }
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismissRequest,
                enabled = !isRenaming,
            ) {
                Text("Cancel")
            }
        },
    )
}
