package dev.luksandroid.ui

import android.text.Editable
import android.text.InputFilter
import android.text.InputType
import android.text.TextWatcher
import android.view.ActionMode
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import dev.luksandroid.security.PassphraseScrubber

@Composable
fun SecurePassphraseField(
    onEditableReady: (Editable) -> Unit,
    onHasContentChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val textColor = MaterialTheme.colorScheme.onSurface.toArgb()
    val hintColor = MaterialTheme.colorScheme.onSurfaceVariant.toArgb()

    val noActionMode = remember {
        object : ActionMode.Callback {
            override fun onCreateActionMode(mode: ActionMode?, menu: Menu?): Boolean = false
            override fun onPrepareActionMode(mode: ActionMode?, menu: Menu?): Boolean = false
            override fun onActionItemClicked(mode: ActionMode?, item: MenuItem?): Boolean = false
            override fun onDestroyActionMode(mode: ActionMode?) {}
        }
    }

    var activeEditable: Editable? = remember { null }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .border(
                width = 1.dp,
                color = MaterialTheme.colorScheme.outline,
                shape = RoundedCornerShape(4.dp)
            )
            .padding(horizontal = 12.dp, vertical = 12.dp)
    ) {
        AndroidView(
            factory = { context ->
                EditText(context).apply {
                    setEditableFactory(object : Editable.Factory() {
                        override fun newEditable(source: CharSequence): Editable {
                            return PassphraseScrubber.newPreSizedEditable().also { it.append(source) }
                        }
                    })

                    filters = arrayOf(InputFilter.LengthFilter(PassphraseScrubber.MAX_PASSPHRASE_CHARS))
                    inputType = InputType.TYPE_CLASS_TEXT or
                            InputType.TYPE_TEXT_VARIATION_PASSWORD or
                            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or
                            0x01000000 // InputType.TYPE_TEXT_FLAG_NO_PERSONALIZED_LEARNING

                    importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                    isSaveEnabled = false
                    background = null // transparent, styled by parent Box
                    setTextColor(textColor)
                    setHintTextColor(hintColor)
                    hint = "Passphrase"
                    maxLines = 1

                    customSelectionActionModeCallback = noActionMode
                    customInsertionActionModeCallback = noActionMode

                    val currentEditable = text
                    activeEditable = currentEditable
                    if (currentEditable != null) {
                        onEditableReady(currentEditable)
                    }

                    addTextChangedListener(object : TextWatcher {
                        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                        override fun afterTextChanged(s: Editable?) {
                            onHasContentChange(s?.isNotEmpty() == true)
                        }
                    })
                }
            },
            modifier = Modifier.fillMaxWidth()
        )
    }

    DisposableEffect(Unit) {
        onDispose {
            activeEditable?.let { PassphraseScrubber.scrub(it) }
        }
    }
}
