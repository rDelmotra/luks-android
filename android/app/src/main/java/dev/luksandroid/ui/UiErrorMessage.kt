package dev.luksandroid.ui

import dev.luksandroid.LuksException
import dev.luksandroid.Trace
import kotlinx.coroutines.CancellationException
import java.io.FileNotFoundException
import java.io.IOException

/**
 * End-to-end user-facing error message mapping and logging.
 *
 * Security Invariants:
 * 1. NEVER include file names, paths, volume labels, or secrets in user-facing exception messages.
 * 2. ALL exceptions processed through this mapper log through [Trace.err] with the numeric error code
 *    and operation name (without logging sensitive paths/passphrases).
 */
object UiErrorMessage {

    /**
     * Maps numeric error code to a clear, actionable user message.
     */
    fun getBaseMessage(code: Int): String = when (code) {
        LuksException.GENERIC -> "An unexpected error occurred. Please try again."
        LuksException.WRONG_PASSWORD -> "Incorrect passphrase. Please verify and try again."
        LuksException.NOT_LUKS -> "The selected partition is not a valid LUKS encrypted volume."
        LuksException.UNSUPPORTED -> "Unsupported encryption algorithm, key size, or filesystem format."
        LuksException.CORRUPT -> "Drive header or filesystem metadata is damaged or corrupted."
        LuksException.NOT_FOUND -> "The requested file or folder was not found."
        LuksException.TRANSPORT -> "USB communication failed. Check the drive cable and OTG adapter connection."
        LuksException.NEEDS_FSCK -> "The filesystem has unrecovered errors and requires repair (fsck)."
        LuksException.IO -> "Storage I/O error occurred while reading or writing."
        LuksException.BAD_HANDLE -> "The device or volume connection was closed or invalidated."
        LuksException.PANIC -> "An internal error occurred. Please reconnect the drive and try again."
        LuksException.NO_SPACE -> "Not enough free space available on the drive."
        LuksException.WRONG_TARGET -> "The target USB device does not match the active session."
        LuksException.UNVERIFIABLE_TARGET -> "Unable to verify the USB mass-storage interface."
        LuksException.ALREADY_EXISTS -> "An item with this name already exists in the destination folder."
        LuksException.WRITER_BUSY -> "Another write operation is currently in progress. Please wait for it to complete."
        LuksException.ITEM_TOO_LARGE -> "The item is too large for the filesystem tree structure limits."
        LuksException.MUTEX_POISONED -> "Drive state was compromised by a previous error. Please lock and unlock the volume to retry."
        LuksException.CANCELLED -> "The operation was cancelled."
        else -> "An unexpected error occurred (code $code)."
    }

    /**
     * Formats user-facing message with operation context and logs the error safely.
     */
    fun getUserMessage(code: Int, operation: String = ""): String {
        Trace.err(code, operation.ifBlank { "unknown_operation" })
        val baseMsg = getBaseMessage(code)
        return if (operation.isNotBlank()) {
            if (code == LuksException.CANCELLED) {
                "$operation cancelled."
            } else {
                "$operation failed: $baseMsg"
            }
        } else {
            baseMsg
        }
    }

    /**
     * Formats [LuksException] with operation context and logs the error safely.
     */
    fun getUserMessage(e: LuksException, operation: String = ""): String {
        return getUserMessage(e.code, operation)
    }

    /**
     * Maps generic [Throwable] to a safe user message and logs via [Trace.err].
     */
    fun getUserMessage(t: Throwable, operation: String = ""): String {
        val op = operation.ifBlank { "unknown_operation" }
        return when (t) {
            is LuksException -> getUserMessage(t.code, op)
            is CancellationException -> getUserMessage(LuksException.CANCELLED, op)
            is FileNotFoundException -> getUserMessage(LuksException.NOT_FOUND, op)
            is IOException -> getUserMessage(LuksException.IO, op)
            is SecurityException -> {
                Trace.err(LuksException.GENERIC, op)
                if (operation.isNotBlank()) "$operation failed: Permission denied." else "Permission denied."
            }
            is IllegalStateException -> {
                val code = if (t.message?.contains("locking", ignoreCase = true) == true ||
                    t.message?.contains("closed", ignoreCase = true) == true ||
                    t.message?.contains("not unlocked", ignoreCase = true) == true
                ) {
                    LuksException.BAD_HANDLE
                } else {
                    LuksException.GENERIC
                }
                getUserMessage(code, op)
            }
            else -> {
                Trace.err(LuksException.GENERIC, op)
                if (operation.isNotBlank()) {
                    "$operation failed: An unexpected error occurred."
                } else {
                    "An unexpected error occurred."
                }
            }
        }
    }
}
