package dev.luksandroid.ui

import dev.luksandroid.LuksException
import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.FileNotFoundException
import java.io.IOException

class UiErrorMessageTest {

    /**
     * Verify all 19 LuksException error codes map to distinct, clear, user-friendly messages.
     */
    @Test
    fun testAll19LuksErrorCodesMapped() {
        val codes = listOf(
            LuksException.GENERIC to "unexpected",
            LuksException.WRONG_PASSWORD to "passphrase",
            LuksException.NOT_LUKS to "valid LUKS",
            LuksException.UNSUPPORTED to "Unsupported",
            LuksException.CORRUPT to "corrupted",
            LuksException.NOT_FOUND to "not found",
            LuksException.TRANSPORT to "USB communication",
            LuksException.NEEDS_FSCK to "fsck",
            LuksException.IO to "I/O error",
            LuksException.BAD_HANDLE to "closed or invalidated",
            LuksException.PANIC to "internal error",
            LuksException.NO_SPACE to "free space",
            LuksException.WRONG_TARGET to "target USB",
            LuksException.UNVERIFIABLE_TARGET to "verify the USB",
            LuksException.ALREADY_EXISTS to "already exists",
            LuksException.WRITER_BUSY to "write operation is currently in progress",
            LuksException.ITEM_TOO_LARGE to "too large",
            LuksException.MUTEX_POISONED to "Drive state was compromised",
            LuksException.CANCELLED to "cancelled",
        )

        assertEquals("Must test exactly 19 error codes", 19, codes.size)

        for ((code, keyword) in codes) {
            val msg = UiErrorMessage.getBaseMessage(code)
            assertTrue("Message for code $code should not be blank", msg.isNotBlank())
            assertTrue(
                "Message for code $code ('$msg') should contain keyword '$keyword'",
                msg.contains(keyword, ignoreCase = true),
            )
        }
    }

    /**
     * Security Invariant: NEVER include file names, paths, or secrets in user-facing exception messages.
     */
    @Test
    fun testSecurityInvariant_noSensitivePathsOrSecretsInUserMessage() {
        val sensitivePath = "/Volumes/Encrypted/passwords/bank_creds.kdbx"
        val secretPassphrase = "SuperSecretMasterPassword123!"

        // An exception that internally had sensitive details in its message
        val exception = LuksException(
            "Failed accessing $sensitivePath with pass $secretPassphrase",
            LuksException.WRONG_PASSWORD,
        )

        val userMessage = UiErrorMessage.getUserMessage(exception, "Unlock")

        assertFalse("User message must NOT leak sensitive paths", userMessage.contains(sensitivePath))
        assertFalse("User message must NOT leak passphrases", userMessage.contains(secretPassphrase))
        assertFalse("User message must NOT contain file extensions", userMessage.contains(".kdbx"))
        assertTrue(userMessage.contains("Unlock failed:"))
        assertTrue(userMessage.contains("Incorrect passphrase"))
    }

    @Test
    fun testOperationContextFormatting() {
        val exportErr = LuksException("disk write failed", LuksException.NO_SPACE)
        val exportMsg = UiErrorMessage.getUserMessage(exportErr, "Export")
        assertEquals("Export failed: Not enough free space available on the drive.", exportMsg)

        val cancelErr = LuksException("cancelled by user", LuksException.CANCELLED)
        val cancelMsg = UiErrorMessage.getUserMessage(cancelErr, "Import")
        assertEquals("Import cancelled.", cancelMsg)

        val noOpMsg = UiErrorMessage.getUserMessage(LuksException.CORRUPT)
        assertEquals("Drive header or filesystem metadata is damaged or corrupted.", noOpMsg)
    }

    @Test
    fun testNonLuksExceptionMapping() {
        val fnf = FileNotFoundException("file /a/b/c not found")
        val fnfMsg = UiErrorMessage.getUserMessage(fnf, "Open")
        assertEquals("Open failed: The requested file or folder was not found.", fnfMsg)

        val io = IOException("broken pipe")
        val ioMsg = UiErrorMessage.getUserMessage(io, "Read")
        assertEquals("Read failed: Storage I/O error occurred while reading or writing.", ioMsg)

        val cancel = CancellationException("coroutine cancelled")
        val cancelMsg = UiErrorMessage.getUserMessage(cancel, "Transfer")
        assertEquals("Transfer cancelled.", cancelMsg)

        val sec = SecurityException("permission denied")
        val secMsg = UiErrorMessage.getUserMessage(sec, "Access")
        assertEquals("Access failed: Permission denied.", secMsg)

        val unknown = RuntimeException("something weird")
        val unknownMsg = UiErrorMessage.getUserMessage(unknown, "Operation")
        assertEquals("Operation failed: An unexpected error occurred.", unknownMsg)
    }
}
