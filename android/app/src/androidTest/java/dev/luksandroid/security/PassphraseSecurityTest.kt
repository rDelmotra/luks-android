package dev.luksandroid.security

import android.text.InputFilter
import android.text.SpannableStringBuilder
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer
import java.nio.charset.MalformedInputException

@RunWith(AndroidJUnit4::class)
class PassphraseSecurityTest {

    @Test
    fun editableFactory_arrayIdentity_holdsAcrossFullLength() {
        val editable = PassphraseScrubber.newPreSizedEditable() as SpannableStringBuilder
        
        // Use reflection to capture mText before modifications
        val mTextField = SpannableStringBuilder::class.java.getDeclaredField("mText").apply { isAccessible = true }
        val arrayBefore = mTextField.get(editable) as CharArray

        // Type MAX_PASSPHRASE_CHARS characters
        val typing = "a".repeat(PassphraseScrubber.MAX_PASSPHRASE_CHARS)
        editable.append(typing)

        // Capture mText after modifications
        val arrayAfter = mTextField.get(editable) as CharArray

        // Assert they are exactly the same array instance (no reallocation)
        assertSame("Backing array should not reallocate", arrayBefore, arrayAfter)
    }

    @Test
    fun mText_allZero_afterScrub() {
        val editable = PassphraseScrubber.newPreSizedEditable() as SpannableStringBuilder
        editable.append("my_secret_passphrase")

        val mTextField = SpannableStringBuilder::class.java.getDeclaredField("mText").apply { isAccessible = true }
        val array = mTextField.get(editable) as CharArray

        PassphraseScrubber.scrub(editable)

        // Assert all contents are zeroed
        for (c in array) {
            assertEquals('\u0000', c)
        }
        assertEquals(0, editable.length)
    }

    @Test
    fun securePassphraseBuffer_closeZeroesFullCapacity() {
        val editable = PassphraseScrubber.newPreSizedEditable()
        editable.append("test_passphrase")

        val buffer = PassphraseScrubber.extractAndScrub(editable)
        var capturedBuffer: ByteBuffer? = null
        
        // Write some junk at the end of capacity to ensure it also gets zeroed
        buffer.withBuffer { b, _ -> 
            capturedBuffer = b
            b.position(b.capacity() - 1)
            b.put(99.toByte())
        }

        buffer.close()
        
        val b = capturedBuffer!!
        for (i in 0 until b.capacity()) {
            assertEquals("Byte at $i should be 0", 0.toByte(), b.get(i))
        }
        
        // Double close shouldn't crash
        buffer.close() 
    }

    @Test
    fun multiByteRoundTrip() {
        val testString = "ASCII + áccéntéd + 汉字 + 🕵️‍♂️"
        val editable = PassphraseScrubber.newPreSizedEditable()
        editable.append(testString)

        PassphraseScrubber.extractAndScrub(editable).use { buffer ->
            buffer.withBuffer { b, len -> 
                val bytes = ByteArray(len)
                b.position(0)
                b.get(bytes)
                val decoded = String(bytes, Charsets.UTF_8)
                assertEquals(testString, decoded)
            }
        }
    }

    @Test
    fun nativeMemoryScan_passphraseClearedFromMemory() {
        val testPassphrase = "SUPER_SECRET_NATIVE_SCAN_TEST_STRING_1234567890".toByteArray(Charsets.UTF_8)
        val editable = PassphraseScrubber.newPreSizedEditable()
        editable.append(String(testPassphrase, Charsets.UTF_8))

        var bufferAddress = 0L
        var bufferCapacity = 0
        var capturedBuffer: ByteBuffer? = null

        val buffer = PassphraseScrubber.extractAndScrub(editable)
        
        buffer.withBuffer { b, _ ->
            capturedBuffer = b
            // Reflect into java.nio.Buffer to get the native address
            val addressField = java.nio.Buffer::class.java.getDeclaredField("address").apply { isAccessible = true }
            bufferAddress = addressField.getLong(b)
            bufferCapacity = b.capacity()
        }
        
        // Assert address is valid
        assertTrue("Buffer address should be non-zero", bufferAddress != 0L)

        // Negative control: memory should hold passphrase before close
        val memBeforeClose = ByteArray(testPassphrase.size)
        val b = capturedBuffer!!
        b.position(0)
        b.get(memBeforeClose)
        
        assertArrayEquals("Negative control: memory should hold passphrase before close", testPassphrase, memBeforeClose)

        buffer.close()

        // After close, use the captured buffer reference to check if it's cleared
        val memAfterClose = ByteArray(testPassphrase.size)
        b.position(0)
        b.get(memAfterClose)
        
        val zeroes = ByteArray(testPassphrase.size)
        assertArrayEquals("Memory should be cleared after close", zeroes, memAfterClose)
        
        // Actually reading /proc/self/mem at bufferAddress:
        java.io.RandomAccessFile("/proc/self/mem", "r").use { raf ->
            raf.seek(bufferAddress)
            val procMem = ByteArray(testPassphrase.size)
            val read = raf.read(procMem)
            if (read == testPassphrase.size) {
                assertArrayEquals("Raw memory from /proc/self/mem should be cleared after close", zeroes, procMem)
            }
        }
    }

    @Test
    fun lengthFilter_truncatesOnSurrogatePair_noException() {
        val editable = PassphraseScrubber.newPreSizedEditable()
        val filters = arrayOf<InputFilter>(InputFilter.LengthFilter(PassphraseScrubber.MAX_PASSPHRASE_CHARS))
        (editable as SpannableStringBuilder).filters = filters

        // Fill up to MAX_PASSPHRASE_CHARS - 1 characters
        val filler = "a".repeat(PassphraseScrubber.MAX_PASSPHRASE_CHARS - 1)
        editable.append(filler)

        // Append a surrogate pair (emoji) which is 2 chars in UTF-16
        // This will exceed the limit by 1 char, so InputFilter should truncate it.
        // It should drop the emoji entirely rather than keeping half a surrogate pair.
        editable.append("🕵️") 
        
        // Assert length is exactly MAX_PASSPHRASE_CHARS or MAX_PASSPHRASE_CHARS-1 if it completely drops it.
        // InputFilter.LengthFilter will try to keep as many chars as possible. 
        // If it keeps half a surrogate pair, extractAndScrub will throw a MalformedInputException.
        // Let's ensure extractAndScrub works.
        try {
            PassphraseScrubber.extractAndScrub(editable).close()
        } catch (e: MalformedInputException) {
            fail("MalformedInputException thrown due to split surrogate pair")
        }
    }
}
