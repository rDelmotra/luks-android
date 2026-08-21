package dev.luksandroid.security

import android.text.Editable
import android.text.SpannableStringBuilder
import dev.luksandroid.Trace
import java.lang.reflect.Field
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.util.Arrays
import kotlin.text.Charsets

object PassphraseScrubber {

    private const val TAG = "PassphraseScrubber"

    /** Enforced at input time by InputFilter.LengthFilter. */
    const val MAX_PASSPHRASE_CHARS = 512

    /** True if any required reflection mitigation is unavailable. */
    @Volatile
    var degradedScrub: Boolean = false
        private set

    private fun degrade(what: String, t: Throwable) {
        degradedScrub = true
        Trace.e(TAG, "mitigation unavailable: $what (${Trace.throwableSummary(t)})")
    }

    private val mTextField: Field? = runCatching {
        SpannableStringBuilder::class.java.getDeclaredField("mText")
            .apply { isAccessible = true }
    }.onFailure { degrade("SpannableStringBuilder.mText", it) }.getOrNull()

    /** Backing char[] pre-grown past the cap so typing never reallocates. */
    fun newPreSizedEditable(): Editable {
        val filler = CharArray(MAX_PASSPHRASE_CHARS + 16) { '\u0000' }
        return SpannableStringBuilder(String(filler)).also { it.clear() }
    }

    fun extractAndScrub(editable: Editable): SecurePassphraseBuffer {
        val chars: CharArray
        var direct: ByteBuffer? = null
        try {
            val len = editable.length
            require(len in 1..MAX_PASSPHRASE_CHARS) { "invalid passphrase length $len" }

            chars = CharArray(len)
            try {
                editable.getChars(0, len, chars, 0)

                val encoder = Charsets.UTF_8.newEncoder()
                val maxBytes = Math.ceil(len * encoder.maxBytesPerChar().toDouble()).toInt()
                direct = ByteBuffer.allocateDirect(maxBytes)

                val cb = CharBuffer.wrap(chars)
                encoder.encode(cb, direct, true).let { if (!it.isUnderflow) it.throwException() }
                encoder.flush(direct).let { if (!it.isUnderflow) it.throwException() }

                return SecurePassphraseBuffer.of(direct, direct.position())
            } finally {
                Arrays.fill(chars, '\u0000')
            }
        } catch (t: Throwable) {
            direct?.let { b -> for (i in 0 until b.capacity()) b.put(i, 0.toByte()) }
            throw t
        } finally {
            scrub(editable)
        }
    }

    /** Zeroes gap buffer without extracting — cancel/dispose path. */
    fun scrub(editable: Editable) {
        if (editable is SpannableStringBuilder) {
            runCatching { (mTextField?.get(editable) as? CharArray)?.let { Arrays.fill(it, '\u0000') } }
                .onFailure { degrade("mText scrub", it) }
        }
        editable.clear()
    }
}
