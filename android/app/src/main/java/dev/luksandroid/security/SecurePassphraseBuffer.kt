package dev.luksandroid.security

import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger

/**
 * Off-heap, zeroable UTF-8 encoding of the passphrase.
 *
 * Ownership: single-threaded. Create, consume, and close on the same thread.
 * The ByteBuffer is address-only: it is intentionally NOT flipped.
 */
class SecurePassphraseBuffer private constructor(
    private val buffer: ByteBuffer, // direct, unflipped, position == length
    val length: Int,
) : AutoCloseable {

    @Volatile
    private var closed = false

    init {
        require(buffer.isDirect) { "buffer must be direct" }
        outstandingInstances.incrementAndGet()
    }

    companion object {
        private const val TAG = "SecurePassphrase"
        val outstandingInstances = AtomicInteger(0)

        fun of(buffer: ByteBuffer, length: Int): SecurePassphraseBuffer {
            return SecurePassphraseBuffer(buffer, length)
        }

        private fun zero(b: ByteBuffer) {
            for (i in 0 until b.capacity()) {
                b.put(i, 0.toByte())
            }
        }
    }

    /** JNI entry point. Buffer is valid only for the duration of [block]. */
    internal fun <R> withBuffer(block: (ByteBuffer, Int) -> R): R {
        check(!closed) { "buffer already closed" }
        return block(buffer, length)
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        zero(buffer)
        outstandingInstances.decrementAndGet()
    }

    inline fun <R> use(block: (SecurePassphraseBuffer) -> R): R {
        return try {
            block(this)
        } finally {
            close()
        }
    }
}
