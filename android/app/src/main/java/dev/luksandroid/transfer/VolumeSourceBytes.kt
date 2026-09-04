package dev.luksandroid.transfer

import dev.luksandroid.LuksVolume
import java.io.InputStream

/**
 * [SourceBytes] over the drive, for export. The mirror of the SAF-backed
 * source [TreeImporter] reads from: `sourceId` here is the absolute volume
 * path, exactly what [VolumeChildSource] puts in [RawChild.id].
 *
 * Reads through [LuksVolume.readChunk] rather than [LuksVolume.readFile],
 * which caps at a few MiB by default and would quietly truncate anything
 * larger. Streaming also keeps peak memory at one chunk regardless of file
 * size, which matters on a phone exporting a video.
 */
class VolumeSourceBytes(
    private val volume: LuksVolume,
    private val chunkBytes: Int = TreeExporter.CHUNK_SIZE,
) : SourceBytes {

    override fun open(sourceId: String): InputStream = VolumeInputStream(volume, sourceId, chunkBytes)
}

/**
 * Pulls a file off the volume one chunk at a time.
 *
 * Deliberately not backed by a `ByteArray` of the whole file: a chunked reader
 * that materialises everything first is the same bug as [LuksVolume.readFile]'s
 * cap, just with a bigger limit.
 */
private class VolumeInputStream(
    private val volume: LuksVolume,
    private val path: String,
    private val chunkBytes: Int,
) : InputStream() {

    private var offset = 0L
    private var buffer = ByteArray(0)
    private var bufferPos = 0

    /**
     * Fills [buffer] if it is spent. Returns false at end of file.
     *
     * A short read is treated as end of file rather than retried: the native
     * side returns what the extent actually holds, so a chunk shorter than
     * requested means the file ended, and looping on it would spin forever on
     * a zero-length return.
     */
    private fun fill(): Boolean {
        if (bufferPos < buffer.size) return true
        val chunk = volume.readChunk(path, offset, chunkBytes)
        if (chunk.isEmpty()) return false
        buffer = chunk
        bufferPos = 0
        offset += chunk.size
        return true
    }

    override fun read(): Int {
        if (!fill()) return -1
        return buffer[bufferPos++].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (!fill()) return -1
        val n = minOf(len, buffer.size - bufferPos)
        System.arraycopy(buffer, bufferPos, b, off, n)
        bufferPos += n
        return n
    }

    override fun available(): Int = buffer.size - bufferPos
}
