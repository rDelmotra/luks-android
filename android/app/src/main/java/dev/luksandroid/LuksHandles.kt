package dev.luksandroid

import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbInterface
import org.json.JSONObject

/**
 * Kotlin-side owners for the two native handles.
 *
 * The handles are bare `Long`s across JNI. Wrapping them in [AutoCloseable]
 * types is what keeps "who frees this, and in what order" from being a comment
 * that drifts out of date.
 *
 * Closing order is not arbitrary: the Rust side reads through the file
 * descriptor owned by [UsbDeviceConnection], so the connection must outlive
 * every native handle built on it. [LuksDevice.close] enforces that.
 */

data class PartitionInfo(
    val index: Int,
    val name: String,
    val offsetBytes: Long,
    val sizeBytes: Long,
    val isLuks: Boolean,
    val luksVersion: Int?,
) {
    val label: String
        get() = buildString {
            append("#$index")
            if (name.isNotBlank()) append(" $name")
            append(" · ${formatSize(sizeBytes)}")
            if (isLuks) append(" · LUKS$luksVersion")
        }
}

data class DeviceInfo(
    val vendor: String,
    val product: String,
    val blockSize: Int,
    val sizeBytes: Long,
    val tableKind: String,
    val partitions: List<PartitionInfo>,
    /**
     * What the drive answered when asked which write commands it accepts,
     * probed once at open. Null in a build without the write path, which is
     * most of them.
     *
     * Carries opcode names, a write-protect bit and sense codes — nothing from
     * the volume — so unlike almost everything else here it is safe to log.
     */
    val writeProbe: String?,
)

data class VolumeInfo(
    val label: String,
    val uuid: String,
    val blockSize: Int,
    val sizeBytes: Long,
    /** "ext4" or "btrfs" — decided natively by signature, not by us. */
    val fsType: String,
    /** Empty on ext4, which has no such concept. */
    val subvolumes: List<SubvolumeInfo>,
)

data class StatFsInfo(
    val totalBytes: Long,
    val freeBytes: Long,
    val availableBytes: Long,
    val totalInodes: Long,
    val freeInodes: Long,
    val blockSize: Int,
)

/**
 * A btrfs subvolume: a separate filesystem tree inside the same filesystem.
 * [path] is where it appears when browsing from the top level, so it can be
 * navigated to directly.
 */
data class SubvolumeInfo(
    val id: Long,
    val name: String,
    val path: String,
    val readOnly: Boolean,
)

/**
 * [isSubvolume] marks a btrfs subvolume boundary. It is still a directory and
 * opens like one; the flag exists because it is a different tree underneath,
 * and may be a read-only snapshot.
 */
data class Entry(val name: String, val type: String, val isSubvolume: Boolean = false) {
    val isDir: Boolean get() = type == "dir"
}

/** A drive that has been identified but not decrypted. */
class LuksDevice internal constructor(
    private var handle: Long,
    private val connection: UsbDeviceConnection,
    private val usbInterface: UsbInterface,
) : AutoCloseable {

    val info: DeviceInfo = parseDeviceInfo(LuksNative.nativeDeviceInfo(handle))

    /** Partitions carrying a LUKS header, found by probing, not by type GUID. */
    val luksPartitions: List<PartitionInfo> get() = info.partitions.filter { it.isLuks }

    /**
     * Derives the master key and mounts the filesystem inside [partitionOffset].
     *
     * Blocking and slow — seconds of CPU and up to a gigabyte of allocation.
     * Call from a background thread with [UnlockService] running.
     *
     * [password] buffer is valid for the duration of this call and zeroed on close.
     */
    fun unlock(partitionOffset: Long, password: dev.luksandroid.security.SecurePassphraseBuffer): LuksVolume {
        check(handle != 0L) { "device is closed" }
        require(password.length > 0) { "empty passphrase" }
        return password.withBuffer { buf, len ->
            LuksVolume(LuksNative.nativeUnlock(handle, partitionOffset, buf, len))
        }
    }

    /** Raw transport throughput, bypassing LUKS and the filesystem entirely. */
    data class Benchmark(
        val bytes: Long,
        val elapsedMs: Long,
        val bytesPerSec: Long,
        val maxTransfer: Int?,
    ) {
        val summary: String
            get() = "raw %.1f MiB/s (%s in %d ms)\ntransfer limit: %s".format(
                bytesPerSec.toDouble() / (1L shl 20),
                formatSize(bytes),
                elapsedMs,
                maxTransfer?.let { formatSize(it.toLong()) } ?: "unknown",
            )
    }

    fun benchmark(bytes: Long = 128L shl 20, chunkBytes: Int = 1 shl 20): Benchmark {
        check(handle != 0L) { "device is closed" }
        val j = JSONObject(LuksNative.nativeBenchmarkRead(handle, bytes, chunkBytes))
        return Benchmark(
            bytes = j.getLong("bytes"),
            elapsedMs = j.getLong("elapsedMs"),
            bytesPerSec = j.getLong("bytesPerSec"),
            maxTransfer = if (j.isNull("maxTransfer")) null else j.getInt("maxTransfer"),
        )
    }

    /**
     * The write counterpart, for separating "our write path is slow" from
     * "this drive writes slowly". Lands past every partition, so it destroys
     * nothing that is addressable through a filesystem.
     */
    fun benchmarkWrite(bytes: Long = 64L shl 20, chunkBytes: Int = 1 shl 20): Benchmark {
        check(handle != 0L) { "device is closed" }
        val j = JSONObject(LuksNative.nativeBenchmarkWrite(handle, bytes, chunkBytes))
        return Benchmark(
            bytes = j.getLong("bytes"),
            elapsedMs = j.getLong("elapsedMs"),
            bytesPerSec = j.getLong("bytesPerSec"),
            maxTransfer = if (j.isNull("maxTransfer")) null else j.getInt("maxTransfer"),
        )
    }

    override fun close() {
        // Native first: it reads through the connection's file descriptor, and
        // releasing the interface or closing the connection first would leave
        // Rust holding a descriptor the kernel may have reissued.
        if (handle != 0L) {
            LuksNative.nativeCloseDevice(handle)
            handle = 0
        }
        runCatching { connection.releaseInterface(usbInterface) }
        runCatching { connection.close() }
    }
}

/** An unlocked volume with a mounted filesystem. */
class LuksVolume internal constructor(private var handle: Long) : AutoCloseable {
    private val activeWriters = mutableSetOf<FileWriter>()

    val info: VolumeInfo = JSONObject(LuksNative.nativeVolumeInfo(handle)).let {
        val subvols = it.optJSONArray("subvolumes")
        VolumeInfo(
            // A volume with no label reports JSON null, and optString would
            // turn that into the literal text "null" on screen.
            label = if (it.isNull("label")) "" else it.optString("label"),
            uuid = it.optString("uuid"),
            blockSize = it.optInt("blockSize"),
            sizeBytes = it.optLong("sizeBytes"),
            fsType = it.optString("fsType"),
            subvolumes = (0 until (subvols?.length() ?: 0)).map { i ->
                val s = subvols!!.getJSONObject(i)
                SubvolumeInfo(
                    id = s.optLong("id"),
                    name = s.optString("name"),
                    path = s.optString("path"),
                    readOnly = s.optBoolean("readOnly"),
                )
            },
        )
    }

    fun listDir(path: String): List<Entry> {
        check(handle != 0L) { "volume is closed" }
        val entries = JSONObject(LuksNative.nativeListDir(handle, path)).getJSONArray("entries")
        return (0 until entries.length()).map { i ->
            val e = entries.getJSONObject(i)
            Entry(
                e.getString("name"),
                e.getString("type"),
                e.optBoolean("isSubvolume"),
            )
        }
    }

    fun fileSize(path: String): Long {
        check(handle != 0L) { "volume is closed" }
        return JSONObject(LuksNative.nativeFileInfo(handle, path)).getLong("size")
    }

    fun readFile(path: String, maxBytes: Long = 4L * 1024 * 1024): ByteArray {
        check(handle != 0L) { "volume is closed" }
        return LuksNative.nativeReadFile(handle, path, maxBytes)
    }

    /**
     * Up to [len] bytes at [offset]. A result shorter than [len] means end of
     * file; an empty result means there was nothing left.
     *
     * This is the only way to move a large file: [readFile] has to materialise
     * the whole thing as a Java `byte[]`, which the app heap will not survive
     * for a multi-gigabyte file.
     */
    fun readChunk(path: String, offset: Long, len: Int): ByteArray {
        check(handle != 0L) { "volume is closed" }
        return LuksNative.nativeReadChunk(handle, path, offset, len)
    }

    /** [sha256] result: digest plus the throughput it was measured at. */
    data class Digest(val sha256: String, val bytes: Long, val elapsedMs: Long, val bytesPerSec: Long)

    fun sha256(path: String, chunkBytes: Int = 0): Digest {
        check(handle != 0L) { "volume is closed" }
        val j = JSONObject(LuksNative.nativeSha256(handle, path, chunkBytes))
        return Digest(
            sha256 = j.getString("sha256"),
            bytes = j.getLong("bytes"),
            elapsedMs = j.getLong("elapsedMs"),
            bytesPerSec = j.getLong("bytesPerSec"),
        )
    }

    /**
     * Whether this process can write to this volume at all.
     *
     * Checks the `.so`, not the volume — a volume on read-only storage or on
     * an unsupported filesystem still fails at [writeFile] itself, with the
     * specific reason as a [LuksException]. This only answers "does the code
     * to try even exist here".
     */
    val canWrite: Boolean get() = LuksNative.nativeWriteSupported()

    /**
     * Creates [name] in the volume's root directory holding [data], returning
     * its inode number.
     *
     * Check [canWrite] first. Calling this when it is false is not a caught
     * error — the symbol does not exist in a `.so` without the write path,
     * and the failure is an `UnsatisfiedLinkError`, not a [LuksException].
     *
     * Blocking: this is the whole write, including the flush through the USB
     * bridge. Off the main thread, same as [unlock].
     */
    fun writeFile(parentPath: String, name: String, data: ByteArray): Long {
        check(handle != 0L) { "volume is closed" }
        return LuksNative.nativeWriteFile(handle, parentPath, name, data)
    }

    fun deleteFile(path: String) {
        check(handle != 0L) { "volume is closed" }
        LuksNative.nativeDeleteFile(handle, path)
    }

    fun createDirectory(parentPath: String, name: String): Long {
        check(handle != 0L) { "volume is closed" }
        return LuksNative.nativeCreateDirectory(handle, parentPath, name)
    }

    fun rename(oldParent: String, oldName: String, newParent: String, newName: String) {
        check(handle != 0L) { "volume is closed" }
        LuksNative.nativeRename(handle, oldParent, oldName, newParent, newName)
    }

    fun statFs(): StatFsInfo {
        check(handle != 0L) { "volume is closed" }
        val o = JSONObject(LuksNative.nativeStatFs(handle))
        return StatFsInfo(
            totalBytes = o.getLong("totalBytes"),
            freeBytes = o.getLong("freeBytes"),
            availableBytes = o.getLong("availableBytes"),
            totalInodes = o.getLong("totalInodes"),
            freeInodes = o.getLong("freeInodes"),
            blockSize = o.getInt("blockSize"),
        )
    }

    /** Starts a fixed-memory transfer. Close without [FileWriter.finish] rolls it back. */
    fun beginFile(sizeBytes: Long): FileWriter {
        check(handle != 0L) { "volume is closed" }
        check(sizeBytes >= 0) { "negative file size" }
        val writer = FileWriter(LuksNative.nativeBeginFile(handle, sizeBytes))
        activeWriters += writer
        return writer
    }

    inner class FileWriter internal constructor(private var writerHandle: Long) : AutoCloseable {
        fun write(data: java.nio.ByteBuffer, len: Int = data.remaining()) {
            check(writerHandle != 0L) { "writer is closed" }
            check(handle != 0L) { "volume is closed" }
            require(data.isDirect) { "buffer must be direct" }
            require(len in 0..data.limit()) { "chunk length exceeds buffer" }
            LuksNative.nativeWriteChunk(handle, writerHandle, data, len)
        }

        fun finish(parentPath: String, name: String): Long {
            check(writerHandle != 0L) { "writer is closed" }
            check(handle != 0L) { "volume is closed" }
            val result = LuksNative.nativeFinishFile(handle, writerHandle, parentPath, name)
            writerHandle = 0
            activeWriters -= this
            return result
        }

        override fun close() {
            if (writerHandle != 0L && handle != 0L) {
                LuksNative.nativeCloseWriter(handle, writerHandle)
            }
            writerHandle = 0
            activeWriters -= this
        }
    }

    /** Dropping this zeroes the master key held on the Rust side. */
    override fun close() {
        if (handle != 0L) {
            activeWriters.toList().forEach { it.close() }
            LuksNative.nativeCloseVolume(handle)
            handle = 0
        }
    }
}

private fun parseDeviceInfo(json: String): DeviceInfo {
    val o = JSONObject(json)
    val arr = o.getJSONArray("partitions")
    val parts = (0 until arr.length()).map { i ->
        val p = arr.getJSONObject(i)
        PartitionInfo(
            index = p.getInt("index"),
            name = p.optString("name"),
            offsetBytes = p.getLong("offsetBytes"),
            sizeBytes = p.getLong("sizeBytes"),
            isLuks = p.getBoolean("isLuks"),
            luksVersion = if (p.isNull("luksVersion")) null else p.getInt("luksVersion"),
        )
    }
    return DeviceInfo(
        vendor = o.optString("vendor"),
        product = o.optString("product"),
        blockSize = o.getInt("blockSize"),
        sizeBytes = o.getLong("sizeBytes"),
        tableKind = o.optString("tableKind"),
        partitions = parts,
        writeProbe = if (o.isNull("writeProbe")) null else o.optString("writeProbe"),
    )
}

fun formatSize(bytes: Long): String = when {
    bytes >= 1L shl 30 -> "%.1f GiB".format(bytes.toDouble() / (1L shl 30))
    bytes >= 1L shl 20 -> "%.1f MiB".format(bytes.toDouble() / (1L shl 20))
    bytes >= 1L shl 10 -> "%.1f KiB".format(bytes.toDouble() / (1L shl 10))
    else -> "$bytes B"
}
