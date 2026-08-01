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
)

data class VolumeInfo(
    val label: String,
    val uuid: String,
    val blockSize: Int,
    val sizeBytes: Long,
)

data class Entry(val name: String, val type: String) {
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
     * [password] is overwritten before this returns, on both the success and the
     * failure path. The caller should still not keep another copy.
     */
    fun unlock(partitionOffset: Long, password: ByteArray): LuksVolume {
        check(handle != 0L) { "device is closed" }
        return try {
            LuksVolume(LuksNative.nativeUnlock(handle, partitionOffset, password))
        } finally {
            password.fill(0)
        }
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

    val info: VolumeInfo = JSONObject(LuksNative.nativeVolumeInfo(handle)).let {
        VolumeInfo(
            label = it.optString("label"),
            uuid = it.optString("uuid"),
            blockSize = it.optInt("blockSize"),
            sizeBytes = it.optLong("sizeBytes"),
        )
    }

    fun listDir(path: String): List<Entry> {
        check(handle != 0L) { "volume is closed" }
        val entries = JSONObject(LuksNative.nativeListDir(handle, path)).getJSONArray("entries")
        return (0 until entries.length()).map { i ->
            val e = entries.getJSONObject(i)
            Entry(e.getString("name"), e.getString("type"))
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

    /** Dropping this zeroes the master key held on the Rust side. */
    override fun close() {
        if (handle != 0L) {
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
    )
}

fun formatSize(bytes: Long): String = when {
    bytes >= 1L shl 30 -> "%.1f GiB".format(bytes.toDouble() / (1L shl 30))
    bytes >= 1L shl 20 -> "%.1f MiB".format(bytes.toDouble() / (1L shl 20))
    bytes >= 1L shl 10 -> "%.1f KiB".format(bytes.toDouble() / (1L shl 10))
    else -> "$bytes B"
}
