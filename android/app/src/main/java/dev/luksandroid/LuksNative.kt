package dev.luksandroid

/**
 * The raw JNI surface. Nothing outside this file should touch it — use
 * [LuksDevice] and [LuksVolume], which own the handles and close them.
 *
 * Implemented in `jni/src/lib.rs`. Every function there is wrapped in
 * `catch_unwind`, so a malformed drive surfaces as a [LuksException] rather
 * than killing the process.
 *
 * Handles are opaque `Long`s. Passing the wrong one is caught on the Rust side
 * (every handle is the same tagged type), but it is still a bug: the wrappers
 * exist so it cannot happen by accident.
 *
 * Structured results come back as JSON strings rather than as constructed Java
 * objects. That keeps the JNI surface to twelve functions with no class lookups
 * or field IDs, and it costs nothing that matters: the payloads are metadata,
 * measured in kilobytes. File *contents* never go through JSON.
 */
internal object LuksNative {

    init {
        // Loads libluks_jni.so from the APK's lib/arm64-v8a/. Built by
        // tools/build-android-libs.sh, not by Gradle.
        System.loadLibrary("luks_jni")
    }

    /** Version of the Rust core. The cheapest possible proof the .so loaded. */
    external fun nativeVersion(): String

    /**
     * @param fd from `UsbDeviceConnection.getFileDescriptor()`. Stays owned by
     *   Java; Rust never closes it, and it must outlive the returned handle.
     * @param maxTransfer bytes per bulk transfer, or 0 for the safe default of
     *   16 KiB (the historical usbfs limit).
     */
    external fun nativeOpenDevice(
        fd: Int,
        epIn: Int,
        epOut: Int,
        iface: Int,
        maxTransfer: Int,
    ): Long

    external fun nativeCloseDevice(handle: Long)

    external fun nativeCloseVolume(handle: Long)

    /** JSON: vendor, product, block size/count, partition table. */
    external fun nativeDeviceInfo(handle: Long): String

    /**
     * Derives the master key and mounts the filesystem. Seconds of CPU and up
     * to a gigabyte of allocation — never on the main thread, and only with
     * [UnlockService] running.
     *
     * @param password raw bytes, **not** a String. Copied into a zeroing buffer
     *   on the Rust side; the caller must overwrite this array afterwards.
     */
    external fun nativeUnlock(handle: Long, partitionOffset: Long, password: ByteArray): Long

    /** JSON: filesystem label, UUID, block size. */
    external fun nativeVolumeInfo(handle: Long): String

    /** JSON: `{ path, entries: [{ name, inode, type }] }`, "." and ".." removed. */
    external fun nativeListDir(handle: Long, path: String): String

    /** JSON: size, mode, uid, gid, links, type, times. */
    external fun nativeFileInfo(handle: Long, path: String): String

    /** Whole file. Throws rather than exceeding [maxBytes], which must fit the heap. */
    external fun nativeReadFile(handle: Long, path: String, maxBytes: Long): ByteArray

    /** Up to [len] bytes at [offset]. A short result means end of file. */
    external fun nativeReadChunk(handle: Long, path: String, offset: Long, len: Int): ByteArray

    /**
     * Streams the file through SHA-256 without materialising it, returning JSON
     * with the digest, byte count and elapsed time. The only way to check a
     * multi-gigabyte file from a phone.
     *
     * @param chunkBytes 0 for the default (1 MiB).
     */
    external fun nativeSha256(handle: Long, path: String, chunkBytes: Int): String
}
