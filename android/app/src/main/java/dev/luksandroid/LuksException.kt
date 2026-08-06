package dev.luksandroid

/**
 * Thrown by every [LuksNative] call that fails.
 *
 * Constructed from Rust by signature `(String, int)` — see `jni/src/lib.rs`.
 * Renaming this class or changing the constructor breaks the bridge at runtime
 * rather than at build time, which is why `proguard-rules.pro` pins both.
 */
class LuksException(message: String, val code: Int) : Exception(message) {

    /** True when the user simply typed the wrong password, and can retry. */
    val isWrongPassword: Boolean get() = code == WRONG_PASSWORD

    override fun toString(): String = "LuksException[$code] ${message.orEmpty()}"

    companion object {
        // Mirrors `bridge::code` in jni/src/bridge.rs. Append-only: never
        // renumber, never reuse. A numeric code exists so the UI can act on
        // WRONG_PASSWORD without matching on an error string that may be
        // reworded.
        const val GENERIC = 1
        const val WRONG_PASSWORD = 2
        const val NOT_LUKS = 3
        const val UNSUPPORTED = 4
        const val CORRUPT = 5
        const val NOT_FOUND = 6
        const val TRANSPORT = 7
        const val NEEDS_FSCK = 8
        const val IO = 9
        const val BAD_HANDLE = 10
        const val PANIC = 11
        const val NO_SPACE = 12
        const val WRONG_TARGET = 13
        const val UNVERIFIABLE_TARGET = 14
        /** A name already taken in the directory being written to. */
        const val ALREADY_EXISTS = 15

        /**
         * Another unlocked volume on the same device already holds the write
         * claim; close it before writing through this one. Distinct from
         * [UNSUPPORTED] — which it used to arrive as, indistinguishable from
         * "this volume is btrfs" — because the remedy is specific.
         */
        const val WRITER_BUSY = 16
    }
}
