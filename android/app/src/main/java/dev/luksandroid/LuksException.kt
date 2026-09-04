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
    val isNotLuks: Boolean get() = code == NOT_LUKS
    val isUnsupported: Boolean get() = code == UNSUPPORTED
    val isCorrupt: Boolean get() = code == CORRUPT
    val isNotFound: Boolean get() = code == NOT_FOUND
    val isTransport: Boolean get() = code == TRANSPORT
    val isNeedsFsck: Boolean get() = code == NEEDS_FSCK
    val isIo: Boolean get() = code == IO
    val isBadHandle: Boolean get() = code == BAD_HANDLE
    val isPanic: Boolean get() = code == PANIC
    val isNoSpace: Boolean get() = code == NO_SPACE
    val isWrongTarget: Boolean get() = code == WRONG_TARGET
    val isUnverifiableTarget: Boolean get() = code == UNVERIFIABLE_TARGET
    val isAlreadyExists: Boolean get() = code == ALREADY_EXISTS
    val isWriterBusy: Boolean get() = code == WRITER_BUSY
    val isItemTooLarge: Boolean get() = code == ITEM_TOO_LARGE
    val isMutexPoisoned: Boolean get() = code == MUTEX_POISONED
    val isCancelled: Boolean get() = code == CANCELLED
    val isDirectoryNotEmpty: Boolean get() = code == DIRECTORY_NOT_EMPTY
    val isWriteSessionFenced: Boolean get() = code == WRITE_SESSION_FENCED

    /**
     * Whether this failure means no further write on this volume can be
     * trusted, so the session must be torn down rather than retried.
     *
     * Both codes have the same remedy -- unlock again -- but different
     * diagnoses: [MUTEX_POISONED] is a panic under the volume lock,
     * [WRITE_SESSION_FENCED] is a transport failure that panicked nothing.
     */
    val isWriteSessionDead: Boolean get() = isMutexPoisoned || isWriteSessionFenced

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

        /**
         * A single btrfs metadata item was too large for a tree node — a
         * geometry limit, not a full drive.
         *
         * Distinct from [NO_SPACE], which it used to arrive as. On 2026-08-16
         * that made a 20 MB transfer to a stick with 676 MiB free tell the
         * user the drive was out of space, which was false and sent the
         * investigation at the hardware.
         */
        const val ITEM_TOO_LARGE = 17

        /**
         * A previous write operation panicked while holding the volume lock.
         * Further writes on this volume are refused to protect disk state.
         */
        const val MUTEX_POISONED = 18

        /**
         * The operation was interrupted via a cancellation token.
         */
        const val CANCELLED = 19

        /**
         * A directory delete found a child it does not know how to remove (a
         * symlink, say) partway through recursion. The directory itself was
         * found and is real — it just still has something in it.
         */
        const val DIRECTORY_NOT_EMPTY = 20

        /**
         * An earlier write failed in a way that left the drive's state
         * unknown, so the write session was fenced. Every later write on this
         * volume is refused until it is unlocked again; reads still work.
         *
         * Distinct from [MUTEX_POISONED], which it would otherwise be lumped
         * in with. Reporting a timed-out cable as "a previous operation
         * panicked" sent one investigation at the wrong layer already.
         */
        const val WRITE_SESSION_FENCED = 21
    }
}
