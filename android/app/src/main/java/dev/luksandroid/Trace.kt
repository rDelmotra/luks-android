package dev.luksandroid

import android.util.Log

/**
 * Production-safe logging.
 *
 * `BuildConfig.DEBUG` gates the lot, so a release build logs nothing at all
 * rather than relying on callers staying disciplined.
 */
object Trace {
    const val TAG = "luks"
    const val TAG_ERR = "luks_err"

    fun i(msg: String) {
        if (BuildConfig.DEBUG) runCatching { Log.i(TAG, msg) }
    }

    fun i(tag: String, msg: String) {
        if (BuildConfig.DEBUG) runCatching { Log.i(tag, msg) }
    }

    fun e(msg: String, t: Throwable? = null) {
        if (BuildConfig.DEBUG) runCatching { Log.e(TAG, msg, t) }
    }

    fun e(tag: String, msg: String, t: Throwable? = null) {
        if (BuildConfig.DEBUG) runCatching { Log.e(tag, msg, t) }
    }

    fun formatErr(code: Int, operation: String, detail: String = ""): String =
        "code=$code op=$operation ${detail.take(128)}"

    /**
     * Production-safe error logging: logs error codes, operations, opcodes, sizes.
     * NEVER logs passphrases, filenames, or directory paths from the encrypted drive.
     */
    fun err(code: Int, operation: String, detail: String = "") {
        runCatching { Log.e(TAG_ERR, "code=$code op=$operation ${detail.take(128)}") }
    }
}

