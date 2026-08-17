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

    /**
     * Deliberately has no `Throwable`-accepting overload: `Log.e(tag, msg, t)`
     * prints `t`'s own message and stack trace, and `LuksException`/`LuksError`
     * messages can embed drive paths (core/src/error.rs). Passing a throwable
     * used to be a call-site discipline problem; now it's a compile error.
     * Callers that need to note *what* failed should log `t.javaClass.simpleName`
     * and/or a `LuksException.code`, never `t` or `t.message`.
     */
    fun e(msg: String) {
        if (BuildConfig.DEBUG) runCatching { Log.e(TAG, msg) }
    }

    fun e(tag: String, msg: String) {
        if (BuildConfig.DEBUG) runCatching { Log.e(tag, msg) }
    }

    /**
     * Shape-only detail for [err]. Deliberately has no `String` variant: a
     * filename or path cannot be constructed as an [ErrDetail], so it cannot
     * be passed into [err] — this is enforced by the compiler, not a rule
     * callers have to remember.
     */
    sealed interface ErrDetail {
        data class Bytes(val n: Long) : ErrDetail
        data class Count(val n: Int) : ErrDetail
        data class Offset(val n: Long) : ErrDetail
        data object None : ErrDetail
    }

    private fun renderDetail(detail: ErrDetail): String = when (detail) {
        is ErrDetail.Bytes -> "bytes=${detail.n}"
        is ErrDetail.Count -> "count=${detail.n}"
        is ErrDetail.Offset -> "offset=${detail.n}"
        ErrDetail.None -> ""
    }

    fun formatErr(code: Int, operation: String, detail: ErrDetail = ErrDetail.None): String =
        "code=$code op=$operation ${renderDetail(detail)}".trimEnd()

    /**
     * Production-safe error logging: logs error codes, operations, opcodes, sizes.
     * NEVER logs passphrases, filenames, or directory paths from the encrypted drive.
     *
     * [detail] is structurally shape-only (see [ErrDetail]) so a filename or
     * path cannot be passed here even by mistake.
     */
    fun err(code: Int, operation: String, detail: ErrDetail = ErrDetail.None) {
        runCatching { Log.e(TAG_ERR, formatErr(code, operation, detail)) }
    }

    /**
     * Non-identifying summary of a [Throwable] safe to pass into [e]: the
     * exception's class name and, if it's a `LuksException`, its error code.
     * Never the throwable itself, never `.message` — both can embed drive
     * paths (see `LuksError::{NotFound,NotADirectory,IsADirectory}` in
     * core/src/error.rs, surfaced via `Fail::parts()` in jni/src/lib.rs).
     */
    fun throwableSummary(t: Throwable): String {
        val code = (t as? LuksException)?.code
        return if (code != null) "${t.javaClass.simpleName}[code=$code]" else t.javaClass.simpleName
    }
}

