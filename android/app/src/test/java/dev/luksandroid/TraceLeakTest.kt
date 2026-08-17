package dev.luksandroid

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Regression coverage for the filename/path leak class described in
 * notes/feature-remediation.md §3 (N.0) and §6.3 (N.9).
 *
 * The defenses that actually work here are compiler- and static-analysis
 * enforced, not test-enforced:
 *  - `Trace.ErrDetail` is shape-only (no `String` variant), so no call site
 *    can pass a filename/path into `Trace.err` — that's a compile error.
 *  - `Trace` has no `Throwable`-accepting overload at all, so no call site
 *    can hand a raw exception (whose `.message` may embed a path) to `Log.e`
 *    — also a compile error.
 *  - The source scan below is the structural backstop for everything the
 *    type system doesn't already protect: the free-text `Trace.e`/`Trace.i`
 *    overloads, and (per the gap-1 fix) any lingering bare-identifier
 *    Throwable argument.
 *
 * A prior version of this file also had a
 * `deleteFileErrorPath_doesNotLeakKnownFilenameIntoEmittedLine` test that
 * hand-built the already-correct `Trace.err(e.code, "delete_file")` call
 * inside the test body and asserted on its own output. It never invoked any
 * production call site, so it passed identically whether or not the real
 * code was ever fixed — exactly the tautological-verification anti-pattern
 * notes/feature-remediation.md §3 (N.1) calls out. Deleted rather than
 * "fixed": a test that cannot fail adds nothing.
 */
class TraceLeakTest {

    // --- source scan ------------------------------------------------------

    // NOTE: "documentId" doesn't contain "name"/"path"/"file"/"dir"/"entry" as
    // a substring, so it's listed explicitly rather than relying on a broader
    // "id" match (which would false-positive on "provider", "guide", etc).
    private val bannedWordPattern = Regex("(?i)(name|path|file|dir|entry|documentId)")

    private fun findAppSourceRoot(): File {
        var dir = File(System.getProperty("user.dir")).absoluteFile
        repeat(8) {
            val candidate = File(dir, "src/main/java/dev/luksandroid")
            if (candidate.isDirectory) return candidate
            val nested = File(dir, "android/app/src/main/java/dev/luksandroid")
            if (nested.isDirectory) return nested
            dir = dir.parentFile ?: return@repeat
        }
        throw IllegalStateException(
            "Could not locate dev/luksandroid main sources from user.dir=${System.getProperty("user.dir")}"
        )
    }

    private fun kotlinFiles(root: File): List<File> =
        root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    /** Extracts the balanced-paren call text starting right after `Trace.xxx(`. */
    private fun extractCallArgs(text: String, openParenIndex: Int): String {
        var depth = 1
        var i = openParenIndex + 1
        val sb = StringBuilder()
        while (i < text.length && depth > 0) {
            val c = text[i]
            if (c == '(') depth++
            if (c == ')') {
                depth--
                if (depth == 0) break
            }
            sb.append(c)
            i++
        }
        return sb.toString()
    }

    /**
     * Splits a balanced-paren argument-list text into top-level arguments,
     * i.e. splitting on commas that are not nested inside `(`/`{`/`[`.
     */
    private fun splitTopLevelArgs(callArgs: String): List<String> {
        val args = mutableListOf<String>()
        var depth = 0
        val sb = StringBuilder()
        for (c in callArgs) {
            when (c) {
                '(', '{', '[' -> { depth++; sb.append(c) }
                ')', '}', ']' -> { depth--; sb.append(c) }
                ',' -> if (depth == 0) {
                    args.add(sb.toString())
                    sb.clear()
                } else {
                    sb.append(c)
                }
                else -> sb.append(c)
            }
        }
        if (sb.isNotBlank()) args.add(sb.toString())
        return args
    }

    /**
     * Extracts identifiers referenced via `$ident` or `${ident...}`
     * interpolation. Whitespace (including newlines) inside a `${...}` block
     * is stripped before matching, so a multi-line interpolation such as
     * `${item\n.fullPath}` — which a naive single-line-identifier regex would
     * truncate at `item` and miss entirely — is still recognized as
     * `item.fullPath`.
     *
     * Known limitation, accepted rather than solved here: a function-call
     * interpolation like `${item.displayName()}` is only caught if the
     * matched identifier text up to the `(` happens to contain a banned
     * word (as `displayName` does, via `Name`). A call like
     * `${item.get()}` returning a path would not be caught by this scan.
     * Full dataflow/type analysis is out of scope for a source-scan test.
     */
    private fun interpolatedIdentifiers(callArgs: String): List<String> {
        val results = mutableListOf<String>()
        val simple = Regex("\\$([a-zA-Z_][a-zA-Z0-9_]*)")
        for (m in simple.findAll(callArgs)) results.add(m.groupValues[1])

        var i = 0
        while (i < callArgs.length) {
            if (callArgs[i] == '$' && i + 1 < callArgs.length && callArgs[i + 1] == '{') {
                var depth = 1
                var j = i + 2
                val sb = StringBuilder()
                while (j < callArgs.length && depth > 0) {
                    val c = callArgs[j]
                    if (c == '{') depth++
                    if (c == '}') {
                        depth--
                        if (depth == 0) break
                    }
                    sb.append(c)
                    j++
                }
                val normalized = sb.toString().filterNot { it.isWhitespace() }
                val identMatch = Regex("^([a-zA-Z_][a-zA-Z0-9_.]*)").find(normalized)
                if (identMatch != null) results.add(identMatch.groupValues[1])
                i = j + 1
            } else {
                i++
            }
        }
        return results
    }

    /**
     * Scans a file for `val`/`var` locals whose initializer is a *pure member
     * access chain* (e.g. `val p = item.fullPath`, no function calls) through
     * a banned-looking member, and returns the set of local identifier names
     * that should therefore be treated as banned for the rest of the file — a
     * renamed alias is exactly as dangerous as the original expression.
     *
     * Deliberately restricted to call-free initializers: `val entries =
     * vol.listDir("/")` and `val ino = writer.finish(parentPath, targetName)`
     * are legitimate real call sites in this codebase (a directory listing
     * count, an inode number) whose *return values* don't carry a path, even
     * though the call or its arguments mention one. A regex can't tell "this
     * function's result is derived from a path" from "this function's result
     * happens to be computed by consuming a path", so — to avoid drowning
     * real findings in false positives — only the direct, call-free rename
     * case (`val p = item.fullPath`) is flagged. Dataflow beyond one hop (an
     * alias of an alias) is likewise out of scope; this catches the direct-
     * rename case the auditor demonstrated.
     */
    private fun bannedLocalAliases(text: String): Set<String> {
        val aliases = mutableSetOf<String>()
        val declRegex = Regex(
            "\\b(?:val|var)\\s+([a-zA-Z_][a-zA-Z0-9_]*)\\s*(?::[^=\\n]+)?=\\s*([^\\n;]+)"
        )
        // Pure member-access chain, e.g. `item.fullPath` or `item.dir.name` —
        // no `(`, so no function/method call anywhere in the initializer.
        val pureMemberChain = Regex("^[a-zA-Z_][a-zA-Z0-9_]*(\\.[a-zA-Z_][a-zA-Z0-9_]*)+$")
        for (m in declRegex.findAll(text)) {
            val localName = m.groupValues[1]
            val initializer = m.groupValues[2].trim()
            if (!pureMemberChain.matches(initializer)) continue
            val components = Regex("[a-zA-Z_][a-zA-Z0-9_]*").findAll(initializer).map { it.value }
            if (components.any { bannedWordPattern.containsMatchIn(it) }) {
                aliases.add(localName)
            }
        }
        return aliases
    }

    @Test
    fun sourceScan_noTraceCallSiteInterpolatesNamePathFileDirOrEntryVariable() {
        val root = findAppSourceRoot()
        val files = kotlinFiles(root)
        assertTrue("expected to find .kt sources under $root", files.isNotEmpty())

        val callSiteRegex = Regex("Trace\\.(err|e|i)\\(")
        val violations = mutableListOf<String>()

        for (file in files) {
            val text = file.readText()
            val localAliases = bannedLocalAliases(text)

            for (m in callSiteRegex.findAll(text)) {
                val openParenIndex = m.range.last
                val args = extractCallArgs(text, openParenIndex)
                val idents = interpolatedIdentifiers(args)
                for (ident in idents) {
                    val root0 = ident.substringBefore(".")
                    val components = ident.split(".")
                    val bannedByWord = components.firstOrNull { bannedWordPattern.containsMatchIn(it) }
                    val bannedByAlias = if (root0 in localAliases) root0 else null
                    val matched = bannedByWord ?: bannedByAlias
                    if (matched != null) {
                        val line = text.substring(0, m.range.first).count { it == '\n' } + 1
                        val reason = if (bannedByWord != null) {
                            "matched `$bannedByWord`"
                        } else {
                            "`$root0` is a local alias of a banned-looking expression"
                        }
                        violations.add("${file.name}:$line interpolates `$ident` ($reason)")
                    }
                }
            }
        }

        assertTrue(
            "Trace call sites must not interpolate name/path/file/dir/entry/documentId-like " +
                "variables (directly, or via a renamed local alias):\n" +
                violations.joinToString("\n"),
            violations.isEmpty(),
        )
    }

    /**
     * Gap-1 enforcement: `Trace` has no `Throwable`-accepting overload, so a
     * bare `Trace.e(msg, t)` is already a compile error. This test makes that
     * a static-analysis invariant too, in case the overload is ever
     * reintroduced: no `Trace.e`/`Trace.i` call may pass a bare identifier as
     * its 2nd argument (the historical `Throwable`/free-text slot), and no
     * `Trace.err` call may pass a bare identifier as its 3rd argument (the
     * `detail` slot — legitimately either omitted or an `ErrDetail.*(...)`
     * constructor call, never a variable reference).
     *
     * `Trace.err`'s 2nd argument (`operation: String`) is deliberately
     * exempt: it's the one position callers legitimately pass as a plain
     * variable today (e.g. `UiErrorMessage.getUserMessage`'s `op`), and it
     * was never the vector either leak used — it's a caller-supplied
     * operation label, not exception content.
     */
    @Test
    fun sourceScan_noTraceCallPassesBareIdentifierInDangerousArgumentPosition() {
        val root = findAppSourceRoot()
        val files = kotlinFiles(root)
        assertTrue("expected to find .kt sources under $root", files.isNotEmpty())

        val callSiteRegex = Regex("Trace\\.(err|e|i)\\(")
        val bareIdentifierRegex = Regex("^[a-zA-Z_][a-zA-Z0-9_]*$")
        val violations = mutableListOf<String>()

        for (file in files) {
            val text = file.readText()
            for (m in callSiteRegex.findAll(text)) {
                val fnName = m.groupValues[1]
                val openParenIndex = m.range.last
                val args = extractCallArgs(text, openParenIndex)
                val topLevelArgs = splitTopLevelArgs(args).map { it.trim() }
                // 0-based dangerous index: Trace.err's detail is arg #3 (index 2);
                // Trace.e/Trace.i's historical Throwable slot is arg #2 (index 1).
                val dangerousIndex = if (fnName == "err") 2 else 1
                val arg = topLevelArgs.getOrNull(dangerousIndex) ?: continue
                if (bareIdentifierRegex.matches(arg)) {
                    val line = text.substring(0, m.range.first).count { it == '\n' } + 1
                    violations.add(
                        "${file.name}:$line passes bare identifier `$arg` as argument #${dangerousIndex + 1} " +
                            "to Trace.$fnName(...) — use a string literal or an " +
                            "ErrDetail.*(...) constructor call instead",
                    )
                }
            }
        }

        assertTrue(
            "Trace call sites must not pass a bare identifier as a 2nd/3rd argument " +
                "(this is how a raw Throwable variable used to reach Log.e):\n" +
                violations.joinToString("\n"),
            violations.isEmpty(),
        )
    }
}
