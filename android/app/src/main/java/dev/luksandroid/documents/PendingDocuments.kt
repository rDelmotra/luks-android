package dev.luksandroid.documents

import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory registry of documents SAF has been told exist (via [LuksDocumentsProvider.createDocument])
 * but that have no on-disk representation yet.
 *
 * SAF's `createDocument` contract requires returning an id for a document that already
 * exists, but the engine has no create-empty-then-append primitive for files --
 * `finish_file(parent, name)` is what actually materializes one, and that only runs once
 * the write proxy closes (see `LuksProxyCallback.onRelease`). This registry is the gap
 * between those two moments: `createDocument` registers here and returns the id, touching
 * nothing on disk; the write proxy consumes the entry (materializing or discarding it) when
 * the caller finishes writing.
 *
 * Deliberately a standalone object rather than a private map on the provider: it needs its
 * own unit tests, and it is consulted from both [LuksDocumentsProvider] (create/query/open)
 * and [LuksProxyCallback] (the write proxy that ends a pending document's life one way or
 * the other).
 */
object PendingDocuments {

    /** A document that has been registered but not yet materialized. */
    data class Pending(val parentPath: String, val name: String)

    private val byId = ConcurrentHashMap<String, Pending>()

    /**
     * Registers a new pending document under [parentPath] named [name], returning its id.
     *
     * The id follows the same `parentPath/name` scheme as every other documentId in this
     * provider (see [LuksDocumentsProvider.queryChildDocuments]) rather than a synthetic
     * counter: once [LuksProxyCallback.onRelease] materializes the file at that exact path,
     * the pending id and the real id are the same string, so nothing downstream has to
     * reconcile two identities for the same document.
     */
    fun register(parentPath: String, name: String): String {
        val docId = if (parentPath == "/") "/$name" else "$parentPath/$name"
        byId[docId] = Pending(parentPath, name)
        return docId
    }

    /** The pending entry for [docId], or null if it is not (or no longer) pending. */
    fun get(docId: String): Pending? = byId[docId]

    /** Whether [docId] currently refers to a pending, not-yet-materialized document. */
    fun isPending(docId: String): Boolean = byId.containsKey(docId)

    /**
     * Removes [docId] from the registry, returning the entry that was there (if any).
     * Called once a pending document is materialized (finished) or discarded (abandoned or
     * explicitly deleted before ever being written) -- see [LuksProxyCallback] and
     * [LuksDocumentsProvider.deleteDocument].
     */
    fun remove(docId: String): Pending? = byId.remove(docId)

    /**
     * Drops every pending entry. Pending documents are meaningless once the session that
     * would materialize them is gone -- called from the same lock/detach/failure transition
     * that revokes issued URI grants (see `LuksDocumentsProvider.onCreate`'s state collector).
     */
    fun clear() {
        byId.clear()
    }
}
