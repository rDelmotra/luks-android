package dev.luksandroid.transfer

import dev.luksandroid.LuksVolume

/**
 * [ChildSource] over the drive itself, via [LuksVolume.listDir]. In-process
 * and native -- no IPC, unlike [SafChildSource] -- so there is no per-call
 * cost to justify here; the "one call per directory" rule in
 * [DirectoryWalker] still applies and is enforced there, not here.
 *
 * Identity is the absolute path on the volume, matching the convention
 * already used for [LuksVolume.listDir] elsewhere (e.g.
 * `ui/browser/BrowserScreen.kt`'s `joinPath`): the root is `"/"`, and a
 * child's path is `"$dir/$name"` except directly under the root, which is
 * `"/$name"` rather than `"//$name"`.
 */
class VolumeChildSource(private val volume: LuksVolume) : ChildSource {

    override fun children(parentId: String): List<RawChild> =
        volume.listDir(parentId).map { entry ->
            RawChild(
                id = childPath(parentId, entry.name),
                name = entry.name,
                isDir = entry.isDir,
                sizeBytes = if (entry.isDir) 0L else entry.size,
                mtime = entry.mtime,
            )
        }

    private fun childPath(parentId: String, name: String): String =
        if (parentId == "/") "/$name" else "$parentId/$name"
}
