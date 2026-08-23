package dev.luksandroid.transfer

/**
 * Builds the [DestinationListing] [precheckTransfer] needs, by looking up only
 * the directories a plan actually touches.
 *
 * Split out of the caller and kept pure -- a lambda in, a listing out -- so the
 * keying can be tested. That keying is the whole difficulty: [DestinationListing]
 * is indexed by *plan-relative* path ("" for the landing directory), while the
 * lookup has to happen against *absolute* paths on the volume. Getting that
 * mapping wrong does not crash; it silently reports every destination directory
 * as empty, which makes the precheck miss every collision and every entry-count
 * breach it exists to catch.
 */

/**
 * @param listDirOrNull returns the directory's children, or null if no such
 *   directory exists at the destination. "Absent" and "present but empty" must
 *   stay distinguishable: an absent directory will be created fresh and merges
 *   with nothing, while an empty one that exists still occupies an entry in its
 *   own parent.
 */
fun surveyDestination(
    plan: TransferPlan,
    destinationRootPath: String,
    listDirOrNull: (absolutePath: String) -> List<DestinationEntry>?,
): DestinationListing {
    val byDir = mutableMapOf<String, List<DestinationEntry>>()

    // childCountByDir's keys are every directory the plan writes into,
    // including "" for the landing directory itself -- exactly the set worth
    // querying, and no more. Walking plan.entries instead would query leaf
    // files' parents repeatedly and miss the landing directory entirely.
    for (relativeDir in plan.childCountByDir.keys) {
        val absolute = absoluteDir(destinationRootPath, relativeDir)
        val children = listDirOrNull(absolute) ?: continue
        byDir[relativeDir] = children
    }

    return DestinationListing(byDir)
}
