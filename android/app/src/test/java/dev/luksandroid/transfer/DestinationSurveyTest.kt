package dev.luksandroid.transfer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The plan-relative to absolute mapping the precheck depends on.
 *
 * A bug here is invisible rather than loud: every destination directory reads
 * as empty, so the precheck finds no collisions and no entry-count breach, and
 * reports a clean "proceed" for a transfer that will fail partway.
 */
class DestinationSurveyTest {

    private fun dir(path: String) = PlanEntry("id:$path", path, isDir = true, sizeBytes = 0, mtime = 0)
    private fun file(path: String) = PlanEntry("id:$path", path, isDir = false, sizeBytes = 1, mtime = 0)

    private val plan = TransferPlan(
        "root",
        listOf(dir("Docs"), file("Docs/a.txt"), dir("Docs/Sub"), file("Docs/Sub/b.txt"), file("top.txt")),
    )

    @Test
    fun `each touched directory is looked up at its absolute path`() {
        val asked = mutableListOf<String>()

        surveyDestination(plan, "/dst") { path ->
            asked += path
            null
        }

        assertEquals(setOf("/dst", "/dst/Docs", "/dst/Docs/Sub"), asked.toSet())
    }

    @Test
    fun `the landing directory is keyed by empty string, not by its own name`() {
        val listing = surveyDestination(plan, "/dst") { path ->
            if (path == "/dst") listOf(DestinationEntry("existing.txt", isDir = false)) else null
        }

        assertEquals(listOf(DestinationEntry("existing.txt", isDir = false)), listing.childrenOf(""))
    }

    @Test
    fun `a nested directory is keyed by its plan-relative path`() {
        val listing = surveyDestination(plan, "/dst") { path ->
            if (path == "/dst/Docs/Sub") listOf(DestinationEntry("b.txt", isDir = false)) else null
        }

        assertEquals(listOf(DestinationEntry("b.txt", isDir = false)), listing.childrenOf("Docs/Sub"))
        assertTrue(listing.childrenOf("Docs").isEmpty())
    }

    @Test
    fun `an absent directory is left out, while a present but empty one is recorded`() {
        // The distinction the precheck relies on: absent means "will be created,
        // merges with nothing"; present-and-empty still occupies an entry in its
        // parent. Collapsing the two makes the ext4 ceiling check under-count.
        val listing = surveyDestination(plan, "/dst") { path ->
            when (path) {
                "/dst/Docs" -> emptyList()
                else -> null
            }
        }

        assertTrue(listing.entriesByDir.containsKey("Docs"))
        assertTrue(listing.entriesByDir["Docs"]!!.isEmpty())
        assertTrue("absent directories must not appear", !listing.entriesByDir.containsKey("Docs/Sub"))
    }

    @Test
    fun `a root destination does not produce a doubled slash`() {
        // joinPath's usual trap: "/" + "/Docs" is "//Docs", which is not the
        // same path to the volume and would report the directory as absent.
        val asked = mutableListOf<String>()

        surveyDestination(plan, "/") { path ->
            asked += path
            null
        }

        assertTrue("got $asked", asked.none { it.startsWith("//") })
        assertTrue("got $asked", asked.contains("/Docs"))
    }

    @Test
    fun `directories are asked for once each, never once per file`() {
        val asked = mutableListOf<String>()
        val many = TransferPlan(
            "root",
            listOf(dir("D")) + (1..50).map { file("D/f$it.txt") },
        )

        surveyDestination(many, "/dst") { path ->
            asked += path
            null
        }

        assertEquals("one query per directory, never per file", asked.size, asked.distinct().size)
        assertEquals(setOf("/dst", "/dst/D"), asked.toSet())
    }
}
