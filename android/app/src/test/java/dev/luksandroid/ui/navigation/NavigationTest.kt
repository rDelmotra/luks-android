package dev.luksandroid.ui.navigation

import dev.luksandroid.BuildConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NavigationTest {

    @Test
    fun `test screen items contains standard tabs`() {
        val items = Screen.items
        assertTrue("Must contain Devices screen", items.contains(Screen.Devices))
        assertTrue("Must contain Browser screen", items.contains(Screen.Browser))
        assertTrue("Must contain Transfers screen", items.contains(Screen.Transfers))
        if (BuildConfig.DEBUG) {
            assertTrue("Debug build must contain Diagnostics screen", items.contains(Screen.Diagnostics))
        } else {
            assertTrue("Release build must not contain Diagnostics screen", !items.contains(Screen.Diagnostics))
        }
    }

    @Test
    fun `test screen routes and titles`() {
        assertEquals("devices", Screen.Devices.route)
        assertEquals("Devices", Screen.Devices.title)

        assertEquals("browser", Screen.Browser.route)
        assertEquals("Browser", Screen.Browser.title)

        assertEquals("transfers", Screen.Transfers.route)
        assertEquals("Transfers", Screen.Transfers.title)

        assertEquals("diagnostics", Screen.Diagnostics.route)
        assertEquals("Diagnostics", Screen.Diagnostics.title)
    }
}
