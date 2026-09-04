package dev.luksandroid.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.SwapVert
import androidx.compose.material.icons.filled.Usb
import androidx.compose.ui.graphics.vector.ImageVector
import dev.luksandroid.BuildConfig

sealed class Screen(val route: String, val title: String, val icon: ImageVector) {
    data object Devices : Screen("devices", "Devices", Icons.Default.Usb)
    data object Browser : Screen("browser", "Browser", Icons.Default.Folder)
    data object Transfers : Screen("transfers", "Transfers", Icons.Default.SwapVert)
    data object Diagnostics : Screen("diagnostics", "Diagnostics", Icons.Default.BugReport)

    companion object {
        val items: List<Screen>
            get() = buildList {
                add(Devices)
                add(Browser)
                add(Transfers)
                if (BuildConfig.DEBUG) {
                    add(Diagnostics)
                }
            }
    }
}
