// Root build file. Plugins are declared here with `apply false` so the version
// is pinned once and each module just names the plugin.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
}
