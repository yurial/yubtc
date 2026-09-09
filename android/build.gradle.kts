// yubtc Android — root build file.
//
// Plugins are declared here without `apply` so they're available to
// subprojects (notably `:app`). Versions are pinned to match the
// plan's stack: AGP 8.5, Gradle 8.7, Kotlin 2.0.20, Compose Compiler
// 1.5.x (Compose Compiler is bundled with Kotlin 2.x via the
// `kotlin-compose` Gradle plugin).

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
}
