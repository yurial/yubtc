// yubtc Android — settings file.
//
// Module layout:
//   :app    — the wallet app (Compose + UniFFI bridge).
//
// Includes settings.gradle.kts versions for plugins (managed via the
// version catalog or hard-pinned here for reproducibility).

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "yubtc-android"
include(":app")
