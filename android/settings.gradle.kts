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
        // Local pre-fetched artifacts, used only on dev machines where the network to
        // Google Maven / Maven Central is unreliable. Absent or empty in CI, where it
        // is simply ignored and artifacts resolve from google()/mavenCentral() below.
        val offlineRepo = file(".claude-dev/offline-repo")
        if (offlineRepo.isDirectory) {
            maven { url = offlineRepo.toURI() }
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "doublethink"
include(":app")
