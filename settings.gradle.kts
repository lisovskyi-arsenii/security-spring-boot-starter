rootProject.name = "lisovskyi-security-starter"
include("security-starter-core")
include("security-starter-autoconfigure")

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}