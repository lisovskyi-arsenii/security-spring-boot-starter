plugins {
    `java-library`
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.maven.publish.plugin)
}

subprojects {
    plugins.apply("java-library")

    group = rootProject.group
    version = rootProject.version

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(25))
        }
    }
}

dependencyManagement {
    imports {
        mavenBom(libs.spring.boot.dependencies.get().toString())
    }
}

dependencies {
    api(project(":security-starter-core"))
    api(project(":security-starter-autoconfigure"))
    api(libs.spring.boot.starter.security)
    api(libs.spring.boot.starter.web)
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(libs.versions.java.get()))
    }
}

mavenPublishing {
    publishToMavenCentral()
    signAllPublications()

    coordinates(
        groupId = project.group.toString(),
        artifactId = "lisovskyi-security-starter",
        version = project.version.toString()
    )

    pom {
        name.set("Lisovskyi Security Spring Boot Starter")
        description.set("Stateless JWT authentication, CSRF/CORS protection, and cookie-based session security auto-configuration starter for Spring Boot")
        inceptionYear.set("2026")
        url.set("https://github.com/lisovskyi-arsenii/security-spring-boot-starter")
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("lisovskyi-arsenii")
                name.set("Arsenii Lisovskyi")
            }
        }
        scm {
            url.set("https://github.com/lisovskyi-arsenii/security-spring-boot-starter")
            connection.set("scm:git:git://github.com/lisovskyi-arsenii/security-spring-boot-starter.git")
            developerConnection.set("scm:git:ssh://git@github.com/lisovskyi-arsenii/security-spring-boot-starter.git")
        }
    }
}

tasks.withType<GenerateModuleMetadata>().configureEach {
    suppressedValidationErrors.add("dependencies-without-versions")
}
