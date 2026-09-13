plugins {
    `java-library`
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.maven.publish.plugin)
}

dependencyManagement {
    imports {
        mavenBom(libs.spring.boot.dependencies.get().toString())
    }
}

dependencies {
    api(project(":security-starter-core"))

    implementation(libs.jjwt.api)
    implementation(libs.spring.boot.starter.validation)
    implementation(libs.spring.boot.starter.data.redis)
    api(libs.caffeine)
    implementation(libs.checker.qual)
    implementation(libs.spring.security.oauth2.jose)

    runtimeOnly(libs.jjwt.impl)
    runtimeOnly(libs.jjwt.jackson)

    compileOnly(libs.spring.boot.autoconfigure)
    compileOnly(libs.spring.boot.starter.security)
    compileOnly(libs.spring.boot.starter.web)

    annotationProcessor(libs.spring.boot.configuration.processor)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testImplementation(libs.spring.boot.starter.security)
    testImplementation(libs.spring.boot.starter.web)
    testImplementation(libs.spring.test)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}

mavenPublishing {
    publishToMavenCentral()
    signAllPublications()

    coordinates(
        groupId = project.group.toString(),
        artifactId = "security-starter-autoconfigure",
        version = project.version.toString()
    )

    pom {
        name.set("Lisovskyi Security Starter Autoconfigure")
        description.set("Auto-configuration module (JWT, CSRF, CORS, cookies, token blacklist) of the Lisovskyi security starter")
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
