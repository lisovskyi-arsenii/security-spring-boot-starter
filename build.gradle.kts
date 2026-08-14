plugins {
    id("java-library")
    id("io.spring.dependency-management") version "1.1.7"
    id("maven-publish")
}

subprojects {
    plugins.apply("java-library")
    plugins.apply("io.spring.dependency-management")
    group = "com.lisovskyi"

    tasks.withType<JavaCompile> {
        sourceCompatibility = "25"
        targetCompatibility = "25"
    }

    repositories {
        mavenLocal()
        mavenCentral()
    }
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:4.1.0")
    }
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    api(project(":security-starter-core"))
    api(project(":security-starter-autoconfigure"))
    api("org.springframework.boot:spring-boot-starter-security")
    api("org.springframework.boot:spring-boot-starter-web")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            groupId = "com.lisovskyi"
            artifactId = "lisovskyi-security-starter"
        }
    }

    repositories {
        mavenLocal()
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/Sentio1/backend-java")
            credentials {
                username = findProperty("gpr.user") as String? ?: System.getenv("GITHUB_ACTOR") ?: ""
                password = findProperty("gpr.token") as String? ?: System.getenv("GITHUB_TOKEN") ?: ""
            }
        }
    }
}