plugins {
    id("java-library")
    id("io.spring.dependency-management") version "1.1.7"
    id("maven-publish")
}

repositories {
    mavenCentral()
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:4.1.0")
    }
}

val lombokVersion = "1.18.46"

dependencies {
    compileOnly("org.springframework.boot:spring-boot-starter-security")
    compileOnly("org.springframework.security:spring-security-core")
    compileOnly("org.springframework.security:spring-security-web")
    compileOnly("org.springframework.security:spring-security-config")
    compileOnly("org.springframework.boot:spring-boot-autoconfigure")
    compileOnly("org.springframework.boot:spring-boot-starter-validation")
    compileOnly("org.projectlombok:lombok:$lombokVersion")

    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    annotationProcessor("org.projectlombok:lombok:$lombokVersion")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            groupId = "com.lisovskyi"
            artifactId = "security-starter-core"
            version = "0.2.1"
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