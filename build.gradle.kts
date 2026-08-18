// GENERATED FILE — do not edit by hand.
// Source of truth: governance/version-catalog.json
// Regenerate with: python3 scripts/render-build.py

plugins {
    java
}

allprojects {
    group = "com.elmpay"
    version = "0.1.0-SNAPSHOT"
}

subprojects {
    apply(plugin = "java")

    java {
        toolchain {
            // Pinned by governance/version-catalog.json (entry: jdk)
            languageVersion.set(JavaLanguageVersion.of(25))
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        // A skipped critical test must never look like a pass (NN-12).
        systemProperty("junit.jupiter.execution.parallel.enabled", "true")
    }
}
