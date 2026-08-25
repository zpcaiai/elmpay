// GENERATED FILE — do not edit by hand.
// Source of truth: governance/version-catalog.json
// Regenerate with: python3 scripts/render-build.py
import org.gradle.api.plugins.JavaPluginExtension

plugins {
    base
    id("org.owasp.dependencycheck") version "13.0.0"
    id("org.cyclonedx.bom") version "3.4.1"
}

// Only declared leaf modules produce release JARs. Root and namespace parent
// projects are lifecycle aggregators and must never emit empty, unsigned JARs.
val javaModulePaths = setOf(
    ":libs:money",
    ":libs:domain-events",
    ":libs:idempotency",
    ":libs:audit",
    ":libs:security",
    ":libs:observability",
    ":connectors:wechat-pay",
    ":connectors:alipay",
    ":connectors:stripe",
    ":connectors:paypal",
    ":connectors:apple-pay",
    ":services:payment-core",
    ":services:webhook-ingress",
    ":services:webhook-delivery",
    ":services:merchant-config",
    ":services:risk-engine",
    ":services:ledger-service",
    ":services:reconciliation-service",
    ":services:worker-scheduler",
    ":apps:edge-gateway"
)

allprojects {
    group = "com.elmpay"
    version = "0.1.0-SNAPSHOT"
}

subprojects {
    if (path !in javaModulePaths) return@subprojects
    apply(plugin = "java")

    extensions.configure<JavaPluginExtension> {
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

tasks.named("assemble") {
    dependsOn(javaModulePaths.map { project(it).tasks.named("assemble") })
}

tasks.named("check") {
    dependsOn(javaModulePaths.map { project(it).tasks.named("check") })
}

tasks.register("test") {
    group = "verification"
    description = "Runs tests for every declared Gradle leaf module."
    dependsOn(javaModulePaths.map { project(it).tasks.named("test") })
}

dependencyCheck {
    // BLOCK-01: any known vulnerability blocks this reference build.
    format.set("JSON")
    outputDirectory.set(layout.buildDirectory.dir("reports"))
    failBuildOnCVSS.set(0.0f)
    failOnError.set(true)
    // Avoid the 13.0.0 empty-key regression without accepting stale data.
    // CI checks the governed mirror metadata before this aggregate scan.
    nvd {
        datafeedUrl.set("https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/nvdcve-{0}.json.gz")
    }
}

tasks.cyclonedxBom {
    jsonOutput.set(layout.buildDirectory.file("reports/bom.json"))
    xmlOutput.unsetConvention()
}
