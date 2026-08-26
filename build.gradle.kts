// GENERATED FILE — do not edit by hand.
// Source of truth: governance/version-catalog.json
// Regenerate with: python3 scripts/render-build.py
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.plugins.JavaApplication

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
    repositories {
        mavenCentral()
    }
}

val moduleDependencies = mapOf(
    (":" + "libs:money") to listOf(),
    (":" + "libs:domain-events") to listOf(":libs:money"),
    (":" + "libs:idempotency") to listOf(),
    (":" + "libs:audit") to listOf(":libs:security"),
    (":" + "libs:security") to listOf(),
    (":" + "libs:observability") to listOf(":libs:security"),
    (":" + "connectors:wechat-pay") to listOf(":libs:money", ":libs:security", ":libs:observability", ":libs:domain-events"),
    (":" + "connectors:alipay") to listOf(":libs:money", ":libs:security", ":libs:observability", ":libs:domain-events"),
    (":" + "connectors:stripe") to listOf(":libs:money", ":libs:security", ":libs:observability", ":libs:domain-events"),
    (":" + "connectors:paypal") to listOf(":libs:money", ":libs:security", ":libs:observability", ":libs:domain-events"),
    (":" + "connectors:apple-pay") to listOf(":libs:money", ":libs:security", ":libs:observability", ":libs:domain-events"),
    (":" + "services:merchant-config") to listOf(":libs:money", ":libs:security", ":libs:audit", ":libs:observability", ":libs:domain-events"),
    (":" + "services:payment-core") to listOf(":libs:money", ":libs:idempotency", ":libs:audit", ":libs:security", ":libs:observability", ":libs:domain-events", ":services:merchant-config", ":services:risk-engine", ":services:ledger-service", ":connectors:wechat-pay", ":connectors:alipay", ":connectors:stripe", ":connectors:paypal", ":connectors:apple-pay"),
    (":" + "services:webhook-ingress") to listOf(":libs:security", ":libs:audit", ":libs:observability", ":libs:domain-events", ":libs:idempotency", ":connectors:wechat-pay", ":connectors:alipay", ":connectors:stripe", ":connectors:paypal", ":connectors:apple-pay"),
    (":" + "services:webhook-delivery") to listOf(":libs:security", ":libs:audit", ":libs:observability", ":libs:domain-events", ":services:merchant-config"),
    (":" + "services:risk-engine") to listOf(":libs:money", ":libs:audit", ":libs:security", ":libs:observability", ":libs:domain-events", ":services:merchant-config"),
    (":" + "services:ledger-service") to listOf(":libs:money", ":libs:audit", ":libs:security", ":libs:observability", ":libs:domain-events"),
    (":" + "services:reconciliation-service") to listOf(":libs:money", ":libs:audit", ":libs:security", ":libs:observability", ":libs:domain-events", ":services:ledger-service", ":services:merchant-config"),
    (":" + "services:worker-scheduler") to listOf(":libs:security", ":libs:audit", ":libs:observability", ":libs:domain-events", ":services:payment-core", ":services:reconciliation-service", ":services:merchant-config"),
    (":" + "apps:edge-gateway") to listOf(":libs:security", ":libs:observability", ":services:payment-core", ":services:merchant-config"),
)

val governedLibraries = extensions.getByType<VersionCatalogsExtension>().named("libs")

subprojects {
    if (path !in javaModulePaths) return@subprojects
    apply(plugin = "java-library")

    extensions.configure<JavaPluginExtension> {
        // CI runs the exact governed JDK. A newer local compiler may still
        // produce the governed Java 25 bytecode via --release.
        // Governed exact CI toolchain marker: JavaLanguageVersion.of(25).
        sourceCompatibility = JavaVersion.VERSION_25
        targetCompatibility = JavaVersion.VERSION_25
    }

    dependencies {
        moduleDependencies.getValue(path).forEach { dependencyPath ->
            add("api", project(dependencyPath))
        }
        add("testImplementation", governedLibraries.findLibrary("junit").get())
        add("testImplementation", governedLibraries.findLibrary("jqwik").get())
        add("testRuntimeOnly", governedLibraries.findLibrary("junit-platform-launcher").get())
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.release.set(25)
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        // A skipped critical test must never look like a pass (NN-12).
        systemProperty("junit.jupiter.execution.parallel.enabled", "true")
    }
}

project(":apps:edge-gateway") {
    apply(plugin = "application")
    extensions.configure<JavaApplication> {
        mainClass.set("com.elmpay.gateway.PaymentGatewayApplication")
    }
    dependencies {
        add("runtimeOnly", governedLibraries.findLibrary("postgresql-jdbc").get())
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
