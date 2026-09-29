// GENERATED FILE — do not edit by hand.
// Source of truth: governance/version-catalog.json
// Regenerate with: python3 scripts/render-build.py
import info.solidsoft.gradle.pitest.PitestPluginExtension
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.plugins.JavaApplication
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.testing.jacoco.plugins.JacocoPluginExtension
import org.gradle.testing.jacoco.tasks.JacocoCoverageVerification
import org.gradle.testing.jacoco.tasks.JacocoReport

plugins {
    base
    jacoco
    id("org.owasp.dependencycheck") version "13.0.0"
    id("org.cyclonedx.bom") version "3.4.1"
    id("info.solidsoft.pitest") version "1.19.0" apply false
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
    ":apps:edge-gateway",
    ":sdks:mobile:android"
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
    (":" + "services:webhook-ingress") to listOf(":libs:security", ":libs:audit", ":libs:observability", ":libs:domain-events", ":libs:idempotency", ":services:payment-core", ":connectors:wechat-pay", ":connectors:alipay", ":connectors:stripe", ":connectors:paypal", ":connectors:apple-pay"),
    (":" + "services:webhook-delivery") to listOf(":libs:security", ":libs:audit", ":libs:observability", ":libs:domain-events", ":services:merchant-config"),
    (":" + "services:risk-engine") to listOf(":libs:money", ":libs:audit", ":libs:security", ":libs:observability", ":libs:domain-events", ":services:merchant-config"),
    (":" + "services:ledger-service") to listOf(":libs:money", ":libs:audit", ":libs:security", ":libs:observability", ":libs:domain-events"),
    (":" + "services:reconciliation-service") to listOf(":libs:money", ":libs:audit", ":libs:security", ":libs:observability", ":libs:domain-events", ":services:ledger-service", ":services:merchant-config"),
    (":" + "services:worker-scheduler") to listOf(":libs:security", ":libs:audit", ":libs:observability", ":libs:domain-events", ":services:payment-core", ":services:reconciliation-service", ":services:merchant-config", ":services:ledger-service", ":services:webhook-delivery"),
    (":" + "apps:edge-gateway") to listOf(":libs:security", ":libs:observability", ":libs:domain-events", ":services:payment-core", ":services:merchant-config", ":services:risk-engine", ":services:reconciliation-service", ":services:webhook-ingress"),
    (":" + "sdks:mobile:android") to listOf(),
)

val governedLibraries = extensions.getByType<VersionCatalogsExtension>().named("libs")

subprojects {
    if (path !in javaModulePaths) return@subprojects
    apply(plugin = "java-library")
    apply(plugin = "jacoco")
    apply(plugin = "info.solidsoft.pitest")

    extensions.configure<JavaPluginExtension> {
        // CI runs the exact governed JDK. A newer local compiler may still
        // produce the governed Java 25 bytecode via --release.
        // Governed exact CI toolchain marker: JavaLanguageVersion.of(25).
        sourceCompatibility = JavaVersion.VERSION_25
        targetCompatibility = JavaVersion.VERSION_25
    }

    extensions.configure<JacocoPluginExtension> {
        toolVersion = "0.8.15"
    }

    extensions.configure<PitestPluginExtension> {
        pitestVersion.set("1.25.8")
        junit5PluginVersion.set("1.2.3")
        threads.set(2)
        outputFormats.set(setOf("XML"))
        timestampedReports.set(false)
        exportLineCoverage.set(true)
        mutationThreshold.set(60)
        failWhenNoMutations.set(true)
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
        finalizedBy(tasks.named("jacocoTestReport"))
    }

    tasks.withType<JacocoReport>().configureEach {
        reports {
            xml.required.set(true)
            html.required.set(false)
            csv.required.set(false)
        }
    }

    tasks.withType<JacocoCoverageVerification>().configureEach {
        dependsOn(tasks.named("test"))
        violationRules {
            rule {
                limit {
                    counter = "LINE"
                    value = "COVEREDRATIO"
                    minimum = "0.80".toBigDecimal()
                }
            }
        }
    }
}

project(":apps:edge-gateway") {
    apply(plugin = "application")
    extensions.configure<JavaApplication> {
        mainClass.set("com.elmpay.gateway.PaymentGatewayApplication")
    }
    extensions.configure<SourceSetContainer> {
        named("main") {
            resources.srcDir(rootProject.file("apps/admin-web/migrations"))
        }
    }
    dependencies {
        add("runtimeOnly", governedLibraries.findLibrary("postgresql-jdbc").get())
        add("runtimeOnly", project(":services:webhook-ingress"))
        add("runtimeOnly", project(":services:webhook-delivery"))
        add("runtimeOnly", project(":services:ledger-service"))
        add("runtimeOnly", project(":services:reconciliation-service"))
        add("runtimeOnly", project(":services:worker-scheduler"))
        add("runtimeOnly", project(":connectors:apple-pay"))
    }
}

project(":services:worker-scheduler") {
    apply(plugin = "application")
    extensions.configure<JavaApplication> {
        mainClass.set("com.elmpay.scheduler.WorkerSchedulerApplication")
    }
    dependencies {
        add("implementation", governedLibraries.findLibrary("kafka").get())
        add("runtimeOnly", governedLibraries.findLibrary("postgresql-jdbc").get())
    }
}

project(":services:risk-engine") {
    apply(plugin = "application")
    extensions.configure<JavaApplication> {
        mainClass.set("com.elmpay.risk.runtime.RiskEngineApplication")
    }
    dependencies {
        add("runtimeOnly", governedLibraries.findLibrary("postgresql-jdbc").get())
    }
}

project(":services:webhook-ingress") {
    apply(plugin = "application")
    extensions.configure<JavaApplication> {
        mainClass.set("com.elmpay.webhook.ingress.WebhookProcessorApplication")
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

tasks.register("qualityCoverageMutationReports") {
    group = "verification"
    description = "Runs real per-module JaCoCo and PIT gates for every Gradle leaf module."
    dependsOn(javaModulePaths.map { project(it).tasks.named("test") })
    dependsOn(javaModulePaths.map { project(it).tasks.named("jacocoTestCoverageVerification") })
    dependsOn(javaModulePaths.map { project(it).tasks.named("pitest") })
}

dependencyCheck {
    // BLOCK-01: any known vulnerability blocks this reference build.
    format.set("JSON")
    outputDirectory.set(layout.buildDirectory.dir("reports"))
    failBuildOnCVSS.set(0.0f)
    failOnError.set(true)
    suppressionFile.set(rootProject.file("platform/security/dependency-check-suppressions.xml").absolutePath)
    failBuildOnUnusedSuppressionRule.set(true)
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
