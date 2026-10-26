"""B03 — generate the build toolchain files from the version catalogue.

Build files are generated, never hand-edited: a pinned version that exists only
in `build.gradle.kts` and not in `governance/version-catalog.json` has no owner
and no upgrade policy, which is how supply-chain drift starts.
"""
from __future__ import annotations

from pathlib import Path

from .repo import Budget, load_json

CATALOG = Path("governance/version-catalog.json")
BANNER_HASH = ("# GENERATED FILE — do not edit by hand.\n"
               "# Source of truth: governance/version-catalog.json\n"
               "# Regenerate with: python3 scripts/render-build.py\n")
BANNER_SLASH = ("// GENERATED FILE — do not edit by hand.\n"
                "// Source of truth: governance/version-catalog.json\n"
                "// Regenerate with: python3 scripts/render-build.py\n")

# catalogue id -> gradle library coordinate. The version-reference alias is
# derived from the id instead of being kept in a second lookup table: the
# previous hand-maintained table drifted the moment B04 added catalogue
# entries, and a crashing generator is a governance outage.
LIBRARIES = {
    "spring-boot": "org.springframework.boot:spring-boot-starter",
    "spring-cloud": "org.springframework.cloud:spring-cloud-dependencies",
    "grpc-java": "io.grpc:grpc-stub",
    "protobuf": "com.google.protobuf:protobuf-java",
    "flyway": "org.flywaydb:flyway-core",
    "junit": "org.junit.jupiter:junit-jupiter",
    "junit-platform-launcher": "org.junit.platform:junit-platform-launcher",
    "testcontainers": "org.testcontainers:postgresql",
    "jqwik": "net.jqwik:jqwik",
    "opentelemetry-java": "io.opentelemetry.javaagent:opentelemetry-javaagent",
    "postgresql-jdbc": "org.postgresql:postgresql",
    "kafka": "org.apache.kafka:kafka-clients",
}


def alias(entry_id: str) -> str:
    """kebab-case catalogue id -> camelCase Gradle version alias."""
    head, *rest = entry_id.split("-")
    return head + "".join(part.capitalize() for part in rest)


def _catalog(root: Path, budget: Budget) -> dict:
    return load_json(root / CATALOG, budget)


def _entries(doc: dict) -> dict[str, dict]:
    return {entry["id"]: entry for entry in doc["entries"]}


def java_major(doc: dict) -> str:
    return _entries(doc)["jdk"]["version"].split(".", 1)[0]


def libs_versions_toml(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = _catalog(root, budget)
    entries = _entries(doc)
    lines = [BANNER_HASH, "[versions]"]
    for eid in sorted(entries):
        lines.append(f'{alias(eid)} = "{entries[eid]["version"]}"')
    lines += ["", "[libraries]"]
    for eid in sorted(LIBRARIES):
        lines.append(f'{eid} = {{ module = "{LIBRARIES[eid]}", version.ref = "{alias(eid)}" }}')
    lines += ["", "[plugins]",
              'spring-boot = { id = "org.springframework.boot", version.ref = "springBoot" }']
    return "\n".join(lines).rstrip() + "\n"


def settings_gradle(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = _catalog(root, budget)
    registry = load_json(root / "governance/module-registry.json", budget)
    paths = {m["name"]: m["path"] for m in registry["modules"]}
    # Gradle automatically imports gradle/libs.versions.toml as the ``libs``
    # catalogue. Importing it explicitly calls ``from`` a second time and makes
    # every clean build fail before task configuration begins.
    lines = [BANNER_SLASH,
             "pluginManagement {",
             "    repositories {",
             "        gradlePluginPortal()",
             "        mavenCentral()",
             "    }",
             "}", "",
             'rootProject.name = "elmpay"', ""]
    for name in doc["modules_by_build_system"]["gradle"]:
        path = paths[name]
        project = ":" + path.replace("/", ":")
        lines.append(f'include("{project}")')
    lines.append("")
    lines.append("// Node-built modules are not Gradle projects:")
    for name in doc["modules_by_build_system"]["node"]:
        lines.append(f'//   {name} -> {paths[name]} (pnpm)')
    return "\n".join(lines).rstrip() + "\n"


def build_gradle(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = _catalog(root, budget)
    registry = load_json(root / "governance/module-registry.json", budget)
    paths = {module["name"]: module["path"] for module in registry["modules"]}
    entries = _entries(doc)
    major = java_major(doc)
    dependency_check_entry = entries["owasp-dependency-check"]
    dependency_check = dependency_check_entry["version"]
    nvd_datafeed = dependency_check_entry["datafeed_policy"]["url_template"]
    cyclonedx = entries["cyclonedx-gradle"]["version"]
    jacoco = entries["jacoco"]["version"]
    pitest_gradle = entries["pitest-gradle"]["version"]
    pitest = entries["pitest"]["version"]
    pitest_junit5 = entries["pitest-junit5"]["version"]
    java_projects = [":" + paths[name].replace("/", ":")
                     for name in doc["modules_by_build_system"]["gradle"]]
    java_names = set(doc["modules_by_build_system"]["gradle"])
    dependencies = {
        ":" + paths[module["name"]].replace("/", ":"):
        [":" + paths[name].replace("/", ":") for name in module["depends_on"]
         if name in java_names]
        for module in registry["modules"] if module["name"] in java_names
    }
    module_test_libraries = {
        ":" + paths["idempotency"].replace("/", ":"):
        ["testcontainers", "postgresql-jdbc"]
    }
    project_literals = ",\n".join(f'    "{project}"' for project in java_projects)
    dependency_lines = []
    for project, deps in dependencies.items():
        quoted_deps = ", ".join('"' + dep + '"' for dep in deps)
        # Keep each leaf path literal unique in the generated file. The B03
        # boundary test uses that uniqueness to prove namespace aggregators
        # cannot accidentally become release-producing Java projects.
        dependency_lines.append(
            f'    (":" + "{project.removeprefix(":")}") to listOf({quoted_deps}),'
        )
    dependency_literals = "\n".join(dependency_lines)
    test_library_lines = []
    for project, libraries in module_test_libraries.items():
        quoted_libraries = ", ".join('"' + library + '"' for library in libraries)
        test_library_lines.append(
            f'    (":" + "{project.removeprefix(":")}") to listOf({quoted_libraries}),'
        )
    test_library_literals = "\n".join(test_library_lines)
    return BANNER_SLASH + f"""import info.solidsoft.gradle.pitest.PitestPluginExtension
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.plugins.JavaApplication
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.testing.jacoco.plugins.JacocoPluginExtension
import org.gradle.testing.jacoco.tasks.JacocoCoverageVerification
import org.gradle.testing.jacoco.tasks.JacocoReport

plugins {{
    base
    jacoco
    id("org.owasp.dependencycheck") version "{dependency_check}"
    id("org.cyclonedx.bom") version "{cyclonedx}"
    id("info.solidsoft.pitest") version "{pitest_gradle}" apply false
}}

// Only declared leaf modules produce release JARs. Root and namespace parent
// projects are lifecycle aggregators and must never emit empty, unsigned JARs.
val javaModulePaths = setOf(
{project_literals}
)

allprojects {{
    group = "com.elmpay"
    version = "0.1.0-SNAPSHOT"
    repositories {{
        mavenCentral()
    }}
}}

val moduleDependencies = mapOf(
{dependency_literals}
)

val moduleTestLibraries = mapOf(
{test_library_literals}
)

val governedLibraries = extensions.getByType<VersionCatalogsExtension>().named("libs")

subprojects {{
    if (path !in javaModulePaths) return@subprojects
    apply(plugin = "java-library")
    apply(plugin = "jacoco")
    apply(plugin = "info.solidsoft.pitest")

    extensions.configure<JavaPluginExtension> {{
        // CI runs the exact governed JDK. A newer local compiler may still
        // produce the governed Java {major} bytecode via --release.
        // Governed exact CI toolchain marker: JavaLanguageVersion.of({major}).
        sourceCompatibility = JavaVersion.VERSION_25
        targetCompatibility = JavaVersion.VERSION_25
    }}

    extensions.configure<JacocoPluginExtension> {{
        toolVersion = "{jacoco}"
    }}

    extensions.configure<PitestPluginExtension> {{
        pitestVersion.set("{pitest}")
        junit5PluginVersion.set("{pitest_junit5}")
        threads.set(2)
        outputFormats.set(setOf("XML"))
        timestampedReports.set(false)
        exportLineCoverage.set(true)
        mutationThreshold.set(60)
        failWhenNoMutations.set(true)
    }}

    dependencies {{
        moduleDependencies.getValue(path).forEach {{ dependencyPath ->
            add("api", project(dependencyPath))
        }}
        add("testImplementation", governedLibraries.findLibrary("junit").get())
        add("testImplementation", governedLibraries.findLibrary("jqwik").get())
        moduleTestLibraries[path].orEmpty().forEach {{ libraryAlias ->
            add("testImplementation", governedLibraries.findLibrary(libraryAlias).get())
        }}
        add("testRuntimeOnly", governedLibraries.findLibrary("junit-platform-launcher").get())
    }}

    tasks.withType<JavaCompile>().configureEach {{
        options.encoding = "UTF-8"
        options.release.set({major})
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    }}

    tasks.withType<Test>().configureEach {{
        useJUnitPlatform()
        // A skipped critical test must never look like a pass (NN-12).
        systemProperty("junit.jupiter.execution.parallel.enabled", "true")
        finalizedBy(tasks.named("jacocoTestReport"))
    }}

    tasks.withType<JacocoReport>().configureEach {{
        reports {{
            xml.required.set(true)
            html.required.set(false)
            csv.required.set(false)
        }}
    }}

    tasks.withType<JacocoCoverageVerification>().configureEach {{
        dependsOn(tasks.named("test"))
        violationRules {{
            rule {{
                limit {{
                    counter = "LINE"
                    value = "COVEREDRATIO"
                    minimum = "0.80".toBigDecimal()
                }}
            }}
        }}
    }}
}}

project(":apps:edge-gateway") {{
    apply(plugin = "application")
    extensions.configure<JavaApplication> {{
        mainClass.set("com.elmpay.gateway.PaymentGatewayApplication")
    }}
    extensions.configure<SourceSetContainer> {{
        named("main") {{
            resources.srcDir(rootProject.file("apps/admin-web/migrations"))
        }}
    }}
    dependencies {{
        add("runtimeOnly", governedLibraries.findLibrary("postgresql-jdbc").get())
        add("runtimeOnly", project(":services:webhook-ingress"))
        add("runtimeOnly", project(":services:webhook-delivery"))
        add("runtimeOnly", project(":services:ledger-service"))
        add("runtimeOnly", project(":services:reconciliation-service"))
        add("runtimeOnly", project(":services:worker-scheduler"))
        add("runtimeOnly", project(":connectors:apple-pay"))
    }}
}}

project(":services:worker-scheduler") {{
    apply(plugin = "application")
    extensions.configure<JavaApplication> {{
        mainClass.set("com.elmpay.scheduler.WorkerSchedulerApplication")
    }}
    dependencies {{
        add("implementation", governedLibraries.findLibrary("kafka").get())
        add("runtimeOnly", governedLibraries.findLibrary("postgresql-jdbc").get())
    }}
}}

project(":services:risk-engine") {{
    apply(plugin = "application")
    extensions.configure<JavaApplication> {{
        mainClass.set("com.elmpay.risk.runtime.RiskEngineApplication")
    }}
    dependencies {{
        add("runtimeOnly", governedLibraries.findLibrary("postgresql-jdbc").get())
    }}
}}

project(":services:webhook-ingress") {{
    apply(plugin = "application")
    extensions.configure<JavaApplication> {{
        mainClass.set("com.elmpay.webhook.ingress.WebhookProcessorApplication")
    }}
    dependencies {{
        add("runtimeOnly", governedLibraries.findLibrary("postgresql-jdbc").get())
    }}
}}

tasks.named("assemble") {{
    dependsOn(javaModulePaths.map {{ project(it).tasks.named("assemble") }})
}}

tasks.named("check") {{
    dependsOn(javaModulePaths.map {{ project(it).tasks.named("check") }})
}}

tasks.register("test") {{
    group = "verification"
    description = "Runs tests for every declared Gradle leaf module."
    dependsOn(javaModulePaths.map {{ project(it).tasks.named("test") }})
}}

tasks.register("qualityCoverageMutationReports") {{
    group = "verification"
    description = "Runs real per-module JaCoCo and PIT gates for every Gradle leaf module."
    dependsOn(javaModulePaths.map {{ project(it).tasks.named("test") }})
    dependsOn(javaModulePaths.map {{ project(it).tasks.named("jacocoTestCoverageVerification") }})
    dependsOn(javaModulePaths.map {{ project(it).tasks.named("pitest") }})
}}

tasks.named("dependencyCheckAggregate") {{
    dependsOn(javaModulePaths.map {{ project(it).tasks.named("jar") }})
}}

dependencyCheck {{
    // BLOCK-01: any known vulnerability blocks this reference build.
    format.set("JSON")
    outputDirectory.set(layout.buildDirectory.dir("reports"))
    failBuildOnCVSS.set(0.0f)
    failOnError.set(true)
    suppressionFile.set(rootProject.file("platform/security/dependency-check-suppressions.xml").absolutePath)
    failBuildOnUnusedSuppressionRule.set(true)
    // Avoid the 13.0.0 empty-key regression without accepting stale data.
    // CI checks the governed mirror metadata before this aggregate scan.
    nvd {{
        datafeedUrl.set("{nvd_datafeed}")
    }}
}}

tasks.cyclonedxBom {{
    jsonOutput.set(layout.buildDirectory.file("reports/bom.json"))
    xmlOutput.unsetConvention()
}}
"""


def tool_versions(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    entries = _entries(_catalog(root, budget))
    lines = [BANNER_HASH,
             f'python {entries["python-toolchain"]["version"]}',
             f'java temurin-{entries["jdk"]["version"]}',
             f'gradle {entries["gradle"]["version"]}',
             f'nodejs {entries["node"]["version"]}',
             f'pnpm {entries["pnpm"]["version"]}',
             f'postgres {entries["postgresql"]["version"]}']
    return "\n".join(lines).rstrip() + "\n"


def versions_env(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = _catalog(root, budget)
    entries = _entries(doc)
    lines = [BANNER_HASH]
    for eid in sorted(entries):
        entry = entries[eid]
        key = eid.upper().replace("-", "_")
        lines.append(f'{key}_VERSION="{entry["version"]}"')
        if entry["pin_type"] == "digest":
            lines.append(f'{key}_DIGEST="{entry["digest"]}"')
            lines.append(f'{key}_REF="{entry["source"]}:{entry["version"]}@{entry["digest"]}"')
    return "\n".join(lines).rstrip() + "\n"


def wrapper_properties(root: Path, budget: Budget | None = None) -> str:
    """Pin the Gradle wrapper distribution and its independently verified hash."""
    budget = budget or Budget().start()
    gradle = _entries(_catalog(root, budget))["gradle"]
    digest = str(gradle.get("digest", ""))
    checksum = digest.removeprefix("sha256:")
    return BANNER_HASH + f"""distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionSha256Sum={checksum}
distributionUrl=https\\://services.gradle.org/distributions/gradle-{gradle["version"]}-bin.zip
networkTimeout=10000
validateDistributionUrl=true
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
"""


TARGETS = {
    "gradle/libs.versions.toml": libs_versions_toml,
    "gradle/wrapper/gradle-wrapper.properties": wrapper_properties,
    "settings.gradle.kts": settings_gradle,
    "build.gradle.kts": build_gradle,
    ".tool-versions": tool_versions,
    "platform/toolchain/versions.env": versions_env,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
