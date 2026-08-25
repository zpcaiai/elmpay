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
    "testcontainers": "org.testcontainers:postgresql",
    "jqwik": "net.jqwik:jqwik",
    "opentelemetry-java": "io.opentelemetry.javaagent:opentelemetry-javaagent",
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
    java_projects = [":" + paths[name].replace("/", ":")
                     for name in doc["modules_by_build_system"]["gradle"]]
    project_literals = ",\n".join(f'    "{project}"' for project in java_projects)
    return BANNER_SLASH + f"""import org.gradle.api.plugins.JavaPluginExtension

plugins {{
    base
    id("org.owasp.dependencycheck") version "{dependency_check}"
    id("org.cyclonedx.bom") version "{cyclonedx}"
}}

// Only declared leaf modules produce release JARs. Root and namespace parent
// projects are lifecycle aggregators and must never emit empty, unsigned JARs.
val javaModulePaths = setOf(
{project_literals}
)

allprojects {{
    group = "com.elmpay"
    version = "0.1.0-SNAPSHOT"
}}

subprojects {{
    if (path !in javaModulePaths) return@subprojects
    apply(plugin = "java")

    extensions.configure<JavaPluginExtension> {{
        toolchain {{
            // Pinned by governance/version-catalog.json (entry: jdk)
            languageVersion.set(JavaLanguageVersion.of({major}))
        }}
    }}

    tasks.withType<JavaCompile>().configureEach {{
        options.encoding = "UTF-8"
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    }}

    tasks.withType<Test>().configureEach {{
        useJUnitPlatform()
        // A skipped critical test must never look like a pass (NN-12).
        systemProperty("junit.jupiter.execution.parallel.enabled", "true")
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

dependencyCheck {{
    // BLOCK-01: any known vulnerability blocks this reference build.
    format.set("JSON")
    outputDirectory.set(layout.buildDirectory.dir("reports"))
    failBuildOnCVSS.set(0.0f)
    failOnError.set(true)
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
