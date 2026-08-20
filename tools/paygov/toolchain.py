"""B03 — version catalogue and generated build-file gate.

Rules, all fail-closed:

* every dependency is pinned exactly — no ranges, no ``+``, no ``latest``,
  no ``SNAPSHOT``;
* container images are pinned by digest, not only by tag;
* every entry has an owner, a source and an upgrade policy;
* every module in the registry is built by exactly one build system;
* the generated build files match the catalogue byte for byte.
"""
from __future__ import annotations

import hashlib
import os
import re
import zipfile
from pathlib import Path
from typing import Any

from . import buildgen, catalogue
from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

PATH = Path("governance/version-catalog.json")
VERSION_OK = re.compile(r"^[0-9][0-9A-Za-z.+_-]*$")
FLOATING = ("latest", "SNAPSHOT", "RELEASE", "master", "main", "dev")
FLOATING_CHARS = ("[", "]", "(", ")", ",", "^", "~", "*")
# Gradle dynamic versions ("1.2.+", "1.+") are floating; SemVer build metadata
# ("25.0.4+7", as used by Temurin) is exact and therefore allowed.
DYNAMIC_PLUS = re.compile(r"\+(?!\d)")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
VALID_PIN = {"exact", "digest"}
VALID_VERIFICATION = {"verified", "unverified-offline"}
EXPECTED_JAVA_MAJOR = "25"


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("toolchain", "B03")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    where = str(PATH)
    try:
        doc: Any = load_json(root / PATH, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("TOOLCHAIN_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(doc.get("schema_version", "")))),
                       "TOOLCHAIN_VERSION", where, "schema_version must be semantic version", "NN-12")
    problems += expect(doc.get("verification_status") in VALID_VERIFICATION,
                       "TOOLCHAIN_VERIFICATION", where,
                       f"verification_status must be one of {sorted(VALID_VERIFICATION)}", "NN-12")
    if doc.get("verification_status") == "unverified-offline":
        problems += expect(len(str(doc.get("verification_note", "")).strip()) >= 20,
                           "TOOLCHAIN_VERIFICATION", where,
                           "an unverified catalogue must state why and where it is tracked", "NN-15")

    entries = doc.get("entries")
    required = doc.get("required_categories")
    build_systems = doc.get("modules_by_build_system")
    if not isinstance(entries, list) or not entries or not isinstance(required, list) \
            or not isinstance(build_systems, dict):
        return problems + [Problem("TOOLCHAIN_SHAPE", where,
                                   "catalogue needs 'entries', 'required_categories' and "
                                   "'modules_by_build_system'", "NN-12")]

    seen: set[str] = set()
    categories: set[str] = set()
    for entry in entries:
        eid = entry.get("id", "?")
        scope = f"{where}#{eid}"
        problems += expect(eid not in seen, "TOOLCHAIN_DUPLICATE", scope,
                           f"duplicate catalogue id '{eid}'", "NN-12")
        seen.add(eid)
        categories.add(entry.get("category"))

        version = str(entry.get("version", ""))
        problems += expect(bool(VERSION_OK.match(version)), "TOOLCHAIN_VERSION_FORMAT", scope,
                           f"'{version}' is not a concrete version string", "NN-12")
        lowered = version.lower()
        for marker in FLOATING:
            problems += expect(marker.lower() not in lowered, "TOOLCHAIN_FLOATING", scope,
                               f"'{version}' is a floating version; builds must be reproducible",
                               "NN-12")
        for char in FLOATING_CHARS:
            problems += expect(char not in version, "TOOLCHAIN_FLOATING", scope,
                               f"'{version}' contains range syntax '{char}'", "NN-12")
        problems += expect(not DYNAMIC_PLUS.search(version), "TOOLCHAIN_FLOATING", scope,
                           f"'{version}' uses a Gradle dynamic version", "NN-12")

        pin = entry.get("pin_type")
        problems += expect(pin in VALID_PIN, "TOOLCHAIN_PIN", scope,
                           f"pin_type must be one of {sorted(VALID_PIN)}", "NN-12")
        if entry.get("category") == "container":
            problems += expect(pin == "digest", "TOOLCHAIN_PIN", scope,
                               "container images must be pinned by digest, not only by tag", "NN-12")
            problems += expect(bool(DIGEST.match(str(entry.get("digest", "")))),
                               "TOOLCHAIN_DIGEST", scope,
                               "digest must be 'sha256:' followed by 64 hex characters", "NN-12")
        for field in ("name", "source", "owner", "upgrade_policy"):
            problems += expect(len(str(entry.get(field, "")).strip()) >= 4,
                               "TOOLCHAIN_METADATA", scope,
                               f"'{field}' is required so that every pin has an accountable owner",
                               "NN-11")

    for category in required:
        problems += expect(category in categories, "TOOLCHAIN_CATEGORY", where,
                           f"required category '{category}' has no catalogue entry", "NN-12")

    problems += _build_systems(root, build_systems, where)
    problems += _java_version(doc, where)
    problems += _gradle_wrapper(root, doc, where)
    problems += _generated(root, budget)
    return problems


def _build_systems(root: Path, build_systems: dict, where: str) -> list[Problem]:
    known = catalogue.module_names(str(root))
    assigned: dict[str, str] = {}
    problems: list[Problem] = []
    for system, names in sorted(build_systems.items()):
        if not isinstance(names, list):
            problems.append(Problem("TOOLCHAIN_BUILD_SYSTEM", where,
                                    f"'{system}' must map to an array of modules", "NN-12"))
            continue
        for name in names:
            if name in assigned:
                problems.append(Problem("TOOLCHAIN_BUILD_SYSTEM", where,
                                        f"module '{name}' is claimed by both '{assigned[name]}' "
                                        f"and '{system}'", "NN-12"))
            assigned[name] = system
            if name not in known:
                problems.append(Problem("TOOLCHAIN_BUILD_SYSTEM", where,
                                        f"unknown module '{name}'", "NN-12"))
    for name in sorted(known - set(assigned)):
        problems.append(Problem("TOOLCHAIN_BUILD_SYSTEM", where,
                                f"module '{name}' has no build system; it cannot be built "
                                f"reproducibly", "NN-12"))
    return problems


def _java_version(doc: dict, where: str) -> list[Problem]:
    jdk = next((e for e in doc["entries"] if e["id"] == "jdk"), None)
    if jdk is None:
        return [Problem("TOOLCHAIN_JDK", where, "catalogue has no 'jdk' entry", "NN-12")]
    major = str(jdk["version"]).split(".", 1)[0]
    return expect(major == EXPECTED_JAVA_MAJOR, "TOOLCHAIN_JDK", where,
                  f"the programme baseline is Java {EXPECTED_JAVA_MAJOR}; catalogue pins {major}",
                  "NN-12")


def _gradle_wrapper(root: Path, doc: dict, where: str) -> list[Problem]:
    """Require a runnable, byte-pinned wrapper in every clean checkout."""
    problems: list[Problem] = []
    required = ("gradlew", "gradlew.bat", "gradle/wrapper/gradle-wrapper.jar",
                "gradle/wrapper/gradle-wrapper.properties")
    for rel in required:
        path = root / rel
        problems += expect(path.is_file() and path.stat().st_size > 0,
                           "TOOLCHAIN_WRAPPER", rel,
                           "the complete Gradle wrapper must be version-controlled", "NN-12")

    launcher = root / "gradlew"
    if launcher.is_file():
        problems += expect(os.access(launcher, os.X_OK), "TOOLCHAIN_WRAPPER", "gradlew",
                           "gradlew must retain its executable bit", "NN-12")
        try:
            launcher_text = launcher.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            launcher_text = ""
        problems += expect("gradle/wrapper/gradle-wrapper.jar" in launcher_text,
                           "TOOLCHAIN_WRAPPER", "gradlew",
                           "gradlew does not launch the pinned wrapper JAR", "NN-12")

    gradle = next((entry for entry in doc["entries"] if entry.get("id") == "gradle"), None)
    if gradle is None:
        return problems
    problems += expect(bool(DIGEST.match(str(gradle.get("digest", "")))),
                       "TOOLCHAIN_DIGEST", f"{where}#gradle",
                       "the Gradle distribution must have a sha256 digest", "NN-12")
    expected_jar = str(gradle.get("wrapper_jar_sha256", ""))
    problems += expect(bool(re.fullmatch(r"[a-f0-9]{64}", expected_jar)),
                       "TOOLCHAIN_WRAPPER", f"{where}#gradle",
                       "wrapper_jar_sha256 must pin the official wrapper JAR", "NN-12")

    for rel, field in (("gradlew", "wrapper_script_sha256"),
                       ("gradlew.bat", "wrapper_bat_sha256")):
        path = root / rel
        expected = str(gradle.get(field, ""))
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
        problems += expect(bool(re.fullmatch(r"[a-f0-9]{64}", expected))
                           and actual == expected,
                           "TOOLCHAIN_WRAPPER", rel,
                           f"{rel} differs from the official catalogue checksum", "NN-12")

    jar = root / "gradle/wrapper/gradle-wrapper.jar"
    if jar.is_file():
        try:
            actual = hashlib.sha256(jar.read_bytes()).hexdigest()
            with zipfile.ZipFile(jar) as archive:
                has_main = "org/gradle/wrapper/GradleWrapperMain.class" in archive.namelist()
        except (OSError, zipfile.BadZipFile):
            actual, has_main = "", False
        problems += expect(actual == expected_jar and has_main,
                           "TOOLCHAIN_WRAPPER", str(jar.relative_to(root)),
                           "wrapper JAR is corrupt or differs from its catalogue checksum",
                           "NN-12")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    for rel, expected in sorted(buildgen.render_all(root).items()):
        budget.check(rel)
        path = root / rel
        if not path.is_file():
            problems.append(Problem("BUILD_MISSING", rel,
                                    "generated build file is missing; run "
                                    "scripts/render-build.py", "NN-12"))
        elif path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("BUILD_DRIFT", rel,
                                    "generated build file differs from the version catalogue; "
                                    "run scripts/render-build.py", "NN-12"))
    return problems
