"""B03 — version catalogue and generated build-file gate.

Rules, all fail-closed:

* every dependency is pinned exactly — no ranges, no ``+``, no ``latest``,
  no ``SNAPSHOT``;
* container images are pinned by digest, not only by tag;
* every entry has an owner, a source and an upgrade policy;
* every module in the registry is built by exactly one build system;
* the generated build files match the catalogue byte for byte;
* the Python that runs this toolchain is itself pinned, and no toolchain source
  may require a language or standard-library feature newer than the declared
  compatibility floor.
"""
from __future__ import annotations

import ast
import hashlib
import os
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

from . import buildgen, catalogue, nvdfeed
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
INTERPRETER_ID = "python-toolchain"
# The toolchain is dependency-free Python, so "which Python" is a real pin: the
# evidence commands for every batch run on it. Sources are checked here rather
# than only at import time because the two ends of the delivery path do not run
# the same interpreter — a feature newer than the floor imports cleanly on the
# reference version and takes the whole validator registry down on the floor.
TOOLCHAIN_SOURCES = ("tools/**/*.py", "scripts/**/*.py", ".ai/*.py")
SECURITY_BUILD_PLUGINS = {
    "owasp-dependency-check": "org.owasp.dependencycheck",
    "cyclonedx-gradle": "org.cyclonedx.bom",
}


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
    problems += _security_build_controls(root, doc, where)
    problems += _interpreter_controls(root, doc, where)
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


def _kotlin_string_span(text: str, index: int) -> int:
    """End offset of the Kotlin string literal starting at *index*."""
    length = len(text)
    if text.startswith('"""', index):
        end = text.find('"""', index + 3)
        return length if end == -1 else end + 3
    cursor = index + 1
    while cursor < length:
        char = text[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char == '"':
            return cursor + 1
        if char == "\n":            # an unterminated literal ends at the line
            return cursor
        cursor += 1
    return length


def _without_kotlin_comments(text: str) -> str:
    """Remove comments so a disabled control cannot satisfy a text invariant.

    String literals are copied through untouched. A regex that deletes from
    ``//`` to end of line does not know it is inside a string, and every URL in
    a Gradle file contains ``//``: it turned
    ``datafeedUrl.set("https://.../nvdcve-{0}.json.gz")`` into
    ``datafeedUrl.set("https:`` before any check ran, so the governed-feed
    assertion could not pass however the build file was written. The same blind
    spot cuts the other way for the checks that assert a token is *absent* —
    anything after a ``//`` inside a literal became invisible, and an override
    such as ``apiKey`` smuggled in there would have read as clean.
    """
    out: list[str] = []
    index, length = 0, len(text)
    while index < length:
        if text[index] == '"':
            end = _kotlin_string_span(text, index)
            out.append(text[index:end])
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = length if end == -1 else end + 2
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end == -1 else end
        else:
            out.append(text[index])
            index += 1
    return "".join(out)


def _kotlin_blocks(text: str, opener: str) -> list[str]:
    """Return the bodies of simple named Kotlin DSL blocks.

    The generated build file is intentionally small.  A brace walk is more
    useful here than loose substring checks because it proves the settings are
    inside the task/extension they are supposed to govern and ignores comments
    that merely quote the desired value.
    """
    bodies: list[str] = []
    pattern = re.compile(opener + r"\s*\{")
    for match in pattern.finditer(text):
        start = text.find("{", match.start())
        depth = 0
        index = start
        # Braces inside string literals are not block delimiters. The governed
        # feed URL ends in "{0}", which happens to balance; an unbalanced brace
        # in any literal would silently hand back the wrong block body, and a
        # check would then be asserting things about the wrong region of the
        # file rather than failing.
        while index < len(text):
            char = text[index]
            if char == '"':
                index = _kotlin_string_span(text, index)
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    bodies.append(text[start + 1:index])
                    break
            index += 1
    return bodies



def _version_tuple(text: str) -> tuple[int, ...] | None:
    parts = str(text).split(".")
    if not parts or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _toolchain_sources(root: Path) -> list[Path]:
    found: list[Path] = []
    for pattern in TOOLCHAIN_SOURCES:
        for path in sorted(root.glob(pattern)):
            if path.is_file() and "__pycache__" not in path.parts:
                found.append(path)
    return found


def _above_floor_uses(tree: ast.AST, wanted: dict[str, list[str]]) -> set[str]:
    """Symbols from *wanted* that this module actually imports or dereferences.

    Matched through the syntax tree, not by substring: 'UTC' and 'batched' are
    ordinary words that appear in prose and in unrelated identifiers, and a
    rule that fires on a docstring teaches people to work around it.
    """
    hits: set[str] = set()
    # Resolve imported module aliases before inspecting attributes.  A single
    # ast.walk pass is deliberately not used for this: the rule must not depend
    # on traversal order when the dereference sits in a nested scope.
    module_aliases: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for alias_node in node.names:
            module = alias_node.name
            if module in wanted:
                local_name = alias_node.asname or module.split(".", 1)[0]
                module_aliases.setdefault(local_name, set()).add(module)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias_node in node.names:
                if alias_node.name in wanted.get(node.module, []):
                    hits.add(f"{node.module}.{alias_node.name}")
            if node.module in wanted.get("", []):
                hits.add(node.module)
        elif isinstance(node, ast.Import):
            for alias_node in node.names:
                if alias_node.name in wanted.get("", []):
                    hits.add(alias_node.name)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            # Preserve detection of the canonical module name even if an
            # unusual loader supplies it without a local import, while mapping
            # ordinary ``import module as alias`` uses back to that canonical
            # name for policy lookup and diagnostics.
            modules = module_aliases.get(node.value.id, {node.value.id})
            for module in modules:
                if node.attr in wanted.get(module, []):
                    hits.add(f"{module}.{node.attr}")
    return hits


def _interpreter_controls(root: Path, doc: dict, where: str) -> list[Problem]:
    """The interpreter is part of the toolchain, so it is pinned like the rest."""
    entries = {entry.get("id"): entry for entry in doc.get("entries", [])
               if isinstance(entry, dict)}
    entry = entries.get(INTERPRETER_ID)
    scope = f"{where}#{INTERPRETER_ID}"
    problems = expect(isinstance(entry, dict), "TOOLCHAIN_INTERPRETER", scope,
                      "the catalogue must pin the Python that runs this toolchain; "
                      "without it two execution environments drift apart silently",
                      "NN-12")
    if not isinstance(entry, dict):
        return problems

    reference = _version_tuple(entry.get("version", ""))
    floor = _version_tuple(entry.get("minimum_supported", ""))
    problems += expect(floor is not None and len(floor) >= 2, "TOOLCHAIN_INTERPRETER", scope,
                       "minimum_supported must be a numeric compatibility floor "
                       "such as '3.10'", "NN-12")
    if floor is None or reference is None:
        return problems
    problems += expect(floor <= reference, "TOOLCHAIN_INTERPRETER", scope,
                       f"the floor {entry['minimum_supported']} is newer than the reference "
                       f"interpreter {entry['version']}", "NN-12")
    problems += expect(sys.version_info[:len(floor)] >= floor, "TOOLCHAIN_INTERPRETER", scope,
                       f"this gate is running on Python "
                       f"{'.'.join(str(p) for p in sys.version_info[:3])}, below the declared "
                       f"floor {entry['minimum_supported']}", "NN-12")

    declared = entry.get("above_floor_symbols")
    problems += expect(isinstance(declared, list) and declared, "TOOLCHAIN_INTERPRETER", scope,
                       "above_floor_symbols must list the newer-than-floor symbols the "
                       "toolchain is not allowed to use", "NN-12")
    if not isinstance(declared, list):
        return problems

    wanted: dict[str, list[str]] = {}
    added_in: dict[str, str] = {}
    for item in declared:
        if not isinstance(item, dict) or not isinstance(item.get("symbol"), str):
            problems.append(Problem("TOOLCHAIN_INTERPRETER", scope,
                                    "each above_floor_symbols item needs a 'symbol' string",
                                    "NN-12"))
            continue
        symbol = item["symbol"]
        version = _version_tuple(item.get("added_in", ""))
        if version is None or version <= floor:
            problems.append(Problem(
                "TOOLCHAIN_INTERPRETER", scope,
                f"'{symbol}' declares added_in={item.get('added_in')!r}, which is not above "
                f"the floor {entry['minimum_supported']}; the list must stay meaningful",
                "NN-12"))
            continue
        module, _, name = symbol.rpartition(".")
        wanted.setdefault(module, []).append(name)
        added_in[symbol] = item["added_in"]

    # Every value that can affect either parsing or the emitted diagnostic is
    # part of the policy key.  A long-lived validator process must not reuse a
    # verdict after the catalogue changes a feature version or symbol policy.
    scan_key = (
        floor[:2],
        str(entry["minimum_supported"]),
        tuple(sorted((mod, tuple(sorted(names))) for mod, names in wanted.items())),
        tuple(sorted(added_in.items())),
    )
    for path in _toolchain_sources(root):
        rel = path.relative_to(root).as_posix()
        problems += _scan_source(path, rel, scan_key, wanted, added_in,
                                 str(entry["minimum_supported"]))
    return problems


# Parsing every toolchain source is cheap once and ruinous 500 times: the
# negative-control harness runs the whole gate per scenario, so an uncached
# scan turned a 13-second shard into a 40-second one and pushed the fail-closed
# proof back over the execution ceiling. Keyed on identity, a SHA-256 digest of
# the bytes actually parsed, and the complete scan policy, so a same-size edit
# with a restored timestamp cannot reuse a stale verdict.
_SCAN_CACHE: dict[tuple, list[tuple[str, str]]] = {}


def _scan_source(path: Path, rel: str, scan_key: tuple, wanted: dict[str, list[str]],
                 added_in: dict[str, str], floor_text: str) -> list[Problem]:
    try:
        content = path.read_bytes()
        source = content.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        return [Problem("TOOLCHAIN_PYTHON_FLOOR", rel,
                        f"toolchain source is unreadable: {exc}", "NN-12")]
    digest = hashlib.sha256(content).hexdigest()
    key = (str(path), rel, digest, scan_key)
    cached = _SCAN_CACHE.get(key)
    if cached is None:
        cached = _scan_uncached(source, rel, wanted, added_in, floor_text, scan_key[0])
        if len(_SCAN_CACHE) > 20000:      # a long-lived process, not a leak
            _SCAN_CACHE.clear()
        _SCAN_CACHE[key] = cached
    return [Problem("TOOLCHAIN_PYTHON_FLOOR", where, message, "NN-12")
            for where, message in cached]


def _scan_uncached(source: str, rel: str, wanted: dict[str, list[str]],
                   added_in: dict[str, str], floor_text: str,
                   feature_version: tuple[int, int]) -> list[tuple[str, str]]:
    try:
        tree = ast.parse(source, filename=rel, feature_version=feature_version)
    except SyntaxError as exc:
        return [(f"{rel}:{exc.lineno or 0}",
                 f"syntax requires a newer Python than the declared floor "
                 f"{floor_text}: {exc.msg}")]
    found = []
    for symbol in sorted(_above_floor_uses(tree, wanted)):
        found.append((rel, f"'{symbol}' was added in Python {added_in.get(symbol, '?')}, "
                           f"above the declared floor {floor_text}; it fails at import time "
                           f"on every environment still running the floor"))
    return found


def _security_build_controls(root: Path, doc: dict, where: str) -> list[Problem]:
    """Validate fail-closed SCA/SBOM semantics independently of the generator.

    ``BUILD_DRIFT`` catches hand edits, but it cannot catch a future edit that
    weakens both ``buildgen.py`` and its generated output.  These invariants
    therefore inspect the effective generated build file as a second line of
    defence.
    """
    path = root / "build.gradle.kts"
    try:
        code = _without_kotlin_comments(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        return [Problem("TOOLCHAIN_SECURITY_BUILD", "build.gradle.kts",
                        f"security build controls are unreadable: {exc}", "NN-12")]

    problems: list[Problem] = []
    entries = {entry.get("id"): entry for entry in doc.get("entries", [])
               if isinstance(entry, dict)}
    for entry_id, plugin_id in SECURITY_BUILD_PLUGINS.items():
        entry = entries.get(entry_id)
        scope = f"{where}#{entry_id}"
        problems += expect(isinstance(entry, dict), "TOOLCHAIN_SECURITY_PLUGIN", scope,
                           f"catalogue must pin the '{plugin_id}' build plugin", "NN-12")
        if not isinstance(entry, dict):
            continue
        problems += expect(entry.get("pin_type") == "exact"
                           and entry.get("category") == "build-plugin",
                           "TOOLCHAIN_SECURITY_PLUGIN", scope,
                           "security build plugins require an exact, owned build-plugin pin",
                           "NN-12")
        version = str(entry.get("version", ""))
        pattern = re.compile(r'id\(\s*"' + re.escape(plugin_id)
                             + r'"\s*\)\s*version\s*"([^"]+)"')
        problems += expect(pattern.findall(code) == [version],
                           "TOOLCHAIN_SECURITY_PLUGIN", "build.gradle.kts",
                           f"root build must apply exactly one catalogue-pinned "
                           f"'{plugin_id}' plugin at version '{version}'", "NN-12")

    dependency_entry = entries.get("owasp-dependency-check")
    datafeed_policy = (dependency_entry.get("datafeed_policy")
                       if isinstance(dependency_entry, dict) else None)
    problems += expect(datafeed_policy == nvdfeed.EXPECTED_POLICY,
                       "TOOLCHAIN_SECURITY_DATAFEED",
                       f"{where}#owasp-dependency-check.datafeed_policy",
                       "the NVD mirror, freshness budget and request timeout must match the "
                       "reviewed OWASP data-feed policy", "NN-12")

    dependency_blocks = _kotlin_blocks(code, r"\bdependencyCheck")
    problems += expect(len(dependency_blocks) == 1, "TOOLCHAIN_SECURITY_GATE",
                       "build.gradle.kts#dependencyCheck",
                       "root build must have exactly one dependencyCheck control block", "NN-12")
    if len(dependency_blocks) == 1:
        body = re.sub(r"\s+", "", dependency_blocks[0])
        problems += expect(body.count('format.set("JSON")') == 1
                           and body.count("format.set(") == 1,
                           "TOOLCHAIN_SECURITY_REPORT", "build.gradle.kts#dependencyCheck",
                           "dependency scan must emit exactly one JSON report", "NN-12")
        problems += expect(
            body.count('outputDirectory.set(layout.buildDirectory.dir("reports"))') == 1
            and body.count("outputDirectory.set(") == 1,
            "TOOLCHAIN_SECURITY_REPORT", "build.gradle.kts#dependencyCheck",
            "dependency scan JSON must be written under build/reports", "NN-12")
        problems += expect(body.count("failBuildOnCVSS.set(0.0f)") == 1
                           and body.count("failBuildOnCVSS.set(") == 1,
                           "TOOLCHAIN_SECURITY_GATE", "build.gradle.kts#dependencyCheck",
                           "every known vulnerability, including unscored findings, must block",
                           "NN-12")
        problems += expect(body.count("failOnError.set(true)") == 1
                           and body.count("failOnError.set(") == 1,
                           "TOOLCHAIN_SECURITY_GATE", "build.gradle.kts#dependencyCheck",
                           "feed, analysis and report errors must fail the build", "NN-12")
        problems += expect("autoUpdate.set(false)" not in body and "autoUpdate=false" not in body,
                           "TOOLCHAIN_SECURITY_GATE", "build.gradle.kts#dependencyCheck",
                           "live vulnerability data updates cannot be disabled", "NN-12")
        nvd_blocks = _kotlin_blocks(dependency_blocks[0], r"\bnvd")
        problems += expect(len(nvd_blocks) == 1,
                           "TOOLCHAIN_SECURITY_DATAFEED",
                           "build.gradle.kts#dependencyCheck.nvd",
                           "dependency scan must configure exactly one governed NVD source",
                           "NN-12")
        if len(nvd_blocks) == 1:
            nvd_body = re.sub(r"\s+", "", nvd_blocks[0])
            expected_feed = f'datafeedUrl.set("{nvdfeed.DATAFEED_URL}")'
            problems += expect(nvd_body.count(expected_feed) == 1
                               and nvd_body.count("datafeedUrl.set(") == 1,
                               "TOOLCHAIN_SECURITY_DATAFEED",
                               "build.gradle.kts#dependencyCheck.nvd",
                               "Dependency-Check must use exactly the governed OWASP data feed",
                               "NN-12")
            for credential in ("apiKey", "datafeedUser", "datafeedPassword",
                               "datafeedBearerToken", "endpoint"):
                problems += expect(credential not in nvd_body,
                                   "TOOLCHAIN_SECURITY_DATAFEED",
                                   "build.gradle.kts#dependencyCheck.nvd",
                                   f"'{credential}' cannot override the keyless governed feed",
                                   "NN-12")
        problems += expect("skip.set(true)" not in body and "skip=true" not in body,
                           "TOOLCHAIN_SECURITY_COVERAGE", "build.gradle.kts#dependencyCheck",
                           "dependency analysis cannot be skipped", "NN-12")
        for restricted in ("skipProjects", "scanProjects", "skipConfigurations",
                           "scanConfigurations"):
            problems += expect(restricted not in body, "TOOLCHAIN_SECURITY_COVERAGE",
                               "build.gradle.kts#dependencyCheck",
                               f"'{restricted}' would narrow the declared multi-project scan",
                               "NN-12")

    cyclonedx_blocks = _kotlin_blocks(code, r"\btasks\.cyclonedxBom")
    problems += expect(len(cyclonedx_blocks) == 1, "TOOLCHAIN_SECURITY_REPORT",
                       "build.gradle.kts#cyclonedxBom",
                       "root build must configure exactly one aggregate CycloneDX task", "NN-12")
    if len(cyclonedx_blocks) == 1:
        body = re.sub(r"\s+", "", cyclonedx_blocks[0])
        problems += expect(
            body.count('jsonOutput.set(layout.buildDirectory.file("reports/bom.json"))') == 1
            and body.count("jsonOutput.set(") == 1,
            "TOOLCHAIN_SECURITY_REPORT", "build.gradle.kts#cyclonedxBom",
            "aggregate SBOM must be written to build/reports/bom.json", "NN-12")
        problems += expect(body.count("xmlOutput.unsetConvention()") == 1,
                           "TOOLCHAIN_SECURITY_REPORT", "build.gradle.kts#cyclonedxBom",
                           "aggregate SBOM must disable the unused XML output explicitly",
                           "NN-12")
        problems += expect("enabled=false" not in body,
                           "TOOLCHAIN_SECURITY_COVERAGE", "build.gradle.kts#cyclonedxBom",
                           "aggregate SBOM generation cannot be disabled", "NN-12")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    try:
        rendered = buildgen.render_all(root)
    except (KeyError, TypeError, ValueError, OSError) as exc:
        return [Problem("BUILD_GENERATOR", str(PATH),
                        f"generated build inputs are incomplete or invalid: {exc}", "NN-12")]
    for rel, expected in sorted(rendered.items()):
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
