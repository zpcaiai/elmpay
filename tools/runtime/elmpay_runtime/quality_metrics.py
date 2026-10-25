"""Machine-enforced line-coverage and mutation-testing gate.

The public runner executes the governed tools itself and evaluates only reports
created by that same invocation.  It never accepts a caller supplied percentage
or a boolean assertion of success.  Coverage.py and JaCoCo line counts are
recomputed from per-file line details; PIT scores are recomputed from every
reported mutant.  Missing tools, stale/missing module reports and malformed
reports fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Mapping, Sequence
import xml.etree.ElementTree as ET

from .common import ValidationError, canonical_json, require_list, require_mapping, require_text


MINIMUM_LINE_COVERAGE = 80.0
MINIMUM_MUTATION_SCORE = 60.0
PYTHON_SOURCE_ROOTS = ("tools/paygov", "tools/runtime/elmpay_runtime")
PYTHON_DISCOVERIES = ("tools/tests", "testing")
QUALITY_TASK = "qualityCoverageMutationReports"
_SAFE_TOOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
_JACOCO_DOCTYPE = (
    b'<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">'
)
_PIT_KILLED = frozenset({"KILLED"})
_PIT_TERMINAL = frozenset(
    {
        "KILLED",
        "SURVIVED",
        "NO_COVERAGE",
        "TIMED_OUT",
        "RUN_ERROR",
        "MEMORY_ERROR",
        "NON_VIABLE",
    }
)


@dataclass(frozen=True)
class LineCounts:
    covered: int
    total: int

    @property
    def percent(self) -> float:
        return 100.0 * self.covered / self.total if self.total else 0.0

    def plus(self, other: "LineCounts") -> "LineCounts":
        return LineCounts(self.covered + other.covered, self.total + other.total)


@dataclass(frozen=True)
class MutationCounts:
    killed: int
    total: int

    @property
    def percent(self) -> float:
        return 100.0 * self.killed / self.total if self.total else 0.0

    def plus(self, other: "MutationCounts") -> "MutationCounts":
        return MutationCounts(self.killed + other.killed, self.total + other.total)


@dataclass(frozen=True)
class ToolExecution:
    tool: str
    command: tuple[str, ...]
    exit_code: int
    duration_ms: int
    stdout_digest: str
    stderr_digest: str
    version: str
    failure_kind: str = "NONE"


@dataclass(frozen=True)
class SourceBinding:
    git_head: str
    source_digest: str
    working_tree_dirty: bool
    generated_at: str


@dataclass(frozen=True)
class QualityMetricResult:
    allowed: bool
    status: str
    reasons: tuple[str, ...]
    checks: tuple[str, ...]
    coverage: LineCounts
    mutation: MutationCounts
    executions: tuple[ToolExecution, ...]
    report_digests: Mapping[str, str]
    source_binding: SourceBinding

    def document(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "status": self.status,
            "reasons": list(self.reasons),
            "checks": list(self.checks),
            "thresholds": {
                "lineCoverageMinimumPercent": MINIMUM_LINE_COVERAGE,
                "mutationScoreMinimumPercent": MINIMUM_MUTATION_SCORE,
            },
            "coverage": {
                "coveredLines": self.coverage.covered,
                "totalLines": self.coverage.total,
                "percent": round(self.coverage.percent, 6),
            },
            "mutation": {
                "killed": self.mutation.killed,
                "total": self.mutation.total,
                "scorePercent": round(self.mutation.percent, 6),
            },
            "executions": [
                {
                    "tool": item.tool,
                    "command": list(item.command),
                    "exitCode": item.exit_code,
                    "durationMilliseconds": item.duration_ms,
                    "stdoutDigest": item.stdout_digest,
                    "stderrDigest": item.stderr_digest,
                    "version": item.version,
                    "failureKind": item.failure_kind,
                }
                for item in self.executions
            ],
            "reportDigests": dict(sorted(self.report_digests.items())),
            "gitHead": self.source_binding.git_head,
            "sourceDigest": self.source_binding.source_digest,
            "workingTreeDirty": self.source_binding.working_tree_dirty,
            "generatedAt": self.source_binding.generated_at,
            "certificationStatus": "NOT_CERTIFIED",
        }


def _integer(value: object, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationError(f"{field} must be an integer >= {minimum}")
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_bounded(path: Path, maximum: int) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValidationError(f"required report is unavailable: {path}") from exc
    if size < 1 or size > maximum:
        raise ValidationError(f"report size is outside the safe bound: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ValidationError(f"required report cannot be read: {path}") from exc


def _safe_report_path(root: Path, relative: str) -> Path:
    text = require_text(relative, "report path")
    candidate = root / text
    resolved_root = root.resolve()
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(resolved_root) or not text.startswith("build/"):
        raise ValidationError("quality report path must remain under repository build/")
    if candidate.is_symlink():
        raise ValidationError("quality report must not be a symbolic link")
    return candidate


def _normalise_source_file(root: Path, value: str) -> str:
    path = Path(value)
    resolved = path.resolve(strict=False) if path.is_absolute() else (root / path).resolve(strict=False)
    if not resolved.is_relative_to(root.resolve()):
        raise ValidationError("coverage source path escapes the repository")
    return resolved.relative_to(root.resolve()).as_posix()


def _expected_python_files(root: Path, source_roots: Sequence[str]) -> set[str]:
    expected: set[str] = set()
    for relative in source_roots:
        source = (root / relative).resolve(strict=False)
        if not source.is_dir() or not source.is_relative_to(root.resolve()):
            raise ValidationError(f"Python coverage source root is unavailable: {relative}")
        for path in source.rglob("*.py"):
            if "__pycache__" not in path.parts:
                expected.add(path.resolve().relative_to(root.resolve()).as_posix())
    if not expected:
        raise ValidationError("Python coverage scope contains no source files")
    return expected


def parse_coverage_json(
    path: Path,
    *,
    root: Path,
    expected_source_roots: Sequence[str],
) -> LineCounts:
    """Recompute Coverage.py line totals from each source file."""

    raw = _read_bounded(path, 64 * 1024 * 1024)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("Coverage.py report is not valid JSON") from exc
    report = require_mapping(document, "Coverage.py report")
    meta = require_mapping(report.get("meta"), "Coverage.py meta")
    version = require_text(meta.get("version"), "Coverage.py version")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
        raise ValidationError("Coverage.py version is invalid")
    files = require_mapping(report.get("files"), "Coverage.py files")
    if not files:
        raise ValidationError("Coverage.py report contains no measured files")
    expected = _expected_python_files(root, expected_source_roots)
    seen: set[str] = set()
    counts = LineCounts(0, 0)
    for raw_name, raw_file in files.items():
        name = _normalise_source_file(root, require_text(raw_name, "coverage file name"))
        if name in seen:
            raise ValidationError("Coverage.py report contains duplicate source files")
        if not any(name == source or name.startswith(source + "/") for source in expected_source_roots):
            raise ValidationError(f"Coverage.py report contains an out-of-scope file: {name}")
        seen.add(name)
        item = require_mapping(raw_file, f"coverage file {name}")
        executed = {
            _integer(value, f"{name}.executed_lines", 1)
            for value in require_list(item.get("executed_lines"), f"{name}.executed_lines")
        }
        missing = {
            _integer(value, f"{name}.missing_lines", 1)
            for value in require_list(item.get("missing_lines"), f"{name}.missing_lines")
        }
        if executed & missing:
            raise ValidationError(f"Coverage.py executed and missing lines overlap: {name}")
        summary = require_mapping(item.get("summary"), f"{name}.summary")
        covered = _integer(summary.get("covered_lines"), f"{name}.covered_lines")
        total = _integer(summary.get("num_statements"), f"{name}.num_statements")
        missing_count = _integer(summary.get("missing_lines"), f"{name}.missing_count")
        if covered != len(executed) or missing_count != len(missing) or total != len(executed | missing):
            raise ValidationError(f"Coverage.py summary does not match detailed lines: {name}")
        counts = counts.plus(LineCounts(covered, total))
    missing_files = sorted(expected - seen)
    if missing_files:
        raise ValidationError(
            "Coverage.py report omits governed source files: " + ",".join(missing_files[:10])
        )
    totals = require_mapping(report.get("totals"), "Coverage.py totals")
    if (
        _integer(totals.get("covered_lines"), "coverage totals covered_lines") != counts.covered
        or _integer(totals.get("num_statements"), "coverage totals num_statements") != counts.total
    ):
        raise ValidationError("Coverage.py aggregate totals do not match file details")
    if counts.total == 0:
        raise ValidationError("Coverage.py report contains no executable lines")
    return counts


def parse_jacoco_xml(path: Path) -> LineCounts:
    """Recompute JaCoCo coverage from source-file LINE counters."""

    raw = _read_bounded(path, 64 * 1024 * 1024)
    upper = raw.upper()
    if b"<!ENTITY" in upper:
        raise ValidationError("JaCoCo report must not contain an entity declaration")
    doctypes = re.findall(br"<!DOCTYPE[^>]*>", raw, flags=re.IGNORECASE)
    if doctypes:
        if doctypes != [_JACOCO_DOCTYPE]:
            raise ValidationError("JaCoCo report contains an untrusted DOCTYPE")
        raw = raw.replace(_JACOCO_DOCTYPE, b"", 1)
    if b"<!DOCTYPE" in raw.upper():
        raise ValidationError("JaCoCo report contains an untrusted DOCTYPE")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValidationError("JaCoCo report is not valid XML") from exc
    if root.tag != "report":
        raise ValidationError("JaCoCo report root must be report")
    sources = root.findall("./package/sourcefile")
    if not sources:
        raise ValidationError("JaCoCo report contains no source files")
    counts = LineCounts(0, 0)
    seen: set[tuple[str, str]] = set()
    for source in sources:
        parent = next(
            (package for package in root.findall("./package") if source in list(package)),
            None,
        )
        if parent is None:
            raise ValidationError("JaCoCo source file has no package")
        key = (parent.attrib.get("name", ""), source.attrib.get("name", ""))
        if not key[1] or key in seen:
            raise ValidationError("JaCoCo report contains a duplicate/unnamed source file")
        seen.add(key)
        counter = next(
            (item for item in source.findall("./counter") if item.attrib.get("type") == "LINE"),
            None,
        )
        if counter is None:
            raise ValidationError("JaCoCo source file has no LINE counter")
        missed = _xml_integer(counter.attrib.get("missed"), "JaCoCo missed lines")
        covered = _xml_integer(counter.attrib.get("covered"), "JaCoCo covered lines")
        detail_covered = 0
        detail_missed = 0
        for line in source.findall("./line"):
            instructions_covered = _xml_integer(line.attrib.get("ci"), "JaCoCo line ci")
            instructions_missed = _xml_integer(line.attrib.get("mi"), "JaCoCo line mi")
            if instructions_covered > 0:
                detail_covered += 1
            elif instructions_missed > 0:
                detail_missed += 1
        if covered != detail_covered or missed != detail_missed:
            raise ValidationError("JaCoCo source counter does not match detailed lines")
        counts = counts.plus(LineCounts(covered, covered + missed))
    root_counter = next(
        (item for item in root.findall("./counter") if item.attrib.get("type") == "LINE"),
        None,
    )
    if root_counter is None:
        raise ValidationError("JaCoCo report has no aggregate LINE counter")
    root_missed = _xml_integer(root_counter.attrib.get("missed"), "JaCoCo total missed")
    root_covered = _xml_integer(root_counter.attrib.get("covered"), "JaCoCo total covered")
    if root_covered != counts.covered or root_covered + root_missed != counts.total:
        raise ValidationError("JaCoCo aggregate counter does not match source details")
    if counts.total == 0:
        raise ValidationError("JaCoCo report contains no executable lines")
    return counts


def _xml_integer(value: object, field: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value):
        raise ValidationError(f"{field} is invalid")
    return int(value)


def parse_pitest_xml(path: Path) -> MutationCounts:
    """Recompute mutation score from every PIT mutation element."""

    raw = _read_bounded(path, 128 * 1024 * 1024)
    upper = raw[:4096].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValidationError("PIT report must not contain a DTD or entity")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValidationError("PIT report is not valid XML") from exc
    if root.tag != "mutations":
        raise ValidationError("PIT report root must be mutations")
    mutations = root.findall("./mutation")
    if not mutations:
        raise ValidationError("PIT report contains no mutants")
    killed = 0
    seen: set[tuple[str, ...]] = set()
    for mutation in mutations:
        status = require_text(mutation.attrib.get("status"), "PIT mutation status")
        if status not in _PIT_TERMINAL:
            raise ValidationError(f"PIT mutation has an unknown status: {status}")
        detected = mutation.attrib.get("detected")
        if detected not in {"true", "false"}:
            raise ValidationError("PIT mutation detected flag is invalid")
        fields = tuple(
            require_text(mutation.findtext(name), f"PIT mutation {name}")
            for name in (
                "sourceFile",
                "mutatedClass",
                "mutatedMethod",
                "methodDescription",
                "lineNumber",
                "mutator",
                "index",
                "block",
            )
        )
        _xml_integer(fields[4], "PIT mutation lineNumber")
        _xml_integer(fields[6], "PIT mutation index")
        _xml_integer(fields[7], "PIT mutation block")
        if fields in seen:
            raise ValidationError("PIT report contains a duplicate mutant")
        seen.add(fields)
        if status in _PIT_KILLED:
            if detected != "true":
                raise ValidationError("PIT killed mutation is not marked detected")
            killed += 1
        elif detected == "true" and status in {"SURVIVED", "NO_COVERAGE"}:
            raise ValidationError("PIT undetected mutation has contradictory detected flag")
    return MutationCounts(killed, len(mutations))


def _gradle_modules(root: Path) -> tuple[tuple[str, Path], ...]:
    try:
        catalog = json.loads((root / "governance/version-catalog.json").read_text())
        registry = json.loads((root / "governance/module-registry.json").read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("Gradle module SSOT cannot be loaded") from exc
    catalog_map = require_mapping(catalog, "version catalog")
    systems = require_mapping(catalog_map.get("modules_by_build_system"), "build systems")
    names = tuple(require_text(item, "Gradle module name") for item in require_list(systems.get("gradle"), "Gradle modules"))
    registry_map = require_mapping(registry, "module registry")
    paths: dict[str, str] = {}
    for raw in require_list(registry_map.get("modules"), "module registry modules"):
        item = require_mapping(raw, "module registry item")
        paths[require_text(item.get("name"), "module name")] = require_text(
            item.get("path"), "module path"
        )
    if len(names) != len(set(names)) or not names:
        raise ValidationError("Gradle module SSOT is empty or duplicated")
    result: list[tuple[str, Path]] = []
    for name in names:
        relative = paths.get(name)
        if relative is None:
            raise ValidationError(f"Gradle module has no registry path: {name}")
        path = (root / relative).resolve(strict=False)
        if not path.is_dir() or not path.is_relative_to(root.resolve()):
            raise ValidationError(f"Gradle module path is unavailable: {name}")
        result.append((name, path))
    return tuple(result)


def _catalogue_version(root: Path, identifier: str) -> str:
    try:
        document = json.loads((root / "governance/version-catalog.json").read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("version catalogue cannot be loaded") from exc
    catalogue = require_mapping(document, "version catalogue")
    matches = [
        require_mapping(item, "version catalogue entry")
        for item in require_list(catalogue.get("entries"), "version catalogue entries")
        if isinstance(item, dict) and item.get("id") == identifier
    ]
    if len(matches) != 1:
        raise ValidationError(f"version catalogue must contain exactly one {identifier}")
    entry = matches[0]
    version = require_text(entry.get("version"), f"{identifier} version")
    if entry.get("pin_type") != "exact" or not _VERSION.fullmatch(version):
        raise ValidationError(f"{identifier} must use an exact version")
    return version


def _validate_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(require_mapping(policy, "quality metrics policy"))
    if value.get("schemaVersion") != 1:
        raise ValidationError("quality metrics policy schemaVersion must be 1")
    if not isinstance(value.get("requireCleanWorkingTree"), bool):
        raise ValidationError("requireCleanWorkingTree must be a boolean")
    thresholds = require_mapping(value.get("thresholds"), "quality metric thresholds")
    line = thresholds.get("lineCoverageMinimumPercent")
    mutation = thresholds.get("mutationScoreMinimumPercent")
    if (
        isinstance(line, bool)
        or not isinstance(line, (int, float))
        or float(line) < MINIMUM_LINE_COVERAGE
        or float(line) > 100
    ):
        raise ValidationError("line coverage threshold cannot be lower than 80%")
    if (
        isinstance(mutation, bool)
        or not isinstance(mutation, (int, float))
        or float(mutation) < MINIMUM_MUTATION_SCORE
        or float(mutation) > 100
    ):
        raise ValidationError("mutation score threshold cannot be lower than 60%")
    python = require_mapping(value.get("pythonCoverage"), "Python coverage policy")
    required_version = require_text(
        python.get("requiredVersion"), "Coverage.py required version"
    )
    if not _VERSION.fullmatch(required_version):
        raise ValidationError("Coverage.py required version must be exact")
    roots = tuple(require_text(item, "Python source root") for item in require_list(python.get("sourceRoots"), "Python source roots"))
    discoveries = tuple(require_text(item, "Python discovery root") for item in require_list(python.get("testDiscoveries"), "Python discoveries"))
    if roots != PYTHON_SOURCE_ROOTS or discoveries != PYTHON_DISCOVERIES:
        raise ValidationError("Python coverage scope must match the governed complete scope")
    candidates = tuple(require_text(item, "coverage executable") for item in require_list(python.get("executableCandidates"), "coverage executables"))
    if not candidates or any(not _SAFE_TOOL.fullmatch(item) for item in candidates):
        raise ValidationError("coverage executable candidates are invalid")
    _safe_relative_build_path(require_text(python.get("dataFile"), "coverage dataFile"))
    _safe_relative_build_path(require_text(python.get("report"), "coverage report"))
    timeout = _integer(python.get("timeoutSeconds"), "Python coverage timeout", 1)
    if timeout > 7_200:
        raise ValidationError("Python coverage timeout is outside the safe bound")
    java = require_mapping(value.get("javaQuality"), "Java quality policy")
    if java.get("task") != QUALITY_TASK or java.get("gradleExecutable") != "./gradlew":
        raise ValidationError("Java quality command must use the governed wrapper task")
    timeout = _integer(java.get("timeoutSeconds"), "Java quality timeout", 1)
    if timeout > 14_400:
        raise ValidationError("Java quality timeout is outside the safe bound")
    if java.get("jacocoReport") != "build/reports/jacoco/test/jacocoTestReport.xml":
        raise ValidationError("JaCoCo report path is not governed")
    if java.get("pitestReport") != "build/reports/pitest/mutations.xml":
        raise ValidationError("PIT report path is not governed")
    return value


def _safe_relative_build_path(value: str) -> None:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not value.startswith("build/"):
        raise ValidationError("quality output path must remain under build/")


def capture_source_binding(root: Path) -> SourceBinding:
    """Bind a gate run to the current commit and all governed test/source inputs."""

    root = root.resolve()
    try:
        head_process = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        status_process = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationError("git source binding is unavailable") from exc
    head = head_process.stdout.decode("ascii", errors="strict").strip()
    if head_process.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
        raise ValidationError("git HEAD source binding is unavailable")
    if status_process.returncode != 0 or len(status_process.stdout) > 4 * 1024 * 1024:
        raise ValidationError("git working-tree binding is unavailable")

    paths: set[Path] = set()
    tree_roots = [root / relative for relative in (*PYTHON_SOURCE_ROOTS, *PYTHON_DISCOVERIES)]
    tree_roots.extend(module / "src" for _, module in _gradle_modules(root))
    for tree in tree_roots:
        if not tree.exists():
            continue
        if tree.is_symlink() or not tree.resolve().is_relative_to(root):
            raise ValidationError("governed source tree is unsafe")
        for path in tree.rglob("*"):
            if path.is_symlink():
                raise ValidationError("governed source input must not be a symbolic link")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                paths.add(path.resolve())
    for relative in (
        "governance/version-catalog.json",
        "governance/module-registry.json",
        "testing/quality-metrics-policy.json",
        "tools/paygov/buildgen.py",
        "tools/quality_gate.py",
        "tools/runtime/elmpay_runtime/quality_metrics.py",
        "build.gradle.kts",
        "settings.gradle.kts",
        "gradle/libs.versions.toml",
        "gradle/wrapper/gradle-wrapper.properties",
        "gradle/wrapper/gradle-wrapper.jar",
    ):
        path = root / relative
        if path.is_symlink():
            raise ValidationError("governed configuration must not be a symbolic link")
        if path.is_file():
            paths.add(path.resolve())
    if not paths:
        raise ValidationError("governed source binding contains no files")

    digest = hashlib.sha256()
    total_bytes = 0
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ValidationError("governed source input is unavailable") from exc
        total_bytes += size
        if size > 64 * 1024 * 1024 or total_bytes > 512 * 1024 * 1024:
            raise ValidationError("governed source binding exceeds the safe size bound")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(size.to_bytes(8, "big"))
        file_digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    file_digest.update(chunk)
        except OSError as exc:
            raise ValidationError("governed source input cannot be read") from exc
        digest.update(file_digest.digest())
    return SourceBinding(
        git_head=head,
        source_digest=digest.hexdigest(),
        working_tree_dirty=bool(status_process.stdout),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def _unknown_source_binding() -> SourceBinding:
    return SourceBinding(
        git_head="UNKNOWN",
        source_digest="",
        working_tree_dirty=True,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def evaluate_quality_reports(
    *,
    root: Path,
    policy: Mapping[str, Any],
    python_report: Path,
    jacoco_reports: Sequence[Path],
    pitest_reports: Sequence[Path],
    executions: Sequence[ToolExecution] = (),
    require_successful_executions: bool = True,
    expected_source_binding: SourceBinding | None = None,
) -> QualityMetricResult:
    """Evaluate detailed reports; intended for the in-process runner and tests."""

    governed = _validate_policy(policy)
    reasons: list[str] = []
    checks: list[str] = []
    thresholds = require_mapping(governed["thresholds"], "quality metric thresholds")
    line_threshold = float(thresholds["lineCoverageMinimumPercent"])
    mutation_threshold = float(thresholds["mutationScoreMinimumPercent"])
    source_binding = _unknown_source_binding()
    try:
        coverage_policy = require_mapping(
            governed["pythonCoverage"], "Python coverage policy"
        )
        required_coverage = require_text(
            coverage_policy["requiredVersion"], "Coverage.py required version"
        )
        if _catalogue_version(root, "coverage-py") != required_coverage:
            reasons.append("coverage_version_ssot_mismatch")
        source_binding = capture_source_binding(root)
        if governed["requireCleanWorkingTree"] and source_binding.working_tree_dirty:
            reasons.append("working_tree_dirty")
        if expected_source_binding is not None and (
            expected_source_binding.git_head != source_binding.git_head
            or expected_source_binding.source_digest != source_binding.source_digest
            or expected_source_binding.working_tree_dirty != source_binding.working_tree_dirty
        ):
            reasons.append("source_binding_changed_during_execution")
    except (OSError, UnicodeError, ValidationError) as exc:
        reasons.append(f"source_binding_invalid:{exc}")
    if require_successful_executions:
        if not _execution_receipts_are_complete(root, python_report, executions):
            reasons.append("execution_receipts_missing")
        if executions and any(item.exit_code != 0 for item in executions):
            reasons.append("quality_tool_execution_failed")
    coverage = LineCounts(0, 0)
    mutation = MutationCounts(0, 0)
    digests: dict[str, str] = {}
    try:
        python_counts = parse_coverage_json(
            python_report,
            root=root,
            expected_source_roots=PYTHON_SOURCE_ROOTS,
        )
        coverage = coverage.plus(python_counts)
        digests[python_report.relative_to(root).as_posix()] = _sha256(python_report.read_bytes())
        checks.append(f"python_line_coverage:{python_counts.covered}/{python_counts.total}")
        if python_counts.percent + 1e-12 < line_threshold:
            reasons.append(
                "python_line_coverage_below_threshold:"
                f"{python_counts.percent:.6f}<{line_threshold:.6f}"
            )
        expected_modules = _gradle_modules(root)
        if len(jacoco_reports) != len(expected_modules) or len(pitest_reports) != len(expected_modules):
            raise ValidationError("every Gradle module must have one JaCoCo and one PIT report")
        for (name, module_path), jacoco_path, pitest_path in zip(
            expected_modules, jacoco_reports, pitest_reports, strict=True
        ):
            expected_jacoco = module_path / "build/reports/jacoco/test/jacocoTestReport.xml"
            expected_pitest = module_path / "build/reports/pitest/mutations.xml"
            if jacoco_path.resolve(strict=False) != expected_jacoco.resolve(strict=False):
                raise ValidationError(f"JaCoCo report path is not bound to module: {name}")
            if pitest_path.resolve(strict=False) != expected_pitest.resolve(strict=False):
                raise ValidationError(f"PIT report path is not bound to module: {name}")
            jacoco = parse_jacoco_xml(jacoco_path)
            pitest = parse_pitest_xml(pitest_path)
            coverage = coverage.plus(jacoco)
            mutation = mutation.plus(pitest)
            digests[jacoco_path.relative_to(root).as_posix()] = _sha256(jacoco_path.read_bytes())
            digests[pitest_path.relative_to(root).as_posix()] = _sha256(pitest_path.read_bytes())
            checks.append(f"jacoco:{name}:{jacoco.covered}/{jacoco.total}")
            checks.append(f"pitest:{name}:{pitest.killed}/{pitest.total}")
            if jacoco.percent + 1e-12 < line_threshold:
                reasons.append(
                    f"jacoco_line_coverage_below_threshold:{name}:"
                    f"{jacoco.percent:.6f}<{line_threshold:.6f}"
                )
            if pitest.percent + 1e-12 < mutation_threshold:
                reasons.append(
                    f"pitest_mutation_score_below_threshold:{name}:"
                    f"{pitest.percent:.6f}<{mutation_threshold:.6f}"
                )
    except (OSError, ValidationError, ValueError) as exc:
        reasons.append(f"quality_report_invalid:{exc}")
    if coverage.total == 0:
        reasons.append("line_coverage_report_missing")
    elif coverage.percent + 1e-12 < line_threshold:
        reasons.append(
            f"line_coverage_below_threshold:{coverage.percent:.6f}<{line_threshold:.6f}"
        )
    if mutation.total == 0:
        reasons.append("mutation_report_missing")
    elif mutation.percent + 1e-12 < mutation_threshold:
        reasons.append(
            f"mutation_score_below_threshold:{mutation.percent:.6f}<{mutation_threshold:.6f}"
        )
    status = "PASSED" if not reasons else "FAILED"
    return QualityMetricResult(
        not reasons,
        status,
        tuple(dict.fromkeys(reasons)),
        tuple(checks),
        coverage,
        mutation,
        tuple(executions),
        digests,
        source_binding,
    )


def _execution_receipts_are_complete(
    root: Path, python_report: Path, executions: Sequence[ToolExecution]
) -> bool:
    expected_coverage_count = len(PYTHON_DISCOVERIES) + 1
    if len(executions) != expected_coverage_count + 1:
        return False
    coverage = executions[:expected_coverage_count]
    gradle = executions[-1]
    if any(item.tool != "coverage.py" for item in coverage):
        return False
    if gradle.tool != "gradle-jacoco-pitest":
        return False
    for item in executions:
        if (
            not item.command
            or isinstance(item.exit_code, bool)
            or not isinstance(item.exit_code, int)
            or isinstance(item.duration_ms, bool)
            or not isinstance(item.duration_ms, int)
            or item.duration_ms < 0
            or not isinstance(item.version, str)
            or not item.version.strip()
            or item.failure_kind not in {
                "NONE",
                "EXECUTION_FAILED",
                "TIMEOUT",
                "OFFLINE_DEPENDENCY_UNAVAILABLE",
            }
            or (item.exit_code == 0 and item.failure_kind != "NONE")
            or not re.fullmatch(r"[0-9a-f]{64}", item.stdout_digest)
            or not re.fullmatch(r"[0-9a-f]{64}", item.stderr_digest)
        ):
            return False
    executable = coverage[0].command[0]
    sources = ",".join(PYTHON_SOURCE_ROOTS)
    for index, discovery in enumerate(PYTHON_DISCOVERIES):
        append = ("--append",) if index else ()
        expected = (
            executable,
            "run",
            *append,
            "--branch",
            f"--source={sources}",
            "-m",
            "unittest",
            "discover",
            "-s",
            discovery,
            "-t",
            ".",
        )
        if coverage[index].command != expected:
            return False
    if coverage[-1].command[:3] != (executable, "json", "-o"):
        return False
    expected_report = python_report.resolve()
    try:
        receipt_report = Path(coverage[-1].command[3]).resolve()
    except (IndexError, OSError):
        return False
    if len(coverage[-1].command) != 4 or receipt_report != expected_report:
        return False
    wrapper = str((root / "gradlew").resolve())
    expected_gradle = {
        (wrapper, "--no-daemon", QUALITY_TASK),
        (wrapper, "--no-daemon", "--offline", QUALITY_TASK),
    }
    return gradle.command in expected_gradle


def _tool_execution(
    tool: str,
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: int,
    version: str,
) -> ToolExecution:
    started = time.monotonic_ns()
    failure_kind = "NONE"
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
        exit_code = int(completed.returncode)
        stdout = completed.stdout
        stderr = completed.stderr
        if exit_code != 0:
            combined = (stdout + b"\n" + stderr).lower()
            offline_dependency_failure = (
                tool == "gradle-jacoco-pitest"
                and "--offline" in command
                and b"offline mode" in combined
                and any(
                    marker in combined
                    for marker in (
                        b"no cached",
                        b"not available",
                        b"could not resolve",
                        b"could not download",
                    )
                )
            )
            failure_kind = (
                "OFFLINE_DEPENDENCY_UNAVAILABLE"
                if offline_dependency_failure
                else "EXECUTION_FAILED"
            )
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = bytes(exc.stdout or b"")
        stderr = bytes(exc.stderr or b"") + b"\nquality tool timed out"
        failure_kind = "TIMEOUT"
    duration = max(0, (time.monotonic_ns() - started) // 1_000_000)
    output_root = _safe_report_path(cwd, "build/quality-metrics/tool-output")
    output_root.mkdir(parents=True, exist_ok=True)
    output_dir = Path(tempfile.mkdtemp(prefix="execution-", dir=output_root))
    receipt = {
        "tool": tool, "command": list(command), "executed": True,
        "executor_pid": os.getpid(), "exit_code": exit_code,
        "stdout_sha256": _sha256(stdout), "stderr_sha256": _sha256(stderr),
    }
    for name, raw in (
        ("stdout.log", stdout), ("stderr.log", stderr),
        ("receipt.json", json.dumps(receipt, sort_keys=True).encode("utf-8")),
    ):
        descriptor = os.open(output_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
    return ToolExecution(
        tool,
        tuple(command),
        exit_code,
        int(duration),
        _sha256(stdout),
        _sha256(stderr),
        version,
        failure_kind,
    )


def _canonical_tool_version(output: bytes) -> str:
    pattern = (
        r"(?:Gradle [0-9]+(?:\.[0-9]+){1,3}|"
        r"Coverage\.py,? version [0-9]+(?:\.[0-9]+){1,3}"
        r"(?: (?:with|without) C extension)?)"
    )
    identities = [line.strip() for line in output.decode("utf-8", errors="replace").splitlines()
                  if re.fullmatch(pattern, line.strip())]
    if len(identities) != 1 or len(identities[0]) > 256:
        raise ValidationError("quality tool canonical version is missing or ambiguous")
    return identities[0]


def _tool_version(executable: str, arguments: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            [executable, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationError(f"quality tool version probe failed: {executable}") from exc
    text = completed.stdout.decode("utf-8", errors="replace").strip().splitlines()
    if completed.returncode != 0 or not text:
        raise ValidationError(f"quality tool version probe failed: {executable}")
    return _canonical_tool_version(completed.stdout)


def _fresh(path: Path, started_ns: int) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and path.stat().st_mtime_ns >= started_ns
    except OSError:
        return False


def run_quality_metrics(
    root: Path,
    policy: Mapping[str, Any],
    *,
    offline: bool = False,
) -> QualityMetricResult:
    """Execute Coverage.py, JaCoCo and PIT, then evaluate this run's reports."""

    root = root.resolve()
    governed = _validate_policy(policy)
    python = require_mapping(governed["pythonCoverage"], "Python coverage policy")
    java = require_mapping(governed["javaQuality"], "Java quality policy")
    try:
        source_binding = capture_source_binding(root)
        required_coverage_version = require_text(
            python["requiredVersion"], "Coverage.py required version"
        )
        if _catalogue_version(root, "coverage-py") != required_coverage_version:
            return _blocked("coverage_version_ssot_mismatch", binding=source_binding)
    except (OSError, UnicodeError, ValidationError) as exc:
        return _blocked(f"source_binding_invalid:{exc}")
    if governed["requireCleanWorkingTree"] and source_binding.working_tree_dirty:
        return _failed("working_tree_dirty", binding=source_binding)
    candidates = tuple(
        require_text(item, "coverage executable")
        for item in require_list(python["executableCandidates"], "coverage executables")
    )
    coverage_executable = next((shutil.which(item) for item in candidates if shutil.which(item)), None)
    if coverage_executable is None:
        return _blocked("coverage_tool_unavailable", binding=source_binding)
    try:
        coverage_version = _tool_version(coverage_executable, ("--version",))
    except ValidationError as exc:
        return _blocked(f"coverage_tool_unavailable:{exc}", binding=source_binding)
    version_match = re.search(
        r"\bCoverage\.py,? version ([0-9]+(?:\.[0-9]+){1,3})\b",
        coverage_version,
    )
    if version_match is None:
        return _blocked("coverage_tool_identity_mismatch", binding=source_binding)
    if version_match.group(1) != required_coverage_version:
        return _blocked(
            "coverage_tool_version_mismatch:"
            f"{version_match.group(1)}!={required_coverage_version}",
            binding=source_binding,
        )

    data_file = _safe_report_path(root, require_text(python["dataFile"], "coverage dataFile"))
    python_report = _safe_report_path(root, require_text(python["report"], "coverage report"))
    modules = _gradle_modules(root)
    jacoco_relative = require_text(java["jacocoReport"], "JaCoCo report path")
    pitest_relative = require_text(java["pitestReport"], "PIT report path")
    jacoco_reports = tuple(path / jacoco_relative for _, path in modules)
    pitest_reports = tuple(path / pitest_relative for _, path in modules)
    outputs = (data_file, python_report, *jacoco_reports, *pitest_reports)
    for output in outputs:
        resolved = output.resolve(strict=False)
        if not resolved.is_relative_to(root) or output.is_symlink():
            return _blocked("quality_report_path_unsafe", binding=source_binding)
        try:
            output.unlink(missing_ok=True)
        except OSError as exc:
            return _blocked(
                f"quality_report_cleanup_failed:{type(exc).__name__}",
                binding=source_binding,
            )
    data_file.parent.mkdir(parents=True, exist_ok=True)
    started_ns = time.time_ns()
    environment = dict(os.environ)
    environment["COVERAGE_FILE"] = str(data_file)
    sources = ",".join(PYTHON_SOURCE_ROOTS)
    timeout = _integer(python["timeoutSeconds"], "Python coverage timeout", 1)
    executions: list[ToolExecution] = []
    commands: list[tuple[str, ...]] = []
    for index, discovery in enumerate(PYTHON_DISCOVERIES):
        append = ("--append",) if index else ()
        commands.append(
            (
                coverage_executable,
                "run",
                *append,
                "--branch",
                f"--source={sources}",
                "-m",
                "unittest",
                "discover",
                "-s",
                discovery,
                "-t",
                ".",
            )
        )
    commands.append((coverage_executable, "json", "-o", str(python_report)))
    for command in commands:
        execution = _tool_execution(
            "coverage.py",
            command,
            cwd=root,
            environment=environment,
            timeout=timeout,
            version=coverage_version,
        )
        executions.append(execution)
        if execution.exit_code != 0:
            return _failed_execution(
                "python_coverage_execution_failed", executions, source_binding
            )

    wrapper = (root / require_text(java["gradleExecutable"], "Gradle executable")).resolve()
    if not wrapper.is_file() or not os.access(wrapper, os.X_OK) or not wrapper.is_relative_to(root):
        return _blocked("gradle_wrapper_unavailable", executions, source_binding)
    try:
        gradle_version = _tool_version(str(wrapper), ("--version",))
    except ValidationError as exc:
        return _blocked(f"gradle_wrapper_unavailable:{exc}", executions, source_binding)
    gradle_command = [str(wrapper), "--no-daemon"]
    if offline:
        gradle_command.append("--offline")
    gradle_command.append(QUALITY_TASK)
    gradle_execution = _tool_execution(
        "gradle-jacoco-pitest",
        gradle_command,
        cwd=root,
        environment=environment,
        timeout=_integer(java["timeoutSeconds"], "Java quality timeout", 1),
        version=gradle_version,
    )
    executions.append(gradle_execution)
    if gradle_execution.exit_code != 0:
        if gradle_execution.failure_kind == "OFFLINE_DEPENDENCY_UNAVAILABLE":
            return _blocked(
                "java_quality_offline_dependency_unavailable",
                executions,
                source_binding,
            )
        return _failed_execution(
            "java_quality_tool_execution_failed", executions, source_binding
        )
    if not all(_fresh(path, started_ns) for path in (python_report, *jacoco_reports, *pitest_reports)):
        return _blocked(
            "quality_report_missing_or_stale", executions, source_binding
        )
    return evaluate_quality_reports(
        root=root,
        policy=governed,
        python_report=python_report,
        jacoco_reports=jacoco_reports,
        pitest_reports=pitest_reports,
        executions=executions,
        expected_source_binding=source_binding,
    )


def _blocked(
    reason: str,
    executions: Sequence[ToolExecution] = (),
    binding: SourceBinding | None = None,
) -> QualityMetricResult:
    return QualityMetricResult(
        False,
        "BLOCKED",
        (reason,),
        (),
        LineCounts(0, 0),
        MutationCounts(0, 0),
        tuple(executions),
        {},
        binding or _unknown_source_binding(),
    )


def _failed_execution(
    reason: str,
    executions: Sequence[ToolExecution],
    binding: SourceBinding,
) -> QualityMetricResult:
    return _failed(reason, executions=executions, binding=binding)


def _failed(
    reason: str,
    executions: Sequence[ToolExecution] = (),
    binding: SourceBinding | None = None,
) -> QualityMetricResult:
    return QualityMetricResult(
        False,
        "FAILED",
        (reason,),
        (),
        LineCounts(0, 0),
        MutationCounts(0, 0),
        tuple(executions),
        {},
        binding or _unknown_source_binding(),
    )


def write_result(path: Path, result: QualityMetricResult) -> None:
    """Atomically write the aggregate gate result below build/."""

    root = Path.cwd().resolve()
    resolved = path.resolve(strict=False)
    if not resolved.is_relative_to(root) or "build" not in resolved.relative_to(root).parts[:1]:
        raise ValidationError("quality result output must remain under repository build/")
    if path.is_symlink():
        raise ValidationError("quality result output must not be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(canonical_json(result.document()) + b"\n")
    os.replace(temporary, path)


def observed_at() -> str:
    return datetime.now(timezone.utc).isoformat()
