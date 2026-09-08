#!/usr/bin/env python3
"""Fail-closed, per-batch implementation inventory.

This audit deliberately does not infer implementation from a populated directory. A batch only
passes when it has an explicit inventory entry identifying exact executable code, runtime wiring,
durable migrations, and tests, and when each file contains the declared implementation marker.
Documentation, generated contracts, evidence, fixtures, and ``reference`` models are rejected as
implementation artifacts.

The inventory is intentionally independent of certification. It never writes evidence, review
attestations, traceability, or completion markers, and a passing implementation inventory still
does not certify a batch.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / ".payment-platform/skill-package/manifest.json"
MODULES = ROOT / "governance/module-registry.json"
INVENTORY = ROOT / ".ai/implementation_inventory.json"
VERSION_CATALOG = ROOT / "governance/version-catalog.json"
REQUIRED_ROLES = ("executable", "runtime_entrypoint", "config", "migrations", "tests")


@dataclass(frozen=True)
class ArtifactRequirement:
    """One exact, reviewable implementation artifact and its semantic anchors."""

    path: str
    markers: tuple[str, ...]


@dataclass(frozen=True)
class BatchImplementation:
    """The minimum independently checkable implementation surface for one batch."""

    executable: tuple[ArtifactRequirement, ...]
    runtime_entrypoint: tuple[ArtifactRequirement, ...]
    config: tuple[ArtifactRequirement, ...]
    migrations: tuple[ArtifactRequirement, ...]
    tests: tuple[ArtifactRequirement, ...]
    migration_required: bool = True
    migration_not_applicable_reason: str = ""
    assessment: str = ""
    known_gaps: tuple[str, ...] = ()


SOURCE_SUFFIXES = {
    ".java", ".py", ".mjs", ".js", ".ts", ".go", ".swift", ".dart", ".cs", ".sh",
}
FORBIDDEN_IMPLEMENTATION_PARTS = {
    "reference", "references", "fixture", "fixtures", "evidence", "docs", "contracts",
    "governance", ".payment-platform", "build", "node_modules", "__pycache__",
}
FORBIDDEN_CONFIG_PARTS = {
    "reference", "references", "fixture", "fixtures", "evidence", "docs",
    ".payment-platform", "build", "node_modules", "__pycache__",
}
IGNORED_PARTS = {
    "build", "node_modules", "__pycache__", ".gradle", ".dart_tool", ".build", "bin", "obj",
}

VERIFY_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("implementation-audit-tests", (
        sys.executable, "-m", "unittest", "discover", "-s", ".ai/tests",
        "-p", "test_implementation_audit.py", "-v")),
    ("test-module-ownership", (
        sys.executable, "scripts/run-code-suite.py", "--check-coverage")),
    ("governance-unit-tests", (
        sys.executable, "scripts/test-summary.py", "--suite-root", "tools/tests",
        "--out", "build/implementation-audit/tools-tests.json",
        "--log", "build/implementation-audit/tools-tests.log")),
    ("b00-b117-local-semantic-matrix", (
        sys.executable, "scripts/run-test-matrix.py", "--execution", "local",
        "--json-out", "build/implementation-audit/local-matrix.json",
        "--junit-out", "build/implementation-audit/local-matrix-junit.xml")),
    # Node's test runner does not consistently expand a directory argument across
    # supported Node versions.  Keep every test file explicit so the audit cannot
    # silently pass after discovering zero tests (or fail on a valid directory).
    ("checkout-web", (
        "node", "--test",
        "apps/checkout-web/test/browser-security.test.mjs",
        "apps/checkout-web/test/checkout.test.mjs",
        "apps/checkout-web/test/edge-transport.test.mjs",
        "apps/checkout-web/test/provider-handlers.test.mjs",
        "apps/checkout-web/test/provider-sdk-bootstrap.test.mjs",
        "apps/checkout-web/test/provider-sdk-policy.test.mjs",
        "apps/checkout-web/test/provider-sdk-server.test.mjs",
        "apps/checkout-web/test/server.test.mjs",
    )),
    ("admin-web", (
        "node", "--test",
        "apps/admin-web/test/action-dispatcher.test.mjs",
        "apps/admin-web/test/admin-domain.test.mjs",
        "apps/admin-web/test/config-logging.test.mjs",
        "apps/admin-web/test/operator-auth.test.mjs",
        "apps/admin-web/test/postgres-store.test.mjs",
        "apps/admin-web/test/server.test.mjs",
    )),
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def files_under(relative: str) -> list[Path]:
    base = ROOT / relative
    if not base.exists():
        return []
    return sorted(
        path.relative_to(ROOT)
        for path in base.rglob("*")
        if path.is_file() and not IGNORED_PARTS.intersection(path.relative_to(ROOT).parts)
    )


def is_test(path: Path) -> bool:
    lowered = str(path).lower()
    return ("/test/" in f"/{lowered}" or "/tests/" in f"/{lowered}"
            or Path(lowered).name.startswith("test_") or ".test." in lowered
            or Path(lowered).name.endswith("_test.go"))


def manifest_batch_records() -> list[dict[str, Any]]:
    document = load_json(MANIFEST)
    records = document.get("batches", [])
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict)]


def manifest_batches() -> list[str]:
    return [str(record.get("id", "")) for record in manifest_batch_records()]


def load_implementation_inventory(path: Path = INVENTORY
                                  ) -> tuple[dict[str, BatchImplementation], list[str]]:
    """Load the reviewable inventory map without converting malformed entries into a pass."""

    problems: list[str] = []
    try:
        document = load_json(path)
    except (OSError, json.JSONDecodeError) as exception:
        return {}, [f"implementation inventory is unreadable: {exception}"]
    if not isinstance(document, dict):
        return {}, ["implementation inventory root must be an object"]
    if document.get("schema_version") != 1:
        problems.append("implementation inventory schema_version must equal 1")
    if document.get("required_roles") != list(REQUIRED_ROLES):
        problems.append(f"implementation inventory required_roles must equal {list(REQUIRED_ROLES)}")
    raw_batches = document.get("batches")
    if not isinstance(raw_batches, dict):
        return {}, problems + ["implementation inventory batches must be an object"]

    decoded: dict[str, BatchImplementation] = {}
    valid_ids = {f"B{number:02d}" for number in range(128)}
    for batch_id, raw_batch in raw_batches.items():
        scope = f"inventory.{batch_id}"
        if batch_id not in valid_ids:
            problems.append(f"{scope}: batch id is outside B00-B127")
            continue
        if not isinstance(raw_batch, dict):
            problems.append(f"{scope}: batch entry must be an object")
            continue
        raw_artifacts = raw_batch.get("artifacts")
        if not isinstance(raw_artifacts, dict):
            problems.append(f"{scope}: artifacts must be an object")
            continue
        unexpected_roles = sorted(set(raw_artifacts) - set(REQUIRED_ROLES))
        if unexpected_roles:
            problems.append(f"{scope}: unexpected artifact roles {unexpected_roles}")
        role_values: dict[str, tuple[ArtifactRequirement, ...]] = {}
        malformed = False
        for role in REQUIRED_ROLES:
            raw_requirements = raw_artifacts.get(role, [])
            if not isinstance(raw_requirements, list):
                problems.append(f"{scope}.{role}: role inventory must be a list")
                malformed = True
                raw_requirements = []
            requirements: list[ArtifactRequirement] = []
            for index, raw_requirement in enumerate(raw_requirements):
                item_scope = f"{scope}.{role}[{index}]"
                if not isinstance(raw_requirement, dict):
                    problems.append(f"{item_scope}: artifact must be an object")
                    malformed = True
                    continue
                artifact_path = raw_requirement.get("path")
                markers = raw_requirement.get("markers")
                if not isinstance(artifact_path, str) or not artifact_path:
                    problems.append(f"{item_scope}: path must be a non-empty string")
                    malformed = True
                    continue
                if (not isinstance(markers, list) or not markers
                        or not all(isinstance(marker, str) and marker for marker in markers)):
                    problems.append(f"{item_scope}: markers must be a non-empty string list")
                    malformed = True
                    continue
                requirements.append(ArtifactRequirement(artifact_path, tuple(markers)))
            role_values[role] = tuple(requirements)
        migration_required = raw_batch.get("migration_required", True)
        if not isinstance(migration_required, bool):
            problems.append(f"{scope}: migration_required must be boolean")
            migration_required = True
            malformed = True
        migration_reason = raw_batch.get("migration_not_applicable_reason", "")
        assessment = raw_batch.get("assessment", "")
        known_gaps = raw_batch.get("known_gaps", [])
        if not isinstance(migration_reason, str) or not isinstance(assessment, str):
            problems.append(f"{scope}: assessment and migration reason must be strings")
            malformed = True
        if (not isinstance(known_gaps, list)
                or not all(isinstance(gap, str) and gap.strip() for gap in known_gaps)):
            problems.append(f"{scope}: known_gaps must be a list of non-empty strings")
            known_gaps = ["malformed known_gaps declaration"]
            malformed = True
        if malformed:
            known_gaps = list(known_gaps) + ["inventory entry is malformed"]
        decoded[batch_id] = BatchImplementation(
            executable=role_values["executable"],
            runtime_entrypoint=role_values["runtime_entrypoint"],
            config=role_values["config"],
            migrations=role_values["migrations"],
            tests=role_values["tests"],
            migration_required=migration_required,
            migration_not_applicable_reason=migration_reason,
            assessment=assessment,
            known_gaps=tuple(known_gaps),
        )
    return decoded, problems


def validate_artifact(root: Path, role: str, requirement: ArtifactRequirement) -> list[str]:
    """Validate one exact artifact without accepting directories, globs, or reference models."""

    problems: list[str] = []
    relative = Path(requirement.path)
    if relative.is_absolute() or ".." in relative.parts:
        return [f"{role} path must be repository-relative: {requirement.path}"]
    if any(character in requirement.path for character in "*?[]{}"):
        return [f"{role} path must be exact, not a glob: {requirement.path}"]
    candidate = root / relative
    if not candidate.is_file() or candidate.is_symlink():
        return [f"{role} artifact is missing or not a regular in-place file: {requirement.path}"]
    lowered_parts = {part.lower() for part in relative.parts}
    if role in {"executable", "runtime_entrypoint"}:
        forbidden = sorted(lowered_parts & FORBIDDEN_IMPLEMENTATION_PARTS)
        if forbidden:
            problems.append(
                f"{role} cannot be satisfied by non-runtime path {requirement.path}: {forbidden}")
        # OCI launchers are intentionally extensionless (their image path is a stable
        # contract), so accept an executable UTF-8 shebang script in addition to the
        # conventional source suffixes.  The executable bit and shebang keep this
        # fail-closed; arbitrary extensionless files are still rejected.
        extensionless_script = False
        if candidate.suffix == "" and os.access(candidate, os.X_OK):
            try:
                with candidate.open("r", encoding="utf-8") as source:
                    extensionless_script = source.readline().startswith("#!")
            except (OSError, UnicodeDecodeError):
                extensionless_script = False
        if candidate.suffix.lower() not in SOURCE_SUFFIXES and not extensionless_script:
            problems.append(f"{role} must be executable source: {requirement.path}")
        if is_test(relative):
            problems.append(f"{role} cannot point at test code: {requirement.path}")
    elif role == "config":
        forbidden = sorted(lowered_parts & FORBIDDEN_CONFIG_PARTS)
        if forbidden:
            problems.append(
                f"config cannot be satisfied by non-runtime path {requirement.path}: {forbidden}")
        if is_test(relative):
            problems.append(f"config cannot point at test code: {requirement.path}")
    elif role == "migrations" and candidate.suffix.lower() != ".sql":
        problems.append(f"migration must be SQL: {requirement.path}")
    elif role == "tests" and not is_test(relative):
        problems.append(f"test artifact is not in a test source path: {requirement.path}")
    if not requirement.markers:
        problems.append(f"{role} artifact has no semantic marker: {requirement.path}")
    else:
        try:
            content = candidate.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            problems.append(f"{role} artifact is not UTF-8 text: {requirement.path}")
        else:
            for marker in requirement.markers:
                if marker not in content:
                    problems.append(
                        f"{role} artifact lacks marker {marker!r}: {requirement.path}")
    return problems


def validate_batch(root: Path, batch_id: str,
                   implementation: BatchImplementation | None) -> tuple[list[str], dict[str, Any]]:
    del batch_id  # The caller owns the id; validation only consumes the explicit contract.
    if implementation is None:
        problems = ["no explicit implementation inventory; broad directory presence is rejected"]
        return problems, {
            "executable": [], "runtime_entrypoint": [], "config": [],
            "migrations": [], "tests": [],
            "migration_required": True,
        }

    role_values: dict[str, tuple[ArtifactRequirement, ...]] = {
        "executable": implementation.executable,
        "runtime_entrypoint": implementation.runtime_entrypoint,
        "config": implementation.config,
        "migrations": implementation.migrations,
        "tests": implementation.tests,
    }
    problems: list[str] = []
    for role in ("executable", "runtime_entrypoint", "config", "tests"):
        if not role_values[role]:
            problems.append(f"{role} inventory is empty")
    if implementation.migration_required and not implementation.migrations:
        problems.append("durable migration inventory is empty")
    if not implementation.migration_required and not implementation.migration_not_applicable_reason.strip():
        problems.append("migration N/A requires a non-empty reason")
    problems.extend(f"declared implementation gap: {gap}" for gap in implementation.known_gaps)
    for role, requirements in role_values.items():
        for requirement in requirements:
            problems.extend(validate_artifact(root, role, requirement))
    roles_by_path: dict[str, dict[str, tuple[str, ...]]] = {}
    for role, requirements in role_values.items():
        for requirement in requirements:
            roles_by_path.setdefault(requirement.path, {})[role] = requirement.markers
    for path, role_markers in roles_by_path.items():
        roles = set(role_markers)
        if len(roles) < 2:
            continue
        # A self-contained executable control may also be its direct callable runtime surface.
        # The two contracts must still identify distinct semantic anchors. Config, migrations and
        # tests are always independent artifacts and can never be reused for another role.
        if roles == {"executable", "runtime_entrypoint"}:
            if set(role_markers["executable"]) == set(role_markers["runtime_entrypoint"]):
                problems.append(
                    f"shared executable/runtime artifact requires distinct markers: {path}")
            continue
        problems.append(f"artifact cannot satisfy incompatible roles {sorted(roles)}: {path}")
    return problems, {
        role: [
            {"path": requirement.path, "markers": list(requirement.markers)}
            for requirement in requirements
        ]
        for role, requirements in role_values.items()
    } | {
        "migration_required": implementation.migration_required,
        "migration_not_applicable_reason": implementation.migration_not_applicable_reason,
        "assessment": implementation.assessment,
        "known_gaps": list(implementation.known_gaps),
    }


def audit(*, run_checks: bool = False, timeout_seconds: int = 900) -> dict[str, Any]:
    issues: list[str] = []
    records = manifest_batch_records()
    batches = [str(record.get("id", "")) for record in records]
    expected = [f"B{number:02d}" for number in range(128)]
    if batches != expected:
        issues.append("manifest must contain contiguous B00-B127 exactly once")

    implementations, inventory_problems = load_implementation_inventory()
    issues.extend(inventory_problems)

    batch_results: list[dict[str, Any]] = []
    for index, batch_id in enumerate(expected):
        record = records[index] if index < len(records) and records[index].get("id") == batch_id else {}
        problems, inventory = validate_batch(ROOT, batch_id, implementations.get(batch_id))
        batch_results.append({
            "id": batch_id,
            "title": str(record.get("title", "")),
            "skill": str(record.get("skill", "")),
            "status": "PASS" if not problems else "FAIL",
            "inventory": inventory,
            "issues": problems,
        })
        issues.extend(f"{batch_id}: {problem}" for problem in problems)

    registry = load_json(MODULES)
    module_results: list[dict[str, Any]] = []
    for module in registry.get("modules", []):
        relative = str(module["path"])
        files = files_under(relative)
        production = [path for path in files if not is_test(path)]
        tests = [path for path in files if is_test(path)]
        module_results.append({
            "name": module["name"], "path": relative,
            "production_files": len(production), "test_files": len(tests),
        })

    inventory_status = "PASS" if not issues else "FAIL"
    checks = verify_commands(timeout_seconds) if run_checks else []
    checks_pass = bool(run_checks) and all(check["exit_code"] == 0 for check in checks)
    implementation_surface = (
        "PASS" if inventory_status == "PASS" and checks_pass
        else "FAIL" if inventory_status == "FAIL" or run_checks
        else "NOT_RUN"
    )
    return {
        "schema_version": 2,
        "inventory_map": str(INVENTORY.relative_to(ROOT)),
        "inventory_schema_issues": inventory_problems,
        "git_head": git_head(),
        "inventory_status": inventory_status,
        "implementation_surface": implementation_surface,
        "verification_executed": run_checks,
        "verification_checks": checks,
        "certification_status": "NOT_CERTIFIED",
        "certified_batches_changed": False,
        "batch_count": len(batches),
        "implemented_batch_count": sum(result["status"] == "PASS" for result in batch_results),
        "gap_batch_count": sum(result["status"] == "FAIL" for result in batch_results),
        "batches": batch_results,
        "module_count": len(module_results),
        "modules": module_results,
        "issues": issues,
        "external_gates": [
            "independent human review",
            "provider sandbox and official certification",
            "production Kubernetes and multi-region DR runtime evidence",
            "PCI, legal, finance UAT and penetration approvals",
            "production shadow, canary and merchant acceptance",
        ],
    }


def verify_commands(timeout_seconds: int) -> list[dict[str, Any]]:
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be positive")
    try:
        environment = verification_environment()
    except RuntimeError as exception:
        return [{
            "name": "toolchain-preflight",
            "command": [],
            "exit_code": 127,
            "timed_out": False,
            "duration_seconds": 0.0,
            "output_tail": str(exception),
        }]
    results: list[dict[str, Any]] = []
    for name, command in VERIFY_COMMANDS:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=timeout_seconds, check=False, env=environment,
            )
            output = completed.stdout[-16_384:]
            exit_code = completed.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exception:
            raw = exception.stdout or ""
            output = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            output = output[-16_384:]
            exit_code = 124
            timed_out = True
        results.append({
            "name": name, "command": list(command), "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_seconds": round(time.monotonic() - started, 3),
            "output_tail": output,
        })
        if exit_code != 0:
            break
    return results


def governed_jdk_identity() -> tuple[str, str]:
    """Return the exact JDK name/version pinned by the B03 version catalogue."""

    document = load_json(VERSION_CATALOG)
    entries = document.get("entries", []) if isinstance(document, dict) else []
    matches = [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("id") == "jdk"
    ]
    if len(matches) != 1:
        raise RuntimeError("toolchain preflight: version catalogue must define one jdk entry")
    name = matches[0].get("name")
    version = matches[0].get("version")
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise RuntimeError("toolchain preflight: governed jdk identity is incomplete")
    return name, version


def candidate_java_homes(environment: dict[str, str]) -> tuple[Path, ...]:
    """Discover local JDK homes without changing the user's global Java selection."""

    candidates: list[Path] = []
    configured = environment.get("JAVA_HOME")
    if configured:
        candidates.append(Path(configured))
    java = shutil.which("java", path=environment.get("PATH", ""))
    if java:
        candidates.append(Path(java).resolve().parent.parent)
    sdkman = Path.home() / ".sdkman" / "candidates" / "java"
    if sdkman.is_dir():
        candidates.extend(sorted(path for path in sdkman.iterdir() if path.is_dir()))
    candidates.extend((
        Path("/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home"),
        Path("/usr/local/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home"),
    ))
    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return tuple(unique)


def java_version_output(java_home: Path) -> str:
    executable = java_home / "bin" / "java"
    if not executable.is_file():
        return ""
    try:
        completed = subprocess.run(
            [str(executable), "-version"], cwd=ROOT, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout


def select_governed_java_home(
    candidates: tuple[Path, ...], *, name: str, version: str,
) -> Path | None:
    """Select only the exact Temurin build pinned by governance."""

    runtime_marker = f"Temurin-{version}"
    feature_marker = f'openjdk version "{version.split("+", 1)[0]}"'
    if "Temurin" not in name:
        raise RuntimeError(f"toolchain preflight: unsupported governed JDK vendor {name}")
    for candidate in candidates:
        output = java_version_output(candidate)
        if runtime_marker in output and feature_marker in output:
            return candidate
    return None


def verification_environment() -> dict[str, str]:
    """Build a child-only environment bound to the exact governed JDK."""

    environment = dict(os.environ)
    name, version = governed_jdk_identity()
    selected = select_governed_java_home(
        candidate_java_homes(environment), name=name, version=version,
    )
    if selected is None:
        raise RuntimeError(
            f"toolchain preflight: exact {name} {version} is unavailable; "
            "install it or set JAVA_HOME without downgrading the repository baseline"
        )
    environment["JAVA_HOME"] = str(selected)
    current_path = environment.get("PATH", "")
    environment["PATH"] = f"{selected / 'bin'}{os.pathsep}{current_path}"
    return environment


def git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the full machine-readable report")
    parser.add_argument("--verify", action="store_true", help="execute the declared local verification commands")
    parser.add_argument("--timeout-seconds", type=int, default=900, help="per-command verification timeout")
    arguments = parser.parse_args(argv)
    report = audit(run_checks=arguments.verify, timeout_seconds=arguments.timeout_seconds)
    if arguments.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"implementation_surface={report['implementation_surface']}")
        print(f"inventory_status={report['inventory_status']}")
        print(f"certification_status={report['certification_status']}")
        print(f"batches={report['batch_count']} implemented={report['implemented_batch_count']} "
              f"gaps={report['gap_batch_count']} modules={report['module_count']}")
        for check in report["verification_checks"]:
            print(f"check={check['name']} exit={check['exit_code']} duration={check['duration_seconds']}")
        for issue in report["issues"]:
            print(f"issue={issue}")
    return 0 if report["inventory_status"] == "PASS" and (
        not arguments.verify or report["implementation_surface"] == "PASS") else 2


if __name__ == "__main__":
    sys.exit(main())
