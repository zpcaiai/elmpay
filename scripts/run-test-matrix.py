#!/usr/bin/env python3
"""Run the repository's SOTA test matrix with fail-closed reporting.

The matrix is deliberately separate from ``.ai/rebaseline.py``.  It executes
tests and produces a report, but never writes batch evidence, completion files,
review attestations, or certification state.

Commands are argv arrays (never shell strings), are run in a sanitized test
environment, and are rejected when they appear to target production.  Manual
and external cases are reported as ``BLOCKED`` until their named evidence is
provided; ``--allow-blocked`` is useful for local engineering runs while the
default remains fail-closed for CI.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = ROOT / "testing/test-matrix.json"
ALLOWED_LEVELS = {"governance", "unit", "contract", "integration", "e2e", "security", "performance", "uat", "release"}
ALLOWED_EXECUTION = {"local", "ci", "manual", "external"}
BATCH_RE = re.compile(r"^B(?:0[0-9]|[1-9][0-9]|1[01][0-9]|12[0-7])$")
PRODUCTION_WORDS = re.compile(r"^(?:prod|production|live)$", re.IGNORECASE)
SECRET_ENV = re.compile(r"(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)", re.IGNORECASE)


class MatrixError(ValueError):
    """A malformed matrix must fail closed before any command runs."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MatrixError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MatrixError(f"cannot read JSON matrix {path}: {exc}") from exc


def matrix_digest(matrix_path: Path) -> str:
    return hashlib.sha256(matrix_path.read_bytes()).hexdigest()


def manifest_batch_ids(root: Path) -> list[str]:
    manifest = load_json(root / ".payment-platform/skill-package/manifest.json")
    batches = manifest.get("batches")
    if not isinstance(batches, list):
        raise MatrixError("skill manifest batches must be a list")
    ids = [item.get("id") for item in batches if isinstance(item, dict)]
    if any(not isinstance(item, str) for item in ids) or len(set(ids)) != len(ids):
        raise MatrixError("skill manifest has invalid or duplicate batch ids")
    return ids


def _relative_target(root: Path, value: Any, *, field: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise MatrixError(f"{field} must be a non-empty repository-relative path")
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise MatrixError(f"{field} escapes repository: {value}") from exc
    target = root / value
    if not target.exists():
        raise MatrixError(f"{field} does not exist: {value}")
    if target.is_dir() and not any(path.is_file() for path in target.rglob("*")):
        raise MatrixError(f"{field} contains no files: {value}")
    return candidate


def _validate_command(command: Any, *, case_id: str) -> list[str]:
    if not isinstance(command, list) or not command or any(not isinstance(token, str) or not token for token in command):
        raise MatrixError(f"{case_id}: command must be a non-empty argv list")
    for token in command:
        if token in {"|", ";", "&&", "||", ">", ">>", "<"} or "\n" in token or "\r" in token:
            raise MatrixError(f"{case_id}: shell metacharacter is not allowed in command")
        if PRODUCTION_WORDS.fullmatch(token.strip("-/=_:,.")):
            raise MatrixError(f"{case_id}: production/live command target is forbidden")
        lowered = token.lower()
        if any(part in lowered for part in ("/production/", "/live/", "prod-secret", "live-secret")):
            raise MatrixError(f"{case_id}: production credential/path target is forbidden")
    return command


def validate_matrix(matrix: dict[str, Any], root: Path = ROOT) -> list[str]:
    """Validate shape, safety, and exact batch coverage without executing code."""
    if not isinstance(matrix, dict):
        raise MatrixError("matrix root must be an object")
    if matrix.get("schema_version") != "1.0.0":
        raise MatrixError("unsupported matrix schema_version")
    coverage = matrix.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("required_batch_source") != "manifest":
        raise MatrixError("coverage.required_batch_source must be manifest")
    required = manifest_batch_ids(root)
    expected_count = coverage.get("expected_batch_count")
    if expected_count != len(required):
        raise MatrixError(f"coverage expected_batch_count={expected_count!r}, manifest has {len(required)}")
    if required != [f"B{number:02d}" for number in range(128)]:
        raise MatrixError("manifest must contain contiguous B00-B127")

    suites = matrix.get("suites")
    if not isinstance(suites, list) or not suites:
        raise MatrixError("suites must be a non-empty list")
    seen_cases: set[str] = set()
    seen_batches: list[str] = []
    for item in suites:
        if not isinstance(item, dict):
            raise MatrixError("each suite must be an object")
        case_id = item.get("id")
        if not isinstance(case_id, str) or not re.fullmatch(r"TM-[A-Z0-9-]+", case_id):
            raise MatrixError(f"invalid suite id: {case_id!r}")
        if case_id in seen_cases:
            raise MatrixError(f"duplicate suite id: {case_id}")
        seen_cases.add(case_id)
        if item.get("level") not in ALLOWED_LEVELS:
            raise MatrixError(f"{case_id}: unknown level")
        execution = item.get("execution")
        if execution not in ALLOWED_EXECUTION:
            raise MatrixError(f"{case_id}: unknown execution mode")
        batch_ids = item.get("batch_ids")
        if not isinstance(batch_ids, list) or not batch_ids or any(not isinstance(batch, str) or not BATCH_RE.fullmatch(batch) for batch in batch_ids):
            raise MatrixError(f"{case_id}: batch_ids must contain valid B00-B127 ids")
        if len(set(batch_ids)) != len(batch_ids):
            raise MatrixError(f"{case_id}: duplicate batch id inside suite")
        seen_batches.extend(batch_ids)
        for target in item.get("target_paths", []):
            _relative_target(root, target, field=f"{case_id}.target_paths")
        scenarios = item.get("scenarios")
        if not isinstance(scenarios, list) or not scenarios:
            raise MatrixError(f"{case_id}: scenarios must be a non-empty list")
        for scenario in scenarios:
            if not isinstance(scenario, dict) or not isinstance(scenario.get("id"), str) or not scenario.get("steps") or not scenario.get("expected"):
                raise MatrixError(f"{case_id}: every scenario needs id, steps, and expected")
        if execution in {"local", "ci"}:
            _validate_command(item.get("command"), case_id=case_id)
            if not isinstance(item.get("timeout_seconds"), int) or item["timeout_seconds"] < 1:
                raise MatrixError(f"{case_id}: timeout_seconds must be positive")
        elif item.get("command") is not None:
            _validate_command(item["command"], case_id=case_id)
        if execution in {"manual", "external"} and not item.get("blocking_evidence"):
            raise MatrixError(f"{case_id}: manual/external cases require blocking_evidence")

    if sorted(seen_batches, key=lambda x: int(x[1:])) != required or len(seen_batches) != len(set(seen_batches)):
        missing = sorted(set(required) - set(seen_batches), key=lambda x: int(x[1:]))
        duplicate = sorted(batch for batch, count in Counter(seen_batches).items() if count > 1)
        raise MatrixError(f"batch coverage must be exact; missing={missing}, duplicate={duplicate}")
    return required


def _sanitized_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items()
        if not SECRET_ENV.search(key) and key not in {"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "KUBECONFIG", "GOOGLE_APPLICATION_CREDENTIALS"}
    }
    environment.update({"ELMPAY_TEST_MODE": "1", "ELMPAY_ENVIRONMENT": "TEST", "CI": "1"})
    return environment


def _tail(text: str, limit: int = 16_384) -> str:
    return text[-limit:]


def _safe_output_path(path: Path, root: Path) -> Path:
    resolved = path if path.is_absolute() else root / path
    resolved = resolved.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise MatrixError(f"report path escapes repository: {path}") from exc
    try:
        resolved.relative_to((root / "evidence").resolve())
    except ValueError:
        pass
    else:
        raise MatrixError("test matrix reports may not be written under evidence/")
    if resolved.name.startswith("B00") or "/B00/" in str(resolved):
        raise MatrixError("test matrix reports may not target B00 evidence")
    return resolved


def _write_report(path: Path, report: dict[str, Any], root: Path) -> None:
    resolved = _safe_output_path(path, root)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{resolved.name}.", dir=resolved.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, resolved)
    finally:
        try:
            Path(temporary).unlink()
        except FileNotFoundError:
            pass


def run_matrix(
    matrix: dict[str, Any],
    matrix_path: Path = DEFAULT_MATRIX,
    *,
    root: Path = ROOT,
    suite_ids: Iterable[str] | None = None,
    batch_ids: Iterable[str] | None = None,
    execution: str | None = None,
    allow_blocked: bool = False,
) -> tuple[int, dict[str, Any]]:
    validate_matrix(matrix, root)
    if execution is not None and execution not in ALLOWED_EXECUTION:
        raise MatrixError(f"unknown execution mode: {execution}")
    wanted_suites = set(suite_ids or [])
    wanted_batches = set(batch_ids or [])
    suites = []
    for item in matrix["suites"]:
        if wanted_suites and item["id"] not in wanted_suites:
            continue
        if wanted_batches and not wanted_batches.intersection(item["batch_ids"]):
            continue
        if execution and item["execution"] != execution:
            continue
        suites.append(item)
    if wanted_suites:
        unknown = wanted_suites - {item["id"] for item in matrix["suites"]}
        if unknown:
            raise MatrixError(f"unknown suite(s): {sorted(unknown)}")
    if wanted_batches:
        manifest_ids = set(manifest_batch_ids(root))
        unknown = wanted_batches - manifest_ids
        if unknown:
            raise MatrixError(f"unknown batch id(s): {sorted(unknown)}")
    started_at = datetime.now(timezone.utc).isoformat()
    results: list[dict[str, Any]] = []
    for item in suites:
        started = time.monotonic()
        result: dict[str, Any] = {
            "id": item["id"],
            "name": item["name"],
            "batch_ids": item["batch_ids"],
            "execution": item["execution"],
            "level": item["level"],
            "critical": bool(item.get("critical", True)),
            "command": item.get("command"),
        }
        if item["execution"] in {"manual", "external"}:
            result.update({"status": "BLOCKED", "reason": item["blocking_evidence"], "exit_code": None})
        else:
            command = item["command"]
            try:
                completed = subprocess.run(
                    command,
                    cwd=root,
                    env=_sanitized_environment(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=item["timeout_seconds"],
                    check=False,
                )
                result.update({
                    "status": "PASS" if completed.returncode == 0 else "FAIL",
                    "exit_code": completed.returncode,
                    "output_tail": _tail(completed.stdout or ""),
                })
            except FileNotFoundError as exc:
                result.update({"status": "FAIL", "exit_code": 127, "reason": f"tool_missing: {exc.filename}"})
            except subprocess.TimeoutExpired as exc:
                raw = exc.stdout or ""
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                result.update({"status": "FAIL", "exit_code": 124, "reason": "timeout", "output_tail": _tail(raw)})
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        results.append(result)

    counts = Counter(result["status"] for result in results)
    covered = sorted({batch for result in results for batch in result["batch_ids"]}, key=lambda x: int(x[1:]))
    required = manifest_batch_ids(root)
    report = {
        "schema_version": 1,
        "matrix_schema_version": matrix["schema_version"],
        "matrix_digest": matrix_digest(matrix_path),
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "repository": str(root),
        "results": results,
        "summary": {
            "selected": len(results),
            "passed": counts.get("PASS", 0),
            "failed": counts.get("FAIL", 0),
            "blocked": counts.get("BLOCKED", 0),
        },
        "coverage": {
            "required_batches": len(required),
            "selected_batches": len(covered),
            "missing_batches": sorted(set(required) - set(covered), key=lambda x: int(x[1:])),
            "complete_matrix_selection": not wanted_suites and not wanted_batches and execution is None,
        },
        "certification_status": "NOT_CERTIFIED",
        "certification_note": "Local test results do not satisfy independent review, provider certification, production, PCI, DR, UAT, or merchant acceptance gates.",
    }
    failed = report["summary"]["failed"]
    blocked = report["summary"]["blocked"]
    missing = report["coverage"]["missing_batches"]
    complete_selection = not wanted_suites and not wanted_batches and execution is None
    exit_code = 0 if failed == 0 and (not complete_selection or not missing) and (allow_blocked or blocked == 0) else 2
    return exit_code, report


def write_junit(path: Path, report: dict[str, Any]) -> None:
    suite = ET.Element("testsuite", name="elmpay-test-matrix", tests=str(len(report["results"])), failures=str(report["summary"]["failed"]), skipped=str(report["summary"]["blocked"]))
    for result in report["results"]:
        case = ET.SubElement(suite, "testcase", name=result["id"], classname=result["level"], time=str(result["duration_seconds"]))
        if result["status"] == "FAIL":
            failure = ET.SubElement(case, "failure", message=result.get("reason", "command failed"))
            failure.text = result.get("output_tail", "")
        elif result["status"] == "BLOCKED":
            skipped = ET.SubElement(case, "skipped", message=result["reason"])
    destination = _safe_output_path(path, ROOT)
    destination.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(destination, encoding="utf-8", xml_declaration=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", default=str(DEFAULT_MATRIX))
    parser.add_argument("--suite", action="append", dest="suites", help="select a suite (repeatable)")
    parser.add_argument("--batch", action="append", dest="batches", help="select suites covering a batch (repeatable)")
    parser.add_argument("--execution", choices=sorted(ALLOWED_EXECUTION), help="select suites by execution mode")
    parser.add_argument("--list", action="store_true", help="list validated suites and exit")
    parser.add_argument("--allow-blocked", action="store_true", help="allow manual/external cases to remain BLOCKED")
    parser.add_argument("--json-out")
    parser.add_argument("--junit-out")
    args = parser.parse_args(argv)
    try:
        matrix_path = Path(args.matrix)
        if not matrix_path.is_absolute():
            matrix_path = (ROOT / matrix_path).resolve()
        matrix = load_json(matrix_path)
        validate_matrix(matrix, ROOT)
        if args.list:
            for item in matrix["suites"]:
                print(f"{item['id']}\t{item['execution']}\t{','.join(item['batch_ids'])}\t{item['name']}")
            return 0
        code, report = run_matrix(matrix, matrix_path, suite_ids=args.suites, batch_ids=args.batches, execution=args.execution, allow_blocked=args.allow_blocked)
        if args.json_out:
            _write_report(Path(args.json_out), report, ROOT)
        if args.junit_out:
            write_junit(Path(args.junit_out), report)
        print(json.dumps({"summary": report["summary"], "coverage": report["coverage"], "certification_status": report["certification_status"]}, ensure_ascii=False, sort_keys=True))
        return code
    except MatrixError as exc:
        print(json.dumps({"status": "INVALID_MATRIX", "error": str(exc)}, ensure_ascii=False))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
