"""Executable, artifact-bound B116 security scanner orchestration."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Mapping

from .common import GateReport, ValidationError, canonical_json, require_mapping, require_text
from .quality import _validate_test_token


SCANNER_EXECUTABLES: Mapping[str, tuple[str, ...]] = {
    "sast": ("semgrep",),
    "secret": ("gitleaks",),
    "dependency": ("trivy", "grype"),
}
REQUIRED_SECURITY_TOOLS = ("sast", "secret", "dependency", "dast", "iast")


@dataclass(frozen=True)
class SecurityOrchestrationResult:
    allowed: bool
    reasons: tuple[str, ...]
    reports: tuple[Mapping[str, Any], ...]
    artifact_digest: str
    environment: str


def orchestrate_security_pipeline(plan: Mapping[str, Any], *, environment: Mapping[str, str],
                                  now: datetime | None = None) -> SecurityOrchestrationResult:
    """Discover/run scanners and bind every result to one immutable artifact digest."""
    if plan.get("schemaVersion") != 1 or plan.get("environment") not in {"TEST", "CI"}:
        raise ValidationError("security orchestration requires schemaVersion=1 and TEST/CI")
    artifact = Path(require_text(plan.get("artifactPath"), "artifactPath")).resolve()
    expected_digest = require_text(plan.get("artifactDigest"), "artifactDigest")
    if not _is_digest(expected_digest) or artifact_digest(artifact) != expected_digest:
        raise ValidationError("security artifact digest does not match immutable input")
    timeout_seconds = _bounded_integer(
        plan.get("scannerTimeoutSeconds", 120), "scannerTimeoutSeconds", 1, 600
    )
    observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    reports: list[Mapping[str, Any]] = []
    for tool in ("sast", "secret", "dependency"):
        report = _run_scanner(
            tool, artifact, expected_digest, plan, environment, timeout_seconds, observed_at
        )
        reports.append(report)
        if artifact_digest(artifact) != expected_digest:
            raise ValidationError(f"security scanner mutated the bound artifact: {tool}")
    reports.append(_run_dynamic_scanner(
        "dast", require_mapping(plan.get("dast"), "dast"), expected_digest,
        environment, timeout_seconds, observed_at,
    ))
    reports.append(_run_dynamic_scanner(
        "iast", require_mapping(plan.get("iast"), "iast"), expected_digest,
        environment, timeout_seconds, observed_at,
    ))
    if artifact_digest(artifact) != expected_digest:
        raise ValidationError("dynamic security testing mutated the bound artifact")
    gate = _evaluate_orchestrated_reports(REQUIRED_SECURITY_TOOLS, reports, expected_digest)
    return SecurityOrchestrationResult(
        gate.allowed, gate.reasons, tuple(reports), expected_digest, str(plan["environment"])
    )


def _run_scanner(tool: str, artifact: Path, artifact_digest_value: str,
                 plan: Mapping[str, Any], environment: Mapping[str, str],
                 timeout_seconds: int, observed_at: datetime) -> Mapping[str, Any]:
    search_path = environment.get("PATH", "")
    executable = next((resolved for candidate in SCANNER_EXECUTABLES[tool]
                       if (resolved := shutil.which(candidate, path=search_path))), None)
    if executable is None:
        return _report(tool, "BLOCKED", artifact_digest_value, 127, 0, 0,
                       hashlib.sha256(f"missing:{tool}".encode()).hexdigest(), observed_at,
                       blocked_reason="scanner_not_installed")
    command = _scanner_command(tool, executable, artifact, plan)
    started_at = datetime.now(timezone.utc)
    safe_environment = {
        key: value for key, value in environment.items()
        if key in {"PATH", "TMPDIR", "LANG", "LC_ALL", "JAVA_HOME", "SSL_CERT_FILE"}
    }
    safe_environment["GRYPE_DB_AUTO_UPDATE"] = "false"
    try:
        completed = subprocess.run(
            command, cwd=artifact if artifact.is_dir() else artifact.parent,
            env=safe_environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_seconds, check=False,
        )
        exit_code = completed.returncode
        output_digest = hashlib.sha256(completed.stdout + b"\0" + completed.stderr).hexdigest()
        status = "COMPLETE" if exit_code == 0 else "FAIL"
        high = 0 if exit_code == 0 else 1
    except subprocess.TimeoutExpired as exception:
        exit_code = 124
        output_digest = hashlib.sha256(
            (exception.stdout or b"") + b"\0" + (exception.stderr or b"")
        ).hexdigest()
        status = "FAIL"
        high = 1
    except OSError as exception:
        exit_code = 126
        output_digest = hashlib.sha256(type(exception).__name__.encode("utf-8")).hexdigest()
        status = "FAIL"
        high = 1
    command_binding: dict[str, Any] = {
        "tool": tool,
        "executableDigest": _file_digest(Path(executable)),
        "arguments": command[1:],
        "artifactDigest": artifact_digest_value,
        "startedAt": started_at.isoformat(),
        "outputDigest": output_digest,
    }
    if tool == "sast":
        command_binding["configurationDigest"] = _file_digest(
            Path(require_text(plan.get("sastConfigPath"), "sastConfigPath")).resolve()
        )
    command_digest = hashlib.sha256(canonical_json(command_binding)).hexdigest()
    return _report(tool, status, artifact_digest_value, exit_code, 0, high,
                   command_digest, observed_at,
                   executable_digest=_file_digest(Path(executable)),
                   output_digest=output_digest)


def _scanner_command(tool: str, executable: str, artifact: Path,
                     plan: Mapping[str, Any]) -> list[str]:
    target = str(artifact)
    if tool == "sast":
        config = Path(require_text(plan.get("sastConfigPath"), "sastConfigPath")).resolve()
        if not config.is_file() or config.is_symlink():
            raise ValidationError("SAST config must be a local regular file")
        return [executable, "--quiet", "--error", "--config", str(config), target]
    if tool == "secret":
        return [executable, "detect", "--no-banner", "--no-git", "--source", target,
                "--exit-code", "1"]
    if Path(executable).name == "trivy":
        return [executable, "fs", "--quiet", "--skip-db-update", "--exit-code", "1",
                "--severity", "HIGH,CRITICAL", target]
    return [executable, target, "--fail-on", "high"]


def _run_dynamic_scanner(tool: str, configuration: Mapping[str, Any],
                         artifact_digest_value: str, environment: Mapping[str, str],
                         timeout_seconds: int, observed_at: datetime) -> Mapping[str, Any]:
    """Run the reviewed scanner executable and derive status from its strict report."""

    scanner = Path(__file__).resolve().parents[2] / "dynamic_security_scanner.py"
    if not scanner.is_file() or scanner.is_symlink():
        return _report(tool, "BLOCKED", artifact_digest_value, 127, 1, 0,
                       hashlib.sha256(f"missing:{tool}:scanner".encode()).hexdigest(),
                       observed_at, blocked_reason="dynamic_scanner_not_installed")
    token_env = require_text(configuration.get("testTokenEnv"), f"{tool}.testTokenEnv")
    token = environment.get(token_env)
    if token is None:
        raise ValidationError("security test token is unavailable")
    _validate_test_token(token)
    command = [sys.executable, str(scanner), "--mode", tool,
               "--artifact-digest", artifact_digest_value]
    safe_environment = {
        "PATH": environment.get("PATH", ""),
        "LANG": environment.get("LANG", "C.UTF-8"),
        token_env: token,
    }
    payload = canonical_json(configuration)
    started_at = datetime.now(timezone.utc)
    try:
        completed = subprocess.run(
            command, cwd=scanner.parents[1], env=safe_environment,
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired as exception:
        output_digest = hashlib.sha256(
            (exception.stdout or b"") + b"\0" + (exception.stderr or b"")
        ).hexdigest()
        return _report(tool, "FAIL", artifact_digest_value, 124, 1, 0,
                       output_digest, observed_at, output_digest=output_digest,
                       executable_digest=_file_digest(scanner))
    if len(completed.stdout) > 131_072 or len(completed.stderr) > 65_536:
        raise ValidationError(f"{tool} scanner output exceeded the safe size")
    output_digest = hashlib.sha256(completed.stdout + b"\0" + completed.stderr).hexdigest()
    try:
        decoded = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ValidationError(f"{tool} scanner output is not strict JSON") from exception
    report = require_mapping(decoded, f"{tool} scanner report")
    critical = report.get("criticalFindings")
    high = report.get("highFindings")
    observed_requests = report.get("observedRequests")
    exit_code = report.get("exitCode")
    valid = (
        report.get("tool") == tool
        and report.get("artifactDigest") == artifact_digest_value
        and isinstance(critical, int) and not isinstance(critical, bool) and critical >= 0
        and isinstance(high, int) and not isinstance(high, bool) and high >= 0
        and isinstance(observed_requests, int) and not isinstance(observed_requests, bool)
        and observed_requests > 0
        and isinstance(exit_code, int) and not isinstance(exit_code, bool)
        and exit_code == completed.returncode
        and report.get("status") in {"COMPLETE", "FAIL"}
        and report.get("scannerVersion") == "elmpay-dynamic-security/1"
        and isinstance(report.get("executionDigest"), str)
        and _is_digest(str(report.get("executionDigest")))
    )
    if not valid:
        return _report(tool, "FAIL", artifact_digest_value, 2, 1, 0,
                       output_digest, observed_at, output_digest=output_digest,
                       executable_digest=_file_digest(scanner),
                       blocked_reason="invalid_dynamic_scanner_report")
    command_binding = {
        "tool": tool, "scannerSourceDigest": _file_digest(scanner),
        "pythonExecutableDigest": _file_digest(Path(sys.executable).resolve()),
        "arguments": command[2:], "configurationDigest": hashlib.sha256(payload).hexdigest(),
        "artifactDigest": artifact_digest_value, "startedAt": started_at.isoformat(),
        "outputDigest": output_digest, "scannerExecutionDigest": report["executionDigest"],
    }
    execution_digest = hashlib.sha256(canonical_json(command_binding)).hexdigest()
    status = "COMPLETE" if (completed.returncode == 0 and exit_code == 0
                            and critical == 0 and high == 0
                            and report.get("status") == "COMPLETE") else "FAIL"
    return _report(
        tool, status, artifact_digest_value, int(exit_code), int(critical), int(high),
        execution_digest, observed_at, output_digest=output_digest,
        executable_digest=_file_digest(scanner), scanner_version=report["scannerVersion"],
        observed_requests=observed_requests,
    )


def _evaluate_orchestrated_reports(required_tools: tuple[str, ...],
                                   reports: list[Mapping[str, Any]],
                                   expected_digest: str) -> GateReport:
    from .quality import evaluate_security_pipeline
    return evaluate_security_pipeline(required_tools, reports, expected_digest)


def _report(tool: str, status: str, artifact_digest_value: str, exit_code: int,
            critical: int, high: int, execution_digest: str, observed_at: datetime,
            **extra: Any) -> Mapping[str, Any]:
    return {
        "tool": tool,
        "status": status,
        "artifactDigest": artifact_digest_value,
        "exitCode": exit_code,
        "criticalFindings": critical,
        "highFindings": high,
        "executionDigest": execution_digest,
        "orchestrated": True,
        "observedAt": observed_at.isoformat(),
        **extra,
    }


def artifact_digest(path: Path) -> str:
    if not path.exists() or path.is_symlink():
        raise ValidationError("security artifact must exist and may not be a symlink")
    digest = hashlib.sha256()
    files = [path] if path.is_file() else sorted(
        item for item in path.rglob("*") if item.is_file()
    )
    total = 0
    for item in files:
        if item.is_symlink():
            raise ValidationError("security artifact tree may not contain symlinks")
        relative = item.name if path.is_file() else item.relative_to(path).as_posix()
        size = item.stat().st_size
        total += size
        if total > 1_073_741_824:
            raise ValidationError("security artifact exceeds the bounded scan size")
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(_stream_digest(item, 1_073_741_824))
    if not files:
        raise ValidationError("security artifact contains no files")
    return digest.hexdigest()


def _file_digest(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValidationError("discovered scanner is not a regular executable")
    return _stream_digest(path, 536_870_912).hex()


def _stream_digest(path: Path, maximum_bytes: int) -> bytes:
    digest = hashlib.sha256()
    observed = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            observed += len(chunk)
            if observed > maximum_bytes:
                raise ValidationError("security input exceeds its bounded digest size")
            digest.update(chunk)
    return digest.digest()


def _is_digest(value: str) -> bool:
    return bool(__import__("re").fullmatch(r"[0-9a-f]{64}", value))


def _bounded_integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValidationError(f"{field} is outside the safe bound")
    return value
