#!/usr/bin/env python3
"""Run one hosted-platform SDK contract suite and emit a fail-closed report.

The iOS suite is valid only on a Darwin runner with Swift 6.  The Flutter
client is currently a pure Dart package and is tested with the exact Dart SDK
declared by the CI catalogue.  A missing host/toolchain is ``BLOCKED``, never a
pass; a launched command that fails or times out is ``FAIL``.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SWIFT_MAJOR = 6
DART_VERSION = "3.8.1"
TIMEOUT_SECONDS = 900
SENSITIVE_ENV_MARKERS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL")


def _target(relative: Path) -> Path:
    if relative.is_absolute() or not relative.parts or relative.parts[0] != "build":
        raise ValueError("report and log paths must be repository-relative under build/")
    root = ROOT.resolve()
    target = (root / relative).resolve(strict=False)
    target.relative_to(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise ValueError(f"output must not be a symbolic link: {relative}")
    return target


def _atomic_write(path: Path, content: str) -> None:
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not any(marker in key.upper() for marker in SENSITIVE_ENV_MARKERS)
    } | {"ELMPAY_TEST_MODE": "1", "ELMPAY_ENVIRONMENT": "TEST"}


def _definition(surface: str) -> tuple[str | None, list[tuple[list[str], Path]], str | None]:
    if surface == "ios":
        if sys.platform != "darwin":
            return None, [], "ios_tests_require_a_macos_hosted_runner"
        tool = shutil.which("swift")
        if tool is None:
            return None, [], "swift_toolchain_missing"
        return tool, [
            ([tool, "--version"], ROOT),
            ([tool, "test", "--package-path", "sdks/mobile/ios"], ROOT),
        ], None
    if surface == "flutter":
        tool = shutil.which("dart")
        if tool is None:
            return None, [], "dart_toolchain_missing"
        package = ROOT / "sdks/mobile/flutter"
        return tool, [
            ([tool, "--version"], ROOT),
            ([tool, "pub", "get", "--enforce-lockfile"], package),
            ([tool, "test"], package),
        ], None
    raise ValueError(f"unsupported platform surface: {surface}")


def _version_matches(surface: str, output: str) -> bool:
    if surface == "ios":
        return re.search(rf"(?:Apple )?Swift version {SWIFT_MAJOR}(?:\.|\s)", output) is not None
    return f"Dart SDK version: {DART_VERSION}" in output


def execute(surface: str, out: Path, log: Path) -> int:
    report_path = _target(out)
    log_path = _target(log)
    started = datetime.now(timezone.utc)
    tool, commands, blocked_reason = _definition(surface)
    entries: list[dict[str, Any]] = []
    log_chunks: list[str] = []
    status = "BLOCKED" if blocked_reason else "PASS"
    reason = blocked_reason or "all_commands_passed"

    if blocked_reason is None:
        for index, (command, cwd) in enumerate(commands):
            display = " ".join(command)
            try:
                completed = subprocess.run(
                    command,
                    cwd=cwd,
                    env=_environment(),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=TIMEOUT_SECONDS,
                    check=False,
                )
                output = completed.stdout or ""
                entries.append({"argv": command, "exitCode": completed.returncode})
                log_chunks.append(f"$ {display}\n{output}")
                if completed.returncode != 0:
                    status = "FAIL"
                    reason = f"command_failed:{index + 1}"
                    break
                if index == 0 and not _version_matches(surface, output):
                    status = "BLOCKED"
                    reason = "hosted_toolchain_version_mismatch"
                    break
            except subprocess.TimeoutExpired as exc:
                output = exc.stdout.decode("utf-8", errors="replace") \
                    if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                entries.append({"argv": command, "exitCode": 124})
                log_chunks.append(f"$ {display}\n{output}\nTIMEOUT")
                status = "FAIL"
                reason = f"command_timeout:{index + 1}"
                break

    finished = datetime.now(timezone.utc)
    report = {
        "schemaVersion": 1,
        "surface": surface,
        "status": status,
        "reason": reason,
        "tool": tool,
        "commands": entries,
        "startedAt": started.isoformat(),
        "finishedAt": finished.isoformat(),
        "evidenceClass": "LOCAL_OR_HOSTED_CONTRACT_TEST",
        "certificationStatus": "NOT_CERTIFIED",
    }
    _atomic_write(log_path, "\n".join(log_chunks) + ("\n" if log_chunks else f"{reason}\n"))
    _atomic_write(report_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if status == "PASS" else 2 if status == "BLOCKED" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("surface", choices=("ios", "flutter"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        return execute(arguments.surface, arguments.out, arguments.log)
    except (OSError, TypeError, ValueError) as exc:
        print(f"platform SDK test configuration failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
