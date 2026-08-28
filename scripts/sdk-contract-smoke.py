#!/usr/bin/env python3
"""Run every checked-in server SDK contract suite with synthetic fixtures.

This is intentionally a small orchestration wrapper, not a certification tool:
it fails closed when a declared SDK toolchain is missing and never contacts a
live endpoint.  Each child process receives a test-only environment.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TIMEOUT_SECONDS = 600


def _dotnet_contract_commands(dotnet: str) -> list[tuple[str, list[str], Path]]:
    """Return a clean-checkout-safe .NET restore/build/run sequence.

    ``obj/project.assets.json`` is intentionally ignored, so a direct
    ``dotnet run --no-restore`` only works in a developer tree that happened to
    be restored already.  CI must establish that input before building and
    must not let either later phase perform a second implicit restore.
    """

    project = "sdks/server/dotnet/tests/ElmPay.ContractTests.csproj"
    return [
        ("dotnet-sdk-restore", [dotnet, "restore", project, "--nologo"], ROOT),
        ("dotnet-sdk-build", [dotnet, "build", project, "--no-restore", "--nologo"], ROOT),
        ("dotnet-sdk", [dotnet, "run", "--project", project, "--no-restore",
                        "--no-build", "--nologo"], ROOT),
    ]


def _run_command(name: str, command: list[str], cwd: Path,
                 environment: dict[str, str]) -> int:
    print(f"== {name}: {' '.join(command)}")
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            check=False,
            timeout=TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        print(f"{name}: tool_missing", file=sys.stderr)
        return 127
    except subprocess.TimeoutExpired:
        print(f"{name}: TIMEOUT ({TIMEOUT_SECONDS}s)", file=sys.stderr)
        return 124
    if completed.returncode:
        print(f"{name}: FAIL ({completed.returncode})", file=sys.stderr)
        return completed.returncode
    print(f"{name}: PASS")
    return 0


def main() -> int:
    dotnet = shutil.which("dotnet")
    dotnet_root = Path("/usr/local/share/dotnet")
    if (dotnet_root / "dotnet").is_file():
        dotnet = str(dotnet_root / "dotnet")
    commands: list[tuple[str, list[str], Path]] = [
        ("node-sdk", ["node", "--test", "sdks/server/node/elmpay-client.test.mjs"], ROOT),
        ("python-sdk", [sys.executable, "-m", "unittest", "discover", "-s", "sdks/server/python", "-p", "test_*.py", "-v"], ROOT),
        ("go-sdk", ["go", "-C", "sdks/server/go", "test", "./..."], ROOT),
    ]
    if dotnet:
        commands.extend(_dotnet_contract_commands(dotnet))
    else:
        print("dotnet-sdk: tool_missing", file=sys.stderr)
        return 127

    environment = {key: value for key, value in os.environ.items() if not any(word in key.upper() for word in ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL"))}
    environment.update({"ELMPAY_TEST_MODE": "1", "ELMPAY_ENVIRONMENT": "TEST"})
    if dotnet and Path(dotnet).parent == dotnet_root:
        environment["DOTNET_ROOT"] = str(dotnet_root)
        environment["PATH"] = f"{dotnet_root}:{environment.get('PATH', '')}"

    javac = shutil.which("javac")
    java = shutil.which("java")
    if not javac or not java:
        print("java-sdk: tool_missing", file=sys.stderr)
        return 127

    with tempfile.TemporaryDirectory(prefix="elmpay-java-sdk-") as classes:
        commands.extend([
            ("java-sdk-compile", [javac, "-d", classes,
                "sdks/server/java/src/main/java/com/elmpay/sdk/ElmpayClient.java",
                "sdks/server/java/src/test/java/com/elmpay/sdk/WebhookGoldenVectorMain.java"], ROOT),
            ("java-sdk", [java, "-cp", classes,
                "com.elmpay.sdk.WebhookGoldenVectorMain",
                "contracts/webhooks/signing-v1.json"], ROOT),
        ])
        for name, command, cwd in commands:
            return_code = _run_command(name, command, cwd, environment)
            if return_code:
                return return_code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
