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


ROOT = Path(__file__).resolve().parents[1]


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
        commands.append(("dotnet-sdk", [dotnet, "run", "--project", "sdks/server/dotnet/tests/ElmPay.ContractTests.csproj", "--no-restore", "--nologo"], ROOT))
    else:
        print("dotnet-sdk: tool_missing", file=sys.stderr)
        return 127

    environment = {key: value for key, value in os.environ.items() if not any(word in key.upper() for word in ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL"))}
    environment.update({"ELMPAY_TEST_MODE": "1", "ELMPAY_ENVIRONMENT": "TEST"})
    if dotnet and Path(dotnet).parent == dotnet_root:
        environment["DOTNET_ROOT"] = str(dotnet_root)
        environment["PATH"] = f"{dotnet_root}:{environment.get('PATH', '')}"

    for name, command, cwd in commands:
        print(f"== {name}: {' '.join(command)}")
        try:
            completed = subprocess.run(command, cwd=cwd, env=environment, check=False)
        except FileNotFoundError:
            print(f"{name}: tool_missing", file=sys.stderr)
            return 127
        if completed.returncode:
            print(f"{name}: FAIL ({completed.returncode})", file=sys.stderr)
            return completed.returncode
        print(f"{name}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
