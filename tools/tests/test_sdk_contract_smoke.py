"""Regression tests for the fail-closed server SDK orchestrator."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

from tools.tests.support import REAL_ROOT


def _load_runner():
    path = REAL_ROOT / "scripts/sdk-contract-smoke.py"
    spec = importlib.util.spec_from_file_location("elmpay_sdk_contract_smoke", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()


class ServerSdkSmokeTest(unittest.TestCase):
    def test_dotnet_is_clean_checkout_restore_build_run(self) -> None:
        commands = runner._dotnet_contract_commands("/tool/dotnet")
        self.assertEqual([name for name, _, _ in commands], [
            "dotnet-sdk-restore", "dotnet-sdk-build", "dotnet-sdk",
        ])
        self.assertEqual(commands[0][1], [
            "/tool/dotnet", "restore",
            "sdks/server/dotnet/tests/ElmPay.ContractTests.csproj", "--nologo",
        ])
        self.assertIn("--no-restore", commands[1][1])
        self.assertIn("--no-restore", commands[2][1])
        self.assertIn("--no-build", commands[2][1])

    def test_missing_tool_fails_closed(self) -> None:
        with mock.patch.object(runner.subprocess, "run", side_effect=FileNotFoundError):
            code = runner._run_command("missing", ["missing"], Path.cwd(), {})
        self.assertEqual(code, 127)

    def test_timeout_fails_closed_and_is_bounded(self) -> None:
        with mock.patch.object(
            runner.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["slow"], runner.TIMEOUT_SECONDS),
        ) as invoked:
            code = runner._run_command("slow", ["slow"], Path.cwd(), {})
        self.assertEqual(code, 124)
        self.assertEqual(invoked.call_args.kwargs["timeout"], runner.TIMEOUT_SECONDS)


if __name__ == "__main__":
    unittest.main()
