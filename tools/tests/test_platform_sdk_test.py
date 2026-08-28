"""Fail-closed tests for hosted iOS and Flutter SDK orchestration."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import platform_sdk_test as runner


class PlatformSdkRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="elmpay-platform-sdk-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.out = Path("build/platform/result.json")
        self.log = Path("build/platform/result.log")

    def _report(self) -> dict:
        return json.loads((self.root / self.out).read_text(encoding="utf-8"))

    def test_ios_on_non_macos_is_blocked_not_passed(self) -> None:
        with mock.patch.object(runner, "ROOT", self.root), \
                mock.patch.object(runner.sys, "platform", "linux"):
            code = runner.execute("ios", self.out, self.log)
        self.assertEqual(code, 2)
        self.assertEqual(self._report()["status"], "BLOCKED")
        self.assertEqual(self._report()["certificationStatus"], "NOT_CERTIFIED")

    def test_missing_dart_is_blocked_not_skipped(self) -> None:
        with mock.patch.object(runner, "ROOT", self.root), \
                mock.patch.object(runner.shutil, "which", return_value=None):
            code = runner.execute("flutter", self.out, self.log)
        self.assertEqual(code, 2)
        self.assertEqual(self._report()["reason"], "dart_toolchain_missing")

    def test_flutter_requires_the_pinned_version_and_every_command(self) -> None:
        results = [
            subprocess.CompletedProcess([], 0, "Dart SDK version: 3.8.1 (stable)\n"),
            subprocess.CompletedProcess([], 0, "resolved\n"),
            subprocess.CompletedProcess([], 0, "all tests passed\n"),
        ]
        with mock.patch.object(runner, "ROOT", self.root), \
                mock.patch.object(runner.shutil, "which", return_value="/bin/dart"), \
                mock.patch.object(runner.subprocess, "run", side_effect=results) as invoked:
            code = runner.execute("flutter", self.out, self.log)
        self.assertEqual(code, 0)
        self.assertEqual(self._report()["status"], "PASS")
        self.assertEqual(invoked.call_count, 3)
        self.assertEqual(self._report()["commands"][-1]["argv"], ["/bin/dart", "test"])

    def test_unpinned_dart_version_is_blocked_before_tests(self) -> None:
        result = subprocess.CompletedProcess([], 0, "Dart SDK version: 3.9.0 (stable)\n")
        with mock.patch.object(runner, "ROOT", self.root), \
                mock.patch.object(runner.shutil, "which", return_value="/bin/dart"), \
                mock.patch.object(runner.subprocess, "run", return_value=result) as invoked:
            code = runner.execute("flutter", self.out, self.log)
        self.assertEqual(code, 2)
        self.assertEqual(self._report()["reason"], "hosted_toolchain_version_mismatch")
        self.assertEqual(invoked.call_count, 1)


if __name__ == "__main__":
    unittest.main()
