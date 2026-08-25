"""Fail-closed tests for CI governance report persistence.

These write through an isolated fixture repository rather than the working
tree. The property under test is "the report must land inside the repository
passed to --repo", which a fixture satisfies just as well as the real checkout
— while writing scratch directories into the live repository root races the
hygiene scanner and artefact hashing, and leaves the tree littered whenever
cleanup fails.
"""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tools.paygov import cli
from tools.tests.support import FixtureTestCase


class CliReports(FixtureTestCase):
    def test_verify_writes_the_exact_stdout_json_atomically(self):
        with tempfile.TemporaryDirectory(dir=self.fixture.root) as temporary:
            relative = Path(temporary).relative_to(self.fixture.root) / "nested" / "report.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main([
                    "verify",
                    "repo-hygiene",
                    "--repo",
                    str(self.fixture.root),
                    "--out",
                    str(relative),
                ])
            self.assertEqual(code, cli.EXIT_OK)
            report = self.fixture.root / relative
            self.assertEqual(report.read_text(encoding="utf-8"), stdout.getvalue())
            self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["ok"], True)
            self.assertEqual(report.stat().st_mode & 0o777, 0o644)
            self.assertEqual(list(report.parent.glob(f".{report.name}.*")), [])

    def test_failing_validation_is_still_recorded(self):
        with tempfile.TemporaryDirectory(dir=self.fixture.root) as temporary:
            relative = Path(temporary).relative_to(self.fixture.root) / "failed.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main([
                    "verify",
                    "does-not-exist",
                    "--repo",
                    str(self.fixture.root),
                    "--out",
                    str(relative),
                ])
            self.assertEqual(code, cli.EXIT_ERROR)
            payload = json.loads((self.fixture.root / relative).read_text(encoding="utf-8"))
            self.assertEqual(payload["ok"], False)
            self.assertEqual(payload["problems"][0]["code"], "CLI_UNKNOWN_VALIDATOR")
            self.assertEqual((self.fixture.root / relative).read_text(encoding="utf-8"), stdout.getvalue())

    def test_report_must_remain_inside_repository(self):
        with tempfile.TemporaryDirectory() as outside:
            destination = Path(outside) / "report.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main([
                    "verify",
                    "repo-hygiene",
                    "--repo",
                    str(self.fixture.root),
                    "--out",
                    str(destination),
                ])
            self.assertEqual(code, cli.EXIT_ERROR)
            self.assertFalse(destination.exists())
            self.assertEqual(json.loads(stdout.getvalue())["problems"][0]["code"],
                             "CLI_REPORT_WRITE")

    def test_report_refuses_symlink_target(self):
        with tempfile.TemporaryDirectory(dir=self.fixture.root) as temporary:
            base = Path(temporary)
            target = base / "target.json"
            target.write_text("preserve\n", encoding="utf-8")
            link = base / "report.json"
            link.symlink_to(target)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main([
                    "verify",
                    "repo-hygiene",
                    "--repo",
                    str(self.fixture.root),
                    "--out",
                    str(link.relative_to(self.fixture.root)),
                ])
            self.assertEqual(code, cli.EXIT_ERROR)
            self.assertEqual(target.read_text(encoding="utf-8"), "preserve\n")
            self.assertEqual(json.loads(stdout.getvalue())["problems"][0]["code"],
                             "CLI_REPORT_WRITE")

    def test_list_validators_rejects_json_report_option(self):
        with self.assertRaises(SystemExit) as raised:
            with redirect_stderr(io.StringIO()):
                cli.main(["list-validators", "--repo", str(self.fixture.root),
                          "--out", "x.json"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
