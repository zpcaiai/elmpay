from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("elmpay_test_matrix_runner", ROOT / "scripts/run-test-matrix.py")
assert _SPEC and _SPEC.loader
runner = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = runner
_SPEC.loader.exec_module(runner)


class MatrixRunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix_path = ROOT / "testing/test-matrix.json"
        cls.matrix = runner.load_json(cls.matrix_path)

    def test_matrix_is_exactly_128_batches_with_no_overlap(self) -> None:
        required = runner.validate_matrix(self.matrix, ROOT)
        self.assertEqual([f"B{number:02d}" for number in range(128)], required)
        seen = [batch for suite in self.matrix["suites"] for batch in suite["batch_ids"]]
        self.assertEqual(128, len(seen))
        self.assertEqual(128, len(set(seen)))

    def test_all_cases_have_reproducible_scenarios_and_existing_targets(self) -> None:
        for suite in self.matrix["suites"]:
            self.assertTrue(suite["scenarios"], suite["id"])
            for scenario in suite["scenarios"]:
                self.assertTrue(scenario["steps"])
                self.assertTrue(scenario["expected"])
            for path in suite.get("target_paths", []):
                self.assertTrue((ROOT / path).exists(), f"missing target {path}")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema_version":"1.0.0","schema_version":"1.0.0"}', encoding="utf-8")
            with self.assertRaises(runner.MatrixError):
                runner.load_json(path)

    def test_path_escape_and_production_command_are_rejected(self) -> None:
        escaped = copy.deepcopy(self.matrix)
        escaped["suites"][0]["target_paths"] = ["../outside"]
        with self.assertRaises(runner.MatrixError):
            runner.validate_matrix(escaped, ROOT)

        production = copy.deepcopy(self.matrix)
        production["suites"][0]["command"] = ["python3", "-c", "print('ok')", "production"]
        with self.assertRaises(runner.MatrixError):
            runner.validate_matrix(production, ROOT)

    def test_manual_external_case_is_blocked_and_never_executed(self) -> None:
        code, report = runner.run_matrix(
            self.matrix,
            self.matrix_path,
            root=ROOT,
            suite_ids=["TM-B118-B119-ACCEPTANCE"],
            allow_blocked=False,
        )
        self.assertEqual(2, code)
        self.assertEqual("BLOCKED", report["results"][0]["status"])
        self.assertIsNone(report["results"][0]["exit_code"])
        self.assertEqual("NOT_CERTIFIED", report["certification_status"])

    def test_execution_filter_is_not_misreported_as_full_matrix(self) -> None:
        code, report = runner.run_matrix(
            self.matrix,
            self.matrix_path,
            root=ROOT,
            execution="external",
            allow_blocked=True,
        )
        self.assertEqual(0, code)
        self.assertFalse(report["coverage"]["complete_matrix_selection"])
        self.assertEqual(3, report["summary"]["blocked"])

    def test_fake_success_and_failure_are_reported_without_shell(self) -> None:
        success = copy.deepcopy(self.matrix)
        success["suites"][0]["command"] = [sys.executable, "-c", "print('matrix-success')"]
        code, report = runner.run_matrix(success, self.matrix_path, root=ROOT, suite_ids=["TM-B00-B07-GOV"])
        self.assertEqual(0, code)  # an explicitly selected passing suite is independently runnable
        self.assertEqual("PASS", report["results"][0]["status"])
        self.assertIn("matrix-success", report["results"][0]["output_tail"])

        failure = copy.deepcopy(self.matrix)
        failure["suites"][0]["command"] = [sys.executable, "-c", "import sys; print('matrix-failure'); sys.exit(7)"]
        code, report = runner.run_matrix(failure, self.matrix_path, root=ROOT, suite_ids=["TM-B00-B07-GOV"])
        self.assertEqual(2, code)
        self.assertEqual("FAIL", report["results"][0]["status"])
        self.assertEqual(7, report["results"][0]["exit_code"])

    def test_reports_cannot_overwrite_evidence_or_b00(self) -> None:
        report = {"results": [], "summary": {"failed": 0, "blocked": 0}, "coverage": {}}
        with self.assertRaises(runner.MatrixError):
            runner._write_report(ROOT / "evidence/test-matrix.json", report, ROOT)
        with self.assertRaises(runner.MatrixError):
            runner._write_report(ROOT / "build/B00-test.json", report, ROOT)


if __name__ == "__main__":
    unittest.main()
