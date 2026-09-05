from __future__ import annotations

import copy
import importlib.util
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

_CODE_SUITE_SPEC = importlib.util.spec_from_file_location(
    "elmpay_code_suite_runner", ROOT / "scripts/run-code-suite.py"
)
assert _CODE_SUITE_SPEC and _CODE_SUITE_SPEC.loader
code_suites = importlib.util.module_from_spec(_CODE_SUITE_SPEC)
sys.modules[_CODE_SUITE_SPEC.name] = code_suites
_CODE_SUITE_SPEC.loader.exec_module(code_suites)


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

    def test_twenty_one_suites_route_every_local_command_through_fail_closed_runner(self) -> None:
        self.assertEqual(21, len(self.matrix["suites"]))
        local = [suite for suite in self.matrix["suites"] if suite["execution"] == "local"]
        external = [suite for suite in self.matrix["suites"] if suite["execution"] == "external"]
        self.assertEqual(18, len(local))
        self.assertEqual(3, len(external))
        routed = set()
        for suite in local:
            self.assertEqual(["python3", "scripts/run-code-suite.py"], suite["command"][:2])
            self.assertEqual(3, len(suite["command"]))
            routed.add(suite["command"][2])
        self.assertEqual(set(code_suites.SUITES), routed)

    def test_every_testing_module_has_one_executed_slice_owner(self) -> None:
        discovered = code_suites.validate_testing_module_coverage(ROOT)
        files = sorted(
            f"testing.{path.stem}" for path in (ROOT / "testing").glob("test_*.py")
        )
        self.assertEqual(tuple(files), discovered)

    def test_new_duplicate_stale_and_unexecuted_modules_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tests = root / "testing"
            tests.mkdir()
            (tests / "test_owned.py").write_text("# synthetic\n", encoding="utf-8")
            owned = code_suites.SuiteSpec(
                commands=(("python3", "-m", "unittest", "testing.test_owned"),),
                test_modules=("testing.test_owned",),
            )
            self.assertEqual(
                ("testing.test_owned",),
                code_suites.validate_testing_module_coverage(root, {"one": owned}),
            )

            (tests / "test_new.py").write_text("# synthetic\n", encoding="utf-8")
            with self.assertRaisesRegex(code_suites.SuiteConfigurationError, "test_new"):
                code_suites.validate_testing_module_coverage(root, {"one": owned})

            (tests / "test_new.py").unlink()
            with self.assertRaisesRegex(code_suites.SuiteConfigurationError, "duplicate_owners"):
                code_suites.validate_testing_module_coverage(root, {"one": owned, "two": owned})

            stale = code_suites.SuiteSpec(
                commands=(("python3", "-m", "unittest", "testing.test_missing"),),
                test_modules=("testing.test_missing",),
            )
            with self.assertRaisesRegex(code_suites.SuiteConfigurationError, "stale"):
                code_suites.validate_testing_module_coverage(root, {"one": owned, "stale": stale})

            not_executed = code_suites.SuiteSpec(
                commands=(("python3", "-c", "print('not a test')"),),
                test_modules=("testing.test_owned",),
            )
            with self.assertRaisesRegex(code_suites.SuiteConfigurationError, "not_executed"):
                code_suites.validate_testing_module_coverage(root, {"one": not_executed})

            undeclared = code_suites.SuiteSpec(
                commands=(("python3", "-m", "unittest", "testing.test_owned"),),
            )
            with self.assertRaisesRegex(code_suites.SuiteConfigurationError, "undeclared_executed"):
                code_suites.validate_testing_module_coverage(root, {"one": undeclared})

    def test_critical_runtime_gaps_are_bound_to_executable_commands(self) -> None:
        self.assertIn(
            "testing.test_b40_b55_provider_contract_matrix",
            code_suites.SUITES["quality-core"].test_modules,
        )
        for suite_name in ("cn-providers", "global-providers"):
            commands = code_suites.SUITES[suite_name].commands
            self.assertTrue(any("scripts/provider-contract-matrix.py" in command for command in commands))
        self.assertIn(
            "testing.test_b89_egress_policy",
            code_suites.SUITES["platform"].test_modules,
        )
        operations = [
            token for command in code_suites.SUITES["operations"].commands for token in command
        ]
        self.assertIn("com.elmpay.payment.provider.AccountAwareProviderAdapterFactoryTest", operations)
        self.assertIn("com.elmpay.payment.provider.JdbcProviderCallCircuitBreakerTest", operations)
        self.assertEqual(
            {
                "testing.test_b116_security_orchestration",
                "testing.test_b117_http_load_profile",
                "testing.test_runtime_scale",
            },
            set(code_suites.SUITES["security-performance"].test_modules),
        )

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

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "empty").mkdir()
            with self.assertRaisesRegex(runner.MatrixError, "contains no files"):
                runner._relative_target(root, "empty", field="target_paths")

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
