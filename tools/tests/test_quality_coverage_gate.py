"""Executable coverage/mutation gate tests.

The fixtures deliberately contain detailed line and mutant records.  A caller
supplied percentage or a green boolean is never sufficient to pass the gate.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools.paygov import buildgen
from tools.runtime.elmpay_runtime.common import ValidationError
from tools.runtime.elmpay_runtime.quality_metrics import (
    PYTHON_DISCOVERIES,
    PYTHON_SOURCE_ROOTS,
    QUALITY_TASK,
    ToolExecution,
    _tool_execution,
    capture_source_binding,
    evaluate_quality_reports,
    parse_coverage_json,
    parse_jacoco_xml,
    run_quality_metrics,
)


REAL_ROOT = Path(__file__).resolve().parents[2]
EMPTY_DIGEST = "0" * 64


def _policy() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "requireCleanWorkingTree": True,
        "thresholds": {
            "lineCoverageMinimumPercent": 80,
            "mutationScoreMinimumPercent": 60,
        },
        "pythonCoverage": {
            "requiredVersion": "7.14.3",
            "executableCandidates": ["coverage", "coverage3"],
            "sourceRoots": list(PYTHON_SOURCE_ROOTS),
            "testDiscoveries": list(PYTHON_DISCOVERIES),
            "dataFile": "build/quality-metrics/.coverage",
            "report": "build/quality-metrics/python-coverage.json",
            "timeoutSeconds": 30,
        },
        "javaQuality": {
            "gradleExecutable": "./gradlew",
            "task": QUALITY_TASK,
            "jacocoReport": "build/reports/jacoco/test/jacocoTestReport.xml",
            "pitestReport": "build/reports/pitest/mutations.xml",
            "timeoutSeconds": 30,
        },
        "result": "build/quality-metrics/gate.json",
    }


class QualityCoverageMutationGateTest(unittest.TestCase):
    def test_real_failed_tool_preserves_private_raw_output_and_digests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = (sys.executable, "-c", (
                "import sys; print('quality stdout'); "
                "sys.stderr.write('quality diagnostic\\n'); sys.exit(7)"))
            result = _tool_execution(
                "coverage.py", command, cwd=root, environment={}, timeout=10,
                version="test-process",
            )
            self.assertEqual(7, result.exit_code)
            self.assertEqual("EXECUTION_FAILED", result.failure_kind)
            receipts = list((root / "build/quality-metrics/tool-output").glob("*/receipt.json"))
            self.assertEqual(1, len(receipts))
            receipt = json.loads(receipts[0].read_text())
            self.assertEqual(list(command), receipt["command"])
            self.assertTrue(receipt["executed"])
            self.assertGreater(receipt["executor_pid"], 0)
            self.assertEqual(7, receipt["exit_code"])
            for name, expected, digest in (
                ("stdout", b"quality stdout\n", result.stdout_digest),
                ("stderr", b"quality diagnostic\n", result.stderr_digest),
            ):
                path = receipts[0].parent / (name + ".log")
                self.assertEqual(expected, path.read_bytes())
                self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(digest, receipt[name + "_sha256"])
                self.assertEqual(0, path.stat().st_mode & 0o077)
            self.assertEqual(0, receipts[0].stat().st_mode & 0o077)
            self.assertEqual(0, receipts[0].parent.stat().st_mode & 0o077)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in (
            "tools/paygov",
            "tools/runtime/elmpay_runtime",
            "governance",
            "module-a",
        ):
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        (self.root / "tools/paygov/a.py").write_text("a = 1\n", encoding="utf-8")
        (self.root / "tools/runtime/elmpay_runtime/b.py").write_text(
            "b = 2\n", encoding="utf-8"
        )
        self._write_json(
            "governance/version-catalog.json",
            {
                "modules_by_build_system": {"gradle": ["module-a"]},
                "entries": [
                    {
                        "id": "coverage-py",
                        "version": "7.14.3",
                        "pin_type": "exact",
                    }
                ],
            },
        )
        self._write_json(
            "governance/module-registry.json",
            {"modules": [{"name": "module-a", "path": "module-a"}]},
        )
        (self.root / ".gitignore").write_text("**/build/\n", encoding="utf-8")
        self._git("init", "-q")
        self._git("config", "user.email", "quality-gate@example.invalid")
        self._git("config", "user.name", "Quality Gate Test")
        self._git("add", ".")
        self._git("commit", "-q", "-m", "fixture")
        self.python_report = self.root / "build/quality-metrics/python-coverage.json"
        self.jacoco_report = (
            self.root
            / "module-a/build/reports/jacoco/test/jacocoTestReport.xml"
        )
        self.pitest_report = self.root / "module-a/build/reports/pitest/mutations.xml"

    def _git(self, *arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=10,
        )

    def _write_json(self, relative: str, value: object) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    @staticmethod
    def _file_coverage(covered: int, total: int) -> dict[str, object]:
        return {
            "executed_lines": list(range(1, covered + 1)),
            "missing_lines": list(range(covered + 1, total + 1)),
            "summary": {
                "covered_lines": covered,
                "missing_lines": total - covered,
                "num_statements": total,
            },
        }

    def _coverage(self, covered: int = 4, total: int = 5) -> None:
        self._write_json(
            "build/quality-metrics/python-coverage.json",
            {
                "meta": {"version": "7.14.3"},
                "files": {
                    "tools/paygov/a.py": self._file_coverage(covered, total),
                    "tools/runtime/elmpay_runtime/b.py": self._file_coverage(
                        covered, total
                    ),
                },
                "totals": {
                    "covered_lines": covered * 2,
                    "num_statements": total * 2,
                },
            },
        )

    def _jacoco(self, covered: int = 4, total: int = 5) -> None:
        lines = []
        for number in range(1, total + 1):
            missed = 0 if number <= covered else 1
            hit = 1 if number <= covered else 0
            lines.append(
                f'<line nr="{number}" mi="{missed}" ci="{hit}" mb="0" cb="0"/>'
            )
        self.jacoco_report.parent.mkdir(parents=True, exist_ok=True)
        self.jacoco_report.write_text(
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">'
            "<report name=\"fixture\"><package name=\"example\">"
            "<sourcefile name=\"Example.java\">"
            + "".join(lines)
            + f'<counter type="LINE" missed="{total - covered}" covered="{covered}"/>'
            "</sourcefile></package>"
            f'<counter type="LINE" missed="{total - covered}" covered="{covered}"/>'
            "</report>",
            encoding="utf-8",
        )

    def _pitest(self, killed: int = 3, total: int = 5) -> None:
        mutants = []
        for index in range(total):
            is_killed = index < killed
            status = "KILLED" if is_killed else "SURVIVED"
            detected = "true" if is_killed else "false"
            mutants.append(
                f'<mutation detected="{detected}" status="{status}">'
                "<sourceFile>Example.java</sourceFile>"
                "<mutatedClass>example.Example</mutatedClass>"
                "<mutatedMethod>method</mutatedMethod>"
                "<methodDescription>()V</methodDescription>"
                f"<lineNumber>{index + 1}</lineNumber>"
                "<mutator>org.pitest.TestMutator</mutator>"
                f"<index>{index}</index><block>0</block>"
                "</mutation>"
            )
        self.pitest_report.parent.mkdir(parents=True, exist_ok=True)
        self.pitest_report.write_text(
            "<mutations>" + "".join(mutants) + "</mutations>", encoding="utf-8"
        )

    def _executions(self) -> tuple[ToolExecution, ...]:
        executable = "/usr/bin/coverage"
        sources = ",".join(PYTHON_SOURCE_ROOTS)
        executions: list[ToolExecution] = []
        for index, discovery in enumerate(PYTHON_DISCOVERIES):
            append = ("--append",) if index else ()
            executions.append(
                ToolExecution(
                    "coverage.py",
                    (
                        executable,
                        "run",
                        *append,
                        "--branch",
                        f"--source={sources}",
                        "-m",
                        "unittest",
                        "discover",
                        "-s",
                        discovery,
                        "-t",
                        ".",
                    ),
                    0,
                    1,
                    EMPTY_DIGEST,
                    EMPTY_DIGEST,
                    "Coverage.py, version 7.14.3",
                )
            )
        executions.append(
            ToolExecution(
                "coverage.py",
                (executable, "json", "-o", str(self.python_report)),
                0,
                1,
                EMPTY_DIGEST,
                EMPTY_DIGEST,
                "Coverage.py, version 7.14.3",
            )
        )
        executions.append(
            ToolExecution(
                "gradle-jacoco-pitest",
                (str((self.root / "gradlew").resolve()), "--no-daemon", QUALITY_TASK),
                0,
                1,
                EMPTY_DIGEST,
                EMPTY_DIGEST,
                "Gradle 9.2.1",
            )
        )
        return tuple(executions)

    def _evaluate(self):
        return evaluate_quality_reports(
            root=self.root,
            policy=_policy(),
            python_report=self.python_report,
            jacoco_reports=(self.jacoco_report,),
            pitest_reports=(self.pitest_report,),
            executions=self._executions(),
        )

    def test_detailed_reports_at_exact_threshold_pass(self) -> None:
        self._coverage()
        self._jacoco()
        self._pitest()

        result = self._evaluate()

        self.assertTrue(result.allowed, result.reasons)
        self.assertEqual(result.status, "PASSED")
        self.assertEqual((result.coverage.covered, result.coverage.total), (12, 15))
        self.assertEqual((result.mutation.killed, result.mutation.total), (3, 5))
        self.assertEqual(result.document()["certificationStatus"], "NOT_CERTIFIED")

    def test_caller_percentage_without_line_details_is_rejected(self) -> None:
        self._write_json(
            "build/quality-metrics/python-coverage.json",
            {"lineCoveragePercent": 100, "allowed": True},
        )

        with self.assertRaises(ValidationError):
            parse_coverage_json(
                self.python_report,
                root=self.root,
                expected_source_roots=PYTHON_SOURCE_ROOTS,
            )

    def test_fabricated_aggregate_is_rejected(self) -> None:
        self._coverage()
        document = json.loads(self.python_report.read_text(encoding="utf-8"))
        document["totals"]["covered_lines"] = 10
        self.python_report.write_text(json.dumps(document), encoding="utf-8")

        with self.assertRaisesRegex(ValidationError, "aggregate totals"):
            parse_coverage_json(
                self.python_report,
                root=self.root,
                expected_source_roots=PYTHON_SOURCE_ROOTS,
            )

    def test_only_official_jacoco_doctype_is_accepted(self) -> None:
        self._jacoco()
        self.assertEqual(parse_jacoco_xml(self.jacoco_report).percent, 80.0)
        value = self.jacoco_report.read_text(encoding="utf-8").replace(
            '-//JACOCO//DTD Report 1.1//EN', "-//ATTACKER//DTD Report 1.1//EN"
        )
        self.jacoco_report.write_text(value, encoding="utf-8")

        with self.assertRaisesRegex(ValidationError, "untrusted DOCTYPE"):
            parse_jacoco_xml(self.jacoco_report)

    def test_incomplete_execution_receipts_fail_closed(self) -> None:
        self._coverage()
        self._jacoco()
        self._pitest()

        result = evaluate_quality_reports(
            root=self.root,
            policy=_policy(),
            python_report=self.python_report,
            jacoco_reports=(self.jacoco_report,),
            pitest_reports=(self.pitest_report,),
            executions=(),
        )

        self.assertFalse(result.allowed)
        self.assertIn("execution_receipts_missing", result.reasons)

    def test_each_scope_must_meet_threshold_independently(self) -> None:
        self._coverage(3, 5)
        self._jacoco(3, 5)
        self._pitest(2, 5)

        result = self._evaluate()

        self.assertFalse(result.allowed)
        self.assertTrue(
            any(reason.startswith("python_line_coverage_below_threshold") for reason in result.reasons)
        )
        self.assertTrue(
            any(reason.startswith("jacoco_line_coverage_below_threshold") for reason in result.reasons)
        )
        self.assertTrue(
            any(reason.startswith("pitest_mutation_score_below_threshold") for reason in result.reasons)
        )

    def test_report_path_substitution_is_rejected(self) -> None:
        self._coverage()
        self._jacoco()
        self._pitest()
        substituted = self.root / "build/fake-jacoco.xml"
        substituted.parent.mkdir(parents=True, exist_ok=True)
        substituted.write_bytes(self.jacoco_report.read_bytes())

        result = evaluate_quality_reports(
            root=self.root,
            policy=_policy(),
            python_report=self.python_report,
            jacoco_reports=(substituted,),
            pitest_reports=(self.pitest_report,),
            executions=self._executions(),
        )

        self.assertFalse(result.allowed)
        self.assertTrue(any("not bound to module" in reason for reason in result.reasons))

    def test_lower_threshold_or_narrower_scope_is_rejected(self) -> None:
        weak_threshold = copy.deepcopy(_policy())
        weak_threshold["thresholds"]["lineCoverageMinimumPercent"] = 79
        with self.assertRaisesRegex(ValidationError, "cannot be lower than 80"):
            run_quality_metrics(self.root, weak_threshold)

        weak_scope = copy.deepcopy(_policy())
        weak_scope["pythonCoverage"]["sourceRoots"] = ["tools/paygov"]
        with self.assertRaisesRegex(ValidationError, "complete scope"):
            run_quality_metrics(self.root, weak_scope)

    def test_missing_coverage_tool_is_blocked(self) -> None:
        with mock.patch(
            "tools.runtime.elmpay_runtime.quality_metrics.shutil.which",
            return_value=None,
        ):
            result = run_quality_metrics(self.root, _policy(), offline=True)

        self.assertFalse(result.allowed)
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.reasons, ("coverage_tool_unavailable",))

    def test_coverage_tool_version_must_exactly_match_ssot(self) -> None:
        with (
            mock.patch(
                "tools.runtime.elmpay_runtime.quality_metrics.shutil.which",
                return_value="/usr/bin/coverage",
            ),
            mock.patch(
                "tools.runtime.elmpay_runtime.quality_metrics._tool_version",
                return_value="Coverage.py, version 7.14.2",
            ),
        ):
            result = run_quality_metrics(self.root, _policy(), offline=True)

        self.assertFalse(result.allowed)
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(
            result.reasons,
            ("coverage_tool_version_mismatch:7.14.2!=7.14.3",),
        )

    def test_source_change_cannot_reuse_previous_reports(self) -> None:
        self._coverage()
        self._jacoco()
        self._pitest()
        before = capture_source_binding(self.root)
        (self.root / "tools/paygov/a.py").write_text("a = 2\n", encoding="utf-8")

        result = evaluate_quality_reports(
            root=self.root,
            policy=_policy(),
            python_report=self.python_report,
            jacoco_reports=(self.jacoco_report,),
            pitest_reports=(self.pitest_report,),
            executions=self._executions(),
            expected_source_binding=before,
        )

        self.assertFalse(result.allowed)
        self.assertIn("source_binding_changed_during_execution", result.reasons)
        self.assertNotEqual(result.source_binding.source_digest, before.source_digest)
        self.assertEqual(result.source_binding.git_head, before.git_head)

    def test_commit_change_cannot_reuse_previous_reports(self) -> None:
        self._coverage()
        self._jacoco()
        self._pitest()
        before = capture_source_binding(self.root)
        self._git("commit", "-q", "--allow-empty", "-m", "new commit")

        result = evaluate_quality_reports(
            root=self.root,
            policy=_policy(),
            python_report=self.python_report,
            jacoco_reports=(self.jacoco_report,),
            pitest_reports=(self.pitest_report,),
            executions=self._executions(),
            expected_source_binding=before,
        )

        self.assertFalse(result.allowed)
        self.assertIn("source_binding_changed_during_execution", result.reasons)
        self.assertNotEqual(result.source_binding.git_head, before.git_head)
        self.assertEqual(result.source_binding.source_digest, before.source_digest)

    def test_gradle_failure_classification_distinguishes_offline_cache(self) -> None:
        environment = {"PATH": str(Path(sys.executable).parent)}
        offline = _tool_execution(
            "gradle-jacoco-pitest",
            (
                sys.executable,
                "-c",
                "import sys;sys.stderr.write('no cached plugin available for offline mode');sys.exit(1)",
                "--offline",
            ),
            cwd=self.root,
            environment=environment,
            timeout=10,
            version="Gradle 9.2.1",
        )
        test_failure = _tool_execution(
            "gradle-jacoco-pitest",
            (
                sys.executable,
                "-c",
                "import sys;sys.stderr.write('mutation threshold failure');sys.exit(1)",
            ),
            cwd=self.root,
            environment=environment,
            timeout=10,
            version="Gradle 9.2.1",
        )

        self.assertEqual(offline.failure_kind, "OFFLINE_DEPENDENCY_UNAVAILABLE")
        self.assertEqual(test_failure.failure_kind, "EXECUTION_FAILED")

    def test_generated_gradle_gate_is_pinned_and_machine_enforced(self) -> None:
        rendered = buildgen.render_all(REAL_ROOT)["build.gradle.kts"]
        catalogue = json.loads(
            (REAL_ROOT / "governance/version-catalog.json").read_text(encoding="utf-8")
        )
        entries = {item["id"]: item["version"] for item in catalogue["entries"]}

        self.assertEqual(
            (REAL_ROOT / "build.gradle.kts").read_text(encoding="utf-8"), rendered
        )
        self.assertIn(
            f'id("info.solidsoft.pitest") version "{entries["pitest-gradle"]}"',
            rendered,
        )
        self.assertIn(f'toolVersion = "{entries["jacoco"]}"', rendered)
        self.assertIn(f'pitestVersion.set("{entries["pitest"]}")', rendered)
        self.assertIn('minimum = "0.80".toBigDecimal()', rendered)
        self.assertIn("mutationThreshold.set(60)", rendered)
        self.assertIn(f'tasks.register("{QUALITY_TASK}")', rendered)


if __name__ == "__main__":
    unittest.main()
