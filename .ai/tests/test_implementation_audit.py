from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "implementation_audit.py"
SPEC = importlib.util.spec_from_file_location("implementation_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class ImplementationAuditTest(unittest.TestCase):
    def test_reports_every_manifest_batch_without_changing_certification(self) -> None:
        report = AUDIT.audit()
        self.assertEqual(128, report["batch_count"])
        self.assertEqual([f"B{number:02d}" for number in range(128)],
                         [batch["id"] for batch in report["batches"]])
        self.assertEqual("PASS", report["inventory_status"], report["issues"])
        self.assertEqual("NOT_RUN", report["implementation_surface"])
        self.assertEqual("NOT_CERTIFIED", report["certification_status"])
        self.assertFalse(report["certified_batches_changed"])
        self.assertFalse(report["verification_executed"])
        self.assertEqual([], report["verification_checks"])

    def test_all_128_batches_have_exact_explicit_role_mappings(self) -> None:
        report = AUDIT.audit()
        batches = {batch["id"]: batch for batch in report["batches"]}
        self.assertEqual({f"B{number:02d}" for number in range(128)}, set(batches))
        for number in range(128):
            batch_id = f"B{number:02d}"
            batch = batches[batch_id]
            self.assertNotIn("no explicit implementation inventory", batch["issues"])
            self.assertEqual("PASS", batch["status"], batch["issues"])
            inventory = batch["inventory"]
            for role in AUDIT.REQUIRED_ROLES:
                if role == "migrations" and not inventory["migration_required"]:
                    self.assertTrue(inventory["migration_not_applicable_reason"].strip(),
                                    f"{batch_id}: migration N/A reason")
                    continue
                self.assertGreater(len(inventory[role]), 0, f"{batch_id}:{role}")
                for requirement in inventory[role]:
                    self.assertFalse(any(character in requirement["path"]
                                         for character in "*?[]{}"))
                    self.assertTrue(requirement["markers"])
                    self.assertFalse(requirement["path"].startswith("evidence/"))
            self.assertEqual([], inventory["known_gaps"], batch_id)

    def test_declared_gap_and_unmapped_batch_fail_closed(self) -> None:
        missing, _ = AUDIT.validate_batch(Path.cwd(), "B40", None)
        self.assertIn("broad directory presence is rejected", missing[0])
        incomplete = AUDIT.BatchImplementation(
            executable=(), runtime_entrypoint=(), config=(), migrations=(), tests=(),
            migration_required=False,
            migration_not_applicable_reason="Stateless control.",
            known_gaps=("production runtime is not wired",),
        )
        problems, _ = AUDIT.validate_batch(Path.cwd(), "B15", incomplete)
        self.assertTrue(any("declared implementation gap: production runtime is not wired"
                            in problem for problem in problems))

    def test_artifact_validator_rejects_directory_glob_and_reference_model(self) -> None:
        with tempfile.TemporaryDirectory(prefix="implementation-inventory-") as temporary:
            root = Path(temporary)
            (root / "libs/reference").mkdir(parents=True)
            (root / "libs/reference/model.py").write_text("def run(): pass\n", encoding="utf-8")
            directory = AUDIT.ArtifactRequirement("libs/reference", ("run",))
            glob = AUDIT.ArtifactRequirement("libs/**/*.py", ("run",))
            reference = AUDIT.ArtifactRequirement("libs/reference/model.py", ("run",))
            self.assertTrue(AUDIT.validate_artifact(root, "executable", directory))
            self.assertTrue(AUDIT.validate_artifact(root, "executable", glob))
            problems = AUDIT.validate_artifact(root, "executable", reference)
            self.assertTrue(any("non-runtime path" in problem for problem in problems))

    def test_semantic_markers_are_required_not_just_file_existence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="implementation-markers-") as temporary:
            root = Path(temporary)
            path = root / "services/example/src/main/java/example/Worker.java"
            path.parent.mkdir(parents=True)
            path.write_text("final class Worker {}\n", encoding="utf-8")
            requirement = AUDIT.ArtifactRequirement(
                "services/example/src/main/java/example/Worker.java", ("SKIP LOCKED",))
            problems = AUDIT.validate_artifact(root, "runtime_entrypoint", requirement)
            self.assertTrue(any("lacks marker" in problem for problem in problems))

    def test_inventory_schema_is_external_strict_and_extensible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="implementation-schema-") as temporary:
            path = Path(temporary) / "inventory.json"
            path.write_text('{"schema_version": 1, "required_roles": [], "batches": {}}',
                            encoding="utf-8")
            decoded, problems = AUDIT.load_implementation_inventory(path)
            self.assertEqual({}, decoded)
            self.assertTrue(any("required_roles" in problem for problem in problems))

    def test_semantic_verification_runs_the_complete_local_matrix_and_web_apps(self) -> None:
        commands = {name: command for name, command in AUDIT.VERIFY_COMMANDS}
        self.assertIn("b00-b117-local-semantic-matrix", commands)
        matrix = commands["b00-b117-local-semantic-matrix"]
        self.assertIn("scripts/run-test-matrix.py", matrix)
        self.assertIn("--execution", matrix)
        self.assertIn("local", matrix)
        self.assertIn("governance-unit-tests", commands)
        self.assertIn("checkout-web", commands)
        self.assertIn("admin-web", commands)

    def test_marker_complete_inventory_cannot_override_a_semantic_failure(self) -> None:
        failed = [{
            "name": "semantic-regression", "command": ["false"], "exit_code": 9,
            "timed_out": False, "duration_seconds": 0.001, "output_tail": "failed",
        }]
        with mock.patch.object(AUDIT, "verify_commands", return_value=failed):
            report = AUDIT.audit(run_checks=True)
        self.assertEqual("PASS", report["inventory_status"])
        self.assertEqual("FAIL", report["implementation_surface"])
        self.assertTrue(report["verification_executed"])
        self.assertEqual(9, report["verification_checks"][0]["exit_code"])


if __name__ == "__main__":
    unittest.main()
