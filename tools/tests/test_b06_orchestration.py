"""B06 / AT-B06-01 — batch orchestration, completion validation and release gate.

The suite does two things the vendored orchestrator cannot do for itself:

1. *differential testing* — the in-repository implementation is run against the
   vendored one on the real repository and must agree on every answer;
2. *tamper testing* — a synthetic evidence tree is corrupted one field at a
   time, and each corruption must be reported.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.paygov.orchestration import Programme
from tools.tests.support import REAL_ROOT, FixtureTestCase

UPSTREAM = ".payment-platform/skill-package/scripts/orchestrate.py"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SyntheticEvidence:
    """A temporary repository containing valid evidence for B00 and B01."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="paygov-orch-")
        self.root = Path(self._tmp.name)
        manifest_rel = Path(".payment-platform/skill-package/manifest.json")
        (self.root / manifest_rel.parent).mkdir(parents=True)
        (self.root / manifest_rel).write_bytes((REAL_ROOT / manifest_rel).read_bytes())
        (self.root / "governance").mkdir()
        (self.root / "tools" / "paygov").mkdir(parents=True)
        self.programme = Programme(self.root)
        self.write_batch("B00")
        self.write_batch("B01")

    def write_batch(self, batch: str) -> None:
        base = self.root / "evidence" / batch
        for name in ("test-results", "runtime", "security"):
            (base / name).mkdir(parents=True, exist_ok=True)
            (base / name / "result.log").write_text("ok\n", encoding="utf-8")
        (base / "plan.md").write_text("# plan\n" + ("scope and rollback. " * 40), encoding="utf-8")
        (base / "commands.ndjson").write_text(
            json.dumps({"timestamp": "2026-08-18T00:00:00Z", "command": "true", "exit_code": 0})
            + "\n", encoding="utf-8")
        (base / "traceability.json").write_text(json.dumps({
            "batch_id": batch, "requirements": [{"id": "R1"}], "code": [{"ref": "x"}],
            "tests": [{"ref": "y"}], "controls": [{"id": "NN-01"}],
            "evidence": [{"path": "z"}]}), encoding="utf-8")

        artefact = self.root / "governance" / f"{batch.lower()}-artifact.json"
        artefact.write_text(json.dumps({"batch": batch}), encoding="utf-8")

        completion_dir = self.root / "evidence" / "completion"
        completion_dir.mkdir(parents=True, exist_ok=True)
        deps = {}
        for dep in self.programme.dependencies(batch):
            deps[dep] = sha256_bytes((completion_dir / f"{dep}.json").read_bytes())
        payload = {
            "batch_id": batch, "status": "passed", "commit_sha": "a" * 40,
            "environment": "integration",
            "started_at": "2026-08-18T00:00:00Z", "completed_at": "2026-08-18T00:01:00Z",
            "executor": "claude-agent", "reviewer": "Ethan",
            "artifacts": [{"path": f"governance/{batch.lower()}-artifact.json",
                           "sha256": sha256_bytes(artefact.read_bytes())}],
            "tests": {"passed": 10, "failed": 0, "skipped_critical": 0},
            "security": {"blocking_findings": 0, "accepted_findings": 0},
            "dependency_hashes": deps,
        }
        (completion_dir / f"{batch}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def completion(self, batch: str) -> dict:
        return json.loads((self.root / "evidence" / "completion" / f"{batch}.json")
                          .read_text(encoding="utf-8"))

    def patch_completion(self, batch: str, fn) -> None:
        data = self.completion(batch)
        fn(data)
        (self.root / "evidence" / "completion" / f"{batch}.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def close(self) -> None:
        self._tmp.cleanup()


class SyntheticCase(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = SyntheticEvidence()
        self.addCleanup(self.evidence.close)
        self.programme = Programme(self.evidence.root)

    def problems(self, batch: str = "B00") -> list[str]:
        return self.programme.problems(batch)


class GraphProperties(FixtureTestCase):
    def test_manifest_graph_is_acyclic_and_complete(self):
        programme = Programme(REAL_ROOT)
        self.assertEqual(programme.cycles(), [])
        self.assertEqual(programme.unknown_dependencies(), [])
        self.assertEqual(len(programme.batches), 128)

    def test_manifest_is_topologically_sorted(self):
        self.assertTrue(Programme(REAL_ROOT).manifest_is_topologically_sorted())

    def test_first_batch_has_no_dependencies(self):
        programme = Programme(REAL_ROOT)
        self.assertEqual(programme.dependencies("B00"), [])

    def test_every_batch_except_the_first_has_a_dependency(self):
        programme = Programme(REAL_ROOT)
        for batch in programme.order[1:]:
            self.assertTrue(programme.dependencies(batch), batch)


class DifferentialAgreement(unittest.TestCase):
    """The two implementations must answer identically on the real repository."""

    def test_crosscheck_reports_no_mismatch(self):
        proc = subprocess.run([sys.executable, "scripts/batch.py", "crosscheck"],
                              cwd=REAL_ROOT, text=True, capture_output=True, timeout=600)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("mismatches=0", proc.stdout)

    def test_status_matches_upstream(self):
        proc = subprocess.run([sys.executable, UPSTREAM, "status", "--repo", "."],
                              cwd=REAL_ROOT, text=True, capture_output=True, timeout=600)
        self.assertEqual(json.loads(proc.stdout), Programme(REAL_ROOT).status())


class CompletionTamperDetection(SyntheticCase):
    def test_untouched_synthetic_evidence_is_valid(self):
        self.assertEqual(self.problems("B00"), [])
        self.assertEqual(self.problems("B01"), [])
        self.assertTrue(self.programme.valid("B01"))

    def test_detects_modified_artifact(self):
        (self.evidence.root / "governance/b00-artifact.json").write_text("{}", encoding="utf-8")
        self.assertTrue(any("hash mismatch" in p for p in self.problems()))

    def test_detects_deleted_artifact(self):
        (self.evidence.root / "governance/b00-artifact.json").unlink()
        self.assertTrue(any("artifact missing" in p for p in self.problems()))

    def test_detects_artifact_path_escaping_the_repository(self):
        self.evidence.patch_completion("B00", lambda d: d["artifacts"].__setitem__(
            0, {"path": "../outside.json", "sha256": "a" * 64}))
        self.assertTrue(any("escapes repository" in p for p in self.problems()))

    def test_detects_dependency_hash_mismatch(self):
        self.evidence.patch_completion("B01", lambda d: d["dependency_hashes"]
                                       .__setitem__("B00", "b" * 64))
        self.assertTrue(any("dependency hash mismatch" in p for p in self.problems("B01")))

    def test_detects_status_not_passed(self):
        self.evidence.patch_completion("B00", lambda d: d.__setitem__("status", "blocked"))
        self.assertIn("completion status must be passed", self.problems())

    def test_detects_same_executor_and_reviewer(self):
        self.evidence.patch_completion("B00", lambda d: d.__setitem__("reviewer", d["executor"]))
        self.assertIn("executor and reviewer must differ", self.problems())

    def test_detects_failed_tests(self):
        self.evidence.patch_completion("B00", lambda d: d["tests"].__setitem__("failed", 1))
        self.assertIn("test summary does not pass", self.problems())

    def test_detects_skipped_critical_tests(self):
        self.evidence.patch_completion("B00",
                                       lambda d: d["tests"].__setitem__("skipped_critical", 1))
        self.assertIn("test summary does not pass", self.problems())

    def test_detects_blocking_security_findings(self):
        self.evidence.patch_completion("B00",
                                       lambda d: d["security"].__setitem__("blocking_findings", 2))
        self.assertIn("blocking security findings remain", self.problems())

    def test_accepted_findings_require_a_recorded_decision(self):
        self.evidence.patch_completion("B00",
                                       lambda d: d["security"].__setitem__("accepted_findings", 1))
        self.assertTrue(any("accepted-findings.json" in p for p in self.problems()))

    def test_detects_reversed_timestamps(self):
        self.evidence.patch_completion("B00", lambda d: d.__setitem__(
            "completed_at", "2026-08-17T00:00:00Z"))
        self.assertIn("completed_at precedes started_at", self.problems())

    def test_detects_invalid_commit_sha(self):
        self.evidence.patch_completion("B00", lambda d: d.__setitem__("commit_sha", "not-a-sha"))
        self.assertTrue(any("commit_sha" in p for p in self.problems()))

    def test_detects_missing_field(self):
        self.evidence.patch_completion("B00", lambda d: d.pop("environment"))
        self.assertTrue(any("missing fields" in p for p in self.problems()))

    def test_detects_empty_traceability_section(self):
        path = self.evidence.root / "evidence/B00/traceability.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["controls"] = []
        path.write_text(json.dumps(data), encoding="utf-8")
        self.assertIn("traceability controls must be a non-empty array", self.problems())

    def test_detects_empty_commands_log(self):
        (self.evidence.root / "evidence/B00/commands.ndjson").write_text("", encoding="utf-8")
        self.assertTrue(any("commands evidence is empty" in p for p in self.problems()))

    def test_detects_command_record_without_exit_code(self):
        (self.evidence.root / "evidence/B00/commands.ndjson").write_text(
            json.dumps({"timestamp": "t", "command": "c"}) + "\n", encoding="utf-8")
        self.assertTrue(any("missing exit_code" in p for p in self.problems()))

    def test_detects_stub_plan(self):
        (self.evidence.root / "evidence/B00/plan.md").write_text("# plan\n", encoding="utf-8")
        self.assertTrue(any("plan evidence missing or too small" in p for p in self.problems()))

    def test_detects_empty_evidence_directory(self):
        (self.evidence.root / "evidence/B00/security/result.log").unlink()
        self.assertTrue(any("has no non-empty file" in p for p in self.problems()))

    def test_invalid_dependency_invalidates_the_dependent(self):
        self.evidence.patch_completion("B00", lambda d: d.__setitem__("status", "failed"))
        self.assertFalse(self.programme.valid("B01"))

    def test_ready_set_reflects_only_valid_evidence(self):
        self.assertIn("B02", self.programme.ready())
        self.evidence.patch_completion("B01", lambda d: d.__setitem__("status", "failed"))
        programme = Programme(self.evidence.root)
        self.assertEqual(programme.ready(), ["B01"])

    def test_release_gate_blocks_while_batches_are_incomplete(self):
        result = self.programme.release_ready()
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["completed"], 2)
        self.assertIn("B127", result["invalid_batches"])
