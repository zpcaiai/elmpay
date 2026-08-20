"""B06 / AT-B06-01 — batch orchestration, completion validation and release gate.

The suite does two things the vendored orchestrator cannot do for itself:

1. *differential testing* — the in-repository implementation is run against the
   vendored one on the real repository and must agree on every answer;
2. *tamper testing* — a synthetic evidence tree is corrupted one field at a
   time, and each corruption must be reported.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.paygov.orchestration import Programme
from tools.paygov.evidence import (command_log_problems, command_spec_sha256,
                                   load_command_records)
from tools.tests.support import REAL_ROOT, FixtureTestCase

UPSTREAM = ".payment-platform/skill-package/scripts/orchestrate.py"


def _script_module(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, REAL_ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        (self.root / "governance" / "project-config.json").write_text(json.dumps({
            "evidence": {"executor": "claude-agent", "reviewer": "Ethan",
                         "environment": "integration"},
        }), encoding="utf-8")
        (self.root / "tools" / "paygov").mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Orchestration Test"],
                       cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"],
                       cwd=self.root, check=True)
        subprocess.run(["git", "add", ".payment-platform", "governance/project-config.json"],
                       cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture baseline"],
                       cwd=self.root, check=True)
        self.head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True,
            capture_output=True, check=True).stdout.strip()
        self.programme = Programme(self.root)
        self.write_batch("B00")
        self.write_batch("B01")

    def write(self, rel: str, data, encoding: str = "utf-8") -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data if isinstance(data, str) else json.dumps(data),
                        encoding=encoding)

    def remove(self, rel: str) -> None:
        (self.root / rel).unlink()

    def write_batch(self, batch: str) -> None:
        base = self.root / "evidence" / batch
        for name in ("test-results", "runtime", "security"):
            (base / name).mkdir(parents=True, exist_ok=True)
            (base / name / "result.log").write_text("ok\n", encoding="utf-8")
        (base / "plan.md").write_text("# plan\n" + ("scope and rollback. " * 40), encoding="utf-8")
        (base / "commands.ndjson").write_text(
            json.dumps({"timestamp": "2026-08-18T00:00:00Z", "command": "true",
                        "exit_code": 0, "expected_exit_code": 0})
            + "\n", encoding="utf-8")
        (base / "commands.spec.json").write_text(json.dumps({
            "batch": batch, "commands": [{"command": "true", "expect": 0}],
        }), encoding="utf-8")
        (base / "test-results" / "summary.json").write_text(
            json.dumps({"run": 10, "passed": 10, "failed": 0, "skipped": 0,
                        "skipped_critical": 0}), encoding="utf-8")
        (base / "traceability.json").write_text(json.dumps({
            "batch_id": batch, "requirements": [{"id": "R1"}], "code": [{"ref": "x"}],
            "tests": [{"ref": "y"}], "controls": [{"id": "NN-01"}],
            "evidence": [{"path": "z"}]}), encoding="utf-8")

        artefact = self.root / "governance" / f"{batch.lower()}-artifact.json"
        artefact.write_text(json.dumps({"batch": batch}), encoding="utf-8")
        artifact_relative = f"governance/{batch.lower()}-artifact.json"
        (base / "artifacts.json").write_text(
            json.dumps([artifact_relative]), encoding="utf-8")

        completion_dir = self.root / "evidence" / "completion"
        completion_dir.mkdir(parents=True, exist_ok=True)
        deps = {}
        for dep in self.programme.dependencies(batch):
            deps[dep] = sha256_bytes((completion_dir / f"{dep}.json").read_bytes())
        payload = {
            "batch_id": batch, "status": "passed", "commit_sha": self.head,
            "environment": "integration",
            "started_at": "2026-08-18T00:00:00Z", "completed_at": "2026-08-18T00:01:00Z",
            "executor": "claude-agent", "reviewer": "Ethan",
            "artifacts": [{"path": artifact_relative,
                           "sha256": sha256_bytes(artefact.read_bytes())}],
            "tests": {"passed": 10, "failed": 0, "skipped_critical": 0},
            "security": {"blocking_findings": 0, "accepted_findings": 0},
            "dependency_hashes": deps,
        }
        (completion_dir / f"{batch}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        review = {
            "schema_version": "1.0.0", "batch_id": batch, "decision": "approved",
            "reviewer": "Ethan", "executor": "claude-agent",
            "reviewed_at": "2026-08-18T08:00:00+08:00",
            "scope": f"{batch} implementation, controls, tests, and evidence",
            "notes": "Independent review found no blocking defect.",
            "bindings": {
                "git_head": payload["commit_sha"],
                "manifest_sha256": sha256_bytes(
                    (self.root / ".payment-platform/skill-package/manifest.json").read_bytes()),
                "commands_spec_sha256": sha256_bytes(
                    (base / "commands.spec.json").read_bytes()),
                "artifacts_json_sha256": sha256_bytes(
                    (base / "artifacts.json").read_bytes()),
                "traceability_sha256": sha256_bytes(
                    (base / "traceability.json").read_bytes()),
                "artifacts": {artifact_relative: sha256_bytes(artefact.read_bytes())},
            },
        }
        (base / "review.json").write_text(
            json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        subprocess.run(["git", "add", f"evidence/{batch}/review.json"],
                       cwd=self.root, check=True)

    def completion(self, batch: str) -> dict:
        return json.loads((self.root / "evidence" / "completion" / f"{batch}.json")
                          .read_text(encoding="utf-8"))

    def patch_completion(self, batch: str, fn) -> None:
        data = self.completion(batch)
        fn(data)
        (self.root / "evidence" / "completion" / f"{batch}.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def patch_review(self, batch: str, fn) -> None:
        path = self.root / "evidence" / batch / "review.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        fn(data)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")

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


# Split into one class per differential rather than one class with two tests:
# the runner parallelises by test class, and both of these shell out to a second
# interpreter that walks the whole evidence tree, so keeping them together made
# this pair the longest pole in the suite and pushed the run back over the
# environment's per-step ceiling.
class DifferentialCrosscheck(unittest.TestCase):
    """Local and vendored orchestrators must agree batch by batch."""

    def test_crosscheck_reports_no_mismatch(self):
        proc = subprocess.run([sys.executable, "scripts/batch.py", "crosscheck"],
                              cwd=REAL_ROOT, text=True, capture_output=True, timeout=600)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("mismatches=0", proc.stdout)


class DifferentialStatus(unittest.TestCase):
    """...and on the programme-level status summary."""

    def test_status_matches_upstream(self):
        proc = subprocess.run([sys.executable, UPSTREAM, "status", "--repo", "."],
                              cwd=REAL_ROOT, text=True, capture_output=True, timeout=600)
        self.assertEqual(json.loads(proc.stdout),
                         Programme(REAL_ROOT).status(extended=False))


class CompletionTamperDetection(SyntheticCase):
    def test_untouched_synthetic_evidence_is_valid(self):
        self.assertEqual(self.problems("B00"), [])
        self.assertEqual(self.problems("B01"), [])
        self.assertTrue(self.programme.valid("B01"))

    def test_detects_modified_artifact(self):
        self.evidence.write("governance/b00-artifact.json", "{}", encoding="utf-8")
        self.assertTrue(any("hash mismatch" in p for p in self.problems()))

    def test_detects_deleted_artifact(self):
        self.evidence.remove("governance/b00-artifact.json")
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
        self.evidence.write("evidence/B00/commands.ndjson", "", encoding="utf-8")
        self.assertTrue(any("commands evidence is empty" in p for p in self.problems()))

    def test_detects_command_record_without_exit_code(self):
        self.evidence.write("evidence/B00/commands.ndjson", json.dumps({"timestamp": "t", "command": "c"}) + "\n", encoding="utf-8")
        self.assertTrue(any("missing exit_code" in p for p in self.problems()))

    def test_detects_stub_plan(self):
        self.evidence.write("evidence/B00/plan.md", "# plan\n", encoding="utf-8")
        self.assertTrue(any("plan evidence missing or too small" in p for p in self.problems()))

    def test_detects_empty_evidence_directory(self):
        self.evidence.remove("evidence/B00/security/result.log")
        self.assertTrue(any("has no non-empty file" in p for p in self.problems()))

    def test_invalid_dependency_invalidates_the_dependent(self):
        self.evidence.patch_completion("B00", lambda d: d.__setitem__("status", "failed"))
        self.assertFalse(self.programme.valid("B01"))

    def test_ready_set_reflects_only_valid_evidence(self):
        self.assertIn("B02", self.programme.ready())
        self.evidence.patch_completion("B01", lambda d: d.__setitem__("status", "failed"))
        programme = Programme(self.evidence.root)
        self.assertEqual(programme.ready(), ["B01"])

    def test_detects_a_command_that_exited_unexpectedly(self):
        path = self.evidence.root / "evidence/B00/commands.ndjson"
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["exit_code"] = 1
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        self.assertTrue(any("but 0 was expected" in p for p in self.problems()))

    def test_detects_a_declared_command_that_never_ran(self):
        base = self.evidence.root / "evidence/B00"
        (base / "commands.spec.json").write_text(json.dumps({"batch": "B00", "commands": [
            {"command": "true", "expect": 0},
            {"command": "python3 scripts/negative-controls.py", "expect": 0}]}),
            encoding="utf-8")
        self.assertTrue(any("never executed" in p for p in self.problems()))

    def test_detects_completion_disagreeing_with_the_runner(self):
        path = self.evidence.root / "evidence/B00/test-results/summary.json"
        path.write_text(json.dumps({"run": 9, "passed": 9, "failed": 0,
                                    "skipped_critical": 0}), encoding="utf-8")
        self.assertTrue(any("but the runner produced" in p for p in self.problems()))

    def test_extended_checks_are_reported_separately_from_the_differential(self):
        path = self.evidence.root / "evidence/B00/commands.ndjson"
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["exit_code"] = 1
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        # Upstream cannot see this, so the like-for-like view must still pass...
        self.assertEqual(self.programme.problems("B00", extended=False), [])
        # ...while the local-only view reports it.
        self.assertTrue(self.programme.extended_only_problems("B00"))

    def test_missing_review_invalidates_only_the_extended_local_view(self):
        self.evidence.remove("evidence/B00/review.json")
        self.assertTrue(any("review attestation is missing" in p for p in self.problems()))
        self.assertTrue(any("review attestation is missing" in p
                            for p in self.programme.extended_only_problems("B00")))
        self.assertEqual(self.programme.problems("B00", extended=False), [])
        self.assertFalse(self.programme.valid("B00"))
        self.assertTrue(self.programme.valid("B00", extended=False))

    def test_stale_review_binding_invalidates_local_status(self):
        self.evidence.patch_review("B00", lambda data: data["bindings"].__setitem__(
            "traceability_sha256", "0" * 64))
        self.assertIn(
            "review binding traceability_sha256 does not match current evidence",
            self.problems())
        self.assertNotIn("B00", self.programme.completed())

    def test_untracked_review_invalidates_local_status(self):
        subprocess.run(["git", "rm", "--cached", "-q", "-f", "--",
                        "evidence/B00/review.json"], cwd=self.evidence.root, check=True)
        self.assertIn("review attestation must be tracked by Git", self.problems())
        self.assertFalse(self.programme.valid("B00"))

    def test_release_gate_blocks_while_batches_are_incomplete(self):
        result = self.programme.release_ready()
        self.assertFalse(result["release_ready"])
        self.assertEqual(result["completed"], 2)
        self.assertIn("B127", result["invalid_batches"])


class CommandRecorderSafety(unittest.TestCase):
    """A failed retry never poisons the durable transcript."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="record-commands-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = self.root / "evidence/B00"
        self.base.mkdir(parents=True)
        self.spec_path = self.base / "commands.spec.json"
        self.log_path = self.base / "commands.ndjson"
        self.allow = self.root / "allow"
        self.module = _script_module("record-commands.py", "record_commands_safety")
        self.module.ROOT = self.root
        command = ("python3 -c \"from pathlib import Path; import sys; "
                   "sys.exit(0 if Path('allow').exists() else 7)\"")
        self.commands = [
            {"command": "python3 -c \"print('first')\"", "expect": 0,
             "save_to": "runtime/first.log"},
            {"command": command, "expect": 0, "save_to": "runtime/retry.log"},
            {"command": "python3 -c \"print('last')\"", "expect": 0,
             "save_to": "runtime/last.log"},
        ]
        self.spec_path.write_text(json.dumps({"batch": "B00", "commands": self.commands}),
                                  encoding="utf-8")

    def _run(self, range_: str, *, append: bool = False) -> int:
        argv = ["B00", "--spec", "evidence/B00/commands.spec.json", "--range", range_]
        if append:
            argv.append("--append")
        return self.module.main(argv)

    def test_failed_replacement_preserves_the_previous_log_atomically(self):
        old = b'{"old":"still authoritative"}\n'
        self.log_path.write_bytes(old)
        self.assertEqual(self._run("0:3"), 1)
        self.assertEqual(self.log_path.read_bytes(), old)

    def test_failed_append_adds_no_poison_record_and_retry_is_clean(self):
        self.assertEqual(self._run("0:1"), 0)
        prefix = self.log_path.read_bytes()
        self.assertEqual(len(load_command_records(self.log_path)), 1)
        self.assertEqual(self._run("1:3", append=True), 1)
        self.assertEqual(self.log_path.read_bytes(), prefix)
        self.allow.write_text("ok", encoding="utf-8")
        self.assertEqual(self._run("1:3", append=True), 0)
        records = load_command_records(self.log_path)
        self.assertEqual([record["spec_index"] for record in records], [0, 1, 2])
        self.assertTrue(all(record["exit_code"] == record["expected_exit_code"]
                            for record in records))

    def test_empty_slice_is_diagnostic_and_does_not_rewrite_state(self):
        self.assertEqual(self._run("0:1"), 0)
        before = self.log_path.read_bytes()
        self.assertEqual(self._run("3:3", append=True), 2)
        self.assertEqual(self.log_path.read_bytes(), before)

    def test_malformed_existing_prefix_blocks_instead_of_auto_healing(self):
        self.log_path.write_text("not json\n", encoding="utf-8")
        self.assertEqual(self._run("1:2", append=True), 2)
        self.assertEqual(self.log_path.read_text(encoding="utf-8"), "not json\n")


class CommandTranscriptSafety(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="command-transcript-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = self.root / "evidence/B06"
        (self.base / "runtime").mkdir(parents=True)
        self.commands = [
            {"command": "first", "expect": 0, "save_to": "runtime/first.log"},
            {"command": "second", "expect": 3, "save_to": "runtime/second.log"},
        ]
        self.spec = self.base / "commands.spec.json"
        self.spec.write_text(json.dumps({"batch": "B06", "commands": self.commands}),
                             encoding="utf-8")
        self.digest = command_spec_sha256(self.spec)
        self.records = []
        for index, entry in enumerate(self.commands):
            output = f"output-{index}".encode()
            (self.base / entry["save_to"]).write_bytes(output)
            digest = hashlib.sha256(output).hexdigest()
            self.records.append({
                "spec_index": index, "spec_sha256": self.digest,
                "command": entry["command"], "exit_code": entry["expect"],
                "expected_exit_code": entry["expect"], "output_sha256": digest,
                "saved_output_sha256": digest, "output_bytes": len(output),
                "saved_to": entry["save_to"],
            })

    def _problems(self, records=None, *, complete=True):
        return command_log_problems(self.root, self.base, self.commands,
                                    self.records if records is None else records,
                                    self.digest, require_complete=complete)

    def test_exact_ordered_successful_transcript_is_accepted(self):
        self.assertEqual(self._problems(), [])

    def test_incomplete_and_empty_transcripts_cannot_finalize(self):
        self.assertTrue(self._problems(self.records[:1]))
        self.assertTrue(self._problems([]))

    def test_same_command_set_in_the_wrong_order_is_rejected(self):
        self.assertTrue(self._problems(list(reversed(self.records))))

    def test_stale_spec_hash_is_rejected(self):
        records = [dict(record) for record in self.records]
        records[0]["spec_sha256"] = "0" * 64
        self.assertTrue(self._problems(records))

    def test_modified_saved_output_is_rejected(self):
        (self.base / "runtime/second.log").write_text("changed", encoding="utf-8")
        self.assertTrue(self._problems())


class FinishBatchPreflightSafety(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="finish-preflight-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = self.root / "evidence/B06"
        (self.base / "test-results").mkdir(parents=True)
        self.module = _script_module("finish-batch.py", "finish_batch_safety")
        self.module.ROOT = self.root
        self.relative = "evidence/B06/test-results/summary.json"
        self.commands = [{
            "command": ("python3 scripts/test-summary.py --out " + self.relative),
            "expect": 0, "save_to": "test-results/summary.log",
        }]
        self.summary = {"run": 8, "passed": 8, "failed": 0, "skipped": 0,
                        "skipped_critical": 0, "shards": 1}
        self.summary_path = self.base / "test-results/summary.json"
        self.summary_path.write_text(json.dumps(self.summary), encoding="utf-8")
        digest = hashlib.sha256(self.summary_path.read_bytes()).hexdigest()
        self.records = [{
            "produced_outputs": [{"path": self.relative, "fresh": True,
                                  "sha256": digest,
                                  "bytes": self.summary_path.stat().st_size}]
        }]

    def test_current_summary_output_proof_is_accepted(self):
        problems, summary = self.module._summary_problems(
            self.base, "B06", self.commands, self.records)
        self.assertEqual(problems, [])
        self.assertEqual(summary, self.summary)

    def test_stale_summary_proof_is_rejected(self):
        self.records[0]["produced_outputs"][0]["fresh"] = False
        problems, _ = self.module._summary_problems(
            self.base, "B06", self.commands, self.records)
        self.assertTrue(problems)

    def test_wrong_shard_count_is_rejected(self):
        self.summary["shards"] = 4
        self.summary_path.write_text(json.dumps(self.summary), encoding="utf-8")
        digest = hashlib.sha256(self.summary_path.read_bytes()).hexdigest()
        proof = self.records[0]["produced_outputs"][0]
        proof.update({"sha256": digest, "bytes": self.summary_path.stat().st_size})
        problems, _ = self.module._summary_problems(
            self.base, "B06", self.commands, self.records)
        self.assertIn("test summary must declare shards=1", problems)

    def test_non_record_only_cli_requires_review_attestation(self):
        (self.base / "artifacts.json").write_text(json.dumps(["artifact.txt"]),
                                                  encoding="utf-8")
        (self.base / "commands.spec.json").write_text(
            json.dumps({"batch": "B06", "commands": self.commands}), encoding="utf-8")
        self.assertEqual(self.module.main(["B06", "--range", "0:0", "--append"]), 3)


class FinishValidationRollbackSafety(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="finish-rollback-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.module = _script_module("finish-batch.py", "finish_validation_rollback")
        self.module.ROOT = self.root
        self.completion = self.root / "evidence/completion/B06.json"
        self.completion.parent.mkdir(parents=True)

    @staticmethod
    def _failed_validation():
        return subprocess.CompletedProcess([], 1, "invalid completion\n", "")

    def test_failed_final_validation_restores_prior_marker(self):
        from unittest import mock

        previous = b'{"previous":true}\n'
        self.completion.write_bytes(b'{"new":true}\n')
        with mock.patch.object(self.module, "run", return_value=self._failed_validation()):
            self.assertEqual(self.module._final_validate("B06", self.completion, previous), 2)
        self.assertEqual(self.completion.read_bytes(), previous)

    def test_failed_final_validation_leaves_no_new_marker(self):
        from unittest import mock

        self.completion.write_bytes(b'{"new":true}\n')
        with mock.patch.object(self.module, "run", return_value=self._failed_validation()):
            self.assertEqual(self.module._final_validate("B06", self.completion, None), 2)
        self.assertFalse(self.completion.exists())

    def test_successful_final_validation_keeps_new_marker(self):
        from unittest import mock

        current = b'{"new":true}\n'
        self.completion.write_bytes(current)
        success = subprocess.CompletedProcess([], 0, "valid\n", "")
        with mock.patch.object(self.module, "run", return_value=success):
            self.assertEqual(self.module._final_validate(
                "B06", self.completion, b'{"previous":true}\n'), 0)
        self.assertEqual(self.completion.read_bytes(), current)


class FinishBatchReviewSafety(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="finish-review-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.module = _script_module("finish-batch.py", "finish_batch_review_safety")
        self.module.ROOT = self.root
        self.base = self.root / "evidence/B06"
        self.base.mkdir(parents=True)
        manifest = self.root / ".payment-platform/skill-package/manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"batches": [
            {"id": "B00", "depends_on": []},
            {"id": "B06", "depends_on": ["B00"]},
        ]}), encoding="utf-8")
        config = self.root / "governance/project-config.json"
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps({"evidence": {
            "executor": "claude-agent", "reviewer": "Ethan",
            "environment": "integration"}}), encoding="utf-8")
        self.spec = self.base / "commands.spec.json"
        self.spec.write_text(json.dumps({"batch": "B06", "commands": [{
            "command": "true", "expect": 0, "save_to": "runtime/true.log"}]}),
                             encoding="utf-8")
        self.artifact = self.root / "artifact.txt"
        self.artifact.write_text("reviewed bytes\n", encoding="utf-8")
        self.artifacts = self.base / "artifacts.json"
        self.artifacts.write_text(json.dumps(["artifact.txt"]), encoding="utf-8")
        self.traceability = self.base / "traceability.json"
        self.traceability.write_text(json.dumps({
            "batch_id": "B06", "requirements": [{"id": "R1"}],
            "code": [{"ref": "artifact.txt"}], "tests": [{"ref": "artifact.txt"}],
            "controls": [{"id": "NN-12"}],
            "evidence": [{"path": "evidence/B06/review.json"}],
        }), encoding="utf-8")
        dependency = self.root / "evidence/completion/B00.json"
        dependency.parent.mkdir(parents=True)
        dependency.write_text('{"batch_id":"B00","status":"passed"}\n', encoding="utf-8")
        self.dependency = dependency
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Evidence Test"],
                       cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "evidence@example.invalid"],
                       cwd=self.root, check=True)
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "review inputs"], cwd=self.root, check=True)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.root,
                              text=True, capture_output=True, check=True).stdout.strip()
        self.review = self.base / "review.json"
        self.payload = {
            "schema_version": "1.0.0", "batch_id": "B06", "decision": "approved",
            "reviewer": "Ethan", "executor": "claude-agent",
            "reviewed_at": "2026-08-20T12:00:00+08:00",
            "scope": "B06 implementation, tests, controls, and evidence",
            "notes": "Independent review found no blocking defect.",
            "bindings": {
                "git_head": head,
                "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "commands_spec_sha256": hashlib.sha256(self.spec.read_bytes()).hexdigest(),
                "artifacts_json_sha256": hashlib.sha256(
                    self.artifacts.read_bytes()).hexdigest(),
                "traceability_sha256": hashlib.sha256(
                    self.traceability.read_bytes()).hexdigest(),
                "artifacts": {"artifact.txt": hashlib.sha256(
                    self.artifact.read_bytes()).hexdigest()},
            },
        }
        self._write_review()
        subprocess.run(["git", "add", "evidence/B06/review.json"],
                       cwd=self.root, check=True)

    def _write_review(self) -> None:
        self.review.write_text(json.dumps(self.payload), encoding="utf-8")

    def _problems(self) -> list[str]:
        return self.module._review_problems(
            self.review, "B06", self.spec, self.artifacts)

    def test_exact_tracked_review_binding_is_accepted(self):
        self.assertEqual(self._problems(), [])

    def test_review_notes_must_be_non_empty(self):
        self.payload["notes"] = "  "
        self._write_review()
        self.assertIn("review notes must be a non-empty string", self._problems())

    def test_review_timestamp_must_have_a_timezone(self):
        self.payload["reviewed_at"] = "2026-08-20T12:00:00"
        self._write_review()
        self.assertIn("reviewed_at must be an ISO-8601 timestamp with timezone",
                      self._problems())

    def test_changed_artifact_invalidates_the_review(self):
        self.artifact.write_text("changed after review\n", encoding="utf-8")
        self.assertIn("review artifact hash set does not exactly match artifacts.json",
                      self._problems())

    def test_changed_final_trace_invalidates_the_review(self):
        self.traceability.write_text('{"changed":true}\n', encoding="utf-8")
        self.assertIn(
            "review binding traceability_sha256 does not match current repository state",
            self._problems())


class MakeCompletionBoundarySafety(FinishBatchReviewSafety):
    """Completion installation rechecks the exact reviewed bytes and rolls back."""

    def setUp(self) -> None:
        super().setUp()
        self.make = _script_module("make-completion.py", "make_completion_safety")
        self.make.ROOT = self.root
        self.completion = self.root / "evidence/completion/B06.json"

    def _args(self) -> list[str]:
        return [
            "B06", "--artifacts", "evidence/B06/artifacts.json",
            "--review-attestation", "evidence/B06/review.json",
            "--started-at", "2026-08-20T00:00:00Z",
            "--completed-at", "2026-08-20T00:01:00Z",
            "--tests-passed", "12",
        ]

    def test_completion_payload_exactly_matches_reviewed_head_and_artifacts(self):
        self.assertEqual(self.make.main(self._args()), 0)
        payload = json.loads(self.completion.read_text(encoding="utf-8"))
        binding = self.payload["bindings"]
        self.assertEqual(payload["commit_sha"], binding["git_head"])
        self.assertEqual({item["path"]: item["sha256"] for item in payload["artifacts"]},
                         binding["artifacts"])

    def test_preexisting_binding_mismatch_creates_no_completion(self):
        self.artifact.write_text("changed before completion\n", encoding="utf-8")
        self.assertEqual(self.make.main(self._args()), 2)
        self.assertFalse(self.completion.exists())

    def test_boundary_race_restores_the_previous_completion(self):
        from unittest import mock

        previous = b'{"previous":true}\n'
        self.completion.parent.mkdir(parents=True, exist_ok=True)
        self.completion.write_bytes(previous)
        actual_snapshot = self.make._binding_snapshot
        calls = 0

        def racing_snapshot(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.artifact.write_text("changed at boundary\n", encoding="utf-8")
            return actual_snapshot(*args)

        with mock.patch.object(self.make, "_binding_snapshot", side_effect=racing_snapshot):
            self.assertEqual(self.make.main(self._args()), 2)
        self.assertEqual(self.completion.read_bytes(), previous)

    def test_boundary_race_leaves_no_new_completion_when_none_existed(self):
        from unittest import mock

        actual_snapshot = self.make._binding_snapshot
        calls = 0

        def racing_snapshot(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.artifact.write_text("changed at boundary\n", encoding="utf-8")
            return actual_snapshot(*args)

        with mock.patch.object(self.make, "_binding_snapshot", side_effect=racing_snapshot):
            self.assertEqual(self.make.main(self._args()), 2)
        self.assertFalse(self.completion.exists())

    def test_failed_atomic_replace_preserves_previous_bytes_and_cleans_temp(self):
        from unittest import mock

        previous = b'{"previous":true}\n'
        self.completion.parent.mkdir(parents=True, exist_ok=True)
        self.completion.write_bytes(previous)
        with mock.patch.object(self.make.os, "replace", side_effect=OSError("injected")):
            with self.assertRaisesRegex(OSError, "injected"):
                self.make._atomic_write(self.completion, b'{"new":true}\n')
        self.assertEqual(self.completion.read_bytes(), previous)
        self.assertEqual(list(self.completion.parent.glob(".B06.json.*.tmp")), [])

    def test_direct_writer_rejects_blank_review_notes(self):
        self.payload["notes"] = " "
        self._write_review()
        self.assertEqual(self.make.main(self._args()), 2)
        self.assertFalse(self.completion.exists())

    def test_direct_writer_rejects_naive_review_timestamp(self):
        self.payload["reviewed_at"] = "2026-08-20T12:00:00"
        self._write_review()
        self.assertEqual(self.make.main(self._args()), 2)
        self.assertFalse(self.completion.exists())

    def test_direct_writer_rejects_extra_review_schema_key(self):
        self.payload["unreviewed_extension"] = True
        self._write_review()
        self.assertEqual(self.make.main(self._args()), 2)
        self.assertFalse(self.completion.exists())

    def test_dependency_race_restores_previous_completion(self):
        from unittest import mock

        previous = b'{"previous":true}\n'
        self.completion.parent.mkdir(parents=True, exist_ok=True)
        self.completion.write_bytes(previous)
        actual_dependencies = self.make._dependency_hashes
        calls = 0

        def racing_dependencies(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.dependency.write_text('{"changed":true}\n', encoding="utf-8")
            return actual_dependencies(*args)

        with mock.patch.object(self.make, "_dependency_hashes",
                               side_effect=racing_dependencies):
            self.assertEqual(self.make.main(self._args()), 2)
        self.assertEqual(self.completion.read_bytes(), previous)

    def test_review_edit_race_restores_previous_completion(self):
        from unittest import mock

        previous = b'{"previous":true}\n'
        self.completion.parent.mkdir(parents=True, exist_ok=True)
        self.completion.write_bytes(previous)
        actual_snapshot = self.make._binding_snapshot
        calls = 0

        def racing_snapshot(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.payload["notes"] = "Approval revoked and replaced during install."
                self._write_review()
            return actual_snapshot(*args)

        with mock.patch.object(self.make, "_binding_snapshot", side_effect=racing_snapshot):
            self.assertEqual(self.make.main(self._args()), 2)
        self.assertEqual(self.completion.read_bytes(), previous)
