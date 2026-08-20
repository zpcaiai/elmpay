"""B06 / AT-B06-01 — the evidence framework gate."""
from __future__ import annotations

import json

from tools.paygov import evidence
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class EvidenceHappyPath(FixtureTestCase):
    def test_real_evidence_tree_passes(self):
        problems = evidence.validate(REAL_ROOT, Budget(seconds=180).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_b06_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("evidence", registry.names())

    def test_every_completed_batch_declares_the_required_command_classes(self):
        policy = json.loads((REAL_ROOT / "governance/evidence-policy.json")
                            .read_text(encoding="utf-8"))
        for path in sorted((REAL_ROOT / "evidence" / "completion").glob("*.json")):
            spec = REAL_ROOT / "evidence" / path.stem / "commands.spec.json"
            joined = "\n".join(c["command"] for c in
                               json.loads(spec.read_text(encoding="utf-8"))["commands"])
            for required in policy["required_command_classes"]:
                self.assertIn(required["match"], joined, f"{path.stem}: {required['id']}")

    def test_every_completion_uses_distinct_principals(self):
        for path in sorted((REAL_ROOT / "evidence" / "completion").glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotEqual(data["executor"], data["reviewer"], path.name)


def _evidence_snapshot() -> dict[str, bytes]:
    """Read the evidence tree once.

    Each test needs its own mutable copy, but re-reading several hundred files
    from the mount per test made the suite unusable.
    """
    blobs: dict[str, bytes] = {}
    for rel in ("governance/evidence-policy.json", ".payment-platform/skill-package/manifest.json"):
        blobs[rel] = (REAL_ROOT / rel).read_bytes()
    for path in sorted((REAL_ROOT / "evidence").rglob("*")):
        if path.is_file():
            blobs[path.relative_to(REAL_ROOT).as_posix()] = path.read_bytes()
    for completion in sorted((REAL_ROOT / "evidence" / "completion").glob("*.json")):
        data = json.loads(completion.read_text(encoding="utf-8"))
        referenced = [a["path"] for a in data["artifacts"]]
        declared = REAL_ROOT / "evidence" / completion.stem / "artifacts.json"
        if declared.is_file():
            referenced += json.loads(declared.read_text(encoding="utf-8"))
        trace = REAL_ROOT / "evidence" / completion.stem / "traceability.json"
        if trace.is_file():
            doc = json.loads(trace.read_text(encoding="utf-8"))
            referenced += [e["ref"] for e in doc.get("code", []) if "ref" in e]
            referenced += [e["ref"] for e in doc.get("tests", []) if "ref" in e]
            referenced += [e["path"] for e in doc.get("evidence", []) if "path" in e]
        for rel in referenced:
            source = REAL_ROOT / rel
            if source.is_file() and rel not in blobs:
                blobs[rel] = source.read_bytes()
    return blobs


_EVIDENCE_SNAPSHOT = _evidence_snapshot()


class EvidenceRejects(FixtureTestCase):
    """Mutations run against a copy of the real evidence tree."""

    def setUp(self) -> None:
        super().setUp()
        for rel, blob in _EVIDENCE_SNAPSHOT.items():
            dest = self.fixture.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(blob)

    def _validate(self):
        return evidence.validate(self.fixture.root, Budget(seconds=180).start())

    def test_baseline_copy_passes(self):
        self.assertEqual(self._validate(), [])

    def test_rejects_dangling_traceability_reference(self):
        path = self.fixture.root / "evidence/B00/traceability.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["code"].append({"ref": "libs/money/DoesNotExist.java", "requirements": ["B00-R1"]})
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        self.assertIn("EVIDENCE_TRACE_DANGLING", self.codes(self._validate()))

    def test_rejects_missing_required_evidence_file(self):
        self.fixture.remove("evidence/B01/artifacts.json")
        self.assertIn("EVIDENCE_FILE", self.codes(self._validate()))

    def test_rejects_missing_evidence_directory(self):
        import shutil
        shutil.rmtree(self.fixture.root / "evidence/B02/security")
        self.assertIn("EVIDENCE_DIR", self.codes(self._validate()))

    def test_rejects_plan_without_rollback_section(self):
        path = self.fixture.root / "evidence/B03/plan.md"
        path.write_text(path.read_text(encoding="utf-8").replace("## 7. 回滚", "## 7. 备注"),
                        encoding="utf-8")
        self.assertIn("EVIDENCE_PLAN_SECTION", self.codes(self._validate()))

    def test_rejects_spec_without_negative_controls(self):
        path = self.fixture.root / "evidence/B04/commands.spec.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["commands"] = [c for c in data["commands"]
                            if "negative-controls" not in c["command"]]
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        self.assertIn("EVIDENCE_COMMAND_CLASS", self.codes(self._validate()))

    def test_rejects_spec_without_timeout_proof(self):
        path = self.fixture.root / "evidence/B05/commands.spec.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["commands"] = [c for c in data["commands"]
                            if "--budget-seconds 0" not in c["command"]]
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        self.assertIn("EVIDENCE_COMMAND_CLASS", self.codes(self._validate()))

    def _respec(self, batch: str, shards: list[str]) -> None:
        path = self.fixture.root / f"evidence/{batch}/commands.spec.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["commands"] = [c for c in data["commands"] if "--shard" not in c["command"]] + [
            {"purpose": "runtime fail-closed proof", "expect": 0,
             "command": f"python3 scripts/negative-controls.py --shard {label}",
             "save_to": f"runtime/nc-{label.replace('/', '-')}.log"} for label in shards]
        self.fixture.write(f"evidence/{batch}/commands.spec.json",
                           json.dumps(data, ensure_ascii=False, indent=2))

    def test_accepts_a_complete_shard_set(self):
        # The rule must not fire on the legitimate case, otherwise the next two
        # tests would pass no matter what the validator does.
        self._respec("B04", ["1/3", "2/3", "3/3"])
        codes = self.codes(self._validate())
        self.assertNotIn("EVIDENCE_SHARD_INCOMPLETE", codes)
        self.assertNotIn("EVIDENCE_SHARD_MIXED", codes)

    def test_rejects_a_shard_set_with_a_hole(self):
        self._respec("B04", ["1/3", "3/3"])
        self.assertIn("EVIDENCE_SHARD_INCOMPLETE", self.codes(self._validate()))

    def test_rejects_shards_from_different_partitions(self):
        self._respec("B04", ["1/2", "2/3"])
        self.assertIn("EVIDENCE_SHARD_MIXED", self.codes(self._validate()))

    def test_rejects_a_declared_artefact_that_does_not_exist(self):
        # Named for what it checks. The earlier name said "out of sync with
        # completion", which is compared in Programme.problems(), not here —
        # and it only passed because the file it used happened to be missing
        # from the fixture.
        path = self.fixture.root / "evidence/B00/artifacts.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data.append("docs/this-artefact-was-never-produced.md")
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        self.assertIn("EVIDENCE_ARTIFACT", self.codes(self._validate()))

    def test_rejects_wrong_reviewer(self):
        path = self.fixture.root / "evidence/completion/B00.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["reviewer"] = "someone-else"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        problems = self._validate()
        self.assertIn("EVIDENCE_PRINCIPAL", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_completion_for_a_batch_outside_the_manifest(self):
        path = self.fixture.root / "evidence/completion/B999.json"
        path.write_text(json.dumps({"batch_id": "B999"}), encoding="utf-8")
        self.assertIn("EVIDENCE_UNKNOWN_BATCH", self.codes(self._validate()))


class ShardFamilyRejects(FixtureTestCase):
    """Command families are independent exact partitions, not pooled regex hits."""

    SCOPE = "evidence/B06"

    @staticmethod
    def _entry(command: str) -> dict:
        return {"command": command, "expect": 0, "save_to": "runtime/result.log"}

    def _codes(self, commands: list[dict]) -> set[str]:
        return self.codes(evidence._shards(commands, self.SCOPE))

    def _families(self, negative_total: int, summary_total: int) -> list[dict]:
        commands = [self._entry(
            f"python3 scripts/negative-controls.py --shard {index}/{negative_total}")
            for index in range(1, negative_total + 1)]
        outputs = [f"evidence/B06/test-results/part-{index}.json"
                   for index in range(1, summary_total + 1)]
        commands += [self._entry(
            f"python3 scripts/test-summary.py --shard {index}/{summary_total} "
            f"--out {outputs[index - 1]}")
            for index in range(1, summary_total + 1)]
        commands.append(self._entry(
            "python3 scripts/test-summary.py --merge " + " ".join(outputs)
            + " --out evidence/B06/test-results/summary.json"))
        return commands

    def test_accepts_different_complete_denominators_for_independent_families(self):
        self.assertEqual(self._codes(self._families(2, 3)), set())

    def test_rejects_duplicate_indices_with_no_hole(self):
        commands = self._families(2, 2)
        commands.insert(1, self._entry(
            "python3 scripts/negative-controls.py --shard 1/2"))
        self.assertIn("EVIDENCE_SHARD_DUPLICATE", self._codes(commands))

    def test_rejects_an_out_of_range_index(self):
        commands = self._families(2, 2)
        commands[1] = self._entry("python3 scripts/negative-controls.py --shard 3/2")
        self.assertIn("EVIDENCE_SHARD_RANGE", self._codes(commands))

    def test_rejects_a_malformed_shard_value(self):
        commands = self._families(2, 2)
        commands[1] = self._entry(
            "python3 scripts/negative-controls.py --shard not-a-partition")
        self.assertIn("EVIDENCE_SHARD_MALFORMED", self._codes(commands))

    def test_rejects_mixed_unsharded_and_sharded_mode(self):
        commands = self._families(2, 2)
        commands.insert(0, self._entry("python3 scripts/negative-controls.py"))
        self.assertIn("EVIDENCE_SHARD_MODE", self._codes(commands))

    def test_rejects_merge_before_the_test_runs(self):
        commands = self._families(2, 2)
        merge = commands.pop()
        commands.insert(2, merge)
        self.assertIn("EVIDENCE_SHARD_MERGE", self._codes(commands))

    def test_rejects_merge_with_an_extra_or_reordered_input(self):
        commands = self._families(2, 2)
        commands[-1] = self._entry(
            "python3 scripts/test-summary.py --merge "
            "evidence/B06/test-results/part-2.json "
            "evidence/B06/test-results/part-1.json "
            "--out evidence/B06/test-results/summary.json")
        self.assertIn("EVIDENCE_SHARD_MERGE", self._codes(commands))

    def test_rejects_sharded_test_run_without_one_exact_merge(self):
        commands = self._families(2, 2)[:-1]
        self.assertIn("EVIDENCE_SHARD_MERGE", self._codes(commands))
