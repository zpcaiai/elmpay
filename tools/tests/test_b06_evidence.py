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


class EvidenceRejects(FixtureTestCase):
    """Mutations run against a copy of the real evidence tree."""

    def setUp(self) -> None:
        super().setUp()
        import shutil
        for rel in ("evidence", "governance/evidence-policy.json",
                    ".payment-platform/skill-package/manifest.json"):
            source = REAL_ROOT / rel
            target = self.fixture.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target, dirs_exist_ok=True)
            else:
                shutil.copyfile(source, target)
        # Artefact paths are repository-relative; mirror the files they name.
        for path in sorted((self.fixture.root / "evidence" / "completion").glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            for artifact in data["artifacts"]:
                dest = self.fixture.root / artifact["path"]
                dest.parent.mkdir(parents=True, exist_ok=True)
                if not dest.exists():
                    dest.write_bytes((REAL_ROOT / artifact["path"]).read_bytes())

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
        (self.fixture.root / "evidence/B01/artifacts.json").unlink()
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

    def test_rejects_artifact_list_out_of_sync_with_completion(self):
        path = self.fixture.root / "evidence/B00/artifacts.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data.append("docs/EVIDENCE.md")
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
