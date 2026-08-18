"""B05 / AT-B05-01 — CI pipeline and quality baseline."""
from __future__ import annotations

from tools.paygov import ci, cigen
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class PipelineHappyPath(FixtureTestCase):
    def test_real_pipeline_passes(self):
        problems = ci.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_b05_validator_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("ci-pipeline", registry.names())

    def test_all_required_stage_families_are_present(self):
        doc = self.fixture.read("governance/ci-pipeline.json")
        ids = {s["id"] for s in doc["stages"]}
        for family in ("build", "static-analysis", "unit-test", "dependency-scan", "secret-scan",
                       "container-scan", "iac-scan", "sbom", "sign", "evidence-archive"):
            self.assertIn(family, ids, family)

    def test_every_required_stage_is_fail_closed(self):
        doc = self.fixture.read("governance/ci-pipeline.json")
        by_id = {s["id"]: s for s in doc["stages"]}
        for name in doc["required_stages"]:
            self.assertTrue(by_id[name]["required"], name)
            self.assertTrue(by_id[name]["fail_closed"], name)

    def test_every_action_is_pinned_to_a_commit_sha(self):
        doc = self.fixture.read("governance/ci-pipeline.json")
        for action in doc["actions"]:
            self.assertRegex(action["ref"], r"^[0-9a-f]{40}$", action["name"])

    def test_batch_mandated_blocking_conditions_exist(self):
        doc = self.fixture.read("governance/ci-pipeline.json")
        ids = {c["id"] for c in doc["blocking_conditions"]}
        for required in ("BLOCK-01", "BLOCK-02", "BLOCK-03", "BLOCK-04"):
            self.assertIn(required, ids)

    def test_workflow_has_a_terminal_release_gate(self):
        text = cigen.workflow(REAL_ROOT)
        self.assertIn("release-gate:", text)
        self.assertIn("release gate blocked", text)

    def test_workflow_does_not_use_dangerous_triggers(self):
        text = cigen.workflow(REAL_ROOT)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("continue-on-error: true", text)

    def test_workflow_uses_the_pinned_java_version(self):
        text = cigen.workflow(REAL_ROOT)
        catalog = self.fixture.read("governance/version-catalog.json")
        jdk = next(e for e in catalog["entries"] if e["id"] == "jdk")["version"].split("+")[0]
        self.assertIn(f"java-version: '{jdk}'", text)

    def test_generation_is_deterministic(self):
        self.assertEqual(cigen.render_all(REAL_ROOT), cigen.render_all(REAL_ROOT))

    def test_sign_script_refuses_to_emit_unsigned_artifacts(self):
        text = cigen.sign_script(REAL_ROOT)
        self.assertIn("refusing to emit an unsigned artefact", text)
        self.assertIn("set -euo pipefail", text)


class PipelineRejects(FixtureTestCase):
    REL = "governance/ci-pipeline.json"

    def _validate(self):
        return ci.validate(self.fixture.root, Budget(seconds=60).start())

    def _stage(self, data, sid):
        return next(s for s in data["stages"] if s["id"] == sid)

    def test_rejects_fail_open_required_stage(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._stage(d, "secret-scan").__setitem__("fail_closed", False))
        self.assertIn("CI_FAIL_OPEN", self.codes(self._validate()))

    def test_rejects_tag_pinned_action(self):
        self.fixture.mutate(self.REL, lambda d: d["actions"][0].__setitem__("ref", "v5"))
        problems = self._validate()
        self.assertIn("CI_ACTION_PIN", self.codes(problems))

    def test_rejects_missing_required_stage(self):
        self.fixture.mutate(self.REL, lambda d: d["required_stages"].append("mutation-test"))
        self.assertIn("CI_REQUIRED_STAGE", self.codes(self._validate()))

    def test_rejects_unknown_stage_dependency(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._stage(d, "build")["needs"].append("ghost"))
        self.assertIn("CI_NEEDS", self.codes(self._validate()))

    def test_rejects_stage_cycle(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._stage(d, "governance")["needs"].append("build"))
        self.assertIn("CI_CYCLE", self.codes(self._validate()))

    def test_rejects_nonzero_security_finding_budget(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["quality_gates"]
                            .__setitem__("blocking_security_findings_max", 1))
        self.assertIn("CI_QUALITY_GATE", self.codes(self._validate()))

    def test_rejects_tolerating_skipped_critical_tests(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["quality_gates"].__setitem__("skipped_critical_max", 2))
        self.assertIn("CI_QUALITY_GATE", self.codes(self._validate()))

    def test_rejects_write_access_to_contents(self):
        self.fixture.mutate(self.REL, lambda d: d["permissions"].__setitem__("contents", "write"))
        problems = self._validate()
        self.assertIn("CI_PERMISSIONS", self.codes(problems))
        self.assertIn("NN-11", self.rules(problems))

    def test_rejects_write_all_permission(self):
        self.fixture.mutate(self.REL, lambda d: d["permissions"].__setitem__("packages", "write-all"))
        self.assertIn("CI_PERMISSIONS", self.codes(self._validate()))

    def test_rejects_removed_blocking_condition(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["blocking_conditions"].__setitem__(
                                slice(None),
                                [c for c in d["blocking_conditions"] if c["id"] != "BLOCK-02"]))
        self.assertIn("CI_BLOCKING_MISSING", self.codes(self._validate()))

    def test_rejects_blocking_condition_without_detector(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["blocking_conditions"][0].__setitem__("detected_by", []))
        self.assertIn("CI_BLOCKING", self.codes(self._validate()))

    def test_rejects_blocking_condition_with_unknown_detector(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["blocking_conditions"][0]["detected_by"].append("ghost"))
        self.assertIn("CI_BLOCKING", self.codes(self._validate()))

    def test_rejects_stage_without_commands(self):
        self.fixture.mutate(self.REL, lambda d: self._stage(d, "sbom").__setitem__("commands", []))
        self.assertIn("CI_STAGE", self.codes(self._validate()))

    def test_rejects_unbounded_stage_timeout(self):
        self.fixture.mutate(self.REL,
                            lambda d: self._stage(d, "build").__setitem__("timeout_minutes", 0))
        self.assertIn("CI_STAGE", self.codes(self._validate()))

    def test_rejects_hand_edited_workflow(self):
        path = self.fixture.root / ".github/workflows/ci.yml"
        path.write_text(path.read_text(encoding="utf-8")
                        .replace("contents: read", "contents: write"), encoding="utf-8")
        self.assertIn("CI_DRIFT", self.codes(self._validate()))

    def test_rejects_missing_workflow(self):
        (self.fixture.root / ".github/workflows/ci.yml").unlink()
        self.assertIn("CI_MISSING", self.codes(self._validate()))
