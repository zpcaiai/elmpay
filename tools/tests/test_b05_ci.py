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
                       "container-scan", "iac-scan", "sbom", "python-floor", "sign",
                       "evidence-archive"):
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

    def test_release_gate_uses_event_aware_environment_inputs(self):
        text = cigen.workflow(REAL_ROOT)
        self.assertIn("ELMPAY_GATE_EVENT_NAME: ${{ github.event_name }}", text)
        self.assertIn(
            "ELMPAY_NEEDS_DEPENDENCY_SCAN: ${{ needs['dependency-scan'].result }}",
            text,
        )
        self.assertIn("validated-not-release-eligible", text)
        self.assertIn("release-eligible", text)
        script = cigen.release_gate_script(REAL_ROOT)
        self.assertNotIn("${{", script)
        self.assertNotIn("contains(needs.*.result", script)

    def test_workflow_does_not_use_dangerous_triggers(self):
        text = cigen.workflow(REAL_ROOT)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("continue-on-error: true", text)

    def test_workflow_uses_the_pinned_java_version(self):
        text = cigen.workflow(REAL_ROOT)
        catalog = self.fixture.read("governance/version-catalog.json")
        jdk = next(e for e in catalog["entries"] if e["id"] == "jdk")["version"].split("+")[0]
        self.assertIn(f"java-version: '{jdk}'", text)

    def test_workflow_runs_exact_reference_and_floor_pythons(self):
        text = cigen.workflow(REAL_ROOT)
        catalog = self.fixture.read("governance/version-catalog.json")
        python = next(e for e in catalog["entries"] if e["id"] == "python-toolchain")
        pipeline = self.fixture.read("governance/ci-pipeline.json")
        action = next(a for a in pipeline["actions"]
                      if a["name"] == "actions/setup-python")
        self.assertEqual(python["version"], "3.12.7")
        self.assertEqual(python["minimum_supported"], "3.10.12")
        self.assertEqual(action["ref"], "5fda3b95a4ea91299a34e894583c3862153e4b97")
        self.assertEqual(text.count(f"uses: actions/setup-python@{action['ref']}"),
                         len(pipeline["stages"]))
        floor_job = text.split("\n  python-floor:\n", 1)[1].split("\n  unit-test:\n", 1)[0]
        self.assertIn("python-version: '3.10.12'", floor_job)
        self.assertEqual(text.count("python-version: '3.10.12'"), 1)
        self.assertEqual(text.count("python-version: '3.12.7'"),
                         len(pipeline["stages"]) - 1)

    def test_tool_versions_pins_the_reference_python(self):
        text = (REAL_ROOT / ".tool-versions").read_text(encoding="utf-8")
        self.assertIn("python 3.12.7\n", text)
        self.assertNotIn("python 3.10.12", text)

    def test_signing_waits_for_the_floor_interpreter_gate(self):
        doc = self.fixture.read("governance/ci-pipeline.json")
        sign = next(stage for stage in doc["stages"] if stage["id"] == "sign")
        self.assertIn("python-floor", sign["needs"])

    def test_failed_dependency_scan_cannot_publish_its_cache(self):
        text = cigen.workflow(REAL_ROOT)
        expression = (
            "cache-read-only: ${{ github.event_name != 'push' || "
            "github.repository != 'zpcaiai/elmpay' || "
            "github.ref != 'refs/heads/main' }}"
        )
        save_condition = (
            "if: success() && github.event_name == 'push' && "
            "github.repository == 'zpcaiai/elmpay' && "
            "github.ref == 'refs/heads/main'"
        )
        self.assertEqual(text.count(expression), 1)
        build_job = text.split("\n  build:\n", 1)[1].split("\n  static-analysis:\n", 1)[0]
        dependency_job = text.split("\n  dependency-scan:\n", 1)[1].split(
            "\n  container-scan:\n", 1)[0]
        self.assertIn(expression, build_job)
        self.assertNotIn(expression, dependency_job)
        self.assertIn("cache-read-only: true", dependency_job)
        self.assertNotIn("dependency-check-data/11.0", build_job)
        self.assertEqual(dependency_job.count("~/.gradle/dependency-check-data/11.0"), 2)
        self.assertIn("uses: actions/cache/restore@", dependency_job)
        self.assertIn("uses: actions/cache/save@", dependency_job)
        self.assertIn(save_condition, dependency_job)
        self.assertLess(dependency_job.index("uses: actions/cache/restore@"),
                        dependency_job.index("tools.paygov.nvdfeed"))
        self.assertLess(dependency_job.index("dependencyCheckAggregate"),
                        dependency_job.index("uses: actions/cache/save@"))
        self.assertIn("cache-read-only: true", text)

    def test_generation_is_deterministic(self):
        self.assertEqual(cigen.render_all(REAL_ROOT), cigen.render_all(REAL_ROOT))

    def test_generated_step_name_keeps_the_shard_suffix_inside_yaml_quotes(self):
        text = cigen.workflow(REAL_ROOT)
        governance = self.fixture.read("governance/ci-pipeline.json")["stages"][0]
        expected = f"      - name: '{governance['purpose']} (1/{len(governance['commands'])})'"
        self.assertIn(expected, text)
        self.assertNotIn(f"      - name: '{governance['purpose']}' (1/", text)

    def test_governance_verifies_the_skill_package_and_installed_mirrors(self):
        doc = self.fixture.read("governance/ci-pipeline.json")
        commands = set(next(s for s in doc["stages"] if s["id"] == "governance")["commands"])
        self.assertTrue(ci.REQUIRED_SKILL_COMMANDS <= commands)

    def test_sign_script_refuses_to_emit_unsigned_artifacts(self):
        text = cigen.sign_script(REAL_ROOT)
        self.assertIn("refusing to emit an unsigned artefact", text)
        self.assertIn("set -euo pipefail", text)

    def test_dependency_and_sbom_stages_invoke_registered_gradle_tasks(self):
        doc = self.fixture.read("governance/ci-pipeline.json")
        by_id = {stage["id"]: stage for stage in doc["stages"]}
        self.assertEqual(
            by_id["dependency-scan"]["commands"],
            [
                "python3 -m tools.paygov.nvdfeed --repo .",
                "./gradlew --no-daemon dependencyCheckAggregate",
            ],
        )
        self.assertEqual(
            by_id["sbom"]["commands"],
            ["./gradlew --no-daemon cyclonedxBom"],
        )

    def test_required_stages_emit_the_machine_reports_they_upload(self):
        doc = self.fixture.read("governance/ci-pipeline.json")
        by_id = {stage["id"]: stage for stage in doc["stages"]}
        for stage in by_id.values():
            if stage["required"]:
                self.assertEqual(stage.get("if_no_files_found"), "error", stage["id"])
                self.assertTrue(stage["artifacts"], stage["id"])
        for stage_id, expected in ci.MACHINE_REPORT_STAGES.items():
            self.assertIn(expected["command"], by_id[stage_id]["commands"])
            self.assertEqual(by_id[stage_id]["artifacts"], [expected["artifact"]])

    def test_pipeline_does_not_claim_unimplemented_product_scanners(self):
        doc = self.fixture.read("governance/ci-pipeline.json")
        by_id = {stage["id"]: stage for stage in doc["stages"]}
        self.assertIn("不宣称生产源码 SAST", by_id["static-analysis"]["purpose"])
        self.assertIn("不宣称镜像漏洞扫描", by_id["container-scan"]["purpose"])
        self.assertIn("不宣称生产 Kubernetes/Terraform 扫描", by_id["iac-scan"]["purpose"])
        self.assertIn("不把聚合 BOM 冒充逐制品 SBOM", by_id["sbom"]["purpose"])


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

    def test_rejects_a_different_setup_python_commit(self):
        self.fixture.mutate(
            self.REL,
            lambda data: next(action for action in data["actions"]
                              if action["name"] == "actions/setup-python")
            .__setitem__("ref", "0" * 40),
        )
        self.assertIn("CI_PYTHON_ACTION", self.codes(self._validate()))

    def test_rejects_python_reference_version_drift(self):
        self.fixture.mutate(
            "governance/version-catalog.json",
            lambda data: next(entry for entry in data["entries"]
                              if entry["id"] == "python-toolchain")
            .__setitem__("version", "3.12.8"),
        )
        self.assertIn("CI_PYTHON_TOOLCHAIN", self.codes(self._validate()))

    def test_rejects_python_floor_version_drift(self):
        self.fixture.mutate(
            "governance/version-catalog.json",
            lambda data: next(entry for entry in data["entries"]
                              if entry["id"] == "python-toolchain")
            .__setitem__("minimum_supported", "3.10.13"),
        )
        self.assertIn("CI_PYTHON_TOOLCHAIN", self.codes(self._validate()))

    def test_rejects_missing_python_catalogue_entry_without_crashing(self):
        self.fixture.mutate(
            "governance/version-catalog.json",
            lambda data: data.__setitem__(
                "entries",
                [entry for entry in data["entries"]
                 if entry.get("id") != "python-toolchain"],
            ),
        )
        problems = self._validate()
        self.assertIn("CI_PYTHON_TOOLCHAIN", self.codes(problems))
        self.assertIn("CI_DRIFT", self.codes(problems))

    def test_rejects_null_jdk_version_without_crashing(self):
        self.fixture.mutate(
            "governance/version-catalog.json",
            lambda data: next(entry for entry in data["entries"]
                              if entry["id"] == "jdk")
            .__setitem__("version", None),
        )
        self.assertIn("CI_DRIFT", self.codes(self._validate()))

    def test_rejects_optional_python_floor_stage(self):
        self.fixture.mutate(
            self.REL,
            lambda data: self._stage(data, "python-floor").__setitem__("fail_closed", False),
        )
        self.assertIn("CI_PYTHON_FLOOR", self.codes(self._validate()))

    def test_rejects_python_floor_report_path_drift(self):
        self.fixture.mutate(
            self.REL,
            lambda data: self._stage(data, "python-floor").__setitem__(
                "artifacts", ["build/python-floor-report.json"]),
        )
        self.assertIn("CI_MACHINE_REPORT", self.codes(self._validate()))

    def test_rejects_signing_detached_from_python_floor(self):
        self.fixture.mutate(
            self.REL,
            lambda data: self._stage(data, "sign")["needs"].remove("python-floor"),
        )
        self.assertIn("CI_SIGNING_INPUT", self.codes(self._validate()))

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

    def test_rejects_dependency_scan_as_the_setup_gradle_cache_writer(self):
        self.fixture.mutate(
            self.REL,
            lambda data: data["gradle_cache_policy"].__setitem__(
                "writer_stage", "dependency-scan"),
        )
        self.assertIn("CI_GRADLE_CACHE", self.codes(self._validate()))

    def test_rejects_broad_dependency_check_cache_surface(self):
        self.fixture.mutate(
            self.REL,
            lambda data: data["gradle_cache_policy"].__setitem__(
                "dependency_data_cache_path", "~/.gradle/dependency-check-data"),
        )
        self.assertIn("CI_GRADLE_CACHE", self.codes(self._validate()))

    def test_rejects_dependency_cache_save_that_can_run_after_failure(self):
        path = self.fixture.root / ".github/workflows/ci.yml"
        text = path.read_text(encoding="utf-8")
        trusted_success = (
            "if: success() && github.event_name == 'push' && "
            "github.repository == 'zpcaiai/elmpay' && "
            "github.ref == 'refs/heads/main'"
        )
        self.assertIn(trusted_success, text)
        path.write_text(text.replace(trusted_success, "if: always()", 1), encoding="utf-8")
        self.assertIn("CI_DRIFT", self.codes(self._validate()))

    def test_rejects_different_dependency_cache_action_commit(self):
        self.fixture.mutate(
            self.REL,
            lambda data: next(action for action in data["actions"]
                              if action["name"] == "actions/cache/save")
            .__setitem__("ref", "0" * 40),
        )
        self.assertIn("CI_GRADLE_CACHE", self.codes(self._validate()))

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
        self.fixture.remove(".github/workflows/ci.yml")
        self.assertIn("CI_MISSING", self.codes(self._validate()))

    def test_rejects_skipping_the_installed_skill_mirror_check(self):
        self.fixture.mutate(
            self.REL,
            lambda d: self._stage(d, "governance").__setitem__(
                "commands", [command for command in self._stage(d, "governance")["commands"]
                             if ".agents/skills" not in command]))
        self.assertIn("CI_SKILL_PACKAGE", self.codes(self._validate()))
