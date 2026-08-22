"""Negative controls for the aggregate dependency scan and CycloneDX gates.

These tests mutate disposable governance fixtures only.  They deliberately do
not execute Dependency-Check, so the suite never downloads the 5–20 minute NVD
database and remains deterministic offline.
"""
from __future__ import annotations

from tools.paygov import ci, toolchain
from tools.paygov.repo import Budget
from tools.tests.support import FixtureTestCase


class SupplyChainPipelineRejects(FixtureTestCase):
    REL = "governance/ci-pipeline.json"

    @staticmethod
    def _stage(data, stage_id):
        return next(stage for stage in data["stages"] if stage["id"] == stage_id)

    def _validate(self):
        return ci.validate(self.fixture.root, Budget(seconds=60).start())

    def test_rejects_single_project_dependency_check_task(self):
        self.fixture.mutate(
            self.REL,
            lambda data: self._stage(data, "dependency-scan").__setitem__(
                "commands", ["./gradlew --no-daemon dependencyCheckAnalyze"]),
        )
        self.assertIn("CI_SUPPLY_CHAIN_TASK", self.codes(self._validate()))

    def test_rejects_missing_dependency_check_json_artifact(self):
        self.fixture.mutate(
            self.REL,
            lambda data: self._stage(data, "dependency-scan").__setitem__(
                "artifacts", ["build/reports/dependency-check/dependency-check-report.json"]),
        )
        self.assertIn("CI_SUPPLY_CHAIN_ARTIFACT", self.codes(self._validate()))

    def test_rejects_nonaggregate_cyclonedx_task(self):
        self.fixture.mutate(
            self.REL,
            lambda data: self._stage(data, "sbom").__setitem__(
                "commands", ["./gradlew --no-daemon cyclonedxDirectBom"]),
        )
        self.assertIn("CI_SUPPLY_CHAIN_TASK", self.codes(self._validate()))

    def test_rejects_missing_supply_chain_stage(self):
        self.fixture.mutate(
            self.REL,
            lambda data: data["stages"].__setitem__(
                slice(None),
                [stage for stage in data["stages"] if stage["id"] != "sbom"],
            ),
        )
        self.assertIn("CI_SUPPLY_CHAIN_STAGE", self.codes(self._validate()))

    def test_rejects_wrong_cyclonedx_json_artifact(self):
        self.fixture.mutate(
            self.REL,
            lambda data: self._stage(data, "sbom").__setitem__(
                "artifacts", ["build/reports/cyclonedx/bom.json"]),
        )
        self.assertIn("CI_SUPPLY_CHAIN_ARTIFACT", self.codes(self._validate()))

    def test_rejects_supply_chain_stage_detached_from_build(self):
        self.fixture.mutate(
            self.REL,
            lambda data: self._stage(data, "dependency-scan").__setitem__("needs", []),
        )
        self.assertIn("CI_SUPPLY_CHAIN_COVERAGE", self.codes(self._validate()))

    def test_rejects_optional_fail_open_supply_chain_stage(self):
        def weaken(data):
            stage = self._stage(data, "dependency-scan")
            stage["required"] = False
            stage["fail_closed"] = False
            data["required_stages"].remove("dependency-scan")

        self.fixture.mutate(self.REL, weaken)
        self.assertIn("CI_SUPPLY_CHAIN_GATE", self.codes(self._validate()))

    def test_rejects_required_stage_with_optional_artifact_upload(self):
        self.fixture.mutate(
            self.REL,
            lambda data: self._stage(data, "dependency-scan").__setitem__(
                "if_no_files_found", "warn"),
        )
        self.assertIn("CI_ARTIFACT_MISSING", self.codes(self._validate()))

    def test_rejects_report_declaration_without_atomic_cli_output(self):
        self.fixture.mutate(
            self.REL,
            lambda data: self._stage(data, "secret-scan").__setitem__(
                "commands", ["python3 -m tools.paygov.cli verify repo-hygiene --repo ."]),
        )
        self.assertIn("CI_MACHINE_REPORT", self.codes(self._validate()))


class SecurityBuildControlsReject(FixtureTestCase):
    REL = "build.gradle.kts"

    def _replace(self, old: str, new: str) -> None:
        path = self.fixture.root / self.REL
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        self.fixture.write(self.REL, text.replace(old, new, 1))

    def _validate(self):
        return toolchain.validate(self.fixture.root, Budget(seconds=60).start())

    def test_missing_security_build_file_fails_closed(self):
        (self.fixture.root / self.REL).unlink()
        self.assertIn("TOOLCHAIN_SECURITY_BUILD", self.codes(self._validate()))

    def test_rejects_nonzero_vulnerability_budget(self):
        self._replace("failBuildOnCVSS.set(0.0f)", "failBuildOnCVSS.set(11.0f)")
        self.assertIn("TOOLCHAIN_SECURITY_GATE", self.codes(self._validate()))

    def test_rejects_late_vulnerability_budget_override(self):
        self._replace("failBuildOnCVSS.set(0.0f)",
                      "failBuildOnCVSS.set(0.0f)\n    failBuildOnCVSS.set(11.0f)")
        self.assertIn("TOOLCHAIN_SECURITY_GATE", self.codes(self._validate()))

    def test_rejects_fail_open_analysis_errors(self):
        self._replace("failOnError.set(true)", "failOnError.set(false)")
        self.assertIn("TOOLCHAIN_SECURITY_GATE", self.codes(self._validate()))

    def test_rejects_disabled_vulnerability_updates(self):
        self._replace("failOnError.set(true)",
                      "failOnError.set(true)\n    autoUpdate.set(false)")
        self.assertIn("TOOLCHAIN_SECURITY_GATE", self.codes(self._validate()))

    def test_rejects_non_json_dependency_report(self):
        self._replace('format.set("JSON")', 'format.set("HTML")')
        self.assertIn("TOOLCHAIN_SECURITY_REPORT", self.codes(self._validate()))

    def test_rejects_wrong_dependency_report_directory(self):
        self._replace('layout.buildDirectory.dir("reports")',
                      'layout.buildDirectory.dir("reports/dependency-check")')
        self.assertIn("TOOLCHAIN_SECURITY_REPORT", self.codes(self._validate()))

    def test_rejects_narrowed_project_coverage(self):
        self._replace("failOnError.set(true)",
                      'failOnError.set(true)\n    skipProjects.set(listOf(":services:payment-core"))')
        self.assertIn("TOOLCHAIN_SECURITY_COVERAGE", self.codes(self._validate()))

    def test_rejects_wrong_aggregate_sbom_path(self):
        self._replace('layout.buildDirectory.file("reports/bom.json")',
                      'layout.buildDirectory.file("reports/cyclonedx/bom.json")')
        self.assertIn("TOOLCHAIN_SECURITY_REPORT", self.codes(self._validate()))

    def test_rejects_late_aggregate_sbom_path_override(self):
        self._replace('jsonOutput.set(layout.buildDirectory.file("reports/bom.json"))',
                      'jsonOutput.set(layout.buildDirectory.file("reports/bom.json"))\n'
                      '    jsonOutput.set(layout.buildDirectory.file("reports/other.json"))')
        self.assertIn("TOOLCHAIN_SECURITY_REPORT", self.codes(self._validate()))

    def test_rejects_disabled_aggregate_sbom(self):
        self._replace('jsonOutput.set(layout.buildDirectory.file("reports/bom.json"))',
                      'jsonOutput.set(layout.buildDirectory.file("reports/bom.json"))\n'
                      '    enabled = false')
        self.assertIn("TOOLCHAIN_SECURITY_COVERAGE", self.codes(self._validate()))

    def test_rejects_undeclared_xml_sbom_output(self):
        self._replace("xmlOutput.unsetConvention()", "")
        self.assertIn("TOOLCHAIN_SECURITY_REPORT", self.codes(self._validate()))

    def test_rejects_removed_security_plugin(self):
        self._replace('    id("org.owasp.dependencycheck") version "13.0.0"\n', "")
        self.assertIn("TOOLCHAIN_SECURITY_PLUGIN", self.codes(self._validate()))

    def test_missing_security_plugin_catalogue_entry_fails_instead_of_crashing(self):
        self.fixture.mutate(
            "governance/version-catalog.json",
            lambda data: data["entries"].__setitem__(
                slice(None),
                [entry for entry in data["entries"]
                 if entry["id"] != "owasp-dependency-check"],
            ),
        )
        codes = self.codes(self._validate())
        self.assertIn("TOOLCHAIN_SECURITY_PLUGIN", codes)
        self.assertIn("BUILD_GENERATOR", codes)

    def test_rejects_floating_security_plugin_version(self):
        self.fixture.mutate(
            "governance/version-catalog.json",
            lambda data: next(entry for entry in data["entries"]
                              if entry["id"] == "owasp-dependency-check")
            .__setitem__("version", "13.+"),
        )
        self.assertIn("TOOLCHAIN_FLOATING", self.codes(self._validate()))

    def test_rejects_security_plugin_outside_build_plugin_category(self):
        self.fixture.mutate(
            "governance/version-catalog.json",
            lambda data: next(entry for entry in data["entries"]
                              if entry["id"] == "cyclonedx-gradle")
            .__setitem__("category", "build"),
        )
        self.assertIn("TOOLCHAIN_SECURITY_PLUGIN", self.codes(self._validate()))
