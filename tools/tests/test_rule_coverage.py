"""Rule coverage — every validator rule must be reachable by a test.

An independent review of Wave W00 deleted four real security rules from source
and the whole suite still passed: 68 of 204 rule codes were unreachable by any
test or negative control. A rule nothing can trigger is indistinguishable from
a rule that does not exist.

This module does two things:

* asserts the rule-coverage gate itself is clean, so a *new* unreachable rule
  cannot be introduced silently;
* actually triggers the rule families that were previously unreachable —
  malformed input, bad schema version, wrong shape — so the knockout test
  (`scripts/rule-knockout.py`) fails when those rules are removed.
"""
from __future__ import annotations

import json

from tools.paygov import (
    adr, boundaries, ci, config, devplatform, evidence, modules, nonneg,
    requirements, rulecov, ssot, threat, toolchain, traceability,
)
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

# (validator module, governance file, unreadable code, version code, shape code,
#  shape mutation applied to the parsed document)
SURFACES = [
    (config, "governance/project-config.json", "CONFIG_UNREADABLE", "CONFIG_VERSION",
     "CONFIG_SHAPE", lambda d: d.pop("providers")),
    (nonneg, "governance/non-negotiables.json", "NONNEG_UNREADABLE", "NONNEG_VERSION",
     "NONNEG_SHAPE", lambda d: d.__setitem__("rules", {})),
    (modules, "governance/module-registry.json", "MODULE_UNREADABLE", "MODULE_VERSION",
     "MODULE_SHAPE", lambda d: d.__setitem__("modules", [{"name": "x"}])),
    (requirements, "governance/requirements.json", "REQ_UNREADABLE", "REQ_VERSION",
     "REQ_SHAPE", lambda d: d.__setitem__("requirements", "not-an-array")),
    (boundaries, "governance/service-boundaries.json", "BOUNDARY_UNREADABLE",
     "BOUNDARY_VERSION", "BOUNDARY_SHAPE", lambda d: d.__setitem__("capabilities", [])),
    (threat, "governance/threat-model.json", "THREAT_UNREADABLE", "THREAT_VERSION",
     "THREAT_SHAPE", lambda d: d.__setitem__("assets", [])),
    (toolchain, "governance/version-catalog.json", "TOOLCHAIN_UNREADABLE",
     "TOOLCHAIN_VERSION", "TOOLCHAIN_SHAPE", lambda d: d.pop("entries")),
    (devplatform, "governance/dev-platform.json", "DEV_UNREADABLE", "DEV_VERSION",
     "DEV_SHAPE", lambda d: d.__setitem__("services", "nope")),
    (ci, "governance/ci-pipeline.json", "CI_UNREADABLE", "CI_VERSION",
     "CI_SHAPE", lambda d: d.pop("stages")),
    (evidence, "governance/evidence-policy.json", "EVIDENCE_UNREADABLE",
     "EVIDENCE_VERSION", None, None),
    (ssot, "governance/ssot-registry.json", "SSOT_UNREADABLE", "SSOT_VERSION",
     "SSOT_SHAPE", lambda d: d.__setitem__("sources", [])),
]


class RuleCoverageGate(FixtureTestCase):
    def test_every_emitted_rule_is_reachable(self):
        problems = rulecov.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_gate_is_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertIn("rule-coverage", registry.names())

    def test_gate_detects_an_unreachable_rule(self):
        emitted = rulecov.emitted_codes(REAL_ROOT)
        self.assertIn("CONFIG_REGULATED", emitted)
        self.assertGreater(len(emitted), 150)
        exercised = rulecov.exercised_codes(REAL_ROOT)
        self.assertEqual(set(emitted) - exercised, set())


class MalformedInputIsRejected(FixtureTestCase):
    """Every governance surface must fail closed on unreadable or malformed input."""

    def test_unreadable_input_is_reported(self):
        for module, rel, unreadable, _version, _shape, _mutate in SURFACES:
            with self.subTest(surface=rel):
                fixture = self.new_fixture()
                fixture.write(rel, "{ this is not json")
                codes = self.codes(module.validate(fixture.root, Budget(seconds=60).start()))
                self.assertIn(unreadable, codes)

    def test_bad_schema_version_is_reported(self):
        for module, rel, _unreadable, version, _shape, _mutate in SURFACES:
            with self.subTest(surface=rel):
                fixture = self.new_fixture()
                fixture.mutate(rel, lambda d: d.__setitem__("schema_version", "one"))
                codes = self.codes(module.validate(fixture.root, Budget(seconds=60).start()))
                self.assertIn(version, codes)

    def test_malformed_shape_is_reported(self):
        for module, rel, _unreadable, _version, shape, mutate in SURFACES:
            if shape is None:
                continue
            with self.subTest(surface=rel):
                fixture = self.new_fixture()
                fixture.mutate(rel, mutate)
                codes = self.codes(module.validate(fixture.root, Budget(seconds=60).start()))
                self.assertIn(shape, codes)


class PreviouslyUnreachableSecurityRules(FixtureTestCase):
    """Rules the independent review deleted without anything going red."""

    def test_dev_platform_rejects_privileged_container(self):
        # DEV_CONTAINER_PRIVILEGE — the rule inspects the *generated* compose
        # text, so the mutation goes into the declaration it is generated from.
        fixture = self.new_fixture()
        fixture.mutate("governance/dev-platform.json",
                       lambda d: d["services"][0]["environment"]
                       .__setitem__("EXTRA", "privileged: true"))
        codes = self.codes(devplatform.validate(fixture.root, Budget(seconds=60).start()))
        self.assertIn("DEV_CONTAINER_PRIVILEGE", codes)

    def test_dev_platform_rejects_port_exposed_beyond_loopback(self):
        # DEV_PORT_EXPOSURE
        fixture = self.new_fixture()
        fixture.mutate("governance/dev-platform.json",
                       lambda d: d["services"][0]["ports"][0].__setitem__("bind", "0.0.0.0"))
        codes = self.codes(devplatform.validate(fixture.root, Budget(seconds=60).start()))
        self.assertIn("DEV_PORT_EXPOSURE", codes)

    def test_dev_platform_rejects_duplicate_service_id(self):
        # DEV_DUPLICATE
        fixture = self.new_fixture()
        fixture.mutate("governance/dev-platform.json",
                       lambda d: d["services"].append(dict(d["services"][0])))
        codes = self.codes(devplatform.validate(fixture.root, Budget(seconds=60).start()))
        self.assertIn("DEV_DUPLICATE", codes)

    def test_ci_rejects_dangerous_workflow_content(self):
        # CI_UNSAFE_WORKFLOW
        fixture = self.new_fixture()
        fixture.mutate("governance/ci-pipeline.json",
                       lambda d: d["stages"][0]["commands"].append(
                           "echo ${{ secrets.DEPLOY_KEY }}"))
        codes = self.codes(ci.validate(fixture.root, Budget(seconds=60).start()))
        self.assertIn("CI_UNSAFE_WORKFLOW", codes)

    def test_ci_rejects_duplicate_stage_and_missing_version_comment(self):
        # CI_DUPLICATE, CI_ACTION
        fixture = self.new_fixture()
        fixture.mutate("governance/ci-pipeline.json",
                       lambda d: d["stages"].append(dict(d["stages"][0])))
        self.assertIn("CI_DUPLICATE",
                      self.codes(ci.validate(fixture.root, Budget(seconds=60).start())))
        other = self.new_fixture()
        other.mutate("governance/ci-pipeline.json",
                     lambda d: d["actions"][0].__setitem__("version_comment", ""))
        self.assertIn("CI_ACTION",
                      self.codes(ci.validate(other.root, Budget(seconds=60).start())))

    def test_hygiene_detects_a_jwt_and_a_test_mode_psp_key(self):
        # SECRET_JWT, SECRET_STRIPE_TEST
        from tools.paygov import hygiene
        fixture = self.new_fixture()
        jwt = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "abcdefghijklmnop"
        fixture.write("services/payment-core/leak.txt", jwt + "\n")
        self.assertIn("SECRET_JWT",
                      self.codes(hygiene.validate(fixture.root, Budget(seconds=60).start())))
        other = self.new_fixture()
        other.write("services/payment-core/leak2.txt", "sk_" + "test_" + "0123456789ABCDEFGH\n")
        self.assertIn("SECRET_STRIPE_TEST",
                      self.codes(hygiene.validate(other.root, Budget(seconds=60).start())))

    def test_config_rejects_weak_service_identity_and_secret_backend(self):
        # CONFIG_SERVICE_IDENTITY, CONFIG_SECRET_BACKEND
        fixture = self.new_fixture()
        fixture.mutate("governance/project-config.json",
                       lambda d: d["security"].__setitem__("service_identity", "network-acl"))
        self.assertIn("CONFIG_SERVICE_IDENTITY",
                      self.codes(config.validate(fixture.root, Budget(seconds=60).start())))
        other = self.new_fixture()
        other.mutate("governance/project-config.json",
                     lambda d: d["security"].__setitem__("secret_backends", ["env-file"]))
        self.assertIn("CONFIG_SECRET_BACKEND",
                      self.codes(config.validate(other.root, Budget(seconds=60).start())))

    def test_config_rejects_credential_reference_carrying_a_literal_secret(self):
        # CONFIG_LITERAL_SECRET
        fixture = self.new_fixture()
        fixture.mutate("governance/project-config.json",
                       lambda d: d["providers"]["wechat"].__setitem__(
                           "credentials", "kms://elmpay/wechat/apiv3/AAAABBBBCCCCDDDD"))
        self.assertIn("CONFIG_LITERAL_SECRET",
                      self.codes(config.validate(fixture.root, Budget(seconds=60).start())))

    def test_module_registry_rejects_unknown_layer_slo_and_migration(self):
        # MODULE_LAYER, MODULE_SLO, MODULE_MIGRATION
        for field, value, code in (("layer", "middleware", "MODULE_LAYER"),
                                   ("slo", {}, "MODULE_SLO"),
                                   ("migration", "   ", "MODULE_MIGRATION")):
            with self.subTest(field=field):
                fixture = self.new_fixture()
                fixture.mutate("governance/module-registry.json",
                               lambda d, f=field, v=value: d["modules"][0].__setitem__(f, v))
                codes = self.codes(modules.validate(fixture.root, Budget(seconds=60).start()))
                self.assertIn(code, codes)

    def test_threat_model_rejects_malformed_due_date_and_unknown_abuse_link(self):
        # THREAT_RISK_DUE, THREAT_RISK_LINK, THREAT_ABUSE_ID
        from datetime import date
        today = date(2026, 8, 18)
        fixture = self.new_fixture()
        fixture.mutate("governance/threat-model.json",
                       lambda d: d["residual_risks"][0].__setitem__("due_date", "soon"))
        self.assertIn("THREAT_RISK_DUE", self.codes(
            threat.validate(fixture.root, Budget(seconds=60).start(), today=today)))

        other = self.new_fixture()
        other.mutate("governance/threat-model.json",
                     lambda d: d["residual_risks"][0]["related_abuse_cases"].append("AC-99"))
        self.assertIn("THREAT_RISK_LINK", self.codes(
            threat.validate(other.root, Budget(seconds=60).start(), today=today)))

        third = self.new_fixture()
        third.mutate("governance/threat-model.json",
                     lambda d: d["abuse_cases"][0].__setitem__("id", "AC-42"))
        self.assertIn("THREAT_ABUSE_ID", self.codes(
            threat.validate(third.root, Budget(seconds=60).start(), today=today)))

    def test_toolchain_rejects_duplicate_entry_and_malformed_version(self):
        # TOOLCHAIN_DUPLICATE, TOOLCHAIN_VERSION_FORMAT
        fixture = self.new_fixture()
        fixture.mutate("governance/version-catalog.json",
                       lambda d: d["entries"].append(dict(d["entries"][0])))
        self.assertIn("TOOLCHAIN_DUPLICATE",
                      self.codes(toolchain.validate(fixture.root, Budget(seconds=60).start())))
        other = self.new_fixture()
        other.mutate("governance/version-catalog.json",
                     lambda d: d["entries"][0].__setitem__("version", "release-candidate"))
        self.assertIn("TOOLCHAIN_VERSION_FORMAT",
                      self.codes(toolchain.validate(other.root, Budget(seconds=60).start())))

    def test_nonnegotiables_rejects_missing_title_and_bad_status(self):
        # NONNEG_TITLE, NONNEG_STATUS
        for field, value, code in (("title", "  ", "NONNEG_TITLE"),
                                   ("status", "someday", "NONNEG_STATUS")):
            with self.subTest(field=field):
                fixture = self.new_fixture()
                fixture.mutate("governance/non-negotiables.json",
                               lambda d, f=field, v=value: d["rules"][0].__setitem__(f, v))
                self.assertIn(code, self.codes(
                    nonneg.validate(fixture.root, Budget(seconds=60).start())))

    def test_requirements_rejects_unknown_status(self):
        # REQ_STATUS
        fixture = self.new_fixture()
        fixture.mutate("governance/requirements.json",
                       lambda d: d["requirements"][0].__setitem__("status", "maybe"))
        self.assertIn("REQ_STATUS",
                      self.codes(requirements.validate(fixture.root, Budget(seconds=60).start())))

    def test_ssot_reports_a_generated_file_that_was_never_produced(self):
        # SSOT_GENERATED_MISSING
        fixture = self.new_fixture()
        fixture.mutate("governance/ssot-registry.json",
                       lambda d: d["sources"][0]["generates"].append("docs/never-rendered.md"))
        self.assertIn("SSOT_GENERATED_MISSING",
                      self.codes(ssot.validate(fixture.root, Budget(seconds=60).start())))

    def test_charter_reports_an_unreadable_red_line_registry(self):
        # CHARTER_REGISTRY
        from tools.paygov import charter
        fixture = self.new_fixture()
        fixture.write("governance/non-negotiables.json", "{ broken")
        self.assertIn("CHARTER_REGISTRY",
                      self.codes(charter.validate(fixture.root, Budget(seconds=60).start())))

    def test_adr_reports_metadata_and_identity_defects(self):
        # ADR_TITLE, ADR_DATE, ADR_DECIDER, ADR_BATCH, ADR_UNREADABLE
        target = "docs/adr/0001-monorepo-modular-boundaries.md"
        for find, replace, code in (
                ("# ADR-0001:", "# ADR-0007:", "ADR_TITLE"),
                ("- 日期：2026-08-18", "- 日期：August 2026", "ADR_DATE"),
                ("- 决策者：payment-platform-architecture", "- 决策者：x", "ADR_DECIDER"),
                ("- 批次：B02", "- 批次：B900", "ADR_BATCH")):
            with self.subTest(code=code):
                fixture = self.new_fixture()
                path = fixture.root / target
                path.write_text(path.read_text(encoding="utf-8").replace(find, replace),
                                encoding="utf-8")
                self.assertIn(code, self.codes(
                    adr.validate(fixture.root, Budget(seconds=60).start())))
        fixture = self.new_fixture()
        fixture.write("governance/requirements.json", "{ broken")
        self.assertIn("ADR_UNREADABLE",
                      self.codes(adr.validate(fixture.root, Budget(seconds=60).start())))

    def test_adr_reports_status_contradiction(self):
        # ADR_SUPERSEDE_STATUS
        fixture = self.new_fixture()
        path = fixture.root / "docs/adr/0002-business-orders-stay-out.md"
        path.write_text(path.read_text(encoding="utf-8").replace("取代：无", "取代：ADR-0001"),
                        encoding="utf-8")
        self.assertIn("ADR_SUPERSEDE_STATUS",
                      self.codes(adr.validate(fixture.root, Budget(seconds=60).start())))

    def test_traceability_reports_unreadable_sources(self):
        # TRACE_UNREADABLE
        fixture = self.new_fixture()
        fixture.write("governance/requirements.json", "{ broken")
        self.assertIn("TRACE_UNREADABLE",
                      self.codes(traceability.validate(fixture.root, Budget(seconds=60).start())))


class EvidenceFrameworkRules(FixtureTestCase):
    """Rules over the evidence tree, exercised against a synthetic tree."""

    def _validate(self, fixture):
        return evidence.validate(fixture.root, Budget(seconds=60).start())

    def test_reports_an_empty_evidence_tree(self):
        # EVIDENCE_EMPTY
        fixture = self.new_fixture()
        self.assertIn("EVIDENCE_EMPTY", self.codes(self._validate(fixture)))

    def test_synthetic_tree_is_accepted(self):
        fixture = self.new_fixture()
        self.write_synthetic_evidence(fixture)
        self.assertEqual(self._validate(fixture), [])

    def test_reports_unreadable_command_spec(self):
        # EVIDENCE_SPEC
        fixture = self.new_fixture()
        self.write_synthetic_evidence(fixture)
        fixture.write("evidence/B00/commands.spec.json", "{", encoding="utf-8")
        self.assertIn("EVIDENCE_SPEC", self.codes(self._validate(fixture)))

    def test_reports_unreadable_traceability(self):
        # EVIDENCE_TRACE
        fixture = self.new_fixture()
        self.write_synthetic_evidence(fixture)
        fixture.write("evidence/B00/traceability.json", "{", encoding="utf-8")
        self.assertIn("EVIDENCE_TRACE", self.codes(self._validate(fixture)))

    def test_reports_unreadable_command_log(self):
        # EVIDENCE_COMMANDS
        fixture = self.new_fixture()
        self.write_synthetic_evidence(fixture)
        fixture.write("evidence/B00/commands.ndjson", "not json\n", encoding="utf-8")
        self.assertIn("EVIDENCE_COMMANDS", self.codes(self._validate(fixture)))

    def test_reports_removal_of_a_mandatory_command_class(self):
        # EVIDENCE_POLICY_FLOOR
        fixture = self.new_fixture()
        self.write_synthetic_evidence(fixture)
        fixture.mutate("governance/evidence-policy.json",
                       lambda d: d.__setitem__("required_command_classes",
                                               [c for c in d["required_command_classes"]
                                                if c["id"] != "negative-controls"]))
        self.assertIn("EVIDENCE_POLICY_FLOOR", self.codes(self._validate(fixture)))


class TraceabilityEvidenceRules(FixtureTestCase):
    """Reverse links from batch evidence back to controls and tests."""

    def _validate(self, fixture):
        return traceability.validate(fixture.root, Budget(seconds=60).start())

    def test_reports_batch_evidence_claiming_no_control(self):
        # TRACE_EVIDENCE_NO_CONTROL
        fixture = self.new_fixture()
        self.write_synthetic_evidence(fixture, controls=[])
        self.assertIn("TRACE_EVIDENCE_NO_CONTROL", self.codes(self._validate(fixture)))

    def test_reports_batch_evidence_claiming_an_unknown_control(self):
        # TRACE_EVIDENCE_UNKNOWN_CONTROL
        fixture = self.new_fixture()
        self.write_synthetic_evidence(fixture, controls=[{"id": "CTRL-999-FAKE"}])
        self.assertIn("TRACE_EVIDENCE_UNKNOWN_CONTROL", self.codes(self._validate(fixture)))

    def test_reports_batch_evidence_referencing_a_missing_test(self):
        # TRACE_EVIDENCE_TEST_MISSING
        fixture = self.new_fixture()
        self.write_synthetic_evidence(fixture, tests=[{"ref": "tools/tests/test_ghost.py"}])
        self.assertIn("TRACE_EVIDENCE_TEST_MISSING", self.codes(self._validate(fixture)))


class ToolchainAndCliFailClosed(FixtureTestCase):
    def test_reports_a_toolchain_file_that_does_not_parse(self):
        # TOOLCHAIN_SYNTAX
        from tools.paygov import hygiene
        fixture = self.new_fixture()
        fixture.write("tools/paygov/broken.py", "def oops(:\n")
        self.assertIn("TOOLCHAIN_SYNTAX",
                      self.codes(hygiene.validate(fixture.root, Budget(seconds=60).start())))

    def test_a_crashing_validator_fails_closed(self):
        # VALIDATOR_CRASHED
        from tools.paygov import cli, registry as validator_registry
        validator_registry.load_all()
        original = validator_registry.get("charter")

        def exploding(root, budget):
            raise RuntimeError("synthetic validator fault")

        validator_registry._REGISTRY["charter"] = ("B00", exploding)
        try:
            code, output = cli.run(["charter"], REAL_ROOT, 30.0)
        finally:
            validator_registry._REGISTRY["charter"] = ("B00", original)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("VALIDATOR_CRASHED", output)
        self.assertIn('"ok": false', output)

    def test_rule_coverage_gate_flags_an_unreachable_new_rule(self):
        # RULE_UNCOVERED
        fixture = self.new_fixture()
        # The probe code is assembled at run time so that this very file does
        # not make it "exercised" — the fixture now carries real test bodies.
        probe = "UNREACHABLE" + "_PROBE" + "_RULE"
        fixture.write("tools/paygov/newrule.py",
                      "from .errors import Problem\n\n\n"
                      "def validate(root, budget=None):\n"
                      f"    return [Problem('{probe}', 'x', 'y')]\n")
        problems = rulecov.validate(fixture.root, Budget(seconds=60).start())
        self.assertIn("RULE_UNCOVERED", self.codes(problems))
        self.assertTrue(any(probe in p.message for p in problems))
