"""B02 / AT-B02-01 — threat model, abuse-case parity and residual risk ledger."""
from __future__ import annotations

from datetime import date, timedelta

from tools.paygov import threat
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase

FIXED_TODAY = date(2026, 8, 18)


class ThreatModelHappyPath(FixtureTestCase):
    def test_real_threat_model_passes(self):
        problems = threat.validate(REAL_ROOT, Budget(seconds=60).start(), today=FIXED_TODAY)
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_all_twelve_upstream_abuse_cases_are_mirrored(self):
        doc = self.fixture.read("governance/threat-model.json")
        self.assertEqual([c["id"] for c in doc["abuse_cases"]],
                         [f"AC-{i:02d}" for i in range(1, 13)])

    def test_every_residual_risk_has_owner_controls_and_deadline(self):
        doc = self.fixture.read("governance/threat-model.json")
        self.assertTrue(doc["residual_risks"])
        for risk in doc["residual_risks"]:
            self.assertTrue(risk["owner"].strip())
            self.assertTrue(risk["compensating_controls"])
            self.assertTrue(risk["due_date"])
            self.assertTrue(risk["review_batch"])

    def test_no_residual_risk_is_critical(self):
        doc = self.fixture.read("governance/threat-model.json")
        for risk in doc["residual_risks"]:
            self.assertNotEqual(risk["severity"], "critical")

    def test_single_executor_risk_is_declared_honestly(self):
        doc = self.fixture.read("governance/threat-model.json")
        ids = {r["id"] for r in doc["residual_risks"]}
        self.assertIn("RR-05", ids)


class ThreatModelRejects(FixtureTestCase):
    REL = "governance/threat-model.json"

    def _validate(self, today=FIXED_TODAY):
        return threat.validate(self.fixture.root, Budget(seconds=60).start(), today=today)

    def test_rejects_expired_security_exception(self):
        problems = self._validate(today=FIXED_TODAY + timedelta(days=400))
        self.assertIn("THREAT_RISK_EXPIRED", self.codes(problems))
        self.assertIn("NN-15", self.rules(problems))

    def test_rejects_critical_residual_risk(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["residual_risks"][0].__setitem__("severity", "critical"))
        self.assertIn("THREAT_RISK_SEVERITY", self.codes(self._validate()))

    def test_rejects_placeholder_owner(self):
        self.fixture.mutate(self.REL, lambda d: d["residual_risks"][1].__setitem__("owner", "TBD"))
        self.assertIn("THREAT_RISK_OWNER", self.codes(self._validate()))

    def test_rejects_risk_without_compensating_controls(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["residual_risks"][2].__setitem__("compensating_controls", []))
        self.assertIn("THREAT_RISK_CONTROL", self.codes(self._validate()))

    def test_rejects_unknown_review_batch(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["residual_risks"][3].__setitem__("review_batch", "B900"))
        self.assertIn("THREAT_RISK_REVIEW", self.codes(self._validate()))

    def test_rejects_dropped_abuse_case(self):
        self.fixture.mutate(self.REL, lambda d: d["abuse_cases"].pop())
        codes = self.codes(self._validate())
        self.assertIn("THREAT_PARITY", codes)

    def test_rejects_abuse_case_without_mitigating_batch(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["abuse_cases"][0].__setitem__("mitigating_batches", []))
        self.assertIn("THREAT_ABUSE", self.codes(self._validate()))

    def test_rejects_abuse_case_with_unknown_adversary(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["abuse_cases"][0].__setitem__("adversaries", ["AD-99"]))
        self.assertIn("THREAT_ABUSE", self.codes(self._validate()))

    def test_rejects_accepted_abuse_case_without_residual_risk(self):
        def accept(d):
            d["abuse_cases"][5]["status"] = "accepted"
            for risk in d["residual_risks"]:
                risk["related_abuse_cases"] = [c for c in risk["related_abuse_cases"]
                                               if c != d["abuse_cases"][5]["id"]]
        self.fixture.mutate(self.REL, accept)
        self.assertIn("THREAT_ACCEPTED_UNTRACKED", self.codes(self._validate()))

    def test_rejects_asset_with_unknown_module(self):
        self.fixture.mutate(self.REL, lambda d: d["assets"][0].__setitem__("modules", ["ghost"]))
        self.assertIn("THREAT_ASSET", self.codes(self._validate()))

    def test_rejects_boundary_with_unknown_zone(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["trust_boundaries"][0].__setitem__("between", ["Z01", "Z99"]))
        self.assertIn("THREAT_BOUNDARY", self.codes(self._validate()))

    def test_rejects_missing_upstream_threat_model(self):
        (self.fixture.root / ".payment-platform/skill-package/security/THREAT_MODEL.md").unlink()
        self.assertIn("THREAT_UPSTREAM_MISSING", self.codes(self._validate()))
