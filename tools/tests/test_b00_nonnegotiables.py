"""B00 / AT-B00-01 — non-negotiable registry integrity and policy parity."""
from __future__ import annotations

from tools.paygov import nonneg
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class RegistryHappyPath(FixtureTestCase):
    def test_real_registry_passes(self):
        self.assertEqual(nonneg.validate(REAL_ROOT, Budget().start()), [])

    def test_all_fifteen_policy_statements_are_mirrored(self):
        registry = self.fixture.read("governance/non-negotiables.json")
        self.assertEqual(len(registry["rules"]), 15)
        self.assertEqual([r["id"] for r in registry["rules"]],
                         [f"NN-{i:02d}" for i in range(1, 16)])


class RegistryRejects(FixtureTestCase):
    REL = "governance/non-negotiables.json"

    def _validate(self):
        return nonneg.validate(self.fixture.root, Budget().start())

    def test_rejects_dropped_rule(self):
        self.fixture.mutate(self.REL, lambda d: d["rules"].pop())
        codes = self.codes(self._validate())
        self.assertIn("NONNEG_COUNT", codes)
        self.assertIn("NONNEG_PARITY", codes)

    def test_rejects_reordered_ids(self):
        def swap(d):
            d["rules"][0], d["rules"][1] = d["rules"][1], d["rules"][0]
        self.fixture.mutate(self.REL, swap)
        self.assertIn("NONNEG_ID", self.codes(self._validate()))

    def test_rejects_rule_without_enforcement(self):
        self.fixture.mutate(self.REL, lambda d: d["rules"][3].__setitem__("enforced_by", []))
        self.assertIn("NONNEG_ENFORCEMENT", self.codes(self._validate()))

    def test_rejects_active_rule_without_a_real_test(self):
        def weaken(d):
            d["rules"][2]["status"] = "active"          # NN-03 is still 'planned'
            d["rules"][2]["enforced_by"] = ["batch:B37"]
        self.fixture.mutate(self.REL, weaken)
        self.assertIn("NONNEG_ACTIVE_WITHOUT_TEST", self.codes(self._validate()))

    def test_rejects_enforcement_test_that_is_an_empty_stub(self):
        """Existence is not enforcement (NONNEG_ENFORCEMENT_EMPTY)."""
        self.fixture.write("tools/tests/test_b00_module_registry.py", "", encoding="utf-8")
        self.assertIn("NONNEG_ENFORCEMENT_EMPTY", self.codes(self._validate()))

    def test_rejects_enforcement_test_that_never_names_the_rule(self):
        """A test that never mentions the rule cannot be shown to enforce it
        (NONNEG_ENFORCEMENT_UNNAMED)."""
        path = self.fixture.root / "tools/tests/test_b00_module_registry.py"
        body = path.read_text(encoding="utf-8").replace("NN-01", "NN-04")
        path.write_text(body, encoding="utf-8")
        self.assertIn("NONNEG_ENFORCEMENT_UNNAMED", self.codes(self._validate()))

    def test_rejects_enforcement_pointing_at_missing_test(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["rules"][0]["enforced_by"].append("test:test_does_not_exist"))
        self.assertIn("NONNEG_ENFORCEMENT", self.codes(self._validate()))

    def test_rejects_invalid_batch_reference(self):
        self.fixture.mutate(self.REL, lambda d: d["rules"][0]["enforced_by"].append("batch:B999"))
        self.assertIn("NONNEG_ENFORCEMENT", self.codes(self._validate()))

    def test_rejects_unknown_severity(self):
        self.fixture.mutate(self.REL, lambda d: d["rules"][0].__setitem__("severity", "cosmetic"))
        self.assertIn("NONNEG_SEVERITY", self.codes(self._validate()))

    def test_rejects_missing_upstream_policy(self):
        self.fixture.remove(".payment-platform/skill-package/policies/non-negotiables.md")
        self.assertIn("NONNEG_POLICY_MISSING", self.codes(self._validate()))
