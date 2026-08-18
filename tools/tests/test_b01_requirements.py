"""B01 / AT-B01-01 — requirement baseline is traceable and complete."""
from __future__ import annotations

from tools.paygov import catalogue, requirements
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class BaselineHappyPath(FixtureTestCase):
    def test_real_baseline_passes(self):
        problems = requirements.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_every_module_owns_at_least_one_requirement(self):
        doc = self.fixture.read("governance/requirements.json")
        owners = {r["owner_module"] for r in doc["requirements"]}
        self.assertEqual(catalogue.module_names(str(self.fixture.root)) - owners, frozenset())

    def test_every_requirement_names_a_control_and_a_batch(self):
        doc = self.fixture.read("governance/requirements.json")
        for req in doc["requirements"]:
            self.assertTrue(req["controls"], req["id"])
            self.assertTrue(req["verified_by_batches"], req["id"])

    def test_multi_project_boundary_is_stated(self):
        doc = self.fixture.read("governance/requirements.json")
        first = doc["requirements"][0]
        self.assertEqual(first["id"], "PAY-REQ-0001")
        self.assertIn("NN-01", first["controls"])


class BaselineRegistration(FixtureTestCase):
    def test_b01_validators_are_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertTrue({"requirements", "service-boundaries", "generated-docs"}
                        <= set(registry.names()))


class BaselineRejects(FixtureTestCase):
    REL = "governance/requirements.json"

    def _validate(self):
        return requirements.validate(self.fixture.root, Budget(seconds=60).start())

    def test_rejects_gap_in_identifiers(self):
        self.fixture.mutate(self.REL, lambda d: d["requirements"].pop(10))
        self.assertIn("REQ_ID", self.codes(self._validate()))

    def test_rejects_unknown_owner_module(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["requirements"][0].__setitem__("owner_module", "ghost"))
        self.assertIn("REQ_OWNER", self.codes(self._validate()))

    def test_rejects_requirement_without_control(self):
        self.fixture.mutate(self.REL, lambda d: d["requirements"][2].__setitem__("controls", []))
        self.assertIn("REQ_CONTROL", self.codes(self._validate()))

    def test_rejects_unknown_control_reference(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["requirements"][2].__setitem__("controls", ["CTRL-999"]))
        self.assertIn("REQ_CONTROL", self.codes(self._validate()))

    def test_rejects_unknown_verification_batch(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["requirements"][3].__setitem__("verified_by_batches", ["B900"]))
        self.assertIn("REQ_VERIFICATION", self.codes(self._validate()))

    def test_rejects_requirement_without_verification(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["requirements"][4].__setitem__("verified_by_batches", []))
        self.assertIn("REQ_VERIFICATION", self.codes(self._validate()))

    def test_rejects_untestable_acceptance(self):
        self.fixture.mutate(self.REL, lambda d: d["requirements"][5].__setitem__("acceptance", "ok"))
        self.assertIn("REQ_TEXT", self.codes(self._validate()))

    def test_rejects_unknown_category(self):
        self.fixture.mutate(self.REL, lambda d: d["requirements"][6].__setitem__("category", "misc"))
        self.assertIn("REQ_CATEGORY", self.codes(self._validate()))

    def test_rejects_invalid_priority(self):
        self.fixture.mutate(self.REL, lambda d: d["requirements"][7].__setitem__("priority", "NICE"))
        self.assertIn("REQ_PRIORITY", self.codes(self._validate()))

    def test_rejects_module_left_without_any_requirement(self):
        def reassign(d):
            for req in d["requirements"]:
                if req["owner_module"] == "apple-pay":
                    req["owner_module"] = "stripe"
        self.fixture.mutate(self.REL, reassign)
        problems = self._validate()
        self.assertIn("REQ_MODULE_UNCOVERED", self.codes(problems))
