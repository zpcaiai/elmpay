"""B01 / AT-B01-01 — service boundaries, ownership and forbidden flows."""
from __future__ import annotations

from tools.paygov import boundaries
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class BoundaryHappyPath(FixtureTestCase):
    def test_real_boundaries_pass(self):
        problems = boundaries.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_every_requirement_is_claimed_exactly_once(self):
        doc = self.fixture.read("governance/service-boundaries.json")
        claimed = [rid for c in doc["capabilities"] for rid in c["requirements"]]
        self.assertEqual(len(claimed), len(set(claimed)))
        total = len(self.fixture.read("governance/requirements.json")["requirements"])
        self.assertEqual(len(set(claimed)), total)

    def test_business_project_owns_the_business_order(self):
        doc = self.fixture.read("governance/service-boundaries.json")
        actor = next(a for a in doc["external_actors"] if a["id"] == "external:business-project")
        self.assertIn("业务订单", actor["owns"])

    def test_forbidden_flows_cover_the_core_abuse_cases(self):
        doc = self.fixture.read("governance/service-boundaries.json")
        enforced = {ref for f in doc["forbidden_flows"] for ref in f["enforced_by"]}
        for rule in ("NN-01", "NN-02", "NN-03", "NN-08", "NN-09", "NN-10", "NN-13"):
            self.assertIn(rule, enforced, rule)


class BoundaryRejects(FixtureTestCase):
    REL = "governance/service-boundaries.json"

    def _validate(self):
        return boundaries.validate(self.fixture.root, Budget(seconds=60).start())

    def test_rejects_unclaimed_requirement(self):
        self.fixture.mutate(self.REL, lambda d: d["capabilities"][0]["requirements"].pop())
        self.assertIn("BOUNDARY_REQ_UNCLAIMED", self.codes(self._validate()))

    def test_rejects_double_claimed_requirement(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["capabilities"][1]["requirements"].append(
                                d["capabilities"][0]["requirements"][0]))
        self.assertIn("BOUNDARY_REQ_DOUBLE_CLAIM", self.codes(self._validate()))

    def test_rejects_reference_to_missing_requirement(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["capabilities"][0]["requirements"].append("PAY-REQ-9999"))
        self.assertIn("BOUNDARY_REQ_MISSING", self.codes(self._validate()))

    def test_rejects_capability_owned_by_unknown_module(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["capabilities"][0].__setitem__("owner_module", "ghost"))
        self.assertIn("BOUNDARY_CAPABILITY", self.codes(self._validate()))

    def test_rejects_edge_to_undeclared_actor(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["capabilities"][0]["inbound_from"].append("external:unknown"))
        self.assertIn("BOUNDARY_EDGE", self.codes(self._validate()))

    def test_rejects_actor_without_prohibitions(self):
        self.fixture.mutate(self.REL, lambda d: d["external_actors"][0].__setitem__("must_not", []))
        self.assertIn("BOUNDARY_ACTOR", self.codes(self._validate()))

    def test_rejects_forbidden_flow_without_enforcement(self):
        self.fixture.mutate(self.REL, lambda d: d["forbidden_flows"][0].__setitem__("enforced_by", []))
        self.assertIn("BOUNDARY_FLOW", self.codes(self._validate()))

    def test_rejects_forbidden_flow_with_unknown_enforcement(self):
        self.fixture.mutate(self.REL,
                            lambda d: d["forbidden_flows"][0]["enforced_by"].append("batch:B900"))
        self.assertIn("BOUNDARY_FLOW", self.codes(self._validate()))
