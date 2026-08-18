"""B07 / AT-B07-01 — bidirectional traceability.

The forward direction (requirement → code → test) is easy to satisfy and easy
to fake. The backward direction is what these tests are for: every red line,
every control, every module and every batch with evidence must be reachable
from the requirement baseline.
"""
from __future__ import annotations

from tools.paygov import traceability
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class TraceHappyPath(FixtureTestCase):
    def test_real_graph_passes(self):
        problems = traceability.validate(REAL_ROOT, Budget(seconds=120).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_every_non_negotiable_is_claimed_by_a_requirement(self):
        graph = traceability.build_graph(REAL_ROOT)
        claimed = {c for r in graph["requirements"] for c in r["controls"]}
        for rule in graph["rules"]:
            self.assertIn(rule, claimed, rule)

    def test_every_control_is_claimed_by_a_requirement(self):
        graph = traceability.build_graph(REAL_ROOT)
        claimed = {c for r in graph["requirements"] for c in r["controls"]}
        for control in graph["controls"]:
            self.assertIn(control, claimed, control)

    def test_every_requirement_belongs_to_a_capability(self):
        graph = traceability.build_graph(REAL_ROOT)
        for req in graph["requirements"]:
            self.assertIn(req["id"], graph["capability_of"], req["id"])

    def test_every_adr_constrains_a_real_requirement(self):
        graph = traceability.build_graph(REAL_ROOT)
        ids = {r["id"] for r in graph["requirements"]}
        for name, links in graph["adrs"].items():
            self.assertTrue(links["requirements"], name)
            self.assertEqual(links["requirements"] - ids, set(), name)

    def test_every_batch_with_evidence_claims_known_controls(self):
        graph = traceability.build_graph(REAL_ROOT)
        universe = set(graph["rules"]) | set(graph["controls"])
        self.assertTrue(graph["batch_evidence"])
        for batch, links in graph["batch_evidence"].items():
            self.assertTrue(links["controls"], batch)
            self.assertEqual(links["controls"] - universe, set(), batch)

    def test_graph_construction_is_deterministic(self):
        first = traceability.build_graph(REAL_ROOT)
        second = traceability.build_graph(REAL_ROOT)
        self.assertEqual(first["capability_of"], second["capability_of"])
        self.assertEqual([r["id"] for r in first["requirements"]],
                         [r["id"] for r in second["requirements"]])

    def test_matrix_contains_reverse_coverage_section(self):
        text = traceability.matrix_markdown(REAL_ROOT)
        self.assertIn("控制 → 需求（反向覆盖）", text)
        self.assertNotIn("**未覆盖**", text)


class TraceRejects(FixtureTestCase):
    REQ = "governance/requirements.json"

    def _validate(self):
        return traceability.validate(self.fixture.root, Budget(seconds=120).start())

    def test_rejects_uncovered_non_negotiable(self):
        self.fixture.mutate(self.REQ, lambda d: [
            r.__setitem__("controls", ["NN-12"]) for r in d["requirements"]
            if "NN-15" in r["controls"]])
        problems = self._validate()
        self.assertIn("TRACE_RULE_UNCOVERED", self.codes(problems))
        self.assertIn("NN-15", self.rules(problems))

    def test_rejects_uncovered_control(self):
        self.fixture.mutate(self.REQ, lambda d: [
            r.__setitem__("controls", ["NN-12"]) for r in d["requirements"]
            if "CTRL-019" in r["controls"]])
        self.assertIn("TRACE_CONTROL_UNCOVERED", self.codes(self._validate()))

    def test_rejects_module_without_requirement(self):
        self.fixture.mutate(self.REQ, lambda d: [
            r.__setitem__("owner_module", "stripe") for r in d["requirements"]
            if r["owner_module"] == "apple-pay"])
        self.assertIn("TRACE_MODULE_UNCOVERED", self.codes(self._validate()))

    def test_rejects_requirement_outside_every_capability(self):
        self.fixture.mutate("governance/service-boundaries.json",
                            lambda d: d["capabilities"][0]["requirements"].clear())
        self.assertIn("TRACE_NO_CAPABILITY", self.codes(self._validate()))

    def test_rejects_requirement_pointing_at_unknown_batch(self):
        self.fixture.mutate(self.REQ,
                            lambda d: d["requirements"][0]
                            .__setitem__("verified_by_batches", ["B900"]))
        self.assertIn("TRACE_BATCH_UNKNOWN", self.codes(self._validate()))

    def test_rejects_adr_referencing_unknown_requirement(self):
        path = self.fixture.root / "docs/adr/0003-integer-minor-units.md"
        path.write_text(path.read_text(encoding="utf-8")
                        .replace("PAY-REQ-0028", "PAY-REQ-9999"), encoding="utf-8")
        self.assertIn("TRACE_ADR_DANGLING", self.codes(self._validate()))

    def test_rejects_adr_without_any_requirement(self):
        path = self.fixture.root / "docs/adr/0010-dependency-free-governance.md"
        path.write_text(path.read_text(encoding="utf-8")
                        .replace("- 关联需求：PAY-REQ-0049", "- 关联需求：无"), encoding="utf-8")
        self.assertIn("TRACE_ADR_ORPHAN", self.codes(self._validate()))
