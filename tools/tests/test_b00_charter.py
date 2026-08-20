"""B00 / AT-B00-01 — charter completeness and charter/registry parity."""
from __future__ import annotations

from tools.paygov import charter
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class CharterHappyPath(FixtureTestCase):
    def test_real_charter_passes(self):
        self.assertEqual(charter.validate(REAL_ROOT, Budget().start()), [])

    def test_fixture_charter_passes(self):
        self.assertEqual(charter.validate(self.fixture.root, Budget().start()), [])


class CharterRejects(FixtureTestCase):
    MAIN = "docs/charter/PROGRAM_CHARTER.md"

    def _validate(self):
        return charter.validate(self.fixture.root, Budget().start())

    def test_rejects_missing_document(self):
        self.fixture.remove("docs/charter/DELIVERY_MODEL.md")
        self.assertIn("CHARTER_MISSING", self.codes(self._validate()))

    def test_rejects_missing_section(self):
        text = (self.fixture.root / self.MAIN).read_text(encoding="utf-8")
        self.fixture.write(self.MAIN, text.replace("## 4. 风险接受原则", "## 4. 其他"))
        self.assertIn("CHARTER_SECTION", self.codes(self._validate()))

    def test_rejects_missing_metadata_header(self):
        text = (self.fixture.root / self.MAIN).read_text(encoding="utf-8")
        self.fixture.write(self.MAIN, text.replace("- 复核人：", "- 备注："))
        # 复核人 is not a required header line, so this must still pass;
        # removing a required one must fail.
        self.assertEqual([p for p in self._validate() if p.code == "CHARTER_HEADER"], [])
        text2 = text.replace("- 负责人：", "- 联系人：")
        self.fixture.write(self.MAIN, text2)
        self.assertIn("CHARTER_HEADER", self.codes(self._validate()))

    def test_rejects_stub_charter(self):
        self.fixture.write(self.MAIN, "# stub\n")
        codes = self.codes(self._validate())
        self.assertIn("CHARTER_TOO_SHORT", codes)
        self.assertIn("CHARTER_SECTION", codes)

    def test_rejects_red_line_dropped_from_charter(self):
        text = (self.fixture.root / self.MAIN).read_text(encoding="utf-8")
        self.fixture.write(self.MAIN, text.replace("| NN-08 |", "| NNX-08 |"))
        problems = self._validate()
        self.assertIn("CHARTER_RED_LINE", self.codes(problems))
        self.assertIn("NN-08", self.rules(problems))

    def test_new_registry_rule_must_reach_the_charter(self):
        def add(d):
            d["rules"].append({"id": "NN-16", "title": "新增红线", "severity": "high",
                               "status": "planned", "enforced_by": ["batch:B99"]})
        self.fixture.mutate("governance/non-negotiables.json", add)
        problems = self._validate()
        self.assertIn("NN-16", self.rules(problems))
