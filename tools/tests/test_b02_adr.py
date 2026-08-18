"""B02 / AT-B02-01 — architecture decision records are complete and linked."""
from __future__ import annotations

from tools.paygov import adr
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class AdrHappyPath(FixtureTestCase):
    def test_real_adrs_pass(self):
        problems = adr.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_b02_validators_are_registered(self):
        from tools.paygov import registry
        registry.load_all()
        self.assertTrue({"adr", "threat-model"} <= set(registry.names()))

    def test_core_decisions_are_recorded(self):
        names = {p.name for p in (REAL_ROOT / "docs/adr").glob("*.md")}
        for expected in ("0002-business-orders-stay-out.md",
                         "0003-integer-minor-units.md",
                         "0004-server-verified-payment-truth.md",
                         "0007-no-raw-card-data.md"):
            self.assertIn(expected, names)


class AdrRejects(FixtureTestCase):
    DIR = "docs/adr"

    def _validate(self):
        return adr.validate(self.fixture.root, Budget(seconds=60).start())

    def _first(self):
        return self.fixture.root / self.DIR / "0001-monorepo-modular-boundaries.md"

    def test_rejects_missing_section(self):
        path = self._first()
        path.write_text(path.read_text(encoding="utf-8").replace("## 备选方案", "## 其他"),
                        encoding="utf-8")
        self.assertIn("ADR_SECTION", self.codes(self._validate()))

    def test_rejects_missing_metadata(self):
        path = self._first()
        path.write_text(path.read_text(encoding="utf-8").replace("- 决策者：", "- 作者："),
                        encoding="utf-8")
        self.assertIn("ADR_META", self.codes(self._validate()))

    def test_rejects_unknown_status(self):
        path = self._first()
        path.write_text(path.read_text(encoding="utf-8").replace("状态：accepted", "状态：maybe"),
                        encoding="utf-8")
        self.assertIn("ADR_STATUS", self.codes(self._validate()))

    def test_rejects_unknown_requirement_link(self):
        path = self._first()
        path.write_text(path.read_text(encoding="utf-8")
                        .replace("关联需求：PAY-REQ-0010", "关联需求：PAY-REQ-9999"),
                        encoding="utf-8")
        self.assertIn("ADR_REQUIREMENT", self.codes(self._validate()))

    def test_rejects_unknown_control_link(self):
        path = self._first()
        path.write_text(path.read_text(encoding="utf-8").replace("关联控制：NN-01", "关联控制：NN-99"),
                        encoding="utf-8")
        self.assertIn("ADR_CONTROL", self.codes(self._validate()))

    def test_rejects_numbering_gap(self):
        (self.fixture.root / self.DIR / "0005-idempotency-inbox-outbox.md").unlink()
        self.assertIn("ADR_NUMBERING", self.codes(self._validate()))

    def test_rejects_bad_filename(self):
        path = self.fixture.root / self.DIR / "draft note.md"
        path.write_text("# ADR-0099: x\n", encoding="utf-8")
        self.assertIn("ADR_FILENAME", self.codes(self._validate()))

    def test_rejects_stub_adr(self):
        path = self._first()
        path.write_text("# ADR-0001: 太短\n", encoding="utf-8")
        codes = self.codes(self._validate())
        self.assertIn("ADR_TOO_SHORT", codes)
        self.assertIn("ADR_SECTION", codes)

    def test_rejects_superseded_without_successor(self):
        path = self._first()
        path.write_text(path.read_text(encoding="utf-8")
                        .replace("状态：accepted", "状态：superseded"), encoding="utf-8")
        self.assertIn("ADR_SUPERSEDED_DANGLING", self.codes(self._validate()))

    def test_rejects_supersede_of_unknown_adr(self):
        path = self._first()
        path.write_text(path.read_text(encoding="utf-8").replace("取代：无", "取代：ADR-9999"),
                        encoding="utf-8")
        self.assertIn("ADR_SUPERSEDES_UNKNOWN", self.codes(self._validate()))

    def test_rejects_empty_adr_directory(self):
        for path in (self.fixture.root / self.DIR).glob("*.md"):
            path.unlink()
        self.assertIn("ADR_EMPTY", self.codes(self._validate()))
