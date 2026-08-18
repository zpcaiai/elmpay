"""B01 / AT-B01-01 — the review documents must match their source of truth."""
from __future__ import annotations

from tools.paygov import docs, render
from tools.paygov.repo import Budget
from tools.tests.support import REAL_ROOT, FixtureTestCase


class GeneratedDocs(FixtureTestCase):
    def test_real_docs_are_up_to_date(self):
        problems = docs.validate(REAL_ROOT, Budget(seconds=60).start())
        self.assertEqual(problems, [], "\n".join(str(p) for p in problems))

    def test_rendering_is_deterministic(self):
        first = render.render_all(REAL_ROOT)
        second = render.render_all(REAL_ROOT)
        self.assertEqual(first, second)

    def test_generated_files_carry_the_do_not_edit_banner(self):
        for content in render.render_all(REAL_ROOT).values():
            self.assertIn("GENERATED FILE", content)

    def test_source_change_makes_the_document_drift(self):
        self.fixture.mutate("governance/requirements.json",
                            lambda d: d["requirements"][0].__setitem__("title", "改过的标题"))
        problems = docs.validate(self.fixture.root, Budget(seconds=60).start())
        self.assertIn("DOC_DRIFT", self.codes(problems))

    def test_missing_document_is_reported(self):
        (self.fixture.root / "docs/requirements/SERVICE_BOUNDARIES.md").unlink()
        problems = docs.validate(self.fixture.root, Budget(seconds=60).start())
        self.assertIn("DOC_MISSING", self.codes(problems))
