from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _load_boundary_module():
    path = ROOT / "scripts" / "external-boundary.py"
    spec = importlib.util.spec_from_file_location("external_boundary", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExternalBoundaryMappingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.boundary = _load_boundary_module()
        cls.policy = json.loads(
            (ROOT / "platform/compliance/external-evidence-policy.json").read_text(
                encoding="utf-8"
            )
        )

    def test_every_required_external_category_has_a_batch_mapping(self) -> None:
        self.assertEqual(
            set(self.policy["requiredCategories"]),
            set(self.boundary.BLOCKS),
        )
        for category, batches in self.boundary.BLOCKS.items():
            with self.subTest(category=category):
                self.assertTrue(batches)

    def test_release_decision_categories_map_to_their_owning_batches(self) -> None:
        expected = {
            "post_launch_reconciliation": "B125",
            "commercial_sla": "B126",
            "go_no_go": "B123",
            "final_release_signoff": "B127",
        }
        for category, batch in expected.items():
            with self.subTest(category=category):
                self.assertIn(batch, {item[0] for item in self.boundary.BLOCKS[category]})


if __name__ == "__main__":
    unittest.main()
