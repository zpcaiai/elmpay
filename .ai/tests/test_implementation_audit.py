from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "implementation_audit.py"
SPEC = importlib.util.spec_from_file_location("implementation_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class ImplementationAuditTest(unittest.TestCase):
    def test_manifest_is_complete_and_certification_is_unchanged(self) -> None:
        report = AUDIT.audit()
        self.assertEqual(128, report["batch_count"])
        self.assertEqual("PASS", report["inventory_status"])
        self.assertEqual("NOT_RUN", report["implementation_surface"])
        self.assertFalse(report["verification_executed"])
        self.assertEqual("NOT_CERTIFIED", report["certification_status"])
        self.assertFalse(report["certified_batches_changed"])

    def test_every_surface_has_code_and_tests(self) -> None:
        report = AUDIT.audit()
        for surface in report["surfaces"]:
            self.assertGreater(surface["production_files"], 0, surface["name"])
            self.assertGreater(surface["test_files"], 0, surface["name"])


if __name__ == "__main__":
    unittest.main()
