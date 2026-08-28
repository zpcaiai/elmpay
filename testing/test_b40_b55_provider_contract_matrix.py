from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ProviderContractMatrixTest(unittest.TestCase):
    def test_every_declared_channel_operation_and_failure_mode(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/provider-contract-matrix.py"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("providers=5", result.stdout)
        self.assertIn("failure_modes=4", result.stdout)
        self.assertIn("failures=0", result.stdout)


if __name__ == "__main__":
    unittest.main()
