from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci-release-evidence-gate.py"


def encoded(value: object) -> str:
    return base64.b64encode(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).decode()


class CiReleaseEvidenceGateTest(unittest.TestCase):
    def environment(self) -> dict[str, str]:
        value = dict(os.environ)
        value.update({
            "GITHUB_ACTIONS": "true",
            "ELMPAY_GATE_EVENT_NAME": "push",
            "ELMPAY_GATE_REPOSITORY": "zpcaiai/elmpay",
            "ELMPAY_GATE_REF": "refs/heads/main",
            "ELMPAY_GATE_SHA": "a" * 40,
        })
        return value

    def run_gate(self, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT)], cwd=ROOT, env=environment,
            text=True, capture_output=True, check=False,
        )

    def test_missing_protected_bundle_blocks_main_release(self) -> None:
        result = self.run_gate(self.environment())
        self.assertEqual(2, result.returncode)
        output = json.loads(result.stdout)
        self.assertFalse(output["allowed"])
        self.assertEqual("NOT_CERTIFIED", output["certificationStatus"])
        self.assertIn("ELMPAY_RELEASE_MANIFEST_B64", output["reasons"][0])

    def test_manifest_must_bind_exact_workflow_commit_before_verification(self) -> None:
        environment = self.environment()
        for name in (
            "ELMPAY_RELEASE_TRUST_B64", "ELMPAY_EXTERNAL_EVIDENCE_B64",
            "ELMPAY_EXTERNAL_TRUST_B64", "ELMPAY_PRODUCT_IMAGE_INDEX_B64",
        ):
            environment[name] = encoded({})
        environment["ELMPAY_RELEASE_MANIFEST_B64"] = encoded({"commitSha": "b" * 40})
        result = self.run_gate(environment)
        self.assertEqual(2, result.returncode)
        self.assertIn("not bound to the workflow commit", result.stdout)

    def test_untrusted_context_blocks_even_with_documents(self) -> None:
        environment = self.environment()
        environment["ELMPAY_GATE_REF"] = "refs/heads/feature"
        for name in (
            "ELMPAY_RELEASE_MANIFEST_B64", "ELMPAY_RELEASE_TRUST_B64",
            "ELMPAY_EXTERNAL_EVIDENCE_B64", "ELMPAY_EXTERNAL_TRUST_B64",
            "ELMPAY_PRODUCT_IMAGE_INDEX_B64",
        ):
            environment[name] = encoded({})
        result = self.run_gate(environment)
        self.assertEqual(2, result.returncode)
        self.assertIn("untrusted release-gate context", result.stdout)


if __name__ == "__main__":
    unittest.main()
