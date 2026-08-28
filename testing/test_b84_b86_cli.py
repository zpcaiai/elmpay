from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SecurityControlCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write_json(self, name: str, value: object) -> Path:
        path = self.directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def run_cli(self, script: str, *arguments: object, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools" / script), *(str(argument) for argument in arguments)],
            cwd=ROOT, check=False, capture_output=True, text=True,
            env={**os.environ, **(environment or {})},
        )

    def test_b84_entrypoint_assesses_idn_and_rejects_unbound_repository_policy(self) -> None:
        policy = self.write_json("brand-policy.json", {
            "schemaVersion": 1,
            "ruleVersion": "brand-cli-v1",
            "officialDomains": ["checkout.elmpay.com"],
            "protectedLabels": ["elmpay"],
            "allowedCertificateAuthorities": ["Example CA"],
            "maximumLabelEditDistance": 1,
            "maximumObservationAgeSeconds": 86400,
            "requiredDomainControls": [
                "DNSSEC", "CAA", "REGISTRY_LOCK", "TRANSFER_LOCK", "HARDWARE_MFA", "DMARC_REJECT",
            ],
            "externalMonitoring": {"status": "BLOCKED", "requiredEvidence": ["provider receipt"]},
        })
        observation = self.write_json("observation.json", {
            "tenantId": "tenant-a", "source": "DNS", "observationId": "obs-cli",
            "domain": "еlmpаy.com", "observedAt": "2026-08-28T01:00:00Z",
        })
        result = self.run_cli(
            "b84_brand_control.py", "--at", "2026-08-28T01:00:00Z", "assess",
            "--policy", policy, "--input", observation,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("TAKEDOWN_CANDIDATE", json.loads(result.stdout)["decision"])

        blocked = self.run_cli(
            "b84_brand_control.py", "assess",
            "--policy", ROOT / "platform/security/brand-protection-policy.json", "--input", observation,
        )
        self.assertEqual(2, blocked.returncode)
        self.assertFalse(json.loads(blocked.stdout)["allowed"])

    def test_b85_entrypoint_verifies_actual_runtime_assets(self) -> None:
        result = self.run_cli(
            "b85_browser_integrity.py",
            "--public-root", ROOT / "apps/checkout-web/public",
            "--manifest", ROOT / "apps/checkout-web/security/script-allowlist.json",
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        output = json.loads(result.stdout)
        self.assertTrue(output["allowed"])
        self.assertEqual("NOT_CERTIFIED", output["certificationStatus"])

        report = self.write_json("browser-report.json", {
            "reportId": "00000000-0000-4000-8000-000000000001",
            "occurredAt": "2026-08-28T01:00:00Z", "category": "BROWSER_INTEGRITY",
            "policyVersion": "checkout-scripts-2026-08-28-v1",
            "type": "PAGE_MUTATION", "reasons": ["UNAUTHORIZED_SCRIPT_ELEMENT"],
        })
        ingested = self.run_cli(
            "b85_browser_report.py", "--database", self.directory / "browser.sqlite",
            "--deployment-id", "checkout-prod-cn",
            "--policy-version", "checkout-scripts-2026-08-28-v1", "--input", report,
            "--at", "2026-08-28T01:00:00Z",
        )
        self.assertEqual(0, ingested.returncode, ingested.stdout + ingested.stderr)
        self.assertTrue(json.loads(ingested.stdout)["accepted"])

    def test_b86_entrypoint_persists_block_and_requires_out_of_band_secret(self) -> None:
        request = self.write_json("abuse.json", {
            "tenantId": "tenant-a", "requestId": "cli-request-1", "layer": "IDENTITY",
            "routeId": "login", "occurredAt": "2026-08-28T01:00:00Z",
            "sourceIp": "203.0.113.9", "accountId": "account-1", "deviceId": "device-1",
            "sessionId": "session-1", "authenticationSucceeded": True,
            "credentialLeakMatch": True,
        })
        arguments = (
            "--at", "2026-08-28T01:00:00Z", "evaluate",
            "--database", self.directory / "security.sqlite",
            "--policy", ROOT / "platform/security/abuse-protection-policy.json",
            "--input", request,
        )
        missing = self.run_cli("b86_abuse_control.py", *arguments, environment={"ELMPAY_SUBJECT_HMAC_KEY_HEX": ""})
        self.assertEqual(2, missing.returncode)
        result = self.run_cli(
            "b86_abuse_control.py", *arguments,
            environment={"ELMPAY_SUBJECT_HMAC_KEY_HEX": (b"k" * 32).hex()},
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual("BLOCK", output["action"])
        self.assertIsNotNone(output["case_id"])
        self.assertEqual("NOT_CERTIFIED", output["certificationStatus"])


if __name__ == "__main__":
    unittest.main()
