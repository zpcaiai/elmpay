from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError, read_json  # noqa: E402
from elmpay_runtime.external_evidence import (  # noqa: E402
    validate_external_evidence,
    validate_test_evidence_template,
)
from elmpay_runtime.validate import _validate_deployment_profile  # noqa: E402


POLICY_PATH = ROOT / "platform/compliance/external-evidence-policy.json"
RELEASE_POLICY_PATH = ROOT / "platform/compliance/required-release-gates.json"
TEMPLATE_PATH = ROOT / "testing/fixtures/china-mvp-external-evidence.placeholder.json"


class ChinaMvpLaunchProfileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = read_json(POLICY_PATH)
        self.release_policy = read_json(RELEASE_POLICY_PATH)
        self.template = read_json(TEMPLATE_PATH)
        self.documents = {
            "platform/compliance/external-evidence-policy.json": self.policy,
            "platform/kubernetes/egress-policy.json": read_json(
                ROOT / "platform/kubernetes/egress-policy.json"
            ),
            "platform/kubernetes/workload-policy.json": read_json(
                ROOT / "platform/kubernetes/workload-policy.json"
            ),
        }

    def test_production_scope_is_exactly_wechat_and_alipay(self) -> None:
        _validate_deployment_profile(ROOT, self.documents)
        self.assertEqual(
            {"wechat", "alipay"},
            set(self.policy["requiredProviderCapabilities"]),
        )

    def test_scope_drift_in_evidence_egress_or_reconciliation_blocks(self) -> None:
        evidence_drift = deepcopy(self.documents)
        evidence_drift["platform/compliance/external-evidence-policy.json"][
            "requiredProviderCapabilities"
        ]["stripe"] = ["card"]
        with self.assertRaisesRegex(ValidationError, "certification scope"):
            _validate_deployment_profile(ROOT, evidence_drift)

        egress_drift = deepcopy(self.documents)
        egress_drift["platform/kubernetes/egress-policy.json"]["destinations"].append(
            {
                "id": "stripe-api",
                "category": "PSP",
                "type": "fqdn",
                "host": "api.stripe.com",
                "port": 443,
                "protocol": "TLS",
            }
        )
        with self.assertRaisesRegex(ValidationError, "PSP network egress scope"):
            _validate_deployment_profile(ROOT, egress_drift)

        reconciliation_drift = deepcopy(self.documents)
        worker = next(
            service
            for service in reconciliation_drift[
                "platform/kubernetes/workload-policy.json"
            ]["services"]
            if service["name"] == "worker-scheduler"
        )
        worker["configuration"]["configMapData"][
            "ELMPAY_RECONCILIATION_PROVIDERS"
        ] = "wechat,alipay,stripe"
        with self.assertRaisesRegex(ValidationError, "reconciliation provider scope"):
            _validate_deployment_profile(ROOT, reconciliation_drift)

    def test_project_configuration_scope_drift_blocks(self) -> None:
        project = read_json(ROOT / "governance/project-config.json")
        project["providers"]["stripe"].update(
            {"enabled": True, "credentials": "vault://elmpay/stripe/test-only"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "governance/project-config.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(project), encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "exactly wechat and alipay"):
                _validate_deployment_profile(root, self.documents)

    def test_placeholder_is_complete_for_local_preflight_only(self) -> None:
        report = validate_test_evidence_template(
            self.policy, self.release_policy, self.template
        )
        self.assertTrue(report.allowed, report.reasons)
        self.assertEqual("NOT_CERTIFIED", self.template["certificationStatus"])

        production = validate_external_evidence(self.policy, self.template, None)
        self.assertFalse(production.allowed)
        self.assertIn("external_evidence_test_only_bundle", production.reasons)
        self.assertIn(
            "provider_certification:test_only_external_evidence_record",
            production.reasons,
        )

    def test_placeholder_preflight_rejects_nested_positive_claims(self) -> None:
        claimed = deepcopy(self.template)
        penetration = next(
            item
            for item in claimed["evidence"]
            if item["category"] == "penetration_test"
        )
        penetration["attestation"]["findings"] = {"remediation": {"status": "PASS"}}
        report = validate_test_evidence_template(
            self.policy, self.release_policy, claimed
        )
        self.assertFalse(report.allowed)
        self.assertIn(
            "test_template[7]:positive_external_claim_forbidden", report.reasons
        )

    def test_placeholder_requires_all_release_approval_roles(self) -> None:
        incomplete = deepcopy(self.template)
        incomplete["releaseApprovals"] = incomplete["releaseApprovals"][:1]
        report = validate_test_evidence_template(
            self.policy, self.release_policy, incomplete
        )
        self.assertFalse(report.allowed)
        self.assertIn(
            "test_template_release_approval_roles_incomplete", report.reasons
        )

    def test_cli_reports_local_success_without_production_approval(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/runtime/control.py"),
                "test-evidence-template",
                "--template",
                str(TEMPLATE_PATH),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["localTemplateValid"])
        self.assertFalse(result["productionReleaseAllowed"])
        self.assertEqual("NOT_CERTIFIED", result["certificationStatus"])


if __name__ == "__main__":
    unittest.main()
