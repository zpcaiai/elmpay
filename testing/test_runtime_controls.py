from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.billing import calculate_invoice  # noqa: E402
from elmpay_runtime.attestation import attach_dsse, generate_ed25519_keypair  # noqa: E402
from elmpay_runtime.capacity import evaluate_capacity  # noqa: E402
from elmpay_runtime.common import GateReport, ValidationError, read_json  # noqa: E402
from elmpay_runtime.compliance import (  # noqa: E402
    evaluate_vendor,
    evaluate_vulnerability_report,
)
from elmpay_runtime.kubernetes import render_workloads  # noqa: E402
from elmpay_runtime.release import (  # noqa: E402
    release_binding,
    verify_release,
)
from elmpay_runtime.rollout import (  # noqa: E402
    ShadowDiff,
    compare_shadow,
    evaluate_canary,
    evaluate_go_no_go,
)
from elmpay_runtime.validate import validate_repository  # noqa: E402


NOW = datetime(2026, 8, 26, 0, 0, tzinfo=timezone.utc)


class PlatformValidationTest(unittest.TestCase):
    def test_repository_platform_policy_is_machine_valid(self) -> None:
        report = validate_repository(ROOT)
        self.assertTrue(report.allowed, report.reasons)
        self.assertGreater(len(report.checks), 20)

    def test_control_cli_is_fail_closed_for_missing_release_input(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/runtime/control.py"),
                "release-gate",
                "--manifest",
                str(ROOT / "testing/does-not-exist.json"),
                "--trust",
                str(ROOT / "testing/does-not-exist-trust.json"),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, result.returncode)
        output = json.loads(result.stdout)
        self.assertFalse(output["allowed"])


class KubernetesControlTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = read_json(ROOT / "platform/kubernetes/workload-policy.json")

    def test_renderer_requires_exact_digest_pinned_images(self) -> None:
        images = {
            item["name"]: f"registry.example/{item['name']}@sha256:" + "a" * 64
            for item in self.policy["services"]
        }
        images["risk-engine"] = "registry.example/risk-engine:latest"
        with self.assertRaises(ValidationError):
            render_workloads(self.policy, images)

    def test_renderer_applies_hardened_ha_workloads(self) -> None:
        rendered = render_workloads(self.policy, {
            item["name"]: f"registry.example/{item['name']}@sha256:" + "a" * 64
            for item in self.policy["services"]
        })
        self.assertEqual(len(self.policy["services"]), len(rendered["items"]))
        for deployment in rendered["items"]:
            self.assertGreaterEqual(deployment["spec"]["replicas"], 3)
            pod = deployment["spec"]["template"]["spec"]
            container = pod["containers"][0]
            self.assertFalse(pod["automountServiceAccountToken"])
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertEqual(["ALL"], container["securityContext"]["capabilities"]["drop"])
            self.assertEqual(2, len(pod["topologySpreadConstraints"]))


class RolloutControlTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = read_json(ROOT / "platform/rollout/policy.json")

    def test_shadow_rejects_mismatch_and_candidate_side_effect(self) -> None:
        baseline = [{
            "requestId": "r1",
            "action": "APPROVE",
            "amountMinor": 100,
            "currency": "USD",
            "reasonCodes": ["OK"],
        }]
        candidate = [{
            "requestId": "r1",
            "action": "BLOCK",
            "amountMinor": 100,
            "currency": "USD",
            "reasonCodes": ["RULE"],
            "sideEffects": ["provider_call"],
        }]
        result = compare_shadow(baseline, candidate)
        self.assertFalse(result.passed)
        self.assertIn("r1", result.candidate_side_effects)
        self.assertIn("r1:action", result.mismatches)

    def test_canary_auto_stops_on_first_ledger_mismatch(self) -> None:
        baseline = self._metrics()
        candidate = self._metrics(ledgerMismatchCount=1)
        report = evaluate_canary(baseline, candidate, self.policy)
        self.assertFalse(report.allowed)
        self.assertIn("ledgerMismatchCount_exceeded", report.reasons)

    def test_canary_rejects_non_finite_string_metrics(self) -> None:
        with self.assertRaises(ValidationError):
            evaluate_canary(
                self._metrics(), self._metrics(errorRate="NaN"), self.policy
            )

    @staticmethod
    def _metrics(**overrides: object) -> dict[str, object]:
        metrics: dict[str, object] = {
            "requestCount": 10000,
            "errorRate": 0.001,
            "latencyP99Ms": 400,
            "authorizationRate": 0.90,
            "ledgerMismatchCount": 0,
            "duplicateSideEffectCount": 0,
            "securityCriticalCount": 0,
        }
        metrics.update(overrides)
        return metrics


class BillingControlTest(unittest.TestCase):
    def test_usage_is_tenant_scoped_and_deduplicated(self) -> None:
        policy = read_json(ROOT / "platform/rollout/billing-policy.json")
        event = {
            "tenantId": "tenant-a",
            "meter": "payment_attempt",
            "attempt_id": "attempt-1",
            "occurredAt": "2026-08-26T00:10:00Z",
        }
        invoice = calculate_invoice(
            policy,
            "tenant-a",
            NOW,
            datetime(2026, 8, 27, tzinfo=timezone.utc),
            [event, dict(event)],
        )
        self.assertEqual(1, invoice.duplicate_events)
        self.assertEqual(3, invoice.total_minor)

        with self.assertRaises(ValidationError):
            calculate_invoice(
                policy,
                "tenant-b",
                NOW,
                datetime(2026, 8, 27, tzinfo=timezone.utc),
                [event],
            )


class CapacityControlTest(unittest.TestCase):
    def test_forecast_below_headroom_blocks_go_no_go(self) -> None:
        policy = read_json(ROOT / "platform/observability/capacity.json")
        samples = {
            resource: [
                {"used": 50, "capacity": 100, "observedAt": "2026-08-01T00:00:00Z"},
                {"used": 55, "capacity": 100, "observedAt": "2026-08-10T00:00:00Z"},
                {"used": 60, "capacity": 100, "observedAt": "2026-08-20T00:00:00Z"},
            ]
            for resource in policy["resources"]
        }
        assessment = evaluate_capacity(policy, samples)
        self.assertFalse(assessment.report.allowed)
        self.assertTrue(any(reason.startswith("forecast_headroom_low") for reason in assessment.report.reasons))

    def test_go_no_go_aggregates_every_gate(self) -> None:
        rollout_policy = read_json(ROOT / "platform/rollout/policy.json")
        allowed = GateReport(True, (), ("verified",))
        shadow = ShadowDiff(10, (), (), (), ())
        blocked_capacity = GateReport(False, ("forecast_headroom_low:database",), ())
        report = evaluate_go_no_go(
            allowed,
            shadow,
            allowed,
            blocked_capacity,
            {"rollbackTestPassed": True, "gitopsDriftCount": 0, "openCriticalIncidents": 0},
            rollout_policy,
        )
        self.assertFalse(report.allowed)
        self.assertIn("capacity:forecast_headroom_low:database", report.reasons)


class ComplianceGateTest(unittest.TestCase):
    def test_missing_scan_type_and_findings_block(self) -> None:
        policy = read_json(ROOT / "platform/compliance/vulnerability-policy.json")
        report = {
            "scans": [{
                "type": "dependency",
                "status": "COMPLETE",
                "artifactDigest": "a" * 64,
                "completedAt": "2026-08-25T23:00:00Z",
                "findings": {"critical": 1, "high": 0, "medium": 0},
            }]
        }
        result = evaluate_vulnerability_report(policy, report, "a" * 64, now=NOW)
        self.assertFalse(result.allowed)
        self.assertIn("finding_threshold_exceeded:dependency:critical", result.reasons)
        self.assertIn("missing_scan:container", result.reasons)

    def test_vendor_requires_independent_current_review(self) -> None:
        policy = read_json(ROOT / "platform/compliance/vendor-policy.json")
        assessment = {
            "vendorId": "vendor-1",
            "critical": True,
            "completedControls": policy["required"],
            "assessor": "reviewer-a",
            "approver": "reviewer-a",
            "reviewedAt": "2026-08-25T00:00:00Z",
        }
        result = evaluate_vendor(policy, assessment, now=NOW)
        self.assertFalse(result.allowed)
        self.assertIn("vendor_approver_not_independent", result.reasons)


class FinalReleaseGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = read_json(ROOT / "platform/compliance/required-release-gates.json")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.private = {}
        public = {}
        for key_id in ("rm", "sec", "external"):
            self.private[key_id], public[key_id] = generate_ed25519_keypair()
        self.trust = {
            "replayDatabase": str(Path(self.temporary.name) / "nonces.db"),
            "keys": {
                "rm": {
                    "identity": "release-a",
                    "role": "release_manager",
                    "algorithm": "Ed25519",
                    "publicKeyPem": public["rm"],
                    "independent": False,
                    "revoked": False,
                    "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
                "sec": {
                    "identity": "security-b",
                    "role": "security",
                    "algorithm": "Ed25519",
                    "publicKeyPem": public["sec"],
                    "independent": False,
                    "revoked": False,
                    "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
                "external": {
                    "identity": "independent-verifier",
                    "role": "external_verifier",
                    "algorithm": "Ed25519",
                    "publicKeyPem": public["external"],
                    "independent": True,
                    "revoked": False,
                    "notBefore": "2026-08-01T00:00:00Z",
                    "notAfter": "2026-09-01T00:00:00Z",
                },
            }
        }

    def test_missing_human_and_external_evidence_blocks(self) -> None:
        manifest = self._base_manifest()
        report = verify_release(
            manifest, self.policy, self.trust, now=NOW
        )
        self.assertFalse(report.allowed)
        self.assertIn("missing_approval_role:security", report.reasons)
        self.assertIn("missing_evidence:uat_acceptance", report.reasons)

    def test_complete_signed_binding_passes_and_tamper_fails(self) -> None:
        manifest = self._base_manifest()
        binding = release_binding(manifest)
        approvals = [
            self._signed(
                {
                    "actor": "release-a",
                    "role": "release_manager",
                    "decision": "APPROVE",
                    "signedAt": "2026-08-25T23:30:00Z",
                    "issuedAt": "2026-08-25T23:30:00Z",
                    "expiresAt": "2026-08-26T12:00:00Z",
                    "nonce": "approval-release-a-0001",
                    "bindingDigest": binding,
                },
                "rm",
            ),
            self._signed(
                {
                    "actor": "security-b",
                    "role": "security",
                    "decision": "APPROVE",
                    "signedAt": "2026-08-25T23:31:00Z",
                    "issuedAt": "2026-08-25T23:31:00Z",
                    "expiresAt": "2026-08-26T12:00:00Z",
                    "nonce": "approval-security-b-0001",
                    "bindingDigest": binding,
                },
                "sec",
            ),
        ]
        evidence = [
            self._signed(
                {
                    "category": category,
                    "verifier": "independent-verifier",
                    "role": "external_verifier",
                    "status": "VERIFIED",
                    "evidenceDigest": f"{index + 1:064x}",
                    "observedAt": "2026-08-25T22:00:00Z",
                    "expiresAt": "2026-08-27T00:00:00Z",
                    "issuedAt": "2026-08-25T22:00:00Z",
                    "nonce": f"evidence-external-{index:04d}",
                    "bindingDigest": binding,
                },
                "external",
            )
            for index, category in enumerate(self.policy["requiredEvidence"])
        ]
        manifest = {**manifest, "approvals": approvals, "evidence": evidence}

        report = verify_release(
            manifest, self.policy, self.trust, now=NOW
        )
        self.assertTrue(report.allowed, report.reasons)

        manifest["images"]["risk-engine"] = "registry.example/risk@sha256:" + "d" * 64
        tampered = verify_release(
            manifest, self.policy, self.trust, now=NOW
        )
        self.assertFalse(tampered.allowed)
        self.assertTrue(any("release_binding_mismatch" in reason for reason in tampered.reasons))

    def _signed(self, record: dict[str, object], key_id: str) -> dict[str, object]:
        return attach_dsse(record, key_id, self.private[key_id])

    @staticmethod
    def _base_manifest() -> dict[str, object]:
        return {
            "releaseId": "release-2026-08-26-1",
            "commitSha": "c" * 40,
            "artifactDigest": "a" * 64,
            "images": {
                "risk-engine": "registry.example/risk@sha256:" + "b" * 64,
                "worker-scheduler": "registry.example/worker@sha256:" + "c" * 64,
            },
            "generatedAt": "2026-08-25T23:00:00Z",
            "expiresAt": "2026-08-26T12:00:00Z",
            "approvals": [],
            "evidence": [],
        }


if __name__ == "__main__":
    unittest.main()
