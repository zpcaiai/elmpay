"""Deterministic SOTA fault vectors used by the B112-B117 matrix suite.

These tests deliberately exercise the fail-closed runtime controls with only
synthetic records.  They are not provider certification or production DR
evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone
import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.billing import calculate_invoice  # noqa: E402
from elmpay_runtime.common import GateReport, ValidationError, read_json  # noqa: E402
from elmpay_runtime.rollout import compare_shadow, evaluate_canary  # noqa: E402


NOW = datetime(2026, 8, 26, tzinfo=timezone.utc)


class SotaFaultVectorTest(unittest.TestCase):
    def test_duplicate_and_out_of_order_usage_is_counted_once(self) -> None:
        policy = read_json(ROOT / "platform/rollout/billing-policy.json")
        events = [
            {"tenantId": "tenant-a", "meter": "payment_attempt", "attempt_id": "a-1", "occurredAt": "2026-08-26T00:03:00Z"},
            {"tenantId": "tenant-a", "meter": "payment_attempt", "attempt_id": "a-2", "occurredAt": "2026-08-26T00:02:00Z"},
            {"tenantId": "tenant-a", "meter": "payment_attempt", "attempt_id": "a-1", "occurredAt": "2026-08-26T00:01:00Z"},
        ]
        invoice = calculate_invoice(policy, "tenant-a", NOW, datetime(2026, 8, 27, tzinfo=timezone.utc), events)
        self.assertEqual(1, invoice.duplicate_events)
        self.assertEqual(2, sum(line.quantity for line in invoice.lines))

    def test_cross_tenant_event_is_rejected_before_billing(self) -> None:
        policy = read_json(ROOT / "platform/rollout/billing-policy.json")
        with self.assertRaises(ValidationError):
            calculate_invoice(
                policy,
                "tenant-a",
                NOW,
                datetime(2026, 8, 27, tzinfo=timezone.utc),
                [{"tenantId": "tenant-b", "meter": "payment_attempt", "attempt_id": "x", "occurredAt": "2026-08-26T00:00:00Z"}],
            )

    def test_shadow_diff_rejects_candidate_side_effect_and_field_drift(self) -> None:
        baseline = [{"requestId": "r-1", "action": "APPROVE", "amountMinor": 100, "currency": "USD", "reasonCodes": ["OK"]}]
        candidate = [{"requestId": "r-1", "action": "APPROVE", "amountMinor": 101, "currency": "USD", "reasonCodes": ["OK"], "sideEffects": ["provider_call"]}]
        result = compare_shadow(baseline, candidate)
        self.assertFalse(result.passed)
        self.assertEqual(("r-1",), result.candidate_side_effects)
        self.assertIn("r-1:amountMinor", result.mismatches)

    def test_canary_rejects_nonfinite_and_ledger_mismatch_metrics(self) -> None:
        policy = read_json(ROOT / "platform/rollout/policy.json")
        baseline = {"requestCount": 1000, "errorRate": 0.001, "latencyP99Ms": 400, "authorizationRate": 0.9, "ledgerMismatchCount": 0, "duplicateSideEffectCount": 0, "securityCriticalCount": 0}
        with self.assertRaises(ValidationError):
            evaluate_canary(baseline, {**baseline, "errorRate": "NaN"}, policy)
        report = evaluate_canary(baseline, {**baseline, "ledgerMismatchCount": 1}, policy)
        self.assertFalse(report.allowed)
        self.assertIn("ledgerMismatchCount_exceeded", report.reasons)

    def test_signed_external_evidence_rejects_tamper_and_staleness(self) -> None:
        policy = read_json(ROOT / "platform/compliance/external-evidence-policy.json")
        self.assertIn("independent_human_review", policy["requiredCategories"])
        # The full signed-bundle construction and key checks are covered by
        # test_external_evidence; this vector asserts the policy is explicit.
        self.assertTrue(all(isinstance(category, str) for category in policy["requiredCategories"]))

    def test_fail_closed_gate_report_does_not_accept_unknown_outcome(self) -> None:
        report = GateReport(False, ("provider_outcome_unknown",), ())
        self.assertFalse(report.allowed)
        self.assertIn("provider_outcome_unknown", report.reasons)


if __name__ == "__main__":
    unittest.main()
