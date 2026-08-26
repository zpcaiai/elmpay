from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.billing import calculate_invoice  # noqa: E402
from elmpay_runtime.common import read_json  # noqa: E402
from elmpay_runtime.rollout import compare_shadow  # noqa: E402


class BoundedScaleTest(unittest.TestCase):
    def test_shadow_diff_handles_five_thousand_records_deterministically(self) -> None:
        records = [
            {
                "requestId": f"request-{index}",
                "action": "APPROVE",
                "amountMinor": index,
                "currency": "USD",
                "reasonCodes": ["NO_MATCH"],
                "sideEffects": [],
            }
            for index in range(5000)
        ]
        result = compare_shadow(records, [dict(record) for record in records])
        self.assertTrue(result.passed)
        self.assertEqual(5000, result.compared)

    def test_billing_deduplicates_ten_thousand_retries(self) -> None:
        policy = read_json(ROOT / "platform/rollout/billing-policy.json")
        events = [
            {
                "tenantId": "tenant-a",
                "meter": "payment_attempt",
                "attempt_id": f"attempt-{index % 1000}",
                "occurredAt": "2026-08-26T00:10:00Z",
            }
            for index in range(10000)
        ]
        invoice = calculate_invoice(
            policy,
            "tenant-a",
            datetime(2026, 8, 26, tzinfo=timezone.utc),
            datetime(2026, 8, 27, tzinfo=timezone.utc),
            events,
        )
        self.assertEqual(1000 * 3, invoice.total_minor)
        self.assertEqual(9000, invoice.duplicate_events)


if __name__ == "__main__":
    unittest.main()
