from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError  # noqa: E402
from elmpay_runtime.risk_control import ModelResult, SQLiteRiskControl  # noqa: E402


NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)


class FixedModel:
    def __init__(self, score: str = "0.10", available: bool = True) -> None:
        self.score_value = score
        self.available = available

    def score(self, request, timeout_milliseconds):
        return ModelResult(self.available, "model-7", "a" * 64, Decimal(self.score_value), "MODEL_VECTOR")


class RiskControlTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        policy = json.loads((ROOT / "platform/risk/runtime-policy.json").read_text())
        self.control = SQLiteRiskControl(str(Path(self.directory.name) / "risk.sqlite"), policy)
        rules = [{"id": "velocity", "priority": 100, "signal": "velocity5m", "operator": "GT",
                  "threshold": "5", "action": "BLOCK", "reasonCode": "VELOCITY_LIMIT"}]
        self.control.propose_rule_set("tenant-a", "rules-1", rules, "risk-a", NOW, NOW)
        self.control.approve_rule_set("tenant-a", "rules-1", "security-b", NOW)

    def tearDown(self) -> None:
        self.control.close()
        self.directory.cleanup()

    def request(self, request_id: str = "request-1"):
        return {"tenantId": "tenant-a", "requestId": request_id, "amountMinor": 100,
                "currency": "USD", "operation": "PAYMENT_CONFIRM", "subjectId": "account-1",
                "attributes": {"channel": "web"}, "occurredAt": "2026-08-28T00:00:00Z"}

    def signals(self, tenant: str = "tenant-a", velocity: str = "1"):
        return {"tenantId": tenant, "version": "signals-1", "collectedAt": "2026-08-27T23:59:30Z",
                "expiresAt": "2026-08-28T00:01:00Z", "values": {
                    "velocity5m": velocity, "deviceReputation": "0.9",
                    "networkReputation": "0.9", "geoAnomaly": "0",
                    "accountAgeDays": "90", "behaviorSequenceRisk": "0.1",
                }}

    def test_versioned_rule_blocks_and_decision_replays(self) -> None:
        first = self.control.decide(self.request(), self.signals(velocity="9"), FixedModel(), now=NOW)
        replay = self.control.decide(self.request(), self.signals(velocity="9"), FixedModel(), now=NOW)
        self.assertEqual("BLOCK", first.action)
        self.assertEqual(first, replay)
        self.assertIn("VELOCITY_LIMIT", first.reason_codes)

        later_request = {**self.request(), "occurredAt": "2026-08-28T00:00:10Z"}
        fresh_signals = {**self.signals(velocity="1"), "version": "signals-retry",
                         "collectedAt": "2026-08-28T00:00:05Z",
                         "expiresAt": "2026-08-28T00:01:10Z"}
        self.assertEqual(first, self.control.decide(
            later_request, fresh_signals, FixedModel(), now=NOW + timedelta(seconds=10)
        ))

    def test_model_failure_and_missing_signal_never_approve(self) -> None:
        unavailable = self.control.decide(self.request("request-2"), self.signals(), FixedModel(available=False), now=NOW)
        self.assertEqual("REVIEW", unavailable.action)
        missing = {**self.signals(), "version": "signals-2", "values": {}}
        decision = self.control.decide(self.request("request-3"), missing, FixedModel(), now=NOW)
        self.assertEqual("REVIEW", decision.action)

    def test_all_governed_operations_are_supported_and_missing_taxonomy_reviews(self) -> None:
        operations = json.loads((ROOT / "platform/risk/runtime-policy.json").read_text())["allowedOperations"]
        for index, operation in enumerate(operations):
            decision = self.control.decide(
                {**self.request(f"operation-{index}"), "operation": operation},
                {**self.signals(), "version": f"signals-{index + 10}"}, FixedModel(), now=NOW,
            )
            self.assertEqual(operation, decision.operation)
        missing = {**self.signals(), "version": "signals-missing-taxonomy",
                   "values": {"velocity5m": "1"}}
        decision = self.control.decide(self.request("missing-taxonomy"), missing, FixedModel(), now=NOW)
        self.assertEqual("REVIEW", decision.action)
        self.assertIn("SIGNAL_MISSING_DEVICE_REPUTATION", decision.reason_codes)
        with self.assertRaises(ValidationError):
            self.control.decide(
                {**self.request("invalid-operation"), "operation": "UNSUPPORTED"},
                self.signals(), FixedModel(), now=NOW,
            )

    def test_decision_and_outbox_are_atomic_and_acknowledgement_is_idempotent(self) -> None:
        decision = self.control.decide(self.request("outbox-1"), self.signals(), FixedModel(), now=NOW)
        events = self.control.pending_decision_events()
        event = next(item for item in events if item["eventId"] == decision.decision_id)
        self.assertEqual("risk.decision.v1", event["eventType"])
        self.assertEqual("PAYMENT_CONFIRM", event["payload"]["operation"])
        self.assertTrue(self.control.mark_event_published(decision.decision_id, NOW))
        self.assertFalse(self.control.mark_event_published(decision.decision_id, NOW))

    def test_cross_tenant_nonfinite_and_idempotency_conflict_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            self.control.decide(self.request(), self.signals("tenant-b"), FixedModel(), now=NOW)
        with self.assertRaises(ValidationError):
            self.control.decide(self.request(), self.signals(velocity="NaN"), FixedModel(), now=NOW)
        self.control.decide(self.request("request-4"), self.signals(), FixedModel(), now=NOW)
        with self.assertRaises(ValidationError):
            self.control.decide({**self.request("request-4"), "amountMinor": 101}, self.signals(), FixedModel(), now=NOW)

    def test_operations_are_digest_bound_tenant_scoped_and_four_eyes(self) -> None:
        operation = self.control.propose_operation(
            "tenant-a", "LIST_ADD", "fingerprint-1", {"listName": "deny"},
            "analyst-a", NOW + timedelta(minutes=5), NOW,
        )
        with self.assertRaises(ValidationError):
            self.control.approve_operation("tenant-a", operation, "analyst-a", NOW)
        with self.assertRaises(ValidationError):
            self.control.approve_operation("tenant-b", operation, "analyst-b", NOW)
        self.control.approve_operation("tenant-a", operation, "analyst-b", NOW)
        self.assertTrue(self.control.is_listed("tenant-a", "deny", "fingerprint-1"))
        self.assertFalse(self.control.is_listed("tenant-b", "deny", "fingerprint-1"))

    def test_cli_initializes_durable_runtime_without_claiming_certification(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/risk_control.py"), "--db",
             str(Path(self.directory.name) / "cli.sqlite"), "init"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        output = json.loads(result.stdout)
        self.assertTrue(output["initialized"])
        self.assertEqual("NOT_CERTIFIED", output["certificationStatus"])


if __name__ == "__main__":
    unittest.main()
