from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import GateReport, ValidationError  # noqa: E402
from elmpay_runtime.operations import (  # noqa: E402
    SQLiteOperationsStore,
    aggregate_funnel,
    evaluate_capacity_freshness,
    evaluate_security_events,
    evaluate_slo_samples,
    execute_provider_call,
    telemetry_record,
)


NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)


class OperationsTest(unittest.TestCase):
    def test_telemetry_correlates_and_redacts(self) -> None:
        record = telemetry_record(
            tenant_id="tenant-a",
            project_id="project-a",
            trace_id="a" * 32,
            correlation_id="correlation-1",
            operation="confirm",
            outcome="UNKNOWN",
            attributes={"authorization": "Bearer secret", "note": "card 4111 1111 1111 1111"},
            baggage={"region": "cn-east"},
        )
        self.assertEqual("[REDACTED]", record["attributes"]["authorization"])
        self.assertNotIn("4111", record["attributes"]["note"])
        with self.assertRaises(ValidationError):
            telemetry_record(
                tenant_id="t", project_id="p", trace_id="b" * 32,
                correlation_id="correlation-2", operation="confirm", outcome="SUCCESSISH",
                attributes={},
            )

    def test_slo_funnel_and_siem_are_machine_evaluated(self) -> None:
        slo_policy = json.loads((ROOT / "platform/observability/slos.json").read_text())
        samples = {
            item["name"]: {"goodEvents": 100000, "totalEvents": 100000, "maximumBurnRate": 0}
            for item in slo_policy["services"]
        }
        self.assertTrue(evaluate_slo_samples(slo_policy, samples).allowed)
        failed = {**samples, "payment-api-availability": {"goodEvents": 900, "totalEvents": 1000, "maximumBurnRate": 20}}
        self.assertFalse(evaluate_slo_samples(slo_policy, failed).allowed)
        event = {
            "eventId": "evt-1", "tenantId": "tenant-a", "stage": "CAPTURED",
            "amountMinor": 123, "projectId": "p", "provider": "stripe", "region": "us",
            "deviceClass": "web", "releaseId": "r1",
        }
        cells = aggregate_funnel([event, dict(event)], "tenant-a")
        self.assertEqual(1, cells[0].captured)
        self.assertEqual(123, cells[0].amount_minor)
        siem = json.loads((ROOT / "platform/alerts/siem-rules.json").read_text())
        alerts = evaluate_security_events(siem, [
            {"eventType": "approval.decided", "actor": "a", "proposerId": "a", "approverId": "a", "phishingResistant": True}
        ])
        self.assertEqual("SIEM-FOUR-EYES-BYPASS", alerts[0].rule_id)

    def test_provider_breaker_is_account_scoped_and_recovers_through_half_open(self) -> None:
        policy = json.loads((ROOT / "platform/policies/provider-resilience.json").read_text())
        policy["circuitBreaker"]["minimumCalls"] = 2
        policy["circuitBreaker"]["halfOpenCalls"] = 1
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteOperationsStore(str(Path(directory) / "operations.sqlite"))
            self.assertEqual("HEALTHY", store.provider_record("t", "acct-a", False, 10, policy, NOW))
            self.assertEqual("OPEN", store.provider_record("t", "acct-a", False, 10, policy, NOW))
            self.assertFalse(store.provider_before_call("t", "acct-a", policy, NOW))
            later = NOW + timedelta(seconds=31)
            self.assertTrue(store.provider_before_call("t", "acct-a", policy, later))
            self.assertEqual("HEALTHY", store.provider_record("t", "acct-a", True, 10, policy, later))
            self.assertTrue(store.provider_before_call("t", "acct-b", policy, NOW))
            store.close()

    def test_provider_call_wrapper_checks_breaker_and_records_success_and_failure(self) -> None:
        policy = json.loads((ROOT / "platform/policies/provider-resilience.json").read_text())
        policy["circuitBreaker"]["minimumCalls"] = 1
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteOperationsStore(str(Path(directory) / "operations.sqlite"))
            ticks = iter((0, 10_000_000, 20_000_000, 30_000_000))
            value = execute_provider_call(
                store, tenant_id="t", account_id="healthy", policy=policy,
                operation=lambda: "provider-result", now=lambda: NOW,
                monotonic_ns=lambda: next(ticks),
            )
            self.assertEqual("provider-result", value)
            failing_ticks = iter((0, 10_000_000))
            with self.assertRaisesRegex(RuntimeError, "provider failed"):
                execute_provider_call(
                    store, tenant_id="t", account_id="failing", policy=policy,
                    operation=lambda: (_ for _ in ()).throw(RuntimeError("provider failed")),
                    now=lambda: NOW, monotonic_ns=lambda: next(failing_ticks),
                )
            self.assertFalse(store.provider_before_call("t", "failing", policy, NOW))
            store.close()

    def test_admin_actions_require_four_eyes_and_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteOperationsStore(str(Path(directory) / "operations.sqlite"))
            action = store.propose_action(
                tenant_id="tenant-a", action_type="WEBHOOK_REPLAY", target="delivery-1",
                payload={"expectedRevision": 4}, proposer="operator-a", now=NOW,
            )
            with self.assertRaises(ValidationError):
                store.approve_action(action, "operator-a", NOW)
            store.approve_action(action, "operator-b", NOW)
            calls: list[str] = []
            def executor(action_id: str, tenant: str, target: str, payload: bytes) -> str:
                self.assertEqual(action, action_id)
                calls.append(f"{tenant}:{target}:{payload.decode()}")
                return "receipt-1"
            self.assertEqual("receipt-1", store.execute_action(action, executor))
            self.assertEqual("receipt-1", store.execute_action(action, executor))
            self.assertEqual(1, len(calls))
            store.close()

    def test_incident_state_and_capacity_freshness_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteOperationsStore(str(Path(directory) / "operations.sqlite"))
            store.open_incident("INC-1", "SEV1", "payment-core", "Payment confirmation delays", "ops-a", NOW)
            store.transition_incident("INC-1", 1, "MITIGATING", NOW)
            with self.assertRaises(ValidationError):
                store.transition_incident("INC-1", 1, "RESOLVED", NOW)
            store.close()
        fresh = {"database": [{"observedAt": "2026-08-27T23:00:00Z"}]}
        self.assertTrue(evaluate_capacity_freshness(GateReport(True, (), ()), fresh, now=NOW).allowed)
        stale = {"database": [{"observedAt": "2026-08-20T00:00:00Z"}]}
        self.assertFalse(evaluate_capacity_freshness(GateReport(True, (), ()), stale, now=NOW).allowed)


if __name__ == "__main__":
    unittest.main()
