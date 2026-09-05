from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.attestation import attach_dsse, generate_ed25519_keypair  # noqa: E402
from elmpay_runtime.common import ValidationError  # noqa: E402
from elmpay_runtime.downstream_receipt import receipt_binding  # noqa: E402
from elmpay_runtime.monitoring_runtime import (  # noqa: E402
    AuthenticatedOtlpHttpExporter,
    DurableSiemService,
    HttpExportResponse,
    MonitoringStore,
    ServiceOperationContext,
    ServiceTelemetryAdapter,
    siem_event_binding,
)


NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


def trust_key(public_key: str, identity: str, role: str, *, independent: bool) -> dict[str, object]:
    return {
        "algorithm": "Ed25519",
        "publicKeyPem": public_key,
        "identity": identity,
        "role": role,
        "independent": independent,
        "revoked": False,
        "notBefore": "2026-08-01T00:00:00Z",
        "notAfter": "2026-09-01T00:00:00Z",
    }


class OtlpRuntimeTest(unittest.TestCase):
    def test_transient_otlp_rejection_has_bounded_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = MonitoringStore(Path(directory) / "monitoring.sqlite")
            adapter = ServiceTelemetryAdapter(
                store,
                service_name="payment-core",
                service_version="1.0.0",
                environment="TEST",
            )
            adapter.record_operation(
                ServiceOperationContext(
                    "retry-operation-0001",
                    "tenant-a",
                    "project-a",
                    "3" * 32,
                    "4" * 16,
                    "retry-correlation-0001",
                    "payment.capture",
                    {},
                ),
                outcome="FAILED",
                duration_ms=1,
                attributes={},
                observed_at=NOW,
            )

            class Unavailable:
                def export(
                    self, signal: str, envelope_id: str, payload: dict[str, object]
                ) -> HttpExportResponse:
                    return HttpExportResponse(503, "0" * 64, {})

            first = adapter.export_pending(
                Unavailable(), worker_id="retry-worker-1", maximum_attempts=2, now=NOW
            )
            self.assertEqual(3, first["retryPending"])
            self.assertEqual({"PENDING"}, {row["state"] for row in store.telemetry_records()})
            second = adapter.export_pending(
                Unavailable(), worker_id="retry-worker-2", maximum_attempts=2, now=NOW
            )
            self.assertEqual(3, second["failed"])
            self.assertEqual({"FAILED"}, {row["state"] for row in store.telemetry_records()})

    def test_telemetry_cli_spools_runtime_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "monitoring.sqlite"
            record = root / "record.json"
            record.write_text(
                json.dumps(
                    {
                        "eventId": "cli-operation-0001",
                        "tenantId": "tenant-a",
                        "projectId": "project-a",
                        "traceId": "1" * 32,
                        "spanId": "2" * 16,
                        "correlationId": "cli-correlation-0001",
                        "operation": "payment.query",
                        "outcome": "UNKNOWN",
                        "durationMilliseconds": 12,
                        "observedAt": "2026-08-28T12:00:00Z",
                        "attributes": {"authorization": "never-persist"},
                        "baggage": {"region": "test-east"},
                    }
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/platform_control.py"),
                    "telemetry-emit",
                    "--record",
                    str(record),
                    "--state",
                    str(state),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            output = json.loads(completed.stdout)
            self.assertEqual("PENDING", output["state"])
            self.assertEqual("NOT_CERTIFIED", output["certificationStatus"])
            self.assertEqual(3, len(MonitoringStore(state).telemetry_records()))

    def test_service_adapter_spools_three_bound_redacted_signals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = MonitoringStore(Path(directory) / "monitoring.sqlite")
            ticks = iter((0, 7_000_000))
            adapter = ServiceTelemetryAdapter(
                store,
                service_name="payment-core",
                service_version="1.2.3",
                environment="TEST",
                clock=lambda: NOW,
                monotonic_ns=lambda: next(ticks),
            )
            context = ServiceOperationContext(
                event_id="operation-0001",
                tenant_id="tenant-a",
                project_id="project-a",
                trace_id="a" * 32,
                span_id="b" * 16,
                correlation_id="correlation-0001",
                operation="payment.authorize",
                baggage={"region": "test-east", "provider": "stripe"},
            )
            self.assertEqual(
                "authorized",
                adapter.invoke(
                    context,
                    lambda: "authorized",
                    attributes={
                        "authorization": "Bearer never-export",
                        "note": "test card 4111 1111 1111 1111",
                    },
                ),
            )
            records = store.telemetry_records("operation-0001")
            self.assertEqual({"logs", "metrics", "traces"}, {row["signal"] for row in records})
            self.assertEqual({"PENDING"}, {row["state"] for row in records})
            for row in records:
                encoded = json.dumps(row["payload"], sort_keys=True)
                self.assertIn("tenant-a", encoded)
                self.assertIn("project-a", encoded)
                self.assertIn("correlation-0001", encoded)
                self.assertNotIn("never-export", encoded)
                self.assertNotIn("4111", encoded)

    def test_authenticated_loopback_otlp_export_records_actual_http_response(self) -> None:
        captured: list[tuple[str, str, dict[str, object]]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                captured.append((self.path, self.headers.get("Authorization", ""), json.loads(body)))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                store = MonitoringStore(Path(directory) / "monitoring.sqlite")
                adapter = ServiceTelemetryAdapter(
                    store,
                    service_name="edge-gateway",
                    service_version="1.0.0",
                    environment="TEST",
                )
                adapter.record_operation(
                    ServiceOperationContext(
                        "operation-0002",
                        "tenant-a",
                        "project-a",
                        "c" * 32,
                        "d" * 16,
                        "correlation-0002",
                        "checkout.confirm",
                        {"region": "test-east"},
                    ),
                    outcome="SUCCEEDED",
                    duration_ms=5,
                    attributes={"status": "ok"},
                    observed_at=NOW,
                )
                token = "test-otlp-token-" + "x" * 32
                exporter = AuthenticatedOtlpHttpExporter(
                    f"http://127.0.0.1:{server.server_port}",
                    token,
                    allow_insecure_loopback=True,
                )
                result = adapter.export_pending(
                    exporter, worker_id="otel-worker-1", now=NOW
                )
                self.assertEqual(
                    {
                        "claimed": 3,
                        "delivered": 3,
                        "retryPending": 0,
                        "failed": 0,
                        "unknown": 0,
                    },
                    result,
                )
                self.assertEqual({"DELIVERED"}, {row["state"] for row in store.telemetry_records()})
            self.assertEqual({"/v1/logs", "/v1/metrics", "/v1/traces"}, {item[0] for item in captured})
            self.assertEqual({f"Bearer {token}"}, {item[1] for item in captured})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        with self.assertRaisesRegex(ValidationError, "requires TLS"):
            AuthenticatedOtlpHttpExporter(
                "http://192.0.2.1:4318", "production-token-" + "z" * 32
            )


class SiemRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        source_private, source_public = generate_ed25519_keypair()
        receipt_private, receipt_public = generate_ed25519_keypair()
        self.source_private = source_private
        self.receipt_private = receipt_private
        self.source_trust = {
            "replayDatabase": str(self.root / "source-nonces.sqlite"),
            "keys": {
                "admin-source": trust_key(
                    source_public,
                    "admin-audit",
                    "siem_event_source",
                    independent=False,
                )
            },
        }
        self.receipt_trust = {
            "replayDatabase": str(self.root / "receipt-nonces.sqlite"),
            "keys": {
                "siem-receipt": trust_key(
                    receipt_public,
                    "enterprise-siem",
                    "siem_exporter",
                    independent=True,
                )
            },
        }
        self.runtime_policy = json.loads(
            (ROOT / "platform/alerts/siem-runtime-policy.json").read_text()
        )
        self.detection_policy = json.loads(
            (ROOT / "platform/alerts/siem-rules.json").read_text()
        )
        self.store = MonitoringStore(self.root / "monitoring.sqlite")

    def service(self, *, with_receipts: bool = False) -> DurableSiemService:
        return DurableSiemService(
            self.store,
            runtime_policy=self.runtime_policy,
            detection_policy=self.detection_policy,
            source_trust=self.source_trust,
            receipt_trust=self.receipt_trust if with_receipts else None,
        )

    def signed_approval(self, event_id: str, nonce: str) -> dict[str, object]:
        event: dict[str, object] = {
            "schemaVersion": 1,
            "eventId": event_id,
            "source": "admin-control",
            "eventType": "approval.decided",
            "tenantId": "tenant-a",
            "projectId": "project-a",
            "actor": "admin-audit",
            "role": "siem_event_source",
            "observedAt": "2026-08-28T11:59:00Z",
            "traceId": "e" * 32,
            "correlationId": f"correlation-{event_id}",
            "details": {
                "subjectActor": "operator-a",
                "proposerId": "operator-a",
                "approverId": "operator-a",
                "phishingResistant": True,
            },
            "nonce": nonce,
            "issuedAt": "2026-08-28T11:58:00Z",
            "expiresAt": "2026-08-28T13:00:00Z",
        }
        event["bindingDigest"] = siem_event_binding(event)
        return attach_dsse(event, "admin-source", self.source_private)

    def test_siem_ingest_cli_persists_signed_event_and_alert(self) -> None:
        current = datetime.now(timezone.utc)
        issued = current - timedelta(seconds=30)
        source_key = self.source_trust["keys"]["admin-source"]
        source_key["notBefore"] = (current - timedelta(minutes=5)).isoformat()
        source_key["notAfter"] = (current + timedelta(minutes=15)).isoformat()
        event: dict[str, object] = {
            "schemaVersion": 1,
            "eventId": "cli-siem-event-0001",
            "source": "admin-control",
            "eventType": "approval.decided",
            "tenantId": "tenant-a",
            "projectId": "project-a",
            "actor": "admin-audit",
            "role": "siem_event_source",
            "observedAt": issued.isoformat(),
            "traceId": "5" * 32,
            "correlationId": "cli-siem-correlation-0001",
            "details": {
                "subjectActor": "operator-a",
                "proposerId": "operator-a",
                "approverId": "operator-a",
                "phishingResistant": True,
            },
            "nonce": "cli-siem-source-nonce-0001",
            "issuedAt": issued.isoformat(),
            "expiresAt": (current + timedelta(minutes=10)).isoformat(),
        }
        event["bindingDigest"] = siem_event_binding(event)
        signed = attach_dsse(event, "admin-source", self.source_private)
        event_path = self.root / "cli-event.json"
        trust_path = self.root / "cli-source-trust.json"
        state = self.root / "cli-monitoring.sqlite"
        event_path.write_text(json.dumps(signed), encoding="utf-8")
        trust_path.write_text(json.dumps(self.source_trust), encoding="utf-8")
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/platform_control.py"),
                "siem-ingest",
                "--event",
                str(event_path),
                "--state",
                str(state),
                "--source-trust",
                str(trust_path),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        output = json.loads(completed.stdout)
        self.assertEqual("NOT_CERTIFIED", output["certificationStatus"])
        self.assertEqual("BLOCKED", output["externalSiemDeploymentStatus"])
        service = DurableSiemService(
            MonitoringStore(state),
            runtime_policy=self.runtime_policy,
            detection_policy=self.detection_policy,
            source_trust=self.source_trust,
        )
        self.assertEqual("PENDING_EXPORT", service.alerts("cli-siem-event-0001")[0]["state"])

    def test_signed_event_is_idempotent_persistent_and_replay_protected(self) -> None:
        event = self.signed_approval("event-0001", "source-event-nonce-0001")
        result = self.service().ingest(event, now=NOW)
        self.assertFalse(result.duplicate)
        self.assertEqual(1, len(result.alert_ids))
        alert = self.service().alerts("event-0001")[0]
        self.assertEqual("SIEM-FOUR-EYES-BYPASS", alert["rule_id"])
        self.assertEqual("PENDING_EXPORT", alert["state"])
        duplicate = self.service().ingest(event, now=NOW)
        self.assertTrue(duplicate.duplicate)
        self.assertEqual(result.alert_ids, duplicate.alert_ids)

        changed = self.signed_approval("event-0002", "source-event-nonce-0001")
        with self.assertRaisesRegex(ValidationError, "nonce"):
            self.service().ingest(changed, now=NOW)

        unsigned = dict(event)
        unsigned["details"] = {**event["details"], "approverId": "operator-b"}
        with self.assertRaises(ValidationError):
            self.service().ingest(unsigned, now=NOW)

    def test_concurrent_identical_ingress_creates_one_event_and_alert(self) -> None:
        event = self.signed_approval("event-concurrent-0001", "source-concurrent-nonce-0001")
        barrier = threading.Barrier(2)

        def ingest() -> object:
            service = self.service()
            barrier.wait(timeout=5)
            return service.ingest(event, now=NOW)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(lambda _: ingest(), range(2)))

        self.assertEqual([False, True], sorted(result.duplicate for result in results))
        self.assertEqual(1, len(self.service().alerts("event-concurrent-0001")))
        with self.store.connect() as connection:
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT COUNT(*) FROM siem_event WHERE event_id=?",
                    ("event-concurrent-0001",),
                ).fetchone()[0],
            )

    def test_export_requires_signed_independent_downstream_receipt(self) -> None:
        self.service().ingest(
            self.signed_approval("event-0003", "source-event-nonce-0003"), now=NOW
        )
        private = self.receipt_private

        class SignedExporter:
            def export(inner_self, alert: dict[str, object]) -> dict[str, object]:
                fields = {
                    "alertId": alert["alertId"],
                    "alertDigest": alert["alertDigest"],
                    "tenantId": alert["tenantId"],
                    "destination": alert["destination"],
                }
                receipt: dict[str, object] = {
                    "receiptType": "SIEM_ALERT",
                    "outcome": "ACCEPTED",
                    "fields": fields,
                    "receiptId": f"receipt-{str(alert['alertId'])[:16]}",
                    "actor": "enterprise-siem",
                    "role": "siem_exporter",
                    "bindingDigest": receipt_binding("SIEM_ALERT", fields),
                    "nonce": "siem-receipt-nonce-0001",
                    "issuedAt": "2026-08-28T11:59:00Z",
                    "expiresAt": "2026-08-28T13:00:00Z",
                }
                return attach_dsse(receipt, "siem-receipt", private)

        summary = self.service(with_receipts=True).export_pending(
            SignedExporter(),
            destination="enterprise-siem",
            worker_id="siem-worker-1",
            now=NOW,
        )
        self.assertEqual({"claimed": 1, "exported": 1, "unknown": 0}, summary)
        exported = self.service(with_receipts=True).alerts("event-0003")[0]
        self.assertEqual("EXPORTED", exported["state"])
        self.assertEqual("enterprise-siem", exported["exporter_identity"])
        self.assertEqual(64, len(exported["receipt_digest"]))

        self.service().ingest(
            self.signed_approval("event-0004", "source-event-nonce-0004"), now=NOW
        )

        class BooleanClaimExporter:
            def export(inner_self, alert: dict[str, object]) -> dict[str, object]:
                return {"accepted": True}

        rejected = self.service(with_receipts=True).export_pending(
            BooleanClaimExporter(),
            destination="enterprise-siem",
            worker_id="siem-worker-2",
            now=NOW,
        )
        self.assertEqual({"claimed": 1, "exported": 0, "unknown": 1}, rejected)
        self.assertEqual(
            "EXPORT_UNKNOWN", self.service(with_receipts=True).alerts("event-0004")[0]["state"]
        )


if __name__ == "__main__":
    unittest.main()
