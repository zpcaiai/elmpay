from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError  # noqa: E402
from elmpay_runtime.service_migration import ServiceMigrationControl  # noqa: E402


NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)
TENANT = "tenant-a"
PROJECT = "project-a"
EVIDENCE = {
    "sourceCount": 2,
    "platformCount": 2,
    "sourceAmountMinor": 300,
    "platformAmountMinor": 300,
    "divergenceCount": 0,
}


class ServiceMigrationRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = Path(self.directory.name) / "migration.sqlite"
        self.runtime = ServiceMigrationControl(self.database)
        self.runtime.register_project(TENANT, PROJECT, {"mapping": "payment-v2"}, now=NOW)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def record(self, *, request_amount: int = 100, operation: str = "operation-1",
               key: str = "idempotency-key-1") -> dict[str, object]:
        return self.runtime.record_provider_result(
            tenant_id=TENANT,
            project_id=PROJECT,
            operation_id=operation,
            idempotency_key=key,
            request={"amountMinor": request_amount},
            provider_reference="provider-payment-1",
            provider_result={"state": "SUCCEEDED"},
            legacy_projection={"state": "SUCCEEDED"},
            platform_projection={"state": "SUCCEEDED"},
            now=NOW,
        )

    def test_provider_result_is_single_journaled_idempotently_and_delivered_with_fencing(self) -> None:
        first = self.record()
        self.assertEqual(["legacy"], first["targets"])
        self.assertIs(self.record()["replayed"], True)
        with self.assertRaisesRegex(ValidationError, "different provider result"):
            self.record(request_amount=101)

        expired = self.runtime.claim_delivery(
            TENANT, PROJECT, "legacy", "worker-one", now=NOW, lease_seconds=5,
        )
        self.assertIsNotNone(expired)
        replacement = self.runtime.claim_delivery(
            TENANT, PROJECT, "legacy", "worker-two",
            now=NOW + timedelta(seconds=6), lease_seconds=5,
        )
        self.assertIsNotNone(replacement)
        assert expired is not None and replacement is not None
        self.assertEqual(expired.lease_token + 1, replacement.lease_token)
        with self.assertRaisesRegex(ValidationError, "fenced"):
            self.runtime.acknowledge_delivery(
                expired, expired.payload_digest, now=NOW + timedelta(seconds=6),
            )
        self.runtime.acknowledge_delivery(
            replacement, replacement.payload_digest, now=NOW + timedelta(seconds=6),
        )

    def test_backfill_is_read_only_input_idempotent_contiguous_and_totals_bound(self) -> None:
        page = [
            {"sourcePosition": 0, "sourceRecordId": "legacy-1", "amountMinor": 100},
            {"sourcePosition": 1, "sourceRecordId": "legacy-2", "amountMinor": 200},
        ]
        expected = {"lastPosition": 1, "recordCount": 2, "amountMinorSum": 300}
        self.assertEqual(expected, self.runtime.import_backfill_page(
            TENANT, PROJECT, "payments", page, now=NOW,
        ))
        self.assertEqual(expected, self.runtime.import_backfill_page(
            TENANT, PROJECT, "payments", page, now=NOW,
        ))
        with self.assertRaisesRegex(ValidationError, "checkpoint gap"):
            self.runtime.import_backfill_page(TENANT, PROJECT, "payments", [{
                "sourcePosition": 3, "sourceRecordId": "legacy-4", "amountMinor": 400,
            }], now=NOW)

    def test_cutover_requires_digest_bound_four_eyes_matched_dual_writes_and_backfill(self) -> None:
        initial_evidence = dict(EVIDENCE, sourceCount=0, platformCount=0,
                                sourceAmountMinor=0, platformAmountMinor=0)
        first = self.runtime.propose_cutover(
            TENANT, PROJECT, "DUAL_WRITE_LEGACY_AUTHORITATIVE", initial_evidence,
            "operator-one", now=NOW,
        )
        with self.assertRaisesRegex(ValidationError, "distinct approver"):
            self.runtime.approve_cutover(
                TENANT, PROJECT, first, "operator-one", initial_evidence, now=NOW,
            )
        self.assertEqual("DUAL_WRITE_LEGACY_AUTHORITATIVE", self.runtime.approve_cutover(
            TENANT, PROJECT, first, "operator-two", initial_evidence, now=NOW,
        ))

        self.runtime.import_backfill_page(TENANT, PROJECT, "payments", [
            {"sourcePosition": 0, "sourceRecordId": "legacy-1", "amountMinor": 100},
            {"sourcePosition": 1, "sourceRecordId": "legacy-2", "amountMinor": 200},
        ], now=NOW)
        journal = self.record(operation="operation-2", key="idempotency-key-2")
        self.assertEqual(["legacy", "platform"], journal["targets"])
        with self.assertRaisesRegex(ValidationError, "matched, fully acknowledged"):
            self.runtime.propose_cutover(
                TENANT, PROJECT, "DUAL_WRITE_PLATFORM_AUTHORITATIVE",
                EVIDENCE, "operator-one", now=NOW,
            )
        for target in ("legacy", "platform"):
            lease = self.runtime.claim_delivery(
                TENANT, PROJECT, target, "delivery-worker", now=NOW,
            )
            self.assertIsNotNone(lease)
            assert lease is not None
            self.runtime.acknowledge_delivery(lease, lease.payload_digest, now=NOW)
        cutover = self.runtime.propose_cutover(
            TENANT, PROJECT, "DUAL_WRITE_PLATFORM_AUTHORITATIVE",
            EVIDENCE, "operator-one", now=NOW,
        )
        with self.assertRaisesRegex(ValidationError, "count reconciliation failed"):
            self.runtime.approve_cutover(
                TENANT, PROJECT, cutover, "operator-two",
                dict(EVIDENCE, platformCount=3), now=NOW,
            )
        self.assertEqual("DUAL_WRITE_PLATFORM_AUTHORITATIVE", self.runtime.approve_cutover(
            TENANT, PROJECT, cutover, "operator-two", EVIDENCE, now=NOW,
        ))
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertGreaterEqual(connection.execute(
                "SELECT COUNT(*) FROM service_migration_audit"
            ).fetchone()[0], 6)


if __name__ == "__main__":
    unittest.main()
