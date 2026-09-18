"""Shared SQLite transaction boundary for B118-B127 offline control planes."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Iterator

from .common import ValidationError


MIGRATION = Path(__file__).resolve().parents[1] / "migrations/V120_127__release_control.sql"


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, traceback))
        finally:
            self.close()


class DurableStore:
    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        if self.database == ":memory:":
            raise ValidationError("durable controls require a filesystem-backed SQLite database")
        path = Path(self.database)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not MIGRATION.is_file():
            raise ValidationError("release-control database migration is missing")
        with self.connect() as connection:
            connection.executescript(MIGRATION.read_text(encoding="utf-8"))
            self._upgrade_legacy_schema(connection)

    @staticmethod
    def _upgrade_legacy_schema(connection: sqlite3.Connection) -> None:
        """Apply the one safe additive upgrade needed by existing control DBs.

        Historical usage rows cannot be assigned a pricing version without
        inventing billing provenance, so the upgrade intentionally leaves the
        new column NULL. Invoice issuance fails closed on those rows while all
        newly metered usage is required to persist an exact version binding.
        """

        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(usage_event)").fetchall()
        }
        if "pricing_version_id" not in columns:
            connection.execute(
                "ALTER TABLE usage_event ADD COLUMN pricing_version_id TEXT "
                "REFERENCES pricing_version(pricing_version_id)"
            )
        export_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(commercial_audit_export)"
            ).fetchall()
        }
        if "manifest_json" not in export_columns:
            connection.execute(
                "ALTER TABLE commercial_audit_export ADD COLUMN manifest_json TEXT"
            )
        if "receipt_json" not in export_columns:
            connection.execute(
                "ALTER TABLE commercial_audit_export ADD COLUMN receipt_json TEXT"
            )
        reconciliation_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(reconciliation_source_receipt)"
            ).fetchall()
        }
        if "receipt_json" not in reconciliation_columns:
            connection.execute(
                "ALTER TABLE reconciliation_source_receipt ADD COLUMN receipt_json TEXT"
            )
        invoice_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(customer_invoice)"
            ).fetchall()
        }
        if invoice_columns:
            if "idempotency_payload_digest" not in invoice_columns:
                connection.execute(
                    "ALTER TABLE customer_invoice ADD COLUMN idempotency_payload_digest TEXT"
                )
            if "split_batch_id" not in invoice_columns:
                connection.execute(
                    "ALTER TABLE customer_invoice ADD COLUMN split_batch_id TEXT"
                )
            if "split_index" not in invoice_columns:
                connection.execute(
                    "ALTER TABLE customer_invoice ADD COLUMN split_index INTEGER NOT NULL DEFAULT 1"
                )
            if "split_count" not in invoice_columns:
                connection.execute(
                    "ALTER TABLE customer_invoice ADD COLUMN split_count INTEGER NOT NULL DEFAULT 1"
                )
            if "settled_amount_minor" not in invoice_columns:
                connection.execute(
                    "ALTER TABLE customer_invoice ADD COLUMN settled_amount_minor INTEGER NOT NULL DEFAULT 0"
                )
            if "settlement_status" not in invoice_columns:
                connection.execute(
                    "ALTER TABLE customer_invoice ADD COLUMN settlement_status TEXT NOT NULL DEFAULT 'UNSETTLED'"
                )
        item_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(customer_invoice_item)"
            ).fetchall()
        }
        if item_columns and "tax_classification_code" not in item_columns:
            connection.execute(
                "ALTER TABLE customer_invoice_item ADD COLUMN tax_classification_code TEXT"
            )
        quota_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(customer_invoice_quota)"
            ).fetchall()
        }
        if quota_columns and "alarm_threshold_pct" not in quota_columns:
            connection.execute(
                "ALTER TABLE customer_invoice_quota ADD COLUMN alarm_threshold_pct INTEGER NOT NULL DEFAULT 85"
            )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS customer_invoice_payment_ref ("
            "  ref_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  invoice_id TEXT NOT NULL REFERENCES customer_invoice(invoice_id),"
            "  payment_intent_id TEXT NOT NULL,"
            "  invoiced_amount_minor INTEGER NOT NULL CHECK(invoiced_amount_minor >= 0),"
            "  created_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, invoice_id, payment_intent_id)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_inv_pay_ref_tenant_pi ON customer_invoice_payment_ref(tenant_id, payment_intent_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS customer_invoice_delivery ("
            "  delivery_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  invoice_id TEXT NOT NULL REFERENCES customer_invoice(invoice_id),"
            "  channel TEXT NOT NULL CHECK(channel IN ('EMAIL', 'SMS', 'WEBHOOK')),"
            "  destination TEXT NOT NULL,"
            "  status TEXT NOT NULL CHECK(status IN ('PENDING', 'SENT', 'DELIVERED', 'FAILED')),"
            "  attempts INTEGER NOT NULL DEFAULT 1,"
            "  error_message TEXT,"
            "  payload_digest TEXT,"
            "  sent_at TEXT,"
            "  delivered_at TEXT,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_inv_delivery_tenant_inv ON customer_invoice_delivery(tenant_id, invoice_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS customer_invoice_reimbursement ("
            "  reimbursement_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  invoice_id TEXT NOT NULL REFERENCES customer_invoice(invoice_id),"
            "  claim_id TEXT NOT NULL,"
            "  claimant TEXT NOT NULL,"
            "  department TEXT NOT NULL,"
            "  expense_category TEXT NOT NULL,"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  status TEXT NOT NULL CHECK(status IN ('SUBMITTED', 'APPROVED', 'REJECTED')),"
            "  claimed_at TEXT NOT NULL,"
            "  created_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, invoice_id)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_inv_reimb_tenant_claim ON customer_invoice_reimbursement(tenant_id, claim_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS customer_invoice_settlement_reconciliation ("
            "  reconciliation_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  invoice_id TEXT NOT NULL REFERENCES customer_invoice(invoice_id),"
            "  settlement_ref TEXT NOT NULL,"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  reconciled_by TEXT NOT NULL,"
            "  notes TEXT,"
            "  reconciled_at TEXT NOT NULL,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_inv_settle_reconcile_tenant_inv ON customer_invoice_settlement_reconciliation(tenant_id, invoice_id)"
        )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database,
            timeout=10,
            isolation_level=None,
            factory=_ClosingConnection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
