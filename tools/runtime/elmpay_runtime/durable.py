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
        connection.execute(
            "CREATE TABLE IF NOT EXISTS commercial_contract ("
            "  contract_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  title TEXT NOT NULL,"
            "  buyer_name TEXT NOT NULL,"
            "  buyer_tax_number TEXT,"
            "  seller_name TEXT NOT NULL,"
            "  seller_tax_number TEXT NOT NULL,"
            "  total_amount_minor INTEGER NOT NULL CHECK(total_amount_minor > 0),"
            "  currency TEXT NOT NULL DEFAULT 'CNY',"
            "  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'COMPLETED', 'TERMINATED')),"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_contract_tenant ON commercial_contract(tenant_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS contract_milestone ("
            "  milestone_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  contract_id TEXT NOT NULL REFERENCES commercial_contract(contract_id),"
            "  seq_order INTEGER NOT NULL CHECK(seq_order >= 1),"
            "  name TEXT NOT NULL,"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  invoiced_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(invoiced_amount_minor >= 0),"
            "  status TEXT NOT NULL CHECK(status IN ('PENDING', 'PARTIALLY_INVOICED', 'FULLY_INVOICED', 'SETTLED')),"
            "  due_date TEXT,"
            "  created_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, contract_id, seq_order)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_contract_milestone_cid ON contract_milestone(tenant_id, contract_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS contract_fulfillment_ledger ("
            "  entry_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  contract_id TEXT NOT NULL REFERENCES commercial_contract(contract_id),"
            "  milestone_id TEXT REFERENCES contract_milestone(milestone_id),"
            "  invoice_id TEXT,"
            "  entry_type TEXT NOT NULL CHECK(entry_type IN ('MILESTONE_INVOICED', 'PAYMENT_APPLIED', 'ADJUSTMENT')),"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  actor_id TEXT NOT NULL,"
            "  notes TEXT,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_contract_ledger_cid ON contract_fulfillment_ledger(tenant_id, contract_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS tax_withholding_certificate ("
            "  certificate_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  certificate_number TEXT NOT NULL UNIQUE,"
            "  payee_type TEXT NOT NULL CHECK(payee_type IN ('INDIVIDUAL', 'ENTERPRISE_NON_RESIDENT')),"
            "  payee_name TEXT NOT NULL,"
            "  payee_id_type TEXT NOT NULL DEFAULT 'RESIDENT_ID',"
            "  payee_id_number TEXT NOT NULL,"
            "  income_type TEXT NOT NULL CHECK(income_type IN ('LABOR_SERVICE', 'ROYALTY', 'PROPERTY_LEASING', 'NON_RESIDENT_WHT')),"
            "  gross_amount_minor INTEGER NOT NULL CHECK(gross_amount_minor > 0),"
            "  statutory_deduction_minor INTEGER NOT NULL CHECK(statutory_deduction_minor >= 0),"
            "  taxable_income_minor INTEGER NOT NULL CHECK(taxable_income_minor >= 0),"
            "  tax_rate_basis_points INTEGER NOT NULL CHECK(tax_rate_basis_points >= 0),"
            "  quick_deduction_minor INTEGER NOT NULL CHECK(quick_deduction_minor >= 0),"
            "  tax_withheld_minor INTEGER NOT NULL CHECK(tax_withheld_minor >= 0),"
            "  net_payout_minor INTEGER NOT NULL CHECK(net_payout_minor >= 0),"
            "  filing_status TEXT NOT NULL CHECK(filing_status IN ('RECORDED', 'SUBMITTED', 'REMITTED')),"
            "  digest TEXT NOT NULL,"
            "  issued_at TEXT NOT NULL,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_tax_withhold_tenant ON tax_withholding_certificate(tenant_id, filing_status)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS tax_remittance_batch ("
            "  batch_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  tax_period TEXT NOT NULL,"
            "  item_count INTEGER NOT NULL CHECK(item_count > 0),"
            "  total_gross_minor INTEGER NOT NULL CHECK(total_gross_minor >= 0),"
            "  total_tax_withheld_minor INTEGER NOT NULL CHECK(total_tax_withheld_minor >= 0),"
            "  batch_digest TEXT NOT NULL,"
            "  status TEXT NOT NULL CHECK(status IN ('PREPARED', 'DECLARED', 'ACCEPTED')),"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_tax_remit_tenant_period ON tax_remittance_batch(tenant_id, tax_period)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS customs_payment_declaration ("
            "  declaration_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  customs_code TEXT NOT NULL,"
            "  ebp_code TEXT NOT NULL,"
            "  ebc_code TEXT NOT NULL,"
            "  order_no TEXT NOT NULL,"
            "  payment_intent_id TEXT NOT NULL,"
            "  payer_name TEXT NOT NULL,"
            "  payer_id_type TEXT NOT NULL DEFAULT '1',"
            "  payer_id_number TEXT NOT NULL,"
            "  payer_phone TEXT NOT NULL,"
            "  currency TEXT NOT NULL DEFAULT '142',"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  status TEXT NOT NULL CHECK(status IN ('PENDING', 'REPORTED', 'CUSTOMS_ACCEPTED', 'CUSTOMS_REJECTED')),"
            "  customs_receipt_code TEXT,"
            "  customs_receipt_message TEXT,"
            "  signature_digest TEXT NOT NULL,"
            "  declared_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, order_no, payment_intent_id)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_customs_decl_tenant_order ON customs_payment_declaration(tenant_id, order_no)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS customs_declaration_log ("
            "  log_id TEXT PRIMARY KEY,"
            "  declaration_id TEXT NOT NULL REFERENCES customs_payment_declaration(declaration_id),"
            "  action TEXT NOT NULL,"
            "  request_payload TEXT NOT NULL,"
            "  response_payload TEXT,"
            "  status TEXT NOT NULL,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_customs_log_decl ON customs_declaration_log(declaration_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS treasury_pool ("
            "  pool_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL UNIQUE,"
            "  pool_name TEXT NOT NULL,"
            "  master_account_id TEXT NOT NULL,"
            "  master_balance_minor INTEGER NOT NULL DEFAULT 0 CHECK(master_balance_minor >= 0),"
            "  currency TEXT NOT NULL DEFAULT 'CNY',"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_treasury_pool_tenant ON treasury_pool(tenant_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS treasury_virtual_account ("
            "  va_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  pool_id TEXT NOT NULL REFERENCES treasury_pool(pool_id),"
            "  account_number TEXT NOT NULL UNIQUE,"
            "  account_name TEXT NOT NULL,"
            "  entity_type TEXT NOT NULL CHECK(entity_type IN ('STORE', 'BRANCH', 'DISTRIBUTOR', 'MERCHANT')),"
            "  balance_minor INTEGER NOT NULL DEFAULT 0 CHECK(balance_minor >= 0),"
            "  sweep_policy TEXT NOT NULL CHECK(sweep_policy IN ('ZERO_BALANCE', 'TARGET_BALANCE', 'MANUAL')),"
            "  target_balance_minor INTEGER NOT NULL DEFAULT 0 CHECK(target_balance_minor >= 0),"
            "  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'FROZEN', 'CLOSED')),"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_treasury_va_tenant_pool ON treasury_virtual_account(tenant_id, pool_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS treasury_transfer_journal ("
            "  journal_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  pool_id TEXT NOT NULL REFERENCES treasury_pool(pool_id),"
            "  source_account_id TEXT NOT NULL,"
            "  dest_account_id TEXT NOT NULL,"
            "  transfer_type TEXT NOT NULL CHECK(transfer_type IN ('SWEEP', 'ALLOCATE', 'DEPOSIT', 'WITHDRAWAL')),"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  source_balance_after_minor INTEGER NOT NULL CHECK(source_balance_after_minor >= 0),"
            "  dest_balance_after_minor INTEGER NOT NULL CHECK(dest_balance_after_minor >= 0),"
            "  actor_id TEXT NOT NULL,"
            "  notes TEXT,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_treasury_journal_tenant_pool ON treasury_transfer_journal(tenant_id, pool_id)"
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
