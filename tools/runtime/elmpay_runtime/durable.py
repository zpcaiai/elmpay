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

        connection.execute(
            "CREATE TABLE IF NOT EXISTS fx_rate_matrix ("
            "  matrix_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  base_currency TEXT NOT NULL CHECK(length(base_currency)=3),"
            "  target_currency TEXT NOT NULL CHECK(length(target_currency)=3),"
            "  spot_rate_units INTEGER NOT NULL CHECK(spot_rate_units > 0),"
            "  spread_basis_points INTEGER NOT NULL DEFAULT 50 CHECK(spread_basis_points >= 0),"
            "  effective_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, base_currency, target_currency)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_fx_matrix_tenant_cur ON fx_rate_matrix(tenant_id, base_currency, target_currency)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS fx_quote_lock ("
            "  quote_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  base_currency TEXT NOT NULL CHECK(length(base_currency)=3),"
            "  target_currency TEXT NOT NULL CHECK(length(target_currency)=3),"
            "  source_amount_minor INTEGER NOT NULL CHECK(source_amount_minor > 0),"
            "  target_amount_minor INTEGER NOT NULL CHECK(target_amount_minor > 0),"
            "  spot_rate_units INTEGER NOT NULL CHECK(spot_rate_units > 0),"
            "  spread_basis_points INTEGER NOT NULL CHECK(spread_basis_points >= 0),"
            "  effective_rate_units INTEGER NOT NULL CHECK(effective_rate_units > 0),"
            "  status TEXT NOT NULL CHECK(status IN ('LOCKED', 'REDEEMED', 'EXPIRED', 'CANCELLED')),"
            "  expires_at TEXT NOT NULL,"
            "  redeemed_at TEXT,"
            "  payment_intent_id TEXT,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_fx_quote_tenant_status ON fx_quote_lock(tenant_id, status)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS fx_conversion_journal ("
            "  conversion_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  quote_id TEXT NOT NULL REFERENCES fx_quote_lock(quote_id),"
            "  payment_intent_id TEXT NOT NULL,"
            "  base_currency TEXT NOT NULL CHECK(length(base_currency)=3),"
            "  target_currency TEXT NOT NULL CHECK(length(target_currency)=3),"
            "  source_amount_minor INTEGER NOT NULL CHECK(source_amount_minor > 0),"
            "  target_amount_minor INTEGER NOT NULL CHECK(target_amount_minor > 0),"
            "  executed_rate_units INTEGER NOT NULL CHECK(executed_rate_units > 0),"
            "  hedged INTEGER NOT NULL DEFAULT 0 CHECK(hedged IN (0, 1)),"
            "  executed_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_fx_journal_tenant_pi ON fx_conversion_journal(tenant_id, payment_intent_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS b2b_credit_facility ("
            "  facility_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  buyer_id TEXT NOT NULL,"
            "  buyer_name TEXT NOT NULL,"
            "  credit_limit_minor INTEGER NOT NULL CHECK(credit_limit_minor > 0),"
            "  drawn_balance_minor INTEGER NOT NULL DEFAULT 0 CHECK(drawn_balance_minor >= 0),"
            "  currency TEXT NOT NULL DEFAULT 'CNY' CHECK(length(currency)=3),"
            "  credit_tier TEXT NOT NULL CHECK(credit_tier IN ('STANDARD', 'PRIME', 'ENTERPRISE')),"
            "  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'FROZEN', 'CLOSED')),"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, buyer_id)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_b2b_facility_tenant_buyer ON b2b_credit_facility(tenant_id, buyer_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS b2b_purchase_order ("
            "  po_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  facility_id TEXT NOT NULL REFERENCES b2b_credit_facility(facility_id),"
            "  po_number TEXT NOT NULL,"
            "  buyer_id TEXT NOT NULL,"
            "  seller_name TEXT NOT NULL,"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  payment_terms TEXT NOT NULL CHECK(payment_terms IN ('DUE_ON_RECEIPT', 'NET_15', 'NET_30', 'NET_60', 'NET_90')),"
            "  issue_date TEXT NOT NULL,"
            "  due_date TEXT NOT NULL,"
            "  settled_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(settled_amount_minor >= 0),"
            "  status TEXT NOT NULL CHECK(status IN ('ISSUED', 'PARTIALLY_SETTLED', 'SETTLED', 'CANCELLED', 'OVERDUE')),"
            "  created_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, po_number)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_b2b_po_tenant_buyer ON b2b_purchase_order(tenant_id, buyer_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_b2b_po_tenant_status ON b2b_purchase_order(tenant_id, status)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS b2b_credit_drawdown_ledger ("
            "  entry_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  facility_id TEXT NOT NULL REFERENCES b2b_credit_facility(facility_id),"
            "  po_id TEXT REFERENCES b2b_purchase_order(po_id),"
            "  action TEXT NOT NULL CHECK(action IN ('DRAWDOWN', 'REPAYMENT', 'LIMIT_ADJUSTMENT', 'PENALTY_ACCRUED')),"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  balance_after_minor INTEGER NOT NULL CHECK(balance_after_minor >= 0),"
            "  notes TEXT,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_b2b_ledger_facility ON b2b_credit_drawdown_ledger(facility_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS mass_payout_batch ("
            "  batch_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  batch_name TEXT NOT NULL,"
            "  currency TEXT NOT NULL DEFAULT 'CNY' CHECK(length(currency)=3),"
            "  total_count INTEGER NOT NULL CHECK(total_count > 0),"
            "  total_amount_minor INTEGER NOT NULL CHECK(total_amount_minor > 0),"
            "  total_fee_minor INTEGER NOT NULL DEFAULT 0 CHECK(total_fee_minor >= 0),"
            "  status TEXT NOT NULL CHECK(status IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'PROCESSING', 'COMPLETED', 'PARTIALLY_FAILED', 'REJECTED')),"
            "  maker_id TEXT NOT NULL,"
            "  checker_id TEXT,"
            "  approved_at TEXT,"
            "  batch_digest TEXT NOT NULL CHECK(length(batch_digest)=64),"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_payout_batch_tenant_status ON mass_payout_batch(tenant_id, status)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS mass_payout_item ("
            "  item_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  batch_id TEXT NOT NULL REFERENCES mass_payout_batch(batch_id),"
            "  recipient_id TEXT NOT NULL,"
            "  recipient_name TEXT NOT NULL,"
            "  channel TEXT NOT NULL CHECK(channel IN ('BANK_WIRE', 'ALIPAY', 'WECHAT_PAY', 'PAYPAL', 'SEPA')),"
            "  account_identifier TEXT NOT NULL,"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  fee_minor INTEGER NOT NULL DEFAULT 0 CHECK(fee_minor >= 0),"
            "  status TEXT NOT NULL CHECK(status IN ('PENDING', 'PROCESSING', 'SUCCESS', 'FAILED', 'REVERSED')),"
            "  failure_reason TEXT,"
            "  channel_reference TEXT,"
            "  executed_at TEXT,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_payout_item_batch ON mass_payout_item(batch_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS card_vault ("
            "  vault_token TEXT PRIMARY KEY,"
            "  network_token TEXT UNIQUE,"
            "  tenant_id TEXT NOT NULL,"
            "  customer_id TEXT NOT NULL,"
            "  card_brand TEXT NOT NULL CHECK(card_brand IN ('VISA', 'MASTERCARD', 'AMEX', 'UNIONPAY', 'JCB', 'DISCOVER')),"
            "  bin_first6 TEXT NOT NULL CHECK(length(bin_first6)=6),"
            "  last4 TEXT NOT NULL CHECK(length(last4)=4),"
            "  exp_month INTEGER NOT NULL CHECK(exp_month BETWEEN 1 AND 12),"
            "  exp_year INTEGER NOT NULL CHECK(exp_year >= 2024),"
            "  cardholder_name TEXT NOT NULL,"
            "  fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64),"
            "  encrypted_pan_envelope TEXT NOT NULL,"
            "  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),"
            "  token_requester_id TEXT NOT NULL DEFAULT 'TRID_ELMPAY_400',"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, customer_id, fingerprint)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_card_vault_tenant_cust ON card_vault(tenant_id, customer_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS card_updater_event ("
            "  event_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  vault_token TEXT NOT NULL REFERENCES card_vault(vault_token),"
            "  event_type TEXT NOT NULL CHECK(event_type IN ('EXPIRY_UPDATE', 'CARD_REPLACED', 'ACCOUNT_CLOSED', 'CONTACT_CARDHOLDER')),"
            "  old_exp_month INTEGER,"
            "  old_exp_year INTEGER,"
            "  new_exp_month INTEGER,"
            "  new_exp_year INTEGER,"
            "  new_last4 TEXT,"
            "  processed_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_card_updater_token ON card_updater_event(vault_token)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS routing_provider_profile ("
            "  profile_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  provider_id TEXT NOT NULL,"
            "  provider_name TEXT NOT NULL,"
            "  supported_methods_csv TEXT NOT NULL,"
            "  supported_currencies_csv TEXT NOT NULL,"
            "  min_amount_minor INTEGER NOT NULL DEFAULT 1 CHECK(min_amount_minor >= 0),"
            "  max_amount_minor INTEGER NOT NULL CHECK(max_amount_minor > 0),"
            "  fee_basis_points INTEGER NOT NULL CHECK(fee_basis_points >= 0),"
            "  fixed_fee_minor INTEGER NOT NULL DEFAULT 0 CHECK(fixed_fee_minor >= 0),"
            "  health_status TEXT NOT NULL CHECK(health_status IN ('HEALTHY', 'DEGRADED', 'CIRCUIT_BROKEN')),"
            "  priority_rank INTEGER NOT NULL DEFAULT 100,"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, provider_id)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_routing_profile_tenant ON routing_provider_profile(tenant_id, health_status)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS smart_routing_decision_log ("
            "  decision_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  payment_intent_id TEXT NOT NULL,"
            "  amount_minor INTEGER NOT NULL,"
            "  currency TEXT NOT NULL,"
            "  payment_method TEXT NOT NULL,"
            "  card_brand TEXT,"
            "  selected_provider_id TEXT NOT NULL,"
            "  estimated_fee_minor INTEGER NOT NULL,"
            "  cascade_routes_json TEXT NOT NULL,"
            "  routed_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_routing_decision_pi ON smart_routing_decision_log(tenant_id, payment_intent_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS merchant_fee_schedule ("
            "  schedule_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL UNIQUE,"
            "  pricing_model TEXT NOT NULL CHECK(pricing_model IN ('BLENDED', 'TIERED_VOLUME', 'INTERCHANGE_PLUS_PLUS')),"
            "  tiers_json TEXT,"
            "  markup_basis_points INTEGER NOT NULL DEFAULT 30 CHECK(markup_basis_points >= 0),"
            "  fixed_fee_minor INTEGER NOT NULL DEFAULT 30 CHECK(fixed_fee_minor >= 0),"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL"
            ")"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS merchant_fee_journal ("
            "  journal_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  transaction_id TEXT NOT NULL,"
            "  amount_minor INTEGER NOT NULL,"
            "  currency TEXT NOT NULL,"
            "  pricing_model TEXT NOT NULL,"
            "  gross_fee_minor INTEGER NOT NULL,"
            "  interchange_cost_minor INTEGER NOT NULL DEFAULT 0,"
            "  scheme_assessment_minor INTEGER NOT NULL DEFAULT 0,"
            "  net_margin_minor INTEGER NOT NULL,"
            "  billed_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_fee_journal_tenant_txn ON merchant_fee_journal(tenant_id, transaction_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS webhook_endpoint_subscription ("
            "  endpoint_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  url TEXT NOT NULL,"
            "  secret_key TEXT NOT NULL,"
            "  subscribed_events_csv TEXT NOT NULL,"
            "  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'DISABLED')),"
            "  created_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, url)"
            ")"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS webhook_event_queue ("
            "  event_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  endpoint_id TEXT NOT NULL REFERENCES webhook_endpoint_subscription(endpoint_id),"
            "  event_type TEXT NOT NULL,"
            "  payload_json TEXT NOT NULL,"
            "  signature_header TEXT NOT NULL,"
            "  status TEXT NOT NULL CHECK(status IN ('PENDING', 'DELIVERED', 'RETRYING', 'DEAD_LETTER')),"
            "  attempt_count INTEGER NOT NULL DEFAULT 0,"
            "  max_attempts INTEGER NOT NULL DEFAULT 5,"
            "  last_http_status INTEGER,"
            "  last_error_message TEXT,"
            "  next_delivery_at TEXT NOT NULL,"
            "  created_at TEXT NOT NULL,"
            "  delivered_at TEXT"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_webhook_queue_status ON webhook_event_queue(tenant_id, status, next_delivery_at)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS webhook_dead_letter ("
            "  dead_letter_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  event_id TEXT NOT NULL UNIQUE REFERENCES webhook_event_queue(event_id),"
            "  endpoint_id TEXT NOT NULL,"
            "  event_type TEXT NOT NULL,"
            "  final_error TEXT NOT NULL,"
            "  replayed_at TEXT,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_webhook_dlq_tenant ON webhook_dead_letter(tenant_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS marketplace_split_order ("
            "  order_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  captured_amount_minor INTEGER NOT NULL CHECK(captured_amount_minor > 0),"
            "  currency TEXT NOT NULL,"
            "  platform_fee_minor INTEGER NOT NULL CHECK(platform_fee_minor >= 0),"
            "  escrow_status TEXT NOT NULL CHECK(escrow_status IN ('HELD', 'RELEASED', 'REFUNDED', 'PARTIALLY_REFUNDED')),"
            "  hold_until TEXT NOT NULL,"
            "  released_at TEXT,"
            "  refunded_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(refunded_amount_minor >= 0),"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_split_order_tenant_status ON marketplace_split_order(tenant_id, escrow_status)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS marketplace_split_recipient ("
            "  recipient_split_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  order_id TEXT NOT NULL REFERENCES marketplace_split_order(order_id),"
            "  vendor_id TEXT NOT NULL,"
            "  allocated_amount_minor INTEGER NOT NULL CHECK(allocated_amount_minor > 0),"
            "  settled_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(settled_amount_minor >= 0),"
            "  refunded_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(refunded_amount_minor >= 0),"
            "  status TEXT NOT NULL CHECK(status IN ('PENDING', 'RELEASED', 'REFUNDED')),"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_split_recip_order ON marketplace_split_recipient(order_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS recon_statement_batch ("
            "  batch_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  channel_id TEXT NOT NULL,"
            "  statement_date TEXT NOT NULL,"
            "  file_name TEXT NOT NULL,"
            "  file_digest TEXT NOT NULL CHECK(length(file_digest)=64),"
            "  total_records INTEGER NOT NULL DEFAULT 0 CHECK(total_records >= 0),"
            "  total_amount_minor INTEGER NOT NULL DEFAULT 0,"
            "  currency TEXT NOT NULL,"
            "  status TEXT NOT NULL CHECK(status IN ('INGESTED', 'RECONCILED', 'DISCREPANCY_FOUND')),"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_recon_batch_tenant ON recon_statement_batch(tenant_id, channel_id, statement_date)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS recon_statement_item ("
            "  item_id TEXT PRIMARY KEY,"
            "  batch_id TEXT NOT NULL REFERENCES recon_statement_batch(batch_id),"
            "  tenant_id TEXT NOT NULL,"
            "  channel_txn_id TEXT NOT NULL,"
            "  internal_txn_id TEXT,"
            "  amount_minor INTEGER NOT NULL,"
            "  fee_minor INTEGER NOT NULL DEFAULT 0,"
            "  currency TEXT NOT NULL,"
            "  txn_type TEXT NOT NULL CHECK(txn_type IN ('PAYMENT', 'REFUND', 'DISPUTE_DEBIT', 'FEE')),"
            "  settled_at TEXT NOT NULL,"
            "  recon_status TEXT NOT NULL CHECK(recon_status IN ('UNMATCHED', 'MATCHED', 'DISCREPANCY')),"
            "  discrepancy_reason TEXT,"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_recon_item_lookup ON recon_statement_item(tenant_id, channel_txn_id, internal_txn_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS recon_discrepancy_journal ("
            "  discrepancy_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  batch_id TEXT NOT NULL,"
            "  item_id TEXT,"
            "  internal_txn_id TEXT,"
            "  channel_txn_id TEXT,"
            "  discrepancy_type TEXT NOT NULL CHECK(discrepancy_type IN ('UNILATERAL_PLATFORM_MISSING', 'UNILATERAL_CHANNEL_MISSING', 'AMOUNT_MISMATCH', 'FEE_DISCREPANCY')),"
            "  delta_amount_minor INTEGER NOT NULL,"
            "  currency TEXT NOT NULL,"
            "  status TEXT NOT NULL CHECK(status IN ('OPEN', 'PENDING_APPROVAL', 'RESOLVED', 'WRITTEN_OFF')),"
            "  proposed_action TEXT,"
            "  maker_id TEXT,"
            "  checker_id TEXT,"
            "  resolution_notes TEXT,"
            "  created_at TEXT NOT NULL,"
            "  resolved_at TEXT"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_recon_disc_tenant ON recon_discrepancy_journal(tenant_id, status)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS recurring_mandate_agreement ("
            "  mandate_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  customer_id TEXT NOT NULL,"
            "  payment_method_ref TEXT NOT NULL,"
            "  mandate_type TEXT NOT NULL CHECK(mandate_type IN ('SEPA_DIRECT_DEBIT', 'BACS_DIRECT_DEBIT', 'CHINA_BANK_DEBIT', 'CARD_RECURRING_TOKEN')),"
            "  status TEXT NOT NULL CHECK(status IN ('PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED', 'REVOKED')),"
            "  max_amount_per_charge_minor INTEGER NOT NULL CHECK(max_amount_per_charge_minor > 0),"
            "  currency TEXT NOT NULL,"
            "  signature_digest TEXT NOT NULL CHECK(length(signature_digest)=64),"
            "  signed_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_mandate_cust ON recurring_mandate_agreement(tenant_id, customer_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS dunning_process_schedule ("
            "  dunning_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  mandate_id TEXT NOT NULL REFERENCES recurring_mandate_agreement(mandate_id),"
            "  invoice_id TEXT NOT NULL,"
            "  attempt_count INTEGER NOT NULL DEFAULT 1 CHECK(attempt_count >= 1),"
            "  max_attempts INTEGER NOT NULL DEFAULT 4 CHECK(max_attempts >= 1),"
            "  decline_type TEXT NOT NULL CHECK(decline_type IN ('SOFT', 'HARD')),"
            "  decline_code TEXT NOT NULL,"
            "  status TEXT NOT NULL CHECK(status IN ('IN_PROGRESS', 'RECOVERED', 'EXHAUSTED')),"
            "  next_retry_at TEXT,"
            "  last_notified_at TEXT,"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_dunning_status ON dunning_process_schedule(tenant_id, status, next_retry_at)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS aml_sanctions_watchlist ("
            "  entry_id TEXT PRIMARY KEY,"
            "  list_source TEXT NOT NULL CHECK(list_source IN ('OFAC_SDN', 'UN_CONSOLIDATED', 'EU_SANCTIONS', 'MOFCOM_CHINA')),"
            "  entity_name TEXT NOT NULL,"
            "  entity_type TEXT NOT NULL CHECK(entity_type IN ('INDIVIDUAL', 'ORGANIZATION', 'VESSEL')),"
            "  country_iso TEXT NOT NULL,"
            "  aliases_csv TEXT,"
            "  added_at TEXT NOT NULL,"
            "  is_active INTEGER NOT NULL DEFAULT 1"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_aml_watchlist_name ON aml_sanctions_watchlist(entity_name)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS aml_screening_log ("
            "  screening_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  entity_name TEXT NOT NULL,"
            "  screening_type TEXT NOT NULL CHECK(screening_type IN ('SANCTIONS', 'PEP', 'ADVERSE_MEDIA')),"
            "  match_confidence INTEGER NOT NULL CHECK(match_confidence >= 0 AND match_confidence <= 100),"
            "  matched_entry_id TEXT,"
            "  decision TEXT NOT NULL CHECK(decision IN ('CLEAR', 'POTENTIAL_MATCH', 'CONFIRMED_BLOCK')),"
            "  screened_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_aml_screen_tenant ON aml_screening_log(tenant_id, decision)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS aml_large_transaction_report ("
            "  report_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  transaction_id TEXT NOT NULL,"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  currency TEXT NOT NULL,"
            "  customer_name TEXT NOT NULL,"
            "  threshold_minor INTEGER NOT NULL,"
            "  report_status TEXT NOT NULL CHECK(report_status IN ('RECORDED', 'FILED', 'EXEMPT')),"
            "  created_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_aml_large_tx ON aml_large_transaction_report(tenant_id, transaction_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS aml_suspicious_activity_log ("
            "  sar_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  customer_id TEXT NOT NULL,"
            "  indicator TEXT NOT NULL CHECK(indicator IN ('STRUCTURING_SMURFING', 'RAPID_VELOCITY', 'HIGH_RISK_GEO')),"
            "  details_json TEXT NOT NULL,"
            "  flagged_at TEXT NOT NULL,"
            "  status TEXT NOT NULL CHECK(status IN ('FLAGGED', 'INVESTIGATING', 'CLEARED', 'REPORTED_FIU'))"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_aml_sar_cust ON aml_suspicious_activity_log(tenant_id, customer_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS subscription_plan ("
            "  plan_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  plan_code TEXT NOT NULL,"
            "  name TEXT NOT NULL,"
            "  billing_interval TEXT NOT NULL CHECK(billing_interval IN ('MONTHLY', 'QUARTERLY', 'ANNUAL')),"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor >= 0),"
            "  currency TEXT NOT NULL,"
            "  created_at TEXT NOT NULL,"
            "  is_active INTEGER NOT NULL DEFAULT 1,"
            "  UNIQUE(tenant_id, plan_code)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_sub_plan_code ON subscription_plan(tenant_id, plan_code)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS customer_subscription ("
            "  subscription_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  customer_id TEXT NOT NULL,"
            "  plan_id TEXT NOT NULL REFERENCES subscription_plan(plan_id),"
            "  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'PAUSED', 'CANCELED')),"
            "  current_period_start TEXT NOT NULL,"
            "  current_period_end TEXT NOT NULL,"
            "  cancel_at_period_end INTEGER NOT NULL DEFAULT 0,"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_cust_sub ON customer_subscription(tenant_id, customer_id, status)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS subscription_proration_adjustment ("
            "  adjustment_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  subscription_id TEXT NOT NULL REFERENCES customer_subscription(subscription_id),"
            "  old_plan_id TEXT NOT NULL,"
            "  new_plan_id TEXT NOT NULL,"
            "  change_type TEXT NOT NULL CHECK(change_type IN ('UPGRADE', 'DOWNGRADE', 'CANCEL_PRORATED')),"
            "  unused_old_credit_minor INTEGER NOT NULL CHECK(unused_old_credit_minor >= 0),"
            "  new_plan_charge_minor INTEGER NOT NULL CHECK(new_plan_charge_minor >= 0),"
            "  net_payable_minor INTEGER NOT NULL,"
            "  credit_balance_applied_minor INTEGER NOT NULL DEFAULT 0,"
            "  final_charge_due_minor INTEGER NOT NULL CHECK(final_charge_due_minor >= 0),"
            "  credit_refunded_to_wallet_minor INTEGER NOT NULL CHECK(credit_refunded_to_wallet_minor >= 0),"
            "  currency TEXT NOT NULL,"
            "  adjusted_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_sub_adj ON subscription_proration_adjustment(tenant_id, subscription_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS customer_credit_ledger ("
            "  credit_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  customer_id TEXT NOT NULL,"
            "  entry_type TEXT NOT NULL CHECK(entry_type IN ('CREDIT_GRANTED', 'CREDIT_CONSUMED', 'REFUND_TO_ORIGINAL')),"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  currency TEXT NOT NULL,"
            "  reason TEXT NOT NULL,"
            "  reference_id TEXT,"
            "  posted_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_cust_credit ON customer_credit_ledger(tenant_id, customer_id, currency)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS financial_double_entry_journal ("
            "  entry_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  sequence_num INTEGER NOT NULL CHECK(sequence_num > 0),"
            "  prev_entry_hash TEXT NOT NULL CHECK(length(prev_entry_hash)=64),"
            "  entry_hash TEXT NOT NULL CHECK(length(entry_hash)=64),"
            "  transaction_type TEXT NOT NULL,"
            "  source_event_id TEXT NOT NULL,"
            "  currency TEXT NOT NULL,"
            "  total_amount_minor INTEGER NOT NULL CHECK(total_amount_minor > 0),"
            "  posted_at TEXT NOT NULL,"
            "  UNIQUE(tenant_id, sequence_num),"
            "  UNIQUE(tenant_id, source_event_id)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_fin_journal_tenant_seq ON financial_double_entry_journal(tenant_id, sequence_num)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS financial_journal_leg ("
            "  leg_id TEXT PRIMARY KEY,"
            "  entry_id TEXT NOT NULL REFERENCES financial_double_entry_journal(entry_id),"
            "  account_code TEXT NOT NULL,"
            "  direction TEXT NOT NULL CHECK(direction IN ('DEBIT', 'CREDIT')),"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0)"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_fin_leg_entry ON financial_journal_leg(entry_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_fin_leg_account ON financial_journal_leg(account_code)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS financial_exception_ticket ("
            "  ticket_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  category TEXT NOT NULL CHECK(category IN ('SURPLUS', 'DEFICIT', 'AMOUNT_MISMATCH', 'TIMING_VARIANCE', 'DUPLICATE_CHARGE')),"
            "  reference_id TEXT NOT NULL,"
            "  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),"
            "  currency TEXT NOT NULL,"
            "  status TEXT NOT NULL CHECK(status IN ('OPEN', 'PENDING_CHECKER', 'APPROVED', 'REJECTED', 'CLOSED_NO_ACTION')),"
            "  maker_id TEXT,"
            "  checker_id TEXT,"
            "  proposed_action TEXT CHECK(proposed_action IS NULL OR proposed_action IN ('MANUAL_POSTING', 'WRITE_OFF', 'REFUND_TO_CUSTOMER', 'CHARGE_BACK_RECOVERY', 'NONE')),"
            "  notes TEXT,"
            "  journal_entry_id TEXT,"
            "  created_at TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_fin_ticket_tenant ON financial_exception_ticket(tenant_id, status)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_fin_ticket_ref ON financial_exception_ticket(tenant_id, reference_id)"
        )

        connection.execute(
            "CREATE TABLE IF NOT EXISTS financial_report_manifest ("
            "  manifest_id TEXT PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  period_start TEXT NOT NULL,"
            "  period_end TEXT NOT NULL,"
            "  currency TEXT NOT NULL,"
            "  metrics_json TEXT NOT NULL,"
            "  manifest_digest TEXT NOT NULL CHECK(length(manifest_digest)=64), "
            "  exported_at TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_fin_report_tenant ON financial_report_manifest(tenant_id, period_start, period_end)"
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
