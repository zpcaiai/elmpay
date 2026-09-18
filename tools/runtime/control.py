#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Any

from elmpay_runtime.billing import calculate_invoice
from elmpay_runtime.capacity import evaluate_capacity
from elmpay_runtime.common import GateReport, ValidationError, read_json
from elmpay_runtime.compliance import evaluate_vendor, evaluate_vulnerability_report
from elmpay_runtime.invoice import (
    CustomerInvoiceLedger,
    export_tax_declaration_csv,
    render_golden_tax_xml,
    render_invoice_batch_html,
    render_invoice_html,
    render_invoice_ofd_manifest,
    verify_invoice_ofd_manifest,
)
from elmpay_runtime.settlement import SettlementLedger, render_settlement_html
from elmpay_runtime.dispute import DisputeLedger
from elmpay_runtime.contract_billing import CommercialContractLedger
from elmpay_runtime.tax_withholding import (
    TaxWithholdingLedger,
    calculate_tax_withholding,
)
from elmpay_runtime.customs_declaration import CustomsPaymentDeclarationManager
from elmpay_runtime.treasury_pool import TreasuryPoolManager
from elmpay_runtime.fx_engine import FXQuoteLockManager
from elmpay_runtime.b2b_credit import B2BCreditManager
from elmpay_runtime.mass_payout import MassPayoutManager
from elmpay_runtime.card_vault import CardVaultManager
from elmpay_runtime.smart_routing import SmartRoutingEngine
from elmpay_runtime.tiered_pricing import TieredPricingEngine
from elmpay_runtime.webhook_engine import EnterpriseWebhookDispatcher, verify_webhook_signature
from elmpay_runtime.marketplace_escrow import MarketplaceEscrowManager
from elmpay_runtime.statement_recon import StatementReconciliationEngine
from elmpay_runtime.mandates_dunning import MandatesDunningEngine
from elmpay_runtime.aml_sanctions import AmlSanctionsEngine
from elmpay_runtime.subscription_proration import SubscriptionProrationEngine
from elmpay_runtime.financial_ledger import FinancialDoubleEntryLedger
from elmpay_runtime.financial_reporting import FinancialExceptionManager, FinancialReportingEngine
from elmpay_runtime.durable import DurableStore
from elmpay_runtime.external_evidence import (
    validate_external_evidence,
    validate_test_evidence_template,
)
from elmpay_runtime.kubernetes import render_workloads, validate_workload_sources
from elmpay_runtime.release import verify_release
from elmpay_runtime.release import release_binding
from elmpay_runtime.rollout import compare_shadow, evaluate_canary, evaluate_go_no_go
from elmpay_runtime.validate import validate_repository


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ELMPay fail-closed runtime and release controls"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser("validate", help="validate owned platform policy")
    validate.add_argument("--root", type=Path, default=REPOSITORY_ROOT)

    render = subcommands.add_parser(
        "render-kubernetes", help="render hardened workloads from digest-pinned images"
    )
    render.add_argument("--images", type=Path, required=True)
    render.add_argument("--policy", type=Path, default=REPOSITORY_ROOT / "platform/kubernetes/workload-policy.json")

    shadow = subcommands.add_parser("shadow-diff", help="compare baseline and side-effect-free shadow output")
    shadow.add_argument("--baseline", type=Path, required=True)
    shadow.add_argument("--candidate", type=Path, required=True)

    canary = subcommands.add_parser("canary", help="evaluate canary auto-stop thresholds")
    canary.add_argument("--baseline", type=Path, required=True)
    canary.add_argument("--candidate", type=Path, required=True)
    canary.add_argument("--policy", type=Path, default=REPOSITORY_ROOT / "platform/rollout/policy.json")

    release = subcommands.add_parser("release-gate", help="verify signed human and external release gates")
    release.add_argument("--manifest", type=Path, required=True)
    release.add_argument("--trust", type=Path, required=True)
    release.add_argument("--policy", type=Path, default=REPOSITORY_ROOT / "platform/compliance/required-release-gates.json")
    release.add_argument(
        "--external-evidence",
        type=Path,
        help="signed external evidence bundle required by the release policy",
    )
    release.add_argument(
        "--external-trust",
        type=Path,
        help="trust material for the external evidence verifier",
    )
    release.add_argument(
        "--external-policy",
        type=Path,
        default=REPOSITORY_ROOT / "platform/compliance/external-evidence-policy.json",
    )

    external = subcommands.add_parser(
        "external-evidence", help="verify independently signed external certification evidence"
    )
    external.add_argument("--bundle", type=Path, required=True)
    external.add_argument("--trust", type=Path, required=True)
    external.add_argument(
        "--policy",
        type=Path,
        default=REPOSITORY_ROOT / "platform/compliance/external-evidence-policy.json",
    )
    external.add_argument(
        "--manifest",
        type=Path,
        help="optional release manifest used to bind the evidence to a commit/artifact/images tuple",
    )

    template = subcommands.add_parser(
        "test-evidence-template",
        help="validate a complete test-only evidence request without certifying it",
    )
    template.add_argument("--template", type=Path, required=True)
    template.add_argument(
        "--policy",
        type=Path,
        default=REPOSITORY_ROOT / "platform/compliance/external-evidence-policy.json",
    )
    template.add_argument(
        "--release-policy",
        type=Path,
        default=REPOSITORY_ROOT / "platform/compliance/required-release-gates.json",
    )

    bill = subcommands.add_parser("bill", help="calculate a deduplicated tenant usage invoice")
    bill.add_argument("--events", type=Path, required=True)
    bill.add_argument("--tenant", required=True)
    bill.add_argument("--period-start", required=True)
    bill.add_argument("--period-end", required=True)
    bill.add_argument("--policy", type=Path, default=REPOSITORY_ROOT / "platform/rollout/billing-policy.json")

    vulnerability = subcommands.add_parser("vulnerability-gate", help="validate complete, fresh artifact-bound scans")
    vulnerability.add_argument("--report", type=Path, required=True)
    vulnerability.add_argument("--artifact-digest", required=True)
    vulnerability.add_argument("--policy", type=Path, default=REPOSITORY_ROOT / "platform/compliance/vulnerability-policy.json")

    vendor = subcommands.add_parser("vendor-gate", help="validate vendor onboarding or renewal controls")
    vendor.add_argument("--assessment", type=Path, required=True)
    vendor.add_argument("--policy", type=Path, default=REPOSITORY_ROOT / "platform/compliance/vendor-policy.json")

    capacity = subcommands.add_parser("capacity-gate", help="evaluate current and forecast resource headroom")
    capacity.add_argument("--samples", type=Path, required=True)
    capacity.add_argument("--policy", type=Path, default=REPOSITORY_ROOT / "platform/observability/capacity.json")

    go_no_go = subcommands.add_parser("go-no-go", help="combine release, shadow, canary, capacity, and operational gates")
    go_no_go.add_argument("--manifest", type=Path, required=True)
    go_no_go.add_argument("--trust", type=Path, required=True)
    go_no_go.add_argument("--shadow-baseline", type=Path, required=True)
    go_no_go.add_argument("--shadow-candidate", type=Path, required=True)
    go_no_go.add_argument("--canary-baseline", type=Path, required=True)
    go_no_go.add_argument("--canary-candidate", type=Path, required=True)
    go_no_go.add_argument("--capacity-samples", type=Path, required=True)
    go_no_go.add_argument("--operations", type=Path, required=True)
    go_no_go.add_argument(
        "--external-evidence",
        type=Path,
        help="signed external evidence bundle; omitted means the Go/No-Go gate is blocked",
    )
    go_no_go.add_argument(
        "--external-trust",
        type=Path,
        help="trust material for the external evidence verifier",
    )
    go_no_go.add_argument(
        "--external-policy",
        type=Path,
        default=REPOSITORY_ROOT / "platform/compliance/external-evidence-policy.json",
    )
    go_no_go.add_argument("--rollout-policy", type=Path, default=REPOSITORY_ROOT / "platform/rollout/policy.json")
    go_no_go.add_argument("--release-policy", type=Path, default=REPOSITORY_ROOT / "platform/compliance/required-release-gates.json")
    go_no_go.add_argument("--capacity-policy", type=Path, default=REPOSITORY_ROOT / "platform/observability/capacity.json")

    inv_bal = subcommands.add_parser("invoice-balance", help="check remaining invoicable balance for a payment intent")
    inv_bal.add_argument("--database", type=Path, required=True)
    inv_bal.add_argument("--tenant", required=True)
    inv_bal.add_argument("--payment-intent", required=True)
    inv_bal.add_argument("--captured-minor", type=int, required=True)
    inv_bal.add_argument("--refunded-minor", type=int, default=0)

    inv_apply = subcommands.add_parser("invoice-apply", help="apply for an enterprise customer invoice")
    inv_apply.add_argument("--database", type=Path, required=True)
    inv_apply.add_argument("--request", type=Path, required=True)

    inv_issue = subcommands.add_parser("invoice-issue", help="approve and issue an applied invoice")
    inv_issue.add_argument("--database", type=Path, required=True)
    inv_issue.add_argument("--tenant", required=True)
    inv_issue.add_argument("--invoice-id", required=True)
    inv_issue.add_argument("--actor", required=True)
    inv_issue.add_argument("--checker")
    inv_issue.add_argument("--payee")

    inv_reject = subcommands.add_parser("invoice-reject", help="reject an applied invoice")
    inv_reject.add_argument("--database", type=Path, required=True)
    inv_reject.add_argument("--tenant", required=True)
    inv_reject.add_argument("--invoice-id", required=True)
    inv_reject.add_argument("--checker", required=True)
    inv_reject.add_argument("--reason", required=True)

    inv_red = subcommands.add_parser("invoice-red-note", help="issue a red note to reverse an issued invoice")
    inv_red.add_argument("--database", type=Path, required=True)
    inv_red.add_argument("--tenant", required=True)
    inv_red.add_argument("--original-invoice-id", required=True)
    inv_red.add_argument("--reason", required=True)
    inv_red.add_argument("--operator", required=True)
    inv_red.add_argument("--red-amount-minor", type=int)
    inv_red.add_argument("--idempotency-key")

    inv_void = subcommands.add_parser("invoice-void", help="void an unfiled or draft/applied invoice")
    inv_void.add_argument("--database", type=Path, required=True)
    inv_void.add_argument("--tenant", required=True)
    inv_void.add_argument("--invoice-id", required=True)
    inv_void.add_argument("--reason", required=True)
    inv_void.add_argument("--operator", required=True)

    inv_verify = subcommands.add_parser("invoice-verify", help="verify an issued invoice with fiscal code")
    inv_verify.add_argument("--database", type=Path, required=True)
    inv_verify.add_argument("--tenant", required=True)
    inv_verify.add_argument("--invoice-id", required=True)
    inv_verify.add_argument("--verification-code", required=True)

    inv_export = subcommands.add_parser("invoice-export", help="export structured invoice ledger for tax/accounting")
    inv_export.add_argument("--database", type=Path, required=True)
    inv_export.add_argument("--tenant", required=True)
    inv_export.add_argument("--start")
    inv_export.add_argument("--end")
    inv_export.add_argument("--status")
    inv_export.add_argument("--limit", type=int, default=1000)

    inv_audit = subcommands.add_parser("invoice-audit-verify", help="verify cryptographic audit chain of customer invoices")
    inv_audit.add_argument("--database", type=Path, required=True)
    inv_audit.add_argument("--tenant", required=True)

    inv_render = subcommands.add_parser("invoice-render", help="render printable HTML or Golden Tax XML invoice")
    inv_render.add_argument("--database", type=Path, required=True)
    inv_render.add_argument("--tenant", required=True)
    inv_render.add_argument("--invoice-id", required=True)
    inv_render.add_argument("--format", choices=["html", "xml"], default="html")
    inv_render.add_argument("--out", type=Path)

    inv_auto = subcommands.add_parser("invoice-auto", help="automatically generate and issue invoice for a payment")
    inv_auto.add_argument("--database", type=Path, required=True)
    inv_auto.add_argument("--tenant", required=True)
    inv_auto.add_argument("--project", required=True)
    inv_auto.add_argument("--payment-intent", required=True)
    inv_auto.add_argument("--buyer-title-id", required=True)
    inv_auto.add_argument("--captured-minor", type=int, required=True)
    inv_auto.add_argument("--refunded-minor", type=int, default=0)
    inv_auto.add_argument("--seller-name", required=True)
    inv_auto.add_argument("--seller-tax-number", required=True)
    inv_auto.add_argument("--operator", required=True)
    inv_auto.add_argument("--actor", required=True)
    inv_auto.add_argument("--idempotency-key", required=True)
    inv_auto.add_argument("--item-name", default="企业支付技术服务费")
    inv_auto.add_argument("--tax-rate-bp", type=int, default=1300)

    inv_rec = subcommands.add_parser("invoice-reconcile", help="cross-reconcile invoice balances against payments")
    inv_rec.add_argument("--database", type=Path, required=True)
    inv_rec.add_argument("--tenant", required=True)
    inv_rec.add_argument("--payments", type=Path)
    inv_rec.add_argument("--start")
    inv_rec.add_argument("--end")

    inv_b_auto = subcommands.add_parser("invoice-batch-auto", help="process batch of payments for automated invoicing")
    inv_b_auto.add_argument("--database", type=Path, required=True)
    inv_b_auto.add_argument("--tenant", required=True)
    inv_b_auto.add_argument("--manifest", type=Path, required=True)
    inv_b_auto.add_argument("--seller-name", required=True)
    inv_b_auto.add_argument("--seller-tax-number", required=True)
    inv_b_auto.add_argument("--operator", default="系统批量开票引擎")
    inv_b_auto.add_argument("--actor", default="batch_engine_service")
    inv_b_auto.add_argument("--checker")
    inv_b_auto.add_argument("--payee")

    inv_ref_red = subcommands.add_parser("invoice-refund-red-note", help="auto-issue red note when a payment is refunded")
    inv_ref_red.add_argument("--database", type=Path, required=True)
    inv_ref_red.add_argument("--tenant", required=True)
    inv_ref_red.add_argument("--payment-intent", required=True)
    inv_ref_red.add_argument("--refund-minor", type=int, required=True)
    inv_ref_red.add_argument("--operator", required=True)
    inv_ref_red.add_argument("--reason", default="原交易发生退款，自动红字冲销")
    inv_ref_red.add_argument("--idempotency-key")

    inv_b_render = subcommands.add_parser("invoice-batch-render", help="render multi-invoice printable booklet")
    inv_b_render.add_argument("--database", type=Path, required=True)
    inv_b_render.add_argument("--tenant", required=True)
    inv_b_render.add_argument("--invoices", type=Path)
    inv_b_render.add_argument("--out", type=Path)
    inv_b_render.add_argument("--title", default="企业电子发票批量装订归档册")

    inv_qc = subcommands.add_parser("invoice-quota-config", help="configure monthly tax invoice quota and single limit")
    inv_qc.add_argument("--database", type=Path, required=True)
    inv_qc.add_argument("--tenant", required=True)
    inv_qc.add_argument("--monthly-quota-minor", type=int, required=True)
    inv_qc.add_argument("--single-limit-minor", type=int, required=True)
    inv_qc.add_argument("--alarm-threshold-pct", type=int, default=85)
    inv_qc.add_argument("--operator", required=True)

    inv_qs = subcommands.add_parser("invoice-quota-status", help="check monthly tax quota and remaining balance")
    inv_qs.add_argument("--database", type=Path, required=True)
    inv_qs.add_argument("--tenant", required=True)
    inv_qs.add_argument("--tax-period")

    inv_sa = subcommands.add_parser("invoice-split-apply", help="apply for an invoice with automatic splitting if over limit")
    inv_sa.add_argument("--database", type=Path, required=True)
    inv_sa.add_argument("--request", type=Path, required=True)
    inv_sa.add_argument("--actor", required=True)
    inv_sa.add_argument("--idempotency-key")

    inv_ssc = subcommands.add_parser("invoice-self-service-create", help="create a time-limited self-service invoice QR session")
    inv_ssc.add_argument("--database", type=Path, required=True)
    inv_ssc.add_argument("--tenant", required=True)
    inv_ssc.add_argument("--payment-intent", required=True)
    inv_ssc.add_argument("--amount-minor", type=int, required=True)
    inv_ssc.add_argument("--created-by", required=True)
    inv_ssc.add_argument("--ttl-hours", type=int, default=72)
    inv_ssc.add_argument("--currency", default="CNY")

    inv_ssr = subcommands.add_parser("invoice-self-service-redeem", help="redeem a self-service session to issue an invoice")
    inv_ssr.add_argument("--database", type=Path, required=True)
    inv_ssr.add_argument("--token", required=True)
    inv_ssr.add_argument("--buyer-name", required=True)
    inv_ssr.add_argument("--buyer-tax-id")
    inv_ssr.add_argument("--buyer-email")
    inv_ssr.add_argument("--buyer-phone")
    inv_ssr.add_argument("--buyer-address-phone")
    inv_ssr.add_argument("--buyer-bank-account")
    inv_ssr.add_argument("--invoice-type", default="VAT_ORDINARY_ELECTRONIC")

    inv_td = subcommands.add_parser("invoice-tax-declaration", help="generate VAT tax declaration auxiliary summary report")
    inv_td.add_argument("--database", type=Path, required=True)
    inv_td.add_argument("--tenant", required=True)
    inv_td.add_argument("--tax-period", required=True)
    inv_td.add_argument("--format", choices=["json", "csv"], default="json")
    inv_td.add_argument("--out", type=Path)

    inv_sub = subcommands.add_parser("invoice-subscription-auto", help="auto-invoice recurring subscription billing")
    inv_sub.add_argument("--database", type=Path, required=True)
    inv_sub.add_argument("--tenant", required=True)
    inv_sub.add_argument("--subscription-id", required=True)
    inv_sub.add_argument("--billing-cycle", required=True)
    inv_sub.add_argument("--amount-minor", type=int, required=True)
    inv_sub.add_argument("--plan-name", required=True)
    inv_sub.add_argument("--buyer-name", required=True)
    inv_sub.add_argument("--buyer-tax-id")
    inv_sub.add_argument("--buyer-email")
    inv_sub.add_argument("--operator", required=True)
    inv_sub.add_argument("--tax-rate-bp", type=int, default=600)
    inv_sub.add_argument("--tax-classification-code", default="3040201010000000000")

    inv_con = subcommands.add_parser("invoice-consolidate", help="consolidate multiple payment intents into a single invoice")
    inv_con.add_argument("--database", type=Path, required=True)
    inv_con.add_argument("--tenant", required=True)
    inv_con.add_argument("--project", default="proj_default")
    inv_con.add_argument("--payment-intents", required=True, help="comma-separated list of payment intent IDs")
    inv_con.add_argument("--buyer-name", required=True)
    inv_con.add_argument("--buyer-tax-id")
    inv_con.add_argument("--buyer-type", default="enterprise")
    inv_con.add_argument("--seller-name", required=True)
    inv_con.add_argument("--seller-tax-number", required=True)
    inv_con.add_argument("--operator", required=True)
    inv_con.add_argument("--title")
    inv_con.add_argument("--amounts-json", type=Path, help="optional JSON file mapping payment intent ID to minor amount")

    inv_v4 = subcommands.add_parser("invoice-verify-four-elements", help="verify invoice against China 4-element matching rule")
    inv_v4.add_argument("--database", type=Path, required=True)
    inv_v4.add_argument("--tenant", required=True)
    inv_v4.add_argument("--invoice-code", required=True)
    inv_v4.add_argument("--invoice-number", required=True)
    inv_v4.add_argument("--issued-date", required=True)
    inv_v4.add_argument("--check-code-or-amount", required=True)
    inv_v4.add_argument("--type", default="vat_electronic_normal")

    inv_rmb = subcommands.add_parser("invoice-reimburse-claim", help="register invoice for expense reimbursement with anti-duplication")
    inv_rmb.add_argument("--database", type=Path, required=True)
    inv_rmb.add_argument("--tenant", required=True)
    inv_rmb.add_argument("--invoice-id", required=True)
    inv_rmb.add_argument("--claim-id", required=True)
    inv_rmb.add_argument("--claimant", required=True)
    inv_rmb.add_argument("--department", required=True)
    inv_rmb.add_argument("--expense-category", required=True)
    inv_rmb.add_argument("--amount-minor", type=int)

    inv_rmb_st = subcommands.add_parser("invoice-reimburse-status", help="check reimbursement status of an invoice")
    inv_rmb_st.add_argument("--database", type=Path, required=True)
    inv_rmb_st.add_argument("--tenant", required=True)
    inv_rmb_st.add_argument("--invoice-id", required=True)

    inv_dlv = subcommands.add_parser("invoice-deliver", help="dispatch invoice across Email, SMS, and Webhook channels")
    inv_dlv.add_argument("--database", type=Path, required=True)
    inv_dlv.add_argument("--tenant", required=True)
    inv_dlv.add_argument("--invoice-id", required=True)
    inv_dlv.add_argument("--channels", required=True, help="comma-separated: EMAIL,SMS,WEBHOOK")
    inv_dlv.add_argument("--email")
    inv_dlv.add_argument("--sms")
    inv_dlv.add_argument("--webhook")
    inv_dlv.add_argument("--actor", default="system")

    inv_dlv_st = subcommands.add_parser("invoice-deliver-status", help="get delivery history for an invoice")
    inv_dlv_st.add_argument("--database", type=Path, required=True)
    inv_dlv_st.add_argument("--tenant", required=True)
    inv_dlv_st.add_argument("--invoice-id", required=True)

    inv_rec = subcommands.add_parser("invoice-reconcile-settlement", help="reconcile invoice with incoming wire settlement write-off")
    inv_rec.add_argument("--database", type=Path, required=True)
    inv_rec.add_argument("--tenant", required=True)
    inv_rec.add_argument("--invoice-id", required=True)
    inv_rec.add_argument("--settlement-ref", required=True)
    inv_rec.add_argument("--amount-minor", type=int, required=True)
    inv_rec.add_argument("--operator", required=True)
    inv_rec.add_argument("--notes", default="")

    inv_rec_st = subcommands.add_parser("invoice-settlement-status", help="get invoice settlement reconciliation status")
    inv_rec_st.add_argument("--database", type=Path, required=True)
    inv_rec_st.add_argument("--tenant", required=True)
    inv_rec_st.add_argument("--invoice-id", required=True)

    inv_ofd = subcommands.add_parser("invoice-ofd-render", help="render China national standard GB/T 33190-2016 OFD manifest")
    inv_ofd.add_argument("--database", type=Path, required=True)
    inv_ofd.add_argument("--tenant", required=True)
    inv_ofd.add_argument("--invoice-id", required=True)
    inv_ofd.add_argument("--out", type=Path)

    # --- Commercial Contract & Milestone Billing ---
    ctr_create = subcommands.add_parser("contract-create", help="create commercial contract")
    ctr_create.add_argument("--database", type=Path, required=True)
    ctr_create.add_argument("--tenant", required=True)
    ctr_create.add_argument("--title", required=True)
    ctr_create.add_argument("--buyer-name", required=True)
    ctr_create.add_argument("--seller-name", required=True)
    ctr_create.add_argument("--seller-tax-number", required=True)
    ctr_create.add_argument("--total-amount-minor", type=int, required=True)
    ctr_create.add_argument("--buyer-tax-number")
    ctr_create.add_argument("--currency", default="CNY")
    ctr_create.add_argument("--contract-id")

    ctr_ms = subcommands.add_parser("contract-milestone-add", help="add phased milestones to a contract")
    ctr_ms.add_argument("--database", type=Path, required=True)
    ctr_ms.add_argument("--tenant", required=True)
    ctr_ms.add_argument("--contract-id", required=True)
    ctr_ms.add_argument("--milestones-json", type=Path, required=True)

    ctr_inv = subcommands.add_parser("contract-milestone-invoice", help="invoice against a contract milestone")
    ctr_inv.add_argument("--database", type=Path, required=True)
    ctr_inv.add_argument("--tenant", required=True)
    ctr_inv.add_argument("--contract-id", required=True)
    ctr_inv.add_argument("--milestone-seq", type=int, required=True)
    ctr_inv.add_argument("--invoice-id", required=True)
    ctr_inv.add_argument("--amount-minor", type=int)
    ctr_inv.add_argument("--actor", default="billing_system")
    ctr_inv.add_argument("--notes")

    ctr_st = subcommands.add_parser("contract-status", help="query contract fulfillment status")
    ctr_st.add_argument("--database", type=Path, required=True)
    ctr_st.add_argument("--tenant", required=True)
    ctr_st.add_argument("--contract-id", required=True)

    # --- Tax Withholding & Remittance ---
    tax_calc = subcommands.add_parser("tax-withhold-calculate", help="calculate China IIT withholding")
    tax_calc.add_argument("--gross-amount-minor", type=int, required=True)
    tax_calc.add_argument("--income-type", default="LABOR_SERVICE")

    tax_cert = subcommands.add_parser("tax-withhold-certificate", help="issue withholding tax certificate")
    tax_cert.add_argument("--database", type=Path, required=True)
    tax_cert.add_argument("--tenant", required=True)
    tax_cert.add_argument("--payee-name", required=True)
    tax_cert.add_argument("--payee-id", required=True)
    tax_cert.add_argument("--gross-amount-minor", type=int, required=True)
    tax_cert.add_argument("--income-type", default="LABOR_SERVICE")
    tax_cert.add_argument("--payee-type", default="INDIVIDUAL")

    tax_exp = subcommands.add_parser("tax-withhold-export", help="export Golden Tax IV withholding CSV")
    tax_exp.add_argument("--database", type=Path, required=True)
    tax_exp.add_argument("--tenant", required=True)
    tax_exp.add_argument("--tax-period")
    tax_exp.add_argument("--out", type=Path)

    # --- Customs Payment Declaration ---
    cus_dec = subcommands.add_parser("customs-payment-declare", help="declare cross-border payment to GACC")
    cus_dec.add_argument("--database", type=Path, required=True)
    cus_dec.add_argument("--tenant", required=True)
    cus_dec.add_argument("--customs-code", required=True)
    cus_dec.add_argument("--ebp-code", required=True)
    cus_dec.add_argument("--ebc-code", required=True)
    cus_dec.add_argument("--order-no", required=True)
    cus_dec.add_argument("--payment-intent-id", required=True)
    cus_dec.add_argument("--payer-name", required=True)
    cus_dec.add_argument("--payer-id", required=True)
    cus_dec.add_argument("--payer-phone", required=True)
    cus_dec.add_argument("--amount-minor", type=int, required=True)
    cus_dec.add_argument("--currency", default="142")

    cus_st = subcommands.add_parser("customs-payment-status", help="query customs payment declaration status")
    cus_st.add_argument("--database", type=Path, required=True)
    cus_st.add_argument("--tenant", required=True)
    cus_st.add_argument("--order-no", required=True)

    # --- Treasury Cash Pool & Virtual Accounts ---
    tr_pool = subcommands.add_parser("treasury-pool-create", help="initialize master corporate treasury pool")
    tr_pool.add_argument("--database", type=Path, required=True)
    tr_pool.add_argument("--tenant", required=True)
    tr_pool.add_argument("--pool-name", required=True)
    tr_pool.add_argument("--master-acc-id", required=True)
    tr_pool.add_argument("--initial-balance-minor", type=int, default=0)
    tr_pool.add_argument("--currency", default="CNY")

    tr_va = subcommands.add_parser("treasury-va-create", help="create virtual sub-account with sweep policy")
    tr_va.add_argument("--database", type=Path, required=True)
    tr_va.add_argument("--tenant", required=True)
    tr_va.add_argument("--pool-id", required=True)
    tr_va.add_argument("--acc-no", required=True)
    tr_va.add_argument("--acc-name", required=True)
    tr_va.add_argument("--entity-type", default="STORE")
    tr_va.add_argument("--sweep-policy", default="ZERO_BALANCE")
    tr_va.add_argument("--target-balance-minor", type=int, default=0)
    tr_va.add_argument("--initial-balance-minor", type=int, default=0)

    tr_swp = subcommands.add_parser("treasury-sweep", help="execute automated sweeping to master pool")
    tr_swp.add_argument("--database", type=Path, required=True)
    tr_swp.add_argument("--tenant", required=True)
    tr_swp.add_argument("--pool-id", required=True)
    tr_swp.add_argument("--va-id")
    tr_swp.add_argument("--actor", default="treasury_sweeper")

    tr_st = subcommands.add_parser("treasury-pool-status", help="query treasury pool and virtual accounts")
    tr_st.add_argument("--database", type=Path, required=True)
    tr_st.add_argument("--tenant", required=True)
    tr_st.add_argument("--pool-id", required=True)

    # FX & DCC
    fx_rs = subcommands.add_parser("fx-rate-set", help="set FX spot rate and spread basis points")
    fx_rs.add_argument("--database", type=Path, required=True)
    fx_rs.add_argument("--tenant", required=True)
    fx_rs.add_argument("--base", required=True)
    fx_rs.add_argument("--target", required=True)
    fx_rs.add_argument("--spot-rate-units", type=int, required=True)
    fx_rs.add_argument("--spread-bp", type=int, default=50)

    fx_ql = subcommands.add_parser("fx-quote-lock", help="create guaranteed FX rate quote lock")
    fx_ql.add_argument("--database", type=Path, required=True)
    fx_ql.add_argument("--tenant", required=True)
    fx_ql.add_argument("--base", required=True)
    fx_ql.add_argument("--target", required=True)
    fx_ql.add_argument("--amount-minor", type=int, required=True)
    fx_ql.add_argument("--ttl-sec", type=int, default=900)

    fx_qr = subcommands.add_parser("fx-quote-redeem", help="redeem active FX quote lock for payment")
    fx_qr.add_argument("--database", type=Path, required=True)
    fx_qr.add_argument("--tenant", required=True)
    fx_qr.add_argument("--quote-id", required=True)
    fx_qr.add_argument("--payment-intent", required=True)

    fx_dc = subcommands.add_parser("fx-dcc-evaluate", help="evaluate Dynamic Currency Conversion offer")
    fx_dc.add_argument("--database", type=Path, required=True)
    fx_dc.add_argument("--tenant", required=True)
    fx_dc.add_argument("--card-currency", required=True)
    fx_dc.add_argument("--merchant-currency", required=True)
    fx_dc.add_argument("--amount-minor", type=int, required=True)

    # B2B Trade Credit
    b2b_cc = subcommands.add_parser("b2b-credit-create", help="create B2B trade credit facility")
    b2b_cc.add_argument("--database", type=Path, required=True)
    b2b_cc.add_argument("--tenant", required=True)
    b2b_cc.add_argument("--buyer-id", required=True)
    b2b_cc.add_argument("--buyer-name", required=True)
    b2b_cc.add_argument("--limit-minor", type=int, required=True)
    b2b_cc.add_argument("--currency", default="CNY")
    b2b_cc.add_argument("--tier", default="STANDARD")

    b2b_pi = subcommands.add_parser("b2b-po-issue", help="issue B2B purchase order with Net terms")
    b2b_pi.add_argument("--database", type=Path, required=True)
    b2b_pi.add_argument("--tenant", required=True)
    b2b_pi.add_argument("--buyer-id", required=True)
    b2b_pi.add_argument("--po-number", required=True)
    b2b_pi.add_argument("--seller-name", required=True)
    b2b_pi.add_argument("--amount-minor", type=int, required=True)
    b2b_pi.add_argument("--terms", default="NET_30")
    b2b_pi.add_argument("--issue-date")

    b2b_pr = subcommands.add_parser("b2b-po-repay", help="repay B2B purchase order and replenish credit")
    b2b_pr.add_argument("--database", type=Path, required=True)
    b2b_pr.add_argument("--tenant", required=True)
    b2b_pr.add_argument("--po-number", required=True)
    b2b_pr.add_argument("--amount-minor", type=int, required=True)

    b2b_ar = subcommands.add_parser("b2b-aging-report", help="calculate B2B overdue aging and late penalties")
    b2b_ar.add_argument("--database", type=Path, required=True)
    b2b_ar.add_argument("--tenant", required=True)
    b2b_ar.add_argument("--buyer-id", required=True)
    b2b_ar.add_argument("--as-of-date")
    b2b_ar.add_argument("--penalty-rate-bp", type=int, default=500)

    # Mass Payout
    po_bc = subcommands.add_parser("payout-batch-create", help="create bulk payout batch")
    po_bc.add_argument("--database", type=Path, required=True)
    po_bc.add_argument("--tenant", required=True)
    po_bc.add_argument("--batch-name", required=True)
    po_bc.add_argument("--currency", default="CNY")
    po_bc.add_argument("--maker", required=True)
    po_bc.add_argument("--items", type=Path, required=True)

    po_ba = subcommands.add_parser("payout-batch-approve", help="four-eyes approval of bulk payout batch")
    po_ba.add_argument("--database", type=Path, required=True)
    po_ba.add_argument("--tenant", required=True)
    po_ba.add_argument("--batch-id", required=True)
    po_ba.add_argument("--checker", required=True)

    po_be = subcommands.add_parser("payout-batch-execute", help="execute bulk payout batch items")
    po_be.add_argument("--database", type=Path, required=True)
    po_be.add_argument("--tenant", required=True)
    po_be.add_argument("--batch-id", required=True)
    po_be.add_argument("--executor", required=True)

    po_xi = subcommands.add_parser("payout-export-iso20022", help="export ISO 20022 pain.001 XML")
    po_xi.add_argument("--database", type=Path, required=True)
    po_xi.add_argument("--tenant", required=True)
    po_xi.add_argument("--batch-id", required=True)
    po_xi.add_argument("--out", type=Path)

    po_xc = subcommands.add_parser("payout-export-csv", help="export payout batch items to CSV")
    po_xc.add_argument("--database", type=Path, required=True)
    po_xc.add_argument("--tenant", required=True)
    po_xc.add_argument("--batch-id", required=True)
    po_xc.add_argument("--out", type=Path)

    # Card Vault & Network Tokenization
    vt_tk = subcommands.add_parser("vault-tokenize", help="tokenize card into vault and network token")
    vt_tk.add_argument("--database", type=Path, required=True)
    vt_tk.add_argument("--tenant", required=True)
    vt_tk.add_argument("--customer-id", required=True)
    vt_tk.add_argument("--pan", required=True)
    vt_tk.add_argument("--exp-month", type=int, required=True)
    vt_tk.add_argument("--exp-year", type=int, required=True)
    vt_tk.add_argument("--name", required=True)

    vt_cg = subcommands.add_parser("vault-cryptogram", help="generate EMVCo 3DS network token cryptogram")
    vt_cg.add_argument("--database", type=Path, required=True)
    vt_cg.add_argument("--tenant", required=True)
    vt_cg.add_argument("--vault-token", required=True)

    vt_au = subcommands.add_parser("vault-account-updater", help="apply card account updater event")
    vt_au.add_argument("--database", type=Path, required=True)
    vt_au.add_argument("--tenant", required=True)
    vt_au.add_argument("--vault-token", required=True)
    vt_au.add_argument("--event-type", required=True)
    vt_au.add_argument("--new-exp-month", type=int)
    vt_au.add_argument("--new-exp-year", type=int)
    vt_au.add_argument("--new-last4")

    vt_pg = subcommands.add_parser("vault-purge", help="purge expired card tokens under PCI DSS 4.0")
    vt_pg.add_argument("--database", type=Path, required=True)
    vt_pg.add_argument("--tenant", required=True)
    vt_pg.add_argument("--year", type=int, required=True)
    vt_pg.add_argument("--month", type=int, required=True)

    # Smart Routing
    rt_pr = subcommands.add_parser("routing-provider-reg", help="register or update payment routing provider")
    rt_pr.add_argument("--database", type=Path, required=True)
    rt_pr.add_argument("--tenant", required=True)
    rt_pr.add_argument("--provider-id", required=True)
    rt_pr.add_argument("--provider-name", required=True)
    rt_pr.add_argument("--methods", required=True, help="comma-separated methods")
    rt_pr.add_argument("--currencies", required=True, help="comma-separated currencies")
    rt_pr.add_argument("--min-minor", type=int, default=1)
    rt_pr.add_argument("--max-minor", type=int, default=100000000)
    rt_pr.add_argument("--fee-bp", type=int, default=30)
    rt_pr.add_argument("--fixed-fee", type=int, default=30)
    rt_pr.add_argument("--priority", type=int, default=100)

    rt_ev = subcommands.add_parser("routing-evaluate", help="evaluate optimal Least-Cost Route for transaction")
    rt_ev.add_argument("--database", type=Path, required=True)
    rt_ev.add_argument("--tenant", required=True)
    rt_ev.add_argument("--payment-intent", required=True)
    rt_ev.add_argument("--amount-minor", type=int, required=True)
    rt_ev.add_argument("--currency", required=True)
    rt_ev.add_argument("--method", required=True)
    rt_ev.add_argument("--brand")

    rt_hu = subcommands.add_parser("routing-health-update", help="update provider circuit breaker health status")
    rt_hu.add_argument("--database", type=Path, required=True)
    rt_hu.add_argument("--tenant", required=True)
    rt_hu.add_argument("--provider-id", required=True)
    rt_hu.add_argument("--status", required=True, choices=["HEALTHY", "DEGRADED", "CIRCUIT_BROKEN"])

    # Tiered Pricing
    pr_sc = subcommands.add_parser("pricing-schedule-set", help="configure merchant tiered/IC++ fee schedule")
    pr_sc.add_argument("--database", type=Path, required=True)
    pr_sc.add_argument("--tenant", required=True)
    pr_sc.add_argument("--model", required=True, choices=["BLENDED", "TIERED_VOLUME", "INTERCHANGE_PLUS_PLUS"])
    pr_sc.add_argument("--tiers", type=Path, help="JSON file with volume tiers")
    pr_sc.add_argument("--markup-bp", type=int, default=30)
    pr_sc.add_argument("--fixed-fee", type=int, default=30)

    pr_fc = subcommands.add_parser("pricing-fee-calc", help="calculate transaction fees under fee schedule")
    pr_fc.add_argument("--database", type=Path, required=True)
    pr_fc.add_argument("--tenant", required=True)
    pr_fc.add_argument("--txn-id", required=True)
    pr_fc.add_argument("--amount-minor", type=int, required=True)
    pr_fc.add_argument("--currency", default="CNY")
    pr_fc.add_argument("--brand", default="VISA")
    pr_fc.add_argument("--monthly-volume", type=int, default=0)

    # Webhook Engine
    wh_er = subcommands.add_parser("webhook-endpoint-reg", help="subscribe webhook endpoint to event topics")
    wh_er.add_argument("--database", type=Path, required=True)
    wh_er.add_argument("--tenant", required=True)
    wh_er.add_argument("--endpoint-id", required=True)
    wh_er.add_argument("--url", required=True)
    wh_er.add_argument("--secret", required=True)
    wh_er.add_argument("--events", required=True, help="comma-separated event types or *")

    wh_dp = subcommands.add_parser("webhook-dispatch", help="dispatch signed webhook event to subscribers")
    wh_dp.add_argument("--database", type=Path, required=True)
    wh_dp.add_argument("--tenant", required=True)
    wh_dp.add_argument("--event-type", required=True)
    wh_dp.add_argument("--payload", type=Path, required=True)
    wh_dp.add_argument("--http-status", type=int, default=200)

    wh_rp = subcommands.add_parser("webhook-replay", help="replay dead-letter queue webhook event")
    wh_rp.add_argument("--database", type=Path, required=True)
    wh_rp.add_argument("--tenant", required=True)
    wh_rp.add_argument("--dlq-id", required=True)
    wh_rp.add_argument("--http-status", type=int, default=200)

    wh_vs = subcommands.add_parser("webhook-verify-sign", help="verify webhook HMAC signature header")
    wh_vs.add_argument("--header", required=True)
    wh_vs.add_argument("--secret", required=True)
    wh_vs.add_argument("--payload", type=Path, required=True)

    # Marketplace Escrow & Split
    mp_sc = subcommands.add_parser("marketplace-split-create", help="create escrow split order")
    mp_sc.add_argument("--database", type=Path, required=True)
    mp_sc.add_argument("--tenant", required=True)
    mp_sc.add_argument("--order-id", required=True)
    mp_sc.add_argument("--amount-minor", type=int, required=True)
    mp_sc.add_argument("--currency", default="CNY")
    mp_sc.add_argument("--platform-fee", type=int, default=0)
    mp_sc.add_argument("--recipients", type=Path, required=True)
    mp_sc.add_argument("--hold-days", type=int, default=7)

    mp_er = subcommands.add_parser("marketplace-escrow-release", help="release marketplace escrow to vendors")
    mp_er.add_argument("--database", type=Path, required=True)
    mp_er.add_argument("--tenant", required=True)
    mp_er.add_argument("--order-id", required=True)

    mp_sr = subcommands.add_parser("marketplace-split-refund", help="proportionately refund marketplace split order")
    mp_sr.add_argument("--database", type=Path, required=True)
    mp_sr.add_argument("--tenant", required=True)
    mp_sr.add_argument("--order-id", required=True)
    mp_sr.add_argument("--refund-amount-minor", type=int, required=True)

    # Reconciliation Engine
    rc_bi = subcommands.add_parser("recon-batch-ingest", help="ingest external channel statement batch")
    rc_bi.add_argument("--database", type=Path, required=True)
    rc_bi.add_argument("--tenant", required=True)
    rc_bi.add_argument("--channel", required=True)
    rc_bi.add_argument("--date", required=True)
    rc_bi.add_argument("--file-name", required=True)
    rc_bi.add_argument("--items", type=Path, required=True)
    rc_bi.add_argument("--currency", default="CNY")

    rc_tw = subcommands.add_parser("recon-run-three-way", help="execute three-way cross reconciliation")
    rc_tw.add_argument("--database", type=Path, required=True)
    rc_tw.add_argument("--tenant", required=True)
    rc_tw.add_argument("--batch-id", required=True)
    rc_tw.add_argument("--internal-txns", type=Path, required=True)
    rc_tw.add_argument("--bank-clearing", type=Path)

    rc_ad = subcommands.add_parser("recon-adjust-discrepancy", help="propose and approve reconciliation discrepancy adjustment")
    rc_ad.add_argument("--database", type=Path, required=True)
    rc_ad.add_argument("--tenant", required=True)
    rc_ad.add_argument("--discrepancy-id", required=True)
    rc_ad.add_argument("--action", required=True, choices=["WRITE_OFF", "MANUAL_SETTLE", "DISPUTE_CLAIM"])
    rc_ad.add_argument("--maker-id", required=True)
    rc_ad.add_argument("--checker-id")
    rc_ad.add_argument("--notes", default="")

    # Mandates & Dunning
    mn_cr = subcommands.add_parser("mandate-create", help="register recurring debit mandate agreement")
    mn_cr.add_argument("--database", type=Path, required=True)
    mn_cr.add_argument("--tenant", required=True)
    mn_cr.add_argument("--customer-id", required=True)
    mn_cr.add_argument("--payment-method", required=True)
    mn_cr.add_argument("--type", required=True, choices=["SEPA_DIRECT_DEBIT", "BACS_DIRECT_DEBIT", "CHINA_BANK_DEBIT", "CARD_RECURRING_TOKEN"])
    mn_cr.add_argument("--max-amount", type=int, required=True)
    mn_cr.add_argument("--currency", default="CNY")

    mn_ch = subcommands.add_parser("mandate-charge", help="execute recurring charge against active customer mandate")
    mn_ch.add_argument("--database", type=Path, required=True)
    mn_ch.add_argument("--tenant", required=True)
    mn_ch.add_argument("--mandate-id", required=True)
    mn_ch.add_argument("--invoice-id", required=True)
    mn_ch.add_argument("--amount-minor", type=int, required=True)

    dn_ev = subcommands.add_parser("dunning-evaluate-failure", help="triage soft vs hard decline and schedule dunning")
    dn_ev.add_argument("--database", type=Path, required=True)
    dn_ev.add_argument("--tenant", required=True)
    dn_ev.add_argument("--mandate-id", required=True)
    dn_ev.add_argument("--invoice-id", required=True)
    dn_ev.add_argument("--decline-code", required=True)

    dn_rt = subcommands.add_parser("dunning-retry", help="process dunning retry attempt")
    dn_rt.add_argument("--database", type=Path, required=True)
    dn_rt.add_argument("--tenant", required=True)
    dn_rt.add_argument("--dunning-id", required=True)
    dn_rt.add_argument("--outcome", default="SUCCESS", choices=["SUCCESS", "FAILED"])

    # AML & Sanctions
    am_sc = subcommands.add_parser("aml-sanctions-screen", help="screen entity against sanctions watchlist")
    am_sc.add_argument("--database", type=Path, required=True)
    am_sc.add_argument("--tenant", required=True)
    am_sc.add_argument("--entity-name", required=True)
    am_sc.add_argument("--screening-type", default="SANCTIONS", choices=["SANCTIONS", "PEP", "ADVERSE_MEDIA"])

    am_lt = subcommands.add_parser("aml-large-tx-check", help="evaluate transaction against AML reporting thresholds")
    am_lt.add_argument("--database", type=Path, required=True)
    am_lt.add_argument("--tenant", required=True)
    am_lt.add_argument("--txn-id", required=True)
    am_lt.add_argument("--amount-minor", type=int, required=True)
    am_lt.add_argument("--customer-name", required=True)
    am_lt.add_argument("--threshold-minor", type=int, default=5000000)

    am_st = subcommands.add_parser("aml-structuring-detect", help="detect structuring smurfing anomaly patterns")
    am_st.add_argument("--database", type=Path, required=True)
    am_st.add_argument("--tenant", required=True)
    am_st.add_argument("--customer-id", required=True)
    am_st.add_argument("--transactions", type=Path, required=True)
    am_st.add_argument("--threshold-minor", type=int, default=5000000)

    # Subscriptions & Proration
    sub_pc = subcommands.add_parser("subscription-plan-create", help="create recurring subscription plan")
    sub_pc.add_argument("--database", type=Path, required=True)
    sub_pc.add_argument("--tenant", required=True)
    sub_pc.add_argument("--code", required=True)
    sub_pc.add_argument("--name", required=True)
    sub_pc.add_argument("--interval", default="MONTHLY", choices=["MONTHLY", "QUARTERLY", "ANNUAL"])
    sub_pc.add_argument("--amount-minor", type=int, required=True)
    sub_pc.add_argument("--currency", default="CNY")

    sub_cr = subcommands.add_parser("subscription-create", help="subscribe customer to a plan")
    sub_cr.add_argument("--database", type=Path, required=True)
    sub_cr.add_argument("--tenant", required=True)
    sub_cr.add_argument("--customer-id", required=True)
    sub_cr.add_argument("--plan-id", required=True)
    sub_cr.add_argument("--start", required=True)
    sub_cr.add_argument("--end", required=True)

    sub_cp = subcommands.add_parser("subscription-change-plan", help="prorated upgrade or downgrade of subscription")
    sub_cp.add_argument("--database", type=Path, required=True)
    sub_cp.add_argument("--tenant", required=True)
    sub_cp.add_argument("--subscription-id", required=True)
    sub_cp.add_argument("--new-plan-id", required=True)
    sub_cp.add_argument("--effective-at")

    sub_cb = subcommands.add_parser("subscription-credit-balance", help="query customer wallet credit balance")
    sub_cb.add_argument("--database", type=Path, required=True)
    sub_cb.add_argument("--tenant", required=True)
    sub_cb.add_argument("--customer-id", required=True)
    sub_cb.add_argument("--currency", default="CNY")

    # Double-Entry Ledger
    led_jp = subcommands.add_parser("ledger-journal-post", help="post balanced double-entry journal entry")
    led_jp.add_argument("--database", type=Path, required=True)
    led_jp.add_argument("--tenant", required=True)
    led_jp.add_argument("--type", required=True)
    led_jp.add_argument("--source-event", required=True)
    led_jp.add_argument("--currency", default="CNY")
    led_jp.add_argument("--legs", type=Path, required=True, help="path to JSON file containing leg items")

    led_ba = subcommands.add_parser("ledger-balance-audit", help="verify ledger hash chain and trial balance")
    led_ba.add_argument("--database", type=Path, required=True)
    led_ba.add_argument("--tenant", required=True)
    led_ba.add_argument("--as-of")

    # Financial Exceptions & Dispute Tickets (B78)
    exc_tc = subcommands.add_parser("exception-ticket-create", help="create financial discrepancy ticket")
    exc_tc.add_argument("--database", type=Path, required=True)
    exc_tc.add_argument("--tenant", required=True)
    exc_tc.add_argument("--category", required=True, choices=["SURPLUS", "DEFICIT", "AMOUNT_MISMATCH", "TIMING_VARIANCE", "DUPLICATE_CHARGE"])
    exc_tc.add_argument("--reference-id", required=True)
    exc_tc.add_argument("--amount-minor", type=int, required=True)
    exc_tc.add_argument("--currency", default="CNY")
    exc_tc.add_argument("--notes")

    exc_tp = subcommands.add_parser("exception-ticket-propose", help="propose resolution action (Maker step)")
    exc_tp.add_argument("--database", type=Path, required=True)
    exc_tp.add_argument("--tenant", required=True)
    exc_tp.add_argument("--ticket-id", required=True)
    exc_tp.add_argument("--action", required=True, choices=["MANUAL_POSTING", "WRITE_OFF", "REFUND_TO_CUSTOMER", "CHARGE_BACK_RECOVERY", "NONE"])
    exc_tp.add_argument("--maker-id", required=True)
    exc_tp.add_argument("--notes", default="")

    exc_ta = subcommands.add_parser("exception-ticket-approve", help="approve resolution action (Checker step with 4-eyes)")
    exc_ta.add_argument("--database", type=Path, required=True)
    exc_ta.add_argument("--tenant", required=True)
    exc_ta.add_argument("--ticket-id", required=True)
    exc_ta.add_argument("--checker-id", required=True)

    exc_tl = subcommands.add_parser("exception-ticket-list", help="list financial exception tickets")
    exc_tl.add_argument("--database", type=Path, required=True)
    exc_tl.add_argument("--tenant", required=True)
    exc_tl.add_argument("--status")
    exc_tl.add_argument("--category")

    # Financial Reporting & Audit Manifest (B79)
    fin_rg = subcommands.add_parser("financial-report-generate", help="generate multi-dimensional financial KPI report")
    fin_rg.add_argument("--database", type=Path, required=True)
    fin_rg.add_argument("--tenant", required=True)
    fin_rg.add_argument("--start", required=True)
    fin_rg.add_argument("--end", required=True)
    fin_rg.add_argument("--currency", default="CNY")

    fin_re = subcommands.add_parser("financial-report-export", help="export tamper-proof signed financial audit manifest")
    fin_re.add_argument("--database", type=Path, required=True)
    fin_re.add_argument("--tenant", required=True)
    fin_re.add_argument("--start", required=True)
    fin_re.add_argument("--end", required=True)
    fin_re.add_argument("--currency", default="CNY")
    fin_re.add_argument("--out", type=Path)

    fin_rv = subcommands.add_parser("financial-report-verify", help="verify cryptographic seal of financial audit manifest")
    fin_rv.add_argument("--manifest", type=Path, required=True)

    stl_cfg = subcommands.add_parser("settlement-config", help="configure merchant settlement rules")
    stl_cfg.add_argument("--database", type=Path, required=True)
    stl_cfg.add_argument("--tenant", required=True)
    stl_cfg.add_argument("--project", required=True)
    stl_cfg.add_argument("--currency", default="CNY")
    stl_cfg.add_argument("--cycle", default="T_PLUS_1")
    stl_cfg.add_argument("--min-payout", type=int, default=1000)
    stl_cfg.add_argument("--commission-bp", type=int, default=30)
    stl_cfg.add_argument("--fee-bp", type=int, default=38)
    stl_cfg.add_argument("--reserve-bp", type=int, default=500)
    stl_cfg.add_argument("--bank-name", required=True)
    stl_cfg.add_argument("--bank-acc", required=True)
    stl_cfg.add_argument("--bank-acc-name", required=True)

    stl_batch = subcommands.add_parser("settlement-batch", help="calculate settlement batch for a period")
    stl_batch.add_argument("--database", type=Path, required=True)
    stl_batch.add_argument("--tenant", required=True)
    stl_batch.add_argument("--project", required=True)
    stl_batch.add_argument("--period-start", required=True)
    stl_batch.add_argument("--period-end", required=True)
    stl_batch.add_argument("--transactions", type=Path, required=True)
    stl_batch.add_argument("--operator", required=True)
    stl_batch.add_argument("--currency", default="CNY")

    stl_appr = subcommands.add_parser("settlement-approve", help="four-eyes approval of settlement payout")
    stl_appr.add_argument("--database", type=Path, required=True)
    stl_appr.add_argument("--tenant", required=True)
    stl_appr.add_argument("--batch-id", required=True)
    stl_appr.add_argument("--approver", required=True)

    stl_exec = subcommands.add_parser("settlement-execute", help="execute approved settlement payout")
    stl_exec.add_argument("--database", type=Path, required=True)
    stl_exec.add_argument("--tenant", required=True)
    stl_exec.add_argument("--batch-id", required=True)
    stl_exec.add_argument("--executor", required=True)
    stl_exec.add_argument("--bank-ref", required=True)

    stl_render = subcommands.add_parser("settlement-render", help="render settlement voucher HTML")
    stl_render.add_argument("--database", type=Path, required=True)
    stl_render.add_argument("--tenant", required=True)
    stl_render.add_argument("--batch-id", required=True)
    stl_render.add_argument("--out", type=Path)

    stl_exp = subcommands.add_parser("settlement-export", help="export bank payout instructions")
    stl_exp.add_argument("--database", type=Path, required=True)
    stl_exp.add_argument("--tenant", required=True)
    stl_exp.add_argument("--batch-id", required=True)
    stl_exp.add_argument("--format", choices=["csv", "json"], default="csv")
    stl_exp.add_argument("--out", type=Path)

    stl_audit = subcommands.add_parser("settlement-audit-verify", help="verify settlement cryptographic audit chain")
    stl_audit.add_argument("--database", type=Path, required=True)
    stl_audit.add_argument("--tenant", required=True)
    stl_audit.add_argument("--batch-id", required=True)

    dsp_rec = subcommands.add_parser("dispute-record", help="record incoming payment dispute")
    dsp_rec.add_argument("--database", type=Path, required=True)
    dsp_rec.add_argument("--tenant", required=True)
    dsp_rec.add_argument("--project", required=True)
    dsp_rec.add_argument("--payment-intent", required=True)
    dsp_rec.add_argument("--amount-minor", type=int, required=True)
    dsp_rec.add_argument("--due-at", required=True)
    dsp_rec.add_argument("--currency", default="CNY")
    dsp_rec.add_argument("--reason", default="UNRECOGNIZED")
    dsp_rec.add_argument("--actor", default="dispute_webhook_service")

    dsp_evd = subcommands.add_parser("dispute-evidence", help="submit dispute rebuttal evidence")
    dsp_evd.add_argument("--database", type=Path, required=True)
    dsp_evd.add_argument("--tenant", required=True)
    dsp_evd.add_argument("--dispute-id", required=True)
    dsp_evd.add_argument("--evidence", type=Path, required=True)
    dsp_evd.add_argument("--actor", required=True)

    dsp_res = subcommands.add_parser("dispute-resolve", help="resolve dispute as WON or LOST")
    dsp_res.add_argument("--database", type=Path, required=True)
    dsp_res.add_argument("--tenant", required=True)
    dsp_res.add_argument("--dispute-id", required=True)
    dsp_res.add_argument("--outcome", choices=["WON", "LOST"], required=True)
    dsp_res.add_argument("--lost-fee-minor", type=int, default=0)
    dsp_res.add_argument("--actor", required=True)

    dsp_list = subcommands.add_parser("dispute-list", help="list disputes for a tenant")
    dsp_list.add_argument("--database", type=Path, required=True)
    dsp_list.add_argument("--tenant", required=True)
    dsp_list.add_argument("--status")

    dsp_audit = subcommands.add_parser("dispute-audit-verify", help="verify dispute cryptographic audit chain")
    dsp_audit.add_argument("--database", type=Path, required=True)
    dsp_audit.add_argument("--tenant", required=True)
    dsp_audit.add_argument("--dispute-id", required=True)

    return parser



def _emit(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def _report(report: GateReport) -> int:
    _emit(
        {
            "allowed": report.allowed,
            "reasons": list(report.reasons),
            "checks": list(report.checks),
        }
    )
    return 0 if report.allowed else 2


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            return _report(validate_repository(args.root.resolve()))
        if args.command == "render-kubernetes":
            images_document = read_json(args.images)
            images = images_document.get("images", images_document) if isinstance(images_document, dict) else images_document
            workload_policy = read_json(args.policy)
            validate_workload_sources(REPOSITORY_ROOT, workload_policy)
            rendered = render_workloads(workload_policy, images)
            _emit(rendered)
            return 0
        if args.command == "shadow-diff":
            result = compare_shadow(read_json(args.baseline), read_json(args.candidate))
            _emit(
                {
                    "passed": result.passed,
                    "compared": result.compared,
                    "mismatches": list(result.mismatches),
                    "missingBaseline": list(result.missing_baseline),
                    "missingCandidate": list(result.missing_candidate),
                    "candidateSideEffects": list(result.candidate_side_effects),
                }
            )
            return 0 if result.passed else 2
        if args.command == "canary":
            return _report(evaluate_canary(read_json(args.baseline), read_json(args.candidate), read_json(args.policy)))
        if args.command == "release-gate":
            manifest = read_json(args.manifest)
            release_policy = read_json(args.policy)
            release_report = verify_release(manifest, release_policy, read_json(args.trust))
            if release_policy.get("externalEvidenceRequired") is True:
                if args.external_evidence and args.external_trust:
                    external_report = validate_external_evidence(
                        read_json(args.external_policy),
                        read_json(args.external_evidence),
                        read_json(args.external_trust),
                        expected_binding=release_binding(manifest),
                    )
                else:
                    external_report = GateReport.from_reasons(["external_evidence_bundle_missing"])
                release_report = GateReport.from_reasons(
                    [
                        *(f"release:{reason}" for reason in release_report.reasons),
                        *(f"external_evidence:{reason}" for reason in external_report.reasons),
                    ],
                    [*release_report.checks, *external_report.checks],
                )
            return _report(release_report)
        if args.command == "external-evidence":
            manifest = read_json(args.manifest) if args.manifest else None
            expected_binding = release_binding(manifest) if manifest is not None else None
            report = validate_external_evidence(
                read_json(args.policy),
                read_json(args.bundle),
                read_json(args.trust),
                expected_binding=expected_binding,
            )
            return _report(report)
        if args.command == "test-evidence-template":
            report = validate_test_evidence_template(
                read_json(args.policy),
                read_json(args.release_policy),
                read_json(args.template),
            )
            _emit(
                {
                    "localTemplateValid": report.allowed,
                    "productionReleaseAllowed": False,
                    "certificationStatus": "NOT_CERTIFIED",
                    "reasons": list(report.reasons),
                    "checks": list(report.checks),
                }
            )
            return 0 if report.allowed else 2
        if args.command == "bill":
            invoice = calculate_invoice(
                read_json(args.policy),
                args.tenant,
                datetime.fromisoformat(args.period_start.replace("Z", "+00:00")),
                datetime.fromisoformat(args.period_end.replace("Z", "+00:00")),
                read_json(args.events),
            )
            _emit(
                {
                    "tenantId": invoice.tenant_id,
                    "periodStart": invoice.period_start.isoformat(),
                    "periodEnd": invoice.period_end.isoformat(),
                    "currency": invoice.currency,
                    "lines": [
                        {
                            "meter": line.meter,
                            "quantity": line.quantity,
                            "unitPriceMinor": line.unit_price_minor,
                            "totalMinor": line.total_minor,
                        }
                        for line in invoice.lines
                    ],
                    "duplicateEvents": invoice.duplicate_events,
                    "totalMinor": invoice.total_minor,
                }
            )
            return 0
        if args.command == "vulnerability-gate":
            return _report(evaluate_vulnerability_report(
                read_json(args.policy), read_json(args.report), args.artifact_digest
            ))
        if args.command == "vendor-gate":
            return _report(evaluate_vendor(read_json(args.policy), read_json(args.assessment)))
        if args.command == "capacity-gate":
            assessment = evaluate_capacity(read_json(args.policy), read_json(args.samples))
            _emit({
                "allowed": assessment.report.allowed,
                "reasons": list(assessment.report.reasons),
                "checks": list(assessment.report.checks),
                "currentHeadroom": {key: str(value) for key, value in assessment.current_headroom.items()},
                "forecastHeadroom": {key: str(value) for key, value in assessment.forecast_headroom.items()},
            })
            return 0 if assessment.report.allowed else 2
        if args.command == "go-no-go":
            rollout_policy = read_json(args.rollout_policy)
            release_report = verify_release(
                read_json(args.manifest), read_json(args.release_policy), read_json(args.trust)
            )
            shadow_report = compare_shadow(
                read_json(args.shadow_baseline), read_json(args.shadow_candidate)
            )
            canary_report = evaluate_canary(
                read_json(args.canary_baseline), read_json(args.canary_candidate), rollout_policy
            )
            capacity_report = evaluate_capacity(
                read_json(args.capacity_policy), read_json(args.capacity_samples)
            ).report
            if args.external_evidence and args.external_trust:
                external_report = validate_external_evidence(
                    read_json(args.external_policy),
                    read_json(args.external_evidence),
                    read_json(args.external_trust),
                    expected_binding=release_binding(read_json(args.manifest)),
                )
            else:
                external_report = GateReport.from_reasons(["external_evidence_bundle_missing"])
            return _report(evaluate_go_no_go(
                release_report,
                shadow_report,
                canary_report,
                capacity_report,
                read_json(args.operations),
                rollout_policy,
                external_report,
            ))
        if args.command == "invoice-balance":
            ledger = CustomerInvoiceLedger(str(args.database))
            balance = ledger.calculate_invoicable_balance(
                args.tenant, args.payment_intent, args.captured_minor, args.refunded_minor
            )
            _emit({
                "tenantId": args.tenant,
                "paymentIntentId": args.payment_intent,
                "invoicableBalanceMinor": balance,
            })
            return 0
        if args.command == "invoice-apply":
            ledger = CustomerInvoiceLedger(str(args.database))
            req = read_json(args.request)
            invoice = ledger.apply_invoice(
                tenant_id=req["tenantId"],
                project_id=req["projectId"],
                payment_intent_id=req["paymentIntentId"],
                captured_amount_minor=req["capturedAmountMinor"],
                refunded_amount_minor=req.get("refundedAmountMinor", 0),
                invoice_type=req["invoiceType"],
                buyer_type=req["buyerType"],
                buyer_name=req["buyerName"],
                buyer_tax_number=req.get("buyerTaxNumber"),
                buyer_address_phone=req.get("buyerAddressPhone"),
                buyer_bank_account=req.get("buyerBankAccount"),
                recipient_email=req.get("recipientEmail"),
                recipient_phone=req.get("recipientPhone"),
                seller_name=req["sellerName"],
                seller_tax_number=req["sellerTaxNumber"],
                seller_address_phone=req.get("sellerAddressPhone"),
                seller_bank_account=req.get("sellerBankAccount"),
                operator=req["operator"],
                items=req["items"],
                idempotency_key=req.get("idempotencyKey"),
                currency=req.get("currency", "CNY"),
            )
            _emit(invoice)
            return 0
        if args.command == "invoice-issue":
            ledger = CustomerInvoiceLedger(str(args.database))
            invoice = ledger.issue_invoice(
                args.tenant, args.invoice_id, actor=args.actor, checker=args.checker, payee=args.payee
            )
            _emit(invoice)
            return 0
        if args.command == "invoice-reject":
            ledger = CustomerInvoiceLedger(str(args.database))
            invoice = ledger.reject_invoice(
                args.tenant, args.invoice_id, reason=args.reason, checker=args.checker
            )
            _emit(invoice)
            return 0
        if args.command == "invoice-red-note":
            ledger = CustomerInvoiceLedger(str(args.database))
            invoice = ledger.issue_red_note(
                args.tenant,
                args.original_invoice_id,
                reason=args.reason,
                operator=args.operator,
                red_amount_minor=args.red_amount_minor,
                idempotency_key=args.idempotency_key,
            )
            _emit(invoice)
            return 0
        if args.command == "invoice-void":
            ledger = CustomerInvoiceLedger(str(args.database))
            invoice = ledger.void_invoice(
                args.tenant, args.invoice_id, reason=args.reason, operator=args.operator
            )
            _emit(invoice)
            return 0
        if args.command == "invoice-verify":
            ledger = CustomerInvoiceLedger(str(args.database))
            result = ledger.verify_invoice(args.tenant, args.invoice_id, args.verification_code)
            _emit(result)
            return 0 if result.get("valid") else 2
        if args.command == "invoice-export":
            ledger = CustomerInvoiceLedger(str(args.database))
            start = datetime.fromisoformat(args.start.replace("Z", "+00:00")) if args.start else None
            end = datetime.fromisoformat(args.end.replace("Z", "+00:00")) if args.end else None
            export = ledger.export_invoice_ledger(
                args.tenant, start_time=start, end_time=end, status=args.status, limit=args.limit
            )
            _emit(export)
            return 0
        if args.command == "invoice-audit-verify":
            ledger = CustomerInvoiceLedger(str(args.database))
            valid = ledger.verify_invoice_audit_chain(args.tenant)
            _emit({"tenantId": args.tenant, "auditChainValid": valid})
            return 0 if valid else 2
        if args.command == "invoice-render":
            ledger = CustomerInvoiceLedger(str(args.database))
            invoice = ledger.get_invoice(args.tenant, args.invoice_id)
            if not invoice:
                raise ValidationError(f"invoice not found: {args.invoice_id}")
            if args.format == "xml":
                content = render_golden_tax_xml(invoice)
            else:
                content = render_invoice_html(invoice)
            if args.out:
                args.out.write_text(content, encoding="utf-8")
                _emit({"tenantId": args.tenant, "invoiceId": args.invoice_id, "rendered": True, "outPath": str(args.out)})
            else:
                print(content)
            return 0
        if args.command == "invoice-auto":
            ledger = CustomerInvoiceLedger(str(args.database))
            invoice = ledger.auto_invoice_payment_intent(
                tenant_id=args.tenant,
                project_id=args.project,
                payment_intent_id=args.payment_intent,
                buyer_title_id=args.buyer_title_id,
                captured_amount_minor=args.captured_minor,
                refunded_amount_minor=args.refunded_minor,
                seller_name=args.seller_name,
                seller_tax_number=args.seller_tax_number,
                operator=args.operator,
                actor_id=args.actor,
                idempotency_key=args.idempotency_key,
                item_name=args.item_name,
                tax_rate_basis_points=args.tax_rate_bp,
            )
            _emit(invoice)
            return 0
        if args.command == "invoice-reconcile":
            ledger = CustomerInvoiceLedger(str(args.database))
            payments = None
            if args.payments:
                payments_data = read_json(args.payments)
                payments = payments_data if isinstance(payments_data, list) else payments_data.get("payments")
            start = datetime.fromisoformat(args.start.replace("Z", "+00:00")) if args.start else None
            end = datetime.fromisoformat(args.end.replace("Z", "+00:00")) if args.end else None
            result = ledger.reconcile_invoices_with_payments(
                args.tenant,
                payments=payments,
                start_time=start,
                end_time=end,
            )
            _emit(result)
            return 0 if result.get("status") == "BALANCED" else 1
        if args.command == "invoice-batch-auto":
            ledger = CustomerInvoiceLedger(str(args.database))
            manifest = read_json(args.manifest)
            items = manifest if isinstance(manifest, list) else manifest.get("items", [])
            res = ledger.batch_auto_invoice(
                tenant_id=args.tenant,
                manifest=items,
                seller_name=args.seller_name,
                seller_tax_number=args.seller_tax_number,
                operator=args.operator,
                actor_id=args.actor,
                checker=args.checker,
                payee=args.payee,
            )
            _emit(res)
            return 0 if res.get("failedCount", 0) == 0 else 1
        if args.command == "invoice-refund-red-note":
            ledger = CustomerInvoiceLedger(str(args.database))
            res = ledger.auto_red_note_on_refund(
                tenant_id=args.tenant,
                payment_intent_id=args.payment_intent,
                refund_amount_minor=args.refund_minor,
                operator=args.operator,
                reason=args.reason,
                idempotency_key=args.idempotency_key,
            )
            _emit(res)
            return 0
        if args.command == "invoice-batch-render":
            ledger = CustomerInvoiceLedger(str(args.database))
            if args.invoices:
                inv_data = read_json(args.invoices)
                invoices = inv_data if isinstance(inv_data, list) else inv_data.get("invoices", [])
            else:
                exp = ledger.export_invoice_ledger(args.tenant, limit=100)
                invoices = exp.get("invoices", [])
            content = render_invoice_batch_html(invoices, title=args.title)
            if args.out:
                args.out.write_text(content, encoding="utf-8")
                _emit({"tenantId": args.tenant, "invoiceCount": len(invoices), "rendered": True, "outPath": str(args.out)})
            else:
                print(content)
            return 0
        if args.command == "invoice-quota-config":
            ledger = CustomerInvoiceLedger(str(args.database))
            res = ledger.configure_tax_quota(
                tenant_id=args.tenant,
                monthly_tax_quota_minor=args.monthly_quota_minor,
                single_invoice_limit_minor=args.single_limit_minor,
                alarm_threshold_pct=args.alarm_threshold_pct,
                operator=args.operator,
            )
            _emit(res)
            return 0
        if args.command == "invoice-quota-status":
            ledger = CustomerInvoiceLedger(str(args.database))
            res = ledger.get_tax_quota_status(args.tenant, tax_period=args.tax_period)
            _emit(res)
            return 0
        if args.command == "invoice-split-apply":
            ledger = CustomerInvoiceLedger(str(args.database))
            req = read_json(args.request)
            invoices = ledger.split_and_apply_invoice(
                tenant_id=req["tenantId"],
                payment_intent_id=req["paymentIntentId"],
                invoice_type=req["invoiceType"],
                buyer_info=req["buyerInfo"],
                seller_info=req["sellerInfo"],
                items=req["items"],
                actor_id=args.actor,
                idempotency_key=args.idempotency_key,
            )
            _emit({"tenantId": req["tenantId"], "splitCount": len(invoices), "invoices": invoices})
            return 0
        if args.command == "invoice-self-service-create":
            ledger = CustomerInvoiceLedger(str(args.database))
            session = ledger.create_self_service_session(
                tenant_id=args.tenant,
                payment_intent_id=args.payment_intent,
                invoicable_amount_minor=args.amount_minor,
                created_by=args.created_by,
                ttl_hours=args.ttl_hours,
                currency=args.currency,
            )
            _emit(session)
            return 0
        if args.command == "invoice-self-service-redeem":
            ledger = CustomerInvoiceLedger(str(args.database))
            buyer_info = {"name": args.buyer_name}
            if args.buyer_tax_id:
                buyer_info["taxId"] = args.buyer_tax_id
            if args.buyer_email:
                buyer_info["email"] = args.buyer_email
            if args.buyer_phone:
                buyer_info["phone"] = args.buyer_phone
            if args.buyer_address_phone:
                buyer_info["addressPhone"] = args.buyer_address_phone
            if args.buyer_bank_account:
                buyer_info["bankAccount"] = args.buyer_bank_account
            invoice = ledger.redeem_self_service_session(
                session_token=args.token,
                buyer_info=buyer_info,
                invoice_type=args.invoice_type,
            )
            _emit(invoice)
            return 0
        if args.command == "invoice-tax-declaration":
            ledger = CustomerInvoiceLedger(str(args.database))
            summary = ledger.generate_tax_declaration_summary(
                tenant_id=args.tenant,
                tax_period=args.tax_period,
            )
            if args.format == "csv":
                csv_content = export_tax_declaration_csv(summary)
                if args.out:
                    args.out.write_text(csv_content, encoding="utf-8")
                    _emit({"tenantId": args.tenant, "taxPeriod": args.tax_period, "exported": True, "outPath": str(args.out)})
                else:
                    print(csv_content)
            else:
                if args.out:
                    args.out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
                    _emit({"tenantId": args.tenant, "taxPeriod": args.tax_period, "exported": True, "outPath": str(args.out)})
                else:
                    _emit(summary)
            return 0
        if args.command == "invoice-subscription-auto":
            ledger = CustomerInvoiceLedger(str(args.database))
            buyer_info = {"name": args.buyer_name}
            if args.buyer_tax_id:
                buyer_info["taxId"] = args.buyer_tax_id
            if args.buyer_email:
                buyer_info["email"] = args.buyer_email
            invoice = ledger.auto_invoice_subscription_billing(
                tenant_id=args.tenant,
                subscription_id=args.subscription_id,
                billing_cycle=args.billing_cycle,
                amount_minor=args.amount_minor,
                plan_name=args.plan_name,
                buyer_info=buyer_info,
                operator=args.operator,
                tax_rate_basis_points=args.tax_rate_bp,
                tax_classification_code=args.tax_classification_code,
            )
            _emit(invoice)
            return 0
        if args.command == "invoice-consolidate":
            ledger = CustomerInvoiceLedger(str(args.database))
            pi_ids = [s.strip() for s in args.payment_intents.split(",") if s.strip()]
            buyer = {
                "buyerType": args.buyer_type,
                "buyerName": args.buyer_name,
                "buyerTaxNumber": args.buyer_tax_id,
            }
            seller = {
                "sellerName": args.seller_name,
                "sellerTaxNumber": args.seller_tax_number,
            }
            amounts_map = None
            if args.amounts_json:
                amounts_map = read_json(args.amounts_json)
            inv = ledger.consolidate_and_apply_invoice(
                tenant_id=args.tenant,
                project_id=args.project,
                payment_intent_ids=pi_ids,
                buyer_info=buyer,
                seller_info=seller,
                invoice_title=args.title,
                payment_amounts_minor=amounts_map,
                operator=args.operator,
            )
            _emit(inv)
            return 0
        if args.command == "invoice-verify-four-elements":
            ledger = CustomerInvoiceLedger(str(args.database))
            res = ledger.verify_invoice_four_elements(
                tenant_id=args.tenant,
                invoice_code=args.invoice_code,
                invoice_number=args.invoice_number,
                issued_date=args.issued_date,
                check_code_or_amount=args.check_code_or_amount,
                invoice_type=args.type,
            )
            _emit(res)
            return 0 if res.get("verified") else 1
        if args.command == "invoice-reimburse-claim":
            ledger = CustomerInvoiceLedger(str(args.database))
            res = ledger.register_invoice_reimbursement(
                tenant_id=args.tenant,
                invoice_id=args.invoice_id,
                claim_id=args.claim_id,
                claimant=args.claimant,
                department=args.department,
                expense_category=args.expense_category,
                amount_minor=args.amount_minor,
            )
            _emit(res)
            return 0
        if args.command == "invoice-reimburse-status":
            ledger = CustomerInvoiceLedger(str(args.database))
            res = ledger.get_reimbursement_status(args.tenant, args.invoice_id)
            _emit(res)
            return 0
        if args.command == "invoice-deliver":
            ledger = CustomerInvoiceLedger(str(args.database))
            ch_list = [s.strip() for s in args.channels.split(",") if s.strip()]
            dests = {}
            if args.email:
                dests["EMAIL"] = args.email
            if args.sms:
                dests["SMS"] = args.sms
            if args.webhook:
                dests["WEBHOOK"] = args.webhook
            res = ledger.deliver_invoice(
                tenant_id=args.tenant,
                invoice_id=args.invoice_id,
                channels=ch_list,
                destinations=dests,
                actor=args.actor,
            )
            _emit({"invoiceId": args.invoice_id, "deliveries": res})
            return 0
        if args.command == "invoice-deliver-status":
            ledger = CustomerInvoiceLedger(str(args.database))
            res = ledger.get_invoice_delivery_history(args.tenant, args.invoice_id)
            _emit({"invoiceId": args.invoice_id, "history": res})
            return 0
        if args.command == "invoice-reconcile-settlement":
            ledger = CustomerInvoiceLedger(str(args.database))
            res = ledger.reconcile_invoice_settlement(
                tenant_id=args.tenant,
                invoice_id=args.invoice_id,
                settlement_ref=args.settlement_ref,
                amount_minor=args.amount_minor,
                operator=args.operator,
                notes=args.notes,
            )
            _emit(res)
            return 0
        if args.command == "invoice-settlement-status":
            ledger = CustomerInvoiceLedger(str(args.database))
            res = ledger.get_invoice_settlement_status(args.tenant, args.invoice_id)
            _emit(res)
            return 0
        if args.command == "invoice-ofd-render":
            ledger = CustomerInvoiceLedger(str(args.database))
            inv = ledger.get_invoice(args.tenant, args.invoice_id)
            if not inv:
                raise ValidationError(f"invoice not found: {args.invoice_id}")
            content = render_invoice_ofd_manifest(inv)
            if args.out:
                args.out.write_text(content, encoding="utf-8")
                _emit({"tenantId": args.tenant, "invoiceId": args.invoice_id, "rendered": True, "outPath": str(args.out)})
            else:
                print(content)
            return 0
        if args.command == "contract-create":
            ledger = CommercialContractLedger(str(args.database))
            res = ledger.create_contract(
                tenant_id=args.tenant,
                title=args.title,
                buyer_name=args.buyer_name,
                buyer_tax_number=args.buyer_tax_number,
                seller_name=args.seller_name,
                seller_tax_number=args.seller_tax_number,
                total_amount_minor=args.total_amount_minor,
                currency=args.currency,
                contract_id=args.contract_id,
            )
            _emit(res)
            return 0
        if args.command == "contract-milestone-add":
            ledger = CommercialContractLedger(str(args.database))
            ms_list = read_json(args.milestones_json)
            res = ledger.add_milestones(args.tenant, args.contract_id, ms_list)
            _emit({"contractId": args.contract_id, "milestones": res})
            return 0
        if args.command == "contract-milestone-invoice":
            ledger = CommercialContractLedger(str(args.database))
            res = ledger.invoice_contract_milestone(
                tenant_id=args.tenant,
                contract_id=args.contract_id,
                milestone_id_or_seq=args.milestone_seq,
                invoice_id=args.invoice_id,
                amount_minor=args.amount_minor,
                actor_id=args.actor,
                notes=args.notes,
            )
            _emit(res)
            return 0
        if args.command == "contract-status":
            ledger = CommercialContractLedger(str(args.database))
            res = ledger.get_contract_fulfillment_status(args.tenant, args.contract_id)
            _emit(res)
            return 0
        if args.command == "tax-withhold-calculate":
            res = calculate_tax_withholding(args.gross_amount_minor, args.income_type)
            _emit(res)
            return 0
        if args.command == "tax-withhold-certificate":
            ledger = TaxWithholdingLedger(str(args.database))
            res = ledger.issue_certificate(
                tenant_id=args.tenant,
                payee_name=args.payee_name,
                payee_id_number=args.payee_id,
                gross_amount_minor=args.gross_amount_minor,
                income_type=args.income_type,
                payee_type=args.payee_type,
            )
            _emit(res)
            return 0
        if args.command == "tax-withhold-export":
            ledger = TaxWithholdingLedger(str(args.database))
            csv_content = ledger.export_golden_tax_csv(args.tenant, args.tax_period)
            if args.out:
                args.out.write_text(csv_content, encoding="utf-8-sig")
                _emit({"tenantId": args.tenant, "exported": True, "outPath": str(args.out)})
            else:
                print(csv_content)
            return 0
        if args.command == "customs-payment-declare":
            mgr = CustomsPaymentDeclarationManager(str(args.database))
            res = mgr.declare_payment(
                tenant_id=args.tenant,
                customs_code=args.customs_code,
                ebp_code=args.ebp_code,
                ebc_code=args.ebc_code,
                order_no=args.order_no,
                payment_intent_id=args.payment_intent_id,
                payer_name=args.payer_name,
                payer_id_number=args.payer_id,
                payer_phone=args.payer_phone,
                amount_minor=args.amount_minor,
                currency=args.currency,
            )
            _emit(res)
            return 0
        if args.command == "customs-payment-status":
            mgr = CustomsPaymentDeclarationManager(str(args.database))
            res = mgr.get_declaration(args.tenant, args.order_no)
            _emit(res)
            return 0
        if args.command == "treasury-pool-create":
            mgr = TreasuryPoolManager(str(args.database))
            res = mgr.create_pool(
                tenant_id=args.tenant,
                pool_name=args.pool_name,
                master_account_id=args.master_acc_id,
                currency=args.currency,
                initial_master_balance_minor=args.initial_balance_minor,
            )
            _emit(res)
            return 0
        if args.command == "treasury-va-create":
            mgr = TreasuryPoolManager(str(args.database))
            res = mgr.create_virtual_account(
                tenant_id=args.tenant,
                pool_id=args.pool_id,
                account_number=args.acc_no,
                account_name=args.acc_name,
                entity_type=args.entity_type,
                sweep_policy=args.sweep_policy,
                target_balance_minor=args.target_balance_minor,
                initial_balance_minor=args.initial_balance_minor,
            )
            _emit(res)
            return 0
        if args.command == "treasury-sweep":
            mgr = TreasuryPoolManager(str(args.database))
            res = mgr.execute_sweep(
                tenant_id=args.tenant,
                pool_id=args.pool_id,
                va_id=args.va_id,
                actor_id=args.actor,
            )
            _emit(res)
            return 0
        if args.command == "treasury-pool-status":
            mgr = TreasuryPoolManager(str(args.database))
            res = mgr.get_pool_status(args.tenant, args.pool_id)
            _emit(res)
            return 0

        # FX & DCC Handlers
        if args.command == "fx-rate-set":
            store = DurableStore(str(args.database))
            mgr = FXQuoteLockManager(store)
            res = mgr.set_rate_matrix(
                tenant_id=args.tenant,
                base_currency=args.base,
                target_currency=args.target,
                spot_rate_units=args.spot_rate_units,
                spread_basis_points=args.spread_bp,
            )
            _emit(res)
            return 0
        if args.command == "fx-quote-lock":
            store = DurableStore(str(args.database))
            mgr = FXQuoteLockManager(store)
            res = mgr.create_quote_lock(
                tenant_id=args.tenant,
                base_currency=args.base,
                target_currency=args.target,
                source_amount_minor=args.amount_minor,
                ttl_seconds=args.ttl_sec,
            )
            _emit(res)
            return 0
        if args.command == "fx-quote-redeem":
            store = DurableStore(str(args.database))
            mgr = FXQuoteLockManager(store)
            res = mgr.redeem_quote_lock(
                tenant_id=args.tenant,
                quote_id=args.quote_id,
                payment_intent_id=args.payment_intent,
            )
            _emit(res)
            return 0
        if args.command == "fx-dcc-evaluate":
            store = DurableStore(str(args.database))
            mgr = FXQuoteLockManager(store)
            res = mgr.evaluate_dcc_offer(
                tenant_id=args.tenant,
                card_currency=args.card_currency,
                merchant_currency=args.merchant_currency,
                transaction_amount_minor=args.amount_minor,
            )
            _emit(res)
            return 0

        # B2B Trade Credit Handlers
        if args.command == "b2b-credit-create":
            store = DurableStore(str(args.database))
            mgr = B2BCreditManager(store)
            res = mgr.create_credit_facility(
                tenant_id=args.tenant,
                buyer_id=args.buyer_id,
                buyer_name=args.buyer_name,
                credit_limit_minor=args.limit_minor,
                currency=args.currency,
                credit_tier=args.tier,
            )
            _emit(res)
            return 0
        if args.command == "b2b-po-issue":
            store = DurableStore(str(args.database))
            mgr = B2BCreditManager(store)
            res = mgr.issue_purchase_order(
                tenant_id=args.tenant,
                buyer_id=args.buyer_id,
                po_number=args.po_number,
                seller_name=args.seller_name,
                amount_minor=args.amount_minor,
                payment_terms=args.terms,
                issue_date=args.issue_date,
            )
            _emit(res)
            return 0
        if args.command == "b2b-po-repay":
            store = DurableStore(str(args.database))
            mgr = B2BCreditManager(store)
            res = mgr.repay_purchase_order(
                tenant_id=args.tenant,
                po_number=args.po_number,
                repayment_amount_minor=args.amount_minor,
            )
            _emit(res)
            return 0
        if args.command == "b2b-aging-report":
            store = DurableStore(str(args.database))
            mgr = B2BCreditManager(store)
            res = mgr.calculate_aging_and_penalties(
                tenant_id=args.tenant,
                buyer_id=args.buyer_id,
                as_of_date=args.as_of_date,
                annual_penalty_rate_bps=args.penalty_rate_bp,
            )
            _emit(res)
            return 0

        # Mass Payout Handlers
        if args.command == "payout-batch-create":
            store = DurableStore(str(args.database))
            mgr = MassPayoutManager(store)
            items_data = read_json(args.items)
            if isinstance(items_data, dict) and "items" in items_data:
                items_data = items_data["items"]
            res = mgr.create_batch(
                tenant_id=args.tenant,
                batch_name=args.batch_name,
                currency=args.currency,
                maker_id=args.maker,
                items=items_data,
            )
            _emit(res)
            return 0
        if args.command == "payout-batch-approve":
            store = DurableStore(str(args.database))
            mgr = MassPayoutManager(store)
            res = mgr.approve_batch(
                tenant_id=args.tenant,
                batch_id=args.batch_id,
                checker_id=args.checker,
            )
            _emit(res)
            return 0
        if args.command == "payout-batch-execute":
            store = DurableStore(str(args.database))
            mgr = MassPayoutManager(store)
            res = mgr.execute_batch(
                tenant_id=args.tenant,
                batch_id=args.batch_id,
                executor_id=args.executor,
            )
            _emit(res)
            return 0
        if args.command == "payout-export-iso20022":
            store = DurableStore(str(args.database))
            mgr = MassPayoutManager(store)
            xml_content = mgr.export_iso20022_pain001(args.tenant, args.batch_id)
            if args.out:
                args.out.write_text(xml_content, encoding="utf-8")
                _emit({"tenantId": args.tenant, "batchId": args.batch_id, "format": "pain.001.001.03", "outPath": str(args.out)})
            else:
                print(xml_content)
            return 0
        if args.command == "payout-export-csv":
            store = DurableStore(str(args.database))
            mgr = MassPayoutManager(store)
            csv_content = mgr.export_payout_csv(args.tenant, args.batch_id)
            if args.out:
                args.out.write_text(csv_content, encoding="utf-8")
                _emit({"tenantId": args.tenant, "batchId": args.batch_id, "format": "csv", "outPath": str(args.out)})
            else:
                print(csv_content)
            return 0

        # Card Vault Handlers
        if args.command == "vault-tokenize":
            store = DurableStore(str(args.database))
            mgr = CardVaultManager(store)
            res = mgr.tokenize_card(
                tenant_id=args.tenant,
                customer_id=args.customer_id,
                raw_pan=args.pan,
                exp_month=args.exp_month,
                exp_year=args.exp_year,
                cardholder_name=args.name,
            )
            _emit(res)
            return 0
        if args.command == "vault-cryptogram":
            store = DurableStore(str(args.database))
            mgr = CardVaultManager(store)
            res = mgr.generate_network_token_cryptogram(args.tenant, args.vault_token)
            _emit(res)
            return 0
        if args.command == "vault-account-updater":
            store = DurableStore(str(args.database))
            mgr = CardVaultManager(store)
            res = mgr.apply_account_updater_event(
                tenant_id=args.tenant,
                vault_token=args.vault_token,
                event_type=args.event_type,
                new_exp_month=args.new_exp_month,
                new_exp_year=args.new_exp_year,
                new_last4=args.new_last4,
            )
            _emit(res)
            return 0
        if args.command == "vault-purge":
            store = DurableStore(str(args.database))
            mgr = CardVaultManager(store)
            count = mgr.purge_expired_tokens(args.tenant, args.year, args.month)
            _emit({"tenantId": args.tenant, "purgedCount": count, "year": args.year, "month": args.month})
            return 0

        # Smart Routing Handlers
        if args.command == "routing-provider-reg":
            store = DurableStore(str(args.database))
            engine = SmartRoutingEngine(store)
            res = engine.register_provider_profile(
                tenant_id=args.tenant,
                provider_id=args.provider_id,
                provider_name=args.provider_name,
                supported_methods=[m.strip() for m in args.methods.split(",") if m.strip()],
                supported_currencies=[c.strip() for c in args.currencies.split(",") if c.strip()],
                min_amount_minor=args.min_minor,
                max_amount_minor=args.max_minor,
                fee_basis_points=args.fee_bp,
                fixed_fee_minor=args.fixed_fee,
                priority_rank=args.priority,
            )
            _emit(res)
            return 0
        if args.command == "routing-evaluate":
            store = DurableStore(str(args.database))
            engine = SmartRoutingEngine(store)
            res = engine.route_transaction(
                tenant_id=args.tenant,
                payment_intent_id=args.payment_intent,
                amount_minor=args.amount_minor,
                currency=args.currency,
                payment_method=args.method,
                card_brand=args.brand,
            )
            _emit(res)
            return 0
        if args.command == "routing-health-update":
            store = DurableStore(str(args.database))
            engine = SmartRoutingEngine(store)
            res = engine.update_provider_health(
                tenant_id=args.tenant,
                provider_id=args.provider_id,
                health_status=args.status,
            )
            _emit(res)
            return 0

        # Tiered Pricing Handlers
        if args.command == "pricing-schedule-set":
            store = DurableStore(str(args.database))
            engine = TieredPricingEngine(store)
            tiers = read_json(args.tiers) if args.tiers else None
            if isinstance(tiers, dict) and "tiers" in tiers:
                tiers = tiers["tiers"]
            res = engine.configure_fee_schedule(
                tenant_id=args.tenant,
                pricing_model=args.model,
                tiers=tiers,
                markup_basis_points=args.markup_bp,
                fixed_fee_minor=args.fixed_fee,
            )
            _emit(res)
            return 0
        if args.command == "pricing-fee-calc":
            store = DurableStore(str(args.database))
            engine = TieredPricingEngine(store)
            res = engine.calculate_merchant_fee(
                tenant_id=args.tenant,
                transaction_id=args.txn_id,
                amount_minor=args.amount_minor,
                currency=args.currency,
                card_brand=args.brand,
                monthly_accumulated_volume_minor=args.monthly_volume,
            )
            _emit(res)
            return 0

        # Webhook Handlers
        if args.command == "webhook-endpoint-reg":
            store = DurableStore(str(args.database))
            dispatcher = EnterpriseWebhookDispatcher(store)
            events = [e.strip() for e in args.events.split(",") if e.strip()]
            res = dispatcher.register_endpoint(
                tenant_id=args.tenant,
                endpoint_id=args.endpoint_id,
                url=args.url,
                secret_key=args.secret,
                subscribed_events=events,
            )
            _emit(res)
            return 0
        if args.command == "webhook-dispatch":
            store = DurableStore(str(args.database))
            dispatcher = EnterpriseWebhookDispatcher(store)
            payload = read_json(args.payload)
            res = dispatcher.dispatch_event(
                tenant_id=args.tenant,
                event_type=args.event_type,
                payload=payload,
                simulate_http_status=args.http_status,
            )
            _emit({"dispatchedCount": len(res), "events": res})
            return 0
        if args.command == "webhook-replay":
            store = DurableStore(str(args.database))
            dispatcher = EnterpriseWebhookDispatcher(store)
            res = dispatcher.replay_dead_letter(
                tenant_id=args.tenant,
                dead_letter_id=args.dlq_id,
                simulate_http_status=args.http_status,
            )
            _emit(res)
            return 0
        if args.command == "webhook-verify-sign":
            try:
                parsed = read_json(args.payload)
                payload_text = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
            except Exception:
                payload_text = args.payload.read_text(encoding="utf-8")
            valid = verify_webhook_signature(args.header, args.secret, payload_text)
            _emit({"signatureValid": valid})
            return 0 if valid else 1

        # Marketplace Escrow & Split Handlers
        if args.command == "marketplace-split-create":
            store = DurableStore(str(args.database))
            mgr = MarketplaceEscrowManager(store)
            recip_data = read_json(args.recipients)
            recips = recip_data if isinstance(recip_data, list) else recip_data.get("recipients", [])
            res = mgr.create_split_order(
                tenant_id=args.tenant,
                order_id=args.order_id,
                captured_amount_minor=args.amount_minor,
                currency=args.currency,
                platform_fee_minor=args.platform_fee,
                recipients=recips,
                hold_days=args.hold_days,
            )
            _emit(res)
            return 0
        if args.command == "marketplace-escrow-release":
            store = DurableStore(str(args.database))
            mgr = MarketplaceEscrowManager(store)
            res = mgr.release_escrow(args.tenant, args.order_id)
            _emit(res)
            return 0
        if args.command == "marketplace-split-refund":
            store = DurableStore(str(args.database))
            mgr = MarketplaceEscrowManager(store)
            res = mgr.refund_split_order(args.tenant, args.order_id, args.refund_amount_minor)
            _emit(res)
            return 0

        # Reconciliation Handlers
        if args.command == "recon-batch-ingest":
            store = DurableStore(str(args.database))
            engine = StatementReconciliationEngine(store)
            items_data = read_json(args.items)
            items = items_data if isinstance(items_data, list) else items_data.get("items", [])
            res = engine.ingest_statement(
                tenant_id=args.tenant,
                channel_id=args.channel,
                statement_date=args.date,
                file_name=args.file_name,
                items=items,
                currency=args.currency,
            )
            _emit(res)
            return 0
        if args.command == "recon-run-three-way":
            store = DurableStore(str(args.database))
            engine = StatementReconciliationEngine(store)
            int_txns = read_json(args.internal_txns)
            int_list = int_txns if isinstance(int_txns, list) else int_txns.get("transactions", [])
            bank_clearing = read_json(args.bank_clearing) if args.bank_clearing else None
            bank_list = (bank_clearing if isinstance(bank_clearing, list) else bank_clearing.get("clearing", [])) if bank_clearing else None
            res = engine.reconcile_three_way(
                tenant_id=args.tenant,
                batch_id=args.batch_id,
                internal_transactions=int_list,
                bank_clearing_records=bank_list,
            )
            _emit(res)
            return 0
        if args.command == "recon-adjust-discrepancy":
            store = DurableStore(str(args.database))
            engine = StatementReconciliationEngine(store)
            p_res = engine.propose_discrepancy_adjustment(
                tenant_id=args.tenant,
                discrepancy_id=args.discrepancy_id,
                proposed_action=args.action,
                maker_id=args.maker_id,
                notes=args.notes,
            )
            if args.checker_id:
                res = engine.approve_discrepancy_adjustment(
                    tenant_id=args.tenant,
                    discrepancy_id=args.discrepancy_id,
                    checker_id=args.checker_id,
                )
                _emit(res)
            else:
                _emit(p_res)
            return 0

        # Mandates & Dunning Handlers
        if args.command == "mandate-create":
            store = DurableStore(str(args.database))
            engine = MandatesDunningEngine(store)
            res = engine.register_mandate(
                tenant_id=args.tenant,
                customer_id=args.customer_id,
                payment_method_ref=args.payment_method,
                mandate_type=args.type,
                max_amount_per_charge_minor=args.max_amount,
                currency=args.currency,
            )
            _emit(res)
            return 0
        if args.command == "mandate-charge":
            store = DurableStore(str(args.database))
            engine = MandatesDunningEngine(store)
            res = engine.execute_mandate_charge(
                tenant_id=args.tenant,
                mandate_id=args.mandate_id,
                invoice_id=args.invoice_id,
                amount_minor=args.amount_minor,
            )
            _emit(res)
            return 0
        if args.command == "dunning-evaluate-failure":
            store = DurableStore(str(args.database))
            engine = MandatesDunningEngine(store)
            res = engine.evaluate_charge_failure(
                tenant_id=args.tenant,
                mandate_id=args.mandate_id,
                invoice_id=args.invoice_id,
                decline_code=args.decline_code,
            )
            _emit(res)
            return 0
        if args.command == "dunning-retry":
            store = DurableStore(str(args.database))
            engine = MandatesDunningEngine(store)
            res = engine.process_dunning_retry(
                tenant_id=args.tenant,
                dunning_id=args.dunning_id,
                simulate_outcome=args.outcome,
            )
            _emit(res)
            return 0

        # AML & Sanctions Handlers
        if args.command == "aml-sanctions-screen":
            store = DurableStore(str(args.database))
            engine = AmlSanctionsEngine(store)
            res = engine.screen_entity(
                tenant_id=args.tenant,
                entity_name=args.entity_name,
                screening_type=args.screening_type,
            )
            _emit(res)
            return 0
        if args.command == "aml-large-tx-check":
            store = DurableStore(str(args.database))
            engine = AmlSanctionsEngine(store)
            res = engine.evaluate_large_transaction(
                tenant_id=args.tenant,
                transaction_id=args.txn_id,
                amount_minor=args.amount_minor,
                customer_name=args.customer_name,
                threshold_minor=args.threshold_minor,
            )
            _emit(res)
            return 0
        if args.command == "aml-structuring-detect":
            store = DurableStore(str(args.database))
            engine = AmlSanctionsEngine(store)
            txns_data = read_json(args.transactions)
            txns = txns_data if isinstance(txns_data, list) else txns_data.get("transactions", [])
            res = engine.detect_structuring_activity(
                tenant_id=args.tenant,
                customer_id=args.customer_id,
                transactions=txns,
                threshold_minor=args.threshold_minor,
            )
            _emit(res)
            return 0

        # Subscriptions & Proration Handlers
        if args.command == "subscription-plan-create":
            store = DurableStore(str(args.database))
            engine = SubscriptionProrationEngine(store)
            res = engine.create_plan(
                tenant_id=args.tenant,
                plan_code=args.code,
                name=args.name,
                billing_interval=args.interval,
                amount_minor=args.amount_minor,
                currency=args.currency,
            )
            _emit(res)
            return 0
        if args.command == "subscription-create":
            store = DurableStore(str(args.database))
            engine = SubscriptionProrationEngine(store)
            res = engine.create_subscription(
                tenant_id=args.tenant,
                customer_id=args.customer_id,
                plan_id=args.plan_id,
                current_period_start=args.start,
                current_period_end=args.end,
            )
            _emit(res)
            return 0
        if args.command == "subscription-change-plan":
            store = DurableStore(str(args.database))
            engine = SubscriptionProrationEngine(store)
            res = engine.change_plan(
                tenant_id=args.tenant,
                subscription_id=args.subscription_id,
                new_plan_id=args.new_plan_id,
                effective_at=args.effective_at,
            )
            _emit(res)
            return 0
        if args.command == "subscription-credit-balance":
            store = DurableStore(str(args.database))
            engine = SubscriptionProrationEngine(store)
            bal = engine.get_customer_credit_balance(
                tenant_id=args.tenant,
                customer_id=args.customer_id,
                currency=args.currency,
            )
            _emit({"tenantId": args.tenant, "customerId": args.customer_id, "currency": args.currency, "balanceMinor": bal})
            return 0

        # Double-Entry Ledger Handlers
        if args.command == "ledger-journal-post":
            store = DurableStore(str(args.database))
            ledger = FinancialDoubleEntryLedger(store)
            legs_data = read_json(args.legs)
            legs_list = legs_data if isinstance(legs_data, list) else legs_data.get("legs", [])
            res = ledger.post_journal_entry(
                tenant_id=args.tenant,
                transaction_type=args.type,
                source_event_id=args.source_event,
                currency=args.currency,
                legs=legs_list,
            )
            _emit(res)
            return 0
        if args.command == "ledger-balance-audit":
            store = DurableStore(str(args.database))
            ledger = FinancialDoubleEntryLedger(store)
            integrity = ledger.verify_chain_integrity(args.tenant)
            tb = ledger.generate_trial_balance(args.tenant, as_of=args.as_of)
            _emit({"tenantId": args.tenant, "integrity": integrity, "trialBalance": tb})
            return 0 if (integrity["valid"] and tb["isBalanced"]) else 1

        # Financial Exceptions & Resolution Handlers (B78)
        if args.command == "exception-ticket-create":
            store = DurableStore(str(args.database))
            mgr = FinancialExceptionManager(store)
            res = mgr.create_ticket(
                tenant_id=args.tenant,
                category=args.category,
                reference_id=args.reference_id,
                amount_minor=args.amount_minor,
                currency=args.currency,
                notes=args.notes,
            )
            _emit(res)
            return 0
        if args.command == "exception-ticket-propose":
            store = DurableStore(str(args.database))
            mgr = FinancialExceptionManager(store)
            res = mgr.propose_resolution(
                tenant_id=args.tenant,
                ticket_id=args.ticket_id,
                action=args.action,
                maker_id=args.maker_id,
                notes=args.notes,
            )
            _emit(res)
            return 0
        if args.command == "exception-ticket-approve":
            store = DurableStore(str(args.database))
            mgr = FinancialExceptionManager(store)
            res = mgr.approve_resolution(
                tenant_id=args.tenant,
                ticket_id=args.ticket_id,
                checker_id=args.checker_id,
            )
            _emit(res)
            return 0
        if args.command == "exception-ticket-list":
            store = DurableStore(str(args.database))
            mgr = FinancialExceptionManager(store)
            res = mgr.list_tickets(
                tenant_id=args.tenant,
                status=args.status,
                category=args.category,
            )
            _emit({"tenantId": args.tenant, "count": len(res), "tickets": res})
            return 0

        # Financial Reporting & Audit Manifest Handlers (B79)
        if args.command == "financial-report-generate":
            store = DurableStore(str(args.database))
            engine = FinancialReportingEngine(store)
            rep = engine.generate_period_report(
                tenant_id=args.tenant,
                period_start=args.start,
                period_end=args.end,
                currency=args.currency,
            )
            _emit(rep)
            return 0
        if args.command == "financial-report-export":
            store = DurableStore(str(args.database))
            engine = FinancialReportingEngine(store)
            manifest = engine.export_financial_audit_manifest(
                tenant_id=args.tenant,
                period_start=args.start,
                period_end=args.end,
                currency=args.currency,
            )
            if args.out:
                args.out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
                _emit({"tenantId": args.tenant, "manifestId": manifest["manifestId"], "manifestDigest": manifest["manifestDigest"], "outPath": str(args.out)})
            else:
                _emit(manifest)
            return 0
        if args.command == "financial-report-verify":
            manifest_data = read_json(args.manifest)
            ver = FinancialReportingEngine.verify_financial_audit_manifest(manifest_data)
            _emit(ver)
            return 0 if ver.get("valid") else 1

        if args.command == "settlement-config":
            ledger = SettlementLedger(str(args.database))
            cfg = ledger.configure_merchant_settlement(
                tenant_id=args.tenant,
                project_id=args.project,
                currency=args.currency,
                settlement_cycle=args.cycle,
                minimum_payout_minor=args.min_payout,
                commission_basis_points=args.commission_bp,
                channel_fee_basis_points=args.fee_bp,
                reserve_holdback_basis_points=args.reserve_bp,
                bank_name=args.bank_name,
                bank_account_number=args.bank_acc,
                bank_account_name=args.bank_acc_name,
            )
            _emit(cfg)
            return 0
        if args.command == "settlement-batch":
            ledger = SettlementLedger(str(args.database))
            tx_data = read_json(args.transactions)
            txs = tx_data if isinstance(tx_data, list) else tx_data.get("transactions", [])
            batch = ledger.calculate_settlement_batch(
                tenant_id=args.tenant,
                project_id=args.project,
                period_start=args.period_start,
                period_end=args.period_end,
                transactions=txs,
                operator=args.operator,
                currency=args.currency,
            )
            _emit(batch)
            return 0
        if args.command == "settlement-approve":
            ledger = SettlementLedger(str(args.database))
            res = ledger.approve_settlement_payout(
                tenant_id=args.tenant,
                batch_id=args.batch_id,
                approver=args.approver,
            )
            _emit(res)
            return 0
        if args.command == "settlement-execute":
            ledger = SettlementLedger(str(args.database))
            res = ledger.execute_settlement_payout(
                tenant_id=args.tenant,
                batch_id=args.batch_id,
                executor=args.executor,
                bank_reference_id=args.bank_ref,
            )
            _emit(res)
            return 0
        if args.command == "settlement-render":
            ledger = SettlementLedger(str(args.database))
            batch = ledger.get_settlement_batch(args.tenant, args.batch_id)
            cfg = ledger.get_merchant_settlement_config(args.tenant, batch["projectId"], currency=batch["currency"])
            content = render_settlement_html(batch, config=cfg)
            if args.out:
                args.out.write_text(content, encoding="utf-8")
                _emit({"tenantId": args.tenant, "batchId": args.batch_id, "rendered": True, "outPath": str(args.out)})
            else:
                print(content)
            return 0
        if args.command == "settlement-export":
            ledger = SettlementLedger(str(args.database))
            content = ledger.export_payout_instructions(
                tenant_id=args.tenant,
                batch_id=args.batch_id,
                format_type=args.format,
            )
            if args.out:
                args.out.write_text(content, encoding="utf-8")
                _emit({"tenantId": args.tenant, "batchId": args.batch_id, "format": args.format, "outPath": str(args.out)})
            else:
                print(content)
            return 0
        if args.command == "settlement-audit-verify":
            ledger = SettlementLedger(str(args.database))
            valid = ledger.verify_settlement_audit_chain(args.tenant, args.batch_id)
            _emit({"tenantId": args.tenant, "batchId": args.batch_id, "auditChainValid": valid})
            return 0 if valid else 1
        if args.command == "dispute-record":
            ledger = DisputeLedger(str(args.database))
            disp = ledger.record_dispute(
                tenant_id=args.tenant,
                project_id=args.project,
                payment_intent_id=args.payment_intent,
                dispute_amount_minor=args.amount_minor,
                evidence_due_at=args.due_at,
                currency=args.currency,
                reason_code=args.reason,
                actor_id=args.actor,
            )
            _emit(disp)
            return 0
        if args.command == "dispute-evidence":
            ledger = DisputeLedger(str(args.database))
            evd_data = read_json(args.evidence)
            disp = ledger.submit_dispute_evidence(
                tenant_id=args.tenant,
                dispute_id=args.dispute_id,
                evidence=evd_data,
                actor_id=args.actor,
            )
            _emit(disp)
            return 0
        if args.command == "dispute-resolve":
            ledger = DisputeLedger(str(args.database))
            disp = ledger.resolve_dispute(
                tenant_id=args.tenant,
                dispute_id=args.dispute_id,
                outcome=args.outcome,
                lost_fee_minor=args.lost_fee_minor,
                actor_id=args.actor,
            )
            _emit(disp)
            return 0
        if args.command == "dispute-list":
            ledger = DisputeLedger(str(args.database))
            disps = ledger.list_disputes(tenant_id=args.tenant, status=args.status)
            _emit({"tenantId": args.tenant, "count": len(disps), "disputes": disps})
            return 0
        if args.command == "dispute-audit-verify":
            ledger = DisputeLedger(str(args.database))
            valid = ledger.verify_dispute_audit_chain(args.tenant, args.dispute_id)
            _emit({"tenantId": args.tenant, "disputeId": args.dispute_id, "auditChainValid": valid})
            return 0 if valid else 1
        raise ValidationError(f"unsupported command: {args.command}")

    except (ValidationError, KeyError, TypeError, ValueError) as exc:
        _emit({"allowed": False, "reasons": [f"input_invalid:{exc}"], "checks": []})
        return 2


if __name__ == "__main__":
    sys.exit(main())
