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
    render_golden_tax_xml,
    render_invoice_batch_html,
    render_invoice_html,
)
from elmpay_runtime.settlement import SettlementLedger, render_settlement_html
from elmpay_runtime.dispute import DisputeLedger
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
