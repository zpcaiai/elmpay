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
from elmpay_runtime.kubernetes import render_workloads
from elmpay_runtime.release import verify_release
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
    go_no_go.add_argument("--rollout-policy", type=Path, default=REPOSITORY_ROOT / "platform/rollout/policy.json")
    go_no_go.add_argument("--release-policy", type=Path, default=REPOSITORY_ROOT / "platform/compliance/required-release-gates.json")
    go_no_go.add_argument("--capacity-policy", type=Path, default=REPOSITORY_ROOT / "platform/observability/capacity.json")
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
            rendered = render_workloads(read_json(args.policy), images)
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
            return _report(verify_release(read_json(args.manifest), read_json(args.policy), read_json(args.trust)))
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
            return _report(evaluate_go_no_go(
                release_report,
                shadow_report,
                canary_report,
                capacity_report,
                read_json(args.operations),
                rollout_policy,
            ))
        raise ValidationError(f"unsupported command: {args.command}")
    except (ValidationError, KeyError, TypeError, ValueError) as exc:
        _emit({"allowed": False, "reasons": [f"input_invalid:{exc}"], "checks": []})
        return 2


if __name__ == "__main__":
    sys.exit(main())
