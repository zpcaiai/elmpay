from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Mapping

from .common import GateReport, parse_instant, require_list, require_mapping, require_text


DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def evaluate_vulnerability_report(
    policy: Mapping[str, Any],
    report: Mapping[str, Any],
    expected_artifact_digest: str,
    *,
    now: datetime | None = None,
) -> GateReport:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    reasons: list[str] = []
    required = set(require_list(policy.get("requiredScans"), "requiredScans"))
    scans = require_list(report.get("scans"), "report.scans")
    completed: set[str] = set()
    maximum_age = policy.get("maximumScanAgeHours")
    if not isinstance(maximum_age, int) or maximum_age <= 0:
        return GateReport.from_reasons(["policy_invalid:maximumScanAgeHours"])
    thresholds = require_mapping(policy.get("thresholds"), "thresholds")
    for index, raw in enumerate(scans):
        scan = require_mapping(raw, f"scan[{index}]")
        scan_type = require_text(scan.get("type"), f"scan[{index}].type")
        if scan_type in completed:
            reasons.append(f"duplicate_scan:{scan_type}")
            continue
        if scan.get("status") != "COMPLETE":
            reasons.append(f"scan_not_complete:{scan_type}")
            continue
        if scan.get("artifactDigest") != expected_artifact_digest:
            reasons.append(f"scan_artifact_mismatch:{scan_type}")
            continue
        try:
            completed_at = parse_instant(scan.get("completedAt"), f"scan[{index}].completedAt")
            if completed_at > current + timedelta(minutes=5):
                reasons.append(f"scan_in_future:{scan_type}")
                continue
            if current - completed_at > timedelta(hours=maximum_age):
                reasons.append(f"scan_stale:{scan_type}")
                continue
        except ValueError as exc:
            reasons.append(f"scan_time_invalid:{scan_type}:{exc}")
            continue
        findings = require_mapping(scan.get("findings"), f"scan[{index}].findings")
        for severity, maximum in thresholds.items():
            count = findings.get(severity)
            if not isinstance(count, int) or count < 0:
                reasons.append(f"finding_count_invalid:{scan_type}:{severity}")
            elif not isinstance(maximum, int) or count > maximum:
                reasons.append(f"finding_threshold_exceeded:{scan_type}:{severity}")
        completed.add(scan_type)
    for scan_type in sorted(required - completed):
        reasons.append(f"missing_scan:{scan_type}")
    if not DIGEST_PATTERN.fullmatch(expected_artifact_digest):
        reasons.append("expected_artifact_digest_invalid")
    return GateReport.from_reasons(reasons, checks=(f"scan:{item}" for item in completed))


def evaluate_vendor(
    policy: Mapping[str, Any],
    assessment: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> GateReport:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    reasons: list[str] = []
    require_text(assessment.get("vendorId"), "vendorId")
    required = set(require_list(policy.get("required"), "vendor required controls"))
    supplied = set(require_list(assessment.get("completedControls"), "completedControls"))
    for control in sorted(required - supplied):
        reasons.append(f"missing_vendor_control:{control}")
    assessor = require_text(assessment.get("assessor"), "assessor")
    approver = require_text(assessment.get("approver"), "approver")
    if policy.get("requiresIndependentApprover") is True and assessor == approver:
        reasons.append("vendor_approver_not_independent")
    try:
        reviewed_at = parse_instant(assessment.get("reviewedAt"), "reviewedAt")
        critical = assessment.get("critical") is True
        maximum_days_key = (
            "criticalVendorReviewMaximumAgeDays" if critical else "reviewMaximumAgeDays"
        )
        maximum_days = policy.get(maximum_days_key)
        if not isinstance(maximum_days, int) or maximum_days <= 0:
            reasons.append(f"vendor_policy_invalid:{maximum_days_key}")
        elif current - reviewed_at > timedelta(days=maximum_days):
            reasons.append("vendor_review_expired")
        if reviewed_at > current + timedelta(minutes=5):
            reasons.append("vendor_review_in_future")
    except ValueError as exc:
        reasons.append(f"vendor_review_time_invalid:{exc}")
    return GateReport.from_reasons(reasons, checks=(f"vendor:{item}" for item in supplied))
