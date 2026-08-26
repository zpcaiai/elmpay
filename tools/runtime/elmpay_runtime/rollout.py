from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping

from .common import GateReport, ValidationError, require_mapping, require_text


@dataclass(frozen=True)
class ShadowDiff:
    compared: int
    mismatches: tuple[str, ...]
    missing_baseline: tuple[str, ...]
    missing_candidate: tuple[str, ...]
    candidate_side_effects: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not (
            self.mismatches
            or self.missing_baseline
            or self.missing_candidate
            or self.candidate_side_effects
        )


def compare_shadow(
    baseline: Iterable[Mapping[str, Any]], candidate: Iterable[Mapping[str, Any]]
) -> ShadowDiff:
    base = _index_records(baseline, "baseline")
    cand = _index_records(candidate, "candidate")
    missing_baseline = tuple(sorted(set(cand) - set(base)))
    missing_candidate = tuple(sorted(set(base) - set(cand)))
    mismatches: list[str] = []
    side_effects: list[str] = []
    for request_id in sorted(set(base) & set(cand)):
        for field in ("action", "amountMinor", "currency", "reasonCodes"):
            if base[request_id].get(field) != cand[request_id].get(field):
                mismatches.append(f"{request_id}:{field}")
        effects = cand[request_id].get("sideEffects", [])
        if not isinstance(effects, list):
            raise ValidationError(f"candidate {request_id}.sideEffects must be an array")
        if effects:
            side_effects.append(request_id)
    return ShadowDiff(
        compared=len(set(base) & set(cand)),
        mismatches=tuple(mismatches),
        missing_baseline=missing_baseline,
        missing_candidate=missing_candidate,
        candidate_side_effects=tuple(side_effects),
    )


def _index_records(
    records: Iterable[Mapping[str, Any]], label: str
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for raw in records:
        record = require_mapping(raw, label)
        request_id = require_text(record.get("requestId"), f"{label}.requestId")
        if request_id in indexed:
            raise ValidationError(f"duplicate {label} requestId: {request_id}")
        indexed[request_id] = record
    if not indexed:
        raise ValidationError(f"{label} data set must not be empty")
    return indexed


def evaluate_canary(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any], policy: Mapping[str, Any]
) -> GateReport:
    limits = require_mapping(policy.get("autoStop"), "autoStop")
    required_metrics = {
        "requestCount",
        "errorRate",
        "latencyP99Ms",
        "authorizationRate",
        "ledgerMismatchCount",
        "duplicateSideEffectCount",
        "securityCriticalCount",
    }
    reasons: list[str] = []
    for label, metrics in (("baseline", baseline), ("candidate", candidate)):
        missing = required_metrics - set(metrics)
        if missing:
            reasons.append(f"{label}_metrics_missing:{','.join(sorted(missing))}")
    if reasons:
        return GateReport.from_reasons(reasons)
    try:
        base_requests = int(baseline["requestCount"])
        candidate_requests = int(candidate["requestCount"])
        base_error = Decimal(str(baseline["errorRate"]))
        candidate_error = Decimal(str(candidate["errorRate"]))
        base_latency = Decimal(str(baseline["latencyP99Ms"]))
        candidate_latency = Decimal(str(candidate["latencyP99Ms"]))
        base_auth = Decimal(str(baseline["authorizationRate"]))
        candidate_auth = Decimal(str(candidate["authorizationRate"]))
    except (ValueError, TypeError, InvalidOperation) as exc:
        raise ValidationError("canary metrics must be finite numeric values") from exc
    numeric_values = (
        base_error,
        candidate_error,
        base_latency,
        candidate_latency,
        base_auth,
        candidate_auth,
    )
    if not all(value.is_finite() for value in numeric_values):
        raise ValidationError("canary metrics must be finite numeric values")
    if not (
        Decimal(0) <= base_error <= Decimal(1)
        and Decimal(0) <= candidate_error <= Decimal(1)
        and Decimal(0) <= base_auth <= Decimal(1)
        and Decimal(0) <= candidate_auth <= Decimal(1)
        and base_latency >= 0
        and candidate_latency >= 0
    ):
        raise ValidationError("canary rates and latency are outside their valid ranges")
    if base_requests <= 0 or candidate_requests <= 0:
        reasons.append("insufficient_canary_traffic")
    if candidate_error - base_error > Decimal(str(limits["errorRateDelta"])):
        reasons.append("error_rate_delta_exceeded")
    if candidate_latency - base_latency > Decimal(str(limits["latencyP99DeltaMs"])):
        reasons.append("latency_p99_delta_exceeded")
    if base_auth - candidate_auth > Decimal(str(limits["authorizationRateDrop"])):
        reasons.append("authorization_rate_drop_exceeded")
    for metric, limit_key in (
        ("ledgerMismatchCount", "ledgerMismatchCount"),
        ("duplicateSideEffectCount", "duplicateSideEffectCount"),
        ("securityCriticalCount", "securityCriticalCount"),
    ):
        value = candidate[metric]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValidationError(f"{metric} must be a non-negative integer")
        if value > int(limits[limit_key]):
            reasons.append(f"{metric}_exceeded")
    return GateReport.from_reasons(reasons, checks=required_metrics)


def evaluate_go_no_go(
    release: GateReport,
    shadow: ShadowDiff,
    canary: GateReport,
    capacity: GateReport,
    operations: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> GateReport:
    reasons: list[str] = []
    checks: list[str] = []
    if not release.allowed:
        reasons.extend(f"release:{reason}" for reason in release.reasons)
    else:
        checks.append("release_gate")
    if not shadow.passed:
        reasons.append("shadow_diff_failed")
    else:
        checks.append("shadow_diff")
    if not canary.allowed:
        reasons.extend(f"canary:{reason}" for reason in canary.reasons)
    else:
        checks.append("canary_gate")
    if not capacity.allowed:
        reasons.extend(f"capacity:{reason}" for reason in capacity.reasons)
    else:
        checks.append("capacity_gate")
    gate = require_mapping(policy.get("goNoGo"), "goNoGo")
    required_operational = {
        "rollbackTestPassed",
        "gitopsDriftCount",
        "openCriticalIncidents",
    }
    missing = required_operational - set(operations)
    for key in sorted(missing):
        reasons.append(f"operations_missing:{key}")
    if operations.get("rollbackTestPassed") is not True:
        reasons.append("rollback_test_not_passed")
    if operations.get("gitopsDriftCount") != 0:
        reasons.append("gitops_drift_present")
    required_open = gate.get("requireOpenCriticalIncidents")
    if operations.get("openCriticalIncidents") != required_open:
        reasons.append("critical_incidents_open")
    return GateReport.from_reasons(reasons, checks)
