from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from .common import GateReport, ValidationError, parse_instant, require_list, require_mapping


@dataclass(frozen=True)
class CapacityAssessment:
    report: GateReport
    current_headroom: Mapping[str, Decimal]
    forecast_headroom: Mapping[str, Decimal]


def evaluate_capacity(
    policy: Mapping[str, Any], samples: Mapping[str, Any]
) -> CapacityAssessment:
    reasons: list[str] = []
    checks: list[str] = []
    minimum_samples = policy.get("minimumSamples")
    horizon_days = policy.get("forecastHorizonDays")
    try:
        minimum_headroom = Decimal(str(policy.get("minimumHeadroomRatio")))
    except InvalidOperation as exc:
        raise ValidationError("minimumHeadroomRatio must be numeric") from exc
    if not minimum_headroom.is_finite() or not Decimal(0) < minimum_headroom < Decimal(1):
        raise ValidationError("minimumHeadroomRatio must be between zero and one")
    if not isinstance(minimum_samples, int) or minimum_samples < 2:
        raise ValidationError("minimumSamples must be at least two")
    if not isinstance(horizon_days, int) or horizon_days <= 0:
        raise ValidationError("forecastHorizonDays must be positive")
    required = set(require_list(policy.get("resources"), "capacity resources"))
    current_headroom: dict[str, Decimal] = {}
    forecast_headroom: dict[str, Decimal] = {}
    for resource in sorted(required):
        raw_series = samples.get(resource)
        if not isinstance(raw_series, list) or len(raw_series) < minimum_samples:
            reasons.append(f"capacity_samples_missing:{resource}")
            continue
        series: list[tuple[datetime, Decimal]] = []
        for index, raw in enumerate(raw_series):
            sample = require_mapping(raw, f"{resource}[{index}]")
            try:
                used = Decimal(str(sample.get("used")))
                capacity = Decimal(str(sample.get("capacity")))
            except InvalidOperation as exc:
                raise ValidationError(f"{resource} sample values must be numeric") from exc
            if not used.is_finite() or not capacity.is_finite():
                reasons.append(f"capacity_sample_invalid:{resource}:{index}")
                continue
            if used < 0 or capacity <= 0 or used > capacity:
                reasons.append(f"capacity_sample_invalid:{resource}:{index}")
                continue
            series.append(
                (parse_instant(sample.get("observedAt"), f"{resource}[{index}].observedAt"), used / capacity)
            )
        series.sort(key=lambda item: item[0])
        if len(series) < minimum_samples or len({item[0] for item in series}) != len(series):
            reasons.append(f"capacity_series_invalid:{resource}")
            continue
        first_time, first_utilization = series[0]
        last_time, last_utilization = series[-1]
        elapsed_days = Decimal(str((last_time - first_time).total_seconds())) / Decimal(86400)
        if elapsed_days <= 0:
            reasons.append(f"capacity_series_not_increasing:{resource}")
            continue
        peak_utilization = max(item[1] for item in series)
        slope = (last_utilization - first_utilization) / elapsed_days
        projected = max(last_utilization, last_utilization + slope * Decimal(horizon_days))
        projected = min(Decimal(1), max(Decimal(0), projected))
        current = Decimal(1) - peak_utilization
        forecast = Decimal(1) - projected
        current_headroom[resource] = current
        forecast_headroom[resource] = forecast
        checks.append(f"capacity:{resource}")
        if current < minimum_headroom:
            reasons.append(f"current_headroom_low:{resource}")
        if forecast < minimum_headroom:
            reasons.append(f"forecast_headroom_low:{resource}")
    for unknown in sorted(set(samples) - required):
        reasons.append(f"unknown_capacity_resource:{unknown}")
    return CapacityAssessment(
        report=GateReport.from_reasons(reasons, checks),
        current_headroom=current_headroom,
        forecast_headroom=forecast_headroom,
    )
