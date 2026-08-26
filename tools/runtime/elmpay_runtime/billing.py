from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping

from .common import ValidationError, parse_instant, require_list, require_mapping, require_text


@dataclass(frozen=True)
class InvoiceLine:
    meter: str
    quantity: int
    unit_price_minor: int

    @property
    def total_minor(self) -> int:
        return self.quantity * self.unit_price_minor


@dataclass(frozen=True)
class Invoice:
    tenant_id: str
    period_start: datetime
    period_end: datetime
    currency: str
    lines: tuple[InvoiceLine, ...]
    duplicate_events: int

    @property
    def total_minor(self) -> int:
        return sum(line.total_minor for line in self.lines)


def calculate_invoice(
    policy: Mapping[str, Any],
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
    events: Iterable[Mapping[str, Any]],
) -> Invoice:
    require_text(tenant_id, "tenant_id")
    if period_start.tzinfo is None or period_end.tzinfo is None or period_end <= period_start:
        raise ValidationError("billing period must be an increasing timezone-aware interval")
    meters: dict[str, Mapping[str, Any]] = {}
    for raw in require_list(policy.get("meters"), "billing meters"):
        meter = require_mapping(raw, "meter")
        name = require_text(meter.get("name"), "meter.name")
        if name in meters:
            raise ValidationError(f"duplicate billing meter: {name}")
        unit = meter.get("unitPriceMinor")
        if isinstance(unit, bool) or not isinstance(unit, int) or unit < 0:
            raise ValidationError("unitPriceMinor must be a non-negative integer")
        meters[name] = meter
    counts = {name: 0 for name in meters}
    seen: set[tuple[str, str]] = set()
    duplicates = 0
    for raw in events:
        event = require_mapping(raw, "usage event")
        if require_text(event.get("tenantId"), "event.tenantId") != tenant_id:
            raise ValidationError("cross-tenant usage event is forbidden")
        name = require_text(event.get("meter"), "event.meter")
        if name not in meters:
            raise ValidationError(f"unknown usage meter: {name}")
        dedupe_field = require_text(meters[name].get("deduplicateBy"), "deduplicateBy")
        dedupe_value = require_text(event.get(dedupe_field), f"event.{dedupe_field}")
        occurred_at = parse_instant(event.get("occurredAt"), "event.occurredAt")
        if not period_start <= occurred_at < period_end:
            continue
        key = (name, dedupe_value)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        counts[name] += 1
    lines = tuple(
        InvoiceLine(name, counts[name], int(meters[name]["unitPriceMinor"]))
        for name in sorted(meters)
        if counts[name] > 0
    )
    return Invoice(
        tenant_id=tenant_id,
        period_start=period_start,
        period_end=period_end,
        currency=require_text(policy.get("currency"), "currency"),
        lines=lines,
        duplicate_events=duplicates,
    )
