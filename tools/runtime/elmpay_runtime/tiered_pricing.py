# tools/runtime/elmpay_runtime/tiered_pricing.py
from __future__ import annotations

import datetime
import json
import uuid
from typing import Any, Dict, List, Optional

from .common import ValidationError
from .durable import DurableStore


class TieredPricingEngine:
    """Merchant tiered pricing, volume discounts, and Interchange Plus Plus (IC++) unbundled pricing."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def configure_fee_schedule(
        self,
        tenant_id: str,
        pricing_model: str,
        tiers: Optional[List[Dict[str, Any]]] = None,
        markup_basis_points: int = 30,
        fixed_fee_minor: int = 30,
    ) -> Dict[str, Any]:
        """Configures merchant contract fee schedule (BLENDED, TIERED_VOLUME, or INTERCHANGE_PLUS_PLUS)."""
        pricing_model = pricing_model.strip().upper()
        if pricing_model not in ("BLENDED", "TIERED_VOLUME", "INTERCHANGE_PLUS_PLUS"):
            raise ValidationError(f"invalid pricing_model: {pricing_model}")
        if markup_basis_points < 0 or fixed_fee_minor < 0:
            raise ValidationError("fee values cannot be negative")

        tiers_json = json.dumps(tiers) if tiers else None
        schedule_id = f"sch_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO merchant_fee_schedule (
                    schedule_id, tenant_id, pricing_model, tiers_json,
                    markup_basis_points, fixed_fee_minor,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    pricing_model = excluded.pricing_model,
                    tiers_json = excluded.tiers_json,
                    markup_basis_points = excluded.markup_basis_points,
                    fixed_fee_minor = excluded.fixed_fee_minor,
                    updated_at = excluded.updated_at
                """,
                (
                    schedule_id, tenant_id, pricing_model, tiers_json,
                    markup_basis_points, fixed_fee_minor,
                    now_iso, now_iso
                ),
            )

        return {
            "tenant_id": tenant_id,
            "pricing_model": pricing_model,
            "tiers": tiers,
            "markup_basis_points": markup_basis_points,
            "fixed_fee_minor": fixed_fee_minor,
            "updated_at": now_iso,
        }

    def calculate_merchant_fee(
        self,
        tenant_id: str,
        transaction_id: str,
        amount_minor: int,
        currency: str = "CNY",
        card_brand: Optional[str] = "VISA",
        monthly_accumulated_volume_minor: int = 0,
    ) -> Dict[str, Any]:
        """Calculates transaction fee breakdown, interchange cost, scheme assessments, and net margin."""
        if amount_minor <= 0:
            raise ValidationError("amount_minor must be strictly positive")

        with self.store.transaction() as conn:
            sched = conn.execute(
                "SELECT * FROM merchant_fee_schedule WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()

        if not sched:
            # Default blended fee: 60 bps + 30 minor
            pricing_model = "BLENDED"
            markup_bps = 60
            fixed_fee = 30
            tiers = None
        else:
            pricing_model = sched["pricing_model"]
            markup_bps = sched["markup_basis_points"]
            fixed_fee = sched["fixed_fee_minor"]
            tiers = json.loads(sched["tiers_json"]) if sched["tiers_json"] else None

        interchange_cost_minor = 0
        scheme_assessment_minor = 0

        if pricing_model == "BLENDED":
            gross_fee_minor = (amount_minor * markup_bps) // 10000 + fixed_fee
            net_margin_minor = gross_fee_minor

        elif pricing_model == "TIERED_VOLUME":
            effective_bps = markup_bps
            if tiers:
                for t in sorted(tiers, key=lambda x: x.get("up_to_minor") or float("inf")):
                    up_to = t.get("up_to_minor")
                    if up_to is None or monthly_accumulated_volume_minor <= up_to:
                        effective_bps = int(t.get("fee_bps", markup_bps))
                        break

            gross_fee_minor = (amount_minor * effective_bps) // 10000 + fixed_fee
            net_margin_minor = gross_fee_minor

        elif pricing_model == "INTERCHANGE_PLUS_PLUS":
            # Typical unbundled interchange: 140 bps, scheme fee: 15 bps
            ic_rate_bps = 140
            scheme_rate_bps = 15
            interchange_cost_minor = (amount_minor * ic_rate_bps) // 10000
            scheme_assessment_minor = (amount_minor * scheme_rate_bps) // 10000
            acquirer_markup = (amount_minor * markup_bps) // 10000 + fixed_fee

            gross_fee_minor = interchange_cost_minor + scheme_assessment_minor + acquirer_markup
            net_margin_minor = acquirer_markup

        else:
            raise ValidationError(f"unsupported pricing_model: {pricing_model}")

        journal_id = f"fej_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO merchant_fee_journal (
                    journal_id, tenant_id, transaction_id, amount_minor,
                    currency, pricing_model, gross_fee_minor,
                    interchange_cost_minor, scheme_assessment_minor,
                    net_margin_minor, billed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    journal_id, tenant_id, transaction_id, amount_minor,
                    currency, pricing_model, gross_fee_minor,
                    interchange_cost_minor, scheme_assessment_minor,
                    net_margin_minor, now_iso
                ),
            )

        return {
            "journal_id": journal_id,
            "tenant_id": tenant_id,
            "transaction_id": transaction_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "pricing_model": pricing_model,
            "gross_fee_minor": gross_fee_minor,
            "interchange_cost_minor": interchange_cost_minor,
            "scheme_assessment_minor": scheme_assessment_minor,
            "net_margin_minor": net_margin_minor,
            "billed_at": now_iso,
        }
