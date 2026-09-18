# tools/runtime/elmpay_runtime/smart_routing.py
from __future__ import annotations

import datetime
import json
import uuid
from typing import Any, Dict, List, Optional

from .common import ValidationError
from .durable import DurableStore


class SmartRoutingEngine:
    """Intelligent multi-provider routing with Least-Cost Routing (LCR), circuit breakers, and fallback cascades."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def register_provider_profile(
        self,
        tenant_id: str,
        provider_id: str,
        provider_name: str,
        supported_methods: List[str],
        supported_currencies: List[str],
        min_amount_minor: int = 1,
        max_amount_minor: int = 100_000_000,
        fee_basis_points: int = 30,
        fixed_fee_minor: int = 30,
        priority_rank: int = 100,
    ) -> Dict[str, Any]:
        """Registers or updates a payment acquiring provider with its pricing and capabilities."""
        if not supported_methods or not supported_currencies:
            raise ValidationError("supported_methods and supported_currencies cannot be empty")
        if min_amount_minor < 0 or max_amount_minor <= min_amount_minor:
            raise ValidationError("invalid amount bounds")
        if fee_basis_points < 0 or fixed_fee_minor < 0:
            raise ValidationError("fee parameters cannot be negative")

        methods_csv = ",".join(sorted(set(m.strip().upper() for m in supported_methods)))
        currencies_csv = ",".join(sorted(set(c.strip().upper() for c in supported_currencies)))
        profile_id = f"rtp_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO routing_provider_profile (
                    profile_id, tenant_id, provider_id, provider_name,
                    supported_methods_csv, supported_currencies_csv,
                    min_amount_minor, max_amount_minor,
                    fee_basis_points, fixed_fee_minor,
                    health_status, priority_rank,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'HEALTHY', ?, ?, ?)
                ON CONFLICT(tenant_id, provider_id) DO UPDATE SET
                    provider_name = excluded.provider_name,
                    supported_methods_csv = excluded.supported_methods_csv,
                    supported_currencies_csv = excluded.supported_currencies_csv,
                    min_amount_minor = excluded.min_amount_minor,
                    max_amount_minor = excluded.max_amount_minor,
                    fee_basis_points = excluded.fee_basis_points,
                    fixed_fee_minor = excluded.fixed_fee_minor,
                    priority_rank = excluded.priority_rank,
                    updated_at = excluded.updated_at
                """,
                (
                    profile_id, tenant_id, provider_id, provider_name,
                    methods_csv, currencies_csv,
                    min_amount_minor, max_amount_minor,
                    fee_basis_points, fixed_fee_minor,
                    priority_rank, now_iso, now_iso
                ),
            )

        return {
            "tenant_id": tenant_id,
            "provider_id": provider_id,
            "provider_name": provider_name,
            "supported_methods": methods_csv.split(","),
            "supported_currencies": currencies_csv.split(","),
            "fee_basis_points": fee_basis_points,
            "fixed_fee_minor": fixed_fee_minor,
            "priority_rank": priority_rank,
            "health_status": "HEALTHY",
        }

    def update_provider_health(self, tenant_id: str, provider_id: str, health_status: str) -> Dict[str, Any]:
        """Sets circuit breaker / health state: HEALTHY, DEGRADED, or CIRCUIT_BROKEN."""
        health_status = health_status.strip().upper()
        if health_status not in ("HEALTHY", "DEGRADED", "CIRCUIT_BROKEN"):
            raise ValidationError(f"invalid health_status: {health_status}")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.store.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE routing_provider_profile
                SET health_status = ?, updated_at = ?
                WHERE tenant_id = ? AND provider_id = ?
                """,
                (health_status, now_iso, tenant_id, provider_id),
            )
            if cur.rowcount == 0:
                raise ValidationError(f"provider {provider_id} not found")

        return {
            "tenant_id": tenant_id,
            "provider_id": provider_id,
            "health_status": health_status,
            "updated_at": now_iso,
        }

    def route_transaction(
        self,
        tenant_id: str,
        payment_intent_id: str,
        amount_minor: int,
        currency: str,
        payment_method: str,
        card_brand: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluates all candidate providers and selects optimal Least-Cost Route with fallback cascades."""
        if amount_minor <= 0:
            raise ValidationError("amount_minor must be strictly positive")
        currency = currency.strip().upper()
        payment_method = payment_method.strip().upper()

        with self.store.transaction() as conn:
            rows = conn.execute(
                """
                SELECT * FROM routing_provider_profile
                WHERE tenant_id = ? AND health_status != 'CIRCUIT_BROKEN'
                  AND min_amount_minor <= ? AND max_amount_minor >= ?
                """,
                (tenant_id, amount_minor, amount_minor),
            ).fetchall()

        candidates: List[Dict[str, Any]] = []
        for r in rows:
            methods = [m.strip().upper() for m in r["supported_methods_csv"].split(",") if m.strip()]
            currencies = [c.strip().upper() for c in r["supported_currencies_csv"].split(",") if c.strip()]

            if payment_method in methods and currency in currencies:
                # Calculate estimated processing fee
                est_fee = (amount_minor * r["fee_basis_points"]) // 10000 + r["fixed_fee_minor"]
                health_penalty = 0 if r["health_status"] == "HEALTHY" else 100000

                candidates.append({
                    "provider_id": r["provider_id"],
                    "provider_name": r["provider_name"],
                    "health_status": r["health_status"],
                    "fee_basis_points": r["fee_basis_points"],
                    "fixed_fee_minor": r["fixed_fee_minor"],
                    "estimated_fee_minor": est_fee,
                    "priority_rank": r["priority_rank"],
                    "_sort_key": (health_penalty, est_fee, r["priority_rank"]),
                })

        if not candidates:
            raise ValidationError(
                f"no eligible payment provider found for routing (currency={currency}, method={payment_method}, amount={amount_minor})"
            )

        # Sort by: Health (healthy before degraded) -> Lowest estimated fee -> Priority rank
        candidates.sort(key=lambda x: x["_sort_key"])
        selected = candidates[0]
        cascade = [c["provider_id"] for c in candidates]

        decision_id = f"rtd_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO smart_routing_decision_log (
                    decision_id, tenant_id, payment_intent_id,
                    amount_minor, currency, payment_method, card_brand,
                    selected_provider_id, estimated_fee_minor,
                    cascade_routes_json, routed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id, tenant_id, payment_intent_id,
                    amount_minor, currency, payment_method, card_brand,
                    selected["provider_id"], selected["estimated_fee_minor"],
                    json.dumps(cascade), now_iso
                ),
            )

        return {
            "decision_id": decision_id,
            "tenant_id": tenant_id,
            "payment_intent_id": payment_intent_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "payment_method": payment_method,
            "card_brand": card_brand,
            "selected_provider_id": selected["provider_id"],
            "selected_provider_name": selected["provider_name"],
            "estimated_fee_minor": selected["estimated_fee_minor"],
            "cascade_routes": cascade,
            "routed_at": now_iso,
        }
