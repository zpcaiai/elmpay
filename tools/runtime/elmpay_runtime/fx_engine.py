# tools/runtime/elmpay_runtime/fx_engine.py
from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, Optional

from .common import ValidationError
from .durable import DurableStore

RATE_SCALE = 1_000_000  # 1.000000 = 1_000_000 units for 6-decimal fixed-point accuracy


class FXQuoteLockManager:
    """Manages guaranteed FX rate locks, spread markups, and Dynamic Currency Conversion (DCC)."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def set_rate_matrix(
        self,
        tenant_id: str,
        base_currency: str,
        target_currency: str,
        spot_rate_units: int,
        spread_basis_points: int = 50,
    ) -> Dict[str, Any]:
        """Sets or updates spot exchange rate and spread markup in basis points (1 bp = 0.01%)."""
        base_currency = base_currency.strip().upper()
        target_currency = target_currency.strip().upper()

        if len(base_currency) != 3 or len(target_currency) != 3:
            raise ValidationError("currency codes must be 3 uppercase letters (ISO 4217)")
        if spot_rate_units <= 0:
            raise ValidationError("spot_rate_units must be strictly positive")
        if spread_basis_points < 0:
            raise ValidationError("spread_basis_points cannot be negative")

        matrix_id = f"mtx_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO fx_rate_matrix (
                    matrix_id, tenant_id, base_currency, target_currency,
                    spot_rate_units, spread_basis_points, effective_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, base_currency, target_currency) DO UPDATE SET
                    spot_rate_units = excluded.spot_rate_units,
                    spread_basis_points = excluded.spread_basis_points,
                    effective_at = excluded.effective_at
                """,
                (matrix_id, tenant_id, base_currency, target_currency, spot_rate_units, spread_basis_points, now_iso),
            )

        return {
            "tenant_id": tenant_id,
            "base_currency": base_currency,
            "target_currency": target_currency,
            "spot_rate_units": spot_rate_units,
            "spread_basis_points": spread_basis_points,
            "effective_at": now_iso,
        }

    def get_rate_matrix(self, tenant_id: str, base_currency: str, target_currency: str) -> Dict[str, Any]:
        base_currency = base_currency.strip().upper()
        target_currency = target_currency.strip().upper()

        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM fx_rate_matrix WHERE tenant_id = ? AND base_currency = ? AND target_currency = ?",
                (tenant_id, base_currency, target_currency),
            ).fetchone()

        if not row:
            raise ValidationError(f"no exchange rate configured for {base_currency}->{target_currency}")

        return dict(row)

    def create_quote_lock(
        self,
        tenant_id: str,
        base_currency: str,
        target_currency: str,
        source_amount_minor: int,
        ttl_seconds: int = 900,
    ) -> Dict[str, Any]:
        """Locks a guaranteed exchange rate for ttl_seconds (default 15 minutes)."""
        base_currency = base_currency.strip().upper()
        target_currency = target_currency.strip().upper()

        if source_amount_minor <= 0:
            raise ValidationError("source_amount_minor must be strictly positive")
        if ttl_seconds <= 0:
            raise ValidationError("ttl_seconds must be positive")

        matrix = self.get_rate_matrix(tenant_id, base_currency, target_currency)
        spot_rate = matrix["spot_rate_units"]
        spread_bps = matrix["spread_basis_points"]

        effective_rate = spot_rate * (10000 + spread_bps) // 10000
        target_amount_minor = (source_amount_minor * effective_rate) // RATE_SCALE
        if target_amount_minor <= 0:
            target_amount_minor = 1

        quote_id = f"qte_{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now.isoformat()
        expires_at = (now + datetime.timedelta(seconds=ttl_seconds)).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO fx_quote_lock (
                    quote_id, tenant_id, base_currency, target_currency,
                    source_amount_minor, target_amount_minor,
                    spot_rate_units, spread_basis_points, effective_rate_units,
                    status, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'LOCKED', ?, ?)
                """,
                (
                    quote_id, tenant_id, base_currency, target_currency,
                    source_amount_minor, target_amount_minor,
                    spot_rate, spread_bps, effective_rate,
                    expires_at, now_iso
                ),
            )

        return {
            "quote_id": quote_id,
            "tenant_id": tenant_id,
            "base_currency": base_currency,
            "target_currency": target_currency,
            "source_amount_minor": source_amount_minor,
            "target_amount_minor": target_amount_minor,
            "spot_rate_units": spot_rate,
            "spread_basis_points": spread_bps,
            "effective_rate_units": effective_rate,
            "status": "LOCKED",
            "expires_at": expires_at,
            "created_at": now_iso,
        }

    def redeem_quote_lock(self, tenant_id: str, quote_id: str, payment_intent_id: str) -> Dict[str, Any]:
        """Redeems an active quote lock for a specific payment intent."""
        now = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now.isoformat()

        with self.store.transaction() as conn:
            quote = conn.execute(
                "SELECT * FROM fx_quote_lock WHERE quote_id = ? AND tenant_id = ?",
                (quote_id, tenant_id),
            ).fetchone()

            if not quote:
                raise ValidationError(f"quote lock {quote_id} not found")

            if quote["status"] != "LOCKED":
                raise ValidationError(f"quote lock {quote_id} is not in LOCKED status (current: {quote['status']})")

            # Check expiration
            expires_at = datetime.datetime.fromisoformat(quote["expires_at"])
            if now >= expires_at:
                conn.execute(
                    "UPDATE fx_quote_lock SET status = 'EXPIRED' WHERE quote_id = ?",
                    (quote_id,),
                )
                raise ValidationError(f"quote lock {quote_id} has expired at {quote['expires_at']}")

            cur = conn.execute(
                """
                UPDATE fx_quote_lock
                SET status = 'REDEEMED', redeemed_at = ?, payment_intent_id = ?
                WHERE quote_id = ? AND tenant_id = ? AND status = 'LOCKED' AND expires_at > ?
                """,
                (now_iso, payment_intent_id, quote_id, tenant_id, now_iso),
            )
            if cur.rowcount == 0:
                raise ValidationError(f"failed to redeem quote {quote_id} (already redeemed or expired)")

            conversion_id = f"fxc_{uuid.uuid4().hex[:12]}"
            conn.execute(
                """
                INSERT INTO fx_conversion_journal (
                    conversion_id, tenant_id, quote_id, payment_intent_id,
                    base_currency, target_currency, source_amount_minor, target_amount_minor,
                    executed_rate_units, hedged, executed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    conversion_id, tenant_id, quote_id, payment_intent_id,
                    quote["base_currency"], quote["target_currency"],
                    quote["source_amount_minor"], quote["target_amount_minor"],
                    quote["effective_rate_units"], now_iso
                ),
            )

        return {
            "conversion_id": conversion_id,
            "quote_id": quote_id,
            "payment_intent_id": payment_intent_id,
            "status": "REDEEMED",
            "base_currency": quote["base_currency"],
            "target_currency": quote["target_currency"],
            "source_amount_minor": quote["source_amount_minor"],
            "target_amount_minor": quote["target_amount_minor"],
            "executed_rate_units": quote["effective_rate_units"],
            "redeemed_at": now_iso,
        }

    def evaluate_dcc_offer(
        self,
        tenant_id: str,
        card_currency: str,
        merchant_currency: str,
        transaction_amount_minor: int,
    ) -> Dict[str, Any]:
        """Evaluates Dynamic Currency Conversion (DCC) eligibility and returns cardholder disclosure receipt."""
        card_currency = card_currency.strip().upper()
        merchant_currency = merchant_currency.strip().upper()

        if card_currency == merchant_currency:
            return {
                "dcc_eligible": False,
                "reason": "card currency matches merchant currency",
                "transaction_currency": merchant_currency,
                "transaction_amount_minor": transaction_amount_minor,
            }

        matrix = self.get_rate_matrix(tenant_id, merchant_currency, card_currency)
        spot_rate = matrix["spot_rate_units"]
        spread_bps = matrix["spread_basis_points"]
        effective_rate = spot_rate * (10000 + spread_bps) // 10000

        converted_amount_minor = (transaction_amount_minor * effective_rate) // RATE_SCALE
        if converted_amount_minor <= 0:
            converted_amount_minor = 1

        markup_percentage = f"{spread_bps / 100.0:.2f}%"

        return {
            "dcc_eligible": True,
            "merchant_currency": merchant_currency,
            "merchant_amount_minor": transaction_amount_minor,
            "cardholder_currency": card_currency,
            "cardholder_amount_minor": converted_amount_minor,
            "exchange_rate_units": effective_rate,
            "spread_basis_points": spread_bps,
            "markup_percentage": markup_percentage,
            "disclosure_notice": (
                f"Cardholder is offered the choice to pay in their billing currency ({card_currency}). "
                f"Includes a currency conversion markup of {markup_percentage} over the interbank exchange rate."
            ),
        }

    def get_quote_status(self, tenant_id: str, quote_id: str) -> Dict[str, Any]:
        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM fx_quote_lock WHERE quote_id = ? AND tenant_id = ?",
                (quote_id, tenant_id),
            ).fetchone()
        if not row:
            raise ValidationError(f"quote {quote_id} not found")
        return dict(row)
