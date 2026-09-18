# tools/runtime/elmpay_runtime/marketplace_escrow.py
from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Optional

from .common import ValidationError
from .durable import DurableStore


class MarketplaceEscrowManager:
    """Manages multi-vendor marketplace split payments, platform commissions, and escrow holding periods."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def create_split_order(
        self,
        tenant_id: str,
        order_id: str,
        captured_amount_minor: int,
        currency: str,
        platform_fee_minor: int,
        recipients: List[Dict[str, Any]],
        hold_days: int = 7,
    ) -> Dict[str, Any]:
        """Creates a marketplace order held in escrow, enforcing mathematical split conservation."""
        if captured_amount_minor <= 0:
            raise ValidationError("captured_amount_minor must be strictly positive")
        if platform_fee_minor < 0:
            raise ValidationError("platform_fee_minor cannot be negative")
        if not recipients:
            raise ValidationError("recipients list cannot be empty")

        currency = currency.strip().upper()
        total_vendor_amount = 0
        validated_recips: List[Dict[str, Any]] = []

        for r in recipients:
            vid = str(r.get("vendor_id", "")).strip()
            amt = int(r.get("amount_minor", 0))
            if not vid:
                raise ValidationError("recipient vendor_id cannot be empty")
            if amt <= 0:
                raise ValidationError(f"vendor {vid} allocated amount must be strictly positive")
            total_vendor_amount += amt
            validated_recips.append({
                "recipient_split_id": f"spt_{uuid.uuid4().hex[:12]}",
                "vendor_id": vid,
                "amount_minor": amt,
            })

        # Mathematical conservation constraint: sum(vendor_splits) + platform_fee == captured_amount
        if total_vendor_amount + platform_fee_minor != captured_amount_minor:
            raise ValidationError(
                f"mathematical split conservation violation: sum of vendor splits ({total_vendor_amount}) "
                f"+ platform fee ({platform_fee_minor}) = {total_vendor_amount + platform_fee_minor}, "
                f"expected captured amount {captured_amount_minor}"
            )

        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now_dt.isoformat()
        hold_until_iso = (now_dt + datetime.timedelta(days=hold_days)).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO marketplace_split_order (
                    order_id, tenant_id, captured_amount_minor, currency,
                    platform_fee_minor, escrow_status, hold_until,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, 'HELD', ?, ?)
                """,
                (order_id, tenant_id, captured_amount_minor, currency, platform_fee_minor, hold_until_iso, now_iso),
            )

            for vr in validated_recips:
                conn.execute(
                    """
                    INSERT INTO marketplace_split_recipient (
                        recipient_split_id, tenant_id, order_id, vendor_id,
                        allocated_amount_minor, settled_amount_minor, refunded_amount_minor,
                        status, created_at
                    ) VALUES (?, ?, ?, ?, ?, 0, 0, 'PENDING', ?)
                    """,
                    (vr["recipient_split_id"], tenant_id, order_id, vr["vendor_id"], vr["amount_minor"], now_iso),
                )

        return {
            "order_id": order_id,
            "tenant_id": tenant_id,
            "captured_amount_minor": captured_amount_minor,
            "currency": currency,
            "platform_fee_minor": platform_fee_minor,
            "vendor_splits_total_minor": total_vendor_amount,
            "escrow_status": "HELD",
            "hold_until": hold_until_iso,
            "recipients": validated_recips,
        }

    def release_escrow(self, tenant_id: str, order_id: str) -> Dict[str, Any]:
        """Releases held escrow funds to respective vendor sub-accounts after inspection."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE marketplace_split_order
                SET escrow_status = 'RELEASED', released_at = ?
                WHERE order_id = ? AND tenant_id = ? AND escrow_status = 'HELD'
                """,
                (now_iso, order_id, tenant_id),
            )
            if cur.rowcount == 0:
                order = conn.execute(
                    "SELECT * FROM marketplace_split_order WHERE order_id = ? AND tenant_id = ?",
                    (order_id, tenant_id),
                ).fetchone()
                if not order:
                    raise ValidationError(f"order {order_id} not found")
                raise ValidationError(f"cannot release order in status {order['escrow_status']}")

            conn.execute(
                """
                UPDATE marketplace_split_recipient
                SET status = 'RELEASED', settled_amount_minor = allocated_amount_minor - refunded_amount_minor
                WHERE order_id = ?
                """,
                (order_id,),
            )

        return {
            "order_id": order_id,
            "escrow_status": "RELEASED",
            "released_at": now_iso,
        }

    def refund_split_order(
        self,
        tenant_id: str,
        order_id: str,
        refund_amount_minor: int,
    ) -> Dict[str, Any]:
        """Proportionately refunds marketplace escrow prior to or after release."""
        if refund_amount_minor <= 0:
            raise ValidationError("refund_amount_minor must be strictly positive")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            order = conn.execute(
                "SELECT * FROM marketplace_split_order WHERE order_id = ? AND tenant_id = ?",
                (order_id, tenant_id),
            ).fetchone()

            if not order:
                raise ValidationError(f"order {order_id} not found")

            available_to_refund = order["captured_amount_minor"] - order["refunded_amount_minor"]
            if refund_amount_minor > available_to_refund:
                raise ValidationError(
                    f"refund amount {refund_amount_minor} exceeds remaining refundable balance {available_to_refund}"
                )

            new_refunded = order["refunded_amount_minor"] + refund_amount_minor
            new_status = "REFUNDED" if new_refunded == order["captured_amount_minor"] else "PARTIALLY_REFUNDED"

            conn.execute(
                """
                UPDATE marketplace_split_order
                SET refunded_amount_minor = ?, escrow_status = ?
                WHERE order_id = ?
                """,
                (new_refunded, new_status, order_id),
            )

            # Proportionately refund each recipient
            recips = conn.execute(
                "SELECT * FROM marketplace_split_recipient WHERE order_id = ?",
                (order_id,),
            ).fetchall()

            for r in recips:
                r_portion = (refund_amount_minor * r["allocated_amount_minor"]) // order["captured_amount_minor"]
                new_r_ref = r["refunded_amount_minor"] + r_portion
                r_status = "REFUNDED" if new_r_ref == r["allocated_amount_minor"] else r["status"]

                conn.execute(
                    """
                    UPDATE marketplace_split_recipient
                    SET refunded_amount_minor = ?, status = ?
                    WHERE recipient_split_id = ?
                    """,
                    (new_r_ref, r_status, r["recipient_split_id"]),
                )

        return {
            "order_id": order_id,
            "refunded_amount_minor": refund_amount_minor,
            "total_refunded_minor": new_refunded,
            "escrow_status": new_status,
        }

    def get_split_order_status(self, tenant_id: str, order_id: str) -> Dict[str, Any]:
        with self.store.transaction() as conn:
            order = conn.execute(
                "SELECT * FROM marketplace_split_order WHERE order_id = ? AND tenant_id = ?",
                (order_id, tenant_id),
            ).fetchone()
            if not order:
                raise ValidationError(f"order {order_id} not found")

            recips = conn.execute(
                "SELECT * FROM marketplace_split_recipient WHERE order_id = ?",
                (order_id,),
            ).fetchall()

        data = dict(order)
        data["recipients"] = [dict(r) for r in recips]
        return data
