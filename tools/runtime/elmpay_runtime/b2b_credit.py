# tools/runtime/elmpay_runtime/b2b_credit.py
from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Optional

from .common import ValidationError
from .durable import DurableStore

TERM_DAYS = {
    "DUE_ON_RECEIPT": 0,
    "NET_15": 15,
    "NET_30": 30,
    "NET_60": 60,
    "NET_90": 90,
}


class B2BCreditManager:
    """Manages B2B trade credit lines, purchase orders with Net terms, aging analysis, and repayments."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def create_credit_facility(
        self,
        tenant_id: str,
        buyer_id: str,
        buyer_name: str,
        credit_limit_minor: int,
        currency: str = "CNY",
        credit_tier: str = "STANDARD",
    ) -> Dict[str, Any]:
        """Creates or registers an enterprise buyer trade credit facility."""
        if credit_limit_minor <= 0:
            raise ValidationError("credit_limit_minor must be strictly positive")
        currency = currency.strip().upper()
        if len(currency) != 3:
            raise ValidationError("currency must be 3 uppercase letters (ISO 4217)")
        if credit_tier not in ("STANDARD", "PRIME", "ENTERPRISE"):
            raise ValidationError(f"invalid credit_tier: {credit_tier}")

        facility_id = f"fac_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO b2b_credit_facility (
                    facility_id, tenant_id, buyer_id, buyer_name,
                    credit_limit_minor, drawn_balance_minor, currency,
                    credit_tier, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, 'ACTIVE', ?, ?)
                """,
                (facility_id, tenant_id, buyer_id, buyer_name, credit_limit_minor, currency, credit_tier, now_iso, now_iso),
            )
            # Log limit creation in ledger
            entry_id = f"crd_{uuid.uuid4().hex[:12]}"
            conn.execute(
                """
                INSERT INTO b2b_credit_drawdown_ledger (
                    entry_id, tenant_id, facility_id, action,
                    amount_minor, balance_after_minor, notes, created_at
                ) VALUES (?, ?, ?, 'LIMIT_ADJUSTMENT', ?, 0, 'Initial credit limit granted', ?)
                """,
                (entry_id, tenant_id, facility_id, credit_limit_minor, now_iso),
            )

        return {
            "facility_id": facility_id,
            "tenant_id": tenant_id,
            "buyer_id": buyer_id,
            "buyer_name": buyer_name,
            "credit_limit_minor": credit_limit_minor,
            "drawn_balance_minor": 0,
            "available_credit_minor": credit_limit_minor,
            "currency": currency,
            "credit_tier": credit_tier,
            "status": "ACTIVE",
            "created_at": now_iso,
        }

    def get_facility_status(self, tenant_id: str, buyer_id: str) -> Dict[str, Any]:
        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM b2b_credit_facility WHERE tenant_id = ? AND buyer_id = ?",
                (tenant_id, buyer_id),
            ).fetchone()
        if not row:
            raise ValidationError(f"no credit facility found for buyer {buyer_id}")
        data = dict(row)
        data["available_credit_minor"] = data["credit_limit_minor"] - data["drawn_balance_minor"]
        return data

    def issue_purchase_order(
        self,
        tenant_id: str,
        buyer_id: str,
        po_number: str,
        seller_name: str,
        amount_minor: int,
        payment_terms: str = "NET_30",
        issue_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Issues a purchase order under the buyer's credit facility, drawing down available credit."""
        if amount_minor <= 0:
            raise ValidationError("amount_minor must be strictly positive")
        if payment_terms not in TERM_DAYS:
            raise ValidationError(f"unsupported payment_terms: {payment_terms} (allowed: {list(TERM_DAYS.keys())})")

        now = datetime.datetime.now(datetime.timezone.utc)
        issue_dt = datetime.date.fromisoformat(issue_date) if issue_date else now.date()
        due_dt = issue_dt + datetime.timedelta(days=TERM_DAYS[payment_terms])
        due_date_str = due_dt.isoformat()
        issue_date_str = issue_dt.isoformat()
        now_iso = now.isoformat()

        po_id = f"po_{uuid.uuid4().hex[:12]}"
        entry_id = f"crd_{uuid.uuid4().hex[:12]}"

        with self.store.transaction() as conn:
            facility = conn.execute(
                "SELECT * FROM b2b_credit_facility WHERE tenant_id = ? AND buyer_id = ?",
                (tenant_id, buyer_id),
            ).fetchone()

            if not facility:
                raise ValidationError(f"no credit facility found for buyer {buyer_id}")
            if facility["status"] != "ACTIVE":
                raise ValidationError(f"buyer credit facility is not ACTIVE (current: {facility['status']})")

            available = facility["credit_limit_minor"] - facility["drawn_balance_minor"]
            if amount_minor > available:
                raise ValidationError(
                    f"insufficient available credit line: requested {amount_minor} minor, "
                    f"available {available} minor (limit: {facility['credit_limit_minor']})"
                )

            # Atomic CAS drawdown
            cur = conn.execute(
                """
                UPDATE b2b_credit_facility
                SET drawn_balance_minor = drawn_balance_minor + ?, updated_at = ?
                WHERE facility_id = ? AND drawn_balance_minor + ? <= credit_limit_minor AND status = 'ACTIVE'
                """,
                (amount_minor, now_iso, facility["facility_id"], amount_minor),
            )
            if cur.rowcount == 0:
                raise ValidationError("concurrent credit drawdown exceeded credit limit")

            conn.execute(
                """
                INSERT INTO b2b_purchase_order (
                    po_id, tenant_id, facility_id, po_number, buyer_id, seller_name,
                    amount_minor, payment_terms, issue_date, due_date,
                    settled_amount_minor, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'ISSUED', ?)
                """,
                (
                    po_id, tenant_id, facility["facility_id"], po_number, buyer_id, seller_name,
                    amount_minor, payment_terms, issue_date_str, due_date_str, now_iso
                ),
            )

            new_drawn = facility["drawn_balance_minor"] + amount_minor
            conn.execute(
                """
                INSERT INTO b2b_credit_drawdown_ledger (
                    entry_id, tenant_id, facility_id, po_id, action,
                    amount_minor, balance_after_minor, notes, created_at
                ) VALUES (?, ?, ?, ?, 'DRAWDOWN', ?, ?, ?, ?)
                """,
                (entry_id, tenant_id, facility["facility_id"], po_id, amount_minor, new_drawn, f"PO {po_number} drawdown", now_iso),
            )

        return {
            "po_id": po_id,
            "po_number": po_number,
            "buyer_id": buyer_id,
            "seller_name": seller_name,
            "amount_minor": amount_minor,
            "payment_terms": payment_terms,
            "issue_date": issue_date_str,
            "due_date": due_date_str,
            "status": "ISSUED",
            "available_credit_minor": facility["credit_limit_minor"] - new_drawn,
        }

    def repay_purchase_order(
        self,
        tenant_id: str,
        po_number: str,
        repayment_amount_minor: int,
    ) -> Dict[str, Any]:
        """Records a payment against a PO and replenishes available credit."""
        if repayment_amount_minor <= 0:
            raise ValidationError("repayment_amount_minor must be strictly positive")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry_id = f"crd_{uuid.uuid4().hex[:12]}"

        with self.store.transaction() as conn:
            po = conn.execute(
                "SELECT * FROM b2b_purchase_order WHERE tenant_id = ? AND po_number = ?",
                (tenant_id, po_number),
            ).fetchone()

            if not po:
                raise ValidationError(f"purchase order {po_number} not found")

            unsettled = po["amount_minor"] - po["settled_amount_minor"]
            if repayment_amount_minor > unsettled:
                raise ValidationError(
                    f"repayment amount ({repayment_amount_minor}) exceeds unsettled balance ({unsettled})"
                )

            new_settled = po["settled_amount_minor"] + repayment_amount_minor
            new_status = "SETTLED" if new_settled == po["amount_minor"] else "PARTIALLY_SETTLED"

            conn.execute(
                """
                UPDATE b2b_purchase_order
                SET settled_amount_minor = ?, status = ?
                WHERE po_id = ?
                """,
                (new_settled, new_status, po["po_id"]),
            )

            # Replenish facility drawn balance
            conn.execute(
                """
                UPDATE b2b_credit_facility
                SET drawn_balance_minor = MAX(0, drawn_balance_minor - ?), updated_at = ?
                WHERE facility_id = ?
                """,
                (repayment_amount_minor, now_iso, po["facility_id"]),
            )

            facility = conn.execute(
                "SELECT * FROM b2b_credit_facility WHERE facility_id = ?",
                (po["facility_id"],),
            ).fetchone()

            conn.execute(
                """
                INSERT INTO b2b_credit_drawdown_ledger (
                    entry_id, tenant_id, facility_id, po_id, action,
                    amount_minor, balance_after_minor, notes, created_at
                ) VALUES (?, ?, ?, ?, 'REPAYMENT', ?, ?, ?, ?)
                """,
                (
                    entry_id, tenant_id, po["facility_id"], po["po_id"],
                    repayment_amount_minor, facility["drawn_balance_minor"],
                    f"Repayment for PO {po_number}", now_iso
                ),
            )

        return {
            "po_number": po_number,
            "repaid_amount_minor": repayment_amount_minor,
            "total_settled_minor": new_settled,
            "remaining_unsettled_minor": po["amount_minor"] - new_settled,
            "status": new_status,
            "available_credit_minor": facility["credit_limit_minor"] - facility["drawn_balance_minor"],
        }

    def calculate_aging_and_penalties(
        self,
        tenant_id: str,
        buyer_id: str,
        as_of_date: Optional[str] = None,
        annual_penalty_rate_bps: int = 500,  # 5.00% annual late payment rate
    ) -> Dict[str, Any]:
        """Calculates accounts receivable aging buckets and overdue penalty interest."""
        as_of_dt = datetime.date.fromisoformat(as_of_date) if as_of_date else datetime.datetime.now(datetime.timezone.utc).date()

        with self.store.transaction() as conn:
            rows = conn.execute(
                """
                SELECT * FROM b2b_purchase_order
                WHERE tenant_id = ? AND buyer_id = ? AND status IN ('ISSUED', 'PARTIALLY_SETTLED', 'OVERDUE')
                """,
                (tenant_id, buyer_id),
            ).fetchall()

        buckets = {
            "current_minor": 0,
            "overdue_1_to_30_minor": 0,
            "overdue_31_to_60_minor": 0,
            "overdue_61_to_90_minor": 0,
            "overdue_over_90_minor": 0,
        }
        total_open_minor = 0
        total_penalty_minor = 0
        po_details: List[Dict[str, Any]] = []

        for row in rows:
            unsettled = row["amount_minor"] - row["settled_amount_minor"]
            total_open_minor += unsettled
            due_dt = datetime.date.fromisoformat(row["due_date"])
            diff_days = (as_of_dt - due_dt).days

            penalty_for_po = 0
            if diff_days <= 0:
                buckets["current_minor"] += unsettled
                bucket_name = "CURRENT"
            else:
                # Accrued penalty: unsettled * rate_bps * days // (365 * 10000)
                penalty_for_po = (unsettled * annual_penalty_rate_bps * diff_days) // (365 * 10000)
                total_penalty_minor += penalty_for_po

                if diff_days <= 30:
                    buckets["overdue_1_to_30_minor"] += unsettled
                    bucket_name = "OVERDUE_1_30"
                elif diff_days <= 60:
                    buckets["overdue_31_to_60_minor"] += unsettled
                    bucket_name = "OVERDUE_31_60"
                elif diff_days <= 90:
                    buckets["overdue_61_to_90_minor"] += unsettled
                    bucket_name = "OVERDUE_61_90"
                else:
                    buckets["overdue_over_90_minor"] += unsettled
                    bucket_name = "OVERDUE_OVER_90"

            po_details.append({
                "po_number": row["po_number"],
                "amount_minor": row["amount_minor"],
                "unsettled_minor": unsettled,
                "due_date": row["due_date"],
                "overdue_days": max(0, diff_days),
                "bucket": bucket_name,
                "penalty_minor": penalty_for_po,
            })

        return {
            "tenant_id": tenant_id,
            "buyer_id": buyer_id,
            "as_of_date": as_of_dt.isoformat(),
            "total_open_minor": total_open_minor,
            "total_penalty_minor": total_penalty_minor,
            "annual_penalty_rate_bps": annual_penalty_rate_bps,
            "buckets": buckets,
            "purchase_orders": po_details,
        }
