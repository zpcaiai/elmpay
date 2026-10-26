"""Enterprise Subscription Proration, Plan Upgrades/Downgrades & Credit Balance Wallet (B70-B71)."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Any, Mapping, Sequence
import uuid

from .common import ValidationError, require_text, parse_instant
from .durable import DurableStore


class BillingInterval(str, Enum):
    MONTHLY = "MONTHLY"
    QUARTERLY = "QUARTERLY"
    ANNUAL = "ANNUAL"


def _current(now: datetime | None = None) -> datetime:
    return now or datetime.now(timezone.utc)


def _to_dt(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    return parse_instant(value, field)


class SubscriptionProrationEngine:
    """Manages subscription plans, subscriptions, integer-accurate proration, and customer credit wallet."""

    def __init__(self, store_or_db: DurableStore | Path | str) -> None:
        if isinstance(store_or_db, DurableStore):
            self.store = store_or_db
        else:
            self.store = DurableStore(Path(store_or_db))

    def create_plan(
        self,
        tenant_id: str,
        *,
        plan_code: str,
        name: str,
        billing_interval: str,
        amount_minor: int,
        currency: str,
        plan_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Create a recurring subscription plan."""
        require_text(tenant_id, "tenant_id")
        require_text(plan_code, "plan_code")
        require_text(name, "name")
        require_text(currency, "currency")

        if not isinstance(billing_interval, str):
            raise ValidationError("billing_interval must be MONTHLY, QUARTERLY, or ANNUAL")
        try:
            interval = BillingInterval(billing_interval.upper())
        except ValueError:
            raise ValidationError("billing_interval must be MONTHLY, QUARTERLY, or ANNUAL") from None

        if not isinstance(amount_minor, int) or amount_minor < 0:
            raise ValidationError("amount_minor must be a non-negative integer in minor units")

        curr = currency.upper()
        pid = plan_id or f"PLAN_{uuid.uuid4().hex[:12]}"
        now_iso = _current(now).isoformat()

        with self.store.transaction() as conn:
            existing = conn.execute(
                "SELECT plan_id FROM subscription_plan WHERE tenant_id=? AND plan_code=?",
                (tenant_id, plan_code),
            ).fetchone()
            if existing:
                raise ValidationError(f"Plan with code '{plan_code}' already exists for tenant '{tenant_id}'")

            conn.execute(
                "INSERT INTO subscription_plan (plan_id, tenant_id, plan_code, name, billing_interval, amount_minor, currency, created_at, is_active) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
                (pid, tenant_id, plan_code, name, interval.value, amount_minor, curr, now_iso),
            )

        return {
            "planId": pid,
            "tenantId": tenant_id,
            "planCode": plan_code,
            "name": name,
            "billingInterval": interval.value,
            "amountMinor": amount_minor,
            "currency": curr,
            "createdAt": now_iso,
            "isActive": True,
        }

    def get_plan(self, tenant_id: str, plan_id: str) -> dict[str, Any]:
        """Fetch plan by plan_id."""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM subscription_plan WHERE tenant_id=? AND plan_id=?",
                (tenant_id, plan_id),
            ).fetchone()
            if not row:
                raise ValidationError(f"Subscription plan '{plan_id}' not found for tenant '{tenant_id}'")
            return {
                "planId": row["plan_id"],
                "tenantId": row["tenant_id"],
                "planCode": row["plan_code"],
                "name": row["name"],
                "billingInterval": row["billing_interval"],
                "amountMinor": row["amount_minor"],
                "currency": row["currency"],
                "createdAt": row["created_at"],
                "isActive": bool(row["is_active"]),
            }

    def create_subscription(
        self,
        tenant_id: str,
        *,
        customer_id: str,
        plan_id: str,
        current_period_start: str | datetime,
        current_period_end: str | datetime,
        subscription_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Subscribe a customer to a plan."""
        require_text(tenant_id, "tenant_id")
        require_text(customer_id, "customer_id")
        require_text(plan_id, "plan_id")

        plan = self.get_plan(tenant_id, plan_id)
        if not plan["isActive"]:
            raise ValidationError(f"Cannot subscribe to inactive plan '{plan_id}'")

        start_dt = _to_dt(current_period_start, "current_period_start")
        end_dt = _to_dt(current_period_end, "current_period_end")
        if end_dt <= start_dt:
            raise ValidationError("current_period_end must be strictly after current_period_start")

        sid = subscription_id or f"SUB_{uuid.uuid4().hex[:12]}"
        now_iso = _current(now).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO customer_subscription (subscription_id, tenant_id, customer_id, plan_id, status, "
                "current_period_start, current_period_end, cancel_at_period_end, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, 0, ?, ?)",
                (sid, tenant_id, customer_id, plan_id, start_dt.isoformat(), end_dt.isoformat(), now_iso, now_iso),
            )

        return {
            "subscriptionId": sid,
            "tenantId": tenant_id,
            "customerId": customer_id,
            "planId": plan_id,
            "status": "ACTIVE",
            "currentPeriodStart": start_dt.isoformat(),
            "currentPeriodEnd": end_dt.isoformat(),
            "cancelAtPeriodEnd": False,
            "createdAt": now_iso,
            "updatedAt": now_iso,
        }

    def get_subscription(self, tenant_id: str, subscription_id: str) -> dict[str, Any]:
        """Fetch subscription details."""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM customer_subscription WHERE tenant_id=? AND subscription_id=?",
                (tenant_id, subscription_id),
            ).fetchone()
            if not row:
                raise ValidationError(f"Subscription '{subscription_id}' not found for tenant '{tenant_id}'")
            return {
                "subscriptionId": row["subscription_id"],
                "tenantId": row["tenant_id"],
                "customerId": row["customer_id"],
                "planId": row["plan_id"],
                "status": row["status"],
                "currentPeriodStart": row["current_period_start"],
                "currentPeriodEnd": row["current_period_end"],
                "cancelAtPeriodEnd": bool(row["cancel_at_period_end"]),
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }

    def change_plan(
        self,
        tenant_id: str,
        *,
        subscription_id: str,
        new_plan_id: str,
        effective_at: str | datetime | None = None,
        allow_credit_deduction: bool = True,
        adjustment_id: str | None = None,
    ) -> dict[str, Any]:
        """Perform mid-cycle subscription plan upgrade/downgrade with exact integer proration and credit balance application."""
        require_text(tenant_id, "tenant_id")
        require_text(subscription_id, "subscription_id")
        require_text(new_plan_id, "new_plan_id")

        with self.store.transaction() as conn:
            sub_row = conn.execute(
                "SELECT * FROM customer_subscription WHERE tenant_id=? AND subscription_id=?",
                (tenant_id, subscription_id),
            ).fetchone()
            if not sub_row:
                raise ValidationError(f"Subscription '{subscription_id}' not found")
            if sub_row["status"] != "ACTIVE":
                raise ValidationError(f"Cannot change plan for non-active subscription (status: {sub_row['status']})")

            old_plan_id = sub_row["plan_id"]
            if old_plan_id == new_plan_id:
                raise ValidationError("New plan must be different from current plan")

            old_plan_row = conn.execute(
                "SELECT * FROM subscription_plan WHERE tenant_id=? AND plan_id=?",
                (tenant_id, old_plan_id),
            ).fetchone()
            new_plan_row = conn.execute(
                "SELECT * FROM subscription_plan WHERE tenant_id=? AND plan_id=?",
                (tenant_id, new_plan_id),
            ).fetchone()

            if not old_plan_row or not new_plan_row:
                raise ValidationError("Plan record missing for upgrade/downgrade")
            if not new_plan_row["is_active"]:
                raise ValidationError("Target plan is inactive")
            if old_plan_row["currency"] != new_plan_row["currency"]:
                raise ValidationError(
                    f"Plan currencies must match (old: {old_plan_row['currency']}, new: {new_plan_row['currency']})"
                )

            currency = old_plan_row["currency"]
            period_start = _to_dt(sub_row["current_period_start"], "current_period_start")
            period_end = _to_dt(sub_row["current_period_end"], "current_period_end")

            now_dt = _to_dt(effective_at, "effective_at") if effective_at else _current()
            total_seconds = int((period_end - period_start).total_seconds())
            if total_seconds <= 0:
                raise ValidationError("Invalid subscription period duration")

            if now_dt <= period_start:
                remaining_seconds = total_seconds
            elif now_dt >= period_end:
                remaining_seconds = 0
            else:
                remaining_seconds = int((period_end - now_dt).total_seconds())

            # Integer proration math: (amount * remaining_sec) // total_sec
            old_amount = int(old_plan_row["amount_minor"])
            new_amount = int(new_plan_row["amount_minor"])

            unused_old_credit_minor = (old_amount * remaining_seconds) // total_seconds
            new_plan_charge_minor = (new_amount * remaining_seconds) // total_seconds
            net_payable_minor = new_plan_charge_minor - unused_old_credit_minor

            adj_id = adjustment_id or f"ADJ_{uuid.uuid4().hex[:12]}"
            now_iso = now_dt.isoformat()
            customer_id = sub_row["customer_id"]

            applied_credit = 0
            final_charge_due = 0
            refund_credited_minor = 0

            if net_payable_minor > 0:
                change_type = "UPGRADE"
                final_charge_due = net_payable_minor

                if allow_credit_deduction:
                    # Check customer credit balance
                    balance_row = conn.execute(
                        "SELECT COALESCE(SUM(CASE "
                        "  WHEN entry_type='CREDIT_GRANTED' THEN amount_minor "
                        "  WHEN entry_type IN ('CREDIT_CONSUMED', 'REFUND_TO_ORIGINAL') THEN -amount_minor "
                        "  ELSE 0 END), 0) as bal "
                        "FROM customer_credit_ledger WHERE tenant_id=? AND customer_id=? AND currency=?",
                        (tenant_id, customer_id, currency),
                    ).fetchone()
                    avail_credit = int(balance_row["bal"] if balance_row else 0)

                    if avail_credit > 0:
                        applied_credit = min(avail_credit, net_payable_minor)
                        final_charge_due = net_payable_minor - applied_credit
                        # Record credit consumption
                        cid = f"CR_{uuid.uuid4().hex[:12]}"
                        conn.execute(
                            "INSERT INTO customer_credit_ledger (credit_id, tenant_id, customer_id, entry_type, amount_minor, currency, reason, reference_id, posted_at) "
                            "VALUES (?, ?, ?, 'CREDIT_CONSUMED', ?, ?, ?, ?, ?)",
                            (cid, tenant_id, customer_id, applied_credit, currency, f"Prorated upgrade to {new_plan_row['plan_code']}", adj_id, now_iso),
                        )
            else:
                change_type = "DOWNGRADE"
                refund_credited_minor = abs(net_payable_minor)
                if refund_credited_minor > 0:
                    # Grant credit to customer wallet
                    cid = f"CR_{uuid.uuid4().hex[:12]}"
                    conn.execute(
                        "INSERT INTO customer_credit_ledger (credit_id, tenant_id, customer_id, entry_type, amount_minor, currency, reason, reference_id, posted_at) "
                        "VALUES (?, ?, ?, 'CREDIT_GRANTED', ?, ?, ?, ?, ?)",
                        (cid, tenant_id, customer_id, refund_credited_minor, currency, f"Prorated downgrade from {old_plan_row['plan_code']} to {new_plan_row['plan_code']}", adj_id, now_iso),
                    )

            # Record adjustment
            conn.execute(
                "INSERT INTO subscription_proration_adjustment ("
                "  adjustment_id, tenant_id, subscription_id, old_plan_id, new_plan_id, change_type, "
                "  unused_old_credit_minor, new_plan_charge_minor, net_payable_minor, credit_balance_applied_minor, "
                "  final_charge_due_minor, credit_refunded_to_wallet_minor, currency, adjusted_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    adj_id,
                    tenant_id,
                    subscription_id,
                    old_plan_id,
                    new_plan_id,
                    change_type,
                    unused_old_credit_minor,
                    new_plan_charge_minor,
                    net_payable_minor,
                    applied_credit,
                    final_charge_due,
                    refund_credited_minor,
                    currency,
                    now_iso,
                ),
            )

            # Update subscription
            conn.execute(
                "UPDATE customer_subscription SET plan_id=?, updated_at=? WHERE tenant_id=? AND subscription_id=?",
                (new_plan_id, now_iso, tenant_id, subscription_id),
            )

        return {
            "adjustmentId": adj_id,
            "tenantId": tenant_id,
            "subscriptionId": subscription_id,
            "customerId": customer_id,
            "oldPlanId": old_plan_id,
            "newPlanId": new_plan_id,
            "changeType": change_type,
            "unusedOldCreditMinor": unused_old_credit_minor,
            "newPlanChargeMinor": new_plan_charge_minor,
            "netPayableMinor": net_payable_minor,
            "creditBalanceAppliedMinor": applied_credit,
            "finalChargeDueMinor": final_charge_due,
            "creditRefundedToWalletMinor": refund_credited_minor,
            "currency": currency,
            "remainingSeconds": remaining_seconds,
            "totalSeconds": total_seconds,
            "adjustedAt": now_iso,
        }

    def cancel_subscription(
        self,
        tenant_id: str,
        *,
        subscription_id: str,
        immediate: bool = False,
        refund_prorated: bool = False,
        effective_at: str | datetime | None = None,
        adjustment_id: str | None = None,
    ) -> dict[str, Any]:
        """Cancel subscription immediately or at period end."""
        require_text(tenant_id, "tenant_id")
        require_text(subscription_id, "subscription_id")

        now_dt = _to_dt(effective_at, "effective_at") if effective_at else _current()
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            sub_row = conn.execute(
                "SELECT * FROM customer_subscription WHERE tenant_id=? AND subscription_id=?",
                (tenant_id, subscription_id),
            ).fetchone()
            if not sub_row:
                raise ValidationError(f"Subscription '{subscription_id}' not found")
            if sub_row["status"] == "CANCELED":
                raise ValidationError("Subscription is already canceled")

            customer_id = sub_row["customer_id"]
            plan_row = conn.execute(
                "SELECT * FROM subscription_plan WHERE tenant_id=? AND plan_id=?",
                (tenant_id, sub_row["plan_id"]),
            ).fetchone()
            currency = plan_row["currency"]

            if not immediate:
                conn.execute(
                    "UPDATE customer_subscription SET cancel_at_period_end=1, updated_at=? WHERE tenant_id=? AND subscription_id=?",
                    (now_iso, tenant_id, subscription_id),
                )
                return {
                    "subscriptionId": subscription_id,
                    "tenantId": tenant_id,
                    "status": sub_row["status"],
                    "cancelAtPeriodEnd": True,
                    "immediate": False,
                    "refundedMinor": 0,
                    "updatedAt": now_iso,
                }

            # Immediate cancel
            refund_amount = 0
            adj_id = None
            if refund_prorated:
                period_start = _to_dt(sub_row["current_period_start"], "current_period_start")
                period_end = _to_dt(sub_row["current_period_end"], "current_period_end")
                total_seconds = int((period_end - period_start).total_seconds())
                if total_seconds > 0 and now_dt < period_end:
                    remaining_seconds = int((period_end - max(period_start, now_dt)).total_seconds())
                    refund_amount = (int(plan_row["amount_minor"]) * remaining_seconds) // total_seconds

                if refund_amount > 0:
                    adj_id = adjustment_id or f"ADJ_{uuid.uuid4().hex[:12]}"
                    cid = f"CR_{uuid.uuid4().hex[:12]}"
                    conn.execute(
                        "INSERT INTO customer_credit_ledger (credit_id, tenant_id, customer_id, entry_type, amount_minor, currency, reason, reference_id, posted_at) "
                        "VALUES (?, ?, ?, 'CREDIT_GRANTED', ?, ?, ?, ?, ?)",
                        (cid, tenant_id, customer_id, refund_amount, currency, "Canceled subscription prorated credit refund", adj_id, now_iso),
                    )
                    conn.execute(
                        "INSERT INTO subscription_proration_adjustment ("
                        "  adjustment_id, tenant_id, subscription_id, old_plan_id, new_plan_id, change_type, "
                        "  unused_old_credit_minor, new_plan_charge_minor, net_payable_minor, credit_balance_applied_minor, "
                        "  final_charge_due_minor, credit_refunded_to_wallet_minor, currency, adjusted_at"
                        ") VALUES (?, ?, ?, ?, ?, 'CANCEL_PRORATED', ?, 0, ?, 0, 0, ?, ?, ?)",
                        (
                            adj_id,
                            tenant_id,
                            subscription_id,
                            sub_row["plan_id"],
                            sub_row["plan_id"],
                            refund_amount,
                            -refund_amount,
                            refund_amount,
                            currency,
                            now_iso,
                        ),
                    )

            conn.execute(
                "UPDATE customer_subscription SET status='CANCELED', updated_at=? WHERE tenant_id=? AND subscription_id=?",
                (now_iso, tenant_id, subscription_id),
            )

        return {
            "subscriptionId": subscription_id,
            "tenantId": tenant_id,
            "status": "CANCELED",
            "cancelAtPeriodEnd": False,
            "immediate": True,
            "refundedMinor": refund_amount,
            "adjustmentId": adj_id,
            "updatedAt": now_iso,
        }

    def pause_subscription(self, tenant_id: str, subscription_id: str) -> dict[str, Any]:
        """Pause an active subscription."""
        now_iso = _current().isoformat()
        with self.store.transaction() as conn:
            sub = conn.execute(
                "SELECT status FROM customer_subscription WHERE tenant_id=? AND subscription_id=?",
                (tenant_id, subscription_id),
            ).fetchone()
            if not sub:
                raise ValidationError("Subscription not found")
            if sub["status"] != "ACTIVE":
                raise ValidationError(f"Only ACTIVE subscriptions can be paused (current: {sub['status']})")
            conn.execute(
                "UPDATE customer_subscription SET status='PAUSED', updated_at=? WHERE tenant_id=? AND subscription_id=?",
                (now_iso, tenant_id, subscription_id),
            )
        return {"subscriptionId": subscription_id, "tenantId": tenant_id, "status": "PAUSED", "updatedAt": now_iso}

    def resume_subscription(self, tenant_id: str, subscription_id: str) -> dict[str, Any]:
        """Resume a paused subscription."""
        now_iso = _current().isoformat()
        with self.store.transaction() as conn:
            sub = conn.execute(
                "SELECT status FROM customer_subscription WHERE tenant_id=? AND subscription_id=?",
                (tenant_id, subscription_id),
            ).fetchone()
            if not sub:
                raise ValidationError("Subscription not found")
            if sub["status"] != "PAUSED":
                raise ValidationError(f"Only PAUSED subscriptions can be resumed (current: {sub['status']})")
            conn.execute(
                "UPDATE customer_subscription SET status='ACTIVE', updated_at=? WHERE tenant_id=? AND subscription_id=?",
                (now_iso, tenant_id, subscription_id),
            )
        return {"subscriptionId": subscription_id, "tenantId": tenant_id, "status": "ACTIVE", "updatedAt": now_iso}

    def get_customer_credit_balance(self, tenant_id: str, customer_id: str, currency: str) -> int:
        """Calculate available credit balance in minor units."""
        require_text(tenant_id, "tenant_id")
        require_text(customer_id, "customer_id")
        require_text(currency, "currency")
        curr = currency.upper()

        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(CASE "
                "  WHEN entry_type='CREDIT_GRANTED' THEN amount_minor "
                "  WHEN entry_type IN ('CREDIT_CONSUMED', 'REFUND_TO_ORIGINAL') THEN -amount_minor "
                "  ELSE 0 END), 0) as bal "
                "FROM customer_credit_ledger WHERE tenant_id=? AND customer_id=? AND currency=?",
                (tenant_id, customer_id, curr),
            ).fetchone()
            return int(row["bal"] if row else 0)

    def grant_customer_credit(
        self,
        tenant_id: str,
        *,
        customer_id: str,
        amount_minor: int,
        currency: str,
        reason: str,
        reference_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Add positive credit to a customer's wallet balance."""
        require_text(tenant_id, "tenant_id")
        require_text(customer_id, "customer_id")
        require_text(currency, "currency")
        require_text(reason, "reason")

        if not isinstance(amount_minor, int) or amount_minor <= 0:
            raise ValidationError("amount_minor must be a positive integer in minor units")

        cid = f"CR_{uuid.uuid4().hex[:12]}"
        curr = currency.upper()
        now_iso = _current(now).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO customer_credit_ledger (credit_id, tenant_id, customer_id, entry_type, amount_minor, currency, reason, reference_id, posted_at) "
                "VALUES (?, ?, ?, 'CREDIT_GRANTED', ?, ?, ?, ?, ?)",
                (cid, tenant_id, customer_id, amount_minor, curr, reason, reference_id, now_iso),
            )

        new_bal = self.get_customer_credit_balance(tenant_id, customer_id, curr)
        return {
            "creditId": cid,
            "tenantId": tenant_id,
            "customerId": customer_id,
            "entryType": "CREDIT_GRANTED",
            "amountMinor": amount_minor,
            "currency": curr,
            "reason": reason,
            "referenceId": reference_id,
            "newBalanceMinor": new_bal,
            "postedAt": now_iso,
        }

    def consume_customer_credit(
        self,
        tenant_id: str,
        *,
        customer_id: str,
        amount_minor: int,
        currency: str,
        reason: str,
        reference_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Consume customer credit for invoice payment or offset."""
        require_text(tenant_id, "tenant_id")
        require_text(customer_id, "customer_id")
        require_text(currency, "currency")
        require_text(reason, "reason")

        if not isinstance(amount_minor, int) or amount_minor <= 0:
            raise ValidationError("amount_minor must be a positive integer in minor units")

        curr = currency.upper()
        now_iso = _current(now).isoformat()

        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(CASE "
                "  WHEN entry_type='CREDIT_GRANTED' THEN amount_minor "
                "  WHEN entry_type IN ('CREDIT_CONSUMED', 'REFUND_TO_ORIGINAL') THEN -amount_minor "
                "  ELSE 0 END), 0) as bal "
                "FROM customer_credit_ledger WHERE tenant_id=? AND customer_id=? AND currency=?",
                (tenant_id, customer_id, curr),
            ).fetchone()
            current_bal = int(row["bal"] if row else 0)

            if current_bal < amount_minor:
                raise ValidationError(
                    f"Insufficient credit balance (available: {current_bal} minor, required: {amount_minor} minor)"
                )

            cid = f"CR_{uuid.uuid4().hex[:12]}"
            conn.execute(
                "INSERT INTO customer_credit_ledger (credit_id, tenant_id, customer_id, entry_type, amount_minor, currency, reason, reference_id, posted_at) "
                "VALUES (?, ?, ?, 'CREDIT_CONSUMED', ?, ?, ?, ?, ?)",
                (cid, tenant_id, customer_id, amount_minor, curr, reason, reference_id, now_iso),
            )

        new_bal = self.get_customer_credit_balance(tenant_id, customer_id, curr)
        return {
            "creditId": cid,
            "tenantId": tenant_id,
            "customerId": customer_id,
            "entryType": "CREDIT_CONSUMED",
            "amountMinor": amount_minor,
            "currency": curr,
            "reason": reason,
            "referenceId": reference_id,
            "newBalanceMinor": new_bal,
            "postedAt": now_iso,
        }
