# tools/runtime/elmpay_runtime/mandates_dunning.py
from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

from .common import ValidationError
from .durable import DurableStore


HARD_DECLINE_CODES = frozenset({
    "CARD_STOLEN",
    "CARD_LOST",
    "FRAUD_SUSPECTED",
    "ACCOUNT_CLOSED",
    "EXPIRED_CARD",
    "REVOKED_AUTHORIZATION",
})

SOFT_DECLINE_CODES = frozenset({
    "INSUFFICIENT_FUNDS",
    "NETWORK_TIMEOUT",
    "ISSUER_TEMPORARY_UNAVAILABLE",
    "PROCESSOR_BUSY",
    "TRANSIENT_SYSTEM_ERROR",
})


class MandatesDunningEngine:
    """Recurring payment mandates, tokenized direct debits, soft/hard decline triage, and smart dunning retries."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def register_mandate(
        self,
        tenant_id: str,
        customer_id: str,
        payment_method_ref: str,
        mandate_type: str,
        max_amount_per_charge_minor: int,
        currency: str = "CNY",
        signature_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Registers an authorized recurring debit mandate with electronic signature digest."""
        mandate_type = mandate_type.strip().upper()
        if mandate_type not in ("SEPA_DIRECT_DEBIT", "BACS_DIRECT_DEBIT", "CHINA_BANK_DEBIT", "CARD_RECURRING_TOKEN"):
            raise ValidationError(f"invalid mandate_type: {mandate_type}")
        if not customer_id or not customer_id.strip():
            raise ValidationError("customer_id cannot be empty")
        if not payment_method_ref or not payment_method_ref.strip():
            raise ValidationError("payment_method_ref cannot be empty")
        if max_amount_per_charge_minor <= 0:
            raise ValidationError("max_amount_per_charge_minor must be strictly positive")

        currency = currency.strip().upper()
        mandate_id = f"mnd_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        sig_raw = json.dumps(signature_data or {"signed_by": customer_id, "at": now_iso}, sort_keys=True).encode("utf-8")
        sig_digest = hashlib.sha256(sig_raw).hexdigest()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO recurring_mandate_agreement (
                    mandate_id, tenant_id, customer_id, payment_method_ref,
                    mandate_type, status, max_amount_per_charge_minor,
                    currency, signature_digest, signed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)
                """,
                (
                    mandate_id, tenant_id, customer_id, payment_method_ref,
                    mandate_type, max_amount_per_charge_minor,
                    currency, sig_digest, now_iso, now_iso
                ),
            )

        return {
            "mandate_id": mandate_id,
            "tenant_id": tenant_id,
            "customer_id": customer_id,
            "mandate_type": mandate_type,
            "status": "ACTIVE",
            "max_amount_per_charge_minor": max_amount_per_charge_minor,
            "currency": currency,
            "signature_digest": sig_digest,
            "signed_at": now_iso,
        }

    def execute_mandate_charge(
        self,
        tenant_id: str,
        mandate_id: str,
        invoice_id: str,
        amount_minor: int,
    ) -> Dict[str, Any]:
        """Executes a recurring charge against an active customer mandate, enforcing authorized quota."""
        if amount_minor <= 0:
            raise ValidationError("charge amount_minor must be strictly positive")

        with self.store.transaction() as conn:
            mandate = conn.execute(
                "SELECT * FROM recurring_mandate_agreement WHERE mandate_id = ? AND tenant_id = ?",
                (mandate_id, tenant_id),
            ).fetchone()

            if not mandate:
                raise ValidationError(f"mandate {mandate_id} not found")
            if mandate["status"] != "ACTIVE":
                raise ValidationError(f"mandate {mandate_id} is in status '{mandate['status']}', charges not permitted")
            if amount_minor > mandate["max_amount_per_charge_minor"]:
                raise ValidationError(
                    f"charge amount {amount_minor} exceeds authorized mandate ceiling {mandate['max_amount_per_charge_minor']}"
                )

        charge_id = f"mch_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return {
            "charge_id": charge_id,
            "mandate_id": mandate_id,
            "invoice_id": invoice_id,
            "amount_minor": amount_minor,
            "currency": mandate["currency"],
            "status": "AUTHORIZED",
            "charged_at": now_iso,
        }

    def evaluate_charge_failure(
        self,
        tenant_id: str,
        mandate_id: str,
        invoice_id: str,
        decline_code: str,
    ) -> Dict[str, Any]:
        """Classifies soft vs hard decline and launches automated dunning schedule or immediate suspension."""
        decline_code = decline_code.strip().upper()
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            mandate = conn.execute(
                "SELECT * FROM recurring_mandate_agreement WHERE mandate_id = ? AND tenant_id = ?",
                (mandate_id, tenant_id),
            ).fetchone()
            if not mandate:
                raise ValidationError(f"mandate {mandate_id} not found")

        is_hard = decline_code in HARD_DECLINE_CODES
        decline_type = "HARD" if is_hard else "SOFT"
        dunning_id = f"dun_{uuid.uuid4().hex[:12]}"

        if is_hard:
            # Immediate fail-closed: suspend mandate, no retry
            with self.store.transaction() as conn:
                conn.execute(
                    "UPDATE recurring_mandate_agreement SET status = 'SUSPENDED', updated_at = ? WHERE mandate_id = ?",
                    (now_iso, mandate_id),
                )
                conn.execute(
                    """
                    INSERT INTO dunning_process_schedule (
                        dunning_id, tenant_id, mandate_id, invoice_id,
                        attempt_count, max_attempts, decline_type, decline_code,
                        status, next_retry_at, last_notified_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 1, 1, 'HARD', ?, 'EXHAUSTED', NULL, ?, ?, ?)
                    """,
                    (dunning_id, tenant_id, mandate_id, invoice_id, decline_code, now_iso, now_iso, now_iso),
                )

            return {
                "dunning_id": dunning_id,
                "mandate_id": mandate_id,
                "decline_type": "HARD",
                "decline_code": decline_code,
                "status": "EXHAUSTED",
                "mandate_status": "SUSPENDED",
                "action_required": "CUSTOMER_PAYMENT_METHOD_UPDATE",
            }

        # Soft decline: schedule Day-1 retry
        next_retry_iso = (now_dt + datetime.timedelta(days=1)).isoformat()
        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO dunning_process_schedule (
                    dunning_id, tenant_id, mandate_id, invoice_id,
                    attempt_count, max_attempts, decline_type, decline_code,
                    status, next_retry_at, last_notified_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 1, 4, 'SOFT', ?, 'IN_PROGRESS', ?, ?, ?, ?)
                """,
                (dunning_id, tenant_id, mandate_id, invoice_id, decline_code, next_retry_iso, now_iso, now_iso, now_iso),
            )

        return {
            "dunning_id": dunning_id,
            "mandate_id": mandate_id,
            "decline_type": "SOFT",
            "decline_code": decline_code,
            "status": "IN_PROGRESS",
            "attempt_count": 1,
            "max_attempts": 4,
            "next_retry_at": next_retry_iso,
        }

    def process_dunning_retry(
        self,
        tenant_id: str,
        dunning_id: str,
        simulate_outcome: str = "SUCCESS",
    ) -> Dict[str, Any]:
        """Executes next scheduled dunning retry attempt, advancing recovery or exhaustion."""
        simulate_outcome = simulate_outcome.strip().upper()
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            dun = conn.execute(
                "SELECT * FROM dunning_process_schedule WHERE dunning_id = ? AND tenant_id = ?",
                (dunning_id, tenant_id),
            ).fetchone()
            if not dun:
                raise ValidationError(f"dunning schedule {dunning_id} not found")
            if dun["status"] != "IN_PROGRESS":
                raise ValidationError(f"dunning schedule is already in final status '{dun['status']}'")

            if simulate_outcome == "SUCCESS":
                conn.execute(
                    "UPDATE dunning_process_schedule SET status = 'RECOVERED', updated_at = ? WHERE dunning_id = ?",
                    (now_iso, dunning_id),
                )
                conn.execute(
                    "UPDATE recurring_mandate_agreement SET status = 'ACTIVE', updated_at = ? WHERE mandate_id = ?",
                    (now_iso, dun["mandate_id"]),
                )
                return {
                    "dunning_id": dunning_id,
                    "status": "RECOVERED",
                    "mandate_status": "ACTIVE",
                    "attempts": dun["attempt_count"],
                }

            # Failure outcome
            new_attempts = dun["attempt_count"] + 1
            if new_attempts >= dun["max_attempts"]:
                conn.execute(
                    """
                    UPDATE dunning_process_schedule
                    SET status = 'EXHAUSTED', attempt_count = ?, next_retry_at = NULL, updated_at = ?
                    WHERE dunning_id = ?
                    """,
                    (new_attempts, now_iso, dunning_id),
                )
                conn.execute(
                    "UPDATE recurring_mandate_agreement SET status = 'SUSPENDED', updated_at = ? WHERE mandate_id = ?",
                    (now_iso, dun["mandate_id"]),
                )
                return {
                    "dunning_id": dunning_id,
                    "status": "EXHAUSTED",
                    "mandate_status": "SUSPENDED",
                    "attempts": new_attempts,
                }

            # Still retrying: schedule next exponential retry
            interval_days = 2 ** (new_attempts - 1)
            next_iso = (now_dt + datetime.timedelta(days=interval_days)).isoformat()
            conn.execute(
                """
                UPDATE dunning_process_schedule
                SET attempt_count = ?, next_retry_at = ?, updated_at = ?
                WHERE dunning_id = ?
                """,
                (new_attempts, next_iso, now_iso, dunning_id),
            )
            return {
                "dunning_id": dunning_id,
                "status": "IN_PROGRESS",
                "attempts": new_attempts,
                "next_retry_at": next_iso,
            }

    def get_mandate_status(self, tenant_id: str, mandate_id: str) -> Dict[str, Any]:
        with self.store.transaction() as conn:
            m = conn.execute(
                "SELECT * FROM recurring_mandate_agreement WHERE mandate_id = ? AND tenant_id = ?",
                (mandate_id, tenant_id),
            ).fetchone()
            if not m:
                raise ValidationError(f"mandate {mandate_id} not found")

            duns = conn.execute(
                "SELECT * FROM dunning_process_schedule WHERE mandate_id = ? ORDER BY created_at DESC",
                (mandate_id,),
            ).fetchall()

        data = dict(m)
        data["dunning_history"] = [dict(d) for d in duns]
        return data
