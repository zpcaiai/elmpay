"""Enterprise dispute, chargeback defense and loss prevention ledger."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping, Sequence
import uuid

from .common import (
    ValidationError,
    canonical_json,
    parse_instant,
    require_mapping,
    require_text,
    sha256_json,
)
from .durable import DurableStore


def _instant(val: datetime | str | None) -> str:
    if val is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.isoformat()
    return str(val)


ALLOWED_REASON_CODES = {
    "FRAUDULENT",
    "UNRECOGNIZED",
    "PRODUCT_NOT_RECEIVED",
    "SUBSCRIPTION_CANCELED",
    "DUPLICATE",
    "OTHER",
}


class DisputeLedger:
    """Enterprise merchant dispute, chargeback rebuttal and loss prevention ledger."""

    def __init__(self, database: str | DurableStore) -> None:
        if isinstance(database, DurableStore):
            self.store = database
        else:
            self.store = DurableStore(database)

    def record_dispute(
        self,
        tenant_id: str,
        project_id: str,
        payment_intent_id: str,
        *,
        dispute_amount_minor: int,
        evidence_due_at: str | datetime,
        currency: str = "CNY",
        reason_code: str = "UNRECOGNIZED",
        actor_id: str = "dispute_webhook_service",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Record an incoming payment dispute / chargeback event from payment network."""
        require_text(tenant_id, "tenant_id")
        require_text(project_id, "project_id")
        require_text(payment_intent_id, "payment_intent_id")

        if dispute_amount_minor <= 0:
            raise ValidationError("dispute_amount_minor must be strictly positive")

        currency = currency.strip().upper()
        if len(currency) != 3:
            raise ValidationError("currency must be 3-letter ISO code")

        reason_code = reason_code.upper()
        if reason_code not in ALLOWED_REASON_CODES:
            raise ValidationError(f"unrecognized dispute reason code: {reason_code}")

        due_iso = _instant(evidence_due_at)
        current_iso = _instant(now)
        dispute_id = f"dsp_{uuid.uuid4().hex[:16]}"

        with self.store.transaction() as conn:
            existing = conn.execute(
                "SELECT dispute_id FROM merchant_dispute WHERE tenant_id=? AND payment_intent_id=?",
                (tenant_id, payment_intent_id),
            ).fetchone()
            if existing:
                raise ValidationError(f"dispute already recorded for payment: {payment_intent_id}")

            conn.execute(
                "INSERT INTO merchant_dispute ("
                "dispute_id, tenant_id, project_id, payment_intent_id, dispute_amount_minor, currency, "
                "reason_code, status, evidence_due_at, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, 'NEEDS_RESPONSE', ?, ?, ?)",
                (
                    dispute_id,
                    tenant_id,
                    project_id,
                    payment_intent_id,
                    dispute_amount_minor,
                    currency,
                    reason_code,
                    due_iso,
                    current_iso,
                    current_iso,
                ),
            )

            payload = {
                "disputeId": dispute_id,
                "tenantId": tenant_id,
                "projectId": project_id,
                "paymentIntentId": payment_intent_id,
                "disputeAmountMinor": dispute_amount_minor,
                "currency": currency,
                "reasonCode": reason_code,
                "status": "NEEDS_RESPONSE",
                "evidenceDueAt": due_iso,
                "createdAt": current_iso,
            }

            self._record_audit(
                conn,
                tenant_id=tenant_id,
                dispute_id=dispute_id,
                event_type="DISPUTE_RECORDED",
                actor_id=actor_id,
                occurred_at=current_iso,
                payload=payload,
            )

        return self.get_dispute(tenant_id, dispute_id)

    def get_dispute(self, tenant_id: str, dispute_id: str) -> dict[str, Any]:
        """Retrieve dispute details."""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM merchant_dispute WHERE tenant_id=? AND dispute_id=?",
                (tenant_id, dispute_id),
            ).fetchone()
        if not row:
            raise ValidationError(f"dispute not found: {dispute_id}")

        evidence = json.loads(row["evidence_json"]) if row["evidence_json"] else None

        return {
            "disputeId": row["dispute_id"],
            "tenantId": row["tenant_id"],
            "projectId": row["project_id"],
            "paymentIntentId": row["payment_intent_id"],
            "disputeAmountMinor": row["dispute_amount_minor"],
            "currency": row["currency"],
            "reasonCode": row["reason_code"],
            "status": row["status"],
            "evidenceDueAt": row["evidence_due_at"],
            "evidence": evidence,
            "lostFeeMinor": row["lost_fee_minor"],
            "resolvedAt": row["resolved_at"],
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def list_disputes(
        self,
        tenant_id: str,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List disputes for a tenant with optional status filter."""
        query = "SELECT * FROM merchant_dispute WHERE tenant_id=?"
        params: list[Any] = [tenant_id]
        if status:
            query += " AND status=?"
            params.append(status.upper())
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self.store.connect() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for row in rows:
            evidence = json.loads(row["evidence_json"]) if row["evidence_json"] else None
            results.append({
                "disputeId": row["dispute_id"],
                "tenantId": row["tenant_id"],
                "projectId": row["project_id"],
                "paymentIntentId": row["payment_intent_id"],
                "disputeAmountMinor": row["dispute_amount_minor"],
                "currency": row["currency"],
                "reasonCode": row["reason_code"],
                "status": row["status"],
                "evidenceDueAt": row["evidence_due_at"],
                "evidence": evidence,
                "lostFeeMinor": row["lost_fee_minor"],
                "resolvedAt": row["resolved_at"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            })
        return results

    def submit_dispute_evidence(
        self,
        tenant_id: str,
        dispute_id: str,
        *,
        evidence: Mapping[str, Any],
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Submit rebuttal evidence before the due date."""
        dispute = self.get_dispute(tenant_id, dispute_id)
        if dispute["status"] != "NEEDS_RESPONSE":
            raise ValidationError(f"cannot submit evidence for dispute in status: {dispute['status']}")

        current_iso = _instant(now)
        due_at = parse_instant(dispute["evidenceDueAt"], "evidenceDueAt")
        curr_dt = parse_instant(current_iso, "current_instant")
        if curr_dt > due_at:
            raise ValidationError("evidence submission window has expired")

        evidence_json = json.dumps(dict(evidence), ensure_ascii=False)

        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE merchant_dispute SET status='UNDER_REVIEW', evidence_json=?, updated_at=? "
                "WHERE tenant_id=? AND dispute_id=?",
                (evidence_json, current_iso, tenant_id, dispute_id),
            )
            payload = {
                "disputeId": dispute_id,
                "previousStatus": "NEEDS_RESPONSE",
                "newStatus": "UNDER_REVIEW",
                "evidenceDigest": hashlib.sha256(evidence_json.encode("utf-8")).hexdigest(),
                "submittedBy": actor_id,
                "submittedAt": current_iso,
            }
            self._record_audit(
                conn,
                tenant_id=tenant_id,
                dispute_id=dispute_id,
                event_type="EVIDENCE_SUBMITTED",
                actor_id=actor_id,
                occurred_at=current_iso,
                payload=payload,
            )

        return self.get_dispute(tenant_id, dispute_id)

    def resolve_dispute(
        self,
        tenant_id: str,
        dispute_id: str,
        *,
        outcome: str,
        lost_fee_minor: int = 0,
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Resolve dispute as WON or LOST and apply financial adjustments."""
        dispute = self.get_dispute(tenant_id, dispute_id)
        if dispute["status"] not in ("NEEDS_RESPONSE", "UNDER_REVIEW"):
            raise ValidationError(f"dispute already resolved; current status: {dispute['status']}")

        outcome = outcome.upper()
        if outcome not in ("WON", "LOST"):
            raise ValidationError(f"invalid outcome: {outcome}; expected 'WON' or 'LOST'")

        if lost_fee_minor < 0:
            raise ValidationError("lost_fee_minor cannot be negative")

        current_iso = _instant(now)
        fee = lost_fee_minor if outcome == "LOST" else 0

        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE merchant_dispute SET status=?, lost_fee_minor=?, resolved_at=?, updated_at=? "
                "WHERE tenant_id=? AND dispute_id=?",
                (outcome, fee, current_iso, current_iso, tenant_id, dispute_id),
            )
            payload = {
                "disputeId": dispute_id,
                "previousStatus": dispute["status"],
                "outcome": outcome,
                "lostFeeMinor": fee,
                "resolvedBy": actor_id,
                "resolvedAt": current_iso,
            }
            self._record_audit(
                conn,
                tenant_id=tenant_id,
                dispute_id=dispute_id,
                event_type=f"DISPUTE_{outcome}",
                actor_id=actor_id,
                occurred_at=current_iso,
                payload=payload,
            )

        return self.get_dispute(tenant_id, dispute_id)

    def verify_dispute_audit_chain(self, tenant_id: str, dispute_id: str) -> bool:
        """Cryptographically verify the tamper-evident SHA-256 audit chain for a dispute."""
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM merchant_dispute_audit WHERE tenant_id=? AND dispute_id=? ORDER BY audit_id ASC",
                (tenant_id, dispute_id),
            ).fetchall()

        if not rows:
            raise ValidationError(f"no audit records found for dispute: {dispute_id}")

        prev_digest: str | None = None
        for r in rows:
            payload_json = r["payload_json"]
            payload_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
            if payload_digest != r["payload_digest"]:
                return False

            if r["previous_digest"] != prev_digest:
                return False

            expected_event_digest = hashlib.sha256(
                f"{r['tenant_id']}:{r['dispute_id']}:{r['event_type']}:{r['actor_id']}:{r['occurred_at']}:{payload_digest}:{prev_digest or ''}".encode("utf-8")
            ).hexdigest()

            if expected_event_digest != r["event_digest"]:
                return False

            prev_digest = r["event_digest"]

        return True

    def _record_audit(
        self,
        conn: Any,
        *,
        tenant_id: str,
        dispute_id: str,
        event_type: str,
        actor_id: str,
        occurred_at: str,
        payload: Mapping[str, Any],
    ) -> None:
        payload_json = canonical_json(payload).decode("utf-8")
        payload_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

        last_row = conn.execute(
            "SELECT event_digest FROM merchant_dispute_audit WHERE tenant_id=? AND dispute_id=? ORDER BY audit_id DESC LIMIT 1",
            (tenant_id, dispute_id),
        ).fetchone()
        previous_digest = last_row["event_digest"] if last_row else None

        event_digest = hashlib.sha256(
            f"{tenant_id}:{dispute_id}:{event_type}:{actor_id}:{occurred_at}:{payload_digest}:{previous_digest or ''}".encode("utf-8")
        ).hexdigest()

        conn.execute(
            "INSERT INTO merchant_dispute_audit ("
            "tenant_id, dispute_id, event_type, actor_id, occurred_at, payload_digest, previous_digest, event_digest, payload_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                dispute_id,
                event_type,
                actor_id,
                occurred_at,
                payload_digest,
                previous_digest,
                event_digest,
                payload_json,
            ),
        )
