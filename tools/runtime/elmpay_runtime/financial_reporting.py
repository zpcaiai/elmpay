"""Enterprise Financial Exception Management, Maker-Checker Resolution & Immutable Financial Reporting (B78-B79)."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence
import uuid

from .common import ValidationError, require_text, parse_instant
from .durable import DurableStore
from .financial_ledger import FinancialDoubleEntryLedger


def _current(now: datetime | None = None) -> datetime:
    return now or datetime.now(timezone.utc)


def _to_dt(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    return parse_instant(value, field)


class FinancialExceptionManager:
    """Manages financial discrepancy tickets, Maker-Checker 4-eyes approvals, and automated ledger adjustments."""

    def __init__(self, store_or_db: DurableStore | Path | str) -> None:
        if isinstance(store_or_db, DurableStore):
            self.store = store_or_db
        else:
            self.store = DurableStore(Path(store_or_db))
        self.ledger = FinancialDoubleEntryLedger(self.store)

    def create_ticket(
        self,
        tenant_id: str,
        *,
        category: str,
        reference_id: str,
        amount_minor: int,
        currency: str,
        notes: str | None = None,
        ticket_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Register a new financial discrepancy ticket."""
        require_text(tenant_id, "tenant_id")
        require_text(category, "category")
        require_text(reference_id, "reference_id")
        require_text(currency, "currency")

        cat = category.upper()
        allowed_categories = ("SURPLUS", "DEFICIT", "AMOUNT_MISMATCH", "TIMING_VARIANCE", "DUPLICATE_CHARGE")
        if cat not in allowed_categories:
            raise ValidationError(f"Invalid category '{category}'. Must be one of {allowed_categories}")

        if not isinstance(amount_minor, int) or amount_minor <= 0:
            raise ValidationError("amount_minor must be a positive integer in minor units")

        tid = ticket_id or f"TKT_{uuid.uuid4().hex[:12]}"
        curr = currency.upper()
        now_iso = _current(now).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO financial_exception_ticket ("
                "  ticket_id, tenant_id, category, reference_id, amount_minor, currency, "
                "  status, maker_id, checker_id, proposed_action, notes, journal_entry_id, "
                "  created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, 'OPEN', NULL, NULL, NULL, ?, NULL, ?, ?)",
                (tid, tenant_id, cat, reference_id, amount_minor, curr, notes or "", now_iso, now_iso),
            )

        return {
            "ticketId": tid,
            "tenantId": tenant_id,
            "category": cat,
            "referenceId": reference_id,
            "amountMinor": amount_minor,
            "currency": curr,
            "status": "OPEN",
            "notes": notes or "",
            "createdAt": now_iso,
            "updatedAt": now_iso,
        }

    def propose_resolution(
        self,
        tenant_id: str,
        *,
        ticket_id: str,
        action: str,
        maker_id: str,
        notes: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Maker step: propose a resolution action for a financial discrepancy."""
        require_text(tenant_id, "tenant_id")
        require_text(ticket_id, "ticket_id")
        require_text(action, "action")
        require_text(maker_id, "maker_id")

        act = action.upper()
        allowed_actions = ("MANUAL_POSTING", "WRITE_OFF", "REFUND_TO_CUSTOMER", "CHARGE_BACK_RECOVERY", "NONE")
        if act not in allowed_actions:
            raise ValidationError(f"Invalid action '{action}'. Must be one of {allowed_actions}")

        now_iso = _current(now).isoformat()

        with self.store.transaction() as conn:
            ticket = conn.execute(
                "SELECT * FROM financial_exception_ticket WHERE tenant_id=? AND ticket_id=?",
                (tenant_id, ticket_id),
            ).fetchone()
            if not ticket:
                raise ValidationError(f"Ticket '{ticket_id}' not found")
            if ticket["status"] not in ("OPEN", "REJECTED"):
                raise ValidationError(f"Cannot propose resolution for ticket in status '{ticket['status']}'")

            cur = conn.execute(
                "UPDATE financial_exception_ticket SET "
                "  status='PENDING_CHECKER', maker_id=?, proposed_action=?, notes=?, updated_at=? "
                "WHERE tenant_id=? AND ticket_id=? AND status IN ('OPEN', 'REJECTED')",
                (maker_id, act, notes, now_iso, tenant_id, ticket_id),
            )
            if cur.rowcount != 1:
                raise ValidationError(f"Ticket '{ticket_id}' was concurrently modified")

        return {
            "ticketId": ticket_id,
            "tenantId": tenant_id,
            "status": "PENDING_CHECKER",
            "makerId": maker_id,
            "proposedAction": act,
            "notes": notes,
            "updatedAt": now_iso,
        }

    def approve_resolution(
        self,
        tenant_id: str,
        *,
        ticket_id: str,
        checker_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Checker step: approve resolution with strict Maker != Checker 4-eyes enforcement and ledger posting."""
        require_text(tenant_id, "tenant_id")
        require_text(ticket_id, "ticket_id")
        require_text(checker_id, "checker_id")

        now_dt = _current(now)
        now_iso = now_dt.isoformat()

        # Step 1: Atomically validate and transition ticket to APPROVED under transaction with CAS
        with self.store.transaction() as conn:
            ticket = conn.execute(
                "SELECT * FROM financial_exception_ticket WHERE tenant_id=? AND ticket_id=?",
                (tenant_id, ticket_id),
            ).fetchone()
            if not ticket:
                raise ValidationError(f"Ticket '{ticket_id}' not found")
            if ticket["status"] != "PENDING_CHECKER":
                raise ValidationError(f"Ticket '{ticket_id}' is not awaiting approval (status: {ticket['status']})")

            maker_id = ticket["maker_id"]
            if checker_id == maker_id:
                raise ValidationError("Maker and checker cannot be the same person (four-eyes principle enforced)")

            action = ticket["proposed_action"]
            amt = int(ticket["amount_minor"])
            curr = ticket["currency"]

            target_status = "CLOSED_NO_ACTION" if action == "NONE" else "APPROVED"
            cur = conn.execute(
                "UPDATE financial_exception_ticket SET "
                "  status=?, checker_id=?, updated_at=? "
                "WHERE tenant_id=? AND ticket_id=? AND status='PENDING_CHECKER'",
                (target_status, checker_id, now_iso, tenant_id, ticket_id),
            )
            if cur.rowcount != 1:
                raise ValidationError(f"Ticket '{ticket_id}' was already processed by another operator")

        # Step 2: Only the winning thread reaches here; post double-entry ledger entry
        journal_entry_id = None
        if action == "WRITE_OFF":
            # Bad debt write-off: DEBIT 5002_BAD_DEBT_EXPENSE, CREDIT 1001_CASH_IN_TRANSIT
            entry = self.ledger.post_journal_entry(
                tenant_id,
                transaction_type="EXCEPTION_WRITE_OFF",
                source_event_id=f"EXC_WRITEOFF_{ticket_id}",
                currency=curr,
                legs=[
                    {"accountCode": "5002_BAD_DEBT_EXPENSE", "direction": "DEBIT", "amountMinor": amt},
                    {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "CREDIT", "amountMinor": amt},
                ],
                now=now_dt,
            )
            journal_entry_id = entry["entryId"]

        elif action == "MANUAL_POSTING":
            # Manual cash in transit recovery: DEBIT 1001_CASH_IN_TRANSIT, CREDIT 2001_MERCHANT_PAYABLE
            entry = self.ledger.post_journal_entry(
                tenant_id,
                transaction_type="EXCEPTION_MANUAL_POSTING",
                source_event_id=f"EXC_POSTING_{ticket_id}",
                currency=curr,
                legs=[
                    {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": amt},
                    {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": amt},
                ],
                now=now_dt,
            )
            journal_entry_id = entry["entryId"]

        elif action == "REFUND_TO_CUSTOMER":
            # Refund customer surplus: DEBIT 2001_MERCHANT_PAYABLE, CREDIT 1001_CASH_IN_TRANSIT
            entry = self.ledger.post_journal_entry(
                tenant_id,
                transaction_type="EXCEPTION_CUSTOMER_REFUND",
                source_event_id=f"EXC_REFUND_{ticket_id}",
                currency=curr,
                legs=[
                    {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "DEBIT", "amountMinor": amt},
                    {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "CREDIT", "amountMinor": amt},
                ],
                now=now_dt,
            )
            journal_entry_id = entry["entryId"]

        # Step 3: Record the journal_entry_id on the ticket
        if journal_entry_id:
            with self.store.transaction() as conn:
                conn.execute(
                    "UPDATE financial_exception_ticket SET journal_entry_id=? WHERE tenant_id=? AND ticket_id=?",
                    (journal_entry_id, tenant_id, ticket_id),
                )

        return {
            "ticketId": ticket_id,
            "tenantId": tenant_id,
            "status": target_status,
            "makerId": maker_id,
            "checkerId": checker_id,
            "proposedAction": action,
            "journalEntryId": journal_entry_id,
            "updatedAt": now_iso,
        }

    def reject_resolution(
        self,
        tenant_id: str,
        *,
        ticket_id: str,
        checker_id: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Checker step: reject the proposed resolution."""
        require_text(tenant_id, "tenant_id")
        require_text(ticket_id, "ticket_id")
        require_text(checker_id, "checker_id")
        require_text(reason, "reason")

        now_iso = _current(now).isoformat()

        with self.store.transaction() as conn:
            ticket = conn.execute(
                "SELECT * FROM financial_exception_ticket WHERE tenant_id=? AND ticket_id=?",
                (tenant_id, ticket_id),
            ).fetchone()
            if not ticket:
                raise ValidationError(f"Ticket '{ticket_id}' not found")
            if ticket["status"] != "PENDING_CHECKER":
                raise ValidationError(f"Ticket '{ticket_id}' is not in PENDING_CHECKER status")

            if checker_id == ticket["maker_id"]:
                raise ValidationError("Maker and checker cannot be the same person")

            cur = conn.execute(
                "UPDATE financial_exception_ticket SET "
                "  status='REJECTED', checker_id=?, notes=?, updated_at=? "
                "WHERE tenant_id=? AND ticket_id=? AND status='PENDING_CHECKER'",
                (checker_id, f"Rejected: {reason}", now_iso, tenant_id, ticket_id),
            )
            if cur.rowcount != 1:
                raise ValidationError(f"Ticket '{ticket_id}' was already processed by another operator")

        return {
            "ticketId": ticket_id,
            "tenantId": tenant_id,
            "status": "REJECTED",
            "checkerId": checker_id,
            "reason": reason,
            "updatedAt": now_iso,
        }

    def list_tickets(
        self,
        tenant_id: str,
        *,
        status: str | None = None,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """List exception tickets with optional filters."""
        require_text(tenant_id, "tenant_id")

        query = "SELECT * FROM financial_exception_ticket WHERE tenant_id=?"
        params: list[Any] = [tenant_id]

        if status:
            query += " AND status=?"
            params.append(status.upper())
        if category:
            query += " AND category=?"
            params.append(category.upper())

        query += " ORDER BY created_at DESC"

        with self.store.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [
                {
                    "ticketId": r["ticket_id"],
                    "tenantId": r["tenant_id"],
                    "category": r["category"],
                    "referenceId": r["reference_id"],
                    "amountMinor": r["amount_minor"],
                    "currency": r["currency"],
                    "status": r["status"],
                    "makerId": r["maker_id"],
                    "checkerId": r["checker_id"],
                    "proposedAction": r["proposed_action"],
                    "notes": r["notes"],
                    "journalEntryId": r["journal_entry_id"],
                    "createdAt": r["created_at"],
                    "updatedAt": r["updated_at"],
                }
                for r in rows
            ]


class FinancialReportingEngine:
    """Generates multi-dimensional financial metrics and exports tamper-proof audit manifests."""

    def __init__(self, store_or_db: DurableStore | Path | str) -> None:
        if isinstance(store_or_db, DurableStore):
            self.store = store_or_db
        else:
            self.store = DurableStore(Path(store_or_db))

    def generate_period_report(
        self,
        tenant_id: str,
        *,
        period_start: str | datetime,
        period_end: str | datetime,
        currency: str,
    ) -> dict[str, Any]:
        """Compute key financial KPIs: GMV, Net Revenue, Fees, Refunds, Disputes, and Take Rate."""
        require_text(tenant_id, "tenant_id")
        require_text(currency, "currency")

        start_dt = _to_dt(period_start, "period_start")
        end_dt = _to_dt(period_end, "period_end")
        if end_dt <= start_dt:
            raise ValidationError("period_end must be strictly after period_start")

        start_iso = start_dt.isoformat()
        end_iso = end_dt.isoformat()
        curr = currency.upper()

        with self.store.connect() as conn:
            # Query ledger journal legs
            legs_query = (
                "SELECT l.account_code, l.direction, l.amount_minor, j.transaction_type, j.entry_id "
                "FROM financial_journal_leg l "
                "JOIN financial_double_entry_journal j ON l.entry_id = j.entry_id "
                "WHERE j.tenant_id = ? AND j.currency = ? AND j.posted_at >= ? AND j.posted_at <= ?"
            )
            legs = conn.execute(legs_query, (tenant_id, curr, start_iso, end_iso)).fetchall()

            # Query exception tickets
            tkt_query = (
                "SELECT status, proposed_action, amount_minor FROM financial_exception_ticket "
                "WHERE tenant_id = ? AND currency = ? AND created_at >= ? AND created_at <= ?"
            )
            tickets = conn.execute(tkt_query, (tenant_id, curr, start_iso, end_iso)).fetchall()

        gmv_minor = 0
        fee_revenue_minor = 0
        interchange_expense_minor = 0
        merchant_payable_minor = 0
        refunds_minor = 0
        disputes_minor = 0
        write_offs_minor = 0
        unique_entry_ids = set()

        for l in legs:
            unique_entry_ids.add(l["entry_id"])
            acct = l["account_code"]
            dirn = l["direction"]
            amt = int(l["amount_minor"])
            ttype = l["transaction_type"]

            # GMV: Cash in transit debited on capture / sales
            if acct == "1001_CASH_IN_TRANSIT" and dirn == "DEBIT" and "REFUND" not in ttype and "REVERSAL" not in ttype:
                gmv_minor += amt

            # Platform processing fee revenue (Credit)
            if acct == "4001_PROCESSING_FEE_REVENUE" and dirn == "CREDIT":
                fee_revenue_minor += amt

            # Interchange & gateway network expense (Debit)
            if acct == "5001_INTERCHANGE_EXPENSE" and dirn == "DEBIT":
                interchange_expense_minor += amt

            # Merchant payable credited
            if acct == "2001_MERCHANT_PAYABLE" and dirn == "CREDIT":
                merchant_payable_minor += amt

            # Refunds (Debit on Merchant Payable or Reversal)
            if ("REFUND" in ttype or "REVERSAL" in ttype) and dirn == "CREDIT" and acct == "1001_CASH_IN_TRANSIT":
                refunds_minor += amt

            # Dispute reserve held back
            if acct == "2003_DISPUTE_RESERVE" and dirn == "CREDIT":
                disputes_minor += amt

            # Bad debt write-offs
            if acct == "5002_BAD_DEBT_EXPENSE" and dirn == "DEBIT":
                write_offs_minor += amt

        net_revenue_minor = fee_revenue_minor - interchange_expense_minor

        # Take Rate and Refund Rate in basis points (integer math)
        take_rate_bps = (fee_revenue_minor * 10000 // gmv_minor) if gmv_minor > 0 else 0
        refund_rate_bps = (refunds_minor * 10000 // gmv_minor) if gmv_minor > 0 else 0

        # Exceptions summary
        total_tickets = len(tickets)
        resolved_tickets = sum(1 for t in tickets if t["status"] in ("APPROVED", "CLOSED_NO_ACTION"))
        tickets_amount_minor = sum(int(t["amount_minor"]) for t in tickets)

        return {
            "tenantId": tenant_id,
            "currency": curr,
            "periodStart": start_iso,
            "periodEnd": end_iso,
            "transactionCount": len(unique_entry_ids),
            "gmvMinor": gmv_minor,
            "feeRevenueMinor": fee_revenue_minor,
            "interchangeExpenseMinor": interchange_expense_minor,
            "netRevenueMinor": net_revenue_minor,
            "merchantPayableMinor": merchant_payable_minor,
            "refundsMinor": refunds_minor,
            "disputesMinor": disputes_minor,
            "writeOffsMinor": write_offs_minor,
            "takeRateBasisPoints": take_rate_bps,
            "refundRateBasisPoints": refund_rate_bps,
            "exceptionTickets": {
                "totalCount": total_tickets,
                "resolvedCount": resolved_tickets,
                "totalAmountMinor": tickets_amount_minor,
            },
        }

    def export_financial_audit_manifest(
        self,
        tenant_id: str,
        *,
        period_start: str | datetime,
        period_end: str | datetime,
        currency: str,
        manifest_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Export an immutable, SHA-256 cryptographically sealed financial audit manifest."""
        metrics = self.generate_period_report(
            tenant_id,
            period_start=period_start,
            period_end=period_end,
            currency=currency,
        )

        mid = manifest_id or f"FAM_{uuid.uuid4().hex[:12]}"
        now_iso = _current(now).isoformat()
        start_iso = metrics["periodStart"]
        end_iso = metrics["periodEnd"]
        curr = metrics["currency"]

        # Fetch underlying journal entry headers for audit trace
        with self.store.connect() as conn:
            j_rows = conn.execute(
                "SELECT entry_id, sequence_num, transaction_type, total_amount_minor, entry_hash "
                "FROM financial_double_entry_journal "
                "WHERE tenant_id=? AND currency=? AND posted_at>=? AND posted_at<=? "
                "ORDER BY sequence_num ASC",
                (tenant_id, curr, start_iso, end_iso),
            ).fetchall()

            journal_summary = [
                {
                    "entryId": r["entry_id"],
                    "sequenceNum": r["sequence_num"],
                    "transactionType": r["transaction_type"],
                    "amountMinor": r["total_amount_minor"],
                    "entryHash": r["entry_hash"],
                }
                for r in j_rows
            ]

        manifest_payload = {
            "manifestId": mid,
            "tenantId": tenant_id,
            "currency": curr,
            "periodStart": start_iso,
            "periodEnd": end_iso,
            "metrics": metrics,
            "journalSummary": journal_summary,
            "exportedAt": now_iso,
        }

        canonical_json = json.dumps(manifest_payload, separators=(",", ":"), sort_keys=True)
        manifest_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO financial_report_manifest ("
                "  manifest_id, tenant_id, period_start, period_end, currency, metrics_json, manifest_digest, exported_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (mid, tenant_id, start_iso, end_iso, curr, canonical_json, manifest_digest, now_iso),
            )

        manifest_payload["manifestDigest"] = manifest_digest
        return manifest_payload

    @staticmethod
    def verify_financial_audit_manifest(manifest_data: Mapping[str, Any]) -> dict[str, Any]:
        """Verify the cryptographic SHA-256 seal of a financial audit manifest."""
        manifest_dict = dict(manifest_data)
        given_digest = manifest_dict.pop("manifestDigest", None)
        if not given_digest:
            return {"valid": False, "reason": "Missing manifestDigest in payload"}

        canonical_json = json.dumps(manifest_dict, separators=(",", ":"), sort_keys=True)
        computed_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        is_valid = (computed_digest == given_digest)
        return {
            "valid": is_valid,
            "manifestId": manifest_dict.get("manifestId"),
            "computedDigest": computed_digest,
            "expectedDigest": given_digest,
        }
