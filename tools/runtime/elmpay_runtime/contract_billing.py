"""Commercial contract and milestone billing ledger for enterprise B2B fulfillment."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping, Sequence
import uuid

from .common import ValidationError, require_text
from .durable import DurableStore


def _current(now: datetime | None = None) -> datetime:
    return now or datetime.now(timezone.utc)


class CommercialContractLedger:
    """Manages B2B commercial contracts, phased milestone billing, and fulfillment reconciliation."""

    def __init__(self, store_or_db: DurableStore | Path | str) -> None:
        if isinstance(store_or_db, DurableStore):
            self.store = store_or_db
        else:
            self.store = DurableStore(Path(store_or_db))

    def create_contract(
        self,
        tenant_id: str,
        *,
        title: str,
        buyer_name: str,
        seller_name: str,
        seller_tax_number: str,
        total_amount_minor: int,
        buyer_tax_number: str | None = None,
        currency: str = "CNY",
        contract_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Register a new enterprise commercial contract."""
        require_text(tenant_id, "tenant_id")
        require_text(title, "title")
        require_text(buyer_name, "buyer_name")
        require_text(seller_name, "seller_name")
        require_text(seller_tax_number, "seller_tax_number")

        if not isinstance(total_amount_minor, int) or total_amount_minor <= 0:
            raise ValidationError("total_amount_minor must be a positive integer in minor units")

        cid = contract_id or f"CTR_{uuid.uuid4().hex[:12]}"
        now_dt = _current(now)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            existing = conn.execute(
                "SELECT contract_id FROM commercial_contract WHERE tenant_id=? AND contract_id=?",
                (tenant_id, cid),
            ).fetchone()
            if existing:
                raise ValidationError(f"contract '{cid}' already exists for tenant '{tenant_id}'")

            conn.execute(
                "INSERT INTO commercial_contract("
                "contract_id, tenant_id, title, buyer_name, buyer_tax_number, "
                "seller_name, seller_tax_number, total_amount_minor, currency, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)",
                (
                    cid,
                    tenant_id,
                    title,
                    buyer_name,
                    buyer_tax_number,
                    seller_name,
                    seller_tax_number,
                    total_amount_minor,
                    currency,
                    now_iso,
                    now_iso,
                ),
            )

        return self.get_contract_fulfillment_status(tenant_id, cid)

    def add_milestones(
        self,
        tenant_id: str,
        contract_id: str,
        milestones: Sequence[Mapping[str, Any]],
        *,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Define phased delivery milestones for an existing contract with mathematical sum conservation."""
        require_text(tenant_id, "tenant_id")
        require_text(contract_id, "contract_id")
        if not milestones:
            raise ValidationError("milestones list cannot be empty")

        now_iso = _current(now).isoformat()

        with self.store.transaction() as conn:
            contract = conn.execute(
                "SELECT * FROM commercial_contract WHERE tenant_id=? AND contract_id=?",
                (tenant_id, contract_id),
            ).fetchone()
            if not contract:
                raise ValidationError(f"contract '{contract_id}' not found")

            existing_count = conn.execute(
                "SELECT COUNT(*) as c FROM contract_milestone WHERE tenant_id=? AND contract_id=?",
                (tenant_id, contract_id),
            ).fetchone()["c"]
            if existing_count > 0:
                raise ValidationError(f"contract '{contract_id}' already has milestones defined")

            total_contract_minor = contract["total_amount_minor"]
            calculated_sum = 0
            inserted_milestones = []

            for idx, ms in enumerate(milestones, start=1):
                name = require_text(ms.get("name"), "milestone name")
                amt = ms.get("amount_minor")
                if not isinstance(amt, int) or amt <= 0:
                    raise ValidationError(f"milestone '{name}' must have a positive integer amount_minor")

                seq = ms.get("seq_order", idx)
                due_date = ms.get("due_date")
                mid = ms.get("milestone_id") or f"MS_{uuid.uuid4().hex[:12]}"

                calculated_sum += amt
                conn.execute(
                    "INSERT INTO contract_milestone("
                    "milestone_id, tenant_id, contract_id, seq_order, name, amount_minor, "
                    "invoiced_amount_minor, status, due_date, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 0, 'PENDING', ?, ?)",
                    (mid, tenant_id, contract_id, seq, name, amt, due_date, now_iso),
                )
                inserted_milestones.append({
                    "milestoneId": mid,
                    "seqOrder": seq,
                    "name": name,
                    "amountMinor": amt,
                    "invoicedAmountMinor": 0,
                    "status": "PENDING",
                    "dueDate": due_date,
                })

            if calculated_sum != total_contract_minor:
                raise ValidationError(
                    f"sum of milestone amounts ({calculated_sum}) must exactly equal "
                    f"contract total ({total_contract_minor})"
                )

            return inserted_milestones

    def invoice_contract_milestone(
        self,
        tenant_id: str,
        contract_id: str,
        milestone_id_or_seq: str | int,
        invoice_id: str,
        *,
        amount_minor: int | None = None,
        actor_id: str = "billing_system",
        notes: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Record an invoice against a specific contract milestone with ceiling enforcement."""
        require_text(tenant_id, "tenant_id")
        require_text(contract_id, "contract_id")
        require_text(invoice_id, "invoice_id")

        now_dt = _current(now)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            contract = conn.execute(
                "SELECT * FROM commercial_contract WHERE tenant_id=? AND contract_id=?",
                (tenant_id, contract_id),
            ).fetchone()
            if not contract:
                raise ValidationError(f"contract '{contract_id}' not found")
            if contract["status"] != "ACTIVE":
                raise ValidationError(f"cannot invoice against contract with status '{contract['status']}'")

            if isinstance(milestone_id_or_seq, int):
                milestone = conn.execute(
                    "SELECT * FROM contract_milestone WHERE tenant_id=? AND contract_id=? AND seq_order=?",
                    (tenant_id, contract_id, milestone_id_or_seq),
                ).fetchone()
            else:
                milestone = conn.execute(
                    "SELECT * FROM contract_milestone WHERE tenant_id=? AND contract_id=? AND milestone_id=?",
                    (tenant_id, contract_id, milestone_id_or_seq),
                ).fetchone()

            if not milestone:
                raise ValidationError(f"milestone '{milestone_id_or_seq}' not found in contract '{contract_id}'")

            mid = milestone["milestone_id"]
            ms_total = milestone["amount_minor"]
            ms_already_invoiced = milestone["invoiced_amount_minor"]

            bill_amt = amount_minor if amount_minor is not None else (ms_total - ms_already_invoiced)
            if not isinstance(bill_amt, int) or bill_amt <= 0:
                raise ValidationError("invoice amount_minor must be a positive integer")

            new_invoiced = ms_already_invoiced + bill_amt
            if new_invoiced > ms_total:
                raise ValidationError(
                    f"invoicing amount {bill_amt} exceeds remaining milestone balance ({ms_total - ms_already_invoiced})"
                )

            tot_invoiced = conn.execute(
                "SELECT SUM(invoiced_amount_minor) as s FROM contract_milestone WHERE tenant_id=? AND contract_id=?",
                (tenant_id, contract_id),
            ).fetchone()["s"] or 0

            if tot_invoiced + bill_amt > contract["total_amount_minor"]:
                raise ValidationError("cumulative invoiced amount exceeds total contract value")

            new_status = "FULLY_INVOICED" if new_invoiced == ms_total else "PARTIALLY_INVOICED"
            conn.execute(
                "UPDATE contract_milestone SET invoiced_amount_minor=?, status=? WHERE milestone_id=?",
                (new_invoiced, new_status, mid),
            )

            entry_id = f"CF_{uuid.uuid4().hex[:12]}"
            conn.execute(
                "INSERT INTO contract_fulfillment_ledger("
                "entry_id, tenant_id, contract_id, milestone_id, invoice_id, "
                "entry_type, amount_minor, actor_id, notes, created_at) "
                "VALUES (?, ?, ?, ?, ?, 'MILESTONE_INVOICED', ?, ?, ?, ?)",
                (entry_id, tenant_id, contract_id, mid, invoice_id, bill_amt, actor_id, notes, now_iso),
            )

            all_invoiced = conn.execute(
                "SELECT COUNT(*) as c FROM contract_milestone "
                "WHERE tenant_id=? AND contract_id=? AND status != 'FULLY_INVOICED'",
                (tenant_id, contract_id),
            ).fetchone()["c"] == 0

            if all_invoiced:
                conn.execute(
                    "UPDATE commercial_contract SET status='COMPLETED', updated_at=? WHERE contract_id=?",
                    (now_iso, contract_id),
                )

        return self.get_contract_fulfillment_status(tenant_id, contract_id)

    def get_contract_fulfillment_status(self, tenant_id: str, contract_id: str) -> dict[str, Any]:
        """Query contract fulfillment progress, milestones breakdown, and ledger history."""
        with self.store.connect() as conn:
            c = conn.execute(
                "SELECT * FROM commercial_contract WHERE tenant_id=? AND contract_id=?",
                (tenant_id, contract_id),
            ).fetchone()
            if not c:
                raise ValidationError(f"contract '{contract_id}' not found")

            milestones = conn.execute(
                "SELECT * FROM contract_milestone WHERE tenant_id=? AND contract_id=? ORDER BY seq_order ASC",
                (tenant_id, contract_id),
            ).fetchall()

            ledger_rows = conn.execute(
                "SELECT * FROM contract_fulfillment_ledger WHERE tenant_id=? AND contract_id=? ORDER BY created_at ASC",
                (tenant_id, contract_id),
            ).fetchall()

            tot_contract = c["total_amount_minor"]
            tot_invoiced = sum(m["invoiced_amount_minor"] for m in milestones)
            unbilled = max(0, tot_contract - tot_invoiced)
            ratio_bps = (tot_invoiced * 10000) // tot_contract if tot_contract > 0 else 0

            return {
                "contractId": c["contract_id"],
                "tenantId": c["tenant_id"],
                "title": c["title"],
                "buyerName": c["buyer_name"],
                "buyerTaxNumber": c["buyer_tax_number"],
                "sellerName": c["seller_name"],
                "sellerTaxNumber": c["seller_tax_number"],
                "totalAmountMinor": tot_contract,
                "currency": c["currency"],
                "status": c["status"],
                "billedAmountMinor": tot_invoiced,
                "remainingUnbilledMinor": unbilled,
                "fulfillmentRatioBasisPoints": ratio_bps,
                "milestones": [
                    {
                        "milestoneId": m["milestone_id"],
                        "seqOrder": m["seq_order"],
                        "name": m["name"],
                        "amountMinor": m["amount_minor"],
                        "invoicedAmountMinor": m["invoiced_amount_minor"],
                        "status": m["status"],
                        "dueDate": m["due_date"],
                    }
                    for m in milestones
                ],
                "ledger": [
                    {
                        "entryId": r["entry_id"],
                        "milestoneId": r["milestone_id"],
                        "invoiceId": r["invoice_id"],
                        "entryType": r["entry_type"],
                        "amountMinor": r["amount_minor"],
                        "actorId": r["actor_id"],
                        "notes": r["notes"],
                        "createdAt": r["created_at"],
                    }
                    for r in ledger_rows
                ],
                "createdAt": c["created_at"],
                "updatedAt": c["updated_at"],
            }
