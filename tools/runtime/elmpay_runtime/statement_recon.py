# tools/runtime/elmpay_runtime/statement_recon.py
from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

from .common import ValidationError
from .durable import DurableStore


class StatementReconciliationEngine:
    """Channel statement ingestion, three-way multi-stream cross-reconciliation, and four-eyes adjustment engine."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def ingest_statement(
        self,
        tenant_id: str,
        channel_id: str,
        statement_date: str,
        file_name: str,
        items: List[Dict[str, Any]],
        currency: str = "CNY",
    ) -> Dict[str, Any]:
        """Ingests, validates, digests, and records an acquirer channel statement batch."""
        if not items:
            raise ValidationError("statement items list cannot be empty")
        if not channel_id or not channel_id.strip():
            raise ValidationError("channel_id cannot be empty")
        if not statement_date or not statement_date.strip():
            raise ValidationError("statement_date cannot be empty")

        currency = currency.strip().upper()
        batch_id = f"stb_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Compute deterministic SHA-256 digest of statement content
        canonical_content = json.dumps(items, sort_keys=True, separators=(",", ":")).encode("utf-8")
        file_digest = hashlib.sha256(canonical_content).hexdigest()

        total_amount = 0
        validated_items: List[Dict[str, Any]] = []

        for idx, item in enumerate(items):
            ch_txn = str(item.get("channel_txn_id", "")).strip()
            amt = int(item.get("amount_minor", 0))
            fee = int(item.get("fee_minor", 0))
            txn_type = str(item.get("txn_type", "PAYMENT")).strip().upper()
            settled_at = str(item.get("settled_at", now_iso)).strip()

            if not ch_txn:
                raise ValidationError(f"item #{idx} missing channel_txn_id")
            if amt <= 0:
                raise ValidationError(f"item #{idx} amount_minor must be strictly positive")
            if fee < 0:
                raise ValidationError(f"item #{idx} fee_minor cannot be negative")
            if txn_type not in ("PAYMENT", "REFUND", "DISPUTE_DEBIT", "FEE"):
                raise ValidationError(f"item #{idx} invalid txn_type: {txn_type}")

            total_amount += amt
            validated_items.append({
                "item_id": f"sti_{uuid.uuid4().hex[:12]}",
                "channel_txn_id": ch_txn,
                "internal_txn_id": item.get("internal_txn_id"),
                "amount_minor": amt,
                "fee_minor": fee,
                "currency": currency,
                "txn_type": txn_type,
                "settled_at": settled_at,
            })

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO recon_statement_batch (
                    batch_id, tenant_id, channel_id, statement_date,
                    file_name, file_digest, total_records, total_amount_minor,
                    currency, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'INGESTED', ?)
                """,
                (
                    batch_id, tenant_id, channel_id, statement_date,
                    file_name, file_digest, len(validated_items), total_amount,
                    currency, now_iso
                ),
            )

            for vi in validated_items:
                conn.execute(
                    """
                    INSERT INTO recon_statement_item (
                        item_id, batch_id, tenant_id, channel_txn_id,
                        internal_txn_id, amount_minor, fee_minor, currency,
                        txn_type, settled_at, recon_status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'UNMATCHED', ?)
                    """,
                    (
                        vi["item_id"], batch_id, tenant_id, vi["channel_txn_id"],
                        vi["internal_txn_id"], vi["amount_minor"], vi["fee_minor"],
                        vi["currency"], vi["txn_type"], vi["settled_at"], now_iso
                    ),
                )

        return {
            "batch_id": batch_id,
            "tenant_id": tenant_id,
            "channel_id": channel_id,
            "statement_date": statement_date,
            "file_name": file_name,
            "file_digest": file_digest,
            "total_records": len(validated_items),
            "total_amount_minor": total_amount,
            "currency": currency,
            "status": "INGESTED",
        }

    def reconcile_three_way(
        self,
        tenant_id: str,
        batch_id: str,
        internal_transactions: List[Dict[str, Any]],
        bank_clearing_records: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Executes 3-way reconciliation across platform ledger, channel statements, and bank clearing."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            batch = conn.execute(
                "SELECT * FROM recon_statement_batch WHERE batch_id = ? AND tenant_id = ?",
                (batch_id, tenant_id),
            ).fetchone()
            if not batch:
                raise ValidationError(f"statement batch {batch_id} not found")

            items = conn.execute(
                "SELECT * FROM recon_statement_item WHERE batch_id = ?",
                (batch_id,),
            ).fetchall()

        int_by_id = {str(t.get("internal_txn_id")): t for t in internal_transactions if t.get("internal_txn_id")}
        int_by_ch = {str(t.get("channel_txn_id")): t for t in internal_transactions if t.get("channel_txn_id")}

        bank_by_ch = {}
        if bank_clearing_records:
            for b in bank_clearing_records:
                ch_ref = str(b.get("channel_txn_id") or b.get("bank_clearing_ref", ""))
                if ch_ref:
                    bank_by_ch[ch_ref] = b

        matched_count = 0
        discrepancy_count = 0
        matched_internal_ids = set()

        discrepancies: List[Dict[str, Any]] = []

        with self.store.transaction() as conn:
            for item in items:
                ch_id = item["channel_txn_id"]
                int_id = item["internal_txn_id"]

                matched_int = int_by_id.get(int_id) if int_id else int_by_ch.get(ch_id)

                if matched_int:
                    matched_internal_ids.add(str(matched_int.get("internal_txn_id")))
                    int_amt = int(matched_int.get("amount_minor", 0))
                    ch_amt = item["amount_minor"]

                    if int_amt != ch_amt:
                        # Discrepancy: Amount mismatch
                        disc_id = f"dsc_{uuid.uuid4().hex[:12]}"
                        conn.execute(
                            """
                            UPDATE recon_statement_item
                            SET recon_status = 'DISCREPANCY', discrepancy_reason = 'AMOUNT_MISMATCH'
                            WHERE item_id = ?
                            """,
                            (item["item_id"],),
                        )
                        conn.execute(
                            """
                            INSERT INTO recon_discrepancy_journal (
                                discrepancy_id, tenant_id, batch_id, item_id,
                                internal_txn_id, channel_txn_id, discrepancy_type,
                                delta_amount_minor, currency, status, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, 'AMOUNT_MISMATCH', ?, ?, 'OPEN', ?)
                            """,
                            (
                                disc_id, tenant_id, batch_id, item["item_id"],
                                matched_int.get("internal_txn_id"), ch_id,
                                abs(int_amt - ch_amt), item["currency"], now_iso
                            ),
                        )
                        discrepancy_count += 1
                        discrepancies.append({
                            "discrepancy_id": disc_id,
                            "type": "AMOUNT_MISMATCH",
                            "delta_minor": abs(int_amt - ch_amt),
                            "channel_txn_id": ch_id,
                        })
                    else:
                        # Matches internal transaction; check bank clearing if present
                        bank_match = bank_by_ch.get(ch_id)
                        if bank_match and int(bank_match.get("amount_minor", 0)) != ch_amt:
                            disc_id = f"dsc_{uuid.uuid4().hex[:12]}"
                            delta = abs(int(bank_match.get("amount_minor", 0)) - ch_amt)
                            conn.execute(
                                """
                                UPDATE recon_statement_item
                                SET recon_status = 'DISCREPANCY', discrepancy_reason = 'FEE_DISCREPANCY'
                                WHERE item_id = ?
                                """,
                                (item["item_id"],),
                            )
                            conn.execute(
                                """
                                INSERT INTO recon_discrepancy_journal (
                                    discrepancy_id, tenant_id, batch_id, item_id,
                                    internal_txn_id, channel_txn_id, discrepancy_type,
                                    delta_amount_minor, currency, status, created_at
                                ) VALUES (?, ?, ?, ?, ?, ?, 'FEE_DISCREPANCY', ?, ?, 'OPEN', ?)
                                """,
                                (
                                    disc_id, tenant_id, batch_id, item["item_id"],
                                    matched_int.get("internal_txn_id"), ch_id,
                                    delta, item["currency"], now_iso
                                ),
                            )
                            discrepancy_count += 1
                            discrepancies.append({
                                "discrepancy_id": disc_id,
                                "type": "FEE_DISCREPANCY",
                                "delta_minor": delta,
                                "channel_txn_id": ch_id,
                            })
                        else:
                            conn.execute(
                                "UPDATE recon_statement_item SET recon_status = 'MATCHED' WHERE item_id = ?",
                                (item["item_id"],),
                            )
                            matched_count += 1
                else:
                    # Unilateral platform missing (Channel has transaction, platform lacks record)
                    disc_id = f"dsc_{uuid.uuid4().hex[:12]}"
                    conn.execute(
                        """
                        UPDATE recon_statement_item
                        SET recon_status = 'DISCREPANCY', discrepancy_reason = 'UNILATERAL_PLATFORM_MISSING'
                        WHERE item_id = ?
                        """,
                        (item["item_id"],),
                    )
                    conn.execute(
                        """
                        INSERT INTO recon_discrepancy_journal (
                            discrepancy_id, tenant_id, batch_id, item_id,
                            internal_txn_id, channel_txn_id, discrepancy_type,
                            delta_amount_minor, currency, status, created_at
                        ) VALUES (?, ?, ?, ?, NULL, ?, 'UNILATERAL_PLATFORM_MISSING', ?, ?, 'OPEN', ?)
                        """,
                        (
                            disc_id, tenant_id, batch_id, item["item_id"],
                            ch_id, item["amount_minor"], item["currency"], now_iso
                        ),
                    )
                    discrepancy_count += 1
                    discrepancies.append({
                        "discrepancy_id": disc_id,
                        "type": "UNILATERAL_PLATFORM_MISSING",
                        "delta_minor": item["amount_minor"],
                        "channel_txn_id": ch_id,
                    })

            # Check for internal transactions missing from channel statements (Unilateral channel missing)
            for int_tx in internal_transactions:
                it_id = str(int_tx.get("internal_txn_id"))
                if it_id and it_id not in matched_internal_ids:
                    disc_id = f"dsc_{uuid.uuid4().hex[:12]}"
                    amt = int(int_tx.get("amount_minor", 0))
                    curr = str(int_tx.get("currency", batch["currency"])).strip().upper()
                    conn.execute(
                        """
                        INSERT INTO recon_discrepancy_journal (
                            discrepancy_id, tenant_id, batch_id, item_id,
                            internal_txn_id, channel_txn_id, discrepancy_type,
                            delta_amount_minor, currency, status, created_at
                        ) VALUES (?, ?, ?, NULL, ?, NULL, 'UNILATERAL_CHANNEL_MISSING', ?, ?, 'OPEN', ?)
                        """,
                        (disc_id, tenant_id, batch_id, it_id, amt, curr, now_iso),
                    )
                    discrepancy_count += 1
                    discrepancies.append({
                        "discrepancy_id": disc_id,
                        "type": "UNILATERAL_CHANNEL_MISSING",
                        "delta_minor": amt,
                        "internal_txn_id": it_id,
                    })

            final_status = "RECONCILED" if discrepancy_count == 0 else "DISCREPANCY_FOUND"
            conn.execute(
                "UPDATE recon_statement_batch SET status = ? WHERE batch_id = ?",
                (final_status, batch_id),
            )

        return {
            "batch_id": batch_id,
            "tenant_id": tenant_id,
            "status": final_status,
            "total_items": len(items),
            "matched_count": matched_count,
            "discrepancy_count": discrepancy_count,
            "discrepancies": discrepancies,
            "reconciled_at": now_iso,
        }

    def propose_discrepancy_adjustment(
        self,
        tenant_id: str,
        discrepancy_id: str,
        proposed_action: str,
        maker_id: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Maker stage of four-eyes discrepancy adjustment."""
        proposed_action = proposed_action.strip().upper()
        if proposed_action not in ("WRITE_OFF", "MANUAL_SETTLE", "DISPUTE_CLAIM"):
            raise ValidationError(f"invalid proposed_action: {proposed_action}")
        if not maker_id or not maker_id.strip():
            raise ValidationError("maker_id cannot be empty")

        with self.store.transaction() as conn:
            disc = conn.execute(
                "SELECT * FROM recon_discrepancy_journal WHERE discrepancy_id = ? AND tenant_id = ?",
                (discrepancy_id, tenant_id),
            ).fetchone()
            if not disc:
                raise ValidationError(f"discrepancy {discrepancy_id} not found")
            if disc["status"] not in ("OPEN", "PENDING_APPROVAL"):
                raise ValidationError(f"cannot adjust discrepancy in status {disc['status']}")

            conn.execute(
                """
                UPDATE recon_discrepancy_journal
                SET status = 'PENDING_APPROVAL', proposed_action = ?, maker_id = ?, resolution_notes = ?
                WHERE discrepancy_id = ?
                """,
                (proposed_action, maker_id, notes, discrepancy_id),
            )

        return {
            "discrepancy_id": discrepancy_id,
            "status": "PENDING_APPROVAL",
            "proposed_action": proposed_action,
            "maker_id": maker_id,
        }

    def approve_discrepancy_adjustment(
        self,
        tenant_id: str,
        discrepancy_id: str,
        checker_id: str,
    ) -> Dict[str, Any]:
        """Checker stage of four-eyes discrepancy adjustment (enforces maker != checker)."""
        if not checker_id or not checker_id.strip():
            raise ValidationError("checker_id cannot be empty")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            disc = conn.execute(
                "SELECT * FROM recon_discrepancy_journal WHERE discrepancy_id = ? AND tenant_id = ?",
                (discrepancy_id, tenant_id),
            ).fetchone()
            if not disc:
                raise ValidationError(f"discrepancy {discrepancy_id} not found")
            if disc["status"] != "PENDING_APPROVAL":
                raise ValidationError(f"discrepancy {discrepancy_id} is not pending approval")

            if disc["maker_id"] == checker_id:
                raise ValidationError("maker and checker cannot be the same individual under four-eyes separation of duties")

            new_status = "RESOLVED" if disc["proposed_action"] != "WRITE_OFF" else "WRITTEN_OFF"
            conn.execute(
                """
                UPDATE recon_discrepancy_journal
                SET status = ?, checker_id = ?, resolved_at = ?
                WHERE discrepancy_id = ?
                """,
                (new_status, checker_id, now_iso, discrepancy_id),
            )

        return {
            "discrepancy_id": discrepancy_id,
            "status": new_status,
            "action": disc["proposed_action"],
            "maker_id": disc["maker_id"],
            "checker_id": checker_id,
            "resolved_at": now_iso,
        }
