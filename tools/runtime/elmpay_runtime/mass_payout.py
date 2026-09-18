# tools/runtime/elmpay_runtime/mass_payout.py
from __future__ import annotations

import csv
import datetime
import hashlib
import io
import json
import uuid
import xml.sax.saxutils as saxutils
from typing import Any, Dict, List, Optional

from .common import ValidationError
from .durable import DurableStore

SUPPORTED_CHANNELS = {"BANK_WIRE", "ALIPAY", "WECHAT_PAY", "PAYPAL", "SEPA"}


def _compute_batch_digest(tenant_id: str, batch_name: str, currency: str, items: List[Dict[str, Any]]) -> str:
    canonical = {
        "tenant_id": tenant_id,
        "batch_name": batch_name,
        "currency": currency,
        "items": [
            {
                "recipient_id": item["recipient_id"],
                "channel": item["channel"],
                "account": item["account_identifier"],
                "amount": item["amount_minor"],
            }
            for item in sorted(items, key=lambda x: str(x.get("recipient_id", "")))
        ],
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class MassPayoutManager:
    """Manages enterprise bulk payouts, maker-checker authorization, item-level execution, and ISO 20022 XML dispatch."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def create_batch(
        self,
        tenant_id: str,
        batch_name: str,
        currency: str,
        maker_id: str,
        items: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Creates a mass payout batch and line items in SUBMITTED state awaiting checker approval."""
        if not items:
            raise ValidationError("mass payout batch must contain at least one item")
        currency = currency.strip().upper()
        if len(currency) != 3:
            raise ValidationError("currency must be a 3-letter ISO code")

        total_amount_minor = 0
        total_fee_minor = 0
        validated_items: List[Dict[str, Any]] = []

        for idx, item in enumerate(items, 1):
            amount = int(item.get("amount_minor", 0))
            if amount <= 0:
                raise ValidationError(f"item #{idx} amount_minor must be strictly positive")
            channel = str(item.get("channel", "")).strip().upper()
            if channel not in SUPPORTED_CHANNELS:
                raise ValidationError(f"item #{idx} channel '{channel}' not supported ({list(SUPPORTED_CHANNELS)})")
            recipient_id = str(item.get("recipient_id", "")).strip()
            recipient_name = str(item.get("recipient_name", "")).strip()
            account_id = str(item.get("account_identifier", "")).strip()
            if not recipient_id or not recipient_name or not account_id:
                raise ValidationError(f"item #{idx} missing required recipient or account identifier")

            fee = int(item.get("fee_minor", 0))
            total_amount_minor += amount
            total_fee_minor += fee

            validated_items.append({
                "item_id": f"poi_{uuid.uuid4().hex[:12]}",
                "recipient_id": recipient_id,
                "recipient_name": recipient_name,
                "channel": channel,
                "account_identifier": account_id,
                "amount_minor": amount,
                "fee_minor": fee,
            })

        batch_id = f"pob_{uuid.uuid4().hex[:12]}"
        digest = _compute_batch_digest(tenant_id, batch_name, currency, validated_items)
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO mass_payout_batch (
                    batch_id, tenant_id, batch_name, currency,
                    total_count, total_amount_minor, total_fee_minor,
                    status, maker_id, batch_digest, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'SUBMITTED', ?, ?, ?, ?)
                """,
                (
                    batch_id, tenant_id, batch_name, currency,
                    len(validated_items), total_amount_minor, total_fee_minor,
                    maker_id, digest, now_iso, now_iso
                ),
            )

            for v in validated_items:
                conn.execute(
                    """
                    INSERT INTO mass_payout_item (
                        item_id, tenant_id, batch_id, recipient_id, recipient_name,
                        channel, account_identifier, amount_minor, fee_minor,
                        status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
                    """,
                    (
                        v["item_id"], tenant_id, batch_id, v["recipient_id"], v["recipient_name"],
                        v["channel"], v["account_identifier"], v["amount_minor"], v["fee_minor"],
                        now_iso
                    ),
                )

        return {
            "batch_id": batch_id,
            "tenant_id": tenant_id,
            "batch_name": batch_name,
            "currency": currency,
            "total_count": len(validated_items),
            "total_amount_minor": total_amount_minor,
            "total_fee_minor": total_fee_minor,
            "status": "SUBMITTED",
            "maker_id": maker_id,
            "batch_digest": digest,
            "created_at": now_iso,
        }

    def approve_batch(self, tenant_id: str, batch_id: str, checker_id: str) -> Dict[str, Any]:
        """Four-eyes principle approval by an independent checker."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            batch = conn.execute(
                "SELECT * FROM mass_payout_batch WHERE batch_id = ? AND tenant_id = ?",
                (batch_id, tenant_id),
            ).fetchone()

            if not batch:
                raise ValidationError(f"payout batch {batch_id} not found")
            if batch["status"] != "SUBMITTED":
                raise ValidationError(f"batch status must be 'SUBMITTED' to approve (current: {batch['status']})")
            if batch["maker_id"] == checker_id:
                raise ValidationError("four-eyes rule violation: maker cannot approve own payout batch")

            conn.execute(
                """
                UPDATE mass_payout_batch
                SET status = 'APPROVED', checker_id = ?, approved_at = ?, updated_at = ?
                WHERE batch_id = ?
                """,
                (checker_id, now_iso, now_iso, batch_id),
            )

        return {
            "batch_id": batch_id,
            "status": "APPROVED",
            "checker_id": checker_id,
            "approved_at": now_iso,
        }

    def execute_batch(
        self,
        tenant_id: str,
        batch_id: str,
        executor_id: str,
        item_outcomes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Dispatches batch to payment channels with item-level success/failure outcomes."""
        item_outcomes = item_outcomes or {}
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            batch = conn.execute(
                "SELECT * FROM mass_payout_batch WHERE batch_id = ? AND tenant_id = ?",
                (batch_id, tenant_id),
            ).fetchone()

            if not batch:
                raise ValidationError(f"payout batch {batch_id} not found")
            if batch["status"] != "APPROVED":
                raise ValidationError(f"batch must be APPROVED to execute (current: {batch['status']})")

            items = conn.execute(
                "SELECT * FROM mass_payout_item WHERE batch_id = ?",
                (batch_id,),
            ).fetchall()

            success_count = 0
            fail_count = 0

            for it in items:
                it_id = it["item_id"]
                outcome = item_outcomes.get(it_id, True)

                if outcome is True or outcome == "SUCCESS":
                    status = "SUCCESS"
                    reason = None
                    ref = f"txn_{uuid.uuid4().hex[:12]}"
                    success_count += 1
                else:
                    status = "FAILED"
                    reason = str(outcome) if isinstance(outcome, str) else "Channel transaction rejected"
                    ref = None
                    fail_count += 1

                conn.execute(
                    """
                    UPDATE mass_payout_item
                    SET status = ?, failure_reason = ?, channel_reference = ?, executed_at = ?
                    WHERE item_id = ?
                    """,
                    (status, reason, ref, now_iso, it_id),
                )

            if fail_count == 0:
                batch_status = "COMPLETED"
            elif success_count == 0:
                batch_status = "REJECTED"
            else:
                batch_status = "PARTIALLY_FAILED"

            conn.execute(
                """
                UPDATE mass_payout_batch
                SET status = ?, updated_at = ?
                WHERE batch_id = ?
                """,
                (batch_status, now_iso, batch_id),
            )

        return {
            "batch_id": batch_id,
            "status": batch_status,
            "total_count": len(items),
            "success_count": success_count,
            "failed_count": fail_count,
            "executed_at": now_iso,
        }

    def export_iso20022_pain001(self, tenant_id: str, batch_id: str) -> str:
        """Generates standard ISO 20022 pain.001.001.03 Customer Credit Transfer XML message."""
        with self.store.transaction() as conn:
            batch = conn.execute(
                "SELECT * FROM mass_payout_batch WHERE batch_id = ? AND tenant_id = ?",
                (batch_id, tenant_id),
            ).fetchone()
            if not batch:
                raise ValidationError(f"payout batch {batch_id} not found")

            items = conn.execute(
                "SELECT * FROM mass_payout_item WHERE batch_id = ?",
                (batch_id,),
            ).fetchall()

        msg_id = f"MSG-{batch['batch_id']}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        ctrl_sum = f"{batch['total_amount_minor'] / 100.0:.2f}"

        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.03">',
            '  <CstmrCdtTrfInitn>',
            '    <GrpHdr>',
            f'      <MsgId>{saxutils.escape(msg_id)}</MsgId>',
            f'      <CreDtTm>{now_iso}</CreDtTm>',
            f'      <NbOfTxs>{batch["total_count"]}</NbOfTxs>',
            f'      <CtrlSum>{ctrl_sum}</CtrlSum>',
            '      <InitgPty>',
            f'        <Nm>{saxutils.escape(tenant_id)}</Nm>',
            '      </InitgPty>',
            '    </GrpHdr>',
            '    <PmtInf>',
            f'      <PmtInfId>PMT-{batch["batch_id"]}</PmtInfId>',
            '      <PmtMtd>TRF</PmtMtd>',
            '      <PmtTpInf>',
            '        <SvcLvl><Cd>SEPA</Cd></SvcLvl>',
            '      </PmtTpInf>',
        ]

        for it in items:
            amt_str = f"{it['amount_minor'] / 100.0:.2f}"
            xml_lines.extend([
                '      <CdtTrfTxInf>',
                '        <PmtId>',
                f'          <EndToEndId>{saxutils.escape(it["item_id"])}</EndToEndId>',
                '        </PmtId>',
                '        <Amt>',
                f'          <InstdAmt Ccy="{batch["currency"]}">{amt_str}</InstdAmt>',
                '        </Amt>',
                '        <Cdtr>',
                f'          <Nm>{saxutils.escape(it["recipient_name"])}</Nm>',
                '        </Cdtr>',
                '        <CdtrAcct>',
                '          <Id>',
                f'            <Othr><Id>{saxutils.escape(it["account_identifier"])}</Id></Othr>',
                '          </Id>',
                '        </CdtrAcct>',
                '      </CdtTrfTxInf>',
            ])

        xml_lines.extend([
            '    </PmtInf>',
            '  </CstmrCdtTrfInitn>',
            '</Document>',
        ])

        return "\n".join(xml_lines)

    def export_payout_csv(self, tenant_id: str, batch_id: str) -> str:
        with self.store.transaction() as conn:
            items = conn.execute(
                "SELECT * FROM mass_payout_item WHERE batch_id = ? AND tenant_id = ?",
                (batch_id, tenant_id),
            ).fetchall()

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "item_id", "batch_id", "recipient_id", "recipient_name",
            "channel", "account_identifier", "amount_minor", "fee_minor",
            "status", "failure_reason", "channel_reference"
        ])
        for it in items:
            writer.writerow([
                it["item_id"], it["batch_id"], it["recipient_id"], it["recipient_name"],
                it["channel"], it["account_identifier"], it["amount_minor"], it["fee_minor"],
                it["status"], it["failure_reason"] or "", it["channel_reference"] or ""
            ])
        return buf.getvalue()

    def get_batch_status(self, tenant_id: str, batch_id: str) -> Dict[str, Any]:
        with self.store.transaction() as conn:
            batch = conn.execute(
                "SELECT * FROM mass_payout_batch WHERE batch_id = ? AND tenant_id = ?",
                (batch_id, tenant_id),
            ).fetchone()
            if not batch:
                raise ValidationError(f"payout batch {batch_id} not found")
            items = conn.execute(
                "SELECT * FROM mass_payout_item WHERE batch_id = ?",
                (batch_id,),
            ).fetchall()
        data = dict(batch)
        data["items"] = [dict(i) for i in items]
        return data
