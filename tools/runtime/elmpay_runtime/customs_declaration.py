"""Cross-border ecommerce customs payment declaration engine (GACC Order 179 compliance)."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping
import uuid
import xml.sax.saxutils

from .common import ValidationError, require_text
from .durable import DurableStore


def _current(now: datetime | None = None) -> datetime:
    return now or datetime.now(timezone.utc)


def _compute_customs_digest(payload: Mapping[str, Any]) -> str:
    canonical = {
        "customsCode": str(payload.get("customsCode", "")),
        "ebpCode": str(payload.get("ebpCode", "")),
        "ebcCode": str(payload.get("ebcCode", "")),
        "orderNo": str(payload.get("orderNo", "")),
        "paymentIntentId": str(payload.get("paymentIntentId", "")),
        "payerName": str(payload.get("payerName", "")),
        "payerIdNumber": str(payload.get("payerIdNumber", "")),
        "amountMinor": int(payload.get("amountMinor", 0)),
        "currency": str(payload.get("currency", "142")),
        "declaredAt": str(payload.get("declaredAt", "")),
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()


def render_customs_179_xml(decl: Mapping[str, Any]) -> str:
    """Render China Customs GACC Order 179 CEB311Message XML packet for payment declaration."""
    guid = str(uuid.uuid4())
    app_time = str(decl.get("declaredAt", ""))
    amount_yuan = f"{int(decl.get('amountMinor', 0)) / 100:.2f}"

    def _x(tag: str, val: Any) -> str:
        esc = xml.sax.saxutils.escape(str(val))
        return f"<{tag}>{esc}</{tag}>"

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<CEB311Message xmlns="http://www.chinaport.gov.cn/ceb" version="1.0">
  <Payment>
    <PaymentHead>
      {_x("guid", guid)}
      {_x("appType", "1")}
      {_x("appTime", app_time)}
      {_x("appStatus", "2")}
      {_x("customsCode", decl.get("customsCode", ""))}
      {_x("ebpCode", decl.get("ebpCode", ""))}
      {_x("ebcCode", decl.get("ebcCode", ""))}
      {_x("orderNo", decl.get("orderNo", ""))}
      {_x("payTransactionId", decl.get("paymentIntentId", ""))}
      {_x("amountPaid", amount_yuan)}
      {_x("currency", decl.get("currency", "142"))}
      {_x("payerName", decl.get("payerName", ""))}
      {_x("payerDocumentType", decl.get("payerIdType", "1"))}
      {_x("payerIdNumber", decl.get("payerIdNumber", ""))}
      {_x("payerTelephone", decl.get("payerPhone", ""))}
    </PaymentHead>
  </Payment>
  <SignatureInfo>
    <DigestMethod>SHA-256</DigestMethod>
    {_x("DigestValue", decl.get("signatureDigest", ""))}
  </SignatureInfo>
</CEB311Message>
""".strip()


class CustomsPaymentDeclarationManager:
    """Manages cross-border e-commerce payment declarations to China Customs (GACC)."""

    def __init__(self, store_or_db: DurableStore | Path | str) -> None:
        if isinstance(store_or_db, DurableStore):
            self.store = store_or_db
        else:
            self.store = DurableStore(Path(store_or_db))

    def declare_payment(
        self,
        tenant_id: str,
        *,
        customs_code: str,
        ebp_code: str,
        ebc_code: str,
        order_no: str,
        payment_intent_id: str,
        payer_name: str,
        payer_id_number: str,
        payer_phone: str,
        amount_minor: int,
        currency: str = "142",
        payer_id_type: str = "1",
        declaration_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Declare a retail import payment to China Customs (GACC) with real-name verification."""
        require_text(tenant_id, "tenant_id")
        require_text(customs_code, "customs_code")
        require_text(ebp_code, "ebp_code")
        require_text(ebc_code, "ebc_code")
        require_text(order_no, "order_no")
        require_text(payment_intent_id, "payment_intent_id")
        require_text(payer_name, "payer_name")
        require_text(payer_id_number, "payer_id_number")
        require_text(payer_phone, "payer_phone")

        if not isinstance(amount_minor, int) or amount_minor <= 0:
            raise ValidationError("amount_minor must be a positive integer in minor units")

        if len(payer_id_number) not in (15, 18):
            raise ValidationError("payer_id_number must be a valid 18-digit citizen ID number")

        decl_id = declaration_id or f"DECL_{uuid.uuid4().hex[:12]}"
        now_dt = _current(now)
        now_iso = now_dt.isoformat()

        payload = {
            "customsCode": customs_code,
            "ebpCode": ebp_code,
            "ebcCode": ebc_code,
            "orderNo": order_no,
            "paymentIntentId": payment_intent_id,
            "payerName": payer_name,
            "payerIdNumber": payer_id_number,
            "amountMinor": amount_minor,
            "currency": currency,
            "declaredAt": now_iso,
        }
        digest = _compute_customs_digest(payload)

        with self.store.transaction() as conn:
            existing = conn.execute(
                "SELECT declaration_id FROM customs_payment_declaration "
                "WHERE tenant_id=? AND (declaration_id=? OR (order_no=? AND payment_intent_id=?))",
                (tenant_id, decl_id, order_no, payment_intent_id),
            ).fetchone()
            if existing:
                raise ValidationError(
                    f"payment declaration for order '{order_no}' and payment '{payment_intent_id}' already exists"
                )

            conn.execute(
                "INSERT INTO customs_payment_declaration("
                "declaration_id, tenant_id, customs_code, ebp_code, ebc_code, "
                "order_no, payment_intent_id, payer_name, payer_id_type, payer_id_number, "
                "payer_phone, currency, amount_minor, status, signature_digest, declared_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'REPORTED', ?, ?, ?)",
                (
                    decl_id,
                    tenant_id,
                    customs_code,
                    ebp_code,
                    ebc_code,
                    order_no,
                    payment_intent_id,
                    payer_name,
                    payer_id_type,
                    payer_id_number,
                    payer_phone,
                    currency,
                    amount_minor,
                    digest,
                    now_iso,
                    now_iso,
                ),
            )

            xml_content = render_customs_179_xml({**payload, "payerIdType": payer_id_type, "payerPhone": payer_phone, "signatureDigest": digest})
            log_id = f"CLOG_{uuid.uuid4().hex[:12]}"
            conn.execute(
                "INSERT INTO customs_declaration_log("
                "log_id, declaration_id, action, request_payload, status, created_at) "
                "VALUES (?, ?, 'CUSTOMS_SUBMISSION', ?, 'SENT', ?)",
                (log_id, decl_id, xml_content, now_iso),
            )

        return self.get_declaration(tenant_id, decl_id)

    def acknowledge_receipt(
        self,
        tenant_id: str,
        declaration_id: str,
        *,
        status: str,
        receipt_code: str | None = None,
        receipt_message: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Acknowledge China Customs declaration receipt (CUSTOMS_ACCEPTED or CUSTOMS_REJECTED)."""
        require_text(tenant_id, "tenant_id")
        require_text(declaration_id, "declaration_id")

        valid_statuses = {"CUSTOMS_ACCEPTED", "CUSTOMS_REJECTED"}
        if status not in valid_statuses:
            raise ValidationError(f"invalid receipt status '{status}', must be one of {sorted(valid_statuses)}")

        now_dt = _current(now)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM customs_payment_declaration WHERE tenant_id=? AND declaration_id=?",
                (tenant_id, declaration_id),
            ).fetchone()
            if not row:
                raise ValidationError(f"declaration '{declaration_id}' not found")

            conn.execute(
                "UPDATE customs_payment_declaration "
                "SET status=?, customs_receipt_code=?, customs_receipt_message=?, updated_at=? "
                "WHERE declaration_id=?",
                (status, receipt_code or ("0" if status == "CUSTOMS_ACCEPTED" else "1"), receipt_message or status, now_iso, declaration_id),
            )

            log_id = f"CLOG_{uuid.uuid4().hex[:12]}"
            conn.execute(
                "INSERT INTO customs_declaration_log("
                "log_id, declaration_id, action, request_payload, response_payload, status, created_at) "
                "VALUES (?, ?, 'CUSTOMS_RECEIPT_CALLBACK', ?, ?, ?, ?)",
                (
                    log_id,
                    declaration_id,
                    json.dumps({"receiptCode": receipt_code, "status": status}),
                    receipt_message or status,
                    status,
                    now_iso,
                ),
            )

        return self.get_declaration(tenant_id, declaration_id)

    def get_declaration(self, tenant_id: str, decl_id_or_order_no: str) -> dict[str, Any]:
        """Retrieve declaration state, raw XML, and audit dispatch logs."""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM customs_payment_declaration "
                "WHERE tenant_id=? AND (declaration_id=? OR order_no=?)",
                (tenant_id, decl_id_or_order_no, decl_id_or_order_no),
            ).fetchone()
            if not row:
                raise ValidationError(f"customs declaration '{decl_id_or_order_no}' not found")

            decl_id = row["declaration_id"]
            logs = conn.execute(
                "SELECT * FROM customs_declaration_log WHERE declaration_id=? ORDER BY created_at ASC",
                (decl_id,),
            ).fetchall()

            decl_dict = {
                "declarationId": row["declaration_id"],
                "tenantId": row["tenant_id"],
                "customsCode": row["customs_code"],
                "ebpCode": row["ebp_code"],
                "ebcCode": row["ebc_code"],
                "orderNo": row["order_no"],
                "paymentIntentId": row["payment_intent_id"],
                "payerName": row["payer_name"],
                "payerIdType": row["payer_id_type"],
                "payerIdNumber": row["payer_id_number"],
                "payerPhone": row["payer_phone"],
                "currency": row["currency"],
                "amountMinor": row["amount_minor"],
                "status": row["status"],
                "customsReceiptCode": row["customs_receipt_code"],
                "customsReceiptMessage": row["customs_receipt_message"],
                "signatureDigest": row["signature_digest"],
                "declaredAt": row["declared_at"],
                "updatedAt": row["updated_at"],
            }

            expected_digest = _compute_customs_digest(decl_dict)
            decl_dict["integrityValid"] = row["signature_digest"] == expected_digest
            decl_dict["xmlPayload"] = render_customs_179_xml(decl_dict)
            decl_dict["logs"] = [
                {
                    "logId": l["log_id"],
                    "action": l["action"],
                    "requestPayload": l["request_payload"],
                    "responsePayload": l["response_payload"],
                    "status": l["status"],
                    "createdAt": l["created_at"],
                }
                for l in logs
            ]
            return decl_dict
