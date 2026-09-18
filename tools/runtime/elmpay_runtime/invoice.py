"""Enterprise payment invoicing service, VAT calculation and anti-over-invoicing engine."""
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
    require_list,
    require_mapping,
    require_text,
    sha256_json,
)
from .durable import DurableStore

USCC_REGEX = re.compile(r"^[0-9A-HJ-NPQRTUWXY]{2}[0-9]{6}[0-9A-HJ-NPQRTUWXY]{10}$")
TAX_NUMBER_REGEX = re.compile(r"^[0-9A-Z]{15,20}$")


def _current(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValidationError("invoice control time must be timezone-aware")
    return current.astimezone(timezone.utc)


def _instant(value: datetime | None = None) -> str:
    return _current(value).isoformat()


@dataclass(frozen=True)
class CalculatedLine:
    item_name: str
    specification: str
    unit: str
    quantity: int
    unit_price_minor: int
    amount_minor: int
    tax_rate_basis_points: int
    tax_amount_minor: int


@dataclass(frozen=True)
class VatBreakdown:
    lines: tuple[CalculatedLine, ...]
    untaxed_amount_minor: int
    tax_amount_minor: int
    total_amount_minor: int


def calculate_vat_breakdown(items: Sequence[Mapping[str, Any]]) -> VatBreakdown:
    if not items:
        raise ValidationError("invoice items list cannot be empty")

    calculated: list[CalculatedLine] = []
    total_untaxed = 0
    total_tax = 0

    for idx, raw in enumerate(items):
        item = require_mapping(raw, f"item[{idx}]")
        name = require_text(item.get("itemName"), f"item[{idx}].itemName")
        spec = str(item.get("specification") or "")
        unit = str(item.get("unit") or "项")
        qty = item.get("quantity")
        if not isinstance(qty, int) or qty == 0:
            raise ValidationError(f"item[{idx}].quantity must be a non-zero integer")
        unit_price = item.get("unitPriceMinor")
        if not isinstance(unit_price, int) or unit_price < 0:
            raise ValidationError(f"item[{idx}].unitPriceMinor must be a non-negative integer")

        tax_rate_bp = item.get("taxRateBasisPoints")
        if not isinstance(tax_rate_bp, int) or tax_rate_bp < 0 or tax_rate_bp > 10000:
            raise ValidationError(f"item[{idx}].taxRateBasisPoints must be between 0 and 10000 (0% - 100%)")

        line_amount = qty * unit_price
        # Integer division with half-up / standard fiscal rounding
        line_tax = (line_amount * tax_rate_bp + 5000) // 10000 if line_amount >= 0 else -((-line_amount * tax_rate_bp + 5000) // 10000)

        total_untaxed += line_amount
        total_tax += line_tax

        calculated.append(
            CalculatedLine(
                item_name=name,
                specification=spec,
                unit=unit,
                quantity=qty,
                unit_price_minor=unit_price,
                amount_minor=line_amount,
                tax_rate_basis_points=tax_rate_bp,
                tax_amount_minor=line_tax,
            )
        )

    return VatBreakdown(
        lines=tuple(calculated),
        untaxed_amount_minor=total_untaxed,
        tax_amount_minor=total_tax,
        total_amount_minor=total_untaxed + total_tax,
    )


def validate_buyer_info(
    buyer_type: str,
    buyer_name: str,
    buyer_tax_number: str | None,
) -> None:
    if buyer_type not in {"enterprise", "individual", "government"}:
        raise ValidationError(f"unsupported buyerType: {buyer_type}")
    if not buyer_name or len(buyer_name.strip()) < 2:
        raise ValidationError("buyerName must be at least 2 characters")

    if buyer_type == "enterprise":
        if not buyer_tax_number:
            raise ValidationError("enterprise buyer requires a valid taxNumber / unified social credit code")
        cleaned_tax = buyer_tax_number.strip().upper()
        if not (USCC_REGEX.match(cleaned_tax) or TAX_NUMBER_REGEX.match(cleaned_tax)):
            raise ValidationError(f"invalid enterprise taxNumber format: {buyer_tax_number}")


def generate_verification_code(invoice_id: str, tenant_id: str, total_minor: int) -> str:
    """Generate deterministic 20-digit electronic invoice verification code."""
    data = f"{invoice_id}:{tenant_id}:{total_minor}:elmpay-tax-fiscal".encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    # Convert hex digest prefix to 20-digit numerical code
    number = int(digest[:16], 16) % 10**20
    return f"{number:020d}"


class CustomerInvoiceLedger:
    """Enterprise payment customer invoice lifecycle and audit ledger."""

    def __init__(self, database: str | DurableStore) -> None:
        if isinstance(database, DurableStore):
            self.store = database
        else:
            self.store = DurableStore(database)

    def _append_audit(
        self,
        connection: Any,
        *,
        tenant_id: str,
        invoice_id: str,
        event_type: str,
        actor_id: str,
        payload: Mapping[str, Any],
        occurred_at: datetime,
    ) -> str:
        safe_payload = dict(require_mapping(dict(payload), "invoice audit payload"))
        payload_digest = sha256_json(safe_payload)
        previous = connection.execute(
            "SELECT event_digest FROM customer_invoice_audit WHERE tenant_id=? "
            "ORDER BY audit_id DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        previous_digest = previous["event_digest"] if previous else None

        body = {
            "tenantId": tenant_id,
            "invoiceId": invoice_id,
            "eventType": event_type,
            "actorId": actor_id,
            "occurredAt": occurred_at.astimezone(timezone.utc).isoformat(),
            "payloadDigest": payload_digest,
            "previousDigest": previous_digest,
        }
        event_digest = sha256_json(body)
        connection.execute(
            "INSERT INTO customer_invoice_audit(tenant_id, invoice_id, event_type, actor_id, "
            "occurred_at, payload_digest, previous_digest, event_digest, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                invoice_id,
                event_type,
                actor_id,
                body["occurredAt"],
                payload_digest,
                previous_digest,
                event_digest,
                canonical_json(safe_payload).decode("utf-8"),
            ),
        )
        return event_digest

    def calculate_invoicable_balance(
        self,
        tenant_id: str,
        payment_intent_id: str,
        captured_amount_minor: int,
        refunded_amount_minor: int,
        connection: Any = None,
    ) -> int:
        """Calculate the remaining eligible amount that can be invoiced for this payment intent."""
        if captured_amount_minor < 0 or refunded_amount_minor < 0:
            raise ValidationError("amounts must be non-negative")
        net_paid = captured_amount_minor - refunded_amount_minor
        if net_paid <= 0:
            return 0

        query = (
            "SELECT invoice_category, total_amount_minor FROM customer_invoice "
            "WHERE tenant_id=? AND payment_intent_id=? AND status IN ('APPLIED', 'ISSUED', 'RED_NOTED')"
        )
        if connection is not None:
            rows = connection.execute(query, (tenant_id, payment_intent_id)).fetchall()
        else:
            with self.store.connect() as conn:
                rows = conn.execute(query, (tenant_id, payment_intent_id)).fetchall()

        # Blue invoices are positive, red invoices are negative.
        # When a blue invoice is fully red-noted, status is RED_NOTED and offset by the red invoice (-).
        invoiced_net = sum(r["total_amount_minor"] for r in rows)
        return max(0, net_paid - invoiced_net)

    def apply_invoice(
        self,
        *,
        tenant_id: str,
        project_id: str,
        payment_intent_id: str,
        captured_amount_minor: int,
        refunded_amount_minor: int,
        invoice_type: str,
        buyer_type: str,
        buyer_name: str,
        buyer_tax_number: str | None = None,
        buyer_address_phone: str | None = None,
        buyer_bank_account: str | None = None,
        recipient_email: str | None = None,
        recipient_phone: str | None = None,
        seller_name: str,
        seller_tax_number: str,
        seller_address_phone: str | None = None,
        seller_bank_account: str | None = None,
        operator: str,
        items: Sequence[Mapping[str, Any]],
        idempotency_key: str | None = None,
        currency: str = "CNY",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Apply for an invoice with strict validation, idempotency, and anti-over-invoicing."""
        require_text(tenant_id, "tenant_id")
        require_text(project_id, "project_id")
        require_text(payment_intent_id, "payment_intent_id")
        require_text(seller_name, "seller_name")
        require_text(seller_tax_number, "seller_tax_number")
        require_text(operator, "operator")

        if not currency or len(currency) != 3 or not currency.isupper():
            raise ValidationError(f"invalid currency code: {currency}")

        if invoice_type not in {"vat_electronic_normal", "vat_electronic_special", "commercial_receipt"}:
            raise ValidationError(f"unsupported invoice_type: {invoice_type}")

        validate_buyer_info(buyer_type, buyer_name, buyer_tax_number)

        breakdown = calculate_vat_breakdown(items)
        if breakdown.total_amount_minor <= 0:
            raise ValidationError("blue invoice total amount must be strictly positive")

        current_time = _current(now)
        current_iso = current_time.isoformat()

        # Build stable request payload digest for strict idempotency
        payload_digest = None
        if idempotency_key:
            payload_body = {
                "tenantId": tenant_id,
                "projectId": project_id,
                "paymentIntentId": payment_intent_id,
                "invoiceType": invoice_type,
                "buyerType": buyer_type,
                "buyerName": buyer_name,
                "buyerTaxNumber": buyer_tax_number,
                "currency": currency,
                "items": [
                    {
                        "itemName": line.item_name,
                        "quantity": line.quantity,
                        "unitPriceMinor": line.unit_price_minor,
                        "taxRateBasisPoints": line.tax_rate_basis_points,
                    }
                    for line in breakdown.lines
                ],
            }
            payload_digest = sha256_json(payload_body)

        with self.store.transaction() as conn:
            # Check idempotency
            if idempotency_key:
                existing = conn.execute(
                    "SELECT invoice_id, idempotency_payload_digest FROM customer_invoice WHERE tenant_id=? AND idempotency_key=?",
                    (tenant_id, idempotency_key),
                ).fetchone()
                if existing:
                    stored_digest = existing["idempotency_payload_digest"]
                    if stored_digest and stored_digest != payload_digest:
                        raise ValidationError(
                            f"idempotency_key_reuse: request payload conflict for key '{idempotency_key}'"
                        )
                    return self._load_invoice_detail(conn, existing["invoice_id"])

            # Verify invoicable balance inside active transaction connection
            invoicable = self.calculate_invoicable_balance(
                tenant_id,
                payment_intent_id,
                captured_amount_minor,
                refunded_amount_minor,
                connection=conn,
            )
            if breakdown.total_amount_minor > invoicable:
                raise ValidationError(
                    f"requested invoice amount ({breakdown.total_amount_minor}) exceeds invoicable balance ({invoicable})"
                )

            invoice_id = str(uuid.uuid4())
            date_prefix = current_time.strftime("%Y%m%d")
            rand_suffix = invoice_id.replace("-", "")[:8].upper()
            invoice_number = f"INV-{date_prefix}-{rand_suffix}"
            invoice_code = f"0{current_time.year % 100}{rand_suffix[:6]}"

            conn.execute(
                "INSERT INTO customer_invoice("
                "invoice_id, tenant_id, project_id, payment_intent_id, invoice_number, invoice_code, "
                "invoice_type, invoice_category, status, currency, untaxed_amount_minor, tax_amount_minor, "
                "total_amount_minor, buyer_type, buyer_name, buyer_tax_number, buyer_address_phone, "
                "buyer_bank_account, recipient_email, recipient_phone, seller_name, seller_tax_number, "
                "seller_address_phone, seller_bank_account, operator, idempotency_key, idempotency_payload_digest, "
                "created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'blue', 'APPLIED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    invoice_id,
                    tenant_id,
                    project_id,
                    payment_intent_id,
                    invoice_number,
                    invoice_code,
                    invoice_type,
                    currency,
                    breakdown.untaxed_amount_minor,
                    breakdown.tax_amount_minor,
                    breakdown.total_amount_minor,
                    buyer_type,
                    buyer_name,
                    buyer_tax_number,
                    buyer_address_phone,
                    buyer_bank_account,
                    recipient_email,
                    recipient_phone,
                    seller_name,
                    seller_tax_number,
                    seller_address_phone,
                    seller_bank_account,
                    operator,
                    idempotency_key,
                    payload_digest,
                    current_iso,
                    current_iso,
                ),
            )

            for line in breakdown.lines:
                conn.execute(
                    "INSERT INTO customer_invoice_item("
                    "item_id, invoice_id, item_name, specification, unit, quantity, "
                    "unit_price_minor, amount_minor, tax_rate_basis_points, tax_amount_minor) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        invoice_id,
                        line.item_name,
                        line.specification,
                        line.unit,
                        line.quantity,
                        line.unit_price_minor,
                        line.amount_minor,
                        line.tax_rate_basis_points,
                        line.tax_amount_minor,
                    ),
                )

            self._append_audit(
                conn,
                tenant_id=tenant_id,
                invoice_id=invoice_id,
                event_type="INVOICE_APPLIED",
                actor_id=operator,
                payload={
                    "invoiceId": invoice_id,
                    "paymentIntentId": payment_intent_id,
                    "totalMinor": breakdown.total_amount_minor,
                    "buyerName": buyer_name,
                },
                occurred_at=current_time,
            )

            return self._load_invoice_detail(conn, invoice_id)

    def issue_invoice(
        self,
        tenant_id: str,
        invoice_id: str,
        *,
        actor: str,
        checker: str | None = None,
        payee: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Approve and formally issue an applied invoice with tax authority verification code."""
        current_time = _current(now)
        current_iso = current_time.isoformat()

        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM customer_invoice WHERE tenant_id=? AND invoice_id=?",
                (tenant_id, invoice_id),
            ).fetchone()
            if not row:
                raise ValidationError(f"invoice not found: {invoice_id}")
            if row["status"] == "ISSUED":
                return self._load_invoice_detail(conn, invoice_id)
            if row["status"] != "APPLIED":
                raise ValidationError(f"cannot issue invoice in status: {row['status']}")

            v_code = generate_verification_code(invoice_id, tenant_id, row["total_amount_minor"])
            download_url = f"/v1/invoices/{invoice_id}/download?token={v_code[:8]}"

            conn.execute(
                "UPDATE customer_invoice SET status='ISSUED', issued_at=?, checker=?, payee=?, "
                "verification_code=?, download_url=?, updated_at=? WHERE tenant_id=? AND invoice_id=?",
                (
                    current_iso,
                    checker or actor,
                    payee or row["seller_name"],
                    v_code,
                    download_url,
                    current_iso,
                    tenant_id,
                    invoice_id,
                ),
            )

            self._append_audit(
                conn,
                tenant_id=tenant_id,
                invoice_id=invoice_id,
                event_type="INVOICE_ISSUED",
                actor_id=actor,
                payload={
                    "invoiceId": invoice_id,
                    "issuedAt": current_iso,
                    "verificationCode": v_code,
                    "totalMinor": row["total_amount_minor"],
                },
                occurred_at=current_time,
            )

            return self._load_invoice_detail(conn, invoice_id)

    def reject_invoice(
        self,
        tenant_id: str,
        invoice_id: str,
        *,
        reason: str,
        checker: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Reject an applied invoice during financial review."""
        require_text(reason, "reason")
        require_text(checker, "checker")
        current_time = _current(now)
        current_iso = current_time.isoformat()

        with self.store.transaction() as conn:
            inv = conn.execute(
                "SELECT * FROM customer_invoice WHERE tenant_id=? AND invoice_id=?",
                (tenant_id, invoice_id),
            ).fetchone()
            if not inv:
                raise ValidationError(f"invoice not found: {invoice_id}")
            if inv["status"] == "REJECTED":
                return self._load_invoice_detail(conn, invoice_id)
            if inv["status"] != "APPLIED":
                raise ValidationError(f"cannot reject invoice in status: {inv['status']}")

            conn.execute(
                "UPDATE customer_invoice SET status='REJECTED', checker=?, voided_at=?, updated_at=? "
                "WHERE tenant_id=? AND invoice_id=?",
                (checker, current_iso, current_iso, tenant_id, invoice_id),
            )

            self._append_audit(
                conn,
                tenant_id=tenant_id,
                invoice_id=invoice_id,
                event_type="INVOICE_REJECTED",
                actor_id=checker,
                payload={"invoiceId": invoice_id, "reason": reason, "rejectedAt": current_iso},
                occurred_at=current_time,
            )

            return self._load_invoice_detail(conn, invoice_id)

    def issue_red_note(
        self,
        tenant_id: str,
        original_invoice_id: str,
        *,
        reason: str,
        operator: str,
        red_amount_minor: int | None = None,
        idempotency_key: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Issue a Red-letter (credit note) invoice to reverse or adjust an issued blue invoice."""
        require_text(reason, "reason")
        require_text(operator, "operator")
        current_time = _current(now)
        current_iso = current_time.isoformat()

        with self.store.transaction() as conn:
            orig = conn.execute(
                "SELECT * FROM customer_invoice WHERE tenant_id=? AND invoice_id=?",
                (tenant_id, original_invoice_id),
            ).fetchone()
            if not orig:
                raise ValidationError(f"original blue invoice not found: {original_invoice_id}")
            if orig["status"] != "ISSUED":
                raise ValidationError(f"cannot red-note invoice in status: {orig['status']}")
            if orig["invoice_category"] != "blue":
                raise ValidationError("cannot red-note an invoice that is not a blue invoice")

            # Check existing red notes for idempotency
            if idempotency_key:
                existing = conn.execute(
                    "SELECT invoice_id FROM customer_invoice WHERE tenant_id=? AND idempotency_key=?",
                    (tenant_id, idempotency_key),
                ).fetchone()
                if existing:
                    return self._load_invoice_detail(conn, existing["invoice_id"])

            orig_items = conn.execute(
                "SELECT * FROM customer_invoice_item WHERE invoice_id=?",
                (original_invoice_id,),
            ).fetchall()

            # Check already red-noted amount
            existing_reds = conn.execute(
                "SELECT total_amount_minor FROM customer_invoice "
                "WHERE tenant_id=? AND original_invoice_id=? AND status='ISSUED'",
                (tenant_id, original_invoice_id),
            ).fetchall()
            already_reversed = sum(-r["total_amount_minor"] for r in existing_reds)
            remaining_reversable = orig["total_amount_minor"] - already_reversed

            if remaining_reversable <= 0:
                raise ValidationError("original invoice has already been fully reversed by red notes")

            target_reverse = red_amount_minor if red_amount_minor is not None else remaining_reversable
            if target_reverse <= 0 or target_reverse > remaining_reversable:
                raise ValidationError(
                    f"invalid red amount ({target_reverse}), maximum reversable is {remaining_reversable}"
                )

            # Generate red invoice
            red_invoice_id = str(uuid.uuid4())
            date_prefix = current_time.strftime("%Y%m%d")
            rand_suffix = red_invoice_id.replace("-", "")[:8].upper()
            red_invoice_number = f"RED-{date_prefix}-{rand_suffix}"
            red_invoice_code = f"9{current_time.year % 100}{rand_suffix[:6]}"

            # Proportional calculation for partial reversal or exact negative for full
            if target_reverse == orig["total_amount_minor"]:
                red_untaxed = -orig["untaxed_amount_minor"]
                red_tax = -orig["tax_amount_minor"]
                red_total = -orig["total_amount_minor"]
            else:
                ratio = target_reverse / orig["total_amount_minor"]
                red_untaxed = -round(orig["untaxed_amount_minor"] * ratio)
                red_total = -target_reverse
                red_tax = red_total - red_untaxed

            v_code = generate_verification_code(red_invoice_id, tenant_id, red_total)
            download_url = f"/v1/invoices/{red_invoice_id}/download?token={v_code[:8]}"

            conn.execute(
                "INSERT INTO customer_invoice("
                "invoice_id, tenant_id, project_id, payment_intent_id, invoice_number, invoice_code, "
                "invoice_type, invoice_category, original_invoice_id, status, currency, untaxed_amount_minor, "
                "tax_amount_minor, total_amount_minor, buyer_type, buyer_name, buyer_tax_number, "
                "buyer_address_phone, buyer_bank_account, recipient_email, recipient_phone, seller_name, "
                "seller_tax_number, seller_address_phone, seller_bank_account, operator, idempotency_key, "
                "issued_at, verification_code, download_url, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'red', ?, 'ISSUED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    red_invoice_id,
                    tenant_id,
                    orig["project_id"],
                    orig["payment_intent_id"],
                    red_invoice_number,
                    red_invoice_code,
                    orig["invoice_type"],
                    original_invoice_id,
                    orig["currency"],
                    red_untaxed,
                    red_tax,
                    red_total,
                    orig["buyer_type"],
                    orig["buyer_name"],
                    orig["buyer_tax_number"],
                    orig["buyer_address_phone"],
                    orig["buyer_bank_account"],
                    orig["recipient_email"],
                    orig["recipient_phone"],
                    orig["seller_name"],
                    orig["seller_tax_number"],
                    orig["seller_address_phone"],
                    orig["seller_bank_account"],
                    operator,
                    idempotency_key,
                    current_iso,
                    v_code,
                    download_url,
                    current_iso,
                    current_iso,
                ),
            )

            # Insert negative lines
            for it in orig_items:
                neg_qty = -it["quantity"]
                neg_amt = -it["amount_minor"]
                neg_tax = -it["tax_amount_minor"]
                conn.execute(
                    "INSERT INTO customer_invoice_item("
                    "item_id, invoice_id, item_name, specification, unit, quantity, "
                    "unit_price_minor, amount_minor, tax_rate_basis_points, tax_amount_minor) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        red_invoice_id,
                        f"[冲红] {it['item_name']}",
                        it["specification"],
                        it["unit"],
                        neg_qty,
                        it["unit_price_minor"],
                        neg_amt,
                        it["tax_rate_basis_points"],
                        neg_tax,
                    ),
                )

            # Mark original as RED_NOTED if fully reversed
            if target_reverse == remaining_reversable:
                conn.execute(
                    "UPDATE customer_invoice SET status='RED_NOTED', voided_at=?, updated_at=? "
                    "WHERE tenant_id=? AND invoice_id=?",
                    (current_iso, current_iso, tenant_id, original_invoice_id),
                )

            self._append_audit(
                conn,
                tenant_id=tenant_id,
                invoice_id=red_invoice_id,
                event_type="INVOICE_RED_NOTED",
                actor_id=operator,
                payload={
                    "redInvoiceId": red_invoice_id,
                    "originalInvoiceId": original_invoice_id,
                    "reason": reason,
                    "redAmountMinor": red_total,
                },
                occurred_at=current_time,
            )

            return self._load_invoice_detail(conn, red_invoice_id)

    def void_invoice(
        self,
        tenant_id: str,
        invoice_id: str,
        *,
        reason: str,
        operator: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Void an unfiled or draft/applied invoice."""
        require_text(reason, "reason")
        require_text(operator, "operator")
        current_time = _current(now)
        current_iso = current_time.isoformat()

        with self.store.transaction() as conn:
            inv = conn.execute(
                "SELECT * FROM customer_invoice WHERE tenant_id=? AND invoice_id=?",
                (tenant_id, invoice_id),
            ).fetchone()
            if not inv:
                raise ValidationError(f"invoice not found: {invoice_id}")
            if inv["status"] in {"VOIDED", "REJECTED"}:
                return self._load_invoice_detail(conn, invoice_id)
            if inv["status"] == "RED_NOTED":
                raise ValidationError("cannot void an already red-noted invoice; red-notes already exist")
            if inv["status"] == "ISSUED":
                raise ValidationError("cannot void an issued invoice; please issue a red note (credit note) instead")

            conn.execute(
                "UPDATE customer_invoice SET status='VOIDED', voided_at=?, updated_at=? "
                "WHERE tenant_id=? AND invoice_id=?",
                (current_iso, current_iso, tenant_id, invoice_id),
            )

            self._append_audit(
                conn,
                tenant_id=tenant_id,
                invoice_id=invoice_id,
                event_type="INVOICE_VOIDED",
                actor_id=operator,
                payload={"invoiceId": invoice_id, "reason": reason},
                occurred_at=current_time,
            )

            return self._load_invoice_detail(conn, invoice_id)

    def verify_invoice(
        self,
        tenant_id: str,
        invoice_id: str,
        verification_code: str,
    ) -> dict[str, Any]:
        """Verify an issued invoice's authenticity against the deterministic fiscal code."""
        require_text(tenant_id, "tenant_id")
        require_text(invoice_id, "invoice_id")
        require_text(verification_code, "verification_code")

        with self.store.connect() as conn:
            inv = conn.execute(
                "SELECT * FROM customer_invoice WHERE tenant_id=? AND invoice_id=?",
                (tenant_id, invoice_id),
            ).fetchone()
            if not inv:
                return {"valid": False, "reason": "invoice_not_found"}
            if inv["status"] not in {"ISSUED", "RED_NOTED"}:
                return {"valid": False, "reason": f"invoice_not_issued_status_{inv['status']}"}
            if inv["verification_code"] != verification_code:
                return {"valid": False, "reason": "verification_code_mismatch"}

            return {
                "valid": True,
                "invoiceId": inv["invoice_id"],
                "invoiceNumber": inv["invoice_number"],
                "invoiceCode": inv["invoice_code"],
                "invoiceType": inv["invoice_type"],
                "invoiceCategory": inv["invoice_category"],
                "status": inv["status"],
                "totalAmountMinor": inv["total_amount_minor"],
                "taxAmountMinor": inv["tax_amount_minor"],
                "untaxedAmountMinor": inv["untaxed_amount_minor"],
                "currency": inv["currency"],
                "buyerName": inv["buyer_name"],
                "buyerTaxNumber": inv["buyer_tax_number"],
                "sellerName": inv["seller_name"],
                "sellerTaxNumber": inv["seller_tax_number"],
                "issuedAt": inv["issued_at"],
            }

    def export_invoice_ledger(
        self,
        tenant_id: str,
        *,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        status: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """Export structured VAT invoice ledger for period tax filing and accounting reconciliation."""
        require_text(tenant_id, "tenant_id")
        with self.store.connect() as conn:
            query = "SELECT invoice_id FROM customer_invoice WHERE tenant_id=?"
            params: list[Any] = [tenant_id]
            if status:
                query += " AND status=?"
                params.append(status)
            if start_time:
                query += " AND created_at >= ?"
                params.append(start_time.astimezone(timezone.utc).isoformat())
            if end_time:
                query += " AND created_at <= ?"
                params.append(end_time.astimezone(timezone.utc).isoformat())
            query += " ORDER BY created_at ASC LIMIT ?"
            params.append(min(10000, max(1, limit)))

            rows = conn.execute(query, params).fetchall()
            invoices = [self._load_invoice_detail(conn, r["invoice_id"]) for r in rows]

            total_amount = sum(inv["totalAmountMinor"] for inv in invoices)
            total_tax = sum(inv["taxAmountMinor"] for inv in invoices)
            total_untaxed = sum(inv["untaxedAmountMinor"] for inv in invoices)
            blue_count = sum(1 for inv in invoices if inv["invoiceCategory"] == "blue")
            red_count = sum(1 for inv in invoices if inv["invoiceCategory"] == "red")

            manifest = {
                "tenantId": tenant_id,
                "invoiceCount": len(invoices),
                "totalAmountMinor": total_amount,
                "totalTaxAmountMinor": total_tax,
                "totalUntaxedAmountMinor": total_untaxed,
                "blueCount": blue_count,
                "redCount": red_count,
                "invoices": invoices,
            }
            manifest_digest = sha256_json(manifest)
            return {
                **manifest,
                "manifestDigest": manifest_digest,
                "exportedAt": datetime.now(timezone.utc).isoformat(),
            }

    def get_invoice(self, tenant_id: str, invoice_id: str) -> dict[str, Any] | None:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM customer_invoice WHERE tenant_id=? AND invoice_id=?",
                (tenant_id, invoice_id),
            ).fetchone()
            if not row:
                return None
            return self._load_invoice_detail(conn, invoice_id)

    def list_invoices(
        self,
        tenant_id: str,
        *,
        payment_intent_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        with self.store.connect() as conn:
            query = "SELECT invoice_id FROM customer_invoice WHERE tenant_id=?"
            params: list[Any] = [tenant_id]
            if payment_intent_id:
                query += " AND payment_intent_id=?"
                params.append(payment_intent_id)
            if status:
                query += " AND status=?"
                params.append(status)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(min(100, max(1, limit)))

            rows = conn.execute(query, params).fetchall()
            return [self._load_invoice_detail(conn, r["invoice_id"]) for r in rows]

    # --- Buyer Title Operations ---
    def save_buyer_title(
        self,
        tenant_id: str,
        buyer_type: str,
        buyer_name: str,
        *,
        title_id: str | None = None,
        buyer_tax_number: str | None = None,
        buyer_address_phone: str | None = None,
        buyer_bank_account: str | None = None,
        recipient_email: str | None = None,
        recipient_phone: str | None = None,
        is_default: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        validate_buyer_info(buyer_type, buyer_name, buyer_tax_number)
        current_iso = _instant(now)
        tid = title_id or str(uuid.uuid4())

        with self.store.transaction() as conn:
            if is_default:
                conn.execute(
                    "UPDATE customer_buyer_title SET is_default=0 WHERE tenant_id=?",
                    (tenant_id,),
                )
            conn.execute(
                "INSERT INTO customer_buyer_title("
                "title_id, tenant_id, buyer_type, buyer_name, buyer_tax_number, "
                "buyer_address_phone, buyer_bank_account, recipient_email, recipient_phone, "
                "is_default, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(title_id) DO UPDATE SET "
                "buyer_type=excluded.buyer_type, buyer_name=excluded.buyer_name, "
                "buyer_tax_number=excluded.buyer_tax_number, buyer_address_phone=excluded.buyer_address_phone, "
                "buyer_bank_account=excluded.buyer_bank_account, recipient_email=excluded.recipient_email, "
                "recipient_phone=excluded.recipient_phone, is_default=excluded.is_default, updated_at=excluded.updated_at",
                (
                    tid,
                    tenant_id,
                    buyer_type,
                    buyer_name,
                    buyer_tax_number,
                    buyer_address_phone,
                    buyer_bank_account,
                    recipient_email,
                    recipient_phone,
                    1 if is_default else 0,
                    current_iso,
                    current_iso,
                ),
            )
            return {
                "titleId": tid,
                "tenantId": tenant_id,
                "buyerType": buyer_type,
                "buyerName": buyer_name,
                "buyerTaxNumber": buyer_tax_number,
                "buyerAddressPhone": buyer_address_phone,
                "buyerBankAccount": buyer_bank_account,
                "recipientEmail": recipient_email,
                "recipientPhone": recipient_phone,
                "isDefault": is_default,
            }

    def list_buyer_titles(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM customer_buyer_title WHERE tenant_id=? ORDER BY is_default DESC, created_at DESC",
                (tenant_id,),
            ).fetchall()
            return [
                {
                    "titleId": r["title_id"],
                    "tenantId": r["tenant_id"],
                    "buyerType": r["buyer_type"],
                    "buyerName": r["buyer_name"],
                    "buyerTaxNumber": r["buyer_tax_number"],
                    "buyerAddressPhone": r["buyer_address_phone"],
                    "buyerBankAccount": r["buyer_bank_account"],
                    "recipientEmail": r["recipient_email"],
                    "recipientPhone": r["recipient_phone"],
                    "isDefault": bool(r["is_default"]),
                }
                for r in rows
            ]

    # --- Audit Chain Verification ---
    def verify_invoice_audit_chain(self, tenant_id: str) -> bool:
        """Verify cryptographic append-only integrity of invoice audit events for a tenant."""
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM customer_invoice_audit WHERE tenant_id=? ORDER BY audit_id ASC",
                (tenant_id,),
            ).fetchall()
            expected_prior: str | None = None
            for row in rows:
                if row["previous_digest"] != expected_prior:
                    return False
                try:
                    payload = json.loads(row["payload_json"])
                except Exception:
                    return False
                if sha256_json(payload) != row["payload_digest"]:
                    return False
                body = {
                    "tenantId": row["tenant_id"],
                    "invoiceId": row["invoice_id"],
                    "eventType": row["event_type"],
                    "actorId": row["actor_id"],
                    "occurredAt": row["occurred_at"],
                    "payloadDigest": row["payload_digest"],
                    "previousDigest": row["previous_digest"],
                }
                if sha256_json(body) != row["event_digest"]:
                    return False
                expected_prior = row["event_digest"]
            return True


    @staticmethod
    def _load_invoice_detail(conn: Any, invoice_id: str) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM customer_invoice WHERE invoice_id=?", (invoice_id,)).fetchone()
        if not row:
            raise ValidationError(f"invoice not found: {invoice_id}")
        items = conn.execute(
            "SELECT * FROM customer_invoice_item WHERE invoice_id=?",
            (invoice_id,),
        ).fetchall()

        keys = row.keys() if hasattr(row, "keys") else []
        payload_digest = row["idempotency_payload_digest"] if "idempotency_payload_digest" in keys else None

        return {
            "invoiceId": row["invoice_id"],
            "tenantId": row["tenant_id"],
            "projectId": row["project_id"],
            "paymentIntentId": row["payment_intent_id"],
            "invoiceNumber": row["invoice_number"],
            "invoiceCode": row["invoice_code"],
            "invoiceType": row["invoice_type"],
            "invoiceCategory": row["invoice_category"],
            "originalInvoiceId": row["original_invoice_id"],
            "status": row["status"],
            "currency": row["currency"],
            "untaxedAmountMinor": row["untaxed_amount_minor"],
            "taxAmountMinor": row["tax_amount_minor"],
            "totalAmountMinor": row["total_amount_minor"],
            "buyerType": row["buyer_type"],
            "buyerName": row["buyer_name"],
            "buyerTaxNumber": row["buyer_tax_number"],
            "buyerAddressPhone": row["buyer_address_phone"],
            "buyerBankAccount": row["buyer_bank_account"],
            "recipientEmail": row["recipient_email"],
            "recipientPhone": row["recipient_phone"],
            "sellerName": row["seller_name"],
            "sellerTaxNumber": row["seller_tax_number"],
            "sellerAddressPhone": row["seller_address_phone"],
            "sellerBankAccount": row["seller_bank_account"],
            "operator": row["operator"],
            "checker": row["checker"],
            "payee": row["payee"],
            "issuedAt": row["issued_at"],
            "voidedAt": row["voided_at"],
            "verificationCode": row["verification_code"],
            "downloadUrl": row["download_url"],
            "idempotencyKey": row["idempotency_key"],
            "idempotencyPayloadDigest": payload_digest,
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
            "items": [
                {
                    "itemId": it["item_id"],
                    "itemName": it["item_name"],
                    "specification": it["specification"],
                    "unit": it["unit"],
                    "quantity": it["quantity"],
                    "unitPriceMinor": it["unit_price_minor"],
                    "amountMinor": it["amount_minor"],
                    "taxRateBasisPoints": it["tax_rate_basis_points"],
                    "taxAmountMinor": it["tax_amount_minor"],
                }
                for it in items
            ],
        }
