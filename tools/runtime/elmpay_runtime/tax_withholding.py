"""Enterprise tax withholding, certificate issuance, and Golden Tax IV remittance engine."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
from typing import Any, Mapping, Sequence
import uuid

from .common import ValidationError, require_text
from .durable import DurableStore


def _current(now: datetime | None = None) -> datetime:
    return now or datetime.now(timezone.utc)


def calculate_tax_withholding(
    gross_amount_minor: int,
    income_type: str = "LABOR_SERVICE",
) -> dict[str, int]:
    """Calculate China Individual Income Tax (IIT) / Withholding Tax (WHT) under PRC tax laws.

    All amounts are in integer minor units (cents). Zero floats.
    """
    if not isinstance(gross_amount_minor, int) or gross_amount_minor <= 0:
        raise ValidationError("gross_amount_minor must be a positive integer in minor units")

    valid_types = {"LABOR_SERVICE", "ROYALTY", "PROPERTY_LEASING", "NON_RESIDENT_WHT"}
    if income_type not in valid_types:
        raise ValidationError(f"unsupported income_type '{income_type}', expected one of {sorted(valid_types)}")

    if income_type == "NON_RESIDENT_WHT":
        # Non-resident corporate WHT: statutory 10% withholding without deduction
        deduction = 0
        taxable = gross_amount_minor
        rate_bps = 1000
        quick_ded = 0
        tax = (taxable * rate_bps + 5000) // 10000
        net = gross_amount_minor - tax
        return {
            "grossAmountMinor": gross_amount_minor,
            "statutoryDeductionMinor": deduction,
            "taxableIncomeMinor": taxable,
            "taxRateBasisPoints": rate_bps,
            "quickDeductionMinor": quick_ded,
            "taxWithheldMinor": tax,
            "netPayoutMinor": net,
        }

    # PRC IIT: Labor Services, Royalties, Property Leasing
    # Statutory deduction: 800 RMB if <= 4000 RMB, else 20%
    if gross_amount_minor <= 400000:
        deduction = min(gross_amount_minor, 80000)
    else:
        deduction = (gross_amount_minor * 2000 + 5000) // 10000

    taxable = max(0, gross_amount_minor - deduction)

    if income_type == "LABOR_SERVICE":
        # Progressive withholding brackets for labor services:
        # <= 20,000 RMB (2,000,000 minor): 20%, quick deduction 0
        # 20,000 ~ 50,000 RMB (5,000,000 minor): 30%, quick deduction 2,000 RMB (200,000 minor)
        # > 50,000 RMB: 40%, quick deduction 7,000 RMB (700,000 minor)
        if taxable <= 2000000:
            rate_bps = 2000
            quick_ded = 0
        elif taxable <= 5000000:
            rate_bps = 3000
            quick_ded = 200000
        else:
            rate_bps = 4000
            quick_ded = 700000
    else:
        # Royalty / Property Leasing: flat 20%
        rate_bps = 2000
        quick_ded = 0

    tax = max(0, (taxable * rate_bps + 5000) // 10000 - quick_ded)
    net = gross_amount_minor - tax

    return {
        "grossAmountMinor": gross_amount_minor,
        "statutoryDeductionMinor": deduction,
        "taxableIncomeMinor": taxable,
        "taxRateBasisPoints": rate_bps,
        "quickDeductionMinor": quick_ded,
        "taxWithheldMinor": tax,
        "netPayoutMinor": net,
    }


def compute_certificate_digest(payload: Mapping[str, Any]) -> str:
    canonical = {
        "certificateNumber": str(payload.get("certificateNumber", "")),
        "payeeName": str(payload.get("payeeName", "")),
        "payeeIdNumber": str(payload.get("payeeIdNumber", "")),
        "incomeType": str(payload.get("incomeType", "")),
        "grossAmountMinor": int(payload.get("grossAmountMinor", 0)),
        "taxWithheldMinor": int(payload.get("taxWithheldMinor", 0)),
        "netPayoutMinor": int(payload.get("netPayoutMinor", 0)),
        "issuedAt": str(payload.get("issuedAt", "")),
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()


class TaxWithholdingLedger:
    """Enterprise tax withholding, statutory certificates, and Golden Tax IV bulk filing batches."""

    def __init__(self, store_or_db: DurableStore | Path | str) -> None:
        if isinstance(store_or_db, DurableStore):
            self.store = store_or_db
        else:
            self.store = DurableStore(Path(store_or_db))

    def issue_certificate(
        self,
        tenant_id: str,
        *,
        payee_name: str,
        payee_id_number: str,
        gross_amount_minor: int,
        income_type: str = "LABOR_SERVICE",
        payee_type: str = "INDIVIDUAL",
        payee_id_type: str = "RESIDENT_ID",
        certificate_number: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Calculate withholding, issue statutory certificate, and compute cryptographic digest."""
        require_text(tenant_id, "tenant_id")
        require_text(payee_name, "payee_name")
        require_text(payee_id_number, "payee_id_number")

        calc = calculate_tax_withholding(gross_amount_minor, income_type)
        now_dt = _current(now)
        now_iso = now_dt.isoformat()
        cert_no = certificate_number or f"WHT{now_dt.strftime('%Y%m%d')}{uuid.uuid4().hex[:8].upper()}"
        cert_id = f"CERT_{uuid.uuid4().hex[:12]}"

        cert_payload = {
            "certificateNumber": cert_no,
            "payeeName": payee_name,
            "payeeIdNumber": payee_id_number,
            "incomeType": income_type,
            "grossAmountMinor": calc["grossAmountMinor"],
            "taxWithheldMinor": calc["taxWithheldMinor"],
            "netPayoutMinor": calc["netPayoutMinor"],
            "issuedAt": now_iso,
        }
        digest = compute_certificate_digest(cert_payload)

        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO tax_withholding_certificate("
                "certificate_id, tenant_id, certificate_number, payee_type, payee_name, "
                "payee_id_type, payee_id_number, income_type, gross_amount_minor, "
                "statutory_deduction_minor, taxable_income_minor, tax_rate_basis_points, "
                "quick_deduction_minor, tax_withheld_minor, net_payout_minor, filing_status, "
                "digest, issued_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RECORDED', ?, ?, ?)",
                (
                    cert_id,
                    tenant_id,
                    cert_no,
                    payee_type,
                    payee_name,
                    payee_id_type,
                    payee_id_number,
                    income_type,
                    calc["grossAmountMinor"],
                    calc["statutoryDeductionMinor"],
                    calc["taxableIncomeMinor"],
                    calc["taxRateBasisPoints"],
                    calc["quickDeductionMinor"],
                    calc["taxWithheldMinor"],
                    calc["netPayoutMinor"],
                    digest,
                    now_iso,
                    now_iso,
                ),
            )

        return self.get_certificate(tenant_id, cert_id)

    def get_certificate(self, tenant_id: str, cert_id_or_no: str) -> dict[str, Any]:
        """Retrieve certificate details and verify digest integrity."""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM tax_withholding_certificate "
                "WHERE tenant_id=? AND (certificate_id=? OR certificate_number=?)",
                (tenant_id, cert_id_or_no, cert_id_or_no),
            ).fetchone()
            if not row:
                raise ValidationError(f"certificate '{cert_id_or_no}' not found for tenant '{tenant_id}'")

            data = {
                "certificateId": row["certificate_id"],
                "tenantId": row["tenant_id"],
                "certificateNumber": row["certificate_number"],
                "payeeType": row["payee_type"],
                "payeeName": row["payee_name"],
                "payeeIdType": row["payee_id_type"],
                "payeeIdNumber": row["payee_id_number"],
                "incomeType": row["income_type"],
                "grossAmountMinor": row["gross_amount_minor"],
                "statutoryDeductionMinor": row["statutory_deduction_minor"],
                "taxableIncomeMinor": row["taxable_income_minor"],
                "taxRateBasisPoints": row["tax_rate_basis_points"],
                "quickDeductionMinor": row["quick_deduction_minor"],
                "taxWithheldMinor": row["tax_withheld_minor"],
                "netPayoutMinor": row["net_payout_minor"],
                "filingStatus": row["filing_status"],
                "digest": row["digest"],
                "issuedAt": row["issued_at"],
                "createdAt": row["created_at"],
            }
            expected_digest = compute_certificate_digest(data)
            data["integrityValid"] = row["digest"] == expected_digest
            return data

    def create_remittance_batch(
        self,
        tenant_id: str,
        tax_period: str,
        *,
        certificate_ids: Sequence[str] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Aggregate certificates into a Golden Tax IV remittance batch for tax authority filing."""
        require_text(tenant_id, "tenant_id")
        require_text(tax_period, "tax_period")

        now_dt = _current(now)
        now_iso = now_dt.isoformat()
        batch_id = f"REMIT_{tax_period.replace('-', '')}_{uuid.uuid4().hex[:8]}"

        with self.store.transaction() as conn:
            if certificate_ids:
                placeholders = ",".join(["?"] * len(certificate_ids))
                rows = conn.execute(
                    f"SELECT * FROM tax_withholding_certificate "
                    f"WHERE tenant_id=? AND certificate_id IN ({placeholders})",
                    [tenant_id, *certificate_ids],
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tax_withholding_certificate "
                    "WHERE tenant_id=? AND filing_status='RECORDED'",
                    (tenant_id,),
                ).fetchall()

            if not rows:
                raise ValidationError(f"no recorded withholding certificates found for remittance batch")

            item_count = len(rows)
            total_gross = sum(r["gross_amount_minor"] for r in rows)
            total_withheld = sum(r["tax_withheld_minor"] for r in rows)

            cert_numbers = sorted([r["certificate_number"] for r in rows])
            batch_canonical = {
                "batchId": batch_id,
                "tenantId": tenant_id,
                "taxPeriod": tax_period,
                "itemCount": item_count,
                "totalGrossMinor": total_gross,
                "totalTaxWithheldMinor": total_withheld,
                "certificates": cert_numbers,
            }
            batch_digest = hashlib.sha256(json.dumps(batch_canonical, sort_keys=True).encode("utf-8")).hexdigest()

            conn.execute(
                "INSERT INTO tax_remittance_batch("
                "batch_id, tenant_id, tax_period, item_count, total_gross_minor, "
                "total_tax_withheld_minor, batch_digest, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?)",
                (
                    batch_id,
                    tenant_id,
                    tax_period,
                    item_count,
                    total_gross,
                    total_withheld,
                    batch_digest,
                    now_iso,
                ),
            )

            # Update certificates status to SUBMITTED
            for r in rows:
                conn.execute(
                    "UPDATE tax_withholding_certificate SET filing_status='SUBMITTED' WHERE certificate_id=?",
                    (r["certificate_id"],),
                )

            return {
                "batchId": batch_id,
                "tenantId": tenant_id,
                "taxPeriod": tax_period,
                "itemCount": item_count,
                "totalGrossMinor": total_gross,
                "totalTaxWithheldMinor": total_withheld,
                "batchDigest": batch_digest,
                "status": "PREPARED",
                "createdAt": now_iso,
            }

    def export_golden_tax_csv(self, tenant_id: str, tax_period: str | None = None) -> str:
        """Export Golden Tax IV compliant CSV report for Individual Income Tax (个税全员全额申报)."""
        with self.store.connect() as conn:
            if tax_period:
                rows = conn.execute(
                    "SELECT * FROM tax_withholding_certificate WHERE tenant_id=? ORDER BY issued_at ASC",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tax_withholding_certificate WHERE tenant_id=? ORDER BY issued_at ASC",
                    (tenant_id,),
                ).fetchall()

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "完税凭证号",
                "所得项目",
                "纳税人姓名",
                "证件类型",
                "证件号码",
                "税前收入额(元)",
                "法定减除费用(元)",
                "应纳税所得额(元)",
                "预扣率(%)",
                "速算扣除数(元)",
                "代扣代缴税额(元)",
                "税后实发额(元)",
                "申报状态",
                "开具时间",
                "防伪数字摘要",
            ])

            for r in rows:
                writer.writerow([
                    r["certificate_number"],
                    r["income_type"],
                    r["payee_name"],
                    r["payee_id_type"],
                    r["payee_id_number"],
                    f"{r['gross_amount_minor'] / 100:.2f}",
                    f"{r['statutory_deduction_minor'] / 100:.2f}",
                    f"{r['taxable_income_minor'] / 100:.2f}",
                    f"{r['tax_rate_basis_points'] / 100:.2f}%",
                    f"{r['quick_deduction_minor'] / 100:.2f}",
                    f"{r['tax_withheld_minor'] / 100:.2f}",
                    f"{r['net_payout_minor'] / 100:.2f}",
                    r["filing_status"],
                    r["issued_at"],
                    r["digest"],
                ])

            return output.getvalue()
