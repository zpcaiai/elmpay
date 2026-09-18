"""Enterprise payment invoicing service, VAT calculation and anti-over-invoicing engine."""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import re
from typing import Any, Mapping, Sequence
import uuid
import xml.sax.saxutils

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

COMMON_TAX_CLASSIFICATIONS: dict[str, str] = {
    "304020101": "信息技术服务*技术服务",
    "3040201010000000000": "信息技术服务*软件服务",
    "107010101": "计算机软件产品*软件开发",
    "1070101010000000000": "计算机软件产品*基础软件",
    "304020102": "信息系统增值服务*运营维护",
    "3040201020000000000": "信息系统增值服务*运营维护服务",
    "307010100": "企业管理服务*业务咨询",
    "3070101000000000000": "企业管理服务*咨询管理",
    "301010102": "电信与增值电信服务*互联网接入",
    "3010101020000000000": "电信与增值电信服务*互联网接入",
    "601000000": "商业零售*现代商业服务",
    "6010000000000000000": "商业零售*现代商业服务",
}


def validate_tax_classification_code(code: str) -> str:
    """Validate standard China tax classification service code."""
    if not code or not isinstance(code, str):
        raise ValidationError("taxClassificationCode must be a non-empty string")
    cleaned = code.strip()
    if not (cleaned.isdigit() and len(cleaned) in {9, 19}):
        raise ValidationError(f"invalid taxClassificationCode: '{code}', must be 9 or 19 digits")
    return cleaned


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
    tax_classification_code: str = "304020101"


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

        tax_class = str(item.get("taxClassificationCode") or "304020101")
        validate_tax_classification_code(tax_class)

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
                tax_classification_code=tax_class,
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


def amount_minor_to_chinese_uppercase(amount_minor: int) -> str:
    """Convert monetary amount in minor units (cents/fen) to official Chinese legal uppercase."""
    if not isinstance(amount_minor, int):
        raise ValidationError("amount_minor must be an integer")

    if amount_minor == 0:
        return "零元整"

    prefix = "(负)" if amount_minor < 0 else ""
    amount = abs(amount_minor)

    yuan = amount // 100
    jiao = (amount % 100) // 10
    fen = amount % 10

    digits = ["零", "壹", "贰", "叁", "肆", "伍", "陆", "柒", "捌", "玖"]
    big_units = ["", "万", "亿", "兆"]

    def _convert_section(sec: int) -> str:
        if sec == 0:
            return ""
        radices = ["", "拾", "佰", "仟"]
        res = []
        zero_pending = False
        s_str = f"{sec:04d}"
        for i, ch in enumerate(s_str):
            d = int(ch)
            unit = radices[3 - i]
            if d == 0:
                if res:
                    zero_pending = True
            else:
                if zero_pending:
                    res.append("零")
                    zero_pending = False
                res.append(digits[d] + unit)
        return "".join(res)

    yuan_str = ""
    if yuan > 0:
        sections: list[int] = []
        tmp = yuan
        while tmp > 0:
            sections.append(tmp % 10000)
            tmp //= 10000

        parts: list[str] = []
        zero_section_flag = False

        for idx in range(len(sections) - 1, -1, -1):
            sec = sections[idx]
            sec_unit = big_units[idx]
            if sec == 0:
                zero_section_flag = True
            else:
                if zero_section_flag:
                    if parts and not parts[-1].endswith("零"):
                        parts.append("零")
                    zero_section_flag = False
                elif parts and sec < 1000:
                    if not parts[-1].endswith("零"):
                        parts.append("零")

                sec_text = _convert_section(sec)
                parts.append(sec_text + sec_unit)

        yuan_str = "".join(parts) + "元"

    # Fraction part
    frac_str = ""
    if jiao == 0 and fen == 0:
        frac_str = "整"
    elif jiao > 0 and fen == 0:
        frac_str = f"{digits[jiao]}角整"
    elif jiao == 0 and fen > 0:
        if yuan > 0:
            frac_str = f"零{digits[fen]}分"
        else:
            frac_str = f"{digits[fen]}分"
    else:
        frac_str = f"{digits[jiao]}角{digits[fen]}分"

    if not yuan_str and (jiao > 0 or fen > 0):
        return f"{prefix}{frac_str}"

    return f"{prefix}{yuan_str}{frac_str}"


def _escape_html(val: Any) -> str:
    """Escape string for safe embedding into HTML documents."""
    s = str(val if val is not None else "")
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _generate_seal_svg(seller_name: str, tax_number: str) -> str:
    """Generate authentic China electronic tax invoice seal SVG (发票专用章)."""
    display_name = seller_name[:24] if seller_name else "发票销售方"
    clean_tax = tax_number[:18] if tax_number else "000000000000000000"
    return (
        '<svg width="150" height="105" viewBox="0 0 150 105" xmlns="http://www.w3.org/2000/svg" '
        'style="transform: rotate(-6deg); opacity: 0.88;">\\n'
        '  <ellipse cx="75" cy="52.5" rx="70" ry="48" fill="none" stroke="#cf222e" stroke-width="2.5" />\\n'
        '  <ellipse cx="75" cy="52.5" rx="66" ry="44" fill="none" stroke="#cf222e" stroke-width="0.8" stroke-dasharray="2,2" />\\n'
        '  <path id="sealTextPath" d="M 15,55 A 60,38 0 0,1 135,55" fill="none" />\\n'
        '  <text font-size="10" font-weight="bold" fill="#cf222e" text-anchor="middle">\\n'
        f'    <textPath href="#sealTextPath" startOffset="50%">{_escape_html(display_name)}</textPath>\\n'
        '  </text>\\n'
        '  <polygon points="75,37 78,45 86,45 80,50 82,58 75,53 68,58 70,50 64,45 72,45" fill="#cf222e" />\\n'
        '  <text x="75" y="70" font-size="12" font-weight="bold" fill="#cf222e" text-anchor="middle" letter-spacing="2">发票专用章</text>\\n'
        f'  <text x="75" y="85" font-size="8" font-family="monospace" fill="#cf222e" text-anchor="middle">{_escape_html(clean_tax)}</text>\\n'
        '</svg>'
    )


def _generate_qr_svg(invoice_code: str, invoice_number: str, amount_yuan: str, verification_code: str) -> str:
    """Generate clean SVG QR matrix representation for invoice header."""
    return (
        '<svg width="86" height="86" viewBox="0 0 86 86" xmlns="http://www.w3.org/2000/svg">\\n'
        '  <rect width="86" height="86" fill="#ffffff" stroke="#8c3b28" stroke-width="1"/>\\n'
        '  <rect x="6" y="6" width="22" height="22" fill="#8c3b28"/>\\n'
        '  <rect x="10" y="10" width="14" height="14" fill="#ffffff"/>\\n'
        '  <rect x="13" y="13" width="8" height="8" fill="#8c3b28"/>\\n'
        '  <rect x="58" y="6" width="22" height="22" fill="#8c3b28"/>\\n'
        '  <rect x="62" y="10" width="14" height="14" fill="#ffffff"/>\\n'
        '  <rect x="65" y="13" width="8" height="8" fill="#8c3b28"/>\\n'
        '  <rect x="6" y="58" width="22" height="22" fill="#8c3b28"/>\\n'
        '  <rect x="10" y="62" width="14" height="14" fill="#ffffff"/>\\n'
        '  <rect x="13" y="65" width="8" height="8" fill="#8c3b28"/>\\n'
        '  <rect x="35" y="8" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="45" y="14" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="36" y="24" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="48" y="32" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="16" y="36" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="26" y="42" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="36" y="42" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="60" y="36" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="70" y="44" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="38" y="56" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="50" y="64" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="66" y="64" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="40" y="74" width="5" height="5" fill="#8c3b28"/>\\n'
        '  <rect x="72" y="76" width="5" height="5" fill="#8c3b28"/>\\n'
        '</svg>'
    )


def render_invoice_html(invoice_detail: Mapping[str, Any]) -> str:
    """Render authentic, printable China VAT Electronic Invoice HTML document."""
    inv_type = str(invoice_detail.get("invoiceType") or "ELECTRONIC_NORMAL").upper()
    inv_category = str(invoice_detail.get("invoiceCategory") or "BLUE").upper()
    status = str(invoice_detail.get("status") or "ISSUED").upper()

    if inv_category == "RED":
        title = "增值税电子专用发票（红字）" if "SPECIAL" in inv_type else "增值税电子普通发票（红字）"
    elif "SPECIAL" in inv_type:
        title = "增值税电子专用发票"
    else:
        title = "增值税电子普通发票"

    watermark_html = ""
    if status == "VOIDED":
        watermark_html = '<div class="watermark watermark-void">作&nbsp;&nbsp;废</div>'
    elif inv_category == "RED" or status == "RED_NOTED":
        watermark_html = '<div class="watermark watermark-red">红&nbsp;&nbsp;字</div>'

    vc = str(invoice_detail.get("verificationCode") or "")
    formatted_vc = " ".join([vc[i:i+5] for i in range(0, len(vc), 5)]) if len(vc) == 20 else vc

    issued_at = invoice_detail.get("issuedAt") or ""
    date_str = ""
    if issued_at:
        try:
            dt = datetime.fromisoformat(str(issued_at).replace("Z", "+00:00"))
            date_str = f"{dt.year}年{dt.month:02d}月{dt.day:02d}日"
        except Exception:
            date_str = str(issued_at)

    total_minor = int(invoice_detail.get("totalAmountMinor", 0))
    untaxed_minor = int(invoice_detail.get("untaxedAmountMinor", 0))
    tax_minor = int(invoice_detail.get("taxAmountMinor", 0))

    total_yuan = f"{total_minor / 100:.2f}"
    untaxed_yuan = f"{untaxed_minor / 100:.2f}"
    tax_yuan = f"{tax_minor / 100:.2f}"
    chinese_total = amount_minor_to_chinese_uppercase(total_minor)

    seller_name = str(invoice_detail.get("sellerName") or "")
    seller_tax = str(invoice_detail.get("sellerTaxNumber") or "")
    seller_addr_phone = str(invoice_detail.get("sellerAddressPhone") or "")
    seller_bank_acc = str(invoice_detail.get("sellerBankAccount") or "")

    buyer_name = str(invoice_detail.get("buyerName") or "")
    buyer_tax = str(invoice_detail.get("buyerTaxNumber") or "无")
    buyer_addr_phone = str(invoice_detail.get("buyerAddressPhone") or "无")
    buyer_bank_acc = str(invoice_detail.get("buyerBankAccount") or "无")

    inv_code = str(invoice_detail.get("invoiceCode") or "")
    inv_num = str(invoice_detail.get("invoiceNumber") or "")

    qr_svg = _generate_qr_svg(inv_code, inv_num, total_yuan, vc)
    seal_svg = _generate_seal_svg(seller_name, seller_tax)

    seed_hash = hashlib.sha256(f"{inv_code}:{inv_num}:{vc}".encode()).hexdigest()
    pw_lines = [
        seed_hash[0:20].upper(),
        seed_hash[20:40].upper(),
        seed_hash[40:60].upper(),
        seed_hash[60:64].upper() + "A8F9E01B34CD",
    ]
    pw_html = "<br/>".join(pw_lines)

    items = invoice_detail.get("items") or []
    items_rows = []
    for item in items:
        qty = item.get("quantity", 1)
        up_minor = item.get("unitPriceMinor", 0)
        amt_minor = item.get("amountMinor", 0)
        tax_bp = item.get("taxRateBasisPoints", 0)
        tax_amt_minor = item.get("taxAmountMinor", 0)

        tax_rate_str = f"{tax_bp / 100:.0f}%" if tax_bp % 100 == 0 else f"{tax_bp / 100:.2f}%"
        if tax_bp == 0:
            tax_rate_str = "免税"

        items_rows.append(
            f'<tr>'
            f'<td>{_escape_html(str(item.get("itemName") or ""))}</td>'
            f'<td>{_escape_html(str(item.get("specification") or ""))}</td>'
            f'<td style="text-align:center;">{_escape_html(str(item.get("unit") or "项"))}</td>'
            f'<td style="text-align:right;">{qty}</td>'
            f'<td style="text-align:right;">¥{up_minor / 100:.2f}</td>'
            f'<td style="text-align:right;">¥{amt_minor / 100:.2f}</td>'
            f'<td style="text-align:center;">{tax_rate_str}</td>'
            f'<td style="text-align:right;">¥{tax_amt_minor / 100:.2f}</td>'
            f'</tr>'
        )

    while len(items_rows) < 3:
        items_rows.append('<tr><td>&nbsp;</td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>')

    items_body = "\n".join(items_rows)

    remarks = []
    if invoice_detail.get("paymentIntentId"):
        remarks.append(f"关联支付意向: {invoice_detail['paymentIntentId']}")
    if invoice_detail.get("originalInvoiceId"):
        remarks.append(f"对应蓝字发票: {invoice_detail['originalInvoiceId']}")
    remarks_text = "<br/>".join(_escape_html(r) for r in remarks)

    payee = _escape_html(str(invoice_detail.get("payee") or seller_name or ""))
    checker = _escape_html(str(invoice_detail.get("checker") or "系统自动复核"))
    operator = _escape_html(str(invoice_detail.get("operator") or "系统自动开具"))

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>{_escape_html(title)} - {_escape_html(inv_num)}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      background-color: #f8fafc;
      color: #2b2625;
      padding: 24px;
      display: flex;
      justify-content: center;
    }}
    .invoice-card {{
      position: relative;
      width: 920px;
      background: #ffffff;
      border: 2px solid #8c3b28;
      border-radius: 6px;
      padding: 24px 28px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
      overflow: hidden;
    }}
    .watermark {{
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%) rotate(-25deg);
      font-size: 78px;
      font-weight: 800;
      letter-spacing: 20px;
      pointer-events: none;
      z-index: 20;
      opacity: 0.22;
      user-select: none;
    }}
    .watermark-void {{ color: #dc2626; border: 5px dashed #dc2626; padding: 12px 40px; border-radius: 12px; }}
    .watermark-red {{ color: #b91c1c; border: 5px solid #b91c1c; padding: 12px 40px; border-radius: 12px; }}

    .header-grid {{
      display: grid;
      grid-template-columns: 100px 1fr 280px;
      align-items: center;
      margin-bottom: 16px;
    }}
    .title-box {{
      text-align: center;
    }}
    .invoice-title {{
      font-size: 24px;
      font-weight: 700;
      color: #8c3b28;
      letter-spacing: 4px;
      border-bottom: 3px double #8c3b28;
      padding-bottom: 4px;
      display: inline-block;
    }}
    .meta-list {{
      font-size: 12px;
      color: #4b5563;
      line-height: 1.6;
    }}
    .meta-label {{
      color: #8c3b28;
      font-weight: 600;
      display: inline-block;
      width: 68px;
    }}
    .meta-value {{
      font-family: monospace;
      font-weight: 600;
      color: #111827;
    }}

    .grid-table {{
      width: 100%;
      border-collapse: collapse;
      margin-bottom: -1px;
      font-size: 12px;
    }}
    .grid-table td, .grid-table th {{
      border: 1px solid #8c3b28;
      padding: 6px 8px;
      vertical-align: middle;
    }}
    .label-col {{
      width: 24px;
      text-align: center;
      color: #8c3b28;
      font-weight: 600;
      padding: 8px 4px !important;
      line-height: 1.3;
      background-color: #fdfaf8;
    }}
    .field-label {{
      color: #8c3b28;
      font-weight: 600;
      width: 110px;
      display: inline-block;
    }}
    .cipher-text {{
      font-family: monospace;
      font-size: 11px;
      letter-spacing: 1px;
      color: #1e293b;
      line-height: 1.5;
    }}

    .items-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-bottom: -1px;
    }}
    .items-table th {{
      background-color: #fdfaf8;
      color: #8c3b28;
      font-weight: 600;
      text-align: center;
      border: 1px solid #8c3b28;
      padding: 6px 4px;
    }}
    .items-table td {{
      border: 1px solid #8c3b28;
      padding: 5px 6px;
      font-size: 12px;
    }}

    .total-row td {{
      padding: 7px 10px;
      font-size: 12px;
      border: 1px solid #8c3b28;
    }}

    .footer-bar {{
      margin-top: 14px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
      color: #374151;
      position: relative;
    }}
    .footer-seal {{
      position: absolute;
      right: 40px;
      bottom: -20px;
      pointer-events: none;
      z-index: 15;
    }}

    @media print {{
      body {{ background: transparent; padding: 0; }}
      .invoice-card {{ box-shadow: none; border: 2px solid #8c3b28; width: 100%; max-width: 100%; padding: 15px; }}
    }}
  </style>
</head>
<body>
  <div class="invoice-card">
    {watermark_html}
    <div class="header-grid">
      <div>{qr_svg}</div>
      <div class="title-box">
        <h1 class="invoice-title">{_escape_html(title)}</h1>
      </div>
      <div class="meta-list">
        <div><span class="meta-label">发票代码:</span><span class="meta-value">{_escape_html(inv_code)}</span></div>
        <div><span class="meta-label">发票号码:</span><span class="meta-value">{_escape_html(inv_num)}</span></div>
        <div><span class="meta-label">开票日期:</span><span class="meta-value">{date_str}</span></div>
        <div><span class="meta-label">校&nbsp;验&nbsp;码:</span><span class="meta-value">{_escape_html(formatted_vc)}</span></div>
      </div>
    </div>

    <!-- Buyer & Password Area -->
    <table class="grid-table">
      <tr>
        <td class="label-col" rowspan="4">购买方</td>
        <td style="width: 48%;">
          <span class="field-label">名&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;称:</span>{_escape_html(buyer_name)}
        </td>
        <td class="label-col" rowspan="4">密码区</td>
        <td rowspan="4" class="cipher-text" style="width: 44%; vertical-align: middle;">
          {pw_html}
        </td>
      </tr>
      <tr>
        <td><span class="field-label">纳税人识别号:</span><span style="font-family: monospace;">{_escape_html(buyer_tax)}</span></td>
      </tr>
      <tr>
        <td><span class="field-label">地&nbsp;址、电&nbsp;话:</span>{_escape_html(buyer_addr_phone)}</td>
      </tr>
      <tr>
        <td><span class="field-label">开户行及账号:</span>{_escape_html(buyer_bank_acc)}</td>
      </tr>
    </table>

    <!-- Line Items Table -->
    <table class="items-table">
      <thead>
        <tr>
          <th style="width: 32%;">项目名称</th>
          <th style="width: 12%;">规格型号</th>
          <th style="width: 6%;">单位</th>
          <th style="width: 8%;">数量</th>
          <th style="width: 12%;">单价</th>
          <th style="width: 14%;">金额</th>
          <th style="width: 8%;">税率</th>
          <th style="width: 14%;">税额</th>
        </tr>
      </thead>
      <tbody>
        {items_body}
        <!-- Subtotal -->
        <tr>
          <td style="text-align: center; font-weight: bold; color: #8c3b28;">合&nbsp;&nbsp;&nbsp;&nbsp;计</td>
          <td></td>
          <td></td>
          <td></td>
          <td></td>
          <td style="text-align: right; font-weight: bold;">¥{untaxed_yuan}</td>
          <td></td>
          <td style="text-align: right; font-weight: bold;">¥{tax_yuan}</td>
        </tr>
      </tbody>
    </table>

    <!-- Total Row -->
    <table class="grid-table total-row">
      <tr>
        <td style="width: 25%; color: #8c3b28; font-weight: 600;">价税合计（大写）</td>
        <td style="width: 45%; font-weight: bold; font-size: 13px;">{_escape_html(chinese_total)}</td>
        <td style="width: 10%; color: #8c3b28; font-weight: 600;">（小写）</td>
        <td style="width: 20%; font-weight: bold; font-family: monospace; font-size: 14px; text-align: right;">¥{total_yuan}</td>
      </tr>
    </table>

    <!-- Seller & Remarks Area -->
    <table class="grid-table">
      <tr>
        <td class="label-col" rowspan="4">销售方</td>
        <td style="width: 48%;">
          <span class="field-label">名&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;称:</span>{_escape_html(seller_name)}
        </td>
        <td class="label-col" rowspan="4">备<br/>注</td>
        <td rowspan="4" style="width: 44%; vertical-align: top; color: #4b5563; font-size: 11px; line-height: 1.6;">
          {remarks_text}
        </td>
      </tr>
      <tr>
        <td><span class="field-label">纳税人识别号:</span><span style="font-family: monospace;">{_escape_html(seller_tax)}</span></td>
      </tr>
      <tr>
        <td><span class="field-label">地&nbsp;址、电&nbsp;话:</span>{_escape_html(seller_addr_phone)}</td>
      </tr>
      <tr>
        <td><span class="field-label">开户行及账号:</span>{_escape_html(seller_bank_acc)}</td>
      </tr>
    </table>

    <!-- Footer Signatures and Seal -->
    <div class="footer-bar">
      <div><span style="color:#8c3b28; font-weight:600;">收款人:</span> {payee}</div>
      <div><span style="color:#8c3b28; font-weight:600;">复&nbsp;&nbsp;核:</span> {checker}</div>
      <div><span style="color:#8c3b28; font-weight:600;">开票人:</span> {operator}</div>
      <div style="width: 180px; text-align: right;"><span style="color:#8c3b28; font-weight:600;">销售方:</span>（章）</div>
      <div class="footer-seal">
        {seal_svg}
      </div>
    </div>
  </div>
</body>
</html>
"""


def render_golden_tax_xml(invoice_detail: Mapping[str, Any]) -> str:
    """Export China State Taxation Administration Golden Tax / Fully Digitalized E-Invoice XML document."""
    def _xtag(tag: str, val: Any) -> str:
        return f"<{tag}>{xml.sax.saxutils.escape(str(val) if val is not None else '')}</{tag}>"

    total_minor = int(invoice_detail.get("totalAmountMinor", 0))
    untaxed_minor = int(invoice_detail.get("untaxedAmountMinor", 0))
    tax_minor = int(invoice_detail.get("taxAmountMinor", 0))
    chinese_total = amount_minor_to_chinese_uppercase(total_minor)

    items = invoice_detail.get("items") or []
    item_nodes: list[str] = []
    for it in items:
        tax_bp = int(it.get("taxRateBasisPoints", 0))
        pct_str = f"{tax_bp / 100:.0f}%" if tax_bp % 100 == 0 else f"{tax_bp / 100:.2f}%"
        up_minor = int(it.get("unitPriceMinor", 0))
        amt_minor = int(it.get("amountMinor", 0))
        tax_amt_minor = int(it.get("taxAmountMinor", 0))

        item_nodes.append(
            '    <Item id="' + xml.sax.saxutils.escape(str(it.get("itemId") or "")) + '">\\n'
            f'      {_xtag("ItemName", it.get("itemName", ""))}\\n'
            f'      {_xtag("Specification", it.get("specification", ""))}\\n'
            f'      {_xtag("Unit", it.get("unit", "项"))}\\n'
            f'      {_xtag("Quantity", it.get("quantity", 1))}\\n'
            f'      {_xtag("UnitPriceMinor", up_minor)}\\n'
            f'      {_xtag("UnitPriceYuan", f"{up_minor / 100:.2f}")}\\n'
            f'      {_xtag("AmountMinor", amt_minor)}\\n'
            f'      {_xtag("AmountYuan", f"{amt_minor / 100:.2f}")}\\n'
            f'      {_xtag("TaxRateBasisPoints", tax_bp)}\\n'
            f'      {_xtag("TaxRatePercentage", pct_str)}\\n'
            f'      {_xtag("TaxClassificationCode", it.get("taxClassificationCode", "304020101"))}\\n'
            f'      {_xtag("TaxAmountMinor", tax_amt_minor)}\\n'
            f'      {_xtag("TaxAmountYuan", f"{tax_amt_minor / 100:.2f}")}\\n'
            '    </Item>'
        )
    items_xml = "\\n".join(item_nodes)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<TaxInvoiceExchange xmlns="http://tax.chinatax.gov.cn/schema/einvoice/v3" version="3.0">
  <Header>
    {_xtag("TenantId", invoice_detail.get("tenantId", ""))}
    {_xtag("ProjectId", invoice_detail.get("projectId", ""))}
    {_xtag("InvoiceId", invoice_detail.get("invoiceId", ""))}
    {_xtag("InvoiceCode", invoice_detail.get("invoiceCode", ""))}
    {_xtag("InvoiceNumber", invoice_detail.get("invoiceNumber", ""))}
    {_xtag("InvoiceType", invoice_detail.get("invoiceType", ""))}
    {_xtag("InvoiceCategory", invoice_detail.get("invoiceCategory", ""))}
    {_xtag("Status", invoice_detail.get("status", ""))}
    {_xtag("OriginalInvoiceId", invoice_detail.get("originalInvoiceId", ""))}
    {_xtag("PaymentIntentId", invoice_detail.get("paymentIntentId", ""))}
    {_xtag("IssueDate", invoice_detail.get("issuedAt", ""))}
    {_xtag("VerificationCode", invoice_detail.get("verificationCode", ""))}
    {_xtag("Currency", invoice_detail.get("currency", "CNY"))}
  </Header>
  <Seller>
    {_xtag("Name", invoice_detail.get("sellerName", ""))}
    {_xtag("TaxNumber", invoice_detail.get("sellerTaxNumber", ""))}
    {_xtag("AddressPhone", invoice_detail.get("sellerAddressPhone", ""))}
    {_xtag("BankAccount", invoice_detail.get("sellerBankAccount", ""))}
  </Seller>
  <Buyer>
    {_xtag("Type", invoice_detail.get("buyerType", ""))}
    {_xtag("Name", invoice_detail.get("buyerName", ""))}
    {_xtag("TaxNumber", invoice_detail.get("buyerTaxNumber", ""))}
    {_xtag("AddressPhone", invoice_detail.get("buyerAddressPhone", ""))}
    {_xtag("BankAccount", invoice_detail.get("buyerBankAccount", ""))}
    {_xtag("RecipientEmail", invoice_detail.get("recipientEmail", ""))}
    {_xtag("RecipientPhone", invoice_detail.get("recipientPhone", ""))}
  </Buyer>
  <Summary>
    {_xtag("UntaxedAmountMinor", untaxed_minor)}
    {_xtag("UntaxedAmountYuan", f"{untaxed_minor / 100:.2f}")}
    {_xtag("TaxAmountMinor", tax_minor)}
    {_xtag("TaxAmountYuan", f"{tax_minor / 100:.2f}")}
    {_xtag("TotalAmountMinor", total_minor)}
    {_xtag("TotalAmountYuan", f"{total_minor / 100:.2f}")}
    {_xtag("ChineseUppercaseTotal", chinese_total)}
  </Summary>
  <Items count="{len(items)}">
{items_xml}
  </Items>
  <Signatures>
    {_xtag("Payee", invoice_detail.get("payee", ""))}
    {_xtag("Checker", invoice_detail.get("checker", ""))}
    {_xtag("Operator", invoice_detail.get("operator", ""))}
    {_xtag("DownloadUrl", invoice_detail.get("downloadUrl", ""))}
  </Signatures>
</TaxInvoiceExchange>
"""


def render_invoice_batch_html(
    invoices: Sequence[Mapping[str, Any]],
    *,
    title: str = "企业电子发票批量装订归档册",
) -> str:
    """Render multiple invoices into a combined, printable booklet with summary cover sheet."""
    total_count = len(invoices)
    total_amount_minor = sum(int(inv.get("totalAmountMinor", 0)) for inv in invoices)
    total_untaxed_minor = sum(int(inv.get("untaxedAmountMinor", 0)) for inv in invoices)
    total_tax_minor = sum(int(inv.get("taxAmountMinor", 0)) for inv in invoices)

    chinese_total = amount_minor_to_chinese_uppercase(total_amount_minor)

    index_rows = []
    for idx, inv in enumerate(invoices, 1):
        num = str(inv.get("invoiceNumber", ""))
        code = str(inv.get("invoiceCode", ""))
        buyer = str(inv.get("buyerName", ""))
        tot_yuan = f"{int(inv.get('totalAmountMinor', 0)) / 100:.2f}"
        tax_yuan = f"{int(inv.get('taxAmountMinor', 0)) / 100:.2f}"
        st = str(inv.get("status", ""))
        date = str(inv.get("issuedAt", "") or "")[:10]
        index_rows.append(
            f'<tr>'
            f'<td style="text-align:center;">{idx}</td>'
            f'<td style="font-family:monospace;">{_escape_html(code)}</td>'
            f'<td style="font-family:monospace;font-weight:600;">{_escape_html(num)}</td>'
            f'<td>{_escape_html(buyer)}</td>'
            f'<td style="text-align:right;">¥{tot_yuan}</td>'
            f'<td style="text-align:right;">¥{tax_yuan}</td>'
            f'<td style="text-align:center;">{_escape_html(st)}</td>'
            f'<td style="text-align:center;">{_escape_html(date)}</td>'
            f'</tr>'
        )
    index_tbody = "\n".join(index_rows)

    cards = []
    for inv in invoices:
        single_html = render_invoice_html(inv)
        start_marker = '<div class="invoice-card">'
        end_marker = '</div>\n</body>'
        start_idx = single_html.find(start_marker)
        end_idx = single_html.rfind(end_marker)
        if start_idx != -1 and end_idx != -1:
            card_content = single_html[start_idx:end_idx + 6]
        else:
            card_content = single_html
        cards.append(f'<div class="invoice-sheet">\n{card_content}\n</div>')

    all_sheets = "\n".join(cards)

    now_str = datetime.now(timezone.utc).strftime("%Y年%m月%d日 %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>{_escape_html(title)} ({total_count} 份)</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      background-color: #f1f5f9;
      color: #1e293b;
      padding: 24px;
    }}
    .booklet-container {{
      max-width: 960px;
      margin: 0 auto;
    }}
    .cover-sheet {{
      background: #ffffff;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      padding: 40px;
      margin-bottom: 32px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
    }}
    .cover-title {{
      font-size: 26px;
      font-weight: bold;
      color: #8c3b28;
      text-align: center;
      margin-bottom: 8px;
    }}
    .cover-subtitle {{
      font-size: 13px;
      color: #64748b;
      text-align: center;
      margin-bottom: 32px;
    }}
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 32px;
    }}
    .stat-box {{
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 16px;
      text-align: center;
    }}
    .stat-label {{
      font-size: 12px;
      color: #64748b;
      margin-bottom: 6px;
    }}
    .stat-value {{
      font-size: 20px;
      font-weight: bold;
      color: #0f172a;
    }}
    .index-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-top: 16px;
    }}
    .index-table th {{
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      padding: 8px 10px;
      color: #475569;
      font-weight: 600;
    }}
    .index-table td {{
      border: 1px solid #e2e8f0;
      padding: 8px 10px;
      color: #334155;
    }}
    .index-table tr:nth-child(even) {{
      background: #f8fafc;
    }}
    .invoice-sheet {{
      display: flex;
      justify-content: center;
      margin-bottom: 40px;
    }}
    .invoice-card {{
      width: 100%;
      max-width: 900px;
      background: #ffffff;
      border: 2px solid #8c3b28;
      border-radius: 4px;
      padding: 24px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
      position: relative;
      overflow: hidden;
    }}
    .watermark {{
      position: absolute;
      top: 45%;
      left: 30%;
      transform: translate(-50%, -50%) rotate(-30deg);
      font-size: 96px;
      font-weight: 900;
      letter-spacing: 24px;
      pointer-events: none;
      z-index: 5;
      user-select: none;
    }}
    .watermark-void {{ color: rgba(100, 116, 139, 0.16); }}
    .watermark-red {{ color: rgba(207, 34, 46, 0.16); }}
    .header-grid {{
      display: grid;
      grid-template-columns: 90px 1fr 220px;
      gap: 16px;
      align-items: center;
      margin-bottom: 20px;
    }}
    .title-box {{ text-align: center; }}
    .invoice-title {{
      font-size: 22px;
      font-weight: bold;
      color: #8c3b28;
      letter-spacing: 4px;
      border-bottom: 2px double #8c3b28;
      display: inline-block;
      padding-bottom: 4px;
    }}
    .meta-list {{ font-size: 12px; line-height: 1.8; color: #4b5563; }}
    .meta-label {{ color: #8c3b28; font-weight: 600; margin-right: 6px; }}
    .meta-value {{ font-family: monospace; font-weight: bold; }}
    .grid-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-bottom: 12px;
    }}
    .grid-table td {{
      border: 1px solid #8c3b28;
      padding: 6px 10px;
      vertical-align: middle;
    }}
    .label-col {{
      width: 24px;
      text-align: center;
      background-color: #fff9f6;
      color: #8c3b28;
      font-weight: 600;
      line-height: 1.4;
      padding: 6px 4px !important;
    }}
    .field-label {{ color: #8c3b28; margin-right: 8px; font-weight: 500; }}
    .cipher-text {{
      font-family: monospace;
      font-size: 11px;
      letter-spacing: 1px;
      line-height: 1.6;
      word-break: break-all;
      color: #1e293b;
    }}
    .items-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-bottom: 12px;
    }}
    .items-table th, .items-table td {{
      border: 1px solid #8c3b28;
      padding: 6px 8px;
    }}
    .items-table th {{
      background-color: #fff9f6;
      color: #8c3b28;
      font-weight: 600;
      text-align: center;
    }}
    .total-row td {{ padding: 8px 10px; font-size: 13px; }}
    .footer-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
      color: #4b5563;
      margin-top: 14px;
      position: relative;
    }}
    .footer-seal {{
      position: absolute;
      right: 20px;
      bottom: -15px;
      pointer-events: none;
      z-index: 10;
    }}
    @media print {{
      body {{ background-color: #ffffff; padding: 0; }}
      .booklet-container {{ max-width: 100%; }}
      .cover-sheet {{ border: none; box-shadow: none; page-break-after: always; }}
      .invoice-sheet {{ margin-bottom: 0; page-break-after: always; }}
      .invoice-card {{ border: 2px solid #8c3b28; box-shadow: none; max-width: 100%; }}
    }}
  </style>
</head>
<body>
  <div class="booklet-container">
    <!-- Cover Sheet -->
    <div class="cover-sheet">
      <h1 class="cover-title">{_escape_html(title)}</h1>
      <div class="cover-subtitle">生成时间: {now_str} &nbsp;|&nbsp; 纳税申报与企业财务记账留存件</div>
      <div class="stat-grid">
        <div class="stat-box">
          <div class="stat-label">发票总张数</div>
          <div class="stat-value">{total_count}</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">价税合计总额</div>
          <div class="stat-value" style="color:#8c3b28;">¥{total_amount_minor / 100:.2f}</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">不含税金额合计</div>
          <div class="stat-value">¥{total_untaxed_minor / 100:.2f}</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">税额合计</div>
          <div class="stat-value" style="color:#059669;">¥{total_tax_minor / 100:.2f}</div>
        </div>
      </div>
      <div style="font-size:13px; margin-bottom:16px;">
        <span style="color:#64748b;">价税合计大写:</span> <strong>{chinese_total}</strong>
      </div>
      <table class="index-table">
        <thead>
          <tr>
            <th style="width: 5%;">序号</th>
            <th style="width: 18%;">发票代码</th>
            <th style="width: 15%;">发票号码</th>
            <th style="width: 26%;">购买方名称</th>
            <th style="width: 12%;">价税合计</th>
            <th style="width: 10%;">税额</th>
            <th style="width: 8%;">状态</th>
            <th style="width: 10%;">开票日期</th>
          </tr>
        </thead>
        <tbody>
          {index_tbody}
        </tbody>
      </table>
    </div>

    <!-- Individual Invoice Sheets -->
    {all_sheets}
  </div>
</body>
</html>
"""


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
        split_batch_id: str | None = None,
        split_index: int = 1,
        split_count: int = 1,
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

        norm_type = str(invoice_type).lower()
        if norm_type in {"vat_electronic_normal", "electronic_normal", "vat_ordinary_electronic", "ordinary_electronic"}:
            invoice_type = "vat_electronic_normal"
        elif norm_type in {"vat_electronic_special", "electronic_special", "vat_special_electronic", "special_electronic"}:
            invoice_type = "vat_electronic_special"
        elif norm_type in {"commercial_receipt", "receipt"}:
            invoice_type = "commercial_receipt"
        else:
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
                    detail = self._load_invoice_detail(conn, existing["invoice_id"])
                    detail["isIdempotentReplay"] = True
                    return detail

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

            # Check tenant tax quota limits
            quota_cfg = self.get_tax_quota(tenant_id)
            if quota_cfg:
                if breakdown.total_amount_minor > quota_cfg["singleInvoiceLimitMinor"] and split_count == 1:
                    raise ValidationError(
                        f"requested amount ({breakdown.total_amount_minor}) exceeds tenant single invoice limit ({quota_cfg['singleInvoiceLimitMinor']}), please use split_and_apply_invoice"
                    )
                status = self.get_tax_quota_status(tenant_id, current_time.year, current_time.month, connection=conn)
                if status["consumedMinor"] + breakdown.total_amount_minor > status["quotaLimitMinor"]:
                    raise ValidationError(
                        f"exceeds tenant monthly invoice quota: consumed={status['consumedMinor']}, requested={breakdown.total_amount_minor}, limit={status['quotaLimitMinor']}"
                    )

            invoice_id = str(uuid.uuid4())
            date_prefix = current_time.strftime("%Y%m%d")
            rand_suffix = invoice_id.replace("-", "")[:8].upper()
            invoice_number = f"INV-{date_prefix}-{rand_suffix}"
            invoice_code = f"0{current_time.year % 100}{rand_suffix[:6]}"

            inv_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(customer_invoice)").fetchall()}
            if "split_batch_id" in inv_cols:
                conn.execute(
                    "INSERT INTO customer_invoice("
                    "invoice_id, tenant_id, project_id, payment_intent_id, invoice_number, invoice_code, "
                    "invoice_type, invoice_category, status, currency, untaxed_amount_minor, tax_amount_minor, "
                    "total_amount_minor, buyer_type, buyer_name, buyer_tax_number, buyer_address_phone, "
                    "buyer_bank_account, recipient_email, recipient_phone, seller_name, seller_tax_number, "
                    "seller_address_phone, seller_bank_account, operator, idempotency_key, idempotency_payload_digest, "
                    "split_batch_id, split_index, split_count, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'blue', 'APPLIED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                        split_batch_id,
                        split_index,
                        split_count,
                        current_iso,
                        current_iso,
                    ),
                )
            else:
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

            item_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(customer_invoice_item)").fetchall()}
            for line in breakdown.lines:
                if "tax_classification_code" in item_cols:
                    conn.execute(
                        "INSERT INTO customer_invoice_item("
                        "item_id, invoice_id, item_name, specification, unit, quantity, "
                        "unit_price_minor, amount_minor, tax_rate_basis_points, tax_amount_minor, tax_classification_code) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                            line.tax_classification_code,
                        ),
                    )
                else:
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
        red_items: list[dict[str, Any]] | None = None,
        actor: str | None = None,
        checker: str | None = None,
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

            if red_items:
                breakdown = calculate_vat_breakdown(red_items)
                target_reverse = breakdown.total_amount_minor
                red_untaxed = -breakdown.untaxed_amount_minor
                red_tax = -breakdown.tax_amount_minor
                red_total = -breakdown.total_amount_minor
            else:
                target_reverse = red_amount_minor if red_amount_minor is not None else remaining_reversable
                if target_reverse <= 0 or target_reverse > remaining_reversable:
                    raise ValidationError(
                        f"invalid red amount ({target_reverse}), maximum reversable is {remaining_reversable}"
                    )

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
            item_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(customer_invoice_item)").fetchall()}
            if red_items:
                for line in breakdown.lines:
                    if "tax_classification_code" in item_cols:
                        conn.execute(
                            "INSERT INTO customer_invoice_item("
                            "item_id, invoice_id, item_name, specification, unit, quantity, "
                            "unit_price_minor, amount_minor, tax_rate_basis_points, tax_amount_minor, tax_classification_code) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                str(uuid.uuid4()),
                                red_invoice_id,
                                f"[冲红] {line.item_name}",
                                line.specification,
                                line.unit,
                                -line.quantity,
                                line.unit_price_minor,
                                -line.amount_minor,
                                line.tax_rate_basis_points,
                                -line.tax_amount_minor,
                                line.tax_classification_code,
                            ),
                        )
                    else:
                        conn.execute(
                            "INSERT INTO customer_invoice_item("
                            "item_id, invoice_id, item_name, specification, unit, quantity, "
                            "unit_price_minor, amount_minor, tax_rate_basis_points, tax_amount_minor) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                str(uuid.uuid4()),
                                red_invoice_id,
                                f"[冲红] {line.item_name}",
                                line.specification,
                                line.unit,
                                -line.quantity,
                                line.unit_price_minor,
                                -line.amount_minor,
                                line.tax_rate_basis_points,
                                -line.tax_amount_minor,
                            ),
                        )
            else:
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

    create_buyer_title = save_buyer_title

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

    def get_buyer_title(self, tenant_id: str, title_id: str | None = None) -> dict[str, Any] | None:
        """Get buyer title by ID or default title for tenant."""
        with self.store.connect() as conn:
            if not title_id or title_id == "default":
                row = conn.execute(
                    "SELECT * FROM customer_buyer_title WHERE tenant_id=? AND is_default=1 LIMIT 1",
                    (tenant_id,),
                ).fetchone()
                if not row:
                    row = conn.execute(
                        "SELECT * FROM customer_buyer_title WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1",
                        (tenant_id,),
                    ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM customer_buyer_title WHERE tenant_id=? AND title_id=?",
                    (tenant_id, title_id),
                ).fetchone()
            if not row:
                return None
            return {
                "titleId": row["title_id"],
                "tenantId": row["tenant_id"],
                "buyerType": row["buyer_type"],
                "buyerName": row["buyer_name"],
                "buyerTaxNumber": row["buyer_tax_number"],
                "buyerAddressPhone": row["buyer_address_phone"],
                "buyerBankAccount": row["buyer_bank_account"],
                "recipientEmail": row["recipient_email"],
                "recipientPhone": row["recipient_phone"],
                "isDefault": bool(row["is_default"]),
            }

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

    # --- Automated Payment Invoicing & Reconciliation ---
    def auto_invoice_payment_intent(
        self,
        *,
        tenant_id: str,
        payment_intent_id: str,
        captured_amount_minor: int,
        seller_name: str,
        seller_tax_number: str,
        project_id: str = "default_project",
        buyer_title_id: str | None = None,
        refunded_amount_minor: int = 0,
        operator: str = "system",
        actor_id: str = "actor_system",
        idempotency_key: str | None = None,
        invoice_type: str = "ELECTRONIC_NORMAL",
        item_name: str = "企业技术服务费",
        specification: str = "",
        unit: str = "项",
        tax_rate_basis_points: int = 1300,
        auto_issue: bool = True,
        checker: str | None = None,
        payee: str | None = None,
        seller_address_phone: str | None = None,
        seller_bank_account: str | None = None,
        currency: str = "CNY",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not idempotency_key:
            idempotency_key = f"auto_{tenant_id}_{payment_intent_id}"

        # Check idempotency key before balance computation
        with self.store.connect() as conn:
            existing = conn.execute(
                "SELECT invoice_id FROM customer_invoice WHERE tenant_id=? AND idempotency_key=?",
                (tenant_id, idempotency_key),
            ).fetchone()
            if existing:
                inv = self.get_invoice(tenant_id, existing["invoice_id"])
                if inv is not None:
                    inv["isIdempotentReplay"] = True
                    return inv

        title = self.get_buyer_title(tenant_id, buyer_title_id)
        if not title:
            raise ValidationError(f"buyer title not found: {buyer_title_id or 'default'}")

        balance = self.calculate_invoicable_balance(
            tenant_id, payment_intent_id, captured_amount_minor, refunded_amount_minor
        )
        if balance <= 0:
            if idempotency_key:
                with self.store.connect() as conn:
                    existing = conn.execute(
                        "SELECT invoice_id FROM customer_invoice "
                        "WHERE tenant_id=? AND idempotency_key=?",
                        (tenant_id, idempotency_key),
                    ).fetchone()
                    if existing:
                        inv = self.get_invoice(tenant_id, existing["invoice_id"])
                        if inv is not None:
                            inv["isIdempotentReplay"] = True
                            return inv
            raise ValidationError(f"no invoicable balance remaining for payment intent: {payment_intent_id}")

        r = tax_rate_basis_points
        u = (balance * 10000 + (10000 + r) // 2) // (10000 + r)
        tax = (u * r + 5000) // 10000
        line_total = u + tax

        items: list[dict[str, Any]] = []
        if line_total == balance:
            items.append({
                "itemName": item_name,
                "specification": specification,
                "unit": unit,
                "quantity": 1,
                "unitPriceMinor": u,
                "taxRateBasisPoints": r,
            })
        elif line_total < balance:
            delta = balance - line_total
            items.append({
                "itemName": item_name,
                "specification": specification,
                "unit": unit,
                "quantity": 1,
                "unitPriceMinor": u,
                "taxRateBasisPoints": r,
            })
            items.append({
                "itemName": f"{item_name}(精度调整)",
                "specification": "",
                "unit": "项",
                "quantity": 1,
                "unitPriceMinor": delta,
                "taxRateBasisPoints": 0,
            })
        else:
            u_adj = max(0, u - 1)
            tax_adj = (u_adj * r + 5000) // 10000
            delta = balance - (u_adj + tax_adj)
            items.append({
                "itemName": item_name,
                "specification": specification,
                "unit": unit,
                "quantity": 1,
                "unitPriceMinor": u_adj,
                "taxRateBasisPoints": r,
            })
            if delta > 0:
                items.append({
                    "itemName": f"{item_name}(精度调整)",
                    "specification": "",
                    "unit": "项",
                    "quantity": 1,
                    "unitPriceMinor": delta,
                    "taxRateBasisPoints": 0,
                })

        applied = self.apply_invoice(
            tenant_id=tenant_id,
            project_id=project_id,
            payment_intent_id=payment_intent_id,
            captured_amount_minor=captured_amount_minor,
            refunded_amount_minor=refunded_amount_minor,
            invoice_type=invoice_type,
            buyer_type=title["buyerType"],
            buyer_name=title["buyerName"],
            buyer_tax_number=title.get("buyerTaxNumber"),
            buyer_address_phone=title.get("buyerAddressPhone"),
            buyer_bank_account=title.get("buyerBankAccount"),
            recipient_email=title.get("recipientEmail"),
            recipient_phone=title.get("recipientPhone"),
            seller_name=seller_name,
            seller_tax_number=seller_tax_number,
            seller_address_phone=seller_address_phone,
            seller_bank_account=seller_bank_account,
            operator=operator,
            items=items,
            idempotency_key=idempotency_key,
            currency=currency,
            now=now,
        )

        if applied.get("isIdempotentReplay"):
            return applied

        if auto_issue and applied["status"] == "APPLIED":
            issued = self.issue_invoice(
                tenant_id,
                applied["invoiceId"],
                actor=actor_id,
                checker=checker or operator,
                payee=payee or seller_name,
                now=now,
            )
            issued["isIdempotentReplay"] = False
            return issued

        applied["isIdempotentReplay"] = False
        return applied

    def reconcile_invoices_with_payments(
        self,
        tenant_id: str,
        *,
        payments: Sequence[Mapping[str, Any]] | None = None,
        start_time: datetime | str | None = None,
        end_time: datetime | str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Cross-reconcile customer invoice balances with payment intents to detect financial discrepancies."""
        current_iso = _instant(now)

        with self.store.connect() as conn:
            query = (
                "SELECT invoice_id, payment_intent_id, status, total_amount_minor, "
                "invoice_category, created_at FROM customer_invoice WHERE tenant_id=?"
            )
            params: list[Any] = [tenant_id]
            if start_time:
                s_iso = start_time.isoformat() if isinstance(start_time, datetime) else start_time
                query += " AND created_at >= ?"
                params.append(s_iso)
            if end_time:
                e_iso = end_time.isoformat() if isinstance(end_time, datetime) else end_time
                query += " AND created_at <= ?"
                params.append(e_iso)

            rows = conn.execute(query, params).fetchall()

        invoices_by_pi: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            pi_id = r["payment_intent_id"]
            if pi_id not in invoices_by_pi:
                invoices_by_pi[pi_id] = []
            invoices_by_pi[pi_id].append({
                "invoiceId": r["invoice_id"],
                "status": r["status"],
                "totalAmountMinor": r["total_amount_minor"],
                "invoiceCategory": r["invoice_category"],
                "createdAt": r["created_at"],
            })

        reconciled_details: list[dict[str, Any]] = []
        discrepancies: list[dict[str, Any]] = []

        total_captured = 0
        total_refunded = 0
        total_invoiced = 0

        payment_map: dict[str, Mapping[str, Any]] = {}
        if payments is not None:
            for p in payments:
                p_id = str(p.get("paymentIntentId") or p.get("id"))
                payment_map[p_id] = p
        else:
            for p_id in invoices_by_pi:
                payment_map[p_id] = {
                    "paymentIntentId": p_id,
                    "capturedAmountMinor": 0,
                    "refundedAmountMinor": 0,
                }

        for pi_id, p_data in payment_map.items():
            cap = int(p_data.get("capturedAmountMinor", 0))
            ref = int(p_data.get("refundedAmountMinor", 0))
            net_cap = max(0, cap - ref)

            total_captured += cap
            total_refunded += ref

            inv_list = invoices_by_pi.get(pi_id, [])
            active_invs = [inv for inv in inv_list if inv["status"] in ("APPLIED", "ISSUED", "RED_NOTED")]
            inv_sum = sum(inv["totalAmountMinor"] for inv in active_invs)
            total_invoiced += inv_sum

            item_discrepancies: list[str] = []

            if payments is not None and inv_sum > net_cap:
                disc = {
                    "code": "OVER_INVOICED",
                    "severity": "CRITICAL",
                    "paymentIntentId": pi_id,
                    "message": f"Invoiced net amount ({inv_sum}) exceeds net captured payment ({net_cap})",
                    "invoicedAmountMinor": inv_sum,
                    "netCapturedAmountMinor": net_cap,
                }
                discrepancies.append(disc)
                item_discrepancies.append("OVER_INVOICED")

            if payments is not None and ref > 0 and inv_sum > net_cap:
                disc = {
                    "code": "REFUND_WITHOUT_RED_NOTE",
                    "severity": "HIGH",
                    "paymentIntentId": pi_id,
                    "message": f"Payment refunded {ref} minor units without matching red-note invoice adjustment",
                    "refundedAmountMinor": ref,
                }
                discrepancies.append(disc)
                item_discrepancies.append("REFUND_WITHOUT_RED_NOTE")

            if payments is not None and 0 < inv_sum < net_cap:
                item_discrepancies.append("PARTIALLY_INVOICED")

            if payments is not None and inv_sum == 0 and net_cap > 0:
                item_discrepancies.append("UNINVOICED_PAYMENT")

            status = "BALANCED" if not item_discrepancies or item_discrepancies == ["PARTIALLY_INVOICED"] else "DISCREPANCY"
            if not item_discrepancies:
                status = "BALANCED"

            reconciled_details.append({
                "paymentIntentId": pi_id,
                "capturedAmountMinor": cap,
                "refundedAmountMinor": ref,
                "netInvoicableAmountMinor": net_cap,
                "invoicedAmountMinor": inv_sum,
                "invoiceCount": len(inv_list),
                "activeInvoiceCount": len(active_invs),
                "status": status,
                "discrepancyCodes": item_discrepancies,
            })

        if payments is not None:
            for pi_id, inv_list in invoices_by_pi.items():
                if pi_id not in payment_map:
                    active_invs = [inv for inv in inv_list if inv["status"] in ("APPLIED", "ISSUED", "RED_NOTED")]
                    inv_sum = sum(inv["totalAmountMinor"] for inv in active_invs)
                    disc = {
                        "code": "UNMATCHED_PAYMENT_INTENT",
                        "severity": "MEDIUM",
                        "paymentIntentId": pi_id,
                        "message": f"Invoice exists for payment {pi_id}, but payment not found in reconciliation input",
                        "invoicedAmountMinor": inv_sum,
                    }
                    discrepancies.append(disc)
                    total_invoiced += inv_sum
                    reconciled_details.append({
                        "paymentIntentId": pi_id,
                        "capturedAmountMinor": 0,
                        "refundedAmountMinor": 0,
                        "netInvoicableAmountMinor": 0,
                        "invoicedAmountMinor": inv_sum,
                        "invoiceCount": len(inv_list),
                        "activeInvoiceCount": len(active_invs),
                        "status": "UNMATCHED",
                        "discrepancyCodes": ["UNMATCHED_PAYMENT_INTENT"],
                    })

        net_invoicable = max(0, total_captured - total_refunded)
        un_invoiced = max(0, net_invoicable - total_invoiced)
        over_invoiced = max(0, total_invoiced - net_invoicable) if payments is not None else 0

        overall_status = "BALANCED" if not any(d["severity"] in ("CRITICAL", "HIGH") for d in discrepancies) else "HAS_DISCREPANCIES"

        return {
            "tenantId": tenant_id,
            "reconciledAt": current_iso,
            "totalPaymentIntents": len(reconciled_details),
            "totalCapturedAmountMinor": total_captured,
            "totalRefundedAmountMinor": total_refunded,
            "netInvoicableAmountMinor": net_invoicable,
            "totalInvoicedAmountMinor": total_invoiced,
            "unInvoicedAmountMinor": un_invoiced,
            "overInvoicedAmountMinor": over_invoiced,
            "discrepancyCount": len(discrepancies),
            "status": overall_status,
            "discrepancies": discrepancies,
            "details": reconciled_details,
        }

    def batch_auto_invoice(
        self,
        tenant_id: str,
        manifest: Sequence[Mapping[str, Any]],
        *,
        seller_name: str,
        seller_tax_number: str,
        seller_address_phone: str = "中国上海市浦东新区张江高科",
        seller_bank_account: str = "招商银行上海张江支行 9876543210987654",
        operator: str = "系统批量开票引擎",
        actor_id: str = "batch_engine_service",
        checker: str | None = "财务自动复核服务",
        payee: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Process a batch of payment intents for automated invoice issuance."""
        success_invoices: list[dict[str, Any]] = []
        skipped_duplicates: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        total_invoiced_minor = 0
        total_tax_minor = 0

        for item in manifest:
            pi_id = str(item.get("paymentIntentId") or "")
            if not pi_id:
                failures.append({"paymentIntentId": "", "error": "missing paymentIntentId"})
                continue
            project_id = str(item.get("projectId") or "default_project")
            captured = int(item.get("capturedAmountMinor", 0))
            refunded = int(item.get("refundedAmountMinor", 0))
            buyer_title_id = item.get("buyerTitleId")
            item_name = str(item.get("itemName") or "企业支付技术服务费")
            tax_rate_bp = int(item.get("taxRateBasisPoints", 1300))
            idempotency_key = item.get("idempotencyKey") or f"batch_auto_{tenant_id}_{pi_id}"
            currency = str(item.get("currency") or "CNY")

            try:
                inv = self.auto_invoice_payment_intent(
                    tenant_id=tenant_id,
                    project_id=project_id,
                    payment_intent_id=pi_id,
                    captured_amount_minor=captured,
                    refunded_amount_minor=refunded,
                    seller_name=seller_name,
                    seller_tax_number=seller_tax_number,
                    buyer_title_id=buyer_title_id,
                    item_name=item_name,
                    tax_rate_basis_points=tax_rate_bp,
                    idempotency_key=idempotency_key,
                    operator=operator,
                    actor_id=actor_id,
                    checker=checker,
                    payee=payee,
                    auto_issue=True,
                    seller_address_phone=seller_address_phone,
                    seller_bank_account=seller_bank_account,
                    currency=currency,
                    now=now,
                )
                if inv.get("isIdempotentReplay") or any(prev["invoiceId"] == inv["invoiceId"] for prev in success_invoices):
                    skipped_duplicates.append(inv)
                elif inv.get("status") in {"ISSUED", "APPLIED"}:
                    success_invoices.append(inv)
                    total_invoiced_minor += int(inv.get("totalAmountMinor", 0))
                    total_tax_minor += int(inv.get("taxAmountMinor", 0))
                else:
                    success_invoices.append(inv)
            except Exception as e:
                failures.append({
                    "paymentIntentId": pi_id,
                    "error": str(e),
                })

        return {
            "tenantId": tenant_id,
            "totalProcessed": len(manifest),
            "successCount": len(success_invoices),
            "skippedDuplicateCount": len(skipped_duplicates),
            "failedCount": len(failures),
            "totalInvoicedAmountMinor": total_invoiced_minor,
            "totalTaxAmountMinor": total_tax_minor,
            "invoices": success_invoices,
            "failures": failures,
        }

    def auto_red_note_on_refund(
        self,
        tenant_id: str,
        payment_intent_id: str,
        refund_amount_minor: int,
        *,
        operator: str,
        reason: str = "原交易发生退款，自动红字冲销",
        idempotency_key: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Automatically issue credit notes (red note) when a payment intent is refunded."""
        if refund_amount_minor <= 0:
            raise ValidationError("refund_amount_minor must be strictly positive")

        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT invoice_id, total_amount_minor, status FROM customer_invoice "
                "WHERE tenant_id=? AND payment_intent_id=? AND invoice_category='blue' "
                "AND status IN ('ISSUED', 'APPLIED', 'RED_NOTED') ORDER BY created_at ASC",
                (tenant_id, payment_intent_id),
            ).fetchall()

        if not rows:
            raise ValidationError(f"no active blue invoice found for payment {payment_intent_id} to red-note")

        with self.store.connect() as conn:
            red_rows = conn.execute(
                "SELECT original_invoice_id, total_amount_minor FROM customer_invoice "
                "WHERE tenant_id=? AND payment_intent_id=? AND invoice_category='red' "
                "AND status IN ('ISSUED', 'APPLIED')",
                (tenant_id, payment_intent_id),
            ).fetchall()

        red_sum_by_orig: dict[str, int] = {}
        for r in red_rows:
            orig = r["original_invoice_id"]
            red_sum_by_orig[orig] = red_sum_by_orig.get(orig, 0) + abs(int(r["total_amount_minor"]))

        remaining_to_red = refund_amount_minor
        issued_red_notes: list[dict[str, Any]] = []

        for r in rows:
            if remaining_to_red <= 0:
                break
            inv_id = r["invoice_id"]
            blue_total = int(r["total_amount_minor"])
            already_red = red_sum_by_orig.get(inv_id, 0)
            avail_for_red = max(0, blue_total - already_red)

            if avail_for_red <= 0:
                continue

            red_portion = min(avail_for_red, remaining_to_red)
            red_key = idempotency_key or f"auto_red_{payment_intent_id}_{inv_id}_{refund_amount_minor}"

            red_note = self.issue_red_note(
                tenant_id=tenant_id,
                original_invoice_id=inv_id,
                reason=reason,
                operator=operator,
                red_amount_minor=red_portion,
                idempotency_key=red_key,
                now=now,
            )
            issued_red_notes.append(red_note)
            remaining_to_red -= red_portion

        if remaining_to_red > 0 and not issued_red_notes:
            raise ValidationError("all existing blue invoices are already fully red-noted")

        return {
            "tenantId": tenant_id,
            "paymentIntentId": payment_intent_id,
            "requestedRefundMinor": refund_amount_minor,
            "creditedAmountMinor": refund_amount_minor - remaining_to_red,
            "uncreditedAmountMinor": remaining_to_red,
            "redNotesCount": len(issued_red_notes),
            "redNotes": issued_red_notes,
        }



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
        split_batch_id = row["split_batch_id"] if "split_batch_id" in keys else None
        split_index = row["split_index"] if "split_index" in keys else 1
        split_count = row["split_count"] if "split_count" in keys else 1

        it_keys = items[0].keys() if items and hasattr(items[0], "keys") else []

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
            "splitBatchId": split_batch_id,
            "splitIndex": split_index,
            "splitCount": split_count,
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
                    "taxClassificationCode": it["tax_classification_code"] if "tax_classification_code" in it_keys else "304020101",
                }
                for it in items
            ],
        }

    # --- Enterprise Tax Quota & Monthly Limits ---
    def configure_tax_quota(
        self,
        tenant_id: str,
        monthly_tax_quota_minor: int,
        single_invoice_limit_minor: int,
        quota_version: str = "SHI_WAN",
        auto_split_enabled: bool = True,
        alarm_threshold_pct: int = 85,
        operator: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Configure monthly invoicing quota and single invoice limit for a tenant."""
        if monthly_tax_quota_minor <= 0:
            raise ValidationError("monthly_tax_quota_minor must be strictly positive")
        if single_invoice_limit_minor <= 0:
            raise ValidationError("single_invoice_limit_minor must be strictly positive")
        if quota_version not in {"WAN", "SHI_WAN", "BAI_WAN", "QIAN_WAN", "UNLIMITED"}:
            raise ValidationError(f"unsupported quota_version: {quota_version}")
        if not (1 <= alarm_threshold_pct <= 100):
            raise ValidationError("alarm_threshold_pct must be between 1 and 100")

        current_iso = _instant(now)
        with self.store.transaction() as conn:
            quota_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(customer_invoice_quota)").fetchall()}
            if "alarm_threshold_pct" in quota_cols:
                conn.execute(
                    "INSERT INTO customer_invoice_quota("
                    "tenant_id, monthly_tax_quota_minor, single_invoice_limit_minor, "
                    "quota_version, auto_split_enabled, alarm_threshold_pct, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(tenant_id) DO UPDATE SET "
                    "monthly_tax_quota_minor=excluded.monthly_tax_quota_minor, "
                    "single_invoice_limit_minor=excluded.single_invoice_limit_minor, "
                    "quota_version=excluded.quota_version, "
                    "auto_split_enabled=excluded.auto_split_enabled, "
                    "alarm_threshold_pct=excluded.alarm_threshold_pct, "
                    "updated_at=excluded.updated_at",
                    (
                        tenant_id,
                        monthly_tax_quota_minor,
                        single_invoice_limit_minor,
                        quota_version,
                        1 if auto_split_enabled else 0,
                        alarm_threshold_pct,
                        current_iso,
                        current_iso,
                    ),
                )
            else:
                conn.execute(
                    "INSERT INTO customer_invoice_quota("
                    "tenant_id, monthly_tax_quota_minor, single_invoice_limit_minor, "
                    "quota_version, auto_split_enabled, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(tenant_id) DO UPDATE SET "
                    "monthly_tax_quota_minor=excluded.monthly_tax_quota_minor, "
                    "single_invoice_limit_minor=excluded.single_invoice_limit_minor, "
                    "quota_version=excluded.quota_version, "
                    "auto_split_enabled=excluded.auto_split_enabled, "
                    "updated_at=excluded.updated_at",
                    (
                        tenant_id,
                        monthly_tax_quota_minor,
                        single_invoice_limit_minor,
                        quota_version,
                        1 if auto_split_enabled else 0,
                        current_iso,
                        current_iso,
                    ),
                )
        return {
            "tenantId": tenant_id,
            "monthlyTaxQuotaMinor": monthly_tax_quota_minor,
            "singleInvoiceLimitMinor": single_invoice_limit_minor,
            "quotaVersion": quota_version,
            "autoSplitEnabled": auto_split_enabled,
            "alarmThresholdPct": alarm_threshold_pct,
            "operator": operator,
            "updatedAt": current_iso,
        }

    def get_tax_quota(self, tenant_id: str) -> dict[str, Any] | None:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM customer_invoice_quota WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            if not row:
                return None
            keys = set(row.keys())
            return {
                "tenantId": row["tenant_id"],
                "monthlyTaxQuotaMinor": row["monthly_tax_quota_minor"],
                "singleInvoiceLimitMinor": row["single_invoice_limit_minor"],
                "quotaVersion": row["quota_version"],
                "autoSplitEnabled": bool(row["auto_split_enabled"]),
                "alarmThresholdPct": row["alarm_threshold_pct"] if "alarm_threshold_pct" in keys else 85,
            }

    def get_tax_quota_status(
        self,
        tenant_id: str,
        year: int | None = None,
        month: int | None = None,
        tax_period: str | None = None,
        connection: Any = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Calculate current month's consumed quota and remaining quota."""
        cfg = self.get_tax_quota(tenant_id)
        monthly_limit = cfg["monthlyTaxQuotaMinor"] if cfg else 50000000
        single_limit = cfg["singleInvoiceLimitMinor"] if cfg else 10000000
        version = cfg["quotaVersion"] if cfg else "SHI_WAN"
        auto_split = cfg["autoSplitEnabled"] if cfg else True
        alarm_threshold = cfg["alarmThresholdPct"] if cfg else 85

        if tax_period:
            parts = tax_period.split("-")
            year = int(parts[0])
            month = int(parts[1])
        elif year is None or month is None:
            ct = _current(now)
            year = ct.year
            month = ct.month

        start_prefix = f"{year:04d}-{month:02d}-01T"
        if month == 12:
            end_prefix = f"{year+1:04d}-01-01T"
        else:
            end_prefix = f"{year:04d}-{month+1:02d}-01T"

        conn = connection or self.store.connect()
        try:
            rows = conn.execute(
                "SELECT invoice_category, total_amount_minor FROM customer_invoice "
                "WHERE tenant_id=? AND status IN ('APPLIED', 'ISSUED', 'RED_NOTED') "
                "AND created_at >= ? AND created_at < ?",
                (tenant_id, start_prefix, end_prefix),
            ).fetchall()
            consumed = 0
            for r in rows:
                amt = r["total_amount_minor"]
                if r["invoice_category"] == "blue":
                    consumed += amt
                elif r["invoice_category"] == "red":
                    consumed += amt  # negative
            consumed = max(0, consumed)
            remaining = max(0, monthly_limit - consumed)
            is_alarm = (consumed / monthly_limit >= alarm_threshold / 100.0) if monthly_limit > 0 else True
            is_exhausted = remaining == 0
            return {
                "tenantId": tenant_id,
                "taxPeriod": f"{year:04d}-{month:02d}",
                "year": year,
                "month": month,
                "quotaLimitMinor": monthly_limit,
                "monthlyTaxQuotaMinor": monthly_limit,
                "singleInvoiceLimitMinor": single_limit,
                "quotaVersion": version,
                "autoSplitEnabled": auto_split,
                "consumedMinor": consumed,
                "usedTaxQuotaMinor": consumed,
                "remainingQuotaMinor": remaining,
                "remainingTaxQuotaMinor": remaining,
                "alarmThresholdPct": alarm_threshold,
                "isAlarm": is_alarm,
                "isExhausted": is_exhausted,
                "usageRatio": round(consumed / monthly_limit, 4) if monthly_limit > 0 else 1.0,
            }
        finally:
            if connection is None:
                conn.close()

    # --- Enterprise Invoice Auto-Splitting ---
    def split_and_apply_invoice(
        self,
        *,
        tenant_id: str,
        payment_intent_id: str,
        invoice_type: str = "vat_electronic_normal",
        buyer_info: dict[str, Any] | None = None,
        seller_info: dict[str, Any] | None = None,
        items: list[dict[str, Any]] | None = None,
        project_id: str = "proj_default",
        captured_amount_minor: int | None = None,
        refunded_amount_minor: int = 0,
        seller_name: str | None = None,
        seller_tax_number: str | None = None,
        operator: str = "system",
        buyer_title_id: str | None = None,
        total_requested_minor: int | None = None,
        item_name: str = "企业技术服务费",
        specification: str = "",
        unit: str = "项",
        tax_rate_basis_points: int = 1300,
        tax_classification_code: str = "3040201010000000000",
        single_invoice_cap_minor: int | None = None,
        auto_issue: bool = False,
        actor_id: str = "actor_split",
        checker: str | None = None,
        payee: str | None = None,
        seller_address_phone: str | None = None,
        seller_bank_account: str | None = None,
        idempotency_key: str | None = None,
        currency: str = "CNY",
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Split oversized payment balance into compliant sub-invoices respecting single-invoice cap."""
        if idempotency_key:
            with self.store.connect() as conn:
                existing_splits = conn.execute(
                    "SELECT invoice_id FROM customer_invoice WHERE tenant_id=? AND idempotency_key LIKE ? ORDER BY split_index ASC",
                    (tenant_id, f"{idempotency_key}_part_%"),
                ).fetchall()
                if existing_splits:
                    return [self._load_invoice_detail(conn, r["invoice_id"]) for r in existing_splits]

        if buyer_info:
            buyer_type = buyer_info.get("buyerType") or ("enterprise" if (buyer_info.get("taxNumber") or buyer_info.get("buyerTaxNumber") or buyer_info.get("taxId")) else "individual")
            buyer_name = buyer_info.get("name") or buyer_info.get("buyerName") or "企业客户"
            buyer_tax_number = buyer_info.get("taxNumber") or buyer_info.get("buyerTaxNumber") or buyer_info.get("taxId")
            buyer_address_phone = buyer_info.get("addressPhone") or buyer_info.get("buyerAddressPhone")
            buyer_bank_account = buyer_info.get("bankAccount") or buyer_info.get("buyerBankAccount")
            recipient_email = buyer_info.get("email") or buyer_info.get("recipientEmail")
            recipient_phone = buyer_info.get("phone") or buyer_info.get("recipientPhone")
        else:
            title = self.get_buyer_title(tenant_id, buyer_title_id)
            if not title:
                raise ValidationError(f"buyer title not found: {buyer_title_id or 'default'}")
            buyer_type = title["buyerType"]
            buyer_name = title["buyerName"]
            buyer_tax_number = title.get("buyerTaxNumber")
            buyer_address_phone = title.get("buyerAddressPhone")
            buyer_bank_account = title.get("buyerBankAccount")
            recipient_email = title.get("recipientEmail")
            recipient_phone = title.get("recipientPhone")

        if seller_info:
            seller_name = seller_info.get("name") or seller_info.get("sellerName") or seller_name or "榆钱儿支付"
            seller_tax_number = seller_info.get("taxNumber") or seller_info.get("sellerTaxNumber") or seller_tax_number or "91110105MA02YYYYYY"
            seller_address_phone = seller_info.get("addressPhone") or seller_address_phone
            seller_bank_account = seller_info.get("bankAccount") or seller_bank_account
        else:
            seller_name = seller_name or "榆钱儿支付"
            seller_tax_number = seller_tax_number or "91110105MA02YYYYYY"

        if items:
            orig_breakdown = calculate_vat_breakdown(items)
            target_amount = orig_breakdown.total_amount_minor
            first_item = items[0]
            item_name = first_item.get("itemName", item_name)
            specification = first_item.get("specification", specification)
            unit = first_item.get("unit", unit)
            tax_rate_basis_points = first_item.get("taxRateBasisPoints", tax_rate_basis_points)
            tax_classification_code = first_item.get("taxClassificationCode", tax_classification_code)
        else:
            invoicable = self.calculate_invoicable_balance(
                tenant_id, payment_intent_id, captured_amount_minor or 0, refunded_amount_minor
            )
            target_amount = total_requested_minor if total_requested_minor is not None else invoicable

        if target_amount <= 0:
            raise ValidationError(f"no invoicable balance remaining for payment intent: {payment_intent_id}")

        quota_cfg = self.get_tax_quota(tenant_id)
        cap = single_invoice_cap_minor or (quota_cfg["singleInvoiceLimitMinor"] if quota_cfg else 10000000)
        if cap <= 0:
            cap = 10000000

        slices: list[int] = []
        rem = target_amount
        while rem > 0:
            take = min(rem, cap)
            slices.append(take)
            rem -= take

        split_count = len(slices)
        split_batch_id = f"split_{uuid.uuid4().hex[:16]}"
        issued_invoices: list[dict[str, Any]] = []

        for idx, slice_amount in enumerate(slices):
            r = tax_rate_basis_points
            u = (slice_amount * 10000 + (10000 + r) // 2) // (10000 + r)
            tax = (u * r + 5000) // 10000
            diff = slice_amount - (u + tax)
            slice_untaxed = u + diff

            slice_items = [
                {
                    "itemName": f"{item_name} (分票 {idx + 1}/{split_count})" if split_count > 1 else item_name,
                    "specification": specification,
                    "unit": unit,
                    "quantity": 1,
                    "unitPriceMinor": slice_untaxed,
                    "taxRateBasisPoints": r,
                    "taxClassificationCode": tax_classification_code,
                }
            ]

            part_idempotency_key = f"{idempotency_key}_part_{idx + 1}" if idempotency_key else None
            applied = self.apply_invoice(
                tenant_id=tenant_id,
                project_id=project_id,
                payment_intent_id=payment_intent_id,
                captured_amount_minor=captured_amount_minor or target_amount,
                refunded_amount_minor=refunded_amount_minor,
                invoice_type=invoice_type,
                buyer_type=buyer_type,
                buyer_name=buyer_name,
                buyer_tax_number=buyer_tax_number,
                buyer_address_phone=buyer_address_phone,
                buyer_bank_account=buyer_bank_account,
                recipient_email=recipient_email,
                recipient_phone=recipient_phone,
                seller_name=seller_name,
                seller_tax_number=seller_tax_number,
                seller_address_phone=seller_address_phone,
                seller_bank_account=seller_bank_account,
                operator=operator,
                items=slice_items,
                idempotency_key=part_idempotency_key,
                split_batch_id=split_batch_id,
                split_index=idx + 1,
                split_count=split_count,
                currency=currency,
                now=now,
            )

            if auto_issue and applied["status"] == "APPLIED":
                issued = self.issue_invoice(
                    tenant_id,
                    applied["invoiceId"],
                    actor=actor_id,
                    checker=checker or operator,
                    payee=payee or seller_name,
                    now=now,
                )
                issued_invoices.append(issued)
            else:
                issued_invoices.append(applied)

        return issued_invoices

    # --- Self-Service Invoicing & QR Ticket Tokens ---
    def create_self_service_session(
        self,
        *,
        tenant_id: str,
        payment_intent_id: str,
        invoicable_amount_minor: int | None = None,
        captured_amount_minor: int | None = None,
        project_id: str = "proj_default",
        seller_name: str = "榆钱儿企业服务（北京）有限公司",
        seller_tax_number: str = "91110105MA02YYYYYY",
        currency: str = "CNY",
        ttl_hours: int | None = None,
        expire_hours: int = 72,
        created_by: str = "system",
        base_portal_url: str = "https://pay.elmpay.com/invoicing/self-service",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Create time-limited, signed self-service invoicing session for customer self-ticketing."""
        amount = invoicable_amount_minor if invoicable_amount_minor is not None else (captured_amount_minor or 0)
        hours = ttl_hours if ttl_hours is not None else expire_hours

        invoicable = self.calculate_invoicable_balance(
            tenant_id, payment_intent_id, amount, 0
        )
        if invoicable <= 0:
            raise ValidationError(f"no invoicable balance remaining for payment intent: {payment_intent_id}")

        current_time = _current(now)
        current_iso = current_time.isoformat()
        expires_time = current_time + timedelta(hours=hours)
        expires_iso = expires_time.isoformat()

        session_id = str(uuid.uuid4())
        raw_token = hashlib.sha256(f"{session_id}:{tenant_id}:{payment_intent_id}:{current_iso}".encode("utf-8")).hexdigest()
        token_digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        qr_url = f"{base_portal_url}?token={raw_token}"

        with self.store.transaction() as conn:
            existing = conn.execute(
                "SELECT * FROM customer_invoice_self_service WHERE tenant_id=? AND payment_intent_id=?",
                (tenant_id, payment_intent_id),
            ).fetchone()
            if existing:
                if existing["status"] == "ACTIVE" and existing["expires_at"] > current_iso:
                    return {
                        "sessionId": existing["session_id"],
                        "tenantId": existing["tenant_id"],
                        "projectId": existing["project_id"],
                        "paymentIntentId": existing["payment_intent_id"],
                        "invoicableAmountMinor": existing["captured_amount_minor"],
                        "capturedAmountMinor": existing["captured_amount_minor"],
                        "currency": existing["currency"],
                        "sellerName": existing["seller_name"],
                        "sellerTaxNumber": existing["seller_tax_number"],
                        "sessionToken": existing["session_token"],
                        "qrPayload": existing["qr_code_url"],
                        "qrCodeUrl": existing["qr_code_url"],
                        "expiresAt": existing["expires_at"],
                        "status": existing["status"],
                        "createdBy": created_by,
                        "createdAt": existing["created_at"],
                    }

            conn.execute(
                "INSERT INTO customer_invoice_self_service("
                "session_id, tenant_id, project_id, payment_intent_id, captured_amount_minor, "
                "currency, seller_name, seller_tax_number, session_token, session_token_digest, "
                "qr_code_url, expires_at, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?) "
                "ON CONFLICT(tenant_id, payment_intent_id) DO UPDATE SET "
                "session_id=excluded.session_id, session_token=excluded.session_token, "
                "session_token_digest=excluded.session_token_digest, qr_code_url=excluded.qr_code_url, "
                "expires_at=excluded.expires_at, status='ACTIVE', created_at=excluded.created_at",
                (
                    session_id,
                    tenant_id,
                    project_id,
                    payment_intent_id,
                    amount,
                    currency,
                    seller_name,
                    seller_tax_number,
                    raw_token,
                    token_digest,
                    qr_url,
                    expires_iso,
                    current_iso,
                ),
            )

        return {
            "sessionId": session_id,
            "tenantId": tenant_id,
            "projectId": project_id,
            "paymentIntentId": payment_intent_id,
            "invoicableAmountMinor": amount,
            "capturedAmountMinor": amount,
            "currency": currency,
            "sellerName": seller_name,
            "sellerTaxNumber": seller_tax_number,
            "sessionToken": raw_token,
            "qrPayload": qr_url,
            "qrCodeUrl": qr_url,
            "expiresAt": expires_iso,
            "status": "ACTIVE",
            "createdBy": created_by,
            "createdAt": current_iso,
        }

    def get_self_service_session(self, session_token: str, now: datetime | None = None) -> dict[str, Any]:
        """Fetch and validate a self-service session."""
        current_iso = _instant(now)
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM customer_invoice_self_service WHERE session_token=?",
                (session_token,),
            ).fetchone()
            if not row:
                raise ValidationError("self-service session not found")

            status = row["status"]
            if status == "ACTIVE" and row["expires_at"] <= current_iso:
                status = "EXPIRED"

            return {
                "sessionId": row["session_id"],
                "tenantId": row["tenant_id"],
                "projectId": row["project_id"],
                "paymentIntentId": row["payment_intent_id"],
                "invoicableAmountMinor": row["captured_amount_minor"],
                "capturedAmountMinor": row["captured_amount_minor"],
                "currency": row["currency"],
                "sellerName": row["seller_name"],
                "sellerTaxNumber": row["seller_tax_number"],
                "sessionToken": row["session_token"],
                "qrPayload": row["qr_code_url"],
                "qrCodeUrl": row["qr_code_url"],
                "expiresAt": row["expires_at"],
                "status": status,
                "redeemedInvoiceId": row["redeemed_invoice_id"],
                "redeemedAt": row["redeemed_at"],
                "createdAt": row["created_at"],
            }

    def redeem_self_service_session(
        self,
        *,
        session_token: str,
        buyer_info: dict[str, Any] | None = None,
        buyer_type: str | None = None,
        buyer_name: str | None = None,
        buyer_tax_number: str | None = None,
        buyer_address_phone: str | None = None,
        buyer_bank_account: str | None = None,
        recipient_email: str | None = None,
        recipient_phone: str | None = None,
        invoice_type: str = "vat_electronic_normal",
        item_name: str = "企业支付技术服务费",
        tax_rate_basis_points: int = 1300,
        tax_classification_code: str = "3040201010000000000",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Buyer redeems self-service ticket, generating official VAT invoice."""
        if buyer_info:
            b_name = buyer_info.get("name") or buyer_info.get("buyerName") or buyer_name or ""
            b_tax = buyer_info.get("taxNumber") or buyer_info.get("buyerTaxNumber") or buyer_info.get("taxId") or buyer_tax_number
            b_type = buyer_info.get("buyerType") or (buyer_type or ("enterprise" if b_tax else "individual"))
            b_addr = buyer_info.get("addressPhone") or buyer_info.get("buyerAddressPhone") or buyer_address_phone
            b_bank = buyer_info.get("bankAccount") or buyer_info.get("buyerBankAccount") or buyer_bank_account
            r_email = buyer_info.get("email") or buyer_info.get("recipientEmail") or recipient_email
            r_phone = buyer_info.get("phone") or buyer_info.get("recipientPhone") or recipient_phone
        else:
            b_type = buyer_type or "individual"
            b_name = buyer_name or ""
            b_tax = buyer_tax_number
            b_addr = buyer_address_phone
            b_bank = buyer_bank_account
            r_email = recipient_email
            r_phone = recipient_phone

        validate_buyer_info(b_type, b_name, b_tax)
        current_time = _current(now)
        current_iso = current_time.isoformat()

        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM customer_invoice_self_service WHERE session_token=?",
                (session_token,),
            ).fetchone()
            if not row:
                raise ValidationError("self-service session not found")
            if row["status"] != "ACTIVE":
                raise ValidationError(f"self-service session already redeemed or invalid: {row['status']}")
            if row["expires_at"] <= current_iso:
                raise ValidationError("self-service session has expired")

            cur = conn.execute(
                "UPDATE customer_invoice_self_service SET status='REDEEMED', redeemed_at=? "
                "WHERE session_token=? AND status='ACTIVE'",
                (current_iso, session_token),
            )
            if cur.rowcount == 0:
                raise ValidationError("self-service session already redeemed")

            tenant_id = row["tenant_id"]
            project_id = row["project_id"]
            pi_id = row["payment_intent_id"]
            captured_minor = row["captured_amount_minor"]
            seller_name = row["seller_name"]
            seller_tax = row["seller_tax_number"]
            currency = row["currency"]

        r = tax_rate_basis_points
        u = (captured_minor * 10000 + (10000 + r) // 2) // (10000 + r)
        tax = (u * r + 5000) // 10000
        diff = captured_minor - (u + tax)

        items = [
            {
                "itemName": item_name,
                "quantity": 1,
                "unitPriceMinor": u + diff,
                "taxRateBasisPoints": r,
                "taxClassificationCode": tax_classification_code,
            }
        ]

        applied = self.apply_invoice(
            tenant_id=tenant_id,
            project_id=project_id,
            payment_intent_id=pi_id,
            captured_amount_minor=captured_minor,
            refunded_amount_minor=0,
            invoice_type=invoice_type,
            buyer_type=b_type,
            buyer_name=b_name,
            buyer_tax_number=b_tax,
            buyer_address_phone=b_addr,
            buyer_bank_account=b_bank,
            recipient_email=r_email,
            recipient_phone=r_phone,
            seller_name=seller_name,
            seller_tax_number=seller_tax,
            operator="self_service_customer",
            items=items,
            idempotency_key=f"self_service_{session_token[:16]}",
            currency=currency,
            now=now,
        )

        issued = self.issue_invoice(
            tenant_id,
            applied["invoiceId"],
            actor="actor_self_service",
            checker="系统自动复核",
            payee=seller_name,
            now=now,
        )

        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE customer_invoice_self_service SET redeemed_invoice_id=? WHERE session_token=?",
                (issued["invoiceId"], session_token),
            )

        return issued

    # --- VAT Declaration & Tax Return Summary ---
    def generate_tax_declaration_summary(
        self,
        tenant_id: str,
        year: int | None = None,
        month: int | None = None,
        tax_period: str | None = None,
        payments: Sequence[Mapping[str, Any]] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Aggregate VAT declaration summary grouped by tax rate brackets."""
        if tax_period:
            parts = tax_period.split("-")
            year = int(parts[0])
            month = int(parts[1])
        elif year is None or month is None:
            ct = _current(now)
            year = ct.year
            month = ct.month

        start_prefix = f"{year:04d}-{month:02d}-01T"
        if month == 12:
            end_prefix = f"{year+1:04d}-01-01T"
        else:
            end_prefix = f"{year:04d}-{month+1:02d}-01T"

        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT ci.invoice_id, ci.invoice_category, ci.status, "
                "cii.tax_rate_basis_points, cii.amount_minor, cii.tax_amount_minor "
                "FROM customer_invoice ci "
                "JOIN customer_invoice_item cii ON ci.invoice_id = cii.invoice_id "
                "WHERE ci.tenant_id=? AND ci.status IN ('ISSUED', 'RED_NOTED') "
                "AND ci.created_at >= ? AND ci.created_at < ?",
                (tenant_id, start_prefix, end_prefix),
            ).fetchall()

            brackets: dict[int, dict[str, int]] = {}
            seen_invoices: set[tuple[int, str, str]] = set()

            for r in rows:
                rate = r["tax_rate_basis_points"]
                cat = r["invoice_category"]
                inv_id = r["invoice_id"]
                if rate not in brackets:
                    brackets[rate] = {
                        "taxRateBasisPoints": rate,
                        "blueInvoiceCount": 0,
                        "blueUntaxedMinor": 0,
                        "blueTaxMinor": 0,
                        "blueTotalMinor": 0,
                        "redInvoiceCount": 0,
                        "redUntaxedMinor": 0,
                        "redTaxMinor": 0,
                        "redTotalMinor": 0,
                        "netSalesUntaxedMinor": 0,
                        "netOutputTaxMinor": 0,
                        "netTotalMinor": 0,
                    }

                b = brackets[rate]
                inv_key = (rate, cat, inv_id)
                if inv_key not in seen_invoices:
                    seen_invoices.add(inv_key)
                    if cat == "blue":
                        b["blueInvoiceCount"] += 1
                    else:
                        b["redInvoiceCount"] += 1

                amt = r["amount_minor"]
                tax = r["tax_amount_minor"]
                if cat == "blue":
                    b["blueUntaxedMinor"] += amt
                    b["blueTaxMinor"] += tax
                    b["blueTotalMinor"] += (amt + tax)
                else:
                    b["redUntaxedMinor"] += (-amt if amt < 0 else amt)
                    b["redTaxMinor"] += (-tax if tax < 0 else tax)
                    b["redTotalMinor"] += (-amt - tax if amt < 0 else amt + tax)

                b["netSalesUntaxedMinor"] += amt
                b["netOutputTaxMinor"] += tax
                b["netTotalMinor"] += (amt + tax)

            total_invoiced_net = sum(b["netTotalMinor"] for b in brackets.values())

            uninvoiced_sales = 0
            if payments:
                total_captured_net = 0
                for p in payments:
                    cap = int(p.get("capturedAmountMinor", 0))
                    ref = int(p.get("refundedAmountMinor", 0))
                    total_captured_net += max(0, cap - ref)
                uninvoiced_sales = max(0, total_captured_net - total_invoiced_net)

            sorted_brackets = [brackets[k] for k in sorted(brackets.keys(), reverse=True)]

            summary_totals = {
                "totalBlueCount": sum(b["blueInvoiceCount"] for b in sorted_brackets),
                "totalRedCount": sum(b["redInvoiceCount"] for b in sorted_brackets),
                "totalNetSalesUntaxedMinor": sum(b["netSalesUntaxedMinor"] for b in sorted_brackets),
                "totalNetOutputTaxMinor": sum(b["netOutputTaxMinor"] for b in sorted_brackets),
                "totalNetTotalMinor": total_invoiced_net,
                "totalNetMinor": total_invoiced_net,
                "uninvoicedSalesMinor": uninvoiced_sales,
            }

            return {
                "tenantId": tenant_id,
                "taxPeriod": f"{year:04d}-{month:02d}",
                "year": year,
                "month": month,
                "taxRateBrackets": sorted_brackets,
                "totals": summary_totals,
            }

    @staticmethod
    def export_tax_declaration_csv(summary: Mapping[str, Any]) -> str:
        """Export VAT declaration summary into CSV table."""
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow([
            "税率(%)", "蓝字发票份数", "蓝字销售额(元)", "蓝字销项税额(元)",
            "红字发票份数", "红字销售额(元)", "红字销项税额(元)",
            "净销售额(元)", "净销项税额(元)", "价税合计(元)"
        ])
        for b in summary.get("taxRateBrackets", []):
            rate_pct = f"{b['taxRateBasisPoints'] / 100:.1f}%"
            writer.writerow([
                rate_pct,
                b["blueInvoiceCount"],
                f"{b['blueUntaxedMinor'] / 100:.2f}",
                f"{b['blueTaxMinor'] / 100:.2f}",
                b["redInvoiceCount"],
                f"{b['redUntaxedMinor'] / 100:.2f}",
                f"{b['redTaxMinor'] / 100:.2f}",
                f"{b['netSalesUntaxedMinor'] / 100:.2f}",
                f"{b['netOutputTaxMinor'] / 100:.2f}",
                f"{b['netTotalMinor'] / 100:.2f}",
            ])
        t = summary.get("totals", {})
        writer.writerow([
            "合计",
            t.get("totalBlueCount", 0),
            "",
            "",
            t.get("totalRedCount", 0),
            "",
            "",
            f"{t.get('totalNetSalesUntaxedMinor', 0) / 100:.2f}",
            f"{t.get('totalNetOutputTaxMinor', 0) / 100:.2f}",
            f"{t.get('totalNetTotalMinor', 0) / 100:.2f}",
        ])
        if t.get("uninvoicedSalesMinor"):
            writer.writerow(["未开票销售额(元)", "", "", "", "", "", "", f"{t['uninvoicedSalesMinor'] / 100:.2f}", "", ""])
        return out.getvalue()

    # --- Subscription & Periodic Billing Auto-Invoicing ---
    def auto_invoice_subscription_billing(
        self,
        *,
        tenant_id: str,
        subscription_id: str,
        billing_cycle: str | None = None,
        amount_minor: int,
        plan_name: str = "企业SaaS专业版订阅",
        buyer_info: dict[str, Any] | None = None,
        operator: str = "subscription_billing_worker",
        tax_rate_basis_points: int = 600,
        tax_classification_code: str = "3040201010000000000",
        project_id: str = "proj_subscription",
        seller_name: str = "榆钱儿企业服务（北京）有限公司",
        seller_tax_number: str = "91110105MA02YYYYYY",
        cycle_index: int = 1,
        period_start: str | None = None,
        period_end: str | None = None,
        buyer_title_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Auto-invoice recurring subscription billing cycle."""
        if buyer_info:
            buyer_type = buyer_info.get("buyerType") or ("enterprise" if (buyer_info.get("taxNumber") or buyer_info.get("taxId")) else "individual")
            buyer_name = buyer_info.get("name") or buyer_info.get("buyerName") or "企业客户"
            buyer_tax_number = buyer_info.get("taxNumber") or buyer_info.get("taxId")
            buyer_address_phone = buyer_info.get("addressPhone")
            buyer_bank_account = buyer_info.get("bankAccount")
            recipient_email = buyer_info.get("email")
            recipient_phone = buyer_info.get("phone")
        else:
            title = self.get_buyer_title(tenant_id, buyer_title_id)
            if not title:
                raise ValidationError(f"buyer title not found: {buyer_title_id or 'default'}")
            buyer_type = title["buyerType"]
            buyer_name = title["buyerName"]
            buyer_tax_number = title.get("buyerTaxNumber")
            buyer_address_phone = title.get("buyerAddressPhone")
            buyer_bank_account = title.get("buyerBankAccount")
            recipient_email = title.get("recipientEmail")
            recipient_phone = title.get("recipientPhone")

        if billing_cycle:
            item_desc = f"{plan_name} ({billing_cycle} 账期)"
            idempotency_key = f"sub_{subscription_id}_{billing_cycle}"
            pi_id = f"pi_sub_{subscription_id}_{billing_cycle}"
        else:
            clean_start = (period_start or "2026-01-01")[:10]
            clean_end = (period_end or "2026-01-31")[:10]
            item_desc = f"{plan_name} ({clean_start} 至 {clean_end}, 第{cycle_index}期)"
            idempotency_key = f"sub_{subscription_id}_cycle_{cycle_index}"
            pi_id = f"pi_sub_{subscription_id}_{cycle_index}"

        r = tax_rate_basis_points
        u = (amount_minor * 10000 + (10000 + r) // 2) // (10000 + r)
        tax = (u * r + 5000) // 10000
        diff = amount_minor - (u + tax)

        items = [
            {
                "itemName": item_desc,
                "quantity": 1,
                "unitPriceMinor": u + diff,
                "taxRateBasisPoints": r,
                "taxClassificationCode": tax_classification_code,
            }
        ]

        applied = self.apply_invoice(
            tenant_id=tenant_id,
            project_id=project_id,
            payment_intent_id=pi_id,
            captured_amount_minor=amount_minor,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type=buyer_type,
            buyer_name=buyer_name,
            buyer_tax_number=buyer_tax_number,
            buyer_address_phone=buyer_address_phone,
            buyer_bank_account=buyer_bank_account,
            recipient_email=recipient_email,
            recipient_phone=recipient_phone,
            seller_name=seller_name,
            seller_tax_number=seller_tax_number,
            operator=operator,
            items=items,
            idempotency_key=idempotency_key,
            now=now,
        )

        if applied.get("isIdempotentReplay"):
            return applied

        issued = self.issue_invoice(
            tenant_id,
            applied["invoiceId"],
            actor="actor_subscription_engine",
            checker="系统自动复核",
            payee=seller_name,
            now=now,
        )
        return issued


export_tax_declaration_csv = CustomerInvoiceLedger.export_tax_declaration_csv

