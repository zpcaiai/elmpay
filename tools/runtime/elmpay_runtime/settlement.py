"""Enterprise merchant settlement, revenue split, clearing batches and payout ledger."""
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


def _sha256_canonical(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj)).hexdigest()


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


class SettlementLedger:
    """Enterprise merchant settlement, revenue split, and payout execution ledger."""

    def __init__(self, database: str | DurableStore) -> None:
        if isinstance(database, DurableStore):
            self.store = database
        else:
            self.store = DurableStore(database)

    def configure_merchant_settlement(
        self,
        tenant_id: str,
        project_id: str,
        *,
        currency: str = "CNY",
        settlement_cycle: str = "T_PLUS_1",
        minimum_payout_minor: int = 1000,
        commission_basis_points: int = 30,
        channel_fee_basis_points: int = 38,
        reserve_holdback_basis_points: int = 500,
        bank_name: str,
        bank_account_number: str,
        bank_account_name: str,
        status: str = "ACTIVE",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Create or update merchant settlement configuration and revenue split parameters."""
        require_text(tenant_id, "tenant_id")
        require_text(project_id, "project_id")
        require_text(bank_name, "bank_name")
        require_text(bank_account_number, "bank_account_number")
        require_text(bank_account_name, "bank_account_name")

        currency = currency.strip().upper()
        if len(currency) != 3:
            raise ValidationError("currency must be a 3-letter ISO code")

        settlement_cycle = settlement_cycle.upper()
        if settlement_cycle not in ("T_PLUS_0", "T_PLUS_1", "WEEKLY", "MONTHLY"):
            raise ValidationError(f"unsupported settlement cycle: {settlement_cycle}")

        for name, bp in (
            ("commission_basis_points", commission_basis_points),
            ("channel_fee_basis_points", channel_fee_basis_points),
            ("reserve_holdback_basis_points", reserve_holdback_basis_points),
        ):
            if bp < 0 or bp > 10000:
                raise ValidationError(f"{name} must be between 0 and 10000 basis points")

        if minimum_payout_minor < 0:
            raise ValidationError("minimum_payout_minor cannot be negative")

        status = status.upper()
        if status not in ("ACTIVE", "SUSPENDED"):
            raise ValidationError(f"invalid status: {status}")

        current_iso = _instant(now)
        config_id = f"cfg_{uuid.uuid4().hex[:16]}"

        with self.store.connect() as conn:
            existing = conn.execute(
                "SELECT config_id FROM merchant_settlement_config WHERE tenant_id=? AND project_id=? AND currency=?",
                (tenant_id, project_id, currency),
            ).fetchone()

            if existing:
                cid = existing["config_id"]
                conn.execute(
                    "UPDATE merchant_settlement_config SET "
                    "settlement_cycle=?, minimum_payout_minor=?, commission_basis_points=?, "
                    "channel_fee_basis_points=?, reserve_holdback_basis_points=?, bank_name=?, "
                    "bank_account_number=?, bank_account_name=?, status=?, updated_at=? "
                    "WHERE config_id=?",
                    (
                        settlement_cycle,
                        minimum_payout_minor,
                        commission_basis_points,
                        channel_fee_basis_points,
                        reserve_holdback_basis_points,
                        bank_name,
                        bank_account_number,
                        bank_account_name,
                        status,
                        current_iso,
                        cid,
                    ),
                )
                config_id = cid
            else:
                conn.execute(
                    "INSERT INTO merchant_settlement_config ("
                    "config_id, tenant_id, project_id, currency, settlement_cycle, minimum_payout_minor, "
                    "commission_basis_points, channel_fee_basis_points, reserve_holdback_basis_points, "
                    "bank_name, bank_account_number, bank_account_name, status, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        config_id,
                        tenant_id,
                        project_id,
                        currency,
                        settlement_cycle,
                        minimum_payout_minor,
                        commission_basis_points,
                        channel_fee_basis_points,
                        reserve_holdback_basis_points,
                        bank_name,
                        bank_account_number,
                        bank_account_name,
                        status,
                        current_iso,
                        current_iso,
                    ),
                )

        return self.get_merchant_settlement_config(tenant_id, project_id, currency=currency)

    def get_merchant_settlement_config(
        self,
        tenant_id: str,
        project_id: str,
        currency: str = "CNY",
    ) -> dict[str, Any]:
        """Retrieve merchant settlement configuration."""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM merchant_settlement_config WHERE tenant_id=? AND project_id=? AND currency=?",
                (tenant_id, project_id, currency.strip().upper()),
            ).fetchone()
        if not row:
            raise ValidationError(f"merchant settlement config not found: {tenant_id}:{project_id}:{currency}")
        return {
            "configId": row["config_id"],
            "tenantId": row["tenant_id"],
            "projectId": row["project_id"],
            "currency": row["currency"],
            "settlementCycle": row["settlement_cycle"],
            "minimumPayoutMinor": row["minimum_payout_minor"],
            "commissionBasisPoints": row["commission_basis_points"],
            "channelFeeBasisPoints": row["channel_fee_basis_points"],
            "reserveHoldbackBasisPoints": row["reserve_holdback_basis_points"],
            "bankName": row["bank_name"],
            "bankAccountNumber": row["bank_account_number"],
            "bankAccountName": row["bank_account_name"],
            "status": row["status"],
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def calculate_settlement_batch(
        self,
        tenant_id: str,
        project_id: str,
        *,
        period_start: str,
        period_end: str,
        transactions: Sequence[Mapping[str, Any]],
        operator: str,
        currency: str = "CNY",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Calculate settlement clearing batch and multi-party revenue split for a given period."""
        config = self.get_merchant_settlement_config(tenant_id, project_id, currency=currency)
        if config["status"] != "ACTIVE":
            raise ValidationError(f"merchant settlement is suspended for {tenant_id}:{project_id}")

        require_text(operator, "operator")
        current_iso = _instant(now)
        batch_id = f"stl_{uuid.uuid4().hex[:16]}"
        date_tag = current_iso[:10].replace("-", "")
        batch_number = f"STL-{date_tag}-{tenant_id[:4].upper()}-{uuid.uuid4().hex[:6].upper()}"

        gross_captured = sum(int(t.get("capturedAmountMinor", 0)) for t in transactions)
        gross_refunded = sum(int(t.get("refundedAmountMinor", 0)) for t in transactions)
        net_captured = max(0, gross_captured - gross_refunded)

        channel_fee_bp = int(config["channelFeeBasisPoints"])
        commission_bp = int(config["commissionBasisPoints"])
        reserve_bp = int(config["reserveHoldbackBasisPoints"])

        channel_fee = (gross_captured * channel_fee_bp) // 10000
        commission = (net_captured * commission_bp) // 10000
        reserve = (net_captured * reserve_bp) // 10000

        total_deductions = channel_fee + commission + reserve
        net_payout = max(0, net_captured - total_deductions)

        min_payout = int(config["minimumPayoutMinor"])
        initial_status = "CALCULATED" if net_payout >= min_payout else "ON_HOLD"

        batch_payload = {
            "batchId": batch_id,
            "tenantId": tenant_id,
            "projectId": project_id,
            "batchNumber": batch_number,
            "periodStart": period_start,
            "periodEnd": period_end,
            "currency": currency,
            "totalTransactions": len(transactions),
            "grossCapturedMinor": gross_captured,
            "grossRefundedMinor": gross_refunded,
            "netCapturedMinor": net_captured,
            "channelFeeMinor": channel_fee,
            "platformCommissionMinor": commission,
            "reserveHoldbackMinor": reserve,
            "netPayoutMinor": net_payout,
            "status": initial_status,
            "createdBy": operator,
            "createdAt": current_iso,
        }

        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO merchant_settlement_batch ("
                "batch_id, tenant_id, project_id, batch_number, period_start, period_end, currency, "
                "total_transactions, gross_captured_minor, gross_refunded_minor, net_captured_minor, "
                "channel_fee_minor, platform_commission_minor, reserve_holdback_minor, net_payout_minor, "
                "status, created_by, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    batch_id,
                    tenant_id,
                    project_id,
                    batch_number,
                    period_start,
                    period_end,
                    currency,
                    len(transactions),
                    gross_captured,
                    gross_refunded,
                    net_captured,
                    channel_fee,
                    commission,
                    reserve,
                    net_payout,
                    initial_status,
                    operator,
                    current_iso,
                    current_iso,
                ),
            )
            self._record_audit(
                conn,
                tenant_id=tenant_id,
                batch_id=batch_id,
                event_type="BATCH_CALCULATED",
                actor_id=operator,
                occurred_at=current_iso,
                payload=batch_payload,
            )

        return self.get_settlement_batch(tenant_id, batch_id)

    def get_settlement_batch(self, tenant_id: str, batch_id: str) -> dict[str, Any]:
        """Retrieve settlement clearing batch details."""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM merchant_settlement_batch WHERE tenant_id=? AND batch_id=?",
                (tenant_id, batch_id),
            ).fetchone()
        if not row:
            raise ValidationError(f"settlement batch not found: {batch_id}")
        return {
            "batchId": row["batch_id"],
            "tenantId": row["tenant_id"],
            "projectId": row["project_id"],
            "batchNumber": row["batch_number"],
            "periodStart": row["period_start"],
            "periodEnd": row["period_end"],
            "currency": row["currency"],
            "totalTransactions": row["total_transactions"],
            "grossCapturedMinor": row["gross_captured_minor"],
            "grossRefundedMinor": row["gross_refunded_minor"],
            "netCapturedMinor": row["net_captured_minor"],
            "channelFeeMinor": row["channel_fee_minor"],
            "platformCommissionMinor": row["platform_commission_minor"],
            "reserveHoldbackMinor": row["reserve_holdback_minor"],
            "netPayoutMinor": row["net_payout_minor"],
            "status": row["status"],
            "createdBy": row["created_by"],
            "approvedBy": row["approved_by"],
            "executedBy": row["executed_by"],
            "bankReferenceId": row["bank_reference_id"],
            "executedAt": row["executed_at"],
            "payoutInstructionDigest": row["payout_instruction_digest"],
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def approve_settlement_payout(
        self,
        tenant_id: str,
        batch_id: str,
        *,
        approver: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Four-eyes approval of merchant payout batch. The approver cannot be the batch creator."""
        require_text(approver, "approver")
        batch = self.get_settlement_batch(tenant_id, batch_id)

        if batch["createdBy"] == approver:
            raise ValidationError("four-eyes principle violation: batch creator cannot approve payout")

        if batch["status"] not in ("CALCULATED", "PENDING_APPROVAL"):
            raise ValidationError(f"cannot approve settlement batch in status: {batch['status']}")

        current_iso = _instant(now)
        audit_payload = {
            "batchId": batch_id,
            "previousStatus": batch["status"],
            "newStatus": "APPROVED",
            "approvedBy": approver,
            "approvedAt": current_iso,
        }

        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE merchant_settlement_batch SET status='APPROVED', approved_by=?, updated_at=? "
                "WHERE tenant_id=? AND batch_id=?",
                (approver, current_iso, tenant_id, batch_id),
            )
            self._record_audit(
                conn,
                tenant_id=tenant_id,
                batch_id=batch_id,
                event_type="PAYOUT_APPROVED",
                actor_id=approver,
                occurred_at=current_iso,
                payload=audit_payload,
            )

        return self.get_settlement_batch(tenant_id, batch_id)

    def execute_settlement_payout(
        self,
        tenant_id: str,
        batch_id: str,
        *,
        executor: str,
        bank_reference_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Mark settlement payout as executed with banking transfer reference."""
        require_text(executor, "executor")
        require_text(bank_reference_id, "bank_reference_id")

        batch = self.get_settlement_batch(tenant_id, batch_id)
        if batch["status"] != "APPROVED":
            raise ValidationError(f"settlement batch must be APPROVED before execution; current: {batch['status']}")

        current_iso = _instant(now)
        instruction_digest = hashlib.sha256(
            f"{batch_id}:{bank_reference_id}:{batch['netPayoutMinor']}:{current_iso}".encode("utf-8")
        ).hexdigest()

        audit_payload = {
            "batchId": batch_id,
            "bankReferenceId": bank_reference_id,
            "executedBy": executor,
            "executedAt": current_iso,
            "payoutInstructionDigest": instruction_digest,
            "netPayoutMinor": batch["netPayoutMinor"],
        }

        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE merchant_settlement_batch SET status='EXECUTED', executed_by=?, "
                "bank_reference_id=?, executed_at=?, payout_instruction_digest=?, updated_at=? "
                "WHERE tenant_id=? AND batch_id=?",
                (executor, bank_reference_id, current_iso, instruction_digest, current_iso, tenant_id, batch_id),
            )
            self._record_audit(
                conn,
                tenant_id=tenant_id,
                batch_id=batch_id,
                event_type="PAYOUT_EXECUTED",
                actor_id=executor,
                occurred_at=current_iso,
                payload=audit_payload,
            )

        return self.get_settlement_batch(tenant_id, batch_id)

    def export_payout_instructions(
        self,
        tenant_id: str,
        batch_id: str,
        *,
        format_type: str = "csv",
    ) -> str:
        """Export standardized banking batch payout instructions file."""
        batch = self.get_settlement_batch(tenant_id, batch_id)
        config = self.get_merchant_settlement_config(tenant_id, batch["projectId"], currency=batch["currency"])

        payout_yuan = f"{batch['netPayoutMinor'] / 100:.2f}"

        if format_type.lower() == "json":
            data = {
                "batchNumber": batch["batchNumber"],
                "tenantId": tenant_id,
                "projectId": batch["projectId"],
                "currency": batch["currency"],
                "payoutAmountYuan": payout_yuan,
                "payoutAmountMinor": batch["netPayoutMinor"],
                "recipientBank": config["bankName"],
                "recipientAccountNumber": config["bankAccountNumber"],
                "recipientAccountName": config["bankAccountName"],
                "status": batch["status"],
                "bankReferenceId": batch.get("bankReferenceId") or "",
                "manifestDigest": _sha256_canonical(batch),
            }
            return json.dumps(data, indent=2, ensure_ascii=False)

        # Default CSV format for direct corporate online banking (网银批量代付)
        headers = [
            "批次号", "商户租户", "币种", "结算出金金额(元)", "收款银行",
            "收款人银行账号", "收款人户名", "出金状态", "银行参考号"
        ]
        row = [
            batch["batchNumber"],
            tenant_id,
            batch["currency"],
            payout_yuan,
            config["bankName"],
            config["bankAccountNumber"],
            config["bankAccountName"],
            batch["status"],
            batch.get("bankReferenceId") or "PENDING",
        ]
        return ",".join(headers) + "\n" + ",".join(f'"{c}"' for c in row) + "\n"

    def verify_settlement_audit_chain(self, tenant_id: str, batch_id: str) -> bool:
        """Cryptographically verify the tamper-evident SHA-256 audit chain for a settlement batch."""
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM merchant_settlement_audit WHERE tenant_id=? AND batch_id=? ORDER BY audit_id ASC",
                (tenant_id, batch_id),
            ).fetchall()

        if not rows:
            raise ValidationError(f"no audit records found for settlement batch: {batch_id}")

        prev_digest: str | None = None
        for r in rows:
            payload_json = r["payload_json"]
            payload_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
            if payload_digest != r["payload_digest"]:
                return False

            if r["previous_digest"] != prev_digest:
                return False

            expected_event_digest = hashlib.sha256(
                f"{r['tenant_id']}:{r['batch_id']}:{r['event_type']}:{r['actor_id']}:{r['occurred_at']}:{payload_digest}:{prev_digest or ''}".encode("utf-8")
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
        batch_id: str,
        event_type: str,
        actor_id: str,
        occurred_at: str,
        payload: Mapping[str, Any],
    ) -> None:
        payload_json = canonical_json(payload).decode("utf-8")
        payload_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

        last_row = conn.execute(
            "SELECT event_digest FROM merchant_settlement_audit WHERE tenant_id=? AND batch_id=? ORDER BY audit_id DESC LIMIT 1",
            (tenant_id, batch_id),
        ).fetchone()
        previous_digest = last_row["event_digest"] if last_row else None

        event_digest = hashlib.sha256(
            f"{tenant_id}:{batch_id}:{event_type}:{actor_id}:{occurred_at}:{payload_digest}:{previous_digest or ''}".encode("utf-8")
        ).hexdigest()

        conn.execute(
            "INSERT INTO merchant_settlement_audit ("
            "tenant_id, batch_id, event_type, actor_id, occurred_at, payload_digest, previous_digest, event_digest, payload_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                batch_id,
                event_type,
                actor_id,
                occurred_at,
                payload_digest,
                previous_digest,
                event_digest,
                payload_json,
            ),
        )


def render_settlement_html(batch_detail: Mapping[str, Any], config: Mapping[str, Any] | None = None) -> str:
    """Render executive printable Merchant Settlement Reconciliation Statement."""
    batch_num = str(batch_detail.get("batchNumber", ""))
    tenant_id = str(batch_detail.get("tenantId", ""))
    project_id = str(batch_detail.get("projectId", ""))
    currency = str(batch_detail.get("currency", "CNY"))
    status = str(batch_detail.get("status", ""))
    p_start = str(batch_detail.get("periodStart", ""))[:10]
    p_end = str(batch_detail.get("periodEnd", ""))[:10]

    gross_cap = int(batch_detail.get("grossCapturedMinor", 0)) / 100
    gross_ref = int(batch_detail.get("grossRefundedMinor", 0)) / 100
    net_cap = int(batch_detail.get("netCapturedMinor", 0)) / 100
    fee = int(batch_detail.get("channelFeeMinor", 0)) / 100
    comm = int(batch_detail.get("platformCommissionMinor", 0)) / 100
    res = int(batch_detail.get("reserveHoldbackMinor", 0)) / 100
    net_payout = int(batch_detail.get("netPayoutMinor", 0)) / 100

    cfg = config or {}
    bank_name = str(cfg.get("bankName") or "待配置银行")
    acc_num = str(cfg.get("bankAccountNumber") or "---")
    acc_name = str(cfg.get("bankAccountName") or "商户结算账户")

    created_by = str(batch_detail.get("createdBy") or "系统清算引擎")
    approved_by = str(batch_detail.get("approvedBy") or "待四眼审批")
    executed_by = str(batch_detail.get("executedBy") or "---")
    bank_ref = str(batch_detail.get("bankReferenceId") or "---")

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>商户结算清算对账凭单 - {_escape_html(batch_num)}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      background-color: #f8fafc;
      color: #1e293b;
      padding: 32px;
      display: flex;
      justify-content: center;
    }}
    .settlement-card {{
      width: 100%;
      max-width: 880px;
      background: #ffffff;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      padding: 36px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
      position: relative;
    }}
    .header {{
      border-bottom: 2px solid #0f172a;
      padding-bottom: 16px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }}
    .title-main {{ font-size: 24px; font-weight: bold; color: #0f172a; }}
    .title-sub {{ font-size: 13px; color: #64748b; margin-top: 4px; }}
    .batch-badge {{
      font-family: monospace;
      font-size: 14px;
      font-weight: bold;
      color: #2563eb;
      background: #eff6ff;
      border: 1px solid #bfdbfe;
      padding: 4px 10px;
      border-radius: 4px;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }}
    .kpi-box {{
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 14px;
      text-align: center;
    }}
    .kpi-label {{ font-size: 11px; color: #64748b; margin-bottom: 4px; }}
    .kpi-value {{ font-size: 18px; font-weight: bold; }}
    .table-section {{ margin-bottom: 24px; }}
    .section-title {{ font-size: 14px; font-weight: 600; color: #334155; margin-bottom: 8px; }}
    table.data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }}
    table.data-table th, table.data-table td {{
      border: 1px solid #cbd5e1;
      padding: 8px 12px;
    }}
    table.data-table th {{ background: #f1f5f9; color: #475569; text-align: left; }}
    .payout-highlight {{
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      border-radius: 6px;
      padding: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
    }}
    .footer-signatures {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      font-size: 12px;
      color: #475569;
      border-top: 1px dashed #cbd5e1;
      padding-top: 16px;
    }}
  </style>
</head>
<body>
  <div class="settlement-card">
    <div class="header">
      <div>
        <div class="title-main">商户结算与分账对账凭单</div>
        <div class="title-sub">ELMPay Enterprise Settlement & Revenue Split Statement</div>
      </div>
      <div>
        <span class="batch-badge">{_escape_html(batch_num)}</span>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="kpi-box">
        <div class="kpi-label">总交易流水</div>
        <div class="kpi-value">¥{gross_cap:.2f}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">退款冲抵</div>
        <div class="kpi-value" style="color:#ef4444;">-¥{gross_ref:.2f}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">费用及佣金</div>
        <div class="kpi-value" style="color:#f59e0b;">-¥{fee + comm:.2f}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">风险质保留存</div>
        <div class="kpi-value" style="color:#6366f1;">¥{res:.2f}</div>
      </div>
    </div>

    <div class="payout-highlight">
      <div>
        <div style="font-size:12px; color:#15803d; font-weight:600;">本期应结净出金 (Net Payable)</div>
        <div style="font-size:11px; color:#64748b;">结算周期: {_escape_html(p_start)} 至 {_escape_html(p_end)} &nbsp;|&nbsp; 状态: {_escape_html(status)}</div>
      </div>
      <div style="font-size:24px; font-weight:bold; color:#16a34a;">¥{net_payout:.2f} <span style="font-size:14px;">{_escape_html(currency)}</span></div>
    </div>

    <div class="table-section">
      <div class="section-title">分账与费用组成明细 (Revenue Split Breakdown)</div>
      <table class="data-table">
        <thead>
          <tr>
            <th>费用科目</th>
            <th>计算基准</th>
            <th>费率基点</th>
            <th style="text-align:right;">金额 (元)</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>支付渠道成本费 (Channel Fee)</td>
            <td>总捕获流水 ¥{gross_cap:.2f}</td>
            <td>{cfg.get("channelFeeBasisPoints", 38)} BP</td>
            <td style="text-align:right;">¥{fee:.2f}</td>
          </tr>
          <tr>
            <td>平台技术服务抽佣 (Commission)</td>
            <td>净交易额 ¥{net_cap:.2f}</td>
            <td>{cfg.get("commissionBasisPoints", 30)} BP</td>
            <td style="text-align:right;">¥{comm:.2f}</td>
          </tr>
          <tr>
            <td>风险质保金预留 (Reserve Holdback)</td>
            <td>净交易额 ¥{net_cap:.2f}</td>
            <td>{cfg.get("reserveHoldbackBasisPoints", 500)} BP</td>
            <td style="text-align:right;">¥{res:.2f}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="table-section">
      <div class="section-title">打款到账银行账户 (Payout Destination)</div>
      <table class="data-table">
        <tr>
          <td style="width:20%; font-weight:600; background:#f8fafc;">开户银行</td>
          <td>{_escape_html(bank_name)}</td>
          <td style="width:20%; font-weight:600; background:#f8fafc;">开户户名</td>
          <td>{_escape_html(acc_name)}</td>
        </tr>
        <tr>
          <td style="font-weight:600; background:#f8fafc;">银行账号</td>
          <td style="font-family:monospace; font-weight:bold;">{_escape_html(acc_num)}</td>
          <td style="font-weight:600; background:#f8fafc;">打款参考号</td>
          <td style="font-family:monospace;">{_escape_html(bank_ref)}</td>
        </tr>
      </table>
    </div>

    <div class="footer-signatures">
      <div>清算制单: {_escape_html(created_by)}</div>
      <div>四眼复核: {_escape_html(approved_by)}</div>
      <div>打款执行: {_escape_html(executed_by)}</div>
    </div>
  </div>
</body>
</html>
"""
