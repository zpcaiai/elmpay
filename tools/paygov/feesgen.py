"""B29 — generate the fee model contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

FEES = Path("governance/fee-model.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/fee-model.json\n"
             "     Regenerate with: python3 scripts/render-fees.py -->\n")
SCHEDULE_FIELDS = ("id", "category", "basis", "provider", "method", "region",
                   "currency", "percentage_bp", "fixed_minor", "min_minor",
                   "max_minor")


def _without_notes(block: dict) -> dict:
    return {k: v for k, v in sorted(block.items()) if k != "notes"}


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / FEES)
    schedules = []
    for entry in sorted(model["schedules"], key=lambda s: s["id"]):
        budget.check(entry["id"])
        schedules.append({field: entry[field] for field in SCHEDULE_FIELDS})
    document = {
        "_generated": "GENERATED FILE — scripts/render-fees.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "categories": [{"id": c["id"], "is_revenue": c["is_revenue"],
                        "charged_to_merchant": c["charged_to_merchant"],
                        "remitted_to_authority": c["remitted_to_authority"]}
                       for c in sorted(model["categories"], key=lambda x: x["id"])],
        "rounding": _without_notes(model["rounding"]),
        "schedules": schedules,
        "settlement": _without_notes(model["settlement"]),
        "split": {**_without_notes(model["split"]),
                  "parties": sorted(model["split"]["parties"])},
        "currency": {**_without_notes(model["currency"]),
                     "rate_record_fields": sorted(model["currency"]["rate_record_fields"])},
        "metering": _without_notes(model["metering"]),
        "audit_event_class": model["audit_event_class"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def fees_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / FEES)
    rounding = model["rounding"]
    settlement = model["settlement"]
    split = model["split"]
    currency = model["currency"]
    metering = model["metering"]

    out = [MD_BANNER, "# 费率、成本、佣金与计量模型（B29）", "", model["principle"], "",
           "## 费用类别", "",
           "| 类别 | 是收入 | 向商户收取 | 代收代缴 | 说明 |",
           "| --- | --- | --- | --- | --- |"]
    for entry in model["categories"]:
        budget.check(entry["id"])
        out.append(f"| `{entry['id']}` | {'是' if entry['is_revenue'] else '否'} | "
                   f"{'是' if entry['charged_to_merchant'] else '否'} | "
                   f"{'是' if entry['remitted_to_authority'] else '否'} | {entry['notes']} |")

    out += ["", "## 舍入", "",
            f"- 方式：`{rounding['mode']}`，单位：{rounding['unit']}",
            f"- 各部分之和必须等于总额：{'是' if rounding['sum_must_equal_total'] else '否'}",
            f"- 余数归属：`{rounding['remainder_owner']}`",
            "", rounding["notes"], "",
            "## 费率表", "",
            "| 编号 | 类别 | 计算基数 | 渠道 | 方式 | 地区 | 币种 | 百分比(基点) | 固定(最小单位) | 下限 | 封顶 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for entry in sorted(model["schedules"], key=lambda s: s["id"]):
        budget.check(entry["id"])
        out.append(f"| `{entry['id']}` | `{entry['category']}` | `{entry['basis']}` | "
                   f"`{entry['provider']}` | "
                   f"`{entry['method']}` | {entry['region']} | {entry['currency']} | "
                   f"{entry['percentage_bp']} | {entry['fixed_minor']} | "
                   f"{entry['min_minor'] or '—'} | {entry['max_minor'] or '—'} |")
    out.append("")
    for entry in model["schedules"]:
        out.append(f"- **`{entry['id']}`**：{entry['notes']}")

    out += ["", "## 结算", "",
            f"- 账面值是估计：{'是' if settlement['book_value_is_estimate'] else '否'}",
            f"- 权威来源：`{settlement['authoritative_source']}`",
            f"- 不一致时开对账项：{'是' if settlement['mismatch_opens_reconciliation'] else '否'}",
            f"- 允许静默覆盖：{'是' if settlement['silent_overwrite_allowed'] else '**否**'}",
            f"- 容差：{settlement['tolerance_minor']}；最长结算滞后："
            f"{settlement['max_settle_lag_days']} 天",
            "", settlement["notes"], "",
            "## 分账", "",
            "- 参与方：" + "、".join(f"`{p}`" for p in split["parties"]),
            f"- 各方之和必须等于总额：{'是' if split['must_sum_to_total'] else '否'}",
            f"- 余数归：`{split['residue_to']}`",
            "", split["notes"], "",
            "## 币种", "",
            "- 费用币种等于支付币种："
            f"{'是' if currency['fee_currency_equals_payment_currency'] else '否'}",
            f"- 允许隐式换算：{'是' if currency['implicit_conversion_allowed'] else '**否**'}",
            "- 汇率记录字段：" + "、".join(f"`{f}`" for f in currency["rate_record_fields"]),
            "", currency["notes"], "",
            "## 计量", "",
            f"- 事件键：`{metering['event_key']}`",
            f"- 幂等：{'是' if metering['idempotent'] else '否'}；"
            f"可重算：{'是' if metering['recomputable'] else '否'}",
            f"- 保留：{metering['retention_days']} 天",
            "", metering["notes"], "",
            f"审计事件类别：`{model['audit_event_class']}`（见 B23）。", ""]
    return "\n".join(out)


TARGETS = {
    "contracts/pricing/fee-model.json": contract_json,
    "docs/pricing/FEE_MODEL.md": fees_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
