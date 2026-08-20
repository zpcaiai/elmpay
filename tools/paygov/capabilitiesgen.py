"""B27 — generate the capability matrix contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

CAPS = Path("governance/provider-capabilities.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/provider-capabilities.json\n"
             "     Regenerate with: python3 scripts/render-capabilities.py -->\n")
ROW_FIELDS = ("provider", "method", "regions", "currencies", "devices",
              "supports_authorization_capture", "authorization_valid_hours",
              "partial_capture", "capture_max_percent", "refund_window_days",
              "partial_refund", "refund_to_original_instrument_only",
              "supports_subscription", "dispute_window_days", "dispute_response_days")


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / CAPS)
    rows = []
    for row in sorted(model["capabilities"], key=lambda x: (x["provider"], x["method"])):
        budget.check(f"{row['provider']}/{row['method']}")
        entry = {}
        for field in ROW_FIELDS:
            value = row[field]
            entry[field] = sorted(value) if isinstance(value, list) else value
        rows.append(entry)
    document = {
        "_generated": "GENERATED FILE — scripts/render-capabilities.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "resolution": {k: v for k, v in sorted(model["resolution"].items()) if k != "notes"},
        "device_kinds": model["device_kinds"],
        "payment_methods": [{"id": m["id"], "kind": m["kind"]}
                            for m in sorted(model["payment_methods"], key=lambda x: x["id"])],
        "capabilities": rows,
        "authorization": {k: v for k, v in sorted(model["authorization"].items())
                          if k != "notes"},
        "refund": {k: v for k, v in sorted(model["refund"].items()) if k != "notes"},
        "dispute": {**{k: v for k, v in sorted(model["dispute"].items()) if k != "notes"},
                    "evidence_required": sorted(model["dispute"]["evidence_required"])},
        "availability": [{k: v for k, v in sorted(a.items()) if k != "notes"}
                         for a in sorted(model["availability"], key=lambda x: x["provider"])],
        "region_policy": [{"region": r["region"],
                           "allowed_methods": sorted(r["allowed_methods"]),
                           "requires_local_acquirer": r["requires_local_acquirer"],
                           "strong_customer_authentication": r["strong_customer_authentication"]}
                          for r in sorted(model["region_policy"], key=lambda x: x["region"])],
        "audit_event_class": model["audit_event_class"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def capabilities_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / CAPS)
    resolution = model["resolution"]
    authorization = model["authorization"]
    refund = model["refund"]
    dispute = model["dispute"]

    out = [MD_BANNER, "# 渠道能力与地区政策矩阵（B27）", "", model["principle"], "",
           "## 解析规则", "",
           f"- 默认：**{resolution['default']}**",
           f"- 未声明的组合：**{resolution['unknown_combination']}**",
           f"- 静默换支付方式：{'允许' if resolution['silent_fallback_to_another_method'] else '**禁止**'}",
           f"- 静默换渠道：{'允许' if resolution['silent_fallback_to_another_provider'] else '**禁止**'}",
           "", resolution["notes"], "",
           "## 支付方式", "", "| 方式 | 类型 | 说明 |", "| --- | --- | --- |"]
    for entry in sorted(model["payment_methods"], key=lambda x: x["id"]):
        out.append(f"| `{entry['id']}` | {entry['kind']} | {entry['notes']} |")

    out += ["", f"设备维度：" + "、".join(f"`{d}`" for d in model["device_kinds"]), "",
            "## 能力矩阵", "",
            "| 渠道 | 方式 | 地区 | 币种 | 设备 | 授权/捕获 | 授权有效期(h) | 部分捕获 | "
            "退款窗口(天) | 部分退款 | 订阅 | 争议窗口(天) | 答复时限(天) |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in sorted(model["capabilities"], key=lambda x: (x["provider"], x["method"])):
        budget.check(f"{row['provider']}/{row['method']}")
        out.append(
            f"| `{row['provider']}` | `{row['method']}` | " + "、".join(row["regions"]) + " | "
            + "、".join(row["currencies"]) + " | " + "、".join(row["devices"]) + " | "
            + ("✅" if row["supports_authorization_capture"] else "—") + " | "
            + (str(row["authorization_valid_hours"])
               if row["supports_authorization_capture"] else "—") + " | "
            + ("✅" if row["partial_capture"] else "—") + " | "
            + f"{row['refund_window_days']} | "
            + ("✅" if row["partial_refund"] else "—") + " | "
            + ("✅" if row["supports_subscription"] else "—") + " | "
            + f"{row['dispute_window_days']} | {row['dispute_response_days']} |")
    out.append("")
    for row in model["capabilities"]:
        out.append(f"- **`{row['provider']}` / `{row['method']}`**：{row['notes']}")

    out += ["", "## 授权与捕获", "",
            f"- 授权有效期上限：{authorization['max_valid_hours']} 小时",
            f"- 过期后捕获：{'允许' if authorization['capture_after_expiry_allowed'] else '**禁止**'}",
            f"- 必须重新授权：{'是' if authorization['reauthorization_required'] else '否'}",
            f"- 超额捕获：{'允许' if authorization['over_capture_allowed'] else '**禁止**'}",
            "", authorization["notes"], "",
            "## 退款", "",
            f"- 窗口外动作：`{refund['beyond_window_action']}`",
            f"- 窗口外仍承诺退款：{'是' if refund['promise_beyond_window'] else '**否**'}",
            f"- 超过捕获金额退款：{'允许' if refund['refund_exceeding_capture_allowed'] else '禁止'}",
            "", refund["notes"], "",
            "## 争议", "",
            f"- 时限由外部设定：{'是' if dispute['deadline_is_external'] else '否'}",
            f"- 未答复即判负：{'是' if dispute['missing_response_loses_by_default'] else '否'}",
            f"- 自动认赔：{'允许' if dispute['auto_accept_allowed'] else '**禁止**'}",
            "- 举证材料：" + "、".join(f"`{e}`" for e in dispute["evidence_required"]),
            "", dispute["notes"], "",
            "## 可用性", "",
            "| 渠道 | 计划维护 | 窗口(UTC) | 降级行为 | 静默切换 |",
            "| --- | --- | --- | --- | --- |"]
    for entry in sorted(model["availability"], key=lambda x: x["provider"]):
        out.append(f"| `{entry['provider']}` | "
                   f"{'是' if entry['scheduled_maintenance'] else '否'} | "
                   f"{entry['maintenance_window_utc'] or '—'} | "
                   f"{entry['degraded_behaviour']} | "
                   f"{'允许' if entry['silent_fallback_allowed'] else '禁止'} |")
    out.append("")
    for entry in model["availability"]:
        out.append(f"- **`{entry['provider']}`**：{entry['notes']}")

    out += ["", "## 地区政策", "",
            "| 地区 | 允许的支付方式 | 需本地收单 | 强客户认证 |",
            "| --- | --- | --- | --- |"]
    for entry in sorted(model["region_policy"], key=lambda x: x["region"]):
        out.append(f"| `{entry['region']}` | "
                   + "、".join(f"`{m}`" for m in entry["allowed_methods"]) + " | "
                   + ("是" if entry["requires_local_acquirer"] else "否") + " | "
                   + ("**是**" if entry["strong_customer_authentication"] else "否") + " |")
    out.append("")
    for entry in model["region_policy"]:
        out.append(f"- **`{entry['region']}`**：{entry['notes']}")
    out += ["", f"审计事件类别：`{model['audit_event_class']}`（见 B23）。", ""]
    return "\n".join(out)


TARGETS = {
    "contracts/provider/capability-matrix.json": contract_json,
    "docs/provider/PROVIDER_CAPABILITIES.md": capabilities_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
