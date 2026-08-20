"""B32 — generate the payment intent contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

INTENT = Path("governance/payment-intent.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/payment-intent.json\n"
             "     Regenerate with: python3 scripts/render-intent.py -->\n")
BLOCKS = ("amount_snapshot", "lifecycle", "expiry", "confirmation", "method_constraints",
          "order_link", "amount_invariants", "client_secret")


def _without_notes(block: dict) -> dict:
    return {k: (sorted(v) if isinstance(v, list) and k != "states" and k != "terminal"
                and k != "success_states" else v)
            for k, v in sorted(block.items()) if k != "notes"}


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / INTENT)
    document = {
        "_generated": "GENERATED FILE — scripts/render-intent.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "audit_event_class": model["audit_event_class"],
    }
    for block in BLOCKS:
        budget.check(block)
        document[block] = _without_notes(model[block])
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def intent_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / INTENT)
    snapshot = model["amount_snapshot"]
    lifecycle = model["lifecycle"]
    expiry = model["expiry"]
    confirmation = model["confirmation"]
    methods = model["method_constraints"]
    order = model["order_link"]
    invariants = model["amount_invariants"]
    secret = model["client_secret"]

    out = [MD_BANNER, "# Payment Intent 服务（B32）", "", model["principle"], "",
           "## 金额快照", "",
           f"- 不可修改：{'是' if snapshot['immutable'] else '否'}；"
           f"改金额需新建意图：{'是' if snapshot['change_requires_new_intent'] else '否'}",
           "- 快照字段：" + "、".join(f"`{f}`" for f in snapshot["fields"]),
           f"- 仅整数最小单位：{'是' if snapshot['minor_units_only'] else '否'}",
           f"- 精度来源：`{snapshot['exponent_source']}`",
           "", snapshot["notes"], "",
           "## 生命周期", "",
           f"- 来源：`{lifecycle['source']}`（B10 定义，此处引用）",
           "- 状态：" + " → ".join(f"`{s}`" for s in lifecycle["states"]),
           f"- 初始：`{lifecycle['initial']}`",
           "- 终态：" + "、".join(f"`{s}`" for s in lifecycle["terminal"]),
           "- 成功态：" + "、".join(f"`{s}`" for s in lifecycle["success_states"]),
           "", lifecycle["notes"], "",
           "## 过期", "",
           f"- 默认：{expiry['default_minutes']} 分钟；上限：{expiry['max_minutes']} 分钟",
           f"- 创建时写入：{'是' if expiry['recorded_at_creation'] else '否'}；"
           f"允许延长：{'是' if expiry['extension_allowed'] else '**否**'}",
           f"- 过期后可确认：{'是' if expiry['expired_can_be_confirmed'] else '**否**'}；"
           f"由 `{expiry['expiry_actor']}` 触发",
           "", expiry["notes"], "",
           "## 确认", "",
           f"- 必须带幂等键：{'是' if confirmation['idempotency_key_required'] else '否'}",
           "- 幂等键唯一范围：" + "、".join(f"`{f}`" for f in confirmation["key_unique_per"]),
           f"- 最多成功一次：{'是' if confirmation['single_success'] else '否'}；"
           f"并发确认串行化："
           f"{'是' if confirmation['concurrent_confirmations_serialized'] else '否'}",
           f"- 回跳页作为支付证据："
           f"{'是' if confirmation['client_return_page_is_evidence'] else '**否**'}",
           "- 权威来源：" + "、".join(f"`{s}`" for s in confirmation["authoritative_sources"]),
           "", confirmation["notes"], "",
           "## 支付方式约束", "",
           f"- 创建时快照：{'是' if methods['snapshot_at_creation'] else '否'}；"
           f"来源：`{methods['source']}`",
           f"- 确认时方式必须在快照内："
           f"{'是' if methods['confirm_method_must_be_in_snapshot'] else '否'}",
           f"- 事后放宽：{'允许' if methods['widen_after_creation_allowed'] else '**禁止**'}；"
           f"事后收窄：{'允许' if methods['narrow_after_creation_allowed'] else '禁止'}",
           "", methods["notes"], "",
           "## 业务订单关联", "",
           f"- 订单归属：`{order['owner']}`",
           "- 引用字段：" + "、".join(f"`{f}`" for f in order["reference_fields"]),
           f"- 一个订单同时只能有一笔在途意图："
           f"{'是' if order['unique_live_intent_per_order'] else '否'}",
           f"- 存储订单内容：{'是' if order['stores_order_content'] else '**否**'}",
           "- 禁止字段：" + "、".join(f"`{f}`" for f in order["forbidden_fields"]),
           "", order["notes"], "",
           "## 金额不变量", "",
           f"- 捕获不得超过快照金额："
           f"{'是' if invariants['captured_cannot_exceed_amount'] else '否'}",
           f"- 退款不得超过捕获：{'是' if invariants['refunded_cannot_exceed_captured'] else '否'}",
           f"- 禁止负数：{'是' if invariants['negative_amounts_forbidden'] else '否'}；"
           f"允许零金额意图：{'是' if invariants['zero_amount_intent_allowed'] else '**否**'}",
           "", invariants["notes"], "",
           "## 客户端引用", "",
           f"- 含凭证：{'是' if secret['contains_credentials'] else '**否**'}",
           f"- 仅对单笔意图有效：{'是' if secret['scoped_to_single_intent'] else '否'}；"
           f"随意图过期：{'是' if secret['expires_with_intent'] else '否'}",
           "", secret["notes"], "",
           f"审计事件类别：`{model['audit_event_class']}`（见 B23）。", ""]
    return "\n".join(out)


TARGETS = {
    "contracts/payment/intent.json": contract_json,
    "docs/payment/PAYMENT_INTENT.md": intent_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
