"""B28 — generate the routing policy contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

ROUTING = Path("governance/routing-policy.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/routing-policy.json\n"
             "     Regenerate with: python3 scripts/render-routing.py -->\n")


def _without_notes(block: dict) -> dict:
    return {k: v for k, v in sorted(block.items()) if k != "notes"}


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / ROUTING)
    rules = []
    for rule in sorted(model["rules"], key=lambda r: r["priority"]):
        budget.check(rule["id"])
        rules.append({"id": rule["id"], "priority": rule["priority"],
                      "when": {k: v for k, v in sorted(rule["when"].items())},
                      "prefer": list(rule["prefer"]), "fallback": list(rule["fallback"])})
    document = {
        "_generated": "GENERATED FILE — scripts/render-routing.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "config_versioning": _without_notes(model["config_versioning"]),
        "determinism": _without_notes(model["determinism"]),
        "rules": rules,
        "scoring": {**_without_notes(model["scoring"]),
                    "factors": [{"id": f["id"], "weight": f["weight"]}
                                for f in sorted(model["scoring"]["factors"],
                                                key=lambda x: x["id"])]},
        "canary": _without_notes(model["canary"]),
        "rollback": _without_notes(model["rollback"]),
        "simulation": _without_notes(model["simulation"]),
        "retry": _without_notes(model["retry"]),
        "audit_event_class": model["audit_event_class"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def routing_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / ROUTING)
    versioning = model["config_versioning"]
    determinism = model["determinism"]
    scoring = model["scoring"]
    canary = model["canary"]
    rollback = model["rollback"]
    simulation = model["simulation"]
    retry = model["retry"]

    out = [MD_BANNER, "# 路由规则、灰度与配置版本（B28）", "", model["principle"], "",
           "## 配置版本", "",
           f"- 版本不可修改：{'是' if versioning['versions_are_immutable'] else '否'}",
           f"- 决定记录版本号：{'是' if versioning['decision_records_config_version'] else '否'}",
           f"- 生效需审批：{'是' if versioning['activation_requires_approval'] else '否'}，"
           f"批准人数 {versioning['activation_approvers_required']}，"
           f"权限 `{versioning['activation_permission']}`",
           f"- 保留版本数：{versioning['retain_versions']}",
           "", versioning["notes"], "",
           "## 确定性", "",
           f"- 同输入同决定：{'是' if determinism['same_inputs_same_decision'] else '否'}",
           f"- 允许随机选择：{'是' if determinism['random_selection_allowed'] else '**否**'}",
           f"- 可重放：{'是' if determinism['replayable'] else '否'}",
           f"- 并列时：`{determinism['tie_break']}`",
           "", determinism["notes"], "",
           "## 路由规则", "",
           "| 优先级 | 规则 | 地区 | 方式 | 币种 | 金额上限(最小单位) | 首选 | 备选 |",
           "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for rule in sorted(model["rules"], key=lambda r: r["priority"]):
        budget.check(rule["id"])
        when = rule["when"]
        out.append(f"| {rule['priority']} | `{rule['id']}` | {when['region']} | "
                   f"`{when['method']}` | {when['currency']} | {when['max_amount_minor']} | "
                   + "、".join(f"`{p}`" for p in rule["prefer"]) + " | "
                   + ("、".join(f"`{p}`" for p in rule["fallback"]) or "—") + " |")
    out.append("")
    for rule in model["rules"]:
        out.append(f"- **`{rule['id']}`**：{rule['notes']}")

    out += ["", "## 打分", "", "| 因子 | 权重 | 说明 |", "| --- | --- | --- |"]
    for factor in scoring["factors"]:
        out.append(f"| `{factor['id']}` | {factor['weight']} | {factor['notes']} |")
    out += ["",
            f"- 统计窗口：{scoring['window_minutes']} 分钟；最小样本：{scoring['min_sample']}",
            f"- **探索下限：{scoring['exploration_floor_percent']}%**；"
            f"饥饿保护：{'开' if scoring['starvation_guard'] else '关'}",
            "", scoring["notes"], "",
            "## 灰度", "",
            f"- 分流键：`{canary['split_key']}`，稳定哈希：{'是' if canary['stable_hash'] else '否'}",
            f"- 允许随机分流：{'是' if canary['random_split_allowed'] else '**否**'}",
            f"- 最大比例：{canary['max_percent']}%；最短观察：{canary['min_observation_minutes']} 分钟",
            f"- 自动放量：{'开' if canary['auto_promote'] else '**关**'}；"
            f"错误率自动回滚：{'开' if canary['auto_rollback_on_error_rate'] else '关'}"
            f"（阈值 {canary['error_rate_threshold_percent']}%）",
            "", canary["notes"], "",
            "## 回滚", "",
            f"- 只能切回已有版本：{'是' if rollback['to_existing_version_only'] else '否'}",
            f"- 需要审批：{'是' if rollback['requires_approval'] else '**否**'}",
            f"- 完成时限：{rollback['max_seconds']} 秒",
            "", rollback["notes"], "",
            "## 影子评估", "",
            f"- 会动钱：{'是' if simulation['shadow_moves_money'] else '**否**'}",
            f"- 使用生产配置：{'是' if simulation['uses_production_config'] else '否'}",
            f"- 与线上决定比对：{'是' if simulation['compares_against_live'] else '否'}",
            "", simulation["notes"], "",
            "## 重试", "",
            f"- 复用幂等键：{'是' if retry['reuse_idempotency_key'] else '否'}",
            f"- 重试可换渠道：{'是' if retry['change_provider_on_retry_allowed'] else '**否**'}",
            f"- 最大次数：{retry['max_attempts']}；退避："
            + "、".join(f"{s}s" for s in retry["backoff_seconds"]),
            "", retry["notes"], "",
            f"审计事件类别：`{model['audit_event_class']}`（见 B23）。", ""]
    return "\n".join(out)


TARGETS = {
    "contracts/routing/policy.json": contract_json,
    "docs/routing/ROUTING_POLICY.md": routing_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
