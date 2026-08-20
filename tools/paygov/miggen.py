"""B15 — generate the migration runbook from the plan."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

PLAN = Path("governance/migration-plan.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/migration-plan.json\n"
             "     Regenerate with: python3 scripts/render-migration.py -->\n")


def plan_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    plan = load_json(root / PLAN)
    document = {
        "_generated": "GENERATED FILE — scripts/render-migration.py; do not edit by hand",
        "schema_version": plan["schema_version"],
        "principle": plan["principle"],
        "binding": plan["ownership"]["binding"],
        "provider_calls_per_payment": plan["dual_write"]["provider_calls_per_payment"],
        "phases": [{"id": p["id"], "write_mode": p["write_mode"],
                    "authoritative_for_payment_facts": p["authoritative_for_payment_facts"],
                    "entry_criteria": p["entry_criteria"], "exit_criteria": p["exit_criteria"],
                    "rollback_preserves_payment_facts":
                        p["rollback"]["payment_facts_preserved"]}
                   for p in plan["phases"]],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def runbook_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    plan = load_json(root / PLAN)
    out = [MD_BANNER, "# 现有项目订单迁移架构（B15）", ""]
    out.append(plan["principle"])
    out.append("")
    ownership = plan["ownership"]
    out.append("## 所有权切分")
    out.append("")
    out.append("| 留在原项目 | 迁到支付平台 |")
    out.append("| --- | --- |")
    legacy, platform = ownership["legacy_owns"], ownership["platform_owns"]
    for index in range(max(len(legacy), len(platform))):
        left = f"`{legacy[index]}`" if index < len(legacy) else ""
        right = f"`{platform[index]}`" if index < len(platform) else ""
        out.append(f"| {left} | {right} |")
    out.append("")
    binding = ownership["binding"]
    out.append(f"两侧只通过 `{binding['field']}` 绑定，唯一性为 "
               f"{'、'.join('`' + f + '`' for f in binding['uniqueness'])}。{binding['policy']}")
    out.append("")
    out.append(f"**旧库访问**：{plan['legacy_database_access']['policy']}")
    out.append("")
    adapter = plan["adapter"]
    out.append("## 适配层")
    out.append("")
    out.append(f"归属 `{adapter['owner']}`，位置：{adapter['location']}。{adapter['policy']}")
    out.append("")
    out.append("| 旧系统动作 | 平台操作 | 幂等键来源 | 透传字段 |")
    out.append("| --- | --- | --- | --- |")
    for entry in adapter["operations"]:
        budget.check(entry["platform_operation"])
        out.append(f"| {entry['legacy_action']} | `{entry['platform_operation']}` | "
                   f"`{entry['idempotency_source']}` | "
                   f"{'、'.join('`' + f + '`' for f in entry['passes_through'])} |")
    out.append("")
    out.append("**禁止透传**：" + "、".join(f"`{f}`" for f in adapter["forbidden_passthrough"]))
    out.append("")
    dual = plan["dual_write"]
    detection = dual["divergence_detection"]
    out.append("## 双写")
    out.append("")
    out.append(f"**每笔支付对渠道的调用次数：{dual['provider_calls_per_payment']}**。"
               f"{dual['policy']}")
    out.append("")
    out.append(f"- 比对字段：{'、'.join('`' + f + '`' for f in detection['compare_fields'])}")
    out.append(f"- 比对窗口：{detection['window_minutes']} 分钟；"
               f"分歧预算：{detection['budget_pct']}%")
    out.append(f"- 分歧落库：`{detection['record_to']}`")
    out.append(f"- 中止规则：{detection['abort_rule']}")
    out.append("")
    backfill = plan["backfill"]
    out.append("## 历史回填")
    out.append("")
    out.append(f"- 来源：{backfill['source']}（只读：{backfill['read_only_on_legacy']}）")
    out.append(f"- 幂等：{backfill['idempotent']}；可续跑：{backfill['resumable']}"
               f"（断点字段 `{backfill['checkpoint_field']}`）")
    out.append(f"- 校验：{'、'.join(backfill['verification']['method'])}；"
               f"容差：{backfill['verification']['tolerance']}")
    out.append("")
    out.append(backfill["policy"])
    out.append("")
    cutover = plan["cutover"]
    switch = cutover["kill_switch"]
    out.append("## 切换与 kill switch")
    out.append("")
    out.append(f"- 粒度：`{cutover['granularity']}`")
    out.append(f"- kill switch：作用域 `{switch['scope']}`，"
               f"{switch['max_activation_seconds']} 秒内生效，需审计事件")
    out.append("")
    out.append(cutover["policy"])
    out.append("")
    out.append("## 阶段")
    out.append("")
    out.append("```mermaid")
    out.append("stateDiagram-v2")
    out.append(f"    [*] --> {plan['phases'][0]['id']}")
    for index in range(len(plan["phases"]) - 1):
        current, nxt = plan["phases"][index], plan["phases"][index + 1]
        out.append(f"    {current['id']} --> {nxt['id']}: 出口条件达成")
        out.append(f"    {nxt['id']} --> {current['id']}: 回退（{nxt['rollback']['action']}）")
    out.append(f"    {plan['phases'][-1]['id']} --> [*]")
    out.append("```")
    out.append("")
    for phase in plan["phases"]:
        budget.check(phase["id"])
        out.append(f"### {phase['id']} — {phase['name']}")
        out.append("")
        out.append(f"写入模式 `{phase['write_mode']}`；"
                   f"支付事实权威方 **{phase['authoritative_for_payment_facts']}**。")
        out.append("")
        out.append(phase["notes"])
        out.append("")
        out.append("| | |")
        out.append("| --- | --- |")
        out.append(f"| 进入条件 | {'；'.join(phase['entry_criteria'])} |")
        out.append(f"| 退出条件 | {'；'.join(phase['exit_criteria'])} |")
        out.append(f"| 回退动作 | {phase['rollback']['action']} |")
        out.append(f"| 回退是否保全支付事实 | "
                   f"{'是' if phase['rollback']['payment_facts_preserved'] else '否'}"
                   f"（{phase['rollback']['reason']}） |")
        out.append(f"| 证据闸门 | {'、'.join('`' + e + '`' for e in phase['evidence_gate'])} |")
        out.append("")
    out.append(f"共 {len(plan['phases'])} 期，每期都有进入条件、退出条件、回退动作与证据闸门。")
    out.append("")
    return "\n".join(out)


TARGETS = {
    "contracts/migration/plan.json": plan_json,
    "docs/migration/MIGRATION_RUNBOOK.md": runbook_markdown,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
