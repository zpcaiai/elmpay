"""B12 — generate the language-neutral event contract and the review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

CATALOG = Path("governance/event-catalog.json")
BANNER_MD = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/event-catalog.json\n"
             "     Regenerate with: python3 scripts/render-events.py -->\n")


def catalog_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    catalog = load_json(root / CATALOG)
    envelope = catalog["envelope"]
    events = []
    for event in catalog["events"]:
        budget.check(event["name"])
        events.append({
            "name": event["name"],
            "version": event["version"],
            "producer": event["producer"],
            "aggregate": event["aggregate"],
            "ordering_key": event["ordering_key"],
            "partition_key": event["partition_key"],
            "retention_days": event["retention_days"],
            "envelope_fields": sorted(envelope["required_fields"]),
            "payload_fields": [{"name": f["name"], "type": f["type"],
                                "classification": f["classification"]}
                               for f in event["fields"]],
            "consumers": sorted(event["consumers"]),
        })
    document = {
        "_generated": "GENERATED FILE — scripts/render-events.py; do not edit by hand",
        "schema_version": catalog["schema_version"],
        "delivery": catalog["delivery"],
        "ordering": catalog["ordering"],
        "versioning": catalog["versioning"],
        "events": sorted(events, key=lambda e: (e["name"], e["version"])),
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def catalog_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    catalog = load_json(root / CATALOG)
    out = [BANNER_MD, "# 事件目录、Outbox 与 Inbox（B12）", ""]
    out.append("本文由 `governance/event-catalog.json` 生成。"
               "事件与状态机转移的绑定由门禁强制一致（`EVENT_TRANSITION_UNKNOWN`、"
               "`EVENT_SUCCESS_UNPUBLISHED`）。")
    out.append("")
    delivery = catalog["delivery"]
    out.append("## 投递保证")
    out.append("")
    out.append(f"- 传输层：`{delivery['transport_guarantee']}`")
    out.append(f"- 业务效果：`{delivery['business_guarantee']}`")
    out.append(f"- {delivery['policy']}")
    out.append("")
    out.append("## 信封")
    out.append("")
    out.append("必备字段：" + "、".join(f"`{f}`" for f in catalog["envelope"]["required_fields"]))
    out.append("")
    out.append(catalog["envelope"]["policy"])
    out.append("")
    out.append("## Outbox")
    out.append("")
    outbox = catalog["outbox"]
    dispatch = outbox["dispatch"]
    out.append(f"- 表：`{outbox['table']}`（属于 `{outbox['owner']}`）")
    out.append(f"- 唯一键：{'、'.join('`' + k + '`' for k in outbox['unique_key'])}")
    out.append(f"- 与状态变更同事务：{'是' if outbox['same_transaction_as_state_change'] else '否'}")
    out.append(f"- 投递：{dispatch['mode']}，批量 {dispatch['batch_size']}，"
               f"{dispatch['backoff']} 退避 {dispatch['initial_delay_ms']}–"
               f"{dispatch['max_delay_ms']}ms，最多 {dispatch['max_attempts']} 次，"
               f"死信表 `{dispatch['dead_letter_table']}`")
    out.append("")
    out.append(outbox["policy"])
    out.append("")
    out.append("## Inbox")
    out.append("")
    inbox = catalog["inbox"]
    out.append(f"- 表：`{inbox['table']}`，唯一键 "
               f"{'、'.join('`' + k + '`' for k in inbox['unique_key'])}")
    out.append(f"- 负载哈希字段：`{inbox['payload_hash_field']}`，"
               f"冲突错误 `{inbox['conflict_error']}`，保留 {inbox['retention_hours']} 小时")
    out.append("")
    out.append(inbox["policy"])
    out.append("")
    out.append("## 乱序容忍")
    out.append("")
    ordering = catalog["ordering"]
    out.append(f"排序键 `{ordering['key_field']}`，序号 `{ordering['sequence_field']}`，"
               f"缓冲空洞上限 {ordering['revision_gap_limit']}。")
    out.append("")
    out.append(ordering["policy"])
    out.append("")
    out.append("## 事件")
    out.append("")
    out.append("| 事件 | 版本 | 生产者 | 聚合 | 由哪条转移产生 | 消费者 | 保留天数 |")
    out.append("| --- | --- | --- | --- | --- | --- | --- |")
    for event in catalog["events"]:
        budget.check(event["name"])
        emitted = event["emitted_by"]
        out.append(f"| `{event['name']}` | v{event['version']} | `{event['producer']}` | "
                   f"{event['aggregate']} | `{emitted['machine']}` / `{emitted['event']}` | "
                   f"{'、'.join('`' + c + '`' for c in event['consumers'])} | "
                   f"{event['retention_days']} |")
    out.append("")
    for event in catalog["events"]:
        if event.get("notes"):
            out.append(f"- **`{event['name']}`**：{event['notes']}")
    out.append("")
    out.append("## 消费者与乱序策略")
    out.append("")
    out.append("| 模块 | 乱序容忍 | 策略 | 订阅数 |")
    out.append("| --- | --- | --- | --- |")
    for consumer in catalog["consumers"]:
        out.append(f"| `{consumer['module']}` | `{consumer['order_tolerance']}` | "
                   f"{consumer['policy']} | {len(consumer['subscribes'])} |")
    out.append("")
    out.append(f"共 {len(catalog['events'])} 个事件、{len(catalog['consumers'])} 个消费者。")
    out.append("")
    return "\n".join(out)


TARGETS = {
    "contracts/events/catalog.json": catalog_json,
    "docs/events/EVENT_CATALOG.md": catalog_markdown,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
