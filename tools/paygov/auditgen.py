"""B23 — generate the audit contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

AUDIT = Path("governance/audit-log.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/audit-log.json\n"
             "     Regenerate with: python3 scripts/render-audit.py -->\n")


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / AUDIT)
    for entry in model["event_classes"]:
        budget.check(entry["id"])
    document = {
        "_generated": "GENERATED FILE — scripts/render-audit.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "hash_chain": model["hash_chain"],
        "anchoring": model["anchoring"],
        "records": model["records"],
        "storage": model["storage"],
        "redaction": model["redaction"],
        "clock": model["clock"],
        "event_classes": [{"id": e["id"], "source": e["source"],
                           "retention_days": e["retention_days"],
                           "contains_pii": e["contains_pii"]}
                          for e in sorted(model["event_classes"], key=lambda x: x["id"])],
        "audited_actions": sorted(model["audited_actions"]),
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def audit_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / AUDIT)
    chain = model["hash_chain"]
    anchoring = model["anchoring"]
    out = [MD_BANNER, "# 不可抵赖审计与防篡改日志（B23）", "", model["principle"], "",
           "## 哈希链", "",
           f"- 算法：`{chain['algorithm']}`；按租户分链："
           f"{'是' if chain['per_tenant_chain'] else '否'}",
           f"- 覆盖前一条哈希与序号：{'是' if chain['includes_previous_hash'] else '否'} / "
           f"{'是' if chain['includes_sequence'] else '否'}",
           f"- 规范化序列化：`{chain['canonical_serialisation']}`",
           "", chain["notes"], "",
           "## 锚定", "",
           f"- 间隔：{anchoring['interval_minutes']} 分钟（**这就是可被否认窗口的大小**）",
           f"- 签名密钥：`{anchoring['signed_by_key']}`；见证方：`{anchoring['witness']}`",
           f"- 锚点保留：{anchoring['anchor_retention_days']} 天",
           "", anchoring["notes"], ""]

    out += ["## 事件类别", "", "| 类别 | 来源 | 保留 | 含个人信息 |", "| --- | --- | --- | --- |"]
    for entry in sorted(model["event_classes"], key=lambda x: x["id"]):
        budget.check(entry["id"])
        out.append(f"| `{entry['id']}` | {entry['source']} | {entry['retention_days']} 天 | "
                   f"{'是' if entry['contains_pii'] else '否'} |")
    out.append("")
    for entry in model["event_classes"]:
        out.append(f"- **`{entry['id']}`**：{entry['notes']}")
    out.append("")

    out += ["## 必须留痕的动作", "",
            "、".join(f"`{a}`" for a in sorted(model["audited_actions"])), "",
            "## 记录字段", "",
            "- 必需：" + "、".join(f"`{f}`" for f in model["records"]["required_fields"]),
            "- 禁止：" + "、".join(f"`{f}`" for f in model["records"]["forbidden_fields"]),
            "", model["records"]["notes"], "",
            "## 存储", "", model["storage"]["notes"], "",
            "## 删除与被遗忘权", "", model["redaction"]["notes"], "",
            "## 时间", "", model["clock"]["notes"], "",
            "## 访问", "", model["access"]["notes"], "",
            "## 验证", "", model["verification"]["notes"], ""]
    return "\n".join(out)


TARGETS = {
    "contracts/security/audit-contract.json": contract_json,
    "docs/security/AUDIT_LOG.md": audit_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
