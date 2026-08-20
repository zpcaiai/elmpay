"""B24 — generate the tenant registry contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

TENANTS = Path("governance/tenant-registry.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/tenant-registry.json\n"
             "     Regenerate with: python3 scripts/render-tenants.py -->\n")
CAPABILITIES = ("accept_payments", "issue_refunds", "receive_webhooks", "settle", "read_data")
LABELS = {"accept_payments": "收款", "issue_refunds": "退款", "receive_webhooks": "接收回调",
          "settle": "结算", "read_data": "读数据"}


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / TENANTS)
    for entry in model["hierarchy"]:
        budget.check(entry["level"])
    document = {
        "_generated": "GENERATED FILE — scripts/render-tenants.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "hierarchy": [{"level": h["level"], "id_prefix": h["id_prefix"], "parent": h["parent"]}
                      for h in model["hierarchy"]],
        "identifier": model["identifier"],
        "environments": [{"id": e["id"], "handles_real_money": e["handles_real_money"]}
                         for e in sorted(model["environments"], key=lambda x: x["id"])],
        "lifecycle": {"states": model["lifecycle"]["states"],
                      "initial": model["lifecycle"]["initial"],
                      "terminal": model["lifecycle"]["terminal"],
                      "transitions": [{"from": t["from"], "to": t["to"],
                                       "requires": sorted(t["requires"])}
                                      for t in model["lifecycle"]["transitions"]]},
        "capability_matrix": [{"state": row["state"],
                               **{c: row[c] for c in CAPABILITIES}}
                              for row in model["capability_matrix"]],
        "quotas": [{"id": q["id"], "scope": q["scope"], "default": q["default"],
                    "hard_ceiling": q["hard_ceiling"]}
                   for q in sorted(model["quotas"], key=lambda x: x["id"])],
        "offboarding": model["offboarding"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def tenants_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / TENANTS)
    out = [MD_BANNER, "# 租户与项目注册中心（B24）", "", model["principle"], "",
           "## 层级", "", "| 层 | 前缀 | 父级 | 说明 |", "| --- | --- | --- | --- |"]
    for entry in model["hierarchy"]:
        budget.check(entry["level"])
        out.append(f"| {entry['level']} | `{entry['id_prefix']}_` | "
                   f"{entry['parent'] or '—'} | {entry['notes']} |")
    out += ["", "## 标识符", "", f"- 模式：`{model['identifier']['pattern']}`",
            f"- 不透明：{'是' if model['identifier']['opaque'] else '否'}；"
            f"不可变：{'是' if model['identifier']['immutable'] else '否'}",
            "", model["identifier"]["notes"], "",
            "## 环境", "", "| 环境 | 真实资金 | 共享密钥 | 共享数据 |", "| --- | --- | --- | --- |"]
    for entry in sorted(model["environments"], key=lambda x: x["id"]):
        out.append(f"| `{entry['id']}` | {'是' if entry['handles_real_money'] else '否'} | "
                   f"{'、'.join(entry['shares_keys_with']) or '无'} | "
                   f"{'、'.join(entry['shares_data_with']) or '无'} |")
    out.append("")
    for entry in model["environments"]:
        out.append(f"- **`{entry['id']}`**：{entry['notes']}")

    lifecycle = model["lifecycle"]
    out += ["", "## 生命周期", "",
            " → ".join(f"`{s}`" for s in lifecycle["states"]), "",
            "| 从 | 到 | 前置条件 | 说明 |", "| --- | --- | --- | --- |"]
    for entry in lifecycle["transitions"]:
        budget.check(f"{entry['from']}->{entry['to']}")
        out.append(f"| `{entry['from']}` | `{entry['to']}` | "
                   f"{'、'.join('`' + r + '`' for r in entry['requires'])} | {entry['notes']} |")

    out += ["", "## 各状态下还能做什么", "",
            "| 状态 | " + " | ".join(LABELS[c] for c in CAPABILITIES) + " |",
            "| --- | " + " | ".join("---" for _ in CAPABILITIES) + " |"]
    for row in model["capability_matrix"]:
        cells = " | ".join("✅" if row[c] else "—" for c in CAPABILITIES)
        out.append(f"| `{row['state']}` | {cells} |")
    out.append("")
    for row in model["capability_matrix"]:
        out.append(f"- **`{row['state']}`**：{row['notes']}")

    out += ["", "## 配额", "", "| 配额 | 作用域 | 默认 | 硬上限 |", "| --- | --- | --- | --- |"]
    for quota in sorted(model["quotas"], key=lambda x: x["id"]):
        out.append(f"| `{quota['id']}` | {quota['scope']} | {quota['default']} | "
                   f"{quota['hard_ceiling']} |")
    out.append("")
    for quota in model["quotas"]:
        out.append(f"- **`{quota['id']}`**：{quota['notes']}")

    out += ["", "## 隔离", "", model["isolation"]["notes"], "",
            "## 注销", "", model["offboarding"]["notes"], "",
            "## 命名", "", model["naming"]["notes"], ""]
    return "\n".join(out)


TARGETS = {
    "contracts/tenancy/registry.json": contract_json,
    "docs/tenancy/TENANT_REGISTRY.md": tenants_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
