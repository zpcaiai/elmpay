"""B01/B07 — deterministic rendering of governance JSON into review documents.

The JSON files are the single source of truth; the markdown under ``docs/`` is
generated from them. ``scripts/render-docs.py --check`` fails when the two drift,
so a reviewer can trust that the document they read matches what CI enforces.
"""
from __future__ import annotations

from pathlib import Path

from . import catalogue
from .repo import Budget, load_json

GENERATED_BANNER = (
    "<!-- GENERATED FILE — do not edit by hand.\n"
    "     Source of truth: {source}\n"
    "     Regenerate with: python3 scripts/render-docs.py -->\n"
)


def _table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |",
           "| " + " | ".join("---" for _ in header) + " |"]
    out += ["| " + " | ".join(cell.replace("|", "\\|") for cell in row) + " |" for row in rows]
    return "\n".join(out)


def requirements_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = load_json(root / "governance/requirements.json", budget)
    titles = catalogue.batch_titles(str(root))

    lines = [GENERATED_BANNER.format(source="governance/requirements.json"),
             "# 需求基线（B01）", "",
             f"共 {len(doc['requirements'])} 条需求，{len(doc['categories'])} 个类别。",
             "每条需求都绑定至少一个控制与至少一个验证批次；未绑定的需求会使治理门禁失败。", ""]

    for category in doc["categories"]:
        items = [r for r in doc["requirements"] if r["category"] == category]
        if not items:
            continue
        lines += [f"## {category}", ""]
        lines.append(_table(
            ["ID", "标题", "优先级", "责任模块", "控制", "验证批次"],
            [[r["id"], r["title"], r["priority"], r["owner_module"],
              " ".join(r["controls"]), " ".join(r["verified_by_batches"])] for r in items]))
        lines.append("")

    lines += ["## 需求详情", ""]
    for r in doc["requirements"]:
        lines += [f"### {r['id']} {r['title']}", "",
                  f"- 类别：{r['category']}　优先级：{r['priority']}　责任模块：`{r['owner_module']}`",
                  f"- 陈述：{r['statement']}",
                  f"- 验收：{r['acceptance']}",
                  f"- 控制：{', '.join(r['controls'])}",
                  "- 验证批次：" + ", ".join(
                      f"{b}（{titles.get(b, '?')}）" for b in r["verified_by_batches"]),
                  ""]
    return "\n".join(lines).rstrip() + "\n"


def boundaries_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = load_json(root / "governance/service-boundaries.json", budget)

    lines = [GENERATED_BANNER.format(source="governance/service-boundaries.json"),
             "# 服务边界与禁止流（B01）", "", "## 外部参与者与所有权", ""]
    lines.append(_table(["参与者", "名称", "拥有", "禁止"],
                        [[a["id"], a["name"], "、".join(a["owns"]), "、".join(a["must_not"])]
                         for a in doc["external_actors"]]))
    lines += ["", "## 能力与责任模块", ""]
    lines.append(_table(["能力", "名称", "责任模块", "需求数", "入向", "出向"],
                        [[c["id"], c["name"], c["owner_module"], str(len(c["requirements"])),
                          "、".join(c["inbound_from"]), "、".join(c["outbound_to"])]
                         for c in doc["capabilities"]]))
    lines += ["", "### 能力到需求", ""]
    for c in doc["capabilities"]:
        lines.append(f"- **{c['id']} {c['name']}** → {', '.join(c['requirements'])}")
    lines += ["", "## 禁止流", ""]
    lines.append(_table(["ID", "描述", "强制方式"],
                        [[f["id"], f["description"], " ".join(f["enforced_by"])]
                         for f in doc["forbidden_flows"]]))
    return "\n".join(lines).rstrip() + "\n"


TARGETS: dict[str, callable] = {
    "docs/requirements/REQUIREMENTS_BASELINE.md": requirements_markdown,
    "docs/requirements/SERVICE_BOUNDARIES.md": boundaries_markdown,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
