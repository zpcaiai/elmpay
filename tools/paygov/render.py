"""B01/B07 — deterministic rendering of governance JSON into review documents.

The JSON files are the single source of truth; the markdown under ``docs/`` is
generated from them. ``scripts/render-docs.py --check`` fails when the two drift,
so a reviewer can trust that the document they read matches what CI enforces.
"""
from __future__ import annotations

from pathlib import Path

from . import adr as adr_mod
from . import traceability as trace_mod
from . import catalogue
from .repo import Budget, load_json, read_text

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


def adr_index_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    rows = []
    for path in sorted((root / "docs/adr").glob("*.md")):
        if path.name == "README.md":
            continue
        text = read_text(path, budget)
        meta, _ = adr_mod.parse(text)
        title = text.splitlines()[0].removeprefix("# ").strip()
        rows.append([f"[{title.split(':')[0]}]({path.name})", title.split(": ", 1)[-1],
                     meta.get("状态", ""), meta.get("日期", ""), meta.get("批次", ""),
                     meta.get("关联控制", "")])
    lines = [GENERATED_BANNER.format(source="docs/adr/*.md"), "# 架构决策记录索引", "",
             f"共 {len(rows)} 条 ADR。新增决策必须新建 ADR，不得原地改写既有决策；",
             "被取代的 ADR 状态改为 `superseded`，并由取代它的 ADR 在“取代”字段中声明。", ""]
    lines.append(_table(["ADR", "标题", "状态", "日期", "批次", "关联控制"], rows))
    return "\n".join(lines).rstrip() + "\n"


def threat_model_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = load_json(root / "governance/threat-model.json", budget)
    lines = [GENERATED_BANNER.format(source="governance/threat-model.json"),
             "# 威胁模型与剩余风险台账（B02）", "", "## 信任域", ""]
    lines.append(_table(["ID", "名称", "信任级别"],
                        [[z["id"], z["name"], z["trust"]] for z in doc["zones"]]))
    lines += ["", "## 高价值资产", ""]
    lines.append(_table(["ID", "资产", "分类", "责任人", "模块", "威胁"],
                        [[a["id"], a["name"], a["classification"], a["owner"],
                          "、".join(a["modules"]), "；".join(a["threats"])] for a in doc["assets"]]))
    lines += ["", "## 信任边界", ""]
    lines.append(_table(["ID", "边界", "跨越", "控制"],
                        [[b["id"], b["name"], " ↔ ".join(b["between"]), " ".join(b["controls"])]
                         for b in doc["trust_boundaries"]]))
    lines += ["", "## 攻击者模型", ""]
    lines.append(_table(["ID", "攻击者", "能力", "动机"],
                        [[a["id"], a["name"], a["capability"], a["motivation"]]
                         for a in doc["adversaries"]]))
    lines += ["", "## 滥用案例", ""]
    lines.append(_table(["ID", "滥用案例", "攻击者", "资产", "控制", "缓解批次", "状态"],
                        [[c["id"], c["title"], " ".join(c["adversaries"]), " ".join(c["assets"]),
                          " ".join(c["controls"]), " ".join(c["mitigating_batches"]), c["status"]]
                         for c in doc["abuse_cases"]]))
    lines += ["", "## 剩余风险台账", "",
              "过期未复审的条目会使治理门禁失败（NN-15）。", ""]
    lines.append(_table(["ID", "风险", "严重度", "风险所有者", "补偿控制", "到期日", "复审批次"],
                        [[r["id"], r["title"], r["severity"], r["owner"],
                          "；".join(r["compensating_controls"]), r["due_date"], r["review_batch"]]
                         for r in doc["residual_risks"]]))
    return "\n".join(lines).rstrip() + "\n"


def version_catalog_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    doc = load_json(root / "governance/version-catalog.json", budget)
    lines = [GENERATED_BANNER.format(source="governance/version-catalog.json"),
             "# 版本目录（B03）", "",
             f"核验状态：`{doc['verification_status']}`。{doc.get('verification_note', '')}", "",
             "所有版本必须精确固定；容器镜像必须以摘要固定。构建文件由本目录生成，漂移即失败。", ""]
    lines.append(_table(["ID", "名称", "类别", "版本", "固定方式", "责任人", "升级策略"],
                        [[e["id"], e["name"], e["category"], e["version"], e["pin_type"],
                          e["owner"], e["upgrade_policy"]] for e in doc["entries"]]))
    lines += ["", "## 构建系统归属", ""]
    lines.append(_table(["构建系统", "模块"],
                        [[system, "、".join(names)]
                         for system, names in sorted(doc["modules_by_build_system"].items())]))
    lines += ["", "## 生成的构建文件", "",
              "`gradle/libs.versions.toml`、`settings.gradle.kts`、`build.gradle.kts`、",
              "`.tool-versions`、`platform/toolchain/versions.env`", "",
              "重新生成：`python3 scripts/render-build.py`"]
    return "\n".join(lines).rstrip() + "\n"


def domain_model_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / "governance/domain-model.json", budget)
    lines = [GENERATED_BANNER.format(source="governance/domain-model.json"),
             "# 支付领域模型（B08）", "",
             f"实体 {len(model['entities'])} 个 · "
             f"字段 {sum(len(e['fields']) for e in model['entities'])} 个 · "
             f"不变量 {sum(len(e['invariants']) for e in model['entities'])} 条。", "",
             "本模型是**语言中立的规范定义**；PostgreSQL DDL 由它生成，",
             "Java 类型与 API 契约在 B11 生成。禁止在生成物中手工新增字段。", ""]
    lines.append(_table(["实体", "所属模块", "表", "租户隔离", "用途"],
                        [[e["name"], f'`{e["module"]}`', f'`{e["table"]}`',
                          "是" if e["tenant_scoped"] else "否", e["purpose"]]
                         for e in model["entities"]]))
    for entity in model["entities"]:
        lines += ["", f'## {entity["name"]}　`{entity["table"]}`', "", entity["purpose"], ""]
        rows = []
        for field in entity["fields"]:
            extra = ""
            if field["type"] == "enum":
                extra = " ".join(field["enum"])
            elif field["type"] == "reference":
                extra = f'→ {field["target"]}'
            rows.append([f'`{field["name"]}`', f'`{field["type"]}`',
                         "可空" if field.get("nullable") else "非空",
                         extra, field.get("semantics", "")])
        lines.append(_table(["字段", "类型", "可空", "取值/引用", "语义"], rows))
        if entity["states"]:
            lines += ["", "状态：" + "、".join(f'`{s}`' for s in entity["states"])]
        lines += ["", "不变量："]
        lines += [f"- {inv}" for inv in entity["invariants"]]
    return "\n".join(lines).rstrip() + "\n"


def glossary_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    doc = load_json(root / "governance/glossary.json", budget)
    lines = [GENERATED_BANNER.format(source="governance/glossary.json"),
             "# 统一语言词表（B08）", "", doc.get("note", ""), ""]
    for kind, title in (("entity", "实体"), ("state", "状态"), ("concept", "核心概念")):
        rows = [[t["term_en"], t["term_cn"], t["definition"]]
                for t in doc["terms"] if t["kind"] == kind]
        lines += [f"## {title}", ""]
        lines.append(_table(["English", "中文", "定义"], rows))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


TARGETS: dict[str, callable] = {
    "docs/domain/DOMAIN_MODEL.md": domain_model_markdown,
    "docs/domain/GLOSSARY.md": glossary_markdown,
    "docs/toolchain/VERSION_CATALOG.md": version_catalog_markdown,
    "docs/traceability/MATRIX.md": trace_mod.matrix_markdown,
    "docs/requirements/REQUIREMENTS_BASELINE.md": requirements_markdown,
    "docs/requirements/SERVICE_BOUNDARIES.md": boundaries_markdown,
    "docs/adr/README.md": adr_index_markdown,
    "docs/security/THREAT_MODEL.md": threat_model_markdown,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
