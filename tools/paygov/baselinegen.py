"""B22 — generate the security baseline matrix and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

BASELINE = Path("governance/security-baseline.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/security-baseline.json\n"
             "     Regenerate with: python3 scripts/render-baseline.py -->\n")


def _rows(model: dict) -> list[dict]:
    return sorted(model["requirements"], key=lambda r: (r["standard"], r["id"]))


def matrix_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / BASELINE)
    rows = _rows(model)
    for row in rows:
        budget.check(row["id"])
    applicable = [r for r in rows if r["applicability"] != "mobile"]
    enforced = [r for r in applicable if r["enforcement"]["kind"] in {"gate_rule", "test"}]
    document = {
        "_generated": "GENERATED FILE — scripts/render-baseline.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "standards": sorted(model["standards"], key=lambda s: s["id"]),
        "coverage": {
            "applicable": len(applicable),
            "enforced": len(enforced),
            "accepted_gaps": sum(1 for r in rows
                                 if r["enforcement"]["kind"] == "accepted_gap"),
        },
        "requirements": [{"id": r["id"], "standard": r["standard"], "level": r["level"],
                          "applicability": r["applicability"],
                          "enforcement": r["enforcement"]["kind"],
                          "refs": sorted(r["enforcement"]["refs"])}
                         for r in rows],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def baseline_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / BASELINE)
    rows = _rows(model)
    applicable = [r for r in rows if r["applicability"] != "mobile"]
    enforced = [r for r in applicable if r["enforcement"]["kind"] in {"gate_rule", "test"}]
    gaps = [r for r in rows if r["enforcement"]["kind"] == "accepted_gap"]

    out = [MD_BANNER, "# 安全基线：ASVS / API Security / MASVS（B22）", "",
           model["principle"], "",
           "## 覆盖", "",
           f"- 适用要求：{len(applicable)} 条；已由规则或测试执行：{len(enforced)} 条 "
           f"（{len(enforced) / len(applicable):.0%}）",
           f"- 明确记录的缺口：{len(gaps)} 条（上限 "
           f"{model['coverage_policy']['max_accepted_gaps']}）", "",
           model["coverage_policy"]["notes"], ""]

    out += ["## 标准", "", "| 标准 | 版本 | 说明 |", "| --- | --- | --- |"]
    for standard in sorted(model["standards"], key=lambda s: s["id"]):
        out.append(f"| `{standard['id']}` | {standard['version']} | {standard['notes']} |")
    out.append("")

    out += ["## 映射", "", "| 要求 | 标准 | 级别 | 适用面 | 执行方式 | 引用 |",
            "| --- | --- | --- | --- | --- | --- |"]
    for row in rows:
        budget.check(row["id"])
        refs = "、".join(f"`{r}`" for r in sorted(row["enforcement"]["refs"])) or "—"
        out.append(f"| `{row['id']}` | {row['standard']} | {row['level']} | "
                   f"{row['applicability']} | {row['enforcement']['kind']} | {refs} |")
    out.append("")
    for row in rows:
        out.append(f"- **`{row['id']}` {row['title']}**：{row['notes']}")
    out.append("")

    out += ["## 明确记录的缺口", "", "| 要求 | 负责人 | 复核批次 | 理由 |",
            "| --- | --- | --- | --- |"]
    for row in gaps:
        out.append(f"| `{row['id']}` | {row['enforcement']['owner']} | "
                   f"{row['enforcement']['review_batch']} | {row['notes']} |")
    out.append("")
    return "\n".join(out)


TARGETS = {
    "contracts/security/baseline-matrix.json": matrix_json,
    "docs/security/SECURITY_BASELINE.md": baseline_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
