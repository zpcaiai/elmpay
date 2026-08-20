"""B07 — bidirectional traceability across the whole programme.

Forward: requirement → capability → module → control → verifying batch → test
→ evidence. Backward: every control, every module and every completed batch
must be reachable from at least one requirement.

The backward direction is the one that catches real gaps. A red line that no
requirement claims is a red line nobody is building for; a completed batch whose
evidence references no known control is evidence nobody can audit.
"""
from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Any

from . import catalogue
from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json, read_text
from .structs import expect

REQUIREMENTS = Path("governance/requirements.json")
BOUNDARIES = Path("governance/service-boundaries.json")
NONNEG = Path("governance/non-negotiables.json")
CONTROLS = Path(".payment-platform/skill-package/compliance/controls-matrix.csv")
ADR_DIR = Path("docs/adr")
EVIDENCE = Path("evidence")
ADR_CONTROLS = re.compile(r"^- 关联控制：(.*)$", re.MULTILINE)
ADR_REQUIREMENTS = re.compile(r"^- 关联需求：(.*)$", re.MULTILINE)
SPLIT = re.compile(r"[,，\s]+")


def _refs(value: str) -> set[str]:
    return {part.strip() for part in SPLIT.split(value) if part.strip() and part.strip() != "无"}


def build_graph(root: Path, budget: Budget | None = None, *,
                include_evidence: bool = True) -> dict:
    """Materialise the trace graph. Used by the validator and by the matrix renderer."""
    budget = budget or Budget(seconds=120).start()
    requirements = load_json(root / REQUIREMENTS, budget)["requirements"]
    boundaries = load_json(root / BOUNDARIES, budget)
    rules = [r["id"] for r in load_json(root / NONNEG, budget)["rules"]]
    control_rows = list(csv.DictReader(io.StringIO(read_text(root / CONTROLS, budget))))
    controls = [row["control_id"].strip() for row in control_rows if row.get("control_id")]

    adrs: dict[str, dict[str, set[str]]] = {}
    for path in sorted((root / ADR_DIR).glob("0*.md")):
        text = read_text(path, budget)
        adrs[path.name] = {
            "controls": _refs(ADR_CONTROLS.search(text).group(1)) if ADR_CONTROLS.search(text) else set(),
            "requirements": _refs(ADR_REQUIREMENTS.search(text).group(1)) if ADR_REQUIREMENTS.search(text) else set(),
        }

    capability_of: dict[str, str] = {}
    for capability in boundaries["capabilities"]:
        for rid in capability["requirements"]:
            capability_of[rid] = capability["id"]

    batch_evidence: dict[str, dict] = {}
    completion_dir = root / EVIDENCE / "completion"
    if include_evidence and completion_dir.is_dir():
        for path in sorted(completion_dir.glob("*.json")):
            trace = root / EVIDENCE / path.stem / "traceability.json"
            if trace.is_file():
                data = json.loads(read_text(trace, budget))
                batch_evidence[path.stem] = {
                    "controls": {c.get("id") for c in data.get("controls", []) if isinstance(c, dict)},
                    "tests": {t.get("ref") for t in data.get("tests", []) if isinstance(t, dict)},
                    "evidence": {e.get("path") for e in data.get("evidence", []) if isinstance(e, dict)},
                }

    return {
        "requirements": requirements,
        "rules": rules,
        "controls": controls,
        "adrs": adrs,
        "capability_of": capability_of,
        "batch_evidence": batch_evidence,
    }


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("traceability", "B07")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget(seconds=120).start()
    where = str(REQUIREMENTS)
    try:
        graph = build_graph(root, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("TRACE_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    requirements: list[dict[str, Any]] = graph["requirements"]
    known_modules = catalogue.module_names(str(root))
    known_batches = catalogue.batch_ids(str(root))

    controls_from_requirements: set[str] = set()
    modules_from_requirements: set[str] = set()
    batches_from_requirements: set[str] = set()
    for req in requirements:
        rid = req["id"]
        scope = f"{where}#{rid}"
        controls_from_requirements |= set(req["controls"])
        modules_from_requirements.add(req["owner_module"])
        batches_from_requirements |= set(req["verified_by_batches"])
        problems += expect(rid in graph["capability_of"], "TRACE_NO_CAPABILITY", scope,
                           "requirement is not claimed by any capability", "NN-12")

    # --- backward coverage -------------------------------------------------
    for rule in graph["rules"]:
        problems += expect(rule in controls_from_requirements, "TRACE_RULE_UNCOVERED", where,
                           f"non-negotiable '{rule}' is claimed by no requirement; nothing in the "
                           f"baseline is being built to satisfy it", rule)
    for control in graph["controls"]:
        problems += expect(control in controls_from_requirements, "TRACE_CONTROL_UNCOVERED", where,
                           f"control '{control}' is claimed by no requirement", control)
    for module in sorted(known_modules - modules_from_requirements):
        problems.append(Problem("TRACE_MODULE_UNCOVERED", where,
                                f"module '{module}' owns no requirement", "NN-12"))
    for batch in sorted(batches_from_requirements - known_batches):
        problems.append(Problem("TRACE_BATCH_UNKNOWN", where,
                                f"requirements point at unknown batch '{batch}'", "NN-12"))

    # --- ADR linkage -------------------------------------------------------
    requirement_ids = {r["id"] for r in requirements}
    for name, links in sorted(graph["adrs"].items()):
        scope = str(ADR_DIR / name)
        problems += expect(bool(links["requirements"]), "TRACE_ADR_ORPHAN", scope,
                           "ADR constrains no requirement", "NN-12")
        for rid in sorted(links["requirements"] - requirement_ids):
            problems.append(Problem("TRACE_ADR_DANGLING", scope,
                                    f"ADR references unknown requirement '{rid}'", "NN-12"))

    # --- evidence linkage --------------------------------------------------
    valid_controls = set(graph["rules"]) | set(graph["controls"])
    for batch, links in sorted(graph["batch_evidence"].items()):
        scope = str(EVIDENCE / batch / "traceability.json")
        problems += expect(bool(links["controls"]), "TRACE_EVIDENCE_NO_CONTROL", scope,
                           "batch evidence claims no control", "NN-12")
        for control in sorted(links["controls"] - valid_controls):
            problems.append(Problem("TRACE_EVIDENCE_UNKNOWN_CONTROL", scope,
                                    f"evidence references unknown control '{control}'", "NN-12"))
        for test in sorted(t for t in links["tests"] if t):
            problems += expect((root / test).is_file(), "TRACE_EVIDENCE_TEST_MISSING", scope,
                               f"evidence references test '{test}' which does not exist", "NN-12")
    return problems


def matrix_markdown(root: Path, budget: Budget | None = None) -> str:
    """Render the review matrix.

    IMPORTANT: this document is a pure function of the *governance* sources
    (requirements, boundaries, ADRs). It deliberately does NOT read
    ``evidence/``. An earlier version included a per-batch evidence table, which
    made the document change every time a completion file was written — so the
    act of completing a batch drifted a document that the same batch pinned by
    hash, and no consistent state existed. Evidence-derived coverage belongs in
    ``scripts/traceability-matrix.py`` output, which is runtime evidence and is
    not hash-pinned.
    """
    budget = budget or Budget(seconds=120).start()
    graph = build_graph(root, budget, include_evidence=False)
    requirements = graph["requirements"]
    header = "<!-- GENERATED FILE — do not edit by hand.\n" \
             "     Source of truth: governance/requirements.json + " \
             "governance/service-boundaries.json + docs/adr/\n" \
             "     Regenerate with: python3 scripts/render-docs.py -->\n"

    adr_by_requirement: dict[str, list[str]] = {}
    for name, links in sorted(graph["adrs"].items()):
        for rid in sorted(links["requirements"]):
            adr_by_requirement.setdefault(rid, []).append(name.split("-", 1)[0])

    lines = [header, "# 双向追踪矩阵（B07）", "",
             f"需求 {len(requirements)} 条 · 能力 {len(set(graph['capability_of'].values()))} 项 · "
             f"ADR {len(graph['adrs'])} 条 · 红线 {len(graph['rules'])} 条 · "
             f"控制 {len(graph['controls'])} 条。", "",
             "批次证据到控制的映射不在本文档中——它随证据变化，放进受哈希固定的文档会造成",
             "“完成一个批次即让该批次失效”的循环。见 `evidence/*/runtime/trace-graph.json`。", "",
             "## 需求 → 能力 → 模块 → 控制 → 验证批次 → ADR", ""]
    head = ["需求", "标题", "能力", "责任模块", "控制", "验证批次", "ADR"]
    lines.append("| " + " | ".join(head) + " |")
    lines.append("| " + " | ".join("---" for _ in head) + " |")
    for req in requirements:
        lines.append("| " + " | ".join([
            req["id"], req["title"], graph["capability_of"].get(req["id"], "—"),
            f'`{req["owner_module"]}`', " ".join(req["controls"]),
            " ".join(req["verified_by_batches"]),
            " ".join(adr_by_requirement.get(req["id"], [])) or "—"]) + " |")

    lines += ["", "## 控制 → 需求（反向覆盖）", ""]
    reverse: dict[str, list[str]] = {}
    for req in requirements:
        for control in req["controls"]:
            reverse.setdefault(control, []).append(req["id"])
    head = ["控制", "被哪些需求认领"]
    lines.append("| " + " | ".join(head) + " |")
    lines.append("| " + " | ".join("---" for _ in head) + " |")
    for control in graph["rules"] + graph["controls"]:
        lines.append(f'| {control} | {" ".join(reverse.get(control, [])) or "**未覆盖**"} |')
    return "\n".join(lines).rstrip() + "\n"
