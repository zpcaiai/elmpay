"""B14 — generate the service-topology graph and the review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

TOPOLOGY = Path("governance/service-topology.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/service-topology.json\n"
             "     Regenerate with: python3 scripts/render-topology.py -->\n")


def graph_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    topology = load_json(root / TOPOLOGY)
    nodes, edges = [], []
    for service in topology["services"]:
        budget.check(service["name"])
        nodes.append({"id": service["name"], "runtime": service["runtime"],
                      "criticality": service["criticality"],
                      "request_budget_ms": service["request_budget_ms"],
                      "slo": service["slo"]})
        for dependency in service["dependencies"]:
            edges.append({"from": service["name"], "to": dependency["target"],
                          "kind": dependency["kind"],
                          "timeout_ms": dependency.get("timeout_ms"),
                          "retries": dependency.get("retries"),
                          "degradation": dependency["degradation"]})
    document = {
        "_generated": "GENERATED FILE — scripts/render-topology.py; do not edit by hand",
        "schema_version": topology["schema_version"],
        "policy": topology["policy"],
        "nodes": sorted(nodes, key=lambda n: n["id"]),
        "edges": sorted(edges, key=lambda e: (e["from"], e["to"])),
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def topology_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    topology = load_json(root / TOPOLOGY)
    policy = topology["policy"]
    out = [MD_BANNER, "# 服务拆分与依赖规则（B14）", ""]
    out.append("本文由 `governance/service-topology.json` 生成。"
               "模块注册表（B00）说的是**构建期**依赖，本文说的是**运行期**依赖："
               "哪些调用是同步的、允许多久、失败时怎么办。")
    out.append("")
    out.append("## 全局规则")
    out.append("")
    out.append(f"- 同步调用链最深 **{policy['max_sync_depth']}** 跳")
    out.append(f"- 预算规则：{policy['sync_budget_rule']}")
    out.append(f"- 资金路径失败模式：**{policy['money_path_failure_mode']}**。"
               f"{policy['money_path_note']}")
    out.append(f"- 数据库访问：`{policy['database_access']}`。{policy['database_note']}")
    out.append("")
    out.append("## 拓扑")
    out.append("")
    out.append("```mermaid")
    out.append("graph LR")
    for service in topology["services"]:
        budget.check(service["name"])
        out.append(f"    {service['name'].replace('-', '_')}"
                   f"[\"{service['name']}<br/>{service['runtime']} · "
                   f"{service['criticality']} · {service['request_budget_ms']}ms\"]")
    for service in topology["services"]:
        for dependency in service["dependencies"]:
            arrow = "-->" if dependency["kind"] == "sync" else "-.->"
            label = (f"|{dependency['timeout_ms']}ms|" if dependency["kind"] == "sync"
                     else "|事件|")
            out.append(f"    {service['name'].replace('-', '_')} {arrow}{label} "
                       f"{dependency['target'].replace('-', '_')}")
    out.append("```")
    out.append("")
    out.append("实线是同步调用（标注超时），虚线是事件（异步）。")
    out.append("")
    out.append("## 服务")
    out.append("")
    out.append("| 服务 | 形态 | 等级 | 请求预算 | 可用性 | p99 | 同步依赖数 | 异步依赖数 |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for service in topology["services"]:
        sync = sum(1 for d in service["dependencies"] if d["kind"] == "sync")
        asyn = sum(1 for d in service["dependencies"] if d["kind"] == "async")
        out.append(f"| `{service['name']}` | {service['runtime']} | {service['criticality']} | "
                   f"{service['request_budget_ms']}ms | {service['slo']['availability']} | "
                   f"{service['slo']['p99_ms']}ms | {sync} | {asyn} |")
    out.append("")
    out.append("## 依赖与降级")
    out.append("")
    out.append("| 调用方 | 被调方 | 方式 | 超时 | 重试 | 被调方不可用时 |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for service in topology["services"]:
        for dependency in service["dependencies"]:
            timeout = (f"{dependency['timeout_ms']}ms" if dependency["kind"] == "sync" else "—")
            retries = (str(dependency["retries"]) if dependency["kind"] == "sync" else "—")
            out.append(f"| `{service['name']}` | `{dependency['target']}` | "
                       f"{dependency['kind']} | {timeout} | {retries} | "
                       f"{dependency['degradation']} |")
    out.append("")
    out.append("## 预算核算")
    out.append("")
    out.append("| 服务 | 同步超时之和 | 自身预算 | 余量 |")
    out.append("| --- | --- | --- | --- |")
    for service in topology["services"]:
        total = sum(d.get("timeout_ms") or 0 for d in service["dependencies"]
                    if d["kind"] == "sync")
        out.append(f"| `{service['name']}` | {total}ms | {service['request_budget_ms']}ms | "
                   f"{service['request_budget_ms'] - total}ms |")
    out.append("")
    out.append("## 边界说明")
    out.append("")
    for service in topology["services"]:
        out.append(f"- **`{service['name']}`**：{service['notes']}")
    out.append("")
    sync_edges = sum(1 for s in topology["services"] for d in s["dependencies"]
                     if d["kind"] == "sync")
    async_edges = sum(1 for s in topology["services"] for d in s["dependencies"]
                      if d["kind"] == "async")
    out.append(f"共 {len(topology['services'])} 个部署单元、{sync_edges} 条同步边、"
               f"{async_edges} 条异步边。")
    out.append("")
    return "\n".join(out)


TARGETS = {
    "contracts/topology/graph.json": graph_json,
    "docs/architecture/SERVICE_TOPOLOGY.md": topology_markdown,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
