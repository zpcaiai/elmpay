"""B10 — generate the state-machine review document from the normative model.

Reviewers read diagrams, not JSON. The diagrams are generated so that the
picture cannot disagree with the rules: if someone adds a transition without
updating the document, the drift check fails the build.
"""
from __future__ import annotations

from pathlib import Path

from .repo import Budget, load_json

MODEL = Path("governance/state-machines.json")
BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
          "     Source of truth: governance/state-machines.json\n"
          "     Regenerate with: python3 scripts/render-states.py -->\n")


def _mermaid(machine: dict) -> list[str]:
    lines = ["```mermaid", "stateDiagram-v2", f"    [*] --> {machine['initial']}"]
    for tr in machine["transitions"]:
        arrow = "-->"
        label = tr["event"]
        if tr.get("kind") == "compensating":
            label += " (补偿)"
        lines.append(f"    {tr['from']} {arrow} {tr['to']}: {label}")
    for state in machine["terminal"]:
        lines.append(f"    {state} --> [*]")
    lines.append("```")
    return lines


def states_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / MODEL)
    out: list[str] = [BANNER, "# 支付状态机与业务不变量（B10）", ""]
    out.append("本文由 `governance/state-machines.json` 生成。状态集合本身来自 "
               "`governance/domain-model.json`（B08），本文只负责**转移**。")
    out.append("")
    out.append("## 参与者与信任边界")
    out.append("")
    out.append("| 参与者 | 说明 | 可否写入成功状态 |")
    out.append("| --- | --- | --- |")
    for actor in model["actors"]:
        trust = "✅ 可以" if actor.get("trusted_for_success") else "❌ 不可以"
        out.append(f"| `{actor['id']}` | {actor['description']} | {trust} |")
    out.append("")
    out.append("> 只有已验签渠道事件与服务端主动查询/对账结果可以写入成功状态（NN-03）。"
               "客户端回跳、同步返回页、未验签通知一律不行——这条在 `STATE_UNTRUSTED_SUCCESS` "
               "里是可执行的规则，不是这段文字。")
    out.append("")
    out.append("## 成功状态清单")
    out.append("")
    for entity, states in sorted(model["success_states"].items()):
        out.append(f"- **{entity}**：{', '.join('`' + s + '`' for s in states)}")
    out.append("")

    for machine in model["machines"]:
        budget.check(machine["name"])
        out.append(f"## {machine['name']} — {machine['entity']}")
        out.append("")
        out.append(machine["notes"])
        out.append("")
        out.append(f"初始状态 `{machine['initial']}`；终态 "
                   f"{', '.join('`' + s + '`' for s in machine['terminal'])}。")
        out.append("")
        out += _mermaid(machine)
        out.append("")
        out.append("| 从 | 到 | 事件 | 参与者 | 类型 | 守卫 | 幂等键 | 效果 |")
        out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for tr in machine["transitions"]:
            effects = "、".join(tr.get("effects") or []) or "—"
            out.append(f"| `{tr['from']}` | `{tr['to']}` | `{tr['event']}` | `{tr['actor']}` | "
                       f"{tr['kind']} | {tr['guard']} | `{tr['idempotency']}` | {effects} |")
        out.append("")

    total = sum(len(m["transitions"]) for m in model["machines"])
    out.append("---")
    out.append("")
    out.append(f"共 {len(model['machines'])} 台状态机、{total} 条转移，全部带守卫与幂等键。")
    out.append("")
    return "\n".join(out)


TARGETS = {"docs/domain/STATE_MACHINES.md": states_markdown}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
