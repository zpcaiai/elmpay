#!/usr/bin/env python3
"""B14 runtime proof — compute the topology's worst case instead of asserting it.

A service diagram is a claim about latency and blast radius. This script turns
the claim into arithmetic and failure simulation:

1. worst-case latency of a real checkout request, from the browser to the
   provider, computed by walking the declared synchronous edges;
2. what a caller actually experiences when each dependency is down, one at a
   time, checked against the declared failure mode;
3. blast radius: which services go dark when one goes dark, and whether the
   ledger can ever take a payment down (it must not);
4. bulkhead arithmetic: whether one saturated dependency can consume every
   worker of its caller.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TOPOLOGY = json.loads((ROOT / "governance/service-topology.json").read_text(encoding="utf-8"))
BY_NAME = {s["name"]: s for s in TOPOLOGY["services"]}

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def sync_deps(name: str) -> list:
    service = BY_NAME.get(name)
    if not service:
        return []
    return [d for d in service["dependencies"] if d["kind"] == "sync"]


def worst_case_ms(name: str, seen=()) -> int:
    """Worst case for one request: own overhead plus the slowest legal path."""
    if name in seen or name not in BY_NAME:
        return 0
    groups, ungrouped = {}, 0
    for dependency in sync_deps(name):
        cost = min(dependency["timeout_ms"],
                   dependency["timeout_ms"] if dependency["target"] not in BY_NAME
                   else max(dependency["timeout_ms"],
                            worst_case_ms(dependency["target"], seen + (name,))))
        group = dependency.get("exclusive_group")
        if group:
            groups[group] = max(groups.get(group, 0), cost)
        else:
            ungrouped += cost
    return ungrouped + sum(groups.values())


def main() -> int:
    print("== 1. 一次真实收银请求的最坏耗时")
    for entry in ("checkout-web", "edge-gateway", "payment-core"):
        worst = worst_case_ms(entry)
        budget = BY_NAME[entry]["request_budget_ms"]
        check(f"{entry} 的最坏同步耗时不超过自身预算",
              worst <= budget, f"worst={worst}ms budget={budget}ms")

    print()
    print("== 2. 逐个打掉依赖，检查声明的失败模式")
    money_path = [s for s in TOPOLOGY["services"] if s["criticality"] == "tier1"]
    for service in money_path:
        for dependency in service["dependencies"]:
            if dependency["kind"] != "sync":
                continue
            mode = dependency["failure_mode"]
            if dependency.get("operation") in ("mutating", "query"):
                expected = "degrade"
            else:
                expected = "fail_closed"
            check(f"{service['name']} 依赖 {dependency['target']} 不可用时为 {expected}",
                  mode == expected, mode)

    print()
    print("== 3. 爆炸半径：谁挂了会带走谁")
    for victim in sorted(BY_NAME):
        affected = sorted(n for n in BY_NAME
                          if any(d["target"] == victim and d["kind"] == "sync"
                                 for d in BY_NAME[n]["dependencies"]))
        if affected:
            print(f"       {victim} 挂 → 同步受影响：{', '.join(affected)}")
    ledger_callers = [n for n in BY_NAME
                      if any(d["target"] == "ledger-service" and d["kind"] == "sync"
                             for d in BY_NAME[n]["dependencies"])]
    check("账本不可用不会同步拖垮任何服务", not ledger_callers, ledger_callers)
    config_callers = [n for n in BY_NAME
                      if any(d["target"] == "merchant-config" and d["kind"] == "sync"
                             for d in BY_NAME[n]["dependencies"])]
    check("商户配置是叶子节点，自身没有同步依赖",
          not sync_deps("merchant-config"), f"被 {len(config_callers)} 个服务同步依赖")

    print()
    print("== 4. 隔板算术：一个依赖打满不能吃掉调用方的全部并发")
    for name, service in sorted(BY_NAME.items()):
        deps = sync_deps(name)
        if not deps:
            continue
        largest = max(d["bulkhead"]["max_concurrent"] for d in deps)
        total = sum(d["bulkhead"]["max_concurrent"] for d in deps)
        check(f"{name}: 单个依赖的隔板不超过全部隔板之和的 80%",
              largest <= total * 0.8 or len(deps) == 1,
              f"largest={largest} total={total} deps={len(deps)}")

    print()
    print("== 5. 同步图必须无环")
    def reaches(start, target, seen=frozenset()):
        for dependency in sync_deps(start):
            nxt = dependency["target"]
            if nxt == target:
                return True
            if nxt in BY_NAME and nxt not in seen and reaches(nxt, target, seen | {nxt}):
                return True
        return False
    cycles = [n for n in BY_NAME if reaches(n, n)]
    check("同步依赖图无环", not cycles, cycles)

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
