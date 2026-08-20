#!/usr/bin/env python3
"""B11 runtime proof — replay the API transition vectors and the contract rules.

The unit tests prove the contract is well formed. This proves it *agrees with
the state machines it claims to drive*, by taking every vector in
``contracts/api/transition-vectors.json`` and running it through the B10
reference interpreter: accepted vectors must land on the declared state,
rejected vectors must be rejected for the declared reason, and every accepted
vector must survive a replay unchanged.

It also asserts the three contract properties that are cheap to state and
expensive to lose: no write operation without an idempotency key, no offset
pagination, and no caller-visible error text that quotes card data back.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.statemachine.reference.machine import (  # noqa: E402
    Instance, TransitionRejected, load)
from tools.paygov import api as api_gate  # noqa: E402

CONTRACT = json.loads((ROOT / "governance/api-contract.json").read_text(encoding="utf-8"))
VECTORS = json.loads(
    (ROOT / "contracts/api/transition-vectors.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def main() -> int:
    machines = load(ROOT / "governance/state-machines.json")

    print("== 1. 每条 accepted 向量都必须走到声明的状态，且重放不变")
    for vector in VECTORS["accepted"]:
        machine = machines[vector["machine"]]
        instance = Instance(machine, state=vector["from"])
        landed = instance.apply(vector["event"], vector["actor"], "tok-1")
        replayed = instance.apply(vector["event"], vector["actor"], "tok-1")
        label = (f"{vector['operation']}: {vector['machine']} "
                 f"{vector['from']} --{vector['event']}--> {vector['expected_to']}")
        check(label, landed == vector["expected_to"] and replayed == landed,
              f"landed={landed} replayed={replayed}")

    print()
    print("== 2. 每条 rejected 向量都必须以声明的理由被拒绝")
    for vector in VECTORS["rejected"]:
        machine = machines[vector["machine"]]
        instance = Instance(machine, state=vector["from"])
        label = (f"{vector['machine']} {vector['from']} --{vector['event']}--> "
                 f"拒绝({vector['expected_rejection']})")
        try:
            instance.apply(vector["event"], vector["actor"], "tok-1")
            check(label, False, "本应被拒绝，却通过了")
        except TransitionRejected as exc:
            check(label, exc.code == vector["expected_rejection"], exc.code)

    print()
    print("== 3. 契约层的三条硬性质")
    writes = [o for o in CONTRACT["operations"] if o["method"] in api_gate.WRITE_METHODS]
    check("每个写操作都要求幂等键",
          all((o.get("idempotency") or {}).get("required") for o in writes),
          f"{len(writes)} 个写操作")
    forbidden = set(CONTRACT["pagination"]["forbidden_params"])
    used = {value for o in CONTRACT["operations"] if o.get("pagination")
            for value in o["pagination"].values() if isinstance(value, str)}
    check("没有任何列表接口使用偏移分页", not (used & forbidden), sorted(used))
    leaks = [e["code"] for e in CONTRACT["errors"]
             for token in api_gate.LEAKY if token in e["safe_message"].lower()]
    check("没有错误文案回显卡数据或凭据", not leaks, leaks)

    print()
    print("== 4. 幂等键作用域与状态机声明逐条一致")
    index = {}
    model = json.loads((ROOT / "governance/state-machines.json").read_text(encoding="utf-8"))
    for machine in model["machines"]:
        for tr in machine["transitions"]:
            index.setdefault((machine["name"], tr["event"]), []).append(tr)
    for operation in CONTRACT["operations"]:
        transition = operation.get("drives_transition")
        if not transition:
            continue
        scopes = {t["idempotency"] for t in index[(transition["machine"], transition["event"])]}
        check(f"{operation['id']} 的幂等作用域与状态机一致",
              scopes == {operation["idempotency"]["scope"]},
              f"api={operation['idempotency']['scope']} model={sorted(scopes)}")

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
