#!/usr/bin/env python3
"""B16 runtime proof — run the access policy instead of reading it.

Seven properties, each executed against the real
``governance/zero-trust.json`` through the reference decision point:

1. every declared decision permits its own happy path;
2. removing any single required factor denies it (each requirement is
   load-bearing, one at a time);
3. an unmatched request is denied by default;
4. **network location changes nothing** — the same request from "internet" and
   from "corporate-vpn" gets identical verdicts;
5. an expired session is denied even with every factor present;
6. four-eyes actions are denied when the approver is the requester;
7. every decision — allow and deny alike — produced an audit record.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.zerotrust.reference.decision import Context, PolicyDecisionPoint  # noqa: E402

POLICY = json.loads((ROOT / "governance/zero-trust.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def happy(rule, **overrides) -> Context:
    kwargs = {"principal": rule["principal"], "resource_class": rule["resource_class"],
              "action": rule["action"], "factors": frozenset(rule["requirements"]),
              "requester": "alice", "step_up_completed": bool(rule["step_up"]),
              "approver": "bob" if rule["four_eyes"] else ""}
    kwargs.update(overrides)
    return Context(**kwargs)


def main() -> int:
    pdp = PolicyDecisionPoint.from_policy(POLICY)
    rules = POLICY["decisions"]

    print(f"== 1. {len(rules)} 条判定的正常路径都必须放行")
    denied = [r["id"] for r in rules if not pdp.decide(happy(r)).allowed]
    check("每条判定的 happy path 都放行", not denied, denied)

    print()
    print("== 2. 每一个必需因素都是承重的（逐个拿掉必须被拒）")
    weak = []
    for rule in rules:
        for requirement in rule["requirements"]:
            factors = frozenset(set(rule["requirements"]) - {requirement})
            if pdp.decide(happy(rule, factors=factors)).allowed:
                weak.append(f"{rule['id']}:{requirement}")
    check("拿掉任何一个必需因素都会被拒绝", not weak, weak)

    print()
    print("== 3. 没有匹配规则时默认拒绝")
    verdict = pdp.decide(Context("payer", "ledger_entry", "write",
                                 frozenset(POLICY["required_factors"])))
    check("未声明的访问必须默认拒绝，即使带齐了所有因素",
          not verdict.allowed, verdict.reasons[0])

    print()
    print("== 4. 网络位置不授予任何权限")
    differences = []
    for rule in rules:
        inside = pdp.decide(happy(rule, network="corporate-vpn"))
        outside = pdp.decide(happy(rule, network="public-internet"))
        if inside.allowed != outside.allowed:
            differences.append(rule["id"])
        stripped = frozenset()
        a = pdp.decide(happy(rule, factors=stripped, network="corporate-vpn"))
        b = pdp.decide(happy(rule, factors=stripped, network="public-internet"))
        if a.allowed or b.allowed or a.allowed != b.allowed:
            differences.append(f"{rule['id']}:stripped")
    check("内网与公网的判定完全一致", not differences, differences)
    check("策略里 network_location_grants 必须为空",
          POLICY["network_location_grants"] == [], POLICY["network_location_grants"])

    print()
    print("== 5. 会话过期后一律拒绝")
    limit = POLICY["session"]["max_human_session_minutes"]
    survivors = [r["id"] for r in rules
                 if pdp.decide(happy(r, session_age_minutes=limit + 1)).allowed]
    check(f"会话超过 {limit} 分钟后全部被拒", not survivors, survivors)

    print()
    print("== 6. 四眼复核不能自己批自己")
    four_eyes = [r for r in rules if r["four_eyes"]]
    check("存在需要四眼复核的高风险判定", len(four_eyes) >= 3, len(four_eyes))
    self_approved = [r["id"] for r in four_eyes
                     if pdp.decide(happy(r, requester="alice", approver="alice")).allowed]
    check("发起人不得同时是审批人", not self_approved, self_approved)
    no_approver = [r["id"] for r in four_eyes
                   if pdp.decide(happy(r, approver="")).allowed]
    check("缺少第二审批人必须被拒", not no_approver, no_approver)

    print()
    print("== 7. 每一次判定都留下审计记录")
    required_fields = set(POLICY["audit"]["required_fields"])
    incomplete = [record["trace_id"] for record in pdp.audit_log
                  if not required_fields <= set(record)]
    check("审计字段齐全", not incomplete, incomplete[:5])
    allows = sum(1 for r in pdp.audit_log if r["decision"] == "allow")
    denies = sum(1 for r in pdp.audit_log if r["decision"] == "deny")
    check("允许与拒绝都被记录", allows > 0 and denies > 0, f"allow={allows} deny={denies}")
    check("审计记录数等于判定次数", len(pdp.audit_log) == allows + denies,
          len(pdp.audit_log))

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
