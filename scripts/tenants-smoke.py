#!/usr/bin/env python3
"""B24 runtime proof — suspend a merchant without stranding their payers.

Scenario 2 is the one this batch exists for. Suspending a merchant must stop new
payments while leaving refunds, provider callbacks and settlement working. The
obvious implementation — flip one boolean and reject everything — leaves the
payers of a suspended merchant with money gone and no route back.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.registry.reference.tenants import (  # noqa: E402
    ACTIVE, CLOSED, DENY_CROSS_TENANT, DENY_NOT_ALLOWED, DENY_QUOTA, DENY_REQUIREMENT,
    DENY_TRANSITION, DENY_WRONG_ENVIRONMENT, OFFBOARDING, SUSPENDED, Credential, Registry,
    RegistryRefused)

MODEL = json.loads((ROOT / "governance/tenant-registry.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def refuses(fn, code: str) -> bool:
    try:
        fn()
        return False
    except RegistryRefused as exc:
        return exc.code == code


def main() -> int:
    registry = Registry(MODEL)
    registry.register("ten_0000000000000001", "org_0000000000000001")
    tenant = "ten_0000000000000001"

    # 1. a draft tenant cannot take money
    check("草稿状态不能收款", registry.may(tenant, "accept_payments") is False)
    check("未完成 KYB 无法激活",
          refuses(lambda: registry.transition(tenant, ACTIVE, satisfied={"contract_signed"},
                                              actor="ops"), DENY_REQUIREMENT))
    registry.transition(tenant, ACTIVE, satisfied={"kyb_verified", "contract_signed"},
                        actor="ops")
    check("完成 KYB 后可以激活并收款", registry.may(tenant, "accept_payments"))

    # 2. suspension stops new money, not money in flight
    registry.transition(tenant, SUSPENDED, satisfied={"reason", "actor"}, actor="risk")
    check("停用后不能再收款", registry.may(tenant, "accept_payments") is False)
    check("**停用后仍然可以退款**", registry.may(tenant, "issue_refunds"))
    check("停用后仍然接收渠道回调", registry.may(tenant, "receive_webhooks"))
    check("停用后仍然结算", registry.may(tenant, "settle"))
    check("被禁止的能力会抛出而不是静默返回",
          refuses(lambda: registry.require(tenant, "accept_payments"), DENY_NOT_ALLOWED))

    # 3. reinstating needs a second person
    check("单人无法恢复被停用的租户",
          refuses(lambda: registry.transition(tenant, ACTIVE, satisfied={"reason", "actor"},
                                              actor="ops"), DENY_REQUIREMENT))
    registry.transition(tenant, ACTIVE,
                        satisfied={"reason", "actor", "second_approver"}, actor="ops")
    check("四眼复核后可以恢复", registry.may(tenant, "accept_payments"))

    # 4. closing order is not negotiable
    registry.transition(tenant, OFFBOARDING,
                        satisfied={"reason", "actor", "second_approver"}, actor="ops")
    check("注销流程中仍可退款与结算",
          registry.may(tenant, "issue_refunds") and registry.may(tenant, "settle"))
    check("结算未完成时不能关闭",
          refuses(lambda: registry.transition(tenant, CLOSED,
                                              satisfied={"retention_period_started",
                                                         "kek_destroyed"}, actor="ops"),
                  DENY_REQUIREMENT))
    registry.transition(tenant, CLOSED,
                        satisfied={"settlement_complete", "retention_period_started",
                                   "kek_destroyed"}, actor="ops")
    check("关闭后一切能力关闭",
          all(registry.may(tenant, c) is False
              for c in ("accept_payments", "issue_refunds", "receive_webhooks", "settle",
                        "read_data")))
    check("关闭即销毁租户密钥", registry.tenants[tenant].kek_destroyed)
    check("非法状态跃迁被拒",
          refuses(lambda: registry.transition(tenant, ACTIVE, satisfied=set(), actor="ops"),
                  DENY_TRANSITION))

    # 5. environments are a hard partition
    live_key = Credential(id="k1", tenant_id=tenant, project_id="prj_1", environment="live")
    check("测试环境不接受 live 凭据",
          refuses(lambda: registry.credential_valid(live_key, tenant_id=tenant,
                                                    environment="test"),
                  DENY_WRONG_ENVIRONMENT))
    check("另一个租户的凭据被拒",
          refuses(lambda: registry.credential_valid(live_key, tenant_id="ten_other",
                                                    environment="live"), DENY_CROSS_TENANT))
    check("live 处理真实资金、test 不处理",
          registry.handles_real_money("live") and not registry.handles_real_money("test"))
    check("未知环境被拒",
          refuses(lambda: registry.handles_real_money("staging"), DENY_WRONG_ENVIRONMENT))

    # 6. quotas
    quota = MODEL["quotas"][0]
    fresh = Registry(MODEL)
    for _ in range(quota["default"]):
        fresh.consume("prj_1", quota["id"])
    check("配额用尽后被拒",
          refuses(lambda: fresh.consume("prj_1", quota["id"]), DENY_QUOTA))
    check("配额按作用域独立计数", fresh.consume("prj_2", quota["id"]) == 1)
    check("超过硬上限的自定义配额被拒",
          refuses(lambda: fresh.consume("prj_3", quota["id"],
                                        limit=quota["hard_ceiling"] + 1), DENY_QUOTA))
    check("未知配额被拒", refuses(lambda: fresh.consume("prj_1", "made_up"), DENY_QUOTA))

    # 7. the model itself
    check("环境之间不共享密钥",
          all(not e["shares_keys_with"] for e in MODEL["environments"]))
    check("停用与注销两行都保留了在途能力",
          all(row[c] for row in MODEL["capability_matrix"]
              if row["state"] in (SUSPENDED, OFFBOARDING)
              for c in ("issue_refunds", "receive_webhooks", "settle")))
    check("注销保留账本与审计",
          MODEL["offboarding"]["ledger_retained"] and MODEL["offboarding"]["audit_retained"])

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
