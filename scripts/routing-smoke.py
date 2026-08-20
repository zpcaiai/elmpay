#!/usr/bin/env python3
"""B28 runtime proof — the same payment routes the same way, months later.

Scenario 1 is why this batch exists. A decision is recorded with the
configuration version that produced it, and replaying that version reproduces
the decision exactly. Without it, "why did this payment go to that provider" has
no answer at the only moment anyone asks: during a dispute or a reconciliation
break, long after the configuration moved on.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.routing.reference.router import (  # noqa: E402
    AMOUNT_ABOVE_CEILING, CANARY_TOO_LARGE, NOT_APPROVED, NO_PREVIOUS_VERSION,
    RETRIES_EXHAUSTED, RETRY_KEY_CHANGED, RETRY_PROVIDER_CHANGED, SELF_APPROVAL,
    SHADOW_CANNOT_MOVE_MONEY, UNKNOWN_VERSION, UNROUTABLE, VERSION_IMMUTABLE, Attempt,
    Payment, Router, RoutingRefused, stable_bucket)

MODEL = json.loads((ROOT / "governance/routing-policy.json").read_text(encoding="utf-8"))
CAPS = json.loads((ROOT / "governance/provider-capabilities.json").read_text(encoding="utf-8"))

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
    except RoutingRefused as exc:
        return exc.code == code


def payment(intent="pi_0001", region="EU", method="card", currency="EUR", amount=5000,
            key="idem_0001") -> Payment:
    return Payment(intent_id=intent, region=region, method=method, currency=currency,
                   amount_minor=amount, idempotency_key=key)


def scores(**overrides) -> dict:
    base = {"stripe": {"success_rate": 9800, "cost": 7000, "risk": 9000, "sample": 5000},
            "paypal": {"success_rate": 9500, "cost": 8000, "risk": 8000, "sample": 5000},
            "wechat": {"success_rate": 9900, "cost": 9000, "risk": 9500, "sample": 5000},
            "alipay": {"success_rate": 9900, "cost": 9000, "risk": 9500, "sample": 5000}}
    base.update(overrides)
    return base


def live() -> Router:
    router = Router(MODEL, CAPS)
    router.publish("v1", MODEL["rules"])
    router.activate("v1", approvers=("risk", "ops"), actor="release")
    return router


def main() -> int:
    router = live()

    # 1. deterministic and replayable
    first = router.route(payment(), scores())
    second = router.route(payment(), scores())
    check("同输入同决定", (first.provider, first.rule_id) == (second.provider, second.rule_id))
    check("决定带着配置版本", first.config_version == "v1")
    check("决定可以被重放", router.replay(payment(), scores(), first))
    check("未知版本不能路由",
          refuses(lambda: router.route(payment(), scores(), version="v9"), UNKNOWN_VERSION))
    check("没有可用规则时拒绝而不是随便挑",
          refuses(lambda: router.route(payment(region="SG", currency="USD"), scores()),
                  UNROUTABLE))
    check("超过金额上限被拒",
          refuses(lambda: router.route(payment(amount=10 ** 9), scores()),
                  AMOUNT_ABOVE_CEILING))
    check("模型禁止随机选择", MODEL["determinism"]["random_selection_allowed"] is False)

    # 2. versions are immutable, activation needs two people, rollback needs none
    check("同名版本不能重复发布",
          refuses(lambda: router.publish("v1", MODEL["rules"]), VERSION_IMMUTABLE))
    router.publish("v2", MODEL["rules"])
    check("发布者不能是自己的批准人",
          refuses(lambda: router.activate("v2", approvers=("ops",), actor="ops"),
                  SELF_APPROVAL))
    check("一个批准人不够",
          refuses(lambda: router.activate("v2", approvers=("ops",), actor="release"),
                  NOT_APPROVED))
    router.activate("v2", approvers=("ops", "risk"), actor="release")
    check("生效后走新版本", router.route(payment(), scores()).config_version == "v2")
    check("回滚不需要审批，且切回的是已有版本", router.rollback() == "v1")
    check("回滚后决定回到旧版本", router.route(payment(), scores()).config_version == "v1")
    fresh = Router(MODEL, CAPS)
    fresh.publish("v1", MODEL["rules"])
    fresh.activate("v1", approvers=("ops", "risk"), actor="release")
    check("没有上一个版本时回滚被拒",
          refuses(fresh.rollback, NO_PREVIOUS_VERSION))
    check("模型要求回滚只能切回已有版本",
          MODEL["rollback"]["to_existing_version_only"] is True)
    check("模型不给回滚加审批", MODEL["rollback"]["requires_approval"] is False)

    # 3. exploration floor — a starved provider can still come back
    multi = Router(MODEL, CAPS)
    multi.publish("m1", [{"id": "eu_cards", "priority": 10,
                          "when": {"region": "EU", "method": "card", "currency": "EUR",
                                   "max_amount_minor": 2000000},
                          "prefer": ["stripe"], "fallback": ["paypal"], "notes": "x"}])
    multi.activate("m1", approvers=("ops", "risk"), actor="release")
    floor = MODEL["scoring"]["exploration_floor_percent"]
    share = multi.allocation(["stripe", "paypal"], scores())
    check("最优渠道拿大头", share["stripe"] == 100 - floor, share)
    check("落后的渠道仍保有探索下限——否则它永远无法证明自己恢复了",
          share["paypal"] == floor)
    dire = multi.allocation(["stripe", "paypal"],
                            scores(paypal={"success_rate": 0, "cost": 0, "risk": 0,
                                           "sample": 5000}))
    check("即使成功率为零也不会被彻底饿死", dire["paypal"] == floor)
    check("只有一个候选时不做无谓拆分",
          multi.allocation(["stripe"], scores()) == {"stripe": 100})
    check("样本不足时不认可其成功率",
          multi.has_enough_sample("paypal",
                                  scores(paypal={"success_rate": 10000, "sample": 3})) is False)
    check("并列时按渠道 ID 取最小而不是随机",
          multi.rank(["paypal", "stripe"],
                     {"stripe": {"success_rate": 10000}, "paypal": {"success_rate": 10000}})[0]
          == "paypal")

    # 4. the canary splits on the payment, so a retry stays in its branch
    percent = MODEL["canary"]["max_percent"]
    branches = {p: router.branch(payment(intent=f"pi_{p:04d}"), percent) for p in range(200)}
    canary = sum(1 for b in branches.values() if b == "canary")
    check("灰度比例大致符合", 0 < canary < 200, f"{canary}/200")
    check("同一笔支付永远落在同一分支",
          all(router.branch(payment(intent=f"pi_{p:04d}"), percent) == branches[p]
              for p in range(200)))
    check("重试不会换分支——这正是重复扣款的来源",
          router.branch(payment(intent="pi_0001"), percent)
          == router.branch(payment(intent="pi_0001", key="idem_retry"), percent))
    check("超过灰度上限被拒",
          refuses(lambda: router.branch(payment(), percent + 1), CANARY_TOO_LARGE))
    check("分流是稳定哈希不是随机数",
          stable_bucket("pi_0001") == stable_bucket("pi_0001"))
    check("模型禁止随机分流", MODEL["canary"]["random_split_allowed"] is False)
    check("模型关闭自动放量、打开自动回滚",
          MODEL["canary"]["auto_promote"] is False
          and MODEL["canary"]["auto_rollback_on_error_rate"] is True)

    # 5. the shadow cannot move money
    shadow = router.simulate(payment(), scores(), version="v1")
    check("影子评估能算出决定", shadow.provider == first.provider)
    check("影子评估不能动钱",
          refuses(lambda: router.execute(shadow, shadow=True), SHADOW_CANNOT_MOVE_MONEY))
    check("正式执行可以", router.execute(shadow, shadow=False) == "SENT")

    # 6. a retry is a retry
    attempt = Attempt(payment=payment(), decision=first)
    check("重试换了幂等键就不是重试",
          refuses(lambda: router.retry(attempt, payment(key="idem_other")),
                  RETRY_KEY_CHANGED))
    check("重试不能换渠道——第一次的终态还没到",
          refuses(lambda: router.retry(attempt, payment(), provider="paypal"),
                  RETRY_PROVIDER_CHANGED))
    router.retry(attempt, payment())
    check("退避是递增的", router.backoff(2) < router.backoff(3))
    router.retry(attempt, payment())
    check("超过次数上限后停止",
          refuses(lambda: router.retry(attempt, payment()), RETRIES_EXHAUSTED))

    # 7. the model itself
    check("因子权重合计 100",
          sum(f["weight"] for f in MODEL["scoring"]["factors"]) == 100)
    check("优先级互不重复",
          len({r["priority"] for r in MODEL["rules"]}) == len(MODEL["rules"]))
    check("每条规则的目标渠道都能服务该组合",
          all(any(row["provider"] == p and row["method"] == r["when"]["method"]
                  and r["when"]["region"] in row["regions"]
                  and r["when"]["currency"] in row["currencies"]
                  for row in CAPS["capabilities"])
              for r in MODEL["rules"] for p in r["prefer"] + r["fallback"]))

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
