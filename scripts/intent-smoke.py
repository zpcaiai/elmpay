#!/usr/bin/env python3
"""B32 runtime proof — the amount a payer agreed to is the amount that is taken.

Scenario 1 is why this batch exists. Every route to changing a created intent's
amount is closed: the snapshot is a frozen dataclass, ``amend()`` refuses the
snapshot fields by name, and there is no privileged caller. Changing the amount
means creating a second intent, which is exactly what it is.
"""
from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.intent.reference.intent import (  # noqa: E402
    ALREADY_TERMINAL, AMOUNT_IMMUTABLE, AMOUNT_NOT_INTEGER, AMOUNT_NOT_POSITIVE, AUTHORIZED,
    CAPTURED, CURRENCY_UNKNOWN, DUPLICATE_LIVE_INTENT, EXPIRED, EXPIRY_NOT_EXTENDABLE,
    EXPIRY_TOO_LONG, IDEMPOTENCY_KEY_REUSED, ILLEGAL_TRANSITION, INTENT_EXPIRED,
    METHOD_NOT_ALLOWED, METHOD_WIDENED, NOT_SCHEDULER, NO_IDEMPOTENCY_KEY, ORDER_CONTENT_FORBIDDEN,
    OVER_CAPTURE, OVER_REFUND, RETURN_PAGE_NOT_EVIDENCE, UNKNOWN_INTENT, UNTRUSTED_SOURCE,
    IntentRefused, Intents)

MODEL = json.loads((ROOT / "governance/payment-intent.json").read_text(encoding="utf-8"))
CAPS = json.loads((ROOT / "governance/provider-capabilities.json").read_text(encoding="utf-8"))
CUR = json.loads((ROOT / "governance/currency-metadata.json").read_text(encoding="utf-8"))

CURRENCIES = {c["code"] for c in CUR["currencies"]}
METHODS = {m["id"] for m in CAPS["payment_methods"]}

CHECKS: list[str] = []
FAILURES: list[str] = []
MINUTE = 10_000


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
    except IntentRefused as exc:
        return exc.code == code


def service() -> Intents:
    return Intents(MODEL, CURRENCIES, METHODS)


def make(intents: Intents, intent_id="pi_1", ref="order_1", amount=10000, currency="EUR",
         methods=("card", "paypal_wallet"), minute=MINUTE, **kw):
    return intents.create(intent_id, tenant_id="ten_1", project_id="prj_1",
                          external_reference=ref, amount_minor=amount, currency=currency,
                          allowed_methods=methods, now_minute=minute, **kw)


def main() -> int:
    intents = service()
    intent = make(intents)

    # 1. THE property — the amount cannot change
    check("金额快照是冻结的 dataclass",
          dataclasses.fields(intent.snapshot) and getattr(type(intent.snapshot),
                                                          "__dataclass_params__").frozen)
    frozen = False
    try:
        setattr(intent.snapshot, "amount_minor", 1)
    except dataclasses.FrozenInstanceError:
        frozen = True
    check("直接改快照字段会抛 FrozenInstanceError", frozen)
    check("amend() 按名字拒绝金额",
          refuses(lambda: intents.amend(intent, amount_minor=99), AMOUNT_IMMUTABLE))
    check("amend() 同样拒绝币种",
          refuses(lambda: intents.amend(intent, currency="USD"), AMOUNT_IMMUTABLE))
    check("改金额的正确做法是新建一笔",
          make(intents, intent_id="pi_2", ref="order_2", amount=99).amount_minor == 99)
    check("模型要求改金额必须新建",
          MODEL["amount_snapshot"]["change_requires_new_intent"] is True)

    # 2. creation refuses the shapes that cause incidents
    check("浮点金额被拒",
          refuses(lambda: make(intents, intent_id="x", ref="o", amount=10.5),
                  AMOUNT_NOT_INTEGER))
    check("零金额意图被拒",
          refuses(lambda: make(intents, intent_id="x", ref="o", amount=0),
                  AMOUNT_NOT_POSITIVE))
    check("负金额被拒",
          refuses(lambda: make(intents, intent_id="x", ref="o", amount=-1),
                  AMOUNT_NOT_POSITIVE))
    check("未知币种被拒",
          refuses(lambda: make(intents, intent_id="x", ref="o", currency="XYZ"),
                  CURRENCY_UNKNOWN))
    check("未知支付方式被拒",
          refuses(lambda: make(intents, intent_id="x", ref="o", methods=("crypto",)),
                  METHOD_NOT_ALLOWED))
    check("**同一业务订单不能有第二笔在途意图**",
          refuses(lambda: make(intents, intent_id="pi_dup", ref="order_1"),
                  DUPLICATE_LIVE_INTENT))
    check("复制订单内容进来被拒",
          refuses(lambda: make(intents, intent_id="x", ref="o",
                               line_items=[{"sku": "A"}]), ORDER_CONTENT_FORBIDDEN))
    check("超过最长有效期被拒",
          refuses(lambda: make(intents, intent_id="x", ref="o",
                               expires_in_minutes=MODEL["expiry"]["max_minutes"] + 1),
                  EXPIRY_TOO_LONG))
    check("未知意图查询被拒", refuses(lambda: intents.get("pi_nope"), UNKNOWN_INTENT))

    # 3. expiry cannot be extended, and expired cannot be confirmed
    check("延长有效期的方法只会抛异常",
          refuses(lambda: intents.extend_expiry(intent, 60), EXPIRY_NOT_EXTENDABLE))
    check("amend() 也改不了有效期",
          refuses(lambda: intents.amend(intent, expires_at_minute=10 ** 9),
                  EXPIRY_NOT_EXTENDABLE))
    expires = intent.snapshot.expires_at_minute
    check("过期后不能确认",
          refuses(lambda: intents.confirm(intent, method="card", idempotency_key="k",
                                          now_minute=expires), INTENT_EXPIRED))
    check("只有调度器能把意图置为过期",
          refuses(lambda: intents.expire(intent, now_minute=expires, actor="api"),
                  NOT_SCHEDULER))
    check("未到期不能置为过期",
          refuses(lambda: intents.expire(intent, now_minute=MINUTE, actor="scheduler"),
                  ILLEGAL_TRANSITION))
    stale = service()
    stale_intent = make(stale, intent_id="pi_stale", ref="order_stale")
    stale.expire(stale_intent, now_minute=stale_intent.snapshot.expires_at_minute,
                 actor="scheduler")
    check("过期后状态为 expired", stale_intent.state == EXPIRED)
    check("过期后原订单可以开新意图",
          make(stale, intent_id="pi_new", ref="order_stale").id == "pi_new")

    # 4. confirmation is idempotent and method-constrained
    fresh = service()
    live = make(fresh, intent_id="pi_live", ref="order_live")
    check("确认必须带幂等键",
          refuses(lambda: fresh.confirm(live, method="card", idempotency_key="",
                                        now_minute=MINUTE), NO_IDEMPOTENCY_KEY))
    check("快照外的支付方式被拒",
          refuses(lambda: fresh.confirm(live, method="wechat_pay", idempotency_key="k1",
                                        now_minute=MINUTE), METHOD_NOT_ALLOWED))
    first = fresh.confirm(live, method="card", idempotency_key="k1", now_minute=MINUTE)
    check("同一幂等键返回同一结果",
          fresh.confirm(live, method="card", idempotency_key="k1", now_minute=MINUTE) == first)
    check("换一个幂等键再确认被拒——那是第二次付款",
          refuses(lambda: fresh.confirm(live, method="card", idempotency_key="k2",
                                        now_minute=MINUTE), IDEMPOTENCY_KEY_REUSED))
    check("事后放宽支付方式被拒",
          refuses(lambda: fresh.narrow_methods(live, ("card", "wechat_pay")), METHOD_WIDENED))
    check("事后收窄是允许的",
          fresh.narrow_methods(live, ("card",)).snapshot.allowed_methods == ("card",))
    check("收窄不影响金额快照", live.amount_minor == 10000)

    # 5. success comes from a verified event, never the browser
    check("回跳页不能把意图置为成功",
          refuses(lambda: fresh.succeed_from_return_page(live), RETURN_PAGE_NOT_EVIDENCE))
    check("不可信来源的状态跃迁被拒",
          refuses(lambda: fresh.transition(live, AUTHORIZED, source="client_return_page"),
                  UNTRUSTED_SOURCE))
    fresh.transition(live, AUTHORIZED, source="verified_provider_event")
    check("已验签渠道事件可以授权", live.state == AUTHORIZED)
    check("非法跃迁被拒",
          refuses(lambda: fresh.transition(live, "created",
                                           source="verified_provider_event"),
                  ILLEGAL_TRANSITION))

    # 6. amount invariants
    check("超额捕获被拒",
          refuses(lambda: fresh.capture(live, 10001, source="verified_provider_event"),
                  OVER_CAPTURE))
    check("正常捕获", fresh.capture(live, 10000, source="verified_provider_event") == 10000)
    check("捕获后状态为 captured", live.state == CAPTURED)
    check("终态后不能再跃迁",
          refuses(lambda: fresh.transition(live, "failed",
                                           source="verified_provider_event"),
                  ALREADY_TERMINAL))
    check("超额退款被拒", refuses(lambda: fresh.refund(live, 10001), OVER_REFUND))
    check("正常退款", fresh.refund(live, 4000) == 4000)

    # 7. the model itself
    machines = json.loads((ROOT / "governance/state-machines.json").read_text(encoding="utf-8"))
    machine = next(m for m in machines["machines"] if m["entity"] == "PaymentIntent")
    check("状态与 B10 完全一致", MODEL["lifecycle"]["states"] == machine["states"])
    check("终态与 B10 完全一致", MODEL["lifecycle"]["terminal"] == machine["terminal"])
    check("成功态与 B10 完全一致",
          MODEL["lifecycle"]["success_states"] == machines["success_states"]["PaymentIntent"])
    check("客户端引用不含凭证", MODEL["client_secret"]["contains_credentials"] is False)
    check("订单归原项目所有", MODEL["order_link"]["owner"] == "originating_project")

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
