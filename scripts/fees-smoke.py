#!/usr/bin/env python3
"""B29 runtime proof — the settlement report does not overwrite the estimate.

Scenario 4 is why this batch exists. The provider reports a different amount
than we computed. The one-line version writes the report over the book value and
the numbers agree again; the question "what did we believe we were charging"
then has no answer, and that question is the entire content of a fee dispute.
This model keeps both and opens a break.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.pricing.reference.fees import (  # noqa: E402
    ALREADY_SETTLED, AMOUNT_NEGATIVE, AMOUNT_NOT_INTEGER, CURRENCY_MISMATCH, DISPUTED,
    ESTIMATED, IMPLICIT_CONVERSION, INCOMPLETE_RATE_RECORD, NO_SCHEDULE, SETTLED,
    SETTLEMENT_OVERDUE, Payment, Pricer, PricingRefused, Rate)

MODEL = json.loads((ROOT / "governance/fee-model.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []
DAY = 500


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
    except PricingRefused as exc:
        return exc.code == code


def payment(pid="pay_0001", provider="stripe", method="card", region="EU", currency="EUR",
            amount=10000, day=DAY) -> Payment:
    return Payment(id=pid, provider=provider, method=method, region=region,
                   currency=currency, amount_minor=amount, day=day)


def main() -> int:
    pricer = Pricer(MODEL)

    # 1. integers only, and the declared rounding
    check("百分比按声明的舍入方式计算",
          pricer.apply_percentage(10000, 140) == 140)
    check("半分向上进位（half_up）",
          pricer.apply_percentage(999, 60) == 6, pricer.apply_percentage(999, 60))
    check("浮点金额被拒绝而不是被舍入",
          refuses(lambda: pricer.apply_percentage(100.5, 60), AMOUNT_NOT_INTEGER))
    check("负数金额被拒",
          refuses(lambda: pricer.apply_percentage(-1, 60), AMOUNT_NEGATIVE))
    check("模型声明了舍入方式", MODEL["rounding"]["declared"] is True)

    # 2. a quote is a breakdown, not a number
    quote = pricer.quote(payment())
    categories = {c.category for c in quote.components}
    check("报价按类别拆开", "provider_cost" in categories and "tax" in categories, categories)
    check("总额等于各部分之和",
          quote.total_minor == sum(c.amount_minor for c in quote.components))
    check("没有费率表的组合被拒——不猜一个默认费率",
          refuses(lambda: pricer.quote(payment(provider="paypal", method="card")),
                  NO_SCHEDULE))

    # 3. tax is not revenue
    revenue = pricer.revenue(quote)
    check("收入只包含平台服务费",
          revenue == quote.by_category("platform_service_fee"), revenue)
    check("税不计入收入", pricer.remitted(quote) == quote.by_category("tax"))
    check("内部成本不向商户收取",
          pricer.charged_to_merchant(quote)
          == quote.total_minor - quote.by_category("internal_cost"))
    check("模型把税标为代收代缴且非收入",
          next(c for c in MODEL["categories"] if c["id"] == "tax")["is_revenue"] is False)

    # 4. THE scenario — settlement disagrees
    book = quote.total_minor
    check("账面值一开始是估计", quote.status == ESTIMATED)
    item = pricer.settle(quote, book + 3, day=DAY + 2, payment_day=DAY)
    check("结算与账面不一致时开出对账项", item is not None and item.difference_minor == 3)
    check("账面值**没有**被覆盖", pricer.book_value(quote) == book)
    check("结算值被单独记录", quote.settled_total_minor == book + 3)
    check("状态变为有争议", quote.status == DISPUTED)
    check("对账项进入列表", len(pricer.breaks) == 1)
    check("重复结算被拒",
          refuses(lambda: pricer.settle(quote, book, day=DAY + 3, payment_day=DAY),
                  ALREADY_SETTLED))
    agreed = pricer.quote(payment(pid="pay_0002"))
    check("一致时不开对账项",
          pricer.settle(agreed, agreed.total_minor, day=DAY + 1, payment_day=DAY) is None)
    check("一致后状态为已结算", agreed.status == SETTLED)
    late = pricer.quote(payment(pid="pay_0003"))
    check("超过最长滞后仍未结算则被拒",
          refuses(lambda: pricer.settle(late, 1, day=DAY + 999, payment_day=DAY),
                  SETTLEMENT_OVERDUE))
    check("模型禁止静默覆盖", MODEL["settlement"]["silent_overwrite_allowed"] is False)

    # 5. the split adds back to the total, exactly
    parts = pricer.split(agreed)
    check("四方之和精确等于总额", sum(parts.values()) == agreed.amount_minor, parts)
    check("余数有明确归属", MODEL["split"]["residue_to"] in parts)
    odd = pricer.quote(payment(pid="pay_0004", amount=9999))
    odd_parts = pricer.split(odd)
    check("奇数金额也不丢一分钱", sum(odd_parts.values()) == 9999, odd_parts)

    # 6. no implicit conversion
    check("同币种不需要汇率",
          pricer.convert(1000, from_currency="EUR", to_currency="EUR", rate=None) == 1000)
    check("跨币种没有汇率记录被拒",
          refuses(lambda: pricer.convert(1000, from_currency="EUR", to_currency="USD",
                                         rate=None), IMPLICIT_CONVERSION))
    check("汇率记录不完整被拒",
          refuses(lambda: pricer.convert(1000, from_currency="EUR", to_currency="USD",
                                         rate=Rate(rate_bp=11000, quoted_at=0, source="ecb")),
                  INCOMPLETE_RATE_RECORD))
    check("完整汇率记录可以换算",
          pricer.convert(1000, from_currency="EUR", to_currency="USD",
                         rate=Rate(rate_bp=11000, quoted_at=DAY, source="ecb")) == 1100)
    check("费用币种必须等于支付币种",
          refuses(lambda: pricer.require_same_currency(agreed, payment(currency="USD")),
                  CURRENCY_MISMATCH))

    # 7. metering is idempotent and recomputable
    fresh = Pricer(MODEL)
    one = fresh.quote(payment(pid="pay_a"))
    check("首次计量被记录", fresh.record(one) == "RECORDED")
    check("重复投递不重复计费", fresh.record(one) == "DUPLICATE")
    check("重复计数被保留", fresh.meter.duplicates == 1)
    payments = [payment(pid="pay_a"), payment(pid="pay_b", amount=20000)]
    for entry in payments:
        fresh.record(fresh.quote(entry))
    check("任何一天的计量都能从原始事件重新推导",
          fresh.recompute(payments) == fresh.metered_total())

    # 8. the model itself
    check("四个费用类别齐全", len(MODEL["categories"]) == 4)
    check("平台服务费都有封顶",
          all(s["max_minor"] > 0 for s in MODEL["schedules"]
              if s["category"] == "platform_service_fee" and s["percentage_bp"]))
    check("容差为零", MODEL["settlement"]["tolerance_minor"] == 0)
    check("计量按支付 ID 幂等", MODEL["metering"]["event_key"] == "payment_id")

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
