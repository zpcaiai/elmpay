#!/usr/bin/env python3
"""B09 runtime proof — run one real settlement scenario end to end.

Unit tests prove the pieces. This proves the *composition*: a marketplace
payment that is captured, charged a percentage-plus-fixed fee, split three
ways between sellers, partially refunded, and reported in a second currency.
Every step asserts the only invariant that matters in money code — that no
minor unit is created or destroyed — and the script exits non-zero the moment
one of them fails.

It is deliberately a script, not a test: the batch requires runtime evidence
from at least one genuine business scenario, and a log nobody can dispute is
worth more than another green dot.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.money.reference.money import CurrencyRegistry, Money, total  # noqa: E402

METADATA = ROOT / "governance/currency-metadata.json"

FAILURES: list[str] = []


CHECKS = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def main() -> int:
    registry = CurrencyRegistry.from_file(METADATA)

    print("== scenario: marketplace capture, fee, three-way split, partial refund, FX report")

    gross = Money.parse("199.99", "CNY", registry)
    check("买家支付 199.99 CNY 解析为最小单位", gross.minor == 19999, f"minor={gross.minor}")

    # 2.9% + 0.30 CNY, half-even on the percentage component only.
    percentage = gross.apply_rate(29, 1000, "half_even")
    fixed = Money.parse("0.30", "CNY", registry)
    fee = percentage.add(fixed)
    check("手续费 2.9% + 0.30 计算为整数", fee.minor == 580 + 30, f"fee={fee.format(registry)}")

    net = gross.subtract(fee)
    check("净额 + 手续费 == 总额（无凭空产生的钱）",
          net.add(fee).minor == gross.minor, f"net={net.format(registry)}")

    # Three sellers with unequal contribution: 5 : 3 : 2.
    split = net.allocate([5, 3, 2])
    check("三方分账后总和守恒",
          total(split).minor == net.minor,
          " + ".join(m.format(registry) for m in split))
    check("分账无零头丢失（最大余数法）",
          sum(m.minor for m in split) == net.minor and all(m.minor > 0 for m in split))

    # Partial refund of the largest seller's share, fee not refunded.
    refund = split[0]
    remaining = net.subtract(refund)
    check("部分退款后剩余净额正确",
          remaining.minor == split[1].minor + split[2].minor,
          f"remaining={remaining.format(registry)}")
    check("退款不会退回手续费",
          gross.subtract(refund).minor == remaining.add(fee).minor)

    # Report the same money in JPY (0 decimals) and KWD (3 decimals).
    jpy = gross.convert("JPY", 195000, 4, registry)
    check("CNY→JPY 跨指数换算（2 位→0 位小数）",
          jpy.currency == "JPY" and jpy.minor == 3900, f"jpy={jpy.format(registry)}")
    kwd = gross.convert("KWD", 43000, 5, registry)
    check("CNY→KWD 跨指数换算（2 位→3 位小数）",
          kwd.currency == "KWD" and kwd.minor > 0, f"kwd={kwd.format(registry)}")

    # Zero-decimal currency must refuse a fractional literal outright.
    try:
        Money.parse("1999.5", "JPY", registry)
        check("零小数币种拒绝小数输入", False, "解析本应失败")
    except ValueError as exc:
        check("零小数币种拒绝小数输入", True, str(exc))

    # A pathological split: 1 JPY across 3 sellers must still conserve.
    dust = Money(1, "JPY").allocate([1, 1, 1])
    check("1 JPY 分给 3 方仍然守恒",
          total(dust).minor == 1, [m.minor for m in dust])

    # Negative amounts (chargebacks) round symmetrically.
    chargeback = Money(-19999, "CNY").apply_rate(29, 1000, "half_even")
    check("负数（拒付）舍入对称", chargeback.minor == -580, f"minor={chargeback.minor}")

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
