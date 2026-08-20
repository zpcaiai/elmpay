#!/usr/bin/env python3
"""B27 runtime proof — the payer finds out before entering their card details.

Scenario 1 is why this batch exists. An Android user in Singapore selects Apple
Pay. A matrix that defaults to allow sends that to the provider and the failure
comes back after the payer has committed, as a third-party error code. This
matrix refuses at selection time, and names the dimension that failed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.capability.reference.matrix import (  # noqa: E402
    ALREADY_CAPTURED, AUTH_EXPIRED, CURRENCY_UNSUPPORTED, DEVICE_UNSUPPORTED,
    DISPUTE_AUTO_ACCEPT, DISPUTE_DEADLINE_PASSED, DISPUTE_EVIDENCE_INCOMPLETE,
    DISPUTE_WINDOW_CLOSED, NO_AUTHORIZATION_STEP, OVER_CAPTURE, OVER_REFUND,
    PARTIAL_CAPTURE_UNSUPPORTED, PROVIDER_UNAVAILABLE, REFUND_ELSEWHERE,
    REFUND_WINDOW_CLOSED, REGION_FORBIDS_METHOD, SILENT_FALLBACK, SUBSCRIPTION_UNSUPPORTED,
    UNKNOWN_METHOD, UNKNOWN_PROVIDER, UNSUPPORTED, CapabilityRefused, Matrix, Request)

MODEL = json.loads((ROOT / "governance/provider-capabilities.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []
HOUR = 1000
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
    except CapabilityRefused as exc:
        return exc.code == code


def main() -> int:
    matrix = Matrix(MODEL)
    card_sg = Request("stripe", "card", "SG", "USD", "web")
    wechat_cn = Request("wechat", "wechat_pay", "CN", "CNY", "ios")
    paypal_eu = Request("paypal", "paypal_wallet", "EU", "EUR", "web")

    # 1. the matrix refuses before the payer commits
    check("声明过的组合可用", matrix.supports(card_sg))
    check("Android 上没有 Apple Pay——设备维度是硬限制",
          refuses(lambda: matrix.resolve(Request("stripe", "apple_pay", "SG", "USD", "android")),
                  DEVICE_UNSUPPORTED))
    check("地区不允许的方式在解析阶段就被拒",
          refuses(lambda: matrix.resolve(Request("wechat", "wechat_pay", "SG", "SGD", "web")),
                  REGION_FORBIDS_METHOD))
    check("渠道支持但币种没声明 → 拒绝",
          refuses(lambda: matrix.resolve(Request("stripe", "card", "SG", "CNY", "web")),
                  CURRENCY_UNSUPPORTED))
    check("未知渠道被拒",
          refuses(lambda: matrix.resolve(Request("klarna", "card", "EU", "EUR", "web")),
                  UNKNOWN_PROVIDER))
    check("未知支付方式被拒",
          refuses(lambda: matrix.resolve(Request("stripe", "crypto", "EU", "EUR", "web")),
                  UNKNOWN_METHOD))
    check("未知地区被拒",
          refuses(lambda: matrix.resolve(Request("stripe", "card", "US", "USD", "web")),
                  UNSUPPORTED))
    check("渠道与方式的组合没声明就是不支持",
          refuses(lambda: matrix.resolve(Request("paypal", "card", "EU", "EUR", "web")),
                  UNSUPPORTED))
    check("模型默认拒绝", MODEL["resolution"]["default"] == "deny")

    # 2. no silent substitution
    check("不能静默换渠道",
          refuses(lambda: matrix.fallback(card_sg,
                                          Request("paypal", "paypal_wallet", "SG", "USD",
                                                  "web")), SILENT_FALLBACK))
    check("不能静默换支付方式",
          refuses(lambda: matrix.fallback(card_sg,
                                          Request("stripe", "apple_pay", "SG", "USD", "web")),
                  SILENT_FALLBACK))
    check("维护窗口内拒绝而不是改道",
          refuses(lambda: matrix.check_available("wechat", in_maintenance=True),
                  PROVIDER_UNAVAILABLE))
    check("非维护期正常", matrix.check_available("wechat", in_maintenance=False) == "OK")

    # 3. authorisation expires
    check("钱包没有授权/捕获两段式",
          refuses(lambda: matrix.authorize(wechat_cn, 9900, hour=HOUR), NO_AUTHORIZATION_STEP))
    auth = matrix.authorize(card_sg, 10000, hour=HOUR)
    expires = matrix.authorization_expires_at(auth)
    check("卡授权七天后过期", expires - HOUR == 168, expires - HOUR)
    check("超额捕获被拒",
          refuses(lambda: matrix.capture(auth, 10001, hour=HOUR + 1), OVER_CAPTURE))
    check("过期后捕获被拒——即使收单机构可能会接受",
          refuses(lambda: matrix.capture(auth, 10000, hour=expires), AUTH_EXPIRED))
    check("有效期内部分捕获可用", matrix.capture(auth, 6000, hour=HOUR + 1) == 6000)
    check("重复捕获被拒",
          refuses(lambda: matrix.capture(auth, 1000, hour=HOUR + 2), ALREADY_CAPTURED))
    stale = matrix.authorize(card_sg, 10000, hour=HOUR)
    fresh = matrix.reauthorize(stale, hour=HOUR + 200)
    check("过期后必须重新授权而不是复用", fresh is not stale)
    check("未过期时重新授权返回原授权",
          matrix.reauthorize(stale, hour=HOUR + 1) is stale)
    apple_cn = Request("apple_pay", "apple_pay", "CN", "CNY", "ios")
    apple_auth = matrix.authorize(apple_cn, 10000, hour=HOUR)
    check("不支持部分捕获的渠道拒绝部分捕获",
          refuses(lambda: matrix.capture(apple_auth, 5000, hour=HOUR + 1),
                  PARTIAL_CAPTURE_UNSUPPORTED))

    # 4. refunds have a window and a direction
    check("窗口内可以退款",
          matrix.refund(auth, 6000, paid_on_day=DAY, day=DAY + 10) == 6000)
    check("超过捕获金额退款被拒",
          refuses(lambda: matrix.refund(auth, 6001, paid_on_day=DAY, day=DAY + 10),
                  OVER_REFUND))
    closes = matrix.refund_closes_on(card_sg, DAY)
    check("退款窗口有明确的关闭日", closes - DAY == 180, closes - DAY)
    check("窗口关闭后不再提供退款按钮",
          matrix.may_offer_refund(card_sg, paid_on_day=DAY, day=closes) is False)
    check("窗口关闭后退款被拒并指出替代路径",
          refuses(lambda: matrix.refund(auth, 100, paid_on_day=DAY, day=closes),
                  REFUND_WINDOW_CLOSED))
    check("退款必须原路返回",
          refuses(lambda: matrix.refund(auth, 100, paid_on_day=DAY, day=DAY + 1,
                                        to_original_instrument=False), REFUND_ELSEWHERE))
    check("模型不允许在窗口外承诺退款",
          MODEL["refund"]["promise_beyond_window"] is False)

    # 5. disputes — the clock is not ours
    due = matrix.open_dispute(card_sg, paid_on_day=DAY, day=DAY + 30)
    check("争议答复时限由渠道设定", due - (DAY + 30) == 20, due - (DAY + 30))
    check("争议窗口外不能再开",
          refuses(lambda: matrix.open_dispute(card_sg, paid_on_day=DAY, day=DAY + 121),
                  DISPUTE_WINDOW_CLOSED))
    check("举证材料不全不能应诉",
          refuses(lambda: matrix.respond_to_dispute(card_sg, opened_on_day=DAY + 30,
                                                    day=DAY + 35,
                                                    evidence={"order_record"}),
                  DISPUTE_EVIDENCE_INCOMPLETE))
    check("材料齐全可以应诉",
          matrix.respond_to_dispute(
              card_sg, opened_on_day=DAY + 30, day=DAY + 35,
              evidence=set(MODEL["dispute"]["evidence_required"])) == "CONTESTED")
    check("错过时限即判负，没有申诉",
          refuses(lambda: matrix.respond_to_dispute(
              card_sg, opened_on_day=DAY + 30, day=due + 1,
              evidence=set(MODEL["dispute"]["evidence_required"])), DISPUTE_DEADLINE_PASSED))
    check("不允许自动认赔",
          refuses(lambda: matrix.respond_to_dispute(card_sg, opened_on_day=DAY + 30,
                                                    day=DAY + 31, evidence=set(),
                                                    accept=True, automated=True),
                  DISPUTE_AUTO_ACCEPT))
    check("人工认赔可以",
          matrix.respond_to_dispute(card_sg, opened_on_day=DAY + 30, day=DAY + 31,
                                    evidence=set(), accept=True) == "ACCEPTED")

    # 6. subscriptions and SCA
    check("支持订阅的组合可以开通", matrix.start_subscription(paypal_eu) == "OK")
    check("不支持订阅的组合被拒",
          refuses(lambda: matrix.start_subscription(Request("stripe", "apple_pay", "EU", "EUR",
                                                            "ios")), SUBSCRIPTION_UNSUPPORTED))
    check("欧盟强制强客户认证", matrix.requires_strong_customer_authentication("EU"))
    check("境内不强制", matrix.requires_strong_customer_authentication("CN") is False)

    # 7. the model itself
    check("每个渠道都有可用性行",
          {a["provider"] for a in MODEL["availability"]} ==
          {c["provider"] for c in MODEL["capabilities"]})
    check("没有任何一行允许超额捕获",
          all(c["capture_max_percent"] == 100 for c in MODEL["capabilities"]))
    check("答复时限都短于争议窗口",
          all(c["dispute_response_days"] < c["dispute_window_days"]
              for c in MODEL["capabilities"]))

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
