#!/usr/bin/env python3
"""B22 runtime proof — hand the hardening layer the things that actually leak.

The centrepiece is scenario 1: a real-shaped stack trace carrying a card number,
a live-looking API key and a bearer token. This is not a hypothetical — a
provider error containing all three is exactly what ends up in a log
aggregator, a crash reporter and a support ticket within the same minute.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.appsec.reference.hardening import (  # noqa: E402
    MASKED_CARD, REDACTED, ValidationError, check_cors, check_request, luhn, parse_amount,
    redact, security_headers)

BASELINE = json.loads((ROOT / "governance/security-baseline.json").read_text(encoding="utf-8"))

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
    except ValidationError as exc:
        return exc.code == code


def main() -> int:
    trace = ("ProviderError: declined\n"
             "  request: {\"card\": \"4111 1111 1111 1111\", \"cvv\": \"123\"}\n"
             "  api_key=sk_live_9aXbYcZd0123456789\n"  # paygov:allow-secret-pattern
             "  Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\n")  # paygov:allow-secret-pattern
    cleaned = redact(trace)
    check("卡号从堆栈里被抹掉", "4111 1111 1111 1111" not in cleaned and MASKED_CARD in cleaned)
    check("API 密钥被抹掉",  # paygov:allow-secret-pattern
          "sk_live_9aXbYcZd0123456789" not in cleaned  # paygov:allow-secret-pattern
          and REDACTED in cleaned)
    check("Bearer 令牌被抹掉", "eyJzdWIiOiIxIn0" not in cleaned)
    check("有用的部分留下来了", "declined" in cleaned)
    check("普通长数字不会被误伤", redact("order 1234567890123 ok") == "order 1234567890123 ok")
    check("Luhn 校验区分卡号与流水号", luhn("4111111111111111") and not luhn("4111111111111112"))

    check("缺少安全响应头会被报出",
          len(security_headers({"content-type": "application/json"})) >= 4)
    check("完整的响应头集合通过", security_headers({
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer"}) == [])
    check("被关掉的 HSTS 会被报出",
          any("max-age=0" in p for p in security_headers({
              "Strict-Transport-Security": "max-age=0",
              "Content-Security-Policy": "default-src 'self'",
              "X-Content-Type-Options": "nosniff",
              "Referrer-Policy": "no-referrer"})))

    check("通配符 CORS + 凭据被拒",
          bool(check_cors({"Access-Control-Allow-Origin": "*",
                           "Access-Control-Allow-Credentials": "true"})))
    check("通配符 CORS 不带凭据可以接受",
          check_cors({"Access-Control-Allow-Origin": "*"}) == [])
    check("null origin 被拒", bool(check_cors({"Access-Control-Allow-Origin": "null"})))

    check("浮点金额被拒", refuses(lambda: parse_amount(12.5, currency_exponent=2),
                                  "AMOUNT_NOT_INTEGER"))
    check("带小数点的字符串金额被拒",
          refuses(lambda: parse_amount("12.50", currency_exponent=2), "AMOUNT_NOT_INTEGER"))
    check("科学计数法被拒",
          refuses(lambda: parse_amount("1e3", currency_exponent=2), "AMOUNT_NOT_INTEGER"))
    check("负数金额被拒", refuses(lambda: parse_amount(-1, currency_exponent=2),
                                  "AMOUNT_NEGATIVE"))
    check("超大金额被拒", refuses(lambda: parse_amount(10 ** 13, currency_exponent=2),
                                  "AMOUNT_TOO_LARGE"))
    check("整数最小单位被接受", parse_amount("1250", currency_exponent=2) == 1250)

    check("写操作缺少幂等键会被报出",
          any("idempotency" in p for p in check_request(
              "POST", {"Authorization": "Bearer x", "Content-Type": "application/json"})))
    check("完整的写请求通过", check_request("POST", {
        "Authorization": "Bearer x", "Idempotency-Key": "k",
        "Content-Type": "application/json"}) == [])
    check("未认证请求会被报出", any("authorization" in p for p in check_request("GET", {})))

    applicable = [r for r in BASELINE["requirements"] if r["applicability"] != "mobile"]
    enforced = [r for r in applicable if r["enforcement"]["kind"] in {"gate_rule", "test"}]
    gaps = [r for r in BASELINE["requirements"] if r["enforcement"]["kind"] == "accepted_gap"]
    check("覆盖率高于声明的下限",
          len(enforced) / len(applicable) >= BASELINE["coverage_policy"]["minimum_covered_ratio"],
          f"{len(enforced)}/{len(applicable)}")
    check("缺口数量在上限之内",
          len(gaps) <= BASELINE["coverage_policy"]["max_accepted_gaps"], len(gaps))
    check("每个缺口都有负责人与复核批次",
          all(r["enforcement"]["owner"] and r["enforcement"]["review_batch"] for r in gaps))

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
