#!/usr/bin/env python3
"""B33 runtime proof — a timeout does not become a retry.

Scenario 2 is why this batch exists. The provider call times out; the outcome is
unknown, not failed. The next attempt is refused until the unknown is resolved
by a query or the settlement file, because the money may already have moved and
the second call is how it moves twice.
"""
from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.attempt.reference.attempt import (  # noqa: E402
    ATTEMPT_IS_FINAL, FAILED, FAILED_FINAL, FAILED_RETRYABLE, ILLEGAL_TRANSITION, KEY_CHANGED,
    KEY_REUSED_FOR_REPLACEMENT, NOT_RETRYABLE, NOT_UNKNOWN, PAYLOAD_NOT_STORED,
    RESOLUTION_METHOD_UNKNOWN,
    RESOLUTION_OVERDUE, RETRIES_EXHAUSTED, SUCCEEDED, SUCCESS, UNKNOWN, UNKNOWN_CLASS,
    TENANT_ID_REQUIRED, TENANT_MISMATCH, UNKNOWN_PROVIDER, UNRESOLVED_UNKNOWN,
    AttemptRefused, Attempts, digest)

MODEL = json.loads((ROOT / "governance/payment-attempt.json").read_text(encoding="utf-8"))
ACC = json.loads((ROOT / "governance/provider-accounts.json").read_text(encoding="utf-8"))
PROVIDERS = {p["id"] for p in ACC["providers"]}

CHECKS: list[str] = []
FAILURES: list[str] = []
NOW = 1_700_000_000
TENANT = "tenant_smoke"


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
    except AttemptRefused as exc:
        return exc.code == code


def request() -> dict:
    return {"amount_minor": 10000, "currency": "EUR", "pan": "4242424242424242",
            "cvv": "123", "credential": "sk_live_x"}


def main() -> int:
    attempts = Attempts(MODEL, PROVIDERS)

    # 1. the request is recorded as a digest, never as itself
    first = attempts.start("pi_1", tenant_id=TENANT, provider="stripe", request=request(),
                           idempotency_key="k1", provider_request_id="req_pi_1",
                           now=NOW)
    check("请求以摘要记录", len(first.request_digest) == 64)
    check("脱敏字段不参与摘要",
          first.request_digest == digest({"amount_minor": 10000, "currency": "EUR"},
                                         tuple(MODEL["request_record"]["redacted_fields"])))
    check("报文本身取不出来",
          refuses(lambda: attempts.stored_request(first, tenant_id=TENANT), PAYLOAD_NOT_STORED))
    check("序号从 1 开始", first.sequence == 1)
    check("attempt 明确绑定租户", first.tenant_id == TENANT)
    check("保留渠道请求号", first.provider_request_id == "req_pi_1")
    check("未知渠道被拒",
          refuses(lambda: attempts.start("pi_x", tenant_id=TENANT, provider="klarna", request={},
                                         idempotency_key="k", now=NOW), UNKNOWN_PROVIDER))
    check("空租户被拒",
          refuses(lambda: attempts.start("pi_no_tenant", tenant_id="", provider="stripe",
                                         request={}, idempotency_key="k", now=NOW),
                  TENANT_ID_REQUIRED))
    other = attempts.start("pi_1", tenant_id="tenant_other", provider="stripe",
                           request=request(), idempotency_key="k",
                           provider_request_id="req_pi_1", now=NOW)
    check("同名 intent 在不同租户隔离",
          attempts.for_intent(TENANT, "pi_1") == [first]
          and attempts.for_intent("tenant_other", "pi_1") == [other])
    check("跨租户读取被拒",
          refuses(lambda: attempts.stored_response(first, tenant_id="tenant_other"),
                  TENANT_MISMATCH))

    racing = Attempts(MODEL, PROVIDERS)
    workers = 8
    barrier = threading.Barrier(workers)

    def concurrent_start(index: int) -> str:
        barrier.wait()
        try:
            racing.start("pi_race", tenant_id=TENANT, provider="stripe", request=request(),
                         idempotency_key="race-key", provider_request_id=f"req_race_{index}",
                         now=NOW)
            return "created"
        except AttemptRefused as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=workers) as pool:
        race_results = list(pool.map(concurrent_start, range(workers)))
    check("并发 start 只创建一条 attempt", race_results.count("created") == 1)
    check("其余并发调用在触达渠道前被拒",
          race_results.count(NOT_RETRYABLE) == workers - 1
          and len(racing.for_intent(TENANT, "pi_race")) == 1)

    # 2. THE scenario — a timeout is unknown, and it blocks the next call
    check("超时归类为未知", attempts.timed_out(first, tenant_id=TENANT, now=NOW + 30) == UNKNOWN_CLASS)
    check("attempt 状态为 unknown", first.state == UNKNOWN)
    check("unknown 不是终态", first.is_final is False)
    check("**未落定的未知挡住下一次尝试**",
          refuses(lambda: attempts.start("pi_1", tenant_id=TENANT, provider="stripe", request=request(),
                                         idempotency_key="k1", now=NOW + 60),
                  UNRESOLVED_UNKNOWN))
    check("落定方式必须是声明过的",
          refuses(lambda: attempts.resolve(first, tenant_id=TENANT, method="ask_support",
                                           provider_code="card_declined", now=NOW + 60),
                  RESOLUTION_METHOD_UNKNOWN))
    check("查询结果仍未知则仍未落定",
          refuses(lambda: attempts.resolve(first, tenant_id=TENANT, method="provider_query",
                                           provider_code="processing_timeout", now=NOW + 60),
                  UNRESOLVED_UNKNOWN))
    response = attempts.stored_response(first, tenant_id=TENANT)
    check("响应只保留规范化证据",
          set(response) == {"provider", "provider_request_id", "provider_transaction_id",
                            "provider_code_namespace", "provider_code", "outcome_class",
                            "response_digest"})
    check("响应证据不含敏感字段",
          set(response).isdisjoint(MODEL["response_record"]["forbidden_fields"]))
    check("响应摘要为 SHA-256", len(response["response_digest"]) == 64)
    check("主动查询把未知落定为失败",
          attempts.resolve(first, tenant_id=TENANT, method="provider_query", provider_code="card_declined",
                           provider_transaction_id="txn_pi_1", now=NOW + 60) == FAILED_FINAL)
    check("保留渠道交易号", first.provider_transaction_id == "txn_pi_1")
    check("落定后状态为 failed", first.state == FAILED)
    check("已落定的不能再落定",
          refuses(lambda: attempts.resolve(first, tenant_id=TENANT, method="provider_query",
                                           provider_code="card_declined", now=NOW + 90),
                  NOT_UNKNOWN))
    check("模型把超时归为 unknown", MODEL["timeout"]["classified_as"] == "unknown")
    check("模型禁止落定前重试",
          MODEL["timeout"]["retry_before_resolution_allowed"] is False)

    # 3. a definitive decline is not retried; a retryable one is
    declined = Attempts(MODEL, PROVIDERS)
    one = declined.start("pi_2", tenant_id=TENANT, provider="stripe", request=request(), idempotency_key="k",
                         now=NOW)
    declined.record(one, tenant_id=TENANT, provider_code="card_declined", now=NOW + 1)
    check("明确拒绝是终态", one.is_final and one.outcome_class == FAILED_FINAL)
    check("明确拒绝不会永久落定 intent",
          declined.intent_outcome(TENANT, "pi_2") is None)
    check("同一资金源不能原样再试",
          refuses(lambda: declined.start("pi_2", tenant_id=TENANT, provider="stripe", request=request(),
                                         idempotency_key="k", now=NOW + 2),
                  NOT_RETRYABLE))
    check("更换资金源不能复用旧幂等键",
          refuses(lambda: declined.start(
              "pi_2", tenant_id=TENANT, provider="stripe", request=request(),
              idempotency_key="k", replacement_request=True, now=NOW + 2),
              KEY_REUSED_FOR_REPLACEMENT))
    replacement = declined.start(
        "pi_2", tenant_id=TENANT, provider="stripe", request=request(),
        idempotency_key="k-new", replacement_request=True, now=NOW + 2)
    check("客户更换资金源后用新请求再试", replacement.sequence == 2)
    retryable = Attempts(MODEL, PROVIDERS)
    a1 = retryable.start("pi_3", tenant_id=TENANT, provider="stripe", request=request(), idempotency_key="k",
                         now=NOW)
    retryable.record(a1, tenant_id=TENANT, provider_code="rate_limit", now=NOW + 1)
    check("限流归类为可重试", a1.outcome_class == FAILED_RETRYABLE)
    check("重试必须复用幂等键",
          refuses(lambda: retryable.start("pi_3", tenant_id=TENANT, provider="stripe", request=request(),
                                          idempotency_key="k2", now=NOW + 2), KEY_CHANGED))
    a2 = retryable.start("pi_3", tenant_id=TENANT, provider="stripe", request=request(), idempotency_key="k",
                         now=NOW + 2)
    check("重试开新的 attempt 而不是改旧的", a2.id != a1.id and a2.sequence == 2)
    check("每次渠道调用有独立请求号", a2.provider_request_id != a1.provider_request_id)
    check("旧 attempt 保持原样", a1.outcome_class == FAILED_RETRYABLE)
    retryable.record(a2, tenant_id=TENANT, provider_code="rate_limit", now=NOW + 3)
    a3 = retryable.start("pi_3", tenant_id=TENANT, provider="stripe", request=request(), idempotency_key="k",
                         now=NOW + 4)
    retryable.record(a3, tenant_id=TENANT, provider_code="rate_limit", now=NOW + 5)
    check("超过重试上限后停止",
          refuses(lambda: retryable.start("pi_3", tenant_id=TENANT, provider="stripe", request=request(),
                                          idempotency_key="k", now=NOW + 6),
                  RETRIES_EXHAUSTED))

    # 4. unmapped codes are unknown, and "already paid" is success
    check("没见过的渠道码归入未知",
          attempts.classify("stripe", "some_new_code_2027") == UNKNOWN_CLASS)
    check("微信「订单已支付」是成功而不是错误",
          attempts.classify("wechat", "ORDERPAID") == SUCCESS)
    check("渠道明说系统错误也是未知",
          attempts.classify("wechat", "SYSTEMERROR") == UNKNOWN_CLASS)
    check("Stripe 顶层 error.code 不与 decline_code 混用",
          attempts.classify("stripe", "card_declined", "stripe.error.code") == FAILED_FINAL
          and attempts.classify("stripe", "card_declined", "stripe.decline_code")
          == UNKNOWN_CLASS)
    check("PayPal 更换资金源后可以重试",
          attempts.classify("paypal", "INSTRUMENT_DECLINED", "paypal.details.issue")
          == FAILED_FINAL
          and MODEL["retry"]["replacement_request_requires_new_idempotency_key"] is True)
    apple = next(e for e in MODEL["error_taxonomy"]
                 if e["provider"] == "apple_pay" and e["provider_code"] == "DECRYPT_FAILED")
    check("Apple Pay 解密错误明确是适配器归一化码",
          apple["code_namespace"] == "adapter.normalized")
    check("模型把未登记的码归入未知", MODEL["unmapped_code_class"] == "unknown")

    # 5. finality — a late contradicting event opens a break
    late = Attempts(MODEL, PROVIDERS)
    b1 = late.start("pi_4", tenant_id=TENANT, provider="wechat", request=request(), idempotency_key="k",
                    now=NOW)
    late.record(b1, tenant_id=TENANT, provider_code="ORDERPAID", provider_transaction_id="wx_txn_pi_4",
                now=NOW + 1)
    check("成功是终态", b1.state == SUCCEEDED)
    check("意图结果取自终态 attempt", late.intent_outcome(TENANT, "pi_4") == SUCCESS)
    item = late.observe_late_event(b1, tenant_id=TENANT, later_outcome=FAILED_FINAL, now=NOW + 100)
    check("矛盾的后到事件开出对账项", item is not None)
    check("**终态 attempt 没有被覆盖**", b1.outcome_class == SUCCESS)
    before = (b1.state, b1.outcome_class, b1.provider_code_namespace, b1.provider_code,
              b1.provider_transaction_id, b1.response_digest, b1.finished_at)
    check("直接赋值也不能改写终态 attempt",
          refuses(lambda: setattr(b1, "provider_code", "SYSTEMERROR"), ATTEMPT_IS_FINAL)
          and before == (b1.state, b1.outcome_class, b1.provider_code_namespace,
                         b1.provider_code,
                         b1.provider_transaction_id, b1.response_digest, b1.finished_at))
    check("一致的后到事件不开对账项",
          late.observe_late_event(b1, tenant_id=TENANT, later_outcome=SUCCESS, now=NOW + 101) is None)
    check("非法跃迁被拒",
          refuses(lambda: late.transition(b1, UNKNOWN, tenant_id=TENANT), ATTEMPT_IS_FINAL))
    check("模型禁止覆盖",
          MODEL["finality"]["contradicting_later_event_overwrites"] is False)

    # 6. the model itself
    machines = json.loads((ROOT / "governance/state-machines.json").read_text(encoding="utf-8"))
    machine = next(m for m in machines["machines"] if m["entity"] == "PaymentAttempt")
    check("状态与 B10 完全一致", MODEL["lifecycle"]["states"] == machine["states"])
    check("unknown 不在 B10 的终态里", "unknown" not in machine["terminal"])
    check("每个已绑定渠道都有错误分类",
          PROVIDERS <= {e["provider"] for e in MODEL["error_taxonomy"]})
    check("四类结果齐全",
          {"succeeded", "failed_final", "failed_retryable", "unknown"}
          == {c["id"] for c in MODEL["outcome_classes"]})

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
