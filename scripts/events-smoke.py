#!/usr/bin/env python3
"""B12 runtime proof — fault injection against the outbox/inbox reference.

Six failures that actually happen in production, each run end to end:

1. the process dies between the state change and the commit;
2. the broker is down and comes back;
3. the broker never comes back and the event must dead-letter, not vanish;
4. the transport delivers the same event twice;
5. the transport delivers events out of order;
6. the same event id arrives carrying a different body.

The property being defended is the one the batch is named after: at-least-once
delivery, exactly-once *business effect*.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.eventing.reference.eventing import (  # noqa: E402
    Broker, CommitFailed, Dispatcher, Inbox, PayloadConflict, RevisionGuardedConsumer, Store)

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def capture(amount: int = 19999):
    store, broker = Store(), Broker()
    store.transact("PaymentIntent", "pi_1", 1, "authorized", "payment_intent.authorized",
                   {"amount_minor": amount, "currency": "CNY"})
    store.transact("PaymentIntent", "pi_1", 2, "captured", "payment_intent.captured",
                   {"amount_minor": amount, "currency": "CNY"})
    return store, broker


def main() -> int:
    print("== 故障 1：状态变更与 outbox 写入之间进程崩溃")
    store, broker = Store(), Broker()
    try:
        store.transact("PaymentIntent", "pi_x", 1, "authorized", "payment_intent.authorized",
                       {"amount_minor": 100, "currency": "CNY"}, crash_before_commit=True)
        check("崩溃必须让整个事务不发生", False, "事务竟然成功了")
    except CommitFailed as exc:
        check("崩溃必须让整个事务不发生",
              not store.state and not store.outbox, str(exc))
    check("崩溃后没有发出任何事件", not broker.delivered)

    print()
    print("== 故障 2：Broker 短暂不可用后恢复")
    store, broker = capture()
    broker.fail_next = 2
    first = Dispatcher(store, broker).run_once()
    check("不可用期间不投递也不丢弃", first["published"] == 0 and first["dead_lettered"] == 0,
          first)
    second = Dispatcher(store, broker).run_once()
    check("恢复后补投全部事件", second["published"] == 2, second)

    print()
    print("== 故障 3：Broker 一直不可用，必须进死信而不是消失")
    store, broker = capture()
    broker.fail_next = 10_000
    dispatcher = Dispatcher(store, broker, max_attempts=3)
    for _ in range(3):
        dispatcher.run_once()
    check("重试用尽后进入死信", len(store.dead_letters) == 2, len(store.dead_letters))
    check("死信事件不会被静默丢弃", all(r.dead_lettered for r in store.dead_letters))
    check("死信事件从未被标记为已发布", not any(r.published for r in store.dead_letters))

    print()
    print("== 故障 4：至少一次传输把同一事件投递两次")
    store, broker = capture()
    Dispatcher(store, broker).run_once()
    consumer = RevisionGuardedConsumer()
    for row in broker.delivered:
        consumer.handle("payment-core", row)
    for row in broker.delivered:
        consumer.handle("payment-core", row)
    check("重复投递不产生第二次业务效果", len(consumer.effects) == 2, len(consumer.effects))
    check("重复被计数而不是被忽略", consumer.duplicates == 2, consumer.duplicates)

    print()
    print("== 故障 5：事件乱序到达")
    store, broker = capture()
    Dispatcher(store, broker).run_once()
    consumer = RevisionGuardedConsumer()
    for row in reversed(broker.delivered):
        consumer.handle("payment-core", row)
    check("乱序后最终状态仍是最高 revision",
          consumer.applied[("PaymentIntent", "pi_1")] == 2,
          consumer.applied)
    check("落后的 revision 被丢弃并计数", consumer.stale == 1, consumer.stale)
    check("乱序不会让已捕获退回已授权",
          consumer.effects[0][0] == "payment_intent.captured", consumer.effects[0][0])

    print()
    print("== 故障 6：同一 event_id 带来了不同的 payload")
    inbox = Inbox()
    inbox.accept("wechat", "evt_1", {"amount_minor": 19999, "currency": "CNY"})
    check("同一 event_id 同一 payload 是重放",
          inbox.accept("wechat", "evt_1", {"amount_minor": 19999, "currency": "CNY"}) is False)
    try:
        inbox.accept("wechat", "evt_1", {"amount_minor": 1, "currency": "CNY"})
        check("同一 event_id 不同 payload 必须报错", False, "竟然被当成重放接受了")
    except PayloadConflict as exc:
        check("同一 event_id 不同 payload 必须报错", True, str(exc))

    print()
    print("== 不变量：唯一键 (aggregate_id, revision) 挡住重复写入")
    store, _ = capture()
    try:
        store.transact("PaymentIntent", "pi_1", 2, "captured", "payment_intent.captured",
                       {"amount_minor": 19999, "currency": "CNY"})
        check("重复 revision 必须被唯一键拒绝", False, "竟然写进去了")
    except ValueError as exc:
        check("重复 revision 必须被唯一键拒绝", True, str(exc)[:60])

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
