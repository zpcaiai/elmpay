#!/usr/bin/env python3
"""B31 runtime proof — every isolation surface refuses the other tenant.

Scenario 1 is why this batch exists. Each probe asserts a *denial*, and the
counter-demonstration at the end shows why: with row-level security left
unforced for the table owner, the positive test ("tenant A sees its own rows")
still passes while tenant A can read everything.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.isolation.reference.probes import (  # noqa: E402
    CACHE_KEY_UNSCOPED, CONSUMER_TENANT_MISMATCH, CROSS_TENANT_READ, CROSS_TENANT_WRITE,
    EXPORT_FILTER_LATE, EXPORT_MULTI_TENANT, JOB_TENANT_MISSING, LOG_FOREIGN_ROW,
    LOG_TENANT_MISSING, NO_TENANT_CONTEXT, OBJECT_PREFIX_DENIED, PROBE_DID_NOT_DENY,
    PROBE_MISSING, TOPIC_TENANT_MISSING, Cache, Database, Exporter, IsolationBreach, Job,
    JobRunner, Logger, Message, MessageBus, Row, Session, run_probes)

MODEL = json.loads((ROOT / "governance/tenant-isolation.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def breaches(fn, code: str) -> bool:
    try:
        fn()
        return False
    except IsolationBreach as exc:
        return exc.code == code


def world():
    database = Database()
    a = Session(principal="svc", tenant_id="ten_a")
    b = Session(principal="svc", tenant_id="ten_b")
    database.insert(a, Row("ten_a", "row_a", {"amount_minor": 100}))
    database.insert(b, Row("ten_b", "row_b", {"amount_minor": 200}))
    return database, a, b


def main() -> int:
    # 1. every declared probe runs and every one asserts a denial
    results = run_probes(MODEL)
    check("每个隔离面的探针都通过", len(results) == len(MODEL["surfaces"]), len(results))
    check("每个探针都断言拒绝",
          all(s["probe"]["asserts_denial"] for s in MODEL["surfaces"]))
    missing = json.loads(json.dumps(MODEL))
    missing["surfaces"][0]["probe"]["id"] = "probe_that_does_not_exist"
    check("声明了不存在的探针会被发现",
          breaches(lambda: run_probes(missing), PROBE_MISSING))

    # 2. the database refuses, rather than widening
    database, a, b = world()
    check("没有租户上下文的查询报错而不是返回全部",
          breaches(lambda: database.select(Session(principal="cron")), NO_TENANT_CONTEXT))
    check("跨租户读被拒", breaches(lambda: database.get(a, "row_b"), CROSS_TENANT_READ))
    check("跨租户写被拒",
          breaches(lambda: database.insert(a, Row("ten_b", "row_x", {})), CROSS_TENANT_WRITE))
    check("本租户只看到自己的行",
          [r.id for r in database.select(a)] == ["row_a"])
    check("持有跨租户权限时才看得到全部",
          len(database.select(Session(principal="ops", tenant_id="ten_a",
                                      cross_tenant_granted=True))) == 2)

    # 3. THE counter-demonstration — positive tests prove nothing
    weak = Database(force_for_owner=False)
    owner_a = Session(principal="app", tenant_id="ten_a", is_table_owner=True)
    weak.insert(owner_a, Row("ten_a", "row_a", {}))
    weak.insert(Session(principal="app", tenant_id="ten_b"), Row("ten_b", "row_b", {}))
    positive_still_passes = any(r.id == "row_a" for r in weak.select(owner_a))
    leaks = any(r.tenant_id == "ten_b" for r in weak.select(owner_a))
    check("**不对属主强制行级安全时，正向测试照样通过**", positive_still_passes)
    check("**而此时租户 A 已经能读到租户 B 的行**", leaks)
    check("模型要求对属主强制", MODEL["forced_controls"]["rls_forced_for_table_owner"] is True)

    # 4. the surfaces everybody forgets
    cache = Cache()
    cache.put("ten_a", "user", "u1", value="A")
    cache.put("ten_b", "user", "u1", value="B")
    check("同名键在不同租户下互不影响",
          cache.get("ten_a", "user", "u1") == "A" and cache.get("ten_b", "user", "u1") == "B")
    check("没有租户的缓存键被拒",
          breaches(lambda: cache.put(None, "user", "u1", value="X"), CACHE_KEY_UNSCOPED))
    check("否定缓存也按租户分区",
          cache.put_negative("ten_a", "obj", "o1").startswith("ten_a:"))

    bus = MessageBus()
    check("消息没有租户不能发布",
          breaches(lambda: bus.publish(Message("payments", None, {})), TOPIC_TENANT_MISSING))
    message = bus.publish(Message("payments", "ten_a", {"id": "p1"}))
    check("消费者校验租户不符即拒",
          breaches(lambda: bus.consume(message, consumer_tenant="ten_b"),
                   CONSUMER_TENANT_MISMATCH))
    check("同租户消费正常", bus.consume(message, consumer_tenant="ten_a") == {"id": "p1"})

    logger = Logger()
    check("日志没有租户字段被拒",
          breaches(lambda: logger.log(tenant_id=None, message="x"), LOG_TENANT_MISSING))
    check("日志里带别人的行被拒",
          breaches(lambda: logger.log(tenant_id="ten_a", message="failed",
                                      rows=(Row("ten_b", "row_b", {}),)), LOG_FOREIGN_ROW))
    check("带自己的行正常",
          logger.log(tenant_id="ten_a", message="ok",
                     rows=(Row("ten_a", "row_a", {}),))["rows"] == ("row_a",))

    exporter = Exporter(database)
    check("一次导出两个租户被拒",
          breaches(lambda: exporter.export(a, tenants=("ten_a", "ten_b")),
                   EXPORT_MULTI_TENANT))
    check("过滤写在应用层被拒",
          breaches(lambda: exporter.export(a, tenants=("ten_a",), filter_in_query=False),
                   EXPORT_FILTER_LATE))
    check("正常导出只含本租户，行数已核对",
          [r.id for r in exporter.export(a, tenants=("ten_a",))] == ["row_a"])

    runner = JobRunner(database)
    check("后台任务没有租户被拒",
          breaches(lambda: runner.run(Job(name="nightly")), JOB_TENANT_MISSING))
    check("绑定租户的任务只处理本租户",
          runner.run(Job(name="nightly", tenant_id="ten_a")) == ["row_a"])

    store_session = Session(principal="svc", tenant_id="ten_a")
    from libs.isolation.reference.probes import ObjectStore
    store = ObjectStore()
    store.put("ten_a", "invoice.pdf", b"a")
    store.put("ten_b", "invoice.pdf", b"b")
    check("对象存储跨前缀读取被拒",
          breaches(lambda: store.get(store_session, "ten_b/invoice.pdf"),
                   OBJECT_PREFIX_DENIED))
    check("自己前缀可读", store.get(store_session, "ten_a/invoice.pdf") == b"a")

    # 5. the model itself
    check("六个必须覆盖的隔离面都在",
          {"database_rows", "object_storage", "cache", "message_topics", "logs", "exports"}
          <= {s["id"] for s in MODEL["surfaces"]})
    check("所有隔离面默认拒绝",
          all(s["default"] == "deny" for s in MODEL["surfaces"]))
    check("探针互不重复",
          len({s["probe"]["id"] for s in MODEL["surfaces"]}) == len(MODEL["surfaces"]))
    check("模型明说仅正向的测试不构成证据",
          MODEL["evidence"]["positive_only_test_is_not_evidence"] is True)

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
