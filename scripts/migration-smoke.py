#!/usr/bin/env python3
"""B15 runtime proof — run the migration plan instead of reading it.

Six things the plan claims, each executed:

1. one provider call per payment in **every** phase (dual write is two records,
   not two charges);
2. rollback from any phase preserves both sides' payment facts;
3. order line data cannot cross into the platform, even by accident;
4. divergence between the two sides is detected on the fields that matter;
5. the backfill is idempotent -- re-running it writes nothing new;
6. the backfill is resumable -- crashing mid-run and restarting from the
   checkpoint produces exactly the same result as a clean run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.migration.reference.dualwrite import (  # noqa: E402
    PHASES, Backfill, BusinessDataLeak, DoubleCharge, Migration, Store)

PLAN = json.loads((ROOT / "governance/migration-plan.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def main() -> int:
    print("== 1. 每一期都只调用渠道一次")
    for index, phase in enumerate(PHASES):
        migration = Migration()
        for _ in range(index):
            migration.advance()
        migration.pay("proj-1", f"ord-{index}", 19999, "CNY")
        calls = migration.provider.calls[f"ord-{index}"]
        recorded = len(migration.legacy.rows) + len(migration.platform.rows)
        expected_records = 1 if phase in ("legacy_only", "platform_only") else 2
        check(f"{phase}: 渠道调用 1 次，记录 {expected_records} 份",
              calls == 1 and recorded == expected_records,
              f"calls={calls} records={recorded}")

    print()
    print("== 2. 重复调用渠道必须被挡住")
    migration = Migration()
    migration.advance()
    migration.pay("proj-1", "ord-x", 19999, "CNY")
    try:
        migration.provider.charge("ord-x")
        check("同一笔支付第二次调用渠道必须失败", False, "竟然通过了")
    except DoubleCharge as exc:
        check("同一笔支付第二次调用渠道必须失败", True, str(exc)[:60])

    print()
    print("== 3. 每一期回退都保全两侧的支付事实")
    migration = Migration()
    for index in range(1, len(PHASES)):
        migration.advance()
        migration.pay("proj-1", f"roll-{index}", 1000 * index, "CNY")
    before = (len(migration.legacy.rows), len(migration.platform.rows))
    steps = []
    while migration.phase != PHASES[0]:
        steps.append(migration.rollback())
    after = (len(migration.legacy.rows), len(migration.platform.rows))
    check("逐期回退到第一期，两侧记录数不变", before == after, f"{before} -> {after}")
    check("回退路径与阶段顺序相反", steps == list(reversed(PHASES[:-1])), steps)

    print()
    print("== 4. 业务订单数据不得越界")
    store = Store("platform")
    for leaky in ("sku", "item_count", "shipping_address", "product_name"):
        try:
            store.write("proj-1", "ord-1", {leaky: "x", "amount_minor": 1})
            check(f"平台必须拒绝字段 {leaky}", False, "竟然写进去了")
        except BusinessDataLeak:
            check(f"平台必须拒绝字段 {leaky}", True)

    print()
    print("== 5. 分歧检测")
    migration = Migration()
    migration.advance()
    migration.pay("proj-1", "ord-d", 19999, "CNY")
    check("两侧一致时无分歧", migration.divergences() == [])
    migration.platform.rows[("proj-1", "ord-d")]["amount_minor"] = 19998
    found = migration.divergences()
    check("金额分歧必须被发现",
          len(found) == 1 and found[0]["fields"] == ["amount_minor"], found)
    compare_fields = PLAN["dual_write"]["divergence_detection"]["compare_fields"]
    check("比对字段包含金额与币种",
          "amount_minor" in compare_fields and "currency" in compare_fields, compare_fields)

    print()
    print("== 6. 回填幂等且可续跑")
    source = [{"legacy_payment_id": f"lp-{i:04d}", "project": "proj-1",
               "external_reference": f"ord-{i}", "amount_minor": 100 * (i + 1),
               "currency": "CNY" if i % 2 == 0 else "JPY", "status": "captured"}
              for i in range(50)]

    clean = Backfill(source, Store("platform"))
    clean.run()
    first_writes = clean.writes
    clean.checkpoint = ""
    clean.run()
    check("重跑回填不产生新写入", clean.writes == first_writes,
          f"writes={clean.writes} first={first_writes}")
    check("回填校验：笔数与总额都对得上",
          clean.verify()["count_ok"] and clean.verify()["totals_ok"], clean.verify())

    crashed = Backfill(source, Store("platform"))
    try:
        crashed.run(crash_after=20)
    except RuntimeError:
        pass
    checkpoint = crashed.checkpoint
    crashed.run()
    check("崩溃后从断点续跑，结果与干净跑一致",
          crashed.target.rows == clean.target.rows,
          f"checkpoint={checkpoint} rows={len(crashed.target.rows)}")
    check("续跑后校验仍然通过",
          crashed.verify()["count_ok"] and crashed.verify()["totals_ok"])

    print()
    print("== 7. 计划本身的硬性约束")
    check("计划声明每笔支付只调用渠道一次",
          PLAN["dual_write"]["provider_calls_per_payment"] == 1)
    check("每一期的回退都保全支付事实",
          all(p["rollback"]["payment_facts_preserved"] for p in PLAN["phases"]))
    check("平台不得访问旧系统数据库",
          PLAN["legacy_database_access"]["allowed"] is False)
    check("切换粒度是项目而不是全局",
          PLAN["cutover"]["granularity"] == "project")

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
