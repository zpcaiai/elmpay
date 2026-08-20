#!/usr/bin/env python3
"""B13 runtime proof — replay tenant isolation against the declared architecture.

Every tenant-scoped table in ``governance/data-architecture.json`` is built into
the reference model and attacked the same way: a session for tenant A tries to
read, write and delete tenant B's row. Then the two failure modes that make RLS
decorative are reproduced deliberately, so the rules that forbid them are shown
to be worth having.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.tenancy.reference.isolation import (  # noqa: E402
    NotPermitted, Policy, Table, TenantNotSet, build)

ARCH = json.loads((ROOT / "governance/data-architecture.json").read_text(encoding="utf-8"))

CHECKS: list[str] = []
FAILURES: list[str] = []

A, B = "tenant-a", "tenant-b"


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def main() -> int:
    scoped = [t for t in ARCH["tables"] if t["tenant_scoped"]]
    print(f"== 1. 对全部 {len(scoped)} 张租户表做同一组跨租户攻击")
    leaks, insert_leaks, delete_leaks = [], [], []
    for spec in scoped:
        table = build(spec)
        table.rows.extend([{"tenant_id": A, "id": "row-a"}, {"tenant_id": B, "id": "row-b"}])
        visible = table.select("app_user", tenant=A)
        if [r["id"] for r in visible] != ["row-a"]:
            leaks.append(spec["table"])
        try:
            table.insert("app_user", {"tenant_id": B, "id": "row-c"}, tenant=A)
            insert_leaks.append(spec["table"])
        except NotPermitted:
            pass
        try:
            if table.delete("app_user", {"id": "row-b"}, tenant=A):
                delete_leaks.append(spec["table"])
        except NotPermitted:
            pass  # append-only tables refuse DELETE outright, which is stronger
    check("没有一张租户表能被跨租户读取", not leaks, leaks)
    check("没有一张租户表能被写入别的租户的行", not insert_leaks, insert_leaks)
    check("没有一张租户表能被跨租户删除", not delete_leaks, delete_leaks)

    print()
    print("== 2. 会话上没有租户时必须拒绝，而不是返回全部")
    table = build(scoped[0])
    table.rows.extend([{"tenant_id": A, "id": "row-a"}, {"tenant_id": B, "id": "row-b"}])
    try:
        table.select("app_user", tenant=None)
        check("无租户会话必须被拒绝", False, "竟然返回了数据")
    except TenantNotSet as exc:
        check("无租户会话必须被拒绝", True, str(exc)[:70])

    print()
    print("== 3. 少写 FORCE 时属主会绕过策略（这正是门禁存在的理由）")
    weak = Table(name="payment_intent", owner_role="app_owner",
                 policy=Policy(name="weak", force_for_owner=False))
    weak.rows.extend([{"tenant_id": A, "id": "row-a"}, {"tenant_id": B, "id": "row-b"}])
    check("未 FORCE 时属主看得见所有租户", len(weak.select("app_owner", tenant=A)) == 2,
          "这就是 DATA_RLS_FORCE 要拦下的情况")
    strong = Table(name="payment_intent", owner_role="app_owner",
                   policy=Policy(name="strong", force_for_owner=True))
    strong.rows.extend([{"tenant_id": A, "id": "row-a"}, {"tenant_id": B, "id": "row-b"}])
    check("FORCE 之后属主也只看得见本租户",
          [r["id"] for r in strong.select("app_owner", tenant=A)] == ["row-a"])

    print()
    print("== 4. 仅追加表在权限层就没有 UPDATE / DELETE")
    append_only = [t for t in ARCH["tables"] if t["mutability"] == "append_only"]
    refused_update, refused_delete = 0, 0
    for spec in append_only:
        table = build(spec)
        table.rows.append({"tenant_id": A, "id": "row-a"})
        try:
            table.update("app_user", {"id": "row-a"}, {"id": "changed"}, tenant=A)
        except NotPermitted:
            refused_update += 1
        try:
            table.delete("app_user", {"id": "row-a"}, tenant=A)
        except NotPermitted:
            refused_delete += 1
    check(f"{len(append_only)} 张仅追加表全部拒绝 UPDATE", refused_update == len(append_only),
          refused_update)
    check(f"{len(append_only)} 张仅追加表全部拒绝 DELETE", refused_delete == len(append_only),
          refused_delete)

    print()
    print("== 5. 紧急通道确实能跨租户——所以它必须被审计与四眼复核")
    table = build(scoped[0])
    table.rows.extend([{"tenant_id": A, "id": "row-a"}, {"tenant_id": B, "id": "row-b"}])
    check("break-glass 角色可以跨租户读取",
          len(table.select("platform_break_glass")) == 2)
    hatch = ARCH["tenancy"]["escape_hatch"]
    check("紧急通道必须留审计事件且需二次审批",
          hatch["requires_audit_event"] and hatch["requires_second_approver"])
    check("紧急通道会话必须过期", 0 < hatch["max_session_minutes"] <= 240,
          hatch["max_session_minutes"])

    print()
    print("== 6. 保留期与归档的一致性")
    bad_order = [t["table"] for t in ARCH["tables"]
                 if not (0 < t["retention"]["hot_days"] <= t["retention"]["warm_days"]
                         <= t["retention"]["cold_days"])]
    check("热/温/冷保留期单调不减", not bad_order, bad_order)
    no_target = [t["table"] for t in ARCH["tables"]
                 if t["retention"]["archive_after_days"] and not t["retention"]["archive_target"]]
    check("每张要归档的表都有归档目标", not no_target, no_target)

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
