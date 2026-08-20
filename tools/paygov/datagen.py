"""B13 — generate the tenancy DDL, the partition DDL and the review document."""
from __future__ import annotations

from pathlib import Path

from .repo import Budget, load_json

ARCH = Path("governance/data-architecture.json")
SQL_BANNER = ("-- GENERATED FILE — do not edit by hand.\n"
              "-- Source of truth: governance/data-architecture.json\n"
              "-- Regenerate with: python3 scripts/render-data.py\n")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/data-architecture.json\n"
             "     Regenerate with: python3 scripts/render-data.py -->\n")


def rls_sql(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    arch = load_json(root / ARCH)
    tenancy = arch["tenancy"]
    out = [SQL_BANNER, "-- 租户隔离：共享库共享表 + 强制行级安全。",
           f"-- 会话变量：{tenancy['session_setting']}",
           "-- 注意 FORCE：不加它时表的属主会绕过策略，而运维脚本正是以属主身份运行的。", ""]
    for table in arch["tables"]:
        budget.check(table["table"])
        rls = table["rls"]
        if not rls.get("enabled"):
            out.append(f"-- {table['table']}: 不做行级隔离 — {rls.get('reason', '')}")
            continue
        name = table["table"]
        out.append(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY;")
        out.append(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY;")
        out.append(f"DROP POLICY IF EXISTS {rls['policy']} ON {name};")
        out.append(f"CREATE POLICY {rls['policy']} ON {name}")
        out.append(f"    USING ({rls['predicate']})")
        out.append(f"    WITH CHECK ({rls['predicate']});")
        if table["mutability"] == "append_only":
            out.append(f"REVOKE UPDATE, DELETE ON {name} FROM PUBLIC;")
            out.append(f"-- {name} 是仅追加表：更新与删除在权限层就被拿掉。")
        out.append("")
    out.append("-- 紧急通道")
    hatch = tenancy["escape_hatch"]
    out.append(f"-- 角色 {hatch['role']}：需审计事件={hatch['requires_audit_event']}，"
               f"需二次审批={hatch['requires_second_approver']}，"
               f"会话上限={hatch['max_session_minutes']} 分钟。")
    out.append("")
    return "\n".join(out)


def partitions_sql(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    arch = load_json(root / ARCH)
    out = [SQL_BANNER, "-- 分区与归档：按月 RANGE 分区，归档是 DETACH 而不是 DELETE。", ""]
    for table in arch["tables"]:
        budget.check(table["table"])
        partition = table["partition"]
        retention = table["retention"]
        name = table["table"]
        if partition["kind"] == "none":
            out.append(f"-- {name}: 不分区 — {partition['reason']}")
            out.append(f"--   保留 {retention['cold_days']} 天，归档至 "
                       f"{retention['archive_target']}")
            out.append("")
            continue
        out.append(f"-- {name}: {partition['kind']} 分区，键 {partition['key']}，"
                   f"间隔 {partition['interval']}")
        out.append(f"--   {partition['reason']}")
        out.append(f"--   热 {retention['hot_days']} 天 / 温 {retention['warm_days']} 天 / "
                   f"冷 {retention['cold_days']} 天")
        out.append(f"ALTER TABLE {name} SET (autovacuum_vacuum_scale_factor = 0.02);")
        out.append(f"-- PARTITION BY RANGE ({partition['key']}) — 分区表创建见迁移脚本；")
        out.append(f"-- 归档：ALTER TABLE {name} DETACH PARTITION {name}_<period>; "
                   f"再导出到 {retention['archive_target']}")
        out.append("")
    return "\n".join(out)


def architecture_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    arch = load_json(root / ARCH)
    tenancy = arch["tenancy"]
    out = [MD_BANNER, "# 数据所有权、分区与租户模型（B13）", ""]
    out.append("本文由 `governance/data-architecture.json` 生成。"
               "表的归属由门禁与 `governance/module-registry.json` 强制一致（`DATA_OWNER`）。")
    out.append("")
    out.append("## 租户模型")
    out.append("")
    out.append(f"- 模型：`{tenancy['model']}`")
    out.append(f"- 租户列：`{tenancy['tenant_column']}`，会话变量 `{tenancy['session_setting']}`")
    out.append(f"- {tenancy['policy']}")
    out.append("")
    hatch = tenancy["escape_hatch"]
    out.append(f"**紧急通道**：角色 `{hatch['role']}`，"
               f"必须留审计事件、必须二次审批、会话最长 {hatch['max_session_minutes']} 分钟。")
    out.append("")
    out.append(hatch["policy"])
    out.append("")
    out.append("## 归档与分片")
    out.append("")
    out.append(f"- 归档：`{arch['archive']['target_scheme']}`，格式 "
               f"{arch['archive']['format']}，完整性 {arch['archive']['integrity']}。"
               f"{arch['archive']['policy']}")
    out.append(f"- 分片：`{arch['sharding']['status']}`，键 `{arch['sharding']['key']}`。"
               f"{arch['sharding']['policy']}")
    out.append("")
    out.append("## 表清单")
    out.append("")
    out.append("| 表 | 属主模块 | 租户隔离 | 可变性 | 分区 | 热/温/冷（天） | 归档目标 |")
    out.append("| --- | --- | --- | --- | --- | --- | --- |")
    for table in arch["tables"]:
        budget.check(table["table"])
        retention = table["retention"]
        partition = table["partition"]
        part = ("不分区" if partition["kind"] == "none"
                else f"{partition['kind']} / `{partition['key']}` / {partition['interval']}")
        out.append(f"| `{table['table']}` | `{table['owner']}` | "
                   f"{'RLS 强制' if table['rls'].get('enabled') else '不适用'} | "
                   f"{table['mutability']} | {part} | "
                   f"{retention['hot_days']} / {retention['warm_days']} / "
                   f"{retention['cold_days']} | `{retention['archive_target']}` |")
    out.append("")
    append_only = [t["table"] for t in arch["tables"] if t["mutability"] == "append_only"]
    out.append(f"### 仅追加表（{len(append_only)} 张）")
    out.append("")
    out.append("这些表记录的是**发生过什么**，不是**现在是什么**。"
               "它们可以被插入和读取，不能被更新或删除——生成的 DDL 在权限层直接拿掉 UPDATE/DELETE。")
    out.append("")
    out.append("、".join(f"`{t}`" for t in append_only))
    out.append("")
    personal = [(t["table"], t["personal_columns"], t.get("deletion_strategy"))
                for t in arch["tables"] if t.get("personal_columns")]
    out.append(f"### 含个人数据的表（{len(personal)} 张）")
    out.append("")
    out.append("| 表 | 个人数据列 | 删除策略 |")
    out.append("| --- | --- | --- |")
    for name, columns, strategy in personal:
        out.append(f"| `{name}` | {'、'.join('`' + c + '`' for c in columns)} | `{strategy}` |")
    out.append("")
    tenant_tables = sum(1 for t in arch["tables"] if t["tenant_scoped"])
    out.append(f"共 {len(arch['tables'])} 张表，其中 {tenant_tables} 张受租户隔离，"
               f"{len(append_only)} 张仅追加。")
    out.append("")
    return "\n".join(out)


TARGETS = {
    "contracts/sql/rls.sql": rls_sql,
    "contracts/sql/partitions.sql": partitions_sql,
    "docs/data/DATA_ARCHITECTURE.md": architecture_markdown,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
