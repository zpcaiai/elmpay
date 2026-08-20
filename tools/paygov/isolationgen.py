"""B31 — generate the tenant isolation contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

ISOLATION = Path("governance/tenant-isolation.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/tenant-isolation.json\n"
             "     Regenerate with: python3 scripts/render-isolation.py -->\n")


def _without_notes(block: dict) -> dict:
    return {k: v for k, v in sorted(block.items()) if k != "notes"}


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / ISOLATION)
    surfaces = []
    for surface in sorted(model["surfaces"], key=lambda s: s["id"]):
        budget.check(surface["id"])
        surfaces.append({"id": surface["id"], "mechanism": surface["mechanism"],
                         "enforced_at": surface["enforced_at"], "default": surface["default"],
                         "tenant_key": surface["tenant_key"],
                         "probe": {k: v for k, v in sorted(surface["probe"].items())}})
    document = {
        "_generated": "GENERATED FILE — scripts/render-isolation.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "surfaces": surfaces,
        "forced_controls": _without_notes(model["forced_controls"]),
        "cache": _without_notes(model["cache"]),
        "messaging": _without_notes(model["messaging"]),
        "logs": _without_notes(model["logs"]),
        "exports": _without_notes(model["exports"]),
        "evidence": _without_notes(model["evidence"]),
        "audit_event_class": model["audit_event_class"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def isolation_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / ISOLATION)
    forced = model["forced_controls"]
    cache = model["cache"]
    messaging = model["messaging"]
    logs = model["logs"]
    exports = model["exports"]
    evidence = model["evidence"]

    out = [MD_BANNER, "# 租户隔离验证（B31）", "", model["principle"], "",
           "## 隔离面与探针", "",
           "| 隔离面 | 机制 | 强制点 | 默认 | 租户键 | 探针（断言拒绝） |",
           "| --- | --- | --- | --- | --- | --- |"]
    for surface in model["surfaces"]:
        budget.check(surface["id"])
        out.append(f"| `{surface['id']}` | {surface['mechanism']} | {surface['enforced_at']} | "
                   f"{surface['default']} | `{surface['tenant_key']}` | "
                   f"`{surface['probe']['id']}` |")
    out.append("")
    for surface in model["surfaces"]:
        out.append(f"- **`{surface['id']}`**：{surface['notes']}")

    out += ["", "## 强制控制", "",
            f"- 行级安全对表属主同样生效："
            f"{'是' if forced['rls_forced_for_table_owner'] else '否'}",
            f"- 查询必须带租户上下文：{'是' if forced['session_tenant_required'] else '否'}",
            f"- 仅靠应用层过滤即可："
            f"{'是' if forced['application_side_filter_alone_sufficient'] else '**否**'}",
            f"- 跨租户权限：`{forced['cross_tenant_permission']}`（见 B19）",
            "", forced["notes"], "",
            "## 缓存", "",
            f"- 键含租户：{'是' if cache['key_includes_tenant'] else '否'}；"
            f"允许共享命名空间：{'是' if cache['shared_namespace_allowed'] else '**否**'}",
            f"- 否定缓存按租户分区：{'是' if cache['negative_cache_scoped'] else '否'}",
            "", cache["notes"], "",
            "## 消息", "",
            f"- 信封带租户：{'是' if messaging['tenant_in_envelope'] else '否'}；"
            f"消费者必须校验："
            f"{'是' if messaging['consumer_must_verify_tenant'] else '否'}",
            f"- 允许跨租户扇出："
            f"{'是' if messaging['cross_tenant_fanout_allowed'] else '**否**'}",
            "", messaging["notes"], "",
            "## 日志", "",
            f"- 必须带租户字段：{'是' if logs['tenant_field_required'] else '否'}；"
            f"载荷脱敏：{'是' if logs['payload_redacted'] else '否'}",
            f"- 跨租户聚合需要权限："
            f"{'是' if logs['cross_tenant_aggregation_requires_permission'] else '否'}",
            "", logs["notes"], "",
            "## 导出", "",
            f"- 过滤写在查询里：{'是' if exports['filter_in_query'] else '否'}；"
            f"一次导出一个租户：{'是' if exports['single_tenant_per_export'] else '否'}",
            f"- 核对行数：{'是' if exports['row_count_verified'] else '否'}",
            "", exports["notes"], "",
            "## 证据", "",
            f"- 每个隔离面都有探针：{'是' if evidence['every_surface_has_probe'] else '否'}",
            f"- 探针必须断言拒绝："
            f"{'是' if evidence['probe_must_assert_denial'] else '否'}",
            f"- 探针在 CI 中运行：{'是' if evidence['probes_run_in_ci'] else '否'}",
            f"- 仅正向的测试不构成证据："
            f"{'是' if evidence['positive_only_test_is_not_evidence'] else '否'}",
            "", evidence["notes"], "",
            f"审计事件类别：`{model['audit_event_class']}`（见 B23）。", ""]
    return "\n".join(out)


TARGETS = {
    "contracts/tenancy/isolation.json": contract_json,
    "docs/tenancy/TENANT_ISOLATION.md": isolation_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
