"""B19 — generate the authorisation matrix and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

AUTHZ = Path("governance/authorization.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/authorization.json\n"
             "     Regenerate with: python3 scripts/render-authz.py -->\n")


def matrix_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / AUTHZ)
    for role in model["roles"]:
        budget.check(role["id"])
    document = {
        "_generated": "GENERATED FILE — scripts/render-authz.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "default_decision": model["default_decision"],
        "privileged_roles": sorted(r["id"] for r in model["roles"] if r["privileged"]),
        "roles": [{"id": r["id"], "kind": r["kind"], "scope": r["scope"],
                   "privileged": r["privileged"],
                   "zero_trust_principal": r["zero_trust_principal"],
                   "permissions": sorted(r["permissions"])}
                  for r in sorted(model["roles"], key=lambda x: x["id"])],
        "permissions": [{"id": p["id"], "scope": p["scope"], "sensitivity": p["sensitivity"],
                         "dual_control": p["dual_control"],
                         "elevation_required": p["elevation_required"]}
                        for p in sorted(model["permissions"], key=lambda x: x["id"])],
        "field_rules": [{"field": f["field"], "classification": f["classification"],
                         "never_readable": f["never_readable"],
                         "masked_by_default": f["masked_by_default"],
                         "readable_by": sorted(f["readable_by"])}
                        for f in sorted(model["field_rules"], key=lambda x: x["field"])],
        "separation_of_duties": [{"id": s["id"], "left": s["left"], "right": s["right"]}
                                 for s in sorted(model["separation_of_duties"],
                                                 key=lambda x: x["id"])],
        "dual_control": model["dual_control"],
        "elevation": model["elevation"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def authz_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / AUTHZ)
    permissions = {p["id"]: p for p in model["permissions"]}
    out = [MD_BANNER, "# 授权、职责分离与限时提权（B19）", "", model["principle"], ""]

    out += ["## 角色", "", "| 角色 | 类型 | 范围 | 特权 | 零信任主体 | 常驻权限 |",
            "| --- | --- | --- | --- | --- | --- |"]
    for role in model["roles"]:
        budget.check(role["id"])
        granted = "、".join(f"`{p}`" for p in sorted(role["permissions"])) or "（无）"
        out.append(f"| `{role['id']}` | {role['kind']} | {role['scope']} | "
                   f"{'✅' if role['privileged'] else '—'} | "
                   f"`{role['zero_trust_principal']}` | {granted} |")
    out.append("")
    for role in model["roles"]:
        out.append(f"- **`{role['id']}`**：{role['notes']}")
    out.append("")

    out += ["## 权限", "", "| 权限 | 层级 | 敏感度 | 双人复核 | 需提权 |", "| --- | --- | --- | --- | --- |"]
    for perm in model["permissions"]:
        budget.check(perm["id"])
        out.append(f"| `{perm['id']}` | {perm['scope']} | {perm['sensitivity']} | "
                   f"{'✅' if perm['dual_control'] else '—'} | "
                   f"{'✅' if perm['elevation_required'] else '—'} |")
    out.append("")

    out += ["## 字段级规则", "", "| 字段 | 分类 | 永不可读 | 默认脱敏 | 可读全文的角色 |",
            "| --- | --- | --- | --- | --- |"]
    for field in model["field_rules"]:
        budget.check(field["field"])
        readers = "、".join(f"`{r}`" for r in sorted(field["readable_by"])) or "（无）"
        out.append(f"| `{field['field']}` | {field['classification']} | "
                   f"{'✅' if field['never_readable'] else '—'} | "
                   f"{'✅' if field['masked_by_default'] else '—'} | {readers} |")
    out.append("")
    for field in model["field_rules"]:
        out.append(f"- **`{field['field']}`**：{field['notes']}")
    out.append("")

    out += ["## 职责分离", "", "| 编号 | 不得由同一人同时持有 | 说明 |", "| --- | --- | --- |"]
    for rule in model["separation_of_duties"]:
        budget.check(rule["id"])
        out.append(f"| {rule['id']} | `{rule['left']}` + `{rule['right']}` | {rule['notes']} |")
    out.append("")

    dual = model["dual_control"]
    out += ["## 双人复核", "",
            f"- 最少审批数：{dual['minimum_approvals']}；审批人必须不同于申请人："
            f"{'是' if dual['approver_must_differ_from_requester'] else '否'}",
            f"- 审批有效期：{dual['approval_ttl_seconds']} 秒；绑定请求摘要："
            f"{'是' if dual['approval_bound_to_request_digest'] else '否'}",
            "", dual["notes"], ""]

    elev = model["elevation"]
    glass = elev["break_glass"]
    out += ["## 限时提权（JIT）", "",
            f"- 常驻特权：{'允许' if elev['standing_privileged_access'] else '**不允许**'}",
            f"- 最长时限：{elev['max_duration_minutes']} 分钟；到点自动收回："
            f"{'是' if elev['auto_revoke'] else '否'}",
            f"- 需审批：{'是' if elev['requires_approval'] else '否'}；需票据："
            f"{'是' if elev['requires_ticket_reference'] else '否'}",
            "- 可提权的权限：" + "、".join(f"`{p}`" for p in sorted(elev["elevatable_permissions"])),
            "- 不可提权的角色：" + "、".join(f"`{r}`" for r in sorted(elev["non_elevatable_roles"])),
            "", elev["notes"], "",
            f"### 紧急通道（`{glass['role']}`）", "",
            f"- 最长 {glass['max_duration_minutes']} 分钟，事后 {glass['post_use_review_hours']} "
            f"小时内必须复核",
            "- 通知渠道：" + "、".join(f"`{c}`" for c in glass["notify_channels"]),
            "", glass["notes"], ""]

    audit = model["audit"]
    out += ["## 审计", "", audit["notes"], ""]

    money = sorted(p for p, entry in permissions.items() if entry["sensitivity"] == "money")
    out += ["## 资金类权限清单（供审查者速查）", "",
            "、".join(f"`{p}`" for p in money), ""]
    return "\n".join(out)


TARGETS = {
    "contracts/security/authorization-matrix.json": matrix_json,
    "docs/security/AUTHORIZATION.md": authz_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
