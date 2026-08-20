"""B16 — generate the zero-trust decision matrix and review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

POLICY = Path("governance/zero-trust.json")
THREAT = Path("governance/threat-model.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/zero-trust.json\n"
             "     Regenerate with: python3 scripts/render-zerotrust.py -->\n")


def matrix_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    policy = load_json(root / POLICY)
    rows = []
    for entry in policy["decisions"]:
        budget.check(entry["id"])
        rows.append({"id": entry["id"], "principal": entry["principal"],
                     "resource_class": entry["resource_class"], "action": entry["action"],
                     "requirements": sorted(entry["requirements"]),
                     "step_up": entry["step_up"], "four_eyes": entry["four_eyes"],
                     "audit_event": entry["audit_event"]})
    document = {
        "_generated": "GENERATED FILE — scripts/render-zerotrust.py; do not edit by hand",
        "schema_version": policy["schema_version"],
        "deny_by_default": policy["deny_by_default"],
        "network_location_grants": policy["network_location_grants"],
        "session": policy["session"],
        "workload_identity": policy["workload_identity"],
        "decisions": sorted(rows, key=lambda r: r["id"]),
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def zerotrust_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    policy = load_json(root / POLICY)
    threat = load_json(root / THREAT)
    boundaries = {b["id"]: b for b in threat["trust_boundaries"]}
    zones = {z["id"]: z for z in threat["zones"]}

    out = [MD_BANNER, "# 零信任访问架构（B16）", ""]
    out.append(policy["principle"])
    out.append("")
    out.append(f"- 默认拒绝：**{policy['deny_by_default']}**")
    out.append(f"- 网络位置授予的权限：**{policy['network_location_grants'] or '无'}**"
               f"（这一项必须为空，否则整套设计退化成防火墙）")
    session = policy["session"]
    out.append(f"- 人的会话最长 {session['max_human_session_minutes']} 分钟；"
               f"撤销必须在 {session['revocation_propagation_seconds']} 秒内全局生效")
    workload = policy["workload_identity"]
    out.append(f"- 工作负载身份：`{workload['scheme']}` over `{workload['transport']}`，"
               f"证书最长 {workload['max_certificate_minutes']} 分钟，"
               f"长期静态凭据：**{'允许' if workload['static_long_lived_credentials_allowed'] else '禁止'}**")
    out.append("")
    out.append(f"> {workload['policy']}")
    out.append("")
    out.append("## 审计")
    out.append("")
    audit = policy["audit"]
    out.append(f"每一次判定（**包括允许**）都要落审计：{audit['every_decision_recorded']}；"
               f"审计不可修改：{audit['immutable']}。")
    out.append("")
    out.append("必备字段：" + "、".join(f"`{f}`" for f in audit["required_fields"]))
    out.append("")
    out.append(f"> {audit['policy']}")
    out.append("")
    out.append("## 主体")
    out.append("")
    out.append("| 主体 | 类别 | 所在区域 | 身份来源 | 凭据 | 有效期(分) | 轮换(天) |")
    out.append("| --- | --- | --- | --- | --- | --- | --- |")
    for principal in policy["principals"]:
        budget.check(principal["id"])
        zone = zones.get(principal["home_zone"], {})
        out.append(f"| `{principal['id']}` | {principal['kind']} | "
                   f"{principal['home_zone']} {zone.get('name', '')} | "
                   f"`{principal['identity_source']}` | `{principal['credential']}` | "
                   f"{principal['credential_lifetime_minutes']} | "
                   f"{principal['rotation_days']} |")
    out.append("")
    for principal in policy["principals"]:
        out.append(f"- **`{principal['id']}`**：{principal['notes']}")
    out.append("")
    out.append("## 访问判定矩阵")
    out.append("")
    out.append("| 编号 | 主体 | 资源 | 动作 | 要求 | Step-up | 四眼 | 审计事件 |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for entry in policy["decisions"]:
        budget.check(entry["id"])
        out.append(f"| {entry['id']} | `{entry['principal']}` | `{entry['resource_class']}` | "
                   f"{entry['action']} | "
                   f"{'、'.join('`' + r + '`' for r in entry['requirements'])} | "
                   f"{'是' if entry['step_up'] else '否'} | "
                   f"{'是' if entry['four_eyes'] else '否'} | `{entry['audit_event']}` |")
    out.append("")
    for entry in policy["decisions"]:
        out.append(f"- **{entry['id']}**：{entry['notes']}")
    out.append("")
    out.append("## 信任边界规则")
    out.append("")
    out.append("| 边界 | 名称 | 连接区域 | 双向 mTLS | 要求 |")
    out.append("| --- | --- | --- | --- | --- |")
    for rule in policy["zone_rules"]:
        boundary = boundaries.get(rule["boundary"], {})
        between = "、".join(f"{z}({zones.get(z, {}).get('trust', '?')})"
                            for z in boundary.get("between", []))
        out.append(f"| {rule['boundary']} | {boundary.get('name', '')} | {between} | "
                   f"{'是' if rule['mutual_tls'] else '否'} | "
                   f"{'、'.join('`' + r + '`' for r in rule['requires'])} |")
    out.append("")
    for rule in policy["zone_rules"]:
        out.append(f"- **{rule['boundary']}**：{rule['notes']}")
    out.append("")
    four_eyes = sum(1 for d in policy["decisions"] if d["four_eyes"])
    out.append(f"共 {len(policy['principals'])} 类主体、{len(policy['decisions'])} 条访问判定"
               f"（其中 {four_eyes} 条需要四眼复核）、{len(policy['zone_rules'])} 条边界规则。")
    out.append("")
    return "\n".join(out)


TARGETS = {
    "contracts/security/zero-trust-matrix.json": matrix_json,
    "docs/security/ZERO_TRUST.md": zerotrust_markdown,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
