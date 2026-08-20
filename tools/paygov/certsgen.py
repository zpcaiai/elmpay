"""B21 — generate the certificate/domain inventory and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

CERTS = Path("governance/certificates.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/certificates.json\n"
             "     Regenerate with: python3 scripts/render-certs.py -->\n")


def inventory_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / CERTS)
    for entry in model["materials"]:
        budget.check(entry["id"])
    document = {
        "_generated": "GENERATED FILE — scripts/render-certs.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "lifecycle_stages": model["lifecycle_stages"],
        "materials": [{"id": m["id"], "kind": m["kind"], "subject": m["subject"],
                       "issuer": m["issuer"], "key_id": m["key_id"],
                       "validity_days": m["validity_days"],
                       "renew_before_days": m["renew_before_days"],
                       "overlap_days": m["overlap_days"],
                       "automated_renewal": m["automated_renewal"],
                       "revocation": m["revocation"], "owner": m["owner"]}
                      for m in sorted(model["materials"], key=lambda x: x["id"])],
        "domains": [{"name": d["name"], "purpose": d["purpose"],
                     "registrar_lock": d["registrar_lock"], "dnssec": d["dnssec"],
                     "caa_records": sorted(d["caa_records"]),
                     "renew_before_days": d["renew_before_days"], "owner": d["owner"]}
                    for d in sorted(model["domains"], key=lambda x: x["name"])],
        "alerting": model["alerting"],
        "recovery": model["recovery"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def certs_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / CERTS)
    out = [MD_BANNER, "# 密钥、证书与域名生命周期（B21）", "", model["principle"], "",
           "## 生命周期阶段", "",
           " → ".join(f"`{stage}`" for stage in model["lifecycle_stages"]), ""]

    out += ["## 材料", "",
            "| 材料 | 类型 | 主体 | 签发方 | 有效期 | 提前续期 | 重叠期 | 自动续期 | 撤销方式 | 负责人 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for entry in sorted(model["materials"], key=lambda x: x["id"]):
        budget.check(entry["id"])
        out.append(f"| `{entry['id']}` | {entry['kind']} | `{entry['subject']}` | "
                   f"{entry['issuer']} | {entry['validity_days']} 天 | "
                   f"{entry['renew_before_days']} 天 | {entry['overlap_days']} 天 | "
                   f"{'✅' if entry['automated_renewal'] else '人工'} | "
                   f"{entry['revocation']} | {entry['owner']} |")
    out.append("")
    for entry in model["materials"]:
        out.append(f"- **`{entry['id']}`**：{entry['notes']}")
    out.append("")

    out += ["## 域名", "", "| 域名 | 用途 | 注册商锁 | DNSSEC | CAA | 提前续费 | 负责人 |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for entry in sorted(model["domains"], key=lambda x: x["name"]):
        budget.check(entry["name"])
        out.append(f"| `{entry['name']}` | {entry['purpose']} | "
                   f"{'✅' if entry['registrar_lock'] else '❌'} | "
                   f"{'✅' if entry['dnssec'] else '❌'} | "
                   f"{'、'.join(entry['caa_records'])} | {entry['renew_before_days']} 天 | "
                   f"{entry['owner']} |")
    out.append("")
    for entry in model["domains"]:
        out.append(f"- **`{entry['name']}`**：{entry['notes']}")
    out.append("")

    alerting = model["alerting"]
    out += ["## 告警", "",
            "- 通道：" + "、".join(f"`{c}`" for c in alerting["channels"]),
            f"- 到期告警阈值：剩余寿命的 {alerting['expiry_warning_ratio']:.0%}",
            f"- 连续 {alerting['escalate_after_failed_renewals']} 次自动续期失败即升级人工",
            f"- 非预期签发方告警：{'是' if alerting['alert_on_unexpected_issuer'] else '否'}；"
            f"CT 日志监控：{'是' if alerting['certificate_transparency_monitoring'] else '否'}",
            "", alerting["notes"], ""]

    recovery = model["recovery"]
    out += ["## 灾难恢复", "",
            f"- 已演练：{'是' if recovery['rehearsed'] else '否'}，"
            f"每 {recovery['rehearsal_interval_days']} 天一次",
            f"- 恢复目标：{recovery['max_recovery_hours']} 小时内",
            f"- CA 离线备份：{'是' if recovery['offline_backup_of_ca'] else '否'}；"
            f"需法定人数：{'是' if recovery['quorum_required'] else '否'}",
            "", recovery["notes"], "",
            "## 禁止项", "", model["forbidden"]["notes"], ""]
    return "\n".join(out)


TARGETS = {
    "contracts/security/certificate-inventory.json": inventory_json,
    "docs/security/CERTIFICATE_LIFECYCLE.md": certs_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
