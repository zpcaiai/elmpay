"""B25 — generate the merchant profile contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

MERCHANT = Path("governance/merchant-profile.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/merchant-profile.json\n"
             "     Regenerate with: python3 scripts/render-merchant.py -->\n")


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / MERCHANT)
    for entry in model["documents"]:
        budget.check(entry["id"])
    document = {
        "_generated": "GENERATED FILE — scripts/render-merchant.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "verification": {
            "platform_is_licensed_verifier": model["verification"]["platform_is_licensed_verifier"],
            "authority_required": model["verification"]["authority_required"],
            "authority_fields": sorted(model["verification"]["authority_fields"]),
            "max_validity_days": model["verification"]["max_validity_days"],
            "self_attestation_allowed_for":
                sorted(model["verification"]["self_attestation_allowed_for"]),
        },
        "entity_kinds": [{"id": e["id"], "required_documents": sorted(e["required_documents"])}
                         for e in sorted(model["entity_kinds"], key=lambda x: x["id"])],
        "documents": [{"id": d["id"], "expires_days": d["expires_days"],
                       "contains_pii": d["contains_pii"], "issuer": d["issuer"]}
                      for d in sorted(model["documents"], key=lambda x: x["id"])],
        "ubo": {"ownership_threshold_percent": model["ubo"]["ownership_threshold_percent"],
                "max_ownership_depth": model["ubo"]["max_ownership_depth"],
                "requires_identity_document": model["ubo"]["requires_identity_document"],
                "screening_required": model["ubo"]["screening_required"]},
        "screening": {"lists": sorted(model["screening"]["lists"]),
                      "rescreen_interval_days": model["screening"]["rescreen_interval_days"],
                      "hit_requires_human_review": model["screening"]["hit_requires_human_review"],
                      "auto_approve_on_hit": model["screening"]["auto_approve_on_hit"]},
        "business_categories": [{"code": c["code"], "risk": c["risk"], "allowed": c["allowed"]}
                                for c in sorted(model["business_categories"],
                                                key=lambda x: x["code"])],
        "operating_regions": [{"code": r["code"],
                               "settlement_currencies": sorted(r["settlement_currencies"]),
                               "requires_local_entity": r["requires_local_entity"]}
                              for r in sorted(model["operating_regions"], key=lambda x: x["code"])],
        "risk_levels": [{"id": r["id"], "daily_limit_minor": r["daily_limit_minor"],
                         "single_limit_minor": r["single_limit_minor"],
                         "settlement_delay_days": r["settlement_delay_days"],
                         "approvers_required": r["approvers_required"]}
                        for r in model["risk_levels"]],
        "material_changes": [{"id": m["id"], "permission": m["permission"],
                              "requires_reverification": m["requires_reverification"],
                              "holds_settlement": m["holds_settlement"]}
                             for m in sorted(model["material_changes"], key=lambda x: x["id"])],
        "retention": model["retention"],
        "audit_event_class": model["audit_event_class"],
        "appeal": model["appeal"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def merchant_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / MERCHANT)
    verification = model["verification"]
    out = [MD_BANNER, "# 商户资料与 KYB 元数据（B25）", "", model["principle"], "",
           "## 核验：谁说了算", "",
           f"- 平台是持牌核验机构：{'是' if verification['platform_is_licensed_verifier'] else '**否**'}",
           f"- 核验决定必须引用外部机构：{'是' if verification['authority_required'] else '否'}",
           "- 必需字段：" + "、".join(f"`{f}`" for f in verification["authority_fields"]),
           f"- 核验结论最长有效期：{verification['max_validity_days']} 天",
           "- 允许商户自证的字段：" +
           "、".join(f"`{f}`" for f in verification["self_attestation_allowed_for"]),
           "", verification["notes"], "",
           "## 主体类型与所需材料", "", "| 主体 | 材料 | 说明 |", "| --- | --- | --- |"]
    for entry in model["entity_kinds"]:
        budget.check(entry["id"])
        out.append(f"| `{entry['id']}` | " +
                   "、".join(f"`{d}`" for d in entry["required_documents"]) +
                   f" | {entry['notes']} |")

    out += ["", "## 材料与有效期", "",
            "| 材料 | 证明什么 | 有效期（天） | 含个人信息 | 出具方 |",
            "| --- | --- | --- | --- | --- |"]
    for entry in sorted(model["documents"], key=lambda x: x["expires_days"]):
        budget.check(entry["id"])
        out.append(f"| `{entry['id']}` | {entry['verifies']} | {entry['expires_days']} | "
                   f"{'是' if entry['contains_pii'] else '否'} | {entry['issuer']} |")
    out.append("")
    for entry in model["documents"]:
        out.append(f"- **`{entry['id']}`**：{entry['notes']}")

    ubo = model["ubo"]
    screening = model["screening"]
    out += ["", "## 实际控制人（UBO）", "",
            f"- 持股门槛：{ubo['ownership_threshold_percent']}%",
            f"- 穿透层数上限：{ubo['max_ownership_depth']}",
            f"- 需要身份证件：{'是' if ubo['requires_identity_document'] else '否'}",
            f"- 需要名单筛查：{'是' if ubo['screening_required'] else '否'}",
            "", ubo["notes"], "",
            "## 名单筛查", "",
            "- 名单：" + "、".join(f"`{n}`" for n in screening["lists"]),
            f"- 重筛周期：{screening['rescreen_interval_days']} 天",
            f"- 命中转人工：{'是' if screening['hit_requires_human_review'] else '否'}",
            f"- 命中后自动放行：{'是' if screening['auto_approve_on_hit'] else '**否**'}",
            "", screening["notes"], "",
            "## 经营类目", "", "| 类目 | 风险 | 是否承接 | 说明 |", "| --- | --- | --- | --- |"]
    for entry in model["business_categories"]:
        out.append(f"| `{entry['code']}` | {entry['risk']} | "
                   f"{'✅' if entry['allowed'] else '❌'} | {entry['notes']} |")

    out += ["", "## 经营地区与结算币种", "",
            "| 地区 | 结算币种 | 需本地主体 | 说明 |", "| --- | --- | --- | --- |"]
    for entry in model["operating_regions"]:
        out.append(f"| `{entry['code']}` | " +
                   "、".join(f"`{c}`" for c in entry["settlement_currencies"]) +
                   f" | {'是' if entry['requires_local_entity'] else '否'} | {entry['notes']} |")

    out += ["", "## 风险等级", "",
            "| 等级 | 日限额（最小单位） | 单笔限额 | 结算延迟（天） | 批准人数 |",
            "| --- | --- | --- | --- | --- |"]
    for entry in model["risk_levels"]:
        out.append(f"| `{entry['id']}` | {entry['daily_limit_minor']} | "
                   f"{entry['single_limit_minor']} | {entry['settlement_delay_days']} | "
                   f"{entry['approvers_required']} |")
    out.append("")
    for entry in model["risk_levels"]:
        out.append(f"- **`{entry['id']}`**：{entry['notes']}")

    out += ["", "## 重大变更", "",
            "| 变更 | 所需权限 | 需重新核验 | 暂停结算 | 说明 |",
            "| --- | --- | --- | --- | --- |"]
    for entry in model["material_changes"]:
        budget.check(entry["id"])
        out.append(f"| `{entry['id']}` | `{entry['permission']}` | "
                   f"{'是' if entry['requires_reverification'] else '否'} | "
                   f"{'是' if entry['holds_settlement'] else '否'} | {entry['notes']} |")

    retention = model["retention"]
    appeal = model["appeal"]
    out += ["", "## 留存", "",
            f"- 离场后保留：{retention['after_offboarding_days']} 天",
            f"- 按声明目的最小化：{'是' if retention['minimise_to_declared_purpose'] else '否'}",
            f"- 材料加密存储：{'是' if retention['documents_encrypted'] else '否'}",
            "", retention["notes"], "",
            f"审计事件类别：`{model['audit_event_class']}`（见 B23）。", "",
            "## 申诉", "",
            f"- 可申诉：{'是' if appeal['available'] else '否'}",
            f"- 决定必须说明理由：{'是' if appeal['decision_must_state_reasons'] else '否'}",
            f"- 复核人须不同于原判人：{'是' if appeal['reviewer_must_differ_from_decider'] else '否'}",
            f"- 答复时限：{appeal['response_days']} 天",
            "", appeal["notes"], ""]
    return "\n".join(out)


TARGETS = {
    "contracts/merchant/profile-model.json": contract_json,
    "docs/merchant/MERCHANT_PROFILE.md": merchant_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
