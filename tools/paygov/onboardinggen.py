"""B30 — generate the onboarding workflow contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

ONBOARDING = Path("governance/onboarding-workflow.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/onboarding-workflow.json\n"
             "     Regenerate with: python3 scripts/render-onboarding.py -->\n")
STEP_FIELDS = ("id", "order", "has_side_effect", "idempotent", "resumable",
               "requires_approval", "evidence_required")


def _without_notes(block: dict) -> dict:
    return {k: v for k, v in sorted(block.items()) if k != "notes"}


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / ONBOARDING)
    steps = []
    for step in sorted(model["steps"], key=lambda s: s["order"]):
        budget.check(step["id"])
        steps.append({field: step[field] for field in STEP_FIELDS})
    document = {
        "_generated": "GENERATED FILE — scripts/render-onboarding.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "steps": steps,
        "approval": {**_without_notes(model["approval"]),
                     "digest_fields": sorted(model["approval"]["digest_fields"])},
        "resumption": _without_notes(model["resumption"]),
        "domain_verification": _without_notes(model["domain_verification"]),
        "callback_verification": _without_notes(model["callback_verification"]),
        "credentials": _without_notes(model["credentials"]),
        "limits": _without_notes(model["limits"]),
        "suspension": _without_notes(model["suspension"]),
        "audit_event_class": model["audit_event_class"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def onboarding_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / ONBOARDING)
    approval = model["approval"]
    resumption = model["resumption"]
    domain = model["domain_verification"]
    callback = model["callback_verification"]
    credentials = model["credentials"]
    limits = model["limits"]
    suspension = model["suspension"]

    out = [MD_BANNER, "# 商户接入与四眼审批（B30）", "", model["principle"], "",
           "## 步骤", "",
           "| 顺序 | 步骤 | 有副作用 | 幂等 | 可恢复 | 需审批 | 产出证据 |",
           "| --- | --- | --- | --- | --- | --- | --- |"]
    for step in sorted(model["steps"], key=lambda s: s["order"]):
        budget.check(step["id"])
        out.append(f"| {step['order']} | `{step['id']}` | "
                   f"{'是' if step['has_side_effect'] else '否'} | "
                   f"{'是' if step['idempotent'] else '否'} | "
                   f"{'是' if step['resumable'] else '否'} | "
                   f"{'是' if step['requires_approval'] else '否'} | "
                   f"`{step['evidence_required']}` |")
    out.append("")
    for step in sorted(model["steps"], key=lambda s: s["order"]):
        out.append(f"- **`{step['id']}`**：{step['notes']}")

    out += ["", "## 四眼审批", "",
            f"- 需要人数：{approval['eyes_required']}；"
            f"批准人不得是申请人：{'是' if approval['approver_differs_from_requester'] else '否'}",
            f"- 绑定内容摘要：{'是' if approval['bound_to_digest'] else '否'}",
            "- 摘要字段：" + "、".join(f"`{f}`" for f in approval["digest_fields"]),
            f"- 有效期：{approval['expires_hours']} 小时；"
            f"内容变更后需重新批准："
            f"{'是' if approval['reapproval_required_on_change'] else '否'}",
            f"- 权限：`{approval['permission']}`（见 B19）",
            "", approval["notes"], "",
            "## 恢复", "",
            f"- 状态落盘：{'是' if resumption['state_persisted'] else '否'}",
            f"- 从最后一个已完成步骤继续："
            f"{'是' if resumption['resume_from_last_completed_step'] else '否'}",
            f"- 重放已完成的副作用："
            f"{'是' if resumption['replay_completed_side_effects'] else '**否**'}",
            f"- 允许手工完成：{'是' if resumption['manual_completion_allowed'] else '**否**'}",
            f"- 最长可恢复：{resumption['max_resume_days']} 天",
            "", resumption["notes"], "",
            "## 域名验证", "",
            f"- 方式：`{domain['method']}`；令牌一次性："
            f"{'是' if domain['token_single_use'] else '否'}",
            f"- 令牌有效期：{domain['token_expires_hours']} 小时；"
            f"允许通配符：{'是' if domain['wildcard_allowed'] else '**否**'}",
            "", domain["notes"], "",
            "## 回调验证", "",
            f"- 需要往返：{'是' if callback['roundtrip_required'] else '否'}；"
            f"需要验签：{'是' if callback['signature_required'] else '否'}",
            f"- 必须 HTTPS：{'是' if callback['https_required'] else '否'}；"
            f"允许内网地址：{'是' if callback['private_address_allowed'] else '**否**'}",
            "", callback["notes"], "",
            "## 凭证", "",
            f"- 允许回显：{'是' if credentials['echo_back_allowed'] else '**否**'}",
            f"- 只导入一次：{'是' if credentials['import_once'] else '否'}；"
            f"经由 B26 绑定存储：{'是' if credentials['stored_via_binding'] else '否'}",
            "", credentials["notes"], "",
            "## 限额", "",
            f"- 上线前必须设置：{'是' if limits['must_be_set_before_go_live'] else '否'}",
            f"- 默认取自风险等级：{'是' if limits['default_from_risk_level'] else '否'}；"
            f"调高需审批：{'是' if limits['raise_requires_approval'] else '否'}",
            "", limits["notes"], "",
            "## 停用与恢复", "",
            f"- 停用需要人数：{suspension['approvals_required']}；"
            f"立即生效：{'是' if suspension['immediate'] else '否'}",
            f"- 恢复需要人数：{suspension['reinstatement_approvals_required']}",
            "", suspension["notes"], "",
            f"审计事件类别：`{model['audit_event_class']}`（见 B23）。", ""]
    return "\n".join(out)


TARGETS = {
    "contracts/onboarding/workflow.json": contract_json,
    "docs/onboarding/ONBOARDING_WORKFLOW.md": onboarding_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
