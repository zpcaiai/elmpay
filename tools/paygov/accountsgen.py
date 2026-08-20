"""B26 — generate the provider account contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

ACCOUNTS = Path("governance/provider-accounts.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/provider-accounts.json\n"
             "     Regenerate with: python3 scripts/render-accounts.py -->\n")
CAPABILITIES = ("initiate_payment", "receive_callback", "issue_refund", "settle",
                "rotate_credential")
LABELS = {"initiate_payment": "发起支付", "receive_callback": "接收回调",
          "issue_refund": "退款", "settle": "结算", "rotate_credential": "轮换凭证"}


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / ACCOUNTS)
    for entry in model["providers"]:
        budget.check(entry["id"])
    document = {
        "_generated": "GENERATED FILE — scripts/render-accounts.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "binding": {"identity_fields": sorted(model["binding"]["identity_fields"]),
                    "unique_key": sorted(model["binding"]["unique_key"]),
                    "immutable_fields": sorted(model["binding"]["immutable_fields"]),
                    "one_credential_per_binding":
                        model["binding"]["one_credential_per_binding"]},
        "providers": [{"id": p["id"], "key_id": p["key_id"],
                       "credential_kind": p["credential_kind"],
                       "environments": sorted(p["environments"]),
                       "settlement_currencies": sorted(p["settlement_currencies"]),
                       "callback_attribution_field": p["callback_attribution_field"],
                       "callback_signed": p["callback_signed"],
                       "credential_rotation_days": p["credential_rotation_days"]}
                      for p in sorted(model["providers"], key=lambda x: x["id"])],
        "credentials": {k: v for k, v in sorted(model["credentials"].items()) if k != "notes"},
        "callback": {k: v for k, v in sorted(model["callback"].items()) if k != "notes"},
        "quarantine": {k: v for k, v in sorted(model["quarantine"].items()) if k != "notes"},
        "activation": {k: v for k, v in sorted(model["activation"].items()) if k != "notes"},
        "lifecycle": {"states": model["lifecycle"]["states"],
                      "initial": model["lifecycle"]["initial"],
                      "terminal": model["lifecycle"]["terminal"],
                      "transitions": [{"from": t["from"], "to": t["to"],
                                       "requires": sorted(t["requires"])}
                                      for t in model["lifecycle"]["transitions"]]},
        "capability_matrix": [{"state": row["state"],
                               **{c: row[c] for c in CAPABILITIES}}
                              for row in model["capability_matrix"]],
        "forbidden": {k: v for k, v in sorted(model["forbidden"].items()) if k != "notes"},
        "audit_event_class": model["audit_event_class"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def accounts_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / ACCOUNTS)
    binding = model["binding"]
    credentials = model["credentials"]
    callback = model["callback"]
    quarantine = model["quarantine"]
    activation = model["activation"]

    out = [MD_BANNER, "# 商户渠道账户与凭证绑定（B26）", "", model["principle"], "",
           "## 绑定是什么", "",
           "- 身份维度：" + "、".join(f"`{f}`" for f in binding["identity_fields"]),
           "- 唯一键：" + "、".join(f"`{f}`" for f in binding["unique_key"]),
           "- 不可变字段：" + "、".join(f"`{f}`" for f in binding["immutable_fields"]),
           f"- 一个绑定一份凭证：{'是' if binding['one_credential_per_binding'] else '否'}",
           "", binding["notes"], "",
           "## 渠道", "",
           "| 渠道 | 凭证类型 | 密钥 | 环境 | 结算币种 | 回调归属字段 | 轮换（天） |",
           "| --- | --- | --- | --- | --- | --- | --- |"]
    for entry in sorted(model["providers"], key=lambda x: x["id"]):
        budget.check(entry["id"])
        out.append(f"| `{entry['id']}` | {entry['credential_kind']} | `{entry['key_id']}` | "
                   + "、".join(entry["environments"]) + " | "
                   + "、".join(entry["settlement_currencies"]) + " | "
                   f"`{entry['callback_attribution_field']}` | "
                   f"{entry['credential_rotation_days']} |")
    out.append("")
    for entry in model["providers"]:
        out.append(f"- **`{entry['id']}`**：{entry['notes']}")

    out += ["", "## 凭证", "",
            f"- 存储：{credentials['storage']}",
            f"- 明文落盘：{'是' if credentials['plaintext_at_rest'] else '否'}；"
            f"明文进日志：{'是' if credentials['plaintext_in_logs'] else '否'}",
            f"- 解密租约上限：{credentials['max_decrypt_lease_seconds']} 秒",
            f"- 轮换：每 {credentials['rotation_max_days']} 天，"
            f"重叠期 {credentials['rotation_overlap_days']} 天",
            "- 共享：租户间"
            f"{'允许' if credentials['shared_across_tenants'] else '禁止'}、"
            f"环境间{'允许' if credentials['shared_across_environments'] else '禁止'}、"
            f"项目间{'允许' if credentials['shared_across_projects'] else '禁止'}",
            "", credentials["notes"], "",
            "## 回调", "",
            f"- 必须验签：{'是' if callback['signature_required'] else '否'}",
            f"- 归属必须确定：{'是' if callback['attribution_must_be_deterministic'] else '否'}",
            f"- 歧义时猜测：{'允许' if callback['guess_on_ambiguity'] else '**禁止**'}",
            f"- 无法归属时隔离：{'是' if callback['quarantine_on_unattributable'] else '否'}",
            f"- 跨租户投递：{'允许' if callback['cross_tenant_delivery_allowed'] else '禁止'}",
            f"- 回跳页作为支付证据：{'是' if callback['client_return_page_is_evidence'] else '**否**'}",
            f"- 接受时窗：{callback['replay_window_seconds']} 秒；"
            f"幂等键字段：`{callback['idempotency_key_field']}`",
            "", callback["notes"], "",
            "## 隔离区", "",
            f"- 保留：{quarantine['retention_days']} 天；"
            f"告警：{'必须' if quarantine['alert_required'] else '不必'}",
            f"- 自动重放：{'允许' if quarantine['auto_replay_allowed'] else '**禁止**'}",
            "- 人工重放必须给出归属："
            f"{'是' if quarantine['manual_replay_requires_attribution'] else '否'}",
            "", quarantine["notes"], "",
            "## 激活", "",
            f"- 需要真实测试交易：{'是' if activation['test_transaction_required'] else '否'}",
            f"- 需要回调往返：{'是' if activation['callback_roundtrip_required'] else '否'}",
            f"- 需要验签通过：{'是' if activation['signature_verification_required'] else '否'}",
            "", activation["notes"], "",
            "## 生命周期", "",
            " → ".join(f"`{s}`" for s in model["lifecycle"]["states"]), "",
            "| 从 | 到 | 前置条件 | 说明 |", "| --- | --- | --- | --- |"]
    for entry in model["lifecycle"]["transitions"]:
        budget.check(f"{entry['from']}->{entry['to']}")
        out.append(f"| `{entry['from']}` | `{entry['to']}` | "
                   + "、".join(f"`{r}`" for r in entry["requires"])
                   + f" | {entry['notes']} |")

    out += ["", "## 各状态下还能做什么", "",
            "| 状态 | " + " | ".join(LABELS[c] for c in CAPABILITIES) + " |",
            "| --- | " + " | ".join("---" for _ in CAPABILITIES) + " |"]
    for row in model["capability_matrix"]:
        out.append(f"| `{row['state']}` | "
                   + " | ".join("✅" if row[c] else "—" for c in CAPABILITIES) + " |")
    out.append("")
    for row in model["capability_matrix"]:
        out.append(f"- **`{row['state']}`**：{row['notes']}")

    out += ["", "## 禁止", ""]
    for key, value in model["forbidden"].items():
        if key != "notes":
            out.append(f"- `{key}`：{'禁止' if value else '允许'}")
    out += ["", model["forbidden"]["notes"], "",
            f"轮换权限：`{model['rotation_permission']}`（见 B19）；"
            f"审计事件类别：`{model['audit_event_class']}`（见 B23）。", ""]
    return "\n".join(out)


TARGETS = {
    "contracts/provider/account-binding.json": contract_json,
    "docs/provider/PROVIDER_ACCOUNTS.md": accounts_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
