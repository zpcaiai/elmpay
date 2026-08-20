"""B20 — generate the key inventory and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

KEYS = Path("governance/key-management.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/key-management.json\n"
             "     Regenerate with: python3 scripts/render-keys.py -->\n")


def inventory_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / KEYS)
    for entry in model["keys"]:
        budget.check(entry["id"])
    document = {
        "_generated": "GENERATED FILE — scripts/render-keys.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "envelope": model["envelope"],
        "hsm": model["hsm"],
        "rotation": model["rotation"],
        "destruction": model["destruction"],
        "keys": [{"id": k["id"], "class": k["class"], "purpose": k["purpose"],
                  "storage": k["storage"], "algorithm": k["algorithm"],
                  "rotation_days": k["rotation_days"], "tenant_scoped": k["tenant_scoped"],
                  "wrapped_by": k.get("wrapped_by"),
                  "protects_fields": sorted(k["protects_fields"])}
                 for k in sorted(model["keys"], key=lambda x: x["id"])],
        "provider_keys": [{"provider": p["provider"], "key_id": p["key_id"],
                           "material": p["material"],
                           "signing_algorithm": p["signing_algorithm"]}
                          for p in sorted(model["provider_keys"], key=lambda x: x["provider"])],
        "forbidden": model["forbidden"],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def keys_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / KEYS)
    env = model["envelope"]
    hsm = model["hsm"]
    rot = model["rotation"]
    out = [MD_BANNER, "# 密钥层级、信封加密与轮换（B20）", "", model["principle"], ""]

    out += ["## 密钥层级", "",
            "| 密钥 | 层 | 用途 | 存储 | 算法 | 轮换 | 租户维度 | 被谁包裹 | 保护字段 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for key in sorted(model["keys"], key=lambda x: (x["class"], x["id"])):
        budget.check(key["id"])
        fields = "、".join(f"`{f}`" for f in sorted(key["protects_fields"])) or "—"
        out.append(f"| `{key['id']}` | {key['class']} | {key['purpose']} | {key['storage']} | "
                   f"{key['algorithm']} | {key['rotation_days']} 天 | "
                   f"{'是' if key['tenant_scoped'] else '否'} | "
                   f"{'`' + key['wrapped_by'] + '`' if key.get('wrapped_by') else '—'} | "
                   f"{fields} |")
    out.append("")
    for key in model["keys"]:
        out.append(f"- **`{key['id']}`**：{key['notes']}")
    out.append("")

    out += ["## 信封加密", "",
            f"- 数据密钥算法：`{env['data_key_algorithm']}`，"
            f"包裹算法：`{env['key_wrapping_algorithm']}`",
            f"- 粒度：每 {env['data_key_per']} 一把；明文数据密钥存活 "
            f"{env['plaintext_data_key_ttl_seconds']} 秒",
            f"- nonce：{env['nonce_bytes']} 字节，禁止重用："
            f"{'是' if env['nonce_reuse_forbidden'] else '否'}",
            "- AAD 绑定：" + "、".join(f"`{f}`" for f in env["aad_fields"]),
            "", env["notes"], ""]

    out += ["## HSM", "",
            f"- 根密钥必须在 HSM：{'是' if hsm['required_for_root'] else '否'}；"
            f"FIPS 140 等级：{hsm['fips_140_level']}",
            f"- 可导出：{'是' if hsm['root_key_exportable'] else '否'}；"
            f"法定人数：{hsm['quorum_m_of_n'][0]}/{hsm['quorum_m_of_n'][1]}",
            "", hsm["notes"], ""]

    out += ["## 轮换", "",
            f"- 根密钥 {rot['root_days']} 天、KEK {rot['kek_days']} 天、"
            f"数据密钥每条记录一把",
            f"- 重叠期 {rot['overlap_window_days']} 天；策略：`{rot['re_encrypt_strategy']}`",
            f"- 紧急轮换：{rot['emergency_rotation_hours']} 小时内",
            "", rot["notes"], ""]

    out += ["## 渠道与身份提供方密钥", "", "| 提供方 | 密钥材料 | 签名算法 | 归属密钥 |",
            "| --- | --- | --- | --- |"]
    for entry in sorted(model["provider_keys"], key=lambda x: x["provider"]):
        budget.check(entry["provider"])
        out.append(f"| `{entry['provider']}` | {entry['material']} | "
                   f"{entry['signing_algorithm']} | `{entry['key_id']}` |")
    out.append("")
    for entry in model["provider_keys"]:
        out.append(f"- **`{entry['provider']}`**：{entry['notes']}")
    out.append("")

    out += ["## 销毁（密码学销毁）", "", model["destruction"]["notes"], "",
            "## 禁止项", "",
            "- 算法：" + "、".join(f"`{a}`" for a in model["forbidden"]["algorithms"]),
            f"- RSA 最小长度：{model['forbidden']['minimum_rsa_bits']} 位",
            "", model["forbidden"]["notes"], ""]
    return "\n".join(out)


TARGETS = {
    "contracts/security/key-inventory.json": inventory_json,
    "docs/security/KEY_MANAGEMENT.md": keys_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
