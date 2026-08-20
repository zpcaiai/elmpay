"""B17 — generate the identity contract and review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

IDENTITY = Path("governance/identity.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/identity.json\n"
             "     Regenerate with: python3 scripts/render-identity.py -->\n")


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    identity = load_json(root / IDENTITY)
    document = {
        "_generated": "GENERATED FILE — scripts/render-identity.py; do not edit by hand",
        "schema_version": identity["schema_version"],
        "bearer_tokens_allowed": identity["bearer_tokens_allowed"],
        "forbidden_algorithms": sorted(identity["forbidden_algorithms"]),
        "oauth": identity["oauth"],
        "revocation": identity["revocation"],
        "session_binding": identity["session_binding"],
        "providers": [{"id": p["id"], "issuer": p["issuer"],
                       "audiences": sorted(p["audiences"]),
                       "algorithms": sorted(p["algorithms"]),
                       "max_token_minutes": p["max_token_minutes"],
                       "clock_skew_seconds": p["clock_skew_seconds"]}
                      for p in sorted(identity["providers"], key=lambda x: x["id"])],
        "tokens": [{"id": t["id"], "kind": t["kind"], "provider": t["provider"],
                    "audience": t["audience"], "lifetime_minutes": t["lifetime_minutes"],
                    "binding": t["binding"], "revocable": t["revocable"]}
                   for t in sorted(identity["tokens"], key=lambda x: x["id"])],
    }
    for provider in identity["providers"]:
        budget.check(provider["id"])
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def identity_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    identity = load_json(root / IDENTITY)
    out = [MD_BANNER, "# 客户、管理员与服务身份（B17）", ""]
    out.append(identity["principle"])
    out.append("")
    out.append(f"- 允许无绑定 bearer 令牌：**{identity['bearer_tokens_allowed']}**")
    out.append(f"- 禁止的签名算法：{'、'.join('`' + a + '`' for a in identity['forbidden_algorithms'])}")
    binding = identity["session_binding"]
    out.append(f"- 令牌绑定：必需={binding['required']}，"
               f"方式 {'、'.join('`' + m + '`' for m in binding['methods'])}")
    out.append("")
    out.append(f"> {binding['policy']}")
    out.append("")
    oauth = identity["oauth"]
    out.append("## OAuth / OIDC")
    out.append("")
    out.append(f"- 允许的流程：{'、'.join('`' + f + '`' for f in oauth['allowed_flows'])}")
    out.append(f"- 禁止的流程：{'、'.join('`' + f + '`' for f in oauth['forbidden_flows'])}")
    out.append(f"- PKCE：{oauth['pkce_required']}（`{oauth['pkce_method']}`）；"
               f"重定向 URI 匹配：`{oauth['redirect_uri_matching']}`；"
               f"state={oauth['state_required']}，nonce={oauth['nonce_required']}")
    out.append("")
    out.append(f"> {oauth['policy']}")
    out.append("")
    revocation = identity["revocation"]
    out.append("## 撤销")
    out.append("")
    out.append(f"机制 `{revocation['mechanism']}`，{revocation['propagation_seconds']} 秒内全局生效，"
               f"每次请求都检查：{revocation['check_on_every_request']}。")
    out.append("")
    out.append(f"> {revocation['policy']}")
    out.append("")
    out.append("## 发行方")
    out.append("")
    out.append("| 发行方 | 用途 | issuer | 受众 | 算法 | 密钥轮换(天) | 令牌上限(分) | 时钟容差(秒) |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for provider in identity["providers"]:
        budget.check(provider["id"])
        out.append(f"| `{provider['id']}` | {provider['purpose']} | `{provider['issuer']}` | "
                   f"{'、'.join('`' + a + '`' for a in provider['audiences'])} | "
                   f"{'、'.join(provider['algorithms'])} | {provider['jwks_rotation_days']} | "
                   f"{provider['max_token_minutes']} | {provider['clock_skew_seconds']} |")
    out.append("")
    for provider in identity["providers"]:
        out.append(f"- **`{provider['id']}`**：{provider['notes']}")
    out.append("")
    out.append("## 令牌")
    out.append("")
    out.append("| 令牌 | 类型 | 发行方 | 受众 | 有效期(分) | 绑定 | 可撤销 |")
    out.append("| --- | --- | --- | --- | --- | --- | --- |")
    for token in identity["tokens"]:
        out.append(f"| `{token['id']}` | {token['kind']} | `{token['provider']}` | "
                   f"`{token['audience']}` | {token['lifetime_minutes']} | "
                   f"`{token['binding']}` | {'是' if token['revocable'] else '否'} |")
    out.append("")
    out.append("## 主体与身份绑定")
    out.append("")
    out.append("| 零信任主体 | 发行方 | 令牌 |")
    out.append("| --- | --- | --- |")
    for entry in identity["principal_bindings"]:
        out.append(f"| `{entry['principal']}` | `{entry['provider']}` | `{entry['token']}` |")
    out.append("")
    out.append("## 账号恢复")
    out.append("")
    out.append("| 主体 | 方式 | 冷静期(小时) | 通知渠道 | 不得降级 | 允许仅短信 |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for entry in identity["recovery"]:
        out.append(f"| `{entry['subject']}` | {'、'.join(entry['methods'])} | "
                   f"{entry['delay_hours']} | {'、'.join(entry['notify_channels'])} | "
                   f"{'是' if entry['requires_same_or_stronger_factor'] else '否'} | "
                   f"{'是' if entry['sms_only_allowed'] else '否'} |")
    out.append("")
    for entry in identity["recovery"]:
        out.append(f"- **`{entry['subject']}`**：{entry['notes']}")
    out.append("")
    accounts = identity["service_accounts"]
    out.append("## 服务账号")
    out.append("")
    out.append(f"允许静态密钥：**{accounts['static_secrets_allowed']}**；"
               f"签发方式 `{accounts['issuance']}`。{accounts['policy']}")
    out.append("")
    out.append(f"共 {len(identity['providers'])} 个发行方、{len(identity['tokens'])} 种令牌、"
               f"{len(identity['recovery'])} 条恢复路径。")
    out.append("")
    return "\n".join(out)


TARGETS = {
    "contracts/security/identity.json": contract_json,
    "docs/security/IDENTITY.md": identity_markdown,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
