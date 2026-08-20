"""B18 — generate the MFA matrix and review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

MFA = Path("governance/mfa.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/mfa.json\n"
             "     Regenerate with: python3 scripts/render-mfa.py -->\n")


def matrix_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    mfa = load_json(root / MFA)
    for entry in mfa["authenticators"]:
        budget.check(entry["id"])
    document = {
        "_generated": "GENERATED FILE — scripts/render-mfa.py; do not edit by hand",
        "schema_version": mfa["schema_version"],
        "phishing_resistant_classes": sorted(mfa["phishing_resistant_classes"]),
        "webauthn": mfa["webauthn"],
        "step_up": mfa["step_up"],
        "fallback": mfa["fallback"],
        "authenticators": [{"id": a["id"], "kind": a["kind"],
                            "phishing_resistant": a["phishing_resistant"],
                            "origin_bound": a["origin_bound"],
                            "allowed_as_sole_factor": a["allowed_as_sole_factor"]}
                           for a in sorted(mfa["authenticators"], key=lambda x: x["id"])],
        "requirements": [{"role": r["role"], "required_class": r["required_class"],
                          "minimum_registered_authenticators":
                              r["minimum_registered_authenticators"],
                          "allowed_authenticators": sorted(r["allowed_authenticators"]),
                          "forbidden_authenticators": sorted(r["forbidden_authenticators"]),
                          "step_up_actions": sorted(r["step_up_actions"])}
                         for r in sorted(mfa["requirements"], key=lambda x: x["role"])],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def mfa_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    mfa = load_json(root / MFA)
    out = [MD_BANNER, "# 抗钓鱼 MFA 与 WebAuthn（B18）", ""]
    out.append(mfa["principle"])
    out.append("")
    out.append("## 认证器")
    out.append("")
    out.append("| 认证器 | 类别 | 抗钓鱼 | 绑定 origin | 可单独使用 |")
    out.append("| --- | --- | --- | --- | --- |")
    for entry in mfa["authenticators"]:
        budget.check(entry["id"])
        out.append(f"| `{entry['id']}` | {entry['kind']} | "
                   f"{'✅' if entry['phishing_resistant'] else '❌'} | "
                   f"{'✅' if entry['origin_bound'] else '❌'} | "
                   f"{'✅' if entry['allowed_as_sole_factor'] else '❌'} |")
    out.append("")
    for entry in mfa["authenticators"]:
        out.append(f"- **`{entry['id']}`**：{entry['notes']}")
    out.append("")
    web = mfa["webauthn"]
    out.append("## WebAuthn 参数")
    out.append("")
    out.append(f"- RP ID：`{web['relying_party_id']}`")
    out.append(f"- 允许的 origin：{'、'.join('`' + o + '`' for o in web['allowed_origins'])}")
    out.append(f"- 用户验证：`{web['user_verification']}`；证明：`{web['attestation']}`；"
               f"常驻密钥：`{web['resident_key']}`")
    out.append(f"- 挑战：{web['challenge_bytes']} 字节，{web['challenge_ttl_seconds']} 秒过期，"
               f"一次性={web['challenge_single_use']}")
    out.append(f"- 签名计数器回退视为克隆：{web['sign_count_regression_is_clone']}")
    out.append(f"- 允许算法（COSE）：{web['allowed_algorithms']}")
    out.append("")
    out.append(f"> {web['policy']}")
    out.append("")
    step_up = mfa["step_up"]
    out.append("## Step-up")
    out.append("")
    out.append(f"高风险必须 step-up：{step_up['required_for_high_risk']}；"
               f"有效期 {step_up['max_age_seconds']} 秒；"
               f"绑定操作：{step_up['transaction_binding']}。")
    out.append("")
    out.append(f"> {step_up['policy']}")
    out.append("")
    out.append("## 回退与注册")
    out.append("")
    out.append(f"- 允许降级回退：**{mfa['fallback']['downgrade_allowed']}**。"
               f"{mfa['fallback']['policy']}")
    enrolment = mfa["enrolment"]
    out.append(f"- 特权账号最少注册 {enrolment['minimum_authenticators_for_privileged']} 个认证器；"
               f"注册前验证={enrolment['verified_before_activation']}；"
               f"注册通知={enrolment['notify_on_registration']}")
    out.append("")
    out.append(f"> {enrolment['policy']}")
    out.append("")
    limits = mfa["rate_limiting"]
    out.append(f"- 限流：每小时最多 {limits['max_attempts_per_hour']} 次，"
               f"锁定 {limits['lockout_seconds']} 秒，"
               f"防推送疲劳={limits['push_fatigue_protection']}")
    out.append("")
    out.append("## 角色要求")
    out.append("")
    out.append("| 角色 | 要求等级 | 最少认证器 | 允许 | 禁止 | 需 step-up 的操作 |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for entry in mfa["requirements"]:
        out.append(f"| `{entry['role']}` | `{entry['required_class']}` | "
                   f"{entry['minimum_registered_authenticators']} | "
                   f"{'、'.join('`' + a + '`' for a in entry['allowed_authenticators'])} | "
                   f"{'、'.join('`' + a + '`' for a in entry['forbidden_authenticators']) or '—'} | "
                   f"{'、'.join('`' + a + '`' for a in entry['step_up_actions']) or '—'} |")
    out.append("")
    for entry in mfa["requirements"]:
        out.append(f"- **`{entry['role']}`**：{entry['notes']}")
    out.append("")
    resistant = sum(1 for a in mfa["authenticators"] if a["phishing_resistant"])
    out.append(f"共 {len(mfa['authenticators'])} 种认证器（其中 {resistant} 种抗钓鱼）、"
               f"{len(mfa['requirements'])} 条角色要求。")
    out.append("")
    return "\n".join(out)


TARGETS = {
    "contracts/security/mfa-matrix.json": matrix_json,
    "docs/security/MFA.md": mfa_markdown,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
