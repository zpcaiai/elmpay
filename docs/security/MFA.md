<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/mfa.json
     Regenerate with: python3 scripts/render-mfa.py -->

# 抗钓鱼 MFA 与 WebAuthn（B18）

「抗钓鱼」不是一个形容词，而是一个可验证的性质：认证器的响应绑定到**它看到的 origin**。只要一个因素可以被中间人转发，它就不抗钓鱼，无论它有几位数字。

## 认证器

| 认证器 | 类别 | 抗钓鱼 | 绑定 origin | 可单独使用 |
| --- | --- | --- | --- | --- |
| `webauthn-roaming` | webauthn | ✅ | ✅ | ✅ |
| `webauthn-platform` | webauthn | ✅ | ✅ | ✅ |
| `totp` | otp | ❌ | ❌ | ❌ |
| `sms-otp` | otp | ❌ | ❌ | ❌ |
| `push-approval` | push | ❌ | ❌ | ❌ |

- **`webauthn-roaming`**：外置安全密钥（USB/NFC）。断言绑定 origin 与 RP ID，钓鱼站点即使拿到用户的一切也拿不到一个能用的断言——这就是「抗钓鱼」的全部含义。
- **`webauthn-platform`**：设备内置认证器（Touch ID / Windows Hello）。同样绑定 origin，但设备丢失即失去该认证器，所以不能是唯一一个。
- **`totp`**：时间口令。**不抗钓鱼**：中间人站点可以实时转发用户念出来的六位数。只能作为附加因素，不能单独用于高权限。
- **`sms-otp`**：短信口令。既不抗钓鱼，也扛不住 SIM 交换。在本平台**不允许**用于运营与紧急通道的任何环节，包括恢复。
- **`push-approval`**：推送批准。**不抗钓鱼**，且容易被推送疲劳攻破（连发直到用户点同意）。只能作为通知手段，不能作为因素。

## WebAuthn 参数

- RP ID：`pay.example.invalid`
- 允许的 origin：`https://pay.example.invalid`、`https://admin.pay.example.invalid`
- 用户验证：`required`；证明：`direct`；常驻密钥：`preferred`
- 挑战：32 字节，120 秒过期，一次性=True
- 签名计数器回退视为克隆：True
- 允许算法（COSE）：[-7, -257]

> 断言必须绑定 origin 与 RP ID，挑战一次性且 120 秒过期，签名计数器回退视为认证器被克隆。user_verification=required 让「密钥被偷」不等于「账号被盗」。

## Step-up

高风险必须 step-up：True；有效期 300 秒；绑定操作：True。

> 高风险操作必须重新验证，且断言要绑定**这一次操作**的摘要。不绑定操作的 step-up 只证明「刚才有人验证过」，证明不了「验证的是这一笔退款」。

## 回退与注册

- 允许降级回退：**False**。不存在「密钥不在手边就用短信」的回退。回退一旦允许降级，账号的真实安全级别就是那个最弱的回退。
- 特权账号最少注册 2 个认证器；注册前验证=True；注册通知=True

> 特权账号必须注册至少两个认证器，注册必须当场验证一次并通知本人。只注册一个的结果不是更安全，而是丢了以后被迫走弱路径。

- 限流：每小时最多 10 次，锁定 900 秒，防推送疲劳=True

## 角色要求

| 角色 | 要求等级 | 最少认证器 | 允许 | 禁止 | 需 step-up 的操作 |
| --- | --- | --- | --- | --- | --- |
| `platform-operator` | `phishing_resistant` | 2 | `webauthn-roaming`、`webauthn-platform` | `sms-otp`、`totp`、`push-approval` | `refund.approve`、`risk_rule.write`、`cross_tenant_data.read` |
| `break-glass` | `phishing_resistant` | 2 | `webauthn-roaming` | `webauthn-platform`、`sms-otp`、`totp`、`push-approval` | `cross_tenant_data.read` |
| `merchant-admin` | `phishing_resistant` | 2 | `webauthn-roaming`、`webauthn-platform` | `sms-otp`、`push-approval` | `api_key.rotate`、`payout_account.write` |
| `payer` | `any` | 1 | `webauthn-platform`、`webauthn-roaming`、`totp` | `push-approval` | — |
| `merchant-finance` | `phishing_resistant` | 2 | `webauthn-roaming`、`webauthn-platform` | `sms-otp`、`totp`、`push-approval` | `refund.approve`、`payout.approve`、`reconciliation.approve` |
| `risk-analyst` | `phishing_resistant` | 2 | `webauthn-roaming`、`webauthn-platform` | `sms-otp`、`totp`、`push-approval` | `risk_rule.write` |

- **`platform-operator`**：运营账号只接受抗钓鱼认证器，且必须注册至少两个——一个丢了不能变成「临时用短信」。
- **`break-glass`**：紧急通道只接受外置安全密钥：它必须能在设备被攻陷时仍然可信，而平台内置认证器与设备同生共死。
- **`merchant-admin`**：商户管理员能改收款账户，属于资金操作，同样要求抗钓鱼。TOTP 未被禁止，但只能作为**附加**因素。
- **`payer`**：付款人不强制 MFA：强制会把大量正常支付挡在门外，而付款人本身不持有平台权限。风险由风控与限额承担，不由 MFA 承担。
- **`merchant-finance`**：商户财务批准退款与出款，是资金真正离开平台的那一步，因此与商户管理员同级：只接受抗钓鱼认证器。
- **`risk-analyst`**：风控分析师能改写「谁会被拦下」的规则；这个账号被钓走，等于攻击者可以给自己开一条绿色通道。

共 5 种认证器（其中 2 种抗钓鱼）、6 条角色要求。
