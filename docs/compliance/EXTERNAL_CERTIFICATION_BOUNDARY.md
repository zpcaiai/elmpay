# 外部认证边界：仓库能证明什么，不能证明什么

> 生成方式：`python3 scripts/external-boundary.py`（映射表在该脚本里，逐条标注了批次标题）。
> 权威判定来自 `platform/compliance/external-evidence-policy.json`，不是本文。

## 1. 为什么需要这份文件

这套程序里有两种「没做完」，必须分开：

- **缺工作**：还没人写。这是排期问题。
- **缺外部签署**：仓库里的活已经干完，但它需要的证明是一份**别人**在仓库之外签的文件。
  这不是排期问题，是边界。

把两者混在一起，最后一定会用「我们本地全绿了」去替代「渠道正式认证通过了」，
而那正是这套证据体系存在的理由。

## 2. 策略本身拒绝本地认证

```
platform/compliance/external-evidence-policy.json
  localValidationMayCertify : false
  independentEvidenceRequired : true
  minimumDistinctVerifiers : 2
  requiredCategories : 12
```

**实测**（`scripts/external-boundary.py`，空证据包 + 真实策略）：

```
release allowed with no external evidence: False
categories unmet = 12 of 12
batches held     = 24（另加：independent_human_review 拦住全部 128 个批次）
```

`tools/runtime/control.py external-evidence` 在同样输入下给出 22 条拒绝理由，
其中 12 条是 `missing_external_evidence:<category>`，5 条是
`provider_certification_missing:<provider>`（微信、支付宝、Stripe、PayPal、Apple Pay）。
**这些门禁能被跑通才说明系统坏了。**

## 3. 十二类外部产物，各自拦住谁

| 类别 | 必须来自 | 有效期 | 拦住的批次 |
| --- | --- | ---: | --- |
| `provider_certification` | `PROVIDER_OFFICIAL` | 720h | B40 B44 B48 B51 B54 B55 B113 B122 |
| `production_kubernetes` | `PRODUCTION_ATTESTATION` | 24h | B93 B123 |
| `dr_exercise` | `PRODUCTION_DR_EXERCISE` | 2160h | B94 B95 |
| `pci_assessor` | `PCI_ASSESSOR` | 2160h | B104 |
| `regional_market_approval` | `REGIONAL_MARKET_AUTHORITY` | 2160h | B105 |
| `legal_compliance` | `EXTERNAL_LEGAL_COUNSEL` | 2160h | B106 B107 B111 |
| `penetration_test` | `INDEPENDENT_PEN_TESTER` | 2160h | B110 B116 |
| `uat_acceptance` | `UAT_SIGNOFF` | 720h | B118 B119 |
| `shadow_rollout` | `PRODUCTION_ROLLOUT_OBSERVER` | 24h | B121 |
| `canary_rollout` | `PRODUCTION_ROLLOUT_OBSERVER` | 24h | B124 |
| `merchant_acceptance` | `MERCHANT_SIGNOFF` | 720h | B122 B123 B127 |
| `independent_human_review` | `INDEPENDENT_REVIEWER` | 24h | **全部 128 个批次** |

`provider_certification` 还额外要求逐渠道逐支付方式到位
（`requiredProviderCapabilities`：wechat/wechat_pay、alipay/alipay、stripe/card+apple_pay、
apple_pay/apple_pay、paypal/paypal_wallet），少一个就少一个。

## 4. 有效期是硬约束，不是提醒

`production_kubernetes`、`shadow_rollout`、`canary_rollout`、`independent_human_review`
的有效期都是 **24 小时**。含义是：这四类证据**不能提前攒**。
它们必须在发布窗口当天产生，过期即失效，重来一遍。
`maximumApprovalAgeHours: 24` 与 `revalidateSignedGateInputsBeforeRollout: true` 是同一件事的两面。

## 5. 这份边界的正确用法

- 排期表里，这 24 个批次**不计入工程工时**，计入「等外部方」的前置周期；
- 任何「先让它过、上线后补」的提案，等价于把 `localValidationMayCertify` 改成 `true`，
  应当被当作变更红线的提案来处理，而不是当作工程权宜；
- 缺失清单随策略变化，**以脚本输出为准**：本文可能过期，`external-boundary.py` 不会。
