# ADR-0007: 卡数据零接触：托管字段与 PSP 令牌

- 状态：accepted
- 日期：2026-08-18
- 批次：B02
- 决策者：payment-platform-security
- 关联需求：PAY-REQ-0016, PAY-REQ-0018, PAY-REQ-0026
- 关联控制：NN-02, CTRL-001
- 取代：无

## 背景

接触原始 PAN/CVV 会把整个平台拉入 PCI DSS 的完整评估范围，成本与风险都不可接受。

## 决策

卡支付一律使用 PSP 的托管字段（Stripe Elements / PaymentSheet）与令牌化；Apple Pay token 直接转交 PSP，平台不持有解密密钥。若某客户要求直接解密，必须建立独立的扩围部署与 HSM 方案，不复用默认环境。

## 后果

部分定制化收银体验受限；换来的是 CDE 范围最小化与更低的审计成本。

## 备选方案

（a）自建卡收单：拒绝，需要牌照与完整 PCI 评估；（b）服务端代理卡字段：拒绝，等同扩围。

## 验证

`test_b00_project_config.py` 强制 `card_data_mode=hosted_fields_only` 与 `direct_token_decryption=false`；B104 范围证据。
