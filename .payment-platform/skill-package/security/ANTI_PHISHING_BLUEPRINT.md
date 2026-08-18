
# 反钓鱼与支付页面保护蓝图

## 官方域名策略

- 只使用一个清晰的 registrable domain 作为托管收银台主域，子域数量最小化。
- 支付链接不接受任意主机名；短链解析后仍展示完整官方域名。
- 对 Unicode/IDN 域名使用 UTS #39 confusable skeleton 和混合脚本检测，监控相似域名注册。
- 注册商启用硬件密钥、registry lock/transfer lock、最小 DNS 权限和双人变更。
- 部署 DNSSEC、CAA、证书透明度监控、HSTS preload；证书异常立即告警并执行应急域名隔离。

## 支付链接和二维码

- 会话绑定 tenant/project/merchant/business_order/amount/currency/allowed_methods/expiry/nonce/return_route_id。
- 使用 KMS 管理的 Ed25519 或等价签名，令牌短期、一次性，可服务端撤销。
- 二维码只包含官方 HTTPS URL 或渠道官方 code_url，不嵌入可编辑金额和外部跳转。
- 页面固定显示商户名称、订单摘要、金额、币种和官方域名提示；金额变化需重新创建会话。

## 浏览器与 E-skimming

- 严格 CSP nonce/hash、`frame-ancestors 'none'`、Trusted Types、SRI、COOP/CORP、Referrer-Policy、Permissions-Policy。
- 第三方脚本默认禁止；每个脚本有 owner、业务理由、版本、完整性、权限和到期复审。
- 对支付页脚本、DOM 和安全头做持续完整性检测；变更触发阻断或紧急审查。
- 不在支付页加载营销标签、聊天组件、热图、A/B 测试或任意远程脚本。

## 邮件与品牌

- SPF、DKIM、DMARC `p=reject`，逐步启用 MTA-STS/TLS-RPT；客户通知不直接要求输入密码或银行卡。
- 提供 `/.well-known/security.txt`、官方域名清单和举报入口。
- 监控仿冒广告、应用、社交账号、搜索结果、证书和域名；建立快速下架与客户通知流程。

## 管理员抗钓鱼

- 管理后台强制 WebAuthn/硬件密钥；SMS、邮件 OTP 和普通推送不得作为高权限唯一第二因素。
- 账户恢复与设备注册同样需要高保证认证、冷静期和双人审批，防止绕过主认证。
