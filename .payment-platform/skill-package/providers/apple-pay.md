
# Apple Pay 实施指南

默认架构通过 Stripe 或其他合格 PSP 处理 Apple Pay token，以缩小 PCI 范围。支持 iOS PassKit 和 Web Apple Pay/Payment Request API。

- Apple Merchant ID、域名注册、验证文件和支付处理证书由受控配置管理。
- 新旧证书必须重叠，切换前后执行沙箱和真实设备测试；到期告警至少覆盖 30/15/7 天。
- 周期或延迟支付使用 merchant token/MPAN 能力，并记录用户授权、撤销和 PSP 令牌状态。
- 直接解密 Apple Pay token 不是默认功能；需要独立 CDE、HSM、密钥仪式、PCI 评估和架构批准。
