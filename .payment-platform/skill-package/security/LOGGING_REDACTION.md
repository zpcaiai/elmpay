
# 日志与追踪脱敏

默认拒绝记录：API 密钥、Authorization、Cookie、Set-Cookie、私钥、证书私钥、PAN、CVV、磁道、完整 Apple Pay/钱包 token、身份证件、完整银行账户、密码、恢复码。

允许记录的支付信息应限于：内部 payment_id、脱敏 provider id、渠道、状态、错误分类、金额最小单位、币种、租户/项目 ID、trace/correlation id。用户标识使用不可逆或受控 token；IP 与设备数据按风险用途和保留计划处理。

日志库必须提供字段级 allowlist，而不是依赖事后正则清洗。对异常对象、HTTP client debug、数据库绑定参数和消息体做专项测试。
