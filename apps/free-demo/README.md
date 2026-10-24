# ElmPay 免费演示

此部署只供演示：真实支付已禁用，不接入真实 PSP，不接收卡号或商户凭据。使用现有 Java local sandbox、内存状态和原收银台控制器。所有结果均从服务器读取；未知结果保持待确认。休眠、重启或重新部署会清空订单。

页面默认提供 **微信支付（模拟）· ￥10.00**，也可选择原银行卡/USD10 演示。微信模拟创建的实际原生订单/签名会话使用 `wechat_native`、`CNY`、1000 分，不是把银行卡订单改名。它仍由原通用 local sandbox 模拟器执行：内部 provider 标识沿用 `stripe`，不代表调用 Stripe 或微信；没有真实微信二维码、微信客户端跳转、JSAPI/官方沙箱协议或商户认证。此演示不能证明真实微信支付接入或渠道认证。

| 场景 | 实际演示结果 |
| --- | --- |
| 模拟成功 | SUCCEEDED，服务器确认模拟完成 |
| 模拟拒绝 | FAILED，服务器观察到 local_declined |
| 模拟未知结果 | PENDING，服务器观察到 local_unknown，不能视为成功 |
| 模拟仅授权 | PENDING，实际本地适配器返回 AUTHORIZED，尚未完成支付 |
| 模拟需要进一步操作 | PENDING，实际本地适配器返回 REQUIRES_ACTION / local_challenge |

最后一种仅展示原生沙箱返回的待操作状态，不接入真实认证页面或模拟绕过认证。页面的场景说明不是结果证据。

界面提供订单摘要、三步进度、明确的结果与错误说明、待确认状态重新查询，以及桌面和手机布局。创建请求的幂等键绑定所选场景和模拟方式：同场景同方式失败重试保持同键，切换场景或方式创建新键。状态轮询保留已选支付方式与焦点；页面不会使用用户所选场景推定支付成功。

Render 使用一个 `Free` Docker Web Service、一个实例，仓库根 Dockerfile。无需数据库、磁盘、Worker 或付费附加项。必须设置：

```text
ELMPAY_DEMO_ENABLED=true
ELMPAY_DEMO_REAL_PAYMENTS_DISABLED=true
ELMPAY_DEMO_PUBLIC_ORIGIN=https://elmpay.vercel.app
```

健康检查为 `/health/ready`。公开 Node 监听 Render PORT；实际 Java 网关只监听内部回环。服务内部管理令牌每次启动随机生成；浏览器只持有短期收银台令牌。适配层只允许固定两套参数：`card`/USD1000 分、`wechat_native`/CNY1000 分和合成支付引用；客户端不能指定金额或币种。原 `/demo/orders` 的 `{scenario}` 请求默认银行卡，微信模拟需附加 `payment_method: "wechat_native"`。其他渠道方法（包括真实微信 JSAPI）、生产 ELMPAY 配置及通用管理接口均被拒绝。原生产启动、安全、证书和部署规则保持原样。

将 `vercel/vercel.json` 放入独立部署目录，并只链接既有 `elmpay` 项目。该配置把同源页面、静态资源和接口转发到已核实的 Render 演示地址，保留 CSP、no-store 和会话授权。不要把仓库、`.env`、CLI 令牌或原生产证书复制进 Vercel 部署目录。

验证命令（将真实创建少量临时模拟订单）：

```sh
node --test apps/free-demo/test/*.test.mjs apps/checkout-web/test/*.test.mjs
python3 apps/free-demo/test/deployed_e2e.py https://elmpay.onrender.com
python3 apps/free-demo/test/deployed_e2e.py https://elmpay.vercel.app
```

API 检查覆盖两套参数各五种服务器结果、实际原生方法/币种/金额、跨方式幂等冲突、会话方式错配、创建重放、重复确认、令牌篡改、跨站请求、金额/币种/查询注入、不支持的真实场景、缺失幂等键、错误内容类型和真实支付引用拦截。现有 HostedCheckoutService 只允许 OPEN 会话确认；成功、授权或需进一步操作后重复请求返回 HTTP 400。拒绝和未知尝试保留核心 OPEN 订单及幂等重放；演示适配层只根据实际网关返回的 local_declined / local_unknown 投影 FAILED / PENDING，保留 gateway_status 和 demo_provider_result，并在后续授权查询中保持显示。用户选择的模拟场景本身不能作为结果证据。浏览器验收另外执行实际点击创建、选择演示方式、确认和状态显示，检查 URL 片段被清除，并检查手机布局、焦点/键盘、错误恢复及重新查询。日志禁止输出短期 bearer 或完整收银台 URL。

Render 免费服务会休眠，首次访问可能等待约一分钟；工作区免费时长、流量及构建额度是共享的。额度不足时保持停止构建或暂停服务，不添加银行卡、不升级。付费服务、持久数据、生产证书、渠道接入和真实资金验收不属于此演示。

验收脚本遇到纯传输错误时最多尝试三次，重用完全相同的请求、请求体和幂等键；HTTP 错误不会被重试，证书和重定向限制不变，最终结果仍需真实响应及全部断言通过。日志保留传输重试和原始失败，不将其算作成功检查。

浏览器请求有 15 秒期限，超时显示未验证/可重试，不能视为成功；创建重试继续使用同场景同方式的幂等键。浏览器 API 有意只提供格式化金额，验收精确检查人民币/美元格式；原始 1000 分及币种通过受限制的创建协议和服务端参数检查。

回滚需先核对远端当前版本，避免覆盖他人变更。Render 可重新部署已验证的演示提交；Vercel 可恢复本任务前的部署。不要退回到未验证状态并称其验收通过。
