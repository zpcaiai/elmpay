# ElmPay 免费演示

此部署只供演示：真实支付已禁用，不接入真实 PSP，不接收卡号或商户凭据。使用现有 Java local sandbox、内存状态和原收银台控制器。成功、拒绝、未知结果均从服务器读取；未知结果保持待确认。休眠、重启或重新部署会清空订单。

Render 使用一个 `Free` Docker Web Service、一个实例，仓库根 Dockerfile。无需数据库、磁盘、Worker 或付费附加项。必须设置：

```text
ELMPAY_DEMO_ENABLED=true
ELMPAY_DEMO_REAL_PAYMENTS_DISABLED=true
ELMPAY_DEMO_PUBLIC_ORIGIN=https://elmpay.vercel.app
```

健康检查为 `/health/ready`。公开 Node 监听 Render PORT；实际 Java 网关只监听内部回环。服务内部管理令牌每次启动随机生成；浏览器只持有短期收银台令牌。适配层只允许固定 USD 10.00 演示订单和合成支付引用，拒绝生产 ELMPAY 配置及通用管理接口。原生产启动、安全、证书和部署规则保持原样。

将 `vercel/vercel.json` 放入独立部署目录，并只链接既有 `elmpay` 项目。该配置把同源页面、静态资源和接口转发到已核实的 Render 演示地址，保留 CSP、no-store 和会话授权。不要把仓库、`.env`、CLI 令牌或原生产证书复制进 Vercel 部署目录。

验证命令（将真实创建少量临时模拟订单）：

```sh
node --test apps/free-demo/test/*.test.mjs apps/checkout-web/test/*.test.mjs
python3 apps/free-demo/test/deployed_e2e.py https://elmpay.onrender.com
python3 apps/free-demo/test/deployed_e2e.py https://elmpay.vercel.app
```

API 检查覆盖三种服务器结果、创建重放、重复确认、令牌篡改、跨站请求、金额注入、真实支付引用拦截。现有 HostedCheckoutService 只允许 OPEN 会话确认；成功后重复请求返回 HTTP 400。拒绝和未知尝试保留核心 OPEN 订单及幂等重放；演示适配层只根据实际网关返回的 local_declined / local_unknown 投影 FAILED / PENDING，保留 gateway_status 和 demo_provider_result，并在后续授权查询中保持显示。用户选择的模拟场景本身不能作为结果证据。浏览器验收另外执行实际点击创建、选择演示方式、确认和状态显示，检查 URL 片段被清除。日志禁止输出短期 bearer 或完整收银台 URL。

Render 免费服务会休眠，首次访问可能等待约一分钟；工作区免费时长、流量及构建额度是共享的。额度不足时保持停止构建或暂停服务，不添加银行卡、不升级。付费服务、持久数据、生产证书、渠道接入和真实资金验收不属于此演示。

回滚需先核对远端当前版本，避免覆盖他人变更。Render 可重新部署已验证的演示提交；Vercel 可恢复本任务前的部署。不要退回到未验证状态并称其验收通过。
