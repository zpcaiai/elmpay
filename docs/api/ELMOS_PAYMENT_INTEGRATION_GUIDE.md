# ELMOS 支付对接与测试接口文档 (ELMPay Platform)

> **版本**：v1  
> **适用业务方**：ELMOS 业务系统  
> **对接模式**：托管收银台 (Hosted Checkout Session) + 签名业务 Webhook 回调  
> **支付渠道**：支付宝 (`alipay`)、微信支付 (`wechat`)  
> **结算币种**：人民币 (`CNY`)  

---

## 1. 对接架构与核心原则

1. **职责划分 (NN-01 原则)**：
   - **ELMOS**：负责管理商品、用户积分、采购/履约单状态及业务订单号（`business_order_no`）。
   - **ELMPay**：负责资金合规流转、渠道通信（支付宝/微信）、风控防刷、支付意图状态机与不可变财务对账。
   - **绑定机制**：双方仅通过 `(project_id, business_order_no)` 进行关联。ELMPay 不反查 ELMOS 内部库，也不存储非支付事实的商品与履约明细。
2. **核心交易流**：
   ```text
   [ 用户浏览器/App ]           [ ELMOS 服务端 ]               [ ELMPay 网关 ]          [ 支付宝 / 微信 ]
          |                              |                             |                      |
          |  1. 确认下单                  |                             |                      |
          |----------------------------->|                             |                      |
          |                              |  2. 创建收银台会话            |                      |
          |                              |  POST /v1/checkout-sessions |                      |
          |                              |---------------------------->|                      |
          |                              |  返回 checkout_url + intent |                      |
          |                              |<----------------------------|                      |
          |  3. 重定向到 checkout_url    |                             |                      |
          |<-----------------------------|                             |                      |
          |                                                            |                      |
          |  4. 用户在 ELMPay 托管页面唤起渠道支付                       |                      |
          |===========================================================>|                      |
          |                                                            |  5. 渠道交易扣款      |
          |                                                            |--------------------->|
          |                                                            |  渠道异步回调         |
          |                                                            |<---------------------|
          |                              |  6. 异步推送 Webhook 事件   |                      |
          |                              |  (payment_intent.captured)  |                      |
          |                              |<----------------------------|                      |
          |                              |                             |                      |
          |                              |  7. 验签 + 校验摘要并履约     |                      |
          |                              |  返回 200 OK                |                      |
          |                              |---------------------------->|                      |
   ```

---

## 2. 全局调用规范与请求头

### 2.1 网关地址 (Base URL)
- **本地沙箱 (Local Sandbox)**：`http://127.0.0.1:8080` (由 `apps/edge-gateway` 启动)
- **测试环境 (Staging)**：`https://pay-staging.example.com`
- **生产环境 (Production)**：`https://pay.example.com` (必须使用 TLS 1.3 + mTLS 客户端证书)

### 2.2 身份鉴权 (Authentication)
- **本地/沙箱测试**：携带 Bearer API Key：
  ```http
  Authorization: Bearer test_api_key_for_elmos
  ```
- **生产环境**：短期 OAuth2 访问令牌（`at+jwt`，RS256 签名，且包含 `cnf.x5t#S256` 客户端证书指纹绑定）。

### 2.3 必须携带的 HTTP 请求头 (Request Headers)
| 请求头 | 必填 | 适用接口 | 格式与说明 |
| :--- | :---: | :---: | :--- |
| `Authorization` | **是** | 所有 | `Bearer <token>` |
| `X-Project-Id` | **是** | 所有 | 项目 UUID（必须与 Token 内授权的 `project_id` 完全一致） |
| `Idempotency-Key` | **是** | 所有 `POST` 写接口 | 幂等键（建议 UUIDv4），保留 168 小时。**同一键不同请求体将直接返回 409 冲突** |
| `X-Request-Id` | **是** | 所有 | 链路请求 ID，正则 `^[A-Za-z0-9._:-]{8,128}$` |
| `traceparent` | **是** | 所有 | W3C Trace Context 规范，如 `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01` |
| `Content-Type` | **是** | 所有 `POST` 接口 | 必须为 `application/json; charset=utf-8` |
| `X-Device-Context-Digest` | 仅退款 | `POST /v1/refunds` | 设备与操作上下文的 64 位 SHA-256 小写哈希（防欺诈举证） |

### 2.4 金额规范 (零浮点原则)
- **单位**：必须为最小货币单位整数（Minor Units）。
  - 人民币 `CNY`：单位为**分**（例：99.00 元请传 `9900`）。
- **禁止**：严禁传递浮点数（如 `99.0` 或 `1.5`），否则网关会直接返回 `400 invalid_request`。
- **币种**：3 位大写字母，目前国内主用 `CNY`。

---

## 3. 核心接口列表

### 3.1 创建托管收银台会话 (Create Checkout Session)
当 ELMOS 用户提交订单并准备付款时，ELMOS 服务端调用此接口创建支付会话，换取收银台 URL。

- **请求方法**：`POST`
- **请求路径**：`/v1/checkout-sessions`
- **权限范围**：`payments.write`

#### 请求参数
```json
{
  "business_order_no": "ELMOS-20260918-99201",
  "amount": 9900,
  "currency": "CNY",
  "return_route_id": "checkout-complete",
  "payment_method": "alipay"
}
```
| 字段名 | 类型 | 必填 | 说明 |
| :--- | :--- | :---: | :--- |
| `business_order_no` | string | 是 | ELMOS 业务系统订单号，最长 160 字符，防重放主键之一 |
| `amount` | integer | 是 | 付款金额（单位：分，正整数） |
| `currency` | string | 是 | 币种代码，固定传 `"CNY"` |
| `return_route_id` | string | 是 | 支付完成后前端跳转白名单路由标识符（如 `"checkout-complete"`） |
| `payment_method` | string | 是 | 指定支付方式：`"alipay"`（支付宝）或 `"wechat"`（微信支付） |

#### 响应示例 (201 Created)
```json
{
  "checkout_session_id": "c7a6e14d-5872-4d22-bca0-4e365cb9d8e1",
  "payment_intent_id": "b3e2189a-0205-4c07-b391-722a45fb318d",
  "expires_at": "2026-09-18T10:30:00Z",
  "checkout_url": "https://pay.example.com/#session=c7a6e14d-5872-4d22-bca0-4e365cb9d8e1&token=M2RkM2...43chars",
  "status": "OPEN"
}
```
| 响应字段 | 类型 | 说明 |
| :--- | :--- | :--- |
| `checkout_session_id` | UUID | 收银台会话唯一 ID |
| `payment_intent_id` | UUID | 关联的权威底层支付意图 ID (ELMOS 可持久化留存) |
| `expires_at` | string (ISO-8601) | 会话超时失效时间（默认 30 分钟） |
| `checkout_url` | string | 托管收银台页面完整访问 URL（安全凭据置于 fragment 中，不入日志） |
| `status` | string | 会话状态：`OPEN` |

---

### 3.2 查询收银台会话状态 (Get Checkout Session)
- **请求方法**：`GET`
- **请求路径**：`/v1/checkout-sessions/{checkout_session_id}`
- **权限范围**：`payments.read`

#### 响应示例 (200 OK)
```json
{
  "checkout_session_id": "c7a6e14d-5872-4d22-bca0-4e365cb9d8e1",
  "payment_intent_id": "b3e2189a-0205-4c07-b391-722a45fb318d",
  "business_order_no": "ELMOS-20260918-99201",
  "amount": 9900,
  "currency": "CNY",
  "status": "SUCCEEDED",
  "payment_method": "alipay",
  "expires_at": "2026-09-18T10:30:00Z",
  "created_at": "2026-09-18T10:00:00Z"
}
```
*状态枚举*：`OPEN` (等待支付)、`SUCCEEDED` (已支付成功)、`FAILED` (支付失败)、`EXPIRED` (已过期)。

---

### 3.3 查询支付意图详情 (Get Payment Intent)
用于主动核实支付事实，查询权威账本状态。

- **请求方法**：`GET`
- **请求路径**：`/v1/payment_intents/{payment_intent_id}`
- **权限范围**：`payments.read`

#### 响应示例 (200 OK)
```json
{
  "id": "b3e2189a-0205-4c07-b391-722a45fb318d",
  "project_id": "a0000000-b000-c000-d000-e00000000202",
  "business_order_no": "ELMOS-20260918-99201",
  "amount": 9900,
  "amount_captured": 9900,
  "amount_refunded": 0,
  "status": "succeeded",
  "currency": "CNY",
  "state": "CAPTURED",
  "created_at": "2026-09-18T10:00:00Z",
  "updated_at": "2026-09-18T10:02:15Z",
  "version": 2
}
```
*`status` 状态字段*：
- `requires_payment_method`：刚创建，待确认方式
- `requires_action`：需用户侧进一步操作（如 3DS 验证或收银台重定向）
- `requires_capture`：已预授权，待捕获（如果开启了 manual capture）
- `succeeded`：已捕获成功，款项已确认
- `failed`：支付失败
- `canceled`：已撤回/取消

---

### 3.4 查询支付状态 (Get Payment Status - 只读投影)
适用于高频状态轮询，性能极高。

- **请求方法**：`GET`
- **请求路径**：`/v1/payment_intents/{payment_intent_id}/status`
- **权限范围**：`payments.read`

#### 响应示例 (200 OK)
```json
{
  "payment_intent_id": "b3e2189a-0205-4c07-b391-722a45fb318d",
  "project_id": "a0000000-b000-c000-d000-e00000000202",
  "status": "succeeded",
  "amount_minor": 9900,
  "currency": "CNY",
  "captured_amount_minor": 9900,
  "refunded_amount_minor": 0
}
```

---

### 3.5 申请退款 (Create Refund)
对已支付完成（`succeeded`）的订单发起原路退款。

- **请求方法**：`POST`
- **请求路径**：`/v1/refunds`
- **权限范围**：`payments.write`
- **特别注意**：必须携带请求头 `X-Device-Context-Digest: <64位小写十六进制 sha256>`。

#### 请求参数
```json
{
  "payment_intent_id": "b3e2189a-0205-4c07-b391-722a45fb318d",
  "amount": 9900,
  "reason": "REQUESTED_BY_CUSTOMER"
}
```
| 字段名 | 类型 | 必填 | 说明 |
| :--- | :--- | :---: | :--- |
| `payment_intent_id` | UUID | 是 | 原支付意图 ID |
| `amount` | integer | 是 | 退款金额（分），支持部分退款（不可超过可退余额） |
| `reason` | string | 是 | 退款原因：`REQUESTED_BY_CUSTOMER`, `DUPLICATE`, `FRAUDULENT` |

#### 响应示例 (201 Created)
```json
{
  "id": "7fa8e23b-6f81-4201-92be-6296b42b1577",
  "project_id": "a0000000-b000-c000-d000-e00000000202",
  "payment_intent_id": "b3e2189a-0205-4c07-b391-722a45fb318d",
  "amount": 9900,
  "currency": "CNY",
  "status": "succeeded",
  "reason": "requested_by_customer",
  "risk_decision": "approved",
  "provider_refund_id": "ali_refund_99812739",
  "created_at": "2026-09-18T11:00:00Z",
  "version": 1
}
```

---

### 3.6 取消支付意图 (Cancel Payment Intent)
在用户尚未支付前主动关单。

- **请求方法**：`POST`
- **请求路径**：`/v1/payment_intents/{payment_intent_id}/cancel`
- **权限范围**：`payments.write`

#### 请求参数
```json
{
  "reason": "order_expired_by_customer"
}
```

---

## 4. 业务 Webhook 回调规范 (ELMOS 接收端)

支付成功后，ELMPay 的 `webhook-delivery` 服务会向 ELMOS 配置的通知 URL 投递签名事件。

### 4.1 回调请求头 (Webhook Headers)
ELMPay 发送到 ELMOS 接收端时携带如下 Header：
```http
POST /api/v1/payments/elmpay-webhook HTTP/1.1
Host: elmos.internal:8000
Content-Type: application/json; charset=utf-8
X-Elmpay-Event-Id: a0000000-b000-c000-d000-e00000000303
X-Elmpay-Event-Type: payment_intent.captured
X-Elmpay-Timestamp: 1789722135
X-Elmpay-Key-Id: key-sec-2026-01
X-Elmpay-Signature: t=1789722135,v1=NgtUFKuSvOfNdb2InZjDTBS3axZlxKNnw1QLrb3elDw
```

### 4.2 签名计算与验证算法 (HMAC-SHA256)
1. **获取原始 Payload 字节流**：必须取 HTTP Request Body 的未经反序列化和二次转义的**原始 UTF-8 字节流** `raw_body_bytes`。
2. **提取时间戳**：从 `X-Elmpay-Signature` 中解析出 `t` 与 `v1`（或读取 `X-Elmpay-Timestamp`）。
3. **构造签名基串**：
   ```text
   string_to_sign = f"{t}.{raw_body_bytes.decode('utf-8')}"
   ```
4. **计算 HMAC-SHA256**：
   使用分配给 ELMOS 项目的 Webhook 密钥（Secret）进行哈希：
   ```python
   expected_sig = base64.urlsafe_b64encode(
       hmac.new(secret_bytes, f"{t}.".encode() + raw_body_bytes, hashlib.sha256).digest()
   ).rstrip(b"=").decode("ascii")
   ```
5. **安全比对**：使用常量时间比较函数（如 `hmac.compare_digest`），并校验时间戳容差（通常不超过 300 秒）。

### 4.3 核心事件：`payment_intent.captured` (v1)
ELMOS 仅需处理 `payment_intent.captured` 版本 1，其余通知类型直接返回 200 确认即可。

#### 回调 Payload 示例：
```json
{
  "payment_intent_id": "b3e2189a-0205-4c07-b391-722a45fb318d",
  "project_id": "a0000000-b000-c000-d000-e00000000202",
  "provider": "alipay",
  "captured_at": "2026-09-18T10:02:15Z",
  "amount_minor": 9900,
  "currency": "CNY",
  "business_order_digest": "4a5a1e2f3d9b0a1c6e8f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d"
}
```

#### ELMOS 履约重要安全规则 (必须执行)：
1. **订单号摘要匹配**：ELMPay 不向外透传明文业务订单号，而是透传其摘要：
   $$\text{business\_order\_digest} = \text{SHA256}(\text{business\_order\_no})$$
   ELMOS 收到回调后，必须计算本地订单号的 SHA-256（64 位小写十六进制），比对是否与 `business_order_digest` 一致！
2. **金额与币种核对**：检查 `amount_minor` 是否等于业务订单应收金额，`currency` 是否为 `"CNY"`。
3. **消费幂等性**：以 `payment_intent_id` 或 `X-Elmpay-Event-Id` 作为唯一幂等键，如果订单已处于履约中/已支付，直接返回 HTTP 200，避免重复发货或赠送权益。
4. **应答确认**：ELMOS 处理完成后，必须在 5 秒内返回 HTTP `200 OK` 或 `204 No Content`。

---

## 5. 错误响应模型 (RFC 7807)

所有错误响应均返回 `application/json; charset=utf-8` 或 `application/problem+json`，格式统一：

```json
{
  "code": "idempotency_key_reuse",
  "message": "同一幂等键曾用于不同的请求体。",
  "request_id": "request-checkout-0001"
}
```

### 错误码对照表与处理建议
| 错误码 (`code`) | HTTP 状态 | 可重试 | 原因及排查建议 |
| :--- | :---: | :---: | :--- |
| `invalid_request` | 400 | 否 | 参数格式错误，例如金额传了小数、缺少必填字段、请求头不合规。请核对文档修正请求。 |
| `unauthenticated` | 401 | 否 | Authorization 头缺失、Bearer 令牌无效或已过期。请重新获取或检查密钥配置。 |
| `permission_denied` | 403 | 否 | 凭据无权操作对应 Project，或缺少 `payments.write`/`payments.read` scope。 |
| `tenant_mismatch` | 403 | 否 | 操作的对象属于其他租户/项目，禁止跨租户访问。 |
| `resource_not_found` | 404 | 否 | 会话 ID 或支付意图 ID 不存在（本系统不区分资源不存在与无权限）。 |
| `idempotency_key_reuse`| 409 | 否 | 同一个 `Idempotency-Key` 之前用过了，但本次请求体与之前不一致。更换新 UUID 重试。 |
| `state_transition_not_allowed` | 409 | 否 | 状态冲突。如：对已支付的订单再次发起支付，或对已取消订单发起退款。请先 GET 查询最新状态。 |
| `rate_limited` | 429 | 是 | 触发限流保护。需解析 `Retry-After` 头，指数退避后重试。 |
| `amount_below_minimum` | 422 | 否 | 交易金额低于该币种的最小交易限制（通常为 1 分钱）。 |
| `currency_not_supported`| 422 | 否 | 不支持的币种（请使用 `"CNY"`）。 |
| `provider_unavailable` | 502 | 是 | 上游支付宝/微信支付网关暂时不可用。按指数退避重试，**不要更换幂等键**。 |
| `provider_timeout` | 504 | 是 | 上游渠道响应超时，结果未决。**绝对不能当作失败**，请用原幂等键重试或轮询查询状态。 |
| `internal_error` | 500 | 是 | ELMPay 内部服务瞬时错误。按指数退避重试，持续发生请联系支付平台值班人员。 |

---

## 6. 测试与快速联调指南

### 6.1 本地沙箱环境准备
在 `elmpay` 仓库根目录下启动沙箱网关：
```bash
# 启动本地开发沙箱模式
export ELMPAY_RUNTIME_MODE=local
export ELMPAY_ENABLE_LOCAL_SANDBOX=true
./gradlew :apps:edge-gateway:run
```
默认网关监听在 `http://127.0.0.1:8080`。

### 6.2 测试固定常量
- **Project ID**：`a0000000-b000-c000-d000-e00000000202`
- **Tenant ID**：`a0000000-b000-c000-d000-e00000000101`
- **API Key (沙箱)**：`test_sandbox_secret_key_001`
- **Webhook 验签 Secret**：`BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc` (base64url)

---

### 6.3 cURL 完整测试联调流程

#### Step 1: 创建收银台会话
```bash
curl -i -X POST http://127.0.0.1:8080/v1/checkout-sessions \
  -H "Authorization: Bearer test_sandbox_secret_key_001" \
  -H "X-Project-Id: a0000000-b000-c000-d000-e00000000202" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "X-Request-Id: req-test-0001" \
  -H "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" \
  -H "Content-Type: application/json" \
  -d '{
    "business_order_no": "ORDER-2026-TEST-01",
    "amount": 1250,
    "currency": "CNY",
    "return_route_id": "checkout-complete",
    "payment_method": "alipay"
  }'
```

#### Step 2: 模拟沙箱支付成功 (针对返回的 Session)
```bash
# 提取返回的 checkout_session_id 进行状态检查
curl -i -X GET http://127.0.0.1:8080/v1/checkout-sessions/<SESSION_ID> \
  -H "Authorization: Bearer test_sandbox_secret_key_001" \
  -H "X-Project-Id: a0000000-b000-c000-d000-e00000000202" \
  -H "X-Request-Id: req-test-0002" \
  -H "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
```

#### Step 3: 查询支付意图详情与状态
```bash
curl -i -X GET http://127.0.0.1:8080/v1/payment_intents/<PAYMENT_INTENT_ID> \
  -H "Authorization: Bearer test_sandbox_secret_key_001" \
  -H "X-Project-Id: a0000000-b000-c000-d000-e00000000202" \
  -H "X-Request-Id: req-test-0003" \
  -H "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
```

#### Step 4: 模拟发起退款
```bash
curl -i -X POST http://127.0.0.1:8080/v1/refunds \
  -H "Authorization: Bearer test_sandbox_secret_key_001" \
  -H "X-Project-Id: a0000000-b000-c000-d000-e00000000202" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "X-Request-Id: req-test-0004" \
  -H "X-Device-Context-Digest: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -H "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" \
  -H "Content-Type: application/json" \
  -d '{
    "payment_intent_id": "<PAYMENT_INTENT_ID>",
    "amount": 1250,
    "reason": "REQUESTED_BY_CUSTOMER"
  }'
```

---

## 7. ELMOS 端 Webhook 验签与履约示例代码 (Python)

以下是 ELMOS 接收并验证 ELMPay Webhook 的生产级参考实现：

```python
import base64
import hashlib
import hmac
import json
import math
import re
import time
from typing import Mapping

def verify_elmpay_webhook(
    secret: bytes,
    raw_body: bytes,
    signature_header: str,
    tolerance: int = 300
) -> bool:
    """
    验证 ELMPay 推送的 Webhook 签名
    :param secret: ELMPay 分配的 Webhook 密钥 (bytes)
    :param raw_body: HTTP 请求的原始未解析 bytes
    :param signature_header: X-Elmpay-Signature 头值 (形如 t=1787702400,v1=NgtUFK...)
    :param tolerance: 时间戳最大容忍秒数 (默认 300 秒)
    """
    if not isinstance(secret, bytes) or len(secret) < 32:
        return False
    if not isinstance(raw_body, bytes) or not isinstance(signature_header, str):
        return False

    # 解析 Header 键值对，禁止重复键覆盖
    parts = {}
    for item in signature_header.split(","):
        key, sep, val = item.strip().partition("=")
        if not sep or key not in {"t", "v1"} or key in parts:
            return False
        parts[key] = val

    if set(parts.keys()) != {"t", "v1"}:
        return False

    try:
        timestamp = int(parts["t"])
        if timestamp < 0:
            return False
        # 解析 Base64URL 签名 (兼容无 padding)
        encoded_sig = parts["v1"]
        padding = "=" * ((4 - len(encoded_sig) % 4) % 4)
        supplied_sig = base64.b64decode(encoded_sig + padding, altchars=b"-_", validate=True)
    except Exception:
        return False

    # 校验时间戳防重放
    if abs(time.time() - timestamp) > tolerance:
        return False

    # 严格按照 <timestamp>.<raw_body> 计算预期 HMAC-SHA256
    string_to_sign = str(timestamp).encode("ascii") + b"." + raw_body
    expected_sig = hmac.new(secret, string_to_sign, hashlib.sha256).digest()

    return hmac.compare_digest(expected_sig, supplied_sig)


def handle_elmpay_captured_event(event_payload: dict, expected_order_no: str, expected_amount_minor: int) -> bool:
    """
    处理 payment_intent.captured 事件并进行业务订单核对
    """
    # 1. 验证订单号摘要 SHA-256
    expected_digest = hashlib.sha256(expected_order_no.encode("utf-8")).hexdigest()
    if event_payload.get("business_order_digest") != expected_digest:
        # 订单号不匹配，拒绝履约
        return False

    # 2. 验证金额与币种
    if event_payload.get("amount_minor") != expected_amount_minor or event_payload.get("currency") != "CNY":
        return False

    # 3. 业务幂等更新为“已支付”并开启后续业务履约
    payment_intent_id = event_payload.get("payment_intent_id")
    # ... 在 elmos 数据库中执行: UPDATE orders SET status='PAID', payment_id=... WHERE ...
    return True
```
---

## 8. ELMOS 端 Webhook 验签与履约示例代码 (Java)

以下是 ELMOS 接收并验证 ELMPay Webhook 的生产级参考实现：

```java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class ElmpayWebhookHandler {
    private static final int TIMESTAMP_TOLERANCE = 300; // 时间戳最大容忍秒数 (默认 300 秒)