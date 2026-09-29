"""
ELMOS Payment Integration & Docking Test Suite (ELMPay Platform)
Conforming to ELMOS_PAYMENT_INTEGRATION_GUIDE.md v1
"""

import base64
import hashlib
import hmac
import json
import os
import time
import unittest
import urllib.error
import urllib.request
import uuid

BASE_URL = "http://127.0.0.1:8080"
HEALTH_URL = "http://127.0.0.1:8090"
API_KEY = os.environ.get("ELMPAY_TEST_API_KEY", "test_sandbox_secret_key_001")  # paygov:allow-secret-pattern
PROJECT_ID = "a0000000-b000-c000-d000-e00000000202"
TENANT_ID = "a0000000-b000-c000-d000-e00000000101"
WEBHOOK_SECRET_B64URL = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"


def verify_elmpay_webhook(
    secret: bytes,
    raw_body: bytes,
    signature_header: str,
    tolerance: int = 300
) -> bool:
    """
    验证 ELMPay 推送的 Webhook 签名 (HMAC-SHA256)
    """
    if not isinstance(secret, bytes) or len(secret) < 32:
        return False
    if not isinstance(raw_body, bytes) or not isinstance(signature_header, str):
        return False

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
        encoded_sig = parts["v1"]
        padding = "=" * ((4 - len(encoded_sig) % 4) % 4)
        supplied_sig = base64.b64decode(encoded_sig + padding, altchars=b"-_", validate=True)
    except Exception:
        return False

    if abs(time.time() - timestamp) > tolerance:
        return False

    string_to_sign = str(timestamp).encode("ascii") + b"." + raw_body
    expected_sig = hmac.new(secret, string_to_sign, hashlib.sha256).digest()
    return hmac.compare_digest(expected_sig, supplied_sig)


def handle_elmpay_captured_event(
    event_payload: dict,
    expected_order_no: str,
    expected_amount_minor: int
) -> bool:
    """
    处理 payment_intent.captured 事件并进行业务订单核对与履约
    """
    expected_digest = hashlib.sha256(expected_order_no.encode("utf-8")).hexdigest()
    if event_payload.get("business_order_digest") != expected_digest:
        return False

    if event_payload.get("amount_minor") != expected_amount_minor or event_payload.get("currency") != "CNY":
        return False

    return True


class ElmosPaymentIntegrationLiveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Verify edge gateway health
        req = urllib.request.Request(f"{HEALTH_URL}/health/ready")
        try:
            with urllib.request.urlopen(req, timeout=1) as resp:
                cls.health_status = resp.status
                body = json.loads(resp.read().decode())
                assert body.get("status") == "ready"
        except Exception as e:
            raise unittest.SkipTest(f"ELMPay Edge Gateway not running at {HEALTH_URL} (start with apps/edge-gateway for live tests): {e}")

    def _headers(self, idempotency_key=None, extra_headers=None):
        h = {
            "Authorization": f"Bearer {API_KEY}",
            "X-Project-Id": PROJECT_ID,
            "X-Request-Id": f"req-test-{uuid.uuid4().hex[:12]}",
            "traceparent": f"00-{uuid.uuid4().hex}-{uuid.uuid4().hex[:16]}-01",
            "Content-Type": "application/json; charset=utf-8",
        }
        if idempotency_key:
            h["Idempotency-Key"] = idempotency_key
        if extra_headers:
            h.update(extra_headers)
        return h

    def test_01_create_and_get_checkout_session(self):
        """3.1 & 3.2: 创建托管收银台会话与状态查询"""
        order_no = f"ELMOS-{int(time.time())}-1001"
        idem_key = str(uuid.uuid4())
        payload = {
            "business_order_no": order_no,
            "amount": 9900,  # 99.00 CNY in minor units (cents)
            "currency": "CNY",
            "return_route_id": "checkout-complete",
            "payment_method": "alipay",
        }
        req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions",
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(idempotency_key=idem_key),
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 201)
            body = json.loads(resp.read().decode())

        self.assertEqual(body.get("status"), "OPEN")
        self.assertIn("checkout_session_id", body)
        self.assertIn("payment_intent_id", body)
        self.assertIn("checkout_url", body)
        self.assertIn("expires_at", body)

        session_id = body["checkout_session_id"]
        checkout_url = body["checkout_url"]
        self.assertIn(f"session={session_id}", checkout_url)
        self.assertIn("&token=", checkout_url)
        self.assertNotIn("?", checkout_url)  # Token must be in fragment, never in query

        # Query Checkout Session (3.2)
        get_req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions/{session_id}",
            headers=self._headers(),
            method="GET",
        )
        with urllib.request.urlopen(get_req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            get_body = json.loads(resp.read().decode())

        self.assertEqual(get_body["checkout_session_id"], session_id)
        self.assertEqual(get_body["business_order_no"], order_no)
        self.assertEqual(get_body["amount"], 9900)
        self.assertEqual(get_body["currency"], "CNY")
        self.assertEqual(get_body["status"], "OPEN")

    def test_02_confirm_checkout_and_query_intent(self):
        """3.2 & 3.3 & 3.4: 模拟支付确认、查询支付意图与状态只读投影"""
        order_no = f"ELMOS-{int(time.time())}-1002"
        create_req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions",
            data=json.dumps({
                "business_order_no": order_no,
                "amount": 1250,
                "currency": "CNY",
                "return_route_id": "checkout-complete",
                "payment_method": "alipay",
            }).encode("utf-8"),
            headers=self._headers(idempotency_key=str(uuid.uuid4())),
            method="POST",
        )
        with urllib.request.urlopen(create_req, timeout=5) as resp:
            body = json.loads(resp.read().decode())
        session_id = body["checkout_session_id"]
        intent_id = body["payment_intent_id"]

        # Confirm checkout
        confirm_req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions/{session_id}/confirm",
            data=json.dumps({"method": "alipay"}).encode("utf-8"),
            headers=self._headers(idempotency_key=str(uuid.uuid4())),
            method="POST",
        )
        with urllib.request.urlopen(confirm_req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            confirm_body = json.loads(resp.read().decode())
        self.assertEqual(confirm_body["status"], "SUCCEEDED")

        # Query Payment Intent (3.3)
        intent_req = urllib.request.Request(
            f"{BASE_URL}/v1/payment_intents/{intent_id}",
            headers=self._headers(),
            method="GET",
        )
        with urllib.request.urlopen(intent_req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            intent_body = json.loads(resp.read().decode())

        self.assertEqual(intent_body["id"], intent_id)
        self.assertEqual(intent_body["project_id"], PROJECT_ID)
        self.assertEqual(intent_body["business_order_no"], order_no)
        self.assertEqual(intent_body["status"], "succeeded")
        self.assertEqual(intent_body["state"], "captured")
        self.assertEqual(intent_body["amount_captured"], 1250)
        self.assertEqual(intent_body["currency"], "CNY")

    def test_03_create_refund_flow(self):
        """3.5: 申请退款并核验状态"""
        order_no = f"ELMOS-{int(time.time())}-1003"
        create_req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions",
            data=json.dumps({
                "business_order_no": order_no,
                "amount": 3500,
                "currency": "CNY",
                "return_route_id": "checkout-complete",
                "payment_method": "alipay",
            }).encode("utf-8"),
            headers=self._headers(idempotency_key=str(uuid.uuid4())),
            method="POST",
        )
        with urllib.request.urlopen(create_req, timeout=5) as resp:
            body = json.loads(resp.read().decode())
        session_id = body["checkout_session_id"]
        intent_id = body["payment_intent_id"]

        # Confirm checkout
        confirm_req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions/{session_id}/confirm",
            data=json.dumps({"method": "alipay"}).encode("utf-8"),
            headers=self._headers(idempotency_key=str(uuid.uuid4())),
            method="POST",
        )
        with urllib.request.urlopen(confirm_req, timeout=5) as resp:
            pass

        # Request Refund
        refund_req = urllib.request.Request(
            f"{BASE_URL}/v1/refunds",
            data=json.dumps({
                "payment_intent_id": intent_id,
                "amount": 3500,
                "reason": "CUSTOMER_REQUEST",
            }).encode("utf-8"),
            headers=self._headers(
                idempotency_key=str(uuid.uuid4()),
                extra_headers={
                    "X-Device-Context-Digest": "11" * 32,
                }
            ),
            method="POST",
        )
        with urllib.request.urlopen(refund_req, timeout=5) as resp:
            self.assertEqual(resp.status, 201)
            refund_body = json.loads(resp.read().decode())

        self.assertEqual(refund_body["status"], "succeeded")
        self.assertEqual(refund_body["amount"], 3500)
        self.assertEqual(refund_body["currency"], "CNY")
        self.assertEqual(refund_body["payment_intent_id"], intent_id)
        self.assertIn("provider_refund_id", refund_body)

    def test_04_cancel_payment_intent(self):
        """3.6: 主动关单取消支付意图"""
        order_no = f"ELMOS-{int(time.time())}-1004"
        create_req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions",
            data=json.dumps({
                "business_order_no": order_no,
                "amount": 6600,
                "currency": "CNY",
                "return_route_id": "checkout-complete",
                "payment_method": "wechat",
            }).encode("utf-8"),
            headers=self._headers(idempotency_key=str(uuid.uuid4())),
            method="POST",
        )
        with urllib.request.urlopen(create_req, timeout=5) as resp:
            body = json.loads(resp.read().decode())
        intent_id = body["payment_intent_id"]

        cancel_req = urllib.request.Request(
            f"{BASE_URL}/v1/payment_intents/{intent_id}/cancel",
            data=json.dumps({"reason": "order_expired_by_customer"}).encode("utf-8"),
            headers=self._headers(idempotency_key=str(uuid.uuid4())),
            method="POST",
        )
        with urllib.request.urlopen(cancel_req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            cancel_body = json.loads(resp.read().decode())

        self.assertEqual(cancel_body["status"], "canceled")
        self.assertEqual(cancel_body["state"], "canceled")

    def test_05_error_contracts_and_safeguards(self):
        """5: 异常与风控保护契约验证 (零浮点、鉴权、幂等防重)"""
        # 1. 浮点金额直接拒绝 (零浮点原则)
        float_req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions",
            data=json.dumps({
                "business_order_no": "ORD-FLOAT",
                "amount": 99.5,
                "currency": "CNY",
                "return_route_id": "checkout-complete",
                "payment_method": "alipay",
            }).encode("utf-8"),
            headers=self._headers(idempotency_key=str(uuid.uuid4())),
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(float_req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)
        err_body = json.loads(ctx.exception.read().decode())
        self.assertEqual(err_body.get("code"), "invalid_request")

        # 2. 缺少鉴权拒绝
        unauth_headers = self._headers(idempotency_key=str(uuid.uuid4()))
        del unauth_headers["Authorization"]
        unauth_req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions",
            data=json.dumps({
                "business_order_no": "ORD-UNAUTH",
                "amount": 1000,
                "currency": "CNY",
                "return_route_id": "checkout-complete",
                "payment_method": "alipay",
            }).encode("utf-8"),
            headers=unauth_headers,
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(unauth_req, timeout=5)
        self.assertEqual(ctx.exception.code, 401)

        # 3. 同一幂等键不同请求体返回 409 冲突
        shared_key = str(uuid.uuid4())
        first_req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions",
            data=json.dumps({
                "business_order_no": "ORD-IDEM-1",
                "amount": 1000,
                "currency": "CNY",
                "return_route_id": "checkout-complete",
                "payment_method": "alipay",
            }).encode("utf-8"),
            headers=self._headers(idempotency_key=shared_key),
            method="POST",
        )
        with urllib.request.urlopen(first_req, timeout=5) as resp:
            self.assertEqual(resp.status, 201)

        conflict_req = urllib.request.Request(
            f"{BASE_URL}/v1/checkout-sessions",
            data=json.dumps({
                "business_order_no": "ORD-IDEM-CONFLICT",
                "amount": 2000,
                "currency": "CNY",
                "return_route_id": "checkout-complete",
                "payment_method": "alipay",
            }).encode("utf-8"),
            headers=self._headers(idempotency_key=shared_key),
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(conflict_req, timeout=5)
        self.assertEqual(ctx.exception.code, 409)
        conflict_body = json.loads(ctx.exception.read().decode())
        self.assertEqual(conflict_body.get("code"), "idempotency_key_reuse")

    def test_06_webhook_hmac_sha256_verification_and_fulfillment(self):
        """4 & 7: Webhook HMAC-SHA256 签名验证与履约核心算法校验"""
        secret_bytes = base64.urlsafe_b64decode(WEBHOOK_SECRET_B64URL + "==")
        order_no = "ELMOS-20260918-99201"
        order_digest = hashlib.sha256(order_no.encode("utf-8")).hexdigest()
        now_ts = int(time.time())

        payload_dict = {
            "payment_intent_id": str(uuid.uuid4()),
            "project_id": PROJECT_ID,
            "provider": "alipay",
            "captured_at": "2026-09-18T10:02:15Z",
            "amount_minor": 9900,
            "currency": "CNY",
            "business_order_digest": order_digest,
        }
        raw_body_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")

        # 构造有效签名
        string_to_sign = f"{now_ts}.".encode("ascii") + raw_body_bytes
        hmac_digest = hmac.new(secret_bytes, string_to_sign, hashlib.sha256).digest()
        sig_v1 = base64.urlsafe_b64encode(hmac_digest).rstrip(b"=").decode("ascii")
        valid_header = f"t={now_ts},v1={sig_v1}"

        # 1. 正常有效签名验签通过
        self.assertTrue(verify_elmpay_webhook(secret_bytes, raw_body_bytes, valid_header))

        # 2. 报文被篡改 (金额从 9900 改为 1000) 验签拒绝
        tampered_body = raw_body_bytes.replace(b"9900", b"1000")
        self.assertFalse(verify_elmpay_webhook(secret_bytes, tampered_body, valid_header))

        # 3. 时间戳过期 (> 300s) 拒绝重放
        expired_ts = now_ts - 305
        string_to_sign_expired = f"{expired_ts}.".encode("ascii") + raw_body_bytes
        hmac_expired = hmac.new(secret_bytes, string_to_sign_expired, hashlib.sha256).digest()
        sig_expired = base64.urlsafe_b64encode(hmac_expired).rstrip(b"=").decode("ascii")
        expired_header = f"t={expired_ts},v1={sig_expired}"
        self.assertFalse(verify_elmpay_webhook(secret_bytes, raw_body_bytes, expired_header, tolerance=300))

        # 4. 业务核验与履约处理 handle_elmpay_captured_event
        self.assertTrue(handle_elmpay_captured_event(payload_dict, order_no, 9900))

        # 5. 业务订单不匹配拒绝履约
        self.assertFalse(handle_elmpay_captured_event(payload_dict, "WRONG-ORDER-NO", 9900))

        # 6. 金额少付/不匹配拒绝履约
        self.assertFalse(handle_elmpay_captured_event(payload_dict, order_no, 10000))


if __name__ == "__main__":
    unittest.main()
