import base64, hashlib, hmac, json, unittest
from elmpay_client import CheckoutRequest, ConfirmRequest, ElmpayClient, verify_webhook

class FakeResponse:
    status = 200
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def read(self): return b'{}'

class ContractTest(unittest.TestCase):
    def test_create_get_and_confirm_use_canonical_contract(self):
        calls = []
        def urlopen(request, timeout):
            calls.append((request, timeout))
            return FakeResponse()
        project = "10000000-0000-4000-8000-000000000002"
        client = ElmpayClient("https://api.example/", "token", project, urlopen=urlopen)
        client.create_checkout_session(CheckoutRequest("order-1", 1250, "USD", "complete"),
                                       "create-idempotency-0001")
        client.get_checkout_session("session/unsafe")
        client.confirm_checkout_session("session-1", ConfirmRequest("stripe_card", "psp://tok/1", "fp"),
                                        "confirm-idempotency-001")
        self.assertEqual([call[0].get_method() for call in calls], ["POST", "GET", "POST"])
        self.assertEqual([urllib_path(call[0].full_url) for call in calls],
                         ["/v1/checkout-sessions", "/v1/checkout-sessions/session%2Funsafe",
                          "/v1/checkout-sessions/session-1/confirm"])
        for request, _ in calls:
            headers = {key.lower(): value for key, value in request.header_items()}
            self.assertEqual(headers["x-project-id"], project)
        created = json.loads(calls[0][0].data)
        self.assertEqual(created, {"business_order_no": "order-1", "amount": 1250,
                                   "currency": "USD", "return_route_id": "complete"})
        self.assertIsInstance(created["amount"], int)
        self.assertFalse({"project_id", "order_reference", "amount_minor", "return_uri"} & created.keys())
        self.assertEqual(json.loads(calls[2][0].data), {"payment_method_type": "stripe_card",
                                                       "payment_method_reference": "psp://tok/1",
                                                       "fingerprint": "fp"})

def urllib_path(value):
    from urllib.parse import urlsplit
    return urlsplit(value).path

class WebhookTest(unittest.TestCase):
    def test_raw_body_and_timestamp_are_bound(self):
        secret = bytes([7]) * 32; body = b'{"ok":true}'; timestamp = 1700000000
        signature = base64.urlsafe_b64encode(hmac.new(secret, str(timestamp).encode() + b'.' + body, hashlib.sha256).digest()).rstrip(b'=').decode()
        header = f't={timestamp},v1={signature}'
        self.assertTrue(verify_webhook(secret, body, header, now=timestamp))
        self.assertFalse(verify_webhook(secret, b'{}', header, now=timestamp))

if __name__ == '__main__': unittest.main()
