import base64, io, json, unittest, urllib.error
from pathlib import Path
from elmpay_client import (ApiError, CheckoutRequest, ConfirmRequest, ElmpayClient,
                           InvalidResponseError, MAX_RESPONSE_BYTES, ResponseTooLargeError,
                           verify_webhook)

class FakeResponse:
    def __init__(self, status=200, body=None, content_type="application/json", headers=None):
        self.status = status
        self._stream = io.BytesIO(body if body is not None else valid_session())
        self.headers = {"content-type": content_type, "x-request-id": "request-1",
                        **(headers or {})}
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def read(self, size=-1): return self._stream.read(size)

def valid_session():
    return json.dumps({"checkout_session_id": "cs_123", "expires_at": "2026-08-30T12:00:00Z",
                       "checkout_url": "https://checkout.example/cs_123"}).encode()

class ContractTest(unittest.TestCase):
    def test_constructor_requires_bounded_timeout(self):
        for timeout in (0, -1, float("inf"), 301):
            with self.assertRaises(ValueError):
                ElmpayClient("https://api.example/", "token", "project", timeout=timeout)
        for base_url in ("https://user:pass@api.example/", "https://api.example/?x=1",
                         "https://api.example/#fragment"):
            with self.assertRaises(ValueError):
                ElmpayClient(base_url, "token", "project")

    def test_create_get_and_confirm_use_canonical_contract(self):
        calls = []
        def urlopen(request, timeout):
            calls.append((request, timeout))
            return FakeResponse(201 if len(calls) == 1 else 200)
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

    def test_rejects_chunked_body_larger_than_uniform_limit(self):
        response = FakeResponse(body=b"{" + b" " * MAX_RESPONSE_BYTES)
        client = ElmpayClient("https://api.example/", "token", "project", maximum_attempts=1,
                              urlopen=lambda *_args, **_kwargs: response)
        with self.assertRaises(ResponseTooLargeError):
            client.get_checkout_session("cs_123")

    def test_rejects_wrong_content_type_and_invalid_typed_schema(self):
        project = "10000000-0000-4000-8000-000000000002"
        wrong_type = ElmpayClient("https://api.example/", "token", project, maximum_attempts=1,
                                  urlopen=lambda *_args, **_kwargs: FakeResponse(content_type="text/html"))
        with self.assertRaises(InvalidResponseError):
            wrong_type.get_checkout_session("cs_123")
        invalid_schema = ElmpayClient(
            "https://api.example/", "token", project, maximum_attempts=1,
            urlopen=lambda *_args, **_kwargs: FakeResponse(body=b'{"checkout_session_id":"cs_123"}'))
        with self.assertRaises(InvalidResponseError):
            invalid_schema.get_checkout_session("cs_123")
        unexpected_status = ElmpayClient(
            "https://api.example/", "token", project, maximum_attempts=1,
            urlopen=lambda *_args, **_kwargs: FakeResponse(status=200))
        with self.assertRaises(InvalidResponseError):
            unexpected_status.create_checkout_session(CheckoutRequest("order-1", 100, "USD"),
                                                       "idem-1")

    def test_maps_typed_problem_and_binds_status(self):
        problem = json.dumps({"type": "https://docs.example/problems/declined", "title": "Declined",
                              "status": 402, "code": "payment_declined", "trace_id": "trace-1"}).encode()
        error = urllib.error.HTTPError(
            "https://api.example/v1/checkout-sessions/cs_123", 402, "Payment Required",
            {"content-type": "application/problem+json", "x-request-id": "request-1"},
            io.BytesIO(problem))
        client = ElmpayClient("https://api.example/", "token", "project", maximum_attempts=1,
                              urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(error))
        with self.assertRaises(ApiError) as raised:
            client.get_checkout_session("cs_123")
        self.assertEqual(raised.exception.problem.code, "payment_declined")
        self.assertEqual(raised.exception.request_id, "request-1")

def urllib_path(value):
    from urllib.parse import urlsplit
    return urlsplit(value).path

class WebhookTest(unittest.TestCase):
    def test_raw_body_and_timestamp_are_bound(self):
        vector = json.loads((Path(__file__).resolve().parents[3] /
                             "contracts/webhooks/signing-v1.json").read_text())
        secret = base64.urlsafe_b64decode(vector["secret_base64url"] + "=")
        body = vector["raw_body_utf8"].encode()
        self.assertTrue(verify_webhook(secret, body, vector["signature_header"],
                                       now=vector["timestamp"]))
        self.assertFalse(verify_webhook(secret, b'{}', vector["signature_header"],
                                        now=vector["timestamp"]))

    def test_signature_header_duplicates_and_malformed_values_fail_closed(self):
        vector = json.loads((Path(__file__).resolve().parents[3] /
                             "contracts/webhooks/signing-v1.json").read_text())
        secret = base64.urlsafe_b64decode(vector["secret_base64url"] + "=")
        body = vector["raw_body_utf8"].encode()
        header = vector["signature_header"]
        self.assertFalse(verify_webhook(secret, body, header + ",t=" + str(vector["timestamp"]),
                                        now=vector["timestamp"]))
        self.assertFalse(verify_webhook(secret, body, header + ",v1=bad",
                                        now=vector["timestamp"]))
        self.assertFalse(verify_webhook(secret, body, header.replace("t=", "t=+"),
                                        now=vector["timestamp"]))

if __name__ == '__main__': unittest.main()
